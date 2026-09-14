//! 活动传输计量。定期/阈值/最终Drop同步持久checkpoint，不依赖异步Drop。

use super::{
    usage_spool::TrafficUsageSpool, TrafficDecision, TrafficPolicyKind, TrafficUsageEvent,
};
use crate::AppState;
use std::{
    io,
    net::IpAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use uuid::Uuid;

const CHECKPOINT_BYTES: u64 = 64 * 1024;

pub(crate) struct TrafficUsageMeter {
    spool: Arc<TrafficUsageSpool>,
    kind: TrafficPolicyKind,
    policy_id: Uuid,
    pending: Mutex<PendingUsage>,
    registered: AtomicBool,
}

#[derive(Default)]
struct PendingUsage {
    bytes: u64,
    staged: Option<TrafficUsageEvent>,
}

impl TrafficUsageMeter {
    pub(crate) fn new(
        spool: Arc<TrafficUsageSpool>,
        kind: TrafficPolicyKind,
        policy_id: Uuid,
    ) -> Arc<Self> {
        let meter = Arc::new(Self {
            spool: spool.clone(),
            kind,
            policy_id,
            pending: Mutex::new(PendingUsage::default()),
            registered: AtomicBool::new(false),
        });
        meter
            .registered
            .store(spool.register_meter(&meter), Ordering::Release);
        meter
    }

    pub(crate) fn add(&self, bytes: u64) -> io::Result<()> {
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| io::Error::other("Traffic meter lock poisoned"))?;
        pending.bytes = pending.bytes.saturating_add(bytes);
        if pending.bytes >= CHECKPOINT_BYTES {
            self.flush_locked(&mut pending).map_err(io::Error::other)?;
        }
        self.ensure_open()
    }

    pub(crate) fn ensure_open(&self) -> io::Result<()> {
        self.spool.ensure_forwarding().map_err(io::Error::other)
    }

    pub(crate) fn checkpoint(&self) -> anyhow::Result<()> {
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| anyhow::anyhow!("Traffic meter lock poisoned"))?;
        self.flush_locked(&mut pending)
    }

    fn flush_locked(&self, pending: &mut PendingUsage) -> anyhow::Result<()> {
        loop {
            if pending.staged.is_none() {
                if pending.bytes == 0 {
                    break;
                }
                pending.staged = Some(TrafficUsageEvent {
                    event_id: Uuid::new_v4(),
                    kind: self.kind,
                    policy_id: self.policy_id,
                    bytes: pending.bytes,
                });
            }
            let event = pending
                .staged
                .as_ref()
                .expect("checkpoint event should exist");
            // 本机commit结果不明时保留同UUID，重试不生成新事件造成复计。
            self.spool.enqueue(event)?;
            pending.bytes = pending.bytes.saturating_sub(event.bytes);
            pending.staged = None;
        }
        Ok(())
    }
}

impl Drop for TrafficUsageMeter {
    fn drop(&mut self) {
        if let Err(error) = self.checkpoint() {
            self.spool.mark_fault();
            // spool自身设置粘性fault；所有新授权和后续IO都拒绝继续。
            tracing::error!("Final traffic checkpoint failed; forwarding blocked: {error}");
        }
        if self.registered.load(Ordering::Acquire) {
            self.spool.finish_meter();
        }
    }
}

pub(crate) struct MeteredIo<T> {
    inner: T,
    meter: Arc<TrafficUsageMeter>,
}
impl<T> MeteredIo<T> {
    pub(crate) fn new(inner: T, meter: Arc<TrafficUsageMeter>) -> Self {
        Self { inner, meter }
    }
}
impl<T: AsyncRead + Unpin> AsyncRead for MeteredIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.meter.ensure_open()?;
        let previous = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            self.meter.add((buf.filled().len() - previous) as u64)?;
        }
        result
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for MeteredIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.meter.ensure_open()?;
        match Pin::new(&mut self.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(bytes)) => {
                self.meter.add(bytes as u64)?;
                Poll::Ready(Ok(bytes))
            }
            result => result,
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub(crate) async fn authorize_traffic(
    state: &AppState,
    kind: TrafficPolicyKind,
    policy_id: Uuid,
    source: IpAddr,
) -> anyhow::Result<TrafficDecision> {
    let token = state.ha_runtime.fencing_token()?;
    anyhow::ensure!(state.accepts_public_work(), "Traffic admission is closed");
    let decision = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let _admission = state.traffic_usage_spool.lock_admission().await;
        state.traffic_usage_spool.ensure_forwarding()?;
        state.traffic_usage_spool.checkpoint_active()?;
        while state.traffic_usage_spool.pending_count()? != 0 {
            state
                .traffic_usage_spool
                .pump(&state.traffic_controls)
                .await?;
        }
        state.traffic_usage_spool.ensure_forwarding()?;
        state
            .traffic_controls
            .authorize(kind, policy_id, source, crate::unix_seconds())
            .await
    })
    .await
    .map_err(|_| anyhow::anyhow!("Traffic admission storage timed out"))??;
    state.traffic_usage_spool.ensure_forwarding()?;
    anyhow::ensure!(
        state.accepts_public_work() && state.ha_runtime.fencing_token()? == token,
        "Traffic admission leadership changed"
    );
    Ok(decision)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::Database;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn queued_bytes(database: &Database) -> u64 {
        database
            .with_connection(|connection| {
                let mut statement = connection.prepare("SELECT bytes FROM traffic_usage_spool")?;
                let bytes = statement
                    .query_map([], |row| row.get::<_, String>(0))?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(bytes
                    .iter()
                    .map(|value| value.parse::<u64>().unwrap())
                    .sum())
            })
            .unwrap()
    }

    #[test]
    fn idle_meter_checkpoint_and_final_drop_do_not_double_count() {
        let database = Database::memory().unwrap();
        let spool = Arc::new(TrafficUsageSpool::open(&database).unwrap());
        let meter = TrafficUsageMeter::new(spool.clone(), TrafficPolicyKind::Http, Uuid::new_v4());
        meter.add(17).unwrap();
        assert_eq!(queued_bytes(&database), 0);
        spool.checkpoint_active().unwrap();
        assert_eq!(queued_bytes(&database), 17);
        meter.add(23).unwrap();
        spool.checkpoint_active().unwrap();
        drop(meter);
        assert_eq!(queued_bytes(&database), 40);
        assert_eq!(spool.active_meter_count().unwrap(), 0);
    }

    #[test]
    fn close_admission_rejects_late_meter_registration_without_hiding_existing_drop() {
        let database = Database::memory().unwrap();
        let spool = Arc::new(TrafficUsageSpool::open(&database).unwrap());
        let meter = TrafficUsageMeter::new(spool.clone(), TrafficPolicyKind::Http, Uuid::new_v4());
        meter.add(19).unwrap();
        spool.close_admission();
        let late = TrafficUsageMeter::new(spool.clone(), TrafficPolicyKind::Http, Uuid::new_v4());
        assert_eq!(spool.active_meter_count().unwrap(), 1);
        assert!(late.ensure_open().is_err());
        drop(late);
        assert_eq!(spool.active_meter_count().unwrap(), 1);
        drop(meter);
        assert_eq!(spool.active_meter_count().unwrap(), 0);
        assert_eq!(queued_bytes(&database), 19);
    }

    #[tokio::test]
    async fn stream_drop_preserves_partial_transfer_and_shutdown_stops_new_io() {
        let database = Database::memory().unwrap();
        let spool = Arc::new(TrafficUsageSpool::open(&database).unwrap());
        let meter = TrafficUsageMeter::new(spool.clone(), TrafficPolicyKind::Tcp, Uuid::new_v4());
        let (local, mut peer) = tokio::io::duplex(128);
        let mut measured = MeteredIo::new(local, meter);
        peer.write_all(b"received").await.unwrap();
        let mut buffer = [0u8; 8];
        measured.read_exact(&mut buffer).await.unwrap();
        measured.write_all(b"sent").await.unwrap();
        spool.close_admission();
        assert!(measured.write_all(b"rejected").await.is_err());
        drop(measured);
        assert_eq!(queued_bytes(&database), 12);
        assert_eq!(spool.active_meter_count().unwrap(), 0);
    }
}
