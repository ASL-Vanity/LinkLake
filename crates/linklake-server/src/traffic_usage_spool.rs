//! 同步持久账务outbox与可排空worker。Drop只落本机事务，不创建异步任务。

use super::usage_meter::TrafficUsageMeter;
use super::{TrafficPolicyKind, TrafficUsageEvent};
use crate::{database::Database, traffic_control_store::TrafficControlStore};
use rusqlite::{params, Connection, TransactionBehavior};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex, Weak,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::{
    sync::{watch, Mutex as AsyncMutex, MutexGuard as AsyncMutexGuard},
    time::{Instant, MissedTickBehavior},
};
use uuid::Uuid;

pub(crate) struct TrafficUsageSpool {
    connection: Mutex<Connection>,
    admission: AsyncMutex<()>,
    faulted: AtomicBool,
    closing: AtomicBool,
    #[cfg(test)]
    persistent: bool,
    meters: Mutex<Vec<Weak<TrafficUsageMeter>>>,
    active_meters: AtomicUsize,
}

impl TrafficUsageSpool {
    pub(crate) fn open(database: &Database) -> anyhow::Result<Self> {
        let connection = database.connect()?;
        // 此连接独立使用FULL，已确认提交的Drop事件可跨进程/系统崩溃恢复。
        connection.execute_batch(
            "PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS traffic_usage_spool (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL UNIQUE,
                kind TEXT NOT NULL,
                policy_id TEXT NOT NULL,
                bytes TEXT NOT NULL
            );",
        )?;
        Ok(Self {
            connection: Mutex::new(connection),
            admission: AsyncMutex::new(()),
            faulted: AtomicBool::new(false),
            closing: AtomicBool::new(false),
            #[cfg(test)]
            persistent: database.is_persistent(),
            meters: Mutex::new(Vec::new()),
            active_meters: AtomicUsize::new(0),
        })
    }

    #[cfg(test)]
    pub(crate) fn is_persistent(&self) -> bool {
        self.persistent
    }

    pub(crate) fn register_meter(&self, meter: &Arc<TrafficUsageMeter>) -> bool {
        match self.meters.lock() {
            Ok(mut meters) => {
                // 与close_admission同一互斥边界；关闭后不再增加活动计数。
                if self.closing.load(Ordering::Acquire) {
                    return false;
                }
                meters.retain(|meter| meter.strong_count() != 0);
                self.active_meters.fetch_add(1, Ordering::AcqRel);
                meters.push(Arc::downgrade(meter));
                true
            }
            Err(_) => {
                self.faulted.store(true, Ordering::Release);
                false
            }
        }
    }

    pub(crate) async fn lock_admission(&self) -> AsyncMutexGuard<'_, ()> {
        self.admission.lock().await
    }

    pub(crate) fn finish_meter(&self) {
        // 只在最终checkpoint完成（或已设置粘性故障）后减少，避免Weak计数先归零。
        self.active_meters.fetch_sub(1, Ordering::AcqRel);
    }

    pub(crate) fn checkpoint_active(&self) -> anyhow::Result<()> {
        let active = {
            let mut meters = self
                .meters
                .lock()
                .map_err(|_| anyhow::anyhow!("Traffic meter registry poisoned"))?;
            meters.retain(|meter| meter.strong_count() != 0);
            meters.iter().filter_map(Weak::upgrade).collect::<Vec<_>>()
        };
        for meter in active {
            meter.checkpoint()?;
        }
        Ok(())
    }

    pub(crate) fn active_meter_count(&self) -> anyhow::Result<usize> {
        Ok(self.active_meters.load(Ordering::Acquire))
    }

    /// root的所有新连接授权先检查该门。落盘失败是粘性故障，后续成功不得掩盖已丢事件。
    pub(crate) fn ensure_healthy(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.faulted.load(Ordering::Acquire),
            "Traffic usage spool failed; new traffic must be stopped"
        );
        Ok(())
    }

    pub(crate) fn mark_fault(&self) {
        self.faulted.store(true, Ordering::Release);
    }

    pub(crate) fn close_admission(&self) {
        match self.meters.lock() {
            Ok(_registration_guard) => self.closing.store(true, Ordering::Release),
            Err(_) => {
                self.closing.store(true, Ordering::Release);
                self.faulted.store(true, Ordering::Release);
            }
        }
    }

    pub(crate) fn ensure_forwarding(&self) -> anyhow::Result<()> {
        self.ensure_healthy()?;
        anyhow::ensure!(
            !self.closing.load(Ordering::Acquire),
            "Traffic accounting is closing"
        );
        Ok(())
    }

    pub(crate) fn enqueue(&self, event: &TrafficUsageEvent) -> anyhow::Result<()> {
        let result = self.enqueue_inner(event);
        if result.is_err() {
            self.faulted.store(true, Ordering::Release);
        }
        result
    }

    fn enqueue_inner(&self, event: &TrafficUsageEvent) -> anyhow::Result<()> {
        anyhow::ensure!(!event.event_id.is_nil(), "Traffic usage event ID is nil");
        if event.bytes == 0 {
            return Ok(());
        }
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("Traffic usage spool lock poisoned"))?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute("INSERT OR IGNORE INTO traffic_usage_spool(event_id,kind,policy_id,bytes) VALUES(?1,?2,?3,?4)", params![event.event_id.to_string(), event.kind.as_str(), event.policy_id.to_string(), event.bytes.to_string()])?;
        let saved: (String, String, String) = transaction.query_row(
            "SELECT kind,policy_id,bytes FROM traffic_usage_spool WHERE event_id=?1",
            [event.event_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        anyhow::ensure!(
            saved
                == (
                    event.kind.as_str().to_owned(),
                    event.policy_id.to_string(),
                    event.bytes.to_string()
                ),
            "Traffic usage spool event identity mismatch"
        );
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn pending_count(&self) -> anyhow::Result<u64> {
        Ok(self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("Traffic usage spool lock poisoned"))?
            .query_row("SELECT COUNT(*) FROM traffic_usage_spool", [], |row| {
                row.get(0)
            })?)
    }

    fn batch(&self) -> anyhow::Result<Vec<TrafficUsageEvent>> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("Traffic usage spool lock poisoned"))?;
        let mut statement = connection.prepare("SELECT event_id,kind,policy_id,bytes FROM traffic_usage_spool ORDER BY sequence LIMIT 64")?;
        let raw = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        raw.into_iter()
            .map(|(id, kind, policy, bytes)| {
                Ok(TrafficUsageEvent {
                    event_id: Uuid::parse_str(&id)?,
                    kind: TrafficPolicyKind::parse(&kind)?,
                    policy_id: Uuid::parse_str(&policy)?,
                    bytes: bytes.parse()?,
                })
            })
            .collect()
    }

    fn acknowledge(&self, event: &TrafficUsageEvent) -> anyhow::Result<()> {
        self.connection.lock().map_err(|_| anyhow::anyhow!("Traffic usage spool lock poisoned"))?.execute(
            "DELETE FROM traffic_usage_spool WHERE event_id=?1 AND kind=?2 AND policy_id=?3 AND bytes=?4", params![event.event_id.to_string(),event.kind.as_str(),event.policy_id.to_string(),event.bytes.to_string()],
        )?;
        Ok(())
    }

    /// 网络提交结果不明时不ack；同UUID再次上传由共享账本去重。
    pub(crate) async fn pump(&self, store: &TrafficControlStore) -> anyhow::Result<usize> {
        self.checkpoint_active()?;
        let batch = self.batch()?;
        let mut uploaded = 0;
        for event in batch {
            let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
            store.enqueue_usage_event(&event, now).await?;
            self.acknowledge(&event)?;
            uploaded += 1;
        }
        store.drain_pending_usage().await?;
        Ok(uploaded)
    }

    /// 调用前先停止新流量并等待连接/Body释放，再发stop；HA成员心跳必须晚于本worker关闭。
    pub(crate) async fn run(
        &self,
        store: &TrafficControlStore,
        mut stop: watch::Receiver<bool>,
        drain_timeout: Duration,
    ) -> anyhow::Result<()> {
        let mut ticker = tokio::time::interval(Duration::from_millis(250));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            if *stop.borrow() {
                break;
            }
            tokio::select! {
                _ = ticker.tick() => {
                    match tokio::time::timeout(Duration::from_secs(10), self.pump(store)).await {
                        Ok(Ok(_)) => {},
                        // 事件仍在持久spool或共享pending；admission_ready防止旧配额继续放行。
                        Ok(Err(error)) => tracing::warn!("Traffic usage upload retained for retry: {error}"),
                        Err(_) => tracing::warn!("Traffic usage upload timed out; durable events retained"),
                    }
                    self.ensure_healthy()?;
                }
                changed = stop.changed() => { if changed.is_err() || *stop.borrow() { break; } }
            }
        }
        self.drain(store, Instant::now() + drain_timeout).await
    }

    pub(crate) async fn drain(
        &self,
        store: &TrafficControlStore,
        deadline: Instant,
    ) -> anyhow::Result<()> {
        loop {
            if self.pending_count()? == 0 {
                return self.ensure_healthy();
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            anyhow::ensure!(
                !remaining.is_zero(),
                "Traffic usage drain timed out; durable events retained"
            );
            match tokio::time::timeout(remaining, self.pump(store)).await {
                Ok(Ok(_)) => {}
                Ok(Err(_)) => {
                    let delay = deadline
                        .saturating_duration_since(Instant::now())
                        .min(Duration::from_millis(250));
                    tokio::time::sleep(delay).await;
                }
                Err(_) => anyhow::bail!("Traffic usage drain timed out; durable events retained"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traffic_control::TrafficControlCatalog;

    #[tokio::test]
    async fn unacknowledged_spool_survives_reopen_and_upload_is_idempotent() {
        let database = Database::memory().unwrap();
        let event = TrafficUsageEvent {
            event_id: Uuid::new_v4(),
            kind: TrafficPolicyKind::Http,
            policy_id: Uuid::new_v4(),
            bytes: 2048,
        };
        let spool = TrafficUsageSpool::open(&database).unwrap();
        spool.enqueue(&event).unwrap();
        spool.enqueue(&event).unwrap();
        assert_eq!(spool.pending_count().unwrap(), 1);
        drop(spool);
        let spool = TrafficUsageSpool::open(&database).unwrap();
        let store = TrafficControlStore::Sqlite(Mutex::new(
            TrafficControlCatalog::open_with_database(&database).unwrap(),
        ));
        // 模拟已上传但在本机ack前中断；worker再次上传不能重复增加日账。
        store.enqueue_usage_event(&event, 100).await.unwrap();
        spool.pump(&store).await.unwrap();
        assert_eq!(spool.pending_count().unwrap(), 0);
        let bytes: i64 = database
            .with_connection(|connection| {
                Ok(connection.query_row(
                    "SELECT bytes FROM traffic_daily_usage WHERE kind='http' AND policy_id=?1",
                    [event.policy_id.to_string()],
                    |row| row.get(0),
                )?)
            })
            .unwrap();
        assert_eq!(bytes, 2048);
    }

    #[tokio::test]
    async fn rejected_upload_is_retained_and_drain_deadline_does_not_discard_it() {
        let database = Database::memory().unwrap();
        let event = TrafficUsageEvent {
            event_id: Uuid::new_v4(),
            kind: TrafficPolicyKind::Tcp,
            policy_id: Uuid::new_v4(),
            bytes: 2048,
        };
        let spool = TrafficUsageSpool::open(&database).unwrap();
        spool.enqueue(&event).unwrap();
        let store = TrafficControlStore::Sqlite(Mutex::new(
            TrafficControlCatalog::open_with_database(&database).unwrap(),
        ));
        let conflict = TrafficUsageEvent {
            bytes: 4096,
            ..event.clone()
        };
        store.enqueue_usage_event(&conflict, 100).await.unwrap();
        assert!(spool.pump(&store).await.is_err());
        assert!(spool.drain(&store, Instant::now()).await.is_err());
        assert_eq!(spool.pending_count().unwrap(), 1);
        assert!(spool.enqueue(&conflict).is_err());
        assert!(spool.ensure_healthy().is_err());
    }
}
