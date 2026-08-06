//! HTTP/1.1 后端连接池运行时。
//!
//! 池只接收已经完成单次消息边界判定的连接。调用方必须在响应使用 EOF
//! 定界、出现协议错误或升级连接时丢弃租约，避免把残留字节交给下一位请求者。

use crate::http_backend_pool::{
    BackendConnectionId, BackendConnectionMode, BackendPoolLimits, BackendPoolState,
    BackendRegisterError, BackendRemoval, BackendRemovalReason, OriginKey,
};
use linklake_core::BoxedIo;
use std::{
    collections::HashMap,
    error::Error,
    fmt,
    future::Future,
    hash::{DefaultHasher, Hash, Hasher},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::Instant,
};
use tokio::sync::Mutex;

#[derive(Default)]
pub(crate) struct Http1BackendCounters {
    pub(crate) active_connections: AtomicUsize,
    pub(crate) active_requests: AtomicUsize,
    pub(crate) connections_total: AtomicU64,
    pub(crate) reused_total: AtomicU64,
    pub(crate) discarded_total: AtomicU64,
    pub(crate) idle_timeouts_total: AtomicU64,
    pub(crate) failures_total: AtomicU64,
    pub(crate) pool_exhausted_total: AtomicU64,
}

#[derive(Debug)]
pub(crate) enum Http1BackendAcquireError<E> {
    Connect(E),
    CapacityBusy,
}

impl<E: fmt::Display> fmt::Display for Http1BackendAcquireError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect(error) => write!(formatter, "HTTP/1 backend connection failed: {error}"),
            Self::CapacityBusy => formatter.write_str("HTTP/1 backend pool is busy"),
        }
    }
}

impl<E: Error + 'static> Error for Http1BackendAcquireError<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Connect(error) => Some(error),
            Self::CapacityBusy => None,
        }
    }
}

struct RuntimeState {
    pool: BackendPoolState,
    idle: HashMap<BackendConnectionId, BoxedIo>,
}

/// 每个正向代理策略持有一个池；池键包含策略、目标、协议和 TLS 身份。
pub(crate) struct Http1BackendPool {
    runtime: Mutex<RuntimeState>,
    connect_gates: Box<[Mutex<()>]>,
    counters: Arc<Http1BackendCounters>,
}

const CONNECT_GATE_SHARDS: usize = 64;

impl Http1BackendPool {
    pub(crate) fn new(limits: BackendPoolLimits, counters: Arc<Http1BackendCounters>) -> Arc<Self> {
        Arc::new(Self {
            runtime: Mutex::new(RuntimeState {
                pool: BackendPoolState::new(limits),
                idle: HashMap::new(),
            }),
            connect_gates: (0..CONNECT_GATE_SHARDS)
                .map(|_| Mutex::new(()))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            counters,
        })
    }

    pub(crate) async fn acquire_or_connect<F, Fut, E>(
        self: &Arc<Self>,
        origin: OriginKey,
        connect: F,
    ) -> Result<Http1BackendLease, Http1BackendAcquireError<E>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<BoxedIo, E>>,
    {
        if let Some(lease) = self.acquire_existing(&origin, true).await {
            return Ok(lease);
        }

        // 串行化建连可避免同一波突发在观察到空池后同时越过每源上限。
        let _gate = self.connect_gate(&origin).lock().await;
        if let Some(lease) = self.acquire_existing(&origin, true).await {
            return Ok(lease);
        }

        let stream = connect().await.map_err(|error| {
            self.counters.failures_total.fetch_add(1, Ordering::Relaxed);
            Http1BackendAcquireError::Connect(error)
        })?;
        let now = Instant::now();
        let mut runtime = self.runtime.lock().await;
        self.prune_locked(&mut runtime, now);
        let registration =
            match runtime
                .pool
                .register(origin.clone(), BackendConnectionMode::Exclusive, now)
            {
                Ok(registration) => registration,
                Err(BackendRegisterError::CapacityBusy) => {
                    self.counters
                        .pool_exhausted_total
                        .fetch_add(1, Ordering::Relaxed);
                    return Err(Http1BackendAcquireError::CapacityBusy);
                }
            };
        self.apply_removals_locked(&mut runtime, registration.removals);
        let Some(metadata) = runtime.pool.acquire(&origin, now) else {
            self.counters
                .pool_exhausted_total
                .fetch_add(1, Ordering::Relaxed);
            let removal = runtime
                .pool
                .disconnected(registration.connection_id)
                .into_iter()
                .collect();
            self.apply_removals_locked(&mut runtime, removal);
            return Err(Http1BackendAcquireError::CapacityBusy);
        };
        debug_assert_eq!(metadata.connection_id, registration.connection_id);
        self.counters
            .active_connections
            .fetch_add(1, Ordering::Relaxed);
        self.counters
            .connections_total
            .fetch_add(1, Ordering::Relaxed);
        self.counters
            .active_requests
            .fetch_add(1, Ordering::Relaxed);
        Ok(Http1BackendLease {
            pool: self.clone(),
            connection_id: metadata.connection_id,
            stream: Some(stream),
            finished: false,
        })
    }

    fn connect_gate(&self, origin: &OriginKey) -> &Mutex<()> {
        let mut hasher = DefaultHasher::new();
        origin.hash(&mut hasher);
        let index = (hasher.finish() as usize) % self.connect_gates.len();
        &self.connect_gates[index]
    }

    pub(crate) async fn invalidate_policy(&self, policy_id: uuid::Uuid) {
        let mut runtime = self.runtime.lock().await;
        let removals = runtime.pool.invalidate_policy(policy_id);
        self.apply_removals_locked(&mut runtime, removals);
    }

    async fn acquire_existing(
        self: &Arc<Self>,
        origin: &OriginKey,
        count_reuse: bool,
    ) -> Option<Http1BackendLease> {
        let now = Instant::now();
        let mut runtime = self.runtime.lock().await;
        self.prune_locked(&mut runtime, now);
        loop {
            let metadata = runtime.pool.acquire(origin, now)?;
            let Some(stream) = runtime.idle.remove(&metadata.connection_id) else {
                let removal = runtime.pool.disconnected(metadata.connection_id);
                if let Some(removal) = removal {
                    self.apply_removal_locked(&mut runtime, removal);
                }
                continue;
            };
            if count_reuse {
                self.counters.reused_total.fetch_add(1, Ordering::Relaxed);
            }
            self.counters
                .active_requests
                .fetch_add(1, Ordering::Relaxed);
            return Some(Http1BackendLease {
                pool: self.clone(),
                connection_id: metadata.connection_id,
                stream: Some(stream),
                finished: false,
            });
        }
    }

    fn prune_locked(&self, runtime: &mut RuntimeState, now: Instant) {
        let removals = runtime.pool.prune_idle(now);
        self.apply_removals_locked(runtime, removals);
    }

    fn apply_removals_locked(&self, runtime: &mut RuntimeState, removals: Vec<BackendRemoval>) {
        for removal in removals {
            self.apply_removal_locked(runtime, removal);
        }
    }

    fn apply_removal_locked(&self, runtime: &mut RuntimeState, removal: BackendRemoval) {
        runtime.idle.remove(&removal.connection_id);
        self.counters
            .active_connections
            .fetch_sub(1, Ordering::Relaxed);
        match removal.reason {
            BackendRemovalReason::IdleTimeout => {
                self.counters
                    .idle_timeouts_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            BackendRemovalReason::Disconnected => {
                self.counters
                    .discarded_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    async fn finish(&self, connection_id: BackendConnectionId, stream: BoxedIo, reusable: bool) {
        self.counters
            .active_requests
            .fetch_sub(1, Ordering::Relaxed);
        let mut runtime = self.runtime.lock().await;
        if reusable {
            if let Some(removal) = runtime.pool.release(connection_id, Instant::now()) {
                self.apply_removal_locked(&mut runtime, removal);
            } else if runtime.pool.contains(connection_id) {
                runtime.idle.insert(connection_id, stream);
            }
        } else if let Some(removal) = runtime.pool.disconnected(connection_id) {
            self.apply_removal_locked(&mut runtime, removal);
        }
    }
}

pub(crate) struct Http1BackendLease {
    pool: Arc<Http1BackendPool>,
    connection_id: BackendConnectionId,
    stream: Option<BoxedIo>,
    finished: bool,
}

impl Http1BackendLease {
    pub(crate) fn stream_mut(&mut self) -> &mut BoxedIo {
        self.stream
            .as_mut()
            .expect("unfinished HTTP/1 backend lease owns its stream")
    }

    pub(crate) fn connection_id(&self) -> u64 {
        self.connection_id.get()
    }

    pub(crate) async fn recycle(mut self) {
        self.finish(true).await;
    }

    pub(crate) async fn discard(mut self) {
        self.finish(false).await;
    }

    async fn finish(&mut self, reusable: bool) {
        if self.finished {
            return;
        }
        self.finished = true;
        let stream = self
            .stream
            .take()
            .expect("unfinished HTTP/1 backend lease owns its stream");
        self.pool.finish(self.connection_id, stream, reusable).await;
    }
}

impl Drop for Http1BackendLease {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
        let Some(stream) = self.stream.take() else {
            return;
        };
        let pool = self.pool.clone();
        let connection_id = self.connection_id;
        // 异常路径不能把未知边界的连接放回池；后台任务只负责同步状态并关闭连接。
        tokio::spawn(async move {
            pool.finish(connection_id, stream, false).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_backend_pool::{BackendProtocol, BackendSecurity};
    use std::{num::NonZeroUsize, time::Duration};
    use tokio::io::duplex;
    use uuid::Uuid;

    fn origin(port: u16) -> OriginKey {
        OriginKey::new(
            Uuid::from_u128(1),
            &format!("example.test:{port}"),
            BackendProtocol::Http1,
            BackendSecurity::Plaintext,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn recycles_only_explicitly_completed_connections() {
        let limits = BackendPoolLimits::new(
            NonZeroUsize::new(2).unwrap(),
            NonZeroUsize::new(2).unwrap(),
            Duration::from_secs(30),
        )
        .unwrap();
        let counters = Arc::new(Http1BackendCounters::default());
        let pool = Http1BackendPool::new(limits, counters.clone());
        let lease = pool
            .acquire_or_connect(origin(80), || async {
                let (client, _server) = duplex(1024);
                Ok::<BoxedIo, std::io::Error>(Box::new(client))
            })
            .await
            .unwrap();
        lease.recycle().await;
        let reused = pool
            .acquire_or_connect(origin(80), || async {
                panic!("an idle connection should be reused");
                #[allow(unreachable_code)]
                Ok::<BoxedIo, std::io::Error>(Box::new(duplex(1).0))
            })
            .await
            .unwrap();
        assert_eq!(counters.reused_total.load(Ordering::Relaxed), 1);
        reused.discard().await;
        assert_eq!(counters.active_connections.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn policy_invalidation_prevents_late_lease_from_reentering_idle_pool() {
        let limits = BackendPoolLimits::new(
            NonZeroUsize::new(2).unwrap(),
            NonZeroUsize::new(2).unwrap(),
            Duration::from_secs(30),
        )
        .unwrap();
        let counters = Arc::new(Http1BackendCounters::default());
        let pool = Http1BackendPool::new(limits, counters);
        let lease = pool
            .acquire_or_connect(origin(80), || async {
                let (client, _server) = duplex(1024);
                Ok::<BoxedIo, std::io::Error>(Box::new(client))
            })
            .await
            .unwrap();
        pool.invalidate_policy(Uuid::from_u128(1)).await;
        lease.recycle().await;

        let runtime = pool.runtime.lock().await;
        assert!(runtime.idle.is_empty());
        assert_eq!(runtime.pool.snapshot().connections, 0);
    }
}
