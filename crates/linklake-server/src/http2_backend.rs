//! HTTP/2 后端连接的真实运行时。
//!
//! `http_backend_pool` 只维护可确定性测试的生命周期元数据；本模块把该状态机
//! 与 Hyper HTTP/2 sender、LinkLake 数据流和 GOAWAY/断线恢复连接起来。

use crate::http_backend_pool::{
    BackendConnectionId, BackendConnectionMode, BackendPoolLimits, BackendPoolState,
    BackendRegisterError, BackendRemoval, BackendRemovalReason, OriginKey,
};
use bytes::Bytes;
use http_body_util::combinators::UnsyncBoxBody;
use hyper::{
    body::Incoming,
    client::conn::http2::{self as client_http2, SendRequest},
    Request, Response,
};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use linklake_core::BoxedIo;
use std::{
    collections::HashMap,
    error::Error,
    fmt,
    future::Future,
    num::NonZeroUsize,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex, Weak,
    },
    time::{Duration, Instant},
};
use tokio::sync::{watch, Mutex as AsyncMutex};
use tokio::time::timeout;

pub(crate) type BoxError = Box<dyn Error + Send + Sync>;
pub(crate) type ProxyBody = UnsyncBoxBody<Bytes, BoxError>;

const HTTP2_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const HTTP2_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(20);
const HTTP2_KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(10);
const HTTP2_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const HTTP2_MAX_CONNECTIONS_PER_ROUTE: usize = 16;
const HTTP2_MAX_HEADER_LIST_BYTES: u32 = 64 * 1024;
const HTTP2_MAX_SEND_BUFFER_BYTES: usize = 1024 * 1024;

#[derive(Default)]
pub(crate) struct Http2BackendCounters {
    pub(crate) active_connections: AtomicUsize,
    pub(crate) active_streams: AtomicUsize,
    pub(crate) connections_total: AtomicU64,
    pub(crate) reused_total: AtomicU64,
    pub(crate) reconnects_total: AtomicU64,
    pub(crate) goaway_total: AtomicU64,
    pub(crate) failures_total: AtomicU64,
    pub(crate) pool_exhausted_total: AtomicU64,
}

#[derive(Debug)]
pub(crate) enum Http2BackendAcquireError {
    Connect(BoxError),
    Handshake(hyper::Error),
    HandshakeTimeout,
    CapacityBusy,
}

impl fmt::Display for Http2BackendAcquireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect(error) => write!(formatter, "HTTP/2 backend connection failed: {error}"),
            Self::Handshake(error) => write!(formatter, "HTTP/2 backend handshake failed: {error}"),
            Self::HandshakeTimeout => formatter.write_str("HTTP/2 backend handshake timed out"),
            Self::CapacityBusy => formatter.write_str("HTTP/2 backend pool is busy"),
        }
    }
}

impl Error for Http2BackendAcquireError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Connect(error) => Some(error.as_ref()),
            Self::Handshake(error) => Some(error),
            Self::HandshakeTimeout | Self::CapacityBusy => None,
        }
    }
}

struct RuntimeConnection {
    sender: SendRequest<ProxyBody>,
    stop_tx: watch::Sender<bool>,
    draining_observed: AtomicBool,
    goaway_observed: AtomicBool,
    failure_observed: AtomicBool,
}

pub(crate) struct Http2BackendPool {
    origin: OriginKey,
    stream_capacity: NonZeroUsize,
    state: Mutex<BackendPoolState>,
    connections: Mutex<HashMap<BackendConnectionId, Arc<RuntimeConnection>>>,
    connect_gate: AsyncMutex<()>,
    counters: Arc<Http2BackendCounters>,
    recovery_pending: AtomicBool,
}

impl Http2BackendPool {
    pub(crate) fn new(
        origin: OriginKey,
        route_stream_limit: usize,
        counters: Arc<Http2BackendCounters>,
    ) -> Arc<Self> {
        let stream_capacity = NonZeroUsize::new(route_stream_limit.clamp(1, 100))
            .expect("clamped HTTP/2 stream capacity is non-zero");
        let required_connections = route_stream_limit.div_ceil(stream_capacity.get());
        let connection_limit = NonZeroUsize::new(
            required_connections
                .saturating_add(1)
                .clamp(2, HTTP2_MAX_CONNECTIONS_PER_ROUTE),
        )
        .expect("clamped HTTP/2 connection limit is non-zero");
        let limits = BackendPoolLimits::new(connection_limit, connection_limit, HTTP2_IDLE_TIMEOUT)
            .expect("static HTTP/2 pool limits are valid");
        Arc::new(Self {
            origin,
            stream_capacity,
            state: Mutex::new(BackendPoolState::new(limits)),
            connections: Mutex::new(HashMap::new()),
            connect_gate: AsyncMutex::new(()),
            counters,
            recovery_pending: AtomicBool::new(false),
        })
    }

    pub(crate) async fn acquire_or_connect<F, Fut>(
        self: &Arc<Self>,
        connect: F,
    ) -> Result<Http2BackendLease, Http2BackendAcquireError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<BoxedIo, BoxError>>,
    {
        self.prune_idle();
        if let Some(lease) = self.acquire_existing(true) {
            return Ok(lease);
        }

        let _connect_guard = self.connect_gate.lock().await;
        self.prune_idle();
        if let Some(lease) = self.acquire_existing(true) {
            return Ok(lease);
        }

        let io = connect().await.map_err(|error| {
            self.counters.failures_total.fetch_add(1, Ordering::Relaxed);
            Http2BackendAcquireError::Connect(error)
        })?;
        let mut builder = client_http2::Builder::new(TokioExecutor::new());
        builder
            .timer(TokioTimer::new())
            .adaptive_window(true)
            .initial_max_send_streams(self.stream_capacity.get())
            .keep_alive_interval(Some(HTTP2_KEEP_ALIVE_INTERVAL))
            .keep_alive_timeout(HTTP2_KEEP_ALIVE_TIMEOUT)
            .keep_alive_while_idle(true)
            .max_header_list_size(HTTP2_MAX_HEADER_LIST_BYTES)
            .max_send_buf_size(HTTP2_MAX_SEND_BUFFER_BYTES);
        let (sender, connection) =
            match timeout(HTTP2_HANDSHAKE_TIMEOUT, builder.handshake(TokioIo::new(io))).await {
                Ok(Ok(value)) => value,
                Ok(Err(error)) => {
                    self.counters.failures_total.fetch_add(1, Ordering::Relaxed);
                    return Err(Http2BackendAcquireError::Handshake(error));
                }
                Err(_) => {
                    self.counters.failures_total.fetch_add(1, Ordering::Relaxed);
                    return Err(Http2BackendAcquireError::HandshakeTimeout);
                }
            };

        let registration = {
            self.state
                .lock()
                .expect("HTTP/2 backend pool lock poisoned")
                .register(
                    self.origin.clone(),
                    BackendConnectionMode::Multiplexed {
                        max_concurrent_streams: self.stream_capacity,
                    },
                    Instant::now(),
                )
        };
        let registration = match registration {
            Ok(registration) => registration,
            Err(BackendRegisterError::CapacityBusy) => {
                self.counters
                    .pool_exhausted_total
                    .fetch_add(1, Ordering::Relaxed);
                return Err(Http2BackendAcquireError::CapacityBusy);
            }
        };
        self.apply_removals(registration.removals);

        let (stop_tx, mut stop_rx) = watch::channel(false);
        let connection_id = registration.connection_id;
        self.connections
            .lock()
            .expect("HTTP/2 runtime connection lock poisoned")
            .insert(
                connection_id,
                Arc::new(RuntimeConnection {
                    sender,
                    stop_tx,
                    draining_observed: AtomicBool::new(false),
                    goaway_observed: AtomicBool::new(false),
                    failure_observed: AtomicBool::new(false),
                }),
            );
        self.counters
            .active_connections
            .fetch_add(1, Ordering::Relaxed);
        self.counters
            .connections_total
            .fetch_add(1, Ordering::Relaxed);
        if self.recovery_pending.swap(false, Ordering::Relaxed) {
            self.counters
                .reconnects_total
                .fetch_add(1, Ordering::Relaxed);
        }

        let weak_pool = Arc::downgrade(self);
        tokio::spawn(async move {
            tokio::pin!(connection);
            let result = tokio::select! {
                _ = stop_rx.changed() => return,
                result = &mut connection => result,
            };
            if let Some(pool) = Weak::upgrade(&weak_pool) {
                pool.connection_finished(connection_id, result);
            }
        });

        self.acquire_existing(false)
            .ok_or(Http2BackendAcquireError::CapacityBusy)
    }

    pub(crate) fn invalidate(&self) {
        let removals = self
            .state
            .lock()
            .expect("HTTP/2 backend pool lock poisoned")
            .invalidate_policy(self.origin.policy_id());
        self.apply_removals(removals);
    }

    fn acquire_existing(self: &Arc<Self>, count_reuse: bool) -> Option<Http2BackendLease> {
        loop {
            let lease = self
                .state
                .lock()
                .expect("HTTP/2 backend pool lock poisoned")
                .acquire(&self.origin, Instant::now())?;
            let runtime = self
                .connections
                .lock()
                .expect("HTTP/2 runtime connection lock poisoned")
                .get(&lease.connection_id)
                .cloned();
            let Some(runtime) = runtime else {
                self.disconnect(lease.connection_id);
                continue;
            };
            if runtime.sender.is_closed() {
                self.mark_draining(lease.connection_id, &runtime);
                self.release(lease.connection_id);
                continue;
            }
            if count_reuse {
                self.counters.reused_total.fetch_add(1, Ordering::Relaxed);
            }
            self.counters.active_streams.fetch_add(1, Ordering::Relaxed);
            return Some(Http2BackendLease {
                pool: self.clone(),
                connection_id: lease.connection_id,
                sender: runtime.sender.clone(),
                released: false,
            });
        }
    }

    fn observe_goaway(&self, connection_id: BackendConnectionId, runtime: &RuntimeConnection) {
        if !runtime.goaway_observed.swap(true, Ordering::Relaxed) {
            self.counters.goaway_total.fetch_add(1, Ordering::Relaxed);
        }
        self.mark_draining(connection_id, runtime);
    }

    fn mark_draining(&self, connection_id: BackendConnectionId, runtime: &RuntimeConnection) {
        if !runtime.draining_observed.swap(true, Ordering::Relaxed) {
            self.recovery_pending.store(true, Ordering::Relaxed);
        }
        let removal = self
            .state
            .lock()
            .expect("HTTP/2 backend pool lock poisoned")
            .mark_goaway(connection_id);
        if let Some(removal) = removal {
            self.apply_removal(removal);
        }
    }

    fn release(&self, connection_id: BackendConnectionId) {
        self.counters.active_streams.fetch_sub(1, Ordering::Relaxed);
        let removal = self
            .state
            .lock()
            .expect("HTTP/2 backend pool lock poisoned")
            .release(connection_id, Instant::now());
        if let Some(removal) = removal {
            self.apply_removal(removal);
        }
    }

    fn prune_idle(&self) {
        let removals = self
            .state
            .lock()
            .expect("HTTP/2 backend pool lock poisoned")
            .prune_idle(Instant::now());
        self.apply_removals(removals);
    }

    fn disconnect(&self, connection_id: BackendConnectionId) {
        let removal = self
            .state
            .lock()
            .expect("HTTP/2 backend pool lock poisoned")
            .disconnected(connection_id);
        if let Some(removal) = removal {
            self.apply_removal(removal);
        }
    }

    fn connection_finished(
        &self,
        connection_id: BackendConnectionId,
        result: Result<(), hyper::Error>,
    ) {
        if result.is_ok() {
            if let Some(runtime) = self
                .connections
                .lock()
                .expect("HTTP/2 runtime connection lock poisoned")
                .get(&connection_id)
                .cloned()
            {
                self.observe_goaway(connection_id, &runtime);
            }
        } else {
            self.recovery_pending.store(true, Ordering::Relaxed);
            if let Some(runtime) = self
                .connections
                .lock()
                .expect("HTTP/2 runtime connection lock poisoned")
                .get(&connection_id)
                .cloned()
            {
                self.record_failure(&runtime);
            } else {
                self.counters.failures_total.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.disconnect(connection_id);
    }

    fn record_failure(&self, runtime: &RuntimeConnection) {
        if !runtime.failure_observed.swap(true, Ordering::Relaxed) {
            self.counters.failures_total.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn apply_removals(&self, removals: Vec<BackendRemoval>) {
        for removal in removals {
            self.apply_removal(removal);
        }
    }

    fn apply_removal(&self, removal: BackendRemoval) {
        if let Some(runtime) = self
            .connections
            .lock()
            .expect("HTTP/2 runtime connection lock poisoned")
            .remove(&removal.connection_id)
        {
            let _ = runtime.stop_tx.send(true);
            self.counters
                .active_connections
                .fetch_sub(1, Ordering::Relaxed);
        }
        if removal.reason == BackendRemovalReason::GoAway {
            tracing::debug!(
                connection_id = removal.connection_id.get(),
                "HTTP/2 backend connection drained after GOAWAY"
            );
        }
    }
}

pub(crate) struct Http2BackendLease {
    pool: Arc<Http2BackendPool>,
    connection_id: BackendConnectionId,
    sender: SendRequest<ProxyBody>,
    released: bool,
}

impl Http2BackendLease {
    pub(crate) async fn send_request(
        &mut self,
        request: Request<ProxyBody>,
    ) -> Result<Response<Incoming>, hyper::Error> {
        let result = match self.sender.ready().await {
            Ok(()) => self.sender.send_request(request).await,
            Err(error) => Err(error),
        };
        if result.is_err() {
            if let Some(runtime) = self
                .pool
                .connections
                .lock()
                .expect("HTTP/2 runtime connection lock poisoned")
                .get(&self.connection_id)
                .cloned()
            {
                self.pool.record_failure(&runtime);
                if runtime.sender.is_closed() {
                    self.pool.mark_draining(self.connection_id, &runtime);
                }
            }
        }
        result
    }

    pub(crate) fn connection_id(&self) -> u64 {
        self.connection_id.get()
    }
}

impl Drop for Http2BackendLease {
    fn drop(&mut self) {
        if !self.released {
            self.released = true;
            self.pool.release(self.connection_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_backend_pool::{BackendProtocol, BackendSecurity};
    use http_body_util::{BodyExt, Channel, Full};
    use hyper::{
        header::{self, HeaderMap, HeaderValue},
        server::conn::http2 as server_http2,
        service::service_fn,
        StatusCode,
    };
    use std::{convert::Infallible, sync::Mutex as StdMutex};
    use tokio::{
        io::duplex,
        sync::oneshot,
        time::{sleep, timeout},
    };
    use uuid::Uuid;

    fn origin() -> OriginKey {
        OriginKey::new(
            Uuid::from_u128(1),
            "grpc.example.test:80",
            BackendProtocol::Http2,
            BackendSecurity::Plaintext,
        )
        .expect("test origin should be valid")
    }

    fn full_body(value: &'static str) -> ProxyBody {
        Full::new(Bytes::from_static(value.as_bytes()))
            .map_err(|never| -> BoxError { match never {} })
            .boxed_unsync()
    }

    fn request(body: ProxyBody) -> Request<ProxyBody> {
        Request::builder()
            .method("POST")
            .uri("http://grpc.example.test/echo.Stream/Call")
            .version(hyper::Version::HTTP_2)
            .header(header::CONTENT_TYPE, "application/grpc")
            .header(header::TE, "trailers")
            .body(body)
            .expect("test request should build")
    }

    fn spawn_backend(connections: Arc<AtomicUsize>, graceful_after_first: bool) -> BoxedIo {
        let (client, server) = duplex(256 * 1024);
        connections.fetch_add(1, Ordering::Relaxed);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let shutdown_tx = Arc::new(StdMutex::new(Some(shutdown_tx)));
        let service = service_fn(move |request: Request<Incoming>| {
            let shutdown_tx = shutdown_tx.clone();
            async move {
                let mut request_body = request.into_body();
                let (mut response_tx, response_body) = Channel::<Bytes, Infallible>::new(8);
                tokio::spawn(async move {
                    while let Some(frame) = request_body.frame().await {
                        let Ok(frame) = frame else {
                            return;
                        };
                        if let Some(data) = frame.data_ref().filter(|data| !data.is_empty()) {
                            let mut echoed = Vec::with_capacity(5 + data.len());
                            echoed.extend_from_slice(b"echo:");
                            echoed.extend_from_slice(data);
                            if response_tx.send_data(Bytes::from(echoed)).await.is_err() {
                                return;
                            }
                        }
                    }
                    let mut trailers = HeaderMap::new();
                    trailers.insert("grpc-status", HeaderValue::from_static("0"));
                    trailers.insert("grpc-message", HeaderValue::from_static("ok"));
                    let _ = response_tx.send_trailers(trailers).await;
                });
                if graceful_after_first {
                    if let Some(shutdown_tx) = shutdown_tx
                        .lock()
                        .expect("test shutdown lock poisoned")
                        .take()
                    {
                        let _ = shutdown_tx.send(());
                    }
                }
                Ok::<_, Infallible>(
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "application/grpc")
                        .body(response_body)
                        .expect("test response should build"),
                )
            }
        });
        tokio::spawn(async move {
            let connection = server_http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(server), service);
            tokio::pin!(connection);
            if graceful_after_first {
                tokio::select! {
                    _ = &mut connection => {}
                    _ = shutdown_rx => {
                        connection.as_mut().graceful_shutdown();
                        let _ = connection.await;
                    }
                }
            } else {
                let _ = connection.await;
            }
        });
        Box::new(client)
    }

    async fn wait_for_counter(counter: &AtomicU64, minimum: u64) {
        timeout(Duration::from_secs(5), async {
            while counter.load(Ordering::Relaxed) < minimum {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("counter should reach expected value");
    }

    #[tokio::test]
    async fn multiplexes_bidirectional_streams_and_preserves_trailers() {
        let counters = Arc::new(Http2BackendCounters::default());
        let connections = Arc::new(AtomicUsize::new(0));
        let pool = Http2BackendPool::new(origin(), 8, counters.clone());

        let first_connections = connections.clone();
        let mut first = pool
            .acquire_or_connect(move || async move { Ok(spawn_backend(first_connections, false)) })
            .await
            .expect("first HTTP/2 stream should connect");
        let first_connection_id = first.connection_id();
        let (mut request_tx, request_body) = Channel::<Bytes, Infallible>::new(4);
        let request_body = request_body
            .map_err(|never| -> BoxError { match never {} })
            .boxed_unsync();
        let mut first_response = first
            .send_request(request(request_body))
            .await
            .expect("streaming request should receive response headers");

        request_tx
            .send_data(Bytes::from_static(b"one"))
            .await
            .expect("first request message should send");
        let first_frame = timeout(Duration::from_secs(2), first_response.body_mut().frame())
            .await
            .expect("first response frame should arrive")
            .expect("first response frame should exist")
            .expect("first response frame should be valid");
        assert_eq!(
            first_frame.data_ref(),
            Some(&Bytes::from_static(b"echo:one"))
        );

        let second_connections = connections.clone();
        let mut second = pool
            .acquire_or_connect(move || async move { Ok(spawn_backend(second_connections, false)) })
            .await
            .expect("second HTTP/2 stream should reuse the connection");
        assert_eq!(second.connection_id(), first_connection_id);
        let second_response = second
            .send_request(request(full_body("two")))
            .await
            .expect("second request should succeed");
        let second_collected = second_response
            .into_body()
            .collect()
            .await
            .expect("second response should collect");
        let second_status = second_collected
            .trailers()
            .and_then(|trailers| trailers.get("grpc-status"))
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        assert_eq!(second_collected.to_bytes(), Bytes::from_static(b"echo:two"));
        assert_eq!(second_status.as_deref(), Some("0"));

        request_tx
            .send_data(Bytes::from_static(b"three"))
            .await
            .expect("second streaming message should send");
        drop(request_tx);
        let remaining = first_response
            .into_body()
            .collect()
            .await
            .expect("streaming response should collect");
        let remaining_status = remaining
            .trailers()
            .and_then(|trailers| trailers.get("grpc-status"))
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        assert_eq!(remaining.to_bytes(), Bytes::from_static(b"echo:three"));
        assert_eq!(remaining_status.as_deref(), Some("0"));

        assert_eq!(connections.load(Ordering::Relaxed), 1);
        assert_eq!(counters.connections_total.load(Ordering::Relaxed), 1);
        assert_eq!(counters.reused_total.load(Ordering::Relaxed), 1);
        assert_eq!(counters.active_streams.load(Ordering::Relaxed), 2);
        drop(first);
        drop(second);
        assert_eq!(counters.active_streams.load(Ordering::Relaxed), 0);
        pool.invalidate();
        assert_eq!(counters.active_connections.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn graceful_goaway_drains_and_next_request_recovers() {
        let counters = Arc::new(Http2BackendCounters::default());
        let connections = Arc::new(AtomicUsize::new(0));
        let pool = Http2BackendPool::new(origin(), 4, counters.clone());

        let first_connections = connections.clone();
        let mut first = pool
            .acquire_or_connect(move || async move { Ok(spawn_backend(first_connections, true)) })
            .await
            .expect("first connection should open");
        let first_id = first.connection_id();
        let first_response = first
            .send_request(request(full_body("before-goaway")))
            .await
            .expect("request before GOAWAY should succeed");
        let first_collected = first_response
            .into_body()
            .collect()
            .await
            .expect("response before GOAWAY should finish");
        assert_eq!(
            first_collected.to_bytes(),
            Bytes::from_static(b"echo:before-goaway")
        );
        drop(first);
        wait_for_counter(&counters.goaway_total, 1).await;

        let second_connections = connections.clone();
        let mut second = pool
            .acquire_or_connect(move || async move { Ok(spawn_backend(second_connections, false)) })
            .await
            .expect("request after GOAWAY should reconnect");
        assert_ne!(second.connection_id(), first_id);
        let second_response = second
            .send_request(request(full_body("after-goaway")))
            .await
            .expect("request after GOAWAY should succeed");
        assert_eq!(
            second_response
                .into_body()
                .collect()
                .await
                .expect("recovered response should collect")
                .to_bytes(),
            Bytes::from_static(b"echo:after-goaway")
        );
        assert_eq!(connections.load(Ordering::Relaxed), 2);
        assert_eq!(counters.connections_total.load(Ordering::Relaxed), 2);
        assert_eq!(counters.reconnects_total.load(Ordering::Relaxed), 1);
        drop(second);
        pool.invalidate();
    }
}
