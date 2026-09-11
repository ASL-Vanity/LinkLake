#[path = "http1_backend.rs"]
mod http1_backend;

use crate::traffic_control::{TrafficDecision, TrafficPolicyKind};
use crate::{
    client_registry::Authentication,
    http_backend_pool::{BackendPoolLimits, BackendProtocol, BackendSecurity, OriginKey},
    public_port_lease::HaPublicPortLease,
    public_port_ownership::PublicPortProtocol,
    record_audit,
    tcp_tunnel::BandwidthLimiter,
    tunnel_catalog::http_proxy_password_matches,
    AppState,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use http1_backend::{Http1BackendAcquireError, Http1BackendCounters, Http1BackendPool};
use linklake_core::{read_control_frame, write_control_frame, BoxedIo, ControlFrame};
use std::{
    collections::HashSet,
    net::{IpAddr, Ipv6Addr},
    num::NonZeroUsize,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{
        split, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
        ReadHalf, WriteHalf,
    },
    net::{TcpListener, TcpStream},
    sync::{mpsc, watch, OwnedSemaphorePermit, Semaphore},
    time::{timeout, Instant},
};
use uuid::Uuid;

const CONTROL_IDLE_TIMEOUT: Duration = Duration::from_secs(35);
const REQUEST_HEADER_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECTION_PAIR_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECTION_MAX_LIFETIME: Duration = Duration::from_secs(2 * 60 * 60);
const BACKEND_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const RESPONSE_HEADER_TIMEOUT: Duration = Duration::from_secs(15);
const EXCHANGE_IO_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_REQUESTS_PER_CONNECTION: usize = 1_000;
const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_HEADER_COUNT: usize = 200;

pub(crate) struct HttpProxyRegistration {
    registration_id: Uuid,
    public_port: u16,
    stop_tx: watch::Sender<()>,
    backend_pool: Arc<Http1BackendPool>,
}

#[derive(Default)]
pub(crate) struct HttpProxyStatistics {
    pub(crate) active_connections: AtomicUsize,
    pub(crate) connections_total: AtomicU64,
    pub(crate) requests_total: AtomicU64,
    pub(crate) connect_requests: AtomicU64,
    pub(crate) authentication_failures: AtomicU64,
    pub(crate) rejected_connections: AtomicU64,
    pub(crate) malformed_requests: AtomicU64,
    pub(crate) bytes_from_public: AtomicU64,
    pub(crate) bytes_to_public: AtomicU64,
    pub(crate) pairing_timeouts: AtomicU64,
    pub(crate) connect_failures: AtomicU64,
    pub(crate) transfer_errors: AtomicU64,
    pub(crate) lifetime_timeouts: AtomicU64,
    pub(crate) client_keep_alive_requests_total: AtomicU64,
    pub(crate) backend_reuse_ineligible_total: AtomicU64,
    pub(crate) http1_backend: Arc<Http1BackendCounters>,
}

#[derive(Clone)]
struct PublicConnectionContext {
    state: Arc<AppState>,
    policy_id: Uuid,
    client_id: Uuid,
    command_tx: mpsc::Sender<ControlFrame>,
    username: Arc<str>,
    password_hash: Arc<str>,
    permits: Arc<Semaphore>,
    statistics: Arc<HttpProxyStatistics>,
    bandwidth_limiter: Option<Arc<BandwidthLimiter>>,
    backend_pool: Arc<Http1BackendPool>,
}

#[derive(Debug, Eq, PartialEq)]
enum ProxyRequestKind {
    Forward {
        encoded_head: Vec<u8>,
        body: RequestBody,
        head_request: bool,
    },
    Connect,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RequestBody {
    None,
    ContentLength(u64),
    Chunked,
}

#[derive(Debug, Eq, PartialEq)]
struct ProxyRequest {
    target_host: String,
    target_port: u16,
    client_keep_alive: bool,
    kind: ProxyRequestKind,
}

#[derive(Debug, Eq, PartialEq)]
enum RequestError {
    Closed,
    Authentication,
    Malformed,
    HeaderTooLarge,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResponseBody {
    None,
    ContentLength(u64),
    Chunked,
    UntilEof,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HttpExchangeOutcome {
    bytes_from_public: u64,
    bytes_to_public: u64,
    backend_reusable: bool,
    client_reusable: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HttpResponseTransfer {
    bytes: u64,
    backend_reusable: bool,
    client_reusable: bool,
}

enum ExchangeCompletion {
    RequestFinishedFirst {
        bytes_from_public: u64,
        response: HttpResponseTransfer,
    },
    ResponseFinishedFirst(HttpResponseTransfer),
}

#[derive(Debug, Eq, PartialEq)]
struct ParsedResponseHead {
    status_line: String,
    http11: bool,
    status: u16,
    headers: Vec<(String, String)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PairTargetError {
    Busy,
    ControlClosed,
    Rejected,
    Timeout,
    Stopped,
}

pub(crate) async fn register_proxy(
    state: Arc<AppState>,
    mut stream: BoxedIo,
    client_id: Uuid,
    client_token: String,
    name: String,
    public_port: u16,
) {
    if !authenticated_client(&state, client_id, &client_token).await {
        reject(&state, &mut stream, "invalid client credentials").await;
        return;
    }
    let runtime_policy = state
        .tunnel_catalog
        .lock()
        .expect("tunnel catalog lock poisoned")
        .http_proxy_runtime_policy(client_id, &name, public_port)
        .unwrap_or(None);
    let Some(runtime_policy) = runtime_policy else {
        reject(
            &state,
            &mut stream,
            "no enabled management policy matches this HTTP proxy",
        )
        .await;
        return;
    };
    let port_lease = match HaPublicPortLease::acquire(
        &state.ha_runtime,
        PublicPortProtocol::Tcp,
        public_port,
        runtime_policy.policy_id,
    )
    .await
    {
        Ok(Some(lease)) => lease,
        Ok(None) => {
            reject(
                &state,
                &mut stream,
                "HTTP proxy port is owned by another HA instance",
            )
            .await;
            return;
        }
        Err(error) => {
            tracing::warn!(
                public_port,
                "Could not acquire HTTP proxy port ownership: {error}"
            );
            reject(
                &state,
                &mut stream,
                "HTTP proxy port ownership is unavailable",
            )
            .await;
            return;
        }
    };
    let listener = match TcpListener::bind(("0.0.0.0", public_port)).await {
        Ok(listener) => listener,
        Err(_) => {
            port_lease.release().await;
            reject(&state, &mut stream, "HTTP proxy public port is unavailable").await;
            return;
        }
    };
    let (command_tx, command_rx) = mpsc::channel(64);
    let (stop_tx, stop_rx) = watch::channel(());
    port_lease.spawn_supervisor(stop_rx.clone(), stop_tx.clone());
    let registration_id = Uuid::new_v4();
    let statistics = state
        .http_proxy_statistics
        .lock()
        .expect("HTTP proxy statistics lock poisoned")
        .entry(runtime_policy.policy_id)
        .or_insert_with(|| Arc::new(HttpProxyStatistics::default()))
        .clone();
    let maximum = NonZeroUsize::new(runtime_policy.max_connections.max(1))
        .expect("HTTP proxy connection limit is non-zero");
    let per_origin = NonZeroUsize::new(runtime_policy.max_connections.clamp(1, 8))
        .expect("HTTP proxy per-origin limit is non-zero");
    let pool_limits = BackendPoolLimits::new(maximum, per_origin, BACKEND_IDLE_TIMEOUT)
        .expect("validated HTTP proxy pool limits are valid");
    let backend_pool = Http1BackendPool::new(pool_limits, statistics.http1_backend.clone());
    let policy_id = runtime_policy.policy_id;
    let previous = state
        .http_proxies
        .lock()
        .expect("HTTP proxy registry lock poisoned")
        .insert(
            runtime_policy.policy_id,
            HttpProxyRegistration {
                registration_id,
                public_port,
                stop_tx: stop_tx.clone(),
                backend_pool: backend_pool.clone(),
            },
        );
    if let Some(previous) = previous {
        let _ = previous.stop_tx.send(());
        tokio::spawn(async move {
            previous.backend_pool.invalidate_policy(policy_id).await;
        });
    }
    state
        .metrics
        .tunnel_registrations_total
        .fetch_add(1, Ordering::Relaxed);
    record_audit(
        &state,
        "http_proxy.registered",
        &runtime_policy.policy_id.to_string(),
        &format!("client={client_id}; name={name}; public_port={public_port}"),
    );
    let context = PublicConnectionContext {
        state: state.clone(),
        policy_id: runtime_policy.policy_id,
        client_id,
        command_tx,
        username: runtime_policy.username.into(),
        password_hash: runtime_policy.password_hash.into(),
        permits: Arc::new(Semaphore::new(runtime_policy.max_connections)),
        statistics,
        bandwidth_limiter: runtime_policy
            .bandwidth_limit_bps
            .map(BandwidthLimiter::new)
            .map(Arc::new),
        backend_pool,
    };
    tokio::spawn(accept_public_connections(
        context,
        listener,
        stop_rx.clone(),
    ));
    let (reader, mut writer) = split(stream);
    if write_control_frame(
        &mut writer,
        &ControlFrame::HttpProxyRegistered {
            proxy_id: runtime_policy.policy_id,
            public_port,
            allow_private_networks: runtime_policy.allow_private_networks,
        },
    )
    .await
    .is_err()
    {
        remove_registration(&state, runtime_policy.policy_id, registration_id);
        return;
    }
    run_registered_control(
        state,
        runtime_policy.policy_id,
        registration_id,
        reader,
        writer,
        command_rx,
        stop_rx,
    )
    .await;
}

async fn run_registered_control(
    state: Arc<AppState>,
    policy_id: Uuid,
    registration_id: Uuid,
    mut reader: ReadHalf<BoxedIo>,
    mut writer: WriteHalf<BoxedIo>,
    mut commands: mpsc::Receiver<ControlFrame>,
    mut stop: watch::Receiver<()>,
) {
    let (frames_tx, mut frames_rx) = mpsc::channel(16);
    let reader_task = tokio::spawn(async move {
        while let Ok(frame) = read_control_frame(&mut reader).await {
            if frames_tx.send(frame).await.is_err() {
                break;
            }
        }
    });
    let idle_timeout = tokio::time::sleep(CONTROL_IDLE_TIMEOUT);
    tokio::pin!(idle_timeout);
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            _ = &mut idle_timeout => break,
            command = commands.recv() => match command {
                Some(command) if write_control_frame(&mut writer, &command).await.is_err() => break,
                Some(_) => {}
                None => break,
            },
            frame = frames_rx.recv() => match frame {
                Some(ControlFrame::ControlHeartbeat { nonce }) => {
                    idle_timeout.as_mut().reset(Instant::now() + CONTROL_IDLE_TIMEOUT);
                    if write_control_frame(&mut writer, &ControlFrame::ControlHeartbeatAck { nonce }).await.is_err() {
                        break;
                    }
                }
                Some(_) => {
                    state.metrics.control_protocol_errors_total.fetch_add(1, Ordering::Relaxed);
                    break;
                }
                None => break,
            }
        }
    }
    reader_task.abort();
    remove_registration(&state, policy_id, registration_id);
}

async fn accept_public_connections(
    context: PublicConnectionContext,
    listener: TcpListener,
    mut stop: watch::Receiver<()>,
) {
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, source)) => {
                    if !context.state.accepts_public_work() {
                        context.statistics.rejected_connections.fetch_add(1, Ordering::Relaxed);
                        drop(stream);
                        continue;
                    }
                    let decision = context.state.traffic_controls.lock().expect("traffic control catalog lock poisoned").authorize(TrafficPolicyKind::HttpProxy, context.policy_id, source.ip(), crate::unix_seconds());
                    if !matches!(decision, Ok(TrafficDecision::Allowed)) {
                        context.statistics.rejected_connections.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    let Ok(policy_permit) = context.permits.clone().try_acquire_owned() else {
                        context.statistics.rejected_connections.fetch_add(1, Ordering::Relaxed);
                        continue;
                    };
                    let Ok(global_permit) = context.state.global_connection_permits.clone().try_acquire_owned() else {
                        context.statistics.rejected_connections.fetch_add(1, Ordering::Relaxed);
                        continue;
                    };
                    let context = context.clone();
                    let connection_stop = stop.clone();
                    tokio::spawn(async move {
                        serve_public_connection(
                            context,
                            stream,
                            policy_permit,
                            global_permit,
                            connection_stop,
                        ).await;
                    });
                }
                Err(error) => tracing::warn!("HTTP proxy listener accept error: {error}"),
            }
        }
    }
}

async fn serve_public_connection(
    context: PublicConnectionContext,
    external: TcpStream,
    _policy_permit: OwnedSemaphorePermit,
    _global_permit: OwnedSemaphorePermit,
    mut stop: watch::Receiver<()>,
) {
    context
        .statistics
        .active_connections
        .fetch_add(1, Ordering::Relaxed);
    context
        .statistics
        .connections_total
        .fetch_add(1, Ordering::Relaxed);
    let mut external = BufReader::new(external);
    let lifetime_deadline = Instant::now() + CONNECTION_MAX_LIFETIME;
    let mut requests = 0_usize;
    loop {
        let request = tokio::select! {
            _ = stop.changed() => break,
            result = tokio::time::timeout_at(
                lifetime_deadline,
                timeout(
                    REQUEST_HEADER_TIMEOUT,
                    read_proxy_request(&mut external, &context.username, &context.password_hash),
                ),
            ) => match result {
                Ok(Ok(Ok(request))) => request,
                Ok(Ok(Err(RequestError::Closed))) => break,
                Ok(Ok(Err(RequestError::Authentication))) => {
                    context.statistics.authentication_failures.fetch_add(1, Ordering::Relaxed);
                    let _ = write_proxy_response(&mut external, 407).await;
                    break;
                }
                Ok(Ok(Err(RequestError::Malformed | RequestError::HeaderTooLarge)))
                | Ok(Err(_)) => {
                    context.statistics.malformed_requests.fetch_add(1, Ordering::Relaxed);
                    let _ = write_proxy_response(&mut external, 400).await;
                    break;
                }
                Err(_) => {
                    context.statistics.lifetime_timeouts.fetch_add(1, Ordering::Relaxed);
                    break;
                }
            },
        };
        requests = requests.saturating_add(1);
        context
            .statistics
            .requests_total
            .fetch_add(1, Ordering::Relaxed);
        if request.client_keep_alive {
            context
                .statistics
                .client_keep_alive_requests_total
                .fetch_add(1, Ordering::Relaxed);
        }

        match request.kind {
            ProxyRequestKind::Connect => {
                context
                    .statistics
                    .connect_requests
                    .fetch_add(1, Ordering::Relaxed);
                let mut agent_stream = match pair_target(
                    &context,
                    &request.target_host,
                    request.target_port,
                    &mut stop,
                )
                .await
                {
                    Ok(stream) => stream,
                    Err(error) => {
                        write_pair_error(&mut external, &context, error).await;
                        break;
                    }
                };
                if write_proxy_response(&mut external, 200).await.is_err() {
                    break;
                }
                let transfer = tokio::select! {
                    _ = stop.changed() => None,
                    result = tokio::time::timeout_at(
                        lifetime_deadline,
                        copy_tunnel_until_either_closes(
                            &mut external,
                            &mut agent_stream,
                            context.bandwidth_limiter.clone(),
                        ),
                    ) => Some(result),
                };
                match transfer {
                    Some(Ok(Ok((from_public, to_public)))) => {
                        record_transfer(&context, from_public, to_public);
                    }
                    Some(Ok(Err(error))) => {
                        context
                            .statistics
                            .transfer_errors
                            .fetch_add(1, Ordering::Relaxed);
                        tracing::warn!("HTTP CONNECT transfer failed: {error}");
                    }
                    Some(Err(_)) => {
                        context
                            .statistics
                            .lifetime_timeouts
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    None => {}
                }
                break;
            }
            ProxyRequestKind::Forward {
                encoded_head,
                body,
                head_request,
            } => {
                let authority = if request.target_host.contains(':') {
                    format!("[{}]:{}", request.target_host, request.target_port)
                } else {
                    format!("{}:{}", request.target_host, request.target_port)
                };
                let origin = match OriginKey::new(
                    context.policy_id,
                    &authority,
                    BackendProtocol::Http1,
                    BackendSecurity::Plaintext,
                ) {
                    Ok(origin) => origin,
                    Err(_) => {
                        context
                            .statistics
                            .malformed_requests
                            .fetch_add(1, Ordering::Relaxed);
                        let _ = write_proxy_response(&mut external, 400).await;
                        break;
                    }
                };
                let target_host = request.target_host.clone();
                let target_port = request.target_port;
                let acquired = context
                    .backend_pool
                    .acquire_or_connect(origin, || async {
                        pair_target(&context, &target_host, target_port, &mut stop).await
                    })
                    .await;
                let mut lease = match acquired {
                    Ok(lease) => lease,
                    Err(Http1BackendAcquireError::Connect(error)) => {
                        write_pair_error(&mut external, &context, error).await;
                        break;
                    }
                    Err(Http1BackendAcquireError::CapacityBusy) => {
                        context
                            .statistics
                            .rejected_connections
                            .fetch_add(1, Ordering::Relaxed);
                        let _ = write_proxy_response(&mut external, 503).await;
                        break;
                    }
                };
                let client_keep_alive =
                    request.client_keep_alive && requests < MAX_REQUESTS_PER_CONNECTION;
                let connection_id = lease.connection_id();
                let transfer = tokio::select! {
                    _ = stop.changed() => None,
                    result = tokio::time::timeout_at(
                        lifetime_deadline,
                        forward_http_exchange(
                            &mut external,
                            lease.stream_mut(),
                            &encoded_head,
                            body,
                            head_request,
                            client_keep_alive,
                            context.bandwidth_limiter.clone(),
                        ),
                    ) => Some(result),
                };
                match transfer {
                    Some(Ok(Ok(outcome))) => {
                        record_transfer(
                            &context,
                            outcome.bytes_from_public,
                            outcome.bytes_to_public,
                        );
                        if outcome.backend_reusable {
                            lease.recycle().await;
                        } else {
                            context
                                .statistics
                                .backend_reuse_ineligible_total
                                .fetch_add(1, Ordering::Relaxed);
                            lease.discard().await;
                        }
                        if !outcome.client_reusable {
                            break;
                        }
                    }
                    Some(Ok(Err(error))) => {
                        context
                            .statistics
                            .transfer_errors
                            .fetch_add(1, Ordering::Relaxed);
                        context
                            .statistics
                            .http1_backend
                            .failures_total
                            .fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(
                            "HTTP proxy exchange failed on backend connection {connection_id}: {error}"
                        );
                        lease.discard().await;
                        break;
                    }
                    Some(Err(_)) => {
                        context
                            .statistics
                            .lifetime_timeouts
                            .fetch_add(1, Ordering::Relaxed);
                        lease.discard().await;
                        break;
                    }
                    None => {
                        lease.discard().await;
                        break;
                    }
                }
            }
        }
    }
    finish_connection(&context.statistics);
}

async fn pair_target(
    context: &PublicConnectionContext,
    target_host: &str,
    target_port: u16,
    stop: &mut watch::Receiver<()>,
) -> Result<BoxedIo, PairTargetError> {
    let Ok(pending_permit) = context
        .state
        .pending_connection_permits
        .clone()
        .try_acquire_owned()
    else {
        return Err(PairTargetError::Busy);
    };
    let connection_id = Uuid::new_v4();
    let (data_tx, data_rx) = tokio::sync::oneshot::channel();
    context
        .state
        .pending_connections
        .lock()
        .await
        .insert(connection_id, (context.client_id, data_tx));
    if context
        .command_tx
        .send(ControlFrame::OpenHttpProxyConnection {
            connection_id,
            target_host: target_host.to_owned(),
            target_port,
        })
        .await
        .is_err()
    {
        context
            .state
            .pending_connections
            .lock()
            .await
            .remove(&connection_id);
        context
            .statistics
            .connect_failures
            .fetch_add(1, Ordering::Relaxed);
        return Err(PairTargetError::ControlClosed);
    }
    let pair_result = tokio::select! {
        _ = stop.changed() => {
            context.state.pending_connections.lock().await.remove(&connection_id);
            return Err(PairTargetError::Stopped);
        }
        result = timeout(CONNECTION_PAIR_TIMEOUT, data_rx) => result,
    };
    drop(pending_permit);
    match pair_result {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(_)) => {
            context
                .statistics
                .connect_failures
                .fetch_add(1, Ordering::Relaxed);
            context
                .state
                .pending_connections
                .lock()
                .await
                .remove(&connection_id);
            Err(PairTargetError::Rejected)
        }
        Err(_) => {
            context
                .statistics
                .pairing_timeouts
                .fetch_add(1, Ordering::Relaxed);
            context
                .statistics
                .connect_failures
                .fetch_add(1, Ordering::Relaxed);
            context
                .state
                .pending_connections
                .lock()
                .await
                .remove(&connection_id);
            Err(PairTargetError::Timeout)
        }
    }
}

async fn write_pair_error(
    external: &mut BufReader<TcpStream>,
    context: &PublicConnectionContext,
    error: PairTargetError,
) {
    let status = match error {
        PairTargetError::Busy => {
            context
                .statistics
                .rejected_connections
                .fetch_add(1, Ordering::Relaxed);
            503
        }
        PairTargetError::Timeout => 504,
        PairTargetError::ControlClosed | PairTargetError::Rejected => 502,
        PairTargetError::Stopped => return,
    };
    let _ = write_proxy_response(external, status).await;
}

fn record_transfer(context: &PublicConnectionContext, from_public: u64, to_public: u64) {
    context
        .statistics
        .bytes_from_public
        .fetch_add(from_public, Ordering::Relaxed);
    context
        .statistics
        .bytes_to_public
        .fetch_add(to_public, Ordering::Relaxed);
    if let Err(error) = context
        .state
        .traffic_controls
        .lock()
        .expect("traffic control catalog lock poisoned")
        .record_bytes(
            TrafficPolicyKind::HttpProxy,
            context.policy_id,
            from_public.saturating_add(to_public),
            crate::unix_seconds(),
        )
    {
        tracing::warn!("Could not persist HTTP proxy traffic usage: {error}");
    }
}

async fn forward_http_exchange<E>(
    external: &mut E,
    agent: &mut BoxedIo,
    encoded_head: &[u8],
    body: RequestBody,
    head_request: bool,
    client_keep_alive: bool,
    limiter: Option<Arc<BandwidthLimiter>>,
) -> std::io::Result<HttpExchangeOutcome>
where
    E: AsyncRead + AsyncWrite + Unpin,
{
    if let Some(limiter) = &limiter {
        limiter.reserve(encoded_head.len()).await;
    }
    agent.write_all(encoded_head).await?;
    let initial_bytes = encoded_head.len() as u64;
    let (mut external_reader, mut external_writer) = split(external);
    let (mut agent_reader, mut agent_writer) = split(agent);
    let request_limiter = limiter.clone();
    let body_progress = Arc::new(AtomicU64::new(0));
    let response_keep_alive =
        client_keep_alive && matches!(body, RequestBody::None | RequestBody::ContentLength(0));
    let completion = {
        let request_progress = body_progress.clone();
        let request = async {
            let body_bytes = copy_request_body(
                &mut external_reader,
                &mut agent_writer,
                body,
                request_limiter,
                Some(request_progress.as_ref()),
            )
            .await?;
            // 普通 HTTP 请求的结束由 Content-Length、chunked 或无请求体语义确定，
            // 不能在响应返回前关闭复用的数据通道写半边。
            flush_with_idle_timeout(&mut agent_writer).await?;
            Ok::<u64, std::io::Error>(initial_bytes.saturating_add(body_bytes))
        };
        let response = async {
            copy_http_response(
                &mut agent_reader,
                &mut external_writer,
                head_request,
                response_keep_alive,
                limiter,
            )
            .await
        };
        tokio::pin!(request);
        tokio::pin!(response);
        tokio::select! {
            request = &mut request => ExchangeCompletion::RequestFinishedFirst {
                bytes_from_public: request?,
                response: response.await?,
            },
            response = &mut response => ExchangeCompletion::ResponseFinishedFirst(response?),
        }
    };
    let (bytes_from_public, response) = match completion {
        ExchangeCompletion::RequestFinishedFirst {
            bytes_from_public,
            response,
        } => (bytes_from_public, response),
        ExchangeCompletion::ResponseFinishedFirst(mut response) => {
            // 最终响应先于请求体完成时，不能继续从公网连接读取旧请求体：
            // 客户端可能在 413 等响应后立即发送下一请求，继续读取会造成请求错位。
            shutdown_with_idle_timeout(&mut agent_writer).await?;
            shutdown_with_idle_timeout(&mut external_writer).await?;
            response.backend_reusable = false;
            response.client_reusable = false;
            (
                initial_bytes.saturating_add(body_progress.load(Ordering::Relaxed)),
                response,
            )
        }
    };
    Ok(HttpExchangeOutcome {
        bytes_from_public,
        bytes_to_public: response.bytes,
        backend_reusable: response.backend_reusable,
        client_reusable: response.client_reusable,
    })
}

async fn copy_tunnel_until_either_closes<A, B>(
    external: &mut A,
    agent: &mut B,
    limiter: Option<Arc<BandwidthLimiter>>,
) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut external_reader, mut external_writer) = split(external);
    let (mut agent_reader, mut agent_writer) = split(agent);
    let from_public = Arc::new(AtomicU64::new(0));
    let to_public = Arc::new(AtomicU64::new(0));
    let from_public_copy = copy_counted_until_eof(
        &mut external_reader,
        &mut agent_writer,
        limiter.clone(),
        from_public.clone(),
    );
    let to_public_copy = copy_counted_until_eof(
        &mut agent_reader,
        &mut external_writer,
        limiter,
        to_public.clone(),
    );
    tokio::try_join!(from_public_copy, to_public_copy)?;
    Ok((
        from_public.load(Ordering::Relaxed),
        to_public.load(Ordering::Relaxed),
    ))
}

async fn copy_counted_until_eof<R, W>(
    reader: &mut R,
    writer: &mut W,
    limiter: Option<Arc<BandwidthLimiter>>,
    transferred: Arc<AtomicU64>,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = read_with_idle_timeout(reader, &mut buffer).await?;
        if read == 0 {
            shutdown_with_idle_timeout(writer).await?;
            return Ok(());
        }
        if let Some(limiter) = &limiter {
            limiter.reserve(read).await;
        }
        write_all_with_idle_timeout(writer, &buffer[..read]).await?;
        transferred.fetch_add(read as u64, Ordering::Relaxed);
    }
}

async fn copy_request_body<R, W>(
    external: &mut R,
    writer: &mut W,
    body: RequestBody,
    limiter: Option<Arc<BandwidthLimiter>>,
    progress: Option<&AtomicU64>,
) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    match body {
        RequestBody::None => Ok(0),
        RequestBody::ContentLength(length) => {
            copy_exact_bytes(external, writer, length, limiter, progress).await
        }
        RequestBody::Chunked => copy_chunked_body(external, writer, limiter, progress).await,
    }
}

async fn copy_exact_bytes<R, W>(
    reader: &mut R,
    writer: &mut W,
    mut remaining: u64,
    limiter: Option<Arc<BandwidthLimiter>>,
    progress: Option<&AtomicU64>,
) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = [0_u8; 16 * 1024];
    let mut transferred = 0_u64;
    while remaining > 0 {
        let wanted = usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
        let read = read_with_idle_timeout(reader, &mut buffer[..wanted]).await?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "HTTP request body closed early",
            ));
        }
        if let Some(limiter) = &limiter {
            limiter.reserve(read).await;
        }
        write_all_with_idle_timeout(writer, &buffer[..read]).await?;
        transferred = transferred.saturating_add(read as u64);
        if let Some(progress) = progress {
            progress.fetch_add(read as u64, Ordering::Relaxed);
        }
        remaining -= read as u64;
    }
    Ok(transferred)
}

async fn copy_chunked_body<R, W>(
    reader: &mut R,
    writer: &mut W,
    limiter: Option<Arc<BandwidthLimiter>>,
    progress: Option<&AtomicU64>,
) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut transferred = 0_u64;
    loop {
        let line = read_body_line(reader, 8 * 1024).await?;
        let size_text =
            std::str::from_utf8(line.strip_suffix(b"\r\n").unwrap_or(&line)).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid chunk size")
            })?;
        let size_text = size_text.split(';').next().unwrap_or_default().trim();
        let size = u64::from_str_radix(size_text, 16).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid chunk size")
        })?;
        write_limited(writer, &line, limiter.as_ref()).await?;
        transferred = transferred.saturating_add(line.len() as u64);
        if let Some(progress) = progress {
            progress.fetch_add(line.len() as u64, Ordering::Relaxed);
        }
        if size == 0 {
            let mut trailers = 0_usize;
            loop {
                let trailer = read_body_line(reader, MAX_HEADER_BYTES).await?;
                trailers = trailers.saturating_add(trailer.len());
                if trailers > MAX_HEADER_BYTES {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "HTTP chunk trailers are too large",
                    ));
                }
                write_limited(writer, &trailer, limiter.as_ref()).await?;
                transferred = transferred.saturating_add(trailer.len() as u64);
                if let Some(progress) = progress {
                    progress.fetch_add(trailer.len() as u64, Ordering::Relaxed);
                }
                if trailer == b"\r\n" {
                    return Ok(transferred);
                }
            }
        }
        transferred = transferred.saturating_add(
            copy_exact_bytes(reader, writer, size, limiter.clone(), progress).await?,
        );
        let mut terminator = [0_u8; 2];
        read_exact_with_idle_timeout(reader, &mut terminator).await?;
        if terminator != *b"\r\n" {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid HTTP chunk terminator",
            ));
        }
        write_limited(writer, &terminator, limiter.as_ref()).await?;
        transferred = transferred.saturating_add(2);
        if let Some(progress) = progress {
            progress.fetch_add(2, Ordering::Relaxed);
        }
    }
}

async fn read_body_line<R>(reader: &mut R, maximum: usize) -> std::io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut line = Vec::new();
    while line.len() <= maximum {
        let mut byte = [0_u8; 1];
        if read_with_idle_timeout(reader, &mut byte).await? == 0 {
            break;
        }
        line.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    if line.is_empty() || line.len() > maximum || !line.ends_with(b"\r\n") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid HTTP chunk line",
        ));
    }
    Ok(line)
}

async fn write_limited<W>(
    writer: &mut W,
    bytes: &[u8],
    limiter: Option<&Arc<BandwidthLimiter>>,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    if let Some(limiter) = limiter {
        limiter.reserve(bytes.len()).await;
    }
    write_all_with_idle_timeout(writer, bytes).await
}

fn idle_timeout_error(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::TimedOut, message)
}

async fn read_with_idle_timeout<R>(reader: &mut R, buffer: &mut [u8]) -> std::io::Result<usize>
where
    R: AsyncRead + Unpin,
{
    timeout(EXCHANGE_IO_IDLE_TIMEOUT, reader.read(buffer))
        .await
        .map_err(|_| idle_timeout_error("HTTP proxy read idle timeout"))?
}

async fn read_exact_with_idle_timeout<R>(reader: &mut R, buffer: &mut [u8]) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
{
    timeout(EXCHANGE_IO_IDLE_TIMEOUT, reader.read_exact(buffer))
        .await
        .map_err(|_| idle_timeout_error("HTTP proxy exact read idle timeout"))??;
    Ok(())
}

async fn write_all_with_idle_timeout<W>(writer: &mut W, bytes: &[u8]) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    timeout(EXCHANGE_IO_IDLE_TIMEOUT, writer.write_all(bytes))
        .await
        .map_err(|_| idle_timeout_error("HTTP proxy write idle timeout"))?
}

async fn flush_with_idle_timeout<W>(writer: &mut W) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    timeout(EXCHANGE_IO_IDLE_TIMEOUT, writer.flush())
        .await
        .map_err(|_| idle_timeout_error("HTTP proxy flush idle timeout"))?
}

async fn shutdown_with_idle_timeout<W>(writer: &mut W) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    timeout(EXCHANGE_IO_IDLE_TIMEOUT, writer.shutdown())
        .await
        .map_err(|_| idle_timeout_error("HTTP proxy shutdown idle timeout"))?
}

async fn copy_http_response<R, W>(
    reader: &mut R,
    writer: &mut W,
    head_request: bool,
    client_keep_alive: bool,
    limiter: Option<Arc<BandwidthLimiter>>,
) -> std::io::Result<HttpResponseTransfer>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut transferred = 0_u64;
    loop {
        let response = timeout(RESPONSE_HEADER_TIMEOUT, read_http_response_head(reader))
            .await
            .map_err(|_| idle_timeout_error("HTTP backend response header timed out"))??;
        if response.status == 101 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "HTTP protocol upgrades require CONNECT",
            ));
        }
        let informational = (100..200).contains(&response.status);
        let body = response_body(&response.headers, response.status, head_request)?;
        let backend_persistent = response.http11
            && !header_has_token(&response.headers, "connection", "close")
            || !response.http11 && header_has_token(&response.headers, "connection", "keep-alive");
        let backend_reusable =
            !informational && backend_persistent && !matches!(body, ResponseBody::UntilEof);
        let response_client_reusable = client_keep_alive && !matches!(body, ResponseBody::UntilEof);
        let encoded_head =
            build_forward_response_head(&response, informational || response_client_reusable);
        write_limited(writer, &encoded_head, limiter.as_ref()).await?;
        transferred = transferred.saturating_add(encoded_head.len() as u64);
        if informational {
            continue;
        }
        let body_bytes = match body {
            ResponseBody::None => 0,
            ResponseBody::UntilEof => copy_until_eof(reader, writer, limiter).await?,
            ResponseBody::ContentLength(length) => {
                copy_exact_bytes(reader, writer, length, limiter, None).await?
            }
            ResponseBody::Chunked => copy_chunked_body(reader, writer, limiter, None).await?,
        };
        flush_with_idle_timeout(writer).await?;
        if !response_client_reusable {
            shutdown_with_idle_timeout(writer).await?;
        }
        return Ok(HttpResponseTransfer {
            bytes: transferred.saturating_add(body_bytes),
            backend_reusable,
            client_reusable: response_client_reusable,
        });
    }
}

async fn read_http_response_head<R>(reader: &mut R) -> std::io::Result<ParsedResponseHead>
where
    R: AsyncRead + Unpin,
{
    let mut lines = Vec::new();
    let mut encoded_len = 0_usize;
    loop {
        if lines.len() > MAX_HEADER_COUNT {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "too many HTTP response headers",
            ));
        }
        let line = read_body_line(reader, MAX_HEADER_BYTES).await?;
        if encoded_len.saturating_add(line.len()) > MAX_HEADER_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "HTTP response headers are too large",
            ));
        }
        encoded_len = encoded_len.saturating_add(line.len());
        if line == b"\r\n" {
            break;
        }
        lines.push(line);
    }
    let status_line = lines.first().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "missing status line")
    })?;
    let status_line = std::str::from_utf8(strip_crlf(status_line))
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid status line"))?;
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or_default();
    let status = parts
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|value| (100..=599).contains(value))
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid status code")
        })?;
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unsupported HTTP response version",
        ));
    }
    let headers = parse_headers(&lines[1..]).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid HTTP response headers",
        )
    })?;
    Ok(ParsedResponseHead {
        status_line: status_line.to_owned(),
        http11: version == "HTTP/1.1",
        status,
        headers,
    })
}

fn response_body(
    headers: &[(String, String)],
    status: u16,
    head_request: bool,
) -> std::io::Result<ResponseBody> {
    let framing = validate_message_framing(headers).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ambiguous HTTP response framing",
        )
    })?;
    if head_request || matches!(status, 204 | 304) || (100..200).contains(&status) {
        return Ok(ResponseBody::None);
    }
    Ok(match framing {
        RequestBody::None => ResponseBody::UntilEof,
        RequestBody::ContentLength(length) => ResponseBody::ContentLength(length),
        RequestBody::Chunked => ResponseBody::Chunked,
    })
}

fn build_forward_response_head(response: &ParsedResponseHead, keep_alive: bool) -> Vec<u8> {
    let connection_tokens = connection_tokens(&response.headers);
    let mut encoded = Vec::with_capacity(MAX_HEADER_BYTES.min(1024));
    encoded.extend_from_slice(response.status_line.as_bytes());
    encoded.extend_from_slice(b"\r\n");
    for (name, value) in &response.headers {
        if is_hop_by_hop_header(name) || connection_tokens.contains(name) {
            continue;
        }
        encoded.extend_from_slice(name.as_bytes());
        encoded.extend_from_slice(b": ");
        encoded.extend_from_slice(value.as_bytes());
        encoded.extend_from_slice(b"\r\n");
    }
    if keep_alive {
        encoded.extend_from_slice(b"connection: keep-alive\r\n");
    } else {
        encoded.extend_from_slice(b"connection: close\r\n");
    }
    encoded.extend_from_slice(b"\r\n");
    encoded
}

async fn copy_until_eof<R, W>(
    reader: &mut R,
    writer: &mut W,
    limiter: Option<Arc<BandwidthLimiter>>,
) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = [0_u8; 16 * 1024];
    let mut transferred = 0_u64;
    loop {
        let read = read_with_idle_timeout(reader, &mut buffer).await?;
        if read == 0 {
            return Ok(transferred);
        }
        if let Some(limiter) = &limiter {
            limiter.reserve(read).await;
        }
        write_all_with_idle_timeout(writer, &buffer[..read]).await?;
        transferred = transferred.saturating_add(read as u64);
    }
}

async fn read_proxy_request(
    stream: &mut BufReader<TcpStream>,
    expected_username: &str,
    expected_password_hash: &str,
) -> Result<ProxyRequest, RequestError> {
    let mut lines = Vec::new();
    let mut total = 0_usize;
    loop {
        if lines.len() > MAX_HEADER_COUNT {
            return Err(RequestError::HeaderTooLarge);
        }
        let mut line = Vec::new();
        let read = stream
            .read_until(b'\n', &mut line)
            .await
            .map_err(|_| RequestError::Malformed)?;
        if read == 0 {
            return if lines.is_empty() {
                Err(RequestError::Closed)
            } else {
                Err(RequestError::Malformed)
            };
        }
        total = total.saturating_add(read);
        if total > MAX_HEADER_BYTES {
            return Err(RequestError::HeaderTooLarge);
        }
        if !line.ends_with(b"\r\n") {
            return Err(RequestError::Malformed);
        }
        if line == b"\r\n" {
            break;
        }
        lines.push(line);
    }
    parse_proxy_request(&lines, expected_username, expected_password_hash)
}

fn parse_proxy_request(
    lines: &[Vec<u8>],
    expected_username: &str,
    expected_password_hash: &str,
) -> Result<ProxyRequest, RequestError> {
    let request_line = lines.first().ok_or(RequestError::Malformed)?;
    let request_line =
        std::str::from_utf8(strip_crlf(request_line)).map_err(|_| RequestError::Malformed)?;
    let parts = request_line.split(' ').collect::<Vec<_>>();
    if parts.len() != 3
        || parts[0].is_empty()
        || !parts[0]
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || matches!(byte, b'-' | b'_'))
        || !matches!(parts[2], "HTTP/1.0" | "HTTP/1.1")
    {
        return Err(RequestError::Malformed);
    }
    let headers = parse_headers(&lines[1..])?;
    authenticate(&headers, expected_username, expected_password_hash)?;
    let body = validate_message_framing(&headers)?;
    let client_keep_alive = request_keep_alive(parts[2], &headers);
    if parts[0] == "CONNECT" {
        if body != RequestBody::None {
            return Err(RequestError::Malformed);
        }
        let (target_host, target_port, _) = parse_authority(parts[1], None)?;
        return Ok(ProxyRequest {
            target_host,
            target_port,
            client_keep_alive,
            kind: ProxyRequestKind::Connect,
        });
    }
    let (target_host, target_port, host_header, origin_form) = parse_http_uri(parts[1])?;
    let host_headers = header_values(&headers, "host").collect::<Vec<_>>();
    if host_headers.len() > 1 {
        return Err(RequestError::Malformed);
    }
    if let Some(host) = host_headers.first() {
        let (_, _, normalized) = parse_authority(host, Some(80))?;
        if normalized != host_header {
            return Err(RequestError::Malformed);
        }
    }
    let encoded_head = build_forward_head(parts[0], &origin_form, &headers, &host_header);
    Ok(ProxyRequest {
        target_host,
        target_port,
        client_keep_alive,
        kind: ProxyRequestKind::Forward {
            encoded_head,
            body,
            head_request: parts[0] == "HEAD",
        },
    })
}

fn parse_headers(lines: &[Vec<u8>]) -> Result<Vec<(String, String)>, RequestError> {
    let mut headers = Vec::with_capacity(lines.len());
    for line in lines {
        let line = strip_crlf(line);
        if line.first().is_some_and(u8::is_ascii_whitespace) {
            return Err(RequestError::Malformed);
        }
        let colon = line
            .iter()
            .position(|byte| *byte == b':')
            .ok_or(RequestError::Malformed)?;
        let name = std::str::from_utf8(&line[..colon]).map_err(|_| RequestError::Malformed)?;
        if name.is_empty()
            || !name.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(
                        byte,
                        b'!' | b'#'
                            | b'$'
                            | b'%'
                            | b'&'
                            | b'\''
                            | b'*'
                            | b'+'
                            | b'-'
                            | b'.'
                            | b'^'
                            | b'_'
                            | b'`'
                            | b'|'
                            | b'~'
                    )
            })
        {
            return Err(RequestError::Malformed);
        }
        let value = std::str::from_utf8(&line[colon + 1..])
            .map_err(|_| RequestError::Malformed)?
            .trim();
        if value
            .bytes()
            .any(|byte| byte.is_ascii_control() && byte != b'\t')
        {
            return Err(RequestError::Malformed);
        }
        headers.push((name.to_ascii_lowercase(), value.to_owned()));
    }
    Ok(headers)
}

fn authenticate(
    headers: &[(String, String)],
    expected_username: &str,
    expected_password_hash: &str,
) -> Result<(), RequestError> {
    let values = headers
        .iter()
        .filter(|(name, _)| name == "proxy-authorization")
        .map(|(_, value)| value)
        .collect::<Vec<_>>();
    if values.len() != 1 {
        return Err(RequestError::Authentication);
    }
    let (scheme, encoded) = values[0]
        .split_once(' ')
        .ok_or(RequestError::Authentication)?;
    if !scheme.eq_ignore_ascii_case("basic") || encoded.is_empty() {
        return Err(RequestError::Authentication);
    }
    if encoded.len() > 512 {
        return Err(RequestError::Authentication);
    }
    let decoded = STANDARD
        .decode(encoded)
        .map_err(|_| RequestError::Authentication)?;
    let colon = decoded
        .iter()
        .position(|byte| *byte == b':')
        .ok_or(RequestError::Authentication)?;
    if &decoded[..colon] != expected_username.as_bytes()
        || !http_proxy_password_matches(&decoded[colon + 1..], expected_password_hash)
    {
        return Err(RequestError::Authentication);
    }
    Ok(())
}

fn parse_http_uri(value: &str) -> Result<(String, u16, String, String), RequestError> {
    let remainder = value
        .strip_prefix("http://")
        .ok_or(RequestError::Malformed)?;
    if remainder.contains('#') {
        return Err(RequestError::Malformed);
    }
    let authority_end = remainder.find(['/', '?']).unwrap_or(remainder.len());
    let authority = &remainder[..authority_end];
    if authority.contains('@') {
        return Err(RequestError::Malformed);
    }
    let origin_form = match &remainder[authority_end..] {
        "" => "/".to_owned(),
        value if value.starts_with('?') => format!("/{value}"),
        value => value.to_owned(),
    };
    if origin_form
        .bytes()
        .any(|byte| byte.is_ascii_control() || byte == b' ')
    {
        return Err(RequestError::Malformed);
    }
    let (host, port, normalized) = parse_authority(authority, Some(80))?;
    Ok((host, port, normalized, origin_form))
}

fn parse_authority(
    value: &str,
    default_port: Option<u16>,
) -> Result<(String, u16, String), RequestError> {
    if value.is_empty()
        || value.len() > 300
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        || value.contains(['/', '\\', '?', '#', '@'])
    {
        return Err(RequestError::Malformed);
    }
    let (host, port) = if let Some(bracketed) = value.strip_prefix('[') {
        let end = bracketed.find(']').ok_or(RequestError::Malformed)?;
        let host = &bracketed[..end];
        host.parse::<Ipv6Addr>()
            .map_err(|_| RequestError::Malformed)?;
        let suffix = &bracketed[end + 1..];
        let port = if suffix.is_empty() {
            default_port.ok_or(RequestError::Malformed)?
        } else {
            suffix
                .strip_prefix(':')
                .ok_or(RequestError::Malformed)?
                .parse::<u16>()
                .map_err(|_| RequestError::Malformed)?
        };
        (host.to_ascii_lowercase(), port)
    } else if let Ok(address) = value.parse::<IpAddr>() {
        let port = default_port.ok_or(RequestError::Malformed)?;
        (address.to_string(), port)
    } else {
        let (host, port) = match value.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => (
                host,
                port.parse::<u16>().map_err(|_| RequestError::Malformed)?,
            ),
            _ => (value, default_port.ok_or(RequestError::Malformed)?),
        };
        if !valid_host(host) {
            return Err(RequestError::Malformed);
        }
        (host.to_ascii_lowercase(), port)
    };
    if port == 0 {
        return Err(RequestError::Malformed);
    }
    let normalized = if host.contains(':') {
        if default_port == Some(port) {
            format!("[{host}]")
        } else {
            format!("[{host}]:{port}")
        }
    } else if default_port == Some(port) {
        host.clone()
    } else {
        format!("{host}:{port}")
    };
    Ok((host, port, normalized))
}

fn valid_host(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn header_values<'a>(
    headers: &'a [(String, String)],
    name: &'a str,
) -> impl Iterator<Item = &'a str> {
    headers
        .iter()
        .filter(move |(header_name, _)| header_name == name)
        .map(|(_, value)| value.as_str())
}

fn header_has_token(headers: &[(String, String)], name: &str, expected: &str) -> bool {
    header_values(headers, name)
        .flat_map(|value| value.split(','))
        .any(|value| value.trim().eq_ignore_ascii_case(expected))
}

fn request_keep_alive(version: &str, headers: &[(String, String)]) -> bool {
    let close = header_has_token(headers, "connection", "close")
        || header_has_token(headers, "proxy-connection", "close");
    if close {
        return false;
    }
    version == "HTTP/1.1"
        || header_has_token(headers, "connection", "keep-alive")
        || header_has_token(headers, "proxy-connection", "keep-alive")
}

fn validate_message_framing(headers: &[(String, String)]) -> Result<RequestBody, RequestError> {
    let content_lengths = header_values(headers, "content-length").collect::<Vec<_>>();
    if content_lengths.len() > 1
        || content_lengths
            .first()
            .is_some_and(|value| value.parse::<u64>().is_err())
    {
        return Err(RequestError::Malformed);
    }
    let transfer_encodings = header_values(headers, "transfer-encoding").collect::<Vec<_>>();
    if transfer_encodings.len() > 1
        || transfer_encodings
            .first()
            .is_some_and(|value| !value.eq_ignore_ascii_case("chunked"))
        || (!content_lengths.is_empty() && !transfer_encodings.is_empty())
    {
        return Err(RequestError::Malformed);
    }
    let connection_tokens = header_values(headers, "connection")
        .flat_map(|value| value.split(','))
        .map(|value| value.trim())
        .collect::<Vec<_>>();
    if connection_tokens.iter().any(|value| {
        value.eq_ignore_ascii_case("content-length")
            || value.eq_ignore_ascii_case("transfer-encoding")
            || value.eq_ignore_ascii_case("host")
    }) {
        return Err(RequestError::Malformed);
    }
    if let Some(value) = transfer_encodings.first() {
        debug_assert!(value.eq_ignore_ascii_case("chunked"));
        Ok(RequestBody::Chunked)
    } else if let Some(value) = content_lengths.first() {
        Ok(RequestBody::ContentLength(
            value.parse::<u64>().map_err(|_| RequestError::Malformed)?,
        ))
    } else {
        Ok(RequestBody::None)
    }
}

fn build_forward_head(
    method: &str,
    origin_form: &str,
    headers: &[(String, String)],
    authority: &str,
) -> Vec<u8> {
    let connection_tokens = connection_tokens(headers);
    let mut encoded = format!("{method} {origin_form} HTTP/1.1\r\n").into_bytes();
    let mut wrote_host = false;
    for (name, value) in headers {
        if name == "proxy-authorization"
            || is_hop_by_hop_header(name)
            || connection_tokens.contains(name)
        {
            continue;
        }
        if name == "host" {
            wrote_host = true;
        }
        encoded.extend_from_slice(name.as_bytes());
        encoded.extend_from_slice(b": ");
        encoded.extend_from_slice(value.as_bytes());
        encoded.extend_from_slice(b"\r\n");
    }
    if !wrote_host {
        encoded.extend_from_slice(b"host: ");
        encoded.extend_from_slice(authority.as_bytes());
        encoded.extend_from_slice(b"\r\n");
    }
    encoded.extend_from_slice(b"connection: keep-alive\r\n\r\n");
    encoded
}

fn connection_tokens(headers: &[(String, String)]) -> HashSet<String> {
    headers
        .iter()
        .filter(|(name, _)| matches!(name.as_str(), "connection" | "proxy-connection"))
        .flat_map(|(_, value)| value.split(','))
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect()
}

fn is_hop_by_hop_header(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "upgrade"
    )
}

fn strip_crlf(value: &[u8]) -> &[u8] {
    value.strip_suffix(b"\r\n").unwrap_or(value)
}

async fn write_proxy_response<W>(writer: &mut W, status: u16) -> std::io::Result<()>
where
    W: AsyncWriteExt + Unpin,
{
    let response = match status {
        200 => "HTTP/1.1 200 Connection Established\r\nProxy-Agent: LinkLake\r\n\r\n",
        400 => "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        407 => "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"LinkLake\"\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        502 => "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        503 => "HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        504 => "HTTP/1.1 504 Gateway Timeout\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        _ => "HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
    };
    writer.write_all(response.as_bytes()).await?;
    writer.flush().await
}

fn finish_connection(statistics: &HttpProxyStatistics) {
    statistics
        .active_connections
        .fetch_sub(1, Ordering::Relaxed);
}

async fn authenticated_client(state: &AppState, client_id: Uuid, token: &str) -> bool {
    let mut clients = state.clients.lock().await;
    matches!(
        clients.authenticate_and_touch(client_id, token).await,
        Ok(Authentication::Authenticated)
    )
}

async fn reject(state: &AppState, stream: &mut BoxedIo, message: &str) {
    state
        .metrics
        .registration_rejections_total
        .fetch_add(1, Ordering::Relaxed);
    let _ = write_control_frame(
        stream,
        &ControlFrame::Error {
            message: message.to_owned(),
        },
    )
    .await;
}

fn remove_registration(state: &AppState, policy_id: Uuid, registration_id: Uuid) {
    let mut proxies = state
        .http_proxies
        .lock()
        .expect("HTTP proxy registry lock poisoned");
    if proxies
        .get(&policy_id)
        .is_some_and(|registration| registration.registration_id == registration_id)
    {
        if let Some(registration) = proxies.remove(&policy_id) {
            let _ = registration.stop_tx.send(());
        }
    }
}

pub(crate) fn stop_policy(state: &AppState, policy_id: Uuid) {
    if let Some(registration) = state
        .http_proxies
        .lock()
        .expect("HTTP proxy registry lock poisoned")
        .remove(&policy_id)
    {
        let _ = registration.stop_tx.send(());
    }
}

pub(crate) fn stop_all(state: &AppState) {
    let registrations = state
        .http_proxies
        .lock()
        .expect("HTTP proxy registry lock poisoned")
        .drain()
        .map(|(_, registration)| registration)
        .collect::<Vec<_>>();
    for registration in registrations {
        let _ = registration.stop_tx.send(());
    }
}

pub(crate) fn online_public_port(registration: &HttpProxyRegistration) -> u16 {
    registration.public_port
}

#[cfg(test)]
mod tests {
    use super::{
        build_forward_head, parse_authority, parse_http_uri, parse_proxy_request, ProxyRequest,
        ProxyRequestKind, RequestError,
    };
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use linklake_core::BoxedIo;
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use sha2::{Digest, Sha256};
    use std::{sync::Arc, time::Duration};
    use tokio::{
        io::{copy_bidirectional, duplex, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
        net::{TcpListener, TcpStream},
    };
    use tokio_rustls::{
        rustls::{
            pki_types::{PrivatePkcs8KeyDer, ServerName},
            ClientConfig, RootCertStore, ServerConfig,
        },
        TlsAcceptor, TlsConnector,
    };

    fn password() -> (String, String) {
        let password = format!("llh_{}", "a".repeat(64));
        let hash = format!("{:x}", Sha256::digest(password.as_bytes()));
        (password, hash)
    }

    fn lines(request: &str) -> Vec<Vec<u8>> {
        request
            .split_inclusive("\r\n")
            .filter(|line| *line != "\r\n")
            .map(|line| line.as_bytes().to_vec())
            .collect()
    }

    #[test]
    fn parses_authenticated_connect_request() {
        let (password, hash) = password();
        let auth = STANDARD.encode(format!("admin:{password}"));
        let request = format!(
            "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic {auth}\r\n\r\n"
        );
        assert_eq!(
            parse_proxy_request(&lines(&request), "admin", &hash),
            Ok(ProxyRequest {
                target_host: "example.com".to_owned(),
                target_port: 443,
                client_keep_alive: true,
                kind: ProxyRequestKind::Connect,
            })
        );
    }

    #[test]
    fn rewrites_absolute_http_uri_and_removes_proxy_credentials() {
        let (password, hash) = password();
        let auth = STANDARD.encode(format!("admin:{password}"));
        let request = format!(
            "GET http://example.com:8080/path?q=1 HTTP/1.1\r\nHost: example.com:8080\r\nProxy-Authorization: Basic {auth}\r\nProxy-Connection: keep-alive\r\nX-Test: yes\r\n\r\n"
        );
        let parsed = parse_proxy_request(&lines(&request), "admin", &hash).unwrap();
        let ProxyRequestKind::Forward { encoded_head, .. } = parsed.kind else {
            panic!("expected forward request")
        };
        let encoded = String::from_utf8(encoded_head).unwrap();
        assert!(encoded.starts_with("GET /path?q=1 HTTP/1.1\r\n"));
        assert!(encoded.contains("host: example.com:8080\r\n"));
        assert!(encoded.contains("x-test: yes\r\n"));
        assert!(encoded.ends_with("connection: keep-alive\r\n\r\n"));
        assert!(!encoded.contains("proxy-authorization"));
        assert!(!encoded.contains("proxy-connection"));
    }

    #[test]
    fn rejects_missing_auth_https_absolute_uri_and_host_mismatch() {
        let (_, hash) = password();
        assert_eq!(
            parse_proxy_request(
                &lines("GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"),
                "admin",
                &hash,
            ),
            Err(RequestError::Authentication)
        );
        let auth = STANDARD.encode(format!("admin:llh_{}", "a".repeat(64)));
        assert_eq!(
            parse_proxy_request(
                &lines(&format!("GET https://example.com/ HTTP/1.1\r\nProxy-Authorization: Basic {auth}\r\n\r\n")),
                "admin",
                &hash,
            ),
            Err(RequestError::Malformed)
        );
        assert_eq!(
            parse_proxy_request(
                &lines(&format!("GET http://example.com/ HTTP/1.1\r\nHost: other.example\r\nProxy-Authorization: Basic {auth}\r\n\r\n")),
                "admin",
                &hash,
            ),
            Err(RequestError::Malformed)
        );
    }

    #[test]
    fn rejects_ambiguous_http_message_framing() {
        let (password, hash) = password();
        let auth = STANDARD.encode(format!("admin:{password}"));
        for framing in [
            "Content-Length: 1\r\nContent-Length: 1\r\n",
            "Content-Length: 1\r\nTransfer-Encoding: chunked\r\n",
            "Transfer-Encoding: gzip\r\n",
            "Host: example.com\r\nHost: example.com\r\n",
            "Connection: Content-Length\r\nContent-Length: 1\r\n",
        ] {
            let request = format!(
                "POST http://example.com/ HTTP/1.1\r\nHost: example.com\r\nProxy-Authorization: Basic {auth}\r\n{framing}\r\n"
            );
            assert_eq!(
                parse_proxy_request(&lines(&request), "admin", &hash),
                Err(RequestError::Malformed)
            );
        }
    }

    #[test]
    fn authority_supports_ipv4_ipv6_and_domains() {
        assert_eq!(
            parse_authority("127.0.0.1:8080", Some(80)).unwrap(),
            ("127.0.0.1".to_owned(), 8080, "127.0.0.1:8080".to_owned())
        );
        assert_eq!(
            parse_authority("[::1]:443", None).unwrap(),
            ("::1".to_owned(), 443, "[::1]:443".to_owned())
        );
        assert_eq!(
            parse_http_uri("http://Example.COM/path").unwrap(),
            (
                "example.com".to_owned(),
                80,
                "example.com".to_owned(),
                "/path".to_owned()
            )
        );
    }

    #[test]
    fn connection_named_headers_are_removed() {
        let headers = vec![
            ("host".to_owned(), "example.com".to_owned()),
            ("connection".to_owned(), "X-Remove".to_owned()),
            ("proxy-connection".to_owned(), "X-Remove-Too".to_owned()),
            ("x-remove".to_owned(), "secret".to_owned()),
            ("x-remove-too".to_owned(), "secret".to_owned()),
            ("x-keep".to_owned(), "ok".to_owned()),
        ];
        let encoded =
            String::from_utf8(build_forward_head("GET", "/", &headers, "example.com")).unwrap();
        assert!(!encoded.contains("x-remove"));
        assert!(!encoded.contains("x-remove-too"));
        assert!(encoded.contains("x-keep: ok"));
    }

    #[tokio::test]
    async fn early_final_response_cancels_unfinished_request_body_and_forces_close() {
        let (external, mut public) = duplex(4096);
        let (agent, mut backend) = duplex(4096);
        let backend_task = tokio::spawn(async move {
            let mut backend = BufReader::new(&mut backend);
            loop {
                let mut line = Vec::new();
                backend.read_until(b'\n', &mut line).await.unwrap();
                if line == b"\r\n" {
                    break;
                }
            }
            backend
                .get_mut()
                .write_all(b"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });
        let exchange = tokio::spawn(async move {
            let mut external = BufReader::new(external);
            let mut agent: BoxedIo = Box::new(agent);
            super::forward_http_exchange(
                &mut external,
                &mut agent,
                b"POST / HTTP/1.1\r\nhost: example.test\r\ncontent-length: 4\r\n\r\n",
                super::RequestBody::ContentLength(4),
                false,
                true,
                None,
            )
            .await
        });
        let mut response = Vec::new();
        public.read_to_end(&mut response).await.unwrap();
        let outcome = tokio::time::timeout(Duration::from_secs(1), exchange)
            .await
            .expect("early final response must cancel the pending body read")
            .unwrap()
            .unwrap();
        assert!(!outcome.backend_reusable);
        assert!(!outcome.client_reusable);
        assert!(response.starts_with(b"HTTP/1.1 413"));
        backend_task.await.unwrap();
    }

    #[tokio::test]
    async fn chunked_request_body_is_forwarded_with_exact_boundaries() {
        let encoded = b"4\r\ntest\r\n0\r\nX-Trailer: yes\r\n\r\n";
        let (mut source_writer, mut source_reader) = duplex(1024);
        let (mut target_writer, mut target_reader) = duplex(1024);
        source_writer.write_all(encoded).await.unwrap();
        source_writer.shutdown().await.unwrap();
        let copied = super::copy_request_body(
            &mut source_reader,
            &mut target_writer,
            super::RequestBody::Chunked,
            None,
            None,
        )
        .await
        .unwrap();
        target_writer.shutdown().await.unwrap();
        let mut actual = Vec::new();
        target_reader.read_to_end(&mut actual).await.unwrap();
        assert_eq!(copied, encoded.len() as u64);
        assert_eq!(actual, encoded);
    }

    #[tokio::test]
    async fn content_length_response_completes_without_waiting_for_eof() {
        let encoded = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ntest";
        let (mut source_writer, mut source_reader) = duplex(1024);
        let (mut public_writer, mut public_reader) = duplex(1024);
        source_writer.write_all(encoded).await.unwrap();
        let copied = tokio::time::timeout(
            Duration::from_secs(1),
            super::copy_http_response(&mut source_reader, &mut public_writer, false, true, None),
        )
        .await
        .expect("response copy should not wait for source EOF")
        .unwrap();
        let expected =
            b"HTTP/1.1 200 OK\r\ncontent-length: 4\r\nconnection: keep-alive\r\n\r\ntest";
        let mut actual = vec![0_u8; expected.len()];
        public_reader.read_exact(&mut actual).await.unwrap();
        assert_eq!(copied.bytes, expected.len() as u64);
        assert!(copied.backend_reusable);
        assert!(copied.client_reusable);
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn forward_exchange_returns_response_over_tls_data_connection() {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["control.linklake.test".to_owned()])
                .expect("test certificate should generate");
        let certificate = cert.der().clone();
        let private_key = PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into();
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], private_key)
            .expect("server TLS config should build");
        let mut roots = RootCertStore::empty();
        roots
            .add(certificate)
            .expect("test certificate should be trusted");
        let client_config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        let target_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("target listener should bind");
        let target_address = target_listener
            .local_addr()
            .expect("target address should exist");
        let target = tokio::spawn(async move {
            let (stream, _) = target_listener
                .accept()
                .await
                .expect("target connection should arrive");
            let mut stream = BufReader::new(stream);
            let mut request = Vec::new();
            loop {
                let mut line = Vec::new();
                stream
                    .read_until(b'\n', &mut line)
                    .await
                    .expect("request line should read");
                request.extend_from_slice(&line);
                if line == b"\r\n" {
                    break;
                }
            }
            assert!(request.starts_with(b"GET / HTTP/1.1\r\n"));
            let mut stream = stream.into_inner();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .expect("target response should write");
            stream
                .shutdown()
                .await
                .expect("target should close cleanly");
        });

        let data_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("data listener should bind");
        let data_address = data_listener
            .local_addr()
            .expect("data address should exist");
        let connector = TlsConnector::from(Arc::new(client_config));
        let client = tokio::spawn(async move {
            let tcp = TcpStream::connect(data_address)
                .await
                .expect("data connection should connect");
            let name = ServerName::try_from("control.linklake.test")
                .expect("test server name should parse")
                .to_owned();
            let mut data = connector
                .connect(name, tcp)
                .await
                .expect("client TLS handshake should succeed");
            let mut target = TcpStream::connect(target_address)
                .await
                .expect("local HTTP target should connect");
            copy_bidirectional(&mut data, &mut target)
                .await
                .expect("client relay should finish cleanly");
        });
        let (tcp, _) = data_listener
            .accept()
            .await
            .expect("data connection should arrive");
        let mut agent: BoxedIo = Box::new(
            TlsAcceptor::from(Arc::new(server_config))
                .accept(tcp)
                .await
                .expect("server TLS handshake should succeed"),
        );

        let public_listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("public listener should bind");
        let public_address = public_listener
            .local_addr()
            .expect("public address should exist");
        let mut public = TcpStream::connect(public_address)
            .await
            .expect("public connection should connect");
        let (external, _) = public_listener
            .accept()
            .await
            .expect("public connection should arrive");
        let response = tokio::spawn(async move {
            let mut response = Vec::new();
            public
                .read_to_end(&mut response)
                .await
                .expect("public response should read");
            response
        });
        let mut external = BufReader::new(external);
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            super::forward_http_exchange(
                &mut external,
                &mut agent,
                b"GET / HTTP/1.1\r\nhost: 127.0.0.1\r\nconnection: close\r\n\r\n",
                super::RequestBody::None,
                false,
                false,
                None,
            ),
        )
        .await
        .expect("forward exchange should not hang");
        assert!(result.is_ok(), "forward exchange failed: {result:?}");
        let response = response.await.expect("response task should finish");
        assert!(response.ends_with(b"\r\n\r\nok"));
        target.await.expect("target task should finish");
        client.await.expect("client relay task should finish");
    }

    #[tokio::test]
    async fn connect_relay_stops_when_public_side_closes() {
        let (external, external_peer) = duplex(1024);
        let (agent, mut agent_peer) = duplex(1024);
        let peer = tokio::spawn(async move {
            let mut buffer = [0_u8; 1];
            assert_eq!(agent_peer.read(&mut buffer).await.unwrap(), 0);
            agent_peer.shutdown().await.unwrap();
        });
        let relay = tokio::spawn(async move {
            let mut external = external;
            let mut agent = agent;
            super::copy_tunnel_until_either_closes(&mut external, &mut agent, None).await
        });
        drop(external_peer);
        tokio::time::timeout(Duration::from_secs(1), relay)
            .await
            .expect("CONNECT relay should stop after public EOF")
            .unwrap()
            .unwrap();
        peer.await.unwrap();
    }
}
