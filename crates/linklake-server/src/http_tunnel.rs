use crate::traffic_control::{TrafficDecision, TrafficPolicyKind};
use crate::{
    client_registry::Authentication,
    http2_backend::{
        BoxError, Http2BackendCounters, Http2BackendLease, Http2BackendPool, ProxyBody,
    },
    http_backend_pool::{BackendProtocol, BackendSecurity, OriginKey},
    http_route_catalog::normalize_hostname,
    record_audit, AppState,
};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{
    body::{Body, Frame, Incoming, SizeHint},
    client::conn::http1 as client_http1,
    header::{self, HeaderName, HeaderValue},
    service::service_fn,
    Request, Response, StatusCode, Version,
};
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto as server_auto,
};
use linklake_core::{read_control_frame, write_control_frame, BoxedIo, ControlFrame};
use std::{
    collections::HashSet,
    convert::Infallible,
    future::Future,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, LazyLock,
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{copy_bidirectional, split, AsyncRead, AsyncWrite, ReadHalf, WriteHalf},
    net::TcpListener,
    sync::{mpsc, oneshot, watch, OwnedSemaphorePermit, Semaphore},
    time::{timeout, timeout_at, Instant},
};
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;

const CONNECTION_PAIR_TIMEOUT: Duration = Duration::from_secs(10);
const CONTROL_IDLE_TIMEOUT: Duration = Duration::from_secs(35);
const HTTP_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
const BACKEND_RESPONSE_TIMEOUT: Duration = Duration::from_secs(120);
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_HTTP_BUFFER_BYTES: usize = 64 * 1024;
const MAX_PUBLIC_HTTP_CONNECTIONS: usize = 2048;
const MAX_PUBLIC_HTTP2_STREAMS: u32 = 256;

static PUBLIC_HTTP_CONNECTION_PERMITS: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(MAX_PUBLIC_HTTP_CONNECTIONS)));

struct PublicHttpConnectionActivity {
    state: Arc<AppState>,
}

impl PublicHttpConnectionActivity {
    fn begin(state: Arc<AppState>) -> Self {
        state
            .metrics
            .public_http_active_connections
            .fetch_add(1, Ordering::Relaxed);
        Self { state }
    }
}

impl Drop for PublicHttpConnectionActivity {
    fn drop(&mut self) {
        self.state
            .metrics
            .public_http_active_connections
            .fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PublicScheme {
    Http,
    Https,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PublicProtocol {
    Auto,
    Http1,
    Http2,
}

impl PublicScheme {
    fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

pub(crate) struct HttpRouteRegistration {
    registration_id: Uuid,
    stop_tx: watch::Sender<()>,
    context: Arc<HttpRouteContext>,
}

#[derive(Default)]
pub(crate) struct HttpRouteStatistics {
    pub(crate) active_connections: AtomicUsize,
    pub(crate) requests_total: AtomicU64,
    pub(crate) failed_requests: AtomicU64,
    pub(crate) bytes_from_public: AtomicU64,
    pub(crate) bytes_to_public: AtomicU64,
    pub(crate) pairing_timeouts: AtomicU64,
    pub(crate) http2_active_streams: AtomicUsize,
    pub(crate) http2_requests_total: AtomicU64,
    pub(crate) grpc_active_streams: AtomicUsize,
    pub(crate) grpc_requests_total: AtomicU64,
    pub(crate) grpc_trailers_total: AtomicU64,
    pub(crate) grpc_failures_total: AtomicU64,
    pub(crate) grpc_cancellations_total: AtomicU64,
    pub(crate) http2_backend: Arc<Http2BackendCounters>,
}

struct HttpRouteContext {
    client_id: Uuid,
    policy_id: Uuid,
    command_tx: mpsc::Sender<ControlFrame>,
    stop: watch::Receiver<()>,
    permits: Arc<Semaphore>,
    statistics: Arc<HttpRouteStatistics>,
    http2_backend: Arc<Http2BackendPool>,
}

struct TrackedBody {
    inner: ProxyBody,
    _activity: Option<ConnectionActivity>,
    _backend_lease: Option<Http2BackendLease>,
    grpc: Option<GrpcBodyState>,
    stop: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
}

struct GrpcBodyState {
    statistics: Arc<HttpRouteStatistics>,
    status_seen: bool,
    failure_recorded: bool,
    completed: bool,
}

struct ConnectionActivity {
    state: Arc<AppState>,
    policy_id: Uuid,
    usage: Arc<AtomicU64>,
    statistics: Arc<HttpRouteStatistics>,
    http2: bool,
    grpc: bool,
    _route_permit: OwnedSemaphorePermit,
    _global_permit: OwnedSemaphorePermit,
}

#[derive(Clone, Copy)]
struct RequestProtocols {
    http2: bool,
    grpc: bool,
}

struct PendingConnectionGuard {
    state: Arc<AppState>,
    connection_id: Uuid,
}

impl TrackedBody {
    fn plain(status: StatusCode, message: &'static str) -> Response<Self> {
        Self::text(status, message.to_owned())
    }

    fn text(status: StatusCode, message: String) -> Response<Self> {
        let body = Full::new(Bytes::from(message))
            .map_err(|never| -> BoxError { match never {} })
            .boxed_unsync();
        Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(Self {
                inner: body,
                _activity: None,
                _backend_lease: None,
                grpc: None,
                stop: None,
            })
            .expect("static HTTP error response should build")
    }

    fn redirect(location: &str) -> Response<Self> {
        let body = Full::new(Bytes::new())
            .map_err(|never| -> BoxError { match never {} })
            .boxed_unsync();
        match HeaderValue::from_str(location) {
            Ok(location) => Response::builder()
                .status(StatusCode::PERMANENT_REDIRECT)
                .header(header::LOCATION, location)
                .body(Self {
                    inner: body,
                    _activity: None,
                    _backend_lease: None,
                    grpc: None,
                    stop: None,
                })
                .expect("HTTPS redirect response should build"),
            Err(_) => Self::plain(StatusCode::BAD_REQUEST, "invalid redirect target"),
        }
    }

    fn proxied(
        inner: ProxyBody,
        activity: Option<ConnectionActivity>,
        stop: Option<watch::Receiver<()>>,
        backend_lease: Option<Http2BackendLease>,
        grpc: Option<GrpcBodyState>,
    ) -> Self {
        let stop = stop.map(|mut stop| {
            Box::pin(async move {
                let _ = stop.changed().await;
            }) as Pin<Box<dyn Future<Output = ()> + Send>>
        });
        Self {
            inner,
            _activity: activity,
            _backend_lease: backend_lease,
            grpc,
            stop,
        }
    }
}

impl GrpcBodyState {
    fn new(statistics: Arc<HttpRouteStatistics>, response: &Response<Incoming>) -> Self {
        let mut state = Self {
            statistics,
            status_seen: false,
            failure_recorded: false,
            completed: false,
        };
        if response.status() != StatusCode::OK {
            state.record_failure();
        }
        if response.headers().contains_key("grpc-status") {
            state.record_trailers(response.headers());
        }
        state
    }

    fn record_trailers(&mut self, trailers: &hyper::HeaderMap) {
        if !self.status_seen {
            self.status_seen = true;
            self.statistics
                .grpc_trailers_total
                .fetch_add(1, Ordering::Relaxed);
        }
        if trailers
            .get("grpc-status")
            .and_then(|value| value.to_str().ok())
            != Some("0")
        {
            self.record_failure();
        }
    }

    fn record_failure(&mut self) {
        if !self.failure_recorded {
            self.failure_recorded = true;
            self.statistics
                .grpc_failures_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    fn finish(&mut self) {
        if !self.completed {
            self.completed = true;
            if !self.status_seen {
                self.record_failure();
            }
        }
    }

    fn fail(&mut self) {
        if !self.completed {
            self.completed = true;
            self.record_failure();
        }
    }

    fn cancel(&mut self) {
        if !self.completed {
            self.completed = true;
            self.statistics
                .grpc_cancellations_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl ConnectionActivity {
    fn new(
        state: Arc<AppState>,
        policy_id: Uuid,
        usage: Arc<AtomicU64>,
        statistics: Arc<HttpRouteStatistics>,
        protocols: RequestProtocols,
        route_permit: OwnedSemaphorePermit,
        global_permit: OwnedSemaphorePermit,
    ) -> Self {
        Self {
            state,
            policy_id,
            usage,
            statistics,
            http2: protocols.http2,
            grpc: protocols.grpc,
            _route_permit: route_permit,
            _global_permit: global_permit,
        }
    }
}

impl Body for TrackedBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if let Some(stop) = self.stop.as_mut() {
            if stop.as_mut().poll(context).is_ready() {
                self.stop = None;
                if let Some(grpc) = self.grpc.as_mut() {
                    grpc.cancel();
                }
                return Poll::Ready(None);
            }
        }
        let result = Pin::new(&mut self.inner).poll_frame(context);
        if let Some(grpc) = self.grpc.as_mut() {
            match &result {
                Poll::Ready(Some(Ok(frame))) => {
                    if let Some(trailers) = frame.trailers_ref() {
                        grpc.record_trailers(trailers);
                    }
                }
                Poll::Ready(Some(Err(_))) => grpc.fail(),
                Poll::Ready(None) => grpc.finish(),
                Poll::Pending => {}
            }
        }
        result
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for TrackedBody {
    fn drop(&mut self) {
        if let Some(grpc) = self.grpc.as_mut() {
            grpc.cancel();
        }
    }
}

impl Drop for ConnectionActivity {
    fn drop(&mut self) {
        self.statistics
            .active_connections
            .fetch_sub(1, Ordering::Relaxed);
        if self.http2 {
            self.statistics
                .http2_active_streams
                .fetch_sub(1, Ordering::Relaxed);
        }
        if self.grpc {
            self.statistics
                .grpc_active_streams
                .fetch_sub(1, Ordering::Relaxed);
        }
        let bytes = self.usage.load(Ordering::Relaxed);
        if let Err(error) = self
            .state
            .traffic_controls
            .lock()
            .expect("traffic control catalog lock poisoned")
            .record_bytes(
                TrafficPolicyKind::Http,
                self.policy_id,
                bytes,
                crate::unix_seconds(),
            )
        {
            tracing::warn!("Could not persist HTTP traffic usage: {error}");
        }
    }
}

impl Drop for PendingConnectionGuard {
    fn drop(&mut self) {
        if let Ok(mut pending) = self.state.pending_connections.try_lock() {
            pending.remove(&self.connection_id);
            return;
        }
        let state = self.state.clone();
        let connection_id = self.connection_id;
        tokio::spawn(async move {
            state
                .pending_connections
                .lock()
                .await
                .remove(&connection_id);
        });
    }
}

pub(crate) async fn run_http_listener(
    state: Arc<AppState>,
    listener: TcpListener,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        let accepted = tokio::select! {
            _ = shutdown.changed() => break,
            accepted = listener.accept() => accepted,
        };
        match accepted {
            Ok((stream, peer)) => {
                if !state.lifecycle.accepts_new_work() {
                    drop(stream);
                    continue;
                }
                let Ok(connection_permit) =
                    PUBLIC_HTTP_CONNECTION_PERMITS.clone().try_acquire_owned()
                else {
                    tracing::warn!("HTTP public connection limit reached; rejecting {peer}");
                    drop(stream);
                    continue;
                };
                let state = state.clone();
                tokio::spawn(async move {
                    let _connection_permit = connection_permit;
                    let _activity = PublicHttpConnectionActivity::begin(state.clone());
                    serve_http_connection(
                        state,
                        stream,
                        peer,
                        PublicScheme::Http,
                        PublicProtocol::Auto,
                        None,
                    )
                    .await;
                });
            }
            Err(error) => tracing::error!("HTTP listener accept error: {error}"),
        }
    }
}

pub(crate) async fn run_https_listener(
    state: Arc<AppState>,
    listener: TcpListener,
    acceptor: TlsAcceptor,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        let accepted = tokio::select! {
            _ = shutdown.changed() => break,
            accepted = listener.accept() => accepted,
        };
        match accepted {
            Ok((stream, peer)) => {
                if !state.lifecycle.accepts_new_work() {
                    drop(stream);
                    continue;
                }
                let Ok(connection_permit) =
                    PUBLIC_HTTP_CONNECTION_PERMITS.clone().try_acquire_owned()
                else {
                    tracing::warn!("HTTPS public connection limit reached; rejecting {peer}");
                    drop(stream);
                    continue;
                };
                let state = state.clone();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let _connection_permit = connection_permit;
                    let _activity = PublicHttpConnectionActivity::begin(state.clone());
                    let tls_stream =
                        match timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                            Ok(Ok(stream)) => stream,
                            Ok(Err(error)) => {
                                state
                                    .metrics
                                    .tls_handshake_failures_total
                                    .fetch_add(1, Ordering::Relaxed);
                                state
                                    .metrics
                                    .https_handshake_failures_total
                                    .fetch_add(1, Ordering::Relaxed);
                                tracing::debug!("HTTPS handshake failed for {peer}: {error}");
                                return;
                            }
                            Err(_) => {
                                state
                                    .metrics
                                    .tls_handshake_failures_total
                                    .fetch_add(1, Ordering::Relaxed);
                                state
                                    .metrics
                                    .https_handshake_failures_total
                                    .fetch_add(1, Ordering::Relaxed);
                                tracing::debug!("HTTPS handshake timed out for {peer}");
                                return;
                            }
                        };
                    let Some(server_name) =
                        tls_stream.get_ref().1.server_name().map(ToOwned::to_owned)
                    else {
                        return;
                    };
                    let protocol = match tls_stream.get_ref().1.alpn_protocol() {
                        Some(b"h2") => PublicProtocol::Http2,
                        Some(b"http/1.1") | None => PublicProtocol::Http1,
                        Some(protocol) => {
                            tracing::debug!(
                                alpn = %String::from_utf8_lossy(protocol),
                                "HTTPS connection negotiated an unsupported ALPN"
                            );
                            return;
                        }
                    };
                    state
                        .metrics
                        .https_active_connections
                        .fetch_add(1, Ordering::Relaxed);
                    serve_http_connection(
                        state.clone(),
                        tls_stream,
                        peer,
                        PublicScheme::Https,
                        protocol,
                        Some(server_name),
                    )
                    .await;
                    state
                        .metrics
                        .https_active_connections
                        .fetch_sub(1, Ordering::Relaxed);
                });
            }
            Err(error) => tracing::error!("HTTPS listener accept error: {error}"),
        }
    }
}

async fn serve_http_connection<S>(
    state: Arc<AppState>,
    stream: S,
    peer: SocketAddr,
    scheme: PublicScheme,
    protocol: PublicProtocol,
    tls_hostname: Option<String>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |request| {
        let state = state.clone();
        let tls_hostname = tls_hostname.clone();
        async move {
            Ok::<_, Infallible>(proxy_request(state, peer, scheme, tls_hostname, request).await)
        }
    });
    let mut builder = server_auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .keep_alive(true)
        .max_buf_size(MAX_HTTP_BUFFER_BYTES)
        .timer(TokioTimer::new())
        .header_read_timeout(Some(HTTP_HEADER_READ_TIMEOUT));
    builder
        .http2()
        .adaptive_window(true)
        .max_concurrent_streams(Some(MAX_PUBLIC_HTTP2_STREAMS))
        .keep_alive_interval(Some(Duration::from_secs(20)))
        .keep_alive_timeout(Duration::from_secs(10))
        .max_header_list_size(MAX_HTTP_BUFFER_BYTES as u32)
        .timer(TokioTimer::new());
    let result = match protocol {
        PublicProtocol::Auto => {
            builder
                .serve_connection_with_upgrades(TokioIo::new(stream), service)
                .await
        }
        PublicProtocol::Http1 => {
            builder
                .http1_only()
                .serve_connection_with_upgrades(TokioIo::new(stream), service)
                .await
        }
        PublicProtocol::Http2 => {
            builder
                .http2_only()
                .serve_connection(TokioIo::new(stream), service)
                .await
        }
    };
    if let Err(error) = result {
        tracing::debug!("HTTP public connection ended: {error}");
    }
}

async fn proxy_request(
    state: Arc<AppState>,
    peer: SocketAddr,
    scheme: PublicScheme,
    tls_hostname: Option<String>,
    mut request: Request<Incoming>,
) -> Response<TrackedBody> {
    let public_version = request.version();
    let public_http2 = public_version == Version::HTTP_2;
    if scheme == PublicScheme::Https {
        state
            .metrics
            .https_requests_total
            .fetch_add(1, Ordering::Relaxed);
    }
    let mut host_values = request.headers().get_all(header::HOST).iter();
    let host_header = match host_values.next() {
        Some(value) => match value.to_str() {
            Ok(value) => Some(value.trim().to_owned()),
            Err(_) => return TrackedBody::plain(StatusCode::BAD_REQUEST, "invalid Host header"),
        },
        None => None,
    };
    if host_values.next().is_some() {
        return TrackedBody::plain(StatusCode::BAD_REQUEST, "multiple Host headers");
    }
    let request_authority = request
        .uri()
        .authority()
        .map(|authority| authority.as_str().trim().to_owned());
    if let (Some(host), Some(authority)) = (&host_header, &request_authority) {
        let Ok(hostname) = normalize_hostname(host) else {
            return TrackedBody::plain(StatusCode::BAD_REQUEST, "invalid Host header");
        };
        let Ok(authority_hostname) = normalize_hostname(authority) else {
            return TrackedBody::plain(StatusCode::BAD_REQUEST, "invalid request authority");
        };
        if hostname != authority_hostname {
            return TrackedBody::plain(
                StatusCode::BAD_REQUEST,
                "request authority conflicts with Host",
            );
        }
    }
    let Some(original_host) = host_header.or(request_authority.clone()) else {
        return TrackedBody::plain(
            StatusCode::BAD_REQUEST,
            if public_http2 {
                "missing request authority"
            } else {
                "missing Host header"
            },
        );
    };
    let Ok(hostname) = normalize_hostname(&original_host) else {
        return TrackedBody::plain(StatusCode::BAD_REQUEST, "invalid Host header");
    };
    if scheme == PublicScheme::Https {
        let Some(tls_hostname) = tls_hostname
            .as_deref()
            .and_then(|value| normalize_hostname(value).ok())
        else {
            return TrackedBody::plain(StatusCode::MISDIRECTED_REQUEST, "missing TLS server name");
        };
        if tls_hostname != hostname {
            return TrackedBody::plain(
                StatusCode::MISDIRECTED_REQUEST,
                "TLS server name conflicts with Host",
            );
        }
        if !state
            .certificate_manager
            .as_ref()
            .is_some_and(|manager| manager.has_certificate(&hostname))
        {
            return TrackedBody::plain(
                StatusCode::MISDIRECTED_REQUEST,
                "HTTPS certificate is no longer active",
            );
        }
    }
    if scheme == PublicScheme::Http {
        if let Some(response) = acme_challenge_response(&state, &hostname, &request) {
            return response;
        }
    }
    if request.method() == hyper::Method::CONNECT {
        return TrackedBody::plain(StatusCode::METHOD_NOT_ALLOWED, "CONNECT is not supported");
    }
    if let Some(authority) = request_authority.as_deref() {
        let Ok(authority_hostname) = normalize_hostname(authority) else {
            return TrackedBody::plain(StatusCode::BAD_REQUEST, "invalid request authority");
        };
        if authority_hostname != hostname {
            return TrackedBody::plain(
                StatusCode::BAD_REQUEST,
                "request authority conflicts with Host",
            );
        }
    } else if request.uri().scheme().is_some() {
        return TrackedBody::plain(StatusCode::BAD_REQUEST, "invalid request target");
    }
    let native_grpc = is_native_grpc_request(&request);
    if native_grpc && !public_http2 {
        return TrackedBody::plain(
            StatusCode::HTTP_VERSION_NOT_SUPPORTED,
            "native gRPC requires HTTP/2",
        );
    }
    if scheme == PublicScheme::Http
        && state
            .https_redirect_hosts
            .lock()
            .expect("HTTPS redirect registry lock poisoned")
            .contains(&hostname)
        && state
            .certificate_manager
            .as_ref()
            .is_some_and(|manager| manager.has_certificate(&hostname))
    {
        let path_and_query = request
            .uri()
            .path_and_query()
            .map_or("/", |value| value.as_str());
        return TrackedBody::redirect(&format!("https://{hostname}{path_and_query}"));
    }
    let context = state
        .http_routes
        .lock()
        .expect("HTTP route registry lock poisoned")
        .get(&hostname)
        .map(|registration| registration.context.clone());
    let Some(context) = context else {
        let configured = state
            .http_route_catalog
            .lock()
            .expect("HTTP route catalog lock poisoned")
            .enabled_hostname_exists(&hostname)
            .unwrap_or(false);
        return if configured {
            TrackedBody::plain(StatusCode::SERVICE_UNAVAILABLE, "HTTP route is offline")
        } else {
            TrackedBody::plain(StatusCode::NOT_FOUND, "unknown HTTP route")
        };
    };
    let decision = state
        .traffic_controls
        .lock()
        .expect("traffic control catalog lock poisoned")
        .authorize(
            TrafficPolicyKind::Http,
            context.policy_id,
            peer.ip(),
            crate::unix_seconds(),
        );
    if !matches!(decision, Ok(TrafficDecision::Allowed)) {
        return TrackedBody::plain(
            StatusCode::FORBIDDEN,
            "HTTP traffic control rejected request",
        );
    }
    let Ok(route_permit) = context.permits.clone().try_acquire_owned() else {
        return TrackedBody::plain(StatusCode::SERVICE_UNAVAILABLE, "HTTP route is busy");
    };
    let Ok(global_permit) = state.global_connection_permits.clone().try_acquire_owned() else {
        return TrackedBody::plain(StatusCode::SERVICE_UNAVAILABLE, "LinkLake is busy");
    };
    context
        .statistics
        .active_connections
        .fetch_add(1, Ordering::Relaxed);
    context
        .statistics
        .requests_total
        .fetch_add(1, Ordering::Relaxed);
    if public_http2 {
        context
            .statistics
            .http2_active_streams
            .fetch_add(1, Ordering::Relaxed);
        context
            .statistics
            .http2_requests_total
            .fetch_add(1, Ordering::Relaxed);
    }
    if native_grpc {
        context
            .statistics
            .grpc_active_streams
            .fetch_add(1, Ordering::Relaxed);
        context
            .statistics
            .grpc_requests_total
            .fetch_add(1, Ordering::Relaxed);
    }
    let usage = Arc::new(AtomicU64::new(0));
    let activity = ConnectionActivity::new(
        state.clone(),
        context.policy_id,
        usage.clone(),
        context.statistics.clone(),
        RequestProtocols {
            http2: public_http2,
            grpc: native_grpc,
        },
        route_permit,
        global_permit,
    );

    let client_upgrade =
        (!public_http2 && is_upgrade_request(&request)).then(|| hyper::upgrade::on(&mut request));
    prepare_forward_headers(&mut request, peer, &original_host, scheme, native_grpc);
    if !request.headers().contains_key(header::HOST) {
        let Ok(host) = HeaderValue::from_str(&original_host) else {
            return TrackedBody::plain(StatusCode::BAD_REQUEST, "invalid Host header");
        };
        request.headers_mut().insert(header::HOST, host);
    }
    let Some(path_and_query) = request.uri().path_and_query().cloned() else {
        return TrackedBody::plain(StatusCode::BAD_REQUEST, "missing request path");
    };
    let backend_uri = if native_grpc {
        hyper::Uri::builder()
            .scheme("http")
            .authority(original_host.as_str())
            .path_and_query(path_and_query)
            .build()
    } else {
        hyper::Uri::builder().path_and_query(path_and_query).build()
    };
    let Ok(backend_uri) = backend_uri else {
        return TrackedBody::plain(StatusCode::BAD_REQUEST, "invalid request target");
    };
    *request.uri_mut() = backend_uri;
    *request.version_mut() = if native_grpc {
        Version::HTTP_2
    } else {
        Version::HTTP_11
    };
    let (parts, body) = request.into_parts();
    let request_statistics = context.statistics.clone();
    let request_usage = usage.clone();
    let body = body
        .inspect_frame(move |frame| {
            if let Some(data) = frame.data_ref() {
                request_statistics
                    .bytes_from_public
                    .fetch_add(data.len() as u64, Ordering::Relaxed);
                request_usage.fetch_add(data.len() as u64, Ordering::Relaxed);
            }
        })
        .map_err(|error| -> BoxError { Box::new(error) })
        .boxed_unsync();
    let request = Request::from_parts(parts, body);

    let (mut response, backend_lease) = if native_grpc {
        let statistics = context.statistics.clone();
        let pool = context.http2_backend.clone();
        let acquire = pool
            .acquire_or_connect(|| async {
                match request_client_stream(&state, &context).await {
                    Ok(stream) => Ok(stream),
                    Err(pairing_timeout) => {
                        if pairing_timeout {
                            statistics.pairing_timeouts.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(Box::new(std::io::Error::new(
                            if pairing_timeout {
                                std::io::ErrorKind::TimedOut
                            } else {
                                std::io::ErrorKind::ConnectionAborted
                            },
                            "LinkLake HTTP/2 backend data stream is unavailable",
                        )) as BoxError)
                    }
                }
            })
            .await;
        let mut lease = match acquire {
            Ok(lease) => lease,
            Err(error) => {
                tracing::warn!("HTTP/2 backend acquisition failed for {hostname}: {error}");
                context
                    .statistics
                    .failed_requests
                    .fetch_add(1, Ordering::Relaxed);
                context
                    .statistics
                    .grpc_failures_total
                    .fetch_add(1, Ordering::Relaxed);
                let status = if matches!(
                    error,
                    crate::http2_backend::Http2BackendAcquireError::CapacityBusy
                ) {
                    StatusCode::SERVICE_UNAVAILABLE
                } else {
                    StatusCode::BAD_GATEWAY
                };
                return TrackedBody::plain(status, "HTTP/2 backend is unavailable");
            }
        };
        let connection_id = lease.connection_id();
        let response = match timeout(BACKEND_RESPONSE_TIMEOUT, lease.send_request(request)).await {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => {
                tracing::warn!(
                    "HTTP/2 backend request failed for {hostname} on connection {connection_id}: {error}"
                );
                context
                    .statistics
                    .failed_requests
                    .fetch_add(1, Ordering::Relaxed);
                context
                    .statistics
                    .grpc_failures_total
                    .fetch_add(1, Ordering::Relaxed);
                return TrackedBody::plain(
                    StatusCode::BAD_GATEWAY,
                    "HTTP/2 backend request failed",
                );
            }
            Err(_) => {
                tracing::warn!(
                    "HTTP/2 backend response timed out for {hostname} on connection {connection_id}"
                );
                context
                    .statistics
                    .failed_requests
                    .fetch_add(1, Ordering::Relaxed);
                context
                    .statistics
                    .grpc_failures_total
                    .fetch_add(1, Ordering::Relaxed);
                return TrackedBody::plain(StatusCode::GATEWAY_TIMEOUT, "HTTP/2 backend timed out");
            }
        };
        (response, Some(lease))
    } else {
        let agent_stream = match request_client_stream(&state, &context).await {
            Ok(stream) => stream,
            Err(pairing_timeout) => {
                context
                    .statistics
                    .failed_requests
                    .fetch_add(1, Ordering::Relaxed);
                if pairing_timeout {
                    context
                        .statistics
                        .pairing_timeouts
                        .fetch_add(1, Ordering::Relaxed);
                }
                return TrackedBody::plain(StatusCode::BAD_GATEWAY, "HTTP backend is unavailable");
            }
        };
        let (mut sender, connection) = match timeout(
            CONNECTION_PAIR_TIMEOUT,
            client_http1::handshake(TokioIo::new(agent_stream)),
        )
        .await
        {
            Ok(Ok(connection)) => connection,
            Ok(Err(error)) => {
                tracing::warn!("HTTP backend handshake failed for {hostname}: {error}");
                context
                    .statistics
                    .failed_requests
                    .fetch_add(1, Ordering::Relaxed);
                return TrackedBody::plain(
                    StatusCode::BAD_GATEWAY,
                    "HTTP backend handshake failed",
                );
            }
            Err(_) => {
                context
                    .statistics
                    .failed_requests
                    .fetch_add(1, Ordering::Relaxed);
                return TrackedBody::plain(
                    StatusCode::GATEWAY_TIMEOUT,
                    "HTTP backend handshake timed out",
                );
            }
        };
        tokio::spawn(async move {
            if let Err(error) = connection.with_upgrades().await {
                tracing::debug!("HTTP backend connection ended: {error}");
            }
        });
        let response = match timeout(BACKEND_RESPONSE_TIMEOUT, sender.send_request(request)).await {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => {
                tracing::warn!("HTTP backend request failed for {hostname}: {error}");
                context
                    .statistics
                    .failed_requests
                    .fetch_add(1, Ordering::Relaxed);
                return TrackedBody::plain(StatusCode::BAD_GATEWAY, "HTTP backend request failed");
            }
            Err(_) => {
                tracing::warn!("HTTP backend response timed out for {hostname}");
                context
                    .statistics
                    .failed_requests
                    .fetch_add(1, Ordering::Relaxed);
                return TrackedBody::plain(StatusCode::GATEWAY_TIMEOUT, "HTTP backend timed out");
            }
        };
        (response, None)
    };
    clean_response_headers(&mut response);
    *response.version_mut() = public_version;
    let grpc = native_grpc.then(|| GrpcBodyState::new(context.statistics.clone(), &response));
    let mut activity = Some(activity);
    if response.status() == StatusCode::SWITCHING_PROTOCOLS {
        if let Some(client_upgrade) = client_upgrade {
            let backend_upgrade = hyper::upgrade::on(&mut response);
            let mut stop = context.stop.clone();
            let upgrade_activity = activity
                .take()
                .expect("HTTP upgrade should own the connection activity");
            tokio::spawn(async move {
                let _activity = upgrade_activity;
                let upgraded = tokio::select! {
                    _ = stop.changed() => return,
                    upgraded = async { tokio::join!(client_upgrade, backend_upgrade) } => upgraded,
                };
                let (Ok(client), Ok(backend)) = upgraded else {
                    return;
                };
                let mut client = TokioIo::new(client);
                let mut backend = TokioIo::new(backend);
                tokio::select! {
                    _ = stop.changed() => {}
                    _ = copy_bidirectional(&mut client, &mut backend) => {}
                }
            });
        } else {
            context
                .statistics
                .failed_requests
                .fetch_add(1, Ordering::Relaxed);
            return TrackedBody::plain(
                StatusCode::BAD_GATEWAY,
                "backend upgraded a non-upgrade request",
            );
        }
    }
    let response_statistics = context.statistics.clone();
    let response_usage = usage;
    let response = response.map(|body| {
        body.inspect_frame(move |frame| {
            if let Some(data) = frame.data_ref() {
                response_statistics
                    .bytes_to_public
                    .fetch_add(data.len() as u64, Ordering::Relaxed);
                response_usage.fetch_add(data.len() as u64, Ordering::Relaxed);
            }
        })
        .map_err(|error| -> BoxError { Box::new(error) })
        .boxed_unsync()
    });
    let stop = activity.as_ref().map(|_| context.stop.clone());
    response.map(|body| TrackedBody::proxied(body, activity, stop, backend_lease, grpc))
}

async fn request_client_stream(
    state: &Arc<AppState>,
    context: &HttpRouteContext,
) -> Result<BoxedIo, bool> {
    let Ok(_pending_permit) = state.pending_connection_permits.clone().try_acquire_owned() else {
        return Err(false);
    };
    let connection_id = Uuid::new_v4();
    let (data_tx, data_rx) = oneshot::channel();
    state
        .pending_connections
        .lock()
        .await
        .insert(connection_id, (context.client_id, data_tx));
    let _pending_guard = PendingConnectionGuard {
        state: state.clone(),
        connection_id,
    };
    let mut stop = context.stop.clone();
    let deadline = Instant::now() + CONNECTION_PAIR_TIMEOUT;
    let send_result = tokio::select! {
        _ = stop.changed() => return Err(false),
        result = timeout_at(
            deadline,
            context.command_tx.send(ControlFrame::OpenTcpConnection { connection_id }),
        ) => result,
    };
    match send_result {
        Ok(Ok(())) => {}
        Ok(Err(_)) => return Err(false),
        Err(_) => return Err(true),
    }
    let result = tokio::select! {
        _ = stop.changed() => return Err(false),
        result = timeout_at(deadline, data_rx) => result,
    };
    match result {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(_)) => Err(false),
        Err(_) => Err(true),
    }
}

pub(crate) async fn register_route(
    state: Arc<AppState>,
    mut stream: BoxedIo,
    client_id: Uuid,
    client_token: String,
    name: String,
    hostname: String,
    target_addr: String,
) {
    if !authenticated_client(&state, client_id, &client_token) {
        state
            .metrics
            .authentication_failures_total
            .fetch_add(1, Ordering::Relaxed);
        state
            .metrics
            .registration_rejections_total
            .fetch_add(1, Ordering::Relaxed);
        send_error(&mut stream, "invalid client credentials").await;
        return;
    }
    let Ok(hostname) = normalize_hostname(&hostname) else {
        send_error(&mut stream, "invalid HTTP route hostname").await;
        return;
    };
    let runtime_policy = state
        .http_route_catalog
        .lock()
        .expect("HTTP route catalog lock poisoned")
        .runtime_policy(client_id, &name, &hostname, &target_addr)
        .unwrap_or(None);
    let Some(runtime_policy) = runtime_policy else {
        state
            .metrics
            .registration_rejections_total
            .fetch_add(1, Ordering::Relaxed);
        send_error(
            &mut stream,
            "no enabled management policy matches this HTTP route",
        )
        .await;
        return;
    };
    let registration_id = Uuid::new_v4();
    let (command_tx, command_rx) = mpsc::channel(64);
    let (stop_tx, stop_rx) = watch::channel(());
    let statistics = {
        let mut statistics = state
            .http_route_statistics
            .lock()
            .expect("HTTP route statistics lock poisoned");
        statistics
            .entry(hostname.clone())
            .or_insert_with(|| Arc::new(HttpRouteStatistics::default()))
            .clone()
    };
    let origin = OriginKey::new(
        runtime_policy.policy_id,
        &format!("{hostname}:80"),
        BackendProtocol::Http2,
        BackendSecurity::Plaintext,
    )
    .expect("validated HTTP hostname must form a backend origin");
    let http2_backend = Http2BackendPool::new(
        origin,
        runtime_policy.max_connections,
        statistics.http2_backend.clone(),
    );
    let context = Arc::new(HttpRouteContext {
        client_id,
        policy_id: runtime_policy.policy_id,
        command_tx,
        stop: stop_rx.clone(),
        permits: Arc::new(Semaphore::new(runtime_policy.max_connections)),
        statistics,
        http2_backend,
    });
    if let Some(previous) = state
        .http_routes
        .lock()
        .expect("HTTP route registry lock poisoned")
        .insert(
            hostname.clone(),
            HttpRouteRegistration {
                registration_id,
                stop_tx,
                context,
            },
        )
    {
        previous.context.http2_backend.invalidate();
        let _ = previous.stop_tx.send(());
    }
    state
        .metrics
        .tunnel_registrations_total
        .fetch_add(1, Ordering::Relaxed);
    if !state
        .seen_http_route_registrations
        .lock()
        .expect("seen HTTP route registrations lock poisoned")
        .insert((client_id, hostname.clone()))
    {
        state
            .metrics
            .tunnel_reconnects_total
            .fetch_add(1, Ordering::Relaxed);
    }
    record_audit(
        &state,
        "http_route.registered",
        &client_id.to_string(),
        &format!("name={name}; hostname={hostname}; target={target_addr}"),
    );
    let (reader, mut writer) = split(stream);
    if write_control_frame(
        &mut writer,
        &ControlFrame::HttpRouteRegistered {
            hostname: hostname.clone(),
        },
    )
    .await
    .is_err()
    {
        remove_route(&state, &hostname, registration_id);
        return;
    }
    run_registered_control(
        state,
        hostname,
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
    hostname: String,
    registration_id: Uuid,
    mut reader: ReadHalf<BoxedIo>,
    mut writer: WriteHalf<BoxedIo>,
    mut commands: mpsc::Receiver<ControlFrame>,
    mut stop: watch::Receiver<()>,
) {
    let (frames_tx, mut frames_rx) = mpsc::channel(16);
    let reader_task = tokio::spawn(async move {
        loop {
            let Ok(frame) = read_control_frame(&mut reader).await else {
                break;
            };
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
                Some(_) => {},
                None => break,
            },
            frame = frames_rx.recv() => match frame {
                Some(ControlFrame::ControlHeartbeat { nonce }) => {
                    idle_timeout.as_mut().reset(Instant::now() + CONTROL_IDLE_TIMEOUT);
                    if write_control_frame(
                        &mut writer,
                        &ControlFrame::ControlHeartbeatAck { nonce },
                    )
                    .await
                    .is_err()
                    {
                        break;
                    }
                }
                Some(_) => break,
                None => break,
            }
        }
    }
    reader_task.abort();
    remove_route(&state, &hostname, registration_id);
}

fn authenticated_client(state: &AppState, client_id: Uuid, token: &str) -> bool {
    let mut clients = state.clients.lock().expect("client registry lock poisoned");
    matches!(
        clients.authenticate_and_touch(client_id, token),
        Ok(Authentication::Authenticated)
    )
}

fn remove_route(state: &AppState, hostname: &str, registration_id: Uuid) {
    let mut routes = state
        .http_routes
        .lock()
        .expect("HTTP route registry lock poisoned");
    if routes
        .get(hostname)
        .is_some_and(|registration| registration.registration_id == registration_id)
    {
        if let Some(route) = routes.remove(hostname) {
            route.context.http2_backend.invalidate();
            let _ = route.stop_tx.send(());
        }
    }
}

pub(crate) fn stop_hostname(state: &AppState, hostname: &str) {
    if let Some(route) = state
        .http_routes
        .lock()
        .expect("HTTP route registry lock poisoned")
        .remove(hostname)
    {
        route.context.http2_backend.invalidate();
        let _ = route.stop_tx.send(());
    }
}

pub(crate) fn stop_all(state: &AppState) {
    let routes = state
        .http_routes
        .lock()
        .expect("HTTP route registry lock poisoned")
        .drain()
        .map(|(_, route)| route)
        .collect::<Vec<_>>();
    for route in routes {
        route.context.http2_backend.invalidate();
        let _ = route.stop_tx.send(());
    }
}

fn acme_challenge_response(
    state: &AppState,
    hostname: &str,
    request: &Request<Incoming>,
) -> Option<Response<TrackedBody>> {
    let token = request
        .uri()
        .path()
        .strip_prefix("/.well-known/acme-challenge/")?;
    if request.method() != hyper::Method::GET && request.method() != hyper::Method::HEAD {
        return Some(TrackedBody::plain(
            StatusCode::METHOD_NOT_ALLOWED,
            "ACME challenge only supports GET and HEAD",
        ));
    }
    if token.is_empty() || token.contains('/') {
        return Some(TrackedBody::plain(
            StatusCode::NOT_FOUND,
            "unknown ACME challenge",
        ));
    }
    let key_authorization = state
        .certificate_manager
        .as_ref()
        .and_then(|manager| manager.challenges().lookup(hostname, token));
    match key_authorization {
        Some(_) if request.method() == hyper::Method::HEAD => {
            Some(TrackedBody::text(StatusCode::OK, String::new()))
        }
        Some(value) => Some(TrackedBody::text(StatusCode::OK, value)),
        None => Some(TrackedBody::plain(
            StatusCode::NOT_FOUND,
            "unknown ACME challenge",
        )),
    }
}

fn prepare_forward_headers<B>(
    request: &mut Request<B>,
    peer: SocketAddr,
    original_host: &str,
    scheme: PublicScheme,
    preserve_te_trailers: bool,
) {
    let client_ip = if scheme == PublicScheme::Http {
        trusted_client_ip(request, peer)
    } else {
        peer.ip()
    };
    let forwarded_proto = if scheme == PublicScheme::Http {
        trusted_forwarded_proto(request, peer)
    } else {
        scheme.as_str()
    };
    let preserve_upgrade = is_upgrade_request(request);
    remove_hop_by_hop_headers(
        request.headers_mut(),
        preserve_upgrade,
        preserve_te_trailers,
    );
    for name in [
        "forwarded",
        "x-real-ip",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
    ] {
        request.headers_mut().remove(name);
    }
    if let Ok(value) = HeaderValue::from_str(&client_ip.to_string()) {
        request
            .headers_mut()
            .insert("x-forwarded-for", value.clone());
        request.headers_mut().insert("x-real-ip", value);
    }
    if let Ok(value) = HeaderValue::from_str(original_host) {
        request.headers_mut().insert("x-forwarded-host", value);
    }
    request.headers_mut().insert(
        "x-forwarded-proto",
        HeaderValue::from_static(forwarded_proto),
    );
}

fn trusted_client_ip<B>(request: &Request<B>, peer: SocketAddr) -> IpAddr {
    if peer.ip().is_loopback() {
        if let Some(ip) = request
            .headers()
            .get("x-real-ip")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse().ok())
        {
            return ip;
        }
    }
    peer.ip()
}

fn trusted_forwarded_proto<B>(request: &Request<B>, peer: SocketAddr) -> &'static str {
    if peer.ip().is_loopback()
        && request
            .headers()
            .get("x-forwarded-proto")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.eq_ignore_ascii_case("https"))
    {
        "https"
    } else {
        "http"
    }
}

fn clean_response_headers(response: &mut Response<Incoming>) {
    let upgrade = response.status() == StatusCode::SWITCHING_PROTOCOLS;
    let preserve_te_trailers = response.version() == Version::HTTP_2;
    remove_hop_by_hop_headers(response.headers_mut(), upgrade, preserve_te_trailers);
}

fn remove_hop_by_hop_headers(
    headers: &mut hyper::HeaderMap,
    preserve_upgrade: bool,
    preserve_te_trailers: bool,
) {
    let connection_headers = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|value| HeaderName::from_bytes(value.trim().as_bytes()).ok())
        .collect::<HashSet<_>>();
    for name in connection_headers {
        if preserve_upgrade && name == header::UPGRADE {
            continue;
        }
        headers.remove(name);
    }
    for name in [
        header::PROXY_AUTHENTICATE,
        header::PROXY_AUTHORIZATION,
        header::TRANSFER_ENCODING,
    ] {
        headers.remove(name);
    }
    if preserve_te_trailers {
        let valid_te = headers
            .get_all(header::TE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .all(|value| value.trim().eq_ignore_ascii_case("trailers"));
        if !valid_te {
            headers.remove(header::TE);
        }
    } else {
        headers.remove(header::TE);
        headers.remove(header::TRAILER);
    }
    headers.remove("proxy-connection");
    headers.remove("keep-alive");
    if !preserve_upgrade {
        headers.remove(header::CONNECTION);
        headers.remove(header::UPGRADE);
    }
}

fn is_native_grpc_request<B>(request: &Request<B>) -> bool {
    request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(';').next().unwrap_or_default().trim())
        .is_some_and(|value| {
            value.eq_ignore_ascii_case("application/grpc")
                || value.to_ascii_lowercase().starts_with("application/grpc+")
        })
}

fn is_upgrade_request<B>(request: &Request<B>) -> bool {
    request.headers().contains_key(header::UPGRADE)
        && request
            .headers()
            .get_all(header::CONNECTION)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .any(|value| value.trim().eq_ignore_ascii_case("upgrade"))
}

async fn send_error(stream: &mut BoxedIo, message: &str) {
    let _ = write_control_frame(
        stream,
        &ControlFrame::Error {
            message: message.to_owned(),
        },
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_proxy_body() -> ProxyBody {
        Full::new(Bytes::new())
            .map_err(|never| -> BoxError { match never {} })
            .boxed_unsync()
    }

    #[test]
    fn native_grpc_detection_excludes_grpc_web() {
        for content_type in [
            "application/grpc",
            "application/grpc+proto",
            "Application/GRPC+json; charset=utf-8",
        ] {
            let request = Request::builder()
                .header(header::CONTENT_TYPE, content_type)
                .body(())
                .expect("test request should build");
            assert!(is_native_grpc_request(&request));
        }
        for content_type in [
            "application/grpc-web",
            "application/grpc-web+proto",
            "application/json",
        ] {
            let request = Request::builder()
                .header(header::CONTENT_TYPE, content_type)
                .body(())
                .expect("test request should build");
            assert!(!is_native_grpc_request(&request));
        }
    }

    #[test]
    fn http2_header_cleanup_preserves_only_te_trailers() {
        let mut valid = hyper::HeaderMap::new();
        valid.insert(header::TE, HeaderValue::from_static("trailers"));
        valid.insert(header::TRAILER, HeaderValue::from_static("grpc-status"));
        valid.insert(
            header::TRANSFER_ENCODING,
            HeaderValue::from_static("chunked"),
        );
        remove_hop_by_hop_headers(&mut valid, false, true);
        assert_eq!(
            valid.get(header::TE),
            Some(&HeaderValue::from_static("trailers"))
        );
        assert_eq!(
            valid.get(header::TRAILER),
            Some(&HeaderValue::from_static("grpc-status"))
        );
        assert!(!valid.contains_key(header::TRANSFER_ENCODING));

        let mut invalid = hyper::HeaderMap::new();
        invalid.insert(header::TE, HeaderValue::from_static("trailers, deflate"));
        invalid.insert(header::CONNECTION, HeaderValue::from_static("keep-alive"));
        invalid.insert("keep-alive", HeaderValue::from_static("timeout=5"));
        remove_hop_by_hop_headers(&mut invalid, false, true);
        assert!(!invalid.contains_key(header::TE));
        assert!(!invalid.contains_key(header::CONNECTION));
        assert!(!invalid.contains_key("keep-alive"));
    }

    #[test]
    fn grpc_terminal_status_and_cancellation_are_counted_once() {
        let success_statistics = Arc::new(HttpRouteStatistics::default());
        let mut success = GrpcBodyState {
            statistics: success_statistics.clone(),
            status_seen: false,
            failure_recorded: false,
            completed: false,
        };
        let mut success_trailers = hyper::HeaderMap::new();
        success_trailers.insert("grpc-status", HeaderValue::from_static("0"));
        success.record_trailers(&success_trailers);
        success.finish();
        success.cancel();
        assert_eq!(
            success_statistics
                .grpc_trailers_total
                .load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            success_statistics
                .grpc_failures_total
                .load(Ordering::Relaxed),
            0
        );
        assert_eq!(
            success_statistics
                .grpc_cancellations_total
                .load(Ordering::Relaxed),
            0
        );

        let cancellation_statistics = Arc::new(HttpRouteStatistics::default());
        let body = TrackedBody {
            inner: empty_proxy_body(),
            _activity: None,
            _backend_lease: None,
            grpc: Some(GrpcBodyState {
                statistics: cancellation_statistics.clone(),
                status_seen: false,
                failure_recorded: false,
                completed: false,
            }),
            stop: None,
        };
        drop(body);
        assert_eq!(
            cancellation_statistics
                .grpc_cancellations_total
                .load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            cancellation_statistics
                .grpc_failures_total
                .load(Ordering::Relaxed),
            0
        );
    }
}
