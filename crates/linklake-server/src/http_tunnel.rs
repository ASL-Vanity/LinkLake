use crate::{
    client_registry::Authentication, http_route_catalog::normalize_hostname, record_audit, AppState,
};
use bytes::Bytes;
use http_body_util::{combinators::UnsyncBoxBody, BodyExt, Full};
use hyper::{
    body::{Body, Frame, Incoming, SizeHint},
    client::conn::http1 as client_http1,
    header::{self, HeaderName, HeaderValue},
    server::conn::http1 as server_http1,
    service::service_fn,
    Request, Response, StatusCode,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use linklake_core::{read_control_frame, write_control_frame, BoxedIo, ControlFrame};
use std::{
    collections::HashSet,
    convert::Infallible,
    error::Error,
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
    io::{copy_bidirectional, split, ReadHalf, WriteHalf},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot, watch, OwnedSemaphorePermit, Semaphore},
    time::{timeout, timeout_at, Instant},
};
use uuid::Uuid;

const CONNECTION_PAIR_TIMEOUT: Duration = Duration::from_secs(10);
const CONTROL_IDLE_TIMEOUT: Duration = Duration::from_secs(35);
const HTTP_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
const BACKEND_RESPONSE_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_HTTP_BUFFER_BYTES: usize = 64 * 1024;
const MAX_PUBLIC_HTTP_CONNECTIONS: usize = 2048;

static PUBLIC_HTTP_CONNECTION_PERMITS: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(MAX_PUBLIC_HTTP_CONNECTIONS)));

type BoxError = Box<dyn Error + Send + Sync>;
type ProxyBody = UnsyncBoxBody<Bytes, BoxError>;

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
}

struct HttpRouteContext {
    client_id: Uuid,
    command_tx: mpsc::Sender<ControlFrame>,
    stop: watch::Receiver<()>,
    permits: Arc<Semaphore>,
    statistics: Arc<HttpRouteStatistics>,
}

struct TrackedBody {
    inner: ProxyBody,
    _activity: Option<ConnectionActivity>,
    stop: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
}

struct ConnectionActivity {
    statistics: Arc<HttpRouteStatistics>,
    _route_permit: OwnedSemaphorePermit,
    _global_permit: OwnedSemaphorePermit,
}

struct PendingConnectionGuard {
    state: Arc<AppState>,
    connection_id: Uuid,
}

impl TrackedBody {
    fn plain(status: StatusCode, message: &'static str) -> Response<Self> {
        let body = Full::new(Bytes::from_static(message.as_bytes()))
            .map_err(|never| -> BoxError { match never {} })
            .boxed_unsync();
        Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(Self {
                inner: body,
                _activity: None,
                stop: None,
            })
            .expect("static HTTP error response should build")
    }

    fn proxied(
        inner: ProxyBody,
        activity: Option<ConnectionActivity>,
        stop: Option<watch::Receiver<()>>,
    ) -> Self {
        let stop = stop.map(|mut stop| {
            Box::pin(async move {
                let _ = stop.changed().await;
            }) as Pin<Box<dyn Future<Output = ()> + Send>>
        });
        Self {
            inner,
            _activity: activity,
            stop,
        }
    }
}

impl ConnectionActivity {
    fn new(
        statistics: Arc<HttpRouteStatistics>,
        route_permit: OwnedSemaphorePermit,
        global_permit: OwnedSemaphorePermit,
    ) -> Self {
        Self {
            statistics,
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
                return Poll::Ready(None);
            }
        }
        Pin::new(&mut self.inner).poll_frame(context)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for ConnectionActivity {
    fn drop(&mut self) {
        self.statistics
            .active_connections
            .fetch_sub(1, Ordering::Relaxed);
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
                    serve_http_connection(state, stream, peer).await;
                });
            }
            Err(error) => tracing::error!("HTTP listener accept error: {error}"),
        }
    }
}

async fn serve_http_connection(state: Arc<AppState>, stream: TcpStream, peer: SocketAddr) {
    let service = service_fn(move |request| {
        let state = state.clone();
        async move { Ok::<_, Infallible>(proxy_request(state, peer, request).await) }
    });
    let mut builder = server_http1::Builder::new();
    builder
        .keep_alive(true)
        .max_buf_size(MAX_HTTP_BUFFER_BYTES)
        .timer(TokioTimer::new())
        .header_read_timeout(HTTP_HEADER_READ_TIMEOUT);
    if let Err(error) = builder
        .serve_connection(TokioIo::new(stream), service)
        .with_upgrades()
        .await
    {
        tracing::debug!("HTTP public connection ended: {error}");
    }
}

async fn proxy_request(
    state: Arc<AppState>,
    peer: SocketAddr,
    mut request: Request<Incoming>,
) -> Response<TrackedBody> {
    let mut host_values = request.headers().get_all(header::HOST).iter();
    let Some(host) = host_values.next().and_then(|value| value.to_str().ok()) else {
        return TrackedBody::plain(StatusCode::BAD_REQUEST, "missing Host header");
    };
    if host_values.next().is_some() {
        return TrackedBody::plain(StatusCode::BAD_REQUEST, "multiple Host headers");
    }
    let original_host = host.trim().to_owned();
    let Ok(hostname) = normalize_hostname(&original_host) else {
        return TrackedBody::plain(StatusCode::BAD_REQUEST, "invalid Host header");
    };
    if request.method() == hyper::Method::CONNECT {
        return TrackedBody::plain(StatusCode::METHOD_NOT_ALLOWED, "CONNECT is not supported");
    }
    if let Some(authority) = request.uri().authority() {
        let Ok(authority_hostname) = normalize_hostname(authority.as_str()) else {
            return TrackedBody::plain(StatusCode::BAD_REQUEST, "invalid request authority");
        };
        if authority_hostname != hostname {
            return TrackedBody::plain(
                StatusCode::BAD_REQUEST,
                "request authority conflicts with Host",
            );
        }
        let Some(path_and_query) = request.uri().path_and_query().cloned() else {
            return TrackedBody::plain(StatusCode::BAD_REQUEST, "missing request path");
        };
        let Ok(origin_form) = hyper::Uri::builder().path_and_query(path_and_query).build() else {
            return TrackedBody::plain(StatusCode::BAD_REQUEST, "invalid request target");
        };
        *request.uri_mut() = origin_form;
    } else if request.uri().scheme().is_some() {
        return TrackedBody::plain(StatusCode::BAD_REQUEST, "invalid request target");
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
    let activity = ConnectionActivity::new(context.statistics.clone(), route_permit, global_permit);

    let client_upgrade = is_upgrade_request(&request).then(|| hyper::upgrade::on(&mut request));
    prepare_forward_headers(&mut request, peer, &original_host);
    let (parts, body) = request.into_parts();
    let request_statistics = context.statistics.clone();
    let body = body.inspect_frame(move |frame| {
        if let Some(data) = frame.data_ref() {
            request_statistics
                .bytes_from_public
                .fetch_add(data.len() as u64, Ordering::Relaxed);
        }
    });
    let request = Request::from_parts(parts, body);

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
    let (mut sender, connection) = match client_http1::handshake(TokioIo::new(agent_stream)).await {
        Ok(connection) => connection,
        Err(error) => {
            tracing::warn!("HTTP backend handshake failed for {hostname}: {error}");
            context
                .statistics
                .failed_requests
                .fetch_add(1, Ordering::Relaxed);
            return TrackedBody::plain(StatusCode::BAD_GATEWAY, "HTTP backend handshake failed");
        }
    };
    tokio::spawn(async move {
        if let Err(error) = connection.with_upgrades().await {
            tracing::debug!("HTTP backend connection ended: {error}");
        }
    });
    let mut response = match timeout(BACKEND_RESPONSE_TIMEOUT, sender.send_request(request)).await {
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
    clean_response_headers(&mut response);
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
    let response = response.map(|body| {
        body.inspect_frame(move |frame| {
            if let Some(data) = frame.data_ref() {
                response_statistics
                    .bytes_to_public
                    .fetch_add(data.len() as u64, Ordering::Relaxed);
            }
        })
        .map_err(|error| -> BoxError { Box::new(error) })
        .boxed_unsync()
    });
    let stop = activity.as_ref().map(|_| context.stop.clone());
    response.map(|body| TrackedBody::proxied(body, activity, stop))
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
    let context = Arc::new(HttpRouteContext {
        client_id,
        command_tx,
        stop: stop_rx.clone(),
        permits: Arc::new(Semaphore::new(runtime_policy.max_connections)),
        statistics,
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
        let _ = route.stop_tx.send(());
    }
}

fn prepare_forward_headers(request: &mut Request<Incoming>, peer: SocketAddr, original_host: &str) {
    let client_ip = trusted_client_ip(request, peer);
    let forwarded_proto = trusted_forwarded_proto(request, peer);
    let preserve_upgrade = is_upgrade_request(request);
    remove_hop_by_hop_headers(request.headers_mut(), preserve_upgrade);
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

fn trusted_client_ip(request: &Request<Incoming>, peer: SocketAddr) -> IpAddr {
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

fn trusted_forwarded_proto(request: &Request<Incoming>, peer: SocketAddr) -> &'static str {
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
    remove_hop_by_hop_headers(response.headers_mut(), upgrade);
}

fn remove_hop_by_hop_headers(headers: &mut hyper::HeaderMap, preserve_upgrade: bool) {
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
        header::TE,
        header::TRAILER,
        header::TRANSFER_ENCODING,
    ] {
        headers.remove(name);
    }
    headers.remove("proxy-connection");
    headers.remove("keep-alive");
    if !preserve_upgrade {
        headers.remove(header::CONNECTION);
        headers.remove(header::UPGRADE);
    }
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
