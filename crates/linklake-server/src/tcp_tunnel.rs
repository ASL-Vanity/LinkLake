use crate::traffic_control::{TrafficDecision, TrafficPolicyKind};
use crate::{client_registry::Authentication, record_audit, AppState};
use linklake_core::{
    read_control_frame, write_control_frame, write_control_frame_and_shutdown, BoxedIo,
    ControlFrame, ManagedConfigMode, ManagedConfigStatus,
};
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot, watch, Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore},
    time::{sleep_until, timeout, Instant},
};
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;

const CONNECTION_PAIR_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECTION_MAX_LIFETIME: Duration = Duration::from_secs(2 * 60 * 60);
const CONTROL_IDLE_TIMEOUT: Duration = Duration::from_secs(35);

pub(crate) struct TunnelRegistration {
    registration_id: Uuid,
    stop_tx: watch::Sender<()>,
}

#[derive(Default)]
pub(crate) struct TunnelStatistics {
    pub(crate) active_connections: AtomicUsize,
    pub(crate) rejected_connections: AtomicU64,
    pub(crate) rejected_policy_limit: AtomicU64,
    pub(crate) rejected_global_limit: AtomicU64,
    pub(crate) rejected_pending_limit: AtomicU64,
    pub(crate) bytes_from_public: AtomicU64,
    pub(crate) bytes_to_public: AtomicU64,
    pub(crate) failed_connections: AtomicU64,
    pub(crate) pairing_timeouts: AtomicU64,
    pub(crate) transfer_errors: AtomicU64,
    pub(crate) lifetime_timeouts: AtomicU64,
}

pub(crate) struct BandwidthLimiter {
    bytes_per_second: u64,
    next_available: AsyncMutex<Instant>,
}

#[derive(Clone)]
struct PublicConnectionContext {
    state: Arc<AppState>,
    command_tx: mpsc::Sender<ControlFrame>,
    client_id: Uuid,
    policy_id: Uuid,
    policy_kind: TrafficPolicyKind,
    permits: Arc<Semaphore>,
    statistics: Arc<TunnelStatistics>,
    bandwidth_limiter: Option<Arc<BandwidthLimiter>>,
    global_permits: Arc<Semaphore>,
}

impl BandwidthLimiter {
    pub(crate) fn new(bytes_per_second: u64) -> Self {
        Self {
            bytes_per_second,
            next_available: AsyncMutex::new(Instant::now()),
        }
    }

    pub(crate) async fn reserve(&self, bytes: usize) {
        let duration = Duration::from_secs_f64(bytes as f64 / self.bytes_per_second as f64);
        let start = {
            let mut next_available = self.next_available.lock().await;
            let now = Instant::now();
            let start = (*next_available).max(now);
            *next_available = start + duration;
            start
        };
        sleep_until(start).await;
    }

    /// UDP 数据报不能像 TCP 一样等待带宽令牌，否则会在内存中形成排队。
    /// 这里与 TCP 共用同一个预约时钟：当前策略已有待发送流量时直接拒绝数据报。
    pub(crate) async fn try_reserve_datagram(&self, bytes: usize) -> bool {
        let duration = Duration::from_secs_f64(bytes as f64 / self.bytes_per_second as f64);
        let mut next_available = self.next_available.lock().await;
        let now = Instant::now();
        if *next_available > now {
            return false;
        }
        *next_available = now + duration;
        true
    }
}

pub(crate) async fn run_control_listener(
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
            Ok((stream, source)) => {
                state
                    .metrics
                    .control_connections_total
                    .fetch_add(1, Ordering::Relaxed);
                let state = state.clone();
                tokio::spawn(
                    async move { handle_connection(state, Box::new(stream), source).await },
                );
            }
            Err(error) => tracing::error!("TCP control listener accept error: {error}"),
        }
    }
}

pub(crate) async fn run_tls_control_listener(
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
            Ok((stream, source)) => {
                state
                    .metrics
                    .control_connections_total
                    .fetch_add(1, Ordering::Relaxed);
                let state = state.clone();
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            handle_connection(state, Box::new(tls_stream), source).await
                        }
                        Err(error) => {
                            state
                                .metrics
                                .tls_handshake_failures_total
                                .fetch_add(1, Ordering::Relaxed);
                            tracing::warn!("TLS control handshake failed: {error}");
                        }
                    }
                });
            }
            Err(error) => tracing::error!("TLS control listener accept error: {error}"),
        }
    }
}

pub(crate) async fn handle_connection(
    state: Arc<AppState>,
    mut stream: BoxedIo,
    source: SocketAddr,
) {
    let frame = match read_control_frame(&mut stream).await {
        Ok(frame) => frame,
        Err(error) => {
            state
                .metrics
                .control_protocol_errors_total
                .fetch_add(1, Ordering::Relaxed);
            tracing::warn!("Invalid TCP control connection: {error}");
            return;
        }
    };
    match frame {
        ControlFrame::RequestManagedConfig {
            client_id,
            client_token,
            mode,
            applied_revision,
            status,
            error,
        } => {
            send_managed_config(
                state,
                stream,
                client_id,
                client_token,
                mode,
                applied_revision,
                status,
                error,
            )
            .await;
        }
        ControlFrame::RegisterTcpTunnel {
            client_id,
            client_token,
            name,
            public_port,
            target_addr,
        } => {
            register_tunnel(
                state,
                stream,
                client_id,
                client_token,
                name,
                public_port,
                target_addr,
            )
            .await;
        }
        ControlFrame::RegisterSecretTunnel {
            client_id,
            client_token,
            name,
            target_addr,
        } => {
            crate::secret_tunnel::register_provider(
                state,
                stream,
                client_id,
                client_token,
                name,
                target_addr,
            )
            .await;
        }
        ControlFrame::ConnectSecretTunnel {
            client_id,
            client_token,
            access_key,
        } => {
            crate::secret_tunnel::connect_visitor(
                state,
                stream,
                client_id,
                client_token,
                access_key,
                source.ip(),
            )
            .await;
        }
        ControlFrame::RegisterSocks5Proxy {
            client_id,
            client_token,
            name,
            public_port,
        } => {
            crate::socks5_tunnel::register_proxy(
                state,
                stream,
                client_id,
                client_token,
                name,
                public_port,
            )
            .await;
        }
        ControlFrame::RegisterHttpProxy {
            client_id,
            client_token,
            name,
            public_port,
        } => {
            crate::http_proxy_tunnel::register_proxy(
                state,
                stream,
                client_id,
                client_token,
                name,
                public_port,
            )
            .await;
        }
        ControlFrame::RegisterHttpRoute {
            client_id,
            client_token,
            name,
            hostname,
            target_addr,
        } => {
            crate::http_tunnel::register_route(
                state,
                stream,
                client_id,
                client_token,
                name,
                hostname,
                target_addr,
            )
            .await;
        }
        ControlFrame::RegisterTlsRoute {
            client_id,
            client_token,
            name,
            hostname,
            target_addr,
        } => {
            crate::sni_tunnel::register_route(
                state,
                stream,
                client_id,
                client_token,
                name,
                hostname,
                target_addr,
            )
            .await;
        }
        ControlFrame::RegisterP2pNode {
            client_id,
            client_token,
            candidates,
        } => {
            crate::p2p_control::register_node(state, stream, client_id, client_token, candidates)
                .await;
        }
        ControlFrame::RequestP2pSession {
            client_id,
            client_token,
            access_key,
        } => {
            crate::p2p_control::request_session(state, stream, client_id, client_token, access_key)
                .await;
        }
        ControlFrame::ValidateP2pTicket {
            client_id,
            client_token,
            ticket,
        } => {
            crate::p2p_control::validate_ticket(state, stream, client_id, client_token, ticket)
                .await;
        }
        ControlFrame::ReportP2pDirectSuccess {
            client_id,
            client_token,
            session_id,
            visitor_client_id,
        } => {
            crate::p2p_control::report_direct_success(
                state,
                stream,
                client_id,
                client_token,
                session_id,
                visitor_client_id,
            )
            .await;
        }
        ControlFrame::RegisterUdpTunnel {
            client_id,
            client_token,
            name,
            public_port,
            target_addr,
        } => {
            crate::udp_tunnel::register_tunnel(
                state,
                stream,
                client_id,
                client_token,
                name,
                public_port,
                target_addr,
            )
            .await;
        }
        ControlFrame::ReportP2pFallback {
            client_id,
            client_token,
            reason,
        } => {
            crate::p2p_control::report_fallback(state, stream, client_id, client_token, reason)
                .await;
        }
        ControlFrame::TcpDataConnection {
            client_id,
            client_token,
            connection_id,
        } => {
            pair_data_connection(state, stream, client_id, client_token, connection_id).await;
        }
        _ => {
            state
                .metrics
                .control_protocol_errors_total
                .fetch_add(1, Ordering::Relaxed);
            let _ = write_control_frame(
                &mut stream,
                &ControlFrame::Error {
                    message: "unexpected initial control frame".to_owned(),
                },
            )
            .await;
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn send_managed_config(
    state: Arc<AppState>,
    mut stream: BoxedIo,
    client_id: Uuid,
    client_token: String,
    mode: ManagedConfigMode,
    applied_revision: Option<String>,
    reported_status: ManagedConfigStatus,
    error: Option<String>,
) {
    let authenticated = {
        let mut clients = state.clients.lock().expect("client registry lock poisoned");
        matches!(
            clients.authenticate_and_touch(client_id, &client_token),
            Ok(Authentication::Authenticated)
        )
    };
    if !authenticated {
        state
            .metrics
            .authentication_failures_total
            .fetch_add(1, Ordering::Relaxed);
        let _ = write_control_frame_and_shutdown(
            &mut stream,
            &ControlFrame::Error {
                message: "invalid client credentials".to_owned(),
            },
        )
        .await;
        return;
    }

    let config = match crate::managed_config_for_client(&state, client_id) {
        Ok(config) => config,
        Err(error) => {
            tracing::error!("Could not build managed configuration for {client_id}: {error}");
            let _ = write_control_frame_and_shutdown(
                &mut stream,
                &ControlFrame::Error {
                    message: "managed configuration is temporarily unavailable".to_owned(),
                },
            )
            .await;
            return;
        }
    };
    let effective_status = if applied_revision.as_deref() == Some(config.revision.as_str()) {
        reported_status
    } else if reported_status == ManagedConfigStatus::ApplyFailed {
        ManagedConfigStatus::ApplyFailed
    } else {
        ManagedConfigStatus::Conflict
    };
    if let Err(update_error) = state
        .clients
        .lock()
        .expect("client registry lock poisoned")
        .update_config_sync(client_id, mode, effective_status, applied_revision, error)
    {
        tracing::warn!("Could not persist managed configuration status: {update_error}");
    }
    let _ = write_control_frame_and_shutdown(&mut stream, &ControlFrame::ManagedConfig { config })
        .await;
}

async fn register_tunnel(
    state: Arc<AppState>,
    mut stream: BoxedIo,
    client_id: Uuid,
    client_token: String,
    name: String,
    public_port: u16,
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
    if name.trim().is_empty() || target_addr.trim().is_empty() {
        state
            .metrics
            .registration_rejections_total
            .fetch_add(1, Ordering::Relaxed);
        send_error(&mut stream, "tunnel name and target address are required").await;
        return;
    }
    if !state.public_port_policy.allows_tcp(public_port) {
        state
            .metrics
            .registration_rejections_total
            .fetch_add(1, Ordering::Relaxed);
        send_error(&mut stream, "public port is not allowed by server policy").await;
        return;
    }
    let runtime_policy = state
        .tunnel_catalog
        .lock()
        .expect("tunnel catalog lock poisoned")
        .runtime_policy(client_id, &name, public_port, &target_addr)
        .unwrap_or(None);
    let Some(runtime_policy) = runtime_policy else {
        state
            .metrics
            .registration_rejections_total
            .fetch_add(1, Ordering::Relaxed);
        send_error(
            &mut stream,
            "no enabled management policy matches this TCP tunnel",
        )
        .await;
        return;
    };
    let listener = match TcpListener::bind(("0.0.0.0", public_port)).await {
        Ok(listener) => listener,
        Err(_) => {
            state
                .metrics
                .registration_rejections_total
                .fetch_add(1, Ordering::Relaxed);
            send_error(&mut stream, "public port is unavailable").await;
            return;
        }
    };
    let (command_tx, command_rx) = mpsc::channel(64);
    let (stop_tx, stop_rx) = watch::channel(());
    let control_stop = stop_rx.clone();
    let registration_id = Uuid::new_v4();
    let statistics = {
        let mut all_statistics = state
            .tunnel_statistics
            .lock()
            .expect("tunnel statistics lock poisoned");
        all_statistics
            .entry(public_port)
            .or_insert_with(|| Arc::new(TunnelStatistics::default()))
            .clone()
    };
    let bandwidth_limiter = runtime_policy
        .bandwidth_limit_bps
        .map(BandwidthLimiter::new)
        .map(Arc::new);
    state
        .metrics
        .tunnel_registrations_total
        .fetch_add(1, Ordering::Relaxed);
    if !state
        .seen_tunnel_registrations
        .lock()
        .expect("seen tunnel registrations lock poisoned")
        .insert((client_id, public_port))
    {
        state
            .metrics
            .tunnel_reconnects_total
            .fetch_add(1, Ordering::Relaxed);
    }
    {
        let mut tunnels = state.tunnels.lock().expect("tunnel registry lock poisoned");
        tunnels.insert(
            public_port,
            TunnelRegistration {
                registration_id,
                stop_tx,
            },
        );
    }
    record_audit(
        &state,
        "tcp_tunnel.registered",
        &client_id.to_string(),
        &format!("name={name}; public_port={public_port}; target={target_addr}"),
    );
    let public_connections = PublicConnectionContext {
        state: state.clone(),
        command_tx,
        client_id,
        policy_id: runtime_policy.policy_id,
        policy_kind: runtime_policy.policy_kind,
        permits: Arc::new(Semaphore::new(runtime_policy.max_connections)),
        statistics,
        bandwidth_limiter,
        global_permits: state.global_connection_permits.clone(),
    };
    tokio::spawn(accept_public_connections(
        public_connections,
        listener,
        stop_rx,
    ));
    let (reader, mut writer) = split(stream);
    if write_control_frame(
        &mut writer,
        &ControlFrame::TcpTunnelRegistered { public_port },
    )
    .await
    .is_err()
    {
        remove_tunnel(&state, public_port, registration_id);
        return;
    }
    run_registered_control(
        state,
        public_port,
        registration_id,
        reader,
        writer,
        command_rx,
        control_stop,
    )
    .await;
}

async fn run_registered_control(
    state: Arc<AppState>,
    public_port: u16,
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
            _ = &mut idle_timeout => {
                tracing::warn!("TCP control session heartbeat timed out on public port {public_port}");
                break;
            }
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
                Some(_) => {
                    state
                        .metrics
                        .control_protocol_errors_total
                        .fetch_add(1, Ordering::Relaxed);
                    break;
                }
                None => break,
            }
        }
    }
    reader_task.abort();
    remove_tunnel(&state, public_port, registration_id);
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
                Ok((external, source)) => {
                    let decision = context.state.traffic_controls
                        .lock()
                        .expect("traffic control catalog lock poisoned")
                        .authorize(context.policy_kind, context.policy_id, source.ip(), crate::unix_seconds());
                    if !matches!(decision, Ok(TrafficDecision::Allowed)) {
                        context.statistics.rejected_connections.fetch_add(1, Ordering::Relaxed);
                        tracing::debug!("TCP traffic control rejected {source}: {decision:?}");
                        continue;
                    }
                    let Ok(permit) = context.permits.clone().try_acquire_owned() else {
                        context.statistics.rejected_connections.fetch_add(1, Ordering::Relaxed);
                        context.statistics.rejected_policy_limit.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(
                            "TCP tunnel {} reached its concurrent connection limit",
                            context.client_id
                        );
                        continue;
                    };
                    let Ok(global_permit) = context.global_permits.clone().try_acquire_owned() else {
                        context.statistics.rejected_connections.fetch_add(1, Ordering::Relaxed);
                        context.statistics.rejected_global_limit.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!("LinkLake server reached its global TCP connection limit");
                        continue;
                    };
                    let context = context.clone();
                    let connection_stop = stop.clone();
                    tokio::spawn(async move {
                        serve_public_connection(
                            context,
                            external,
                            permit,
                            global_permit,
                            connection_stop,
                        )
                        .await
                    });
                }
                Err(error) => tracing::error!("TCP tunnel accept error: {error}"),
            }
        }
    }
}

async fn serve_public_connection(
    context: PublicConnectionContext,
    mut external: TcpStream,
    _permit: OwnedSemaphorePermit,
    _global_permit: OwnedSemaphorePermit,
    mut stop: watch::Receiver<()>,
) {
    let PublicConnectionContext {
        state,
        command_tx,
        client_id,
        policy_id,
        policy_kind,
        statistics,
        bandwidth_limiter,
        ..
    } = context;
    statistics
        .active_connections
        .fetch_add(1, Ordering::Relaxed);
    let Ok(pending_permit) = state.pending_connection_permits.clone().try_acquire_owned() else {
        statistics
            .rejected_connections
            .fetch_add(1, Ordering::Relaxed);
        statistics
            .rejected_pending_limit
            .fetch_add(1, Ordering::Relaxed);
        statistics
            .active_connections
            .fetch_sub(1, Ordering::Relaxed);
        return;
    };
    let connection_id = Uuid::new_v4();
    let (data_tx, data_rx) = oneshot::channel();
    {
        let mut pending = state.pending_connections.lock().await;
        pending.insert(connection_id, (client_id, data_tx));
    }
    if command_tx
        .send(ControlFrame::OpenTcpConnection { connection_id })
        .await
        .is_err()
    {
        state
            .pending_connections
            .lock()
            .await
            .remove(&connection_id);
        statistics
            .failed_connections
            .fetch_add(1, Ordering::Relaxed);
        statistics
            .active_connections
            .fetch_sub(1, Ordering::Relaxed);
        return;
    }
    let pair_result = tokio::select! {
        _ = stop.changed() => {
            state.pending_connections.lock().await.remove(&connection_id);
            statistics.active_connections.fetch_sub(1, Ordering::Relaxed);
            return;
        }
        result = timeout(CONNECTION_PAIR_TIMEOUT, data_rx) => result,
    };
    match pair_result {
        Ok(Ok(mut agent_stream)) => {
            drop(pending_permit);
            let transfer_result = tokio::select! {
                _ = stop.changed() => {
                    statistics.active_connections.fetch_sub(1, Ordering::Relaxed);
                    return;
                }
                result = timeout(
                    CONNECTION_MAX_LIFETIME,
                    copy_bidirectional_with_limit(&mut external, &mut agent_stream, bandwidth_limiter),
                ) => result,
            };
            match transfer_result {
                Ok(Ok((from_public, to_public))) => {
                    statistics
                        .bytes_from_public
                        .fetch_add(from_public, Ordering::Relaxed);
                    statistics
                        .bytes_to_public
                        .fetch_add(to_public, Ordering::Relaxed);
                    if let Err(error) = state
                        .traffic_controls
                        .lock()
                        .expect("traffic control catalog lock poisoned")
                        .record_bytes(
                            policy_kind,
                            policy_id,
                            from_public.saturating_add(to_public),
                            crate::unix_seconds(),
                        )
                    {
                        tracing::warn!("Could not persist TCP traffic usage: {error}");
                    }
                }
                Ok(Err(error)) => {
                    statistics
                        .failed_connections
                        .fetch_add(1, Ordering::Relaxed);
                    statistics.transfer_errors.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!("TCP tunnel transfer failed: {error}");
                }
                Err(_) => {
                    statistics
                        .failed_connections
                        .fetch_add(1, Ordering::Relaxed);
                    statistics.lifetime_timeouts.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!("TCP tunnel connection reached its maximum lifetime");
                }
            }
        }
        Ok(Err(_)) => {
            drop(pending_permit);
            statistics
                .failed_connections
                .fetch_add(1, Ordering::Relaxed);
            state
                .pending_connections
                .lock()
                .await
                .remove(&connection_id);
        }
        Err(_) => {
            drop(pending_permit);
            statistics
                .failed_connections
                .fetch_add(1, Ordering::Relaxed);
            statistics.pairing_timeouts.fetch_add(1, Ordering::Relaxed);
            tracing::warn!("TCP tunnel data connection pairing timed out");
            state
                .pending_connections
                .lock()
                .await
                .remove(&connection_id);
        }
    }
    statistics
        .active_connections
        .fetch_sub(1, Ordering::Relaxed);
}

pub(crate) async fn copy_bidirectional_with_limit<A, B>(
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
    let from_public = copy_direction(
        &mut external_reader,
        &mut agent_writer,
        limiter.clone(),
        false,
    );
    let to_public = copy_direction(&mut agent_reader, &mut external_writer, limiter, true);
    tokio::try_join!(from_public, to_public)
}

async fn copy_direction<R, W>(
    reader: &mut R,
    writer: &mut W,
    limiter: Option<Arc<BandwidthLimiter>>,
    allow_unexpected_eof: bool,
) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = [0_u8; 16 * 1024];
    let mut transferred = 0_u64;
    loop {
        let read = match reader.read(&mut buffer).await {
            Ok(read) => read,
            Err(error)
                if allow_unexpected_eof && error.kind() == std::io::ErrorKind::UnexpectedEof =>
            {
                // 业务数据通道本身是原始字节流。客户端进程退出或旧版本未发送
                // TLS close_notify 时，rustls 会把底层 TCP EOF 报为 UnexpectedEof；
                // 已收到的业务字节仍然有效，应按普通半关闭处理而不是污染失败指标。
                writer.shutdown().await?;
                return Ok(transferred);
            }
            Err(error) => return Err(error),
        };
        if read == 0 {
            writer.shutdown().await?;
            return Ok(transferred);
        }
        if let Some(limiter) = &limiter {
            // 一个策略的双向连接共享同一个预约时钟，因此限制的是策略总吞吐。
            limiter.reserve(read).await;
        }
        writer.write_all(&buffer[..read]).await?;
        transferred = transferred.saturating_add(read as u64);
    }
}

async fn pair_data_connection(
    state: Arc<AppState>,
    stream: BoxedIo,
    client_id: Uuid,
    _client_token: String,
    connection_id: Uuid,
) {
    // connection_id 是服务端仅通过已认证控制会话下发的随机一次性能力凭据。
    // pending 表中的原子 remove 保证它只能消费一次；同时继续校验 client_id，防止客户端串线。
    // client_token 字段暂时保留以兼容现有控制帧，但数据连接不再重复执行 Argon2 和 SQLite 更新。
    let pending = state
        .pending_connections
        .lock()
        .await
        .remove(&connection_id);
    if let Some((expected_client_id, sender)) = pending {
        if expected_client_id == client_id {
            let _ = sender.send(stream);
        } else {
            state
                .metrics
                .control_protocol_errors_total
                .fetch_add(1, Ordering::Relaxed);
        }
    } else {
        state
            .metrics
            .control_protocol_errors_total
            .fetch_add(1, Ordering::Relaxed);
    }
}

fn authenticated_client(state: &AppState, client_id: Uuid, token: &str) -> bool {
    let mut clients = state.clients.lock().expect("client registry lock poisoned");
    matches!(
        clients.authenticate_and_touch(client_id, token),
        Ok(Authentication::Authenticated)
    )
}

fn remove_tunnel(state: &AppState, public_port: u16, registration_id: Uuid) {
    let mut tunnels = state.tunnels.lock().expect("tunnel registry lock poisoned");
    let matches_registration = tunnels
        .get(&public_port)
        .is_some_and(|tunnel| tunnel.registration_id == registration_id);
    if matches_registration {
        if let Some(tunnel) = tunnels.remove(&public_port) {
            let _ = tunnel.stop_tx.send(());
        }
    }
}

pub(crate) fn stop_public_port(state: &AppState, public_port: u16) {
    if let Some(tunnel) = state
        .tunnels
        .lock()
        .expect("tunnel registry lock poisoned")
        .remove(&public_port)
    {
        let _ = tunnel.stop_tx.send(());
    }
}

pub(crate) fn stop_all(state: &AppState) {
    let registrations = state
        .tunnels
        .lock()
        .expect("tunnel registry lock poisoned")
        .drain()
        .map(|(_, tunnel)| tunnel)
        .collect::<Vec<_>>();
    for tunnel in registrations {
        let _ = tunnel.stop_tx.send(());
    }
}

async fn send_error(stream: &mut BoxedIo, message: &str) {
    let _ = write_control_frame_and_shutdown(
        stream,
        &ControlFrame::Error {
            message: message.to_owned(),
        },
    )
    .await;
}

#[cfg(test)]
mod bandwidth_limiter_tests {
    use super::{copy_direction, BandwidthLimiter};
    use std::{
        io,
        pin::Pin,
        task::{Context, Poll},
    };
    use tokio::io::{duplex, AsyncRead, AsyncReadExt, ReadBuf};

    struct UnexpectedEofReader {
        bytes: &'static [u8],
        offset: usize,
    }

    impl AsyncRead for UnexpectedEofReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            buffer: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.offset < self.bytes.len() {
                let length = buffer.remaining().min(self.bytes.len() - self.offset);
                buffer.put_slice(&self.bytes[self.offset..self.offset + length]);
                self.offset += length;
                Poll::Ready(Ok(()))
            } else {
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "TLS peer omitted close_notify",
                )))
            }
        }
    }

    #[tokio::test]
    async fn udp_datagrams_share_the_tcp_policy_reservation_clock() {
        let limiter = BandwidthLimiter::new(1_024);
        limiter.reserve(1_024).await;
        assert!(!limiter.try_reserve_datagram(1).await);
    }

    #[tokio::test]
    async fn first_udp_datagram_is_admitted_without_waiting() {
        let limiter = BandwidthLimiter::new(1_024);
        assert!(limiter.try_reserve_datagram(512).await);
        assert!(!limiter.try_reserve_datagram(512).await);
    }

    #[tokio::test]
    async fn data_channel_unexpected_eof_preserves_transferred_bytes() {
        let mut reader = UnexpectedEofReader {
            bytes: b"linklake-data",
            offset: 0,
        };
        let (mut writer, mut peer) = duplex(128);
        let copied = copy_direction(&mut reader, &mut writer, None, true)
            .await
            .expect("data-channel EOF should be treated as a half-close");
        let mut actual = Vec::new();
        peer.read_to_end(&mut actual)
            .await
            .expect("forwarded bytes should remain readable");
        assert_eq!(copied, actual.len() as u64);
        assert_eq!(actual, b"linklake-data");
    }
}
