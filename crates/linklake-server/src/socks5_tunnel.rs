use crate::traffic_control::{TrafficDecision, TrafficPolicyKind};
use crate::{
    client_registry::Authentication,
    dual_stack_udp::{bind_public_socket, DualStackUdpSocket, PublicUdpEndpoint},
    record_audit,
    tcp_tunnel::{copy_bidirectional_with_limit, BandwidthLimiter},
    tunnel_catalog::socks5_password_matches,
    udp_data_plane::AuthenticatedUdpConnection,
    AppState,
};
use bytes::Bytes;
use linklake_core::{
    read_control_frame, read_udp_data_plane_control_frame,
    socks5_udp::{decode_socks5_udp_datagram, Socks5UdpError},
    udp_protocol::{fragment_datagram, UdpDirection, UdpFragment, MAX_UDP_DATAGRAM_BYTES},
    udp_reassembly::{UdpReassembler, UdpReassemblyConfig, UdpReassemblyOutcome},
    write_control_frame, write_udp_data_plane_control_frame, BoxedIo, ControlFrame,
    UdpDataPlaneControlFrame, UdpSessionCloseReason,
};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::{
    io::{split, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    net::{TcpListener, TcpStream},
    sync::{mpsc, watch, OwnedSemaphorePermit, Semaphore},
    time::{interval, timeout, Instant, MissedTickBehavior},
};
use uuid::Uuid;

const CONTROL_IDLE_TIMEOUT: Duration = Duration::from_secs(35);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECTION_PAIR_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECTION_MAX_LIFETIME: Duration = Duration::from_secs(2 * 60 * 60);

pub(crate) struct Socks5ProxyRegistration {
    registration_id: Uuid,
    public_port: u16,
    stop_tx: watch::Sender<()>,
}

#[derive(Default)]
pub(crate) struct Socks5ProxyStatistics {
    pub(crate) active_connections: AtomicUsize,
    pub(crate) connections_total: AtomicU64,
    pub(crate) requests_total: AtomicU64,
    pub(crate) authentication_failures: AtomicU64,
    pub(crate) rejected_connections: AtomicU64,
    pub(crate) unsupported_commands: AtomicU64,
    pub(crate) bind_rejected_total: AtomicU64,
    pub(crate) handshake_errors: AtomicU64,
    pub(crate) handshake_timeouts: AtomicU64,
    pub(crate) bytes_from_public: AtomicU64,
    pub(crate) bytes_to_public: AtomicU64,
    pub(crate) pairing_timeouts: AtomicU64,
    pub(crate) connect_failures: AtomicU64,
    pub(crate) transfer_errors: AtomicU64,
    pub(crate) lifetime_timeouts: AtomicU64,
    pub(crate) udp_active_associations: AtomicUsize,
    pub(crate) udp_datagrams_from_public: AtomicU64,
    pub(crate) udp_datagrams_to_public: AtomicU64,
    pub(crate) udp_bytes_from_public: AtomicU64,
    pub(crate) udp_bytes_to_public: AtomicU64,
    pub(crate) udp_dropped_datagrams: AtomicU64,
    pub(crate) udp_dropped_bandwidth_limit: AtomicU64,
    pub(crate) udp_fragmentation_unsupported_total: AtomicU64,
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
    statistics: Arc<Socks5ProxyStatistics>,
    bandwidth_limiter: Option<Arc<BandwidthLimiter>>,
    udp: Option<Arc<UdpProxyContext>>,
}

#[derive(Debug, Eq, PartialEq)]
enum HandshakeError {
    Authentication,
    UnsupportedCommand { command: u8 },
    Protocol,
}

#[derive(Debug, Eq, PartialEq)]
enum Socks5Request {
    Connect {
        host: String,
        port: u16,
    },
    UdpAssociate {
        requested: Option<UdpAssociationRequest>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UdpAssociationRequest {
    ip: Option<IpAddr>,
    port: Option<u16>,
}

struct UdpAssociation {
    peer_ip: IpAddr,
    requested: Option<UdpAssociationRequest>,
    public_endpoint: Option<PublicUdpEndpoint>,
}

struct UdpProxyContext {
    state: Arc<AppState>,
    policy_id: Uuid,
    public_port: u16,
    associations: Mutex<HashMap<Uuid, UdpAssociation>>,
    commands: mpsc::Sender<UdpRuntimeCommand>,
    bandwidth_limiter: Option<Arc<BandwidthLimiter>>,
}

enum UdpRuntimeCommand {
    Close(Uuid),
}

pub(crate) async fn register_proxy(
    state: Arc<AppState>,
    mut stream: BoxedIo,
    client_id: Uuid,
    client_token: String,
    name: String,
    public_port: u16,
) {
    if !authenticated_client(&state, client_id, &client_token) {
        reject(&state, &mut stream, "invalid client credentials").await;
        return;
    }
    let runtime_policy = state
        .tunnel_catalog
        .lock()
        .expect("tunnel catalog lock poisoned")
        .socks5_runtime_policy(client_id, &name, public_port)
        .unwrap_or(None);
    let Some(runtime_policy) = runtime_policy else {
        reject(
            &state,
            &mut stream,
            "no enabled management policy matches this SOCKS5 proxy",
        )
        .await;
        return;
    };
    let listener = match TcpListener::bind(("0.0.0.0", public_port)).await {
        Ok(listener) => listener,
        Err(_) => {
            reject(&state, &mut stream, "SOCKS5 public port is unavailable").await;
            return;
        }
    };
    let (command_tx, command_rx) = mpsc::channel(64);
    let (stop_tx, stop_rx) = watch::channel(());
    let registration_id = Uuid::new_v4();
    let statistics = state
        .socks5_proxy_statistics
        .lock()
        .expect("SOCKS5 statistics lock poisoned")
        .entry(runtime_policy.policy_id)
        .or_insert_with(|| Arc::new(Socks5ProxyStatistics::default()))
        .clone();
    let bandwidth_limiter = runtime_policy
        .bandwidth_limit_bps
        .map(BandwidthLimiter::new)
        .map(Arc::new);
    let udp_runtime = if let Some(data_plane) = state.udp_data_plane.clone() {
        let socket = match bind_public_socket(&state, public_port, "socks5_udp_associate").await {
            Ok(socket) => socket,
            Err(_) => {
                reject(&state, &mut stream, "SOCKS5 UDP public port is unavailable").await;
                return;
            }
        };
        let attachment = data_plane.reserve_attachment(client_id, registration_id);
        let offer = attachment.offer().clone();
        if write_control_frame(
            &mut stream,
            &ControlFrame::Socks5UdpDataPlaneOffer {
                registration_id,
                ticket: offer.ticket,
                endpoint: offer.endpoint,
                server_name: offer.server_name,
                max_datagram_size: offer.max_datagram_size,
                session_idle_timeout_seconds: 120,
            },
        )
        .await
        .is_err()
        {
            return;
        }
        let mut authenticated = match attachment.wait().await {
            Ok(connection) => connection,
            Err(error) => {
                tracing::warn!("SOCKS5 UDP data-plane attachment failed: {error}");
                reject(
                    &state,
                    &mut stream,
                    "SOCKS5 UDP data-plane attachment failed",
                )
                .await;
                return;
            }
        };
        let max_datagram_size = authenticated
            .connection
            .max_datagram_size()
            .unwrap_or(offer.max_datagram_size as usize)
            .min(offer.max_datagram_size as usize);
        if write_udp_data_plane_control_frame(
            &mut authenticated.control_send,
            &UdpDataPlaneControlFrame::Ready {
                registration_id,
                negotiated_max_datagram_size: max_datagram_size as u32,
            },
        )
        .await
        .is_err()
        {
            return;
        }
        let (udp_command_tx, udp_command_rx) = mpsc::channel(256);
        let udp_context = Arc::new(UdpProxyContext {
            state: state.clone(),
            policy_id: runtime_policy.policy_id,
            public_port,
            associations: Mutex::new(HashMap::new()),
            commands: udp_command_tx,
            bandwidth_limiter: bandwidth_limiter.clone(),
        });
        Some((
            udp_context,
            socket,
            authenticated,
            max_datagram_size,
            udp_command_rx,
        ))
    } else {
        None
    };
    let udp_enabled = udp_runtime.is_some();
    if let Some(previous) = state
        .socks5_proxies
        .lock()
        .expect("SOCKS5 proxy registry lock poisoned")
        .insert(
            runtime_policy.policy_id,
            Socks5ProxyRegistration {
                registration_id,
                public_port,
                stop_tx: stop_tx.clone(),
            },
        )
    {
        let _ = previous.stop_tx.send(());
    }
    state
        .metrics
        .tunnel_registrations_total
        .fetch_add(1, Ordering::Relaxed);
    record_audit(
        &state,
        "socks5_proxy.registered",
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
        statistics: statistics.clone(),
        bandwidth_limiter,
        udp: udp_runtime.as_ref().map(|runtime| runtime.0.clone()),
    };
    tokio::spawn(accept_public_connections(
        context,
        listener,
        stop_rx.clone(),
    ));
    if let Some((udp_context, socket, authenticated, max_datagram_size, commands)) = udp_runtime {
        let runtime_stop = stop_rx.clone();
        let runtime_stop_tx = stop_tx.clone();
        tokio::spawn(async move {
            if let Err(error) = run_udp_runtime(
                socket,
                authenticated,
                max_datagram_size,
                udp_context,
                statistics,
                commands,
                runtime_stop,
            )
            .await
            {
                tracing::warn!("SOCKS5 UDP runtime stopped: {error}");
                let _ = runtime_stop_tx.send(());
            }
        });
    }
    let (reader, mut writer) = split(stream);
    if write_control_frame(
        &mut writer,
        &ControlFrame::Socks5ProxyRegistered {
            proxy_id: runtime_policy.policy_id,
            public_port,
            udp_associate: udp_enabled,
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

async fn run_udp_runtime(
    socket: DualStackUdpSocket,
    mut authenticated: AuthenticatedUdpConnection,
    max_datagram_size: usize,
    context: Arc<UdpProxyContext>,
    statistics: Arc<Socks5ProxyStatistics>,
    mut commands: mpsc::Receiver<UdpRuntimeCommand>,
    mut stop: watch::Receiver<()>,
) -> anyhow::Result<()> {
    let (control_events_tx, mut control_events_rx) = mpsc::channel(64);
    let control_reader = tokio::spawn(async move {
        loop {
            let frame = read_udp_data_plane_control_frame(&mut authenticated.control_receive).await;
            if control_events_tx.send(frame).await.is_err() {
                break;
            }
        }
    });
    let connection = authenticated.connection.clone();
    let mut reassembler = UdpReassembler::new(UdpReassemblyConfig::default())?;
    let mut receive_buffer = vec![0_u8; MAX_UDP_DATAGRAM_BYTES];
    let mut next_datagram_id = 1_u64;
    let mut usage_pending = 0_u64;
    let mut cleanup = interval(Duration::from_secs(1));
    cleanup.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            command = commands.recv() => match command {
                Some(UdpRuntimeCommand::Close(session_id)) => {
                    let _ = write_udp_data_plane_control_frame(
                        &mut authenticated.control_send,
                        &UdpDataPlaneControlFrame::CloseSession {
                            session_id,
                            reason: UdpSessionCloseReason::PolicyDisabled,
                        },
                    ).await;
                }
                None => break,
            },
            control = control_events_rx.recv() => match control {
                Some(Ok(UdpDataPlaneControlFrame::CloseSession { .. })) => {}
                Some(Ok(UdpDataPlaneControlFrame::Error { code, message })) => {
                    anyhow::bail!("SOCKS5 UDP data plane closed ({code}): {message}");
                }
                Some(Ok(frame)) => anyhow::bail!("unexpected SOCKS5 UDP control frame: {frame:?}"),
                Some(Err(error)) => return Err(error.into()),
                None => anyhow::bail!("SOCKS5 UDP control reader stopped"),
            },
            incoming = socket.recv_from(&mut receive_buffer) => {
                let incoming = incoming?;
                let received = incoming.length;
                let source = incoming.source;
                let encoded = &receive_buffer[..received];
                if !accept_socks5_udp_datagram(encoded, &statistics) {
                    continue;
                }
                let Some(session_id) = association_for_source(&context.associations, source) else {
                    statistics.udp_dropped_datagrams.fetch_add(1, Ordering::Relaxed);
                    continue;
                };
                if let Some(limiter) = &context.bandwidth_limiter {
                    if !limiter.try_reserve_datagram(received).await {
                        statistics.udp_dropped_datagrams.fetch_add(1, Ordering::Relaxed);
                        statistics.udp_dropped_bandwidth_limit.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                }
                let frames = match fragment_datagram(
                    UdpDirection::PublicToTarget,
                    session_id,
                    next_datagram_id,
                    encoded,
                    max_datagram_size,
                ) {
                    Ok(frames) => frames,
                    Err(_) => {
                        statistics.udp_dropped_datagrams.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };
                next_datagram_id = next_datagram_id.wrapping_add(1);
                let mut sent = true;
                for frame in frames {
                    if connection.send_datagram(Bytes::from(frame)).is_err() {
                        sent = false;
                        break;
                    }
                }
                if sent {
                    statistics.udp_datagrams_from_public.fetch_add(1, Ordering::Relaxed);
                    statistics.udp_bytes_from_public.fetch_add(received as u64, Ordering::Relaxed);
                    usage_pending = usage_pending.saturating_add(received as u64);
                } else {
                    statistics.udp_dropped_datagrams.fetch_add(1, Ordering::Relaxed);
                }
            },
            incoming = connection.read_datagram() => {
                let encoded = incoming?;
                let fragment = match UdpFragment::decode(&encoded) {
                    Ok(fragment) if fragment.direction == UdpDirection::TargetToPublic => fragment,
                    _ => {
                        statistics.udp_dropped_datagrams.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };
                let session_id = fragment.session_id;
                let payload = match reassembler.push(fragment, std::time::Instant::now()) {
                    Ok(UdpReassemblyOutcome::Complete(payload)) => payload,
                    Ok(UdpReassemblyOutcome::Pending | UdpReassemblyOutcome::Duplicate) => continue,
                    Err(_) => {
                        statistics.udp_dropped_datagrams.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };
                if !accept_socks5_udp_datagram(&payload, &statistics) {
                    continue;
                }
                let endpoint = context.associations
                    .lock()
                    .expect("SOCKS5 UDP association lock poisoned")
                    .get(&session_id)
                    .and_then(|association| association.public_endpoint);
                let Some(endpoint) = endpoint else {
                    statistics.udp_dropped_datagrams.fetch_add(1, Ordering::Relaxed);
                    continue;
                };
                if let Some(limiter) = &context.bandwidth_limiter {
                    if !limiter.try_reserve_datagram(payload.len()).await {
                        statistics.udp_dropped_datagrams.fetch_add(1, Ordering::Relaxed);
                        statistics.udp_dropped_bandwidth_limit.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                }
                if socket.send_to(&payload, endpoint).await? == payload.len() {
                    statistics.udp_datagrams_to_public.fetch_add(1, Ordering::Relaxed);
                    statistics.udp_bytes_to_public.fetch_add(payload.len() as u64, Ordering::Relaxed);
                    usage_pending = usage_pending.saturating_add(payload.len() as u64);
                }
            },
            _ = cleanup.tick() => {
                if usage_pending != 0 {
                    if let Err(error) = context
                        .state
                        .traffic_controls
                        .lock()
                        .expect("traffic control catalog lock poisoned")
                        .record_bytes(
                            TrafficPolicyKind::Socks5,
                            context.policy_id,
                            usage_pending,
                            crate::unix_seconds(),
                        )
                    {
                        tracing::warn!("Could not persist SOCKS5 UDP traffic usage: {error}");
                    } else {
                        usage_pending = 0;
                    }
                }
                let expired = reassembler.expire(std::time::Instant::now());
                statistics.udp_dropped_datagrams.fetch_add(
                    expired.incomplete_datagrams as u64,
                    Ordering::Relaxed,
                );
            }
        }
    }
    if usage_pending != 0 {
        if let Err(error) = context
            .state
            .traffic_controls
            .lock()
            .expect("traffic control catalog lock poisoned")
            .record_bytes(
                TrafficPolicyKind::Socks5,
                context.policy_id,
                usage_pending,
                crate::unix_seconds(),
            )
        {
            tracing::warn!("Could not persist final SOCKS5 UDP traffic usage: {error}");
        }
    }
    control_reader.abort();
    connection.close(0_u32.into(), b"SOCKS5 UDP runtime stopped");
    Ok(())
}

fn association_for_source(
    associations: &Mutex<HashMap<Uuid, UdpAssociation>>,
    source: PublicUdpEndpoint,
) -> Option<Uuid> {
    let mut associations = associations
        .lock()
        .expect("SOCKS5 UDP association lock poisoned");
    if let Some((id, _)) = associations
        .iter()
        .find(|(_, association)| association.public_endpoint == Some(source))
    {
        return Some(*id);
    }
    let candidates = associations
        .iter()
        .filter_map(|(id, association)| {
            let source_address = source.address();
            let source_matches = match association.requested {
                Some(requested) => {
                    requested.ip.map_or_else(
                        || association.peer_ip == source_address.ip(),
                        |ip| ip == source_address.ip(),
                    ) && requested
                        .port
                        .is_none_or(|port| port == source_address.port())
                }
                None => association.peer_ip == source_address.ip(),
            };
            (association.public_endpoint.is_none() && source_matches).then_some(*id)
        })
        .collect::<Vec<_>>();
    if candidates.len() != 1 {
        return None;
    }
    let id = candidates[0];
    if let Some(association) = associations.get_mut(&id) {
        association.public_endpoint = Some(source);
    }
    Some(id)
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
                    let decision = context.state.traffic_controls.lock().expect("traffic control catalog lock poisoned").authorize(TrafficPolicyKind::Socks5, context.policy_id, source.ip(), crate::unix_seconds());
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
                Err(error) => tracing::warn!("SOCKS5 listener accept error: {error}"),
            }
        }
    }
}

async fn serve_public_connection(
    context: PublicConnectionContext,
    mut external: TcpStream,
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
    let handshake = timeout(
        HANDSHAKE_TIMEOUT,
        perform_handshake(
            &mut external,
            context.username.as_bytes(),
            &context.password_hash,
        ),
    )
    .await;
    let request = match handshake {
        Ok(Ok(request)) => request,
        Ok(Err(HandshakeError::Authentication)) => {
            context
                .statistics
                .authentication_failures
                .fetch_add(1, Ordering::Relaxed);
            finish_connection(&context.statistics);
            return;
        }
        Ok(Err(HandshakeError::UnsupportedCommand { command })) => {
            record_unsupported_command(&context.statistics, command);
            finish_connection(&context.statistics);
            return;
        }
        Ok(Err(HandshakeError::Protocol)) => {
            context
                .statistics
                .handshake_errors
                .fetch_add(1, Ordering::Relaxed);
            finish_connection(&context.statistics);
            return;
        }
        Err(_) => {
            context
                .statistics
                .handshake_timeouts
                .fetch_add(1, Ordering::Relaxed);
            finish_connection(&context.statistics);
            return;
        }
    };
    let (target_host, target_port) = match request {
        Socks5Request::Connect { host, port } => (host, port),
        Socks5Request::UdpAssociate { requested } => {
            serve_udp_association(&context, &mut external, requested, &mut stop).await;
            finish_connection(&context.statistics);
            return;
        }
    };
    context
        .statistics
        .requests_total
        .fetch_add(1, Ordering::Relaxed);
    let Ok(pending_permit) = context
        .state
        .pending_connection_permits
        .clone()
        .try_acquire_owned()
    else {
        context
            .statistics
            .rejected_connections
            .fetch_add(1, Ordering::Relaxed);
        let _ = write_socks5_reply(&mut external, 0x01).await;
        finish_connection(&context.statistics);
        return;
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
        .send(ControlFrame::OpenSocks5Connection {
            connection_id,
            target_host,
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
        let _ = write_socks5_reply(&mut external, 0x01).await;
        finish_connection(&context.statistics);
        return;
    }
    let pair_result = tokio::select! {
        _ = stop.changed() => {
            context.state.pending_connections.lock().await.remove(&connection_id);
            finish_connection(&context.statistics);
            return;
        }
        result = timeout(CONNECTION_PAIR_TIMEOUT, data_rx) => result,
    };
    match pair_result {
        Ok(Ok(mut agent_stream)) => {
            drop(pending_permit);
            if write_socks5_reply(&mut external, 0x00).await.is_err() {
                finish_connection(&context.statistics);
                return;
            }
            let transfer = tokio::select! {
                _ = stop.changed() => None,
                result = timeout(
                    CONNECTION_MAX_LIFETIME,
                    copy_bidirectional_with_limit(
                        &mut external,
                        &mut agent_stream,
                        context.bandwidth_limiter.clone(),
                    ),
                ) => Some(result),
            };
            match transfer {
                Some(Ok(Ok((from_public, to_public)))) => {
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
                            TrafficPolicyKind::Socks5,
                            context.policy_id,
                            from_public.saturating_add(to_public),
                            crate::unix_seconds(),
                        )
                    {
                        tracing::warn!("Could not persist SOCKS5 traffic usage: {error}");
                    }
                }
                Some(Ok(Err(error))) => {
                    context
                        .statistics
                        .transfer_errors
                        .fetch_add(1, Ordering::Relaxed);
                    tracing::warn!("SOCKS5 transfer failed: {error}");
                }
                Some(Err(_)) => {
                    context
                        .statistics
                        .lifetime_timeouts
                        .fetch_add(1, Ordering::Relaxed);
                }
                None => {}
            }
        }
        Ok(Err(_)) => {
            drop(pending_permit);
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
            let _ = write_socks5_reply(&mut external, 0x04).await;
        }
        Err(_) => {
            drop(pending_permit);
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
            let _ = write_socks5_reply(&mut external, 0x04).await;
        }
    }
    finish_connection(&context.statistics);
}

async fn serve_udp_association(
    context: &PublicConnectionContext,
    external: &mut TcpStream,
    requested: Option<UdpAssociationRequest>,
    stop: &mut watch::Receiver<()>,
) {
    let Some(udp) = &context.udp else {
        let _ = write_socks5_reply(external, 0x07).await;
        return;
    };
    let Ok(peer) = external.peer_addr() else {
        let _ = write_socks5_reply(external, 0x01).await;
        return;
    };
    let association_id = Uuid::new_v4();
    udp.associations
        .lock()
        .expect("SOCKS5 UDP association lock poisoned")
        .insert(
            association_id,
            UdpAssociation {
                peer_ip: peer.ip(),
                requested,
                public_endpoint: None,
            },
        );
    context
        .statistics
        .udp_active_associations
        .fetch_add(1, Ordering::Relaxed);
    let bound = external
        .local_addr()
        .map(|address| udp_associate_reply_address(address.ip(), udp.public_port))
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], udp.public_port)));
    if write_socks5_bound_reply(external, 0x00, bound)
        .await
        .is_ok()
    {
        let mut buffer = [0_u8; 1];
        tokio::select! {
            _ = stop.changed() => {}
            _ = external.read(&mut buffer) => {}
        }
    }
    udp.associations
        .lock()
        .expect("SOCKS5 UDP association lock poisoned")
        .remove(&association_id);
    let _ = udp
        .commands
        .send(UdpRuntimeCommand::Close(association_id))
        .await;
    context
        .statistics
        .udp_active_associations
        .fetch_sub(1, Ordering::Relaxed);
}

async fn perform_handshake(
    stream: &mut TcpStream,
    expected_username: &[u8],
    expected_password_hash: &str,
) -> Result<Socks5Request, HandshakeError> {
    let mut greeting = [0_u8; 2];
    stream
        .read_exact(&mut greeting)
        .await
        .map_err(|_| HandshakeError::Protocol)?;
    if greeting[0] != 0x05 || greeting[1] == 0 {
        return Err(HandshakeError::Protocol);
    }
    let mut methods = vec![0_u8; greeting[1] as usize];
    stream
        .read_exact(&mut methods)
        .await
        .map_err(|_| HandshakeError::Protocol)?;
    if !methods.contains(&0x02) {
        let _ = stream.write_all(&[0x05, 0xff]).await;
        return Err(HandshakeError::Authentication);
    }
    stream
        .write_all(&[0x05, 0x02])
        .await
        .map_err(|_| HandshakeError::Protocol)?;
    let mut auth_header = [0_u8; 2];
    stream
        .read_exact(&mut auth_header)
        .await
        .map_err(|_| HandshakeError::Authentication)?;
    if auth_header[0] != 0x01 || auth_header[1] == 0 {
        let _ = stream.write_all(&[0x01, 0x01]).await;
        return Err(HandshakeError::Authentication);
    }
    let mut username = vec![0_u8; auth_header[1] as usize];
    stream
        .read_exact(&mut username)
        .await
        .map_err(|_| HandshakeError::Authentication)?;
    let password_length = stream
        .read_u8()
        .await
        .map_err(|_| HandshakeError::Authentication)?;
    if password_length == 0 {
        let _ = stream.write_all(&[0x01, 0x01]).await;
        return Err(HandshakeError::Authentication);
    }
    let mut password = vec![0_u8; password_length as usize];
    stream
        .read_exact(&mut password)
        .await
        .map_err(|_| HandshakeError::Authentication)?;
    if username != expected_username || !socks5_password_matches(&password, expected_password_hash)
    {
        let _ = stream.write_all(&[0x01, 0x01]).await;
        return Err(HandshakeError::Authentication);
    }
    stream
        .write_all(&[0x01, 0x00])
        .await
        .map_err(|_| HandshakeError::Protocol)?;

    let mut request = [0_u8; 4];
    stream
        .read_exact(&mut request)
        .await
        .map_err(|_| HandshakeError::Protocol)?;
    if request[0] != 0x05 || request[2] != 0x00 {
        let _ = write_socks5_reply(stream, 0x01).await;
        return Err(HandshakeError::Protocol);
    }
    let host = match request[3] {
        0x01 => {
            let mut address = [0_u8; 4];
            stream
                .read_exact(&mut address)
                .await
                .map_err(|_| HandshakeError::Protocol)?;
            Ipv4Addr::from(address).to_string()
        }
        0x03 => {
            let length = stream
                .read_u8()
                .await
                .map_err(|_| HandshakeError::Protocol)?;
            if length == 0 {
                let _ = write_socks5_reply(stream, 0x08).await;
                return Err(HandshakeError::Protocol);
            }
            let mut domain = vec![0_u8; length as usize];
            stream
                .read_exact(&mut domain)
                .await
                .map_err(|_| HandshakeError::Protocol)?;
            let domain = String::from_utf8(domain).map_err(|_| HandshakeError::Protocol)?;
            if !valid_domain(&domain) {
                let _ = write_socks5_reply(stream, 0x08).await;
                return Err(HandshakeError::Protocol);
            }
            domain
        }
        0x04 => {
            let mut address = [0_u8; 16];
            stream
                .read_exact(&mut address)
                .await
                .map_err(|_| HandshakeError::Protocol)?;
            Ipv6Addr::from(address).to_string()
        }
        _ => {
            let _ = write_socks5_reply(stream, 0x08).await;
            return Err(HandshakeError::Protocol);
        }
    };
    let port = stream
        .read_u16()
        .await
        .map_err(|_| HandshakeError::Protocol)?;
    match request[1] {
        0x01 if port != 0 => Ok(Socks5Request::Connect { host, port }),
        0x03 => {
            let address = host
                .parse::<IpAddr>()
                .map_err(|_| HandshakeError::Protocol)?;
            let requested = UdpAssociationRequest {
                ip: (!address.is_unspecified()).then_some(address),
                port: (port != 0).then_some(port),
            };
            let requested =
                (requested.ip.is_some() || requested.port.is_some()).then_some(requested);
            Ok(Socks5Request::UdpAssociate { requested })
        }
        0x01 => {
            let _ = write_socks5_reply(stream, 0x08).await;
            Err(HandshakeError::Protocol)
        }
        command => {
            let _ = write_socks5_reply(stream, 0x07).await;
            let _ = stream.shutdown().await;
            Err(HandshakeError::UnsupportedCommand { command })
        }
    }
}

fn record_unsupported_command(statistics: &Socks5ProxyStatistics, command: u8) {
    statistics
        .unsupported_commands
        .fetch_add(1, Ordering::Relaxed);
    if command == 0x02 {
        statistics
            .bind_rejected_total
            .fetch_add(1, Ordering::Relaxed);
    }
}

fn accept_socks5_udp_datagram(encoded: &[u8], statistics: &Socks5ProxyStatistics) -> bool {
    match decode_socks5_udp_datagram(encoded) {
        Ok(_) => true,
        Err(error) => {
            statistics
                .udp_dropped_datagrams
                .fetch_add(1, Ordering::Relaxed);
            if error == Socks5UdpError::FragmentationUnsupported {
                statistics
                    .udp_fragmentation_unsupported_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            false
        }
    }
}

fn valid_domain(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.is_ascii()
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

async fn write_socks5_reply(stream: &mut TcpStream, reply: u8) -> std::io::Result<()> {
    stream
        .write_all(&[0x05, reply, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        .await?;
    stream.flush().await
}

async fn write_socks5_bound_reply(
    stream: &mut TcpStream,
    reply: u8,
    bound: SocketAddr,
) -> std::io::Result<()> {
    let mut response = vec![0x05, reply, 0x00];
    match bound.ip() {
        IpAddr::V4(address) => {
            response.push(0x01);
            response.extend_from_slice(&address.octets());
        }
        IpAddr::V6(address) => {
            response.push(0x04);
            response.extend_from_slice(&address.octets());
        }
    }
    response.extend_from_slice(&bound.port().to_be_bytes());
    stream.write_all(&response).await?;
    stream.flush().await
}

fn udp_associate_reply_address(local_ip: IpAddr, public_port: u16) -> SocketAddr {
    // 服务端可能位于云厂商 NAT 后，不能把私网接口地址暴露给公网客户端。
    // 未指定地址要求客户端沿用已连接的 SOCKS5 服务器主机，仅替换 UDP 端口。
    match local_ip {
        IpAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], public_port)),
        IpAddr::V6(_) => SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], public_port)),
    }
}

fn finish_connection(statistics: &Socks5ProxyStatistics) {
    statistics
        .active_connections
        .fetch_sub(1, Ordering::Relaxed);
}

fn authenticated_client(state: &AppState, client_id: Uuid, token: &str) -> bool {
    let mut clients = state.clients.lock().expect("client registry lock poisoned");
    matches!(
        clients.authenticate_and_touch(client_id, token),
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
        .socks5_proxies
        .lock()
        .expect("SOCKS5 proxy registry lock poisoned");
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
        .socks5_proxies
        .lock()
        .expect("SOCKS5 proxy registry lock poisoned")
        .remove(&policy_id)
    {
        let _ = registration.stop_tx.send(());
    }
}

pub(crate) fn stop_all(state: &AppState) {
    let registrations = state
        .socks5_proxies
        .lock()
        .expect("SOCKS5 proxy registry lock poisoned")
        .drain()
        .map(|(_, registration)| registration)
        .collect::<Vec<_>>();
    for registration in registrations {
        let _ = registration.stop_tx.send(());
    }
}

pub(crate) fn online_public_port(registration: &Socks5ProxyRegistration) -> u16 {
    registration.public_port
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn association(peer_ip: IpAddr, requested: Option<UdpAssociationRequest>) -> UdpAssociation {
        UdpAssociation {
            peer_ip,
            requested,
            public_endpoint: None,
        }
    }

    async fn authenticate_test_client(client: &mut TcpStream, username: &[u8], password: &[u8]) {
        client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [0x05, 0x02]);

        let mut auth = vec![0x01, username.len() as u8];
        auth.extend_from_slice(username);
        auth.push(password.len() as u8);
        auth.extend_from_slice(password);
        client.write_all(&auth).await.unwrap();
        let mut auth_reply = [0_u8; 2];
        client.read_exact(&mut auth_reply).await.unwrap();
        assert_eq!(auth_reply, [0x01, 0x00]);
    }

    #[test]
    fn first_udp_datagram_binds_the_only_matching_association() {
        let id = Uuid::new_v4();
        let source = SocketAddr::from(([192, 0, 2, 10], 40_000));
        let endpoint = PublicUdpEndpoint::from(source);
        let associations = Mutex::new(HashMap::from([(id, association(source.ip(), None))]));

        assert_eq!(association_for_source(&associations, endpoint), Some(id));
        assert_eq!(
            associations
                .lock()
                .unwrap()
                .get(&id)
                .unwrap()
                .public_endpoint,
            Some(endpoint)
        );
        assert_eq!(association_for_source(&associations, endpoint), Some(id));
    }

    #[test]
    fn ambiguous_unbound_associations_from_same_ip_are_rejected() {
        let source = SocketAddr::from(([192, 0, 2, 10], 40_000));
        let associations = Mutex::new(HashMap::from([
            (Uuid::new_v4(), association(source.ip(), None)),
            (Uuid::new_v4(), association(source.ip(), None)),
        ]));

        assert_eq!(association_for_source(&associations, source.into()), None);
        assert!(associations
            .lock()
            .unwrap()
            .values()
            .all(|association| association.public_endpoint.is_none()));
    }

    #[test]
    fn requested_udp_port_is_enforced_even_with_unspecified_address() {
        let id = Uuid::new_v4();
        let peer_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let associations = Mutex::new(HashMap::from([(
            id,
            association(
                peer_ip,
                Some(UdpAssociationRequest {
                    ip: None,
                    port: Some(40_000),
                }),
            ),
        )]));

        assert_eq!(
            association_for_source(&associations, SocketAddr::new(peer_ip, 40_001).into(),),
            None
        );
        assert_eq!(
            association_for_source(&associations, SocketAddr::new(peer_ip, 40_000).into(),),
            Some(id)
        );
    }

    #[test]
    fn explicit_ipv6_udp_source_can_match_an_ipv4_control_connection() {
        let id = Uuid::new_v4();
        let requested_ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let requested_port = 40_000;
        let associations = Mutex::new(HashMap::from([(
            id,
            association(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                Some(UdpAssociationRequest {
                    ip: Some(requested_ip),
                    port: Some(requested_port),
                }),
            ),
        )]));

        assert_eq!(
            association_for_source(
                &associations,
                SocketAddr::new(requested_ip, requested_port).into(),
            ),
            Some(id)
        );
    }

    #[test]
    fn unspecified_udp_source_still_matches_the_tcp_peer_ip() {
        let id = Uuid::new_v4();
        let peer_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let associations = Mutex::new(HashMap::from([(id, association(peer_ip, None))]));

        assert_eq!(
            association_for_source(
                &associations,
                SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 40_000).into(),
            ),
            None
        );
        assert_eq!(
            association_for_source(&associations, SocketAddr::new(peer_ip, 40_000).into(),),
            Some(id)
        );
    }

    #[tokio::test]
    async fn udp_associate_handshake_preserves_requested_port() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let password = format!("llp_{}", "a".repeat(64));
        let password_hash = format!("{:x}", Sha256::digest(password.as_bytes()));
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            perform_handshake(&mut stream, b"admin", &password_hash)
                .await
                .unwrap()
        });

        let mut client = TcpStream::connect(address).await.unwrap();
        authenticate_test_client(&mut client, b"admin", password.as_bytes()).await;

        client
            .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0x9c, 0x40])
            .await
            .unwrap();
        assert_eq!(
            server.await.unwrap(),
            Socks5Request::UdpAssociate {
                requested: Some(UdpAssociationRequest {
                    ip: None,
                    port: Some(40_000),
                })
            }
        );
    }

    #[tokio::test]
    async fn bind_is_deterministically_rejected_with_command_not_supported() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let password = format!("llp_{}", "b".repeat(64));
        let password_hash = format!("{:x}", Sha256::digest(password.as_bytes()));
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            perform_handshake(&mut stream, b"admin", &password_hash).await
        });

        let mut client = TcpStream::connect(address).await.unwrap();
        authenticate_test_client(&mut client, b"admin", password.as_bytes()).await;
        client
            .write_all(&[0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0, 80])
            .await
            .unwrap();
        let mut reply = [0_u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[0], 0x05);
        assert_eq!(reply[1], 0x07);
        assert_eq!(
            server.await.unwrap(),
            Err(HandshakeError::UnsupportedCommand { command: 0x02 })
        );
    }

    #[test]
    fn unsupported_bind_and_udp_fragmentation_have_independent_counters() {
        let statistics = Socks5ProxyStatistics::default();
        record_unsupported_command(&statistics, 0x02);
        record_unsupported_command(&statistics, 0x04);
        assert_eq!(statistics.unsupported_commands.load(Ordering::Relaxed), 2);
        assert_eq!(statistics.bind_rejected_total.load(Ordering::Relaxed), 1);

        let valid = [0, 0, 0, 1, 127, 0, 0, 1, 0, 53];
        let fragmented = [0, 0, 1, 1, 127, 0, 0, 1, 0, 53];
        let malformed = [1, 0, 0, 1, 127, 0, 0, 1, 0, 53];
        assert!(accept_socks5_udp_datagram(&valid, &statistics));
        assert!(!accept_socks5_udp_datagram(&fragmented, &statistics));
        assert!(!accept_socks5_udp_datagram(&malformed, &statistics));
        assert_eq!(
            statistics
                .udp_fragmentation_unsupported_total
                .load(Ordering::Relaxed),
            1
        );
        assert_eq!(statistics.udp_dropped_datagrams.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn udp_associate_does_not_advertise_a_private_listener_address() {
        assert_eq!(
            udp_associate_reply_address(IpAddr::V4(Ipv4Addr::new(10, 3, 0, 11)), 32_030),
            SocketAddr::from(([0, 0, 0, 0], 32_030))
        );
        assert_eq!(
            udp_associate_reply_address(IpAddr::V6(Ipv6Addr::LOCALHOST), 32_030),
            SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 32_030))
        );
    }
}
