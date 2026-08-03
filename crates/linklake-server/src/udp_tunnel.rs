//! 服务端 UDP 隧道注册、会话映射与 QUIC DATAGRAM 转发。

use crate::traffic_control::TrafficDecision;
use crate::{
    client_registry::Authentication,
    dual_stack_udp::{bind_public_socket, DualStackUdpSocket, PublicUdpEndpoint},
    record_audit,
    udp_data_plane::AuthenticatedUdpConnection,
    AppState,
};
use bytes::Bytes;
use linklake_core::{
    read_control_frame, read_udp_data_plane_control_frame,
    udp_protocol::{
        fragment_datagram, UdpDirection, UdpFragment, UdpProtocolError, MAX_UDP_DATAGRAM_BYTES,
    },
    udp_reassembly::{
        UdpReassembler, UdpReassemblyConfig, UdpReassemblyError, UdpReassemblyOutcome,
    },
    write_control_frame, write_udp_data_plane_control_frame, BoxedIo, ControlFrame,
    UdpDataPlaneControlFrame, UdpSessionCloseReason,
};
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex, OnceLock,
    },
    time::{Duration, Instant},
};
use tokio::{
    io::split,
    sync::{mpsc, watch, OwnedSemaphorePermit, Semaphore},
    time::{interval, timeout, MissedTickBehavior},
};
use uuid::Uuid;

const CONTROL_IDLE_TIMEOUT: Duration = Duration::from_secs(35);
const SESSION_SWEEP_INTERVAL: Duration = Duration::from_secs(1);
const CONTROL_WRITE_TIMEOUT: Duration = Duration::from_millis(250);
const UDP_RECEIVE_BUFFER_BYTES: usize = MAX_UDP_DATAGRAM_BYTES;
const MAX_SESSIONS_PER_SOURCE_IP: usize = 64;
const SOURCE_NEW_SESSIONS_PER_SECOND: f64 = 20.0;
const SOURCE_NEW_SESSION_BURST: f64 = 40.0;
const POLICY_NEW_SESSIONS_PER_SECOND: f64 = 200.0;
const POLICY_NEW_SESSION_BURST: f64 = 400.0;
const GLOBAL_NEW_SESSIONS_PER_SECOND: f64 = 2_000.0;
const GLOBAL_NEW_SESSION_BURST: f64 = 4_000.0;
const MAX_SOURCE_ADMISSION_ENTRIES: usize = 4_096;
const SOURCE_ADMISSION_RETENTION: Duration = Duration::from_secs(120);

static GLOBAL_NEW_SESSION_LIMITER: OnceLock<Mutex<EventTokenBucket>> = OnceLock::new();

pub(crate) struct UdpTunnelRegistration {
    registration_id: Uuid,
    pub(crate) policy_id: Uuid,
    stop_tx: watch::Sender<()>,
}

#[derive(Default)]
pub(crate) struct UdpTunnelStatistics {
    pub(crate) active_sessions: AtomicUsize,
    pub(crate) packets_from_public: AtomicU64,
    pub(crate) packets_to_public: AtomicU64,
    pub(crate) bytes_from_public: AtomicU64,
    pub(crate) bytes_to_public: AtomicU64,
    pub(crate) dropped_packets: AtomicU64,
    pub(crate) dropped_oversized: AtomicU64,
    pub(crate) dropped_malformed: AtomicU64,
    pub(crate) dropped_unknown_session: AtomicU64,
    pub(crate) dropped_queue_full: AtomicU64,
    pub(crate) dropped_policy_limit: AtomicU64,
    pub(crate) dropped_global_limit: AtomicU64,
    pub(crate) dropped_bandwidth_limit: AtomicU64,
    pub(crate) session_timeouts: AtomicU64,
    pub(crate) reassembly_timeouts: AtomicU64,
    pub(crate) attach_timeouts: AtomicU64,
    pub(crate) transport_errors: AtomicU64,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct UdpTunnelStatisticsSnapshot {
    pub(crate) active_sessions: usize,
    pub(crate) packets_from_public: u64,
    pub(crate) packets_to_public: u64,
    pub(crate) bytes_from_public: u64,
    pub(crate) bytes_to_public: u64,
    pub(crate) dropped_packets: u64,
    pub(crate) dropped_oversized: u64,
    pub(crate) dropped_malformed: u64,
    pub(crate) dropped_unknown_session: u64,
    pub(crate) dropped_queue_full: u64,
    pub(crate) dropped_policy_limit: u64,
    pub(crate) dropped_global_limit: u64,
    pub(crate) dropped_bandwidth_limit: u64,
    pub(crate) session_timeouts: u64,
    pub(crate) reassembly_timeouts: u64,
    pub(crate) attach_timeouts: u64,
    pub(crate) transport_errors: u64,
}

impl UdpTunnelStatistics {
    pub(crate) fn snapshot(&self) -> UdpTunnelStatisticsSnapshot {
        UdpTunnelStatisticsSnapshot {
            active_sessions: self.active_sessions.load(Ordering::Relaxed),
            packets_from_public: self.packets_from_public.load(Ordering::Relaxed),
            packets_to_public: self.packets_to_public.load(Ordering::Relaxed),
            bytes_from_public: self.bytes_from_public.load(Ordering::Relaxed),
            bytes_to_public: self.bytes_to_public.load(Ordering::Relaxed),
            dropped_packets: self.dropped_packets.load(Ordering::Relaxed),
            dropped_oversized: self.dropped_oversized.load(Ordering::Relaxed),
            dropped_malformed: self.dropped_malformed.load(Ordering::Relaxed),
            dropped_unknown_session: self.dropped_unknown_session.load(Ordering::Relaxed),
            dropped_queue_full: self.dropped_queue_full.load(Ordering::Relaxed),
            dropped_policy_limit: self.dropped_policy_limit.load(Ordering::Relaxed),
            dropped_global_limit: self.dropped_global_limit.load(Ordering::Relaxed),
            dropped_bandwidth_limit: self.dropped_bandwidth_limit.load(Ordering::Relaxed),
            session_timeouts: self.session_timeouts.load(Ordering::Relaxed),
            reassembly_timeouts: self.reassembly_timeouts.load(Ordering::Relaxed),
            attach_timeouts: self.attach_timeouts.load(Ordering::Relaxed),
            transport_errors: self.transport_errors.load(Ordering::Relaxed),
        }
    }
}

impl UdpTunnelStatisticsSnapshot {
    pub(crate) fn add_assign(&mut self, other: Self) {
        self.active_sessions += other.active_sessions;
        self.packets_from_public += other.packets_from_public;
        self.packets_to_public += other.packets_to_public;
        self.bytes_from_public += other.bytes_from_public;
        self.bytes_to_public += other.bytes_to_public;
        self.dropped_packets += other.dropped_packets;
        self.dropped_oversized += other.dropped_oversized;
        self.dropped_malformed += other.dropped_malformed;
        self.dropped_unknown_session += other.dropped_unknown_session;
        self.dropped_queue_full += other.dropped_queue_full;
        self.dropped_policy_limit += other.dropped_policy_limit;
        self.dropped_global_limit += other.dropped_global_limit;
        self.dropped_bandwidth_limit += other.dropped_bandwidth_limit;
        self.session_timeouts += other.session_timeouts;
        self.reassembly_timeouts += other.reassembly_timeouts;
        self.attach_timeouts += other.attach_timeouts;
        self.transport_errors += other.transport_errors;
    }
}

struct UdpSession {
    session_id: Uuid,
    source_ip: IpAddr,
    last_activity: Instant,
    _policy_permit: OwnedSemaphorePermit,
    _global_permit: OwnedSemaphorePermit,
}

#[derive(Debug, Clone)]
struct EventTokenBucket {
    tokens_per_second: f64,
    capacity: f64,
    available: f64,
    last_refill: Instant,
}

impl EventTokenBucket {
    fn new(tokens_per_second: f64, capacity: f64, now: Instant) -> Self {
        Self {
            tokens_per_second,
            capacity,
            available: capacity,
            last_refill: now,
        }
    }

    fn try_take(&mut self, now: Instant) -> bool {
        let elapsed = now
            .checked_duration_since(self.last_refill)
            .unwrap_or_default()
            .as_secs_f64();
        self.available = (self.available + elapsed * self.tokens_per_second).min(self.capacity);
        self.last_refill = now;
        if self.available < 1.0 {
            return false;
        }
        self.available -= 1.0;
        true
    }
}

#[derive(Debug)]
struct SourceAdmission {
    active_sessions: usize,
    new_session_limiter: EventTokenBucket,
    last_seen: Instant,
}

#[derive(Debug)]
struct SessionAdmission {
    sources: HashMap<IpAddr, SourceAdmission>,
    policy_limiter: EventTokenBucket,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionAdmissionRejection {
    SourceLimit,
    PolicyRate,
    GlobalRate,
}

impl SessionAdmission {
    fn new(now: Instant) -> Self {
        Self {
            sources: HashMap::new(),
            policy_limiter: EventTokenBucket::new(
                POLICY_NEW_SESSIONS_PER_SECOND,
                POLICY_NEW_SESSION_BURST,
                now,
            ),
        }
    }

    fn try_admit(
        &mut self,
        source_ip: IpAddr,
        now: Instant,
    ) -> Result<(), SessionAdmissionRejection> {
        self.cleanup(now);
        if !self.sources.contains_key(&source_ip) {
            if self.sources.len() >= MAX_SOURCE_ADMISSION_ENTRIES {
                self.evict_oldest_inactive();
            }
            if self.sources.len() >= MAX_SOURCE_ADMISSION_ENTRIES {
                return Err(SessionAdmissionRejection::SourceLimit);
            }
            self.sources.insert(
                source_ip,
                SourceAdmission {
                    active_sessions: 0,
                    new_session_limiter: EventTokenBucket::new(
                        SOURCE_NEW_SESSIONS_PER_SECOND,
                        SOURCE_NEW_SESSION_BURST,
                        now,
                    ),
                    last_seen: now,
                },
            );
        }

        let source = self
            .sources
            .get_mut(&source_ip)
            .expect("source admission was inserted before use");
        source.last_seen = now;
        if source.active_sessions >= MAX_SESSIONS_PER_SOURCE_IP
            || !source.new_session_limiter.try_take(now)
        {
            return Err(SessionAdmissionRejection::SourceLimit);
        }
        if !self.policy_limiter.try_take(now) {
            return Err(SessionAdmissionRejection::PolicyRate);
        }
        let global_limiter = GLOBAL_NEW_SESSION_LIMITER.get_or_init(|| {
            Mutex::new(EventTokenBucket::new(
                GLOBAL_NEW_SESSIONS_PER_SECOND,
                GLOBAL_NEW_SESSION_BURST,
                now,
            ))
        });
        if !global_limiter
            .lock()
            .expect("global UDP session admission lock poisoned")
            .try_take(now)
        {
            return Err(SessionAdmissionRejection::GlobalRate);
        }
        source.active_sessions += 1;
        Ok(())
    }

    fn release(&mut self, source_ip: IpAddr, now: Instant) {
        if let Some(source) = self.sources.get_mut(&source_ip) {
            source.active_sessions = source.active_sessions.saturating_sub(1);
            source.last_seen = now;
        }
    }

    fn cleanup(&mut self, now: Instant) {
        self.sources.retain(|_, source| {
            source.active_sessions != 0
                || now
                    .checked_duration_since(source.last_seen)
                    .unwrap_or_default()
                    < SOURCE_ADMISSION_RETENTION
        });
    }

    fn evict_oldest_inactive(&mut self) {
        let oldest = self
            .sources
            .iter()
            .filter(|(_, source)| source.active_sessions == 0)
            .min_by_key(|(_, source)| source.last_seen)
            .map(|(source_ip, _)| *source_ip);
        if let Some(source_ip) = oldest {
            self.sources.remove(&source_ip);
        }
    }
}

struct TokenBucket {
    bytes_per_second: u64,
    capacity: f64,
    available: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(bytes_per_second: u64) -> Self {
        let capacity = bytes_per_second.max(MAX_UDP_DATAGRAM_BYTES as u64) as f64;
        Self {
            bytes_per_second,
            capacity,
            available: capacity,
            last_refill: Instant::now(),
        }
    }

    /// UDP 不能等待带宽令牌，否则会制造无界排队；令牌不足时直接丢包。
    fn try_consume(&mut self, bytes: usize, now: Instant) -> bool {
        let elapsed = now
            .checked_duration_since(self.last_refill)
            .unwrap_or_default()
            .as_secs_f64();
        self.available =
            (self.available + elapsed * self.bytes_per_second as f64).min(self.capacity);
        self.last_refill = now;
        if self.available < bytes as f64 {
            return false;
        }
        self.available -= bytes as f64;
        true
    }
}

enum RuntimeStop {
    PolicyDisabled,
    ControlClosed,
    DataPlaneClosed,
}

struct RegisteredTunnelRuntime {
    state: Arc<AppState>,
    public_port: u16,
    registration_id: Uuid,
    socket: DualStackUdpSocket,
    authenticated: AuthenticatedUdpConnection,
    policy: crate::tunnel_catalog::UdpTunnelRuntimePolicy,
    statistics: Arc<UdpTunnelStatistics>,
    control_stream: BoxedIo,
    stop: watch::Receiver<()>,
}

pub(crate) async fn register_tunnel(
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
        reject_registration(
            &state,
            &mut stream,
            "tunnel name and target address are required",
        )
        .await;
        return;
    }
    let runtime_policy = state
        .tunnel_catalog
        .lock()
        .expect("tunnel catalog lock poisoned")
        .udp_runtime_policy(client_id, &name, public_port, &target_addr)
        .unwrap_or(None);
    let Some(runtime_policy) = runtime_policy else {
        reject_registration(
            &state,
            &mut stream,
            "no enabled management policy matches this UDP tunnel",
        )
        .await;
        return;
    };
    let Some(data_plane) = state.udp_data_plane.clone() else {
        reject_registration(
            &state,
            &mut stream,
            "UDP data plane is not configured on this server",
        )
        .await;
        return;
    };
    let public_socket = match bind_public_socket(&state, public_port, "udp_tunnel").await {
        Ok(socket) => socket,
        Err(_) => {
            reject_registration(&state, &mut stream, "public UDP port is unavailable").await;
            return;
        }
    };

    let registration_id = Uuid::new_v4();
    let attachment = data_plane.reserve_attachment(client_id, registration_id);
    let offer = attachment.offer().clone();
    if write_control_frame(
        &mut stream,
        &ControlFrame::UdpDataPlaneOffer {
            registration_id,
            ticket: offer.ticket,
            endpoint: offer.endpoint,
            server_name: offer.server_name,
            max_datagram_size: offer.max_datagram_size,
            session_idle_timeout_seconds: runtime_policy.session_idle_timeout_seconds as u32,
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
            let statistics = statistics_for(&state, runtime_policy.policy_id);
            statistics.attach_timeouts.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                "UDP data-plane attachment failed for public port {public_port}: {error}"
            );
            send_error(
                &mut stream,
                "UDP data-plane attachment timed out or was rejected",
            )
            .await;
            return;
        }
    };

    // ticket 等待期间策略可能已被管理员禁用或删除，启动运行时前必须再次确认。
    let policy_still_enabled = state
        .tunnel_catalog
        .lock()
        .expect("tunnel catalog lock poisoned")
        .udp_runtime_policy(client_id, &name, public_port, &target_addr)
        .ok()
        .flatten()
        .is_some_and(|current| current.policy_id == runtime_policy.policy_id);
    if !policy_still_enabled {
        authenticated
            .connection
            .close(5_u8.into(), b"UDP policy was disabled");
        send_error(
            &mut stream,
            "UDP tunnel policy was disabled during attachment",
        )
        .await;
        return;
    }

    let negotiated_max_datagram_size = authenticated
        .connection
        .max_datagram_size()
        .unwrap_or(offer.max_datagram_size as usize)
        .min(offer.max_datagram_size as usize);
    if write_ready(
        &mut authenticated.control_send,
        registration_id,
        negotiated_max_datagram_size,
    )
    .await
    .is_err()
    {
        authenticated
            .connection
            .close(6_u8.into(), b"could not send UDP ready frame");
        return;
    }
    if write_control_frame(
        &mut stream,
        &ControlFrame::UdpTunnelRegistered {
            registration_id,
            public_port,
        },
    )
    .await
    .is_err()
    {
        authenticated
            .connection
            .close(7_u8.into(), b"UDP registration control connection closed");
        return;
    }

    let statistics = statistics_for(&state, runtime_policy.policy_id);
    let (stop_tx, stop_rx) = watch::channel(());
    {
        let mut tunnels = state
            .udp_tunnels
            .lock()
            .expect("UDP tunnel registry lock poisoned");
        if let Some(previous) = tunnels.insert(
            public_port,
            UdpTunnelRegistration {
                registration_id,
                policy_id: runtime_policy.policy_id,
                stop_tx,
            },
        ) {
            let _ = previous.stop_tx.send(());
        }
    }
    state
        .metrics
        .tunnel_registrations_total
        .fetch_add(1, Ordering::Relaxed);
    if !state
        .seen_udp_tunnel_registrations
        .lock()
        .expect("seen UDP tunnel registrations lock poisoned")
        .insert((client_id, public_port))
    {
        state
            .metrics
            .tunnel_reconnects_total
            .fetch_add(1, Ordering::Relaxed);
    }
    record_audit(
        &state,
        "udp_tunnel.registered",
        &client_id.to_string(),
        &format!("name={name}; public_port={public_port}; target={target_addr}"),
    );
    run_tunnel(RegisteredTunnelRuntime {
        state,
        public_port,
        registration_id,
        socket: public_socket,
        authenticated,
        policy: runtime_policy,
        statistics,
        control_stream: stream,
        stop: stop_rx,
    })
    .await;
}

async fn write_ready(
    control_send: &mut quinn::SendStream,
    registration_id: Uuid,
    negotiated_max_datagram_size: usize,
) -> Result<(), linklake_core::ControlFrameError> {
    write_udp_data_plane_control_frame(
        control_send,
        &UdpDataPlaneControlFrame::Ready {
            registration_id,
            negotiated_max_datagram_size: negotiated_max_datagram_size as u32,
        },
    )
    .await
}

fn statistics_for(state: &AppState, policy_id: Uuid) -> Arc<UdpTunnelStatistics> {
    state
        .udp_tunnel_statistics
        .lock()
        .expect("UDP tunnel statistics lock poisoned")
        .entry(policy_id)
        .or_insert_with(|| Arc::new(UdpTunnelStatistics::default()))
        .clone()
}

async fn run_tunnel(runtime: RegisteredTunnelRuntime) {
    let RegisteredTunnelRuntime {
        state,
        public_port,
        registration_id,
        socket,
        authenticated,
        policy,
        statistics,
        control_stream,
        stop,
    } = runtime;
    let AuthenticatedUdpConnection {
        connection,
        control_send,
        control_receive,
        active_attachment_permit: _active_attachment_permit,
    } = authenticated;
    let (control_reader, control_writer) = split(control_stream);
    let (tcp_frames_tx, tcp_frames_rx) = mpsc::channel(16);
    let tcp_reader_task = tokio::spawn(read_tcp_control_frames(control_reader, tcp_frames_tx));
    let (quic_frames_tx, quic_frames_rx) = mpsc::channel(16);
    let quic_reader_task = tokio::spawn(read_quic_control_frames(control_receive, quic_frames_tx));

    let stop_reason = run_tunnel_loop(
        &state,
        public_port,
        socket,
        &connection,
        control_send,
        control_writer,
        tcp_frames_rx,
        quic_frames_rx,
        policy,
        &statistics,
        stop,
    )
    .await;
    tcp_reader_task.abort();
    quic_reader_task.abort();
    let message = match stop_reason {
        RuntimeStop::PolicyDisabled => b"UDP policy disabled".as_slice(),
        RuntimeStop::ControlClosed => b"UDP control connection closed".as_slice(),
        RuntimeStop::DataPlaneClosed => b"UDP data plane closed".as_slice(),
    };
    connection.close(0_u8.into(), message);
    remove_tunnel(&state, public_port, registration_id);
}

#[allow(clippy::too_many_arguments)]
async fn run_tunnel_loop(
    state: &Arc<AppState>,
    public_port: u16,
    socket: DualStackUdpSocket,
    connection: &quinn::Connection,
    mut quic_control_send: quinn::SendStream,
    mut tcp_control_writer: tokio::io::WriteHalf<BoxedIo>,
    mut tcp_frames: mpsc::Receiver<ControlFrame>,
    mut quic_frames: mpsc::Receiver<UdpDataPlaneControlFrame>,
    policy: crate::tunnel_catalog::UdpTunnelRuntimePolicy,
    statistics: &Arc<UdpTunnelStatistics>,
    mut stop: watch::Receiver<()>,
) -> RuntimeStop {
    let policy_permits = Arc::new(Semaphore::new(policy.max_sessions));
    let mut sessions_by_external = HashMap::<PublicUdpEndpoint, UdpSession>::new();
    let mut external_by_session = HashMap::<Uuid, PublicUdpEndpoint>::new();
    let mut session_admission = SessionAdmission::new(Instant::now());
    let mut reassembler = UdpReassembler::new(UdpReassemblyConfig::default())
        .expect("the built-in UDP reassembly configuration is valid");
    let mut limiter = policy.bandwidth_limit_bps.map(TokenBucket::new);
    let mut datagram_id = 0_u64;
    let mut usage_pending = 0_u64;
    let mut public_buffer = vec![0_u8; UDP_RECEIVE_BUFFER_BYTES];
    let mut sweep = interval(SESSION_SWEEP_INTERVAL);
    sweep.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut control_deadline = Instant::now() + CONTROL_IDLE_TIMEOUT;

    let stop_reason = loop {
        tokio::select! {
            _ = stop.changed() => break RuntimeStop::PolicyDisabled,
            _ = connection.closed() => {
                statistics.transport_errors.fetch_add(1, Ordering::Relaxed);
                break RuntimeStop::DataPlaneClosed;
            }
            frame = tcp_frames.recv() => match frame {
                Some(ControlFrame::ControlHeartbeat { nonce }) => {
                    control_deadline = Instant::now() + CONTROL_IDLE_TIMEOUT;
                    if !matches!(timeout(
                        CONTROL_WRITE_TIMEOUT,
                        write_control_frame(
                            &mut tcp_control_writer,
                            &ControlFrame::ControlHeartbeatAck { nonce },
                        ),
                    )
                    .await, Ok(Ok(())))
                    {
                        break RuntimeStop::ControlClosed;
                    }
                }
                Some(_) => {
                    statistics.transport_errors.fetch_add(1, Ordering::Relaxed);
                    break RuntimeStop::ControlClosed;
                }
                None => break RuntimeStop::ControlClosed,
            },
            frame = quic_frames.recv() => match frame {
                Some(UdpDataPlaneControlFrame::CloseSession { session_id, reason }) => {
                    if let Some(address) = external_by_session.get(&session_id).copied() {
                        if remove_session(
                            &mut sessions_by_external,
                            &mut external_by_session,
                            &mut session_admission,
                            address,
                            Instant::now(),
                        ).is_some() {
                            reassembler.discard_session(session_id);
                            statistics.active_sessions.fetch_sub(1, Ordering::Relaxed);
                            if reason == UdpSessionCloseReason::IdleTimeout {
                                statistics.session_timeouts.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    } else {
                        statistics.dropped_unknown_session.fetch_add(1, Ordering::Relaxed);
                    }
                    tracing::debug!(
                        "UDP client closed session {session_id} on port {public_port}: {reason:?}"
                    );
                }
                Some(UdpDataPlaneControlFrame::Error { code, message }) => {
                    tracing::warn!("UDP client data-plane error on port {public_port}: {code}: {message}");
                    statistics.transport_errors.fetch_add(1, Ordering::Relaxed);
                    break RuntimeStop::DataPlaneClosed;
                }
                Some(_) => {
                    statistics.transport_errors.fetch_add(1, Ordering::Relaxed);
                    break RuntimeStop::DataPlaneClosed;
                }
                None => break RuntimeStop::DataPlaneClosed,
            },
            received = socket.recv_from(&mut public_buffer) => match received {
                Ok(received) => {
                    let length = received.length;
                    let external_endpoint = received.source;
                    let external_address = external_endpoint.address();
                    let now = Instant::now();
                    if let Some(limiter) = &mut limiter {
                        if !limiter.try_consume(length, now) {
                            record_drop(statistics, &statistics.dropped_bandwidth_limit);
                            continue;
                        }
                    }
                    let (session_id, created_new_session) = if let Some(session) = sessions_by_external.get_mut(&external_endpoint) {
                        session.last_activity = now;
                        (session.session_id, false)
                    } else {
                        let decision = state.traffic_controls
                            .lock()
                            .expect("traffic control catalog lock poisoned")
                            .authorize(policy.policy_kind, policy.policy_id, external_address.ip(), crate::unix_seconds());
                        if !matches!(decision, Ok(TrafficDecision::Allowed)) {
                            record_drop(statistics, &statistics.dropped_policy_limit);
                            tracing::debug!("UDP traffic control rejected {external_address}: {decision:?}");
                            continue;
                        }
                        let Ok(policy_permit) = policy_permits.clone().try_acquire_owned() else {
                            record_drop(statistics, &statistics.dropped_policy_limit);
                            continue;
                        };
                        let Ok(global_permit) = state.global_udp_session_permits.clone().try_acquire_owned() else {
                            record_drop(statistics, &statistics.dropped_global_limit);
                            continue;
                        };
                        match session_admission.try_admit(external_address.ip(), now) {
                            Ok(()) => {}
                            Err(SessionAdmissionRejection::GlobalRate) => {
                                record_drop(statistics, &statistics.dropped_global_limit);
                                continue;
                            }
                            Err(
                                SessionAdmissionRejection::SourceLimit
                                | SessionAdmissionRejection::PolicyRate,
                            ) => {
                                record_drop(statistics, &statistics.dropped_policy_limit);
                                continue;
                            }
                        }
                        let session_id = Uuid::new_v4();
                        sessions_by_external.insert(external_endpoint, UdpSession {
                            session_id,
                            source_ip: external_address.ip(),
                            last_activity: now,
                            _policy_permit: policy_permit,
                            _global_permit: global_permit,
                        });
                        external_by_session.insert(session_id, external_endpoint);
                        statistics.active_sessions.fetch_add(1, Ordering::Relaxed);
                        (session_id, true)
                    };
                    datagram_id = datagram_id.wrapping_add(1);
                    let max_frame_size = connection.max_datagram_size().unwrap_or(1_200).min(1_200);
                    let frames = match fragment_datagram(
                        UdpDirection::PublicToTarget,
                        session_id,
                        datagram_id,
                        &public_buffer[..length],
                        max_frame_size,
                    ) {
                        Ok(frames) => frames,
                        Err(error) => {
                            record_protocol_drop(statistics, &error);
                            if created_new_session
                                && remove_session(
                                    &mut sessions_by_external,
                                    &mut external_by_session,
                                    &mut session_admission,
                                    external_endpoint,
                                    now,
                                )
                                .is_some()
                            {
                                statistics.active_sessions.fetch_sub(1, Ordering::Relaxed);
                            }
                            continue;
                        }
                    };
                    if frames.into_iter().any(|frame| connection.send_datagram(Bytes::from(frame)).is_err()) {
                        record_drop(statistics, &statistics.dropped_queue_full);
                        if created_new_session
                            && remove_session(
                                &mut sessions_by_external,
                                &mut external_by_session,
                                &mut session_admission,
                                external_endpoint,
                                now,
                            )
                            .is_some()
                        {
                            statistics.active_sessions.fetch_sub(1, Ordering::Relaxed);
                        }
                        continue;
                    }
                    statistics.packets_from_public.fetch_add(1, Ordering::Relaxed);
                    statistics.bytes_from_public.fetch_add(length as u64, Ordering::Relaxed);
                    usage_pending = usage_pending.saturating_add(length as u64);
                }
                Err(error) => {
                    statistics.transport_errors.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!("UDP public socket receive failed on port {public_port}: {error}");
                    break RuntimeStop::ControlClosed;
                }
            },
            received = connection.read_datagram() => match received {
                Ok(encoded) => {
                    let fragment = match UdpFragment::decode(&encoded) {
                        Ok(fragment) if fragment.direction == UdpDirection::TargetToPublic => fragment,
                        Ok(_) => {
                            record_drop(statistics, &statistics.dropped_malformed);
                            continue;
                        }
                        Err(error) => {
                            record_protocol_drop(statistics, &error);
                            continue;
                        }
                    };
                    let Some(external_endpoint) = external_by_session.get(&fragment.session_id).copied() else {
                        record_drop(statistics, &statistics.dropped_unknown_session);
                        continue;
                    };
                    let now = Instant::now();
                    match reassembler.push(fragment, now) {
                        Ok(UdpReassemblyOutcome::Pending | UdpReassemblyOutcome::Duplicate) => {}
                        Ok(UdpReassemblyOutcome::Complete(payload)) => {
                            if let Some(limiter) = &mut limiter {
                                if !limiter.try_consume(payload.len(), now) {
                                    record_drop(statistics, &statistics.dropped_bandwidth_limit);
                                    continue;
                                }
                            }
                            match socket.send_to(&payload, external_endpoint).await {
                                Ok(sent) if sent == payload.len() => {
                                    if let Some(session) = sessions_by_external.get_mut(&external_endpoint) {
                                        session.last_activity = now;
                                    }
                                    statistics.packets_to_public.fetch_add(1, Ordering::Relaxed);
                                    statistics.bytes_to_public.fetch_add(sent as u64, Ordering::Relaxed);
                                    usage_pending = usage_pending.saturating_add(sent as u64);
                                }
                                Ok(_) | Err(_) => {
                                    statistics.transport_errors.fetch_add(1, Ordering::Relaxed);
                                    record_drop(statistics, &statistics.dropped_queue_full);
                                }
                            }
                        }
                        Err(error) => record_reassembly_drop(statistics, &error),
                    }
                }
                Err(_) => {
                    statistics.transport_errors.fetch_add(1, Ordering::Relaxed);
                    break RuntimeStop::DataPlaneClosed;
                }
            },
            _ = sweep.tick() => {
                let now = Instant::now();
                if usage_pending != 0 {
                    if let Err(error) = state.traffic_controls
                        .lock()
                        .expect("traffic control catalog lock poisoned")
                        .record_bytes(policy.policy_kind, policy.policy_id, usage_pending, crate::unix_seconds())
                    {
                        tracing::warn!("Could not persist UDP traffic usage: {error}");
                    } else {
                        usage_pending = 0;
                    }
                }
                if now >= control_deadline {
                    statistics.transport_errors.fetch_add(1, Ordering::Relaxed);
                    break RuntimeStop::ControlClosed;
                }
                let idle_timeout = Duration::from_secs(policy.session_idle_timeout_seconds);
                let expired = sessions_by_external
                    .iter()
                    .filter_map(|(address, session)| {
                        now.checked_duration_since(session.last_activity)
                            .is_some_and(|elapsed| elapsed >= idle_timeout)
                            .then_some((*address, session.session_id))
                    })
                    .collect::<Vec<_>>();
                for (address, session_id) in &expired {
                    remove_session(
                        &mut sessions_by_external,
                        &mut external_by_session,
                        &mut session_admission,
                        *address,
                        now,
                    );
                    reassembler.discard_session(*session_id);
                    statistics.active_sessions.fetch_sub(1, Ordering::Relaxed);
                    statistics.session_timeouts.fetch_add(1, Ordering::Relaxed);
                }
                session_admission.cleanup(now);
                // 批量回收先于通知，并让整批通知共用一个总超时，避免大量空闲会话阻塞转发循环。
                let notify_expired = async {
                    for (_, session_id) in expired {
                        write_udp_data_plane_control_frame(
                            &mut quic_control_send,
                            &UdpDataPlaneControlFrame::CloseSession {
                                session_id,
                                reason: UdpSessionCloseReason::IdleTimeout,
                            },
                        )
                        .await?;
                    }
                    Ok::<(), linklake_core::ControlFrameError>(())
                };
                let _ = timeout(CONTROL_WRITE_TIMEOUT, notify_expired).await;
                let expired_fragments = reassembler.expire(now);
                if expired_fragments.incomplete_datagrams != 0 {
                    statistics.dropped_packets.fetch_add(
                        expired_fragments.incomplete_datagrams as u64,
                        Ordering::Relaxed,
                    );
                    statistics.reassembly_timeouts.fetch_add(
                        expired_fragments.incomplete_datagrams as u64,
                        Ordering::Relaxed,
                    );
                }
            }
        }
    };

    let close_reason = match stop_reason {
        RuntimeStop::PolicyDisabled => UdpSessionCloseReason::PolicyDisabled,
        RuntimeStop::ControlClosed | RuntimeStop::DataPlaneClosed => {
            UdpSessionCloseReason::DataPlaneClosed
        }
    };
    if usage_pending != 0 {
        if let Err(error) = state
            .traffic_controls
            .lock()
            .expect("traffic control catalog lock poisoned")
            .record_bytes(
                policy.policy_kind,
                policy.policy_id,
                usage_pending,
                crate::unix_seconds(),
            )
        {
            tracing::warn!("Could not persist final UDP traffic usage: {error}");
        }
    }
    let session_ids = sessions_by_external
        .values()
        .map(|session| session.session_id)
        .collect::<Vec<_>>();
    // 先释放会话持有的策略与全局 permit，再在一个总超时内尽力通知客户端。
    // 这样即使 QUIC 控制流阻塞，策略禁用和重连也不会被会话数量线性拖慢。
    sessions_by_external.clear();
    external_by_session.clear();
    statistics.active_sessions.store(0, Ordering::Relaxed);
    let notify_sessions = async {
        for session_id in session_ids {
            write_udp_data_plane_control_frame(
                &mut quic_control_send,
                &UdpDataPlaneControlFrame::CloseSession {
                    session_id,
                    reason: close_reason,
                },
            )
            .await?;
        }
        Ok::<(), linklake_core::ControlFrameError>(())
    };
    let _ = timeout(CONTROL_WRITE_TIMEOUT, notify_sessions).await;
    stop_reason
}

async fn read_tcp_control_frames(
    mut reader: tokio::io::ReadHalf<BoxedIo>,
    frames: mpsc::Sender<ControlFrame>,
) {
    while let Ok(frame) = read_control_frame(&mut reader).await {
        if frames.send(frame).await.is_err() {
            return;
        }
    }
}

fn remove_session(
    sessions_by_external: &mut HashMap<PublicUdpEndpoint, UdpSession>,
    external_by_session: &mut HashMap<Uuid, PublicUdpEndpoint>,
    session_admission: &mut SessionAdmission,
    external_endpoint: PublicUdpEndpoint,
    now: Instant,
) -> Option<Uuid> {
    let session = sessions_by_external.remove(&external_endpoint)?;
    external_by_session.remove(&session.session_id);
    session_admission.release(session.source_ip, now);
    Some(session.session_id)
}

async fn read_quic_control_frames(
    mut reader: quinn::RecvStream,
    frames: mpsc::Sender<UdpDataPlaneControlFrame>,
) {
    while let Ok(frame) = read_udp_data_plane_control_frame(&mut reader).await {
        if frames.send(frame).await.is_err() {
            return;
        }
    }
}

fn record_drop(statistics: &UdpTunnelStatistics, reason: &AtomicU64) {
    statistics.dropped_packets.fetch_add(1, Ordering::Relaxed);
    reason.fetch_add(1, Ordering::Relaxed);
}

fn record_protocol_drop(statistics: &UdpTunnelStatistics, error: &UdpProtocolError) {
    let reason = if matches!(error, UdpProtocolError::DatagramTooLarge(_)) {
        &statistics.dropped_oversized
    } else {
        &statistics.dropped_malformed
    };
    record_drop(statistics, reason);
}

fn record_reassembly_drop(statistics: &UdpTunnelStatistics, error: &UdpReassemblyError) {
    if let UdpReassemblyError::InvalidFragment(protocol_error) = error {
        record_protocol_drop(statistics, protocol_error);
    } else {
        record_drop(statistics, &statistics.dropped_malformed);
    }
}

fn authenticated_client(state: &AppState, client_id: Uuid, token: &str) -> bool {
    let mut clients = state.clients.lock().expect("client registry lock poisoned");
    matches!(
        clients.authenticate_and_touch(client_id, token),
        Ok(Authentication::Authenticated)
    )
}

async fn reject_registration(state: &AppState, stream: &mut BoxedIo, message: &str) {
    state
        .metrics
        .registration_rejections_total
        .fetch_add(1, Ordering::Relaxed);
    send_error(stream, message).await;
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

fn remove_tunnel(state: &AppState, public_port: u16, registration_id: Uuid) {
    let mut tunnels = state
        .udp_tunnels
        .lock()
        .expect("UDP tunnel registry lock poisoned");
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
        .udp_tunnels
        .lock()
        .expect("UDP tunnel registry lock poisoned")
        .remove(&public_port)
    {
        let _ = tunnel.stop_tx.send(());
    }
}

pub(crate) fn stop_all(state: &AppState) {
    let registrations = state
        .udp_tunnels
        .lock()
        .expect("UDP tunnel registry lock poisoned")
        .drain()
        .map(|(_, tunnel)| tunnel)
        .collect::<Vec<_>>();
    for tunnel in registrations {
        let _ = tunnel.stop_tx.send(());
    }
}

#[cfg(test)]
mod tests {
    use super::{
        record_protocol_drop, record_reassembly_drop, EventTokenBucket, SessionAdmission,
        SessionAdmissionRejection, SourceAdmission, TokenBucket, UdpSession, UdpTunnelStatistics,
        UdpTunnelStatisticsSnapshot, MAX_SESSIONS_PER_SOURCE_IP,
    };
    use crate::dual_stack_udp::PublicUdpEndpoint;
    use linklake_core::{udp_protocol::UdpProtocolError, udp_reassembly::UdpReassemblyError};
    use std::{
        collections::HashMap,
        net::{IpAddr, SocketAddr},
        sync::{atomic::Ordering, Arc},
        time::{Duration, Instant},
    };
    use tokio::sync::Semaphore;
    use uuid::Uuid;

    #[test]
    fn token_bucket_drops_without_waiting_and_refills() {
        let mut bucket = TokenBucket::new(1_024);
        let now = Instant::now();
        assert!(bucket.try_consume(65_507, now));
        assert!(!bucket.try_consume(1, now));
        assert!(bucket.try_consume(1_024, now + Duration::from_secs(1)));
    }

    #[test]
    fn protocol_drop_reasons_and_snapshots_remain_consistent() {
        let statistics = UdpTunnelStatistics::default();
        statistics.packets_from_public.store(7, Ordering::Relaxed);
        record_protocol_drop(&statistics, &UdpProtocolError::DatagramTooLarge(65_508));
        record_protocol_drop(&statistics, &UdpProtocolError::InvalidMagic);
        record_reassembly_drop(&statistics, &UdpReassemblyError::MemoryLimit);

        let snapshot = statistics.snapshot();
        assert_eq!(snapshot.packets_from_public, 7);
        assert_eq!(snapshot.dropped_packets, 3);
        assert_eq!(snapshot.dropped_oversized, 1);
        assert_eq!(snapshot.dropped_malformed, 2);

        let mut totals = UdpTunnelStatisticsSnapshot::default();
        totals.add_assign(snapshot);
        totals.add_assign(snapshot);
        assert_eq!(totals.packets_from_public, 14);
        assert_eq!(totals.dropped_packets, 6);
        assert_eq!(totals.dropped_oversized, 2);
        assert_eq!(totals.dropped_malformed, 4);
    }

    #[tokio::test]
    async fn clearing_sessions_releases_policy_and_global_permits() {
        let policy_permits = Arc::new(Semaphore::new(1));
        let global_permits = Arc::new(Semaphore::new(1));
        let mut sessions = HashMap::new();
        sessions.insert(
            "127.0.0.1:40000"
                .parse::<SocketAddr>()
                .map(PublicUdpEndpoint::from)
                .expect("valid address"),
            UdpSession {
                session_id: Uuid::new_v4(),
                source_ip: "127.0.0.1".parse().expect("valid IP"),
                last_activity: Instant::now(),
                _policy_permit: policy_permits
                    .clone()
                    .acquire_owned()
                    .await
                    .expect("policy permit should be available"),
                _global_permit: global_permits
                    .clone()
                    .acquire_owned()
                    .await
                    .expect("global permit should be available"),
            },
        );
        assert_eq!(policy_permits.available_permits(), 0);
        assert_eq!(global_permits.available_permits(), 0);

        sessions.clear();

        assert_eq!(policy_permits.available_permits(), 1);
        assert_eq!(global_permits.available_permits(), 1);
    }

    #[test]
    fn event_token_bucket_is_non_blocking_and_refills() {
        let now = Instant::now();
        let mut bucket = EventTokenBucket::new(2.0, 2.0, now);
        assert!(bucket.try_take(now));
        assert!(bucket.try_take(now));
        assert!(!bucket.try_take(now));
        assert!(bucket.try_take(now + Duration::from_millis(500)));
    }

    #[test]
    fn source_session_cap_rejects_before_global_admission() {
        let now = Instant::now();
        let source_ip: IpAddr = "192.0.2.10".parse().expect("valid IP");
        let mut admission = SessionAdmission::new(now);
        admission.sources.insert(
            source_ip,
            SourceAdmission {
                active_sessions: MAX_SESSIONS_PER_SOURCE_IP,
                new_session_limiter: EventTokenBucket::new(20.0, 40.0, now),
                last_seen: now,
            },
        );
        assert_eq!(
            admission.try_admit(source_ip, now),
            Err(SessionAdmissionRejection::SourceLimit)
        );
    }
}
