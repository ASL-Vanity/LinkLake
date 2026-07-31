use super::{
    connect_control, send_control_heartbeats, ControlTransport, CONTROL_HEARTBEAT_TIMEOUT,
    TARGET_CONNECT_TIMEOUT,
};
use bytes::Bytes;
use linklake_core::{
    read_control_frame, read_udp_data_plane_control_frame,
    udp_protocol::{fragment_datagram, UdpDirection, UdpFragment, MAX_UDP_DATAGRAM_BYTES},
    udp_reassembly::{
        UdpReassembler, UdpReassemblyConfig, UdpReassemblyOutcome, UDP_REASSEMBLY_TIMEOUT,
    },
    write_control_frame, write_udp_data_plane_control_frame, ControlFrame,
    UdpDataPlaneControlFrame, UdpSessionCloseReason, UDP_DATA_PLANE_ALPN,
    UDP_DATA_PLANE_PROTOCOL_VERSION,
};
use quinn::crypto::rustls::QuicClientConfig;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{split, ReadHalf},
    net::{lookup_host, UdpSocket},
    sync::{mpsc, OwnedSemaphorePermit, Semaphore},
    time::{interval, timeout, MissedTickBehavior},
};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use uuid::Uuid;

pub(super) const UDP_QUEUE_BUDGET_BYTES: usize = 32 * 1024 * 1024;
// QUIC DATAGRAM 和 Windows 调度都可能把原本均匀的流量成批交付。
// 每会话需要吸收常见的小突发；总内存仍由 UDP_QUEUE_BUDGET_BYTES 严格限制。
const SESSION_QUEUE_CAPACITY: usize = 256;
const SESSION_EVENT_CAPACITY: usize = 256;
const CONTROL_EVENT_CAPACITY: usize = 64;
const SESSION_CLEANUP_INTERVAL: Duration = Duration::from_secs(1);
const CLOSED_SESSION_RETENTION: Duration = UDP_REASSEMBLY_TIMEOUT;

pub(crate) struct UdpDataPlaneOffer {
    pub(crate) registration_id: Uuid,
    pub(crate) ticket: String,
    pub(crate) endpoint: String,
    pub(crate) server_name: String,
    pub(crate) max_datagram_size: usize,
    pub(crate) session_idle_timeout: Duration,
}

pub(crate) struct EstablishedDataPlane {
    pub(crate) _endpoint: quinn::Endpoint,
    pub(crate) connection: quinn::Connection,
    pub(crate) control_send: quinn::SendStream,
    pub(crate) control_recv: quinn::RecvStream,
    pub(crate) max_datagram_size: usize,
}

struct TargetSession {
    sender: mpsc::Sender<QueuedDatagram>,
    last_activity: Arc<Mutex<Instant>>,
    worker: tokio::task::JoinHandle<()>,
}

struct QueuedDatagram {
    payload: Vec<u8>,
    _permit: OwnedSemaphorePermit,
}

#[derive(Debug, PartialEq, Eq)]
enum QueueDatagramError {
    BudgetExhausted,
    Full,
    Closed,
}

impl Drop for TargetSession {
    fn drop(&mut self) {
        // 会话从映射中移除时立即取消目标 socket worker，避免它继续接收并回送旧会话报文。
        self.worker.abort();
    }
}

enum SessionEvent {
    Close {
        session_id: Uuid,
        reason: UdpSessionCloseReason,
    },
}

pub(super) fn build_quic_client_config(
    roots: RootCertStore,
) -> anyhow::Result<quinn::ClientConfig> {
    let mut crypto = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![UDP_DATA_PLANE_ALPN.to_vec()];
    Ok(quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(crypto)?,
    )))
}

/// 运行 UDP 隧道并在控制通道或数据平面断开后持续重连。
pub(super) async fn run_udp_agent(
    transport: ControlTransport,
    client_id: Uuid,
    token: String,
    public_port: u16,
    target: String,
    name: String,
    queue_budget: Arc<Semaphore>,
) -> anyhow::Result<()> {
    let mut retry_seconds = 1_u64;
    loop {
        let session_started = Instant::now();
        let result = run_udp_agent_session(
            transport.clone(),
            client_id,
            token.clone(),
            public_port,
            target.clone(),
            name.clone(),
            queue_budget.clone(),
        )
        .await;
        if session_started.elapsed() >= Duration::from_secs(30) {
            retry_seconds = 1;
        }
        let jitter_millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_millis() as u64
            % 750;
        let retry_delay = Duration::from_millis(retry_seconds * 1_000 + jitter_millis);
        match result {
            Ok(()) => {
                tracing::warn!("UDP control session ended; reconnecting in {retry_delay:?}.")
            }
            Err(error) => tracing::warn!(
                "UDP control session lost: {error}; reconnecting in {retry_delay:?}."
            ),
        }
        tokio::time::sleep(retry_delay).await;
        retry_seconds = (retry_seconds * 2).min(30);
    }
}

async fn run_udp_agent_session(
    transport: ControlTransport,
    client_id: Uuid,
    token: String,
    public_port: u16,
    target: String,
    name: String,
    queue_budget: Arc<Semaphore>,
) -> anyhow::Result<()> {
    let mut tcp_control = connect_control(&transport).await?;
    write_control_frame(
        &mut tcp_control,
        &ControlFrame::RegisterUdpTunnel {
            client_id,
            client_token: token,
            name,
            public_port,
            target_addr: target.clone(),
        },
    )
    .await?;

    let offer = match read_control_frame(&mut tcp_control).await? {
        ControlFrame::UdpDataPlaneOffer {
            registration_id,
            ticket,
            endpoint,
            server_name,
            max_datagram_size,
            session_idle_timeout_seconds,
        } => UdpDataPlaneOffer {
            registration_id,
            ticket,
            endpoint,
            server_name,
            max_datagram_size: max_datagram_size as usize,
            session_idle_timeout: Duration::from_secs(u64::from(session_idle_timeout_seconds)),
        },
        ControlFrame::Error { message } => {
            anyhow::bail!("server rejected UDP tunnel: {message}")
        }
        frame => anyhow::bail!("unexpected UDP data-plane offer response: {frame:?}"),
    };

    let mut data_plane = establish_data_plane(&transport, client_id, &offer).await?;
    match timeout(
        CONTROL_HEARTBEAT_TIMEOUT,
        read_control_frame(&mut tcp_control),
    )
    .await
    .map_err(|_| anyhow::anyhow!("UDP registration acknowledgement timed out"))??
    {
        ControlFrame::UdpTunnelRegistered {
            registration_id,
            public_port: registered_port,
        } if registration_id == offer.registration_id && registered_port == public_port => {
            tracing::info!("UDP tunnel registered on public port {public_port}.");
        }
        ControlFrame::Error { message } => {
            anyhow::bail!("server rejected UDP tunnel after data-plane attach: {message}")
        }
        frame => anyhow::bail!("unexpected UDP registration response: {frame:?}"),
    }

    let target_address = timeout(TARGET_CONNECT_TIMEOUT, resolve_target(&target))
        .await
        .map_err(|_| anyhow::anyhow!("UDP target address resolution timed out"))??;
    let (tcp_reader, tcp_writer) = split(tcp_control);
    let heartbeat = tokio::spawn(send_control_heartbeats(tcp_writer));
    let tcp_monitor = tokio::spawn(monitor_registered_tcp_control(tcp_reader));
    let result = run_data_plane(
        data_plane.connection.clone(),
        &mut data_plane.control_send,
        data_plane.control_recv,
        data_plane.max_datagram_size,
        offer.session_idle_timeout,
        target_address,
        queue_budget,
        tcp_monitor,
    )
    .await;
    heartbeat.abort();
    data_plane
        .connection
        .close(0_u32.into(), b"control session ended");
    result
}

pub(crate) async fn establish_data_plane(
    transport: &ControlTransport,
    client_id: Uuid,
    offer: &UdpDataPlaneOffer,
) -> anyhow::Result<EstablishedDataPlane> {
    let quic_config = transport
        .quic
        .clone()
        .ok_or_else(|| anyhow::anyhow!("UDP data plane requires --control-ca-cert"))?;
    let remote = preferred_address(lookup_host(&offer.endpoint).await?)
        .ok_or_else(|| anyhow::anyhow!("UDP data-plane endpoint did not resolve"))?;
    let bind_address = if remote.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    };
    let mut endpoint = quinn::Endpoint::client(bind_address)?;
    endpoint.set_default_client_config(quic_config);
    let connection = endpoint
        .connect(remote, &offer.server_name)?
        .await
        .map_err(|error| anyhow::anyhow!("UDP QUIC connection failed: {error}"))?;
    let (mut control_send, mut control_recv) = connection.open_bi().await?;
    write_udp_data_plane_control_frame(
        &mut control_send,
        &UdpDataPlaneControlFrame::Attach {
            client_id,
            registration_id: offer.registration_id,
            ticket: offer.ticket.clone(),
            protocol_version: UDP_DATA_PLANE_PROTOCOL_VERSION,
        },
    )
    .await?;
    let negotiated_max_datagram_size = match timeout(
        CONTROL_HEARTBEAT_TIMEOUT,
        read_udp_data_plane_control_frame(&mut control_recv),
    )
    .await
    .map_err(|_| anyhow::anyhow!("UDP data-plane Ready frame timed out"))??
    {
        UdpDataPlaneControlFrame::Ready {
            registration_id,
            negotiated_max_datagram_size,
        } if registration_id == offer.registration_id => negotiated_max_datagram_size as usize,
        UdpDataPlaneControlFrame::Error { code, message } => {
            anyhow::bail!("UDP data-plane attach rejected ({code}): {message}")
        }
        frame => anyhow::bail!("unexpected UDP data-plane attach response: {frame:?}"),
    };
    let connection_limit = connection
        .max_datagram_size()
        .ok_or_else(|| anyhow::anyhow!("UDP QUIC peer did not negotiate DATAGRAM frame support"))?;
    let max_datagram_size = offer
        .max_datagram_size
        .min(negotiated_max_datagram_size)
        .min(connection_limit);
    anyhow::ensure!(
        max_datagram_size > linklake_core::udp_protocol::UDP_DATAGRAM_HEADER_BYTES,
        "negotiated UDP QUIC datagram size is too small"
    );
    Ok(EstablishedDataPlane {
        _endpoint: endpoint,
        connection,
        control_send,
        control_recv,
        max_datagram_size,
    })
}

#[allow(clippy::too_many_arguments)]
async fn run_data_plane(
    connection: quinn::Connection,
    control_send: &mut quinn::SendStream,
    control_recv: quinn::RecvStream,
    max_datagram_size: usize,
    session_idle_timeout: Duration,
    target_address: SocketAddr,
    queue_budget: Arc<Semaphore>,
    mut tcp_monitor: tokio::task::JoinHandle<anyhow::Result<()>>,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        !session_idle_timeout.is_zero(),
        "UDP session idle timeout must be greater than zero"
    );
    let mut reassembler = UdpReassembler::new(UdpReassemblyConfig::default())?;
    let next_datagram_id = Arc::new(AtomicU64::new(1));
    let mut sessions = HashMap::<Uuid, TargetSession>::new();
    let mut closed_sessions = HashMap::<Uuid, Instant>::new();
    let (session_event_tx, mut session_event_rx) = mpsc::channel(SESSION_EVENT_CAPACITY);
    let (control_event_tx, mut control_event_rx) = mpsc::channel(CONTROL_EVENT_CAPACITY);
    let control_reader = tokio::spawn(read_data_plane_control(control_recv, control_event_tx));
    let mut cleanup = interval(SESSION_CLEANUP_INTERVAL);
    cleanup.set_missed_tick_behavior(MissedTickBehavior::Delay);

    let result = loop {
        tokio::select! {
            tcp_result = &mut tcp_monitor => {
                break tcp_result
                    .map_err(|error| anyhow::anyhow!("UDP TCP control reader task failed: {error}"))?;
            }
            control_event = control_event_rx.recv() => {
                match control_event {
                    Some(Ok(UdpDataPlaneControlFrame::CloseSession { session_id, reason })) => {
                        sessions.remove(&session_id);
                        reassembler.discard_session(session_id);
                        closed_sessions.insert(session_id, Instant::now() + CLOSED_SESSION_RETENTION);
                        tracing::debug!("Server closed UDP session {session_id}: {reason:?}");
                    }
                    Some(Ok(UdpDataPlaneControlFrame::Error { code, message })) => {
                        break Err(anyhow::anyhow!("UDP data plane closed ({code}): {message}"));
                    }
                    Some(Ok(frame)) => {
                        break Err(anyhow::anyhow!("unexpected UDP data-plane control frame: {frame:?}"));
                    }
                    Some(Err(error)) => break Err(error),
                    None => break Err(anyhow::anyhow!("UDP data-plane control reader stopped")),
                }
            }
            session_event = session_event_rx.recv() => {
                if let Some(SessionEvent::Close { session_id, reason }) = session_event {
                    if sessions.remove(&session_id).is_some() {
                        reassembler.discard_session(session_id);
                        closed_sessions.insert(session_id, Instant::now() + CLOSED_SESSION_RETENTION);
                        send_close_session(control_send, session_id, reason).await?;
                    }
                }
            }
            incoming = connection.read_datagram() => {
                let encoded = incoming
                    .map_err(|error| anyhow::anyhow!("UDP QUIC data plane closed: {error}"))?;
                let fragment = match UdpFragment::decode(&encoded) {
                    Ok(fragment) => fragment,
                    Err(error) => {
                        tracing::debug!("Discarded malformed UDP data-plane fragment: {error}");
                        continue;
                    }
                };
                if fragment.direction != UdpDirection::PublicToTarget {
                    tracing::debug!("Discarded UDP fragment with the wrong direction.");
                    continue;
                }
                let session_id = fragment.session_id;
                let now = Instant::now();
                if closed_sessions
                    .get(&session_id)
                    .is_some_and(|expires_at| *expires_at > now)
                {
                    continue;
                }
                closed_sessions.remove(&session_id);
                let payload = match reassembler.push(fragment, now) {
                    Ok(UdpReassemblyOutcome::Complete(payload)) => payload,
                    Ok(UdpReassemblyOutcome::Pending | UdpReassemblyOutcome::Duplicate) => continue,
                    Err(error) => {
                        tracing::debug!("Discarded UDP fragment that could not be reassembled: {error}");
                        continue;
                    }
                };
                if let std::collections::hash_map::Entry::Vacant(entry) =
                    sessions.entry(session_id)
                {
                    match create_target_session(
                        session_id,
                        target_address,
                        connection.clone(),
                        max_datagram_size,
                        next_datagram_id.clone(),
                        session_event_tx.clone(),
                    ).await {
                        Ok(session) => {
                            entry.insert(session);
                        }
                        Err(error) => {
                            tracing::warn!("Could not create UDP target session {session_id}: {error}");
                            closed_sessions.insert(
                                session_id,
                                Instant::now() + CLOSED_SESSION_RETENTION,
                            );
                            send_close_session(
                                control_send,
                                session_id,
                                UdpSessionCloseReason::TargetUnavailable,
                            ).await?;
                            continue;
                        }
                    }
                }
                let Some(session) = sessions.get(&session_id) else { continue; };
                // 已完成重组的公网报文代表会话仍活跃；即使目标队列已满也不应误判为空闲。
                touch(&session.last_activity);
                match enqueue_datagram(&session.sender, payload, &queue_budget) {
                    Ok(()) => {}
                    Err(QueueDatagramError::BudgetExhausted) => {
                        tracing::debug!("UDP client queue budget is exhausted; datagram dropped.");
                    }
                    Err(QueueDatagramError::Full) => {
                        tracing::debug!("UDP target queue for session {session_id} is full; datagram dropped.");
                    }
                    Err(QueueDatagramError::Closed) => {
                        sessions.remove(&session_id);
                        reassembler.discard_session(session_id);
                        closed_sessions.insert(
                            session_id,
                            Instant::now() + CLOSED_SESSION_RETENTION,
                        );
                        send_close_session(
                            control_send,
                            session_id,
                            UdpSessionCloseReason::TargetUnavailable,
                        ).await?;
                    }
                }
            }
            _ = cleanup.tick() => {
                let now = Instant::now();
                let expired = sessions
                    .iter()
                    .filter_map(|(session_id, session)| {
                        is_idle(&session.last_activity, now, session_idle_timeout)
                            .then_some(*session_id)
                    })
                    .collect::<Vec<_>>();
                for session_id in expired {
                    sessions.remove(&session_id);
                    reassembler.discard_session(session_id);
                    closed_sessions.insert(session_id, now + CLOSED_SESSION_RETENTION);
                    send_close_session(
                        control_send,
                        session_id,
                        UdpSessionCloseReason::IdleTimeout,
                    ).await?;
                }
                closed_sessions.retain(|_, expires_at| *expires_at > now);
                let expiration = reassembler.expire(now);
                if expiration.incomplete_datagrams != 0 {
                    tracing::debug!(
                        "Expired {} incomplete UDP datagrams.",
                        expiration.incomplete_datagrams
                    );
                }
            }
        }
    };

    sessions.clear();
    control_reader.abort();
    if !tcp_monitor.is_finished() {
        tcp_monitor.abort();
    }
    result
}

fn enqueue_datagram(
    sender: &mpsc::Sender<QueuedDatagram>,
    payload: Vec<u8>,
    queue_budget: &Arc<Semaphore>,
) -> Result<(), QueueDatagramError> {
    let permits = u32::try_from(payload.len().max(1))
        .expect("maximum UDP datagram length must fit in semaphore permits");
    let permit = queue_budget
        .clone()
        .try_acquire_many_owned(permits)
        .map_err(|_| QueueDatagramError::BudgetExhausted)?;
    match sender.try_send(QueuedDatagram {
        payload,
        _permit: permit,
    }) {
        Ok(()) => Ok(()),
        Err(mpsc::error::TrySendError::Full(_)) => Err(QueueDatagramError::Full),
        Err(mpsc::error::TrySendError::Closed(_)) => Err(QueueDatagramError::Closed),
    }
}

async fn create_target_session(
    session_id: Uuid,
    target_address: SocketAddr,
    connection: quinn::Connection,
    max_datagram_size: usize,
    next_datagram_id: Arc<AtomicU64>,
    events: mpsc::Sender<SessionEvent>,
) -> anyhow::Result<TargetSession> {
    let bind_address = if target_address.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    };
    let socket = UdpSocket::bind(bind_address).await?;
    socket.connect(target_address).await?;
    let (sender, receiver) = mpsc::channel(SESSION_QUEUE_CAPACITY);
    let last_activity = Arc::new(Mutex::new(Instant::now()));
    let worker = tokio::spawn(run_target_session(
        session_id,
        socket,
        receiver,
        connection,
        max_datagram_size,
        next_datagram_id,
        last_activity.clone(),
        events,
    ));
    Ok(TargetSession {
        sender,
        last_activity,
        worker,
    })
}

#[allow(clippy::too_many_arguments)]
async fn run_target_session(
    session_id: Uuid,
    socket: UdpSocket,
    mut incoming: mpsc::Receiver<QueuedDatagram>,
    connection: quinn::Connection,
    max_datagram_size: usize,
    next_datagram_id: Arc<AtomicU64>,
    last_activity: Arc<Mutex<Instant>>,
    events: mpsc::Sender<SessionEvent>,
) {
    let mut receive_buffer = vec![0_u8; MAX_UDP_DATAGRAM_BYTES];
    loop {
        tokio::select! {
            payload = incoming.recv() => {
                let Some(QueuedDatagram { payload, _permit }) = payload else { return; };
                match socket.send(&payload).await {
                    Ok(sent) if sent == payload.len() => touch(&last_activity),
                    Ok(sent) => {
                        tracing::warn!("UDP target accepted only {sent} of {} bytes.", payload.len());
                        notify_target_unavailable(&events, session_id).await;
                        return;
                    }
                    Err(error) => {
                        tracing::warn!("UDP target send failed for session {session_id}: {error}");
                        notify_target_unavailable(&events, session_id).await;
                        return;
                    }
                }
            }
            result = socket.recv(&mut receive_buffer) => {
                let received = match result {
                    Ok(received) => received,
                    Err(error) => {
                        tracing::warn!("UDP target receive failed for session {session_id}: {error}");
                        notify_target_unavailable(&events, session_id).await;
                        return;
                    }
                };
                let datagram_id = next_datagram_id.fetch_add(1, Ordering::Relaxed);
                let frames = match fragment_datagram(
                    UdpDirection::TargetToPublic,
                    session_id,
                    datagram_id,
                    &receive_buffer[..received],
                    max_datagram_size,
                ) {
                    Ok(frames) => frames,
                    Err(error) => {
                        tracing::warn!("UDP target response could not be fragmented: {error}");
                        continue;
                    }
                };
                let mut sent_all = true;
                for frame in frames {
                    if let Err(error) = connection.send_datagram(Bytes::from(frame)) {
                        tracing::debug!("UDP QUIC send queue rejected a datagram fragment: {error}");
                        sent_all = false;
                        break;
                    }
                }
                if sent_all {
                    touch(&last_activity);
                }
            }
        }
    }
}

async fn notify_target_unavailable(events: &mpsc::Sender<SessionEvent>, session_id: Uuid) {
    let _ = events
        .send(SessionEvent::Close {
            session_id,
            reason: UdpSessionCloseReason::TargetUnavailable,
        })
        .await;
}

async fn send_close_session(
    control_send: &mut quinn::SendStream,
    session_id: Uuid,
    reason: UdpSessionCloseReason,
) -> anyhow::Result<()> {
    write_udp_data_plane_control_frame(
        control_send,
        &UdpDataPlaneControlFrame::CloseSession { session_id, reason },
    )
    .await?;
    Ok(())
}

async fn read_data_plane_control(
    mut control_recv: quinn::RecvStream,
    events: mpsc::Sender<anyhow::Result<UdpDataPlaneControlFrame>>,
) {
    loop {
        let frame = read_udp_data_plane_control_frame(&mut control_recv)
            .await
            .map_err(anyhow::Error::from);
        let failed = frame.is_err();
        if events.send(frame).await.is_err() || failed {
            return;
        }
    }
}

async fn monitor_registered_tcp_control(
    mut reader: ReadHalf<linklake_core::BoxedIo>,
) -> anyhow::Result<()> {
    loop {
        let frame = timeout(CONTROL_HEARTBEAT_TIMEOUT, read_control_frame(&mut reader))
            .await
            .map_err(|_| anyhow::anyhow!("UDP control heartbeat acknowledgement timed out"))??;
        match frame {
            ControlFrame::ControlHeartbeatAck { .. } => {}
            ControlFrame::Error { message } => anyhow::bail!("server closed UDP tunnel: {message}"),
            frame => anyhow::bail!("unexpected UDP control frame: {frame:?}"),
        }
    }
}

async fn resolve_target(target: &str) -> anyhow::Result<SocketAddr> {
    preferred_address(lookup_host(target).await?)
        .ok_or_else(|| anyhow::anyhow!("UDP target address did not resolve"))
}

fn preferred_address(addresses: impl Iterator<Item = SocketAddr>) -> Option<SocketAddr> {
    let addresses = addresses.collect::<Vec<_>>();
    addresses
        .iter()
        .copied()
        .find(SocketAddr::is_ipv4)
        .or_else(|| addresses.first().copied())
}

fn touch(last_activity: &Mutex<Instant>) {
    *last_activity
        .lock()
        .expect("UDP session activity lock poisoned") = Instant::now();
}

fn is_idle(last_activity: &Mutex<Instant>, now: Instant, idle_timeout: Duration) -> bool {
    now.saturating_duration_since(
        *last_activity
            .lock()
            .expect("UDP session activity lock poisoned"),
    ) >= idle_timeout
}

#[cfg(test)]
mod tests {
    use super::{
        enqueue_datagram, QueueDatagramError, QueuedDatagram, TargetSession, SESSION_QUEUE_CAPACITY,
    };
    use std::{
        sync::{Arc, Mutex},
        time::Instant,
    };
    use tokio::sync::{mpsc, Semaphore};

    #[tokio::test]
    async fn dropping_session_aborts_target_worker() {
        let (sender, _receiver) = mpsc::channel::<QueuedDatagram>(1);
        let worker = tokio::spawn(std::future::pending::<()>());
        let abort_handle = worker.abort_handle();
        let session = TargetSession {
            sender,
            last_activity: Arc::new(Mutex::new(Instant::now())),
            worker,
        };

        drop(session);
        tokio::task::yield_now().await;

        assert!(abort_handle.is_finished());
    }

    #[tokio::test]
    async fn queue_budget_is_released_when_datagram_leaves_queue() {
        let budget = Arc::new(Semaphore::new(4));
        let (sender, mut receiver) = mpsc::channel(2);

        assert_eq!(enqueue_datagram(&sender, vec![1, 2, 3, 4], &budget), Ok(()));
        assert_eq!(budget.available_permits(), 0);
        assert_eq!(
            enqueue_datagram(&sender, vec![5], &budget),
            Err(QueueDatagramError::BudgetExhausted)
        );

        let queued = receiver.recv().await.expect("queued datagram should exist");
        assert_eq!(queued.payload, vec![1, 2, 3, 4]);
        drop(queued);
        assert_eq!(budget.available_permits(), 4);

        assert_eq!(enqueue_datagram(&sender, Vec::new(), &budget), Ok(()));
        assert_eq!(budget.available_permits(), 3);
        drop(
            receiver
                .recv()
                .await
                .expect("zero-byte datagram should exist"),
        );
        assert_eq!(budget.available_permits(), 4);
    }

    #[tokio::test]
    async fn session_queue_absorbs_normal_datagram_burst() {
        const BURST_PACKETS: usize = 64;
        const PAYLOAD_BYTES: usize = 512;
        let budget = Arc::new(Semaphore::new(BURST_PACKETS * PAYLOAD_BYTES));
        let (sender, mut receiver) = mpsc::channel(SESSION_QUEUE_CAPACITY);

        for sequence in 0..BURST_PACKETS {
            assert_eq!(
                enqueue_datagram(
                    &sender,
                    vec![u8::try_from(sequence).expect("sequence fits in u8"); PAYLOAD_BYTES],
                    &budget,
                ),
                Ok(())
            );
        }
        assert_eq!(budget.available_permits(), 0);

        for sequence in 0..BURST_PACKETS {
            let queued = receiver.recv().await.expect("burst datagram should exist");
            assert_eq!(
                queued.payload[0],
                u8::try_from(sequence).expect("sequence fits in u8")
            );
        }
        assert_eq!(budget.available_permits(), BURST_PACKETS * PAYLOAD_BYTES);
    }

    #[test]
    fn closed_queue_releases_acquired_budget() {
        let budget = Arc::new(Semaphore::new(8));
        let (sender, receiver) = mpsc::channel(1);
        drop(receiver);
        assert_eq!(
            enqueue_datagram(&sender, vec![1, 2, 3], &budget),
            Err(QueueDatagramError::Closed)
        );
        assert_eq!(budget.available_permits(), 8);
    }
}
