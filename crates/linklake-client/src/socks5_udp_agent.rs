use bytes::Bytes;
use linklake_core::{
    read_udp_data_plane_control_frame,
    socks5_udp::{
        decode_socks5_udp_datagram, encode_socks5_udp_response, Socks5UdpDatagram, Socks5UdpTarget,
    },
    udp_protocol::{fragment_datagram, UdpDirection, UdpFragment, MAX_UDP_DATAGRAM_BYTES},
    udp_reassembly::{UdpReassembler, UdpReassemblyConfig, UdpReassemblyOutcome},
    write_udp_data_plane_control_frame, UdpDataPlaneControlFrame, UdpSessionCloseReason,
};
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::{
    net::{lookup_host, UdpSocket},
    sync::{mpsc, Semaphore},
    time::{interval, MissedTickBehavior},
};
use uuid::Uuid;

use crate::udp_agent::EstablishedDataPlane;

const SESSION_QUEUE_CAPACITY: usize = 16;
const MAX_TARGETS_PER_ASSOCIATION: usize = 256;

struct TargetSession {
    sender: mpsc::Sender<QueuedDatagram>,
    last_activity: Arc<Mutex<Instant>>,
    worker: tokio::task::JoinHandle<()>,
}

struct QueuedDatagram {
    datagram: Socks5UdpDatagram,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl Drop for TargetSession {
    fn drop(&mut self) {
        self.worker.abort();
    }
}

pub(crate) async fn run(
    mut data_plane: EstablishedDataPlane,
    idle_timeout: Duration,
    queue_budget: Arc<Semaphore>,
) -> anyhow::Result<()> {
    let connection = data_plane.connection.clone();
    let max_datagram_size = data_plane.max_datagram_size;
    let mut reassembler = UdpReassembler::new(UdpReassemblyConfig::default())?;
    let mut sessions = HashMap::<Uuid, TargetSession>::new();
    let next_datagram_id = Arc::new(AtomicU64::new(1));
    let (control_tx, mut control_rx) = mpsc::channel(64);
    let _control_reader = tokio::spawn(async move {
        loop {
            let frame = read_udp_data_plane_control_frame(&mut data_plane.control_recv).await;
            if control_tx.send(frame).await.is_err() {
                break;
            }
        }
    });
    let mut cleanup = interval(Duration::from_secs(1));
    cleanup.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            control = control_rx.recv() => match control {
                Some(Ok(UdpDataPlaneControlFrame::CloseSession { session_id, .. })) => {
                    sessions.remove(&session_id);
                    reassembler.discard_session(session_id);
                }
                Some(Ok(UdpDataPlaneControlFrame::Error { code, message })) => {
                    anyhow::bail!("SOCKS5 UDP data plane closed ({code}): {message}");
                }
                Some(Ok(frame)) => anyhow::bail!("unexpected SOCKS5 UDP control frame: {frame:?}"),
                Some(Err(error)) => return Err(error.into()),
                None => anyhow::bail!("SOCKS5 UDP control reader stopped"),
            },
            incoming = connection.read_datagram() => {
                let encoded = incoming?;
                let fragment = match UdpFragment::decode(&encoded) {
                    Ok(fragment) if fragment.direction == UdpDirection::PublicToTarget => fragment,
                    _ => continue,
                };
                let session_id = fragment.session_id;
                let payload = match reassembler.push(fragment, Instant::now()) {
                    Ok(UdpReassemblyOutcome::Complete(payload)) => payload,
                    Ok(UdpReassemblyOutcome::Pending | UdpReassemblyOutcome::Duplicate) => continue,
                    Err(_) => continue,
                };
                let datagram = match decode_socks5_udp_datagram(&payload) {
                    Ok(datagram) => datagram,
                    Err(_) => continue,
                };
                if let std::collections::hash_map::Entry::Vacant(entry) = sessions.entry(session_id) {
                    entry.insert(create_session(
                        session_id,
                        connection.clone(),
                        max_datagram_size,
                        next_datagram_id.clone(),
                    ).await?);
                }
                let Some(session) = sessions.get(&session_id) else { continue; };
                *session.last_activity.lock().expect("SOCKS5 UDP activity lock poisoned") = Instant::now();
                let permits = u32::try_from(datagram.payload.len().max(1))?;
                let Ok(permit) = queue_budget.clone().try_acquire_many_owned(permits) else { continue; };
                let _ = session.sender.try_send(QueuedDatagram { datagram, _permit: permit });
            },
            _ = cleanup.tick() => {
                let now = Instant::now();
                reassembler.expire(now);
                let expired = sessions.iter().filter_map(|(id, session)| {
                    (now.duration_since(*session.last_activity.lock().expect("SOCKS5 UDP activity lock poisoned")) >= idle_timeout).then_some(*id)
                }).collect::<Vec<_>>();
                for id in expired {
                    sessions.remove(&id);
                    reassembler.discard_session(id);
                    let _ = write_udp_data_plane_control_frame(
                        &mut data_plane.control_send,
                        &UdpDataPlaneControlFrame::CloseSession {
                            session_id: id,
                            reason: UdpSessionCloseReason::IdleTimeout,
                        },
                    ).await;
                }
            }
        }
    }
    #[allow(unreachable_code)]
    {
        Ok(())
    }
}

async fn create_session(
    session_id: Uuid,
    connection: quinn::Connection,
    max_datagram_size: usize,
    next_datagram_id: Arc<AtomicU64>,
) -> anyhow::Result<TargetSession> {
    let ipv4 = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)).await?;
    let ipv6 = UdpSocket::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0))
        .await
        .ok();
    let (sender, receiver) = mpsc::channel(SESSION_QUEUE_CAPACITY);
    let last_activity = Arc::new(Mutex::new(Instant::now()));
    let worker = tokio::spawn(run_session(
        session_id,
        ipv4,
        ipv6,
        receiver,
        connection,
        max_datagram_size,
        next_datagram_id,
        last_activity.clone(),
    ));
    Ok(TargetSession {
        sender,
        last_activity,
        worker,
    })
}

#[allow(clippy::too_many_arguments)]
async fn run_session(
    session_id: Uuid,
    ipv4: UdpSocket,
    ipv6: Option<UdpSocket>,
    mut incoming: mpsc::Receiver<QueuedDatagram>,
    connection: quinn::Connection,
    max_datagram_size: usize,
    next_datagram_id: Arc<AtomicU64>,
    last_activity: Arc<Mutex<Instant>>,
) {
    let mut allowed_targets = HashSet::<SocketAddr>::new();
    let mut ipv4_buffer = vec![0_u8; MAX_UDP_DATAGRAM_BYTES];
    let mut ipv6_buffer = vec![0_u8; MAX_UDP_DATAGRAM_BYTES];
    loop {
        tokio::select! {
            datagram = incoming.recv() => {
                let Some(QueuedDatagram { datagram, _permit }) = datagram else { return; };
                let Some(target) = resolve_target(&datagram).await else { continue; };
                if !target_is_admissible(&allowed_targets, target) {
                    continue;
                }
                let result = if target.is_ipv4() {
                    ipv4.send_to(&datagram.payload, target).await
                } else if let Some(ipv6) = &ipv6 {
                    ipv6.send_to(&datagram.payload, target).await
                } else {
                    continue;
                };
                if result.is_ok_and(|sent| sent == datagram.payload.len()) {
                    allowed_targets.insert(target);
                    touch(&last_activity);
                }
            }
            response = ipv4.recv_from(&mut ipv4_buffer) => {
                let Ok((received, source)) = response else { return; };
                if allowed_targets.contains(&source) {
                    send_response(session_id, source, &ipv4_buffer[..received], &connection, max_datagram_size, &next_datagram_id).await;
                    touch(&last_activity);
                }
            }
            response = async {
                match &ipv6 {
                    Some(socket) => socket.recv_from(&mut ipv6_buffer).await,
                    None => std::future::pending().await,
                }
            } => {
                let Ok((received, source)) = response else { return; };
                if allowed_targets.contains(&source) {
                    send_response(session_id, source, &ipv6_buffer[..received], &connection, max_datagram_size, &next_datagram_id).await;
                    touch(&last_activity);
                }
            }
        }
    }
}

async fn resolve_target(datagram: &Socks5UdpDatagram) -> Option<SocketAddr> {
    match &datagram.target {
        Socks5UdpTarget::Ip(ip) => Some(SocketAddr::new(*ip, datagram.port)),
        Socks5UdpTarget::Domain(domain) => {
            let mut addresses = lookup_host((domain.as_str(), datagram.port)).await.ok()?;
            let first = addresses.next()?;
            if first.is_ipv4() {
                Some(first)
            } else {
                addresses.find(SocketAddr::is_ipv4).or(Some(first))
            }
        }
    }
}

fn target_is_admissible(allowed_targets: &HashSet<SocketAddr>, target: SocketAddr) -> bool {
    allowed_targets.contains(&target) || allowed_targets.len() < MAX_TARGETS_PER_ASSOCIATION
}

async fn send_response(
    session_id: Uuid,
    source: SocketAddr,
    payload: &[u8],
    connection: &quinn::Connection,
    max_datagram_size: usize,
    next_datagram_id: &AtomicU64,
) {
    let Ok(encoded) = encode_socks5_udp_response(source, payload) else {
        return;
    };
    let id = next_datagram_id.fetch_add(1, Ordering::Relaxed);
    let Ok(frames) = fragment_datagram(
        UdpDirection::TargetToPublic,
        session_id,
        id,
        &encoded,
        max_datagram_size,
    ) else {
        return;
    };
    for frame in frames {
        if connection.send_datagram(Bytes::from(frame)).is_err() {
            break;
        }
    }
}

fn touch(last_activity: &Mutex<Instant>) {
    *last_activity
        .lock()
        .expect("SOCKS5 UDP activity lock poisoned") = Instant::now();
}

#[cfg(test)]
mod tests {
    use super::{target_is_admissible, MAX_TARGETS_PER_ASSOCIATION};
    use std::{collections::HashSet, net::SocketAddr};

    #[test]
    fn target_allowlist_accepts_existing_target_when_full() {
        let mut targets = HashSet::new();
        for port in 1..=MAX_TARGETS_PER_ASSOCIATION as u16 {
            targets.insert(SocketAddr::from(([127, 0, 0, 1], port)));
        }
        let existing = SocketAddr::from(([127, 0, 0, 1], 1));
        let new_target = SocketAddr::from(([127, 0, 0, 1], 30_000));
        assert!(target_is_admissible(&targets, existing));
        assert!(!target_is_admissible(&targets, new_target));
    }

    #[test]
    fn target_allowlist_accepts_new_target_below_limit() {
        let targets = HashSet::new();
        assert!(target_is_admissible(
            &targets,
            SocketAddr::from(([127, 0, 0, 1], 53))
        ));
    }
}
