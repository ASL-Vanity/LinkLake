//! UDP 隧道使用的 QUIC 数据平面入口。

use linklake_core::{
    read_udp_data_plane_control_frame, write_udp_data_plane_control_frame,
    UdpDataPlaneControlFrame, UDP_DATA_PLANE_ALPN, UDP_DATA_PLANE_PROTOCOL_VERSION,
};
use quinn::crypto::rustls::QuicServerConfig;
use rustls_pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use std::{
    collections::HashMap,
    fs::File,
    io::BufReader,
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    sync::{oneshot, OwnedSemaphorePermit, Semaphore},
    time::Instant,
};
use tokio_rustls::rustls;
use uuid::Uuid;

/// 控制面发出的 ticket 有效期；这不是单次 QUIC attach 操作的执行时限。
const TICKET_TTL: Duration = Duration::from_secs(15);
/// 已通过 Retry 地址校验的 QUIC 连接，必须在该时限内完成握手、打开控制流并发送 Attach。
const ATTACH_OPERATION_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_PENDING_ATTACHMENTS: usize = 128;
const MAX_PENDING_ATTACHMENTS_PER_IP: usize = 8;
const MAX_ACTIVE_ATTACHMENTS: usize = 512;
const QUIC_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(10);
const QUIC_IDLE_TIMEOUT: Duration = Duration::from_secs(35);
const DATAGRAM_BUFFER_BYTES: usize = 256 * 1024;
const OFFERED_MAX_DATAGRAM_SIZE: u32 = 1_200;

/// 创建 QUIC 监听器所需的配置。证书与 TCP 控制平面共用。
pub(crate) struct UdpDataPlaneConfig<'a> {
    pub(crate) bind_address: SocketAddr,
    pub(crate) advertised_endpoint: String,
    pub(crate) server_name: String,
    pub(crate) certificate_path: &'a Path,
    pub(crate) private_key_path: &'a Path,
}

/// 发给客户端的短期连接参数。
#[derive(Debug, Clone)]
pub(crate) struct UdpAttachmentOffer {
    pub(crate) ticket: String,
    pub(crate) endpoint: String,
    pub(crate) server_name: String,
    pub(crate) max_datagram_size: u32,
}

/// 已通过一次性 ticket 鉴权的 QUIC 连接。
pub(crate) struct AuthenticatedUdpConnection {
    pub(crate) connection: quinn::Connection,
    pub(crate) control_send: quinn::SendStream,
    pub(crate) control_receive: quinn::RecvStream,
    /// 此 permit 必须随已认证 QUIC 连接一起存活，防止已挂接连接突破全局上限。
    pub(crate) active_attachment_permit: OwnedSemaphorePermit,
}

struct PendingTicket {
    client_id: Uuid,
    registration_id: Uuid,
    expires_at: Instant,
    attached: oneshot::Sender<AuthenticatedUdpConnection>,
}

/// QUIC attach 的两级准入控制。
///
/// pending 只覆盖地址验证后的握手和 Attach 解析阶段；active 则由
/// `AuthenticatedUdpConnection` 持有，直到注册运行时关闭连接。
struct AttachmentLimits {
    pending: Arc<Semaphore>,
    active: Arc<Semaphore>,
    pending_by_ip: Arc<Mutex<HashMap<IpAddr, usize>>>,
    pending_per_ip_limit: usize,
}

/// 一个处于 attach 中的连接所持有的全局和源 IP 配额。
struct PendingAttachmentPermit {
    _global_permit: OwnedSemaphorePermit,
    pending_by_ip: Arc<Mutex<HashMap<IpAddr, usize>>>,
    source_ip: IpAddr,
}

impl AttachmentLimits {
    fn new() -> Self {
        Self::with_limits(
            MAX_PENDING_ATTACHMENTS,
            MAX_PENDING_ATTACHMENTS_PER_IP,
            MAX_ACTIVE_ATTACHMENTS,
        )
    }

    fn with_limits(pending_limit: usize, pending_per_ip_limit: usize, active_limit: usize) -> Self {
        debug_assert!(pending_per_ip_limit > 0);
        Self {
            pending: Arc::new(Semaphore::new(pending_limit)),
            active: Arc::new(Semaphore::new(active_limit)),
            pending_by_ip: Arc::new(Mutex::new(HashMap::with_capacity(
                pending_per_ip_limit.min(pending_limit),
            ))),
            pending_per_ip_limit,
        }
    }

    /// 不等待配额；UDP 公网入口的过载连接必须立即拒绝，不能形成任务队列。
    fn try_acquire_pending(&self, source_ip: IpAddr) -> Option<PendingAttachmentPermit> {
        let global_permit = self.pending.clone().try_acquire_owned().ok()?;
        let mut pending_by_ip = self
            .pending_by_ip
            .lock()
            .expect("UDP pending attachment limit lock poisoned");
        let count = pending_by_ip.entry(source_ip).or_insert(0);
        if *count >= self.pending_per_ip_limit {
            return None;
        }
        *count += 1;
        drop(pending_by_ip);
        Some(PendingAttachmentPermit {
            _global_permit: global_permit,
            pending_by_ip: self.pending_by_ip.clone(),
            source_ip,
        })
    }

    fn has_active_capacity(&self) -> bool {
        self.active.available_permits() != 0
    }

    fn try_acquire_active(&self) -> Option<OwnedSemaphorePermit> {
        self.active.clone().try_acquire_owned().ok()
    }
}

impl Drop for PendingAttachmentPermit {
    fn drop(&mut self) {
        let mut pending_by_ip = match self.pending_by_ip.lock() {
            Ok(pending_by_ip) => pending_by_ip,
            Err(_) => return,
        };
        match pending_by_ip.get_mut(&self.source_ip) {
            Some(count) if *count > 1 => *count -= 1,
            Some(_) => {
                pending_by_ip.remove(&self.source_ip);
            }
            None => {}
        }
    }
}

struct UdpDataPlaneInner {
    endpoint: quinn::Endpoint,
    advertised_endpoint: String,
    server_name: String,
    tickets: Mutex<HashMap<String, PendingTicket>>,
    attachment_limits: AttachmentLimits,
}

/// 全局 QUIC UDP 数据平面。所有 UDP 策略共用同一个监听端口。
#[derive(Clone)]
pub(crate) struct UdpDataPlane {
    inner: Arc<UdpDataPlaneInner>,
}

/// ticket 租约负责在注册失败、控制连接断开或超时时撤销尚未消费的 ticket。
pub(crate) struct UdpAttachmentLease {
    data_plane: UdpDataPlane,
    offer: UdpAttachmentOffer,
    receiver: Option<oneshot::Receiver<AuthenticatedUdpConnection>>,
}

impl UdpDataPlane {
    pub(crate) fn bind(config: UdpDataPlaneConfig<'_>) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !config.advertised_endpoint.trim().is_empty(),
            "UDP data-plane advertised endpoint is required"
        );
        anyhow::ensure!(
            !config.server_name.trim().is_empty(),
            "UDP data-plane server name is required"
        );

        let certificates = {
            let reader = BufReader::new(File::open(config.certificate_path)?);
            CertificateDer::pem_reader_iter(reader).collect::<Result<Vec<_>, _>>()?
        };
        anyhow::ensure!(
            !certificates.is_empty(),
            "UDP data-plane certificate file contains no certificates"
        );
        let private_key = {
            let reader = BufReader::new(File::open(config.private_key_path)?);
            PrivateKeyDer::pem_reader_iter(reader)
                .next()
                .transpose()?
                .ok_or_else(|| {
                    anyhow::anyhow!("UDP data-plane private key file contains no private key")
                })?
        };
        let server_config = build_server_config(certificates, private_key)?;
        let endpoint = quinn::Endpoint::server(server_config, config.bind_address)?;
        let data_plane = Self {
            inner: Arc::new(UdpDataPlaneInner {
                endpoint,
                advertised_endpoint: config.advertised_endpoint,
                server_name: config.server_name,
                tickets: Mutex::new(HashMap::new()),
                attachment_limits: AttachmentLimits::new(),
            }),
        };
        tokio::spawn(run_accept_loop(data_plane.clone()));
        Ok(data_plane)
    }

    /// 为一次隧道注册创建 15 秒有效、原子消费的一次性 ticket。
    pub(crate) fn reserve_attachment(
        &self,
        client_id: Uuid,
        registration_id: Uuid,
    ) -> UdpAttachmentLease {
        let ticket = generate_ticket();
        let (attached, receiver) = oneshot::channel();
        let mut tickets = self
            .inner
            .tickets
            .lock()
            .expect("UDP data-plane ticket registry lock poisoned");
        purge_expired_tickets(&mut tickets, Instant::now());
        tickets.insert(
            ticket.clone(),
            PendingTicket {
                client_id,
                registration_id,
                expires_at: Instant::now() + TICKET_TTL,
                attached,
            },
        );
        drop(tickets);
        UdpAttachmentLease {
            data_plane: self.clone(),
            offer: UdpAttachmentOffer {
                ticket,
                endpoint: self.inner.advertised_endpoint.clone(),
                server_name: self.inner.server_name.clone(),
                max_datagram_size: OFFERED_MAX_DATAGRAM_SIZE,
            },
            receiver: Some(receiver),
        }
    }

    fn cancel_ticket(&self, ticket: &str) {
        self.inner
            .tickets
            .lock()
            .expect("UDP data-plane ticket registry lock poisoned")
            .remove(ticket);
    }
}

impl UdpAttachmentLease {
    pub(crate) fn offer(&self) -> &UdpAttachmentOffer {
        &self.offer
    }

    pub(crate) async fn wait(mut self) -> anyhow::Result<AuthenticatedUdpConnection> {
        let receiver = self
            .receiver
            .take()
            .expect("UDP attachment lease receiver must exist");
        match tokio::time::timeout(TICKET_TTL, receiver).await {
            Ok(Ok(connection)) => Ok(connection),
            Ok(Err(_)) => anyhow::bail!("UDP data-plane attachment was rejected"),
            Err(_) => anyhow::bail!("UDP data-plane attachment timed out"),
        }
    }
}

impl Drop for UdpAttachmentLease {
    fn drop(&mut self) {
        self.data_plane.cancel_ticket(&self.offer.ticket);
    }
}

fn build_server_config(
    certificates: Vec<rustls::pki_types::CertificateDer<'static>>,
    private_key: PrivateKeyDer<'static>,
) -> anyhow::Result<quinn::ServerConfig> {
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)?;
    tls.alpn_protocols = vec![UDP_DATA_PLANE_ALPN.to_vec()];

    let crypto = QuicServerConfig::try_from(tls)?;
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport
        .keep_alive_interval(Some(QUIC_KEEP_ALIVE_INTERVAL))
        .max_idle_timeout(Some(QUIC_IDLE_TIMEOUT.try_into()?))
        .max_concurrent_bidi_streams(1_u8.into())
        .max_concurrent_uni_streams(0_u8.into())
        .datagram_receive_buffer_size(Some(DATAGRAM_BUFFER_BYTES))
        .datagram_send_buffer_size(DATAGRAM_BUFFER_BYTES);
    server.transport_config(Arc::new(transport));
    Ok(server)
}

async fn run_accept_loop(data_plane: UdpDataPlane) {
    while let Some(incoming) = data_plane.inner.endpoint.accept().await {
        // 对未验证的初始包只发 Retry，先完成地址验证后再分配任何用户态资源。
        if !incoming.remote_address_validated() {
            let _ = incoming.retry();
            continue;
        }
        if !data_plane.inner.attachment_limits.has_active_capacity() {
            incoming.refuse();
            continue;
        }
        let source_ip = incoming.remote_address().ip();
        let Some(pending_attachment_permit) = data_plane
            .inner
            .attachment_limits
            .try_acquire_pending(source_ip)
        else {
            incoming.refuse();
            continue;
        };
        let data_plane = data_plane.clone();
        tokio::spawn(async move {
            let result = authenticate_connection(data_plane, incoming).await;
            // 显式在认证完成后释放 pending 配额；active 配额会转交给认证后的连接。
            drop(pending_attachment_permit);
            if let Err(error) = result {
                // 未认证公网流量可被任意伪造，拒绝不使用 warn，避免日志被探测流量淹没。
                tracing::debug!("UDP QUIC attachment rejected: {error}");
            }
        });
    }
}

async fn authenticate_connection(
    data_plane: UdpDataPlane,
    incoming: quinn::Incoming,
) -> anyhow::Result<()> {
    tokio::time::timeout(
        ATTACH_OPERATION_TIMEOUT,
        authenticate_connection_inner(data_plane, incoming),
    )
    .await
    .map_err(|_| anyhow::anyhow!("UDP data-plane attach operation timed out"))?
}

async fn authenticate_connection_inner(
    data_plane: UdpDataPlane,
    incoming: quinn::Incoming,
) -> anyhow::Result<()> {
    let connection = incoming.await?;
    let (mut control_send, mut control_receive) = connection.accept_bi().await?;
    let attach = read_udp_data_plane_control_frame(&mut control_receive).await?;
    let UdpDataPlaneControlFrame::Attach {
        client_id,
        registration_id,
        ticket,
        protocol_version,
    } = attach
    else {
        reject_attachment(
            &mut control_send,
            "unexpected_frame",
            "the first UDP data-plane frame must be attach",
        )
        .await;
        connection.close(1_u8.into(), b"unexpected UDP attach frame");
        anyhow::bail!("unexpected initial UDP data-plane frame");
    };
    if protocol_version != UDP_DATA_PLANE_PROTOCOL_VERSION {
        reject_attachment(
            &mut control_send,
            "unsupported_protocol_version",
            "the UDP data-plane protocol version is unsupported",
        )
        .await;
        connection.close(2_u8.into(), b"unsupported UDP protocol version");
        anyhow::bail!("unsupported UDP data-plane protocol version");
    }

    // 在消费 ticket 前先占用 active 配额。若当前满载，ticket 保持有效，客户端可在
    // 15 秒有效期内重新尝试，而不会被一次拥塞拒绝消耗掉。
    let Some(active_attachment_permit) = data_plane.inner.attachment_limits.try_acquire_active()
    else {
        reject_attachment(
            &mut control_send,
            "active_attachment_limit",
            "the UDP data-plane active connection limit has been reached",
        )
        .await;
        connection.close(4_u8.into(), b"UDP active attachment limit reached");
        anyhow::bail!("UDP data-plane active attachment limit reached");
    };

    let pending = consume_ticket(
        &data_plane.inner.tickets,
        &ticket,
        client_id,
        registration_id,
        Instant::now(),
    );
    let Some(pending) = pending else {
        reject_attachment(
            &mut control_send,
            "invalid_or_expired_ticket",
            "the UDP data-plane ticket is invalid, expired, or already used",
        )
        .await;
        connection.close(3_u8.into(), b"invalid UDP attachment ticket");
        anyhow::bail!("invalid, expired, or already consumed UDP attachment ticket");
    };

    let authenticated = AuthenticatedUdpConnection {
        connection: connection.clone(),
        control_send,
        control_receive,
        active_attachment_permit,
    };
    if pending.attached.send(authenticated).is_err() {
        connection.close(5_u8.into(), b"UDP registration no longer exists");
        anyhow::bail!("UDP registration disappeared before attachment completed");
    }
    Ok(())
}

fn consume_ticket(
    tickets: &Mutex<HashMap<String, PendingTicket>>,
    ticket: &str,
    client_id: Uuid,
    registration_id: Uuid,
    now: Instant,
) -> Option<PendingTicket> {
    let mut tickets = tickets
        .lock()
        .expect("UDP data-plane ticket registry lock poisoned");
    purge_expired_tickets(&mut tickets, now);
    let matches = tickets.get(ticket).is_some_and(|pending| {
        pending.client_id == client_id
            && pending.registration_id == registration_id
            && pending.expires_at > now
    });
    matches.then(|| tickets.remove(ticket)).flatten()
}

fn purge_expired_tickets(tickets: &mut HashMap<String, PendingTicket>, now: Instant) {
    tickets.retain(|_, pending| pending.expires_at > now);
}

async fn reject_attachment(send: &mut quinn::SendStream, code: &str, message: &str) {
    let _ = write_udp_data_plane_control_frame(
        send,
        &UdpDataPlaneControlFrame::Error {
            code: code.to_owned(),
            message: message.to_owned(),
        },
    )
    .await;
    let _ = send.finish();
}

fn generate_ticket() -> String {
    format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())
}

#[cfg(test)]
mod tests {
    use super::{consume_ticket, generate_ticket, AttachmentLimits, PendingTicket};
    use std::{collections::HashMap, net::IpAddr, sync::Mutex, time::Duration};
    use tokio::{sync::oneshot, time::Instant};
    use uuid::Uuid;

    #[test]
    fn ticket_is_sixty_four_lowercase_hex_characters() {
        let ticket = generate_ticket();
        assert_eq!(ticket.len(), 64);
        assert!(ticket.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!(ticket, ticket.to_ascii_lowercase());
    }

    #[test]
    fn ticket_is_bound_and_consumed_once() {
        let client_id = Uuid::new_v4();
        let registration_id = Uuid::new_v4();
        let ticket = generate_ticket();
        let (attached, _receiver) = oneshot::channel();
        let tickets = Mutex::new(HashMap::from([(
            ticket.clone(),
            PendingTicket {
                client_id,
                registration_id,
                expires_at: Instant::now() + Duration::from_secs(1),
                attached,
            },
        )]));

        assert!(consume_ticket(
            &tickets,
            &ticket,
            Uuid::new_v4(),
            registration_id,
            Instant::now()
        )
        .is_none());
        assert!(consume_ticket(
            &tickets,
            &ticket,
            client_id,
            registration_id,
            Instant::now()
        )
        .is_some());
        assert!(consume_ticket(
            &tickets,
            &ticket,
            client_id,
            registration_id,
            Instant::now()
        )
        .is_none());
    }

    #[test]
    fn expired_ticket_is_removed_and_cannot_be_replayed() {
        let client_id = Uuid::new_v4();
        let registration_id = Uuid::new_v4();
        let ticket = generate_ticket();
        let now = Instant::now();
        let (attached, _receiver) = oneshot::channel();
        let tickets = Mutex::new(HashMap::from([(
            ticket.clone(),
            PendingTicket {
                client_id,
                registration_id,
                expires_at: now - Duration::from_millis(1),
                attached,
            },
        )]));

        assert!(consume_ticket(&tickets, &ticket, client_id, registration_id, now).is_none());
        assert!(tickets
            .lock()
            .expect("ticket registry lock should work")
            .is_empty());
    }

    #[test]
    fn pending_attachment_limits_are_global_and_per_ip_and_release_on_drop() {
        let limits = AttachmentLimits::with_limits(3, 2, 2);
        let first_ip = "192.0.2.1".parse::<IpAddr>().expect("valid IP");
        let second_ip = "192.0.2.2".parse::<IpAddr>().expect("valid IP");
        let third_ip = "192.0.2.3".parse::<IpAddr>().expect("valid IP");

        let first = limits
            .try_acquire_pending(first_ip)
            .expect("first connection should pass");
        let second = limits
            .try_acquire_pending(first_ip)
            .expect("second connection from one IP should pass");
        assert!(limits.try_acquire_pending(first_ip).is_none());
        let third = limits
            .try_acquire_pending(second_ip)
            .expect("remaining global connection should pass");
        assert!(limits.try_acquire_pending(third_ip).is_none());

        drop(first);
        assert!(limits.try_acquire_pending(third_ip).is_some());
        drop(second);
        drop(third);
        assert!(limits
            .pending_by_ip
            .lock()
            .expect("pending IP registry should work")
            .is_empty());
        assert_eq!(limits.pending.available_permits(), 3);
    }

    #[test]
    fn active_attachment_limit_releases_with_connection_owner() {
        let limits = AttachmentLimits::with_limits(3, 2, 2);
        let first = limits
            .try_acquire_active()
            .expect("first active connection should pass");
        let second = limits
            .try_acquire_active()
            .expect("second active connection should pass");
        assert!(!limits.has_active_capacity());
        assert!(limits.try_acquire_active().is_none());

        drop(first);
        assert!(limits.has_active_capacity());
        assert!(limits.try_acquire_active().is_some());
        drop(second);
    }
}
