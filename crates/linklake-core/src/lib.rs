//! LinkLake 共用的、与传输方式无关的领域类型。

use crate::p2p_protocol::P2pCandidate;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;

pub mod fleet_protocol;
pub mod p2p_protocol;
pub mod port_mapping;
pub mod public_ports;
pub mod socks5_udp;
pub mod target_pool;
pub mod udp_protocol;
pub mod udp_reassembly;

pub const API_VERSION: &str = "v1";
pub const PRODUCT_NAME: &str = "LinkLake";
pub const UDP_DATA_PLANE_PROTOCOL_VERSION: u16 = 1;
pub const UDP_DATA_PLANE_ALPN: &[u8] = b"linklake-udp/1";

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct BuildInfo {
    pub product: &'static str,
    pub version: &'static str,
    pub target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<&'static str>,
}

impl BuildInfo {
    pub fn current(product: &'static str) -> Self {
        Self {
            product,
            version: env!("CARGO_PKG_VERSION"),
            target: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
            commit: option_env!("LINKLAKE_GIT_COMMIT").filter(|value| !value.trim().is_empty()),
        }
    }

    pub fn display_line(&self) -> String {
        match self.commit {
            Some(commit) => format!(
                "{} {} target={} commit={}",
                self.product, self.version, self.target, commit
            ),
            None => format!("{} {} target={}", self.product, self.version, self.target),
        }
    }
}

pub trait AsyncIo: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> AsyncIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub type BoxedIo = Box<dyn AsyncIo>;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TunnelProtocol {
    Tcp,
    Udp,
    Http,
    Https,
    HttpProxy,
    Socks5,
    File,
    Secret,
    P2p,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct TunnelSpec {
    pub id: Uuid,
    pub name: String,
    pub protocol: TunnelProtocol,
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ClientEnrollmentRequest {
    pub name: String,
    pub platform: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ClientEnrollmentResponse {
    pub client_id: Uuid,
    /// 仅在客户端注册时返回，必须作为密钥安全保存。
    pub client_token: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ClientSummary {
    pub client_id: Uuid,
    pub name: String,
    pub platform: String,
    pub group_name: Option<String>,
    pub tags: Vec<String>,
    pub notes: Option<String>,
    pub enabled: bool,
    pub created_unix_seconds: u64,
    pub token_rotated_unix_seconds: Option<u64>,
    pub last_seen_unix_seconds: u64,
    pub config_mode: ManagedConfigMode,
    pub config_sync_status: ManagedConfigStatus,
    pub applied_config_revision: Option<String>,
    pub config_sync_error: Option<String>,
    pub config_checked_unix_seconds: Option<u64>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ManagedConfigMode {
    #[default]
    Local,
    ReportOnly,
    ServerManaged,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ManagedConfigStatus {
    #[default]
    Unknown,
    Synchronized,
    Conflict,
    ApplyFailed,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ManagedTcpTunnel {
    pub name: String,
    pub public_port: u16,
    pub target_addr: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ManagedUdpTunnel {
    pub name: String,
    pub public_port: u16,
    pub target_addr: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ManagedHttpRoute {
    pub name: String,
    pub hostname: String,
    pub target_addr: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ManagedTlsRoute {
    pub name: String,
    pub hostname: String,
    pub target_addr: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ManagedSecretTunnel {
    pub name: String,
    pub target_addr: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ManagedSocks5Proxy {
    pub name: String,
    pub public_port: u16,
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ManagedHttpProxy {
    pub name: String,
    pub public_port: u16,
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct ManagedClientConfig {
    pub revision: String,
    pub tcp_tunnels: Vec<ManagedTcpTunnel>,
    pub udp_tunnels: Vec<ManagedUdpTunnel>,
    pub http_routes: Vec<ManagedHttpRoute>,
    #[serde(default)]
    pub tls_routes: Vec<ManagedTlsRoute>,
    pub secret_tunnels: Vec<ManagedSecretTunnel>,
    #[serde(default)]
    pub socks5_proxies: Vec<ManagedSocks5Proxy>,
    #[serde(default)]
    pub http_proxies: Vec<ManagedHttpProxy>,
}

pub fn managed_config_revision(config: &ManagedClientConfig) -> Result<String, serde_json::Error> {
    let canonical = serde_json::to_vec(&(
        config.tcp_tunnels.as_slice(),
        config.udp_tunnels.as_slice(),
        config.http_routes.as_slice(),
        config.tls_routes.as_slice(),
        config.secret_tunnels.as_slice(),
        config.socks5_proxies.as_slice(),
        config.http_proxies.as_slice(),
    ))?;
    Ok(format!("sha256:{:x}", Sha256::digest(canonical)))
}

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("tunnel name must not be blank")]
    EmptyTunnelName,
    #[error("client name must not be blank")]
    EmptyClientName,
    #[error("client platform must not be blank")]
    EmptyClientPlatform,
}

impl ClientEnrollmentRequest {
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.name.trim().is_empty() {
            return Err(CoreError::EmptyClientName);
        }
        if self.platform.trim().is_empty() {
            return Err(CoreError::EmptyClientPlatform);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ControlFrame {
    RequestManagedConfig {
        client_id: Uuid,
        client_token: String,
        mode: ManagedConfigMode,
        applied_revision: Option<String>,
        status: ManagedConfigStatus,
        error: Option<String>,
    },
    ManagedConfig {
        config: ManagedClientConfig,
    },
    RegisterSecretTunnel {
        client_id: Uuid,
        client_token: String,
        name: String,
        target_addr: String,
    },
    SecretTunnelRegistered {
        tunnel_id: Uuid,
    },
    ConnectSecretTunnel {
        client_id: Uuid,
        client_token: String,
        access_key: String,
    },
    SecretTunnelConnected {
        tunnel_id: Uuid,
    },
    OpenSecretConnection {
        connection_id: Uuid,
    },
    RegisterSocks5Proxy {
        client_id: Uuid,
        client_token: String,
        name: String,
        public_port: u16,
    },
    Socks5ProxyRegistered {
        proxy_id: Uuid,
        public_port: u16,
        udp_associate: bool,
    },
    Socks5UdpDataPlaneOffer {
        registration_id: Uuid,
        ticket: String,
        endpoint: String,
        server_name: String,
        max_datagram_size: u32,
        session_idle_timeout_seconds: u32,
    },
    OpenSocks5Connection {
        connection_id: Uuid,
        target_host: String,
        target_port: u16,
    },
    RegisterHttpProxy {
        client_id: Uuid,
        client_token: String,
        name: String,
        public_port: u16,
    },
    HttpProxyRegistered {
        proxy_id: Uuid,
        public_port: u16,
    },
    OpenHttpProxyConnection {
        connection_id: Uuid,
        target_host: String,
        target_port: u16,
    },
    RegisterTcpTunnel {
        client_id: Uuid,
        client_token: String,
        name: String,
        public_port: u16,
        target_addr: String,
    },
    RegisterHttpRoute {
        client_id: Uuid,
        client_token: String,
        name: String,
        hostname: String,
        target_addr: String,
    },
    RegisterTlsRoute {
        client_id: Uuid,
        client_token: String,
        name: String,
        hostname: String,
        target_addr: String,
    },
    RegisterUdpTunnel {
        client_id: Uuid,
        client_token: String,
        name: String,
        public_port: u16,
        target_addr: String,
    },
    TcpTunnelRegistered {
        public_port: u16,
    },
    HttpRouteRegistered {
        hostname: String,
    },
    TlsRouteRegistered {
        hostname: String,
    },
    RegisterP2pNode {
        client_id: Uuid,
        client_token: String,
        candidates: Vec<P2pCandidate>,
    },
    P2pNodeRegistered,
    RequestP2pSession {
        client_id: Uuid,
        client_token: String,
        access_key: String,
    },
    P2pSessionOffer {
        ticket: String,
        noise_psk: [u8; 32],
        candidates: Vec<P2pCandidate>,
        relay_available: bool,
    },
    ValidateP2pTicket {
        client_id: Uuid,
        client_token: String,
        ticket: String,
    },
    P2pTicketValid {
        session_id: Uuid,
        visitor_client_id: Uuid,
        target_addr: String,
        noise_psk: [u8; 32],
    },
    ReportP2pDirectSuccess {
        client_id: Uuid,
        client_token: String,
        session_id: Uuid,
        visitor_client_id: Uuid,
    },
    P2pDirectSuccessRecorded,
    ReportP2pFallback {
        client_id: Uuid,
        client_token: String,
        reason: crate::p2p_protocol::P2pFallbackReason,
    },
    P2pFallbackRecorded,
    UdpDataPlaneOffer {
        registration_id: Uuid,
        ticket: String,
        endpoint: String,
        server_name: String,
        max_datagram_size: u32,
        session_idle_timeout_seconds: u32,
    },
    UdpTunnelRegistered {
        registration_id: Uuid,
        public_port: u16,
    },
    OpenTcpConnection {
        connection_id: Uuid,
    },
    TcpDataConnection {
        client_id: Uuid,
        client_token: String,
        connection_id: Uuid,
    },
    ControlHeartbeat {
        nonce: u64,
    },
    ControlHeartbeatAck {
        nonce: u64,
    },
    Error {
        message: String,
    },
}

/// UDP 数据面可靠控制流使用的帧，不与普通 TCP 控制连接的数据帧混用。
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UdpDataPlaneControlFrame {
    Attach {
        client_id: Uuid,
        registration_id: Uuid,
        ticket: String,
        protocol_version: u16,
    },
    Ready {
        registration_id: Uuid,
        negotiated_max_datagram_size: u32,
    },
    CloseSession {
        session_id: Uuid,
        reason: UdpSessionCloseReason,
    },
    Error {
        code: String,
        message: String,
    },
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UdpSessionCloseReason {
    IdleTimeout,
    TargetUnavailable,
    PolicyDisabled,
    DataPlaneClosed,
    ProtocolError,
}

#[derive(Debug, Error)]
pub enum ControlFrameError {
    #[error("control frame is too large")]
    FrameTooLarge,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid control frame: {0}")]
    Json(#[from] serde_json::Error),
}

const MAX_CONTROL_FRAME_BYTES: usize = 64 * 1024;

pub async fn write_control_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &ControlFrame,
) -> Result<(), ControlFrameError> {
    let payload = serde_json::to_vec(frame)?;
    if payload.len() > MAX_CONTROL_FRAME_BYTES {
        return Err(ControlFrameError::FrameTooLarge);
    }
    writer.write_u32(payload.len() as u32).await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    Ok(())
}

/// 写入一次性控制响应后执行优雅关闭，确保 TLS close_notify 和尾部记录完整送达。
pub async fn write_control_frame_and_shutdown<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &ControlFrame,
) -> Result<(), ControlFrameError> {
    write_control_frame(writer, frame).await?;
    writer.shutdown().await?;
    Ok(())
}

pub async fn read_control_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<ControlFrame, ControlFrameError> {
    let length = reader.read_u32().await? as usize;
    if length > MAX_CONTROL_FRAME_BYTES {
        return Err(ControlFrameError::FrameTooLarge);
    }
    let mut payload = vec![0; length];
    reader.read_exact(&mut payload).await?;
    Ok(serde_json::from_slice(&payload)?)
}

pub async fn write_udp_data_plane_control_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &UdpDataPlaneControlFrame,
) -> Result<(), ControlFrameError> {
    let payload = serde_json::to_vec(frame)?;
    if payload.len() > MAX_CONTROL_FRAME_BYTES {
        return Err(ControlFrameError::FrameTooLarge);
    }
    writer.write_u32(payload.len() as u32).await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_udp_data_plane_control_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<UdpDataPlaneControlFrame, ControlFrameError> {
    let length = reader.read_u32().await? as usize;
    if length > MAX_CONTROL_FRAME_BYTES {
        return Err(ControlFrameError::FrameTooLarge);
    }
    let mut payload = vec![0; length];
    reader.read_exact(&mut payload).await?;
    Ok(serde_json::from_slice(&payload)?)
}

impl TunnelSpec {
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.name.trim().is_empty() {
            return Err(CoreError::EmptyTunnelName);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enrollment_requires_name_and_platform() {
        assert!(ClientEnrollmentRequest {
            name: "".to_owned(),
            platform: "linux".to_owned()
        }
        .validate()
        .is_err());
        assert!(ClientEnrollmentRequest {
            name: "node-1".to_owned(),
            platform: "".to_owned()
        }
        .validate()
        .is_err());
        assert!(ClientEnrollmentRequest {
            name: "node-1".to_owned(),
            platform: "linux".to_owned()
        }
        .validate()
        .is_ok());
    }

    #[tokio::test]
    async fn terminal_control_response_delivers_frame_before_eof() {
        let (mut client, mut server) = tokio::io::duplex(4 * 1024);
        let writer = tokio::spawn(async move {
            write_control_frame_and_shutdown(&mut server, &ControlFrame::P2pNodeRegistered)
                .await
                .expect("terminal response should write and close");
        });
        let frame = read_control_frame(&mut client)
            .await
            .expect("client should receive the complete terminal frame");
        assert_eq!(frame, ControlFrame::P2pNodeRegistered);
        let mut trailing = [0_u8; 1];
        assert_eq!(
            client
                .read(&mut trailing)
                .await
                .expect("EOF should be readable"),
            0
        );
        writer.await.expect("writer task should finish");
    }

    #[tokio::test]
    async fn control_frames_round_trip() {
        let expected = ControlFrame::OpenTcpConnection {
            connection_id: Uuid::new_v4(),
        };
        let (mut writer, mut reader) = tokio::io::duplex(1024);
        let write = write_control_frame(&mut writer, &expected);
        let read = read_control_frame(&mut reader);
        let (_, actual) = tokio::join!(write, read);
        assert_eq!(actual.expect("frame should decode"), expected);
    }

    #[tokio::test]
    async fn control_heartbeat_frames_round_trip() {
        let expected = ControlFrame::ControlHeartbeat { nonce: 42 };
        let (mut writer, mut reader) = tokio::io::duplex(1024);
        let write = write_control_frame(&mut writer, &expected);
        let read = read_control_frame(&mut reader);
        let (_, actual) = tokio::join!(write, read);
        assert_eq!(actual.expect("heartbeat frame should decode"), expected);
    }

    #[tokio::test]
    async fn socks5_udp_negotiation_frames_round_trip() {
        let registration_id = Uuid::new_v4();
        let frames = [
            ControlFrame::Socks5UdpDataPlaneOffer {
                registration_id,
                ticket: "single-use-ticket".to_owned(),
                endpoint: "127.0.0.1:32001".to_owned(),
                server_name: "localhost".to_owned(),
                max_datagram_size: 1200,
                session_idle_timeout_seconds: 120,
            },
            ControlFrame::Socks5ProxyRegistered {
                proxy_id: registration_id,
                public_port: 1080,
                udp_associate: true,
            },
        ];
        for expected in frames {
            let (mut writer, mut reader) = tokio::io::duplex(2048);
            let write = write_control_frame(&mut writer, &expected);
            let read = read_control_frame(&mut reader);
            let (_, actual) = tokio::join!(write, read);
            assert_eq!(actual.expect("SOCKS5 UDP frame should decode"), expected);
        }
    }

    #[tokio::test]
    async fn http_proxy_control_frames_round_trip() {
        let proxy_id = Uuid::new_v4();
        let connection_id = Uuid::new_v4();
        let frames = [
            ControlFrame::RegisterHttpProxy {
                client_id: Uuid::new_v4(),
                client_token: "token".to_owned(),
                name: "web-exit".to_owned(),
                public_port: 32022,
            },
            ControlFrame::HttpProxyRegistered {
                proxy_id,
                public_port: 32022,
            },
            ControlFrame::OpenHttpProxyConnection {
                connection_id,
                target_host: "example.com".to_owned(),
                target_port: 443,
            },
        ];
        for expected in frames {
            let (mut writer, mut reader) = tokio::io::duplex(2048);
            let write = write_control_frame(&mut writer, &expected);
            let read = read_control_frame(&mut reader);
            let (_, actual) = tokio::join!(write, read);
            assert_eq!(actual.expect("HTTP proxy frame should decode"), expected);
        }
    }

    #[tokio::test]
    async fn managed_configuration_frames_round_trip() {
        let expected = ControlFrame::ManagedConfig {
            config: ManagedClientConfig {
                revision: "sha256:test".to_owned(),
                tcp_tunnels: vec![ManagedTcpTunnel {
                    name: "game".to_owned(),
                    public_port: 32_001,
                    target_addr: "127.0.0.1:2333".to_owned(),
                    enabled: true,
                }],
                udp_tunnels: Vec::new(),
                http_routes: Vec::new(),
                tls_routes: Vec::new(),
                secret_tunnels: Vec::new(),
                socks5_proxies: Vec::new(),
                http_proxies: Vec::new(),
            },
        };
        let (mut writer, mut reader) = tokio::io::duplex(4096);
        let write = write_control_frame(&mut writer, &expected);
        let read = read_control_frame(&mut reader);
        let (_, actual) = tokio::join!(write, read);
        assert_eq!(
            actual.expect("managed config frame should decode"),
            expected
        );
    }

    #[test]
    fn managed_configuration_revision_detects_policy_changes() {
        let mut config = ManagedClientConfig {
            revision: String::new(),
            tcp_tunnels: vec![ManagedTcpTunnel {
                name: "game".to_owned(),
                public_port: 32_001,
                target_addr: "127.0.0.1:2333".to_owned(),
                enabled: true,
            }],
            udp_tunnels: Vec::new(),
            http_routes: Vec::new(),
            tls_routes: Vec::new(),
            secret_tunnels: Vec::new(),
            socks5_proxies: Vec::new(),
            http_proxies: Vec::new(),
        };
        let first = managed_config_revision(&config).expect("revision should calculate");
        config.tcp_tunnels[0].enabled = false;
        let second = managed_config_revision(&config).expect("revision should calculate");
        assert_ne!(first, second);
        assert!(first.starts_with("sha256:"));
        assert_eq!(first.len(), 71);
    }

    #[tokio::test]
    async fn udp_data_plane_control_frames_round_trip() {
        let expected = UdpDataPlaneControlFrame::Attach {
            client_id: Uuid::new_v4(),
            registration_id: Uuid::new_v4(),
            ticket: "single-use-ticket".to_owned(),
            protocol_version: UDP_DATA_PLANE_PROTOCOL_VERSION,
        };
        let (mut writer, mut reader) = tokio::io::duplex(1024);
        let write = write_udp_data_plane_control_frame(&mut writer, &expected);
        let read = read_udp_data_plane_control_frame(&mut reader);
        let (_, actual) = tokio::join!(write, read);
        assert_eq!(actual.expect("UDP control frame should decode"), expected);
    }

    #[tokio::test]
    async fn udp_data_plane_control_reader_rejects_oversized_frame() {
        let (mut writer, mut reader) = tokio::io::duplex(16);
        let write = async move {
            writer
                .write_u32((MAX_CONTROL_FRAME_BYTES + 1) as u32)
                .await
                .expect("length should write");
        };
        let read = read_udp_data_plane_control_frame(&mut reader);
        let (_, actual) = tokio::join!(write, read);
        assert!(matches!(actual, Err(ControlFrameError::FrameTooLarge)));
    }
}
