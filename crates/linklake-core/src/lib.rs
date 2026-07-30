//! LinkLake 共用的、与传输方式无关的领域类型。

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;

pub mod udp_protocol;
pub mod udp_reassembly;

pub const API_VERSION: &str = "v1";
pub const PRODUCT_NAME: &str = "LinkLake";
pub const UDP_DATA_PLANE_PROTOCOL_VERSION: u16 = 1;
pub const UDP_DATA_PLANE_ALPN: &[u8] = b"linklake-udp/1";

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
    pub last_seen_unix_seconds: u64,
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
