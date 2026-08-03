//! 公网 UDP 端口的独立 IPv4/IPv6 socket、降级策略与地址族安全回包。

use socket2::{Domain, Protocol, Socket, Type};
use std::{
    fmt, io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    str::FromStr,
    sync::atomic::Ordering,
};
use tokio::net::UdpSocket;

use crate::AppState;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum PublicUdpBindMode {
    #[default]
    Auto,
    Ipv4Only,
    DualStackRequired,
}

impl PublicUdpBindMode {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Ipv4Only => "ipv4_only",
            Self::DualStackRequired => "dual_stack_required",
        }
    }
}

impl FromStr for PublicUdpBindMode {
    type Err = ParsePublicUdpBindModeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "ipv4_only" | "ipv4-only" | "ipv4" => Ok(Self::Ipv4Only),
            "dual_stack_required" | "dual-stack-required" | "required" => {
                Ok(Self::DualStackRequired)
            }
            _ => Err(ParsePublicUdpBindModeError),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ParsePublicUdpBindModeError;

impl fmt::Display for ParsePublicUdpBindModeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UDP public bind mode must be auto, ipv4_only, or dual_stack_required")
    }
}

impl std::error::Error for ParsePublicUdpBindModeError {}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum UdpAddressFamily {
    Ipv4,
    Ipv6,
}

impl UdpAddressFamily {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct PublicUdpEndpoint {
    address: SocketAddr,
    family: UdpAddressFamily,
}

impl PublicUdpEndpoint {
    pub(crate) fn new(address: SocketAddr, family: UdpAddressFamily) -> io::Result<Self> {
        if address_family(address) != family {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "UDP endpoint address family does not match its receiving socket",
            ));
        }
        Ok(Self { address, family })
    }

    pub(crate) const fn address(self) -> SocketAddr {
        self.address
    }

    pub(crate) const fn family(self) -> UdpAddressFamily {
        self.family
    }
}

impl From<SocketAddr> for PublicUdpEndpoint {
    fn from(address: SocketAddr) -> Self {
        Self {
            address,
            family: address_family(address),
        }
    }
}

impl fmt::Display for PublicUdpEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} ({})", self.address, self.family.as_str())
    }
}

#[derive(Debug)]
pub(crate) struct ReceivedUdpDatagram {
    pub(crate) length: usize,
    pub(crate) source: PublicUdpEndpoint,
}

#[derive(Debug)]
pub(crate) struct DualStackUdpSocket {
    ipv4: UdpSocket,
    ipv6: Option<UdpSocket>,
    mode: PublicUdpBindMode,
    ipv6_fallback_error: Option<String>,
    local_port: u16,
}

impl DualStackUdpSocket {
    pub(crate) async fn bind(port: u16, mode: PublicUdpBindMode) -> io::Result<Self> {
        Self::bind_with_ipv6(port, mode, bind_ipv6_socket).await
    }

    async fn bind_with_ipv6<F>(port: u16, mode: PublicUdpBindMode, bind_ipv6: F) -> io::Result<Self>
    where
        F: FnOnce(u16) -> io::Result<UdpSocket>,
    {
        let ipv4 = bind_ipv4_socket(port)?;
        let local_port = ipv4.local_addr()?.port();
        if mode == PublicUdpBindMode::Ipv4Only {
            return Ok(Self {
                ipv4,
                ipv6: None,
                mode,
                ipv6_fallback_error: None,
                local_port,
            });
        }

        match bind_ipv6(local_port) {
            Ok(ipv6) => Ok(Self {
                ipv4,
                ipv6: Some(ipv6),
                mode,
                ipv6_fallback_error: None,
                local_port,
            }),
            Err(error) if mode == PublicUdpBindMode::Auto && can_fallback_to_ipv4(&error) => {
                Ok(Self {
                    ipv4,
                    ipv6: None,
                    mode,
                    ipv6_fallback_error: Some(error.to_string()),
                    local_port,
                })
            }
            Err(error) => Err(io::Error::new(
                error.kind(),
                format!("IPv6 UDP bind failed on port {local_port}: {error}"),
            )),
        }
    }

    pub(crate) const fn mode(&self) -> PublicUdpBindMode {
        self.mode
    }

    pub(crate) const fn local_port(&self) -> u16 {
        self.local_port
    }

    pub(crate) const fn ipv6_enabled(&self) -> bool {
        self.ipv6.is_some()
    }

    pub(crate) fn ipv6_fallback_error(&self) -> Option<&str> {
        self.ipv6_fallback_error.as_deref()
    }

    #[cfg(test)]
    pub(crate) fn local_addr(&self, family: UdpAddressFamily) -> io::Result<SocketAddr> {
        match family {
            UdpAddressFamily::Ipv4 => self.ipv4.local_addr(),
            UdpAddressFamily::Ipv6 => self
                .ipv6
                .as_ref()
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::AddrNotAvailable, "IPv6 UDP is not enabled")
                })?
                .local_addr(),
        }
    }

    pub(crate) async fn recv_from(&self, buffer: &mut [u8]) -> io::Result<ReceivedUdpDatagram> {
        loop {
            let family = if let Some(ipv6) = &self.ipv6 {
                tokio::select! {
                    ready = self.ipv4.readable() => {
                        ready?;
                        UdpAddressFamily::Ipv4
                    }
                    ready = ipv6.readable() => {
                        ready?;
                        UdpAddressFamily::Ipv6
                    }
                }
            } else {
                self.ipv4.readable().await?;
                UdpAddressFamily::Ipv4
            };
            let socket = match family {
                UdpAddressFamily::Ipv4 => &self.ipv4,
                UdpAddressFamily::Ipv6 => self
                    .ipv6
                    .as_ref()
                    .expect("selected IPv6 readiness requires an IPv6 socket"),
            };
            match socket.try_recv_from(buffer) {
                Ok((length, address)) => {
                    return Ok(ReceivedUdpDatagram {
                        length,
                        source: PublicUdpEndpoint::new(address, family)?,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => return Err(error),
            }
        }
    }

    pub(crate) async fn send_to(
        &self,
        payload: &[u8],
        endpoint: PublicUdpEndpoint,
    ) -> io::Result<usize> {
        let socket = match endpoint.family() {
            UdpAddressFamily::Ipv4 if endpoint.address().is_ipv4() => &self.ipv4,
            UdpAddressFamily::Ipv6 if endpoint.address().is_ipv6() => {
                self.ipv6.as_ref().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::AddrNotAvailable,
                        "cannot reply to IPv6 because the IPv6 UDP socket is unavailable",
                    )
                })?
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "UDP endpoint address family changed before reply",
                ));
            }
        };
        socket.send_to(payload, endpoint.address()).await
    }
}

pub(crate) async fn bind_public_socket(
    state: &AppState,
    port: u16,
    listener_kind: &'static str,
) -> io::Result<DualStackUdpSocket> {
    let socket = match DualStackUdpSocket::bind(port, state.udp_public_bind_mode).await {
        Ok(socket) => socket,
        Err(error) => {
            state
                .metrics
                .udp_public_bind_failures_total
                .fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                listener = listener_kind,
                public_port = port,
                mode = state.udp_public_bind_mode.as_str(),
                "Public UDP listener bind failed: {error}"
            );
            return Err(error);
        }
    };
    state
        .metrics
        .udp_public_ipv4_bind_successes_total
        .fetch_add(1, Ordering::Relaxed);
    if socket.ipv6_enabled() {
        state
            .metrics
            .udp_public_ipv6_bind_successes_total
            .fetch_add(1, Ordering::Relaxed);
        tracing::info!(
            listener = listener_kind,
            public_port = socket.local_port(),
            mode = socket.mode().as_str(),
            "Public UDP listener is active on IPv4 and IPv6"
        );
    } else if let Some(error) = socket.ipv6_fallback_error() {
        state
            .metrics
            .udp_public_ipv6_bind_fallbacks_total
            .fetch_add(1, Ordering::Relaxed);
        tracing::warn!(
            listener = listener_kind,
            public_port = socket.local_port(),
            mode = socket.mode().as_str(),
            "Public UDP listener fell back to IPv4 only: {error}"
        );
    } else {
        tracing::info!(
            listener = listener_kind,
            public_port = socket.local_port(),
            mode = socket.mode().as_str(),
            "Public UDP listener is active on IPv4 only"
        );
    }
    Ok(socket)
}

fn bind_ipv4_socket(port: u16) -> io::Result<UdpSocket> {
    bind_socket(
        Domain::IPV4,
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)),
        false,
    )
}

fn bind_ipv6_socket(port: u16) -> io::Result<UdpSocket> {
    bind_socket(
        Domain::IPV6,
        SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0)),
        true,
    )
}

fn bind_socket(domain: Domain, address: SocketAddr, ipv6_only: bool) -> io::Result<UdpSocket> {
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if ipv6_only {
        socket.set_only_v6(true)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    let socket: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(socket)
}

fn can_fallback_to_ipv4(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::AddrNotAvailable | io::ErrorKind::Unsupported
    ) || raw_error_means_ipv6_is_unsupported(error.raw_os_error())
}

#[cfg(windows)]
const fn raw_error_means_ipv6_is_unsupported(code: Option<i32>) -> bool {
    // WinSock does not currently map these address-family/protocol errors to
    // ErrorKind::Unsupported, so keep the narrow OS classification explicit.
    matches!(code, Some(10_042 | 10_043 | 10_046 | 10_047))
}

#[cfg(target_os = "linux")]
const fn raw_error_means_ipv6_is_unsupported(code: Option<i32>) -> bool {
    // ENOPROTOOPT, EPROTONOSUPPORT, EAFNOSUPPORT.
    matches!(code, Some(92 | 93 | 97))
}

#[cfg(target_os = "macos")]
const fn raw_error_means_ipv6_is_unsupported(code: Option<i32>) -> bool {
    // ENOPROTOOPT, EPROTONOSUPPORT, EAFNOSUPPORT.
    matches!(code, Some(42 | 43 | 47))
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
const fn raw_error_means_ipv6_is_unsupported(_code: Option<i32>) -> bool {
    false
}

const fn address_family(address: SocketAddr) -> UdpAddressFamily {
    match address {
        SocketAddr::V4(_) => UdpAddressFamily::Ipv4,
        SocketAddr::V6(_) => UdpAddressFamily::Ipv6,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{timeout, Duration};

    #[test]
    fn bind_mode_parser_is_explicit() {
        assert_eq!(
            "auto".parse::<PublicUdpBindMode>().unwrap(),
            PublicUdpBindMode::Auto
        );
        assert_eq!(
            "ipv4_only".parse::<PublicUdpBindMode>().unwrap(),
            PublicUdpBindMode::Ipv4Only
        );
        assert_eq!(
            "dual_stack_required".parse::<PublicUdpBindMode>().unwrap(),
            PublicUdpBindMode::DualStackRequired
        );
        assert!("best_effort".parse::<PublicUdpBindMode>().is_err());
    }

    #[tokio::test]
    async fn ipv4_only_does_not_create_an_ipv6_socket() {
        let socket = DualStackUdpSocket::bind(0, PublicUdpBindMode::Ipv4Only)
            .await
            .unwrap();
        assert_eq!(socket.mode(), PublicUdpBindMode::Ipv4Only);
        assert!(!socket.ipv6_enabled());
        assert!(socket.ipv6_fallback_error().is_none());
        assert!(socket.local_port() != 0);
        assert!(socket.local_addr(UdpAddressFamily::Ipv6).is_err());
    }

    #[tokio::test]
    async fn auto_falls_back_when_ipv6_bind_is_unavailable() {
        let socket = DualStackUdpSocket::bind_with_ipv6(0, PublicUdpBindMode::Auto, |_| {
            Err(io::Error::new(io::ErrorKind::AddrNotAvailable, "test"))
        })
        .await
        .unwrap();
        assert!(!socket.ipv6_enabled());
        assert_eq!(socket.ipv6_fallback_error(), Some("test"));
    }

    #[tokio::test]
    async fn auto_fails_closed_on_ipv6_port_conflicts() {
        let error = DualStackUdpSocket::bind_with_ipv6(0, PublicUdpBindMode::Auto, |_| {
            Err(io::Error::new(io::ErrorKind::AddrInUse, "test conflict"))
        })
        .await
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
        assert!(error.to_string().contains("test conflict"));
    }

    #[tokio::test]
    async fn auto_fails_closed_on_ipv6_permission_errors() {
        let error = DualStackUdpSocket::bind_with_ipv6(0, PublicUdpBindMode::Auto, |_| {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "test permission",
            ))
        })
        .await
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("test permission"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_address_family_errors_are_fallback_eligible() {
        // WSAEAFNOSUPPORT is returned when the host has no usable IPv6 stack.
        let error = io::Error::from_raw_os_error(10_047);
        assert!(can_fallback_to_ipv4(&error));
    }

    #[tokio::test]
    async fn required_mode_fails_closed_when_ipv6_bind_is_unavailable() {
        let error =
            DualStackUdpSocket::bind_with_ipv6(0, PublicUdpBindMode::DualStackRequired, |_| {
                Err(io::Error::new(io::ErrorKind::AddrNotAvailable, "test"))
            })
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::AddrNotAvailable);
        assert!(error.to_string().contains("IPv6 UDP bind failed"));
    }

    #[tokio::test]
    async fn ipv4_and_ipv6_share_a_port_and_reply_through_the_receiving_family() {
        let server = match DualStackUdpSocket::bind(0, PublicUdpBindMode::DualStackRequired).await {
            Ok(server) => server,
            Err(error) if error.kind() == io::ErrorKind::AddrNotAvailable => {
                eprintln!("IPv6 loopback is unavailable on this host: {error}");
                return;
            }
            Err(error) => panic!("dual-stack UDP bind failed: {error}"),
        };
        let port = server.local_port();
        assert_eq!(
            server.local_addr(UdpAddressFamily::Ipv4).unwrap().port(),
            port
        );
        assert_eq!(
            server.local_addr(UdpAddressFamily::Ipv6).unwrap().port(),
            port
        );

        let ipv4 = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        ipv4.send_to(b"ipv4", (Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        let mut buffer = [0_u8; 32];
        let received = timeout(Duration::from_secs(2), server.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.source.family(), UdpAddressFamily::Ipv4);
        assert_eq!(&buffer[..received.length], b"ipv4");
        server
            .send_to(&buffer[..received.length], received.source)
            .await
            .unwrap();
        let (length, source) = timeout(Duration::from_secs(2), ipv4.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert!(source.is_ipv4());
        assert_eq!(&buffer[..length], b"ipv4");

        let ipv6 = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).await.unwrap();
        ipv6.send_to(b"ipv6", (Ipv6Addr::LOCALHOST, port))
            .await
            .unwrap();
        let received = timeout(Duration::from_secs(2), server.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.source.family(), UdpAddressFamily::Ipv6);
        assert_eq!(&buffer[..received.length], b"ipv6");
        server
            .send_to(&buffer[..received.length], received.source)
            .await
            .unwrap();
        let (length, source) = timeout(Duration::from_secs(2), ipv6.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert!(source.is_ipv6());
        assert_eq!(&buffer[..length], b"ipv6");
    }
}
