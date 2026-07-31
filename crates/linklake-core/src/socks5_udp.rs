use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Socks5UdpTarget {
    Ip(IpAddr),
    Domain(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks5UdpDatagram {
    pub target: Socks5UdpTarget,
    pub port: u16,
    pub payload: Vec<u8>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Socks5UdpError {
    #[error("SOCKS5 UDP datagram is too short")]
    TooShort,
    #[error("SOCKS5 UDP reserved bytes are invalid")]
    InvalidReserved,
    #[error("SOCKS5 UDP fragmentation is not supported")]
    FragmentationUnsupported,
    #[error("SOCKS5 UDP address type is unsupported")]
    UnsupportedAddressType,
    #[error("SOCKS5 UDP domain is invalid")]
    InvalidDomain,
    #[error("SOCKS5 UDP destination port is invalid")]
    InvalidPort,
    #[error("SOCKS5 UDP encoded datagram is too large")]
    TooLarge,
}

pub fn decode_socks5_udp_datagram(encoded: &[u8]) -> Result<Socks5UdpDatagram, Socks5UdpError> {
    if encoded.len() < 7 {
        return Err(Socks5UdpError::TooShort);
    }
    if encoded[0] != 0 || encoded[1] != 0 {
        return Err(Socks5UdpError::InvalidReserved);
    }
    if encoded[2] != 0 {
        return Err(Socks5UdpError::FragmentationUnsupported);
    }
    let (target, port_offset) = match encoded[3] {
        0x01 => {
            if encoded.len() < 10 {
                return Err(Socks5UdpError::TooShort);
            }
            (
                Socks5UdpTarget::Ip(IpAddr::V4(Ipv4Addr::new(
                    encoded[4], encoded[5], encoded[6], encoded[7],
                ))),
                8,
            )
        }
        0x03 => {
            let length = encoded[4] as usize;
            if length == 0 || encoded.len() < 5 + length + 2 {
                return Err(Socks5UdpError::TooShort);
            }
            let domain = std::str::from_utf8(&encoded[5..5 + length])
                .map_err(|_| Socks5UdpError::InvalidDomain)?;
            if !valid_domain(domain) {
                return Err(Socks5UdpError::InvalidDomain);
            }
            (Socks5UdpTarget::Domain(domain.to_owned()), 5 + length)
        }
        0x04 => {
            if encoded.len() < 22 {
                return Err(Socks5UdpError::TooShort);
            }
            let address = <[u8; 16]>::try_from(&encoded[4..20])
                .expect("the validated IPv6 SOCKS5 UDP header contains 16 bytes");
            (Socks5UdpTarget::Ip(IpAddr::V6(Ipv6Addr::from(address))), 20)
        }
        _ => return Err(Socks5UdpError::UnsupportedAddressType),
    };
    let port = u16::from_be_bytes([encoded[port_offset], encoded[port_offset + 1]]);
    if port == 0 {
        return Err(Socks5UdpError::InvalidPort);
    }
    Ok(Socks5UdpDatagram {
        target,
        port,
        payload: encoded[port_offset + 2..].to_vec(),
    })
}

pub fn encode_socks5_udp_response(
    source: SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, Socks5UdpError> {
    let header_len: usize = if source.is_ipv4() { 10 } else { 22 };
    let total = header_len
        .checked_add(payload.len())
        .ok_or(Socks5UdpError::TooLarge)?;
    if total > u16::MAX as usize {
        return Err(Socks5UdpError::TooLarge);
    }
    let mut encoded = Vec::with_capacity(total);
    encoded.extend_from_slice(&[0, 0, 0]);
    match source.ip() {
        IpAddr::V4(address) => {
            encoded.push(0x01);
            encoded.extend_from_slice(&address.octets());
        }
        IpAddr::V6(address) => {
            encoded.push(0x04);
            encoded.extend_from_slice(&address.octets());
        }
    }
    encoded.extend_from_slice(&source.port().to_be_bytes());
    encoded.extend_from_slice(payload);
    Ok(encoded)
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

#[cfg(test)]
mod tests {
    use super::{
        decode_socks5_udp_datagram, encode_socks5_udp_response, Socks5UdpError, Socks5UdpTarget,
    };
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    #[test]
    fn decodes_ipv4_domain_and_ipv6_requests() {
        let ipv4 = decode_socks5_udp_datagram(&[0, 0, 0, 1, 127, 0, 0, 1, 0x14, 0xe9, 1, 2, 3])
            .expect("IPv4 request should decode");
        assert_eq!(
            ipv4.target,
            Socks5UdpTarget::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
        assert_eq!(ipv4.port, 5353);
        assert_eq!(ipv4.payload, vec![1, 2, 3]);

        let mut domain = vec![0, 0, 0, 3, 9];
        domain.extend_from_slice(b"localhost");
        domain.extend_from_slice(&[0, 53, 4]);
        assert_eq!(
            decode_socks5_udp_datagram(&domain)
                .expect("domain request should decode")
                .target,
            Socks5UdpTarget::Domain("localhost".to_owned())
        );

        let address = Ipv6Addr::LOCALHOST.octets();
        let mut ipv6 = vec![0, 0, 0, 4];
        ipv6.extend_from_slice(&address);
        ipv6.extend_from_slice(&[0, 53]);
        assert_eq!(
            decode_socks5_udp_datagram(&ipv6)
                .expect("IPv6 request should decode")
                .target,
            Socks5UdpTarget::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
    }

    #[test]
    fn rejects_fragmented_and_malformed_requests() {
        assert_eq!(
            decode_socks5_udp_datagram(&[0, 0, 1, 1, 127, 0, 0, 1, 0, 53]),
            Err(Socks5UdpError::FragmentationUnsupported)
        );
        assert_eq!(
            decode_socks5_udp_datagram(&[0, 0, 0, 3, 3, b'a', b'.', b'.', 0, 53]),
            Err(Socks5UdpError::InvalidDomain)
        );
    }

    #[test]
    fn response_round_trip_preserves_source_and_payload() {
        for source in [
            SocketAddr::from(([127, 0, 0, 1], 53)),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 5353),
        ] {
            let encoded =
                encode_socks5_udp_response(source, b"reply").expect("response should encode");
            let decoded = decode_socks5_udp_datagram(&encoded)
                .expect("encoded response should share the request envelope");
            assert_eq!(decoded.target, Socks5UdpTarget::Ip(source.ip()));
            assert_eq!(decoded.port, source.port());
            assert_eq!(decoded.payload, b"reply");
        }
    }
}
