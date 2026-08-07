use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use thiserror::Error;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socks5UdpFragment {
    pub sequence: u8,
    pub final_fragment: bool,
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
    #[error("SOCKS5 UDP fragment sequence is invalid")]
    InvalidFragmentSequence,
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
    let fragment = decode_socks5_udp_fragment(encoded)?;
    if fragment.sequence != 0 || fragment.final_fragment {
        return Err(Socks5UdpError::FragmentationUnsupported);
    }
    Ok(Socks5UdpDatagram {
        target: fragment.target,
        port: fragment.port,
        payload: fragment.payload,
    })
}

pub fn decode_socks5_udp_fragment(encoded: &[u8]) -> Result<Socks5UdpFragment, Socks5UdpError> {
    if encoded.len() < 7 {
        return Err(Socks5UdpError::TooShort);
    }
    if encoded[0] != 0 || encoded[1] != 0 {
        return Err(Socks5UdpError::InvalidReserved);
    }
    let fragment_byte = encoded[2];
    let sequence = fragment_byte & 0x7f;
    let final_fragment = fragment_byte & 0x80 != 0;
    if final_fragment && sequence == 0 {
        return Err(Socks5UdpError::InvalidFragmentSequence);
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
    Ok(Socks5UdpFragment {
        sequence,
        final_fragment,
        target,
        port,
        payload: encoded[port_offset + 2..].to_vec(),
    })
}

pub fn encode_socks5_udp_datagram(datagram: &Socks5UdpDatagram) -> Result<Vec<u8>, Socks5UdpError> {
    let header_bytes = socks5_udp_envelope_header_len(&datagram.target)?;
    let total = header_bytes
        .checked_add(datagram.payload.len())
        .ok_or(Socks5UdpError::TooLarge)?;
    if total > u16::MAX as usize {
        return Err(Socks5UdpError::TooLarge);
    }
    let mut encoded = Vec::with_capacity(total);
    encoded.extend_from_slice(&[0, 0, 0]);
    match &datagram.target {
        Socks5UdpTarget::Ip(IpAddr::V4(address)) => {
            encoded.push(0x01);
            encoded.extend_from_slice(&address.octets());
        }
        Socks5UdpTarget::Ip(IpAddr::V6(address)) => {
            encoded.push(0x04);
            encoded.extend_from_slice(&address.octets());
        }
        Socks5UdpTarget::Domain(domain) => {
            encoded.push(0x03);
            encoded.push(domain.len() as u8);
            encoded.extend_from_slice(domain.as_bytes());
        }
    }
    encoded.extend_from_slice(&datagram.port.to_be_bytes());
    encoded.extend_from_slice(&datagram.payload);
    Ok(encoded)
}

/// 返回 SOCKS5 UDP 包头（保留字节、FRAG、地址和端口）的长度。
pub fn socks5_udp_envelope_header_len(target: &Socks5UdpTarget) -> Result<usize, Socks5UdpError> {
    let address_bytes = match target {
        Socks5UdpTarget::Ip(IpAddr::V4(_)) => 1 + 4,
        Socks5UdpTarget::Ip(IpAddr::V6(_)) => 1 + 16,
        Socks5UdpTarget::Domain(domain) => {
            if !valid_domain(domain) || domain.len() > u8::MAX as usize {
                return Err(Socks5UdpError::InvalidDomain);
            }
            2 + domain.len()
        }
    };
    3_usize
        .checked_add(address_bytes)
        .and_then(|value| value.checked_add(2))
        .ok_or(Socks5UdpError::TooLarge)
}

/// 返回一个 SOCKS5 UDP 分片完整封套的编码长度。
pub fn socks5_udp_fragment_encoded_len(
    fragment: &Socks5UdpFragment,
) -> Result<usize, Socks5UdpError> {
    socks5_udp_envelope_header_len(&fragment.target)?
        .checked_add(fragment.payload.len())
        .ok_or(Socks5UdpError::TooLarge)
}

pub fn encode_socks5_udp_response(
    source: SocketAddr,
    payload: &[u8],
) -> Result<Vec<u8>, Socks5UdpError> {
    encode_socks5_udp_datagram(&Socks5UdpDatagram {
        target: Socks5UdpTarget::Ip(source.ip()),
        port: source.port(),
        payload: payload.to_vec(),
    })
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
        decode_socks5_udp_datagram, decode_socks5_udp_fragment, encode_socks5_udp_datagram,
        encode_socks5_udp_response, Socks5UdpDatagram, Socks5UdpError, Socks5UdpTarget,
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
        let final_fragment = decode_socks5_udp_fragment(&[0, 0, 0x82, 1, 127, 0, 0, 1, 0, 53, 1])
            .expect("valid final fragment should decode");
        assert_eq!(final_fragment.sequence, 2);
        assert!(final_fragment.final_fragment);
        assert_eq!(
            decode_socks5_udp_fragment(&[0, 0, 0x80, 1, 127, 0, 0, 1, 0, 53]),
            Err(Socks5UdpError::InvalidFragmentSequence)
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

    #[test]
    fn generic_encoder_preserves_domain_targets() {
        let datagram = Socks5UdpDatagram {
            target: Socks5UdpTarget::Domain("dns.example".to_owned()),
            port: 53,
            payload: b"query".to_vec(),
        };
        let encoded = encode_socks5_udp_datagram(&datagram).unwrap();
        assert_eq!(decode_socks5_udp_datagram(&encoded).unwrap(), datagram);
    }
}
