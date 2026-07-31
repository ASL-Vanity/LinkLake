//! P2P 直连候选、短期票据和显式回退决策。

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

pub const P2P_PROTOCOL_VERSION: u16 = 1;
const TICKET_PREFIX: &str = "llp2p_";

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum P2pTransport {
    #[default]
    Tcp,
    IrohQuic,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct P2pCandidate {
    #[serde(default)]
    pub transport: P2pTransport,
    pub endpoint: String,
    pub priority: u16,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct P2pIrohAddress {
    pub endpoint_id: String,
    pub direct_addresses: Vec<String>,
    pub relay_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<P2pNetworkProfile>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct P2pNetworkProfile {
    pub udp_v4: bool,
    pub udp_v6: bool,
    pub mapping_behavior: P2pMappingBehavior,
    pub global_v4: Option<String>,
    pub global_v6: Option<String>,
    pub port_mapping: bool,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum P2pMappingBehavior {
    EndpointIndependent,
    DestinationDependent,
    Blocked,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct P2pTicketClaims {
    pub session_id: Uuid,
    pub provider_client_id: Uuid,
    pub visitor_client_id: Uuid,
    pub target_addr: String,
    pub issued_unix_seconds: u64,
    pub expires_unix_seconds: u64,
    pub protocol_version: u16,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum P2pPath {
    Direct,
    Relay,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum P2pFallbackReason {
    NoCandidate,
    DirectTimeout,
    DirectRefused,
    AuthenticationFailed,
    ProtocolError,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum P2pTicketError {
    #[error("invalid P2P ticket format")]
    InvalidFormat,
    #[error("invalid P2P ticket signature")]
    InvalidSignature,
    #[error("P2P ticket expired")]
    Expired,
    #[error("P2P ticket is not valid yet")]
    NotYetValid,
    #[error("unsupported P2P protocol version")]
    UnsupportedVersion,
    #[error("invalid P2P ticket payload")]
    InvalidPayload,
}

pub fn issue_ticket(claims: &P2pTicketClaims, secret: &[u8]) -> Result<String, serde_json::Error> {
    let payload = serde_json::to_vec(claims)?;
    let signature = hmac_sha256(secret, &payload);
    Ok(format!(
        "{TICKET_PREFIX}{}.{}",
        encode_hex(&payload),
        encode_hex(&signature)
    ))
}

pub fn verify_ticket(
    ticket: &str,
    secret: &[u8],
    now_unix_seconds: u64,
) -> Result<P2pTicketClaims, P2pTicketError> {
    let value = ticket
        .strip_prefix(TICKET_PREFIX)
        .ok_or(P2pTicketError::InvalidFormat)?;
    let (payload, signature) = value.split_once('.').ok_or(P2pTicketError::InvalidFormat)?;
    let payload = decode_hex(payload).ok_or(P2pTicketError::InvalidFormat)?;
    let signature = decode_hex(signature).ok_or(P2pTicketError::InvalidFormat)?;
    if !constant_time_equal(&signature, &hmac_sha256(secret, &payload)) {
        return Err(P2pTicketError::InvalidSignature);
    }
    let claims: P2pTicketClaims =
        serde_json::from_slice(&payload).map_err(|_| P2pTicketError::InvalidPayload)?;
    if claims.protocol_version != P2P_PROTOCOL_VERSION {
        return Err(P2pTicketError::UnsupportedVersion);
    }
    if now_unix_seconds < claims.issued_unix_seconds {
        return Err(P2pTicketError::NotYetValid);
    }
    if now_unix_seconds >= claims.expires_unix_seconds {
        return Err(P2pTicketError::Expired);
    }
    Ok(claims)
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut normalized = [0_u8; BLOCK];
    if key.len() > BLOCK {
        normalized[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }
    let mut inner_key = [0x36_u8; BLOCK];
    let mut outer_key = [0x5c_u8; BLOCK];
    for index in 0..BLOCK {
        inner_key[index] ^= normalized[index];
        outer_key[index] ^= normalized[index];
    }
    let mut inner = Sha256::new();
    inner.update(inner_key);
    inner.update(message);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_key);
    outer.update(inner);
    outer.finalize().into()
}

fn encode_hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).ok())
        .collect()
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticket_is_signed_versioned_and_time_limited() {
        let claims = P2pTicketClaims {
            session_id: Uuid::new_v4(),
            provider_client_id: Uuid::new_v4(),
            visitor_client_id: Uuid::new_v4(),
            target_addr: "127.0.0.1:2333".to_owned(),
            issued_unix_seconds: 100,
            expires_unix_seconds: 130,
            protocol_version: P2P_PROTOCOL_VERSION,
        };
        let ticket = issue_ticket(&claims, b"test-secret").expect("ticket should issue");
        assert_eq!(
            verify_ticket(&ticket, b"test-secret", 110).expect("ticket should verify"),
            claims
        );
        assert_eq!(
            verify_ticket(&ticket, b"wrong-secret", 110),
            Err(P2pTicketError::InvalidSignature)
        );
        assert_eq!(
            verify_ticket(&ticket, b"test-secret", 130),
            Err(P2pTicketError::Expired)
        );
    }

    #[test]
    fn target_address_is_covered_by_the_ticket_signature() {
        let claims = P2pTicketClaims {
            session_id: Uuid::new_v4(),
            provider_client_id: Uuid::new_v4(),
            visitor_client_id: Uuid::new_v4(),
            target_addr: "127.0.0.1:2333".to_owned(),
            issued_unix_seconds: 100,
            expires_unix_seconds: 130,
            protocol_version: P2P_PROTOCOL_VERSION,
        };
        let ticket = issue_ticket(&claims, b"test-secret").expect("ticket should issue");
        let tampered = ticket.replacen("32333333", "32333334", 1);
        assert_ne!(tampered, ticket);
        assert_eq!(
            verify_ticket(&tampered, b"test-secret", 110),
            Err(P2pTicketError::InvalidSignature)
        );
    }
}
