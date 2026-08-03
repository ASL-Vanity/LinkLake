use crate::{client_registry::Authentication, record_audit, unix_seconds, AppState};
use linklake_core::{
    p2p_protocol::{
        issue_ticket, verify_ticket, P2pFallbackReason, P2pTicketClaims, P2P_PROTOCOL_VERSION,
    },
    write_control_frame_and_shutdown, BoxedIo, ControlFrame,
};
use std::{
    collections::HashMap,
    sync::{atomic::Ordering, Arc},
};
use uuid::Uuid;

pub(crate) const NODE_FRESHNESS_SECONDS: u64 = 120;
const TICKET_LIFETIME_SECONDS: u64 = 30;

pub(crate) struct PendingP2pSession {
    expires_unix_seconds: u64,
    noise_psk: [u8; 32],
}

pub(crate) fn node_is_fresh(updated_unix_seconds: u64, now_unix_seconds: u64) -> bool {
    now_unix_seconds.saturating_sub(updated_unix_seconds) <= NODE_FRESHNESS_SECONDS
}

pub(crate) async fn register_node(
    state: Arc<AppState>,
    mut stream: BoxedIo,
    client_id: Uuid,
    client_token: String,
    candidates: Vec<linklake_core::p2p_protocol::P2pCandidate>,
) {
    if !authenticated(&state, client_id, &client_token) {
        reject(&mut stream, "invalid client credentials").await;
        return;
    }
    let result = state
        .p2p_node_catalog
        .lock()
        .expect("P2P node catalog lock poisoned")
        .upsert(client_id, candidates, unix_seconds());
    if result.is_err() {
        reject(&mut stream, "invalid P2P node candidates").await;
        return;
    }
    record_audit(
        &state,
        "p2p_node.registered",
        &client_id.to_string(),
        "direct candidates updated",
    );
    let _ = write_control_frame_and_shutdown(&mut stream, &ControlFrame::P2pNodeRegistered).await;
}

pub(crate) async fn report_fallback(
    state: Arc<AppState>,
    mut stream: BoxedIo,
    client_id: Uuid,
    client_token: String,
    reason: P2pFallbackReason,
) {
    if !authenticated(&state, client_id, &client_token) {
        reject(&mut stream, "invalid client credentials").await;
        return;
    }
    state
        .metrics
        .p2p_relay_fallbacks_total
        .fetch_add(1, Ordering::Relaxed);
    record_audit(
        &state,
        "p2p.relay_fallback",
        &client_id.to_string(),
        &format!("reason={}", fallback_reason_name(reason)),
    );
    let _ = write_control_frame_and_shutdown(&mut stream, &ControlFrame::P2pFallbackRecorded).await;
}

pub(crate) async fn report_direct_success(
    state: Arc<AppState>,
    mut stream: BoxedIo,
    provider_client_id: Uuid,
    client_token: String,
    session_id: Uuid,
    visitor_client_id: Uuid,
) {
    if !authenticated(&state, provider_client_id, &client_token) {
        reject(&mut stream, "invalid client credentials").await;
        return;
    }
    state
        .metrics
        .p2p_direct_connections_total
        .fetch_add(1, Ordering::Relaxed);
    record_audit(
        &state,
        "p2p.direct_connected",
        &provider_client_id.to_string(),
        &format!("session={session_id}; visitor={visitor_client_id}"),
    );
    let _ = write_control_frame_and_shutdown(&mut stream, &ControlFrame::P2pDirectSuccessRecorded)
        .await;
}

pub(crate) async fn request_session(
    state: Arc<AppState>,
    mut stream: BoxedIo,
    visitor_client_id: Uuid,
    client_token: String,
    access_key: String,
) {
    if !authenticated(&state, visitor_client_id, &client_token) {
        reject(&mut stream, "invalid client credentials").await;
        return;
    }
    let policy = state
        .secret_tunnel_catalog
        .lock()
        .expect("secret tunnel catalog lock poisoned")
        .access_runtime_policy(visitor_client_id, &access_key)
        .unwrap_or(None);
    let Some(policy) = policy else {
        reject(&mut stream, "invalid or unauthorized P2P access key").await;
        return;
    };
    let now = unix_seconds();
    let candidates = state
        .p2p_node_catalog
        .lock()
        .expect("P2P node catalog lock poisoned")
        .get(policy.provider_client_id)
        .ok()
        .flatten()
        .filter(|node| node_is_fresh(node.updated_unix_seconds, now))
        .map_or_else(Vec::new, |node| node.candidates);
    let session_id = Uuid::new_v4();
    let claims = P2pTicketClaims {
        session_id,
        provider_client_id: policy.provider_client_id,
        visitor_client_id,
        target_addr: policy.target_addr,
        issued_unix_seconds: now,
        expires_unix_seconds: now + TICKET_LIFETIME_SECONDS,
        protocol_version: P2P_PROTOCOL_VERSION,
    };
    let Ok(ticket) = issue_ticket(&claims, state.enrollment_token.as_bytes()) else {
        reject(&mut stream, "could not issue P2P ticket").await;
        return;
    };
    let mut noise_psk = [0_u8; 32];
    if getrandom::fill(&mut noise_psk).is_err() {
        reject(&mut stream, "could not generate P2P session key").await;
        return;
    }
    {
        let mut sessions = state
            .p2p_sessions
            .lock()
            .expect("P2P session registry lock poisoned");
        purge_expired_sessions(&mut sessions, now);
        sessions.insert(
            session_id,
            PendingP2pSession {
                expires_unix_seconds: claims.expires_unix_seconds,
                noise_psk,
            },
        );
    }
    let relay_available = state
        .secret_tunnels
        .lock()
        .expect("secret tunnel registry lock poisoned")
        .contains_key(&policy.policy_id);
    state
        .metrics
        .p2p_session_offers_total
        .fetch_add(1, Ordering::Relaxed);
    let _ = write_control_frame_and_shutdown(
        &mut stream,
        &ControlFrame::P2pSessionOffer {
            ticket,
            noise_psk,
            candidates,
            relay_available,
        },
    )
    .await;
}

pub(crate) async fn validate_ticket(
    state: Arc<AppState>,
    mut stream: BoxedIo,
    provider_client_id: Uuid,
    client_token: String,
    ticket: String,
) {
    if !authenticated(&state, provider_client_id, &client_token) {
        reject(&mut stream, "invalid client credentials").await;
        return;
    }
    let now = unix_seconds();
    let claims = verify_ticket(&ticket, state.enrollment_token.as_bytes(), now);
    let Ok(claims) = claims else {
        reject(&mut stream, "invalid or expired P2P ticket").await;
        return;
    };
    if !ticket_matches_provider(&claims, provider_client_id) {
        reject(&mut stream, "P2P ticket belongs to another provider").await;
        return;
    }
    let noise_psk = consume_session(
        &mut state
            .p2p_sessions
            .lock()
            .expect("P2P session registry lock poisoned"),
        claims.session_id,
        now,
    );
    let Some(noise_psk) = noise_psk else {
        reject(&mut stream, "P2P ticket was already consumed").await;
        return;
    };
    let _ = write_control_frame_and_shutdown(
        &mut stream,
        &ControlFrame::P2pTicketValid {
            session_id: claims.session_id,
            visitor_client_id: claims.visitor_client_id,
            target_addr: claims.target_addr,
            noise_psk,
        },
    )
    .await;
}

fn purge_expired_sessions(sessions: &mut HashMap<Uuid, PendingP2pSession>, now: u64) {
    sessions.retain(|_, session| session.expires_unix_seconds > now);
}

pub(crate) fn pending_session_count(state: &AppState, now: u64) -> usize {
    let mut sessions = state
        .p2p_sessions
        .lock()
        .expect("P2P session registry lock poisoned");
    purge_expired_sessions(&mut sessions, now);
    sessions.len()
}

fn consume_session(
    sessions: &mut HashMap<Uuid, PendingP2pSession>,
    session_id: Uuid,
    now: u64,
) -> Option<[u8; 32]> {
    sessions
        .remove(&session_id)
        .filter(|session| session.expires_unix_seconds > now)
        .map(|session| session.noise_psk)
}

fn ticket_matches_provider(claims: &P2pTicketClaims, provider_client_id: Uuid) -> bool {
    claims.provider_client_id == provider_client_id
}

fn fallback_reason_name(reason: P2pFallbackReason) -> &'static str {
    match reason {
        P2pFallbackReason::NoCandidate => "no_candidate",
        P2pFallbackReason::DirectTimeout => "direct_timeout",
        P2pFallbackReason::DirectRefused => "direct_refused",
        P2pFallbackReason::AuthenticationFailed => "authentication_failed",
        P2pFallbackReason::ProtocolError => "protocol_error",
    }
}

fn authenticated(state: &AppState, client_id: Uuid, token: &str) -> bool {
    matches!(
        state
            .clients
            .lock()
            .expect("client registry lock poisoned")
            .authenticate_and_touch(client_id, token),
        Ok(Authentication::Authenticated)
    )
}

async fn reject(stream: &mut BoxedIo, message: &str) {
    let _ = write_control_frame_and_shutdown(
        stream,
        &ControlFrame::Error {
            message: message.to_owned(),
        },
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(provider_client_id: Uuid) -> P2pTicketClaims {
        P2pTicketClaims {
            session_id: Uuid::new_v4(),
            provider_client_id,
            visitor_client_id: Uuid::new_v4(),
            target_addr: "127.0.0.1:2333".to_owned(),
            issued_unix_seconds: 100,
            expires_unix_seconds: 130,
            protocol_version: P2P_PROTOCOL_VERSION,
        }
    }

    #[test]
    fn node_freshness_includes_the_boundary() {
        assert!(node_is_fresh(100, 220));
        assert!(!node_is_fresh(100, 221));
    }

    #[test]
    fn session_can_only_be_consumed_once() {
        let session_id = Uuid::new_v4();
        let key = [7_u8; 32];
        let mut sessions = HashMap::from([(
            session_id,
            PendingP2pSession {
                expires_unix_seconds: 130,
                noise_psk: key,
            },
        )]);
        assert_eq!(consume_session(&mut sessions, session_id, 110), Some(key));
        assert_eq!(consume_session(&mut sessions, session_id, 110), None);
    }

    #[test]
    fn ticket_provider_identity_must_match() {
        let provider = Uuid::new_v4();
        let claims = claims(provider);
        assert!(ticket_matches_provider(&claims, provider));
        assert!(!ticket_matches_provider(&claims, Uuid::new_v4()));
    }

    #[test]
    fn expired_sessions_are_removed_before_new_offers() {
        let live = Uuid::new_v4();
        let expired = Uuid::new_v4();
        let mut sessions = HashMap::from([
            (
                live,
                PendingP2pSession {
                    expires_unix_seconds: 131,
                    noise_psk: [1; 32],
                },
            ),
            (
                expired,
                PendingP2pSession {
                    expires_unix_seconds: 130,
                    noise_psk: [2; 32],
                },
            ),
        ]);
        purge_expired_sessions(&mut sessions, 130);
        assert_eq!(sessions.len(), 1);
        assert!(sessions.contains_key(&live));
    }
}
