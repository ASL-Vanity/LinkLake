//! 动态代理出口的解析与连接辅助。
//!
//! 域名只解析一次，所有返回地址都在连接前校验，随后直接使用已校验的
//! `SocketAddr` 建连，避免连接 API 再次解析导致 DNS rebinding。

use linklake_core::egress_policy::EgressPolicy;
use std::{collections::HashSet, net::SocketAddr};
use tokio::net::{lookup_host, TcpStream};

const MAX_RESOLVED_ADDRESSES: usize = 32;

pub(crate) async fn connect_tcp(
    host: &str,
    port: u16,
    policy: EgressPolicy,
) -> anyhow::Result<TcpStream> {
    let addresses = resolve_addresses(host, port, policy).await?;
    let mut last_error = None;
    for address in addresses {
        match TcpStream::connect(address).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    let _ = last_error;
    anyhow::bail!("proxy_target_connect_failed")
}

pub(crate) async fn resolve_udp_target(
    host: &str,
    port: u16,
    policy: EgressPolicy,
) -> anyhow::Result<SocketAddr> {
    let addresses = resolve_addresses(host, port, policy).await?;
    preferred_address(&addresses).ok_or_else(|| anyhow::anyhow!("proxy_target_did_not_resolve"))
}

async fn resolve_addresses(
    host: &str,
    port: u16,
    policy: EgressPolicy,
) -> anyhow::Result<Vec<SocketAddr>> {
    if host.is_empty() || port == 0 {
        anyhow::bail!("proxy_target_is_invalid");
    }
    let candidates = if let Ok(address) = host.parse() {
        vec![SocketAddr::new(address, port)]
    } else {
        lookup_host((host, port))
            .await
            .map_err(|_| anyhow::anyhow!("proxy_target_resolution_failed"))?
            .take(MAX_RESOLVED_ADDRESSES + 1)
            .collect()
    };
    validate_candidates(candidates, policy)
}

fn validate_candidates(
    candidates: Vec<SocketAddr>,
    policy: EgressPolicy,
) -> anyhow::Result<Vec<SocketAddr>> {
    if candidates.is_empty() {
        anyhow::bail!("proxy_target_did_not_resolve");
    }
    if candidates.len() > MAX_RESOLVED_ADDRESSES {
        anyhow::bail!("proxy_target_resolution_limit_exceeded");
    }

    let mut seen = HashSet::with_capacity(candidates.len());
    let mut validated = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        if !seen.insert(candidate) {
            continue;
        }
        policy
            .validate_ip(candidate.ip())
            .map_err(|error| anyhow::anyhow!(error.code()))?;
        validated.push(candidate);
    }
    if validated.is_empty() {
        anyhow::bail!("proxy_target_did_not_resolve");
    }
    Ok(validated)
}

fn preferred_address(addresses: &[SocketAddr]) -> Option<SocketAddr> {
    addresses
        .iter()
        .copied()
        .find(SocketAddr::is_ipv4)
        .or_else(|| addresses.first().copied())
}

#[cfg(test)]
mod tests {
    use super::{preferred_address, validate_candidates, MAX_RESOLVED_ADDRESSES};
    use linklake_core::egress_policy::EgressPolicy;
    use std::net::SocketAddr;

    #[test]
    fn mixed_public_and_sensitive_dns_answer_fails_closed() {
        let candidates = vec![
            SocketAddr::from(([1, 1, 1, 1], 443)),
            SocketAddr::from(([169, 254, 169, 254], 443)),
        ];
        assert_eq!(
            validate_candidates(candidates, EgressPolicy::public_only())
                .unwrap_err()
                .to_string(),
            "cloud_metadata_target_denied"
        );
    }

    #[test]
    fn private_override_does_not_unlock_loopback() {
        let candidates = vec![SocketAddr::from(([127, 0, 0, 1], 8080))];
        assert_eq!(
            validate_candidates(candidates, EgressPolicy::new(true))
                .unwrap_err()
                .to_string(),
            "sensitive_network_target_denied"
        );
    }

    #[test]
    fn duplicate_answers_are_deduplicated_after_validation() {
        let target = SocketAddr::from(([8, 8, 8, 8], 53));
        assert_eq!(
            validate_candidates(vec![target, target], EgressPolicy::public_only()).unwrap(),
            vec![target]
        );
    }

    #[test]
    fn oversized_dns_answer_is_rejected() {
        let candidates = (0..=MAX_RESOLVED_ADDRESSES)
            .map(|index| SocketAddr::from(([8, 8, 8, index as u8], 53)))
            .collect();
        assert_eq!(
            validate_candidates(candidates, EgressPolicy::public_only())
                .unwrap_err()
                .to_string(),
            "proxy_target_resolution_limit_exceeded"
        );
    }

    #[test]
    fn udp_prefers_ipv4_without_re_resolving() {
        let ipv6 = "[2606:4700:4700::1111]:53".parse().unwrap();
        let ipv4 = SocketAddr::from(([1, 1, 1, 1], 53));
        assert_eq!(preferred_address(&[ipv6, ipv4]), Some(ipv4));
    }
}
