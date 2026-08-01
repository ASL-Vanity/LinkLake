//! 多目标地址解析与加权轮询选择。

use thiserror::Error;

pub const MAX_TARGETS: usize = 16;
pub const MAX_TARGET_WEIGHT: u32 = 10_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeightedTarget {
    pub address: String,
    pub weight: u32,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TargetPoolError {
    #[error("target pool is empty")]
    Empty,
    #[error("target pool contains too many targets")]
    TooMany,
    #[error("target address is invalid")]
    InvalidAddress,
    #[error("target weight is invalid")]
    InvalidWeight,
}

pub fn parse_target_pool(value: &str) -> Result<Vec<WeightedTarget>, TargetPoolError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(TargetPoolError::Empty);
    }
    let segments = value.split(',').collect::<Vec<_>>();
    if segments.len() > MAX_TARGETS {
        return Err(TargetPoolError::TooMany);
    }
    segments
        .into_iter()
        .map(|segment| {
            let segment = segment.trim();
            let (address, weight) = match segment.rsplit_once('@') {
                Some((address, weight)) => {
                    let weight = weight
                        .parse::<u32>()
                        .map_err(|_| TargetPoolError::InvalidWeight)?;
                    if weight == 0 || weight > MAX_TARGET_WEIGHT {
                        return Err(TargetPoolError::InvalidWeight);
                    }
                    (address.trim(), weight)
                }
                None => (segment, 1),
            };
            validate_address(address)?;
            Ok(WeightedTarget {
                address: address.to_owned(),
                weight,
            })
        })
        .collect()
}

pub fn select_weighted_target(targets: &[WeightedTarget], sequence: u64) -> Option<&str> {
    let total = targets
        .iter()
        .map(|target| u64::from(target.weight))
        .sum::<u64>();
    if total == 0 {
        return None;
    }
    let mut slot = sequence % total;
    for target in targets {
        let weight = u64::from(target.weight);
        if slot < weight {
            return Some(&target.address);
        }
        slot -= weight;
    }
    None
}

fn validate_address(value: &str) -> Result<(), TargetPoolError> {
    if value.is_empty()
        || value.len() > 255
        || value.chars().any(|character| {
            character.is_whitespace()
                || character.is_control()
                || matches!(character, '/' | '\\' | '?' | '#' | '@')
        })
        || value.contains("://")
    {
        return Err(TargetPoolError::InvalidAddress);
    }
    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        let (host, port) = rest
            .split_once("]:")
            .ok_or(TargetPoolError::InvalidAddress)?;
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(TargetPoolError::InvalidAddress);
        }
        (host, port)
    } else {
        let (host, port) = value
            .rsplit_once(':')
            .ok_or(TargetPoolError::InvalidAddress)?;
        if host.contains(':') {
            return Err(TargetPoolError::InvalidAddress);
        }
        (host, port)
    };
    if host.is_empty() || host.contains('[') || host.contains(']') {
        return Err(TargetPoolError::InvalidAddress);
    }
    let port = port
        .parse::<u16>()
        .map_err(|_| TargetPoolError::InvalidAddress)?;
    if port == 0 {
        return Err(TargetPoolError::InvalidAddress);
    }
    if !value.starts_with('[')
        && host.parse::<std::net::Ipv4Addr>().is_err()
        && !valid_dns_name(host)
    {
        return Err(TargetPoolError::InvalidAddress);
    }
    Ok(())
}

fn valid_dns_name(host: &str) -> bool {
    host.len() <= 253
        && host.split('.').all(|label| {
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
    use super::*;

    #[test]
    fn weighted_pool_is_parsed_and_selected_without_expansion() {
        let targets = parse_target_pool("127.0.0.1:2333@2, game.local:2444@1").unwrap();
        assert_eq!(select_weighted_target(&targets, 0), Some("127.0.0.1:2333"));
        assert_eq!(select_weighted_target(&targets, 1), Some("127.0.0.1:2333"));
        assert_eq!(select_weighted_target(&targets, 2), Some("game.local:2444"));
        assert_eq!(select_weighted_target(&targets, 3), Some("127.0.0.1:2333"));
    }

    #[test]
    fn single_and_ipv6_targets_remain_compatible() {
        assert_eq!(
            parse_target_pool("[2001:db8::1]:443").unwrap()[0].address,
            "[2001:db8::1]:443"
        );
        assert!(parse_target_pool("localhost:80").is_ok());
        assert!(parse_target_pool("localhost:0").is_err());
        assert!(parse_target_pool("localhost:80@0").is_err());
    }
}
