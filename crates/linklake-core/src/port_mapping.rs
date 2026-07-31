//! 多端口与端口范围表达式的解析和规范化。

use std::collections::HashSet;
use thiserror::Error;

/// 单个端口组允许展开的最大映射数量。
pub const MAX_PORT_MAPPINGS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortPair {
    pub public_port: u16,
    pub target_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPortMappings {
    pub public_ports: String,
    pub target_ports: String,
    pub pairs: Vec<PortPair>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PortMappingError {
    #[error("port expression must not be blank")]
    Empty,
    #[error("invalid port expression")]
    InvalidSyntax,
    #[error("port range must be in ascending order")]
    DescendingRange,
    #[error("port is outside the allowed range")]
    PortOutOfRange,
    #[error("port expression contains a duplicate port")]
    DuplicatePort,
    #[error("port expression expands to too many ports")]
    TooManyPorts,
    #[error("public and target port counts must match")]
    CountMismatch,
}

/// 解析单端口、逗号列表和闭区间混合表达式。
pub fn parse_port_set(
    expression: &str,
    minimum: u16,
    maximum: u16,
    maximum_count: usize,
) -> Result<Vec<u16>, PortMappingError> {
    if expression.trim().is_empty() {
        return Err(PortMappingError::Empty);
    }
    if minimum == 0 || minimum > maximum || maximum_count == 0 {
        return Err(PortMappingError::PortOutOfRange);
    }

    let mut ports = Vec::new();
    let mut seen = HashSet::new();
    for item in expression.split(',') {
        let item = item.trim();
        if item.is_empty() {
            return Err(PortMappingError::InvalidSyntax);
        }

        let pieces = item.split('-').map(str::trim).collect::<Vec<_>>();
        let (start, end) = match pieces.as_slice() {
            [port] => {
                let port = parse_port(port)?;
                (port, port)
            }
            [start, end] if !start.is_empty() && !end.is_empty() => {
                (parse_port(start)?, parse_port(end)?)
            }
            _ => return Err(PortMappingError::InvalidSyntax),
        };

        if start > end {
            return Err(PortMappingError::DescendingRange);
        }
        if start < minimum || end > maximum {
            return Err(PortMappingError::PortOutOfRange);
        }

        for port in start..=end {
            if !seen.insert(port) {
                return Err(PortMappingError::DuplicatePort);
            }
            ports.push(port);
            if ports.len() > maximum_count {
                return Err(PortMappingError::TooManyPorts);
            }
        }
    }

    Ok(ports)
}

/// 按两侧表达式的展开顺序建立一一映射，并返回无歧义的规范化表达式。
pub fn parse_port_mappings(
    public_expression: &str,
    target_expression: &str,
    public_minimum: u16,
    public_maximum: u16,
    maximum_count: usize,
) -> Result<ParsedPortMappings, PortMappingError> {
    let public_ports = parse_port_set(
        public_expression,
        public_minimum,
        public_maximum,
        maximum_count,
    )?;
    let target_ports = parse_port_set(target_expression, 1, u16::MAX, maximum_count)?;
    if public_ports.len() != target_ports.len() {
        return Err(PortMappingError::CountMismatch);
    }

    let pairs = public_ports
        .iter()
        .copied()
        .zip(target_ports.iter().copied())
        .map(|(public_port, target_port)| PortPair {
            public_port,
            target_port,
        })
        .collect();

    Ok(ParsedPortMappings {
        public_ports: normalize_port_set(&public_ports),
        target_ports: normalize_port_set(&target_ports),
        pairs,
    })
}

fn parse_port(value: &str) -> Result<u16, PortMappingError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(PortMappingError::InvalidSyntax);
    }
    value
        .parse::<u16>()
        .map_err(|_| PortMappingError::PortOutOfRange)
}

fn normalize_port_set(ports: &[u16]) -> String {
    let mut result = Vec::new();
    let mut index = 0;
    while index < ports.len() {
        let start = ports[index];
        let mut end = start;
        while index + 1 < ports.len() && ports[index + 1] == end.saturating_add(1) {
            index += 1;
            end = ports[index];
        }
        if start == end {
            result.push(start.to_string());
        } else {
            result.push(format!("{start}-{end}"));
        }
        index += 1;
    }
    result.join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_normalizes_mixed_port_mappings() {
        let parsed = parse_port_mappings(
            " 32001, 32010 - 32012 ",
            "2333,2400,2401-2402",
            32_000,
            32_999,
            MAX_PORT_MAPPINGS,
        )
        .expect("mapping should parse");

        assert_eq!(parsed.public_ports, "32001,32010-32012");
        assert_eq!(parsed.target_ports, "2333,2400-2402");
        assert_eq!(
            parsed.pairs,
            vec![
                PortPair {
                    public_port: 32_001,
                    target_port: 2_333,
                },
                PortPair {
                    public_port: 32_010,
                    target_port: 2_400,
                },
                PortPair {
                    public_port: 32_011,
                    target_port: 2_401,
                },
                PortPair {
                    public_port: 32_012,
                    target_port: 2_402,
                },
            ]
        );
    }

    #[test]
    fn preserves_mapping_order() {
        let parsed = parse_port_mappings("32010,32001", "80,443", 32_000, 32_999, 2)
            .expect("mapping should parse");
        assert_eq!(parsed.public_ports, "32010,32001");
        assert_eq!(parsed.pairs[0].target_port, 80);
        assert_eq!(parsed.pairs[1].target_port, 443);
    }

    #[test]
    fn rejects_ambiguous_or_unsafe_expressions() {
        assert_eq!(
            parse_port_set("", 1, u16::MAX, 256),
            Err(PortMappingError::Empty)
        );
        assert_eq!(
            parse_port_set("80,,81", 1, u16::MAX, 256),
            Err(PortMappingError::InvalidSyntax)
        );
        assert_eq!(
            parse_port_set("82-80", 1, u16::MAX, 256),
            Err(PortMappingError::DescendingRange)
        );
        assert_eq!(
            parse_port_set("80,79-80", 1, u16::MAX, 256),
            Err(PortMappingError::DuplicatePort)
        );
        assert_eq!(
            parse_port_set("0", 1, u16::MAX, 256),
            Err(PortMappingError::PortOutOfRange)
        );
        assert_eq!(
            parse_port_set("32000-32002", 32_000, 32_999, 2),
            Err(PortMappingError::TooManyPorts)
        );
    }

    #[test]
    fn rejects_count_mismatch_and_public_ports_outside_namespace() {
        assert_eq!(
            parse_port_mappings("32000-32001", "80", 32_000, 32_999, 256),
            Err(PortMappingError::CountMismatch)
        );
        assert_eq!(
            parse_port_mappings("31999", "80", 32_000, 32_999, 256),
            Err(PortMappingError::PortOutOfRange)
        );
    }
}
