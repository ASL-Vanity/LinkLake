//! 公网监听端口策略及紧凑端口区间解析。

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct PortRanges {
    ranges: Vec<PortRange>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PortRangesError {
    #[error("port expression is empty")]
    Empty,
    #[error("port value is invalid")]
    InvalidPort,
    #[error("port range must be in ascending order")]
    DescendingRange,
    #[error("port expression contains an empty segment")]
    EmptySegment,
}

impl PortRanges {
    pub fn parse(expression: &str) -> Result<Self, PortRangesError> {
        let ranges = parse_ranges(expression, false)?;
        Ok(Self { ranges })
    }

    pub fn parse_optional(expression: &str) -> Result<Self, PortRangesError> {
        let ranges = parse_ranges(expression, true)?;
        Ok(Self { ranges })
    }

    pub fn empty() -> Self {
        Self { ranges: Vec::new() }
    }

    pub fn contains(&self, port: u16) -> bool {
        port != 0
            && self
                .ranges
                .binary_search_by(|range| {
                    if port < range.start {
                        std::cmp::Ordering::Greater
                    } else if port > range.end {
                        std::cmp::Ordering::Less
                    } else {
                        std::cmp::Ordering::Equal
                    }
                })
                .is_ok()
    }

    pub fn ranges(&self) -> &[PortRange] {
        &self.ranges
    }

    pub fn expression(&self) -> String {
        self.ranges
            .iter()
            .map(|range| {
                if range.start == range.end {
                    range.start.to_string()
                } else {
                    format!("{}-{}", range.start, range.end)
                }
            })
            .collect::<Vec<_>>()
            .join(",")
    }

    pub fn including_ports<I>(&self, ports: I) -> Self
    where
        I: IntoIterator<Item = u16>,
    {
        let mut ranges = self.ranges.clone();
        ranges.extend(
            ports
                .into_iter()
                .filter(|port| *port != 0)
                .map(|port| PortRange {
                    start: port,
                    end: port,
                }),
        );
        Self {
            ranges: normalize_ranges(ranges),
        }
    }
}

fn parse_ranges(expression: &str, allow_empty: bool) -> Result<Vec<PortRange>, PortRangesError> {
    let expression = expression.trim();
    if expression.is_empty() {
        return if allow_empty {
            Ok(Vec::new())
        } else {
            Err(PortRangesError::Empty)
        };
    }

    let mut ranges = Vec::new();
    for segment in expression.split(',') {
        let segment = segment.trim();
        if segment.is_empty() {
            return Err(PortRangesError::EmptySegment);
        }
        let range = match segment.split_once('-') {
            Some((start, end)) => {
                if end.contains('-') {
                    return Err(PortRangesError::InvalidPort);
                }
                let start = parse_port(start)?;
                let end = parse_port(end)?;
                if start > end {
                    return Err(PortRangesError::DescendingRange);
                }
                PortRange { start, end }
            }
            None => {
                let port = parse_port(segment)?;
                PortRange {
                    start: port,
                    end: port,
                }
            }
        };
        ranges.push(range);
    }
    Ok(normalize_ranges(ranges))
}

fn parse_port(value: &str) -> Result<u16, PortRangesError> {
    let value = value.trim();
    value
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or(PortRangesError::InvalidPort)
}

fn normalize_ranges(mut ranges: Vec<PortRange>) -> Vec<PortRange> {
    ranges.sort_by_key(|range| (range.start, range.end));
    let mut normalized: Vec<PortRange> = Vec::with_capacity(ranges.len());
    for range in ranges {
        if let Some(previous) = normalized.last_mut() {
            if range.start <= previous.end.saturating_add(1) {
                previous.end = previous.end.max(range.end);
                continue;
            }
        }
        normalized.push(range);
    }
    normalized
}

#[cfg(test)]
mod tests {
    use super::{PortRange, PortRanges, PortRangesError};

    #[test]
    fn parses_and_normalizes_ranges() {
        let parsed = PortRanges::parse("443,80,100-110,108-120,81").unwrap();
        assert_eq!(parsed.expression(), "80-81,100-120,443");
        assert!(parsed.contains(80));
        assert!(parsed.contains(115));
        assert!(!parsed.contains(82));
    }

    #[test]
    fn supports_full_port_space_without_expansion() {
        let parsed = PortRanges::parse("1-65535").unwrap();
        assert_eq!(
            parsed.ranges(),
            &[PortRange {
                start: 1,
                end: 65535
            }]
        );
        assert!(parsed.contains(1));
        assert!(parsed.contains(65535));
    }

    #[test]
    fn rejects_invalid_expressions() {
        assert_eq!(PortRanges::parse(""), Err(PortRangesError::Empty));
        assert_eq!(PortRanges::parse("0"), Err(PortRangesError::InvalidPort));
        assert_eq!(
            PortRanges::parse("100-99"),
            Err(PortRangesError::DescendingRange)
        );
        assert_eq!(
            PortRanges::parse("80,,443"),
            Err(PortRangesError::EmptySegment)
        );
    }

    #[test]
    fn merges_runtime_reserved_ports() {
        let parsed = PortRanges::parse("20-22,80").unwrap();
        assert_eq!(
            parsed.including_ports([23, 81, 443]).expression(),
            "20-23,80-81,443"
        );
    }
}
