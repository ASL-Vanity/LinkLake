use linklake_core::public_ports::PortRanges;
use serde::Serialize;
use std::net::SocketAddr;

const DEFAULT_PUBLIC_PORTS: &str = "32000-32999";
const DEFAULT_RESERVED_TCP_PORTS: &str = "22";

#[derive(Debug, Clone)]
pub(crate) struct PublicPortPolicy {
    tcp_allowed: PortRanges,
    udp_allowed: PortRanges,
    tcp_reserved: PortRanges,
    udp_reserved: PortRanges,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct PublicPortPolicyView {
    pub(crate) tcp_allowed: String,
    pub(crate) udp_allowed: String,
    pub(crate) tcp_reserved: String,
    pub(crate) udp_reserved: String,
}

impl PublicPortPolicy {
    pub(crate) fn from_environment(
        tcp_listeners: impl IntoIterator<Item = SocketAddr>,
        udp_listeners: impl IntoIterator<Item = SocketAddr>,
    ) -> anyhow::Result<Self> {
        let common =
            environment_value(&["LINKLAKE_PUBLIC_PORT_RANGES", "LINKLAKE_PUBLIC_PORT_RANGE"])
                .unwrap_or_else(|| DEFAULT_PUBLIC_PORTS.to_owned());
        let tcp_allowed = PortRanges::parse(
            environment_value(&["LINKLAKE_TCP_PUBLIC_PORTS"])
                .as_deref()
                .unwrap_or(&common),
        )?;
        let udp_allowed = PortRanges::parse(
            environment_value(&["LINKLAKE_UDP_PUBLIC_PORTS"])
                .as_deref()
                .unwrap_or(&common),
        )?;
        let tcp_reserved = PortRanges::parse_optional(
            environment_value(&["LINKLAKE_RESERVED_TCP_PORTS"])
                .as_deref()
                .unwrap_or(DEFAULT_RESERVED_TCP_PORTS),
        )?
        .including_ports(tcp_listeners.into_iter().map(|address| address.port()));
        let udp_reserved = PortRanges::parse_optional(
            environment_value(&["LINKLAKE_RESERVED_UDP_PORTS"])
                .as_deref()
                .unwrap_or(""),
        )?
        .including_ports(udp_listeners.into_iter().map(|address| address.port()));

        anyhow::ensure!(
            has_available_port(&tcp_allowed, &tcp_reserved),
            "TCP public port policy has no available port"
        );
        anyhow::ensure!(
            has_available_port(&udp_allowed, &udp_reserved),
            "UDP public port policy has no available port"
        );
        Ok(Self {
            tcp_allowed,
            udp_allowed,
            tcp_reserved,
            udp_reserved,
        })
    }

    #[cfg(test)]
    pub(crate) fn development_default() -> Self {
        Self {
            tcp_allowed: PortRanges::parse(DEFAULT_PUBLIC_PORTS).unwrap(),
            udp_allowed: PortRanges::parse(DEFAULT_PUBLIC_PORTS).unwrap(),
            tcp_reserved: PortRanges::empty(),
            udp_reserved: PortRanges::empty(),
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        tcp_allowed: &str,
        udp_allowed: &str,
        tcp_reserved: &str,
        udp_reserved: &str,
    ) -> Self {
        Self {
            tcp_allowed: PortRanges::parse(tcp_allowed).unwrap(),
            udp_allowed: PortRanges::parse(udp_allowed).unwrap(),
            tcp_reserved: PortRanges::parse_optional(tcp_reserved).unwrap(),
            udp_reserved: PortRanges::parse_optional(udp_reserved).unwrap(),
        }
    }

    pub(crate) fn allows_tcp(&self, port: u16) -> bool {
        self.tcp_allowed.contains(port) && !self.tcp_reserved.contains(port)
    }

    pub(crate) fn allows_udp(&self, port: u16) -> bool {
        self.udp_allowed.contains(port) && !self.udp_reserved.contains(port)
    }

    pub(crate) fn view(&self) -> PublicPortPolicyView {
        PublicPortPolicyView {
            tcp_allowed: self.tcp_allowed.expression(),
            udp_allowed: self.udp_allowed.expression(),
            tcp_reserved: self.tcp_reserved.expression(),
            udp_reserved: self.udp_reserved.expression(),
        }
    }
}

fn environment_value(names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| {
        std::env::var(name)
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
    })
}

fn has_available_port(allowed: &PortRanges, reserved: &PortRanges) -> bool {
    allowed
        .ranges()
        .iter()
        .any(|range| (range.start..=range.end).any(|port| !reserved.contains(port)))
}

#[cfg(test)]
mod tests {
    use super::PublicPortPolicy;

    #[test]
    fn development_policy_keeps_previous_defaults() {
        let policy = PublicPortPolicy::development_default();
        assert!(policy.allows_tcp(32_000));
        assert!(policy.allows_udp(32_999));
        assert!(!policy.allows_tcp(31_999));
        assert!(!policy.allows_udp(33_000));
    }

    #[test]
    fn custom_policy_supports_disjoint_ranges_and_reservations() {
        let policy =
            PublicPortPolicy::for_test("80,443,10000-65535", "53,10000-65535", "443,32100", "53");
        assert!(policy.allows_tcp(80));
        assert!(!policy.allows_tcp(443));
        assert!(policy.allows_tcp(50_000));
        assert!(!policy.allows_udp(53));
        assert!(policy.allows_udp(10_000));
    }
}
