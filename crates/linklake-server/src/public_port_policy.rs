use linklake_core::public_ports::PortRanges;
use serde::Serialize;
use std::{
    collections::HashSet,
    error::Error,
    fmt,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DynamicPortProtocol {
    Tcp,
}

/// 动态端口租约接口不假定存储位置；当前本地实现由单进程持有，HA 线可替换为分布式租约。
pub(crate) trait DynamicPortLease: Send + Sync {
    fn protocol(&self) -> DynamicPortProtocol;
    fn port(&self) -> u16;
}

pub(crate) trait DynamicPortLeaseProvider: Send + Sync {
    fn acquire_tcp(
        &self,
        policy: &PublicPortPolicy,
    ) -> Result<Box<dyn DynamicPortLease>, DynamicPortLeaseError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DynamicPortLeaseError {
    Exhausted,
}

impl fmt::Display for DynamicPortLeaseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("no dynamic TCP public port is available")
    }
}

impl Error for DynamicPortLeaseError {}

#[derive(Clone, Default)]
pub(crate) struct LocalDynamicPortLeaseProvider {
    state: Arc<Mutex<LocalDynamicPortLeaseState>>,
}

#[derive(Default)]
struct LocalDynamicPortLeaseState {
    tcp: HashSet<u16>,
    next_tcp: u16,
}

struct LocalDynamicPortLease {
    state: Arc<Mutex<LocalDynamicPortLeaseState>>,
    port: u16,
}

impl DynamicPortLease for LocalDynamicPortLease {
    fn protocol(&self) -> DynamicPortProtocol {
        DynamicPortProtocol::Tcp
    }

    fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for LocalDynamicPortLease {
    fn drop(&mut self) {
        self.state
            .lock()
            .expect("dynamic port lease lock poisoned")
            .tcp
            .remove(&self.port);
    }
}

impl DynamicPortLeaseProvider for LocalDynamicPortLeaseProvider {
    fn acquire_tcp(
        &self,
        policy: &PublicPortPolicy,
    ) -> Result<Box<dyn DynamicPortLease>, DynamicPortLeaseError> {
        let mut state = self.state.lock().expect("dynamic port lease lock poisoned");
        let cursor = state.next_tcp.max(1) as u32;
        let port = (0..u16::MAX as u32)
            .map(|offset| ((cursor - 1 + offset) % u16::MAX as u32 + 1) as u16)
            .find(|port| policy.allows_tcp(*port) && !state.tcp.contains(port))
            .ok_or(DynamicPortLeaseError::Exhausted)?;
        state.tcp.insert(port);
        state.next_tcp = port.wrapping_add(1).max(1);
        Ok(Box::new(LocalDynamicPortLease {
            state: self.state.clone(),
            port,
        }))
    }
}

impl PublicPortPolicy {
    pub(crate) fn schema_migration() -> Self {
        Self {
            tcp_allowed: PortRanges::parse("1-65535").expect("full TCP port range is valid"),
            udp_allowed: PortRanges::parse("1-65535").expect("full UDP port range is valid"),
            tcp_reserved: PortRanges::empty(),
            udp_reserved: PortRanges::empty(),
        }
    }

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
    use super::{DynamicPortLeaseProvider, LocalDynamicPortLeaseProvider, PublicPortPolicy};

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

    #[test]
    fn local_dynamic_leases_are_unique_rotating_and_released_on_drop() {
        let policy = PublicPortPolicy::for_test("32000-32001", "32000", "", "");
        let provider = LocalDynamicPortLeaseProvider::default();
        let first = provider.acquire_tcp(&policy).unwrap();
        let second = provider.acquire_tcp(&policy).unwrap();
        assert_ne!(first.port(), second.port());
        assert!(provider.acquire_tcp(&policy).is_err());
        let released = first.port();
        drop(first);
        assert_eq!(provider.acquire_tcp(&policy).unwrap().port(), released);
    }
}
