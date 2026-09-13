use crate::{
    ha_runtime::HaRuntime,
    public_port_ownership::{PublicPortLease, PublicPortProtocol},
};
use linklake_core::public_ports::PortRanges;
use serde::Serialize;
#[cfg(test)]
use std::{collections::HashSet, sync::Mutex};
use std::{
    error::Error,
    fmt,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc,
    },
    time::Duration,
};
use uuid::Uuid;

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

/// 动态端口租约由 HA 协调器提供，独立本地实现仅用于租约接口测试。
pub(crate) trait DynamicPortLease: Send + Sync {
    fn protocol(&self) -> DynamicPortProtocol;
    fn port(&self) -> u16;
    fn lease_id(&self) -> &str;
    fn renewal_interval(&self) -> Duration;
    fn renew<'a>(&'a self) -> DynamicPortLeaseOperationFuture<'a>;
    fn release(self: Box<Self>) -> DynamicPortLeaseReleaseFuture;
}

pub(crate) type DynamicPortLeaseAcquireFuture<'a> = Pin<
    Box<dyn Future<Output = Result<Box<dyn DynamicPortLease>, DynamicPortLeaseError>> + Send + 'a>,
>;
pub(crate) type DynamicPortLeaseOperationFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), DynamicPortLeaseError>> + Send + 'a>>;
pub(crate) type DynamicPortLeaseReleaseFuture =
    Pin<Box<dyn Future<Output = Result<(), DynamicPortLeaseError>> + Send + 'static>>;

pub(crate) trait DynamicPortLeaseProvider: Send + Sync {
    fn acquire_tcp<'a>(
        &'a self,
        policy: &'a PublicPortPolicy,
        policy_id: Uuid,
    ) -> DynamicPortLeaseAcquireFuture<'a>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DynamicPortLeaseError {
    Exhausted,
    Unavailable,
}

impl fmt::Display for DynamicPortLeaseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exhausted => formatter.write_str("no dynamic TCP public port is available"),
            Self::Unavailable => {
                formatter.write_str("dynamic TCP public port leasing is unavailable")
            }
        }
    }
}

impl Error for DynamicPortLeaseError {}

#[cfg(test)]
#[derive(Clone, Default)]
pub(crate) struct LocalDynamicPortLeaseProvider {
    state: Arc<Mutex<LocalDynamicPortLeaseState>>,
}

#[cfg(test)]
#[derive(Default)]
struct LocalDynamicPortLeaseState {
    tcp: HashSet<u16>,
    next_tcp: u16,
    next_lease_id: u64,
}

#[cfg(test)]
struct LocalDynamicPortLease {
    state: Arc<Mutex<LocalDynamicPortLeaseState>>,
    port: u16,
    lease_id: String,
    released: AtomicBool,
}

#[cfg(test)]
impl DynamicPortLease for LocalDynamicPortLease {
    fn protocol(&self) -> DynamicPortProtocol {
        DynamicPortProtocol::Tcp
    }

    fn port(&self) -> u16 {
        self.port
    }

    fn lease_id(&self) -> &str {
        &self.lease_id
    }

    fn renewal_interval(&self) -> Duration {
        Duration::from_secs(30)
    }

    fn renew<'a>(&'a self) -> DynamicPortLeaseOperationFuture<'a> {
        Box::pin(async { Ok(()) })
    }

    fn release(self: Box<Self>) -> DynamicPortLeaseReleaseFuture {
        if self.released.swap(true, Ordering::AcqRel) {
            return Box::pin(async { Ok(()) });
        }
        self.state
            .lock()
            .expect("dynamic port lease lock poisoned")
            .tcp
            .remove(&self.port);
        Box::pin(async { Ok(()) })
    }
}

#[cfg(test)]
impl Drop for LocalDynamicPortLease {
    fn drop(&mut self) {
        if self.released.swap(true, Ordering::AcqRel) {
            return;
        }
        self.state
            .lock()
            .expect("dynamic port lease lock poisoned")
            .tcp
            .remove(&self.port);
    }
}

#[cfg(test)]
impl DynamicPortLeaseProvider for LocalDynamicPortLeaseProvider {
    fn acquire_tcp<'a>(
        &'a self,
        policy: &'a PublicPortPolicy,
        _policy_id: Uuid,
    ) -> DynamicPortLeaseAcquireFuture<'a> {
        let state = self.state.clone();
        Box::pin(async move {
            let mut locked = state.lock().expect("dynamic port lease lock poisoned");
            let cursor = locked.next_tcp.max(1) as u32;
            let port = (0..u16::MAX as u32)
                .map(|offset| ((cursor - 1 + offset) % u16::MAX as u32 + 1) as u16)
                .find(|port| policy.allows_tcp(*port) && !locked.tcp.contains(port))
                .ok_or(DynamicPortLeaseError::Exhausted)?;
            locked.tcp.insert(port);
            locked.next_tcp = port.wrapping_add(1).max(1);
            locked.next_lease_id = locked.next_lease_id.wrapping_add(1).max(1);
            let lease_id = format!("local-tcp-{}", locked.next_lease_id);
            drop(locked);
            Ok(Box::new(LocalDynamicPortLease {
                state,
                port,
                lease_id,
                released: AtomicBool::new(false),
            }) as Box<dyn DynamicPortLease>)
        })
    }
}

#[derive(Clone)]
pub(crate) struct HaDynamicPortLeaseProvider {
    runtime: Arc<HaRuntime>,
    next_tcp: Arc<AtomicU32>,
}

impl HaDynamicPortLeaseProvider {
    pub(crate) fn new(runtime: Arc<HaRuntime>) -> Self {
        Self {
            runtime,
            next_tcp: Arc::new(AtomicU32::new(1)),
        }
    }
}

struct HaDynamicPortLease {
    runtime: Arc<HaRuntime>,
    ownership: crate::public_port_ownership::PublicPortOwnership,
    lease: PublicPortLease,
    renewal_interval: Duration,
    lease_id: String,
    released: AtomicBool,
}

impl DynamicPortLease for HaDynamicPortLease {
    fn protocol(&self) -> DynamicPortProtocol {
        DynamicPortProtocol::Tcp
    }

    fn port(&self) -> u16 {
        self.lease.public_port
    }

    fn lease_id(&self) -> &str {
        &self.lease_id
    }

    fn renewal_interval(&self) -> Duration {
        self.renewal_interval
    }

    fn renew<'a>(&'a self) -> DynamicPortLeaseOperationFuture<'a> {
        Box::pin(async move {
            if self.released.load(Ordering::Acquire) {
                return Err(DynamicPortLeaseError::Unavailable);
            }
            if self.runtime.fencing_token().ok() != Some(self.lease.fencing_token) {
                return Err(DynamicPortLeaseError::Unavailable);
            }
            self.ownership
                .renew(
                    self.lease.protocol,
                    self.lease.public_port,
                    self.lease.policy_id,
                    self.lease.lease_id,
                    self.lease.fencing_token,
                )
                .await
                .map_err(|_| DynamicPortLeaseError::Unavailable)?
                .ok_or(DynamicPortLeaseError::Unavailable)
                .map(|_| ())
        })
    }

    fn release(self: Box<Self>) -> DynamicPortLeaseReleaseFuture {
        if self.released.swap(true, Ordering::AcqRel) {
            return Box::pin(async { Ok(()) });
        }
        let ownership = self.ownership.clone();
        let lease = self.lease.clone();
        Box::pin(async move {
            ownership
                .release(
                    lease.protocol,
                    lease.public_port,
                    lease.policy_id,
                    lease.lease_id,
                    lease.fencing_token,
                )
                .await
                .map(|_| ())
                .map_err(|_| DynamicPortLeaseError::Unavailable)
        })
    }
}

impl DynamicPortLeaseProvider for HaDynamicPortLeaseProvider {
    fn acquire_tcp<'a>(
        &'a self,
        policy: &'a PublicPortPolicy,
        policy_id: Uuid,
    ) -> DynamicPortLeaseAcquireFuture<'a> {
        Box::pin(async move {
            let fencing_token = self
                .runtime
                .fencing_token()
                .map_err(|_| DynamicPortLeaseError::Unavailable)?;
            let cursor = self.next_tcp.fetch_add(1, Ordering::Relaxed).max(1);
            for offset in 0..u16::MAX as u32 {
                let port = ((cursor - 1 + offset) % u16::MAX as u32 + 1) as u16;
                if !policy.allows_tcp(port) {
                    continue;
                }
                let lease = self
                    .runtime
                    .public_ports()
                    .acquire(PublicPortProtocol::Tcp, port, policy_id, fencing_token)
                    .await
                    .map_err(|_| DynamicPortLeaseError::Unavailable)?;
                let Some(lease) = lease else {
                    continue;
                };
                self.next_tcp
                    .store(u32::from(port.wrapping_add(1).max(1)), Ordering::Relaxed);
                return Ok(Box::new(HaDynamicPortLease {
                    runtime: self.runtime.clone(),
                    ownership: self.runtime.public_ports().clone(),
                    renewal_interval: self.runtime.heartbeat(),
                    lease_id: lease.lease_id.to_string(),
                    lease,
                    released: AtomicBool::new(false),
                }) as Box<dyn DynamicPortLease>);
            }
            Err(DynamicPortLeaseError::Exhausted)
        })
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
    use uuid::Uuid;

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

    #[tokio::test]
    async fn local_dynamic_leases_are_unique_rotating_and_released_on_drop() {
        let policy = PublicPortPolicy::for_test("32000-32001", "32000", "", "");
        let provider = LocalDynamicPortLeaseProvider::default();
        let policy_id = Uuid::new_v4();
        let first = provider.acquire_tcp(&policy, policy_id).await.unwrap();
        let second = provider.acquire_tcp(&policy, policy_id).await.unwrap();
        assert_ne!(first.port(), second.port());
        assert!(provider.acquire_tcp(&policy, policy_id).await.is_err());
        let released = first.port();
        drop(first);
        assert_eq!(
            provider
                .acquire_tcp(&policy, policy_id)
                .await
                .unwrap()
                .port(),
            released
        );
    }
}
