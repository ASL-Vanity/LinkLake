//! Fleet Bundle v2 的纯协议模型、规范化摘要与结构校验。

use crate::{
    port_mapping::{parse_port_mappings, MAX_PORT_MAPPINGS},
    target_pool::parse_target_pool,
};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
use thiserror::Error;
use uuid::Uuid;

pub const FLEET_BUNDLE_SCHEMA_VERSION: u16 = 2;

const MAX_CLIENTS: usize = 4_096;
const MAX_RESOURCES: usize = 65_535;
const MAX_NAME_BYTES: usize = 80;
const MAX_PORT_GROUP_NAME_BYTES: usize = 64;
const MAX_TARGET_POOL_BYTES: usize = 4_096;
const MIN_BANDWIDTH_LIMIT_BPS: u64 = 1_024;
const MAX_BANDWIDTH_LIMIT_BPS: u64 = 1_000_000_000;
const MAX_CONNECTIONS: u16 = 1_024;
const MAX_UDP_SESSIONS: u16 = 4_096;
const MIN_UDP_IDLE_TIMEOUT_SECONDS: u32 = 30;
const MAX_UDP_IDLE_TIMEOUT_SECONDS: u32 = 3_600;

/// Fleet 中的稳定客户端引用。该 ID 与单台服务端签发的 client_id、token 无关。
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FleetClientRef {
    pub agent_instance_id: Uuid,
    pub name: String,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FleetPortGroupProtocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FleetTcpResource {
    pub agent_instance_id: Uuid,
    pub name: String,
    pub public_port: u16,
    pub target_addr: String,
    pub max_connections: u16,
    pub bandwidth_limit_bps: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FleetUdpResource {
    pub agent_instance_id: Uuid,
    pub name: String,
    pub public_port: u16,
    pub target_addr: String,
    pub max_sessions: u16,
    pub session_idle_timeout_seconds: u32,
    pub bandwidth_limit_bps: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FleetPortGroupResource {
    pub agent_instance_id: Uuid,
    pub name: String,
    pub protocol: FleetPortGroupProtocol,
    pub public_ports: String,
    pub target_host: String,
    pub target_ports: String,
    pub max_connections: u16,
    pub max_sessions: u16,
    pub session_idle_timeout_seconds: u32,
    pub bandwidth_limit_bps: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FleetHttpRouteResource {
    pub agent_instance_id: Uuid,
    pub name: String,
    pub hostname: String,
    pub target_addr: String,
    pub max_connections: u16,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FleetSniRouteResource {
    pub agent_instance_id: Uuid,
    pub name: String,
    pub hostname: String,
    pub target_addr: String,
    pub max_connections: u16,
    pub bandwidth_limit_bps: Option<u64>,
}

/// credential_ref 仅是外部凭据记录的稳定标识，不携带访问密钥或哈希。
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FleetSecretTunnelResource {
    pub provider_agent_instance_id: Uuid,
    pub allowed_agent_instance_id: Option<Uuid>,
    pub credential_ref: Uuid,
    pub name: String,
    pub target_addr: String,
    pub max_connections: u16,
    pub bandwidth_limit_bps: Option<u64>,
}

/// credential_ref 仅是外部凭据记录的稳定标识，不携带密码或哈希。
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FleetSocks5ProxyResource {
    pub agent_instance_id: Uuid,
    pub credential_ref: Uuid,
    pub name: String,
    pub public_port: u16,
    pub username: String,
    pub max_connections: u16,
    pub bandwidth_limit_bps: Option<u64>,
}

/// credential_ref 仅是外部凭据记录的稳定标识，不携带密码或哈希。
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FleetHttpProxyResource {
    pub agent_instance_id: Uuid,
    pub credential_ref: Uuid,
    pub name: String,
    pub public_port: u16,
    pub username: String,
    pub max_connections: u16,
    pub bandwidth_limit_bps: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(
    deny_unknown_fields,
    tag = "kind",
    content = "settings",
    rename_all = "snake_case"
)]
pub enum FleetResourceSpec {
    Tcp(FleetTcpResource),
    Udp(FleetUdpResource),
    PortGroup(FleetPortGroupResource),
    HttpRoute(FleetHttpRouteResource),
    SniRoute(FleetSniRouteResource),
    SecretTunnel(FleetSecretTunnelResource),
    Socks5Proxy(FleetSocks5ProxyResource),
    HttpProxy(FleetHttpProxyResource),
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FleetResource {
    pub resource_id: Uuid,
    pub enabled: bool,
    pub spec: FleetResourceSpec,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FleetTrafficControl {
    pub resource_id: Uuid,
    pub enabled: bool,
    #[serde(default)]
    pub allowed_cidrs: Vec<String>,
    #[serde(default)]
    pub denied_cidrs: Vec<String>,
    pub max_connections_per_minute: Option<u32>,
    pub daily_quota_bytes: Option<u64>,
    #[serde(default)]
    pub active_weekdays_utc: Vec<u8>,
    pub start_minute_utc: Option<u16>,
    pub end_minute_utc: Option<u16>,
}

/// Fleet Bundle v2。反序列化时会执行完整校验和摘要验证。
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FleetBundleV2 {
    pub schema_version: u16,
    pub source_instance_id: Uuid,
    pub generation: u64,
    pub generated_unix_seconds: u64,
    pub clients: Vec<FleetClientRef>,
    pub resources: Vec<FleetResource>,
    pub traffic_controls: Vec<FleetTrafficControl>,
    /// 不带前缀的 64 位小写十六进制 SHA-256。
    pub content_sha256: String,
    /// 与 content_sha256 对应的稳定修订号，格式为 sha256:<digest>。
    pub revision: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FleetBundleWire {
    schema_version: u16,
    source_instance_id: Uuid,
    generation: u64,
    generated_unix_seconds: u64,
    clients: Vec<FleetClientRef>,
    resources: Vec<FleetResource>,
    traffic_controls: Vec<FleetTrafficControl>,
    content_sha256: String,
    revision: String,
}

impl<'de> Deserialize<'de> for FleetBundleV2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = FleetBundleWire::deserialize(deserializer)?;
        let bundle = Self {
            schema_version: wire.schema_version,
            source_instance_id: wire.source_instance_id,
            generation: wire.generation,
            generated_unix_seconds: wire.generated_unix_seconds,
            clients: wire.clients,
            resources: wire.resources,
            traffic_controls: wire.traffic_controls,
            content_sha256: wire.content_sha256,
            revision: wire.revision,
        };
        bundle.validate().map_err(D::Error::custom)?;
        Ok(bundle)
    }
}

#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum FleetBundleError {
    #[error("unsupported Fleet bundle schema version {0}")]
    UnsupportedSchemaVersion(u16),
    #[error("invalid Fleet bundle field: {0}")]
    InvalidField(&'static str),
    #[error("duplicate Fleet client reference {0}")]
    DuplicateClient(Uuid),
    #[error("duplicate Fleet resource ID {0}")]
    DuplicateResource(Uuid),
    #[error("duplicate Fleet traffic control for resource {0}")]
    DuplicateTrafficControl(Uuid),
    #[error("Fleet resource references unknown client {0}")]
    UnknownClient(Uuid),
    #[error("Fleet traffic control references unknown resource {0}")]
    UnknownResource(Uuid),
    #[error("Fleet bundle content SHA-256 is invalid")]
    InvalidContentSha256,
    #[error("Fleet bundle content SHA-256 does not match its canonical content")]
    ContentSha256Mismatch,
    #[error("Fleet bundle revision does not match its canonical content")]
    RevisionMismatch,
    #[error("could not serialize canonical Fleet bundle content: {0}")]
    CanonicalSerialization(String),
}

#[derive(Serialize)]
struct CanonicalFleetContent {
    schema_version: u16,
    source_instance_id: Uuid,
    generation: u64,
    generated_unix_seconds: u64,
    clients: Vec<FleetClientRef>,
    resources: Vec<FleetResource>,
    traffic_controls: Vec<FleetTrafficControl>,
}

impl FleetBundleV2 {
    pub fn new(
        source_instance_id: Uuid,
        generation: u64,
        generated_unix_seconds: u64,
        clients: Vec<FleetClientRef>,
        resources: Vec<FleetResource>,
        traffic_controls: Vec<FleetTrafficControl>,
    ) -> Result<Self, FleetBundleError> {
        let mut bundle = Self {
            schema_version: FLEET_BUNDLE_SCHEMA_VERSION,
            source_instance_id,
            generation,
            generated_unix_seconds,
            clients,
            resources,
            traffic_controls,
            content_sha256: String::new(),
            revision: String::new(),
        };
        bundle.validate_structure()?;
        bundle.refresh_integrity()?;
        bundle.validate()?;
        Ok(bundle)
    }

    /// 在调用方修改公开字段后重新计算摘要与修订号。
    pub fn refresh_integrity(&mut self) -> Result<(), FleetBundleError> {
        self.validate_structure()?;
        let digest = self.calculate_content_sha256()?;
        self.content_sha256.clone_from(&digest);
        self.revision = format!("sha256:{digest}");
        Ok(())
    }

    pub fn validate(&self) -> Result<(), FleetBundleError> {
        self.validate_structure()?;
        if !valid_sha256(&self.content_sha256) {
            return Err(FleetBundleError::InvalidContentSha256);
        }
        let expected = self.calculate_content_sha256()?;
        if self.content_sha256 != expected {
            return Err(FleetBundleError::ContentSha256Mismatch);
        }
        if self.revision != format!("sha256:{expected}") {
            return Err(FleetBundleError::RevisionMismatch);
        }
        Ok(())
    }

    pub fn calculate_content_sha256(&self) -> Result<String, FleetBundleError> {
        let content = self.canonical_content();
        let encoded = serde_json::to_vec(&content)
            .map_err(|error| FleetBundleError::CanonicalSerialization(error.to_string()))?;
        Ok(format!("{:x}", Sha256::digest(encoded)))
    }

    /// 返回字段顺序、集合顺序和流量控制集合均稳定的完整 JSON。
    pub fn to_canonical_json(&self) -> Result<Vec<u8>, FleetBundleError> {
        self.validate()?;
        let content = self.canonical_content();
        let canonical = FleetBundleV2 {
            schema_version: content.schema_version,
            source_instance_id: content.source_instance_id,
            generation: content.generation,
            generated_unix_seconds: content.generated_unix_seconds,
            clients: content.clients,
            resources: content.resources,
            traffic_controls: content.traffic_controls,
            content_sha256: self.content_sha256.clone(),
            revision: self.revision.clone(),
        };
        serde_json::to_vec(&canonical)
            .map_err(|error| FleetBundleError::CanonicalSerialization(error.to_string()))
    }

    fn canonical_content(&self) -> CanonicalFleetContent {
        let mut clients = self.clients.clone();
        clients.sort_by_key(|client| client.agent_instance_id);

        let mut resources = self.resources.clone();
        resources.sort_by_key(|resource| resource.resource_id);

        let mut traffic_controls = self.traffic_controls.clone();
        for control in &mut traffic_controls {
            control.allowed_cidrs = normalized_cidrs(&control.allowed_cidrs)
                .expect("validated CIDR values must normalize");
            control.denied_cidrs = normalized_cidrs(&control.denied_cidrs)
                .expect("validated CIDR values must normalize");
            control.allowed_cidrs.sort();
            control.denied_cidrs.sort();
            control.active_weekdays_utc.sort_unstable();
        }
        traffic_controls.sort_by_key(|control| control.resource_id);

        CanonicalFleetContent {
            schema_version: self.schema_version,
            source_instance_id: self.source_instance_id,
            generation: self.generation,
            generated_unix_seconds: self.generated_unix_seconds,
            clients,
            resources,
            traffic_controls,
        }
    }

    fn validate_structure(&self) -> Result<(), FleetBundleError> {
        if self.schema_version != FLEET_BUNDLE_SCHEMA_VERSION {
            return Err(FleetBundleError::UnsupportedSchemaVersion(
                self.schema_version,
            ));
        }
        if self.source_instance_id.is_nil() {
            return Err(FleetBundleError::InvalidField("source_instance_id"));
        }
        if self.generation == 0 {
            return Err(FleetBundleError::InvalidField("generation"));
        }
        if self.generated_unix_seconds == 0 {
            return Err(FleetBundleError::InvalidField("generated_unix_seconds"));
        }
        if self.clients.len() > MAX_CLIENTS {
            return Err(FleetBundleError::InvalidField("clients"));
        }
        if self.resources.len() > MAX_RESOURCES || self.traffic_controls.len() > MAX_RESOURCES {
            return Err(FleetBundleError::InvalidField("resources"));
        }

        let mut clients = HashSet::with_capacity(self.clients.len());
        for client in &self.clients {
            if client.agent_instance_id.is_nil() {
                return Err(FleetBundleError::InvalidField("clients.agent_instance_id"));
            }
            if !valid_name(&client.name, MAX_NAME_BYTES) {
                return Err(FleetBundleError::InvalidField("clients.name"));
            }
            if !clients.insert(client.agent_instance_id) {
                return Err(FleetBundleError::DuplicateClient(client.agent_instance_id));
            }
        }

        let mut resources = HashSet::with_capacity(self.resources.len());
        for resource in &self.resources {
            if resource.resource_id.is_nil() {
                return Err(FleetBundleError::InvalidField("resources.resource_id"));
            }
            if !resources.insert(resource.resource_id) {
                return Err(FleetBundleError::DuplicateResource(resource.resource_id));
            }
            resource.spec.validate()?;
            for client_id in resource.spec.referenced_clients() {
                if !clients.contains(&client_id) {
                    return Err(FleetBundleError::UnknownClient(client_id));
                }
            }
        }

        let mut controls = HashSet::with_capacity(self.traffic_controls.len());
        for control in &self.traffic_controls {
            if control.resource_id.is_nil() {
                return Err(FleetBundleError::InvalidField(
                    "traffic_controls.resource_id",
                ));
            }
            if !resources.contains(&control.resource_id) {
                return Err(FleetBundleError::UnknownResource(control.resource_id));
            }
            if !controls.insert(control.resource_id) {
                return Err(FleetBundleError::DuplicateTrafficControl(
                    control.resource_id,
                ));
            }
            control.validate()?;
        }
        Ok(())
    }
}

impl FleetResourceSpec {
    fn referenced_clients(&self) -> Vec<Uuid> {
        match self {
            Self::Tcp(resource) => vec![resource.agent_instance_id],
            Self::Udp(resource) => vec![resource.agent_instance_id],
            Self::PortGroup(resource) => vec![resource.agent_instance_id],
            Self::HttpRoute(resource) => vec![resource.agent_instance_id],
            Self::SniRoute(resource) => vec![resource.agent_instance_id],
            Self::SecretTunnel(resource) => {
                let mut clients = vec![resource.provider_agent_instance_id];
                clients.extend(resource.allowed_agent_instance_id);
                clients
            }
            Self::Socks5Proxy(resource) => vec![resource.agent_instance_id],
            Self::HttpProxy(resource) => vec![resource.agent_instance_id],
        }
    }

    fn validate(&self) -> Result<(), FleetBundleError> {
        match self {
            Self::Tcp(resource) => {
                validate_agent_id(resource.agent_instance_id)?;
                validate_policy_name(&resource.name, MAX_NAME_BYTES)?;
                validate_port(resource.public_port)?;
                validate_target_pool(&resource.target_addr)?;
                validate_connections(resource.max_connections)?;
                validate_bandwidth(resource.bandwidth_limit_bps)
            }
            Self::Udp(resource) => {
                validate_agent_id(resource.agent_instance_id)?;
                validate_policy_name(&resource.name, MAX_NAME_BYTES)?;
                validate_port(resource.public_port)?;
                validate_target_pool(&resource.target_addr)?;
                validate_sessions(resource.max_sessions)?;
                validate_idle_timeout(resource.session_idle_timeout_seconds)?;
                validate_bandwidth(resource.bandwidth_limit_bps)
            }
            Self::PortGroup(resource) => {
                validate_agent_id(resource.agent_instance_id)?;
                validate_policy_name(&resource.name, MAX_PORT_GROUP_NAME_BYTES)?;
                validate_target_host(&resource.target_host)?;
                let mappings = parse_port_mappings(
                    &resource.public_ports,
                    &resource.target_ports,
                    1,
                    u16::MAX,
                    MAX_PORT_MAPPINGS,
                )
                .map_err(|_| FleetBundleError::InvalidField("resources.port_group.ports"))?;
                if mappings.public_ports != resource.public_ports
                    || mappings.target_ports != resource.target_ports
                {
                    return Err(FleetBundleError::InvalidField("resources.port_group.ports"));
                }
                validate_connections(resource.max_connections)?;
                validate_sessions(resource.max_sessions)?;
                validate_idle_timeout(resource.session_idle_timeout_seconds)?;
                validate_bandwidth(resource.bandwidth_limit_bps)
            }
            Self::HttpRoute(resource) => {
                validate_agent_id(resource.agent_instance_id)?;
                validate_policy_name(&resource.name, MAX_NAME_BYTES)?;
                validate_hostname(&resource.hostname)?;
                validate_target_pool(&resource.target_addr)?;
                validate_connections(resource.max_connections)
            }
            Self::SniRoute(resource) => {
                validate_agent_id(resource.agent_instance_id)?;
                validate_policy_name(&resource.name, MAX_NAME_BYTES)?;
                validate_hostname(&resource.hostname)?;
                validate_target_pool(&resource.target_addr)?;
                validate_connections(resource.max_connections)?;
                validate_bandwidth(resource.bandwidth_limit_bps)
            }
            Self::SecretTunnel(resource) => {
                validate_agent_id(resource.provider_agent_instance_id)?;
                if let Some(client_id) = resource.allowed_agent_instance_id {
                    validate_agent_id(client_id)?;
                }
                validate_credential_ref(resource.credential_ref)?;
                validate_policy_name(&resource.name, MAX_NAME_BYTES)?;
                validate_target_pool(&resource.target_addr)?;
                validate_connections(resource.max_connections)?;
                validate_bandwidth(resource.bandwidth_limit_bps)
            }
            Self::Socks5Proxy(resource) => {
                validate_agent_id(resource.agent_instance_id)?;
                validate_credential_ref(resource.credential_ref)?;
                validate_policy_name(&resource.name, MAX_NAME_BYTES)?;
                validate_port(resource.public_port)?;
                validate_username(&resource.username)?;
                validate_connections(resource.max_connections)?;
                validate_bandwidth(resource.bandwidth_limit_bps)
            }
            Self::HttpProxy(resource) => {
                validate_agent_id(resource.agent_instance_id)?;
                validate_credential_ref(resource.credential_ref)?;
                validate_policy_name(&resource.name, MAX_NAME_BYTES)?;
                validate_port(resource.public_port)?;
                validate_username(&resource.username)?;
                validate_connections(resource.max_connections)?;
                validate_bandwidth(resource.bandwidth_limit_bps)
            }
        }
    }
}

impl FleetTrafficControl {
    fn validate(&self) -> Result<(), FleetBundleError> {
        if self.allowed_cidrs.len() > 64 || self.denied_cidrs.len() > 64 {
            return Err(FleetBundleError::InvalidField("traffic_controls.cidrs"));
        }
        let allowed = normalized_cidrs(&self.allowed_cidrs).ok_or(
            FleetBundleError::InvalidField("traffic_controls.allowed_cidrs"),
        )?;
        let denied = normalized_cidrs(&self.denied_cidrs).ok_or(FleetBundleError::InvalidField(
            "traffic_controls.denied_cidrs",
        ))?;
        if has_duplicates(&allowed)
            || has_duplicates(&denied)
            || allowed.iter().any(|cidr| denied.contains(cidr))
        {
            return Err(FleetBundleError::InvalidField("traffic_controls.cidrs"));
        }
        if self
            .max_connections_per_minute
            .is_some_and(|value| !(1..=1_000_000).contains(&value))
        {
            return Err(FleetBundleError::InvalidField(
                "traffic_controls.max_connections_per_minute",
            ));
        }
        if self.daily_quota_bytes.is_some_and(|value| value < 1_024) {
            return Err(FleetBundleError::InvalidField(
                "traffic_controls.daily_quota_bytes",
            ));
        }
        if self.active_weekdays_utc.iter().any(|weekday| *weekday > 6)
            || has_duplicates(&self.active_weekdays_utc)
        {
            return Err(FleetBundleError::InvalidField(
                "traffic_controls.active_weekdays_utc",
            ));
        }
        if self.start_minute_utc.is_some() != self.end_minute_utc.is_some()
            || self.start_minute_utc.is_some_and(|value| value >= 1_440)
            || self.end_minute_utc.is_some_and(|value| value >= 1_440)
        {
            return Err(FleetBundleError::InvalidField("traffic_controls.schedule"));
        }
        Ok(())
    }
}

fn validate_agent_id(value: Uuid) -> Result<(), FleetBundleError> {
    if value.is_nil() {
        Err(FleetBundleError::InvalidField(
            "resources.agent_instance_id",
        ))
    } else {
        Ok(())
    }
}

fn validate_credential_ref(value: Uuid) -> Result<(), FleetBundleError> {
    if value.is_nil() {
        Err(FleetBundleError::InvalidField("resources.credential_ref"))
    } else {
        Ok(())
    }
}

fn validate_policy_name(value: &str, maximum: usize) -> Result<(), FleetBundleError> {
    if valid_name(value, maximum) {
        Ok(())
    } else {
        Err(FleetBundleError::InvalidField("resources.name"))
    }
}

fn valid_name(value: &str, maximum: usize) -> bool {
    value == value.trim()
        && !value.is_empty()
        && value.len() <= maximum
        && !value.chars().any(char::is_control)
}

fn validate_port(value: u16) -> Result<(), FleetBundleError> {
    if value == 0 {
        Err(FleetBundleError::InvalidField("resources.public_port"))
    } else {
        Ok(())
    }
}

fn validate_connections(value: u16) -> Result<(), FleetBundleError> {
    if (1..=MAX_CONNECTIONS).contains(&value) {
        Ok(())
    } else {
        Err(FleetBundleError::InvalidField("resources.max_connections"))
    }
}

fn validate_sessions(value: u16) -> Result<(), FleetBundleError> {
    if (1..=MAX_UDP_SESSIONS).contains(&value) {
        Ok(())
    } else {
        Err(FleetBundleError::InvalidField("resources.max_sessions"))
    }
}

fn validate_idle_timeout(value: u32) -> Result<(), FleetBundleError> {
    if (MIN_UDP_IDLE_TIMEOUT_SECONDS..=MAX_UDP_IDLE_TIMEOUT_SECONDS).contains(&value) {
        Ok(())
    } else {
        Err(FleetBundleError::InvalidField(
            "resources.session_idle_timeout_seconds",
        ))
    }
}

fn validate_bandwidth(value: Option<u64>) -> Result<(), FleetBundleError> {
    if value
        .is_some_and(|limit| !(MIN_BANDWIDTH_LIMIT_BPS..=MAX_BANDWIDTH_LIMIT_BPS).contains(&limit))
    {
        Err(FleetBundleError::InvalidField(
            "resources.bandwidth_limit_bps",
        ))
    } else {
        Ok(())
    }
}

fn validate_username(value: &str) -> Result<(), FleetBundleError> {
    if value == value.trim()
        && !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        Ok(())
    } else {
        Err(FleetBundleError::InvalidField("resources.username"))
    }
}

fn validate_target_pool(value: &str) -> Result<(), FleetBundleError> {
    if value.len() > MAX_TARGET_POOL_BYTES {
        return Err(FleetBundleError::InvalidField("resources.target_addr"));
    }
    let targets = parse_target_pool(value)
        .map_err(|_| FleetBundleError::InvalidField("resources.target_addr"))?;
    let canonical = targets
        .into_iter()
        .map(|target| {
            if target.weight == 1 {
                target.address
            } else {
                format!("{}@{}", target.address, target.weight)
            }
        })
        .collect::<Vec<_>>()
        .join(",");
    if canonical == value {
        Ok(())
    } else {
        Err(FleetBundleError::InvalidField("resources.target_addr"))
    }
}

fn validate_hostname(value: &str) -> Result<(), FleetBundleError> {
    if value.is_empty()
        || value.len() > 253
        || value != value.to_ascii_lowercase()
        || !value.contains('.')
        || value.parse::<IpAddr>().is_ok()
        || value.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        Err(FleetBundleError::InvalidField("resources.hostname"))
    } else {
        Ok(())
    }
}

fn validate_target_host(value: &str) -> Result<(), FleetBundleError> {
    if value.is_empty()
        || value.len() > 253
        || value != value.trim()
        || value.bytes().any(|byte| byte.is_ascii_whitespace())
        || value.contains(['/', '[', ']'])
    {
        return Err(FleetBundleError::InvalidField(
            "resources.port_group.target_host",
        ));
    }
    if let Ok(address) = value.parse::<IpAddr>() {
        if address.to_string() == value {
            return Ok(());
        }
        return Err(FleetBundleError::InvalidField(
            "resources.port_group.target_host",
        ));
    }
    if value.contains(':')
        || value != value.to_ascii_lowercase()
        || value.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        Err(FleetBundleError::InvalidField(
            "resources.port_group.target_host",
        ))
    } else {
        Ok(())
    }
}

fn normalized_cidrs(values: &[String]) -> Option<Vec<String>> {
    values.iter().map(|value| normalize_cidr(value)).collect()
}

fn normalize_cidr(value: &str) -> Option<String> {
    if value != value.trim() || value.is_empty() {
        return None;
    }
    let (address, prefix) = match value.split_once('/') {
        Some((address, prefix)) => (address.parse::<IpAddr>().ok()?, prefix.parse::<u8>().ok()?),
        None => {
            let address = value.parse::<IpAddr>().ok()?;
            let prefix = if address.is_ipv4() { 32 } else { 128 };
            (address, prefix)
        }
    };
    match address {
        IpAddr::V4(address) if prefix <= 32 => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            let network = Ipv4Addr::from(u32::from(address) & mask);
            Some(format!("{network}/{prefix}"))
        }
        IpAddr::V6(address) if prefix <= 128 => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            let network = Ipv6Addr::from(u128::from(address) & mask);
            Some(format!("{network}/{prefix}"))
        }
        _ => None,
    }
}

fn has_duplicates<T>(values: &[T]) -> bool
where
    T: Clone + Eq + std::hash::Hash,
{
    let mut seen = HashSet::with_capacity(values.len());
    values.iter().any(|value| !seen.insert(value.clone()))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn ids() -> (Uuid, Uuid, Uuid) {
        (
            Uuid::parse_str("10000000-0000-4000-8000-000000000001").unwrap(),
            Uuid::parse_str("10000000-0000-4000-8000-000000000002").unwrap(),
            Uuid::parse_str("10000000-0000-4000-8000-000000000003").unwrap(),
        )
    }

    fn resource_id(index: u8) -> Uuid {
        Uuid::parse_str(&format!("20000000-0000-4000-8000-{index:012}")).unwrap()
    }

    fn credential_id(index: u8) -> Uuid {
        Uuid::parse_str(&format!("30000000-0000-4000-8000-{index:012}")).unwrap()
    }

    fn all_resources() -> (Vec<FleetClientRef>, Vec<FleetResource>) {
        let (provider, visitor, edge) = ids();
        let clients = vec![
            FleetClientRef {
                agent_instance_id: provider,
                name: "provider".to_owned(),
            },
            FleetClientRef {
                agent_instance_id: visitor,
                name: "visitor".to_owned(),
            },
            FleetClientRef {
                agent_instance_id: edge,
                name: "edge".to_owned(),
            },
        ];
        let resources = vec![
            FleetResource {
                resource_id: resource_id(1),
                enabled: true,
                spec: FleetResourceSpec::Tcp(FleetTcpResource {
                    agent_instance_id: provider,
                    name: "game-tcp".to_owned(),
                    public_port: 32_001,
                    target_addr: "127.0.0.1:2333".to_owned(),
                    max_connections: 64,
                    bandwidth_limit_bps: Some(10_000_000),
                }),
            },
            FleetResource {
                resource_id: resource_id(2),
                enabled: true,
                spec: FleetResourceSpec::Udp(FleetUdpResource {
                    agent_instance_id: provider,
                    name: "game-udp".to_owned(),
                    public_port: 32_002,
                    target_addr: "[::1]:2334".to_owned(),
                    max_sessions: 256,
                    session_idle_timeout_seconds: 120,
                    bandwidth_limit_bps: None,
                }),
            },
            FleetResource {
                resource_id: resource_id(3),
                enabled: true,
                spec: FleetResourceSpec::PortGroup(FleetPortGroupResource {
                    agent_instance_id: provider,
                    name: "game-ports".to_owned(),
                    protocol: FleetPortGroupProtocol::Tcp,
                    public_ports: "32100-32102".to_owned(),
                    target_host: "127.0.0.1".to_owned(),
                    target_ports: "2335-2337".to_owned(),
                    max_connections: 64,
                    max_sessions: 256,
                    session_idle_timeout_seconds: 120,
                    bandwidth_limit_bps: None,
                }),
            },
            FleetResource {
                resource_id: resource_id(4),
                enabled: true,
                spec: FleetResourceSpec::HttpRoute(FleetHttpRouteResource {
                    agent_instance_id: provider,
                    name: "website".to_owned(),
                    hostname: "www.example.test".to_owned(),
                    target_addr: "127.0.0.1:8080".to_owned(),
                    max_connections: 64,
                }),
            },
            FleetResource {
                resource_id: resource_id(5),
                enabled: true,
                spec: FleetResourceSpec::SniRoute(FleetSniRouteResource {
                    agent_instance_id: provider,
                    name: "mail-tls".to_owned(),
                    hostname: "mail.example.test".to_owned(),
                    target_addr: "127.0.0.1:465".to_owned(),
                    max_connections: 64,
                    bandwidth_limit_bps: None,
                }),
            },
            FleetResource {
                resource_id: resource_id(6),
                enabled: true,
                spec: FleetResourceSpec::SecretTunnel(FleetSecretTunnelResource {
                    provider_agent_instance_id: provider,
                    allowed_agent_instance_id: Some(visitor),
                    credential_ref: credential_id(1),
                    name: "private-rdp".to_owned(),
                    target_addr: "127.0.0.1:3389".to_owned(),
                    max_connections: 32,
                    bandwidth_limit_bps: None,
                }),
            },
            FleetResource {
                resource_id: resource_id(7),
                enabled: true,
                spec: FleetResourceSpec::Socks5Proxy(FleetSocks5ProxyResource {
                    agent_instance_id: edge,
                    credential_ref: credential_id(2),
                    name: "office-socks".to_owned(),
                    public_port: 32_007,
                    username: "office_user".to_owned(),
                    max_connections: 64,
                    bandwidth_limit_bps: None,
                }),
            },
            FleetResource {
                resource_id: resource_id(8),
                enabled: true,
                spec: FleetResourceSpec::HttpProxy(FleetHttpProxyResource {
                    agent_instance_id: edge,
                    credential_ref: credential_id(3),
                    name: "office-http".to_owned(),
                    public_port: 32_008,
                    username: "office_user".to_owned(),
                    max_connections: 64,
                    bandwidth_limit_bps: None,
                }),
            },
        ];
        (clients, resources)
    }

    fn bundle() -> FleetBundleV2 {
        let (clients, resources) = all_resources();
        FleetBundleV2::new(
            Uuid::parse_str("40000000-0000-4000-8000-000000000001").unwrap(),
            7,
            1_786_000_000,
            clients,
            resources,
            vec![FleetTrafficControl {
                resource_id: resource_id(1),
                enabled: true,
                allowed_cidrs: vec!["2001:db8::1/64".to_owned(), "10.0.0.1/8".to_owned()],
                denied_cidrs: vec!["192.0.2.0/24".to_owned()],
                max_connections_per_minute: Some(600),
                daily_quota_bytes: Some(1_000_000),
                active_weekdays_utc: vec![4, 1, 3],
                start_minute_utc: Some(480),
                end_minute_utc: Some(1_200),
            }],
        )
        .unwrap()
    }

    #[test]
    fn all_eight_resource_kinds_round_trip() {
        let bundle = bundle();
        let encoded = serde_json::to_vec_pretty(&bundle).unwrap();
        let decoded: FleetBundleV2 = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, bundle);
        assert_eq!(decoded.resources.len(), 8);
        assert!(matches!(
            decoded.resources[0].spec,
            FleetResourceSpec::Tcp(_)
        ));
        assert!(matches!(
            decoded.resources[1].spec,
            FleetResourceSpec::Udp(_)
        ));
        assert!(matches!(
            decoded.resources[2].spec,
            FleetResourceSpec::PortGroup(_)
        ));
        assert!(matches!(
            decoded.resources[3].spec,
            FleetResourceSpec::HttpRoute(_)
        ));
        assert!(matches!(
            decoded.resources[4].spec,
            FleetResourceSpec::SniRoute(_)
        ));
        assert!(matches!(
            decoded.resources[5].spec,
            FleetResourceSpec::SecretTunnel(_)
        ));
        assert!(matches!(
            decoded.resources[6].spec,
            FleetResourceSpec::Socks5Proxy(_)
        ));
        assert!(matches!(
            decoded.resources[7].spec,
            FleetResourceSpec::HttpProxy(_)
        ));
    }

    #[test]
    fn canonical_digest_and_json_ignore_collection_order() {
        let first = bundle();
        let mut second = first.clone();
        second.clients.reverse();
        second.resources.reverse();
        second.traffic_controls[0].allowed_cidrs =
            vec!["10.0.0.0/8".to_owned(), "2001:db8::/64".to_owned()];
        second.traffic_controls[0].active_weekdays_utc.reverse();
        second.refresh_integrity().unwrap();

        assert_eq!(first.content_sha256, second.content_sha256);
        assert_eq!(first.revision, second.revision);
        assert_eq!(
            first.to_canonical_json().unwrap(),
            second.to_canonical_json().unwrap()
        );
    }

    #[test]
    fn tampered_content_is_rejected_during_deserialization() {
        let mut value = serde_json::to_value(bundle()).unwrap();
        value["resources"][0]["spec"]["settings"]["target_addr"] =
            Value::String("127.0.0.1:9999".to_owned());
        let error = serde_json::from_value::<FleetBundleV2>(value).unwrap_err();
        assert!(error.to_string().contains("does not match"));
    }

    #[test]
    fn duplicate_resource_and_traffic_control_ids_are_rejected() {
        let mut value = serde_json::to_value(bundle()).unwrap();
        let duplicated = value["resources"][0].clone();
        value["resources"].as_array_mut().unwrap().push(duplicated);
        let error = serde_json::from_value::<FleetBundleV2>(value).unwrap_err();
        assert!(error.to_string().contains("duplicate Fleet resource ID"));

        let mut value = serde_json::to_value(bundle()).unwrap();
        let duplicated = value["traffic_controls"][0].clone();
        value["traffic_controls"]
            .as_array_mut()
            .unwrap()
            .push(duplicated);
        let error = serde_json::from_value::<FleetBundleV2>(value).unwrap_err();
        assert!(error
            .to_string()
            .contains("duplicate Fleet traffic control"));
    }

    #[test]
    fn old_and_unknown_schema_versions_are_rejected() {
        for schema in [1, 3, u16::MAX] {
            let mut value = serde_json::to_value(bundle()).unwrap();
            value["schema_version"] = json!(schema);
            let error = serde_json::from_value::<FleetBundleV2>(value).unwrap_err();
            assert!(error
                .to_string()
                .contains("unsupported Fleet bundle schema"));
        }
    }

    #[test]
    fn secret_bearing_fields_are_rejected_at_every_envelope_level() {
        for field in [
            "client_token",
            "password",
            "password_hash",
            "access_key",
            "access_key_hash",
            "private_key",
            "certificate_private_key",
        ] {
            let mut value = serde_json::to_value(bundle()).unwrap();
            value[field] = json!("must-not-enter-the-bundle");
            assert!(serde_json::from_value::<FleetBundleV2>(value).is_err());
        }

        let mut value = serde_json::to_value(bundle()).unwrap();
        value["clients"][0]["client_token"] = json!("llc_secret");
        assert!(serde_json::from_value::<FleetBundleV2>(value).is_err());

        let mut value = serde_json::to_value(bundle()).unwrap();
        value["resources"][6]["spec"]["settings"]["password"] = json!("llp_secret");
        assert!(serde_json::from_value::<FleetBundleV2>(value).is_err());

        let mut value = serde_json::to_value(bundle()).unwrap();
        value["resources"][6]["spec"]["password"] = json!("llp_secret");
        assert!(serde_json::from_value::<FleetBundleV2>(value).is_err());

        let mut value = serde_json::to_value(bundle()).unwrap();
        value["resources"][5]["spec"]["settings"]["access_key"] = json!("lls_secret");
        assert!(serde_json::from_value::<FleetBundleV2>(value).is_err());
    }

    #[test]
    fn invalid_empty_and_cross_reference_fields_are_rejected() {
        let mut invalid = bundle();
        invalid.clients[0].name = " ".to_owned();
        assert_eq!(
            invalid.validate(),
            Err(FleetBundleError::InvalidField("clients.name"))
        );

        let mut invalid = bundle();
        if let FleetResourceSpec::Tcp(resource) = &mut invalid.resources[0].spec {
            resource.public_port = 0;
        }
        assert_eq!(
            invalid.validate(),
            Err(FleetBundleError::InvalidField("resources.public_port"))
        );

        let mut invalid = bundle();
        if let FleetResourceSpec::HttpRoute(resource) = &mut invalid.resources[3].spec {
            resource.hostname = "HTTP://EXAMPLE.TEST".to_owned();
        }
        assert_eq!(
            invalid.validate(),
            Err(FleetBundleError::InvalidField("resources.hostname"))
        );

        let mut invalid = bundle();
        if let FleetResourceSpec::Socks5Proxy(resource) = &mut invalid.resources[6].spec {
            resource.agent_instance_id = Uuid::new_v4();
        }
        assert!(matches!(
            invalid.validate(),
            Err(FleetBundleError::UnknownClient(_))
        ));

        let mut invalid = bundle();
        invalid.traffic_controls[0].allowed_cidrs = vec!["not-a-cidr".to_owned()];
        assert_eq!(
            invalid.validate(),
            Err(FleetBundleError::InvalidField(
                "traffic_controls.allowed_cidrs"
            ))
        );
    }

    #[test]
    fn content_digest_and_revision_have_strict_formats() {
        let mut invalid = bundle();
        invalid.content_sha256 = "SHA256:bad".to_owned();
        assert_eq!(
            invalid.validate(),
            Err(FleetBundleError::InvalidContentSha256)
        );

        let mut invalid = bundle();
        invalid.revision = format!("sha256:{}", "0".repeat(64));
        assert_eq!(invalid.validate(), Err(FleetBundleError::RevisionMismatch));
    }
}
