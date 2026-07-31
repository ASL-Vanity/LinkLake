use rusqlite::{params, Connection, ErrorCode, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fmt, fs, net::Ipv6Addr, path::Path};
use uuid::Uuid;

use linklake_core::port_mapping::{
    parse_port_mappings, ParsedPortMappings, PortMappingError, MAX_PORT_MAPPINGS,
};

pub(crate) const MIN_TCP_TUNNEL_PORT: u16 = 32_000;
pub(crate) const MAX_TCP_TUNNEL_PORT: u16 = 32_999;
pub(crate) const MIN_UDP_TUNNEL_PORT: u16 = 32_000;
pub(crate) const MAX_UDP_TUNNEL_PORT: u16 = 32_999;
const DEFAULT_MAX_CONNECTIONS: u16 = 64;
const DEFAULT_MAX_SESSIONS: u16 = 256;
const MAX_UDP_SESSIONS: u16 = 4_096;
const DEFAULT_UDP_IDLE_TIMEOUT_SECONDS: u32 = 120;
const MIN_UDP_IDLE_TIMEOUT_SECONDS: u32 = 30;
const MAX_UDP_IDLE_TIMEOUT_SECONDS: u32 = 3_600;
const MIN_BANDWIDTH_LIMIT_BPS: u64 = 1_024;
const MAX_BANDWIDTH_LIMIT_BPS: u64 = 1_000_000_000;

#[derive(Deserialize)]
pub(crate) struct CreateTcpTunnelPolicy {
    pub(crate) client_id: Uuid,
    pub(crate) name: String,
    pub(crate) public_port: u16,
    pub(crate) target_addr: String,
    pub(crate) max_connections: Option<u16>,
    pub(crate) bandwidth_limit_bps: Option<u64>,
}

// 更新接口采用完整替换语义，字段格式与创建接口保持一致。
pub(crate) type UpdateTcpTunnelPolicy = CreateTcpTunnelPolicy;

#[derive(Serialize, Clone)]
pub(crate) struct TcpTunnelPolicy {
    pub(crate) id: Uuid,
    pub(crate) client_id: Uuid,
    pub(crate) name: String,
    pub(crate) public_port: u16,
    pub(crate) target_addr: String,
    pub(crate) max_connections: u16,
    pub(crate) bandwidth_limit_bps: Option<u64>,
    pub(crate) enabled: bool,
}

#[derive(Debug, PartialEq)]
pub(crate) struct TcpTunnelRuntimePolicy {
    pub(crate) max_connections: usize,
    pub(crate) bandwidth_limit_bps: Option<u64>,
}

#[derive(Deserialize)]
pub(crate) struct CreateSocks5ProxyPolicy {
    pub(crate) client_id: Uuid,
    pub(crate) name: String,
    pub(crate) public_port: u16,
    pub(crate) username: String,
    pub(crate) max_connections: Option<u16>,
    pub(crate) bandwidth_limit_bps: Option<u64>,
}

// 更新代理策略时不会重置一次性生成的密码，只更新公开策略字段。
pub(crate) type UpdateSocks5ProxyPolicy = CreateSocks5ProxyPolicy;

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub(crate) struct Socks5ProxyPolicy {
    pub(crate) id: Uuid,
    pub(crate) client_id: Uuid,
    pub(crate) name: String,
    pub(crate) public_port: u16,
    pub(crate) username: String,
    pub(crate) max_connections: u16,
    pub(crate) bandwidth_limit_bps: Option<u64>,
    pub(crate) enabled: bool,
}

#[derive(Serialize)]
pub(crate) struct CreatedSocks5ProxyPolicy {
    #[serde(flatten)]
    pub(crate) policy: Socks5ProxyPolicy,
    pub(crate) password: String,
}

#[derive(Debug, Clone)]
pub(crate) struct Socks5ProxyRuntimePolicy {
    pub(crate) policy_id: Uuid,
    pub(crate) username: String,
    pub(crate) password_hash: String,
    pub(crate) max_connections: usize,
    pub(crate) bandwidth_limit_bps: Option<u64>,
}

#[derive(Deserialize)]
pub(crate) struct CreateHttpProxyPolicy {
    pub(crate) client_id: Uuid,
    pub(crate) name: String,
    pub(crate) public_port: u16,
    pub(crate) username: String,
    pub(crate) max_connections: Option<u16>,
    pub(crate) bandwidth_limit_bps: Option<u64>,
}

pub(crate) type UpdateHttpProxyPolicy = CreateHttpProxyPolicy;

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub(crate) struct HttpProxyPolicy {
    pub(crate) id: Uuid,
    pub(crate) client_id: Uuid,
    pub(crate) name: String,
    pub(crate) public_port: u16,
    pub(crate) username: String,
    pub(crate) max_connections: u16,
    pub(crate) bandwidth_limit_bps: Option<u64>,
    pub(crate) enabled: bool,
}

#[derive(Serialize)]
pub(crate) struct CreatedHttpProxyPolicy {
    #[serde(flatten)]
    pub(crate) policy: HttpProxyPolicy,
    pub(crate) password: String,
}

#[derive(Debug, Clone)]
pub(crate) struct HttpProxyRuntimePolicy {
    pub(crate) policy_id: Uuid,
    pub(crate) username: String,
    pub(crate) password_hash: String,
    pub(crate) max_connections: usize,
    pub(crate) bandwidth_limit_bps: Option<u64>,
}

#[derive(Debug)]
pub(crate) enum HttpProxyPolicyError {
    InvalidName,
    InvalidPublicPort,
    InvalidUsername,
    InvalidConnectionLimit,
    InvalidBandwidthLimit,
    DuplicateName,
    DuplicatePublicPort,
    Database(rusqlite::Error),
}

impl HttpProxyPolicyError {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::InvalidName => "invalid_name",
            Self::InvalidPublicPort => "invalid_public_port",
            Self::InvalidUsername => "invalid_http_proxy_username",
            Self::InvalidConnectionLimit => "invalid_connection_limit",
            Self::InvalidBandwidthLimit => "invalid_bandwidth_limit",
            Self::DuplicateName => "duplicate_http_proxy",
            Self::DuplicatePublicPort => "duplicate_tcp_public_port",
            Self::Database(_) => "http_proxy_policy_storage_error",
        }
    }
}

impl fmt::Display for HttpProxyPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for HttpProxyPolicyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Database(error) => Some(error),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for HttpProxyPolicyError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error)
    }
}

#[derive(Debug)]
pub(crate) enum Socks5PolicyError {
    InvalidName,
    InvalidPublicPort,
    InvalidUsername,
    InvalidConnectionLimit,
    InvalidBandwidthLimit,
    DuplicateName,
    DuplicatePublicPort,
    Database(rusqlite::Error),
}

impl Socks5PolicyError {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::InvalidName => "invalid_name",
            Self::InvalidPublicPort => "invalid_public_port",
            Self::InvalidUsername => "invalid_socks5_username",
            Self::InvalidConnectionLimit => "invalid_connection_limit",
            Self::InvalidBandwidthLimit => "invalid_bandwidth_limit",
            Self::DuplicateName => "duplicate_socks5_proxy",
            Self::DuplicatePublicPort => "duplicate_tcp_public_port",
            Self::Database(_) => "socks5_policy_storage_error",
        }
    }
}

impl fmt::Display for Socks5PolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for Socks5PolicyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Database(error) => Some(error),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for Socks5PolicyError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error)
    }
}

#[derive(Deserialize)]
pub(crate) struct CreateUdpTunnelPolicy {
    pub(crate) client_id: Uuid,
    pub(crate) name: String,
    pub(crate) public_port: u16,
    pub(crate) target_addr: String,
    pub(crate) max_sessions: Option<u16>,
    pub(crate) session_idle_timeout_seconds: Option<u32>,
    pub(crate) bandwidth_limit_bps: Option<u64>,
}

pub(crate) type UpdateUdpTunnelPolicy = CreateUdpTunnelPolicy;

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub(crate) struct UdpTunnelPolicy {
    pub(crate) id: Uuid,
    pub(crate) client_id: Uuid,
    pub(crate) name: String,
    pub(crate) public_port: u16,
    pub(crate) target_addr: String,
    pub(crate) max_sessions: u16,
    pub(crate) session_idle_timeout_seconds: u32,
    pub(crate) bandwidth_limit_bps: Option<u64>,
    pub(crate) enabled: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct UdpTunnelRuntimePolicy {
    pub(crate) policy_id: Uuid,
    pub(crate) max_sessions: usize,
    pub(crate) session_idle_timeout_seconds: u64,
    pub(crate) bandwidth_limit_bps: Option<u64>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PortGroupProtocol {
    Tcp,
    Udp,
}

impl PortGroupProtocol {
    fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }

    fn parse(value: &str) -> rusqlite::Result<Self> {
        match value {
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            _ => Err(rusqlite::Error::InvalidQuery),
        }
    }
}

#[derive(Deserialize)]
pub(crate) struct CreatePortGroupPolicy {
    pub(crate) client_id: Uuid,
    pub(crate) name: String,
    pub(crate) protocol: PortGroupProtocol,
    pub(crate) public_ports: String,
    pub(crate) target_host: String,
    pub(crate) target_ports: String,
    pub(crate) max_connections: Option<u16>,
    pub(crate) max_sessions: Option<u16>,
    pub(crate) session_idle_timeout_seconds: Option<u32>,
    pub(crate) bandwidth_limit_bps: Option<u64>,
}

pub(crate) type UpdatePortGroupPolicy = CreatePortGroupPolicy;

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub(crate) struct PortGroupPolicy {
    pub(crate) id: Uuid,
    pub(crate) client_id: Uuid,
    pub(crate) name: String,
    pub(crate) protocol: PortGroupProtocol,
    pub(crate) public_ports: String,
    pub(crate) target_host: String,
    pub(crate) target_ports: String,
    pub(crate) mapping_count: usize,
    pub(crate) max_connections: u16,
    pub(crate) max_sessions: u16,
    pub(crate) session_idle_timeout_seconds: u32,
    pub(crate) bandwidth_limit_bps: Option<u64>,
    pub(crate) enabled: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct PortGroupMapping {
    pub(crate) public_port: u16,
    pub(crate) target_port: u16,
    pub(crate) target_addr: String,
}

#[derive(Debug)]
pub(crate) enum PortGroupPolicyError {
    InvalidName,
    InvalidPorts(PortMappingError),
    InvalidTargetHost,
    InvalidConnectionLimit,
    InvalidSessionLimit,
    InvalidIdleTimeout,
    InvalidBandwidthLimit,
    DuplicateName,
    DuplicatePublicPort,
    Database(rusqlite::Error),
}

impl PortGroupPolicyError {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::InvalidName => "invalid_name",
            Self::InvalidPorts(PortMappingError::CountMismatch) => "port_count_mismatch",
            Self::InvalidPorts(PortMappingError::DuplicatePort) => "duplicate_port_in_group",
            Self::InvalidPorts(PortMappingError::TooManyPorts) => "too_many_port_mappings",
            Self::InvalidPorts(_) => "invalid_port_expression",
            Self::InvalidTargetHost => "invalid_target_host",
            Self::InvalidConnectionLimit => "invalid_connection_limit",
            Self::InvalidSessionLimit => "invalid_session_limit",
            Self::InvalidIdleTimeout => "invalid_idle_timeout",
            Self::InvalidBandwidthLimit => "invalid_bandwidth_limit",
            Self::DuplicateName => "duplicate_port_group",
            Self::DuplicatePublicPort => "duplicate_public_port",
            Self::Database(_) => "port_group_policy_storage_error",
        }
    }
}

impl fmt::Display for PortGroupPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for PortGroupPolicyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidPorts(error) => Some(error),
            Self::Database(error) => Some(error),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for PortGroupPolicyError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error)
    }
}

#[derive(Debug)]
pub(crate) enum UdpPolicyError {
    InvalidName,
    InvalidPublicPort,
    InvalidTarget,
    InvalidSessionLimit,
    InvalidIdleTimeout,
    InvalidBandwidthLimit,
    DuplicatePublicPort,
    Database(rusqlite::Error),
}

impl UdpPolicyError {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::InvalidName => "invalid_name",
            Self::InvalidPublicPort => "invalid_public_port",
            Self::InvalidTarget => "invalid_target",
            Self::InvalidSessionLimit => "invalid_session_limit",
            Self::InvalidIdleTimeout => "invalid_idle_timeout",
            Self::InvalidBandwidthLimit => "invalid_bandwidth_limit",
            Self::DuplicatePublicPort => "duplicate_public_port",
            Self::Database(_) => "udp_policy_storage_error",
        }
    }
}

impl fmt::Display for UdpPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for UdpPolicyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Database(error) => Some(error),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for UdpPolicyError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error)
    }
}

pub(crate) struct TunnelCatalog {
    database: Connection,
}

impl TunnelCatalog {
    pub(crate) fn open(data_dir: Option<&Path>) -> anyhow::Result<Self> {
        let database = match data_dir {
            Some(data_dir) => {
                fs::create_dir_all(data_dir)?;
                Connection::open(data_dir.join("linklake.sqlite3"))?
            }
            None => Connection::open_in_memory()?,
        };
        database.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS tcp_tunnel_policies (
                id TEXT PRIMARY KEY NOT NULL,
                client_id TEXT NOT NULL,
                name TEXT NOT NULL,
                public_port INTEGER NOT NULL UNIQUE,
                target_addr TEXT NOT NULL,
                max_connections INTEGER NOT NULL DEFAULT 64,
                bandwidth_limit_bps INTEGER,
                enabled INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS udp_tunnel_policies (
                id TEXT PRIMARY KEY NOT NULL,
                client_id TEXT NOT NULL,
                name TEXT NOT NULL,
                public_port INTEGER NOT NULL UNIQUE,
                target_addr TEXT NOT NULL,
                max_sessions INTEGER NOT NULL DEFAULT 256,
                session_idle_timeout_seconds INTEGER NOT NULL DEFAULT 120,
                bandwidth_limit_bps INTEGER,
                enabled INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS socks5_proxy_policies (
                id TEXT PRIMARY KEY NOT NULL,
                client_id TEXT NOT NULL,
                name TEXT NOT NULL,
                public_port INTEGER NOT NULL UNIQUE,
                username TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                max_connections INTEGER NOT NULL DEFAULT 64,
                bandwidth_limit_bps INTEGER,
                enabled INTEGER NOT NULL DEFAULT 1,
                UNIQUE(client_id, name)
            );
            CREATE TABLE IF NOT EXISTS http_proxy_policies (
                id TEXT PRIMARY KEY NOT NULL,
                client_id TEXT NOT NULL,
                name TEXT NOT NULL,
                public_port INTEGER NOT NULL UNIQUE,
                username TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                max_connections INTEGER NOT NULL DEFAULT 64,
                bandwidth_limit_bps INTEGER,
                enabled INTEGER NOT NULL DEFAULT 1,
                UNIQUE(client_id, name)
            );
            CREATE TABLE IF NOT EXISTS port_group_policies (
                id TEXT PRIMARY KEY NOT NULL,
                client_id TEXT NOT NULL,
                name TEXT NOT NULL,
                protocol TEXT NOT NULL CHECK(protocol IN ('tcp', 'udp')),
                public_ports TEXT NOT NULL,
                target_host TEXT NOT NULL,
                target_ports TEXT NOT NULL,
                mapping_count INTEGER NOT NULL,
                max_connections INTEGER NOT NULL DEFAULT 64,
                max_sessions INTEGER NOT NULL DEFAULT 256,
                session_idle_timeout_seconds INTEGER NOT NULL DEFAULT 120,
                bandwidth_limit_bps INTEGER,
                enabled INTEGER NOT NULL DEFAULT 1,
                UNIQUE(client_id, protocol, name)
            );
            CREATE TABLE IF NOT EXISTS port_group_mappings (
                policy_id TEXT NOT NULL,
                protocol TEXT NOT NULL CHECK(protocol IN ('tcp', 'udp')),
                public_port INTEGER NOT NULL,
                target_port INTEGER NOT NULL,
                target_addr TEXT NOT NULL,
                PRIMARY KEY(policy_id, public_port),
                UNIQUE(protocol, public_port)
            );
            CREATE INDEX IF NOT EXISTS port_group_mappings_policy_id
                ON port_group_mappings(policy_id);
            ",
        )?;
        let count: i64 = database.query_row("SELECT COUNT(*) FROM pragma_table_info('tcp_tunnel_policies') WHERE name = 'max_connections'", [], |row| row.get(0))?;
        if count == 0 {
            database.execute("ALTER TABLE tcp_tunnel_policies ADD COLUMN max_connections INTEGER NOT NULL DEFAULT 64", [])?;
        }
        let count: i64 = database.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('tcp_tunnel_policies') WHERE name = 'bandwidth_limit_bps'",
            [],
            |row| row.get(0),
        )?;
        if count == 0 {
            database.execute(
                "ALTER TABLE tcp_tunnel_policies ADD COLUMN bandwidth_limit_bps INTEGER",
                [],
            )?;
        }
        Ok(Self { database })
    }

    pub(crate) fn create(
        &mut self,
        request: CreateTcpTunnelPolicy,
    ) -> anyhow::Result<TcpTunnelPolicy> {
        validate_policy(&request)?;
        let proxy_port_in_use: bool = self.database.query_row(
            "SELECT EXISTS(SELECT 1 FROM socks5_proxy_policies WHERE public_port = ?1 UNION ALL SELECT 1 FROM http_proxy_policies WHERE public_port = ?1 UNION ALL SELECT 1 FROM port_group_mappings WHERE protocol = 'tcp' AND public_port = ?1)",
            [request.public_port],
            |row| row.get(0),
        )?;
        anyhow::ensure!(!proxy_port_in_use, "public port is already assigned");
        let policy = TcpTunnelPolicy {
            id: Uuid::new_v4(),
            client_id: request.client_id,
            name: request.name.trim().to_owned(),
            public_port: request.public_port,
            target_addr: request.target_addr.trim().to_owned(),
            max_connections: request.max_connections.unwrap_or(DEFAULT_MAX_CONNECTIONS),
            bandwidth_limit_bps: request.bandwidth_limit_bps,
            enabled: true,
        };
        self.database.execute(
            "INSERT INTO tcp_tunnel_policies (id, client_id, name, public_port, target_addr, max_connections, bandwidth_limit_bps, enabled) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1)",
            params![policy.id.to_string(), policy.client_id.to_string(), policy.name, policy.public_port, policy.target_addr, policy.max_connections, policy.bandwidth_limit_bps],
        )?;
        Ok(policy)
    }

    pub(crate) fn list(&self) -> anyhow::Result<Vec<TcpTunnelPolicy>> {
        let mut statement = self.database.prepare(
            "SELECT id, client_id, name, public_port, target_addr, max_connections, bandwidth_limit_bps, enabled FROM tcp_tunnel_policies ORDER BY public_port",
        )?;
        let rows = statement.query_map([], |row| {
            let id: String = row.get(0)?;
            let client_id: String = row.get(1)?;
            Ok(TcpTunnelPolicy {
                id: Uuid::parse_str(&id).map_err(|_| rusqlite::Error::InvalidQuery)?,
                client_id: Uuid::parse_str(&client_id)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?,
                name: row.get(2)?,
                public_port: row.get(3)?,
                target_addr: row.get(4)?,
                max_connections: row.get(5)?,
                bandwidth_limit_bps: row.get(6)?,
                enabled: row.get::<_, i64>(7)? != 0,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub(crate) fn policy_by_id(&self, id: Uuid) -> anyhow::Result<Option<TcpTunnelPolicy>> {
        self.database
            .query_row(
                "SELECT id, client_id, name, public_port, target_addr, max_connections, bandwidth_limit_bps, enabled FROM tcp_tunnel_policies WHERE id = ?1",
                [id.to_string()],
                |row| {
                    let id: String = row.get(0)?;
                    let client_id: String = row.get(1)?;
                    Ok(TcpTunnelPolicy {
                        id: Uuid::parse_str(&id).map_err(|_| rusqlite::Error::InvalidQuery)?,
                        client_id: Uuid::parse_str(&client_id)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        name: row.get(2)?,
                        public_port: row.get(3)?,
                        target_addr: row.get(4)?,
                        max_connections: row.get(5)?,
                        bandwidth_limit_bps: row.get(6)?,
                        enabled: row.get::<_, i64>(7)? != 0,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub(crate) fn update(
        &mut self,
        id: Uuid,
        request: UpdateTcpTunnelPolicy,
    ) -> anyhow::Result<Option<TcpTunnelPolicy>> {
        validate_policy(&request)?;
        let Some(current) = self.policy_by_id(id)? else {
            return Ok(None);
        };
        let proxy_port_in_use: bool = self.database.query_row(
            "SELECT EXISTS(SELECT 1 FROM tcp_tunnel_policies WHERE public_port = ?1 AND id <> ?2 UNION ALL SELECT 1 FROM socks5_proxy_policies WHERE public_port = ?1 UNION ALL SELECT 1 FROM http_proxy_policies WHERE public_port = ?1 UNION ALL SELECT 1 FROM port_group_mappings WHERE protocol = 'tcp' AND public_port = ?1 AND policy_id <> ?2)",
            params![request.public_port, id.to_string()],
            |row| row.get(0),
        )?;
        anyhow::ensure!(!proxy_port_in_use, "public port is already assigned");
        let policy = TcpTunnelPolicy {
            id,
            client_id: request.client_id,
            name: request.name.trim().to_owned(),
            public_port: request.public_port,
            target_addr: request.target_addr.trim().to_owned(),
            max_connections: request.max_connections.unwrap_or(DEFAULT_MAX_CONNECTIONS),
            bandwidth_limit_bps: request.bandwidth_limit_bps,
            enabled: current.enabled,
        };
        self.database.execute(
            "UPDATE tcp_tunnel_policies SET client_id = ?1, name = ?2, public_port = ?3, target_addr = ?4, max_connections = ?5, bandwidth_limit_bps = ?6 WHERE id = ?7",
            params![
                policy.client_id.to_string(),
                policy.name,
                policy.public_port,
                policy.target_addr,
                policy.max_connections,
                policy.bandwidth_limit_bps,
                policy.id.to_string(),
            ],
        )?;
        Ok(Some(policy))
    }

    pub(crate) fn set_enabled(&mut self, id: Uuid, enabled: bool) -> anyhow::Result<bool> {
        Ok(self.database.execute(
            "UPDATE tcp_tunnel_policies SET enabled = ?1 WHERE id = ?2",
            params![enabled, id.to_string()],
        )? != 0)
    }

    pub(crate) fn delete(&mut self, id: Uuid) -> anyhow::Result<bool> {
        Ok(self.database.execute(
            "DELETE FROM tcp_tunnel_policies WHERE id = ?1",
            [id.to_string()],
        )? != 0)
    }

    pub(crate) fn runtime_policy(
        &self,
        client_id: Uuid,
        name: &str,
        public_port: u16,
        target_addr: &str,
    ) -> anyhow::Result<Option<TcpTunnelRuntimePolicy>> {
        let value: Option<(i64, Option<i64>)> = self.database.query_row(
            "SELECT max_connections, bandwidth_limit_bps FROM tcp_tunnel_policies WHERE client_id = ?1 AND name = ?2 AND public_port = ?3 AND target_addr = ?4 AND enabled = 1",
            params![client_id.to_string(), name, public_port, target_addr],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional()?;
        if let Some(value) = value {
            let (max_connections, bandwidth_limit_bps) = value;
            return Ok(Some(TcpTunnelRuntimePolicy {
                max_connections: max_connections as usize,
                bandwidth_limit_bps: bandwidth_limit_bps.map(|value| value as u64),
            }));
        }
        let value: Option<(i64, Option<i64>)> = self.database.query_row(
            "SELECT p.max_connections, p.bandwidth_limit_bps FROM port_group_policies p JOIN port_group_mappings m ON m.policy_id = p.id WHERE p.client_id = ?1 AND p.protocol = 'tcp' AND p.name = ?2 AND m.public_port = ?3 AND m.target_addr = ?4 AND p.enabled = 1",
            params![client_id.to_string(), name, public_port, target_addr],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional()?;
        Ok(value.map(
            |(max_connections, bandwidth_limit_bps)| TcpTunnelRuntimePolicy {
                max_connections: max_connections as usize,
                bandwidth_limit_bps: bandwidth_limit_bps.map(|value| value as u64),
            },
        ))
    }

    pub(crate) fn create_socks5(
        &mut self,
        request: CreateSocks5ProxyPolicy,
    ) -> Result<CreatedSocks5ProxyPolicy, Socks5PolicyError> {
        validate_socks5_policy(&request)?;
        let tcp_port_in_use: bool = self.database.query_row(
            "SELECT EXISTS(SELECT 1 FROM tcp_tunnel_policies WHERE public_port = ?1 UNION ALL SELECT 1 FROM udp_tunnel_policies WHERE public_port = ?1 UNION ALL SELECT 1 FROM http_proxy_policies WHERE public_port = ?1 UNION ALL SELECT 1 FROM port_group_mappings WHERE public_port = ?1)",
            [request.public_port],
            |row| row.get(0),
        )?;
        if tcp_port_in_use {
            return Err(Socks5PolicyError::DuplicatePublicPort);
        }
        let password = format!("llp_{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let policy = Socks5ProxyPolicy {
            id: Uuid::new_v4(),
            client_id: request.client_id,
            name: request.name.trim().to_owned(),
            public_port: request.public_port,
            username: request.username.trim().to_owned(),
            max_connections: request.max_connections.unwrap_or(DEFAULT_MAX_CONNECTIONS),
            bandwidth_limit_bps: request.bandwidth_limit_bps,
            enabled: true,
        };
        let result = self.database.execute(
            "INSERT INTO socks5_proxy_policies (id, client_id, name, public_port, username, password_hash, max_connections, bandwidth_limit_bps, enabled) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1)",
            params![
                policy.id.to_string(),
                policy.client_id.to_string(),
                policy.name,
                policy.public_port,
                policy.username,
                hash_socks5_password(&password),
                policy.max_connections,
                policy.bandwidth_limit_bps,
            ],
        );
        match result {
            Ok(_) => Ok(CreatedSocks5ProxyPolicy { policy, password }),
            Err(error) if is_constraint_violation(&error) => {
                let port_exists: bool = self.database.query_row(
                    "SELECT EXISTS(SELECT 1 FROM socks5_proxy_policies WHERE public_port = ?1)",
                    [request.public_port],
                    |row| row.get(0),
                )?;
                if port_exists {
                    Err(Socks5PolicyError::DuplicatePublicPort)
                } else {
                    Err(Socks5PolicyError::DuplicateName)
                }
            }
            Err(error) => Err(Socks5PolicyError::Database(error)),
        }
    }

    pub(crate) fn list_socks5(&self) -> Result<Vec<Socks5ProxyPolicy>, Socks5PolicyError> {
        let mut statement = self.database.prepare(
            "SELECT id, client_id, name, public_port, username, max_connections, bandwidth_limit_bps, enabled FROM socks5_proxy_policies ORDER BY public_port",
        )?;
        let rows = statement.query_map([], read_socks5_policy)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub(crate) fn set_socks5_enabled(
        &mut self,
        id: Uuid,
        enabled: bool,
    ) -> Result<bool, Socks5PolicyError> {
        Ok(self.database.execute(
            "UPDATE socks5_proxy_policies SET enabled = ?1 WHERE id = ?2",
            params![enabled, id.to_string()],
        )? != 0)
    }

    pub(crate) fn delete_socks5(
        &mut self,
        id: Uuid,
    ) -> Result<Option<Socks5ProxyPolicy>, Socks5PolicyError> {
        let policy = self.socks5_policy_by_id(id)?;
        if policy.is_some() {
            self.database.execute(
                "DELETE FROM socks5_proxy_policies WHERE id = ?1",
                [id.to_string()],
            )?;
        }
        Ok(policy)
    }

    pub(crate) fn socks5_policy_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<Socks5ProxyPolicy>, Socks5PolicyError> {
        self.database
            .query_row(
                "SELECT id, client_id, name, public_port, username, max_connections, bandwidth_limit_bps, enabled FROM socks5_proxy_policies WHERE id = ?1",
                [id.to_string()],
                read_socks5_policy,
            )
            .optional()
            .map_err(Into::into)
    }

    pub(crate) fn update_socks5(
        &mut self,
        id: Uuid,
        request: UpdateSocks5ProxyPolicy,
    ) -> Result<Option<Socks5ProxyPolicy>, Socks5PolicyError> {
        validate_socks5_policy(&request)?;
        let Some(current) = self.socks5_policy_by_id(id)? else {
            return Ok(None);
        };
        let duplicate_name: bool = self.database.query_row(
            "SELECT EXISTS(SELECT 1 FROM socks5_proxy_policies WHERE client_id = ?1 AND name = ?2 AND id <> ?3)",
            params![request.client_id.to_string(), request.name.trim(), id.to_string()],
            |row| row.get(0),
        )?;
        if duplicate_name {
            return Err(Socks5PolicyError::DuplicateName);
        }
        let tcp_port_in_use: bool = self.database.query_row(
            "SELECT EXISTS(SELECT 1 FROM tcp_tunnel_policies WHERE public_port = ?1 UNION ALL SELECT 1 FROM udp_tunnel_policies WHERE public_port = ?1 UNION ALL SELECT 1 FROM http_proxy_policies WHERE public_port = ?1 UNION ALL SELECT 1 FROM socks5_proxy_policies WHERE public_port = ?1 AND id <> ?2 UNION ALL SELECT 1 FROM port_group_mappings WHERE public_port = ?1 AND policy_id <> ?2)",
            params![request.public_port, id.to_string()],
            |row| row.get(0),
        )?;
        if tcp_port_in_use {
            return Err(Socks5PolicyError::DuplicatePublicPort);
        }
        let policy = Socks5ProxyPolicy {
            id,
            client_id: request.client_id,
            name: request.name.trim().to_owned(),
            public_port: request.public_port,
            username: request.username.trim().to_owned(),
            max_connections: request.max_connections.unwrap_or(DEFAULT_MAX_CONNECTIONS),
            bandwidth_limit_bps: request.bandwidth_limit_bps,
            enabled: current.enabled,
        };
        self.database.execute(
            "UPDATE socks5_proxy_policies SET client_id = ?1, name = ?2, public_port = ?3, username = ?4, max_connections = ?5, bandwidth_limit_bps = ?6 WHERE id = ?7",
            params![
                policy.client_id.to_string(),
                policy.name,
                policy.public_port,
                policy.username,
                policy.max_connections,
                policy.bandwidth_limit_bps,
                policy.id.to_string(),
            ],
        )?;
        Ok(Some(policy))
    }

    pub(crate) fn socks5_runtime_policy(
        &self,
        client_id: Uuid,
        name: &str,
        public_port: u16,
    ) -> Result<Option<Socks5ProxyRuntimePolicy>, Socks5PolicyError> {
        self.database
            .query_row(
                "SELECT id, username, password_hash, max_connections, bandwidth_limit_bps FROM socks5_proxy_policies WHERE client_id = ?1 AND name = ?2 AND public_port = ?3 AND enabled = 1",
                params![client_id.to_string(), name, public_port],
                |row| {
                    let id: String = row.get(0)?;
                    Ok(Socks5ProxyRuntimePolicy {
                        policy_id: Uuid::parse_str(&id)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        username: row.get(1)?,
                        password_hash: row.get(2)?,
                        max_connections: row.get::<_, i64>(3)? as usize,
                        bandwidth_limit_bps: row
                            .get::<_, Option<i64>>(4)?
                            .map(|value| value as u64),
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub(crate) fn create_http_proxy(
        &mut self,
        request: CreateHttpProxyPolicy,
    ) -> Result<CreatedHttpProxyPolicy, HttpProxyPolicyError> {
        validate_http_proxy_policy(&request)?;
        let port_in_use: bool = self.database.query_row(
            "SELECT EXISTS(SELECT 1 FROM tcp_tunnel_policies WHERE public_port = ?1 UNION ALL SELECT 1 FROM socks5_proxy_policies WHERE public_port = ?1 UNION ALL SELECT 1 FROM port_group_mappings WHERE protocol = 'tcp' AND public_port = ?1)",
            [request.public_port],
            |row| row.get(0),
        )?;
        if port_in_use {
            return Err(HttpProxyPolicyError::DuplicatePublicPort);
        }
        let password = format!("llh_{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let policy = HttpProxyPolicy {
            id: Uuid::new_v4(),
            client_id: request.client_id,
            name: request.name.trim().to_owned(),
            public_port: request.public_port,
            username: request.username.trim().to_owned(),
            max_connections: request.max_connections.unwrap_or(DEFAULT_MAX_CONNECTIONS),
            bandwidth_limit_bps: request.bandwidth_limit_bps,
            enabled: true,
        };
        let result = self.database.execute(
            "INSERT INTO http_proxy_policies (id, client_id, name, public_port, username, password_hash, max_connections, bandwidth_limit_bps, enabled) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1)",
            params![
                policy.id.to_string(),
                policy.client_id.to_string(),
                policy.name,
                policy.public_port,
                policy.username,
                hash_http_proxy_password(&password),
                policy.max_connections,
                policy.bandwidth_limit_bps,
            ],
        );
        match result {
            Ok(_) => Ok(CreatedHttpProxyPolicy { policy, password }),
            Err(error) if is_constraint_violation(&error) => {
                let port_exists: bool = self.database.query_row(
                    "SELECT EXISTS(SELECT 1 FROM http_proxy_policies WHERE public_port = ?1)",
                    [request.public_port],
                    |row| row.get(0),
                )?;
                if port_exists {
                    Err(HttpProxyPolicyError::DuplicatePublicPort)
                } else {
                    Err(HttpProxyPolicyError::DuplicateName)
                }
            }
            Err(error) => Err(HttpProxyPolicyError::Database(error)),
        }
    }

    pub(crate) fn list_http_proxies(&self) -> Result<Vec<HttpProxyPolicy>, HttpProxyPolicyError> {
        let mut statement = self.database.prepare(
            "SELECT id, client_id, name, public_port, username, max_connections, bandwidth_limit_bps, enabled FROM http_proxy_policies ORDER BY public_port",
        )?;
        let rows = statement.query_map([], read_http_proxy_policy)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub(crate) fn set_http_proxy_enabled(
        &mut self,
        id: Uuid,
        enabled: bool,
    ) -> Result<bool, HttpProxyPolicyError> {
        Ok(self.database.execute(
            "UPDATE http_proxy_policies SET enabled = ?1 WHERE id = ?2",
            params![enabled, id.to_string()],
        )? != 0)
    }

    pub(crate) fn delete_http_proxy(
        &mut self,
        id: Uuid,
    ) -> Result<Option<HttpProxyPolicy>, HttpProxyPolicyError> {
        let policy = self.http_proxy_policy_by_id(id)?;
        if policy.is_some() {
            self.database.execute(
                "DELETE FROM http_proxy_policies WHERE id = ?1",
                [id.to_string()],
            )?;
        }
        Ok(policy)
    }

    pub(crate) fn http_proxy_policy_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<HttpProxyPolicy>, HttpProxyPolicyError> {
        self.database
            .query_row(
                "SELECT id, client_id, name, public_port, username, max_connections, bandwidth_limit_bps, enabled FROM http_proxy_policies WHERE id = ?1",
                [id.to_string()],
                read_http_proxy_policy,
            )
            .optional()
            .map_err(Into::into)
    }

    pub(crate) fn update_http_proxy(
        &mut self,
        id: Uuid,
        request: UpdateHttpProxyPolicy,
    ) -> Result<Option<HttpProxyPolicy>, HttpProxyPolicyError> {
        validate_http_proxy_policy(&request)?;
        let Some(current) = self.http_proxy_policy_by_id(id)? else {
            return Ok(None);
        };
        let duplicate_name: bool = self.database.query_row(
            "SELECT EXISTS(SELECT 1 FROM http_proxy_policies WHERE client_id = ?1 AND name = ?2 AND id <> ?3)",
            params![request.client_id.to_string(), request.name.trim(), id.to_string()],
            |row| row.get(0),
        )?;
        if duplicate_name {
            return Err(HttpProxyPolicyError::DuplicateName);
        }
        let port_in_use: bool = self.database.query_row(
            "SELECT EXISTS(SELECT 1 FROM tcp_tunnel_policies WHERE public_port = ?1 UNION ALL SELECT 1 FROM socks5_proxy_policies WHERE public_port = ?1 UNION ALL SELECT 1 FROM http_proxy_policies WHERE public_port = ?1 AND id <> ?2 UNION ALL SELECT 1 FROM port_group_mappings WHERE protocol = 'tcp' AND public_port = ?1 AND policy_id <> ?2)",
            params![request.public_port, id.to_string()],
            |row| row.get(0),
        )?;
        if port_in_use {
            return Err(HttpProxyPolicyError::DuplicatePublicPort);
        }
        let policy = HttpProxyPolicy {
            id,
            client_id: request.client_id,
            name: request.name.trim().to_owned(),
            public_port: request.public_port,
            username: request.username.trim().to_owned(),
            max_connections: request.max_connections.unwrap_or(DEFAULT_MAX_CONNECTIONS),
            bandwidth_limit_bps: request.bandwidth_limit_bps,
            enabled: current.enabled,
        };
        self.database.execute(
            "UPDATE http_proxy_policies SET client_id = ?1, name = ?2, public_port = ?3, username = ?4, max_connections = ?5, bandwidth_limit_bps = ?6 WHERE id = ?7",
            params![
                policy.client_id.to_string(),
                policy.name,
                policy.public_port,
                policy.username,
                policy.max_connections,
                policy.bandwidth_limit_bps,
                policy.id.to_string(),
            ],
        )?;
        Ok(Some(policy))
    }

    pub(crate) fn http_proxy_runtime_policy(
        &self,
        client_id: Uuid,
        name: &str,
        public_port: u16,
    ) -> Result<Option<HttpProxyRuntimePolicy>, HttpProxyPolicyError> {
        self.database
            .query_row(
                "SELECT id, username, password_hash, max_connections, bandwidth_limit_bps FROM http_proxy_policies WHERE client_id = ?1 AND name = ?2 AND public_port = ?3 AND enabled = 1",
                params![client_id.to_string(), name, public_port],
                |row| {
                    let id: String = row.get(0)?;
                    Ok(HttpProxyRuntimePolicy {
                        policy_id: Uuid::parse_str(&id)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        username: row.get(1)?,
                        password_hash: row.get(2)?,
                        max_connections: row.get::<_, i64>(3)? as usize,
                        bandwidth_limit_bps: row
                            .get::<_, Option<i64>>(4)?
                            .map(|value| value as u64),
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub(crate) fn create_udp(
        &mut self,
        request: CreateUdpTunnelPolicy,
    ) -> Result<UdpTunnelPolicy, UdpPolicyError> {
        validate_udp_policy(&request)?;
        let port_in_use: bool = self.database.query_row(
            "SELECT EXISTS(SELECT 1 FROM socks5_proxy_policies WHERE public_port = ?1 UNION ALL SELECT 1 FROM port_group_mappings WHERE protocol = 'udp' AND public_port = ?1)",
            [request.public_port],
            |row| row.get(0),
        )?;
        if port_in_use {
            return Err(UdpPolicyError::DuplicatePublicPort);
        }
        let policy = UdpTunnelPolicy {
            id: Uuid::new_v4(),
            client_id: request.client_id,
            name: request.name.trim().to_owned(),
            public_port: request.public_port,
            target_addr: request.target_addr.trim().to_owned(),
            max_sessions: request.max_sessions.unwrap_or(DEFAULT_MAX_SESSIONS),
            session_idle_timeout_seconds: request
                .session_idle_timeout_seconds
                .unwrap_or(DEFAULT_UDP_IDLE_TIMEOUT_SECONDS),
            bandwidth_limit_bps: request.bandwidth_limit_bps,
            enabled: true,
        };
        let result = self.database.execute(
            "INSERT INTO udp_tunnel_policies (id, client_id, name, public_port, target_addr, max_sessions, session_idle_timeout_seconds, bandwidth_limit_bps, enabled) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1)",
            params![
                policy.id.to_string(),
                policy.client_id.to_string(),
                policy.name,
                policy.public_port,
                policy.target_addr,
                policy.max_sessions,
                policy.session_idle_timeout_seconds,
                policy.bandwidth_limit_bps,
            ],
        );
        match result {
            Ok(_) => Ok(policy),
            Err(error) if is_constraint_violation(&error) => {
                Err(UdpPolicyError::DuplicatePublicPort)
            }
            Err(error) => Err(UdpPolicyError::Database(error)),
        }
    }

    pub(crate) fn list_udp(&self) -> Result<Vec<UdpTunnelPolicy>, UdpPolicyError> {
        let mut statement = self.database.prepare(
            "SELECT id, client_id, name, public_port, target_addr, max_sessions, session_idle_timeout_seconds, bandwidth_limit_bps, enabled FROM udp_tunnel_policies ORDER BY public_port",
        )?;
        let rows = statement.query_map([], |row| {
            let id: String = row.get(0)?;
            let client_id: String = row.get(1)?;
            Ok(UdpTunnelPolicy {
                id: Uuid::parse_str(&id).map_err(|_| rusqlite::Error::InvalidQuery)?,
                client_id: Uuid::parse_str(&client_id)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?,
                name: row.get(2)?,
                public_port: row.get(3)?,
                target_addr: row.get(4)?,
                max_sessions: row.get(5)?,
                session_idle_timeout_seconds: row.get(6)?,
                bandwidth_limit_bps: row.get(7)?,
                enabled: row.get::<_, i64>(8)? != 0,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub(crate) fn udp_policy_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<UdpTunnelPolicy>, UdpPolicyError> {
        self.database
            .query_row(
                "SELECT id, client_id, name, public_port, target_addr, max_sessions, session_idle_timeout_seconds, bandwidth_limit_bps, enabled FROM udp_tunnel_policies WHERE id = ?1",
                [id.to_string()],
                |row| {
                    let id: String = row.get(0)?;
                    let client_id: String = row.get(1)?;
                    Ok(UdpTunnelPolicy {
                        id: Uuid::parse_str(&id).map_err(|_| rusqlite::Error::InvalidQuery)?,
                        client_id: Uuid::parse_str(&client_id)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        name: row.get(2)?,
                        public_port: row.get(3)?,
                        target_addr: row.get(4)?,
                        max_sessions: row.get(5)?,
                        session_idle_timeout_seconds: row.get(6)?,
                        bandwidth_limit_bps: row.get(7)?,
                        enabled: row.get::<_, i64>(8)? != 0,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub(crate) fn update_udp(
        &mut self,
        id: Uuid,
        request: UpdateUdpTunnelPolicy,
    ) -> Result<Option<UdpTunnelPolicy>, UdpPolicyError> {
        validate_udp_policy(&request)?;
        let Some(current) = self.udp_policy_by_id(id)? else {
            return Ok(None);
        };
        let port_in_use: bool = self.database.query_row(
            "SELECT EXISTS(SELECT 1 FROM udp_tunnel_policies WHERE public_port = ?1 AND id <> ?2 UNION ALL SELECT 1 FROM socks5_proxy_policies WHERE public_port = ?1 UNION ALL SELECT 1 FROM port_group_mappings WHERE protocol = 'udp' AND public_port = ?1 AND policy_id <> ?2)",
            params![request.public_port, id.to_string()],
            |row| row.get(0),
        )?;
        if port_in_use {
            return Err(UdpPolicyError::DuplicatePublicPort);
        }
        let policy = UdpTunnelPolicy {
            id,
            client_id: request.client_id,
            name: request.name.trim().to_owned(),
            public_port: request.public_port,
            target_addr: request.target_addr.trim().to_owned(),
            max_sessions: request.max_sessions.unwrap_or(DEFAULT_MAX_SESSIONS),
            session_idle_timeout_seconds: request
                .session_idle_timeout_seconds
                .unwrap_or(DEFAULT_UDP_IDLE_TIMEOUT_SECONDS),
            bandwidth_limit_bps: request.bandwidth_limit_bps,
            enabled: current.enabled,
        };
        self.database.execute(
            "UPDATE udp_tunnel_policies SET client_id = ?1, name = ?2, public_port = ?3, target_addr = ?4, max_sessions = ?5, session_idle_timeout_seconds = ?6, bandwidth_limit_bps = ?7 WHERE id = ?8",
            params![
                policy.client_id.to_string(),
                policy.name,
                policy.public_port,
                policy.target_addr,
                policy.max_sessions,
                policy.session_idle_timeout_seconds,
                policy.bandwidth_limit_bps,
                policy.id.to_string(),
            ],
        )?;
        Ok(Some(policy))
    }

    pub(crate) fn set_udp_enabled(
        &mut self,
        id: Uuid,
        enabled: bool,
    ) -> Result<bool, UdpPolicyError> {
        Ok(self.database.execute(
            "UPDATE udp_tunnel_policies SET enabled = ?1 WHERE id = ?2",
            params![enabled, id.to_string()],
        )? != 0)
    }

    pub(crate) fn delete_udp(&mut self, id: Uuid) -> Result<bool, UdpPolicyError> {
        Ok(self.database.execute(
            "DELETE FROM udp_tunnel_policies WHERE id = ?1",
            [id.to_string()],
        )? != 0)
    }

    pub(crate) fn udp_runtime_policy(
        &self,
        client_id: Uuid,
        name: &str,
        public_port: u16,
        target_addr: &str,
    ) -> Result<Option<UdpTunnelRuntimePolicy>, UdpPolicyError> {
        let value: Option<(String, i64, i64, Option<i64>)> = self.database.query_row(
            "SELECT id, max_sessions, session_idle_timeout_seconds, bandwidth_limit_bps FROM udp_tunnel_policies WHERE client_id = ?1 AND name = ?2 AND public_port = ?3 AND target_addr = ?4 AND enabled = 1",
            params![client_id.to_string(), name, public_port, target_addr],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        ).optional()?;
        if let Some(value) = value {
            return Some(value)
                .map(
                    |(
                        policy_id,
                        max_sessions,
                        session_idle_timeout_seconds,
                        bandwidth_limit_bps,
                    )|
                     -> Result<UdpTunnelRuntimePolicy, rusqlite::Error> {
                        Ok(UdpTunnelRuntimePolicy {
                            policy_id: Uuid::parse_str(&policy_id)
                                .map_err(|_| rusqlite::Error::InvalidQuery)?,
                            max_sessions: max_sessions as usize,
                            session_idle_timeout_seconds: session_idle_timeout_seconds as u64,
                            bandwidth_limit_bps: bandwidth_limit_bps.map(|value| value as u64),
                        })
                    },
                )
                .transpose()
                .map_err(Into::into);
        }
        let value: Option<(String, i64, i64, Option<i64>)> = self.database.query_row(
            "SELECT p.id, p.max_sessions, p.session_idle_timeout_seconds, p.bandwidth_limit_bps FROM port_group_policies p JOIN port_group_mappings m ON m.policy_id = p.id WHERE p.client_id = ?1 AND p.protocol = 'udp' AND p.name = ?2 AND m.public_port = ?3 AND m.target_addr = ?4 AND p.enabled = 1",
            params![client_id.to_string(), name, public_port, target_addr],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        ).optional()?;
        value
            .map(
                |(policy_id, max_sessions, session_idle_timeout_seconds, bandwidth_limit_bps)| -> Result<UdpTunnelRuntimePolicy, rusqlite::Error> {
                    Ok(UdpTunnelRuntimePolicy {
                        policy_id: Uuid::parse_str(&policy_id)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        max_sessions: max_sessions as usize,
                        session_idle_timeout_seconds: session_idle_timeout_seconds as u64,
                        bandwidth_limit_bps: bandwidth_limit_bps.map(|value| value as u64),
                    })
                },
            )
            .transpose()
            .map_err(Into::into)
    }

    pub(crate) fn create_port_group(
        &mut self,
        request: CreatePortGroupPolicy,
    ) -> Result<PortGroupPolicy, PortGroupPolicyError> {
        let parsed = validate_port_group_policy(&request)?;
        let target_host = request.target_host.trim().to_owned();
        let policy = PortGroupPolicy {
            id: Uuid::new_v4(),
            client_id: request.client_id,
            name: request.name.trim().to_owned(),
            protocol: request.protocol,
            public_ports: parsed.public_ports.clone(),
            target_host: target_host.clone(),
            target_ports: parsed.target_ports.clone(),
            mapping_count: parsed.pairs.len(),
            max_connections: request.max_connections.unwrap_or(DEFAULT_MAX_CONNECTIONS),
            max_sessions: request.max_sessions.unwrap_or(DEFAULT_MAX_SESSIONS),
            session_idle_timeout_seconds: request
                .session_idle_timeout_seconds
                .unwrap_or(DEFAULT_UDP_IDLE_TIMEOUT_SECONDS),
            bandwidth_limit_bps: request.bandwidth_limit_bps,
            enabled: true,
        };

        let transaction = self.database.transaction()?;
        for pair in &parsed.pairs {
            let conflict: bool = match request.protocol {
                PortGroupProtocol::Tcp => transaction.query_row(
                    "SELECT EXISTS(SELECT 1 FROM tcp_tunnel_policies WHERE public_port = ?1 UNION ALL SELECT 1 FROM socks5_proxy_policies WHERE public_port = ?1 UNION ALL SELECT 1 FROM http_proxy_policies WHERE public_port = ?1 UNION ALL SELECT 1 FROM port_group_mappings WHERE protocol = 'tcp' AND public_port = ?1)",
                    [pair.public_port],
                    |row| row.get(0),
                )?,
                PortGroupProtocol::Udp => transaction.query_row(
                    "SELECT EXISTS(SELECT 1 FROM udp_tunnel_policies WHERE public_port = ?1 UNION ALL SELECT 1 FROM socks5_proxy_policies WHERE public_port = ?1 UNION ALL SELECT 1 FROM port_group_mappings WHERE protocol = 'udp' AND public_port = ?1)",
                    [pair.public_port],
                    |row| row.get(0),
                )?,
            };
            if conflict {
                return Err(PortGroupPolicyError::DuplicatePublicPort);
            }
        }

        let insertion = transaction.execute(
            "INSERT INTO port_group_policies (id, client_id, name, protocol, public_ports, target_host, target_ports, mapping_count, max_connections, max_sessions, session_idle_timeout_seconds, bandwidth_limit_bps, enabled) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 1)",
            params![
                policy.id.to_string(),
                policy.client_id.to_string(),
                policy.name,
                policy.protocol.as_str(),
                policy.public_ports,
                policy.target_host,
                policy.target_ports,
                policy.mapping_count,
                policy.max_connections,
                policy.max_sessions,
                policy.session_idle_timeout_seconds,
                policy.bandwidth_limit_bps,
            ],
        );
        if let Err(error) = insertion {
            if is_constraint_violation(&error) {
                return Err(PortGroupPolicyError::DuplicateName);
            }
            return Err(PortGroupPolicyError::Database(error));
        }
        for pair in parsed.pairs {
            transaction.execute(
                "INSERT INTO port_group_mappings (policy_id, protocol, public_port, target_port, target_addr) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    policy.id.to_string(),
                    policy.protocol.as_str(),
                    pair.public_port,
                    pair.target_port,
                    target_addr(&target_host, pair.target_port),
                ],
            )?;
        }
        transaction.commit()?;
        Ok(policy)
    }

    pub(crate) fn list_port_groups(&self) -> Result<Vec<PortGroupPolicy>, PortGroupPolicyError> {
        let mut statement = self.database.prepare(
            "SELECT id, client_id, name, protocol, public_ports, target_host, target_ports, mapping_count, max_connections, max_sessions, session_idle_timeout_seconds, bandwidth_limit_bps, enabled FROM port_group_policies ORDER BY protocol, public_ports",
        )?;
        let rows = statement.query_map([], read_port_group_policy)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub(crate) fn port_group_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<PortGroupPolicy>, PortGroupPolicyError> {
        self.database
            .query_row(
                "SELECT id, client_id, name, protocol, public_ports, target_host, target_ports, mapping_count, max_connections, max_sessions, session_idle_timeout_seconds, bandwidth_limit_bps, enabled FROM port_group_policies WHERE id = ?1",
                [id.to_string()],
                read_port_group_policy,
            )
            .optional()
            .map_err(Into::into)
    }

    pub(crate) fn update_port_group(
        &mut self,
        id: Uuid,
        request: UpdatePortGroupPolicy,
    ) -> Result<Option<PortGroupPolicy>, PortGroupPolicyError> {
        let parsed = validate_port_group_policy(&request)?;
        let Some(current) = self.port_group_by_id(id)? else {
            return Ok(None);
        };
        let target_host = request.target_host.trim().to_owned();
        let duplicate_name: bool = self.database.query_row(
            "SELECT EXISTS(SELECT 1 FROM port_group_policies WHERE client_id = ?1 AND protocol = ?2 AND name = ?3 AND id <> ?4)",
            params![
                request.client_id.to_string(),
                request.protocol.as_str(),
                request.name.trim(),
                id.to_string()
            ],
            |row| row.get(0),
        )?;
        if duplicate_name {
            return Err(PortGroupPolicyError::DuplicateName);
        }
        let policy = PortGroupPolicy {
            id,
            client_id: request.client_id,
            name: request.name.trim().to_owned(),
            protocol: request.protocol,
            public_ports: parsed.public_ports.clone(),
            target_host: target_host.clone(),
            target_ports: parsed.target_ports.clone(),
            mapping_count: parsed.pairs.len(),
            max_connections: request.max_connections.unwrap_or(DEFAULT_MAX_CONNECTIONS),
            max_sessions: request.max_sessions.unwrap_or(DEFAULT_MAX_SESSIONS),
            session_idle_timeout_seconds: request
                .session_idle_timeout_seconds
                .unwrap_or(DEFAULT_UDP_IDLE_TIMEOUT_SECONDS),
            bandwidth_limit_bps: request.bandwidth_limit_bps,
            enabled: current.enabled,
        };

        let transaction = self.database.transaction()?;
        for pair in &parsed.pairs {
            let conflict: bool = match request.protocol {
                PortGroupProtocol::Tcp => transaction.query_row(
                    "SELECT EXISTS(SELECT 1 FROM tcp_tunnel_policies WHERE public_port = ?1 UNION ALL SELECT 1 FROM socks5_proxy_policies WHERE public_port = ?1 UNION ALL SELECT 1 FROM http_proxy_policies WHERE public_port = ?1 UNION ALL SELECT 1 FROM port_group_mappings WHERE protocol = 'tcp' AND public_port = ?1 AND policy_id <> ?2)",
                    params![pair.public_port, id.to_string()],
                    |row| row.get(0),
                )?,
                PortGroupProtocol::Udp => transaction.query_row(
                    "SELECT EXISTS(SELECT 1 FROM udp_tunnel_policies WHERE public_port = ?1 UNION ALL SELECT 1 FROM socks5_proxy_policies WHERE public_port = ?1 UNION ALL SELECT 1 FROM port_group_mappings WHERE protocol = 'udp' AND public_port = ?1 AND policy_id <> ?2)",
                    params![pair.public_port, id.to_string()],
                    |row| row.get(0),
                )?,
            };
            if conflict {
                return Err(PortGroupPolicyError::DuplicatePublicPort);
            }
        }

        let insertion = transaction.execute(
            "UPDATE port_group_policies SET client_id = ?1, name = ?2, protocol = ?3, public_ports = ?4, target_host = ?5, target_ports = ?6, mapping_count = ?7, max_connections = ?8, max_sessions = ?9, session_idle_timeout_seconds = ?10, bandwidth_limit_bps = ?11 WHERE id = ?12",
            params![
                policy.client_id.to_string(),
                policy.name,
                policy.protocol.as_str(),
                policy.public_ports,
                policy.target_host,
                policy.target_ports,
                policy.mapping_count,
                policy.max_connections,
                policy.max_sessions,
                policy.session_idle_timeout_seconds,
                policy.bandwidth_limit_bps,
                policy.id.to_string(),
            ],
        );
        if let Err(error) = insertion {
            if is_constraint_violation(&error) {
                return Err(PortGroupPolicyError::DuplicateName);
            }
            return Err(PortGroupPolicyError::Database(error));
        }
        transaction.execute(
            "DELETE FROM port_group_mappings WHERE policy_id = ?1",
            [id.to_string()],
        )?;
        for pair in parsed.pairs {
            transaction.execute(
                "INSERT INTO port_group_mappings (policy_id, protocol, public_port, target_port, target_addr) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    policy.id.to_string(),
                    policy.protocol.as_str(),
                    pair.public_port,
                    pair.target_port,
                    target_addr(&target_host, pair.target_port),
                ],
            )?;
        }
        transaction.commit()?;
        Ok(Some(policy))
    }

    pub(crate) fn port_group_mappings(
        &self,
        id: Uuid,
    ) -> Result<Vec<PortGroupMapping>, PortGroupPolicyError> {
        let mut statement = self.database.prepare(
            "SELECT public_port, target_port, target_addr FROM port_group_mappings WHERE policy_id = ?1 ORDER BY rowid",
        )?;
        let rows = statement.query_map([id.to_string()], |row| {
            Ok(PortGroupMapping {
                public_port: row.get(0)?,
                target_port: row.get(1)?,
                target_addr: row.get(2)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub(crate) fn set_port_group_enabled(
        &mut self,
        id: Uuid,
        enabled: bool,
    ) -> Result<bool, PortGroupPolicyError> {
        Ok(self.database.execute(
            "UPDATE port_group_policies SET enabled = ?1 WHERE id = ?2",
            params![enabled, id.to_string()],
        )? != 0)
    }

    pub(crate) fn delete_port_group(
        &mut self,
        id: Uuid,
    ) -> Result<Option<PortGroupPolicy>, PortGroupPolicyError> {
        let policy = self.port_group_by_id(id)?;
        if policy.is_none() {
            return Ok(None);
        }
        let transaction = self.database.transaction()?;
        transaction.execute(
            "DELETE FROM port_group_mappings WHERE policy_id = ?1",
            [id.to_string()],
        )?;
        transaction.execute(
            "DELETE FROM port_group_policies WHERE id = ?1",
            [id.to_string()],
        )?;
        transaction.commit()?;
        Ok(policy)
    }
}

fn read_port_group_policy(row: &rusqlite::Row<'_>) -> rusqlite::Result<PortGroupPolicy> {
    let id: String = row.get(0)?;
    let client_id: String = row.get(1)?;
    let protocol: String = row.get(3)?;
    Ok(PortGroupPolicy {
        id: Uuid::parse_str(&id).map_err(|_| rusqlite::Error::InvalidQuery)?,
        client_id: Uuid::parse_str(&client_id).map_err(|_| rusqlite::Error::InvalidQuery)?,
        name: row.get(2)?,
        protocol: PortGroupProtocol::parse(&protocol)?,
        public_ports: row.get(4)?,
        target_host: row.get(5)?,
        target_ports: row.get(6)?,
        mapping_count: row.get(7)?,
        max_connections: row.get(8)?,
        max_sessions: row.get(9)?,
        session_idle_timeout_seconds: row.get(10)?,
        bandwidth_limit_bps: row.get(11)?,
        enabled: row.get::<_, i64>(12)? != 0,
    })
}

fn validate_port_group_policy(
    request: &CreatePortGroupPolicy,
) -> Result<ParsedPortMappings, PortGroupPolicyError> {
    let name = request.name.trim();
    if name.is_empty() || name.len() > 64 {
        return Err(PortGroupPolicyError::InvalidName);
    }
    let target_host = request.target_host.trim();
    if !valid_target_host(target_host) {
        return Err(PortGroupPolicyError::InvalidTargetHost);
    }
    if !(1..=1_024).contains(&request.max_connections.unwrap_or(DEFAULT_MAX_CONNECTIONS)) {
        return Err(PortGroupPolicyError::InvalidConnectionLimit);
    }
    if request.max_sessions == Some(0)
        || request
            .max_sessions
            .is_some_and(|value| value > MAX_UDP_SESSIONS)
    {
        return Err(PortGroupPolicyError::InvalidSessionLimit);
    }
    if request.session_idle_timeout_seconds.is_some_and(|value| {
        !(MIN_UDP_IDLE_TIMEOUT_SECONDS..=MAX_UDP_IDLE_TIMEOUT_SECONDS).contains(&value)
    }) {
        return Err(PortGroupPolicyError::InvalidIdleTimeout);
    }
    if request
        .bandwidth_limit_bps
        .is_some_and(|value| !(MIN_BANDWIDTH_LIMIT_BPS..=MAX_BANDWIDTH_LIMIT_BPS).contains(&value))
    {
        return Err(PortGroupPolicyError::InvalidBandwidthLimit);
    }
    parse_port_mappings(
        &request.public_ports,
        &request.target_ports,
        MIN_TCP_TUNNEL_PORT,
        MAX_TCP_TUNNEL_PORT,
        MAX_PORT_MAPPINGS,
    )
    .map_err(PortGroupPolicyError::InvalidPorts)
}

fn target_addr(host: &str, port: u16) -> String {
    if host.parse::<Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn valid_target_host(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 253
        || value.bytes().any(|byte| byte.is_ascii_whitespace())
        || value.contains('/')
        || value.contains('[')
        || value.contains(']')
    {
        return false;
    }
    if value.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    if value.contains(':') {
        return false;
    }
    value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

fn read_socks5_policy(row: &rusqlite::Row<'_>) -> rusqlite::Result<Socks5ProxyPolicy> {
    let id: String = row.get(0)?;
    let client_id: String = row.get(1)?;
    Ok(Socks5ProxyPolicy {
        id: Uuid::parse_str(&id).map_err(|_| rusqlite::Error::InvalidQuery)?,
        client_id: Uuid::parse_str(&client_id).map_err(|_| rusqlite::Error::InvalidQuery)?,
        name: row.get(2)?,
        public_port: row.get(3)?,
        username: row.get(4)?,
        max_connections: row.get(5)?,
        bandwidth_limit_bps: row.get(6)?,
        enabled: row.get::<_, i64>(7)? != 0,
    })
}

fn read_http_proxy_policy(row: &rusqlite::Row<'_>) -> rusqlite::Result<HttpProxyPolicy> {
    let id: String = row.get(0)?;
    let client_id: String = row.get(1)?;
    Ok(HttpProxyPolicy {
        id: Uuid::parse_str(&id).map_err(|_| rusqlite::Error::InvalidQuery)?,
        client_id: Uuid::parse_str(&client_id).map_err(|_| rusqlite::Error::InvalidQuery)?,
        name: row.get(2)?,
        public_port: row.get(3)?,
        username: row.get(4)?,
        max_connections: row.get(5)?,
        bandwidth_limit_bps: row.get(6)?,
        enabled: row.get::<_, i64>(7)? != 0,
    })
}

fn validate_socks5_policy(request: &CreateSocks5ProxyPolicy) -> Result<(), Socks5PolicyError> {
    let name = request.name.trim();
    if name.is_empty() || name.len() > 80 || name.chars().any(char::is_control) {
        return Err(Socks5PolicyError::InvalidName);
    }
    if !(MIN_TCP_TUNNEL_PORT..=MAX_TCP_TUNNEL_PORT).contains(&request.public_port) {
        return Err(Socks5PolicyError::InvalidPublicPort);
    }
    let username = request.username.trim();
    if username != request.username
        || username.is_empty()
        || username.len() > 64
        || !username
            .bytes()
            .all(|value| value.is_ascii_alphanumeric() || matches!(value, b'.' | b'_' | b'-'))
    {
        return Err(Socks5PolicyError::InvalidUsername);
    }
    if !(1..=1_024).contains(&request.max_connections.unwrap_or(DEFAULT_MAX_CONNECTIONS)) {
        return Err(Socks5PolicyError::InvalidConnectionLimit);
    }
    if request
        .bandwidth_limit_bps
        .is_some_and(|limit| !(MIN_BANDWIDTH_LIMIT_BPS..=MAX_BANDWIDTH_LIMIT_BPS).contains(&limit))
    {
        return Err(Socks5PolicyError::InvalidBandwidthLimit);
    }
    Ok(())
}

fn validate_http_proxy_policy(request: &CreateHttpProxyPolicy) -> Result<(), HttpProxyPolicyError> {
    let name = request.name.trim();
    if name.is_empty() || name.len() > 80 || name.chars().any(char::is_control) {
        return Err(HttpProxyPolicyError::InvalidName);
    }
    if !(MIN_TCP_TUNNEL_PORT..=MAX_TCP_TUNNEL_PORT).contains(&request.public_port) {
        return Err(HttpProxyPolicyError::InvalidPublicPort);
    }
    let username = request.username.trim();
    if username != request.username
        || username.is_empty()
        || username.len() > 64
        || !username
            .bytes()
            .all(|value| value.is_ascii_alphanumeric() || matches!(value, b'.' | b'_' | b'-'))
    {
        return Err(HttpProxyPolicyError::InvalidUsername);
    }
    if !(1..=1_024).contains(&request.max_connections.unwrap_or(DEFAULT_MAX_CONNECTIONS)) {
        return Err(HttpProxyPolicyError::InvalidConnectionLimit);
    }
    if request
        .bandwidth_limit_bps
        .is_some_and(|limit| !(MIN_BANDWIDTH_LIMIT_BPS..=MAX_BANDWIDTH_LIMIT_BPS).contains(&limit))
    {
        return Err(HttpProxyPolicyError::InvalidBandwidthLimit);
    }
    Ok(())
}

pub(crate) fn socks5_password_matches(password: &[u8], expected_hash: &str) -> bool {
    if password.len() != 68
        || !password.starts_with(b"llp_")
        || !password[4..].iter().all(u8::is_ascii_hexdigit)
    {
        return false;
    }
    hash_socks5_password_bytes(password) == expected_hash
}

fn hash_socks5_password(password: &str) -> String {
    hash_socks5_password_bytes(password.as_bytes())
}

fn hash_socks5_password_bytes(password: &[u8]) -> String {
    format!("{:x}", Sha256::digest(password))
}

pub(crate) fn http_proxy_password_matches(password: &[u8], expected_hash: &str) -> bool {
    if password.len() != 68
        || !password.starts_with(b"llh_")
        || !password[4..].iter().all(u8::is_ascii_hexdigit)
    {
        return false;
    }
    hash_http_proxy_password_bytes(password) == expected_hash
}

fn hash_http_proxy_password(password: &str) -> String {
    hash_http_proxy_password_bytes(password.as_bytes())
}

fn hash_http_proxy_password_bytes(password: &[u8]) -> String {
    format!("{:x}", Sha256::digest(password))
}

fn validate_policy(request: &CreateTcpTunnelPolicy) -> anyhow::Result<()> {
    anyhow::ensure!(
        !request.name.trim().is_empty() && request.name.len() <= 80,
        "tunnel name is invalid"
    );
    anyhow::ensure!(
        (MIN_TCP_TUNNEL_PORT..=MAX_TCP_TUNNEL_PORT).contains(&request.public_port),
        "public port is outside the permitted range"
    );
    anyhow::ensure!(
        valid_target_address(request.target_addr.trim()) && request.target_addr.len() <= 255,
        "target address is invalid"
    );
    anyhow::ensure!(
        request.max_connections.unwrap_or(DEFAULT_MAX_CONNECTIONS) >= 1
            && request.max_connections.unwrap_or(DEFAULT_MAX_CONNECTIONS) <= 1024,
        "connection limit is invalid"
    );
    anyhow::ensure!(
        request.bandwidth_limit_bps.is_none_or(|limit| {
            (MIN_BANDWIDTH_LIMIT_BPS..=MAX_BANDWIDTH_LIMIT_BPS).contains(&limit)
        }),
        "bandwidth limit is invalid"
    );
    Ok(())
}

fn valid_target_address(value: &str) -> bool {
    if value.parse::<std::net::SocketAddr>().is_ok() {
        return true;
    }
    let Some((host, port)) = value.rsplit_once(':') else {
        return false;
    };
    !host.is_empty()
        && !host.chars().any(char::is_whitespace)
        && port.parse::<u16>().is_ok_and(|port| port != 0)
}

fn validate_udp_policy(request: &CreateUdpTunnelPolicy) -> Result<(), UdpPolicyError> {
    let name = request.name.trim();
    if name.is_empty() || name.len() > 80 || name.chars().any(char::is_control) {
        return Err(UdpPolicyError::InvalidName);
    }
    if !(MIN_UDP_TUNNEL_PORT..=MAX_UDP_TUNNEL_PORT).contains(&request.public_port) {
        return Err(UdpPolicyError::InvalidPublicPort);
    }
    let target = request.target_addr.trim();
    if target != request.target_addr || target.len() > 255 || !valid_udp_target_address(target) {
        return Err(UdpPolicyError::InvalidTarget);
    }
    if !(1..=MAX_UDP_SESSIONS).contains(&request.max_sessions.unwrap_or(DEFAULT_MAX_SESSIONS)) {
        return Err(UdpPolicyError::InvalidSessionLimit);
    }
    if !(MIN_UDP_IDLE_TIMEOUT_SECONDS..=MAX_UDP_IDLE_TIMEOUT_SECONDS).contains(
        &request
            .session_idle_timeout_seconds
            .unwrap_or(DEFAULT_UDP_IDLE_TIMEOUT_SECONDS),
    ) {
        return Err(UdpPolicyError::InvalidIdleTimeout);
    }
    if request
        .bandwidth_limit_bps
        .is_some_and(|limit| !(MIN_BANDWIDTH_LIMIT_BPS..=MAX_BANDWIDTH_LIMIT_BPS).contains(&limit))
    {
        return Err(UdpPolicyError::InvalidBandwidthLimit);
    }
    Ok(())
}

// UDP 目标只接受 IP socket 地址或严格的 ASCII DNS 主机名加端口。
fn valid_udp_target_address(value: &str) -> bool {
    if value.is_empty()
        || value.chars().any(|character| {
            character.is_whitespace()
                || character.is_control()
                || matches!(character, '/' | '\\' | '?' | '#' | '@')
        })
        || value.contains("://")
    {
        return false;
    }
    if let Ok(address) = value.parse::<std::net::SocketAddr>() {
        return address.port() != 0;
    }
    let Some((host, port)) = value.rsplit_once(':') else {
        return false;
    };
    if host.is_empty()
        || host.len() > 253
        || host.contains(':')
        || !port.parse::<u16>().is_ok_and(|port| port != 0)
    {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

fn is_constraint_violation(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(database_error, _)
            if database_error.code == ErrorCode::ConstraintViolation
    )
}

#[cfg(test)]
mod tests {
    use super::{
        http_proxy_password_matches, socks5_password_matches, CreateHttpProxyPolicy,
        CreatePortGroupPolicy, CreateSocks5ProxyPolicy, CreateTcpTunnelPolicy,
        CreateUdpTunnelPolicy, HttpProxyPolicyError, PortGroupPolicyError, PortGroupProtocol,
        Socks5PolicyError, TunnelCatalog, UdpPolicyError, UdpTunnelRuntimePolicy,
    };
    use std::fs;
    use uuid::Uuid;

    fn udp_request(client_id: Uuid, public_port: u16) -> CreateUdpTunnelPolicy {
        CreateUdpTunnelPolicy {
            client_id,
            name: "dns-relay".to_owned(),
            public_port,
            target_addr: "resolver.example.com:53".to_owned(),
            max_sessions: None,
            session_idle_timeout_seconds: None,
            bandwidth_limit_bps: None,
        }
    }

    fn socks5_request(client_id: Uuid, public_port: u16) -> CreateSocks5ProxyPolicy {
        CreateSocks5ProxyPolicy {
            client_id,
            name: "office-exit".to_owned(),
            public_port,
            username: "linklake-user".to_owned(),
            max_connections: Some(8),
            bandwidth_limit_bps: Some(1_048_576),
        }
    }

    fn http_proxy_request(client_id: Uuid, public_port: u16) -> CreateHttpProxyPolicy {
        CreateHttpProxyPolicy {
            client_id,
            name: "web-exit".to_owned(),
            public_port,
            username: "proxy-user".to_owned(),
            max_connections: Some(8),
            bandwidth_limit_bps: Some(1_048_576),
        }
    }

    fn port_group_request(
        client_id: Uuid,
        protocol: PortGroupProtocol,
        public_ports: &str,
    ) -> CreatePortGroupPolicy {
        CreatePortGroupPolicy {
            client_id,
            name: "game-range".to_owned(),
            protocol,
            public_ports: public_ports.to_owned(),
            target_host: "127.0.0.1".to_owned(),
            target_ports: "2333,2400-2402".to_owned(),
            max_connections: Some(12),
            max_sessions: Some(24),
            session_idle_timeout_seconds: Some(90),
            bandwidth_limit_bps: Some(1_000_000),
        }
    }

    #[test]
    fn tcp_port_group_persists_mappings_and_authorizes_exact_registrations() {
        let client_id = Uuid::new_v4();
        let mut catalog = TunnelCatalog::open(None).expect("catalog should open");
        let policy = catalog
            .create_port_group(port_group_request(
                client_id,
                PortGroupProtocol::Tcp,
                "32001,32010-32012",
            ))
            .expect("port group should create");
        assert_eq!(policy.public_ports, "32001,32010-32012");
        assert_eq!(policy.target_ports, "2333,2400-2402");
        assert_eq!(policy.mapping_count, 4);
        let mappings = catalog
            .port_group_mappings(policy.id)
            .expect("mappings should list");
        assert_eq!(mappings[0].target_addr, "127.0.0.1:2333");
        assert_eq!(mappings[3].target_addr, "127.0.0.1:2402");
        assert_eq!(
            catalog
                .runtime_policy(client_id, "game-range", 32011, "127.0.0.1:2401")
                .expect("runtime policy should query"),
            Some(super::TcpTunnelRuntimePolicy {
                max_connections: 12,
                bandwidth_limit_bps: Some(1_000_000),
            })
        );
        assert!(catalog
            .runtime_policy(client_id, "game-range", 32011, "127.0.0.1:2402")
            .expect("runtime policy should query")
            .is_none());
        catalog
            .set_port_group_enabled(policy.id, false)
            .expect("group should disable");
        assert!(catalog
            .runtime_policy(client_id, "game-range", 32011, "127.0.0.1:2401")
            .expect("runtime policy should query")
            .is_none());
    }

    #[test]
    fn udp_port_group_uses_one_policy_identity_and_allows_same_numeric_tcp_ports() {
        let client_id = Uuid::new_v4();
        let mut catalog = TunnelCatalog::open(None).expect("catalog should open");
        let policy = catalog
            .create_port_group(port_group_request(
                client_id,
                PortGroupProtocol::Udp,
                "32020-32023",
            ))
            .expect("UDP port group should create");
        catalog
            .create(CreateTcpTunnelPolicy {
                client_id,
                name: "same-number-tcp".to_owned(),
                public_port: 32020,
                target_addr: "127.0.0.1:80".to_owned(),
                max_connections: None,
                bandwidth_limit_bps: None,
            })
            .expect("TCP may use the same numeric port");
        let runtime = catalog
            .udp_runtime_policy(client_id, "game-range", 32022, "127.0.0.1:2401")
            .expect("runtime policy should query")
            .expect("mapping should authorize");
        assert_eq!(runtime.policy_id, policy.id);
        assert_eq!(runtime.max_sessions, 24);
        assert_eq!(runtime.session_idle_timeout_seconds, 90);
    }

    #[test]
    fn port_groups_share_protocol_namespaces_with_single_ports_and_proxies() {
        let client_id = Uuid::new_v4();
        let mut catalog = TunnelCatalog::open(None).expect("catalog should open");
        catalog
            .create_port_group(port_group_request(
                client_id,
                PortGroupProtocol::Tcp,
                "32030-32033",
            ))
            .expect("TCP port group should create");
        assert!(catalog
            .create(CreateTcpTunnelPolicy {
                client_id,
                name: "conflict".to_owned(),
                public_port: 32031,
                target_addr: "127.0.0.1:80".to_owned(),
                max_connections: None,
                bandwidth_limit_bps: None,
            })
            .is_err());
        let mut proxy = http_proxy_request(client_id, 32032);
        proxy.name = "conflict-http".to_owned();
        assert!(matches!(
            catalog.create_http_proxy(proxy),
            Err(HttpProxyPolicyError::DuplicatePublicPort)
        ));

        catalog
            .create_udp(udp_request(client_id, 32040))
            .expect("UDP single policy should create");
        let mut group = port_group_request(client_id, PortGroupProtocol::Udp, "32040-32043");
        group.name = "udp-conflict".to_owned();
        assert!(matches!(
            catalog.create_port_group(group),
            Err(PortGroupPolicyError::DuplicatePublicPort)
        ));
    }

    #[test]
    fn socks5_reserves_both_tcp_and_udp_namespaces() {
        let client_id = Uuid::new_v4();
        let mut catalog = TunnelCatalog::open(None).expect("catalog should open");
        catalog
            .create_udp(udp_request(client_id, 32050))
            .expect("UDP policy should create");
        assert!(matches!(
            catalog.create_socks5(socks5_request(client_id, 32050)),
            Err(Socks5PolicyError::DuplicatePublicPort)
        ));
        catalog
            .create_socks5(socks5_request(client_id, 32051))
            .expect("SOCKS5 policy should create");
        assert!(matches!(
            catalog.create_udp(udp_request(client_id, 32051)),
            Err(UdpPolicyError::DuplicatePublicPort)
        ));
    }

    #[test]
    fn http_proxy_credentials_are_returned_once_and_registration_is_exact() {
        let client_id = Uuid::new_v4();
        let mut catalog = TunnelCatalog::open(None).expect("catalog should open");
        let created = catalog
            .create_http_proxy(http_proxy_request(client_id, 32045))
            .expect("HTTP proxy policy should create");
        assert!(created.password.starts_with("llh_"));
        assert_eq!(created.password.len(), 68);
        let runtime = catalog
            .http_proxy_runtime_policy(client_id, "web-exit", 32045)
            .expect("runtime policy should query")
            .expect("runtime policy should match");
        assert_eq!(runtime.policy_id, created.policy.id);
        assert!(http_proxy_password_matches(
            created.password.as_bytes(),
            &runtime.password_hash
        ));
        assert!(catalog
            .http_proxy_runtime_policy(client_id, "other", 32045)
            .expect("runtime policy should query")
            .is_none());
    }

    #[test]
    fn tcp_socks5_and_http_proxy_share_the_tcp_port_namespace() {
        let client_id = Uuid::new_v4();
        let mut catalog = TunnelCatalog::open(None).expect("catalog should open");
        catalog
            .create_http_proxy(http_proxy_request(client_id, 32046))
            .expect("HTTP proxy policy should create");
        assert!(catalog
            .create(CreateTcpTunnelPolicy {
                client_id,
                name: "tcp-conflict".to_owned(),
                public_port: 32046,
                target_addr: "127.0.0.1:1".to_owned(),
                max_connections: None,
                bandwidth_limit_bps: None,
            })
            .is_err());
        let mut socks = socks5_request(client_id, 32046);
        socks.name = "socks-conflict".to_owned();
        assert!(matches!(
            catalog.create_socks5(socks),
            Err(Socks5PolicyError::DuplicatePublicPort)
        ));

        catalog
            .create_socks5(socks5_request(client_id, 32047))
            .expect("SOCKS5 policy should create");
        let mut http = http_proxy_request(client_id, 32047);
        http.name = "http-conflict".to_owned();
        assert!(matches!(
            catalog.create_http_proxy(http),
            Err(HttpProxyPolicyError::DuplicatePublicPort)
        ));
    }

    #[test]
    fn socks5_credentials_are_returned_once_and_exact_registration_is_required() {
        let client_id = Uuid::new_v4();
        let mut catalog = TunnelCatalog::open(None).expect("catalog should open");
        let created = catalog
            .create_socks5(socks5_request(client_id, 32040))
            .expect("SOCKS5 policy should create");
        assert!(created.password.starts_with("llp_"));
        assert_eq!(created.password.len(), 68);
        assert_eq!(
            catalog.list_socks5().expect("policies should list").len(),
            1
        );
        let runtime = catalog
            .socks5_runtime_policy(client_id, "office-exit", 32040)
            .expect("runtime policy should query")
            .expect("runtime policy should match");
        assert_eq!(runtime.policy_id, created.policy.id);
        assert_eq!(runtime.username, "linklake-user");
        assert!(socks5_password_matches(
            created.password.as_bytes(),
            &runtime.password_hash
        ));
        assert!(!socks5_password_matches(
            format!("llp_{}", "0".repeat(64)).as_bytes(),
            &runtime.password_hash
        ));
        assert!(catalog
            .socks5_runtime_policy(client_id, "other", 32040)
            .expect("runtime policy should query")
            .is_none());
    }

    #[test]
    fn socks5_and_tcp_share_the_tcp_public_port_namespace() {
        let client_id = Uuid::new_v4();
        let mut catalog = TunnelCatalog::open(None).expect("catalog should open");
        catalog
            .create_socks5(socks5_request(client_id, 32041))
            .expect("SOCKS5 policy should create");
        assert!(catalog
            .create(CreateTcpTunnelPolicy {
                client_id,
                name: "tcp-conflict".to_owned(),
                public_port: 32041,
                target_addr: "127.0.0.1:1".to_owned(),
                max_connections: None,
                bandwidth_limit_bps: None,
            })
            .is_err());

        catalog
            .create(CreateTcpTunnelPolicy {
                client_id,
                name: "tcp-first".to_owned(),
                public_port: 32042,
                target_addr: "127.0.0.1:1".to_owned(),
                max_connections: None,
                bandwidth_limit_bps: None,
            })
            .expect("TCP policy should create");
        assert!(matches!(
            catalog.create_socks5(socks5_request(client_id, 32042)),
            Err(Socks5PolicyError::DuplicatePublicPort)
        ));
    }

    #[test]
    fn socks5_policy_rejects_unsafe_usernames_and_duplicate_names() {
        let client_id = Uuid::new_v4();
        let mut catalog = TunnelCatalog::open(None).expect("catalog should open");
        let mut invalid = socks5_request(client_id, 32043);
        invalid.username = "bad user".to_owned();
        assert!(matches!(
            catalog.create_socks5(invalid),
            Err(Socks5PolicyError::InvalidUsername)
        ));
        catalog
            .create_socks5(socks5_request(client_id, 32043))
            .expect("SOCKS5 policy should create");
        let mut duplicate_name = socks5_request(client_id, 32044);
        duplicate_name.name = "office-exit".to_owned();
        assert!(matches!(
            catalog.create_socks5(duplicate_name),
            Err(Socks5PolicyError::DuplicateName)
        ));
    }

    #[test]
    fn enabled_policy_authorizes_only_an_exact_tunnel_registration() {
        let client_id = Uuid::new_v4();
        let mut catalog = TunnelCatalog::open(None).expect("catalog should open");
        let policy = catalog
            .create(CreateTcpTunnelPolicy {
                client_id,
                name: "game".to_owned(),
                public_port: 32001,
                target_addr: "127.0.0.1:2333".to_owned(),
                max_connections: Some(12),
                bandwidth_limit_bps: Some(1_000_000),
            })
            .expect("policy should be created");
        assert_eq!(
            catalog
                .runtime_policy(client_id, "game", 32001, "127.0.0.1:2333")
                .expect("authorization should work"),
            Some(super::TcpTunnelRuntimePolicy {
                max_connections: 12,
                bandwidth_limit_bps: Some(1_000_000),
            })
        );
        assert_eq!(
            catalog
                .runtime_policy(client_id, "game", 32002, "127.0.0.1:2333")
                .expect("authorization should work"),
            None
        );
        catalog
            .set_enabled(policy.id, false)
            .expect("policy should update");
        assert_eq!(
            catalog
                .runtime_policy(client_id, "game", 32001, "127.0.0.1:2333")
                .expect("authorization should work"),
            None
        );
    }

    #[test]
    fn updates_preserve_policy_identity_state_and_proxy_credentials() {
        let client_id = Uuid::new_v4();
        let mut catalog = TunnelCatalog::open(None).expect("catalog should open");

        let tcp = catalog
            .create(CreateTcpTunnelPolicy {
                client_id,
                name: "old-tcp".to_owned(),
                public_port: 32060,
                target_addr: "127.0.0.1:6000".to_owned(),
                max_connections: Some(4),
                bandwidth_limit_bps: None,
            })
            .expect("TCP policy should create");
        catalog
            .set_enabled(tcp.id, false)
            .expect("TCP policy should disable");
        let tcp_updated = catalog
            .update(
                tcp.id,
                CreateTcpTunnelPolicy {
                    client_id,
                    name: "new-tcp".to_owned(),
                    public_port: 32061,
                    target_addr: "127.0.0.1:6100".to_owned(),
                    max_connections: Some(9),
                    bandwidth_limit_bps: Some(2_000_000),
                },
            )
            .expect("TCP policy should update")
            .expect("TCP policy should exist");
        assert_eq!(tcp_updated.id, tcp.id);
        assert!(!tcp_updated.enabled);
        assert_eq!(tcp_updated.name, "new-tcp");
        assert_eq!(tcp_updated.public_port, 32061);

        let udp = catalog
            .create_udp(udp_request(client_id, 32066))
            .expect("UDP policy should create");
        catalog
            .set_udp_enabled(udp.id, false)
            .expect("UDP policy should disable");
        let mut udp_update = udp_request(client_id, 32067);
        udp_update.name = "updated-udp".to_owned();
        udp_update.target_addr = "127.0.0.1:6700".to_owned();
        udp_update.max_sessions = Some(33);
        let udp_updated = catalog
            .update_udp(udp.id, udp_update)
            .expect("UDP policy should update")
            .expect("UDP policy should exist");
        assert_eq!(udp_updated.id, udp.id);
        assert!(!udp_updated.enabled);
        assert_eq!(udp_updated.public_port, 32067);
        assert_eq!(udp_updated.max_sessions, 33);

        let socks = catalog
            .create_socks5(socks5_request(client_id, 32062))
            .expect("SOCKS5 policy should create");
        let mut socks_update = socks5_request(client_id, 32063);
        socks_update.name = "updated-exit".to_owned();
        socks_update.username = "updated-user".to_owned();
        let socks_updated = catalog
            .update_socks5(socks.policy.id, socks_update)
            .expect("SOCKS5 policy should update")
            .expect("SOCKS5 policy should exist");
        assert_eq!(socks_updated.id, socks.policy.id);
        let runtime = catalog
            .socks5_runtime_policy(client_id, "updated-exit", 32063)
            .expect("SOCKS5 runtime should query")
            .expect("updated SOCKS5 runtime should match");
        assert_eq!(runtime.username, "updated-user");
        assert!(socks5_password_matches(
            socks.password.as_bytes(),
            &runtime.password_hash
        ));
        assert!(catalog
            .socks5_runtime_policy(client_id, "office-exit", 32062)
            .expect("old SOCKS5 runtime should query")
            .is_none());

        let http = catalog
            .create_http_proxy(http_proxy_request(client_id, 32064))
            .expect("HTTP proxy policy should create");
        let mut http_update = http_proxy_request(client_id, 32065);
        http_update.name = "updated-web-exit".to_owned();
        http_update.username = "updated-proxy-user".to_owned();
        let http_updated = catalog
            .update_http_proxy(http.policy.id, http_update)
            .expect("HTTP proxy policy should update")
            .expect("HTTP proxy policy should exist");
        assert_eq!(http_updated.id, http.policy.id);
        let runtime = catalog
            .http_proxy_runtime_policy(client_id, "updated-web-exit", 32065)
            .expect("HTTP proxy runtime should query")
            .expect("updated HTTP proxy runtime should match");
        assert_eq!(runtime.username, "updated-proxy-user");
        assert!(http_proxy_password_matches(
            http.password.as_bytes(),
            &runtime.password_hash
        ));
    }

    #[test]
    fn port_group_update_replaces_mappings_and_preserves_enabled_state() {
        let client_id = Uuid::new_v4();
        let mut catalog = TunnelCatalog::open(None).expect("catalog should open");
        let policy = catalog
            .create_port_group(port_group_request(
                client_id,
                PortGroupProtocol::Tcp,
                "32070-32073",
            ))
            .expect("port group should create");
        catalog
            .set_port_group_enabled(policy.id, false)
            .expect("port group should disable");
        let mut update = port_group_request(client_id, PortGroupProtocol::Udp, "32074-32077");
        update.name = "updated-game-range".to_owned();
        update.target_host = "127.0.0.2".to_owned();
        let updated = catalog
            .update_port_group(policy.id, update)
            .expect("port group should update")
            .expect("port group should exist");
        assert_eq!(updated.id, policy.id);
        assert!(!updated.enabled);
        assert_eq!(updated.protocol, PortGroupProtocol::Udp);
        assert_eq!(updated.public_ports, "32074-32077");
        let mappings = catalog
            .port_group_mappings(policy.id)
            .expect("updated mappings should list");
        assert_eq!(mappings.len(), 4);
        assert_eq!(mappings[0].public_port, 32074);
        assert_eq!(mappings[0].target_addr, "127.0.0.2:2333");
        assert!(mappings.iter().all(|mapping| mapping.public_port >= 32074));
    }

    #[test]
    fn udp_policy_uses_defaults_and_persists() {
        let directory = std::env::temp_dir().join(format!("linklake-udp-{}", Uuid::new_v4()));
        let client_id = Uuid::new_v4();
        let expected = {
            let mut catalog = TunnelCatalog::open(Some(&directory)).expect("catalog should open");
            catalog
                .create_udp(udp_request(client_id, 32010))
                .expect("UDP policy should be created")
        };
        assert_eq!(expected.max_sessions, 256);
        assert_eq!(expected.session_idle_timeout_seconds, 120);
        assert!(expected.enabled);

        let catalog = TunnelCatalog::open(Some(&directory)).expect("catalog should reopen");
        assert_eq!(
            catalog.list_udp().expect("UDP policies should load"),
            vec![expected]
        );
        drop(catalog);
        fs::remove_dir_all(directory).expect("temporary catalog should be removed");
    }

    #[test]
    fn udp_policy_validates_all_boundaries_and_targets() {
        let client_id = Uuid::new_v4();
        let mut catalog = TunnelCatalog::open(None).expect("catalog should open");

        let mut request = udp_request(client_id, 32000);
        request.name = " \u{0007}".to_owned();
        assert!(matches!(
            catalog.create_udp(request),
            Err(UdpPolicyError::InvalidName)
        ));

        let request = udp_request(client_id, 31999);
        assert!(matches!(
            catalog.create_udp(request),
            Err(UdpPolicyError::InvalidPublicPort)
        ));
        let request = udp_request(client_id, 33000);
        assert!(matches!(
            catalog.create_udp(request),
            Err(UdpPolicyError::InvalidPublicPort)
        ));

        for target in [
            "http://example.com:53",
            "example.com/path:53",
            "bad host:53",
            " resolver.example.com:53",
            "resolver.example.com:53 ",
            "resolver.example.com:\u{0007}53",
            "2001:db8::1:53",
            "-bad.example:53",
            "bad-.example:53",
            "example.com:0",
        ] {
            let mut request = udp_request(client_id, 32000);
            request.target_addr = target.to_owned();
            assert!(
                matches!(
                    catalog.create_udp(request),
                    Err(UdpPolicyError::InvalidTarget)
                ),
                "target should be rejected: {target}"
            );
        }

        let mut request = udp_request(client_id, 32000);
        request.max_sessions = Some(0);
        assert!(matches!(
            catalog.create_udp(request),
            Err(UdpPolicyError::InvalidSessionLimit)
        ));
        let mut request = udp_request(client_id, 32000);
        request.max_sessions = Some(4097);
        assert!(matches!(
            catalog.create_udp(request),
            Err(UdpPolicyError::InvalidSessionLimit)
        ));

        let mut request = udp_request(client_id, 32000);
        request.session_idle_timeout_seconds = Some(29);
        assert!(matches!(
            catalog.create_udp(request),
            Err(UdpPolicyError::InvalidIdleTimeout)
        ));
        let mut request = udp_request(client_id, 32000);
        request.session_idle_timeout_seconds = Some(3601);
        assert!(matches!(
            catalog.create_udp(request),
            Err(UdpPolicyError::InvalidIdleTimeout)
        ));

        let mut request = udp_request(client_id, 32000);
        request.bandwidth_limit_bps = Some(1023);
        assert!(matches!(
            catalog.create_udp(request),
            Err(UdpPolicyError::InvalidBandwidthLimit)
        ));
        let mut request = udp_request(client_id, 32000);
        request.bandwidth_limit_bps = Some(1_000_000_001);
        assert!(matches!(
            catalog.create_udp(request),
            Err(UdpPolicyError::InvalidBandwidthLimit)
        ));

        for (port, target) in [
            (32000, "127.0.0.1:53"),
            (32001, "[2001:db8::1]:53"),
            (32999, "resolver-1.example.com:65535"),
        ] {
            let mut request = udp_request(client_id, port);
            request.target_addr = target.to_owned();
            request.max_sessions = Some(if port == 32000 { 1 } else { 4096 });
            request.session_idle_timeout_seconds = Some(if port == 32000 { 30 } else { 3600 });
            request.bandwidth_limit_bps = Some(if port == 32000 { 1024 } else { 1_000_000_000 });
            catalog
                .create_udp(request)
                .expect("boundary policy should be valid");
        }
    }

    #[test]
    fn udp_port_is_unique_only_inside_the_udp_namespace() {
        let client_id = Uuid::new_v4();
        let mut catalog = TunnelCatalog::open(None).expect("catalog should open");
        catalog
            .create(CreateTcpTunnelPolicy {
                client_id,
                name: "tcp-game".to_owned(),
                public_port: 32020,
                target_addr: "127.0.0.1:2333".to_owned(),
                max_connections: None,
                bandwidth_limit_bps: None,
            })
            .expect("TCP policy should be created");
        catalog
            .create_udp(udp_request(client_id, 32020))
            .expect("the same numeric UDP port should be allowed");
        assert!(matches!(
            catalog.create_udp(udp_request(client_id, 32020)),
            Err(UdpPolicyError::DuplicatePublicPort)
        ));
    }

    #[test]
    fn enabled_udp_policy_authorizes_only_an_exact_registration() {
        let client_id = Uuid::new_v4();
        let mut catalog = TunnelCatalog::open(None).expect("catalog should open");
        let mut request = udp_request(client_id, 32030);
        request.name = "game-udp".to_owned();
        request.target_addr = "127.0.0.1:2333".to_owned();
        request.max_sessions = Some(12);
        request.session_idle_timeout_seconds = Some(90);
        request.bandwidth_limit_bps = Some(1_000_000);
        let policy = catalog
            .create_udp(request)
            .expect("UDP policy should be created");
        assert_eq!(
            catalog
                .udp_runtime_policy(client_id, "game-udp", 32030, "127.0.0.1:2333")
                .expect("authorization should work"),
            Some(UdpTunnelRuntimePolicy {
                policy_id: policy.id,
                max_sessions: 12,
                session_idle_timeout_seconds: 90,
                bandwidth_limit_bps: Some(1_000_000),
            })
        );
        for (name, port, target) in [
            ("other", 32030, "127.0.0.1:2333"),
            ("game-udp", 32031, "127.0.0.1:2333"),
            ("game-udp", 32030, "127.0.0.1:2334"),
        ] {
            assert_eq!(
                catalog
                    .udp_runtime_policy(client_id, name, port, target)
                    .expect("authorization should be checked"),
                None
            );
        }
        assert!(catalog
            .set_udp_enabled(policy.id, false)
            .expect("policy should update"));
        assert_eq!(
            catalog
                .udp_runtime_policy(client_id, "game-udp", 32030, "127.0.0.1:2333")
                .expect("authorization should be checked"),
            None
        );
        assert!(catalog.delete_udp(policy.id).expect("policy should delete"));
        assert!(catalog
            .list_udp()
            .expect("UDP policies should load")
            .is_empty());
    }

    #[test]
    fn udp_error_codes_are_stable() {
        let errors = [
            (UdpPolicyError::InvalidName, "invalid_name"),
            (UdpPolicyError::InvalidPublicPort, "invalid_public_port"),
            (UdpPolicyError::InvalidTarget, "invalid_target"),
            (UdpPolicyError::InvalidSessionLimit, "invalid_session_limit"),
            (UdpPolicyError::InvalidIdleTimeout, "invalid_idle_timeout"),
            (
                UdpPolicyError::InvalidBandwidthLimit,
                "invalid_bandwidth_limit",
            ),
            (UdpPolicyError::DuplicatePublicPort, "duplicate_public_port"),
        ];
        for (error, expected) in errors {
            assert_eq!(error.code(), expected);
            assert_eq!(error.to_string(), expected);
        }
    }
}
