use rusqlite::{params, Connection, ErrorCode, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::{fmt, fs, path::Path};
use uuid::Uuid;

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
pub(crate) struct CreateUdpTunnelPolicy {
    pub(crate) client_id: Uuid,
    pub(crate) name: String,
    pub(crate) public_port: u16,
    pub(crate) target_addr: String,
    pub(crate) max_sessions: Option<u16>,
    pub(crate) session_idle_timeout_seconds: Option<u32>,
    pub(crate) bandwidth_limit_bps: Option<u64>,
}

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
        Ok(value.map(
            |(max_connections, bandwidth_limit_bps)| TcpTunnelRuntimePolicy {
                max_connections: max_connections as usize,
                bandwidth_limit_bps: bandwidth_limit_bps.map(|value| value as u64),
            },
        ))
    }

    pub(crate) fn create_udp(
        &mut self,
        request: CreateUdpTunnelPolicy,
    ) -> Result<UdpTunnelPolicy, UdpPolicyError> {
        validate_udp_policy(&request)?;
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
        CreateTcpTunnelPolicy, CreateUdpTunnelPolicy, TunnelCatalog, UdpPolicyError,
        UdpTunnelRuntimePolicy,
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
