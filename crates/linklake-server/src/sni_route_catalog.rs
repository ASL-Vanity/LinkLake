use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::{error::Error, fmt, fs, path::Path};
use uuid::Uuid;

use crate::http_route_catalog::normalize_hostname;

const DEFAULT_MAX_CONNECTIONS: u16 = 64;
const MIN_BANDWIDTH_LIMIT_BPS: u64 = 1_024;
const MAX_BANDWIDTH_LIMIT_BPS: u64 = 1_000_000_000;

#[derive(Clone, Deserialize)]
pub(crate) struct CreateSniRoutePolicy {
    pub(crate) client_id: Uuid,
    pub(crate) name: String,
    pub(crate) hostname: String,
    pub(crate) target_addr: String,
    pub(crate) max_connections: Option<u16>,
    pub(crate) bandwidth_limit_bps: Option<u64>,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub(crate) struct SniRoutePolicy {
    pub(crate) id: Uuid,
    pub(crate) client_id: Uuid,
    pub(crate) name: String,
    pub(crate) hostname: String,
    pub(crate) target_addr: String,
    pub(crate) max_connections: u16,
    pub(crate) bandwidth_limit_bps: Option<u64>,
    pub(crate) enabled: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SniRouteRuntimePolicy {
    pub(crate) policy_id: Uuid,
    pub(crate) max_connections: usize,
    pub(crate) bandwidth_limit_bps: Option<u64>,
}

#[derive(Debug)]
pub(crate) enum SniRoutePolicyError {
    InvalidName,
    InvalidHostname,
    InvalidTarget,
    InvalidConnectionLimit,
    InvalidBandwidthLimit,
    DuplicateHostname,
    Database(rusqlite::Error),
}

impl SniRoutePolicyError {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::InvalidName => "invalid_name",
            Self::InvalidHostname => "invalid_hostname",
            Self::InvalidTarget => "invalid_target",
            Self::InvalidConnectionLimit => "invalid_connection_limit",
            Self::InvalidBandwidthLimit => "invalid_bandwidth_limit",
            Self::DuplicateHostname => "duplicate_sni_hostname",
            Self::Database(_) => "sni_route_policy_storage_error",
        }
    }
}

impl fmt::Display for SniRoutePolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for SniRoutePolicyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Database(error) => Some(error),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for SniRoutePolicyError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error)
    }
}

pub(crate) struct SniRouteCatalog {
    database: Connection,
}

impl SniRouteCatalog {
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
            CREATE TABLE IF NOT EXISTS sni_route_policies (
                id TEXT PRIMARY KEY NOT NULL,
                client_id TEXT NOT NULL,
                name TEXT NOT NULL,
                hostname TEXT NOT NULL UNIQUE,
                target_addr TEXT NOT NULL,
                max_connections INTEGER NOT NULL DEFAULT 64,
                bandwidth_limit_bps INTEGER,
                enabled INTEGER NOT NULL DEFAULT 1
            );
            ",
        )?;
        Ok(Self { database })
    }

    pub(crate) fn create(
        &mut self,
        request: CreateSniRoutePolicy,
    ) -> Result<SniRoutePolicy, SniRoutePolicyError> {
        let hostname = normalize_hostname(&request.hostname)
            .map_err(|_| SniRoutePolicyError::InvalidHostname)?;
        validate_policy(&request)?;
        let exists: bool = self.database.query_row(
            "SELECT EXISTS(SELECT 1 FROM sni_route_policies WHERE hostname = ?1)",
            [&hostname],
            |row| row.get(0),
        )?;
        if exists {
            return Err(SniRoutePolicyError::DuplicateHostname);
        }
        let policy = SniRoutePolicy {
            id: Uuid::new_v4(),
            client_id: request.client_id,
            name: request.name.trim().to_owned(),
            hostname,
            target_addr: request.target_addr.trim().to_owned(),
            max_connections: request.max_connections.unwrap_or(DEFAULT_MAX_CONNECTIONS),
            bandwidth_limit_bps: request.bandwidth_limit_bps,
            enabled: true,
        };
        self.database.execute(
            "INSERT INTO sni_route_policies (id, client_id, name, hostname, target_addr, max_connections, bandwidth_limit_bps, enabled) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1)",
            params![policy.id.to_string(), policy.client_id.to_string(), policy.name, policy.hostname, policy.target_addr, policy.max_connections, policy.bandwidth_limit_bps],
        )?;
        Ok(policy)
    }

    pub(crate) fn list(&self) -> Result<Vec<SniRoutePolicy>, SniRoutePolicyError> {
        let mut statement = self.database.prepare(
            "SELECT id, client_id, name, hostname, target_addr, max_connections, bandwidth_limit_bps, enabled FROM sni_route_policies ORDER BY hostname",
        )?;
        let rows = statement.query_map([], read_policy)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub(crate) fn policy_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<SniRoutePolicy>, SniRoutePolicyError> {
        self.database
            .query_row(
                "SELECT id, client_id, name, hostname, target_addr, max_connections, bandwidth_limit_bps, enabled FROM sni_route_policies WHERE id = ?1",
                [id.to_string()],
                read_policy,
            )
            .optional()
            .map_err(Into::into)
    }

    pub(crate) fn set_enabled(
        &mut self,
        id: Uuid,
        enabled: bool,
    ) -> Result<bool, SniRoutePolicyError> {
        Ok(self.database.execute(
            "UPDATE sni_route_policies SET enabled = ?1 WHERE id = ?2",
            params![enabled, id.to_string()],
        )? != 0)
    }

    pub(crate) fn delete(
        &mut self,
        id: Uuid,
    ) -> Result<Option<SniRoutePolicy>, SniRoutePolicyError> {
        let policy = self.policy_by_id(id)?;
        if policy.is_some() {
            self.database.execute(
                "DELETE FROM sni_route_policies WHERE id = ?1",
                [id.to_string()],
            )?;
        }
        Ok(policy)
    }

    pub(crate) fn runtime_policy(
        &self,
        client_id: Uuid,
        name: &str,
        hostname: &str,
        target_addr: &str,
    ) -> Result<Option<SniRouteRuntimePolicy>, SniRoutePolicyError> {
        let hostname =
            normalize_hostname(hostname).map_err(|_| SniRoutePolicyError::InvalidHostname)?;
        self.database
            .query_row(
                "SELECT id, max_connections, bandwidth_limit_bps FROM sni_route_policies WHERE client_id = ?1 AND name = ?2 AND hostname = ?3 AND target_addr = ?4 AND enabled = 1",
                params![client_id.to_string(), name, hostname, target_addr],
                |row| {
                    let id: String = row.get(0)?;
                    Ok(SniRouteRuntimePolicy {
                        policy_id: Uuid::parse_str(&id)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        max_connections: row.get::<_, i64>(1)? as usize,
                        bandwidth_limit_bps: row
                            .get::<_, Option<i64>>(2)?
                            .map(|value| value as u64),
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }
}

fn read_policy(row: &rusqlite::Row<'_>) -> rusqlite::Result<SniRoutePolicy> {
    let id: String = row.get(0)?;
    let client_id: String = row.get(1)?;
    Ok(SniRoutePolicy {
        id: Uuid::parse_str(&id).map_err(|_| rusqlite::Error::InvalidQuery)?,
        client_id: Uuid::parse_str(&client_id).map_err(|_| rusqlite::Error::InvalidQuery)?,
        name: row.get(2)?,
        hostname: row.get(3)?,
        target_addr: row.get(4)?,
        max_connections: row.get(5)?,
        bandwidth_limit_bps: row.get(6)?,
        enabled: row.get::<_, i64>(7)? != 0,
    })
}

fn validate_policy(request: &CreateSniRoutePolicy) -> Result<(), SniRoutePolicyError> {
    if request.name.trim().is_empty() || request.name.len() > 80 {
        return Err(SniRoutePolicyError::InvalidName);
    }
    let target = request.target_addr.trim();
    if target != request.target_addr || target.len() > 255 || !valid_target_address(target) {
        return Err(SniRoutePolicyError::InvalidTarget);
    }
    if !(1..=1_024).contains(&request.max_connections.unwrap_or(DEFAULT_MAX_CONNECTIONS)) {
        return Err(SniRoutePolicyError::InvalidConnectionLimit);
    }
    if request
        .bandwidth_limit_bps
        .is_some_and(|value| !(MIN_BANDWIDTH_LIMIT_BPS..=MAX_BANDWIDTH_LIMIT_BPS).contains(&value))
    {
        return Err(SniRoutePolicyError::InvalidBandwidthLimit);
    }
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
        && !host.contains('/')
        && !host.contains('@')
        && port.parse::<u16>().is_ok_and(|port| port != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_enabled_route_is_required_and_hostname_is_unique() {
        let client_id = Uuid::new_v4();
        let mut catalog = SniRouteCatalog::open(None).expect("catalog should open");
        let request = CreateSniRoutePolicy {
            client_id,
            name: "mail-tls".to_owned(),
            hostname: "Mail.Example.COM.".to_owned(),
            target_addr: "127.0.0.1:465".to_owned(),
            max_connections: Some(8),
            bandwidth_limit_bps: Some(1_000_000),
        };
        let policy = catalog.create(request).expect("policy should create");
        assert_eq!(policy.hostname, "mail.example.com");
        assert_eq!(
            catalog
                .runtime_policy(client_id, "mail-tls", "mail.example.com", "127.0.0.1:465")
                .expect("runtime should query"),
            Some(SniRouteRuntimePolicy {
                policy_id: policy.id,
                max_connections: 8,
                bandwidth_limit_bps: Some(1_000_000),
            })
        );
        catalog
            .set_enabled(policy.id, false)
            .expect("policy should disable");
        assert!(catalog
            .runtime_policy(client_id, "mail-tls", "mail.example.com", "127.0.0.1:465")
            .expect("runtime should query")
            .is_none());
    }

    #[test]
    fn invalid_limits_targets_and_duplicate_hostnames_are_rejected() {
        let client_id = Uuid::new_v4();
        let mut catalog = SniRouteCatalog::open(None).expect("catalog should open");
        let valid = CreateSniRoutePolicy {
            client_id,
            name: "secure-web".to_owned(),
            hostname: "secure.example.test".to_owned(),
            target_addr: "127.0.0.1:8443".to_owned(),
            max_connections: Some(4),
            bandwidth_limit_bps: None,
        };
        catalog.create(valid.clone()).expect("policy should create");
        assert!(matches!(
            catalog.create(valid),
            Err(SniRoutePolicyError::DuplicateHostname)
        ));

        let invalid_target = CreateSniRoutePolicy {
            client_id,
            name: "invalid-target".to_owned(),
            hostname: "invalid-target.example.test".to_owned(),
            target_addr: "https://127.0.0.1:8443".to_owned(),
            max_connections: Some(4),
            bandwidth_limit_bps: None,
        };
        assert!(matches!(
            catalog.create(invalid_target),
            Err(SniRoutePolicyError::InvalidTarget)
        ));

        let invalid_limit = CreateSniRoutePolicy {
            client_id,
            name: "invalid-limit".to_owned(),
            hostname: "invalid-limit.example.test".to_owned(),
            target_addr: "127.0.0.1:8443".to_owned(),
            max_connections: Some(0),
            bandwidth_limit_bps: None,
        };
        assert!(matches!(
            catalog.create(invalid_limit),
            Err(SniRoutePolicyError::InvalidConnectionLimit)
        ));
    }
}
