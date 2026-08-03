use linklake_core::target_pool::parse_target_pool;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::{error::Error, fmt, net::IpAddr, path::Path};
use uuid::Uuid;

use crate::database::Database;

const DEFAULT_MAX_CONNECTIONS: u16 = 64;

#[derive(Deserialize)]
pub(crate) struct CreateHttpRoutePolicy {
    pub(crate) client_id: Uuid,
    pub(crate) name: String,
    pub(crate) hostname: String,
    pub(crate) target_addr: String,
    pub(crate) max_connections: Option<u16>,
}

// 更新接口采用完整替换语义，字段格式与创建接口一致。
pub(crate) type UpdateHttpRoutePolicy = CreateHttpRoutePolicy;

#[derive(Serialize, Clone)]
pub(crate) struct HttpRoutePolicy {
    pub(crate) id: Uuid,
    pub(crate) client_id: Uuid,
    pub(crate) name: String,
    pub(crate) hostname: String,
    pub(crate) target_addr: String,
    pub(crate) max_connections: u16,
    pub(crate) enabled: bool,
}

#[derive(Debug, PartialEq)]
pub(crate) struct HttpRouteRuntimePolicy {
    pub(crate) policy_id: Uuid,
    pub(crate) max_connections: usize,
}

#[derive(Debug)]
pub(crate) enum CreateHttpRouteError {
    InvalidName,
    InvalidHostname,
    DuplicateHostname,
    InvalidTarget,
    InvalidConnectionLimit,
    Database(rusqlite::Error),
}

impl fmt::Display for CreateHttpRouteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidName => "route name is invalid",
            Self::InvalidHostname => "hostname is invalid",
            Self::DuplicateHostname => "hostname is already assigned to another route",
            Self::InvalidTarget => "target address is invalid",
            Self::InvalidConnectionLimit => "connection limit is invalid",
            Self::Database(_) => "HTTP route database operation failed",
        };
        formatter.write_str(message)
    }
}

impl Error for CreateHttpRouteError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Database(error) => Some(error),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for CreateHttpRouteError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error)
    }
}

pub(crate) struct HttpRouteCatalog {
    database: Connection,
}

impl HttpRouteCatalog {
    #[allow(dead_code)]
    pub(crate) fn open(data_dir: Option<&Path>) -> anyhow::Result<Self> {
        let database = Database::open(data_dir)?;
        Self::open_with_database(&database)
    }

    pub(crate) fn open_with_database(database: &Database) -> anyhow::Result<Self> {
        let database = database.connect()?;
        database.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS http_route_policies (
                id TEXT PRIMARY KEY NOT NULL,
                client_id TEXT NOT NULL,
                name TEXT NOT NULL,
                hostname TEXT NOT NULL UNIQUE,
                target_addr TEXT NOT NULL,
                max_connections INTEGER NOT NULL DEFAULT 64,
                enabled INTEGER NOT NULL DEFAULT 1
            );
            ",
        )?;
        Ok(Self { database })
    }

    pub(crate) fn create(
        &mut self,
        request: CreateHttpRoutePolicy,
    ) -> Result<HttpRoutePolicy, CreateHttpRouteError> {
        let hostname = normalize_hostname(&request.hostname)
            .map_err(|_| CreateHttpRouteError::InvalidHostname)?;
        validate_policy(&request, &hostname)?;
        let duplicate_count: i64 = self.database.query_row(
            "SELECT COUNT(*) FROM http_route_policies WHERE hostname = ?1",
            [&hostname],
            |row| row.get(0),
        )?;
        if duplicate_count != 0 {
            return Err(CreateHttpRouteError::DuplicateHostname);
        }
        let policy = HttpRoutePolicy {
            id: Uuid::new_v4(),
            client_id: request.client_id,
            name: request.name.trim().to_owned(),
            hostname,
            target_addr: request.target_addr.trim().to_owned(),
            max_connections: request.max_connections.unwrap_or(DEFAULT_MAX_CONNECTIONS),
            enabled: true,
        };
        self.database.execute(
            "INSERT INTO http_route_policies (id, client_id, name, hostname, target_addr, max_connections, enabled) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1)",
            params![policy.id.to_string(), policy.client_id.to_string(), policy.name, policy.hostname, policy.target_addr, policy.max_connections],
        )?;
        Ok(policy)
    }

    pub(crate) fn list(&self) -> anyhow::Result<Vec<HttpRoutePolicy>> {
        let mut statement = self.database.prepare(
            "SELECT id, client_id, name, hostname, target_addr, max_connections, enabled FROM http_route_policies ORDER BY hostname",
        )?;
        let rows = statement.query_map([], |row| {
            let id: String = row.get(0)?;
            let client_id: String = row.get(1)?;
            Ok(HttpRoutePolicy {
                id: Uuid::parse_str(&id).map_err(|_| rusqlite::Error::InvalidQuery)?,
                client_id: Uuid::parse_str(&client_id)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?,
                name: row.get(2)?,
                hostname: row.get(3)?,
                target_addr: row.get(4)?,
                max_connections: row.get(5)?,
                enabled: row.get::<_, i64>(6)? != 0,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub(crate) fn policy_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<HttpRoutePolicy>, CreateHttpRouteError> {
        self.database
            .query_row(
                "SELECT id, client_id, name, hostname, target_addr, max_connections, enabled FROM http_route_policies WHERE id = ?1",
                [id.to_string()],
                |row| {
                    let id: String = row.get(0)?;
                    let client_id: String = row.get(1)?;
                    Ok(HttpRoutePolicy {
                        id: Uuid::parse_str(&id).map_err(|_| rusqlite::Error::InvalidQuery)?,
                        client_id: Uuid::parse_str(&client_id)
                            .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        name: row.get(2)?,
                        hostname: row.get(3)?,
                        target_addr: row.get(4)?,
                        max_connections: row.get(5)?,
                        enabled: row.get::<_, i64>(6)? != 0,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub(crate) fn update(
        &mut self,
        id: Uuid,
        request: UpdateHttpRoutePolicy,
    ) -> Result<Option<HttpRoutePolicy>, CreateHttpRouteError> {
        let hostname = normalize_hostname(&request.hostname)
            .map_err(|_| CreateHttpRouteError::InvalidHostname)?;
        validate_policy(&request, &hostname)?;
        let Some(current) = self.policy_by_id(id)? else {
            return Ok(None);
        };
        let duplicate_count: i64 = self.database.query_row(
            "SELECT COUNT(*) FROM http_route_policies WHERE hostname = ?1 AND id <> ?2",
            params![hostname, id.to_string()],
            |row| row.get(0),
        )?;
        if duplicate_count != 0 {
            return Err(CreateHttpRouteError::DuplicateHostname);
        }
        let policy = HttpRoutePolicy {
            id,
            client_id: request.client_id,
            name: request.name.trim().to_owned(),
            hostname,
            target_addr: request.target_addr.trim().to_owned(),
            max_connections: request.max_connections.unwrap_or(DEFAULT_MAX_CONNECTIONS),
            enabled: current.enabled,
        };
        self.database.execute(
            "UPDATE http_route_policies SET client_id = ?1, name = ?2, hostname = ?3, target_addr = ?4, max_connections = ?5 WHERE id = ?6",
            params![
                policy.client_id.to_string(),
                policy.name,
                policy.hostname,
                policy.target_addr,
                policy.max_connections,
                policy.id.to_string(),
            ],
        )?;
        Ok(Some(policy))
    }

    pub(crate) fn set_enabled(&mut self, id: Uuid, enabled: bool) -> anyhow::Result<bool> {
        Ok(self.database.execute(
            "UPDATE http_route_policies SET enabled = ?1 WHERE id = ?2",
            params![enabled, id.to_string()],
        )? != 0)
    }

    pub(crate) fn delete(&mut self, id: Uuid) -> anyhow::Result<bool> {
        Ok(self.database.execute(
            "DELETE FROM http_route_policies WHERE id = ?1",
            [id.to_string()],
        )? != 0)
    }

    pub(crate) fn hostname_for_id(&self, id: Uuid) -> anyhow::Result<Option<String>> {
        self.database
            .query_row(
                "SELECT hostname FROM http_route_policies WHERE id = ?1",
                [id.to_string()],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    pub(crate) fn enabled_hostname_exists(&self, hostname: &str) -> anyhow::Result<bool> {
        let hostname = normalize_hostname(hostname)?;
        let count: i64 = self.database.query_row(
            "SELECT COUNT(*) FROM http_route_policies WHERE hostname = ?1 AND enabled = 1",
            [hostname],
            |row| row.get(0),
        )?;
        Ok(count != 0)
    }

    pub(crate) fn runtime_policy(
        &self,
        client_id: Uuid,
        name: &str,
        hostname: &str,
        target_addr: &str,
    ) -> anyhow::Result<Option<HttpRouteRuntimePolicy>> {
        let hostname = normalize_hostname(hostname)?;
        let value: Option<(String, i64)> = self
            .database
            .query_row(
                "SELECT id, max_connections FROM http_route_policies WHERE client_id = ?1 AND name = ?2 AND hostname = ?3 AND target_addr = ?4 AND enabled = 1",
                params![client_id.to_string(), name, hostname, target_addr],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        value
            .map(|(policy_id, max_connections)| {
                Ok(HttpRouteRuntimePolicy {
                    policy_id: Uuid::parse_str(&policy_id)?,
                    max_connections: max_connections as usize,
                })
            })
            .transpose()
    }
}

pub(crate) fn normalize_hostname(value: &str) -> anyhow::Result<String> {
    let mut value = value.trim().to_ascii_lowercase();
    anyhow::ensure!(
        !value.is_empty()
            && value.len() <= 253
            && !value.contains("//")
            && !value.contains('/')
            && !value.contains('@')
            && !value.chars().any(char::is_whitespace),
        "hostname is invalid"
    );
    if let Some((host, port)) = value.rsplit_once(':') {
        if !host.contains(':') && port.parse::<u16>().is_ok_and(|port| port != 0) {
            value = host.to_owned();
        }
    }
    while value.ends_with('.') {
        value.pop();
    }
    anyhow::ensure!(
        value.contains('.') && value.parse::<IpAddr>().is_err(),
        "hostname is invalid"
    );
    for label in value.split('.') {
        anyhow::ensure!(
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
            "hostname is invalid"
        );
    }
    Ok(value)
}

fn validate_policy(
    request: &CreateHttpRoutePolicy,
    hostname: &str,
) -> Result<(), CreateHttpRouteError> {
    if request.name.trim().is_empty() || request.name.len() > 80 {
        return Err(CreateHttpRouteError::InvalidName);
    }
    if hostname.is_empty() {
        return Err(CreateHttpRouteError::InvalidHostname);
    }
    if parse_target_pool(request.target_addr.trim()).is_err() || request.target_addr.len() > 4096 {
        return Err(CreateHttpRouteError::InvalidTarget);
    }
    if !(1..=1024).contains(&request.max_connections.unwrap_or(DEFAULT_MAX_CONNECTIONS)) {
        return Err(CreateHttpRouteError::InvalidConnectionLimit);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        normalize_hostname, CreateHttpRouteError, CreateHttpRoutePolicy, HttpRouteCatalog,
    };
    use uuid::Uuid;

    #[test]
    fn hostname_normalization_is_strict_and_port_aware() {
        assert_eq!(
            normalize_hostname(" Example.COM.:8080 ").expect("hostname should normalize"),
            "example.com"
        );
        assert!(normalize_hostname("http://example.com").is_err());
        assert!(normalize_hostname("127.0.0.1").is_err());
        assert!(normalize_hostname("bad_label.example.com").is_err());
    }

    #[test]
    fn enabled_policy_authorizes_only_an_exact_route_registration() {
        let client_id = Uuid::new_v4();
        let mut catalog = HttpRouteCatalog::open(None).expect("catalog should open");
        let policy = catalog
            .create(CreateHttpRoutePolicy {
                client_id,
                name: "site".to_owned(),
                hostname: "Site.Example.com".to_owned(),
                target_addr: "127.0.0.1:8080".to_owned(),
                max_connections: Some(12),
            })
            .expect("route should be created");
        assert_eq!(policy.hostname, "site.example.com");
        assert_eq!(
            catalog
                .runtime_policy(client_id, "site", "SITE.EXAMPLE.COM:80", "127.0.0.1:8080")
                .expect("authorization should work"),
            Some(super::HttpRouteRuntimePolicy {
                policy_id: policy.id,
                max_connections: 12,
            })
        );
        catalog
            .set_enabled(policy.id, false)
            .expect("route should update");
        assert_eq!(
            catalog
                .runtime_policy(client_id, "site", "site.example.com", "127.0.0.1:8080")
                .expect("authorization should work"),
            None
        );
    }

    #[test]
    fn create_reports_stable_validation_errors() {
        let client_id = Uuid::new_v4();
        let mut catalog = HttpRouteCatalog::open(None).expect("catalog should open");
        let request = |name: &str, hostname: &str, target_addr: &str, max_connections| {
            CreateHttpRoutePolicy {
                client_id,
                name: name.to_owned(),
                hostname: hostname.to_owned(),
                target_addr: target_addr.to_owned(),
                max_connections,
            }
        };

        assert!(matches!(
            catalog.create(request("", "site.example.com", "127.0.0.1:8080", Some(1))),
            Err(CreateHttpRouteError::InvalidName)
        ));
        assert!(matches!(
            catalog.create(request("site", "bad_host", "127.0.0.1:8080", Some(1))),
            Err(CreateHttpRouteError::InvalidHostname)
        ));
        assert!(matches!(
            catalog.create(request("site", "site.example.com", "missing-port", Some(1))),
            Err(CreateHttpRouteError::InvalidTarget)
        ));
        assert!(matches!(
            catalog.create(request(
                "site",
                "site.example.com",
                "127.0.0.1:8080",
                Some(0)
            )),
            Err(CreateHttpRouteError::InvalidConnectionLimit)
        ));
    }

    #[test]
    fn duplicate_hostname_is_detected_after_normalization() {
        let client_id = Uuid::new_v4();
        let mut catalog = HttpRouteCatalog::open(None).expect("catalog should open");
        let request = |hostname: &str| CreateHttpRoutePolicy {
            client_id,
            name: "site".to_owned(),
            hostname: hostname.to_owned(),
            target_addr: "127.0.0.1:8080".to_owned(),
            max_connections: Some(64),
        };
        catalog
            .create(request("site.example.com"))
            .expect("first route should be created");
        assert!(matches!(
            catalog.create(request("SITE.EXAMPLE.COM.:80")),
            Err(CreateHttpRouteError::DuplicateHostname)
        ));
    }

    #[test]
    fn update_preserves_identity_and_enabled_state() {
        let client_id = Uuid::new_v4();
        let mut catalog = HttpRouteCatalog::open(None).expect("catalog should open");
        let policy = catalog
            .create(CreateHttpRoutePolicy {
                client_id,
                name: "old-site".to_owned(),
                hostname: "old.example.com".to_owned(),
                target_addr: "127.0.0.1:8080".to_owned(),
                max_connections: Some(8),
            })
            .expect("route should create");
        catalog
            .set_enabled(policy.id, false)
            .expect("route should disable");
        let updated = catalog
            .update(
                policy.id,
                CreateHttpRoutePolicy {
                    client_id,
                    name: "new-site".to_owned(),
                    hostname: "New.Example.com.".to_owned(),
                    target_addr: "127.0.0.1:9090".to_owned(),
                    max_connections: Some(16),
                },
            )
            .expect("route should update")
            .expect("route should exist");
        assert_eq!(updated.id, policy.id);
        assert!(!updated.enabled);
        assert_eq!(updated.hostname, "new.example.com");
        assert_eq!(updated.target_addr, "127.0.0.1:9090");
        assert_eq!(updated.max_connections, 16);
    }
}
