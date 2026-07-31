use rusqlite::{params, Connection, ErrorCode, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fmt, fs, net::SocketAddr, path::Path};
use uuid::Uuid;

const DEFAULT_MAX_CONNECTIONS: u16 = 32;
const MAX_CONNECTIONS: u16 = 1_024;
const MIN_BANDWIDTH_LIMIT_BPS: u64 = 1_024;
const MAX_BANDWIDTH_LIMIT_BPS: u64 = 1_000_000_000;

#[derive(Deserialize)]
pub(crate) struct CreateSecretTunnelPolicy {
    pub(crate) provider_client_id: Uuid,
    pub(crate) allowed_client_id: Option<Uuid>,
    pub(crate) name: String,
    pub(crate) target_addr: String,
    pub(crate) max_connections: Option<u16>,
    pub(crate) bandwidth_limit_bps: Option<u64>,
}

// 更新接口不会重置已有 access key；密钥轮换应使用独立的安全操作。
pub(crate) type UpdateSecretTunnelPolicy = CreateSecretTunnelPolicy;

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub(crate) struct SecretTunnelPolicy {
    pub(crate) id: Uuid,
    pub(crate) provider_client_id: Uuid,
    pub(crate) allowed_client_id: Option<Uuid>,
    pub(crate) name: String,
    pub(crate) target_addr: String,
    pub(crate) max_connections: u16,
    pub(crate) bandwidth_limit_bps: Option<u64>,
    pub(crate) enabled: bool,
}

#[derive(Serialize)]
pub(crate) struct CreatedSecretTunnelPolicy {
    #[serde(flatten)]
    pub(crate) policy: SecretTunnelPolicy,
    pub(crate) access_key: String,
}

#[derive(Debug, Clone)]
pub(crate) struct SecretTunnelRuntimePolicy {
    pub(crate) policy_id: Uuid,
    pub(crate) provider_client_id: Uuid,
    pub(crate) target_addr: String,
    pub(crate) max_connections: usize,
    pub(crate) bandwidth_limit_bps: Option<u64>,
}

#[derive(Debug)]
pub(crate) enum SecretPolicyError {
    InvalidName,
    InvalidTarget,
    InvalidConnectionLimit,
    InvalidBandwidthLimit,
    DuplicateName,
    Database(rusqlite::Error),
}

impl SecretPolicyError {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::InvalidName => "invalid_name",
            Self::InvalidTarget => "invalid_target",
            Self::InvalidConnectionLimit => "invalid_connection_limit",
            Self::InvalidBandwidthLimit => "invalid_bandwidth_limit",
            Self::DuplicateName => "duplicate_secret_tunnel",
            Self::Database(_) => "secret_policy_storage_error",
        }
    }
}

impl fmt::Display for SecretPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for SecretPolicyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Database(error) => Some(error),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for SecretPolicyError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error)
    }
}

pub(crate) struct SecretTunnelCatalog {
    database: Connection,
}

impl SecretTunnelCatalog {
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
            CREATE TABLE IF NOT EXISTS secret_tunnel_policies (
                id TEXT PRIMARY KEY NOT NULL,
                provider_client_id TEXT NOT NULL,
                allowed_client_id TEXT,
                name TEXT NOT NULL,
                target_addr TEXT NOT NULL,
                access_key_hash TEXT NOT NULL UNIQUE,
                max_connections INTEGER NOT NULL DEFAULT 32,
                bandwidth_limit_bps INTEGER,
                enabled INTEGER NOT NULL DEFAULT 1,
                UNIQUE(provider_client_id, name)
            );
            ",
        )?;
        Ok(Self { database })
    }

    pub(crate) fn create(
        &mut self,
        request: CreateSecretTunnelPolicy,
    ) -> Result<CreatedSecretTunnelPolicy, SecretPolicyError> {
        validate_policy(&request)?;
        let access_key = format!("lls_{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let policy = SecretTunnelPolicy {
            id: Uuid::new_v4(),
            provider_client_id: request.provider_client_id,
            allowed_client_id: request.allowed_client_id,
            name: request.name.trim().to_owned(),
            target_addr: request.target_addr.trim().to_owned(),
            max_connections: request.max_connections.unwrap_or(DEFAULT_MAX_CONNECTIONS),
            bandwidth_limit_bps: request.bandwidth_limit_bps,
            enabled: true,
        };
        let result = self.database.execute(
            "INSERT INTO secret_tunnel_policies (id, provider_client_id, allowed_client_id, name, target_addr, access_key_hash, max_connections, bandwidth_limit_bps, enabled) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1)",
            params![
                policy.id.to_string(),
                policy.provider_client_id.to_string(),
                policy.allowed_client_id.map(|value| value.to_string()),
                policy.name,
                policy.target_addr,
                hash_access_key(&access_key),
                policy.max_connections,
                policy.bandwidth_limit_bps,
            ],
        );
        match result {
            Ok(_) => Ok(CreatedSecretTunnelPolicy { policy, access_key }),
            Err(error) if is_constraint_violation(&error) => Err(SecretPolicyError::DuplicateName),
            Err(error) => Err(SecretPolicyError::Database(error)),
        }
    }

    pub(crate) fn list(&self) -> Result<Vec<SecretTunnelPolicy>, SecretPolicyError> {
        let mut statement = self.database.prepare(
            "SELECT id, provider_client_id, allowed_client_id, name, target_addr, max_connections, bandwidth_limit_bps, enabled FROM secret_tunnel_policies ORDER BY name",
        )?;
        let rows = statement.query_map([], read_policy)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub(crate) fn set_enabled(
        &mut self,
        id: Uuid,
        enabled: bool,
    ) -> Result<bool, SecretPolicyError> {
        Ok(self.database.execute(
            "UPDATE secret_tunnel_policies SET enabled = ?1 WHERE id = ?2",
            params![enabled, id.to_string()],
        )? != 0)
    }

    pub(crate) fn delete(
        &mut self,
        id: Uuid,
    ) -> Result<Option<SecretTunnelPolicy>, SecretPolicyError> {
        let policy = self.policy_by_id(id)?;
        if policy.is_some() {
            self.database.execute(
                "DELETE FROM secret_tunnel_policies WHERE id = ?1",
                [id.to_string()],
            )?;
        }
        Ok(policy)
    }

    pub(crate) fn policy_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<SecretTunnelPolicy>, SecretPolicyError> {
        self.database
            .query_row(
                "SELECT id, provider_client_id, allowed_client_id, name, target_addr, max_connections, bandwidth_limit_bps, enabled FROM secret_tunnel_policies WHERE id = ?1",
                [id.to_string()],
                read_policy,
            )
            .optional()
            .map_err(Into::into)
    }

    pub(crate) fn update(
        &mut self,
        id: Uuid,
        request: UpdateSecretTunnelPolicy,
    ) -> Result<Option<SecretTunnelPolicy>, SecretPolicyError> {
        validate_policy(&request)?;
        let Some(current) = self.policy_by_id(id)? else {
            return Ok(None);
        };
        let duplicate: bool = self.database.query_row(
            "SELECT EXISTS(SELECT 1 FROM secret_tunnel_policies WHERE provider_client_id = ?1 AND name = ?2 AND id <> ?3)",
            params![
                request.provider_client_id.to_string(),
                request.name.trim(),
                id.to_string()
            ],
            |row| row.get(0),
        )?;
        if duplicate {
            return Err(SecretPolicyError::DuplicateName);
        }
        let policy = SecretTunnelPolicy {
            id,
            provider_client_id: request.provider_client_id,
            allowed_client_id: request.allowed_client_id,
            name: request.name.trim().to_owned(),
            target_addr: request.target_addr.trim().to_owned(),
            max_connections: request.max_connections.unwrap_or(DEFAULT_MAX_CONNECTIONS),
            bandwidth_limit_bps: request.bandwidth_limit_bps,
            enabled: current.enabled,
        };
        self.database.execute(
            "UPDATE secret_tunnel_policies SET provider_client_id = ?1, allowed_client_id = ?2, name = ?3, target_addr = ?4, max_connections = ?5, bandwidth_limit_bps = ?6 WHERE id = ?7",
            params![
                policy.provider_client_id.to_string(),
                policy.allowed_client_id.map(|value| value.to_string()),
                policy.name,
                policy.target_addr,
                policy.max_connections,
                policy.bandwidth_limit_bps,
                policy.id.to_string(),
            ],
        )?;
        Ok(Some(policy))
    }

    pub(crate) fn provider_runtime_policy(
        &self,
        provider_client_id: Uuid,
        name: &str,
        target_addr: &str,
    ) -> Result<Option<SecretTunnelRuntimePolicy>, SecretPolicyError> {
        self.database
            .query_row(
                "SELECT id, provider_client_id, target_addr, max_connections, bandwidth_limit_bps FROM secret_tunnel_policies WHERE provider_client_id = ?1 AND name = ?2 AND target_addr = ?3 AND enabled = 1",
                params![provider_client_id.to_string(), name, target_addr],
                read_runtime_policy,
            )
            .optional()
            .map_err(Into::into)
    }

    pub(crate) fn access_runtime_policy(
        &self,
        visitor_client_id: Uuid,
        access_key: &str,
    ) -> Result<Option<SecretTunnelRuntimePolicy>, SecretPolicyError> {
        if !valid_access_key(access_key) {
            return Ok(None);
        }
        self.database
            .query_row(
                "SELECT id, provider_client_id, target_addr, max_connections, bandwidth_limit_bps FROM secret_tunnel_policies WHERE access_key_hash = ?1 AND enabled = 1 AND (allowed_client_id IS NULL OR allowed_client_id = ?2)",
                params![hash_access_key(access_key), visitor_client_id.to_string()],
                read_runtime_policy,
            )
            .optional()
            .map_err(Into::into)
    }
}

fn read_policy(row: &rusqlite::Row<'_>) -> rusqlite::Result<SecretTunnelPolicy> {
    let id: String = row.get(0)?;
    let provider_client_id: String = row.get(1)?;
    let allowed_client_id: Option<String> = row.get(2)?;
    Ok(SecretTunnelPolicy {
        id: Uuid::parse_str(&id).map_err(|_| rusqlite::Error::InvalidQuery)?,
        provider_client_id: Uuid::parse_str(&provider_client_id)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        allowed_client_id: allowed_client_id
            .map(|value| Uuid::parse_str(&value).map_err(|_| rusqlite::Error::InvalidQuery))
            .transpose()?,
        name: row.get(3)?,
        target_addr: row.get(4)?,
        max_connections: row.get(5)?,
        bandwidth_limit_bps: row.get(6)?,
        enabled: row.get::<_, i64>(7)? != 0,
    })
}

fn read_runtime_policy(row: &rusqlite::Row<'_>) -> rusqlite::Result<SecretTunnelRuntimePolicy> {
    let id: String = row.get(0)?;
    let provider_client_id: String = row.get(1)?;
    Ok(SecretTunnelRuntimePolicy {
        policy_id: Uuid::parse_str(&id).map_err(|_| rusqlite::Error::InvalidQuery)?,
        provider_client_id: Uuid::parse_str(&provider_client_id)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        target_addr: row.get(2)?,
        max_connections: row.get::<_, i64>(3)? as usize,
        bandwidth_limit_bps: row.get::<_, Option<i64>>(4)?.map(|value| value as u64),
    })
}

fn validate_policy(request: &CreateSecretTunnelPolicy) -> Result<(), SecretPolicyError> {
    let name = request.name.trim();
    if name.is_empty() || name.len() > 80 || name.chars().any(char::is_control) {
        return Err(SecretPolicyError::InvalidName);
    }
    let target = request.target_addr.trim();
    if target != request.target_addr || target.len() > 255 || !valid_target(target) {
        return Err(SecretPolicyError::InvalidTarget);
    }
    if !(1..=MAX_CONNECTIONS).contains(&request.max_connections.unwrap_or(DEFAULT_MAX_CONNECTIONS))
    {
        return Err(SecretPolicyError::InvalidConnectionLimit);
    }
    if request
        .bandwidth_limit_bps
        .is_some_and(|value| !(MIN_BANDWIDTH_LIMIT_BPS..=MAX_BANDWIDTH_LIMIT_BPS).contains(&value))
    {
        return Err(SecretPolicyError::InvalidBandwidthLimit);
    }
    Ok(())
}

fn valid_target(value: &str) -> bool {
    if value.parse::<SocketAddr>().is_ok() {
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

fn valid_access_key(value: &str) -> bool {
    value.len() == 68
        && value.starts_with("lls_")
        && value[4..].bytes().all(|value| value.is_ascii_hexdigit())
}

fn hash_access_key(value: &str) -> String {
    format!("{:x}", Sha256::digest(value.as_bytes()))
}

fn is_constraint_violation(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(inner, _)
            if inner.code == ErrorCode::ConstraintViolation
    )
}

#[cfg(test)]
mod tests {
    use super::{CreateSecretTunnelPolicy, SecretPolicyError, SecretTunnelCatalog};
    use uuid::Uuid;

    fn request(provider: Uuid) -> CreateSecretTunnelPolicy {
        CreateSecretTunnelPolicy {
            provider_client_id: provider,
            allowed_client_id: None,
            name: "private-rdp".to_owned(),
            target_addr: "127.0.0.1:3389".to_owned(),
            max_connections: Some(4),
            bandwidth_limit_bps: Some(1_048_576),
        }
    }

    #[test]
    fn access_key_is_returned_once_and_only_its_hash_is_queryable() {
        let provider = Uuid::new_v4();
        let visitor = Uuid::new_v4();
        let mut catalog = SecretTunnelCatalog::open(None).expect("catalog should open");
        let created = catalog
            .create(request(provider))
            .expect("policy should create");
        assert!(created.access_key.starts_with("lls_"));
        assert_eq!(created.access_key.len(), 68);
        assert_eq!(
            catalog
                .access_runtime_policy(visitor, &created.access_key)
                .expect("access should query")
                .expect("policy should match")
                .provider_client_id,
            provider
        );
        assert!(catalog
            .access_runtime_policy(visitor, "lls_invalid")
            .expect("invalid access should query")
            .is_none());
    }

    #[test]
    fn exact_provider_registration_and_optional_visitor_restriction_are_enforced() {
        let provider = Uuid::new_v4();
        let allowed = Uuid::new_v4();
        let denied = Uuid::new_v4();
        let mut policy = request(provider);
        policy.allowed_client_id = Some(allowed);
        let mut catalog = SecretTunnelCatalog::open(None).expect("catalog should open");
        let created = catalog.create(policy).expect("policy should create");
        assert!(catalog
            .provider_runtime_policy(provider, "private-rdp", "127.0.0.1:3389")
            .expect("provider should query")
            .is_some());
        assert!(catalog
            .provider_runtime_policy(provider, "private-rdp", "127.0.0.1:3390")
            .expect("provider should query")
            .is_none());
        assert!(catalog
            .access_runtime_policy(allowed, &created.access_key)
            .expect("allowed visitor should query")
            .is_some());
        assert!(catalog
            .access_runtime_policy(denied, &created.access_key)
            .expect("denied visitor should query")
            .is_none());
    }

    #[test]
    fn duplicate_name_and_invalid_fields_are_rejected() {
        let provider = Uuid::new_v4();
        let mut catalog = SecretTunnelCatalog::open(None).expect("catalog should open");
        catalog
            .create(request(provider))
            .expect("policy should create");
        assert!(matches!(
            catalog.create(request(provider)),
            Err(SecretPolicyError::DuplicateName)
        ));
        let mut invalid = request(Uuid::new_v4());
        invalid.target_addr = "http://127.0.0.1:1".to_owned();
        assert!(matches!(
            catalog.create(invalid),
            Err(SecretPolicyError::InvalidTarget)
        ));
    }

    #[test]
    fn update_preserves_identity_enabled_state_and_access_key() {
        let provider = Uuid::new_v4();
        let new_provider = Uuid::new_v4();
        let visitor = Uuid::new_v4();
        let mut catalog = SecretTunnelCatalog::open(None).expect("catalog should open");
        let created = catalog
            .create(request(provider))
            .expect("policy should create");
        catalog
            .set_enabled(created.policy.id, false)
            .expect("policy should disable");
        let updated = catalog
            .update(
                created.policy.id,
                CreateSecretTunnelPolicy {
                    provider_client_id: new_provider,
                    allowed_client_id: Some(visitor),
                    name: "updated-rdp".to_owned(),
                    target_addr: "127.0.0.1:3390".to_owned(),
                    max_connections: Some(9),
                    bandwidth_limit_bps: Some(2_000_000),
                },
            )
            .expect("policy should update")
            .expect("policy should exist");
        assert_eq!(updated.id, created.policy.id);
        assert!(!updated.enabled);
        assert_eq!(updated.provider_client_id, new_provider);
        assert_eq!(updated.allowed_client_id, Some(visitor));

        catalog
            .set_enabled(updated.id, true)
            .expect("policy should re-enable");
        let runtime = catalog
            .access_runtime_policy(visitor, &created.access_key)
            .expect("access key should query")
            .expect("original access key should remain valid");
        assert_eq!(runtime.policy_id, updated.id);
        assert_eq!(runtime.provider_client_id, new_provider);
    }
}
