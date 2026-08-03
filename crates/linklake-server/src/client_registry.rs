use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use linklake_core::{ClientSummary, ManagedConfigMode, ManagedConfigStatus};
use rusqlite::{params, Connection};
use std::{collections::HashMap, path::Path};
use uuid::Uuid;

use crate::database::Database;
use crate::unix_seconds;

#[derive(Debug, Clone, serde::Deserialize)]
pub(crate) struct UpdateClient {
    pub(crate) name: String,
    pub(crate) group_name: Option<String>,
    #[serde(default)]
    pub(crate) tags: Vec<String>,
    pub(crate) notes: Option<String>,
    pub(crate) enabled: bool,
}

pub(crate) struct ClientRegistry {
    clients: HashMap<Uuid, RegisteredClient>,
    database: Option<Connection>,
}

#[derive(Clone)]
struct RegisteredClient {
    agent_instance_id: Uuid,
    name: String,
    platform: String,
    group_name: Option<String>,
    tags: Vec<String>,
    notes: Option<String>,
    enabled: bool,
    created_unix_seconds: u64,
    token_rotated_unix_seconds: Option<u64>,
    access_token_hash: String,
    last_seen_unix_seconds: u64,
    config_mode: ManagedConfigMode,
    config_sync_status: ManagedConfigStatus,
    applied_config_revision: Option<String>,
    config_sync_error: Option<String>,
    config_checked_unix_seconds: Option<u64>,
}

pub(crate) enum Authentication {
    Authenticated,
    UnknownClient,
    DisabledClient,
    InvalidToken,
}

impl ClientRegistry {
    #[allow(dead_code)]
    pub(crate) fn open(data_dir: Option<&Path>) -> anyhow::Result<Self> {
        let database = Database::open(data_dir)?;
        Self::open_with_database(&database)
    }

    pub(crate) fn open_with_database(database: &Database) -> anyhow::Result<Self> {
        let database = database.connect()?;
        database.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS clients (
                client_id TEXT PRIMARY KEY NOT NULL,
                agent_instance_id TEXT NOT NULL UNIQUE,
                name TEXT NOT NULL,
                platform TEXT NOT NULL,
                group_name TEXT,
                tags_json TEXT NOT NULL DEFAULT '[]',
                notes TEXT,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_unix_seconds INTEGER NOT NULL DEFAULT 0,
                token_rotated_unix_seconds INTEGER,
                access_token_hash TEXT NOT NULL,
                last_seen_unix_seconds INTEGER NOT NULL,
                config_mode TEXT NOT NULL DEFAULT 'local',
                config_sync_status TEXT NOT NULL DEFAULT 'unknown',
                applied_config_revision TEXT,
                config_sync_error TEXT,
                config_checked_unix_seconds INTEGER
            );
            ",
        )?;
        ensure_column(&database, "agent_instance_id", "TEXT")?;
        database.execute(
            "UPDATE clients SET agent_instance_id = client_id WHERE agent_instance_id IS NULL OR TRIM(agent_instance_id) = ''",
            [],
        )?;
        database.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS clients_agent_instance_id ON clients(agent_instance_id)",
            [],
        )?;
        ensure_column(&database, "config_mode", "TEXT NOT NULL DEFAULT 'local'")?;
        ensure_column(&database, "group_name", "TEXT")?;
        ensure_column(&database, "tags_json", "TEXT NOT NULL DEFAULT '[]'")?;
        ensure_column(&database, "notes", "TEXT")?;
        ensure_column(&database, "enabled", "INTEGER NOT NULL DEFAULT 1")?;
        ensure_column(
            &database,
            "created_unix_seconds",
            "INTEGER NOT NULL DEFAULT 0",
        )?;
        ensure_column(&database, "token_rotated_unix_seconds", "INTEGER")?;
        ensure_column(
            &database,
            "config_sync_status",
            "TEXT NOT NULL DEFAULT 'unknown'",
        )?;
        ensure_column(&database, "applied_config_revision", "TEXT")?;
        ensure_column(&database, "config_sync_error", "TEXT")?;
        ensure_column(&database, "config_checked_unix_seconds", "INTEGER")?;

        let mut statement = database.prepare(
            "SELECT client_id, agent_instance_id, name, platform, group_name, tags_json, notes, enabled, created_unix_seconds, token_rotated_unix_seconds, access_token_hash, last_seen_unix_seconds, config_mode, config_sync_status, applied_config_revision, config_sync_error, config_checked_unix_seconds FROM clients",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                RegisteredClient {
                    agent_instance_id: Uuid::parse_str(&row.get::<_, String>(1)?)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    name: row.get(2)?,
                    platform: row.get(3)?,
                    group_name: row.get(4)?,
                    tags: serde_json::from_str(&row.get::<_, String>(5)?).unwrap_or_default(),
                    notes: row.get(6)?,
                    enabled: row.get::<_, i64>(7)? != 0,
                    created_unix_seconds: row.get::<_, i64>(8)?.max(0) as u64,
                    token_rotated_unix_seconds: row
                        .get::<_, Option<i64>>(9)?
                        .map(|value| value.max(0) as u64),
                    access_token_hash: row.get(10)?,
                    last_seen_unix_seconds: row.get(11)?,
                    config_mode: parse_config_mode(&row.get::<_, String>(12)?),
                    config_sync_status: parse_config_status(&row.get::<_, String>(13)?),
                    applied_config_revision: row.get(14)?,
                    config_sync_error: row.get(15)?,
                    config_checked_unix_seconds: row.get(16)?,
                },
            ))
        })?;
        let mut clients = HashMap::new();
        for row in rows {
            let (client_id, client) = row?;
            let client_id = Uuid::parse_str(&client_id)
                .map_err(|_| anyhow::anyhow!("client database contains an invalid client ID"))?;
            clients.insert(client_id, client);
        }
        drop(statement);

        Ok(Self {
            clients,
            database: Some(database),
        })
    }

    pub(crate) fn count(&self) -> usize {
        self.clients.len()
    }

    pub(crate) fn contains(&self, client_id: Uuid) -> bool {
        self.clients
            .get(&client_id)
            .is_some_and(|client| client.enabled)
    }

    pub(crate) fn summaries(&self) -> Vec<ClientSummary> {
        let mut summaries: Vec<_> = self
            .clients
            .iter()
            .map(|(client_id, client)| ClientSummary {
                client_id: *client_id,
                agent_instance_id: client.agent_instance_id,
                name: client.name.clone(),
                platform: client.platform.clone(),
                group_name: client.group_name.clone(),
                tags: client.tags.clone(),
                notes: client.notes.clone(),
                enabled: client.enabled,
                created_unix_seconds: client.created_unix_seconds,
                token_rotated_unix_seconds: client.token_rotated_unix_seconds,
                last_seen_unix_seconds: client.last_seen_unix_seconds,
                config_mode: client.config_mode,
                config_sync_status: client.config_sync_status,
                applied_config_revision: client.applied_config_revision.clone(),
                config_sync_error: client.config_sync_error.clone(),
                config_checked_unix_seconds: client.config_checked_unix_seconds,
            })
            .collect();
        summaries.sort_by(|left, right| left.name.cmp(&right.name));
        summaries
    }

    pub(crate) fn summary_by_id(&self, client_id: Uuid) -> Option<ClientSummary> {
        self.summary(client_id)
    }

    pub(crate) fn enroll(
        &mut self,
        name: String,
        platform: String,
        agent_instance_id: Option<Uuid>,
    ) -> anyhow::Result<(Uuid, Uuid, String)> {
        let client_id = Uuid::new_v4();
        let agent_instance_id = agent_instance_id.unwrap_or_else(Uuid::new_v4);
        anyhow::ensure!(
            !agent_instance_id.is_nil(),
            "agent instance ID must not be nil"
        );
        let client_token = format!("llc_{}", Uuid::new_v4().simple());
        let now = unix_seconds();
        let client = RegisteredClient {
            agent_instance_id,
            name,
            platform,
            group_name: None,
            tags: Vec::new(),
            notes: None,
            enabled: true,
            created_unix_seconds: now,
            token_rotated_unix_seconds: None,
            access_token_hash: hash_token(&client_token)?,
            last_seen_unix_seconds: now,
            config_mode: ManagedConfigMode::Local,
            config_sync_status: ManagedConfigStatus::Unknown,
            applied_config_revision: None,
            config_sync_error: None,
            config_checked_unix_seconds: None,
        };
        self.persist_client(client_id, &client)?;
        self.clients.insert(client_id, client);
        Ok((client_id, agent_instance_id, client_token))
    }

    pub(crate) fn authenticate_and_touch(
        &mut self,
        client_id: Uuid,
        token: &str,
    ) -> anyhow::Result<Authentication> {
        let Some(mut client) = self.clients.get(&client_id).cloned() else {
            return Ok(Authentication::UnknownClient);
        };
        if !client.enabled {
            return Ok(Authentication::DisabledClient);
        }
        if !verify_token(token, &client.access_token_hash)? {
            return Ok(Authentication::InvalidToken);
        }
        client.last_seen_unix_seconds = unix_seconds();
        self.persist_client(client_id, &client)?;
        self.clients.insert(client_id, client);
        Ok(Authentication::Authenticated)
    }

    pub(crate) fn update(
        &mut self,
        client_id: Uuid,
        request: UpdateClient,
    ) -> anyhow::Result<Option<ClientSummary>> {
        validate_name(&request.name)?;
        let group_name = normalize_optional_text(request.group_name, 64, "client group")?;
        let notes = normalize_optional_text(request.notes, 512, "client notes")?;
        let tags = normalize_tags(request.tags)?;
        let Some(mut client) = self.clients.get(&client_id).cloned() else {
            return Ok(None);
        };
        client.name = request.name.trim().to_owned();
        client.group_name = group_name;
        client.tags = tags;
        client.notes = notes;
        client.enabled = request.enabled;
        self.persist_client(client_id, &client)?;
        self.clients.insert(client_id, client);
        Ok(self.summary(client_id))
    }

    pub(crate) fn rotate_token(&mut self, client_id: Uuid) -> anyhow::Result<Option<String>> {
        let Some(mut client) = self.clients.get(&client_id).cloned() else {
            return Ok(None);
        };
        let client_token = format!("llc_{}", Uuid::new_v4().simple());
        client.access_token_hash = hash_token(&client_token)?;
        client.token_rotated_unix_seconds = Some(unix_seconds());
        self.persist_client(client_id, &client)?;
        self.clients.insert(client_id, client);
        Ok(Some(client_token))
    }

    pub(crate) fn delete(&mut self, client_id: Uuid) -> anyhow::Result<bool> {
        if self.clients.remove(&client_id).is_none() {
            return Ok(false);
        }
        if let Some(database) = &self.database {
            database.execute(
                "DELETE FROM clients WHERE client_id = ?1",
                [client_id.to_string()],
            )?;
        }
        Ok(true)
    }

    fn summary(&self, client_id: Uuid) -> Option<ClientSummary> {
        let client = self.clients.get(&client_id)?;
        Some(ClientSummary {
            client_id,
            agent_instance_id: client.agent_instance_id,
            name: client.name.clone(),
            platform: client.platform.clone(),
            group_name: client.group_name.clone(),
            tags: client.tags.clone(),
            notes: client.notes.clone(),
            enabled: client.enabled,
            created_unix_seconds: client.created_unix_seconds,
            token_rotated_unix_seconds: client.token_rotated_unix_seconds,
            last_seen_unix_seconds: client.last_seen_unix_seconds,
            config_mode: client.config_mode,
            config_sync_status: client.config_sync_status,
            applied_config_revision: client.applied_config_revision.clone(),
            config_sync_error: client.config_sync_error.clone(),
            config_checked_unix_seconds: client.config_checked_unix_seconds,
        })
    }

    pub(crate) fn update_config_sync(
        &mut self,
        client_id: Uuid,
        mode: ManagedConfigMode,
        status: ManagedConfigStatus,
        applied_revision: Option<String>,
        error: Option<String>,
    ) -> anyhow::Result<()> {
        let Some(mut client) = self.clients.get(&client_id).cloned() else {
            anyhow::bail!("unknown client");
        };
        client.config_mode = mode;
        client.config_sync_status = status;
        client.applied_config_revision = applied_revision.filter(|value| value.len() <= 128);
        client.config_sync_error = error
            .map(|value| value.trim().chars().take(512).collect::<String>())
            .filter(|value| !value.is_empty());
        client.config_checked_unix_seconds = Some(unix_seconds());
        self.persist_client(client_id, &client)?;
        self.clients.insert(client_id, client);
        Ok(())
    }

    fn persist_client(&self, client_id: Uuid, client: &RegisteredClient) -> anyhow::Result<()> {
        let Some(database) = &self.database else {
            return Ok(());
        };
        database.execute(
            "
            INSERT INTO clients (client_id, agent_instance_id, name, platform, group_name, tags_json, notes, enabled, created_unix_seconds, token_rotated_unix_seconds, access_token_hash, last_seen_unix_seconds, config_mode, config_sync_status, applied_config_revision, config_sync_error, config_checked_unix_seconds)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)
            ON CONFLICT(client_id) DO UPDATE SET
                agent_instance_id = excluded.agent_instance_id,
                name = excluded.name,
                platform = excluded.platform,
                group_name = excluded.group_name,
                tags_json = excluded.tags_json,
                notes = excluded.notes,
                enabled = excluded.enabled,
                created_unix_seconds = excluded.created_unix_seconds,
                token_rotated_unix_seconds = excluded.token_rotated_unix_seconds,
                access_token_hash = excluded.access_token_hash,
                last_seen_unix_seconds = excluded.last_seen_unix_seconds,
                config_mode = excluded.config_mode,
                config_sync_status = excluded.config_sync_status,
                applied_config_revision = excluded.applied_config_revision,
                config_sync_error = excluded.config_sync_error,
                config_checked_unix_seconds = excluded.config_checked_unix_seconds
            ",
            params![
                client_id.to_string(),
                client.agent_instance_id.to_string(),
                client.name,
                client.platform,
                client.group_name,
                serde_json::to_string(&client.tags)?,
                client.notes,
                client.enabled,
                client.created_unix_seconds,
                client.token_rotated_unix_seconds,
                client.access_token_hash,
                client.last_seen_unix_seconds,
                config_mode_name(client.config_mode),
                config_status_name(client.config_sync_status),
                client.applied_config_revision,
                client.config_sync_error,
                client.config_checked_unix_seconds,
            ],
        )?;
        Ok(())
    }
}

fn ensure_column(database: &Connection, name: &str, definition: &str) -> anyhow::Result<()> {
    let count: i64 = database.query_row(
        "SELECT COUNT(*) FROM pragma_table_info('clients') WHERE name = ?1",
        [name],
        |row| row.get(0),
    )?;
    if count == 0 {
        database.execute(
            &format!("ALTER TABLE clients ADD COLUMN {name} {definition}"),
            [],
        )?;
    }
    Ok(())
}

fn validate_name(name: &str) -> anyhow::Result<()> {
    let name = name.trim();
    anyhow::ensure!(
        !name.is_empty() && name.chars().count() <= 80 && !name.chars().any(char::is_control),
        "client name must contain 1-80 visible characters"
    );
    Ok(())
}

fn normalize_optional_text(
    value: Option<String>,
    maximum: usize,
    field: &str,
) -> anyhow::Result<Option<String>> {
    let Some(value) = value else { return Ok(None) };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    anyhow::ensure!(
        value.chars().count() <= maximum && !value.chars().any(char::is_control),
        "{field} is invalid"
    );
    Ok(Some(value.to_owned()))
}

fn normalize_tags(tags: Vec<String>) -> anyhow::Result<Vec<String>> {
    anyhow::ensure!(tags.len() <= 16, "client tags exceed the limit");
    let mut normalized = Vec::new();
    for tag in tags {
        let tag = tag.trim().to_ascii_lowercase();
        anyhow::ensure!(
            (1..=32).contains(&tag.len())
                && tag
                    .bytes()
                    .all(|value| value.is_ascii_alphanumeric()
                        || matches!(value, b'-' | b'_' | b'.')),
            "client tag is invalid"
        );
        if !normalized.contains(&tag) {
            normalized.push(tag);
        }
    }
    normalized.sort();
    Ok(normalized)
}

fn config_mode_name(mode: ManagedConfigMode) -> &'static str {
    match mode {
        ManagedConfigMode::Local => "local",
        ManagedConfigMode::ReportOnly => "report_only",
        ManagedConfigMode::ServerManaged => "server_managed",
    }
}

fn parse_config_mode(value: &str) -> ManagedConfigMode {
    match value {
        "report_only" => ManagedConfigMode::ReportOnly,
        "server_managed" => ManagedConfigMode::ServerManaged,
        _ => ManagedConfigMode::Local,
    }
}

fn config_status_name(status: ManagedConfigStatus) -> &'static str {
    match status {
        ManagedConfigStatus::Unknown => "unknown",
        ManagedConfigStatus::Synchronized => "synchronized",
        ManagedConfigStatus::Conflict => "conflict",
        ManagedConfigStatus::ApplyFailed => "apply_failed",
    }
}

fn parse_config_status(value: &str) -> ManagedConfigStatus {
    match value {
        "synchronized" => ManagedConfigStatus::Synchronized,
        "conflict" => ManagedConfigStatus::Conflict,
        "apply_failed" => ManagedConfigStatus::ApplyFailed,
        _ => ManagedConfigStatus::Unknown,
    }
}

fn hash_token(token: &str) -> anyhow::Result<String> {
    let salt = SaltString::encode_b64(Uuid::new_v4().as_bytes())
        .map_err(|error| anyhow::anyhow!("could not create token salt: {error}"))?;
    Ok(Argon2::default()
        .hash_password(token.as_bytes(), &salt)
        .map_err(|error| anyhow::anyhow!("could not hash client token: {error}"))?
        .to_string())
}

fn verify_token(token: &str, token_hash: &str) -> anyhow::Result<bool> {
    let parsed_hash = PasswordHash::new(token_hash)
        .map_err(|error| anyhow::anyhow!("stored client token hash is invalid: {error}"))?;
    Ok(Argon2::default()
        .verify_password(token.as_bytes(), &parsed_hash)
        .is_ok())
}

#[cfg(test)]
mod tests {
    use super::{Authentication, ClientRegistry, UpdateClient};
    use linklake_core::{ManagedConfigMode, ManagedConfigStatus};

    #[test]
    fn client_token_is_verified_without_being_stored_in_plaintext() {
        let mut registry = ClientRegistry::open(None).expect("in-memory registry should open");
        let (client_id, _, token) = registry
            .enroll("test-client".to_owned(), "windows".to_owned(), None)
            .expect("client should enroll");

        assert!(matches!(
            registry.authenticate_and_touch(client_id, &token),
            Ok(Authentication::Authenticated)
        ));
        assert!(matches!(
            registry.authenticate_and_touch(client_id, "wrong-token"),
            Ok(Authentication::InvalidToken)
        ));
    }

    #[test]
    fn persistent_registry_survives_reopen() {
        let data_dir =
            std::env::temp_dir().join(format!("linklake-registry-test-{}", uuid::Uuid::new_v4()));
        let (client_id, token) = {
            let mut registry =
                ClientRegistry::open(Some(&data_dir)).expect("persistent registry should open");
            let (client_id, _, token) = registry
                .enroll("persisted-client".to_owned(), "windows".to_owned(), None)
                .expect("client should enroll");
            (client_id, token)
        };

        let mut reloaded =
            ClientRegistry::open(Some(&data_dir)).expect("persistent registry should reopen");
        assert!(matches!(
            reloaded.authenticate_and_touch(client_id, &token),
            Ok(Authentication::Authenticated)
        ));
        drop(reloaded);
        std::fs::remove_dir_all(data_dir).expect("temporary registry should be removed");
    }

    #[test]
    fn managed_configuration_status_persists() {
        let data_dir = std::env::temp_dir().join(format!(
            "linklake-config-status-test-{}",
            uuid::Uuid::new_v4()
        ));
        let client_id = {
            let mut registry =
                ClientRegistry::open(Some(&data_dir)).expect("persistent registry should open");
            let (client_id, _, _) = registry
                .enroll("managed-client".to_owned(), "windows".to_owned(), None)
                .expect("client should enroll");
            registry
                .update_config_sync(
                    client_id,
                    ManagedConfigMode::ServerManaged,
                    ManagedConfigStatus::Synchronized,
                    Some("sha256:revision".to_owned()),
                    None,
                )
                .expect("sync status should update");
            client_id
        };

        let registry =
            ClientRegistry::open(Some(&data_dir)).expect("persistent registry should reopen");
        let summary = registry
            .summaries()
            .into_iter()
            .find(|summary| summary.client_id == client_id)
            .expect("client summary should exist");
        assert_eq!(summary.config_mode, ManagedConfigMode::ServerManaged);
        assert_eq!(
            summary.config_sync_status,
            ManagedConfigStatus::Synchronized
        );
        assert_eq!(
            summary.applied_config_revision.as_deref(),
            Some("sha256:revision")
        );
        drop(registry);
        std::fs::remove_dir_all(data_dir).expect("temporary registry should be removed");
    }

    #[test]
    fn client_metadata_revocation_rotation_and_deletion_are_persistent() {
        let data_dir = std::env::temp_dir().join(format!(
            "linklake-client-management-test-{}",
            uuid::Uuid::new_v4()
        ));
        let (client_id, original_token, rotated_token) = {
            let mut registry =
                ClientRegistry::open(Some(&data_dir)).expect("persistent registry should open");
            let (client_id, _, token) = registry
                .enroll("managed-client".to_owned(), "windows".to_owned(), None)
                .expect("client should enroll");
            let summary = registry
                .update(
                    client_id,
                    UpdateClient {
                        name: "Game Server".to_owned(),
                        group_name: Some("Home Lab".to_owned()),
                        tags: vec!["Game".to_owned(), "asia".to_owned(), "game".to_owned()],
                        notes: Some("Primary game host".to_owned()),
                        enabled: false,
                    },
                )
                .expect("client update should execute")
                .expect("client should exist");
            assert_eq!(summary.name, "Game Server");
            assert_eq!(summary.group_name.as_deref(), Some("Home Lab"));
            assert_eq!(summary.tags, vec!["asia", "game"]);
            assert!(!summary.enabled);
            assert!(matches!(
                registry.authenticate_and_touch(client_id, &token),
                Ok(Authentication::DisabledClient)
            ));
            registry
                .update(
                    client_id,
                    UpdateClient {
                        name: summary.name,
                        group_name: summary.group_name,
                        tags: summary.tags,
                        notes: summary.notes,
                        enabled: true,
                    },
                )
                .expect("client should be re-enabled");
            let rotated = registry
                .rotate_token(client_id)
                .expect("token rotation should execute")
                .expect("client should exist");
            assert!(matches!(
                registry.authenticate_and_touch(client_id, &token),
                Ok(Authentication::InvalidToken)
            ));
            assert!(matches!(
                registry.authenticate_and_touch(client_id, &rotated),
                Ok(Authentication::Authenticated)
            ));
            (client_id, token, rotated)
        };

        let mut registry =
            ClientRegistry::open(Some(&data_dir)).expect("persistent registry should reopen");
        let summary = registry
            .summary_by_id(client_id)
            .expect("client metadata should persist");
        assert_eq!(summary.tags, vec!["asia", "game"]);
        assert!(summary.token_rotated_unix_seconds.is_some());
        assert!(matches!(
            registry.authenticate_and_touch(client_id, &original_token),
            Ok(Authentication::InvalidToken)
        ));
        assert!(matches!(
            registry.authenticate_and_touch(client_id, &rotated_token),
            Ok(Authentication::Authenticated)
        ));
        assert!(registry.delete(client_id).expect("client should delete"));
        assert!(registry.summary_by_id(client_id).is_none());
        drop(registry);
        std::fs::remove_dir_all(data_dir).expect("temporary registry should be removed");
    }
}
