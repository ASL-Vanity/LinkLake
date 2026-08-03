//! SQLite 架构版本检查、迁移前备份与可校验迁移账本。

use crate::database::Database;
use rusqlite::{params, OptionalExtension};
use sha2::{Digest, Sha256};
use std::path::Path;

pub(crate) const CURRENT_SCHEMA_VERSION: u32 = 11;

const MIGRATION_V10_NAME: &str = "shared_database_foundation";
const MIGRATION_V10_SQL: &str = "CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    checksum_sha256 TEXT NOT NULL,
    applied_unix_seconds INTEGER NOT NULL
);";

const MIGRATION_V11_NAME: &str = "fleet_policy_service";
const MIGRATION_V11_CLIENT_CONTRACT: &str = "CREATE TABLE IF NOT EXISTS clients (... agent_instance_id TEXT NOT NULL UNIQUE ...);
-- Existing clients table only: ALTER TABLE clients ADD COLUMN agent_instance_id TEXT;
UPDATE clients SET agent_instance_id = client_id WHERE agent_instance_id IS NULL OR TRIM(agent_instance_id) = '';
CREATE UNIQUE INDEX IF NOT EXISTS clients_agent_instance_id ON clients(agent_instance_id);";

/// Fleet v2 的持久化元数据。内存数据库也复用同一份 DDL，避免测试与生产漂移。
pub(crate) const FLEET_V11_SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS fleet_local_state (
    singleton_id INTEGER PRIMARY KEY NOT NULL CHECK(singleton_id = 1),
    source_instance_id TEXT NOT NULL UNIQUE,
    generation INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS fleet_source_states (
    source_instance_id TEXT PRIMARY KEY NOT NULL,
    generation INTEGER NOT NULL,
    revision TEXT NOT NULL,
    applied_unix_seconds INTEGER NOT NULL,
    resource_count INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS fleet_resource_ownership (
    source_instance_id TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    resource_sha256 TEXT NOT NULL,
    credential_ref TEXT,
    PRIMARY KEY(source_instance_id, resource_id),
    UNIQUE(kind, policy_id)
);
CREATE INDEX IF NOT EXISTS fleet_resource_ownership_policy
    ON fleet_resource_ownership(kind, policy_id);
CREATE TABLE IF NOT EXISTS fleet_credential_bindings (
    source_instance_id TEXT NOT NULL,
    credential_ref TEXT NOT NULL,
    kind TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    created_unix_seconds INTEGER NOT NULL,
    PRIMARY KEY(source_instance_id, credential_ref, kind),
    UNIQUE(kind, policy_id)
);
"#;

pub(crate) struct MigrationPlan {
    database: Database,
    from_version: u32,
    backup_path: Option<std::path::PathBuf>,
}

impl MigrationPlan {
    pub(crate) fn source_version(&self) -> u32 {
        self.from_version
    }

    pub(crate) fn backup_path(&self) -> Option<&Path> {
        self.backup_path.as_deref()
    }

    pub(crate) fn finish(self) -> anyhow::Result<()> {
        if self.from_version == CURRENT_SCHEMA_VERSION {
            return Ok(());
        }
        anyhow::ensure!(
            self.from_version < CURRENT_SCHEMA_VERSION,
            "database migration plan has an invalid source version"
        );
        self.database.with_transaction(|transaction| {
            transaction.execute_batch(MIGRATION_V10_SQL)?;
            for version in 10.max(self.from_version.saturating_add(1))..=CURRENT_SCHEMA_VERSION {
                let existing: bool = transaction.query_row(
                    "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = ?1)",
                    [version],
                    |row| row.get(0),
                )?;
                anyhow::ensure!(
                    !existing,
                    "database migration ledger already contains schema version {version} while PRAGMA user_version is {}",
                    self.from_version
                );
                let (name, checksum) = match version {
                    10 => {
                        transaction.execute_batch(MIGRATION_V10_SQL)?;
                        (MIGRATION_V10_NAME, migration_checksum(MIGRATION_V10_SQL))
                    }
                    11 => {
                        apply_v11(transaction)?;
                        (MIGRATION_V11_NAME, migration_v11_checksum())
                    }
                    _ => anyhow::bail!("unsupported database migration version {version}"),
                };
                transaction.execute(
                    "INSERT INTO schema_migrations (version, name, checksum_sha256, applied_unix_seconds) VALUES (?1, ?2, ?3, ?4)",
                    params![version, name, checksum, crate::unix_seconds() as i64],
                )?;
                transaction.execute_batch(&format!("PRAGMA user_version = {version};"))?;
            }
            Ok(())
        })
    }
}

fn apply_v11(transaction: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    // 新数据库先得到完整 clients 表；旧数据库则只补稳定实例 ID 列。
    transaction.execute_batch(
        "CREATE TABLE IF NOT EXISTS clients (
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
        );",
    )?;
    let agent_column_exists: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('clients') WHERE name = 'agent_instance_id')",
        [],
        |row| row.get(0),
    )?;
    if !agent_column_exists {
        transaction.execute("ALTER TABLE clients ADD COLUMN agent_instance_id TEXT", [])?;
    }
    transaction.execute(
        "UPDATE clients SET agent_instance_id = client_id WHERE agent_instance_id IS NULL OR TRIM(agent_instance_id) = ''",
        [],
    )?;
    transaction.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS clients_agent_instance_id ON clients(agent_instance_id)",
        [],
    )?;
    transaction.execute_batch(FLEET_V11_SCHEMA_SQL)?;
    Ok(())
}

pub(crate) fn prepare(database: &Database) -> anyhow::Result<MigrationPlan> {
    let database_path = database
        .path()
        .ok_or_else(|| anyhow::anyhow!("persistent database path is required for migration"))?
        .to_path_buf();
    let from_version = database.with_connection(|connection| {
        Ok(connection.query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0))?)
    })?;
    anyhow::ensure!(
        from_version <= CURRENT_SCHEMA_VERSION,
        "database schema version {from_version} is newer than this LinkLake build ({CURRENT_SCHEMA_VERSION})"
    );
    database.with_connection(|connection| verify_migration_ledger(connection, from_version))?;

    let has_application_tables = database.with_connection(|connection| {
        Ok(connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name <> 'schema_migrations')",
            [],
            |row| row.get::<_, bool>(0),
        )?)
    })?;

    let backup_path = if from_version < CURRENT_SCHEMA_VERSION && has_application_tables {
        let data_dir = database_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("database path has no parent directory"))?;
        let mut backup = data_dir.join(format!(
            "linklake.sqlite3.pre-migration-v{from_version}-{}",
            crate::unix_seconds()
        ));
        let mut suffix = 0_u32;
        while backup.exists() {
            suffix = suffix.saturating_add(1);
            backup = data_dir.join(format!(
                "linklake.sqlite3.pre-migration-v{from_version}-{}-{suffix}",
                crate::unix_seconds()
            ));
        }
        crate::database_tools::backup(&database_path, &backup)?;
        Some(backup)
    } else {
        None
    };

    Ok(MigrationPlan {
        database: database.clone(),
        from_version,
        backup_path,
    })
}

fn verify_migration_ledger(
    connection: &rusqlite::Connection,
    user_version: u32,
) -> anyhow::Result<()> {
    let table_exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations')",
        [],
        |row| row.get(0),
    )?;
    if user_version < 10 {
        if table_exists {
            let rows: i64 =
                connection.query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| {
                    row.get(0)
                })?;
            anyhow::ensure!(
                rows == 0,
                "database migration ledger is inconsistent with PRAGMA user_version"
            );
        }
        return Ok(());
    }
    anyhow::ensure!(
        table_exists,
        "database schema version {user_version} is missing its migration ledger"
    );
    for version in 10..=user_version {
        let (expected_name, expected_checksum) = match version {
            10 => (MIGRATION_V10_NAME, migration_checksum(MIGRATION_V10_SQL)),
            11 => (MIGRATION_V11_NAME, migration_v11_checksum()),
            _ => anyhow::bail!("unsupported database migration version {version}"),
        };
        let record = connection
            .query_row(
                "SELECT name, checksum_sha256 FROM schema_migrations WHERE version = ?1",
                [version],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        let Some((name, checksum)) = record else {
            anyhow::bail!("database migration ledger is missing schema version {version}");
        };
        anyhow::ensure!(
            name == expected_name && checksum == expected_checksum,
            "database migration checksum mismatch for schema version {version}"
        );
    }
    let ledger_rows: u32 =
        connection.query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| {
            row.get(0)
        })?;
    anyhow::ensure!(
        ledger_rows == user_version.saturating_sub(9),
        "database migration ledger contains unexpected versions"
    );
    Ok(())
}

fn migration_checksum(sql: &str) -> String {
    Sha256::digest(sql.as_bytes())
        .iter()
        .map(|value| format!("{value:02x}"))
        .collect()
}

fn migration_v11_checksum() -> String {
    let mut digest = Sha256::new();
    digest.update(MIGRATION_V11_CLIENT_CONTRACT.as_bytes());
    digest.update(FLEET_V11_SCHEMA_SQL.as_bytes());
    digest
        .finalize()
        .iter()
        .map(|value| format!("{value:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use std::fs;

    fn temporary_directory(prefix: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("{prefix}-{}", uuid::Uuid::new_v4()))
    }

    #[test]
    fn existing_database_is_backed_up_and_versioned_after_success() {
        let root = temporary_directory("linklake-migration");
        fs::create_dir_all(&root).expect("temporary directory should exist");
        let database_path = root.join("linklake.sqlite3");
        Connection::open(&database_path)
            .expect("database should open")
            .execute_batch(
                "CREATE TABLE legacy(value TEXT); INSERT INTO legacy VALUES ('kept');
                 PRAGMA user_version = 9;",
            )
            .expect("legacy schema should write");

        let database = Database::persistent(&root).expect("database should lock");
        let plan = prepare(&database).expect("migration should prepare");
        assert_eq!(plan.source_version(), 9);
        let backup = plan
            .backup_path()
            .expect("existing schema should be backed up")
            .to_path_buf();
        plan.finish().expect("migration should finish");

        let connection = database.connect().expect("database should reopen");
        let version: u32 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .expect("version should read");
        assert_eq!(version, CURRENT_SCHEMA_VERSION);
        let ledger: (String, String) = connection
            .query_row(
                "SELECT name, checksum_sha256 FROM schema_migrations WHERE version = 10",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("migration ledger should read");
        assert_eq!(ledger.0, MIGRATION_V10_NAME);
        assert_eq!(ledger.1, migration_checksum(MIGRATION_V10_SQL));
        let value: String = Connection::open(&backup)
            .expect("backup should open")
            .query_row("SELECT value FROM legacy", [], |row| row.get(0))
            .expect("backup content should remain");
        assert_eq!(value, "kept");
        drop(connection);
        drop(database);
        fs::remove_dir_all(root).expect("temporary directory should clean up");
    }

    #[test]
    fn current_database_with_changed_checksum_is_rejected() {
        let root = temporary_directory("linklake-migration-checksum");
        fs::create_dir_all(&root).unwrap();
        let database_path = root.join("linklake.sqlite3");
        Connection::open(&database_path)
            .unwrap()
            .execute_batch(
                "CREATE TABLE schema_migrations (
                    version INTEGER PRIMARY KEY NOT NULL,
                    name TEXT NOT NULL,
                    checksum_sha256 TEXT NOT NULL,
                    applied_unix_seconds INTEGER NOT NULL
                 );
                 INSERT INTO schema_migrations VALUES (10, 'shared_database_foundation', 'changed', 1);
                 PRAGMA user_version = 10;",
            )
            .unwrap();
        let database = Database::persistent(&root).unwrap();
        let error = prepare(&database)
            .err()
            .expect("checksum mismatch must fail closed");
        assert!(error.to_string().contains("checksum mismatch"));
        drop(database);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn newer_database_is_rejected_without_modification() {
        let root = temporary_directory("linklake-newer-schema");
        fs::create_dir_all(&root).expect("temporary directory should exist");
        let database_path = root.join("linklake.sqlite3");
        Connection::open(&database_path)
            .expect("database should open")
            .execute_batch("PRAGMA user_version = 999;")
            .expect("future version should write");
        let database = Database::persistent(&root).unwrap();
        assert!(prepare(&database).is_err());
        drop(database);
        fs::remove_dir_all(root).expect("temporary directory should clean up");
    }

    #[test]
    fn empty_database_does_not_create_a_backup() {
        let root = temporary_directory("linklake-empty-schema");
        let database = Database::persistent(&root).unwrap();
        let plan = prepare(&database).unwrap();
        assert!(plan.backup_path().is_none());
        plan.finish().unwrap();
        prepare(&database).expect("current migration ledger should verify");
        drop(database);
        fs::remove_dir_all(root).unwrap();
    }
}
