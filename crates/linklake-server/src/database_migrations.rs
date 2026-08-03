//! SQLite 架构版本检查、迁移前备份与可校验迁移账本。

use crate::database::Database;
use rusqlite::{params, OptionalExtension};
use sha2::{Digest, Sha256};
use std::path::Path;

pub(crate) const CURRENT_SCHEMA_VERSION: u32 = 10;

const MIGRATION_V10_NAME: &str = "shared_database_foundation";
const MIGRATION_V10_SQL: &str = "CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    checksum_sha256 TEXT NOT NULL,
    applied_unix_seconds INTEGER NOT NULL
);";

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
        let checksum = migration_checksum(MIGRATION_V10_SQL);
        self.database.with_transaction(|transaction| {
            transaction.execute_batch(MIGRATION_V10_SQL)?;
            let existing = transaction
                .query_row(
                    "SELECT name, checksum_sha256 FROM schema_migrations WHERE version = ?1",
                    [CURRENT_SCHEMA_VERSION],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()?;
            anyhow::ensure!(
                existing.is_none(),
                "database migration ledger already contains schema version {CURRENT_SCHEMA_VERSION} while PRAGMA user_version is {}",
                self.from_version
            );
            transaction.execute(
                "INSERT INTO schema_migrations (version, name, checksum_sha256, applied_unix_seconds) VALUES (?1, ?2, ?3, ?4)",
                params![
                    CURRENT_SCHEMA_VERSION,
                    MIGRATION_V10_NAME,
                    checksum,
                    crate::unix_seconds() as i64,
                ],
            )?;
            transaction.execute_batch(&format!(
                "PRAGMA user_version = {CURRENT_SCHEMA_VERSION};"
            ))?;
            Ok(())
        })
    }
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
    if user_version < CURRENT_SCHEMA_VERSION {
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
    let expected_checksum = migration_checksum(MIGRATION_V10_SQL);
    let record = connection
        .query_row(
            "SELECT name, checksum_sha256 FROM schema_migrations WHERE version = ?1",
            [CURRENT_SCHEMA_VERSION],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    let Some((name, checksum)) = record else {
        anyhow::bail!(
            "database migration ledger is missing schema version {CURRENT_SCHEMA_VERSION}"
        );
    };
    anyhow::ensure!(
        name == MIGRATION_V10_NAME && checksum == expected_checksum,
        "database migration checksum mismatch for schema version {CURRENT_SCHEMA_VERSION}"
    );
    Ok(())
}

fn migration_checksum(sql: &str) -> String {
    Sha256::digest(sql.as_bytes())
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
