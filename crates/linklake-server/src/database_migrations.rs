//! SQLite 架构版本检查、迁移前备份与可校验迁移账本。

use crate::database::Database;
use rusqlite::{params, OptionalExtension};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

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
        crate::database_tools::backup_managed(&database_path, &backup)?;
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

pub(crate) fn validate_restore_database(path: &Path) -> anyhow::Result<u32> {
    let connection =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let version = connection.query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0))?;
    anyhow::ensure!(
        version <= CURRENT_SCHEMA_VERSION,
        "database schema version {version} is newer than this LinkLake build ({CURRENT_SCHEMA_VERSION})"
    );
    verify_migration_ledger(&connection, version)?;
    Ok(version)
}

/// 在独立暂存目录内验证并迁移待恢复数据库，绝不直接修改当前在线数据。
pub(crate) fn migrate_restore_candidate(data_dir: &Path) -> anyhow::Result<()> {
    validate_restore_database(&data_dir.join("linklake.sqlite3"))?;
    let database = Database::persistent(data_dir)?;
    let plan = prepare(&database)?;
    let migration_backup = plan.backup_path().map(Path::to_path_buf);
    crate::migrate_application_schema(&database)?;
    plan.finish()?;

    let database_path = database
        .path()
        .ok_or_else(|| anyhow::anyhow!("restore candidate must use a persistent database"))?
        .to_path_buf();
    database.with_connection(|connection| {
        let version = connection.query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0))?;
        anyhow::ensure!(
            version == CURRENT_SCHEMA_VERSION,
            "restored database schema version {version} was not migrated to {CURRENT_SCHEMA_VERSION}"
        );
        verify_migration_ledger(connection, version)
    })?;
    crate::database_tools::checkpoint_database(&database_path)?;
    drop(database);

    crate::database_tools::remove_sidecars(&database_path)?;
    if let Some(backup) = migration_backup {
        fs::remove_file(backup)?;
    }
    let lock_path = data_dir.join("linklake.sqlite3.lock");
    match fs::remove_file(&lock_path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    crate::database_tools::validate_database(&database_path)
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
    let mut statement = connection
        .prepare("SELECT version, name, checksum_sha256 FROM schema_migrations ORDER BY version")?;
    let records = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, u32>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    anyhow::ensure!(
        records.len() == 1,
        "database migration ledger contains unknown, missing, or extra entries"
    );
    let (version, name, checksum) = &records[0];
    anyhow::ensure!(
        *version == CURRENT_SCHEMA_VERSION
            && name == MIGRATION_V10_NAME
            && checksum == &expected_checksum,
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
    fn current_database_with_extra_ledger_rows_is_rejected() {
        for extra_version in [1_u32, 999_u32] {
            let root = temporary_directory("linklake-migration-extra-ledger");
            fs::create_dir_all(&root).unwrap();
            let database_path = root.join("linklake.sqlite3");
            let connection = Connection::open(&database_path).unwrap();
            connection.execute_batch(MIGRATION_V10_SQL).unwrap();
            connection
                .execute(
                    "INSERT INTO schema_migrations VALUES (?1, ?2, ?3, 1)",
                    params![
                        CURRENT_SCHEMA_VERSION,
                        MIGRATION_V10_NAME,
                        migration_checksum(MIGRATION_V10_SQL)
                    ],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO schema_migrations VALUES (?1, 'unexpected', 'unexpected', 1)",
                    [extra_version],
                )
                .unwrap();
            connection
                .execute_batch(&format!("PRAGMA user_version = {CURRENT_SCHEMA_VERSION};"))
                .unwrap();
            drop(connection);

            let error = validate_restore_database(&database_path).unwrap_err();
            assert!(error.to_string().contains("extra entries"));
            fs::remove_dir_all(root).unwrap();
        }
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

    #[test]
    fn restore_candidate_is_migrated_and_auxiliary_files_are_removed() {
        let root = temporary_directory("linklake-restore-candidate");
        fs::create_dir_all(&root).unwrap();
        let database_path = root.join("linklake.sqlite3");
        Connection::open(&database_path)
            .unwrap()
            .execute_batch(
                "CREATE TABLE legacy(value TEXT NOT NULL);
                 INSERT INTO legacy VALUES ('preserved');
                 PRAGMA user_version = 9;",
            )
            .unwrap();

        migrate_restore_candidate(&root).expect("restore candidate should migrate");

        let connection = Connection::open(&database_path).unwrap();
        let version: u32 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        let value: String = connection
            .query_row("SELECT value FROM legacy", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, CURRENT_SCHEMA_VERSION);
        assert_eq!(value, "preserved");
        verify_migration_ledger(&connection, version).unwrap();
        drop(connection);
        assert!(!root.join("linklake.sqlite3.lock").exists());
        assert!(!root.join("linklake.sqlite3-wal").exists());
        assert!(!root.join("linklake.sqlite3-shm").exists());
        assert!(!fs::read_dir(&root)
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| entry
                .file_name()
                .to_string_lossy()
                .contains("pre-migration")));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn restore_candidate_runs_real_legacy_catalog_migrations_before_commit() {
        let root = temporary_directory("linklake-real-legacy-restore-candidate");
        fs::create_dir_all(&root).unwrap();
        let database_path = root.join("linklake.sqlite3");
        let administrator = "legacy-admin";
        let client_id = uuid::Uuid::new_v4();
        let tunnel_id = uuid::Uuid::new_v4();
        let connection = Connection::open(&database_path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE administrators (
                    username TEXT PRIMARY KEY NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_unix_seconds INTEGER NOT NULL
                 );
                 CREATE TABLE admin_sessions (
                    session_id TEXT PRIMARY KEY NOT NULL,
                    session_secret_hash TEXT NOT NULL,
                    username TEXT NOT NULL,
                    expires_unix_seconds INTEGER NOT NULL
                 );
                 CREATE TABLE clients (
                    client_id TEXT PRIMARY KEY NOT NULL,
                    name TEXT NOT NULL,
                    platform TEXT NOT NULL,
                    access_token_hash TEXT NOT NULL,
                    last_seen_unix_seconds INTEGER NOT NULL
                 );
                 CREATE TABLE tcp_tunnel_policies (
                    id TEXT PRIMARY KEY NOT NULL,
                    client_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    public_port INTEGER NOT NULL UNIQUE,
                    target_addr TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1
                 );
                 PRAGMA user_version = 9;",
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO administrators VALUES (?1, 'legacy-hash', 1)",
                [administrator],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO clients VALUES (?1, 'legacy-client', 'windows', 'legacy-token-hash', 2)",
                [client_id.to_string()],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO tcp_tunnel_policies VALUES (?1, ?2, 'legacy-web', 80, '127.0.0.1:8080', 1)",
                params![tunnel_id.to_string(), client_id.to_string()],
            )
            .unwrap();
        drop(connection);

        migrate_restore_candidate(&root).expect("all legacy catalog migrations should succeed");

        let connection = Connection::open(&database_path).unwrap();
        for (table, column) in [
            ("administrators", "totp_enabled"),
            ("admin_sessions", "created_unix_seconds"),
            ("clients", "config_sync_status"),
            ("tcp_tunnel_policies", "max_connections"),
            ("tcp_tunnel_policies", "bandwidth_limit_bps"),
        ] {
            let present: bool = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM pragma_table_info(?1) WHERE name = ?2)",
                    params![table, column],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(present, "{table}.{column} should be migrated");
        }
        let restored_admin: String = connection
            .query_row("SELECT username FROM administrators", [], |row| row.get(0))
            .unwrap();
        assert_eq!(restored_admin, administrator);
        let placeholder_count: u64 = connection
            .query_row(
                "SELECT COUNT(*) FROM administrators WHERE username LIKE 'schema-migration-%'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(placeholder_count, 0);
        let (name, port, target, max_connections): (String, u16, String, u32) = connection
            .query_row(
                "SELECT name, public_port, target_addr, max_connections FROM tcp_tunnel_policies WHERE id = ?1",
                [tunnel_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(
            (name.as_str(), port, target.as_str(), max_connections),
            ("legacy-web", 80, "127.0.0.1:8080", 64)
        );
        drop(connection);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn restore_candidate_rejects_newer_schema_without_replacing_it() {
        let root = temporary_directory("linklake-newer-restore-candidate");
        fs::create_dir_all(&root).unwrap();
        let database_path = root.join("linklake.sqlite3");
        Connection::open(&database_path)
            .unwrap()
            .execute_batch("CREATE TABLE future(value TEXT); PRAGMA user_version = 999;")
            .unwrap();

        let error = migrate_restore_candidate(&root).unwrap_err();
        assert!(error.to_string().contains("newer than this LinkLake build"));
        let version: u32 = Connection::open(&database_path)
            .unwrap()
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 999);
        fs::remove_dir_all(root).unwrap();
    }
}
