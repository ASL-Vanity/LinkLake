//! SQLite 架构版本检查、迁移前备份与可校验迁移账本。

use crate::database::Database;
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
};
use uuid::Uuid;

pub(crate) const CURRENT_SCHEMA_VERSION: u32 = 13;
pub(crate) const MIN_READABLE_SCHEMA_VERSION: u32 = 0;
pub(crate) const MAX_READABLE_SCHEMA_VERSION: u32 = CURRENT_SCHEMA_VERSION;

const LEDGER_DIGEST_DOMAIN: &[u8] = b"linklake-schema-ledger-v1";
const STARTUP_MIGRATION_MARKER_FILE: &str = "linklake.sqlite3.startup-migration.json";
const STARTUP_MIGRATION_MARKER_VERSION: u32 = 1;
const MAX_STARTUP_MIGRATION_MARKER_BYTES: u64 = 8 * 1024;

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

const MIGRATION_V12_NAME: &str = "fleet_identity_binding";
const MIGRATION_V12_CONTRACT: &str = "ALTER TABLE clients ADD COLUMN agent_identity_public_key TEXT;
CREATE UNIQUE INDEX clients_agent_identity_public_key ON clients(agent_identity_public_key) WHERE agent_identity_public_key IS NOT NULL;
ALTER TABLE management_api_tokens ADD COLUMN fleet_source_instance_id TEXT;";

const MIGRATION_V13_NAME: &str = "certificate_routing_metadata";
const MIGRATION_V13_CONTRACT: &str = "CREATE TABLE IF NOT EXISTS acme_config (... challenge_type TEXT NOT NULL DEFAULT 'http-01' ...);
CREATE TABLE IF NOT EXISTS http_route_tls_policies (... certificate_identifier TEXT ...);
ALTER TABLE acme_config ADD COLUMN challenge_type TEXT NOT NULL DEFAULT 'http-01';
ALTER TABLE http_route_tls_policies ADD COLUMN certificate_identifier TEXT;
INSERT OR IGNORE INTO acme_config (... challenge_type ...) VALUES (... 'http-01' ...);";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DatabaseCompatibilityInspection {
    pub(crate) observed_schema: u32,
    pub(crate) ledger_sha256: String,
    pub(crate) can_migrate: bool,
}

pub(crate) struct MigrationPlan {
    database: Database,
    from_version: u32,
    backup_path: Option<PathBuf>,
    rollback: Option<StartupMigrationRollback>,
}

/// 在版本化迁移已提交、但业务 Catalog DDL 尚未全部确认前保留的恢复句柄。
///
/// 该值不持有 `Database`，因此调用方可以先释放进程锁，再从迁移前快照精确恢复。
pub(crate) struct AppliedMigration {
    rollback: Option<StartupMigrationRollback>,
}

#[derive(Debug, Clone)]
struct StartupMigrationRollback {
    database_path: PathBuf,
    marker_path: PathBuf,
    source_schema: u32,
    backup_path: Option<PathBuf>,
    backup_sha256: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StartupMigrationMarker {
    schema_version: u32,
    source_schema: u32,
    backup_file_name: Option<String>,
    backup_sha256: Option<String>,
}

impl MigrationPlan {
    pub(crate) fn source_version(&self) -> u32 {
        self.from_version
    }

    pub(crate) fn backup_path(&self) -> Option<&Path> {
        self.backup_path.as_deref()
    }

    /// 仅完成版本化 SQLite 迁移。
    ///
    /// 这个入口仍供独立 Catalog 的兼容包装器使用；它不假设调用方接下来会执行
    /// 全部 Catalog DDL，因此不会留下启动恢复 marker。完整服务端启动必须通过
    /// [`apply_startup_schema`]，以便把版本迁移和 Catalog DDL 视为同一个恢复单元。
    pub(crate) fn finish(self) -> anyhow::Result<()> {
        self.finish_inner(false).map(|_| ())
    }

    /// 完成服务端启动所需的版本化迁移，并在 Catalog DDL 完成前保留恢复 marker。
    fn finish_for_startup(self) -> anyhow::Result<AppliedMigration> {
        self.finish_inner(true)
    }

    fn finish_inner(self, retain_startup_rollback: bool) -> anyhow::Result<AppliedMigration> {
        let MigrationPlan {
            database,
            from_version,
            rollback,
            ..
        } = self;
        let rollback = if retain_startup_rollback {
            rollback
        } else {
            None
        };
        if from_version == CURRENT_SCHEMA_VERSION {
            return Ok(AppliedMigration { rollback });
        }
        anyhow::ensure!(
            from_version < CURRENT_SCHEMA_VERSION,
            "database migration plan has an invalid source version"
        );
        if let Some(rollback) = rollback.as_ref() {
            write_startup_migration_marker(
                &rollback.marker_path,
                &StartupMigrationMarker {
                    schema_version: STARTUP_MIGRATION_MARKER_VERSION,
                    source_schema: rollback.source_schema,
                    backup_file_name: rollback
                        .backup_path
                        .as_deref()
                        .map(backup_file_name)
                        .transpose()?,
                    backup_sha256: rollback.backup_sha256.clone(),
                },
            )?;
        }

        let result = database.with_transaction(|transaction| {
            transaction.execute_batch(MIGRATION_V10_SQL)?;
            for version in 10.max(from_version.saturating_add(1))..=CURRENT_SCHEMA_VERSION {
                let existing: bool = transaction.query_row(
                    "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = ?1)",
                    [version],
                    |row| row.get(0),
                )?;
                anyhow::ensure!(
                    !existing,
                    "database migration ledger already contains schema version {version} while PRAGMA user_version is {}",
                    from_version
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
                    12 => {
                        apply_v12(transaction)?;
                        (MIGRATION_V12_NAME, migration_v12_checksum())
                    }
                    13 => {
                        apply_v13(transaction)?;
                        (MIGRATION_V13_NAME, migration_v13_checksum())
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
        });
        match result {
            Ok(()) => Ok(AppliedMigration { rollback }),
            Err(migration_error) => {
                if let Some(rollback) = rollback {
                    if let Err(marker_error) =
                        remove_startup_migration_marker(&rollback.marker_path)
                    {
                        anyhow::bail!(
                            "database migration failed and the startup recovery marker could not be removed; the database transaction was rolled back but recovery is still required before another startup: {migration_error:#}; marker cleanup error: {marker_error:#}"
                        );
                    }
                }
                Err(migration_error)
            }
        }
    }
}

impl AppliedMigration {
    fn has_startup_rollback(&self) -> bool {
        self.rollback.is_some()
    }

    fn confirm_application_schema(self) -> anyhow::Result<()> {
        if let Some(rollback) = self.rollback {
            remove_startup_migration_marker(&rollback.marker_path)?;
        }
        Ok(())
    }

    fn rollback_application_schema_failure(self) -> anyhow::Result<()> {
        let Some(rollback) = self.rollback else {
            return Ok(());
        };
        rollback.restore_exact_snapshot()
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

fn apply_v12(transaction: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    let identity_column_exists: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('clients') WHERE name = 'agent_identity_public_key')",
        [],
        |row| row.get(0),
    )?;
    if !identity_column_exists {
        transaction.execute(
            "ALTER TABLE clients ADD COLUMN agent_identity_public_key TEXT",
            [],
        )?;
    }
    transaction.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS clients_agent_identity_public_key
         ON clients(agent_identity_public_key)
         WHERE agent_identity_public_key IS NOT NULL",
        [],
    )?;
    transaction.execute_batch(
        "CREATE TABLE IF NOT EXISTS management_api_tokens (
            id TEXT PRIMARY KEY NOT NULL,
            name TEXT NOT NULL UNIQUE,
            scope TEXT NOT NULL,
            token_hash BLOB NOT NULL UNIQUE,
            created_unix_seconds INTEGER NOT NULL,
            expires_unix_seconds INTEGER,
            last_used_unix_seconds INTEGER,
            fleet_source_instance_id TEXT
        );
        CREATE INDEX IF NOT EXISTS management_api_tokens_expiry
            ON management_api_tokens(expires_unix_seconds);",
    )?;
    let source_column_exists: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('management_api_tokens') WHERE name = 'fleet_source_instance_id')",
        [],
        |row| row.get(0),
    )?;
    if !source_column_exists {
        transaction.execute(
            "ALTER TABLE management_api_tokens ADD COLUMN fleet_source_instance_id TEXT",
            [],
        )?;
    }
    Ok(())
}

fn apply_v13(transaction: &rusqlite::Transaction<'_>) -> anyhow::Result<()> {
    transaction.execute_batch(
        "CREATE TABLE IF NOT EXISTS acme_config (
            singleton_id INTEGER PRIMARY KEY NOT NULL CHECK (singleton_id = 1),
            enabled INTEGER NOT NULL,
            environment TEXT NOT NULL,
            directory_url TEXT NOT NULL,
            contact_email TEXT NOT NULL,
            terms_accepted INTEGER NOT NULL,
            challenge_type TEXT NOT NULL DEFAULT 'http-01',
            renew_before_days INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS http_route_tls_policies (
            route_id TEXT PRIMARY KEY NOT NULL,
            mode TEXT NOT NULL,
            redirect_http_to_https INTEGER NOT NULL,
            certificate_identifier TEXT,
            updated_at INTEGER NOT NULL
        );",
    )?;

    let challenge_type_exists: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('acme_config') WHERE name = 'challenge_type')",
        [],
        |row| row.get(0),
    )?;
    if !challenge_type_exists {
        transaction.execute(
            "ALTER TABLE acme_config ADD COLUMN challenge_type TEXT NOT NULL DEFAULT 'http-01'",
            [],
        )?;
    }

    let certificate_identifier_exists: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_table_info('http_route_tls_policies') WHERE name = 'certificate_identifier')",
        [],
        |row| row.get(0),
    )?;
    if !certificate_identifier_exists {
        transaction.execute(
            "ALTER TABLE http_route_tls_policies ADD COLUMN certificate_identifier TEXT",
            [],
        )?;
    }

    transaction.execute(
        "INSERT OR IGNORE INTO acme_config (
            singleton_id, enabled, environment, directory_url, contact_email,
            terms_accepted, challenge_type, renew_before_days, updated_at
        ) VALUES (
            1, 0, 'production',
            'https://acme-v02.api.letsencrypt.org/directory', '', 0, 'http-01', 30, 0
        )",
        [],
    )?;
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

    let data_dir = database_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("database path has no parent directory"))?;
    anyhow::ensure!(
        !data_dir.join(STARTUP_MIGRATION_MARKER_FILE).exists(),
        "an interrupted LinkLake startup migration must be recovered before starting another migration"
    );
    let backup_path = if from_version < CURRENT_SCHEMA_VERSION && has_application_tables {
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

    let rollback = if from_version < CURRENT_SCHEMA_VERSION {
        let backup_sha256 = backup_path.as_deref().map(sha256_file).transpose()?;
        Some(StartupMigrationRollback {
            database_path: database_path.clone(),
            marker_path: data_dir.join(STARTUP_MIGRATION_MARKER_FILE),
            source_schema: from_version,
            backup_path,
            backup_sha256,
        })
    } else {
        None
    };

    Ok(MigrationPlan {
        database: database.clone(),
        from_version,
        backup_path: rollback
            .as_ref()
            .and_then(|rollback| rollback.backup_path.clone()),
        rollback,
    })
}

/// 在版本化迁移和业务 Catalog DDL 之间维持一个可恢复边界。
///
/// Catalog 目前各自使用独立 SQLite 连接，不能被包进 `MigrationPlan::finish` 的
/// 单一事务。持久化数据库因此先留下经过校验的迁移前快照和 marker；若任一
/// Catalog 初始化失败，本函数会释放数据库锁并精确恢复迁移前数据库。成功时才
/// 删除 marker，让后续进程不会把已确认的迁移误判为中断状态。
pub(crate) fn apply_startup_schema(
    database: Database,
    plan: Option<MigrationPlan>,
    application_schema: impl FnOnce(&Database) -> anyhow::Result<()>,
) -> anyhow::Result<Database> {
    let applied = plan.map(MigrationPlan::finish_for_startup).transpose()?;
    match application_schema(&database) {
        Ok(()) => {
            if let Some(applied) = applied {
                applied.confirm_application_schema()?;
            }
            Ok(database)
        }
        Err(application_error) => {
            let Some(applied) = applied else {
                return Err(application_error);
            };
            if !applied.has_startup_rollback() {
                return Err(application_error);
            }

            // `Database` 持有跨进程锁；先释放它，恢复路径才能排他替换 SQLite 文件。
            drop(database);
            match applied.rollback_application_schema_failure() {
                Ok(()) => anyhow::bail!(
                    "application schema migration failed; the pre-migration database was restored: {application_error:#}"
                ),
                Err(rollback_error) => anyhow::bail!(
                    "application schema migration failed and the pre-migration database could not be restored automatically: {application_error:#}; rollback error: {rollback_error:#}"
                ),
            }
        }
    }
}

/// 在打开数据库前恢复上次进程在 Catalog DDL 阶段异常退出时留下的迁移前快照。
///
/// marker 只在真正跨 schema 版本迁移时创建。恢复操作取得同一份离线锁，因此不会
/// 在仍有服务端持有数据库时覆盖文件。
pub(crate) fn recover_interrupted_startup_migration(data_dir: &Path) -> anyhow::Result<()> {
    if !data_dir.exists() {
        return Ok(());
    }
    let data_dir = fs::canonicalize(data_dir)?;
    anyhow::ensure!(
        data_dir.is_dir(),
        "LinkLake data directory is not a directory"
    );
    let marker_path = data_dir.join(STARTUP_MIGRATION_MARKER_FILE);
    if !marker_path.exists() {
        return Ok(());
    }

    let offline = crate::disaster_recovery::acquire_offline_data_directory(&data_dir)?;
    let marker_path = offline.path().join(STARTUP_MIGRATION_MARKER_FILE);
    if !marker_path.exists() {
        return Ok(());
    }
    let rollback = read_startup_migration_marker(offline.path(), &marker_path)?;
    rollback.restore_exact_snapshot()
}

impl StartupMigrationRollback {
    fn restore_exact_snapshot(&self) -> anyhow::Result<()> {
        match (&self.backup_path, &self.backup_sha256) {
            (Some(backup_path), Some(backup_sha256)) => {
                restore_database_backup_exact(
                    &self.database_path,
                    backup_path,
                    backup_sha256,
                    self.source_schema,
                )?;
            }
            (None, None) => {
                // 没有应用表的全新数据库没有用户数据可保留；移除它即可让下次启动
                // 回到迁移前的空状态，而不是留下已提交的 schema 账本。
                remove_fresh_migration_database(&self.database_path)?;
            }
            _ => anyhow::bail!("startup migration rollback marker has an invalid backup binding"),
        }
        remove_startup_migration_marker(&self.marker_path)
    }
}

fn write_startup_migration_marker(
    marker_path: &Path,
    marker: &StartupMigrationMarker,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        !marker_path.exists(),
        "startup migration marker already exists"
    );
    let bytes = serde_json::to_vec(marker)?;
    anyhow::ensure!(
        bytes.len() as u64 <= MAX_STARTUP_MIGRATION_MARKER_BYTES,
        "startup migration marker exceeds the size limit"
    );
    let parent = marker_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("startup migration marker has no parent directory"))?;
    let file_name = marker_path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("startup migration marker has no file name"))?
        .to_string_lossy();
    let temporary = parent.join(format!(".{file_name}.tmp-{}", Uuid::new_v4().simple()));
    let result = (|| -> anyhow::Result<()> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        crate::disaster_recovery::restrict_file_permissions(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        crate::disaster_recovery::install_no_replace(&temporary, marker_path)?;
        sync_startup_migration_parent(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn read_startup_migration_marker(
    data_dir: &Path,
    marker_path: &Path,
) -> anyhow::Result<StartupMigrationRollback> {
    let metadata = fs::symlink_metadata(marker_path)?;
    anyhow::ensure!(
        metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
        "startup migration marker is not a regular file"
    );
    anyhow::ensure!(
        metadata.len() <= MAX_STARTUP_MIGRATION_MARKER_BYTES,
        "startup migration marker exceeds the size limit"
    );
    let marker: StartupMigrationMarker = serde_json::from_slice(&fs::read(marker_path)?)?;
    anyhow::ensure!(
        marker.schema_version == STARTUP_MIGRATION_MARKER_VERSION,
        "startup migration marker version is unsupported"
    );
    anyhow::ensure!(
        marker.source_schema < CURRENT_SCHEMA_VERSION,
        "startup migration marker source schema is invalid"
    );

    let (backup_path, backup_sha256) = match (marker.backup_file_name, marker.backup_sha256) {
        (Some(file_name), Some(sha256)) => {
            validate_lowercase_sha256(&sha256, "startup migration backup SHA-256")?;
            let name = Path::new(&file_name);
            anyhow::ensure!(
                name.components().count() == 1
                    && matches!(name.components().next(), Some(Component::Normal(_))),
                "startup migration backup name is invalid"
            );
            let backup_path = fs::canonicalize(data_dir.join(name))?;
            anyhow::ensure!(
                backup_path.parent() == Some(data_dir),
                "startup migration backup escapes the data directory"
            );
            anyhow::ensure!(
                backup_path.is_file(),
                "startup migration backup is not a regular file"
            );
            (Some(backup_path), Some(sha256))
        }
        (None, None) => (None, None),
        _ => anyhow::bail!("startup migration marker backup binding is incomplete"),
    };

    Ok(StartupMigrationRollback {
        database_path: data_dir.join("linklake.sqlite3"),
        marker_path: marker_path.to_path_buf(),
        source_schema: marker.source_schema,
        backup_path,
        backup_sha256,
    })
}

fn backup_file_name(path: &Path) -> anyhow::Result<String> {
    path.file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow::anyhow!("migration backup has no UTF-8 file name"))
}

fn remove_startup_migration_marker(marker_path: &Path) -> anyhow::Result<()> {
    let parent = marker_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("startup migration marker has no parent directory"))?;
    fs::remove_file(marker_path)?;
    sync_startup_migration_parent(parent)
}

fn restore_database_backup_exact(
    database_path: &Path,
    backup_path: &Path,
    backup_sha256: &str,
    expected_schema: u32,
) -> anyhow::Result<()> {
    validate_lowercase_sha256(backup_sha256, "startup migration backup SHA-256")?;
    let source_length = fs::metadata(backup_path)?.len();
    anyhow::ensure!(
        source_length <= crate::database_tools::MAX_DATABASE_BYTES,
        "startup migration backup exceeds the maximum supported size"
    );
    anyhow::ensure!(
        sha256_file(backup_path)? == backup_sha256,
        "startup migration backup digest changed"
    );
    anyhow::ensure!(
        crate::database_tools::validate_database(backup_path).is_ok(),
        "startup migration backup integrity check failed"
    );
    anyhow::ensure!(
        validate_restore_database(backup_path)? == expected_schema,
        "startup migration backup schema does not match its marker"
    );

    let parent = database_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("database path has no parent directory"))?;
    let temporary = parent.join(format!(
        ".linklake.sqlite3.startup-rollback-{}",
        Uuid::new_v4().simple()
    ));
    let result = (|| -> anyhow::Result<()> {
        let mut source = File::open(backup_path)?;
        let mut destination = crate::disaster_recovery::create_managed_new_file(&temporary)?;
        let mut limited_source = (&mut source).take(crate::database_tools::MAX_DATABASE_BYTES + 1);
        let copied = std::io::copy(&mut limited_source, &mut destination)?;
        anyhow::ensure!(
            copied == source_length,
            "startup migration backup copy is incomplete"
        );
        destination.sync_all()?;
        drop(destination);
        anyhow::ensure!(
            sha256_file(&temporary)? == backup_sha256,
            "startup migration rollback copy digest mismatch"
        );

        remove_database_auxiliary_files(database_path)?;
        replace_database_file_atomically(&temporary, database_path)?;
        remove_database_auxiliary_files(database_path)?;
        crate::database_tools::validate_database(database_path)?;
        anyhow::ensure!(
            validate_restore_database(database_path)? == expected_schema,
            "restored database schema does not match the pre-migration marker"
        );
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn remove_fresh_migration_database(database_path: &Path) -> anyhow::Result<()> {
    let parent = database_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("database path has no parent directory"))?;
    remove_database_auxiliary_files(database_path)?;
    match fs::remove_file(database_path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    sync_startup_migration_parent(parent)
}

fn remove_database_auxiliary_files(database_path: &Path) -> anyhow::Result<()> {
    crate::database_tools::remove_sidecars(database_path)?;
    let mut rollback_journal = database_path.as_os_str().to_os_string();
    rollback_journal.push("-journal");
    match fs::remove_file(PathBuf::from(rollback_journal)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(unix)]
fn replace_database_file_atomically(temporary: &Path, database_path: &Path) -> anyhow::Result<()> {
    fs::rename(temporary, database_path)?;
    let parent = database_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("database path has no parent directory"))?;
    sync_startup_migration_parent(parent)
}

#[cfg(windows)]
fn replace_database_file_atomically(temporary: &Path, database_path: &Path) -> anyhow::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let temporary = temporary
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let database_path = database_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    // 两个路径均直接位于受管数据目录，且源文件已完成同步。WRITE_THROUGH 会让
    // 替换操作在断电时保持可恢复的持久性。
    let moved = unsafe {
        MoveFileExW(
            temporary.as_ptr(),
            database_path.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if moved == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn replace_database_file_atomically(temporary: &Path, database_path: &Path) -> anyhow::Result<()> {
    fs::rename(temporary, database_path)?;
    Ok(())
}

#[cfg(unix)]
fn sync_startup_migration_parent(parent: &Path) -> anyhow::Result<()> {
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_startup_migration_parent(_parent: &Path) -> anyhow::Result<()> {
    Ok(())
}

fn validate_lowercase_sha256(value: &str, label: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "{label} must contain 64 hexadecimal characters"
    );
    anyhow::ensure!(
        value.bytes().all(|byte| !byte.is_ascii_uppercase()),
        "{label} must use lowercase hexadecimal"
    );
    Ok(())
}

fn sha256_file(path: &Path) -> anyhow::Result<String> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

/// 只读检查一个数据库是否处于当前构建能够验证和迁移的版本边界内。
///
/// 账本摘要只包含版本、名称和迁移校验和，不包含应用时间，因此同一迁移链在
/// 独立预检和真实升级中会得到相同结果。
pub(crate) fn inspect_database(path: &Path) -> anyhow::Result<DatabaseCompatibilityInspection> {
    let connection =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let observed_schema =
        connection.query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0))?;
    let ledger_sha256 = database_ledger_sha256(&connection)?;
    let can_migrate = (MIN_READABLE_SCHEMA_VERSION..=MAX_READABLE_SCHEMA_VERSION)
        .contains(&observed_schema)
        && verify_migration_ledger(&connection, observed_schema).is_ok();
    Ok(DatabaseCompatibilityInspection {
        observed_schema,
        ledger_sha256,
        can_migrate,
    })
}

/// 当前构建支持的完整迁移合同摘要。
pub(crate) fn migration_contract_sha256() -> String {
    let entries = (10..=CURRENT_SCHEMA_VERSION)
        .map(|version| {
            let (name, checksum) = expected_migration(version)
                .expect("current schema range must have a migration contract");
            (version, name.to_owned(), checksum)
        })
        .collect::<Vec<_>>();
    ledger_digest(&entries)
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

/// Validate and migrate a restore candidate in its isolated staging directory.
pub(crate) fn migrate_restore_candidate(data_dir: &Path) -> anyhow::Result<()> {
    // 预检或恢复过程若在 Catalog DDL 阶段中断，重试前同样必须回到迁移前快照，
    // 不能把保留 marker 的半完成数据库当作当前 schema 继续使用。
    recover_interrupted_startup_migration(data_dir)?;
    validate_restore_database(&data_dir.join("linklake.sqlite3"))?;
    let database = Database::persistent(data_dir)?;
    let plan = prepare(&database)?;
    let migration_backup = plan.backup_path().map(Path::to_path_buf);
    let database = apply_startup_schema(database, Some(plan), crate::migrate_application_schema)?;

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
        let (expected_name, expected_checksum) = expected_migration(version)?;
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

fn database_ledger_sha256(connection: &rusqlite::Connection) -> anyhow::Result<String> {
    let table_exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations')",
        [],
        |row| row.get(0),
    )?;
    if !table_exists {
        return Ok(ledger_digest(&[]));
    }
    let mut statement = connection
        .prepare("SELECT version, name, checksum_sha256 FROM schema_migrations ORDER BY version")?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, u32>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    let entries = rows.collect::<Result<Vec<_>, _>>()?;
    Ok(ledger_digest(&entries))
}

fn ledger_digest(entries: &[(u32, String, String)]) -> String {
    let mut digest = Sha256::new();
    digest.update(LEDGER_DIGEST_DOMAIN);
    digest.update((entries.len() as u64).to_be_bytes());
    for (version, name, checksum) in entries {
        digest.update(version.to_be_bytes());
        update_length_prefixed(&mut digest, name.as_bytes());
        update_length_prefixed(&mut digest, checksum.as_bytes());
    }
    format!("{:x}", digest.finalize())
}

fn update_length_prefixed(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

fn expected_migration(version: u32) -> anyhow::Result<(&'static str, String)> {
    match version {
        10 => Ok((MIGRATION_V10_NAME, migration_checksum(MIGRATION_V10_SQL))),
        11 => Ok((MIGRATION_V11_NAME, migration_v11_checksum())),
        12 => Ok((MIGRATION_V12_NAME, migration_v12_checksum())),
        13 => Ok((MIGRATION_V13_NAME, migration_v13_checksum())),
        _ => anyhow::bail!("unsupported database migration version {version}"),
    }
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

fn migration_v12_checksum() -> String {
    migration_checksum(MIGRATION_V12_CONTRACT)
}

fn migration_v13_checksum() -> String {
    migration_checksum(MIGRATION_V13_CONTRACT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use std::fs;

    fn temporary_directory(prefix: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("{prefix}-{}", uuid::Uuid::new_v4()))
    }

    fn seed_v12_migration_ledger(connection: &Connection) {
        connection
            .execute_batch(MIGRATION_V10_SQL)
            .expect("migration ledger should be created");
        for (version, name, checksum) in [
            (
                10_u32,
                MIGRATION_V10_NAME,
                migration_checksum(MIGRATION_V10_SQL),
            ),
            (11_u32, MIGRATION_V11_NAME, migration_v11_checksum()),
            (12_u32, MIGRATION_V12_NAME, migration_v12_checksum()),
        ] {
            connection
                .execute(
                    "INSERT INTO schema_migrations (
                        version, name, checksum_sha256, applied_unix_seconds
                    ) VALUES (?1, ?2, ?3, 1)",
                    params![version, name, checksum],
                )
                .expect("migration ledger row should be written");
        }
        connection
            .execute_batch("PRAGMA user_version = 12;")
            .expect("schema version should be written");
    }

    fn contract_digest_through(version: u32) -> String {
        let entries = (10..=version)
            .map(|migration_version| {
                let (name, checksum) = expected_migration(migration_version)
                    .expect("test schema must have a migration contract");
                (migration_version, name.to_owned(), checksum)
            })
            .collect::<Vec<_>>();
        ledger_digest(&entries)
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
        assert!(
            !root.join(STARTUP_MIGRATION_MARKER_FILE).exists(),
            "standalone versioned migration must not arm startup rollback"
        );

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
        let agent_key_column: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_table_info('clients') WHERE name = 'agent_identity_public_key')",
                [],
                |row| row.get(0),
            )
            .expect("agent identity column should exist");
        let source_binding_column: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_table_info('management_api_tokens') WHERE name = 'fleet_source_instance_id')",
                [],
                |row| row.get(0),
            )
            .expect("Fleet source binding column should exist");
        assert!(agent_key_column && source_binding_column);
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
    fn schema_nine_runtime_catalogs_are_upgraded_before_first_query() {
        let root = temporary_directory("linklake-schema-nine-runtime-upgrade");
        fs::create_dir_all(&root).expect("temporary directory should exist");
        let database_path = root.join("linklake.sqlite3");
        Connection::open(&database_path)
            .expect("legacy database should open")
            .execute_batch(
                "CREATE TABLE acme_config (
                    singleton_id INTEGER PRIMARY KEY NOT NULL,
                    enabled INTEGER NOT NULL,
                    environment TEXT NOT NULL,
                    directory_url TEXT NOT NULL,
                    contact_email TEXT NOT NULL,
                    terms_accepted INTEGER NOT NULL,
                    renew_before_days INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                 );
                 INSERT INTO acme_config VALUES (
                    1, 1, 'production',
                    'https://acme-v02.api.letsencrypt.org/directory',
                    'legacy@example.com', 1, 30, 1
                 );
                 CREATE TABLE http_route_tls_policies (
                    route_id TEXT PRIMARY KEY NOT NULL,
                    mode TEXT NOT NULL,
                    redirect_http_to_https INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                 );
                 INSERT INTO http_route_tls_policies VALUES (
                    'legacy-route', 'manual', 1, 9
                 );
                 PRAGMA user_version = 9;",
            )
            .expect("legacy schema should write");

        let database = Database::persistent(&root).expect("database should lock");
        let plan = prepare(&database).expect("migration should prepare");
        plan.finish().expect("versioned migration should finish");

        let connection = database.connect().expect("database should reopen");
        let version: u32 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .expect("version should read");
        let challenge_type: String = connection
            .query_row(
                "SELECT challenge_type FROM acme_config WHERE singleton_id = 1",
                [],
                |row| row.get(0),
            )
            .expect("migrated ACME config should read");
        let contact_email: String = connection
            .query_row(
                "SELECT contact_email FROM acme_config WHERE singleton_id = 1",
                [],
                |row| row.get(0),
            )
            .expect("legacy ACME data should remain");
        let route: (String, i64, Option<String>) = connection
            .query_row(
                "SELECT mode, updated_at, certificate_identifier
                 FROM http_route_tls_policies WHERE route_id = 'legacy-route'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("legacy route should remain");
        let ledger: (String, String) = connection
            .query_row(
                "SELECT name, checksum_sha256 FROM schema_migrations WHERE version = 13",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("v13 migration ledger should read");
        assert_eq!(version, CURRENT_SCHEMA_VERSION);
        assert_eq!(challenge_type, "http-01");
        assert_eq!(contact_email, "legacy@example.com");
        assert_eq!(route, ("manual".into(), 9, None));
        assert_eq!(ledger.0, MIGRATION_V13_NAME);
        assert_eq!(ledger.1, migration_v13_checksum());
        drop(connection);

        drop(
            crate::certificate_catalog::CertificateCatalog::open_with_database(&database)
                .expect("certificate catalog should open after v13 migration"),
        );
        let second_plan = prepare(&database).expect("current schema should verify again");
        assert_eq!(second_plan.source_version(), CURRENT_SCHEMA_VERSION);
        assert!(second_plan.backup_path().is_none());
        second_plan
            .finish()
            .expect("current schema should be idempotent");
        drop(database);
        fs::remove_dir_all(root).expect("temporary directory should clean up");
    }

    #[test]
    fn schema_twelve_failure_residue_is_repaired_by_v13() {
        let root = temporary_directory("linklake-schema-twelve-certificate-residue");
        fs::create_dir_all(&root).expect("temporary directory should exist");
        let database_path = root.join("linklake.sqlite3");
        let connection = Connection::open(&database_path).expect("database should open");
        connection
            .execute_batch(
                "CREATE TABLE acme_config (
                    singleton_id INTEGER PRIMARY KEY NOT NULL,
                    enabled INTEGER NOT NULL,
                    environment TEXT NOT NULL,
                    directory_url TEXT NOT NULL,
                    contact_email TEXT NOT NULL,
                    terms_accepted INTEGER NOT NULL,
                    renew_before_days INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                 );
                 INSERT INTO acme_config VALUES (
                    1, 1, 'staging', 'https://example.invalid/directory',
                    'residue@example.com', 1, 17, 44
                 );
                 CREATE TABLE http_route_tls_policies (
                    route_id TEXT PRIMARY KEY NOT NULL,
                    mode TEXT NOT NULL,
                    redirect_http_to_https INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                 );
                 INSERT INTO http_route_tls_policies VALUES (
                    'residue-route', 'automatic', 0, 45
                 );",
            )
            .expect("failure residue should be written");
        seed_v12_migration_ledger(&connection);
        drop(connection);

        let database = Database::persistent(&root).expect("database should lock");
        let plan = prepare(&database).expect("v12 ledger should verify");
        assert_eq!(plan.source_version(), 12);
        plan.finish().expect("v13 repair should finish");

        let connection = database.connect().expect("database should reopen");
        let version: u32 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .expect("version should read");
        let acme: (String, i64, String) = connection
            .query_row(
                "SELECT contact_email, renew_before_days, challenge_type
                 FROM acme_config WHERE singleton_id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("ACME residue should remain");
        let route: (String, i64, Option<String>) = connection
            .query_row(
                "SELECT mode, updated_at, certificate_identifier
                 FROM http_route_tls_policies WHERE route_id = 'residue-route'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("route residue should remain");
        let v13_rows: u32 = connection
            .query_row(
                "SELECT COUNT(*) FROM schema_migrations WHERE version = 13",
                [],
                |row| row.get(0),
            )
            .expect("v13 ledger should read");
        assert_eq!(version, 13);
        assert_eq!(acme, ("residue@example.com".into(), 17, "http-01".into()));
        assert_eq!(route, ("automatic".into(), 45, None));
        assert_eq!(v13_rows, 1);
        drop(connection);

        let second_plan = prepare(&database).expect("repaired database should verify");
        second_plan
            .finish()
            .expect("repaired database should be idempotent");
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
    fn compatibility_inspection_covers_schema_nine_twelve_and_current() {
        let schema_nine_root = temporary_directory("linklake-inspect-schema-nine");
        fs::create_dir_all(&schema_nine_root).unwrap();
        let schema_nine_path = schema_nine_root.join("linklake.sqlite3");
        Connection::open(&schema_nine_path)
            .unwrap()
            .execute_batch("CREATE TABLE legacy(value TEXT); PRAGMA user_version = 9;")
            .unwrap();
        let schema_nine = inspect_database(&schema_nine_path).unwrap();
        assert_eq!(schema_nine.observed_schema, 9);
        assert_eq!(schema_nine.ledger_sha256, ledger_digest(&[]));
        assert!(schema_nine.can_migrate);

        let schema_twelve_root = temporary_directory("linklake-inspect-schema-twelve");
        fs::create_dir_all(&schema_twelve_root).unwrap();
        let schema_twelve_path = schema_twelve_root.join("linklake.sqlite3");
        let schema_twelve_connection = Connection::open(&schema_twelve_path).unwrap();
        seed_v12_migration_ledger(&schema_twelve_connection);
        let schema_twelve = inspect_database(&schema_twelve_path).unwrap();
        assert_eq!(schema_twelve.observed_schema, 12);
        assert_eq!(schema_twelve.ledger_sha256, contract_digest_through(12));
        assert!(schema_twelve.can_migrate);
        schema_twelve_connection
            .execute(
                "UPDATE schema_migrations SET applied_unix_seconds = 999 WHERE version = 12",
                [],
            )
            .unwrap();
        assert_eq!(
            inspect_database(&schema_twelve_path).unwrap().ledger_sha256,
            schema_twelve.ledger_sha256,
            "application timestamps must not affect the deterministic ledger digest"
        );
        drop(schema_twelve_connection);

        let current_root = temporary_directory("linklake-inspect-current-schema");
        let current_database = Database::persistent(&current_root).unwrap();
        prepare(&current_database).unwrap().finish().unwrap();
        let current_path = current_root.join("linklake.sqlite3");
        let current = inspect_database(&current_path).unwrap();
        assert_eq!(current.observed_schema, CURRENT_SCHEMA_VERSION);
        assert_eq!(current.ledger_sha256, migration_contract_sha256());
        assert!(current.can_migrate);
        drop(current_database);

        fs::remove_dir_all(schema_nine_root).unwrap();
        fs::remove_dir_all(schema_twelve_root).unwrap();
        fs::remove_dir_all(current_root).unwrap();
    }

    #[test]
    fn compatibility_inspection_reports_tampered_ledger_without_mutating_it() {
        let root = temporary_directory("linklake-inspect-tampered-ledger");
        fs::create_dir_all(&root).unwrap();
        let database_path = root.join("linklake.sqlite3");
        let connection = Connection::open(&database_path).unwrap();
        seed_v12_migration_ledger(&connection);
        connection
            .execute(
                "UPDATE schema_migrations SET checksum_sha256 = 'tampered' WHERE version = 12",
                [],
            )
            .unwrap();
        let before = connection
            .query_row(
                "SELECT checksum_sha256 FROM schema_migrations WHERE version = 12",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap();
        drop(connection);

        let inspection = inspect_database(&database_path).unwrap();
        assert_eq!(inspection.observed_schema, 12);
        assert!(!inspection.can_migrate);
        assert_ne!(inspection.ledger_sha256, contract_digest_through(12));
        let after = Connection::open(&database_path)
            .unwrap()
            .query_row(
                "SELECT checksum_sha256 FROM schema_migrations WHERE version = 12",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap();
        assert_eq!(before, after);
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
        let connection = database.connect().expect("database should reopen");
        for (table, column) in [
            ("acme_config", "challenge_type"),
            ("http_route_tls_policies", "certificate_identifier"),
        ] {
            let present: bool = connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM pragma_table_info(?1) WHERE name = ?2)",
                    [table, column],
                    |row| row.get(0),
                )
                .expect("v13 column should exist after versioned migration");
            assert!(present, "missing v13 column {table}.{column}");
        }
        let challenge_type: String = connection
            .query_row(
                "SELECT challenge_type FROM acme_config WHERE singleton_id = 1",
                [],
                |row| row.get(0),
            )
            .expect("default ACME row should exist");
        assert_eq!(challenge_type, "http-01");
        drop(connection);
        prepare(&database).expect("current migration ledger should verify");
        drop(database);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn application_catalog_failure_restores_legacy_database_and_removes_marker() {
        let root = temporary_directory("linklake-application-schema-rollback");
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

        let database = Database::persistent(&root).unwrap();
        let plan = prepare(&database).unwrap();
        let backup = plan
            .backup_path()
            .expect("legacy database requires a rollback snapshot")
            .to_path_buf();
        let error = apply_startup_schema(database, Some(plan), |database| {
            database.with_connection(|connection| {
                connection.execute_batch(
                    "CREATE TABLE partial_application_catalog(value TEXT NOT NULL);
                     INSERT INTO partial_application_catalog VALUES ('must disappear');",
                )?;
                Ok(())
            })?;
            anyhow::bail!("simulated application catalog migration failure")
        })
        .err()
        .expect("application catalog failure must fail startup");
        assert!(error
            .to_string()
            .contains("pre-migration database was restored"));

        let connection = Connection::open(&database_path).unwrap();
        let version: u32 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        let legacy: String = connection
            .query_row("SELECT value FROM legacy", [], |row| row.get(0))
            .unwrap();
        let partial_catalog: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'partial_application_catalog')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let ledger: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, 9);
        assert_eq!(legacy, "preserved");
        assert!(!partial_catalog);
        assert!(!ledger);
        assert!(backup.is_file());
        assert!(!root.join(STARTUP_MIGRATION_MARKER_FILE).exists());
        drop(connection);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn interrupted_catalog_migration_is_restored_before_the_next_startup() {
        let root = temporary_directory("linklake-interrupted-application-schema");
        fs::create_dir_all(&root).unwrap();
        let database_path = root.join("linklake.sqlite3");
        Connection::open(&database_path)
            .unwrap()
            .execute_batch(
                "CREATE TABLE legacy(value TEXT NOT NULL);
                 INSERT INTO legacy VALUES ('preserved after crash');
                 PRAGMA user_version = 9;",
            )
            .unwrap();

        let database = Database::persistent(&root).unwrap();
        let plan = prepare(&database).unwrap();
        let applied = plan.finish_for_startup().unwrap();
        database
            .with_connection(|connection| {
                connection.execute_batch(
                    "CREATE TABLE partial_application_catalog(value TEXT NOT NULL);
                     INSERT INTO partial_application_catalog VALUES ('must disappear');",
                )?;
                Ok(())
            })
            .unwrap();
        drop(database);
        drop(applied);

        assert!(root.join(STARTUP_MIGRATION_MARKER_FILE).is_file());
        recover_interrupted_startup_migration(&root).unwrap();

        let connection = Connection::open(&database_path).unwrap();
        let version: u32 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        let legacy: String = connection
            .query_row("SELECT value FROM legacy", [], |row| row.get(0))
            .unwrap();
        let partial_catalog: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'partial_application_catalog')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, 9);
        assert_eq!(legacy, "preserved after crash");
        assert!(!partial_catalog);
        assert!(!root.join(STARTUP_MIGRATION_MARKER_FILE).exists());
        drop(connection);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn fresh_database_catalog_failure_removes_the_versioned_schema() {
        let root = temporary_directory("linklake-fresh-application-schema-rollback");
        let database_path = root.join("linklake.sqlite3");
        let database = Database::persistent(&root).unwrap();
        let plan = prepare(&database).unwrap();
        assert!(plan.backup_path().is_none());
        let error = apply_startup_schema(database, Some(plan), |database| {
            database.with_connection(|connection| {
                connection.execute_batch(
                    "CREATE TABLE partial_application_catalog(value TEXT NOT NULL);",
                )?;
                Ok(())
            })?;
            anyhow::bail!("simulated fresh application catalog migration failure")
        })
        .err()
        .expect("fresh application catalog failure must fail startup");
        assert!(error
            .to_string()
            .contains("pre-migration database was restored"));
        assert!(!database_path.exists());
        assert!(!root.join(STARTUP_MIGRATION_MARKER_FILE).exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn interrupted_fresh_catalog_migration_removes_database_before_next_startup() {
        let root = temporary_directory("linklake-interrupted-fresh-application-schema");
        let database_path = root.join("linklake.sqlite3");
        let database = Database::persistent(&root).unwrap();
        let plan = prepare(&database).unwrap();
        let applied = plan.finish_for_startup().unwrap();
        database
            .with_connection(|connection| {
                connection.execute_batch(
                    "CREATE TABLE partial_application_catalog(value TEXT NOT NULL);
                     INSERT INTO partial_application_catalog VALUES ('must disappear');",
                )?;
                Ok(())
            })
            .unwrap();
        drop(database);
        drop(applied);

        assert!(root.join(STARTUP_MIGRATION_MARKER_FILE).is_file());
        recover_interrupted_startup_migration(&root).unwrap();

        assert!(!database_path.exists());
        assert!(!root.join("linklake.sqlite3-wal").exists());
        assert!(!root.join("linklake.sqlite3-shm").exists());
        assert!(!root.join("linklake.sqlite3-journal").exists());
        assert!(!root.join(STARTUP_MIGRATION_MARKER_FILE).exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn restore_candidate_recovers_interrupted_catalog_migration_before_retrying() {
        let root = temporary_directory("linklake-interrupted-restore-candidate");
        fs::create_dir_all(&root).unwrap();
        let database_path = root.join("linklake.sqlite3");
        Connection::open(&database_path)
            .unwrap()
            .execute_batch(
                "CREATE TABLE legacy(value TEXT NOT NULL);
                 INSERT INTO legacy VALUES ('preserved after retry');
                 PRAGMA user_version = 9;",
            )
            .unwrap();

        let database = Database::persistent(&root).unwrap();
        let plan = prepare(&database).unwrap();
        let applied = plan.finish_for_startup().unwrap();
        database
            .with_connection(|connection| {
                connection.execute_batch(
                    "CREATE TABLE partial_application_catalog(value TEXT NOT NULL);
                     INSERT INTO partial_application_catalog VALUES ('must disappear');",
                )?;
                Ok(())
            })
            .unwrap();
        drop(database);
        drop(applied);

        migrate_restore_candidate(&root)
            .expect("interrupted restore candidate should retry safely");

        let connection = Connection::open(&database_path).unwrap();
        let version: u32 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        let legacy: String = connection
            .query_row("SELECT value FROM legacy", [], |row| row.get(0))
            .unwrap();
        let partial_catalog: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'partial_application_catalog')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, CURRENT_SCHEMA_VERSION);
        assert_eq!(legacy, "preserved after retry");
        assert!(!partial_catalog);
        assert!(!root.join(STARTUP_MIGRATION_MARKER_FILE).exists());
        drop(connection);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn current_restore_database_accepts_additive_notification_tables() {
        let root = temporary_directory("linklake-additive-notification-restore");
        fs::create_dir_all(&root).unwrap();
        let database_path = root.join("linklake.sqlite3");
        let database = Database::persistent(&root).unwrap();
        let plan = prepare(&database).unwrap();
        plan.finish().unwrap();
        database
            .with_connection(|connection| {
                connection.execute_batch(
                    "CREATE TABLE notification_delivery_log (
                        notification_id TEXT PRIMARY KEY NOT NULL,
                        delivered_unix_seconds INTEGER NOT NULL
                    );
                    INSERT INTO notification_delivery_log VALUES ('notification-1', 42);",
                )?;
                Ok(())
            })
            .unwrap();
        drop(database);

        assert_eq!(
            validate_restore_database(&database_path).unwrap(),
            CURRENT_SCHEMA_VERSION
        );
        migrate_restore_candidate(&root).unwrap();
        let restored: (String, u64) = Connection::open(&database_path)
            .unwrap()
            .query_row(
                "SELECT notification_id, delivered_unix_seconds FROM notification_delivery_log",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(restored, ("notification-1".into(), 42));
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

    #[test]
    fn failed_v12_migration_rolls_back_v11_schema_and_ledger() {
        let root = temporary_directory("linklake-migration-rollback");
        fs::create_dir_all(&root).unwrap();
        let database_path = root.join("linklake.sqlite3");
        let checksum = migration_checksum(MIGRATION_V10_SQL);
        Connection::open(&database_path)
            .unwrap()
            .execute_batch(&format!(
                "CREATE TABLE schema_migrations (
                    version INTEGER PRIMARY KEY NOT NULL,
                    name TEXT NOT NULL,
                    checksum_sha256 TEXT NOT NULL,
                    applied_unix_seconds INTEGER NOT NULL
                 );
                 INSERT INTO schema_migrations VALUES (10, '{MIGRATION_V10_NAME}', '{checksum}', 1);
                 CREATE TABLE clients (
                    client_id TEXT PRIMARY KEY NOT NULL,
                    name TEXT NOT NULL,
                    platform TEXT NOT NULL,
                    access_token_hash TEXT NOT NULL,
                    last_seen_unix_seconds INTEGER NOT NULL
                 );
                 CREATE VIEW management_api_tokens AS SELECT client_id AS id FROM clients;
                 PRAGMA user_version = 10;"
            ))
            .unwrap();
        let database = Database::persistent(&root).unwrap();
        let plan = prepare(&database).unwrap();
        assert!(plan.finish_for_startup().is_err());
        assert!(
            !root.join(STARTUP_MIGRATION_MARKER_FILE).exists(),
            "failed standalone migration must not leave a startup rollback marker"
        );
        let connection = database.connect().unwrap();
        let version: u32 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        let agent_column: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_table_info('clients') WHERE name = 'agent_instance_id')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let fleet_table: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'fleet_local_state')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let ledger_rows: u32 = connection
            .query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(version, 10);
        assert!(!agent_column);
        assert!(!fleet_table);
        assert_eq!(ledger_rows, 1);
        drop(connection);
        drop(database);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn failed_v13_migration_preserves_v12_schema_ledger_and_data() {
        let root = temporary_directory("linklake-v13-migration-rollback");
        fs::create_dir_all(&root).expect("temporary directory should exist");
        let database_path = root.join("linklake.sqlite3");
        let connection = Connection::open(&database_path).expect("database should open");
        connection
            .execute_batch(
                "CREATE TABLE acme_config (
                    singleton_id INTEGER PRIMARY KEY NOT NULL,
                    enabled INTEGER NOT NULL,
                    environment TEXT NOT NULL,
                    directory_url TEXT NOT NULL,
                    contact_email TEXT NOT NULL,
                    terms_accepted INTEGER NOT NULL,
                    renew_before_days INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                 );
                 INSERT INTO acme_config VALUES (
                    1, 1, 'production', 'https://example.invalid/directory',
                    'atomic@example.com', 1, 21, 77
                 );
                 CREATE VIEW http_route_tls_policies AS
                    SELECT 'conflict' AS route_id, 'manual' AS mode,
                           0 AS redirect_http_to_https, 1 AS updated_at;",
            )
            .expect("v12 schema should be written");
        seed_v12_migration_ledger(&connection);
        drop(connection);

        let database = Database::persistent(&root).expect("database should lock");
        let plan = prepare(&database).expect("v12 migration should prepare");
        let error = plan.finish().expect_err("conflicting view must fail v13");
        assert!(
            error.to_string().contains("Cannot add a column to a view"),
            "unexpected v13 migration error: {error:#}"
        );

        let connection = database.connect().expect("database should reopen");
        let version: u32 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .expect("version should read");
        let ledger_rows: u32 = connection
            .query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .expect("ledger should read");
        let challenge_type_exists: bool = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_table_info('acme_config') WHERE name = 'challenge_type')",
                [],
                |row| row.get(0),
            )
            .expect("column state should read");
        let acme: (String, i64) = connection
            .query_row(
                "SELECT contact_email, updated_at FROM acme_config WHERE singleton_id = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("old data should remain");
        assert_eq!(version, 12);
        assert_eq!(ledger_rows, 3);
        assert!(!challenge_type_exists);
        assert_eq!(acme, ("atomic@example.com".into(), 77));
        drop(connection);
        drop(database);
        fs::remove_dir_all(root).expect("temporary directory should clean up");
    }
}
