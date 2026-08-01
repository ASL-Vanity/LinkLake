//! SQLite 架构版本检查、迁移前备份与提交。

use rusqlite::Connection;
use std::{fs, path::Path};

pub(crate) const CURRENT_SCHEMA_VERSION: u32 = 3;

pub(crate) struct MigrationPlan {
    database_path: std::path::PathBuf,
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
        let connection = Connection::open(&self.database_path)?;
        connection.execute_batch(&format!(
            "BEGIN IMMEDIATE; PRAGMA user_version = {CURRENT_SCHEMA_VERSION}; COMMIT;"
        ))?;
        Ok(())
    }
}

pub(crate) fn prepare(data_dir: &Path) -> anyhow::Result<MigrationPlan> {
    fs::create_dir_all(data_dir)?;
    let database_path = data_dir.join("linklake.sqlite3");
    let existed = database_path.exists();
    let connection = Connection::open(&database_path)?;
    let from_version =
        connection.query_row("PRAGMA user_version", [], |row| row.get::<_, u32>(0))?;
    anyhow::ensure!(
        from_version <= CURRENT_SCHEMA_VERSION,
        "database schema version {from_version} is newer than this LinkLake build ({CURRENT_SCHEMA_VERSION})"
    );
    let has_application_tables = existed
        && connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%')",
            [],
            |row| row.get::<_, bool>(0),
        )?;
    drop(connection);

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
        crate::database_tools::backup(&database_path, &backup)?;
        Some(backup)
    } else {
        None
    };

    Ok(MigrationPlan {
        database_path,
        from_version,
        backup_path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn existing_database_is_backed_up_and_versioned_after_success() {
        let root =
            std::env::temp_dir().join(format!("linklake-migration-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).expect("temporary directory should exist");
        let database = root.join("linklake.sqlite3");
        Connection::open(&database)
            .expect("database should open")
            .execute_batch("CREATE TABLE legacy(value TEXT); INSERT INTO legacy VALUES ('kept');")
            .expect("legacy schema should write");

        let plan = prepare(&root).expect("migration should prepare");
        assert_eq!(plan.source_version(), 0);
        let backup = plan
            .backup_path()
            .expect("existing schema should be backed up")
            .to_path_buf();
        plan.finish().expect("migration should finish");

        let version: u32 = Connection::open(&database)
            .expect("database should reopen")
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .expect("version should read");
        assert_eq!(version, CURRENT_SCHEMA_VERSION);
        let value: String = Connection::open(&backup)
            .expect("backup should open")
            .query_row("SELECT value FROM legacy", [], |row| row.get(0))
            .expect("backup content should remain");
        assert_eq!(value, "kept");
        fs::remove_dir_all(root).expect("temporary directory should clean up");
    }

    #[test]
    fn newer_database_is_rejected_without_modification() {
        let root =
            std::env::temp_dir().join(format!("linklake-newer-schema-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).expect("temporary directory should exist");
        let database = root.join("linklake.sqlite3");
        Connection::open(&database)
            .expect("database should open")
            .execute_batch("PRAGMA user_version = 999;")
            .expect("future version should write");
        assert!(prepare(&root).is_err());
        fs::remove_dir_all(root).expect("temporary directory should clean up");
    }
}
