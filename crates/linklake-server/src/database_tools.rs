use rusqlite::{
    backup::{Backup, StepResult},
    Connection, OpenFlags,
};
use std::{
    fs,
    path::{Path, PathBuf},
};
use uuid::Uuid;

pub(crate) const MAX_DATABASE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const BACKUP_PAGES_PER_STEP: i32 = 16;

#[derive(Clone, Copy)]
enum SnapshotPermissions {
    ManagedState,
    ExternalBackup,
}

struct PendingDatabaseFile {
    path: PathBuf,
    armed: bool,
}

impl PendingDatabaseFile {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PendingDatabaseFile {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let _ = fs::remove_file(&self.path);
        let _ = remove_sidecars(&self.path);
    }
}

pub(crate) fn backup(database_path: &Path, output_path: &Path) -> anyhow::Result<()> {
    backup_with_permissions(
        database_path,
        output_path,
        SnapshotPermissions::ExternalBackup,
    )
}

pub(crate) fn backup_managed(database_path: &Path, output_path: &Path) -> anyhow::Result<()> {
    backup_with_permissions(
        database_path,
        output_path,
        SnapshotPermissions::ManagedState,
    )
}

fn backup_with_permissions(
    database_path: &Path,
    output_path: &Path,
    permissions: SnapshotPermissions,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        database_path.is_file(),
        "LinkLake database does not exist: {}",
        database_path.display()
    );
    anyhow::ensure!(
        !output_path.exists(),
        "backup output already exists: {}",
        output_path.display()
    );
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = temporary_sibling(output_path, "backup");
    let mut pending = PendingDatabaseFile::new(temporary.clone());
    copy_database_snapshot(database_path, &temporary, MAX_DATABASE_BYTES, permissions)?;
    validate_database(&temporary)?;
    crate::database_migrations::validate_restore_database(&temporary)?;
    remove_sidecars(&temporary)?;
    crate::disaster_recovery::install_no_replace(&temporary, output_path)?;
    pending.disarm();
    Ok(())
}

pub(crate) fn stage_restore(input_path: &Path, staged_path: &Path) -> anyhow::Result<()> {
    anyhow::ensure!(
        input_path.is_file(),
        "backup input does not exist: {}",
        input_path.display()
    );
    validate_database(input_path)?;
    crate::database_migrations::validate_restore_database(input_path)?;
    anyhow::ensure!(
        !staged_path.exists(),
        "restore staging output already exists: {}",
        staged_path.display()
    );
    if let Some(parent) = staged_path.parent() {
        fs::create_dir_all(parent)?;
        crate::disaster_recovery::restrict_directory_permissions(parent)?;
    }
    let mut pending = PendingDatabaseFile::new(staged_path.to_path_buf());
    copy_database_snapshot(
        input_path,
        staged_path,
        MAX_DATABASE_BYTES,
        SnapshotPermissions::ManagedState,
    )?;
    validate_database(staged_path)?;
    crate::database_migrations::validate_restore_database(staged_path)?;
    remove_sidecars(staged_path)?;
    pending.disarm();
    Ok(())
}

fn copy_database_snapshot(
    source_path: &Path,
    output_path: &Path,
    limit: u64,
    permissions: SnapshotPermissions,
) -> anyhow::Result<()> {
    let result = (|| -> anyhow::Result<()> {
        let source = Connection::open_with_flags(source_path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let page_size = pragma_u64(&source, "page_size")?;
        let initial_pages = pragma_u64(&source, "page_count")?;
        ensure_page_budget(initial_pages, page_size, limit)?;

        let output = match permissions {
            SnapshotPermissions::ManagedState => {
                crate::disaster_recovery::create_managed_new_file(output_path)?
            }
            SnapshotPermissions::ExternalBackup => {
                crate::disaster_recovery::create_external_backup_new_file(output_path)?
            }
        };
        drop(output);
        let mut destination =
            Connection::open_with_flags(output_path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        let backup = Backup::new(&source, &mut destination)?;
        loop {
            let step = backup.step(BACKUP_PAGES_PER_STEP)?;
            let progress = backup.progress();
            anyhow::ensure!(
                progress.pagecount >= 0,
                "SQLite backup page count is invalid"
            );
            ensure_page_budget(progress.pagecount as u64, page_size, limit)?;
            if let Ok(metadata) = fs::metadata(output_path) {
                anyhow::ensure!(
                    metadata.len() <= limit,
                    "SQLite backup exceeds the maximum supported size"
                );
            }
            match step {
                StepResult::Done => break,
                StepResult::More => {}
                StepResult::Busy => anyhow::bail!("SQLite backup source is busy"),
                StepResult::Locked => anyhow::bail!("SQLite backup source is locked"),
                _ => anyhow::bail!("SQLite backup returned an unsupported step result"),
            }
        }
        drop(backup);
        drop(destination);
        let final_bytes = fs::metadata(output_path)?.len();
        anyhow::ensure!(
            final_bytes <= limit,
            "SQLite backup exceeds the maximum supported size"
        );
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(output_path);
        let _ = remove_sidecars(output_path);
    }
    result
}

fn pragma_u64(connection: &Connection, name: &str) -> anyhow::Result<u64> {
    let value = connection.query_row(&format!("PRAGMA {name}"), [], |row| row.get::<_, i64>(0))?;
    anyhow::ensure!(value >= 0, "SQLite {name} is invalid");
    Ok(value as u64)
}

fn ensure_page_budget(page_count: u64, page_size: u64, limit: u64) -> anyhow::Result<()> {
    let bytes = page_count
        .checked_mul(page_size)
        .ok_or_else(|| anyhow::anyhow!("SQLite backup size overflows the supported range"))?;
    anyhow::ensure!(
        bytes <= limit,
        "SQLite backup exceeds the maximum supported size"
    );
    Ok(())
}

pub(crate) fn validate_database(path: &Path) -> anyhow::Result<()> {
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let result: String = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    anyhow::ensure!(result == "ok", "SQLite integrity check failed: {result}");
    let mut statement = connection.prepare("PRAGMA foreign_key_check")?;
    let mut rows = statement.query([])?;
    anyhow::ensure!(rows.next()?.is_none(), "SQLite foreign key check failed");
    Ok(())
}

pub(crate) fn checkpoint_database(path: &Path) -> anyhow::Result<()> {
    let connection = Connection::open(path)?;
    connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    Ok(())
}

pub(crate) fn remove_sidecars(database: &Path) -> anyhow::Result<()> {
    for suffix in ["-wal", "-shm"] {
        let sidecar = sidecar_path(database, suffix);
        if sidecar.exists() {
            fs::remove_file(sidecar)?;
        }
    }
    Ok(())
}

fn temporary_sibling(path: &Path, purpose: &str) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("linklake.sqlite3");
    path.with_file_name(format!("{name}.{purpose}-{}.tmp", Uuid::new_v4()))
}

fn sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

#[cfg(test)]
mod tests {
    use super::{
        backup, copy_database_snapshot, stage_restore, validate_database, SnapshotPermissions,
    };
    use rusqlite::Connection;
    use std::fs;
    use uuid::Uuid;

    #[test]
    fn backup_and_staged_restore_preserve_a_consistent_database() {
        let root = std::env::temp_dir().join(format!("linklake-db-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let database = root.join("linklake.sqlite3");
        let archive = root.join("backup.sqlite3");
        Connection::open(&database)
            .unwrap()
            .execute_batch("CREATE TABLE sample(value TEXT); INSERT INTO sample VALUES ('before');")
            .unwrap();

        backup(&database, &archive).unwrap();
        Connection::open(&database)
            .unwrap()
            .execute("UPDATE sample SET value = 'after'", [])
            .unwrap();

        let staged = root.join("staging/linklake.sqlite3");
        stage_restore(&archive, &staged).unwrap();
        let staged_value: String = Connection::open(&staged)
            .unwrap()
            .query_row("SELECT value FROM sample", [], |row| row.get(0))
            .unwrap();
        let current_value: String = Connection::open(&database)
            .unwrap()
            .query_row("SELECT value FROM sample", [], |row| row.get(0))
            .unwrap();
        assert_eq!(staged_value, "before");
        assert_eq!(current_value, "after");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn backup_never_replaces_an_existing_output() {
        let root = std::env::temp_dir().join(format!("linklake-db-output-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let database = root.join("linklake.sqlite3");
        let output = root.join("backup.sqlite3");
        Connection::open(&database)
            .unwrap()
            .execute_batch("CREATE TABLE sample(value TEXT);")
            .unwrap();
        fs::write(&output, b"preexisting").unwrap();
        assert!(backup(&database, &output).is_err());
        assert_eq!(fs::read(&output).unwrap(), b"preexisting");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn backup_validation_failure_removes_plaintext_temporary_database_files() {
        let root = std::env::temp_dir().join(format!("linklake-db-cleanup-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let database = root.join("linklake.sqlite3");
        let output = root.join("backup.sqlite3");
        Connection::open(&database)
            .unwrap()
            .execute_batch("CREATE TABLE sample(value TEXT); PRAGMA user_version = 999;")
            .unwrap();

        let error = backup(&database, &output).unwrap_err();
        assert!(error.to_string().contains("newer than this LinkLake build"));
        assert!(!output.exists());
        assert!(!fs::read_dir(&root)
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                name.contains(".backup-") || name.ends_with("-wal") || name.ends_with("-shm")
            }));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn staged_restore_rejects_a_newer_schema_without_creating_output() {
        let root = std::env::temp_dir().join(format!("linklake-db-newer-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let input = root.join("future.sqlite3");
        let staged = root.join("staged.sqlite3");
        Connection::open(&input)
            .unwrap()
            .execute_batch("CREATE TABLE sample(value TEXT); PRAGMA user_version = 999;")
            .unwrap();
        let error = stage_restore(&input, &staged).unwrap_err();
        assert!(error.to_string().contains("newer than this LinkLake build"));
        assert!(!staged.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn database_validation_rejects_foreign_key_violations() {
        let root = std::env::temp_dir().join(format!("linklake-db-fk-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let database = root.join("invalid.sqlite3");
        Connection::open(&database)
            .unwrap()
            .execute_batch(
                "PRAGMA foreign_keys = OFF;
                 CREATE TABLE parent(id INTEGER PRIMARY KEY);
                 CREATE TABLE child(parent_id INTEGER REFERENCES parent(id));
                 INSERT INTO child VALUES (42);",
            )
            .unwrap();
        assert!(validate_database(&database).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn database_copy_enforces_the_limit_before_leaving_an_output() {
        let root = std::env::temp_dir().join(format!("linklake-db-limit-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let database = root.join("source.sqlite3");
        let output = root.join("too-large.sqlite3");
        Connection::open(&database)
            .unwrap()
            .execute_batch(
                "CREATE TABLE sample(value BLOB); INSERT INTO sample VALUES (zeroblob(8192));",
            )
            .unwrap();
        let error =
            copy_database_snapshot(&database, &output, 1, SnapshotPermissions::ManagedState)
                .unwrap_err();
        assert!(error.to_string().contains("maximum supported size"));
        assert!(!output.exists());
        fs::remove_dir_all(root).unwrap();
    }
}
