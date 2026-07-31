use rusqlite::{Connection, DatabaseName, OpenFlags};
use std::{
    fs,
    path::{Path, PathBuf},
};
use uuid::Uuid;

pub(crate) fn backup(database_path: &Path, output_path: &Path) -> anyhow::Result<()> {
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
    let source = Connection::open_with_flags(database_path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    source.backup(DatabaseName::Main, &temporary, None)?;
    drop(source);
    validate_database(&temporary)?;
    remove_sidecars(&temporary)?;
    fs::rename(&temporary, output_path)?;
    Ok(())
}

pub(crate) fn restore(database_path: &Path, input_path: &Path) -> anyhow::Result<Option<PathBuf>> {
    anyhow::ensure!(
        input_path.is_file(),
        "backup input does not exist: {}",
        input_path.display()
    );
    validate_database(input_path)?;
    if let Some(parent) = database_path.parent() {
        fs::create_dir_all(parent)?;
    }

    // 先复制并校验到同一目录，最终替换只需要一次原子重命名。
    let staged = temporary_sibling(database_path, "restore");
    let source = Connection::open_with_flags(input_path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    source.backup(DatabaseName::Main, &staged, None)?;
    drop(source);
    validate_database(&staged)?;
    remove_sidecars(&staged)?;

    let previous = if database_path.exists() {
        checkpoint_database(database_path)?;
        let previous =
            database_path.with_extension(format!("sqlite3.pre-restore-{}", crate::unix_seconds()));
        fs::rename(database_path, &previous)?;
        preserve_sidecar(database_path, &previous, "-wal")?;
        preserve_sidecar(database_path, &previous, "-shm")?;
        Some(previous)
    } else {
        None
    };

    if let Err(error) = fs::rename(&staged, database_path) {
        if let Some(previous) = &previous {
            let _ = fs::rename(previous, database_path);
        }
        return Err(error.into());
    }
    Ok(previous)
}

fn validate_database(path: &Path) -> anyhow::Result<()> {
    let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let result: String = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    anyhow::ensure!(result == "ok", "SQLite integrity check failed: {result}");
    Ok(())
}

fn checkpoint_database(path: &Path) -> anyhow::Result<()> {
    let connection = Connection::open(path)?;
    connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    Ok(())
}

fn preserve_sidecar(database: &Path, previous: &Path, suffix: &str) -> anyhow::Result<()> {
    let source = PathBuf::from(format!("{}{suffix}", database.display()));
    if source.exists() {
        let destination = PathBuf::from(format!("{}{suffix}", previous.display()));
        fs::rename(source, destination)?;
    }
    Ok(())
}

fn remove_sidecars(database: &Path) -> anyhow::Result<()> {
    for suffix in ["-wal", "-shm"] {
        let sidecar = PathBuf::from(format!("{}{suffix}", database.display()));
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

#[cfg(test)]
mod tests {
    use super::{backup, restore};
    use rusqlite::Connection;
    use std::fs;
    use uuid::Uuid;

    #[test]
    fn backup_and_restore_preserve_a_consistent_database() {
        let root = std::env::temp_dir().join(format!("linklake-db-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).expect("test directory should be created");
        let database = root.join("linklake.sqlite3");
        let archive = root.join("backup.sqlite3");
        let connection = Connection::open(&database).expect("database should open");
        connection
            .execute_batch("CREATE TABLE sample(value TEXT); INSERT INTO sample VALUES ('before');")
            .expect("test data should be created");
        drop(connection);

        backup(&database, &archive).expect("backup should succeed");
        assert!(!fs::read_dir(&root)
            .expect("test directory should list")
            .filter_map(Result::ok)
            .any(|entry| entry.file_name().to_string_lossy().contains(".tmp-")));
        let connection = Connection::open(&database).expect("database should reopen");
        connection
            .execute("UPDATE sample SET value = 'after'", [])
            .expect("test data should update");
        drop(connection);

        let previous = restore(&database, &archive)
            .expect("restore should succeed")
            .expect("previous database should be preserved");
        let restored: String = Connection::open(&database)
            .expect("restored database should open")
            .query_row("SELECT value FROM sample", [], |row| row.get(0))
            .expect("restored value should exist");
        assert_eq!(restored, "before");
        assert!(previous.is_file());
        fs::remove_dir_all(root).expect("test directory should be removed");
    }
}
