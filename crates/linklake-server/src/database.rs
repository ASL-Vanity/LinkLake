//! LinkLake 服务端共享 SQLite 数据库入口。
//!
//! 所有 Catalog 都必须从同一个 `Database` 句柄创建连接，避免各模块自行选择
//! PRAGMA、超时和内存数据库语义。跨 Catalog 的原子操作通过 `with_transaction`
//! 使用一条独立连接完成，后续 Fleet reconcile 不需要借用任意 Catalog 的内部连接。

use fs2::FileExt;
use rusqlite::{Connection, OpenFlags, TransactionBehavior};
use std::{
    fs::{self, File, OpenOptions},
    io::{Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub(crate) struct Database {
    inner: Arc<DatabaseInner>,
}

struct DatabaseInner {
    location: DatabaseLocation,
    // 内存数据库必须至少保留一条连接，否则最后一个 Catalog 暂时释放连接时数据会消失。
    _memory_keeper: Option<Mutex<Connection>>,
    // 文件锁由操作系统持有；进程异常退出时会自动释放，不依赖删除锁文件。
    _process_lock: Option<File>,
}

enum DatabaseLocation {
    File(PathBuf),
    Memory(String),
}

impl Database {
    pub(crate) fn open(data_dir: Option<&Path>) -> anyhow::Result<Self> {
        match data_dir {
            Some(data_dir) => Self::persistent(data_dir),
            None => Self::memory(),
        }
    }

    pub(crate) fn persistent(data_dir: &Path) -> anyhow::Result<Self> {
        fs::create_dir_all(data_dir)?;
        let data_dir = data_dir.canonicalize()?;
        let database_path = data_dir.join("linklake.sqlite3");
        let lock_path = data_dir.join("linklake.sqlite3.lock");
        let mut process_lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)?;
        process_lock.try_lock_exclusive().map_err(|error| {
            anyhow::anyhow!(
                "another LinkLake server process is already using {}: {error}",
                database_path.display()
            )
        })?;
        process_lock.set_len(0)?;
        process_lock.seek(SeekFrom::Start(0))?;
        writeln!(process_lock, "pid={}", std::process::id())?;
        process_lock.sync_data()?;
        let maintenance = crate::disaster_recovery::acquire_restore_maintenance(&data_dir)?;
        crate::disaster_recovery::recover_interrupted_restore(&data_dir, &maintenance)?;
        drop(maintenance);

        let database = Self {
            inner: Arc::new(DatabaseInner {
                location: DatabaseLocation::File(database_path),
                _memory_keeper: None,
                _process_lock: Some(process_lock),
            }),
        };
        // 启动时立即验证路径、权限和 PRAGMA，不能等到第一个 Catalog 才失败。
        drop(database.connect()?);
        Ok(database)
    }

    pub(crate) fn memory() -> anyhow::Result<Self> {
        let uri = format!(
            "file:linklake-{}?mode=memory&cache=shared",
            uuid::Uuid::new_v4()
        );
        let keeper = open_memory_connection(&uri)?;
        Ok(Self {
            inner: Arc::new(DatabaseInner {
                location: DatabaseLocation::Memory(uri),
                _memory_keeper: Some(Mutex::new(keeper)),
                _process_lock: None,
            }),
        })
    }

    pub(crate) fn connect(&self) -> rusqlite::Result<Connection> {
        match &self.inner.location {
            DatabaseLocation::File(path) => {
                let connection = Connection::open(path)?;
                configure_connection(&connection, true)?;
                Ok(connection)
            }
            DatabaseLocation::Memory(uri) => open_memory_connection(uri),
        }
    }

    pub(crate) fn path(&self) -> Option<&Path> {
        match &self.inner.location {
            DatabaseLocation::File(path) => Some(path),
            DatabaseLocation::Memory(_) => None,
        }
    }

    pub(crate) fn is_persistent(&self) -> bool {
        matches!(self.inner.location, DatabaseLocation::File(_))
    }

    pub(crate) fn with_connection<T>(
        &self,
        operation: impl FnOnce(&Connection) -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        let connection = self.connect()?;
        operation(&connection)
    }

    pub(crate) fn with_transaction<T>(
        &self,
        operation: impl FnOnce(&rusqlite::Transaction<'_>) -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let value = operation(&transaction)?;
        transaction.commit()?;
        Ok(value)
    }
}

fn open_memory_connection(uri: &str) -> rusqlite::Result<Connection> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_CREATE
        | OpenFlags::SQLITE_OPEN_URI;
    let connection = Connection::open_with_flags(uri, flags)?;
    configure_connection(&connection, false)?;
    Ok(connection)
}

fn configure_connection(connection: &Connection, persistent: bool) -> rusqlite::Result<()> {
    connection.busy_timeout(BUSY_TIMEOUT)?;
    connection.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA synchronous = NORMAL;
         PRAGMA temp_store = MEMORY;
         PRAGMA trusted_schema = OFF;",
    )?;
    if persistent {
        let journal_mode: String =
            connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
        if !journal_mode.eq_ignore_ascii_case("wal") {
            return Err(rusqlite::Error::InvalidQuery);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_directory(prefix: &str) -> PathBuf {
        std::env::temp_dir().join(format!("{prefix}-{}", uuid::Uuid::new_v4()))
    }

    #[test]
    fn persistent_connections_share_strict_pragmas() {
        let root = temporary_directory("linklake-database-pragmas");
        let database = Database::persistent(&root).expect("database should open");
        let connection = database.connect().expect("connection should open");
        let foreign_keys: i64 = connection
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .unwrap();
        let journal_mode: String = connection
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        let synchronous: i64 = connection
            .query_row("PRAGMA synchronous", [], |row| row.get(0))
            .unwrap();
        assert_eq!(foreign_keys, 1);
        assert_eq!(journal_mode.to_ascii_lowercase(), "wal");
        assert_eq!(synchronous, 1);
        drop(connection);
        drop(database);
        fs::remove_dir_all(root).expect("temporary database should clean up");
    }

    #[test]
    fn cloned_memory_database_is_shared() {
        let database = Database::memory().expect("memory database should open");
        database
            .with_connection(|connection| {
                connection.execute_batch(
                    "CREATE TABLE shared_state(value TEXT NOT NULL);
                     INSERT INTO shared_state VALUES ('visible');",
                )?;
                Ok(())
            })
            .unwrap();
        let clone = database.clone();
        let value: String = clone
            .with_connection(|connection| {
                Ok(
                    connection.query_row("SELECT value FROM shared_state", [], |row| {
                        row.get::<_, String>(0)
                    })?,
                )
            })
            .unwrap();
        assert_eq!(value, "visible");
    }

    #[test]
    fn transaction_rolls_back_all_tables_on_error() {
        let database = Database::memory().expect("memory database should open");
        database
            .with_connection(|connection| {
                connection.execute_batch(
                    "CREATE TABLE first_table(value INTEGER NOT NULL);
                     CREATE TABLE second_table(value INTEGER NOT NULL);",
                )?;
                Ok(())
            })
            .unwrap();
        let result: anyhow::Result<()> = database.with_transaction(|transaction| {
            transaction.execute("INSERT INTO first_table VALUES (1)", [])?;
            transaction.execute("INSERT INTO second_table VALUES (2)", [])?;
            anyhow::bail!("forced rollback")
        });
        assert!(result.is_err());
        database
            .with_connection(|connection| {
                let first: i64 =
                    connection
                        .query_row("SELECT COUNT(*) FROM first_table", [], |row| row.get(0))?;
                let second: i64 =
                    connection
                        .query_row("SELECT COUNT(*) FROM second_table", [], |row| row.get(0))?;
                assert_eq!((first, second), (0, 0));
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn second_server_process_handle_is_rejected() {
        let root = temporary_directory("linklake-database-lock");
        let first = Database::persistent(&root).expect("first database should lock");
        let error = Database::persistent(&root)
            .err()
            .expect("second database handle must fail");
        assert!(error
            .to_string()
            .contains("another LinkLake server process"));
        drop(first);
        Database::persistent(&root).expect("lock should be released after drop");
        fs::remove_dir_all(root).expect("temporary database should clean up");
    }
}
