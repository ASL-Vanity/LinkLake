//! HA 协调平面的存储入口。
//!
//! 业务 Catalog 在本批次仍使用现有 SQLite 数据库；只有需要跨实例共享的租约、
//! fencing、业务健康和 Fleet 账本通过本模块选择 SQLite 或 PostgreSQL。显式选择
//! PostgreSQL 时必须提供连接串，连接或迁移失败会阻止服务端启动。

use crate::{database::Database, postgres_migrations};
use postgres::{Client, NoTls, Transaction};
use serde::Serialize;
use std::{
    env, fmt,
    sync::{Arc, Mutex},
};

pub(crate) const STORAGE_BACKEND_ENV: &str = "LINKLAKE_STORAGE_BACKEND";
pub(crate) const POSTGRES_URL_ENV: &str = "LINKLAKE_POSTGRES_URL";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StorageBackend {
    #[default]
    Sqlite,
    Postgres,
}

impl StorageBackend {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Sqlite => "sqlite",
            Self::Postgres => "postgres",
        }
    }
}

impl std::str::FromStr for StorageBackend {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "sqlite" => Ok(Self::Sqlite),
            "postgres" | "postgresql" => Ok(Self::Postgres),
            other => {
                anyhow::bail!("{STORAGE_BACKEND_ENV} must be sqlite or postgres, got {other:?}")
            }
        }
    }
}

#[derive(Clone)]
pub(crate) struct StorageConfig {
    backend: StorageBackend,
    postgres_url: Option<String>,
}

impl fmt::Debug for StorageConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StorageConfig")
            .field("backend", &self.backend)
            .field(
                "postgres_url",
                &self.postgres_url.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl StorageConfig {
    pub(crate) fn from_environment() -> anyhow::Result<Self> {
        let backend = env::var(STORAGE_BACKEND_ENV)
            .unwrap_or_else(|_| "sqlite".to_owned())
            .parse()?;
        let postgres_url = env::var(POSTGRES_URL_ENV)
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty());
        match backend {
            StorageBackend::Sqlite => anyhow::ensure!(
                postgres_url.is_none(),
                "{POSTGRES_URL_ENV} is set while {STORAGE_BACKEND_ENV}=sqlite; refusing ambiguous storage configuration"
            ),
            StorageBackend::Postgres => anyhow::ensure!(
                postgres_url.is_some(),
                "{POSTGRES_URL_ENV} is required when {STORAGE_BACKEND_ENV}=postgres"
            ),
        }
        Ok(Self {
            backend,
            postgres_url,
        })
    }

    pub(crate) fn backend(&self) -> StorageBackend {
        self.backend
    }
}

#[derive(Clone)]
pub(crate) enum CoordinationStorage {
    Sqlite(Database),
    Postgres(Arc<Mutex<Client>>),
}

impl CoordinationStorage {
    pub(crate) fn open(config: &StorageConfig, sqlite: &Database) -> anyhow::Result<Self> {
        match config.backend {
            StorageBackend::Sqlite => Ok(Self::Sqlite(sqlite.clone())),
            StorageBackend::Postgres => {
                let url = config
                    .postgres_url
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("PostgreSQL URL was not configured"))?;
                let mut client = Client::connect(url, NoTls)
                    .map_err(|error| anyhow::anyhow!("could not connect to PostgreSQL: {error}"))?;
                postgres_migrations::apply(&mut client)?;
                Ok(Self::Postgres(Arc::new(Mutex::new(client))))
            }
        }
    }

    pub(crate) fn backend(&self) -> StorageBackend {
        match self {
            Self::Sqlite(_) => StorageBackend::Sqlite,
            Self::Postgres(_) => StorageBackend::Postgres,
        }
    }

    pub(crate) fn sqlite(&self) -> anyhow::Result<&Database> {
        match self {
            Self::Sqlite(database) => Ok(database),
            Self::Postgres(_) => {
                anyhow::bail!("operation requires the SQLite coordination backend")
            }
        }
    }

    pub(crate) fn with_postgres<T>(
        &self,
        operation: impl FnOnce(&mut Client) -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        let Self::Postgres(client) = self else {
            anyhow::bail!("operation requires the PostgreSQL coordination backend");
        };
        let mut client = client
            .lock()
            .map_err(|_| anyhow::anyhow!("PostgreSQL client lock poisoned"))?;
        operation(&mut client)
    }

    pub(crate) fn with_postgres_transaction<T>(
        &self,
        operation: impl FnOnce(&mut Transaction<'_>) -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        self.with_postgres(|client| {
            let mut transaction = client.transaction()?;
            let value = operation(&mut transaction)?;
            transaction.commit()?;
            Ok(value)
        })
    }

    pub(crate) fn database_unix_seconds(&self) -> anyhow::Result<u64> {
        match self {
            Self::Sqlite(database) => database.with_connection(|connection| {
                let value: i64 = connection.query_row(
                    "SELECT CAST(unixepoch('now') AS INTEGER)",
                    [],
                    |row| row.get(0),
                )?;
                nonnegative_time(value)
            }),
            Self::Postgres(_) => self.with_postgres(|client| {
                let row = client.query_one(
                    "SELECT CAST(EXTRACT(EPOCH FROM clock_timestamp()) AS BIGINT)",
                    &[],
                )?;
                nonnegative_time(row.get::<_, i64>(0))
            }),
        }
    }
}

fn nonnegative_time(value: i64) -> anyhow::Result<u64> {
    u64::try_from(value).map_err(|_| anyhow::anyhow!("database clock returned a negative value"))
}
