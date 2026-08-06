//! HA 协调平面的存储入口。
//!
//! 业务 Catalog 在本批次仍使用现有 SQLite 数据库；只有需要跨实例共享的租约、
//! fencing、业务健康和 Fleet 账本通过本模块选择 SQLite 或 PostgreSQL。显式选择
//! PostgreSQL 时必须提供连接串，连接或迁移失败会阻止服务端启动。

use crate::{database::Database, postgres_migrations};
use rustls::{ClientConfig, RootCertStore};
use serde::Serialize;
use std::{
    env, fmt,
    net::IpAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};
use tokio::sync::{Mutex, OwnedMutexGuard};
use tokio_postgres::{
    config::{Host, SslMode},
    Client,
};
use tokio_postgres_rustls::MakeRustlsConnect;

pub(crate) const STORAGE_BACKEND_ENV: &str = "LINKLAKE_STORAGE_BACKEND";
pub(crate) const POSTGRES_URL_ENV: &str = "LINKLAKE_POSTGRES_URL";
pub(crate) const POSTGRES_POOL_SIZE_ENV: &str = "LINKLAKE_POSTGRES_POOL_SIZE";
pub(crate) const POSTGRES_INSECURE_LOOPBACK_ENV: &str = "LINKLAKE_POSTGRES_ALLOW_INSECURE_LOOPBACK";

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
    Postgres(Arc<PostgresPool>),
}

impl CoordinationStorage {
    pub(crate) async fn open(config: &StorageConfig, sqlite: &Database) -> anyhow::Result<Self> {
        match config.backend {
            StorageBackend::Sqlite => Ok(Self::Sqlite(sqlite.clone())),
            StorageBackend::Postgres => {
                let url = config
                    .postgres_url
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("PostgreSQL URL was not configured"))?;
                let pool = PostgresPool::connect(url).await?;
                let mut client = pool.acquire().await;
                postgres_migrations::apply(&mut client).await?;
                drop(client);
                Ok(Self::Postgres(Arc::new(pool)))
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

    pub(crate) async fn postgres_client(&self) -> anyhow::Result<OwnedMutexGuard<Client>> {
        let Self::Postgres(pool) = self else {
            anyhow::bail!("operation requires the PostgreSQL coordination backend");
        };
        Ok(pool.acquire().await)
    }

    pub(crate) async fn database_unix_seconds(&self) -> anyhow::Result<u64> {
        match self {
            Self::Sqlite(database) => database.with_connection(|connection| {
                let value: i64 = connection.query_row(
                    "SELECT CAST(unixepoch('now') AS INTEGER)",
                    [],
                    |row| row.get(0),
                )?;
                nonnegative_time(value)
            }),
            Self::Postgres(_) => {
                let client = self.postgres_client().await?;
                let row = client
                    .query_one(
                        "SELECT CAST(EXTRACT(EPOCH FROM clock_timestamp()) AS BIGINT)",
                        &[],
                    )
                    .await?;
                nonnegative_time(row.get::<_, i64>(0))
            }
        }
    }
}

pub(crate) struct PostgresPool {
    clients: Vec<Arc<Mutex<Client>>>,
    next: AtomicUsize,
}

impl PostgresPool {
    async fn connect(url: &str) -> anyhow::Result<Self> {
        let mut config = url
            .parse::<tokio_postgres::Config>()
            .map_err(|_| anyhow::anyhow!("PostgreSQL connection configuration is invalid"))?;
        let insecure_loopback = parse_boolean_environment(POSTGRES_INSECURE_LOOPBACK_ENV)?;
        if insecure_loopback {
            anyhow::ensure!(
                config.get_hosts().iter().all(loopback_host),
                "{POSTGRES_INSECURE_LOOPBACK_ENV} is only valid for loopback or Unix-socket PostgreSQL hosts"
            );
            config.ssl_mode(SslMode::Disable);
        } else {
            // Prefer 模式允许服务端拒绝 TLS 后回退明文；生产默认必须彻底禁止回退。
            config.ssl_mode(SslMode::Require);
        }
        config.application_name("linklake-server-ha");

        let pool_size = env::var(POSTGRES_POOL_SIZE_ENV)
            .ok()
            .map(|value| value.parse::<usize>())
            .transpose()
            .map_err(|_| anyhow::anyhow!("{POSTGRES_POOL_SIZE_ENV} must be an integer"))?
            .unwrap_or(4);
        anyhow::ensure!(
            (1..=32).contains(&pool_size),
            "{POSTGRES_POOL_SIZE_ENV} must be between 1 and 32"
        );
        let tls = postgres_tls_connector()?;
        let mut clients = Vec::with_capacity(pool_size);
        for _ in 0..pool_size {
            let (client, connection) = config.connect(tls.clone()).await.map_err(|_| {
                anyhow::anyhow!("could not establish a verified PostgreSQL connection")
            })?;
            tokio::spawn(async move {
                if connection.await.is_err() {
                    // 驱动错误可能包含连接目标信息，因此这里只记录固定消息。
                    tracing::error!("PostgreSQL connection task stopped");
                }
            });
            clients.push(Arc::new(Mutex::new(client)));
        }
        Ok(Self {
            clients,
            next: AtomicUsize::new(0),
        })
    }

    async fn acquire(&self) -> OwnedMutexGuard<Client> {
        let index = self.next.fetch_add(1, Ordering::Relaxed) % self.clients.len();
        self.clients[index].clone().lock_owned().await
    }
}

fn postgres_tls_connector() -> anyhow::Result<MakeRustlsConnect> {
    let native = rustls_native_certs::load_native_certs();
    let mut roots = RootCertStore::empty();
    for certificate in native.certs {
        roots
            .add(certificate)
            .map_err(|_| anyhow::anyhow!("could not load a native PostgreSQL trust anchor"))?;
    }
    anyhow::ensure!(
        !roots.is_empty(),
        "no native trust anchors are available for PostgreSQL TLS verification"
    );
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(MakeRustlsConnect::new(config))
}

fn loopback_host(host: &Host) -> bool {
    match host {
        Host::Tcp(host) => {
            host.eq_ignore_ascii_case("localhost")
                || host
                    .parse::<IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
        }
        #[cfg(unix)]
        Host::Unix(_) => true,
        #[allow(unreachable_patterns)]
        _ => false,
    }
}

fn parse_boolean_environment(name: &str) -> anyhow::Result<bool> {
    match env::var(name).ok().as_deref().map(str::trim) {
        None | Some("") | Some("0") | Some("false") | Some("FALSE") => Ok(false),
        Some("1") | Some("true") | Some("TRUE") => Ok(true),
        Some(_) => anyhow::bail!("{name} must be true or false"),
    }
}

fn nonnegative_time(value: i64) -> anyhow::Result<u64> {
    u64::try_from(value).map_err(|_| anyhow::anyhow!("database clock returned a negative value"))
}
