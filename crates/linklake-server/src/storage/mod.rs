//! HA 协调平面的存储入口。
//!
//! PostgreSQL 保存共享身份、策略和业务状态；本机 SQLite 保留独立实例标识、
//! 更新暂存和待确认流量账务。数据库连接或迁移失败会阻止服务启动。

use crate::{database::Database, postgres_migrations};
use rustls::{ClientConfig, RootCertStore};
use serde::Serialize;
use std::{
    env, fmt,
    net::IpAddr,
    ops::{Deref, DerefMut},
    sync::Arc,
    time::Duration,
};
use tokio::sync::{mpsc, Mutex, OwnedMutexGuard};
use tokio::time::timeout;
use tokio_postgres::{
    config::{Host, SslMode},
    Client,
};
use tokio_postgres_rustls::MakeRustlsConnect;

pub(crate) const STORAGE_BACKEND_ENV: &str = "LINKLAKE_STORAGE_BACKEND";
pub(crate) const POSTGRES_URL_ENV: &str = "LINKLAKE_POSTGRES_URL";
pub(crate) const POSTGRES_POOL_SIZE_ENV: &str = "LINKLAKE_POSTGRES_POOL_SIZE";
pub(crate) const POSTGRES_INSECURE_LOOPBACK_ENV: &str = "LINKLAKE_POSTGRES_ALLOW_INSECURE_LOOPBACK";
pub(crate) const POSTGRES_ACQUIRE_TIMEOUT_ENV: &str = "LINKLAKE_POSTGRES_ACQUIRE_TIMEOUT_SECONDS";
pub(crate) const POSTGRES_CONNECT_TIMEOUT_ENV: &str = "LINKLAKE_POSTGRES_CONNECT_TIMEOUT_SECONDS";
pub(crate) const POSTGRES_HEALTH_TIMEOUT_ENV: &str = "LINKLAKE_POSTGRES_HEALTH_TIMEOUT_SECONDS";
pub(crate) const HA_REPLICATED_STATE_ENV: &str = "LINKLAKE_HA_REPLICATED_STATE";

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
    replicated_state: bool,
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
            .field("replicated_state", &self.replicated_state)
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
        let replicated_state = parse_boolean_environment(HA_REPLICATED_STATE_ENV)?;
        Self::from_parts(backend, postgres_url, replicated_state)
    }

    fn from_parts(
        backend: StorageBackend,
        postgres_url: Option<String>,
        replicated_state: bool,
    ) -> anyhow::Result<Self> {
        match backend {
            StorageBackend::Sqlite => {
                anyhow::ensure!(
                    postgres_url.is_none(),
                    "{POSTGRES_URL_ENV} is set while {STORAGE_BACKEND_ENV}=sqlite; refusing ambiguous storage configuration"
                );
                anyhow::ensure!(
                    !replicated_state,
                    "{HA_REPLICATED_STATE_ENV} is only valid with PostgreSQL coordination storage"
                );
            }
            StorageBackend::Postgres => {
                anyhow::ensure!(
                    postgres_url.is_some(),
                    "{POSTGRES_URL_ENV} is required when {STORAGE_BACKEND_ENV}=postgres"
                );
                // 兼容旧环境变量；共享业务状态不再依赖外部逐副本复制。
            }
        }
        Ok(Self {
            backend,
            postgres_url,
            replicated_state: backend == StorageBackend::Postgres,
        })
    }

    pub(crate) fn backend(&self) -> StorageBackend {
        self.backend
    }

    pub(crate) fn replicated_state(&self) -> bool {
        self.replicated_state
    }
}

#[derive(Clone)]
pub(crate) enum CoordinationStorage {
    Sqlite(Database),
    Postgres(Arc<PostgresPool>),
}

impl CoordinationStorage {
    pub(crate) async fn initialize_empty_postgres(config: &StorageConfig) -> anyhow::Result<()> {
        anyhow::ensure!(
            config.backend == StorageBackend::Postgres,
            "initialization requires PostgreSQL storage"
        );
        let url = config
            .postgres_url
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("PostgreSQL URL was not configured"))?;
        let pool = Arc::new(PostgresPool::connect(url).await?);
        let mut client = pool.acquire().await?;
        postgres_migrations::initialize_empty(&mut client).await
    }

    /// 停服维护使用现有共享数据库，不启动 HA、创建本机目录或隐式迁移。
    pub(crate) async fn open_existing_postgres(config: &StorageConfig) -> anyhow::Result<Self> {
        anyhow::ensure!(
            config.backend == StorageBackend::Postgres,
            "maintenance requires PostgreSQL storage"
        );
        let url = config
            .postgres_url
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("PostgreSQL URL was not configured"))?;
        let pool = Arc::new(PostgresPool::connect(url).await?);
        let mut client = pool.acquire().await?;
        postgres_migrations::verify_existing(&mut client).await?;
        drop(client);
        Ok(Self::Postgres(pool))
    }

    pub(crate) async fn open(config: &StorageConfig, sqlite: &Database) -> anyhow::Result<Self> {
        match config.backend {
            StorageBackend::Sqlite => Ok(Self::Sqlite(sqlite.clone())),
            StorageBackend::Postgres => {
                let url = config
                    .postgres_url
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("PostgreSQL URL was not configured"))?;
                let pool = Arc::new(PostgresPool::connect(url).await?);
                let mut client = pool.acquire().await?;
                postgres_migrations::apply(&mut client).await?;
                drop(client);
                Ok(Self::Postgres(pool))
            }
        }
    }

    pub(crate) fn backend(&self) -> StorageBackend {
        match self {
            Self::Sqlite(_) => StorageBackend::Sqlite,
            Self::Postgres(_) => StorageBackend::Postgres,
        }
    }

    pub(crate) async fn postgres_client(&self) -> anyhow::Result<PostgresClientGuard> {
        let Self::Postgres(pool) = self else {
            anyhow::bail!("operation requires the PostgreSQL coordination backend");
        };
        pool.acquire().await
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
    config: tokio_postgres::Config,
    tls: MakeRustlsConnect,
    slots: Vec<Arc<Mutex<Option<Client>>>>,
    available_tx: mpsc::Sender<usize>,
    available_rx: Mutex<mpsc::Receiver<usize>>,
    acquire_timeout: Duration,
    connect_timeout: Duration,
    health_timeout: Duration,
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
            // Require 模式禁止服务端回退到明文；生产默认必须保持 TLS 校验。
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
        let acquire_timeout = parse_duration_environment(POSTGRES_ACQUIRE_TIMEOUT_ENV, 5, 1, 60)?;
        let connect_timeout = parse_duration_environment(POSTGRES_CONNECT_TIMEOUT_ENV, 10, 1, 120)?;
        let health_timeout = parse_duration_environment(POSTGRES_HEALTH_TIMEOUT_ENV, 3, 1, 30)?;
        let tls = postgres_tls_connector()?;
        let (available_tx, available_rx) = mpsc::channel(pool_size);
        let mut slots = Vec::with_capacity(pool_size);
        for index in 0..pool_size {
            let client = connect_postgres_client(&config, &tls, connect_timeout).await?;
            slots.push(Arc::new(Mutex::new(Some(client))));
            available_tx.try_send(index).map_err(|_| {
                anyhow::anyhow!("could not initialize the PostgreSQL connection pool")
            })?;
        }
        Ok(Self {
            config,
            tls,
            slots,
            available_tx,
            available_rx: Mutex::new(available_rx),
            acquire_timeout,
            connect_timeout,
            health_timeout,
        })
    }

    async fn acquire(self: &Arc<Self>) -> anyhow::Result<PostgresClientGuard> {
        let index = timeout(self.acquire_timeout, async {
            let mut receiver = self.available_rx.lock().await;
            receiver.recv().await
        })
        .await
        .map_err(|_| anyhow::anyhow!("timed out waiting for a PostgreSQL connection"))?
        .ok_or_else(|| anyhow::anyhow!("PostgreSQL connection pool is closed"))?;
        let lease = PostgresSlotLease {
            pool: self.clone(),
            index,
        };
        let mut client = self.slots[index].clone().lock_owned().await;
        let healthy = if let Some(existing) = client.as_ref() {
            !existing.is_closed()
                && matches!(
                    timeout(self.health_timeout, existing.simple_query("SELECT 1")).await,
                    Ok(Ok(_))
                )
        } else {
            false
        };
        if !healthy {
            *client = None;
            let replacement =
                connect_postgres_client(&self.config, &self.tls, self.connect_timeout).await?;
            *client = Some(replacement);
        }
        Ok(PostgresClientGuard {
            client: Some(client),
            lease: Some(lease),
        })
    }
}

pub(crate) struct PostgresClientGuard {
    // 先释放客户端锁，再把槽位归还可用队列。
    client: Option<OwnedMutexGuard<Option<Client>>>,
    lease: Option<PostgresSlotLease>,
}

impl Deref for PostgresClientGuard {
    type Target = Client;

    fn deref(&self) -> &Self::Target {
        self.client
            .as_ref()
            .and_then(|client| client.as_ref())
            .expect("PostgreSQL pool guard must contain a connected client")
    }
}

impl DerefMut for PostgresClientGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.client
            .as_mut()
            .and_then(|client| client.as_mut())
            .expect("PostgreSQL pool guard must contain a connected client")
    }
}

impl Drop for PostgresClientGuard {
    fn drop(&mut self) {
        if let Some(client) = self.client.as_mut() {
            if client.as_ref().is_some_and(Client::is_closed) {
                **client = None;
            }
        }
        drop(self.client.take());
        drop(self.lease.take());
    }
}

struct PostgresSlotLease {
    pool: Arc<PostgresPool>,
    index: usize,
}

impl Drop for PostgresSlotLease {
    fn drop(&mut self) {
        if self.pool.available_tx.try_send(self.index).is_err() {
            tracing::error!("PostgreSQL pool slot could not be returned");
        }
    }
}

async fn connect_postgres_client(
    config: &tokio_postgres::Config,
    tls: &MakeRustlsConnect,
    connect_timeout: Duration,
) -> anyhow::Result<Client> {
    let (client, connection) = timeout(connect_timeout, config.connect(tls.clone()))
        .await
        .map_err(|_| anyhow::anyhow!("timed out establishing a verified PostgreSQL connection"))?
        .map_err(|_| anyhow::anyhow!("could not establish a verified PostgreSQL connection"))?;
    tokio::spawn(async move {
        if connection.await.is_err() {
            // 驱动错误可能包含连接目标信息，因此这里只记录固定消息。
            tracing::error!("PostgreSQL connection task stopped");
        }
    });
    Ok(client)
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

fn parse_duration_environment(
    name: &str,
    default_seconds: u64,
    minimum_seconds: u64,
    maximum_seconds: u64,
) -> anyhow::Result<Duration> {
    let seconds = env::var(name)
        .ok()
        .map(|value| value.trim().parse::<u64>())
        .transpose()
        .map_err(|_| anyhow::anyhow!("{name} must be an integer"))?
        .unwrap_or(default_seconds);
    anyhow::ensure!(
        (minimum_seconds..=maximum_seconds).contains(&seconds),
        "{name} must be between {minimum_seconds} and {maximum_seconds} seconds"
    );
    Ok(Duration::from_secs(seconds))
}

fn nonnegative_time(value: i64) -> anyhow::Result<u64> {
    u64::try_from(value).map_err(|_| anyhow::anyhow!("database clock returned a negative value"))
}

#[cfg(test)]
mod tests {
    use super::{StorageBackend, StorageConfig};

    #[test]
    fn postgres_uses_shared_application_state_without_external_replication_acknowledgement() {
        for acknowledgement in [false, true] {
            let config = StorageConfig::from_parts(
                StorageBackend::Postgres,
                Some("postgresql://example.invalid/linklake".to_owned()),
                acknowledgement,
            )
            .unwrap();
            assert_eq!(config.backend(), StorageBackend::Postgres);
            assert!(config.replicated_state());
        }
    }
    #[test]
    fn sqlite_rejects_postgres_only_configuration() {
        assert!(StorageConfig::from_parts(
            StorageBackend::Sqlite,
            Some("postgresql://example.invalid/linklake".to_owned()),
            false,
        )
        .is_err());
        assert!(StorageConfig::from_parts(StorageBackend::Sqlite, None, true).is_err());

        let config = StorageConfig::from_parts(StorageBackend::Sqlite, None, false)
            .expect("default SQLite mode should remain valid");
        assert_eq!(config.backend(), StorageBackend::Sqlite);
        assert!(!config.replicated_state());
    }
}
