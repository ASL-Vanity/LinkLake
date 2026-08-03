mod admin_auth;
mod alerting;
mod api_tokens;
mod audit_log;
mod certificate_catalog;
mod certificate_manager;
mod client_registry;
mod database;
mod database_migrations;
mod database_tools;
mod dual_stack_udp;
mod fleet;
mod http2_backend;
pub mod http_backend_pool;
mod http_proxy_tunnel;
mod http_route_catalog;
mod http_tunnel;
mod lifecycle;
mod notifications;
mod p2p_control;
mod p2p_node_catalog;
mod public_port_policy;
mod secret_tunnel;
mod secret_tunnel_catalog;
mod sni_route_catalog;
mod sni_tunnel;
mod socks5_tunnel;
mod tcp_tunnel;
mod traffic_control;
mod tunnel_catalog;
mod udp_data_plane;
mod udp_tunnel;

use admin_auth::{
    AdminAuth, BootstrapCredentials, CreateUser, LoginAttempt, SessionIdentity, SessionRecord,
    UpdateUser, UserRecord, UserRole,
};
use alerting::{
    AlertCatalog, AlertEvent, AlertMetric, AlertNotification, AlertRule, AlertSignal,
    CreateAlertRule, UpdateAlertRule,
};
use api_tokens::{ApiTokenCatalog, ApiTokenScope, CreateApiToken, CreatedApiToken};
use audit_log::{AuditEvent, AuditLog};
use axum::{
    extract::{ConnectInfo, Path, Query, Request, State},
    http::{header, HeaderMap, Method, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post, put},
    Json, Router,
};
use axum_server::tls_rustls::RustlsConfig as ManagementTlsConfig;
use certificate_catalog::{
    AcmeConfig, CertificateCatalog, CertificateCatalogError, CertificateState, CertificateStatus,
    RouteTlsMode, RouteTlsPolicy, UpdateAcmeConfig, UpdateRouteTlsPolicy,
};
use certificate_manager::CertificateManager;
use clap::{Parser, Subcommand};
use client_registry::{Authentication, ClientRegistry, UpdateClient};
use database::Database;
use dual_stack_udp::{DualStackUdpSocket, PublicUdpBindMode};
use fleet::{FleetCatalog, FleetImportResult, FleetPeer, FleetPolicyBundle, UpsertFleetPeer};
use http_route_catalog::{
    CreateHttpRouteError, CreateHttpRoutePolicy, HttpRouteCatalog, HttpRoutePolicy,
    UpdateHttpRoutePolicy,
};
use lifecycle::{LifecycleController, LifecyclePhase, LifecycleSnapshot, LifecycleTransitionError};
use linklake_core::{
    managed_config_revision, BoxedIo, BuildInfo, ClientEnrollmentRequest, ClientEnrollmentResponse,
    ManagedClientConfig, ManagedHttpProxy, ManagedHttpRoute, ManagedSecretTunnel,
    ManagedSocks5Proxy, ManagedTcpTunnel, ManagedTlsRoute, ManagedUdpTunnel, API_VERSION,
    PRODUCT_NAME,
};
use linklake_update::{SignaturePolicy, UpdateChannel, UpdateProduct};
use p2p_node_catalog::{P2pNodeCatalog, P2pNodeRecord};
use public_port_policy::{PublicPortPolicy, PublicPortPolicyView};
use rusqlite::{params, Connection};
use secret_tunnel_catalog::{
    CreateSecretTunnelPolicy, CreatedSecretTunnelPolicy, SecretPolicyError, SecretTunnelCatalog,
    SecretTunnelPolicy, UpdateSecretTunnelPolicy,
};
use serde::{Deserialize, Serialize};
use sni_route_catalog::{
    CreateSniRoutePolicy, SniRouteCatalog, SniRoutePolicy, SniRoutePolicyError,
    UpdateSniRoutePolicy,
};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    fmt::Write as _,
    fs::File,
    io::BufReader,
    net::SocketAddr,
    path::{Path as FsPath, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::net::TcpListener;
use tokio::sync::{watch, Mutex as AsyncMutex, Semaphore};
use tokio_rustls::{
    rustls::{self, ServerConfig},
    TlsAcceptor,
};
use tower_http::trace::TraceLayer;
use traffic_control::{TrafficControlCatalog, TrafficPolicyKind, UpsertTrafficControl};
use tunnel_catalog::{
    CreateHttpProxyPolicy, CreatePortGroupPolicy, CreateSocks5ProxyPolicy, CreateTcpTunnelPolicy,
    CreateUdpTunnelPolicy, CreatedHttpProxyPolicy, CreatedSocks5ProxyPolicy, HttpProxyPolicy,
    HttpProxyPolicyError, PortGroupMapping, PortGroupPolicy, PortGroupPolicyError,
    PortGroupProtocol, Socks5PolicyError, Socks5ProxyPolicy, TcpTunnelPolicy, TunnelCatalog,
    UdpPolicyError, UdpTunnelPolicy, UpdateHttpProxyPolicy, UpdatePortGroupPolicy,
    UpdateSocks5ProxyPolicy, UpdateTcpTunnelPolicy, UpdateUdpTunnelPolicy,
};
use udp_data_plane::{UdpDataPlane, UdpDataPlaneConfig};
use uuid::Uuid;

const MANAGEMENT_UI: &str = include_str!("../web/index.html");
const GLOBAL_CONNECTION_LIMIT: usize = 1024;
const PENDING_CONNECTION_LIMIT: usize = 256;
const GLOBAL_UDP_SESSION_LIMIT: usize = 16_384;
const SESSION_AUTHENTICATION_TYPE: &str = "session";
const METRICS_HISTORY_SAMPLE_INTERVAL_SECONDS: u64 = 5;
const METRICS_HISTORY_RECENT_RETENTION_SECONDS: u64 = 12 * 60 * 60;
const METRICS_HISTORY_ARCHIVE_SAMPLE_INTERVAL_SECONDS: u64 = 60;
const METRICS_HISTORY_RETENTION_SECONDS: u64 = 30 * 24 * 60 * 60;
const METRICS_HISTORY_CAPACITY: usize = (METRICS_HISTORY_RECENT_RETENTION_SECONDS
    / METRICS_HISTORY_SAMPLE_INTERVAL_SECONDS) as usize
    + 2;
const METRICS_HISTORY_ARCHIVE_CAPACITY: usize =
    (METRICS_HISTORY_RETENTION_SECONDS / METRICS_HISTORY_ARCHIVE_SAMPLE_INTERVAL_SECONDS) as usize
        + 2;
const METRICS_HISTORY_DEFAULT_MAX_POINTS: u64 = 300;
const ALERT_EVALUATION_INTERVAL_SECONDS: u64 = 30;
const LOGIN_HASH_CONCURRENCY: usize = 1;
const LOGIN_FAILURE_BASE_DELAY_MILLIS: u64 = 250;
const LOGIN_FAILURE_MAX_DELAY_SECONDS: u64 = 30;
const LOGIN_THROTTLE_MAX_IDENTITIES: usize = 1_024;
const DEFAULT_DRAIN_TIMEOUT_SECONDS: u64 = 30;
const MAX_DRAIN_TIMEOUT_SECONDS: u64 = 60 * 60;

pub(crate) fn managed_config_for_client(
    state: &AppState,
    client_id: Uuid,
) -> anyhow::Result<ManagedClientConfig> {
    let mut tcp_tunnels = state
        .tunnel_catalog
        .lock()
        .expect("tunnel catalog lock poisoned")
        .list()?
        .into_iter()
        .filter(|policy| policy.client_id == client_id)
        .map(|policy| ManagedTcpTunnel {
            name: policy.name,
            public_port: policy.public_port,
            target_addr: policy.target_addr,
            enabled: policy.enabled,
        })
        .collect::<Vec<_>>();
    let mut udp_tunnels = state
        .tunnel_catalog
        .lock()
        .expect("tunnel catalog lock poisoned")
        .list_udp()
        .map_err(|error| anyhow::anyhow!(error))?
        .into_iter()
        .filter(|policy| policy.client_id == client_id)
        .map(|policy| ManagedUdpTunnel {
            name: policy.name,
            public_port: policy.public_port,
            target_addr: policy.target_addr,
            enabled: policy.enabled,
        })
        .collect::<Vec<_>>();
    let port_groups = {
        let catalog = state
            .tunnel_catalog
            .lock()
            .expect("tunnel catalog lock poisoned");
        catalog
            .list_port_groups()
            .map_err(|error| anyhow::anyhow!(error))?
            .into_iter()
            .filter(|policy| policy.client_id == client_id)
            .map(|policy| {
                let mappings = catalog
                    .port_group_mappings(policy.id)
                    .map_err(|error| anyhow::anyhow!(error))?;
                Ok((policy, mappings))
            })
            .collect::<anyhow::Result<Vec<_>>>()?
    };
    for (policy, mappings) in port_groups {
        match policy.protocol {
            PortGroupProtocol::Tcp => {
                tcp_tunnels.extend(mappings.into_iter().map(|mapping| ManagedTcpTunnel {
                    name: policy.name.clone(),
                    public_port: mapping.public_port,
                    target_addr: mapping.target_addr,
                    enabled: policy.enabled,
                }))
            }
            PortGroupProtocol::Udp => {
                udp_tunnels.extend(mappings.into_iter().map(|mapping| ManagedUdpTunnel {
                    name: policy.name.clone(),
                    public_port: mapping.public_port,
                    target_addr: mapping.target_addr,
                    enabled: policy.enabled,
                }))
            }
        }
    }
    tcp_tunnels.sort_by_key(|tunnel| tunnel.public_port);
    udp_tunnels.sort_by_key(|tunnel| tunnel.public_port);
    let http_routes = state
        .http_route_catalog
        .lock()
        .expect("HTTP route catalog lock poisoned")
        .list()?
        .into_iter()
        .filter(|policy| policy.client_id == client_id)
        .map(|policy| ManagedHttpRoute {
            name: policy.name,
            hostname: policy.hostname,
            target_addr: policy.target_addr,
            enabled: policy.enabled,
        })
        .collect::<Vec<_>>();
    let tls_routes = state
        .sni_route_catalog
        .lock()
        .expect("SNI route catalog lock poisoned")
        .list()
        .map_err(|error| anyhow::anyhow!(error))?
        .into_iter()
        .filter(|policy| policy.client_id == client_id)
        .map(|policy| ManagedTlsRoute {
            name: policy.name,
            hostname: policy.hostname,
            target_addr: policy.target_addr,
            enabled: policy.enabled,
        })
        .collect::<Vec<_>>();
    let secret_tunnels = state
        .secret_tunnel_catalog
        .lock()
        .expect("secret tunnel catalog lock poisoned")
        .list()
        .map_err(|error| anyhow::anyhow!(error))?
        .into_iter()
        .filter(|policy| policy.provider_client_id == client_id)
        .map(|policy| ManagedSecretTunnel {
            name: policy.name,
            target_addr: policy.target_addr,
            enabled: policy.enabled,
        })
        .collect::<Vec<_>>();
    let socks5_proxies = state
        .tunnel_catalog
        .lock()
        .expect("tunnel catalog lock poisoned")
        .list_socks5()
        .map_err(|error| anyhow::anyhow!(error))?
        .into_iter()
        .filter(|policy| policy.client_id == client_id)
        .map(|policy| ManagedSocks5Proxy {
            name: policy.name,
            public_port: policy.public_port,
            enabled: policy.enabled,
        })
        .collect::<Vec<_>>();
    let http_proxies = state
        .tunnel_catalog
        .lock()
        .expect("tunnel catalog lock poisoned")
        .list_http_proxies()
        .map_err(|error| anyhow::anyhow!(error))?
        .into_iter()
        .filter(|policy| policy.client_id == client_id)
        .map(|policy| ManagedHttpProxy {
            name: policy.name,
            public_port: policy.public_port,
            enabled: policy.enabled,
        })
        .collect::<Vec<_>>();

    // 修订号只覆盖客户端需要执行的字段，服务端限流等策略不会造成无意义重启。
    let mut config = ManagedClientConfig {
        revision: String::new(),
        tcp_tunnels,
        udp_tunnels,
        http_routes,
        tls_routes,
        secret_tunnels,
        socks5_proxies,
        http_proxies,
    };
    config.revision = managed_config_revision(&config)?;
    Ok(config)
}

struct AppState {
    // 持有进程级数据库锁和共享内存数据库 keeper，必须与 AppState 同生命周期。
    _database: Database,
    started_at: Instant,
    instance_id: String,
    lifecycle: LifecycleController,
    enrollment_token: String,
    management_token: Option<String>,
    admin_auth: Mutex<AdminAuth>,
    api_tokens: Mutex<ApiTokenCatalog>,
    login_throttle: Mutex<LoginThrottle>,
    login_hash_permits: Arc<Semaphore>,
    audit: Mutex<AuditLog>,
    alerts: Mutex<AlertCatalog>,
    fleet: Mutex<FleetCatalog>,
    traffic_controls: Mutex<TrafficControlCatalog>,
    management_cookies_secure: bool,
    public_port_policy: PublicPortPolicy,
    udp_public_bind_mode: PublicUdpBindMode,
    clients: Mutex<ClientRegistry>,
    tunnel_catalog: Mutex<TunnelCatalog>,
    tunnels: Mutex<HashMap<u16, tcp_tunnel::TunnelRegistration>>,
    tunnel_statistics: Mutex<HashMap<u16, Arc<tcp_tunnel::TunnelStatistics>>>,
    seen_tunnel_registrations: Mutex<HashSet<(Uuid, u16)>>,
    udp_data_plane: Option<UdpDataPlane>,
    udp_tunnels: Mutex<HashMap<u16, udp_tunnel::UdpTunnelRegistration>>,
    udp_tunnel_statistics: Mutex<HashMap<Uuid, Arc<udp_tunnel::UdpTunnelStatistics>>>,
    seen_udp_tunnel_registrations: Mutex<HashSet<(Uuid, u16)>>,
    http_route_catalog: Mutex<HttpRouteCatalog>,
    http_routes: Mutex<HashMap<String, http_tunnel::HttpRouteRegistration>>,
    http_route_statistics: Mutex<HashMap<String, Arc<http_tunnel::HttpRouteStatistics>>>,
    seen_http_route_registrations: Mutex<HashSet<(Uuid, String)>>,
    sni_route_catalog: Mutex<SniRouteCatalog>,
    sni_routes: Mutex<HashMap<String, sni_tunnel::SniRouteRegistration>>,
    sni_route_statistics: Mutex<HashMap<String, Arc<sni_tunnel::SniRouteStatistics>>>,
    p2p_node_catalog: Mutex<P2pNodeCatalog>,
    p2p_sessions: Mutex<HashMap<Uuid, p2p_control::PendingP2pSession>>,
    secret_tunnel_catalog: Mutex<SecretTunnelCatalog>,
    secret_tunnels: Mutex<HashMap<Uuid, secret_tunnel::SecretTunnelRegistration>>,
    secret_tunnel_statistics: Mutex<HashMap<Uuid, Arc<secret_tunnel::SecretTunnelStatistics>>>,
    socks5_proxies: Mutex<HashMap<Uuid, socks5_tunnel::Socks5ProxyRegistration>>,
    socks5_proxy_statistics: Mutex<HashMap<Uuid, Arc<socks5_tunnel::Socks5ProxyStatistics>>>,
    http_proxies: Mutex<HashMap<Uuid, http_proxy_tunnel::HttpProxyRegistration>>,
    http_proxy_statistics: Mutex<HashMap<Uuid, Arc<http_proxy_tunnel::HttpProxyStatistics>>>,
    certificate_catalog: Mutex<CertificateCatalog>,
    certificate_manager: Option<CertificateManager>,
    certificate_jobs: Mutex<HashMap<String, Uuid>>,
    https_redirect_hosts: Mutex<HashSet<String>>,
    pending_connections: AsyncMutex<HashMap<Uuid, (Uuid, tokio::sync::oneshot::Sender<BoxedIo>)>>,
    global_connection_permits: Arc<Semaphore>,
    pending_connection_permits: Arc<Semaphore>,
    global_udp_session_permits: Arc<Semaphore>,
    metrics: ServerCounters,
    metrics_history: Mutex<MetricsHistory>,
}

#[derive(Default)]
struct ServerCounters {
    control_connections_total: AtomicU64,
    control_protocol_errors_total: AtomicU64,
    tls_handshake_failures_total: AtomicU64,
    tunnel_registrations_total: AtomicU64,
    tunnel_reconnects_total: AtomicU64,
    registration_rejections_total: AtomicU64,
    authentication_failures_total: AtomicU64,
    public_http_active_connections: AtomicU64,
    https_active_connections: AtomicU64,
    https_requests_total: AtomicU64,
    https_handshake_failures_total: AtomicU64,
    acme_orders_total: AtomicU64,
    acme_orders_failed_total: AtomicU64,
    acme_renewals_total: AtomicU64,
    acme_renewal_failures_total: AtomicU64,
    acme_http01_challenges_total: AtomicU64,
    sni_client_hello_errors_total: AtomicU64,
    sni_unknown_hostname_total: AtomicU64,
    p2p_session_offers_total: AtomicU64,
    p2p_direct_connections_total: AtomicU64,
    p2p_relay_fallbacks_total: AtomicU64,
    udp_public_ipv4_bind_successes_total: AtomicU64,
    udp_public_ipv6_bind_successes_total: AtomicU64,
    udp_public_ipv6_bind_fallbacks_total: AtomicU64,
    udp_public_bind_failures_total: AtomicU64,
}

#[derive(Clone, Copy)]
struct LoginThrottleEntry {
    failures: u32,
    next_allowed: Instant,
}

#[derive(Default)]
struct LoginThrottle {
    identities: HashMap<String, LoginThrottleEntry>,
    global_next_allowed: Option<Instant>,
}

impl LoginThrottle {
    fn delay(&self, identity: &str, now: Instant) -> Duration {
        let global = self
            .global_next_allowed
            .and_then(|deadline| deadline.checked_duration_since(now))
            .unwrap_or_default();
        let identity = self
            .identities
            .get(identity)
            .and_then(|entry| entry.next_allowed.checked_duration_since(now))
            .unwrap_or_default();
        global.max(identity)
    }

    fn record_failure(&mut self, identity: &str, now: Instant) -> Duration {
        if !self.identities.contains_key(identity)
            && self.identities.len() >= LOGIN_THROTTLE_MAX_IDENTITIES
        {
            self.identities.retain(|_, entry| entry.next_allowed > now);
        }
        let identity = if !self.identities.contains_key(identity)
            && self.identities.len() >= LOGIN_THROTTLE_MAX_IDENTITIES
        {
            if !self.identities.contains_key("__overflow__") {
                if let Some(expiring_first) = self
                    .identities
                    .iter()
                    .min_by_key(|(_, entry)| entry.next_allowed)
                    .map(|(identity, _)| identity.clone())
                {
                    self.identities.remove(&expiring_first);
                }
            }
            "__overflow__"
        } else {
            identity
        };
        let entry = self
            .identities
            .entry(identity.to_owned())
            .or_insert(LoginThrottleEntry {
                failures: 0,
                next_allowed: now,
            });
        entry.failures = entry.failures.saturating_add(1);
        let multiplier = 1_u64 << entry.failures.saturating_sub(1).min(16);
        let delay = Duration::from_millis(
            LOGIN_FAILURE_BASE_DELAY_MILLIS
                .saturating_mul(multiplier)
                .min(LOGIN_FAILURE_MAX_DELAY_SECONDS * 1_000),
        );
        entry.next_allowed = now + delay;
        let global_delay = Duration::from_millis(LOGIN_FAILURE_BASE_DELAY_MILLIS);
        let global_deadline = now + global_delay;
        self.global_next_allowed = Some(
            self.global_next_allowed
                .map_or(global_deadline, |current| current.max(global_deadline)),
        );
        delay
    }

    fn record_success(&mut self, identity: &str) {
        self.identities.remove(identity);
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
struct HistoryCounters {
    bytes_from_public: u64,
    bytes_to_public: u64,
    active_connections: u64,
    active_sessions: u64,
    requests_total: u64,
    errors_total: u64,
}

impl HistoryCounters {
    fn saturating_add(self, other: Self) -> Self {
        Self {
            bytes_from_public: self
                .bytes_from_public
                .saturating_add(other.bytes_from_public),
            bytes_to_public: self.bytes_to_public.saturating_add(other.bytes_to_public),
            active_connections: self
                .active_connections
                .saturating_add(other.active_connections),
            active_sessions: self.active_sessions.saturating_add(other.active_sessions),
            requests_total: self.requests_total.saturating_add(other.requests_total),
            errors_total: self.errors_total.saturating_add(other.errors_total),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct MetricsHistorySample {
    timestamp_unix_seconds: u64,
    #[serde(default)]
    authentication_failures_total: u64,
    tcp: HistoryCounters,
    udp: HistoryCounters,
    web: HistoryCounters,
    proxy: HistoryCounters,
    secret: HistoryCounters,
    #[serde(default)]
    policies: HashMap<String, HistoryCounters>,
}

impl MetricsHistorySample {
    fn counters(&self, protocol: MetricsHistoryProtocol) -> HistoryCounters {
        match protocol {
            MetricsHistoryProtocol::Total => self
                .tcp
                .saturating_add(self.udp)
                .saturating_add(self.web)
                .saturating_add(self.proxy)
                .saturating_add(self.secret),
            MetricsHistoryProtocol::Tcp => self.tcp,
            MetricsHistoryProtocol::Udp => self.udp,
            MetricsHistoryProtocol::Web => self.web,
            MetricsHistoryProtocol::Proxy => self.proxy,
            MetricsHistoryProtocol::Secret => self.secret,
        }
    }
}

struct MetricsHistory {
    samples: VecDeque<MetricsHistorySample>,
    archive_samples: VecDeque<MetricsHistorySample>,
    capacity: usize,
    archive_capacity: usize,
    database: Option<Connection>,
}

impl MetricsHistory {
    fn new(capacity: usize, archive_capacity: usize) -> Self {
        Self {
            samples: VecDeque::with_capacity(capacity),
            archive_samples: VecDeque::with_capacity(archive_capacity),
            capacity: capacity.max(2),
            archive_capacity: archive_capacity.max(2),
            database: None,
        }
    }

    #[allow(dead_code)]
    fn open(
        data_dir: Option<&FsPath>,
        capacity: usize,
        archive_capacity: usize,
    ) -> anyhow::Result<Self> {
        let database = Database::open(data_dir)?;
        Self::open_with_database(&database, capacity, archive_capacity)
    }

    fn open_with_database(
        database: &Database,
        capacity: usize,
        archive_capacity: usize,
    ) -> anyhow::Result<Self> {
        let mut history = Self::new(capacity, archive_capacity);
        if !database.is_persistent() {
            return Ok(history);
        }
        let database = database.connect()?;
        database.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS metrics_history_recent (
                timestamp_unix_seconds INTEGER PRIMARY KEY NOT NULL,
                sample_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS metrics_history_archive (
                minute_bucket INTEGER PRIMARY KEY NOT NULL,
                timestamp_unix_seconds INTEGER NOT NULL,
                sample_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS metrics_history_archive_timestamp
                ON metrics_history_archive(timestamp_unix_seconds);
            ",
        )?;
        let now = unix_seconds();
        let recent_cutoff = now.saturating_sub(METRICS_HISTORY_RECENT_RETENTION_SECONDS);
        let archive_cutoff = now.saturating_sub(METRICS_HISTORY_RETENTION_SECONDS);
        database.execute(
            "DELETE FROM metrics_history_recent WHERE timestamp_unix_seconds < ?1",
            [recent_cutoff as i64],
        )?;
        database.execute(
            "DELETE FROM metrics_history_archive WHERE timestamp_unix_seconds < ?1",
            [archive_cutoff as i64],
        )?;
        {
            let mut statement = database.prepare(
                "SELECT sample_json FROM metrics_history_recent ORDER BY timestamp_unix_seconds",
            )?;
            let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
            for row in rows {
                match row {
                    Ok(json) => match serde_json::from_str::<MetricsHistorySample>(&json) {
                        Ok(sample) => history.samples.push_back(sample),
                        Err(error) => tracing::warn!(
                            "Skipping invalid recent metrics history sample: {error}"
                        ),
                    },
                    Err(error) => {
                        tracing::warn!("Skipping unreadable recent metrics history row: {error}")
                    }
                }
            }
        }
        {
            let mut statement = database.prepare(
                "SELECT sample_json FROM metrics_history_archive ORDER BY timestamp_unix_seconds",
            )?;
            let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
            for row in rows {
                match row {
                    Ok(json) => match serde_json::from_str::<MetricsHistorySample>(&json) {
                        Ok(sample) => history.archive_samples.push_back(sample),
                        Err(error) => tracing::warn!(
                            "Skipping invalid archived metrics history sample: {error}"
                        ),
                    },
                    Err(error) => {
                        tracing::warn!("Skipping unreadable archived metrics history row: {error}")
                    }
                }
            }
        }
        while history.samples.len() > history.capacity {
            history.samples.pop_front();
        }
        while history.archive_samples.len() > history.archive_capacity {
            history.archive_samples.pop_front();
        }
        history.database = Some(database);
        Ok(history)
    }

    fn push(&mut self, sample: MetricsHistorySample) {
        let clock_rollback = self
            .samples
            .back()
            .is_some_and(|last| last.timestamp_unix_seconds > sample.timestamp_unix_seconds);
        if self
            .samples
            .back()
            .is_some_and(|last| last.timestamp_unix_seconds > sample.timestamp_unix_seconds)
        {
            // 系统时间回拨时开始一条新序列，避免此后的正常样本持续被旧时间基线拒绝。
            self.samples.clear();
            self.archive_samples.clear();
        }
        if self
            .samples
            .back()
            .is_some_and(|last| last.timestamp_unix_seconds == sample.timestamp_unix_seconds)
        {
            self.samples.pop_back();
        }
        let archive_bucket =
            sample.timestamp_unix_seconds / METRICS_HISTORY_ARCHIVE_SAMPLE_INTERVAL_SECONDS;
        if self.archive_samples.back().is_some_and(|last| {
            last.timestamp_unix_seconds / METRICS_HISTORY_ARCHIVE_SAMPLE_INTERVAL_SECONDS
                == archive_bucket
        }) {
            self.archive_samples.pop_back();
        }
        self.archive_samples.push_back(sample.clone());
        while self.archive_samples.len() > self.archive_capacity {
            self.archive_samples.pop_front();
        }
        if let Err(error) = self.persist_sample(&sample, clock_rollback) {
            tracing::error!("Could not persist metrics history sample: {error}");
        }
        self.samples.push_back(sample);
        while self.samples.len() > self.capacity {
            self.samples.pop_front();
        }
    }

    fn persist_sample(
        &mut self,
        sample: &MetricsHistorySample,
        clock_rollback: bool,
    ) -> anyhow::Result<()> {
        let Some(database) = self.database.as_mut() else {
            return Ok(());
        };
        let transaction = database.transaction()?;
        if clock_rollback {
            transaction.execute("DELETE FROM metrics_history_recent", [])?;
            transaction.execute("DELETE FROM metrics_history_archive", [])?;
        }
        let json = serde_json::to_string(sample)?;
        transaction.execute(
            "INSERT OR REPLACE INTO metrics_history_recent (timestamp_unix_seconds, sample_json) VALUES (?1, ?2)",
            params![sample.timestamp_unix_seconds as i64, json],
        )?;
        transaction.execute(
            "INSERT OR REPLACE INTO metrics_history_archive (minute_bucket, timestamp_unix_seconds, sample_json) VALUES (?1, ?2, ?3)",
            params![
                (sample.timestamp_unix_seconds / METRICS_HISTORY_ARCHIVE_SAMPLE_INTERVAL_SECONDS) as i64,
                sample.timestamp_unix_seconds as i64,
                serde_json::to_string(sample)?,
            ],
        )?;
        transaction.execute(
            "DELETE FROM metrics_history_recent WHERE timestamp_unix_seconds < ?1",
            [sample
                .timestamp_unix_seconds
                .saturating_sub(METRICS_HISTORY_RECENT_RETENTION_SECONDS) as i64],
        )?;
        transaction.execute(
            "DELETE FROM metrics_history_archive WHERE timestamp_unix_seconds < ?1",
            [sample
                .timestamp_unix_seconds
                .saturating_sub(METRICS_HISTORY_RETENTION_SECONDS) as i64],
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn tier(&self, range_seconds: u64) -> (&VecDeque<MetricsHistorySample>, u64) {
        if range_seconds <= METRICS_HISTORY_RECENT_RETENTION_SECONDS {
            (&self.samples, METRICS_HISTORY_SAMPLE_INTERVAL_SECONDS)
        } else {
            (
                &self.archive_samples,
                METRICS_HISTORY_ARCHIVE_SAMPLE_INTERVAL_SECONDS,
            )
        }
    }
}

#[derive(Serialize)]
struct HealthResponse {
    product: &'static str,
    api_version: &'static str,
    status: &'static str,
}

#[derive(Serialize)]
struct ProbeResponse {
    product: &'static str,
    api_version: &'static str,
    status: &'static str,
    phase: LifecyclePhase,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DrainRequest {
    #[serde(default = "default_drain_timeout_seconds")]
    timeout_seconds: u64,
}

fn default_drain_timeout_seconds() -> u64 {
    DEFAULT_DRAIN_TIMEOUT_SECONDS
}

#[derive(Serialize)]
struct LifecycleResponse {
    #[serde(flatten)]
    lifecycle: LifecycleSnapshot,
    accepting_new_work: bool,
    active_tcp_connections: usize,
    pending_connection_pairings: usize,
    active_udp_sessions: usize,
    pending_p2p_sessions: usize,
    drained: bool,
    drain_deadline_reached: bool,
}

#[derive(Serialize)]
struct StatusResponse {
    product: &'static str,
    api_version: &'static str,
    instance_id: String,
    tunnels: usize,
    udp_tunnels: usize,
    http_routes: usize,
    https_routes: usize,
    secret_tunnels: usize,
    socks5_proxies: usize,
    http_proxies: usize,
    port_groups: usize,
    sni_routes: usize,
    p2p_nodes: usize,
    p2p_nodes_total: usize,
    clients: usize,
    udp_public_bind_mode: &'static str,
}

#[derive(Serialize)]
struct P2pNodeView {
    #[serde(flatten)]
    node: P2pNodeRecord,
    fresh: bool,
    age_seconds: u64,
}

#[derive(Serialize)]
struct MetricsResponse {
    uptime_seconds: u64,
    tcp_active_connections: usize,
    tcp_pending_connections: usize,
    tcp_bytes_from_public: u64,
    tcp_bytes_to_public: u64,
    tcp_failed_connections: u64,
    tcp_pairing_timeouts: u64,
    tcp_transfer_errors: u64,
    tcp_lifetime_timeouts: u64,
    tcp_rejected_policy_limit: u64,
    tcp_rejected_global_limit: u64,
    tcp_rejected_pending_limit: u64,
    socks5_capabilities: Socks5CapabilitiesView,
    socks5_active_connections: usize,
    socks5_requests_total: u64,
    socks5_authentication_failures: u64,
    socks5_rejected_connections: u64,
    socks5_bind_rejected_total: u64,
    socks5_bytes_from_public: u64,
    socks5_bytes_to_public: u64,
    socks5_handshake_errors: u64,
    socks5_handshake_timeouts: u64,
    socks5_connect_failures: u64,
    socks5_pairing_timeouts: u64,
    socks5_transfer_errors: u64,
    socks5_udp_active_associations: usize,
    socks5_udp_datagrams_from_public: u64,
    socks5_udp_datagrams_to_public: u64,
    socks5_udp_bytes_from_public: u64,
    socks5_udp_bytes_to_public: u64,
    socks5_udp_dropped_datagrams: u64,
    socks5_udp_dropped_bandwidth_limit: u64,
    socks5_udp_fragmentation_unsupported_total: u64,
    http_proxy_active_connections: usize,
    http_proxy_requests_total: u64,
    http_proxy_connect_requests: u64,
    http_proxy_authentication_failures: u64,
    http_proxy_rejected_connections: u64,
    http_proxy_malformed_requests: u64,
    http_proxy_bytes_from_public: u64,
    http_proxy_bytes_to_public: u64,
    http_proxy_pairing_timeouts: u64,
    http_proxy_connect_failures: u64,
    http_proxy_transfer_errors: u64,
    #[serde(flatten)]
    udp: UdpMetricsResponse,
    udp_public_ipv4_bind_successes_total: u64,
    udp_public_ipv6_bind_successes_total: u64,
    udp_public_ipv6_bind_fallbacks_total: u64,
    udp_public_bind_failures_total: u64,
    control_connections_total: u64,
    control_protocol_errors_total: u64,
    tls_handshake_failures_total: u64,
    tunnel_registrations_total: u64,
    tunnel_reconnects_total: u64,
    registration_rejections_total: u64,
    authentication_failures_total: u64,
    http_transport_capabilities: HttpTransportCapabilitiesView,
    http_active_connections: usize,
    http_requests_total: u64,
    http_failed_requests: u64,
    http_bytes_from_public: u64,
    http_bytes_to_public: u64,
    http_pairing_timeouts: u64,
    http2_active_streams: usize,
    http2_requests_total: u64,
    grpc_active_streams: usize,
    grpc_requests_total: u64,
    grpc_trailers_total: u64,
    grpc_failures_total: u64,
    grpc_cancellations_total: u64,
    http2_backend_active_connections: usize,
    http2_backend_active_streams: usize,
    http2_backend_connections_total: u64,
    http2_backend_reused_total: u64,
    http2_backend_reconnects_total: u64,
    http2_backend_goaway_total: u64,
    http2_backend_failures_total: u64,
    http2_backend_pool_exhausted_total: u64,
    sni_active_connections: usize,
    sni_connections_total: u64,
    sni_rejected_connections: u64,
    sni_client_hello_errors: u64,
    sni_unknown_hostname: u64,
    sni_bytes_from_public: u64,
    sni_bytes_to_public: u64,
    sni_pairing_timeouts: u64,
    sni_transfer_errors: u64,
    p2p_session_offers_total: u64,
    p2p_direct_connections_total: u64,
    p2p_relay_fallbacks_total: u64,
    https_active_connections: u64,
    https_requests_total: u64,
    https_handshake_failures_total: u64,
    certificates_managed: usize,
    certificates_active: usize,
    certificates_expiring_30d: usize,
    certificates_expired: usize,
    certificate_nearest_expiry_unix_seconds: Option<i64>,
    acme_orders_total: u64,
    acme_orders_failed_total: u64,
    acme_renewals_total: u64,
    acme_renewal_failures_total: u64,
    acme_http01_challenges_total: u64,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct UdpMetricsResponse {
    udp_active_sessions: usize,
    udp_packets_from_public: u64,
    udp_packets_to_public: u64,
    udp_bytes_from_public: u64,
    udp_bytes_to_public: u64,
    udp_dropped_packets: u64,
    udp_dropped_oversized: u64,
    udp_dropped_malformed: u64,
    udp_dropped_unknown_session: u64,
    udp_dropped_queue_full: u64,
    udp_dropped_policy_session_limit: u64,
    udp_dropped_global_session_limit: u64,
    udp_dropped_bandwidth_limit: u64,
    udp_session_timeouts: u64,
    udp_reassembly_timeouts: u64,
    udp_attach_timeouts: u64,
    udp_transport_errors: u64,
}

#[derive(Serialize)]
struct HeartbeatResponse {
    server_time_unix_seconds: u64,
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
    #[serde(default)]
    totp_code: Option<String>,
}

#[derive(Serialize)]
struct LoginResponse {
    session_id: Uuid,
    username: String,
    display_name: String,
    role: UserRole,
    authentication_type: &'static str,
    expires_unix_seconds: u64,
    password_change_required: bool,
    totp_enabled: bool,
}

#[derive(Serialize)]
struct AuthMeResponse {
    session_id: Uuid,
    username: String,
    display_name: String,
    role: UserRole,
    authentication_type: &'static str,
    expires_unix_seconds: u64,
    password_change_required: bool,
    totp_enabled: bool,
}

#[derive(Deserialize)]
struct TotpCodeRequest {
    code: String,
}

#[derive(Serialize)]
struct TotpSetupResponse {
    secret: String,
    provisioning_uri: String,
}

#[derive(Deserialize)]
struct ChangePasswordRequest {
    new_password: String,
}

#[derive(Deserialize)]
struct ResetUserPasswordRequest {
    new_password: String,
    #[serde(default = "default_force_password_change")]
    force_password_change: bool,
}

fn default_force_password_change() -> bool {
    true
}

#[derive(Deserialize)]
struct AuditQuery {
    limit: Option<usize>,
}

#[derive(Deserialize)]
struct AlertEventsQuery {
    active: Option<bool>,
    limit: Option<usize>,
}

#[derive(Deserialize)]
struct SearchQuery {
    q: String,
}

#[derive(Serialize)]
struct SearchResult {
    kind: &'static str,
    id: String,
    title: String,
    subtitle: String,
    href: String,
}

#[derive(Debug, Serialize)]
struct FleetPeerStatus {
    #[serde(flatten)]
    peer: FleetPeer,
    online: bool,
    latency_millis: Option<u64>,
    error: Option<String>,
    active_connections: u64,
    bytes_total: u64,
    clients: u64,
    policies: u64,
}

#[derive(Debug, Serialize)]
struct FleetOverview {
    preferred_peer_id: Option<Uuid>,
    failover_order: Vec<Uuid>,
    conflicts: Vec<String>,
    peers: Vec<FleetPeerStatus>,
}

#[derive(Deserialize, Serialize)]
struct FleetImportRequest {
    bundle: FleetPolicyBundle,
    #[serde(default)]
    dry_run: bool,
}

#[derive(Deserialize)]
struct FleetSyncRequest {
    #[serde(default)]
    peer_ids: Vec<Uuid>,
    #[serde(default = "default_true_value")]
    dry_run: bool,
}

fn default_true_value() -> bool {
    true
}

#[derive(Serialize)]
struct FleetPeerSyncResult {
    peer_id: Uuid,
    peer_name: String,
    created: usize,
    unchanged: usize,
    conflicts: Vec<String>,
    error: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum MetricsHistoryProtocol {
    #[default]
    Total,
    Tcp,
    Udp,
    Web,
    Proxy,
    Secret,
}

#[derive(Deserialize)]
struct MetricsHistoryQuery {
    range: Option<String>,
    step: Option<u64>,
    protocol: Option<MetricsHistoryProtocol>,
}

#[derive(Deserialize)]
struct MetricsExportQuery {
    range: Option<String>,
    step: Option<u64>,
    protocol: Option<MetricsHistoryProtocol>,
    format: Option<String>,
}

#[derive(Deserialize)]
struct AuditExportQuery {
    from: Option<i64>,
    to: Option<i64>,
    limit: Option<usize>,
    format: Option<String>,
}

#[derive(Debug, Serialize, PartialEq)]
struct MetricsHistoryPoint {
    timestamp_unix_seconds: u64,
    inbound_bps: f64,
    outbound_bps: f64,
    active_connections: u64,
    active_sessions: u64,
    requests_per_second: f64,
    errors_per_second: f64,
    requests_total: u64,
    errors_total: u64,
}

#[derive(Debug, Serialize, PartialEq)]
struct MetricsHistoryResponse {
    protocol: MetricsHistoryProtocol,
    range: &'static str,
    sample_interval_seconds: u64,
    step_seconds: u64,
    retention_seconds: u64,
    series_started_unix_seconds: Option<u64>,
    from_unix_seconds: u64,
    to_unix_seconds: u64,
    points: Vec<MetricsHistoryPoint>,
}

#[derive(Debug, Serialize, PartialEq)]
struct PolicyMetricsHistoryResponse {
    kind: String,
    policy_id: Uuid,
    range: &'static str,
    sample_interval_seconds: u64,
    step_seconds: u64,
    retention_seconds: u64,
    series_started_unix_seconds: Option<u64>,
    from_unix_seconds: u64,
    to_unix_seconds: u64,
    points: Vec<MetricsHistoryPoint>,
}

#[derive(Deserialize)]
struct EnableTunnelRequest {
    enabled: bool,
}

#[derive(Serialize)]
struct TcpTunnelView {
    #[serde(flatten)]
    policy: TcpTunnelPolicy,
    online: bool,
    active_connections: usize,
    rejected_connections: u64,
    bytes_from_public: u64,
    bytes_to_public: u64,
    failed_connections: u64,
    rejected_policy_limit: u64,
    rejected_global_limit: u64,
    rejected_pending_limit: u64,
    pairing_timeouts: u64,
    transfer_errors: u64,
    lifetime_timeouts: u64,
}

#[derive(Serialize)]
struct UdpTunnelView {
    #[serde(flatten)]
    policy: UdpTunnelPolicy,
    online: bool,
    active_sessions: usize,
    packets_from_public: u64,
    packets_to_public: u64,
    bytes_from_public: u64,
    bytes_to_public: u64,
    dropped_packets: u64,
    dropped_bandwidth_limit: u64,
    dropped_policy_session_limit: u64,
    dropped_global_session_limit: u64,
    dropped_oversized: u64,
    dropped_malformed: u64,
    dropped_unknown_session: u64,
    dropped_queue_full: u64,
    reassembly_timeouts: u64,
    session_timeouts: u64,
    attach_timeouts: u64,
    transport_errors: u64,
}

#[derive(Serialize)]
struct PortGroupView {
    #[serde(flatten)]
    policy: PortGroupPolicy,
    mappings: Vec<PortGroupMapping>,
    online_mappings: usize,
    active_connections: usize,
    active_sessions: usize,
    bytes_from_public: u64,
    bytes_to_public: u64,
    packets_from_public: u64,
    packets_to_public: u64,
}

#[derive(Serialize)]
struct HttpTransportCapabilitiesView {
    http1: bool,
    http2: bool,
    grpc: bool,
    tls_alpn: bool,
    h2c_prior_knowledge: bool,
    grpc_backend_transport: &'static str,
}

impl Default for HttpTransportCapabilitiesView {
    fn default() -> Self {
        Self {
            http1: true,
            http2: true,
            grpc: true,
            tls_alpn: true,
            h2c_prior_knowledge: true,
            grpc_backend_transport: "h2c",
        }
    }
}

#[derive(Serialize)]
struct HttpRouteView {
    #[serde(flatten)]
    policy: HttpRoutePolicy,
    online: bool,
    active_connections: usize,
    requests_total: u64,
    failed_requests: u64,
    bytes_from_public: u64,
    bytes_to_public: u64,
    pairing_timeouts: u64,
    capabilities: HttpTransportCapabilitiesView,
    http2_active_streams: usize,
    http2_requests_total: u64,
    grpc_active_streams: usize,
    grpc_requests_total: u64,
    grpc_trailers_total: u64,
    grpc_failures_total: u64,
    grpc_cancellations_total: u64,
    http2_backend_active_connections: usize,
    http2_backend_active_streams: usize,
    http2_backend_connections_total: u64,
    http2_backend_reused_total: u64,
    http2_backend_reconnects_total: u64,
    http2_backend_goaway_total: u64,
    http2_backend_failures_total: u64,
    http2_backend_pool_exhausted_total: u64,
    tls: RouteTlsView,
}

#[derive(Serialize)]
struct SniRouteView {
    #[serde(flatten)]
    policy: SniRoutePolicy,
    online: bool,
    active_connections: usize,
    connections_total: u64,
    rejected_connections: u64,
    client_hello_errors: u64,
    unknown_sni: u64,
    bytes_from_public: u64,
    bytes_to_public: u64,
    pairing_timeouts: u64,
    transfer_errors: u64,
    lifetime_timeouts: u64,
}

#[derive(Serialize)]
struct SecretTunnelView {
    #[serde(flatten)]
    policy: SecretTunnelPolicy,
    online: bool,
    active_connections: usize,
    connections_total: u64,
    rejected_connections: u64,
    bytes_from_visitor: u64,
    bytes_to_visitor: u64,
    pairing_timeouts: u64,
    transfer_errors: u64,
    lifetime_timeouts: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
struct Socks5CapabilitiesView {
    connect: bool,
    udp_associate: bool,
    bind: bool,
    udp_fragmentation: bool,
}

impl Socks5CapabilitiesView {
    const fn new(udp_associate: bool) -> Self {
        Self {
            connect: true,
            udp_associate,
            bind: false,
            udp_fragmentation: false,
        }
    }
}

#[derive(Serialize)]
struct Socks5ProxyView {
    #[serde(flatten)]
    policy: Socks5ProxyPolicy,
    online: bool,
    capabilities: Socks5CapabilitiesView,
    active_connections: usize,
    connections_total: u64,
    requests_total: u64,
    authentication_failures: u64,
    rejected_connections: u64,
    unsupported_commands: u64,
    bind_rejected_total: u64,
    handshake_errors: u64,
    handshake_timeouts: u64,
    bytes_from_public: u64,
    bytes_to_public: u64,
    pairing_timeouts: u64,
    connect_failures: u64,
    transfer_errors: u64,
    lifetime_timeouts: u64,
    udp_active_associations: usize,
    udp_datagrams_from_public: u64,
    udp_datagrams_to_public: u64,
    udp_bytes_from_public: u64,
    udp_bytes_to_public: u64,
    udp_dropped_datagrams: u64,
    udp_dropped_bandwidth_limit: u64,
    udp_fragmentation_unsupported_total: u64,
}

#[derive(Serialize)]
struct HttpProxyView {
    #[serde(flatten)]
    policy: HttpProxyPolicy,
    online: bool,
    active_connections: usize,
    connections_total: u64,
    requests_total: u64,
    connect_requests: u64,
    authentication_failures: u64,
    rejected_connections: u64,
    malformed_requests: u64,
    bytes_from_public: u64,
    bytes_to_public: u64,
    pairing_timeouts: u64,
    connect_failures: u64,
    transfer_errors: u64,
    lifetime_timeouts: u64,
}

#[derive(Serialize)]
struct RouteTlsView {
    mode: RouteTlsMode,
    redirect_http_to_https: bool,
    https_online: bool,
    status: CertificateStatus,
    issuer: Option<String>,
    not_before_unix_seconds: Option<i64>,
    not_after_unix_seconds: Option<i64>,
    next_renewal_unix_seconds: Option<i64>,
    last_attempt_unix_seconds: Option<i64>,
    last_success_unix_seconds: Option<i64>,
    failure_count: u32,
    last_error_code: Option<String>,
    last_error_message: Option<String>,
}

#[derive(Serialize)]
struct AcmeConfigView {
    enabled: bool,
    environment: certificate_catalog::AcmeEnvironment,
    directory_url: String,
    contact_email: Option<String>,
    terms_accepted: bool,
    challenge_type: &'static str,
    renew_before_days: u8,
    account_registered: bool,
    updated_at_unix_seconds: Option<i64>,
}

#[derive(Serialize)]
struct CertificateOperationResponse {
    route_id: Uuid,
    operation: &'static str,
    status: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CertificateOperation {
    Issue,
    Renew,
}

struct ApiError(StatusCode, &'static str);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({ "error": self.1 }))).into_response()
    }
}

struct CodedApiError(StatusCode, &'static str, &'static str);

impl IntoResponse for CodedApiError {
    fn into_response(self) -> Response {
        (
            self.0,
            Json(serde_json::json!({ "code": self.1, "error": self.2 })),
        )
            .into_response()
    }
}

fn coded_management_error(error: ApiError) -> CodedApiError {
    CodedApiError(error.0, "management_authorization_failed", error.1)
}

fn coded_tcp_policy_error(error: anyhow::Error) -> CodedApiError {
    let message = error.to_string();
    let code = if message.contains("tunnel name is invalid") {
        "invalid_name"
    } else if message.contains("public port is outside") {
        "invalid_public_port"
    } else if message.contains("target address is invalid") {
        "invalid_target"
    } else if message.contains("connection limit is invalid") {
        "invalid_connection_limit"
    } else if message.contains("bandwidth limit is invalid") {
        "invalid_bandwidth_limit"
    } else if message.contains("public port is already assigned")
        || message.contains("UNIQUE constraint failed")
    {
        "duplicate_public_port"
    } else {
        "tcp_policy_storage_error"
    };
    let status = match code {
        "tcp_policy_storage_error" => StatusCode::INTERNAL_SERVER_ERROR,
        "duplicate_public_port" => StatusCode::CONFLICT,
        _ => StatusCode::BAD_REQUEST,
    };
    CodedApiError(status, code, "TCP tunnel policy operation failed")
}

fn coded_http_route_creation_error(error: CreateHttpRouteError) -> CodedApiError {
    match error {
        CreateHttpRouteError::InvalidName => CodedApiError(
            StatusCode::BAD_REQUEST,
            "invalid_name",
            "HTTP route name is invalid",
        ),
        CreateHttpRouteError::InvalidHostname => CodedApiError(
            StatusCode::BAD_REQUEST,
            "invalid_hostname",
            "HTTP route hostname is invalid",
        ),
        CreateHttpRouteError::DuplicateHostname => CodedApiError(
            StatusCode::CONFLICT,
            "duplicate_hostname",
            "HTTP route hostname is already in use",
        ),
        CreateHttpRouteError::InvalidTarget => CodedApiError(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "HTTP route target address is invalid",
        ),
        CreateHttpRouteError::InvalidConnectionLimit => CodedApiError(
            StatusCode::BAD_REQUEST,
            "invalid_connection_limit",
            "HTTP route connection limit is invalid",
        ),
        CreateHttpRouteError::Database(_) => CodedApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "could not create HTTP route",
        ),
    }
}

fn coded_udp_policy_error(error: UdpPolicyError) -> CodedApiError {
    let status = match error {
        UdpPolicyError::DuplicatePublicPort => StatusCode::CONFLICT,
        UdpPolicyError::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::BAD_REQUEST,
    };
    CodedApiError(status, error.code(), "UDP tunnel policy is invalid")
}

fn coded_secret_policy_error(error: SecretPolicyError) -> CodedApiError {
    let status = match error {
        SecretPolicyError::DuplicateName => StatusCode::CONFLICT,
        SecretPolicyError::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::BAD_REQUEST,
    };
    CodedApiError(status, error.code(), "secret tunnel policy is invalid")
}

fn coded_socks5_policy_error(error: Socks5PolicyError) -> CodedApiError {
    let status = match error {
        Socks5PolicyError::DuplicateName | Socks5PolicyError::DuplicatePublicPort => {
            StatusCode::CONFLICT
        }
        Socks5PolicyError::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::BAD_REQUEST,
    };
    CodedApiError(status, error.code(), "SOCKS5 proxy policy is invalid")
}

fn coded_http_proxy_policy_error(error: HttpProxyPolicyError) -> CodedApiError {
    let status = match error {
        HttpProxyPolicyError::DuplicateName | HttpProxyPolicyError::DuplicatePublicPort => {
            StatusCode::CONFLICT
        }
        HttpProxyPolicyError::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::BAD_REQUEST,
    };
    CodedApiError(status, error.code(), "HTTP proxy policy is invalid")
}

fn coded_port_group_policy_error(error: PortGroupPolicyError) -> CodedApiError {
    let status = match error {
        PortGroupPolicyError::DuplicateName | PortGroupPolicyError::DuplicatePublicPort => {
            StatusCode::CONFLICT
        }
        PortGroupPolicyError::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::BAD_REQUEST,
    };
    CodedApiError(status, error.code(), "port group policy is invalid")
}

fn coded_sni_route_policy_error(error: SniRoutePolicyError) -> CodedApiError {
    let status = match error {
        SniRoutePolicyError::DuplicateHostname => StatusCode::CONFLICT,
        SniRoutePolicyError::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::BAD_REQUEST,
    };
    CodedApiError(status, error.code(), "TLS SNI route policy is invalid")
}

fn coded_certificate_catalog_error(error: CertificateCatalogError) -> CodedApiError {
    let status = match &error {
        CertificateCatalogError::InvalidDirectoryUrl
        | CertificateCatalogError::DirectoryUrlDoesNotMatchEnvironment
        | CertificateCatalogError::InvalidContactEmail
        | CertificateCatalogError::TermsNotAccepted
        | CertificateCatalogError::InvalidRenewalWindow
        | CertificateCatalogError::InvalidRedirectPolicy => StatusCode::BAD_REQUEST,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    CodedApiError(status, error.code(), "certificate configuration is invalid")
}

fn acme_config_view(state: &AppState, config: AcmeConfig) -> AcmeConfigView {
    let account_registered = state
        .certificate_manager
        .as_ref()
        .is_some_and(|manager| manager.account_registered(&config.directory_url));
    AcmeConfigView {
        enabled: config.enabled,
        environment: config.environment,
        directory_url: config.directory_url,
        contact_email: (!config.contact_email.is_empty()).then_some(config.contact_email),
        terms_accepted: config.terms_accepted,
        challenge_type: "http-01",
        renew_before_days: config.renew_before_days,
        account_registered,
        updated_at_unix_seconds: (config.updated_at > 0).then_some(config.updated_at),
    }
}

fn route_tls_view(
    state: &AppState,
    hostname: &str,
    policy: Option<RouteTlsPolicy>,
    certificate: Option<CertificateState>,
) -> RouteTlsView {
    let mode = policy
        .as_ref()
        .map_or(RouteTlsMode::Disabled, |policy| policy.mode);
    let redirect_http_to_https = policy
        .as_ref()
        .is_some_and(|policy| policy.redirect_http_to_https);
    let status = certificate
        .as_ref()
        .map_or(CertificateStatus::Disabled, |certificate| {
            certificate.status
        });
    let https_online = state
        .certificate_manager
        .as_ref()
        .is_some_and(|manager| manager.has_certificate(hostname));
    RouteTlsView {
        mode,
        redirect_http_to_https,
        https_online,
        status,
        issuer: certificate.as_ref().and_then(|value| value.issuer.clone()),
        not_before_unix_seconds: certificate.as_ref().and_then(|value| value.not_before),
        not_after_unix_seconds: certificate.as_ref().and_then(|value| value.not_after),
        next_renewal_unix_seconds: certificate.as_ref().and_then(|value| value.next_renewal),
        last_attempt_unix_seconds: certificate.as_ref().and_then(|value| value.last_attempt),
        last_success_unix_seconds: certificate.as_ref().and_then(|value| value.last_success),
        failure_count: certificate.as_ref().map_or(0, |value| value.failure_count),
        last_error_code: certificate
            .as_ref()
            .and_then(|value| value.last_error_code.clone()),
        last_error_message: certificate.and_then(|value| value.last_error_message),
    }
}

fn main() -> anyhow::Result<()> {
    if print_version_if_requested("LinkLake Server")? {
        return Ok(());
    }
    if run_update_utility()? {
        return Ok(());
    }
    if run_database_utility()? {
        return Ok(());
    }
    let _log_guard = init_logging()?;
    if std::env::args_os().any(|argument| argument == "--windows-service") {
        #[cfg(windows)]
        {
            return windows_service_host::run().map_err(Into::into);
        }
        #[cfg(not(windows))]
        anyhow::bail!("--windows-service is available only on Windows");
    }
    tokio::runtime::Runtime::new()?.block_on(run_server(None))
}

fn print_version_if_requested(product: &'static str) -> anyhow::Result<bool> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if arguments.iter().any(|value| value == "--version-json") {
        println!("{}", serde_json::to_string(&BuildInfo::current(product))?);
        return Ok(true);
    }
    if arguments.iter().any(|value| value == "--version") {
        println!("{}", BuildInfo::current(product).display_line());
        return Ok(true);
    }
    Ok(false)
}

#[derive(Parser)]
#[command(name = "linklake-server", disable_version_flag = true)]
struct ServerMaintenanceCli {
    #[command(subcommand)]
    command: ServerMaintenanceCommand,
}

#[derive(Subcommand)]
enum ServerMaintenanceCommand {
    CheckUpdate {
        #[arg(long, default_value = "ASL-Vanity/LinkLake")]
        repository: String,
        #[arg(long, value_enum, default_value_t = UpdateChannel::Auto)]
        channel: UpdateChannel,
        #[arg(long)]
        development_signature: bool,
    },
    Update {
        #[command(subcommand)]
        action: ServerUpdateAction,
    },
    #[command(name = "__update-helper", hide = true)]
    UpdateHelper {
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        plan_sha256: String,
    },
}

#[derive(Subcommand)]
enum ServerUpdateAction {
    Download {
        #[arg(long, default_value = "ASL-Vanity/LinkLake")]
        repository: String,
        #[arg(long, value_enum, default_value_t = UpdateChannel::Auto)]
        channel: UpdateChannel,
        #[arg(long)]
        state_dir: Option<PathBuf>,
        #[arg(long)]
        allow_downgrade: bool,
        #[arg(long)]
        development_signature: bool,
    },
    Apply {
        #[arg(long, default_value = "ASL-Vanity/LinkLake")]
        repository: String,
        #[arg(long, value_enum, default_value_t = UpdateChannel::Auto)]
        channel: UpdateChannel,
        #[arg(long)]
        state_dir: Option<PathBuf>,
        #[arg(long)]
        allow_downgrade: bool,
        #[arg(long)]
        development_signature: bool,
        #[arg(long)]
        yes: bool,
    },
    Status {
        #[arg(long)]
        state_dir: Option<PathBuf>,
    },
    Rollback {
        #[arg(long)]
        state_dir: Option<PathBuf>,
        #[arg(long)]
        yes: bool,
    },
}

fn run_update_utility() -> anyhow::Result<bool> {
    let first = std::env::args_os().nth(1);
    let recognized = matches!(
        first.as_deref().and_then(|value| value.to_str()),
        Some("check-update" | "update" | "__update-helper")
    );
    if !recognized {
        return Ok(false);
    }
    let command = ServerMaintenanceCli::parse().command;
    match command {
        ServerMaintenanceCommand::CheckUpdate {
            repository,
            channel,
            development_signature,
        } => {
            let result = tokio::runtime::Runtime::new()?.block_on(linklake_update::check(
                UpdateProduct::Server,
                &repository,
                channel,
                signature_policy(development_signature),
            ))?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        ServerMaintenanceCommand::Update { action } => match action {
            ServerUpdateAction::Download {
                repository,
                channel,
                state_dir,
                allow_downgrade,
                development_signature,
            } => {
                let state = state_dir.unwrap_or_else(|| {
                    linklake_update::default_state_directory(UpdateProduct::Server)
                });
                let result =
                    tokio::runtime::Runtime::new()?.block_on(linklake_update::download(
                        UpdateProduct::Server,
                        &repository,
                        channel,
                        &state,
                        allow_downgrade,
                        signature_policy(development_signature),
                    ))?;
                println!("{}", serde_json::to_string_pretty(&result)?);
            }
            ServerUpdateAction::Apply {
                repository,
                channel,
                state_dir,
                allow_downgrade,
                development_signature,
                yes,
            } => {
                let state = state_dir.unwrap_or_else(|| {
                    linklake_update::default_state_directory(UpdateProduct::Server)
                });
                let result = tokio::runtime::Runtime::new()?.block_on(linklake_update::apply(
                    UpdateProduct::Server,
                    &repository,
                    channel,
                    &state,
                    allow_downgrade,
                    yes,
                    signature_policy(development_signature),
                ))?;
                println!("{}", serde_json::to_string_pretty(&result)?);
            }
            ServerUpdateAction::Status { state_dir } => {
                let state = state_dir.unwrap_or_else(|| {
                    linklake_update::default_state_directory(UpdateProduct::Server)
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&linklake_update::status(
                        UpdateProduct::Server,
                        &state,
                    )?)?
                );
            }
            ServerUpdateAction::Rollback { state_dir, yes } => {
                let state = state_dir.unwrap_or_else(|| {
                    linklake_update::default_state_directory(UpdateProduct::Server)
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&linklake_update::rollback(
                        UpdateProduct::Server,
                        &state,
                        yes,
                    )?)?
                );
            }
        },
        ServerMaintenanceCommand::UpdateHelper { plan, plan_sha256 } => {
            linklake_update::run_helper(&plan, &plan_sha256)?;
        }
    }
    Ok(true)
}

fn signature_policy(development: bool) -> SignaturePolicy {
    if development {
        SignaturePolicy::Development
    } else {
        SignaturePolicy::Production
    }
}

fn run_database_utility() -> anyhow::Result<bool> {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    let Some(command) = arguments.first().and_then(|value| value.to_str()) else {
        return Ok(false);
    };
    if command != "backup" && command != "restore" {
        return Ok(false);
    }
    let data_directory = path_argument(&arguments, "--data-dir")
        .or_else(|| std::env::var_os("LINKLAKE_DATA_DIR").map(PathBuf::from))
        .ok_or_else(|| anyhow::anyhow!("--data-dir or LINKLAKE_DATA_DIR is required"))?;
    let database = data_directory.join("linklake.sqlite3");
    match command {
        "backup" => {
            let output = path_argument(&arguments, "--output")
                .ok_or_else(|| anyhow::anyhow!("backup requires --output <path>"))?;
            database_tools::backup(&database, &output)?;
            println!("LinkLake backup created: {}", output.display());
        }
        "restore" => {
            let input = path_argument(&arguments, "--input")
                .ok_or_else(|| anyhow::anyhow!("restore requires --input <path>"))?;
            let previous = database_tools::restore(&database, &input)?;
            println!("LinkLake database restored from: {}", input.display());
            if let Some(previous) = previous {
                println!("Previous database preserved at: {}", previous.display());
            }
        }
        _ => unreachable!(),
    }
    Ok(true)
}

fn path_argument(arguments: &[std::ffi::OsString], name: &str) -> Option<PathBuf> {
    arguments
        .windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| PathBuf::from(&pair[1]))
}

async fn run_server(
    service_shutdown: Option<tokio::sync::oneshot::Receiver<()>>,
) -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let bind = std::env::var("LINKLAKE_BIND").unwrap_or_else(|_| "127.0.0.1:32100".to_owned());
    let address: SocketAddr = bind.parse()?;
    let control_bind =
        std::env::var("LINKLAKE_CONTROL_BIND").unwrap_or_else(|_| "127.0.0.1:32101".to_owned());
    let control_address: SocketAddr = control_bind.parse()?;
    let http_address = std::env::var("LINKLAKE_HTTP_BIND")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.parse::<SocketAddr>())
        .transpose()?;
    let https_address = std::env::var("LINKLAKE_HTTPS_BIND")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.parse::<SocketAddr>())
        .transpose()?;
    let sni_address = std::env::var("LINKLAKE_TLS_PASSTHROUGH_BIND")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.parse::<SocketAddr>())
        .transpose()?;
    anyhow::ensure!(
        sni_address.is_none() || sni_address != https_address,
        "LINKLAKE_TLS_PASSTHROUGH_BIND must not equal LINKLAKE_HTTPS_BIND"
    );
    let udp_relay_address = std::env::var("LINKLAKE_UDP_RELAY_BIND")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.parse::<SocketAddr>())
        .transpose()?;
    let udp_relay_endpoint = std::env::var("LINKLAKE_UDP_RELAY_ENDPOINT")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let udp_relay_server_name = std::env::var("LINKLAKE_UDP_RELAY_SERVER_NAME")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let udp_public_bind_mode = std::env::var("LINKLAKE_UDP_PUBLIC_BIND_MODE")
        .unwrap_or_else(|_| "auto".to_owned())
        .parse::<PublicUdpBindMode>()?;
    tracing::info!(
        mode = udp_public_bind_mode.as_str(),
        "Loaded public UDP bind mode"
    );
    if udp_public_bind_mode == PublicUdpBindMode::DualStackRequired {
        let probe = DualStackUdpSocket::bind(0, udp_public_bind_mode)
            .await
            .map_err(|error| {
                anyhow::anyhow!(
                    "dual-stack public UDP is required, but the host capability probe failed: {error}"
                )
            })?;
        drop(probe);
    }
    let public_port_policy = PublicPortPolicy::from_environment(
        std::iter::once(address)
            .chain(std::iter::once(control_address))
            .chain(http_address)
            .chain(https_address)
            .chain(sni_address),
        udp_relay_address,
    )?;
    let public_port_policy_view = public_port_policy.view();
    tracing::info!(
        tcp_allowed = %public_port_policy_view.tcp_allowed,
        tcp_reserved = %public_port_policy_view.tcp_reserved,
        udp_allowed = %public_port_policy_view.udp_allowed,
        udp_reserved = %public_port_policy_view.udp_reserved,
        "Loaded public port policy"
    );
    let control_cert = std::env::var("LINKLAKE_CONTROL_CERT_PATH").ok();
    let control_key = std::env::var("LINKLAKE_CONTROL_KEY_PATH").ok();
    let management_cert = std::env::var("LINKLAKE_MANAGEMENT_CERT_PATH").ok();
    let management_key = std::env::var("LINKLAKE_MANAGEMENT_KEY_PATH").ok();
    let configured_token = std::env::var("LINKLAKE_ENROLLMENT_TOKEN")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let configured_management_token = std::env::var("LINKLAKE_MANAGEMENT_TOKEN")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let data_dir = std::env::var_os("LINKLAKE_DATA_DIR").map(PathBuf::from);
    let insecure_default_requested = std::env::var("LINKLAKE_ALLOW_INSECURE_DEFAULT_ADMIN")
        .ok()
        .is_some_and(|value| value == "1");
    if configured_token.is_none() && !address.ip().is_loopback() {
        anyhow::bail!(
            "LINKLAKE_ENROLLMENT_TOKEN is required when binding to a non-loopback address"
        );
    }
    let management_tls = match (management_cert, management_key) {
        (Some(cert), Some(key)) => Some(ManagementTlsConfig::from_pem_file(cert, key).await?),
        (None, None) if address.ip().is_loopback() => None,
        (None, None) => anyhow::bail!("LINKLAKE_MANAGEMENT_CERT_PATH and LINKLAKE_MANAGEMENT_KEY_PATH are required for remote management"),
        _ => anyhow::bail!("both TLS certificate and key paths are required for management"),
    };
    let control_tls = match (&control_cert, &control_key) {
        (Some(cert), Some(key)) => Some(load_control_tls(cert, key)?),
        (None, None) if control_address.ip().is_loopback() => None,
        (None, None) => anyhow::bail!("LINKLAKE_CONTROL_CERT_PATH and LINKLAKE_CONTROL_KEY_PATH are required for remote TCP control"),
        _ => anyhow::bail!("both TLS certificate and key paths are required for TCP control"),
    };
    let udp_data_plane = match udp_relay_address {
        Some(bind_address) => {
            let advertised_endpoint = udp_relay_endpoint.ok_or_else(|| {
                anyhow::anyhow!("LINKLAKE_UDP_RELAY_ENDPOINT is required when UDP relay is enabled")
            })?;
            let server_name = udp_relay_server_name.ok_or_else(|| {
                anyhow::anyhow!(
                    "LINKLAKE_UDP_RELAY_SERVER_NAME is required when UDP relay is enabled"
                )
            })?;
            let certificate_path = control_cert
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("UDP relay requires LINKLAKE_CONTROL_CERT_PATH"))?;
            let private_key_path = control_key
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("UDP relay requires LINKLAKE_CONTROL_KEY_PATH"))?;
            Some(UdpDataPlane::bind(UdpDataPlaneConfig {
                bind_address,
                advertised_endpoint,
                server_name,
                certificate_path: std::path::Path::new(certificate_path),
                private_key_path: std::path::Path::new(private_key_path),
            })?)
        }
        None => {
            anyhow::ensure!(
                udp_relay_endpoint.is_none() && udp_relay_server_name.is_none(),
                "LINKLAKE_UDP_RELAY_BIND is required when UDP relay endpoint settings are provided"
            );
            None
        }
    };
    let enrollment_token = configured_token.unwrap_or_else(|| {
        let token = Uuid::new_v4().to_string();
        tracing::warn!("Generated local development enrollment token: {token}");
        token
    });
    if data_dir.is_none() && !address.ip().is_loopback() {
        anyhow::bail!("LINKLAKE_DATA_DIR is required for remote management");
    }
    if https_address.is_some() && data_dir.is_none() {
        anyhow::bail!("LINKLAKE_DATA_DIR is required when LINKLAKE_HTTPS_BIND is configured");
    }
    if insecure_default_requested && !address.ip().is_loopback() {
        anyhow::bail!(
            "LINKLAKE_ALLOW_INSECURE_DEFAULT_ADMIN is permitted only for loopback development"
        );
    }
    if insecure_default_requested && data_dir.is_none() {
        anyhow::bail!("LINKLAKE_ALLOW_INSECURE_DEFAULT_ADMIN requires LINKLAKE_DATA_DIR");
    }
    if data_dir.is_none() {
        tracing::warn!("No LINKLAKE_DATA_DIR configured; identities and administrator sessions are in-memory only.");
    }
    let bootstrap_admin = BootstrapCredentials::from_environment(insecure_default_requested)?;
    let database = Database::open(data_dir.as_deref())?;
    let migration_plan = database
        .is_persistent()
        .then(|| database_migrations::prepare(&database))
        .transpose()?;
    if let Some(plan) = &migration_plan {
        if let Some(backup) = plan.backup_path() {
            tracing::info!(
                from_version = plan.source_version(),
                to_version = database_migrations::CURRENT_SCHEMA_VERSION,
                backup = %backup.display(),
                "Prepared LinkLake database migration backup"
            );
        }
    }
    let certificate_manager = data_dir
        .as_ref()
        .map(|data_dir| CertificateManager::new(data_dir.clone()))
        .transpose()?;
    let management_cookies_secure = management_tls.is_some();
    let state = Arc::new(AppState {
        _database: database.clone(),
        started_at: Instant::now(),
        instance_id: uuid::Uuid::new_v4().to_string(),
        lifecycle: LifecycleController::new(unix_seconds()),
        enrollment_token,
        management_token: configured_management_token,
        admin_auth: Mutex::new(AdminAuth::open_with_database(&database, bootstrap_admin)?),
        api_tokens: Mutex::new(ApiTokenCatalog::open_with_database(&database)?),
        login_throttle: Mutex::new(LoginThrottle::default()),
        login_hash_permits: Arc::new(Semaphore::new(LOGIN_HASH_CONCURRENCY)),
        audit: Mutex::new(AuditLog::open_with_database(&database)?),
        alerts: Mutex::new(AlertCatalog::open_with_database(&database)?),
        fleet: Mutex::new(FleetCatalog::open_with_database(&database)?),
        traffic_controls: Mutex::new(TrafficControlCatalog::open_with_database(&database)?),
        management_cookies_secure,
        public_port_policy: public_port_policy.clone(),
        udp_public_bind_mode,
        clients: Mutex::new(ClientRegistry::open_with_database(&database)?),
        tunnel_catalog: Mutex::new(TunnelCatalog::open_with_database(
            &database,
            public_port_policy,
        )?),
        tunnels: Mutex::new(HashMap::new()),
        tunnel_statistics: Mutex::new(HashMap::new()),
        seen_tunnel_registrations: Mutex::new(HashSet::new()),
        udp_data_plane,
        udp_tunnels: Mutex::new(HashMap::new()),
        udp_tunnel_statistics: Mutex::new(HashMap::new()),
        seen_udp_tunnel_registrations: Mutex::new(HashSet::new()),
        http_route_catalog: Mutex::new(HttpRouteCatalog::open_with_database(&database)?),
        http_routes: Mutex::new(HashMap::new()),
        http_route_statistics: Mutex::new(HashMap::new()),
        seen_http_route_registrations: Mutex::new(HashSet::new()),
        sni_route_catalog: Mutex::new(SniRouteCatalog::open_with_database(&database)?),
        sni_routes: Mutex::new(HashMap::new()),
        sni_route_statistics: Mutex::new(HashMap::new()),
        p2p_node_catalog: Mutex::new(P2pNodeCatalog::open_with_database(&database)?),
        p2p_sessions: Mutex::new(HashMap::new()),
        secret_tunnel_catalog: Mutex::new(SecretTunnelCatalog::open_with_database(&database)?),
        secret_tunnels: Mutex::new(HashMap::new()),
        secret_tunnel_statistics: Mutex::new(HashMap::new()),
        socks5_proxies: Mutex::new(HashMap::new()),
        socks5_proxy_statistics: Mutex::new(HashMap::new()),
        http_proxies: Mutex::new(HashMap::new()),
        http_proxy_statistics: Mutex::new(HashMap::new()),
        certificate_catalog: Mutex::new(CertificateCatalog::open_with_database(&database)?),
        certificate_manager,
        certificate_jobs: Mutex::new(HashMap::new()),
        https_redirect_hosts: Mutex::new(HashSet::new()),
        pending_connections: AsyncMutex::new(HashMap::new()),
        global_connection_permits: Arc::new(Semaphore::new(GLOBAL_CONNECTION_LIMIT)),
        pending_connection_permits: Arc::new(Semaphore::new(PENDING_CONNECTION_LIMIT)),
        global_udp_session_permits: Arc::new(Semaphore::new(GLOBAL_UDP_SESSION_LIMIT)),
        metrics: ServerCounters::default(),
        metrics_history: Mutex::new(MetricsHistory::open_with_database(
            &database,
            METRICS_HISTORY_CAPACITY,
            METRICS_HISTORY_ARCHIVE_CAPACITY,
        )?),
    });
    if let Some(plan) = migration_plan {
        plan.finish()?;
    }
    restore_managed_certificates(&state)?;
    let app = Router::new()
        .route("/", get(management_ui))
        .route("/api/v1/health", get(health))
        .route("/livez", get(live_probe))
        .route("/readyz", get(ready_probe))
        .route("/startupz", get(startup_probe))
        .route("/api/v1/health/live", get(live_probe))
        .route("/api/v1/health/ready", get(ready_probe))
        .route("/api/v1/health/startup", get(startup_probe))
        .route("/api/v1/lifecycle", get(get_lifecycle))
        .route("/api/v1/lifecycle/drain", post(drain_lifecycle))
        .route("/api/v1/lifecycle/resume", post(resume_lifecycle))
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/me", get(auth_me))
        .route("/api/v1/auth/logout", post(logout))
        .route("/api/v1/auth/change-password", post(change_password))
        .route("/api/v1/auth/totp/setup", post(setup_totp))
        .route("/api/v1/auth/totp/enable", post(enable_totp))
        .route("/api/v1/auth/totp/disable", post(disable_totp))
        .route("/api/v1/users", get(list_users).post(create_user))
        .route(
            "/api/v1/users/:username",
            put(update_user).delete(delete_user),
        )
        .route(
            "/api/v1/users/:username/reset-password",
            post(reset_user_password),
        )
        .route(
            "/api/v1/users/:username/revoke-sessions",
            post(revoke_user_sessions),
        )
        .route("/api/v1/sessions", get(list_sessions))
        .route(
            "/api/v1/api-tokens",
            get(list_api_tokens).post(create_api_token),
        )
        .route(
            "/api/v1/api-tokens/:token_id",
            axum::routing::delete(revoke_api_token),
        )
        .route(
            "/api/v1/sessions/:session_id",
            axum::routing::delete(revoke_session),
        )
        .route("/api/v1/status", get(status))
        .route("/api/v1/public-port-policy", get(get_public_port_policy))
        .route("/api/v1/metrics", get(metrics))
        .route("/api/v1/metrics/prometheus", get(prometheus_metrics))
        .route("/api/v1/metrics/history", get(metrics_history))
        .route(
            "/api/v1/metrics/history/export",
            get(export_metrics_history),
        )
        .route(
            "/api/v1/metrics/policies/:kind/:policy_id/history",
            get(policy_metrics_history),
        )
        .route(
            "/api/v1/acme/config",
            get(get_acme_config).put(update_acme_config),
        )
        .route("/api/v1/clients", get(list_clients))
        .route("/api/v1/search", get(global_search))
        .route(
            "/api/v1/clients/:client_id",
            put(update_client).delete(delete_client),
        )
        .route(
            "/api/v1/clients/:client_id/rotate-token",
            post(rotate_client_token),
        )
        .route("/api/v1/audit", get(list_audit_events))
        .route("/api/v1/audit/export", get(export_audit_events))
        .route(
            "/api/v1/alerts/rules",
            get(list_alert_rules).post(create_alert_rule),
        )
        .route(
            "/api/v1/alerts/rules/:rule_id",
            put(update_alert_rule).delete(delete_alert_rule),
        )
        .route("/api/v1/alerts/events", get(list_alert_events))
        .route("/api/v1/alerts/channels", get(alert_notification_channels))
        .route(
            "/api/v1/fleet/peers",
            get(list_fleet_peers).post(create_fleet_peer),
        )
        .route(
            "/api/v1/fleet/peers/:peer_id",
            put(update_fleet_peer).delete(delete_fleet_peer),
        )
        .route("/api/v1/fleet/overview", get(fleet_overview))
        .route("/api/v1/fleet/import", post(import_fleet_policies))
        .route("/api/v1/fleet/sync", post(sync_fleet_policies))
        .route(
            "/api/v1/traffic-controls/:kind/:policy_id",
            get(get_traffic_control)
                .put(upsert_traffic_control)
                .delete(delete_traffic_control),
        )
        .route(
            "/api/v1/tcp-tunnels",
            get(list_tcp_tunnels).post(create_tcp_tunnel),
        )
        .route(
            "/api/v1/tcp-tunnels/:tunnel_id",
            axum::routing::delete(delete_tcp_tunnel).put(update_tcp_tunnel),
        )
        .route(
            "/api/v1/tcp-tunnels/:tunnel_id/enabled",
            post(set_tcp_tunnel_enabled),
        )
        .route(
            "/api/v1/udp-tunnels",
            get(list_udp_tunnels).post(create_udp_tunnel),
        )
        .route(
            "/api/v1/udp-tunnels/:tunnel_id",
            axum::routing::delete(delete_udp_tunnel).put(update_udp_tunnel),
        )
        .route(
            "/api/v1/udp-tunnels/:tunnel_id/enabled",
            post(set_udp_tunnel_enabled),
        )
        .route(
            "/api/v1/port-groups",
            get(list_port_groups).post(create_port_group),
        )
        .route(
            "/api/v1/port-groups/:group_id",
            axum::routing::delete(delete_port_group).put(update_port_group),
        )
        .route(
            "/api/v1/port-groups/:group_id/enabled",
            post(set_port_group_enabled),
        )
        .route(
            "/api/v1/http-routes",
            get(list_http_routes).post(create_http_route),
        )
        .route(
            "/api/v1/http-routes/:route_id",
            axum::routing::delete(delete_http_route).put(update_http_route),
        )
        .route(
            "/api/v1/http-routes/:route_id/enabled",
            post(set_http_route_enabled),
        )
        .route(
            "/api/v1/sni-routes",
            get(list_sni_routes).post(create_sni_route),
        )
        .route(
            "/api/v1/sni-routes/:route_id",
            axum::routing::delete(delete_sni_route).put(update_sni_route),
        )
        .route(
            "/api/v1/sni-routes/:route_id/enabled",
            post(set_sni_route_enabled),
        )
        .route("/api/v1/p2p/nodes", get(list_p2p_nodes))
        .route("/api/v1/http-routes/:route_id/tls", put(set_http_route_tls))
        .route(
            "/api/v1/http-routes/:route_id/certificate/issue",
            post(issue_http_route_certificate),
        )
        .route(
            "/api/v1/http-routes/:route_id/certificate/renew",
            post(renew_http_route_certificate),
        )
        .route(
            "/api/v1/secret-tunnels",
            get(list_secret_tunnels).post(create_secret_tunnel),
        )
        .route(
            "/api/v1/secret-tunnels/:tunnel_id",
            axum::routing::delete(delete_secret_tunnel).put(update_secret_tunnel),
        )
        .route(
            "/api/v1/secret-tunnels/:tunnel_id/enabled",
            post(set_secret_tunnel_enabled),
        )
        .route(
            "/api/v1/socks5-proxies",
            get(list_socks5_proxies).post(create_socks5_proxy),
        )
        .route(
            "/api/v1/socks5-proxies/:proxy_id",
            axum::routing::delete(delete_socks5_proxy).put(update_socks5_proxy),
        )
        .route(
            "/api/v1/socks5-proxies/:proxy_id/enabled",
            post(set_socks5_proxy_enabled),
        )
        .route(
            "/api/v1/http-proxies",
            get(list_http_proxies).post(create_http_proxy),
        )
        .route(
            "/api/v1/http-proxies/:proxy_id",
            axum::routing::delete(delete_http_proxy).put(update_http_proxy),
        )
        .route(
            "/api/v1/http-proxies/:proxy_id/enabled",
            post(set_http_proxy_enabled),
        )
        .route("/api/v1/clients/enroll", post(enroll_client))
        .route("/api/v1/clients/:client_id/heartbeat", post(heartbeat))
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            enforce_management_role,
        ))
        .layer(TraceLayer::new_for_http())
        .layer(middleware::from_fn(cache_control_headers))
        .layer(middleware::from_fn(security_headers));

    // 先绑定所有由环境变量配置的静态监听器，任何一个失败都保持 Starting 并让启动失败。
    let control_listener = TcpListener::bind(control_address).await?;
    let http_listener = match http_address {
        Some(http_address) => Some((http_address, TcpListener::bind(http_address).await?)),
        None => None,
    };
    let https_listener = match https_address {
        Some(https_address) => {
            let certificate_manager = state
                .certificate_manager
                .as_ref()
                .expect("HTTPS requires a certificate manager");
            Some((
                https_address,
                TcpListener::bind(https_address).await?,
                TlsAcceptor::from(certificate_manager.tls_config()),
            ))
        }
        None => None,
    };
    let sni_listener = match sni_address {
        Some(sni_address) => Some((sni_address, TcpListener::bind(sni_address).await?)),
        None => None,
    };
    let management_tls_listener = if management_tls.is_some() {
        let listener = std::net::TcpListener::bind(address)?;
        listener.set_nonblocking(true)?;
        Some(listener)
    } else {
        None
    };
    let management_http_listener = if management_tls.is_none() {
        Some(TcpListener::bind(address).await?)
    } else {
        None
    };

    state.lifecycle.mark_ready(unix_seconds());
    tracing::info!("{PRODUCT_NAME} startup completed; lifecycle is ready");

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    record_metrics_history_sample(&state);
    tokio::spawn(run_metrics_history_sampler(
        state.clone(),
        shutdown_rx.clone(),
    ));
    tokio::spawn(run_alert_evaluator(state.clone(), shutdown_rx.clone()));
    tokio::spawn(run_certificate_maintenance(
        state.clone(),
        shutdown_rx.clone(),
    ));
    let shutdown_state = state.clone();
    tokio::spawn(async move {
        match service_shutdown {
            Some(shutdown) => {
                let _ = shutdown.await;
            }
            None => wait_for_os_shutdown().await,
        }
        shutdown_state.lifecycle.begin_stopping(unix_seconds());
        tracing::info!(
            "LinkLake received a shutdown signal; closing tunnels and draining requests."
        );
        tcp_tunnel::stop_all(&shutdown_state);
        udp_tunnel::stop_all(&shutdown_state);
        http_tunnel::stop_all(&shutdown_state);
        sni_tunnel::stop_all(&shutdown_state);
        secret_tunnel::stop_all(&shutdown_state);
        socks5_tunnel::stop_all(&shutdown_state);
        http_proxy_tunnel::stop_all(&shutdown_state);
        let _ = shutdown_tx.send(true);
    });
    if let Some(acceptor) = control_tls {
        tracing::info!("{PRODUCT_NAME} TLS TCP control listening on {control_address}");
        tokio::spawn(tcp_tunnel::run_tls_control_listener(
            state.clone(),
            control_listener,
            acceptor,
            shutdown_rx.clone(),
        ));
    } else {
        tracing::info!("{PRODUCT_NAME} development TCP control listening on {control_address}");
        tokio::spawn(tcp_tunnel::run_control_listener(
            state.clone(),
            control_listener,
            shutdown_rx.clone(),
        ));
    }
    if let Some((http_address, http_listener)) = http_listener {
        tracing::info!("{PRODUCT_NAME} HTTP route listener active on {http_address}");
        tokio::spawn(http_tunnel::run_http_listener(
            state.clone(),
            http_listener,
            shutdown_rx.clone(),
        ));
    }
    if let Some((https_address, https_listener, acceptor)) = https_listener {
        tracing::info!("{PRODUCT_NAME} HTTPS route listener active on {https_address}");
        tokio::spawn(http_tunnel::run_https_listener(
            state.clone(),
            https_listener,
            acceptor,
            shutdown_rx.clone(),
        ));
    }
    if let Some((sni_address, sni_listener)) = sni_listener {
        tracing::info!("{PRODUCT_NAME} TLS SNI pass-through listener active on {sni_address}");
        tokio::spawn(sni_tunnel::run_listener(
            state.clone(),
            sni_listener,
            shutdown_rx.clone(),
        ));
    }
    if let Some(config) = management_tls {
        let listener = management_tls_listener.expect("TLS management listener must be bound");
        tracing::info!("{PRODUCT_NAME} HTTPS management listening on https://{address}");
        let handle = axum_server::Handle::new();
        let shutdown_handle = handle.clone();
        let management_shutdown = shutdown_rx.clone();
        tokio::spawn(async move {
            wait_for_shutdown(management_shutdown).await;
            shutdown_handle.graceful_shutdown(Some(std::time::Duration::from_secs(10)));
        });
        axum_server::from_tcp_rustls(listener, config)
            .handle(handle)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await?;
    } else {
        let listener = management_http_listener.expect("HTTP management listener must be bound");
        tracing::info!("{PRODUCT_NAME} development HTTP management listening on http://{address}");
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(wait_for_shutdown(shutdown_rx))
        .await?;
    }
    Ok(())
}

async fn wait_for_os_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match signal(SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = terminate.recv() => {}
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

async fn wait_for_shutdown(mut shutdown: watch::Receiver<bool>) {
    if !*shutdown.borrow() {
        let _ = shutdown.changed().await;
    }
}

fn init_logging() -> anyhow::Result<tracing_appender::non_blocking::WorkerGuard> {
    use tracing_appender::rolling::{RollingFileAppender, Rotation};
    use tracing_subscriber::EnvFilter;

    let log_directory = std::env::var_os("LINKLAKE_LOG_DIR")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("LINKLAKE_DATA_DIR")
                .map(PathBuf::from)
                .map(|path| path.join("logs"))
        })
        .unwrap_or_else(|| PathBuf::from("logs"));
    std::fs::create_dir_all(&log_directory)?;
    let appender = RollingFileAppender::builder()
        .rotation(Rotation::HOURLY)
        .filename_prefix("linklake-server.log")
        .max_log_files(168)
        .build(log_directory)?;
    let (writer, guard) = tracing_appender::non_blocking(appender);
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_ansi(false)
        .with_writer(writer)
        .init();
    Ok(guard)
}

async fn cache_control_headers(request: Request, next: Next) -> Response {
    let path = request.uri().path().to_owned();
    let mut response = next.run(request).await;
    apply_cache_control(&path, response.headers_mut());
    response
}

async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        axum::http::HeaderValue::from_static(
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        ),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        axum::http::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::X_FRAME_OPTIONS,
        axum::http::HeaderValue::from_static("DENY"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        axum::http::HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        axum::http::HeaderName::from_static("permissions-policy"),
        axum::http::HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    response
}

fn apply_cache_control(path: &str, headers: &mut HeaderMap) {
    let value = if path == "/api/v1" || path.starts_with("/api/v1/") {
        Some("no-store, private")
    } else if path == "/" {
        Some("no-cache")
    } else {
        None
    };
    if let Some(value) = value {
        headers.insert(
            header::CACHE_CONTROL,
            axum::http::HeaderValue::from_static(value),
        );
    }
}

async fn management_ui() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        Html(MANAGEMENT_UI),
    )
}

async fn health(State(state): State<Arc<AppState>>) -> Response {
    let healthy = state.lifecycle.is_live();
    (
        if healthy {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        Json(HealthResponse {
            product: PRODUCT_NAME,
            api_version: API_VERSION,
            status: if healthy { "ok" } else { "stopping" },
        }),
    )
        .into_response()
}

async fn live_probe(State(state): State<Arc<AppState>>) -> Response {
    lifecycle_probe(&state, state.lifecycle.is_live(), "ok", "not_live")
}

async fn ready_probe(State(state): State<Arc<AppState>>) -> Response {
    lifecycle_probe(&state, state.lifecycle.is_ready(), "ready", "not_ready")
}

async fn startup_probe(State(state): State<Arc<AppState>>) -> Response {
    lifecycle_probe(
        &state,
        state.lifecycle.startup_complete(),
        "started",
        "starting",
    )
}

fn lifecycle_probe(
    state: &AppState,
    healthy: bool,
    healthy_status: &'static str,
    unhealthy_status: &'static str,
) -> Response {
    (
        if healthy {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        Json(ProbeResponse {
            product: PRODUCT_NAME,
            api_version: API_VERSION,
            status: if healthy {
                healthy_status
            } else {
                unhealthy_status
            },
            phase: state.lifecycle.snapshot().phase,
        }),
    )
        .into_response()
}

async fn get_lifecycle(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<LifecycleResponse>, ApiError> {
    authorize_management(&state, &headers)?;
    Ok(Json(lifecycle_response(&state).await))
}

async fn drain_lifecycle(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    request: Option<Json<DrainRequest>>,
) -> Result<Json<LifecycleResponse>, CodedApiError> {
    let principal = require_administrator(&state, &headers)?;
    let timeout_seconds = request
        .map(|Json(request)| request.timeout_seconds)
        .unwrap_or(DEFAULT_DRAIN_TIMEOUT_SECONDS);
    if timeout_seconds == 0 || timeout_seconds > MAX_DRAIN_TIMEOUT_SECONDS {
        return Err(CodedApiError(
            StatusCode::BAD_REQUEST,
            "invalid_drain_timeout",
            "timeout_seconds must be between 1 and 3600",
        ));
    }
    let now = unix_seconds();
    state
        .lifecycle
        .begin_drain(now, Duration::from_secs(timeout_seconds))
        .map_err(lifecycle_transition_error)?;
    record_audit(
        &state,
        "lifecycle.drain",
        &principal.username,
        &format!(
            "timeout_seconds={timeout_seconds}; deadline_unix_seconds={}",
            now.saturating_add(timeout_seconds)
        ),
    );
    Ok(Json(lifecycle_response(&state).await))
}

async fn resume_lifecycle(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<LifecycleResponse>, CodedApiError> {
    let principal = require_administrator(&state, &headers)?;
    state
        .lifecycle
        .resume(unix_seconds())
        .map_err(lifecycle_transition_error)?;
    record_audit(
        &state,
        "lifecycle.resume",
        &principal.username,
        "new work admission resumed",
    );
    Ok(Json(lifecycle_response(&state).await))
}

fn lifecycle_transition_error(error: LifecycleTransitionError) -> CodedApiError {
    CodedApiError(
        StatusCode::CONFLICT,
        "lifecycle_transition_rejected",
        match error {
            LifecycleTransitionError::StartupIncomplete => "server startup is not complete",
            LifecycleTransitionError::Stopping => "server is stopping",
        },
    )
}

async fn lifecycle_response(state: &AppState) -> LifecycleResponse {
    let lifecycle = state.lifecycle.snapshot();
    let active_tcp_connections = state
        .tunnel_statistics
        .lock()
        .expect("tunnel statistics lock poisoned")
        .values()
        .map(|statistics| statistics.active_connections.load(Ordering::Relaxed))
        .sum::<usize>()
        .saturating_add(
            state
                .sni_route_statistics
                .lock()
                .expect("SNI route statistics lock poisoned")
                .values()
                .map(|statistics| statistics.active_connections.load(Ordering::Relaxed))
                .sum::<usize>(),
        )
        .saturating_add(
            state
                .secret_tunnel_statistics
                .lock()
                .expect("secret tunnel statistics lock poisoned")
                .values()
                .map(|statistics| statistics.active_connections.load(Ordering::Relaxed))
                .sum::<usize>(),
        )
        .saturating_add(
            state
                .socks5_proxy_statistics
                .lock()
                .expect("SOCKS5 statistics lock poisoned")
                .values()
                .map(|statistics| statistics.active_connections.load(Ordering::Relaxed))
                .sum::<usize>(),
        )
        .saturating_add(
            state
                .http_proxy_statistics
                .lock()
                .expect("HTTP proxy statistics lock poisoned")
                .values()
                .map(|statistics| statistics.active_connections.load(Ordering::Relaxed))
                .sum::<usize>(),
        )
        .saturating_add(
            state
                .metrics
                .public_http_active_connections
                .load(Ordering::Relaxed) as usize,
        );
    let pending_connection_pairings = state.pending_connections.lock().await.len();
    let active_udp_sessions = state
        .udp_tunnel_statistics
        .lock()
        .expect("UDP tunnel statistics lock poisoned")
        .values()
        .map(|statistics| statistics.active_sessions.load(Ordering::Relaxed))
        .sum::<usize>()
        .saturating_add(
            state
                .socks5_proxy_statistics
                .lock()
                .expect("SOCKS5 statistics lock poisoned")
                .values()
                .map(|statistics| statistics.udp_active_associations.load(Ordering::Relaxed))
                .sum::<usize>(),
        );
    let pending_p2p_sessions = p2p_control::pending_session_count(state, unix_seconds());
    let drained = active_tcp_connections == 0
        && pending_connection_pairings == 0
        && active_udp_sessions == 0
        && pending_p2p_sessions == 0;
    let now = unix_seconds();
    LifecycleResponse {
        lifecycle,
        accepting_new_work: state.lifecycle.accepts_new_work(),
        active_tcp_connections,
        pending_connection_pairings,
        active_udp_sessions,
        pending_p2p_sessions,
        drained,
        drain_deadline_reached: lifecycle
            .drain_deadline_unix_seconds
            .is_some_and(|deadline| now >= deadline),
    }
}

async fn get_public_port_policy(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<PublicPortPolicyView>, ApiError> {
    authorize_management(&state, &headers)?;
    Ok(Json(state.public_port_policy.view()))
}

async fn status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<StatusResponse>, ApiError> {
    authorize_management(&state, &headers)?;
    let clients = state.clients.lock().expect("client registry lock poisoned");
    let tunnels = state.tunnels.lock().expect("tunnel registry lock poisoned");
    let udp_tunnels = state
        .udp_tunnels
        .lock()
        .expect("UDP tunnel registry lock poisoned");
    let http_routes = state
        .http_routes
        .lock()
        .expect("HTTP route registry lock poisoned");
    let secret_tunnels = state
        .secret_tunnels
        .lock()
        .expect("secret tunnel registry lock poisoned");
    let socks5_proxies = state
        .socks5_proxies
        .lock()
        .expect("SOCKS5 proxy registry lock poisoned");
    let http_proxies = state
        .http_proxies
        .lock()
        .expect("HTTP proxy registry lock poisoned");
    let sni_routes = state
        .sni_routes
        .lock()
        .expect("SNI route registry lock poisoned");
    let port_groups = state
        .tunnel_catalog
        .lock()
        .expect("tunnel catalog lock poisoned")
        .list_port_groups()
        .map_err(|_| {
            ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not read port groups",
            )
        })?
        .len();
    let p2p_node_records = state
        .p2p_node_catalog
        .lock()
        .expect("P2P node catalog lock poisoned")
        .list()
        .map_err(|_| {
            ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not read P2P nodes",
            )
        })?;
    let now = unix_seconds();
    let p2p_nodes = p2p_node_records
        .iter()
        .filter(|node| p2p_control::node_is_fresh(node.updated_unix_seconds, now))
        .count();
    let p2p_nodes_total = p2p_node_records.len();
    Ok(Json(StatusResponse {
        product: PRODUCT_NAME,
        api_version: API_VERSION,
        instance_id: state.instance_id.clone(),
        tunnels: tunnels.len(),
        udp_tunnels: udp_tunnels.len(),
        http_routes: http_routes.len(),
        secret_tunnels: secret_tunnels.len(),
        socks5_proxies: socks5_proxies.len(),
        http_proxies: http_proxies.len(),
        port_groups,
        sni_routes: sni_routes.len(),
        p2p_nodes,
        p2p_nodes_total,
        udp_public_bind_mode: state.udp_public_bind_mode.as_str(),
        https_routes: state
            .certificate_manager
            .as_ref()
            .map_or(0, CertificateManager::certificate_count),
        clients: clients.count(),
    }))
}

async fn metrics(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<MetricsResponse>, ApiError> {
    authorize_management(&state, &headers)?;
    let statistics = state
        .tunnel_statistics
        .lock()
        .expect("tunnel statistics lock poisoned");
    let sum_u64 = |load: fn(&tcp_tunnel::TunnelStatistics) -> u64| {
        statistics.values().map(|statistics| load(statistics)).sum()
    };
    let udp_statistics = state
        .udp_tunnel_statistics
        .lock()
        .expect("UDP tunnel statistics lock poisoned");
    let mut udp_totals = udp_tunnel::UdpTunnelStatisticsSnapshot::default();
    for statistics in udp_statistics.values() {
        udp_totals.add_assign(statistics.snapshot());
    }
    let http_statistics = state
        .http_route_statistics
        .lock()
        .expect("HTTP route statistics lock poisoned");
    let sum_http_u64 = |load: fn(&http_tunnel::HttpRouteStatistics) -> u64| {
        http_statistics
            .values()
            .map(|statistics| load(statistics))
            .sum()
    };
    let sum_http_usize = |load: fn(&http_tunnel::HttpRouteStatistics) -> usize| {
        http_statistics
            .values()
            .map(|statistics| load(statistics))
            .sum()
    };
    let socks5_statistics = state
        .socks5_proxy_statistics
        .lock()
        .expect("SOCKS5 statistics lock poisoned");
    let sum_socks5_u64 = |load: fn(&socks5_tunnel::Socks5ProxyStatistics) -> u64| {
        socks5_statistics
            .values()
            .map(|statistics| load(statistics))
            .sum()
    };
    let http_proxy_statistics = state
        .http_proxy_statistics
        .lock()
        .expect("HTTP proxy statistics lock poisoned");
    let sum_http_proxy_u64 = |load: fn(&http_proxy_tunnel::HttpProxyStatistics) -> u64| {
        http_proxy_statistics
            .values()
            .map(|statistics| load(statistics))
            .sum()
    };
    let sni_statistics = state
        .sni_route_statistics
        .lock()
        .expect("SNI route statistics lock poisoned");
    let sum_sni_u64 = |load: fn(&sni_tunnel::SniRouteStatistics) -> u64| {
        sni_statistics
            .values()
            .map(|statistics| load(statistics))
            .sum()
    };
    let certificate_states = state
        .certificate_catalog
        .lock()
        .expect("certificate catalog lock poisoned")
        .list_certificate_states()
        .map_err(|_| {
            ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not read certificates",
            )
        })?;
    let now = unix_seconds() as i64;
    let expiring_boundary = now.saturating_add(30 * 86_400);
    let certificates_expired = certificate_states
        .iter()
        .filter(|certificate| certificate.expired_at(now))
        .count();
    let certificates_expiring_30d = certificate_states
        .iter()
        .filter(|certificate| {
            certificate
                .not_after
                .is_some_and(|not_after| not_after > now && not_after <= expiring_boundary)
        })
        .count();
    let certificate_nearest_expiry_unix_seconds = certificate_states
        .iter()
        .filter_map(|certificate| certificate.not_after)
        .filter(|not_after| *not_after > now)
        .min();
    Ok(Json(MetricsResponse {
        uptime_seconds: state.started_at.elapsed().as_secs(),
        tcp_active_connections: GLOBAL_CONNECTION_LIMIT
            - state.global_connection_permits.available_permits(),
        tcp_pending_connections: PENDING_CONNECTION_LIMIT
            - state.pending_connection_permits.available_permits(),
        tcp_bytes_from_public: sum_u64(|statistics| {
            statistics.bytes_from_public.load(Ordering::Relaxed)
        }),
        tcp_bytes_to_public: sum_u64(|statistics| {
            statistics.bytes_to_public.load(Ordering::Relaxed)
        }),
        tcp_failed_connections: sum_u64(|statistics| {
            statistics.failed_connections.load(Ordering::Relaxed)
        }),
        tcp_pairing_timeouts: sum_u64(|statistics| {
            statistics.pairing_timeouts.load(Ordering::Relaxed)
        }),
        tcp_transfer_errors: sum_u64(|statistics| {
            statistics.transfer_errors.load(Ordering::Relaxed)
        }),
        tcp_lifetime_timeouts: sum_u64(|statistics| {
            statistics.lifetime_timeouts.load(Ordering::Relaxed)
        }),
        tcp_rejected_policy_limit: sum_u64(|statistics| {
            statistics.rejected_policy_limit.load(Ordering::Relaxed)
        }),
        tcp_rejected_global_limit: sum_u64(|statistics| {
            statistics.rejected_global_limit.load(Ordering::Relaxed)
        }),
        tcp_rejected_pending_limit: sum_u64(|statistics| {
            statistics.rejected_pending_limit.load(Ordering::Relaxed)
        }),
        sni_active_connections: sni_statistics
            .values()
            .map(|statistics| statistics.active_connections.load(Ordering::Relaxed))
            .sum(),
        sni_connections_total: sum_sni_u64(|statistics| {
            statistics.connections_total.load(Ordering::Relaxed)
        }),
        sni_rejected_connections: sum_sni_u64(|statistics| {
            statistics.rejected_connections.load(Ordering::Relaxed)
        }),
        sni_client_hello_errors: state
            .metrics
            .sni_client_hello_errors_total
            .load(Ordering::Relaxed),
        sni_unknown_hostname: state
            .metrics
            .sni_unknown_hostname_total
            .load(Ordering::Relaxed),
        sni_bytes_from_public: sum_sni_u64(|statistics| {
            statistics.bytes_from_public.load(Ordering::Relaxed)
        }),
        sni_bytes_to_public: sum_sni_u64(|statistics| {
            statistics.bytes_to_public.load(Ordering::Relaxed)
        }),
        sni_pairing_timeouts: sum_sni_u64(|statistics| {
            statistics.pairing_timeouts.load(Ordering::Relaxed)
        }),
        sni_transfer_errors: sum_sni_u64(|statistics| {
            statistics.transfer_errors.load(Ordering::Relaxed)
        }),
        p2p_session_offers_total: state
            .metrics
            .p2p_session_offers_total
            .load(Ordering::Relaxed),
        p2p_direct_connections_total: state
            .metrics
            .p2p_direct_connections_total
            .load(Ordering::Relaxed),
        p2p_relay_fallbacks_total: state
            .metrics
            .p2p_relay_fallbacks_total
            .load(Ordering::Relaxed),
        socks5_capabilities: Socks5CapabilitiesView::new(state.udp_data_plane.is_some()),
        socks5_active_connections: socks5_statistics
            .values()
            .map(|statistics| statistics.active_connections.load(Ordering::Relaxed))
            .sum(),
        socks5_requests_total: sum_socks5_u64(|statistics| {
            statistics.requests_total.load(Ordering::Relaxed)
        }),
        socks5_authentication_failures: sum_socks5_u64(|statistics| {
            statistics.authentication_failures.load(Ordering::Relaxed)
        }),
        socks5_rejected_connections: sum_socks5_u64(|statistics| {
            statistics.rejected_connections.load(Ordering::Relaxed)
        }),
        socks5_bind_rejected_total: sum_socks5_u64(|statistics| {
            statistics.bind_rejected_total.load(Ordering::Relaxed)
        }),
        socks5_bytes_from_public: sum_socks5_u64(|statistics| {
            statistics.bytes_from_public.load(Ordering::Relaxed)
        }),
        socks5_bytes_to_public: sum_socks5_u64(|statistics| {
            statistics.bytes_to_public.load(Ordering::Relaxed)
        }),
        socks5_handshake_errors: sum_socks5_u64(|statistics| {
            statistics.handshake_errors.load(Ordering::Relaxed)
        }),
        socks5_handshake_timeouts: sum_socks5_u64(|statistics| {
            statistics.handshake_timeouts.load(Ordering::Relaxed)
        }),
        socks5_connect_failures: sum_socks5_u64(|statistics| {
            statistics.connect_failures.load(Ordering::Relaxed)
        }),
        socks5_pairing_timeouts: sum_socks5_u64(|statistics| {
            statistics.pairing_timeouts.load(Ordering::Relaxed)
        }),
        socks5_transfer_errors: sum_socks5_u64(|statistics| {
            statistics.transfer_errors.load(Ordering::Relaxed)
        }),
        socks5_udp_active_associations: socks5_statistics
            .values()
            .map(|statistics| statistics.udp_active_associations.load(Ordering::Relaxed))
            .sum(),
        socks5_udp_datagrams_from_public: sum_socks5_u64(|statistics| {
            statistics.udp_datagrams_from_public.load(Ordering::Relaxed)
        }),
        socks5_udp_datagrams_to_public: sum_socks5_u64(|statistics| {
            statistics.udp_datagrams_to_public.load(Ordering::Relaxed)
        }),
        socks5_udp_bytes_from_public: sum_socks5_u64(|statistics| {
            statistics.udp_bytes_from_public.load(Ordering::Relaxed)
        }),
        socks5_udp_bytes_to_public: sum_socks5_u64(|statistics| {
            statistics.udp_bytes_to_public.load(Ordering::Relaxed)
        }),
        socks5_udp_dropped_datagrams: sum_socks5_u64(|statistics| {
            statistics.udp_dropped_datagrams.load(Ordering::Relaxed)
        }),
        socks5_udp_dropped_bandwidth_limit: sum_socks5_u64(|statistics| {
            statistics
                .udp_dropped_bandwidth_limit
                .load(Ordering::Relaxed)
        }),
        socks5_udp_fragmentation_unsupported_total: sum_socks5_u64(|statistics| {
            statistics
                .udp_fragmentation_unsupported_total
                .load(Ordering::Relaxed)
        }),
        http_proxy_active_connections: http_proxy_statistics
            .values()
            .map(|statistics| statistics.active_connections.load(Ordering::Relaxed))
            .sum(),
        http_proxy_requests_total: sum_http_proxy_u64(|statistics| {
            statistics.requests_total.load(Ordering::Relaxed)
        }),
        http_proxy_connect_requests: sum_http_proxy_u64(|statistics| {
            statistics.connect_requests.load(Ordering::Relaxed)
        }),
        http_proxy_authentication_failures: sum_http_proxy_u64(|statistics| {
            statistics.authentication_failures.load(Ordering::Relaxed)
        }),
        http_proxy_rejected_connections: sum_http_proxy_u64(|statistics| {
            statistics.rejected_connections.load(Ordering::Relaxed)
        }),
        http_proxy_malformed_requests: sum_http_proxy_u64(|statistics| {
            statistics.malformed_requests.load(Ordering::Relaxed)
        }),
        http_proxy_bytes_from_public: sum_http_proxy_u64(|statistics| {
            statistics.bytes_from_public.load(Ordering::Relaxed)
        }),
        http_proxy_bytes_to_public: sum_http_proxy_u64(|statistics| {
            statistics.bytes_to_public.load(Ordering::Relaxed)
        }),
        http_proxy_pairing_timeouts: sum_http_proxy_u64(|statistics| {
            statistics.pairing_timeouts.load(Ordering::Relaxed)
        }),
        http_proxy_connect_failures: sum_http_proxy_u64(|statistics| {
            statistics.connect_failures.load(Ordering::Relaxed)
        }),
        http_proxy_transfer_errors: sum_http_proxy_u64(|statistics| {
            statistics.transfer_errors.load(Ordering::Relaxed)
        }),
        udp: udp_metrics_response(udp_totals),
        udp_public_ipv4_bind_successes_total: state
            .metrics
            .udp_public_ipv4_bind_successes_total
            .load(Ordering::Relaxed),
        udp_public_ipv6_bind_successes_total: state
            .metrics
            .udp_public_ipv6_bind_successes_total
            .load(Ordering::Relaxed),
        udp_public_ipv6_bind_fallbacks_total: state
            .metrics
            .udp_public_ipv6_bind_fallbacks_total
            .load(Ordering::Relaxed),
        udp_public_bind_failures_total: state
            .metrics
            .udp_public_bind_failures_total
            .load(Ordering::Relaxed),
        control_connections_total: state
            .metrics
            .control_connections_total
            .load(Ordering::Relaxed),
        control_protocol_errors_total: state
            .metrics
            .control_protocol_errors_total
            .load(Ordering::Relaxed),
        tls_handshake_failures_total: state
            .metrics
            .tls_handshake_failures_total
            .load(Ordering::Relaxed),
        tunnel_registrations_total: state
            .metrics
            .tunnel_registrations_total
            .load(Ordering::Relaxed),
        tunnel_reconnects_total: state
            .metrics
            .tunnel_reconnects_total
            .load(Ordering::Relaxed),
        registration_rejections_total: state
            .metrics
            .registration_rejections_total
            .load(Ordering::Relaxed),
        authentication_failures_total: state
            .metrics
            .authentication_failures_total
            .load(Ordering::Relaxed),
        http_transport_capabilities: HttpTransportCapabilitiesView::default(),
        http_active_connections: http_statistics
            .values()
            .map(|statistics| statistics.active_connections.load(Ordering::Relaxed))
            .sum(),
        http_requests_total: sum_http_u64(|statistics| {
            statistics.requests_total.load(Ordering::Relaxed)
        }),
        http_failed_requests: sum_http_u64(|statistics| {
            statistics.failed_requests.load(Ordering::Relaxed)
        }),
        http_bytes_from_public: sum_http_u64(|statistics| {
            statistics.bytes_from_public.load(Ordering::Relaxed)
        }),
        http_bytes_to_public: sum_http_u64(|statistics| {
            statistics.bytes_to_public.load(Ordering::Relaxed)
        }),
        http_pairing_timeouts: sum_http_u64(|statistics| {
            statistics.pairing_timeouts.load(Ordering::Relaxed)
        }),
        http2_active_streams: sum_http_usize(|statistics| {
            statistics.http2_active_streams.load(Ordering::Relaxed)
        }),
        http2_requests_total: sum_http_u64(|statistics| {
            statistics.http2_requests_total.load(Ordering::Relaxed)
        }),
        grpc_active_streams: sum_http_usize(|statistics| {
            statistics.grpc_active_streams.load(Ordering::Relaxed)
        }),
        grpc_requests_total: sum_http_u64(|statistics| {
            statistics.grpc_requests_total.load(Ordering::Relaxed)
        }),
        grpc_trailers_total: sum_http_u64(|statistics| {
            statistics.grpc_trailers_total.load(Ordering::Relaxed)
        }),
        grpc_failures_total: sum_http_u64(|statistics| {
            statistics.grpc_failures_total.load(Ordering::Relaxed)
        }),
        grpc_cancellations_total: sum_http_u64(|statistics| {
            statistics.grpc_cancellations_total.load(Ordering::Relaxed)
        }),
        http2_backend_active_connections: sum_http_usize(|statistics| {
            statistics
                .http2_backend
                .active_connections
                .load(Ordering::Relaxed)
        }),
        http2_backend_active_streams: sum_http_usize(|statistics| {
            statistics
                .http2_backend
                .active_streams
                .load(Ordering::Relaxed)
        }),
        http2_backend_connections_total: sum_http_u64(|statistics| {
            statistics
                .http2_backend
                .connections_total
                .load(Ordering::Relaxed)
        }),
        http2_backend_reused_total: sum_http_u64(|statistics| {
            statistics
                .http2_backend
                .reused_total
                .load(Ordering::Relaxed)
        }),
        http2_backend_reconnects_total: sum_http_u64(|statistics| {
            statistics
                .http2_backend
                .reconnects_total
                .load(Ordering::Relaxed)
        }),
        http2_backend_goaway_total: sum_http_u64(|statistics| {
            statistics
                .http2_backend
                .goaway_total
                .load(Ordering::Relaxed)
        }),
        http2_backend_failures_total: sum_http_u64(|statistics| {
            statistics
                .http2_backend
                .failures_total
                .load(Ordering::Relaxed)
        }),
        http2_backend_pool_exhausted_total: sum_http_u64(|statistics| {
            statistics
                .http2_backend
                .pool_exhausted_total
                .load(Ordering::Relaxed)
        }),
        https_active_connections: state
            .metrics
            .https_active_connections
            .load(Ordering::Relaxed),
        https_requests_total: state.metrics.https_requests_total.load(Ordering::Relaxed),
        https_handshake_failures_total: state
            .metrics
            .https_handshake_failures_total
            .load(Ordering::Relaxed),
        certificates_managed: certificate_states.len(),
        certificates_active: state
            .certificate_manager
            .as_ref()
            .map_or(0, CertificateManager::certificate_count),
        certificates_expiring_30d,
        certificates_expired,
        certificate_nearest_expiry_unix_seconds,
        acme_orders_total: state.metrics.acme_orders_total.load(Ordering::Relaxed),
        acme_orders_failed_total: state
            .metrics
            .acme_orders_failed_total
            .load(Ordering::Relaxed),
        acme_renewals_total: state.metrics.acme_renewals_total.load(Ordering::Relaxed),
        acme_renewal_failures_total: state
            .metrics
            .acme_renewal_failures_total
            .load(Ordering::Relaxed),
        acme_http01_challenges_total: state
            .metrics
            .acme_http01_challenges_total
            .load(Ordering::Relaxed),
    }))
}

async fn prometheus_metrics(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let Json(metrics) = metrics(State(state), headers).await?;
    let value = serde_json::to_value(metrics).map_err(|_| {
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not encode Prometheus metrics",
        )
    })?;
    let output = render_prometheus_metrics(&value);
    Ok((
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        output,
    )
        .into_response())
}

fn render_prometheus_metrics(value: &serde_json::Value) -> String {
    let mut output = String::new();
    if let Some(fields) = value.as_object() {
        for (name, value) in fields {
            if !value.is_number() {
                continue;
            }
            let metric = format!("linklake_{}", name.replace('-', "_"));
            // 保留 JSON 数字的原始十进制表示，避免大流量计数转换为 f64 后丢失精度。
            let _ = writeln!(output, "# TYPE {metric} gauge");
            let _ = writeln!(output, "{metric} {value}");
        }
    }
    output
}

async fn metrics_history(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<MetricsHistoryQuery>,
) -> Result<Json<MetricsHistoryResponse>, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    let (range_name, range_seconds, default_step_seconds) =
        parse_metrics_history_range(query.range.as_deref()).ok_or(CodedApiError(
            StatusCode::BAD_REQUEST,
            "invalid_metrics_range",
            "metrics history range must be one of 1h, 12h, 1d, 7d, or 30d",
        ))?;
    let sample_interval_seconds = if range_seconds <= METRICS_HISTORY_RECENT_RETENTION_SECONDS {
        METRICS_HISTORY_SAMPLE_INTERVAL_SECONDS
    } else {
        METRICS_HISTORY_ARCHIVE_SAMPLE_INTERVAL_SECONDS
    };
    let step_seconds = normalize_metrics_history_step(
        query.step,
        range_seconds,
        default_step_seconds,
        sample_interval_seconds,
    )
    .ok_or(CodedApiError(
        StatusCode::BAD_REQUEST,
        "invalid_metrics_step",
        "metrics history step must be between the sample interval and selected range",
    ))?;
    let protocol = query.protocol.unwrap_or_default();
    let response = build_metrics_history_response(
        &state
            .metrics_history
            .lock()
            .expect("metrics history lock poisoned"),
        unix_seconds(),
        range_name,
        range_seconds,
        step_seconds,
        protocol,
    );
    Ok(Json(response))
}

async fn export_metrics_history(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<MetricsExportQuery>,
) -> Result<Response, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    let (range_name, range_seconds, default_step_seconds) =
        parse_metrics_history_range(query.range.as_deref()).ok_or(CodedApiError(
            StatusCode::BAD_REQUEST,
            "invalid_metrics_range",
            "metrics history range must be one of 1h, 12h, 1d, 7d, or 30d",
        ))?;
    let sample_interval_seconds = if range_seconds <= METRICS_HISTORY_RECENT_RETENTION_SECONDS {
        METRICS_HISTORY_SAMPLE_INTERVAL_SECONDS
    } else {
        METRICS_HISTORY_ARCHIVE_SAMPLE_INTERVAL_SECONDS
    };
    let step_seconds = normalize_metrics_history_step(
        query.step,
        range_seconds,
        default_step_seconds,
        sample_interval_seconds,
    )
    .ok_or(CodedApiError(
        StatusCode::BAD_REQUEST,
        "invalid_metrics_step",
        "metrics history step must be between the sample interval and selected range",
    ))?;
    let response = build_metrics_history_response(
        &state
            .metrics_history
            .lock()
            .expect("metrics history lock poisoned"),
        unix_seconds(),
        range_name,
        range_seconds,
        step_seconds,
        query.protocol.unwrap_or_default(),
    );
    let format = query.format.as_deref().unwrap_or("csv");
    if format == "json" {
        let body = serde_json::to_string_pretty(&response).map_err(|_| {
            CodedApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "export_failed",
                "could not serialize metrics export",
            )
        })?;
        return Ok(download_response(
            body,
            "application/json; charset=utf-8",
            &format!("linklake-metrics-{range_name}.json"),
        ));
    }
    if format != "csv" {
        return Err(CodedApiError(
            StatusCode::BAD_REQUEST,
            "invalid_export_format",
            "export format must be csv or json",
        ));
    }
    let mut body = String::from("timestamp_unix_seconds,inbound_bps,outbound_bps,active_connections,active_sessions,requests_per_second,errors_per_second,requests_total,errors_total\n");
    for point in response.points {
        body.push_str(&format!(
            "{},{:.6},{:.6},{},{},{:.6},{:.6},{},{}\n",
            point.timestamp_unix_seconds,
            point.inbound_bps,
            point.outbound_bps,
            point.active_connections,
            point.active_sessions,
            point.requests_per_second,
            point.errors_per_second,
            point.requests_total,
            point.errors_total,
        ));
    }
    Ok(download_response(
        body,
        "text/csv; charset=utf-8",
        &format!("linklake-metrics-{range_name}.csv"),
    ))
}

async fn policy_metrics_history(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((kind, policy_id)): Path<(String, Uuid)>,
    Query(query): Query<MetricsHistoryQuery>,
) -> Result<Json<PolicyMetricsHistoryResponse>, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    let (kind, key) = policy_history_key(&kind, policy_id).ok_or(CodedApiError(
        StatusCode::BAD_REQUEST,
        "invalid_policy_kind",
        "policy kind must be tcp, udp, port_group, http, sni, secret, socks5, or http_proxy",
    ))?;
    let (range_name, range_seconds, default_step_seconds) =
        parse_metrics_history_range(query.range.as_deref()).ok_or(CodedApiError(
            StatusCode::BAD_REQUEST,
            "invalid_metrics_range",
            "metrics history range must be one of 1h, 12h, 1d, 7d, or 30d",
        ))?;
    let sample_interval_seconds = if range_seconds <= METRICS_HISTORY_RECENT_RETENTION_SECONDS {
        METRICS_HISTORY_SAMPLE_INTERVAL_SECONDS
    } else {
        METRICS_HISTORY_ARCHIVE_SAMPLE_INTERVAL_SECONDS
    };
    let step_seconds = normalize_metrics_history_step(
        query.step,
        range_seconds,
        default_step_seconds,
        sample_interval_seconds,
    )
    .ok_or(CodedApiError(
        StatusCode::BAD_REQUEST,
        "invalid_metrics_step",
        "metrics history step must be between the sample interval and selected range",
    ))?;
    let history = state
        .metrics_history
        .lock()
        .expect("metrics history lock poisoned");
    let (sample_interval_seconds, series_started_unix_seconds, points) =
        build_metrics_history_points(
            &history,
            unix_seconds(),
            range_seconds,
            step_seconds,
            |sample| sample.policies.get(&key).copied(),
        );
    Ok(Json(PolicyMetricsHistoryResponse {
        kind: kind.to_owned(),
        policy_id,
        range: range_name,
        sample_interval_seconds,
        step_seconds,
        retention_seconds: METRICS_HISTORY_RETENTION_SECONDS,
        series_started_unix_seconds,
        from_unix_seconds: unix_seconds().saturating_sub(range_seconds),
        to_unix_seconds: unix_seconds(),
        points,
    }))
}

fn policy_history_key(kind: &str, policy_id: Uuid) -> Option<(&'static str, String)> {
    let canonical = match kind.trim().to_ascii_lowercase().as_str() {
        "tcp" => "tcp",
        "udp" => "udp",
        "port_group" | "port-group" | "group" => "port_group",
        "http" | "https" => "http",
        "sni" | "tls_sni" | "tls-sni" => "sni",
        "secret" => "secret",
        "socks5" => "socks5",
        "http_proxy" | "http-proxy" | "proxy" => "http_proxy",
        _ => return None,
    };
    Some((canonical, format!("{canonical}:{policy_id}")))
}

fn parse_metrics_history_range(value: Option<&str>) -> Option<(&'static str, u64, u64)> {
    match value.unwrap_or("1h") {
        "1h" => Some(("1h", 60 * 60, 15)),
        "12h" => Some(("12h", 12 * 60 * 60, 150)),
        "1d" => Some(("1d", 24 * 60 * 60, 300)),
        "7d" => Some(("7d", 7 * 24 * 60 * 60, 2_100)),
        "30d" => Some(("30d", 30 * 24 * 60 * 60, 9_000)),
        _ => None,
    }
}

fn normalize_metrics_history_step(
    requested: Option<u64>,
    range_seconds: u64,
    default_step_seconds: u64,
    sample_interval_seconds: u64,
) -> Option<u64> {
    let requested = requested.unwrap_or(default_step_seconds);
    if requested == 0 || requested > range_seconds {
        return None;
    }
    let minimum_for_payload = range_seconds
        .div_ceil(METRICS_HISTORY_DEFAULT_MAX_POINTS)
        .max(sample_interval_seconds);
    let step = requested
        .max(minimum_for_payload)
        .max(sample_interval_seconds);
    Some(step.div_ceil(sample_interval_seconds) * sample_interval_seconds)
}

fn build_metrics_history_response(
    history: &MetricsHistory,
    now: u64,
    range_name: &'static str,
    range_seconds: u64,
    step_seconds: u64,
    protocol: MetricsHistoryProtocol,
) -> MetricsHistoryResponse {
    let from = now.saturating_sub(range_seconds);
    let (sample_interval_seconds, series_started_unix_seconds, points) =
        build_metrics_history_points(history, now, range_seconds, step_seconds, |sample| {
            Some(sample.counters(protocol))
        });
    MetricsHistoryResponse {
        protocol,
        range: range_name,
        sample_interval_seconds,
        step_seconds,
        retention_seconds: METRICS_HISTORY_RETENTION_SECONDS,
        series_started_unix_seconds,
        from_unix_seconds: from,
        to_unix_seconds: now,
        points,
    }
}

fn build_metrics_history_points<F>(
    history: &MetricsHistory,
    now: u64,
    range_seconds: u64,
    step_seconds: u64,
    mut select: F,
) -> (u64, Option<u64>, Vec<MetricsHistoryPoint>)
where
    F: FnMut(&MetricsHistorySample) -> Option<HistoryCounters>,
{
    let (tier, sample_interval_seconds) = history.tier(range_seconds);
    let minimum_step = range_seconds
        .div_ceil(METRICS_HISTORY_DEFAULT_MAX_POINTS)
        .max(sample_interval_seconds);
    let step_seconds = step_seconds
        .max(minimum_step)
        .div_ceil(sample_interval_seconds)
        * sample_interval_seconds;
    let from = now.saturating_sub(range_seconds);
    let selected = tier
        .iter()
        .filter_map(|sample| {
            select(sample).map(|counters| (sample.timestamp_unix_seconds, counters))
        })
        .collect::<Vec<_>>();
    let series_started_unix_seconds = selected.first().map(|sample| sample.0);
    let mut points = Vec::new();
    let mut samples = selected.iter().peekable();
    let mut previous = None;
    while samples.peek().is_some_and(|sample| sample.0 <= from) {
        previous = samples.next().copied();
    }
    let mut bucket_start = from;
    while bucket_start < now {
        let bucket_end = bucket_start.saturating_add(step_seconds).min(now);
        let mut first = None;
        let mut last = None;
        let mut count = 0_u128;
        let mut active_connections = 0_u128;
        let mut active_sessions = 0_u128;
        while samples.peek().is_some_and(|sample| sample.0 <= bucket_end) {
            let sample = *samples.next().expect("peeked metrics history sample");
            first.get_or_insert(sample);
            last = Some(sample);
            count += 1;
            active_connections += sample.1.active_connections as u128;
            active_sessions += sample.1.active_sessions as u128;
        }
        if let Some(last) = last {
            let base = previous
                .or(first)
                .expect("history bucket has a base sample");
            let elapsed = last.0.saturating_sub(base.0);
            let divisor = elapsed.max(1) as f64;
            points.push(MetricsHistoryPoint {
                timestamp_unix_seconds: last.0,
                inbound_bps: last
                    .1
                    .bytes_from_public
                    .saturating_sub(base.1.bytes_from_public) as f64
                    / divisor,
                outbound_bps: last
                    .1
                    .bytes_to_public
                    .saturating_sub(base.1.bytes_to_public) as f64
                    / divisor,
                active_connections: (active_connections / count) as u64,
                active_sessions: (active_sessions / count) as u64,
                requests_per_second: last.1.requests_total.saturating_sub(base.1.requests_total)
                    as f64
                    / divisor,
                errors_per_second: last.1.errors_total.saturating_sub(base.1.errors_total) as f64
                    / divisor,
                requests_total: last.1.requests_total,
                errors_total: last.1.errors_total,
            });
            previous = Some(last);
        }
        bucket_start = bucket_end;
    }
    debug_assert!(points.len() <= METRICS_HISTORY_DEFAULT_MAX_POINTS as usize);
    (sample_interval_seconds, series_started_unix_seconds, points)
}

fn record_metrics_history_sample(state: &AppState) {
    let sample = collect_metrics_history_sample(state, unix_seconds());
    state
        .metrics_history
        .lock()
        .expect("metrics history lock poisoned")
        .push(sample);
}

async fn run_metrics_history_sampler(state: Arc<AppState>, mut shutdown: watch::Receiver<bool>) {
    let start =
        tokio::time::Instant::now() + Duration::from_secs(METRICS_HISTORY_SAMPLE_INTERVAL_SECONDS);
    let mut interval = tokio::time::interval_at(
        start,
        Duration::from_secs(METRICS_HISTORY_SAMPLE_INTERVAL_SECONDS),
    );
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            _ = interval.tick() => record_metrics_history_sample(&state),
        }
    }
}

async fn run_alert_evaluator(state: Arc<AppState>, mut shutdown: watch::Receiver<bool>) {
    let start = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut interval = tokio::time::interval_at(
        start,
        Duration::from_secs(ALERT_EVALUATION_INTERVAL_SECONDS),
    );
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            _ = interval.tick() => evaluate_alerts(&state).await,
        }
    }
}

async fn evaluate_alerts(state: &Arc<AppState>) {
    let rules = match state
        .alerts
        .lock()
        .expect("alert catalog lock poisoned")
        .list_rules()
    {
        Ok(rules) => rules,
        Err(error) => {
            tracing::error!("Could not read alert rules: {error}");
            return;
        }
    };
    let signals = collect_alert_signals(state, &rules);
    let notifications = match state
        .alerts
        .lock()
        .expect("alert catalog lock poisoned")
        .evaluate(&signals, unix_seconds())
    {
        Ok(notifications) => notifications,
        Err(error) => {
            tracing::error!("Could not evaluate alerts: {error}");
            return;
        }
    };
    for notification in notifications {
        let action = if notification.resolved {
            "alert.resolved"
        } else {
            "alert.triggered"
        };
        record_audit(
            state,
            action,
            &notification.event.subject,
            &format!(
                "rule={}; severity={:?}; value={}; threshold={}; {}",
                notification.event.rule_name,
                notification.event.severity,
                notification.event.value,
                notification.event.threshold,
                notification.event.message
            ),
        );
        dispatch_alert_notification(notification).await;
    }
}

fn collect_alert_signals(state: &AppState, rules: &[AlertRule]) -> Vec<AlertSignal> {
    let now = unix_seconds();
    let mut signals = Vec::new();
    for client in state
        .clients
        .lock()
        .expect("client registry lock poisoned")
        .summaries()
        .into_iter()
        .filter(|client| client.enabled && now.saturating_sub(client.last_seen_unix_seconds) > 120)
    {
        let age = now.saturating_sub(client.last_seen_unix_seconds);
        signals.push(AlertSignal {
            metric: AlertMetric::ClientOffline,
            subject: client.client_id.to_string(),
            value: 1.0,
            message: format!("client {} has been offline for {age} seconds", client.name),
            window_seconds: None,
        });
    }
    collect_unavailable_policy_signals(state, &mut signals);

    let history = state
        .metrics_history
        .lock()
        .expect("metrics history lock poisoned");
    if let Some(current) = history.samples.back() {
        let total = current.counters(MetricsHistoryProtocol::Total);
        signals.push(AlertSignal {
            metric: AlertMetric::ActiveConnections,
            subject: "global".to_owned(),
            value: total
                .active_connections
                .saturating_add(total.active_sessions) as f64,
            message: format!(
                "{} active connections and sessions",
                total
                    .active_connections
                    .saturating_add(total.active_sessions)
            ),
            window_seconds: None,
        });
        let windows = rules
            .iter()
            .filter(|rule| {
                matches!(
                    rule.metric,
                    AlertMetric::AuthenticationFailures | AlertMetric::TrafficBytesPerSecond
                )
            })
            .map(|rule| rule.evaluation_window_seconds)
            .collect::<HashSet<_>>();
        for window in windows {
            let target = current.timestamp_unix_seconds.saturating_sub(window);
            let baseline = history
                .samples
                .iter()
                .rev()
                .find(|sample| sample.timestamp_unix_seconds <= target)
                .or_else(|| history.samples.front());
            if let Some(baseline) = baseline {
                let elapsed = current
                    .timestamp_unix_seconds
                    .saturating_sub(baseline.timestamp_unix_seconds)
                    .max(1);
                let authentication_failures = current
                    .authentication_failures_total
                    .saturating_sub(baseline.authentication_failures_total);
                signals.push(AlertSignal {
                    metric: AlertMetric::AuthenticationFailures,
                    subject: "global".to_owned(),
                    value: authentication_failures as f64,
                    message: format!(
                        "{authentication_failures} authentication failures in {elapsed} seconds"
                    ),
                    window_seconds: Some(window),
                });
                let base = baseline.counters(MetricsHistoryProtocol::Total);
                let bytes = total
                    .bytes_from_public
                    .saturating_add(total.bytes_to_public)
                    .saturating_sub(base.bytes_from_public.saturating_add(base.bytes_to_public));
                let rate = bytes as f64 / elapsed as f64;
                signals.push(AlertSignal {
                    metric: AlertMetric::TrafficBytesPerSecond,
                    subject: "global".to_owned(),
                    value: rate,
                    message: format!("{rate:.2} bytes per second over {elapsed} seconds"),
                    window_seconds: Some(window),
                });
            }
        }
    }
    drop(history);

    let route_names = state
        .http_route_catalog
        .lock()
        .expect("HTTP route catalog lock poisoned")
        .list()
        .unwrap_or_default()
        .into_iter()
        .map(|route| (route.id, route.hostname))
        .collect::<HashMap<_, _>>();
    if let Ok(certificates) = state
        .certificate_catalog
        .lock()
        .expect("certificate catalog lock poisoned")
        .list_certificate_states()
    {
        for certificate in certificates {
            if let Some(not_after) = certificate.not_after {
                let remaining_seconds = not_after.saturating_sub(now as i64);
                let days = remaining_seconds as f64 / 86_400.0;
                let subject = route_names
                    .get(&certificate.route_id)
                    .cloned()
                    .unwrap_or_else(|| certificate.route_id.to_string());
                signals.push(AlertSignal {
                    metric: AlertMetric::CertificateDaysRemaining,
                    subject,
                    value: days,
                    message: format!("certificate has {days:.1} days remaining"),
                    window_seconds: None,
                });
            }
        }
    }
    signals
}

fn collect_unavailable_policy_signals(state: &AppState, signals: &mut Vec<AlertSignal>) {
    let online_tcp = state
        .tunnels
        .lock()
        .expect("tunnel registry lock poisoned")
        .keys()
        .copied()
        .collect::<HashSet<_>>();
    let online_udp = state
        .udp_tunnels
        .lock()
        .expect("UDP tunnel registry lock poisoned")
        .iter()
        .map(|(port, registration)| (*port, registration.policy_id))
        .collect::<HashMap<_, _>>();
    let (tcp, udp, groups) = {
        let catalog = state
            .tunnel_catalog
            .lock()
            .expect("tunnel catalog lock poisoned");
        let tcp = catalog.list().unwrap_or_default();
        let udp = catalog.list_udp().unwrap_or_default();
        let groups = catalog
            .list_port_groups()
            .unwrap_or_default()
            .into_iter()
            .map(|policy| {
                let mappings = catalog.port_group_mappings(policy.id).unwrap_or_default();
                (policy, mappings)
            })
            .collect::<Vec<_>>();
        (tcp, udp, groups)
    };
    for policy in tcp
        .into_iter()
        .filter(|policy| policy.enabled && !online_tcp.contains(&policy.public_port))
    {
        push_policy_unavailable(signals, "tcp", policy.id, &policy.name, 1.0);
    }
    for policy in udp.into_iter().filter(|policy| {
        policy.enabled
            && online_udp
                .get(&policy.public_port)
                .is_none_or(|id| id != &policy.id)
    }) {
        push_policy_unavailable(signals, "udp", policy.id, &policy.name, 1.0);
    }
    for (policy, mappings) in groups.into_iter().filter(|(policy, _)| policy.enabled) {
        let missing = match policy.protocol {
            PortGroupProtocol::Tcp => mappings
                .iter()
                .filter(|mapping| !online_tcp.contains(&mapping.public_port))
                .count(),
            PortGroupProtocol::Udp => mappings
                .iter()
                .filter(|mapping| {
                    online_udp
                        .get(&mapping.public_port)
                        .is_none_or(|id| id != &policy.id)
                })
                .count(),
        };
        if missing > 0 {
            push_policy_unavailable(
                signals,
                "port_group",
                policy.id,
                &policy.name,
                missing as f64,
            );
        }
    }

    let online_http = state
        .http_routes
        .lock()
        .expect("HTTP route registry lock poisoned")
        .keys()
        .cloned()
        .collect::<HashSet<_>>();
    for policy in state
        .http_route_catalog
        .lock()
        .expect("HTTP route catalog lock poisoned")
        .list()
        .unwrap_or_default()
        .into_iter()
        .filter(|policy| policy.enabled && !online_http.contains(&policy.hostname))
    {
        push_policy_unavailable(signals, "http", policy.id, &policy.name, 1.0);
    }
    let online_sni = state
        .sni_routes
        .lock()
        .expect("SNI route registry lock poisoned")
        .keys()
        .cloned()
        .collect::<HashSet<_>>();
    for policy in state
        .sni_route_catalog
        .lock()
        .expect("SNI route catalog lock poisoned")
        .list()
        .unwrap_or_default()
        .into_iter()
        .filter(|policy| policy.enabled && !online_sni.contains(&policy.hostname))
    {
        push_policy_unavailable(signals, "sni", policy.id, &policy.name, 1.0);
    }
    let online_secret = state
        .secret_tunnels
        .lock()
        .expect("secret tunnel registry lock poisoned")
        .keys()
        .copied()
        .collect::<HashSet<_>>();
    for policy in state
        .secret_tunnel_catalog
        .lock()
        .expect("secret tunnel catalog lock poisoned")
        .list()
        .unwrap_or_default()
        .into_iter()
        .filter(|policy| policy.enabled && !online_secret.contains(&policy.id))
    {
        push_policy_unavailable(signals, "secret", policy.id, &policy.name, 1.0);
    }
    let online_socks5 = state
        .socks5_proxies
        .lock()
        .expect("SOCKS5 proxy registry lock poisoned")
        .keys()
        .copied()
        .collect::<HashSet<_>>();
    let online_http_proxy = state
        .http_proxies
        .lock()
        .expect("HTTP proxy registry lock poisoned")
        .keys()
        .copied()
        .collect::<HashSet<_>>();
    let catalog = state
        .tunnel_catalog
        .lock()
        .expect("tunnel catalog lock poisoned");
    for policy in catalog
        .list_socks5()
        .unwrap_or_default()
        .into_iter()
        .filter(|policy| policy.enabled && !online_socks5.contains(&policy.id))
    {
        push_policy_unavailable(signals, "socks5", policy.id, &policy.name, 1.0);
    }
    for policy in catalog
        .list_http_proxies()
        .unwrap_or_default()
        .into_iter()
        .filter(|policy| policy.enabled && !online_http_proxy.contains(&policy.id))
    {
        push_policy_unavailable(signals, "http_proxy", policy.id, &policy.name, 1.0);
    }
}

fn push_policy_unavailable(
    signals: &mut Vec<AlertSignal>,
    kind: &str,
    id: Uuid,
    name: &str,
    value: f64,
) {
    signals.push(AlertSignal {
        metric: AlertMetric::PolicyUnavailable,
        subject: format!("{kind}:{id}"),
        value,
        message: format!("policy {name} is unavailable ({value:.0} missing endpoints)"),
        window_seconds: None,
    });
}

async fn dispatch_alert_notification(notification: AlertNotification) {
    notifications::dispatch(notification).await;
}

fn collect_metrics_history_sample(
    state: &AppState,
    timestamp_unix_seconds: u64,
) -> MetricsHistorySample {
    let tcp_tunnels = {
        let statistics = state
            .tunnel_statistics
            .lock()
            .expect("tunnel statistics lock poisoned");
        HistoryCounters {
            bytes_from_public: statistics
                .values()
                .map(|value| value.bytes_from_public.load(Ordering::Relaxed))
                .sum(),
            bytes_to_public: statistics
                .values()
                .map(|value| value.bytes_to_public.load(Ordering::Relaxed))
                .sum(),
            active_connections: statistics
                .values()
                .map(|value| value.active_connections.load(Ordering::Relaxed) as u64)
                .sum(),
            errors_total: statistics
                .values()
                .map(|value| tcp_history_error_total(value))
                .sum(),
            ..HistoryCounters::default()
        }
    };
    let secret_tunnels = {
        let statistics = state
            .secret_tunnel_statistics
            .lock()
            .expect("secret tunnel statistics lock poisoned");
        HistoryCounters {
            bytes_from_public: statistics
                .values()
                .map(|value| value.bytes_from_visitor.load(Ordering::Relaxed))
                .sum(),
            bytes_to_public: statistics
                .values()
                .map(|value| value.bytes_to_visitor.load(Ordering::Relaxed))
                .sum(),
            active_connections: statistics
                .values()
                .map(|value| value.active_connections.load(Ordering::Relaxed) as u64)
                .sum(),
            requests_total: statistics
                .values()
                .map(|value| value.connections_total.load(Ordering::Relaxed))
                .sum(),
            errors_total: statistics
                .values()
                .map(|value| {
                    value
                        .rejected_connections
                        .load(Ordering::Relaxed)
                        .saturating_add(value.pairing_timeouts.load(Ordering::Relaxed))
                        .saturating_add(value.transfer_errors.load(Ordering::Relaxed))
                        .saturating_add(value.lifetime_timeouts.load(Ordering::Relaxed))
                })
                .sum(),
            ..HistoryCounters::default()
        }
    };
    let tcp = tcp_tunnels;
    let secret = secret_tunnels;

    let udp = {
        let statistics = state
            .udp_tunnel_statistics
            .lock()
            .expect("UDP tunnel statistics lock poisoned");
        let mut totals = udp_tunnel::UdpTunnelStatisticsSnapshot::default();
        for value in statistics.values() {
            totals.add_assign(value.snapshot());
        }
        HistoryCounters {
            bytes_from_public: totals.bytes_from_public,
            bytes_to_public: totals.bytes_to_public,
            active_sessions: totals.active_sessions as u64,
            requests_total: totals.packets_from_public,
            // dropped_packets 已包含各类 dropped_* 原因计数，这里只加互不重叠的超时和传输错误。
            errors_total: udp_history_error_total(&totals),
            ..HistoryCounters::default()
        }
    };

    let http = {
        let statistics = state
            .http_route_statistics
            .lock()
            .expect("HTTP route statistics lock poisoned");
        HistoryCounters {
            bytes_from_public: statistics
                .values()
                .map(|value| value.bytes_from_public.load(Ordering::Relaxed))
                .sum(),
            bytes_to_public: statistics
                .values()
                .map(|value| value.bytes_to_public.load(Ordering::Relaxed))
                .sum(),
            active_connections: statistics
                .values()
                .map(|value| value.active_connections.load(Ordering::Relaxed) as u64)
                .sum(),
            requests_total: statistics
                .values()
                .map(|value| value.requests_total.load(Ordering::Relaxed))
                .sum(),
            errors_total: statistics
                .values()
                .map(|value| value.failed_requests.load(Ordering::Relaxed))
                .sum(),
            ..HistoryCounters::default()
        }
    };
    let sni = {
        let statistics = state
            .sni_route_statistics
            .lock()
            .expect("SNI route statistics lock poisoned");
        HistoryCounters {
            bytes_from_public: statistics
                .values()
                .map(|value| value.bytes_from_public.load(Ordering::Relaxed))
                .sum(),
            bytes_to_public: statistics
                .values()
                .map(|value| value.bytes_to_public.load(Ordering::Relaxed))
                .sum(),
            active_connections: statistics
                .values()
                .map(|value| value.active_connections.load(Ordering::Relaxed) as u64)
                .sum(),
            requests_total: statistics
                .values()
                .map(|value| value.connections_total.load(Ordering::Relaxed))
                .sum(),
            errors_total: statistics
                .values()
                .map(|value| {
                    value
                        .rejected_connections
                        .load(Ordering::Relaxed)
                        .saturating_add(value.client_hello_errors.load(Ordering::Relaxed))
                        .saturating_add(value.unknown_sni.load(Ordering::Relaxed))
                        .saturating_add(value.transfer_errors.load(Ordering::Relaxed))
                })
                .sum::<u64>()
                .saturating_add(
                    state
                        .metrics
                        .https_handshake_failures_total
                        .load(Ordering::Relaxed),
                ),
            ..HistoryCounters::default()
        }
    };
    let web = http.saturating_add(sni);

    let socks5 = {
        let statistics = state
            .socks5_proxy_statistics
            .lock()
            .expect("SOCKS5 statistics lock poisoned");
        HistoryCounters {
            bytes_from_public: statistics
                .values()
                .map(|value| {
                    value
                        .bytes_from_public
                        .load(Ordering::Relaxed)
                        .saturating_add(value.udp_bytes_from_public.load(Ordering::Relaxed))
                })
                .sum(),
            bytes_to_public: statistics
                .values()
                .map(|value| {
                    value
                        .bytes_to_public
                        .load(Ordering::Relaxed)
                        .saturating_add(value.udp_bytes_to_public.load(Ordering::Relaxed))
                })
                .sum(),
            active_connections: statistics
                .values()
                .map(|value| value.active_connections.load(Ordering::Relaxed) as u64)
                .sum(),
            active_sessions: statistics
                .values()
                .map(|value| value.udp_active_associations.load(Ordering::Relaxed) as u64)
                .sum(),
            requests_total: statistics
                .values()
                .map(|value| {
                    value
                        .requests_total
                        .load(Ordering::Relaxed)
                        .saturating_add(value.udp_datagrams_from_public.load(Ordering::Relaxed))
                })
                .sum(),
            errors_total: statistics
                .values()
                .map(|value| {
                    value
                        .authentication_failures
                        .load(Ordering::Relaxed)
                        .saturating_add(value.rejected_connections.load(Ordering::Relaxed))
                        .saturating_add(value.handshake_errors.load(Ordering::Relaxed))
                        .saturating_add(value.connect_failures.load(Ordering::Relaxed))
                        .saturating_add(value.transfer_errors.load(Ordering::Relaxed))
                        .saturating_add(value.udp_dropped_datagrams.load(Ordering::Relaxed))
                })
                .sum(),
        }
    };
    let http_proxy = {
        let statistics = state
            .http_proxy_statistics
            .lock()
            .expect("HTTP proxy statistics lock poisoned");
        HistoryCounters {
            bytes_from_public: statistics
                .values()
                .map(|value| value.bytes_from_public.load(Ordering::Relaxed))
                .sum(),
            bytes_to_public: statistics
                .values()
                .map(|value| value.bytes_to_public.load(Ordering::Relaxed))
                .sum(),
            active_connections: statistics
                .values()
                .map(|value| value.active_connections.load(Ordering::Relaxed) as u64)
                .sum(),
            requests_total: statistics
                .values()
                .map(|value| value.requests_total.load(Ordering::Relaxed))
                .sum(),
            errors_total: statistics
                .values()
                .map(|value| {
                    value
                        .authentication_failures
                        .load(Ordering::Relaxed)
                        .saturating_add(value.rejected_connections.load(Ordering::Relaxed))
                        .saturating_add(value.malformed_requests.load(Ordering::Relaxed))
                        .saturating_add(value.connect_failures.load(Ordering::Relaxed))
                        .saturating_add(value.transfer_errors.load(Ordering::Relaxed))
                })
                .sum(),
            ..HistoryCounters::default()
        }
    };
    let proxy = socks5.saturating_add(http_proxy);
    let policies = collect_policy_history_counters(state);

    MetricsHistorySample {
        timestamp_unix_seconds,
        authentication_failures_total: state
            .metrics
            .authentication_failures_total
            .load(Ordering::Relaxed),
        tcp,
        udp,
        web,
        proxy,
        secret,
        policies,
    }
}

fn collect_policy_history_counters(state: &AppState) -> HashMap<String, HistoryCounters> {
    let mut policies = HashMap::new();
    let (tcp_policies, udp_policies, port_groups) = {
        let catalog = state
            .tunnel_catalog
            .lock()
            .expect("tunnel catalog lock poisoned");
        let tcp = catalog.list().unwrap_or_else(|error| {
            tracing::warn!("Could not list TCP policies for metrics history: {error}");
            Vec::new()
        });
        let udp = catalog.list_udp().unwrap_or_else(|error| {
            tracing::warn!("Could not list UDP policies for metrics history: {error}");
            Vec::new()
        });
        let groups = catalog
            .list_port_groups()
            .unwrap_or_else(|error| {
                tracing::warn!("Could not list port groups for metrics history: {error}");
                Vec::new()
            })
            .into_iter()
            .map(|policy| {
                let mappings = catalog
                    .port_group_mappings(policy.id)
                    .unwrap_or_else(|error| {
                        tracing::warn!(
                            "Could not list mappings for port group {}: {error}",
                            policy.id
                        );
                        Vec::new()
                    });
                (policy, mappings)
            })
            .collect::<Vec<_>>();
        (tcp, udp, groups)
    };
    {
        let statistics = state
            .tunnel_statistics
            .lock()
            .expect("tunnel statistics lock poisoned");
        for policy in tcp_policies {
            let counters = statistics.get(&policy.public_port).map_or_else(
                HistoryCounters::default,
                |value| HistoryCounters {
                    bytes_from_public: value.bytes_from_public.load(Ordering::Relaxed),
                    bytes_to_public: value.bytes_to_public.load(Ordering::Relaxed),
                    active_connections: value.active_connections.load(Ordering::Relaxed) as u64,
                    errors_total: tcp_history_error_total(value),
                    ..HistoryCounters::default()
                },
            );
            policies.insert(format!("tcp:{}", policy.id), counters);
        }
        for (policy, mappings) in port_groups
            .iter()
            .filter(|(policy, _)| policy.protocol == PortGroupProtocol::Tcp)
        {
            let counters = mappings
                .iter()
                .fold(HistoryCounters::default(), |total, mapping| {
                    total.saturating_add(statistics.get(&mapping.public_port).map_or_else(
                        HistoryCounters::default,
                        |value| HistoryCounters {
                            bytes_from_public: value.bytes_from_public.load(Ordering::Relaxed),
                            bytes_to_public: value.bytes_to_public.load(Ordering::Relaxed),
                            active_connections: value.active_connections.load(Ordering::Relaxed)
                                as u64,
                            errors_total: tcp_history_error_total(value),
                            ..HistoryCounters::default()
                        },
                    ))
                });
            policies.insert(format!("port_group:{}", policy.id), counters);
        }
    }
    {
        let statistics = state
            .udp_tunnel_statistics
            .lock()
            .expect("UDP tunnel statistics lock poisoned");
        for policy in udp_policies {
            policies.insert(
                format!("udp:{}", policy.id),
                statistics
                    .get(&policy.id)
                    .map_or_else(HistoryCounters::default, |value| {
                        udp_history_counters(value.snapshot())
                    }),
            );
        }
        for (policy, _) in port_groups
            .iter()
            .filter(|(policy, _)| policy.protocol == PortGroupProtocol::Udp)
        {
            policies.insert(
                format!("port_group:{}", policy.id),
                statistics
                    .get(&policy.id)
                    .map_or_else(HistoryCounters::default, |value| {
                        udp_history_counters(value.snapshot())
                    }),
            );
        }
    }

    let http_policies = state
        .http_route_catalog
        .lock()
        .expect("HTTP route catalog lock poisoned")
        .list()
        .unwrap_or_else(|error| {
            tracing::warn!("Could not list HTTP policies for metrics history: {error}");
            Vec::new()
        });
    {
        let statistics = state
            .http_route_statistics
            .lock()
            .expect("HTTP route statistics lock poisoned");
        for policy in http_policies {
            let counters =
                statistics
                    .get(&policy.hostname)
                    .map_or_else(HistoryCounters::default, |value| HistoryCounters {
                        bytes_from_public: value.bytes_from_public.load(Ordering::Relaxed),
                        bytes_to_public: value.bytes_to_public.load(Ordering::Relaxed),
                        active_connections: value.active_connections.load(Ordering::Relaxed) as u64,
                        requests_total: value.requests_total.load(Ordering::Relaxed),
                        errors_total: value.failed_requests.load(Ordering::Relaxed),
                        ..HistoryCounters::default()
                    });
            policies.insert(format!("http:{}", policy.id), counters);
        }
    }

    let sni_policies = state
        .sni_route_catalog
        .lock()
        .expect("SNI route catalog lock poisoned")
        .list()
        .unwrap_or_else(|error| {
            tracing::warn!("Could not list SNI policies for metrics history: {error}");
            Vec::new()
        });
    {
        let statistics = state
            .sni_route_statistics
            .lock()
            .expect("SNI route statistics lock poisoned");
        for policy in sni_policies {
            let counters = statistics
                .get(&policy.hostname)
                .map_or_else(HistoryCounters::default, |value| {
                    sni_history_counters(value)
                });
            policies.insert(format!("sni:{}", policy.id), counters);
        }
    }

    let secret_policies = state
        .secret_tunnel_catalog
        .lock()
        .expect("secret tunnel catalog lock poisoned")
        .list()
        .unwrap_or_else(|error| {
            tracing::warn!("Could not list Secret policies for metrics history: {error}");
            Vec::new()
        });
    {
        let statistics = state
            .secret_tunnel_statistics
            .lock()
            .expect("secret tunnel statistics lock poisoned");
        for policy in secret_policies {
            let counters = statistics
                .get(&policy.id)
                .map_or_else(HistoryCounters::default, |value| {
                    secret_history_counters(value)
                });
            policies.insert(format!("secret:{}", policy.id), counters);
        }
    }

    let (socks5_policies, http_proxy_policies) = {
        let catalog = state
            .tunnel_catalog
            .lock()
            .expect("tunnel catalog lock poisoned");
        (
            catalog.list_socks5().unwrap_or_else(|error| {
                tracing::warn!("Could not list SOCKS5 policies for metrics history: {error}");
                Vec::new()
            }),
            catalog.list_http_proxies().unwrap_or_else(|error| {
                tracing::warn!("Could not list HTTP proxy policies for metrics history: {error}");
                Vec::new()
            }),
        )
    };
    {
        let statistics = state
            .socks5_proxy_statistics
            .lock()
            .expect("SOCKS5 statistics lock poisoned");
        for policy in socks5_policies {
            let counters = statistics
                .get(&policy.id)
                .map_or_else(HistoryCounters::default, |value| {
                    socks5_history_counters(value)
                });
            policies.insert(format!("socks5:{}", policy.id), counters);
        }
    }
    {
        let statistics = state
            .http_proxy_statistics
            .lock()
            .expect("HTTP proxy statistics lock poisoned");
        for policy in http_proxy_policies {
            let counters = statistics
                .get(&policy.id)
                .map_or_else(HistoryCounters::default, |value| {
                    http_proxy_history_counters(value)
                });
            policies.insert(format!("http_proxy:{}", policy.id), counters);
        }
    }
    policies
}

fn udp_history_counters(statistics: udp_tunnel::UdpTunnelStatisticsSnapshot) -> HistoryCounters {
    HistoryCounters {
        bytes_from_public: statistics.bytes_from_public,
        bytes_to_public: statistics.bytes_to_public,
        active_sessions: statistics.active_sessions as u64,
        requests_total: statistics.packets_from_public,
        errors_total: udp_history_error_total(&statistics),
        ..HistoryCounters::default()
    }
}

fn sni_history_counters(value: &sni_tunnel::SniRouteStatistics) -> HistoryCounters {
    HistoryCounters {
        bytes_from_public: value.bytes_from_public.load(Ordering::Relaxed),
        bytes_to_public: value.bytes_to_public.load(Ordering::Relaxed),
        active_connections: value.active_connections.load(Ordering::Relaxed) as u64,
        requests_total: value.connections_total.load(Ordering::Relaxed),
        errors_total: value
            .rejected_connections
            .load(Ordering::Relaxed)
            .saturating_add(value.client_hello_errors.load(Ordering::Relaxed))
            .saturating_add(value.unknown_sni.load(Ordering::Relaxed))
            .saturating_add(value.transfer_errors.load(Ordering::Relaxed)),
        ..HistoryCounters::default()
    }
}

fn secret_history_counters(value: &secret_tunnel::SecretTunnelStatistics) -> HistoryCounters {
    HistoryCounters {
        bytes_from_public: value.bytes_from_visitor.load(Ordering::Relaxed),
        bytes_to_public: value.bytes_to_visitor.load(Ordering::Relaxed),
        active_connections: value.active_connections.load(Ordering::Relaxed) as u64,
        requests_total: value.connections_total.load(Ordering::Relaxed),
        errors_total: value
            .rejected_connections
            .load(Ordering::Relaxed)
            .saturating_add(value.pairing_timeouts.load(Ordering::Relaxed))
            .saturating_add(value.transfer_errors.load(Ordering::Relaxed))
            .saturating_add(value.lifetime_timeouts.load(Ordering::Relaxed)),
        ..HistoryCounters::default()
    }
}

fn socks5_history_counters(value: &socks5_tunnel::Socks5ProxyStatistics) -> HistoryCounters {
    HistoryCounters {
        bytes_from_public: value
            .bytes_from_public
            .load(Ordering::Relaxed)
            .saturating_add(value.udp_bytes_from_public.load(Ordering::Relaxed)),
        bytes_to_public: value
            .bytes_to_public
            .load(Ordering::Relaxed)
            .saturating_add(value.udp_bytes_to_public.load(Ordering::Relaxed)),
        active_connections: value.active_connections.load(Ordering::Relaxed) as u64,
        active_sessions: value.udp_active_associations.load(Ordering::Relaxed) as u64,
        requests_total: value
            .requests_total
            .load(Ordering::Relaxed)
            .saturating_add(value.udp_datagrams_from_public.load(Ordering::Relaxed)),
        errors_total: value
            .authentication_failures
            .load(Ordering::Relaxed)
            .saturating_add(value.rejected_connections.load(Ordering::Relaxed))
            .saturating_add(value.handshake_errors.load(Ordering::Relaxed))
            .saturating_add(value.connect_failures.load(Ordering::Relaxed))
            .saturating_add(value.transfer_errors.load(Ordering::Relaxed))
            .saturating_add(value.udp_dropped_datagrams.load(Ordering::Relaxed)),
    }
}

fn http_proxy_history_counters(value: &http_proxy_tunnel::HttpProxyStatistics) -> HistoryCounters {
    HistoryCounters {
        bytes_from_public: value.bytes_from_public.load(Ordering::Relaxed),
        bytes_to_public: value.bytes_to_public.load(Ordering::Relaxed),
        active_connections: value.active_connections.load(Ordering::Relaxed) as u64,
        requests_total: value.requests_total.load(Ordering::Relaxed),
        errors_total: value
            .authentication_failures
            .load(Ordering::Relaxed)
            .saturating_add(value.rejected_connections.load(Ordering::Relaxed))
            .saturating_add(value.malformed_requests.load(Ordering::Relaxed))
            .saturating_add(value.connect_failures.load(Ordering::Relaxed))
            .saturating_add(value.transfer_errors.load(Ordering::Relaxed)),
        ..HistoryCounters::default()
    }
}

fn tcp_history_error_total(statistics: &tcp_tunnel::TunnelStatistics) -> u64 {
    // failed_connections 已包含配对、传输和生存期等失败分类，不能再叠加 breakdown。
    statistics
        .rejected_connections
        .load(Ordering::Relaxed)
        .saturating_add(statistics.failed_connections.load(Ordering::Relaxed))
}

fn udp_history_error_total(statistics: &udp_tunnel::UdpTunnelStatisticsSnapshot) -> u64 {
    // dropped_packets 已包含 dropped_oversized 等原因分类，只叠加互不重叠的错误。
    statistics
        .dropped_packets
        .saturating_add(statistics.session_timeouts)
        .saturating_add(statistics.reassembly_timeouts)
        .saturating_add(statistics.attach_timeouts)
        .saturating_add(statistics.transport_errors)
}

fn udp_metrics_response(statistics: udp_tunnel::UdpTunnelStatisticsSnapshot) -> UdpMetricsResponse {
    UdpMetricsResponse {
        udp_active_sessions: statistics.active_sessions,
        udp_packets_from_public: statistics.packets_from_public,
        udp_packets_to_public: statistics.packets_to_public,
        udp_bytes_from_public: statistics.bytes_from_public,
        udp_bytes_to_public: statistics.bytes_to_public,
        udp_dropped_packets: statistics.dropped_packets,
        udp_dropped_oversized: statistics.dropped_oversized,
        udp_dropped_malformed: statistics.dropped_malformed,
        udp_dropped_unknown_session: statistics.dropped_unknown_session,
        udp_dropped_queue_full: statistics.dropped_queue_full,
        udp_dropped_policy_session_limit: statistics.dropped_policy_limit,
        udp_dropped_global_session_limit: statistics.dropped_global_limit,
        udp_dropped_bandwidth_limit: statistics.dropped_bandwidth_limit,
        udp_session_timeouts: statistics.session_timeouts,
        udp_reassembly_timeouts: statistics.reassembly_timeouts,
        udp_attach_timeouts: statistics.attach_timeouts,
        udp_transport_errors: statistics.transport_errors,
    }
}

async fn get_acme_config(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<AcmeConfigView>, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    let config = state
        .certificate_catalog
        .lock()
        .expect("certificate catalog lock poisoned")
        .get_acme_config()
        .map_err(coded_certificate_catalog_error)?;
    Ok(Json(acme_config_view(&state, config)))
}

async fn update_acme_config(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<UpdateAcmeConfig>,
) -> Result<Json<AcmeConfigView>, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    let config = state
        .certificate_catalog
        .lock()
        .expect("certificate catalog lock poisoned")
        .update_acme_config(request, unix_seconds() as i64)
        .map_err(coded_certificate_catalog_error)?;
    record_audit(
        &state,
        "acme.config.updated",
        "global",
        &format!(
            "enabled={}; environment={:?}; renew_before_days={}",
            config.enabled, config.environment, config.renew_before_days
        ),
    );
    Ok(Json(acme_config_view(&state, config)))
}

async fn set_http_route_tls(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(route_id): Path<Uuid>,
    Json(request): Json<UpdateRouteTlsPolicy>,
) -> Result<Json<RouteTlsPolicy>, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    let route = http_route_policy_for_id(&state, route_id)?.ok_or(CodedApiError(
        StatusCode::NOT_FOUND,
        "unknown_http_route",
        "HTTP route does not exist",
    ))?;
    let certificate_jobs = state
        .certificate_jobs
        .lock()
        .expect("certificate jobs lock poisoned");
    if request.mode == RouteTlsMode::Disabled && certificate_jobs.contains_key(&route.hostname) {
        return Err(CodedApiError(
            StatusCode::CONFLICT,
            "certificate_operation_in_progress",
            "certificate operation is already in progress",
        ));
    }
    let mode = request.mode;
    let mut issue_automatically = false;
    let policy = state
        .certificate_catalog
        .lock()
        .expect("certificate catalog lock poisoned")
        .set_route_tls(route_id, request, unix_seconds() as i64)
        .map_err(coded_certificate_catalog_error)?;
    {
        let mut redirects = state
            .https_redirect_hosts
            .lock()
            .expect("HTTPS redirect registry lock poisoned");
        if route.enabled && policy.mode == RouteTlsMode::Acme && policy.redirect_http_to_https {
            redirects.insert(route.hostname.clone());
        } else {
            redirects.remove(&route.hostname);
        }
    }
    if mode == RouteTlsMode::Disabled {
        if let Some(manager) = &state.certificate_manager {
            manager.remove_certificate(&route.hostname);
        }
        set_persisted_certificate_status(&state, route_id, CertificateStatus::Disabled)?;
    } else {
        let can_restore = state
            .certificate_catalog
            .lock()
            .expect("certificate catalog lock poisoned")
            .get_certificate_state(route_id)
            .map_err(coded_certificate_catalog_error)?
            .is_some_and(|certificate| !certificate.expired_at(unix_seconds() as i64));
        let restored = route.enabled
            && can_restore
            && state
                .certificate_manager
                .as_ref()
                .is_some_and(|manager| manager.load_certificate(&route.hostname).is_ok());
        if restored {
            set_persisted_certificate_status(&state, route_id, CertificateStatus::Active)?;
        } else {
            ensure_pending_certificate_state(&state, route_id)?;
            issue_automatically = route.enabled
                && state
                    .certificate_catalog
                    .lock()
                    .expect("certificate catalog lock poisoned")
                    .get_acme_config()
                    .is_ok_and(|config| config.enabled);
        }
    }
    drop(certificate_jobs);
    record_audit(
        &state,
        "http_route.tls.updated",
        &route_id.to_string(),
        &format!(
            "hostname={}; mode={:?}; redirect={}",
            route.hostname, policy.mode, policy.redirect_http_to_https
        ),
    );
    if issue_automatically {
        let _ = queue_certificate_operation(state.clone(), route_id, CertificateOperation::Issue);
    }
    Ok(Json(policy))
}

async fn issue_http_route_certificate(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(route_id): Path<Uuid>,
) -> Result<(StatusCode, Json<CertificateOperationResponse>), CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    queue_certificate_operation(state, route_id, CertificateOperation::Issue)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(CertificateOperationResponse {
            route_id,
            operation: "issue",
            status: "issuing",
        }),
    ))
}

async fn renew_http_route_certificate(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(route_id): Path<Uuid>,
) -> Result<(StatusCode, Json<CertificateOperationResponse>), CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    queue_certificate_operation(state, route_id, CertificateOperation::Renew)?;
    Ok((
        StatusCode::ACCEPTED,
        Json(CertificateOperationResponse {
            route_id,
            operation: "renew",
            status: "renewing",
        }),
    ))
}

fn http_route_policy_for_id(
    state: &AppState,
    route_id: Uuid,
) -> Result<Option<HttpRoutePolicy>, CodedApiError> {
    state
        .http_route_catalog
        .lock()
        .expect("HTTP route catalog lock poisoned")
        .list()
        .map(|routes| routes.into_iter().find(|route| route.id == route_id))
        .map_err(|_| {
            CodedApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "could not read HTTP route",
            )
        })
}

fn ensure_pending_certificate_state(state: &AppState, route_id: Uuid) -> Result<(), CodedApiError> {
    let mut catalog = state
        .certificate_catalog
        .lock()
        .expect("certificate catalog lock poisoned");
    match catalog
        .get_certificate_state(route_id)
        .map_err(coded_certificate_catalog_error)?
    {
        None => {
            catalog
                .update_certificate_status(route_id, None, CertificateStatus::Pending, None)
                .map_err(coded_certificate_catalog_error)?;
        }
        Some(certificate)
            if matches!(
                certificate.status,
                CertificateStatus::Disabled | CertificateStatus::Expired
            ) =>
        {
            catalog
                .update_certificate_status(
                    route_id,
                    Some(certificate.status),
                    CertificateStatus::Pending,
                    None,
                )
                .map_err(coded_certificate_catalog_error)?;
        }
        Some(_) => {}
    }
    Ok(())
}

fn set_persisted_certificate_status(
    state: &AppState,
    route_id: Uuid,
    status: CertificateStatus,
) -> Result<(), CodedApiError> {
    let mut catalog = state
        .certificate_catalog
        .lock()
        .expect("certificate catalog lock poisoned");
    let current = catalog
        .get_certificate_state(route_id)
        .map_err(coded_certificate_catalog_error)?;
    match current {
        Some(current) => {
            catalog
                .update_certificate_status(route_id, Some(current.status), status, None)
                .map_err(coded_certificate_catalog_error)?;
        }
        None => {
            catalog
                .update_certificate_status(route_id, None, status, None)
                .map_err(coded_certificate_catalog_error)?;
        }
    }
    Ok(())
}

fn mark_certificate_operation_status(
    state: &AppState,
    route_id: Uuid,
    status: CertificateStatus,
) -> Result<(), CodedApiError> {
    let mut catalog = state
        .certificate_catalog
        .lock()
        .expect("certificate catalog lock poisoned");
    let current = catalog
        .get_certificate_state(route_id)
        .map_err(coded_certificate_catalog_error)?;
    match current {
        Some(current) => {
            catalog
                .update_certificate_status(
                    route_id,
                    Some(current.status),
                    status,
                    Some(unix_seconds() as i64),
                )
                .map_err(coded_certificate_catalog_error)?;
        }
        None => {
            catalog
                .update_certificate_status(route_id, None, status, Some(unix_seconds() as i64))
                .map_err(coded_certificate_catalog_error)?;
        }
    }
    Ok(())
}

fn queue_certificate_operation(
    state: Arc<AppState>,
    route_id: Uuid,
    operation: CertificateOperation,
) -> Result<(), CodedApiError> {
    let route = http_route_policy_for_id(&state, route_id)?.ok_or(CodedApiError(
        StatusCode::NOT_FOUND,
        "unknown_http_route",
        "HTTP route does not exist",
    ))?;
    if !route.enabled {
        return Err(CodedApiError(
            StatusCode::CONFLICT,
            "http_route_disabled",
            "HTTP route is disabled",
        ));
    }
    let (tls_policy, certificate, acme_config) = {
        let catalog = state
            .certificate_catalog
            .lock()
            .expect("certificate catalog lock poisoned");
        (
            catalog
                .get_route_tls(route_id)
                .map_err(coded_certificate_catalog_error)?,
            catalog
                .get_certificate_state(route_id)
                .map_err(coded_certificate_catalog_error)?,
            catalog
                .get_acme_config()
                .map_err(coded_certificate_catalog_error)?,
        )
    };
    if tls_policy.as_ref().map(|policy| policy.mode) != Some(RouteTlsMode::Acme) {
        return Err(CodedApiError(
            StatusCode::CONFLICT,
            "tls_not_enabled",
            "automatic TLS is not enabled for this route",
        ));
    }
    if !acme_config.enabled {
        return Err(CodedApiError(
            StatusCode::CONFLICT,
            "acme_disabled",
            "ACME is disabled",
        ));
    }
    let Some(manager) = state.certificate_manager.clone() else {
        return Err(CodedApiError(
            StatusCode::CONFLICT,
            "certificate_storage_unavailable",
            "certificate storage is unavailable",
        ));
    };
    match operation {
        CertificateOperation::Issue
            if certificate.as_ref().is_some_and(|certificate| {
                certificate.status == CertificateStatus::Active
                    && !certificate.expired_at(unix_seconds() as i64)
            }) =>
        {
            return Err(CodedApiError(
                StatusCode::CONFLICT,
                "certificate_already_valid",
                "certificate is already valid",
            ));
        }
        CertificateOperation::Renew if !manager.has_certificate(&route.hostname) => {
            return Err(CodedApiError(
                StatusCode::CONFLICT,
                "certificate_not_available",
                "certificate is not currently available",
            ));
        }
        _ => {}
    }
    if certificate
        .as_ref()
        .and_then(|value| value.last_attempt)
        .is_some_and(|last_attempt| {
            unix_seconds() as i64
                <= last_attempt.saturating_add(certificate_operation_cooldown_seconds())
        })
    {
        return Err(CodedApiError(
            StatusCode::CONFLICT,
            "certificate_operation_cooldown",
            "certificate operation was attempted too recently",
        ));
    }
    if !reserve_certificate_job(&state, &route)? {
        return Err(CodedApiError(
            StatusCode::CONFLICT,
            "certificate_operation_in_progress",
            "certificate operation is already in progress",
        ));
    }
    let target_status = match operation {
        CertificateOperation::Issue => CertificateStatus::Issuing,
        CertificateOperation::Renew => CertificateStatus::Renewing,
    };
    if let Err(error) = mark_certificate_operation_status(&state, route_id, target_status) {
        release_certificate_job(&state, &route.hostname, route_id);
        return Err(error);
    }
    state
        .metrics
        .acme_orders_total
        .fetch_add(1, Ordering::Relaxed);
    if matches!(operation, CertificateOperation::Renew) {
        state
            .metrics
            .acme_renewals_total
            .fetch_add(1, Ordering::Relaxed);
    }
    record_audit(
        &state,
        match operation {
            CertificateOperation::Issue => "certificate.issue.started",
            CertificateOperation::Renew => "certificate.renew.started",
        },
        &route_id.to_string(),
        &format!("hostname={}", route.hostname),
    );
    tokio::spawn(run_certificate_operation(
        state,
        manager,
        route,
        acme_config,
        operation,
    ));
    Ok(())
}

fn reserve_certificate_job(
    state: &AppState,
    expected: &HttpRoutePolicy,
) -> Result<bool, CodedApiError> {
    let mut jobs = state
        .certificate_jobs
        .lock()
        .expect("certificate jobs lock poisoned");
    if jobs.contains_key(&expected.hostname) {
        return Ok(false);
    }
    let current = http_route_policy_for_id(state, expected.id)?.ok_or(CodedApiError(
        StatusCode::NOT_FOUND,
        "unknown_http_route",
        "HTTP route does not exist",
    ))?;
    if !current.enabled {
        return Err(CodedApiError(
            StatusCode::CONFLICT,
            "http_route_disabled",
            "HTTP route is disabled",
        ));
    }
    if current.hostname != expected.hostname {
        return Err(CodedApiError(
            StatusCode::CONFLICT,
            "http_route_changed",
            "HTTP route changed before certificate operation started",
        ));
    }
    let tls_policy = state
        .certificate_catalog
        .lock()
        .expect("certificate catalog lock poisoned")
        .get_route_tls(expected.id)
        .map_err(coded_certificate_catalog_error)?;
    if tls_policy.as_ref().map(|policy| policy.mode) != Some(RouteTlsMode::Acme) {
        return Err(CodedApiError(
            StatusCode::CONFLICT,
            "tls_not_enabled",
            "automatic TLS is not enabled for this route",
        ));
    }
    Ok(reserve_certificate_job_slot(
        &mut jobs,
        &expected.hostname,
        expected.id,
    ))
}

fn release_certificate_job(state: &AppState, hostname: &str, route_id: Uuid) {
    let mut jobs = state
        .certificate_jobs
        .lock()
        .expect("certificate jobs lock poisoned");
    release_certificate_job_slot(&mut jobs, hostname, route_id);
}

fn reserve_certificate_job_slot(
    jobs: &mut HashMap<String, Uuid>,
    hostname: &str,
    route_id: Uuid,
) -> bool {
    if jobs.contains_key(hostname) {
        return false;
    }
    jobs.insert(hostname.to_owned(), route_id);
    true
}

fn release_certificate_job_slot(jobs: &mut HashMap<String, Uuid>, hostname: &str, route_id: Uuid) {
    if jobs.get(hostname) == Some(&route_id) {
        jobs.remove(hostname);
    }
}

async fn run_certificate_operation(
    state: Arc<AppState>,
    manager: CertificateManager,
    route: HttpRoutePolicy,
    acme_config: AcmeConfig,
    operation: CertificateOperation,
) {
    let issue_config = certificate_manager::AcmeIssueConfig {
        directory_url: acme_config.directory_url,
        contact_email: acme_config.contact_email,
        root_ca_path: std::env::var_os("LINKLAKE_ACME_ROOT_CA_PATH").map(PathBuf::from),
    };
    let result = manager
        .issue_certificate(&route.hostname, &issue_config)
        .await;
    let now = unix_seconds() as i64;
    match result {
        Ok(result) => {
            state
                .metrics
                .acme_http01_challenges_total
                .fetch_add(result.challenges_completed, Ordering::Relaxed);
            let current = record_certificate_success_if_current(
                &state,
                &route,
                &result.metadata.issuer,
                result.metadata.not_before_unix_seconds as i64,
                result.metadata.not_after_unix_seconds as i64,
                now,
            );
            match current {
                Ok(true) => record_audit(
                    &state,
                    match operation {
                        CertificateOperation::Issue => "certificate.issue.succeeded",
                        CertificateOperation::Renew => "certificate.renew.succeeded",
                    },
                    &route.id.to_string(),
                    &format!("hostname={}", route.hostname),
                ),
                Ok(false) => discard_stale_certificate_result(&state, &manager, &route, operation),
                Err(error) => {
                    tracing::error!(
                        "could not verify or persist certificate metadata for {}: {error}",
                        route.hostname
                    );
                    discard_stale_certificate_result(&state, &manager, &route, operation);
                }
            }
        }
        Err(error) => {
            state
                .metrics
                .acme_orders_failed_total
                .fetch_add(1, Ordering::Relaxed);
            if matches!(operation, CertificateOperation::Renew) {
                state
                    .metrics
                    .acme_renewal_failures_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            let message = sanitize_certificate_error(&error.to_string());
            match record_certificate_failure_if_current(
                &state,
                &route,
                match operation {
                    CertificateOperation::Issue => "certificate_issue_failed",
                    CertificateOperation::Renew => "certificate_renew_failed",
                },
                &message,
                now,
            ) {
                Ok(true) => {
                    record_audit(
                        &state,
                        match operation {
                            CertificateOperation::Issue => "certificate.issue.failed",
                            CertificateOperation::Renew => "certificate.renew.failed",
                        },
                        &route.id.to_string(),
                        &format!("hostname={}; code=acme_operation_failed", route.hostname),
                    );
                    tracing::warn!("ACME operation failed for {}: {}", route.hostname, message);
                }
                Ok(false) => record_audit(
                    &state,
                    match operation {
                        CertificateOperation::Issue => "certificate.issue.discarded",
                        CertificateOperation::Renew => "certificate.renew.discarded",
                    },
                    &route.id.to_string(),
                    &format!("hostname={}; reason=route_state_changed", route.hostname),
                ),
                Err(store_error) => tracing::error!(
                    "could not verify or persist certificate failure for {}: {store_error}",
                    route.hostname
                ),
            }
        }
    }
    release_certificate_job(&state, &route.hostname, route.id);
}

fn certificate_target_matches(
    expected: &HttpRoutePolicy,
    current: Option<&HttpRoutePolicy>,
    tls_policy: Option<&RouteTlsPolicy>,
) -> bool {
    current.is_some_and(|current| {
        current.id == expected.id
            && current.hostname == expected.hostname
            && current.enabled
            && tls_policy.is_some_and(|policy| {
                policy.route_id == expected.id && policy.mode == RouteTlsMode::Acme
            })
    })
}

fn record_certificate_success_if_current(
    state: &AppState,
    expected: &HttpRoutePolicy,
    issuer: &str,
    not_before: i64,
    not_after: i64,
    completed_at: i64,
) -> anyhow::Result<bool> {
    let route_catalog = state
        .http_route_catalog
        .lock()
        .expect("HTTP route catalog lock poisoned");
    let routes = route_catalog.list()?;
    let current = routes.iter().find(|route| route.id == expected.id);
    let mut certificate_catalog = state
        .certificate_catalog
        .lock()
        .expect("certificate catalog lock poisoned");
    let tls_policy = certificate_catalog.get_route_tls(expected.id)?;
    if !certificate_target_matches(expected, current, tls_policy.as_ref()) {
        return Ok(false);
    }
    certificate_catalog.record_certificate_success(
        expected.id,
        issuer,
        not_before,
        not_after,
        completed_at,
    )?;
    drop(certificate_catalog);
    drop(route_catalog);
    Ok(true)
}

fn record_certificate_failure_if_current(
    state: &AppState,
    expected: &HttpRoutePolicy,
    error_code: &str,
    error_message: &str,
    attempted_at: i64,
) -> anyhow::Result<bool> {
    let route_catalog = state
        .http_route_catalog
        .lock()
        .expect("HTTP route catalog lock poisoned");
    let routes = route_catalog.list()?;
    let current = routes.iter().find(|route| route.id == expected.id);
    let mut certificate_catalog = state
        .certificate_catalog
        .lock()
        .expect("certificate catalog lock poisoned");
    let tls_policy = certificate_catalog.get_route_tls(expected.id)?;
    if !certificate_target_matches(expected, current, tls_policy.as_ref()) {
        return Ok(false);
    }
    certificate_catalog.record_certificate_failure(
        expected.id,
        error_code,
        error_message,
        attempted_at,
    )?;
    drop(certificate_catalog);
    drop(route_catalog);
    Ok(true)
}

fn discard_stale_certificate_result(
    state: &AppState,
    manager: &CertificateManager,
    route: &HttpRoutePolicy,
    operation: CertificateOperation,
) {
    if let Err(error) = manager.delete_certificate(&route.hostname) {
        tracing::warn!(
            "could not remove stale certificate result for {}: {error}",
            route.hostname
        );
    }
    record_audit(
        state,
        match operation {
            CertificateOperation::Issue => "certificate.issue.discarded",
            CertificateOperation::Renew => "certificate.renew.discarded",
        },
        &route.id.to_string(),
        &format!("hostname={}; reason=route_state_changed", route.hostname),
    );
}

fn sanitize_certificate_error(value: &str) -> String {
    let sanitized = value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect::<String>();
    sanitized.chars().take(1_000).collect()
}

fn certificate_operation_cooldown_seconds() -> i64 {
    std::env::var("LINKLAKE_CERTIFICATE_OPERATION_COOLDOWN_SECONDS")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| (1..=3_600).contains(value))
        .unwrap_or(60)
}

fn restore_managed_certificates(state: &Arc<AppState>) -> anyhow::Result<()> {
    let Some(manager) = &state.certificate_manager else {
        return Ok(());
    };
    let routes = state
        .http_route_catalog
        .lock()
        .expect("HTTP route catalog lock poisoned")
        .list()?;
    let now = unix_seconds() as i64;
    for route in routes.into_iter().filter(|route| route.enabled) {
        let (tls_policy, certificate) = {
            let catalog = state
                .certificate_catalog
                .lock()
                .expect("certificate catalog lock poisoned");
            (
                catalog.get_route_tls(route.id)?,
                catalog.get_certificate_state(route.id)?,
            )
        };
        let Some(tls_policy) = tls_policy else {
            continue;
        };
        if tls_policy.mode != RouteTlsMode::Acme {
            continue;
        }
        if certificate
            .as_ref()
            .is_some_and(|certificate| certificate.expired_at(now))
        {
            set_persisted_certificate_status(state, route.id, CertificateStatus::Expired)
                .map_err(|error| anyhow::anyhow!(error.2))?;
            continue;
        }
        if certificate
            .as_ref()
            .and_then(|value| value.not_after)
            .is_some()
        {
            match manager.load_certificate(&route.hostname) {
                Ok(_) => {
                    if certificate.as_ref().is_some_and(|certificate| {
                        matches!(
                            certificate.status,
                            CertificateStatus::Issuing
                                | CertificateStatus::Renewing
                                | CertificateStatus::Disabled
                        )
                    }) {
                        set_persisted_certificate_status(
                            state,
                            route.id,
                            CertificateStatus::Active,
                        )
                        .map_err(|error| anyhow::anyhow!(error.2))?;
                    }
                    if tls_policy.redirect_http_to_https {
                        state
                            .https_redirect_hosts
                            .lock()
                            .expect("HTTPS redirect registry lock poisoned")
                            .insert(route.hostname.clone());
                    }
                }
                Err(error) => {
                    let message = sanitize_certificate_error(&error.to_string());
                    let _ = state
                        .certificate_catalog
                        .lock()
                        .expect("certificate catalog lock poisoned")
                        .record_certificate_failure(
                            route.id,
                            "certificate_load_failed",
                            &message,
                            now,
                        );
                    tracing::warn!(
                        "could not restore certificate for {}: {}",
                        route.hostname,
                        message
                    );
                }
            }
        } else if certificate.as_ref().is_some_and(|certificate| {
            matches!(
                certificate.status,
                CertificateStatus::Issuing
                    | CertificateStatus::Renewing
                    | CertificateStatus::Disabled
            )
        }) {
            set_persisted_certificate_status(state, route.id, CertificateStatus::Pending)
                .map_err(|error| anyhow::anyhow!(error.2))?;
        }
    }
    Ok(())
}

async fn run_certificate_maintenance(state: Arc<AppState>, mut shutdown: watch::Receiver<bool>) {
    let start = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut interval = tokio::time::interval_at(start, Duration::from_secs(60));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = interval.tick() => scan_certificate_maintenance(state.clone()),
        }
    }
}

fn scan_certificate_maintenance(state: Arc<AppState>) {
    let config_enabled = state
        .certificate_catalog
        .lock()
        .expect("certificate catalog lock poisoned")
        .get_acme_config()
        .is_ok_and(|config| config.enabled);
    if !config_enabled {
        return;
    }
    let Ok(routes) = state
        .http_route_catalog
        .lock()
        .expect("HTTP route catalog lock poisoned")
        .list()
    else {
        return;
    };
    let now = unix_seconds() as i64;
    for route in routes.into_iter().filter(|route| route.enabled) {
        let (tls_policy, certificate) = {
            let catalog = state
                .certificate_catalog
                .lock()
                .expect("certificate catalog lock poisoned");
            (
                catalog.get_route_tls(route.id).ok().flatten(),
                catalog.get_certificate_state(route.id).ok().flatten(),
            )
        };
        if tls_policy.as_ref().map(|policy| policy.mode) != Some(RouteTlsMode::Acme) {
            continue;
        }
        if certificate.as_ref().is_some_and(|certificate| {
            certificate.status != CertificateStatus::Error && certificate.expired_at(now)
        }) {
            if let Some(manager) = &state.certificate_manager {
                manager.remove_certificate(&route.hostname);
            }
            let _ = set_persisted_certificate_status(&state, route.id, CertificateStatus::Expired);
        } else if certificate
            .as_ref()
            .is_some_and(|certificate| certificate.expired_at(now))
        {
            if let Some(manager) = &state.certificate_manager {
                manager.remove_certificate(&route.hostname);
            }
        }
        let has_certificate = state
            .certificate_manager
            .as_ref()
            .is_some_and(|manager| manager.has_certificate(&route.hostname));
        let operation =
            select_certificate_maintenance_operation(certificate.as_ref(), has_certificate, now);
        if let Some(operation) = operation {
            let _ = queue_certificate_operation(state.clone(), route.id, operation);
        }
    }
}

fn select_certificate_maintenance_operation(
    certificate: Option<&CertificateState>,
    has_certificate: bool,
    now: i64,
) -> Option<CertificateOperation> {
    match certificate {
        None => Some(CertificateOperation::Issue),
        Some(certificate) if certificate.status == CertificateStatus::Error => {
            certificate_retry_due(certificate, now).then_some(if has_certificate {
                CertificateOperation::Renew
            } else {
                CertificateOperation::Issue
            })
        }
        Some(certificate) if certificate.expired_at(now) => Some(CertificateOperation::Issue),
        Some(certificate) if certificate.status == CertificateStatus::Pending => {
            Some(CertificateOperation::Issue)
        }
        Some(certificate) if certificate.status == CertificateStatus::Issuing => {
            Some(CertificateOperation::Issue)
        }
        Some(certificate) if certificate.status == CertificateStatus::Renewing => {
            Some(if has_certificate {
                CertificateOperation::Renew
            } else {
                CertificateOperation::Issue
            })
        }
        Some(certificate) if certificate.renewal_due(now) => Some(CertificateOperation::Renew),
        _ => None,
    }
}

fn certificate_retry_due(certificate: &CertificateState, now: i64) -> bool {
    let delay = match certificate.failure_count {
        0 | 1 => 60,
        2 => 5 * 60,
        3 => 15 * 60,
        4 => 60 * 60,
        _ => 6 * 60 * 60,
    };
    certificate
        .last_attempt
        .is_none_or(|last_attempt| now >= last_attempt.saturating_add(delay))
}

async fn list_clients(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<linklake_core::ClientSummary>>, ApiError> {
    authorize_management(&state, &headers)?;
    let clients = state.clients.lock().expect("client registry lock poisoned");
    Ok(Json(clients.summaries()))
}

async fn global_search(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<SearchQuery>,
) -> Result<Json<Vec<SearchResult>>, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    let query = query.q.trim().to_lowercase();
    if query.len() < 2 {
        return Ok(Json(Vec::new()));
    }
    let mut results = Vec::new();
    let mut add =
        |kind: &'static str, id: String, title: String, subtitle: String, href: &'static str| {
            if results.len() >= 50 {
                return;
            }
            let haystack = format!("{id} {title} {subtitle}").to_lowercase();
            if haystack.contains(&query) {
                results.push(SearchResult {
                    kind,
                    id,
                    title,
                    subtitle,
                    href: href.to_owned(),
                });
            }
        };
    for client in state
        .clients
        .lock()
        .expect("client registry lock poisoned")
        .summaries()
    {
        add(
            "client",
            client.client_id.to_string(),
            client.name,
            format!(
                "{} · {} · {}",
                client.platform,
                client.group_name.unwrap_or_default(),
                client.tags.join(",")
            ),
            "#/clients",
        );
    }
    let catalog = state
        .tunnel_catalog
        .lock()
        .expect("tunnel catalog lock poisoned");
    for policy in catalog.list().map_err(coded_client_management_error)? {
        add(
            "tcp",
            policy.id.to_string(),
            policy.name,
            format!("{} → {}", policy.public_port, policy.target_addr),
            "#/services/tcp",
        );
    }
    for policy in catalog
        .list_udp()
        .map_err(|error| coded_client_management_error(error.into()))?
    {
        add(
            "udp",
            policy.id.to_string(),
            policy.name,
            format!("{} → {}", policy.public_port, policy.target_addr),
            "#/services/udp",
        );
    }
    for policy in catalog
        .list_port_groups()
        .map_err(|error| coded_client_management_error(error.into()))?
    {
        add(
            "ports",
            policy.id.to_string(),
            policy.name,
            format!(
                "{} → {}:{}",
                policy.public_ports, policy.target_host, policy.target_ports
            ),
            "#/services/ports",
        );
    }
    for policy in catalog
        .list_socks5()
        .map_err(|error| coded_client_management_error(error.into()))?
    {
        add(
            "socks5",
            policy.id.to_string(),
            policy.name,
            format!("{} · {}", policy.public_port, policy.username),
            "#/services/socks5",
        );
    }
    for policy in catalog
        .list_http_proxies()
        .map_err(|error| coded_client_management_error(error.into()))?
    {
        add(
            "http_proxy",
            policy.id.to_string(),
            policy.name,
            format!("{} · {}", policy.public_port, policy.username),
            "#/services/http-proxy",
        );
    }
    drop(catalog);
    for policy in state
        .http_route_catalog
        .lock()
        .expect("HTTP route catalog lock poisoned")
        .list()
        .map_err(coded_client_management_error)?
    {
        add(
            "http",
            policy.id.to_string(),
            policy.name,
            format!("{} → {}", policy.hostname, policy.target_addr),
            "#/services/http",
        );
    }
    for policy in state
        .sni_route_catalog
        .lock()
        .expect("SNI route catalog lock poisoned")
        .list()
        .map_err(|error| coded_client_management_error(error.into()))?
    {
        add(
            "sni",
            policy.id.to_string(),
            policy.name,
            format!("{} → {}", policy.hostname, policy.target_addr),
            "#/services/sni",
        );
    }
    for policy in state
        .secret_tunnel_catalog
        .lock()
        .expect("secret tunnel catalog lock poisoned")
        .list()
        .map_err(|error| coded_client_management_error(error.into()))?
    {
        add(
            "secret",
            policy.id.to_string(),
            policy.name,
            policy.target_addr,
            "#/services/secret",
        );
    }
    Ok(Json(results))
}

async fn update_client(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(client_id): Path<Uuid>,
    Json(request): Json<UpdateClient>,
) -> Result<Json<linklake_core::ClientSummary>, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    let client = state
        .clients
        .lock()
        .expect("client registry lock poisoned")
        .update(client_id, request)
        .map_err(coded_client_management_error)?
        .ok_or(CodedApiError(
            StatusCode::NOT_FOUND,
            "unknown_client",
            "client does not exist",
        ))?;
    record_audit(
        &state,
        "client.updated",
        &client_id.to_string(),
        &format!(
            "name={}; group={}; enabled={}; tags={}",
            client.name,
            client.group_name.as_deref().unwrap_or(""),
            client.enabled,
            client.tags.join(",")
        ),
    );
    Ok(Json(client))
}

async fn rotate_client_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(client_id): Path<Uuid>,
) -> Result<Json<ClientEnrollmentResponse>, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    let client_token = state
        .clients
        .lock()
        .expect("client registry lock poisoned")
        .rotate_token(client_id)
        .map_err(coded_client_management_error)?
        .ok_or(CodedApiError(
            StatusCode::NOT_FOUND,
            "unknown_client",
            "client does not exist",
        ))?;
    record_audit(
        &state,
        "client.token.rotated",
        &client_id.to_string(),
        "client token rotated; existing control sessions will fail on their next authentication",
    );
    Ok(Json(ClientEnrollmentResponse {
        client_id,
        client_token,
    }))
}

async fn delete_client(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(client_id): Path<Uuid>,
) -> Result<StatusCode, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    let client = state
        .clients
        .lock()
        .expect("client registry lock poisoned")
        .summary_by_id(client_id)
        .ok_or(CodedApiError(
            StatusCode::NOT_FOUND,
            "unknown_client",
            "client does not exist",
        ))?;
    if client.enabled && unix_seconds().saturating_sub(client.last_seen_unix_seconds) <= 120 {
        return Err(CodedApiError(
            StatusCode::CONFLICT,
            "client_is_online",
            "disable the client identity and wait for it to disconnect before deletion",
        ));
    }
    let references = client_policy_reference_count(&state, client_id)?;
    if references > 0 {
        return Err(CodedApiError(
            StatusCode::CONFLICT,
            "client_has_policies",
            "delete or migrate policies that reference this client first",
        ));
    }
    let deleted = state
        .clients
        .lock()
        .expect("client registry lock poisoned")
        .delete(client_id)
        .map_err(coded_client_management_error)?;
    if !deleted {
        return Err(CodedApiError(
            StatusCode::NOT_FOUND,
            "unknown_client",
            "client does not exist",
        ));
    }
    record_audit(
        &state,
        "client.deleted",
        &client_id.to_string(),
        "client identity deleted",
    );
    Ok(StatusCode::NO_CONTENT)
}

fn client_policy_reference_count(
    state: &AppState,
    client_id: Uuid,
) -> Result<usize, CodedApiError> {
    let tunnel_catalog = state
        .tunnel_catalog
        .lock()
        .expect("tunnel catalog lock poisoned");
    let mut count = tunnel_catalog
        .list()
        .map_err(coded_client_management_error)?
        .into_iter()
        .filter(|policy| policy.client_id == client_id)
        .count();
    count += tunnel_catalog
        .list_udp()
        .map_err(|error| coded_client_management_error(error.into()))?
        .into_iter()
        .filter(|policy| policy.client_id == client_id)
        .count();
    count += tunnel_catalog
        .list_port_groups()
        .map_err(|error| coded_client_management_error(error.into()))?
        .into_iter()
        .filter(|policy| policy.client_id == client_id)
        .count();
    count += tunnel_catalog
        .list_socks5()
        .map_err(|error| coded_client_management_error(error.into()))?
        .into_iter()
        .filter(|policy| policy.client_id == client_id)
        .count();
    count += tunnel_catalog
        .list_http_proxies()
        .map_err(|error| coded_client_management_error(error.into()))?
        .into_iter()
        .filter(|policy| policy.client_id == client_id)
        .count();
    drop(tunnel_catalog);
    count += state
        .http_route_catalog
        .lock()
        .expect("HTTP route catalog lock poisoned")
        .list()
        .map_err(coded_client_management_error)?
        .into_iter()
        .filter(|policy| policy.client_id == client_id)
        .count();
    count += state
        .sni_route_catalog
        .lock()
        .expect("SNI route catalog lock poisoned")
        .list()
        .map_err(|error| coded_client_management_error(error.into()))?
        .into_iter()
        .filter(|policy| policy.client_id == client_id)
        .count();
    count += state
        .secret_tunnel_catalog
        .lock()
        .expect("secret tunnel catalog lock poisoned")
        .list()
        .map_err(|error| coded_client_management_error(error.into()))?
        .into_iter()
        .filter(|policy| {
            policy.provider_client_id == client_id || policy.allowed_client_id == Some(client_id)
        })
        .count();
    Ok(count)
}

async fn list_p2p_nodes(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<P2pNodeView>>, ApiError> {
    authorize_management(&state, &headers)?;
    let nodes = state
        .p2p_node_catalog
        .lock()
        .expect("P2P node catalog lock poisoned")
        .list()
        .map_err(|_| {
            ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not read P2P nodes",
            )
        })?;
    let now = unix_seconds();
    Ok(Json(
        nodes
            .into_iter()
            .map(|node| P2pNodeView {
                fresh: p2p_control::node_is_fresh(node.updated_unix_seconds, now),
                age_seconds: now.saturating_sub(node.updated_unix_seconds),
                node,
            })
            .collect(),
    ))
}

async fn list_audit_events(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> Result<Json<Vec<AuditEvent>>, ApiError> {
    authorize_management(&state, &headers)?;
    let events = state
        .audit
        .lock()
        .expect("audit log lock poisoned")
        .recent(query.limit.unwrap_or(20))
        .map_err(|_| {
            ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not read audit events",
            )
        })?;
    Ok(Json(events))
}

async fn export_audit_events(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<AuditExportQuery>,
) -> Result<Response, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    if query.from.zip(query.to).is_some_and(|(from, to)| from > to) {
        return Err(CodedApiError(
            StatusCode::BAD_REQUEST,
            "invalid_export_range",
            "audit export start must not be later than end",
        ));
    }
    let events = state
        .audit
        .lock()
        .expect("audit log lock poisoned")
        .export(query.from, query.to, query.limit.unwrap_or(100_000))
        .map_err(|_| {
            CodedApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "audit_export_failed",
                "could not export audit events",
            )
        })?;
    let format = query.format.as_deref().unwrap_or("csv");
    if format == "json" {
        let body = serde_json::to_string_pretty(&events).map_err(|_| {
            CodedApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "audit_export_failed",
                "could not serialize audit events",
            )
        })?;
        return Ok(download_response(
            body,
            "application/json; charset=utf-8",
            "linklake-audit.json",
        ));
    }
    if format != "csv" {
        return Err(CodedApiError(
            StatusCode::BAD_REQUEST,
            "invalid_export_format",
            "export format must be csv or json",
        ));
    }
    let mut body = String::from("id,occurred_unix_seconds,action,subject,detail\n");
    for event in events {
        body.push_str(&format!(
            "{},{},{},{},{}\n",
            event.id,
            event.occurred_unix_seconds,
            csv_field(&event.action),
            csv_field(&event.subject),
            csv_field(&event.detail),
        ));
    }
    Ok(download_response(
        body,
        "text/csv; charset=utf-8",
        "linklake-audit.csv",
    ))
}

fn csv_field(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn download_response(body: String, content_type: &str, filename: &str) -> Response {
    (
        [
            (header::CONTENT_TYPE, content_type.to_owned()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
        ],
        body,
    )
        .into_response()
}

async fn list_alert_rules(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<AlertRule>>, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    let rules = state
        .alerts
        .lock()
        .expect("alert catalog lock poisoned")
        .list_rules()
        .map_err(coded_alert_error)?;
    Ok(Json(rules))
}

async fn create_alert_rule(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<CreateAlertRule>,
) -> Result<(StatusCode, Json<AlertRule>), CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    let rule = state
        .alerts
        .lock()
        .expect("alert catalog lock poisoned")
        .create_rule(request, unix_seconds())
        .map_err(coded_alert_error)?;
    record_audit(
        &state,
        "alert.rule.created",
        &rule.id.to_string(),
        &format!(
            "name={}; metric={:?}; enabled={}",
            rule.name, rule.metric, rule.enabled
        ),
    );
    Ok((StatusCode::CREATED, Json(rule)))
}

async fn update_alert_rule(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(rule_id): Path<Uuid>,
    Json(request): Json<UpdateAlertRule>,
) -> Result<Json<AlertRule>, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    let rule = state
        .alerts
        .lock()
        .expect("alert catalog lock poisoned")
        .update_rule(rule_id, request, unix_seconds())
        .map_err(coded_alert_error)?
        .ok_or(CodedApiError(
            StatusCode::NOT_FOUND,
            "unknown_alert_rule",
            "alert rule does not exist",
        ))?;
    record_audit(
        &state,
        "alert.rule.updated",
        &rule_id.to_string(),
        &format!(
            "name={}; metric={:?}; enabled={}",
            rule.name, rule.metric, rule.enabled
        ),
    );
    Ok(Json(rule))
}

async fn delete_alert_rule(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(rule_id): Path<Uuid>,
) -> Result<StatusCode, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    let deleted = state
        .alerts
        .lock()
        .expect("alert catalog lock poisoned")
        .delete_rule(rule_id, unix_seconds())
        .map_err(coded_alert_error)?;
    if !deleted {
        return Err(CodedApiError(
            StatusCode::NOT_FOUND,
            "unknown_alert_rule",
            "alert rule does not exist",
        ));
    }
    record_audit(
        &state,
        "alert.rule.deleted",
        &rule_id.to_string(),
        "alert rule deleted",
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn list_alert_events(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<AlertEventsQuery>,
) -> Result<Json<Vec<AlertEvent>>, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    let events = state
        .alerts
        .lock()
        .expect("alert catalog lock poisoned")
        .list_events(query.active.unwrap_or(false), query.limit.unwrap_or(100))
        .map_err(coded_alert_error)?;
    Ok(Json(events))
}

async fn alert_notification_channels(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<notifications::NotificationChannelView>, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    Ok(Json(notifications::channel_view()))
}

async fn list_fleet_peers(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<FleetPeer>>, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    Ok(Json(
        state
            .fleet
            .lock()
            .expect("fleet catalog lock poisoned")
            .list()
            .map_err(coded_fleet_error)?,
    ))
}

async fn create_fleet_peer(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<UpsertFleetPeer>,
) -> Result<(StatusCode, Json<FleetPeer>), CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    let peer = state
        .fleet
        .lock()
        .expect("fleet catalog lock poisoned")
        .create(request, unix_seconds())
        .map_err(coded_fleet_error)?;
    record_audit(
        &state,
        "fleet.peer.created",
        &peer.id.to_string(),
        &peer.name,
    );
    Ok((StatusCode::CREATED, Json(peer)))
}

async fn update_fleet_peer(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(peer_id): Path<Uuid>,
    Json(request): Json<UpsertFleetPeer>,
) -> Result<Json<FleetPeer>, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    let peer = state
        .fleet
        .lock()
        .expect("fleet catalog lock poisoned")
        .update(peer_id, request, unix_seconds())
        .map_err(coded_fleet_error)?
        .ok_or(CodedApiError(
            StatusCode::NOT_FOUND,
            "unknown_fleet_peer",
            "fleet peer does not exist",
        ))?;
    record_audit(
        &state,
        "fleet.peer.updated",
        &peer_id.to_string(),
        &peer.name,
    );
    Ok(Json(peer))
}

async fn delete_fleet_peer(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(peer_id): Path<Uuid>,
) -> Result<StatusCode, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    if !state
        .fleet
        .lock()
        .expect("fleet catalog lock poisoned")
        .delete(peer_id)
        .map_err(coded_fleet_error)?
    {
        return Err(CodedApiError(
            StatusCode::NOT_FOUND,
            "unknown_fleet_peer",
            "fleet peer does not exist",
        ));
    }
    record_audit(
        &state,
        "fleet.peer.deleted",
        &peer_id.to_string(),
        "peer deleted",
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn fleet_overview(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<FleetOverview>, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    let peers = state
        .fleet
        .lock()
        .expect("fleet catalog lock poisoned")
        .list()
        .map_err(coded_fleet_error)?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .map_err(|error| coded_fleet_error(error.into()))?;
    let mut statuses = Vec::with_capacity(peers.len());
    for peer in peers {
        statuses.push(probe_fleet_peer(&client, peer).await);
    }
    let mut available = statuses
        .iter()
        .filter(|status| status.peer.enabled && status.online)
        .collect::<Vec<_>>();
    available.sort_by_key(|status| (status.peer.priority, std::cmp::Reverse(status.peer.weight)));
    let failover_order = available
        .iter()
        .map(|status| status.peer.id)
        .collect::<Vec<_>>();
    let preferred_peer_id = failover_order.first().copied();
    let mut conflicts = Vec::new();
    let mut placement = HashMap::<(String, u16), Vec<String>>::new();
    for status in statuses.iter().filter(|status| status.peer.enabled) {
        placement
            .entry((status.peer.region.clone(), status.peer.priority))
            .or_default()
            .push(status.peer.name.clone());
    }
    for ((region, priority), names) in placement.into_iter().filter(|(_, names)| names.len() > 1) {
        conflicts.push(format!(
            "region {region} has multiple peers at priority {priority}: {}",
            names.join(", ")
        ));
    }
    Ok(Json(FleetOverview {
        preferred_peer_id,
        failover_order,
        conflicts,
        peers: statuses,
    }))
}

async fn import_fleet_policies(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<FleetImportRequest>,
) -> Result<Json<FleetImportResult>, CodedApiError> {
    let principal = require_administrator(&state, &headers)?;
    let clients = state
        .clients
        .lock()
        .expect("client registry lock poisoned")
        .summaries();
    let result = fleet::import_policy_bundle(
        &request.bundle,
        &clients,
        &mut state
            .tunnel_catalog
            .lock()
            .expect("tunnel catalog lock poisoned"),
        request.dry_run,
    )
    .map_err(coded_fleet_error)?;
    record_audit(
        &state,
        if request.dry_run {
            "fleet.policy_import.previewed"
        } else {
            "fleet.policy_import.applied"
        },
        "fleet",
        &format!(
            "actor={}; created={}; unchanged={}; conflicts={}",
            principal.username,
            result.created,
            result.unchanged,
            result.conflicts.len()
        ),
    );
    Ok(Json(result))
}

async fn sync_fleet_policies(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<FleetSyncRequest>,
) -> Result<Json<Vec<FleetPeerSyncResult>>, CodedApiError> {
    let principal = require_administrator(&state, &headers)?;
    let clients = state
        .clients
        .lock()
        .expect("client registry lock poisoned")
        .summaries();
    let bundle = fleet::export_policy_bundle(
        &clients,
        &state
            .tunnel_catalog
            .lock()
            .expect("tunnel catalog lock poisoned"),
    )
    .map_err(coded_fleet_error)?;
    let peers = state
        .fleet
        .lock()
        .expect("fleet catalog lock poisoned")
        .list()
        .map_err(coded_fleet_error)?
        .into_iter()
        .filter(|peer| {
            peer.enabled && (request.peer_ids.is_empty() || request.peer_ids.contains(&peer.id))
        })
        .collect::<Vec<_>>();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|error| coded_fleet_error(error.into()))?;
    let mut results = Vec::with_capacity(peers.len());
    for peer in peers {
        let Some(token) =
            std::env::var_os(&peer.token_env).and_then(|value| value.into_string().ok())
        else {
            results.push(FleetPeerSyncResult {
                peer_id: peer.id,
                peer_name: peer.name,
                created: 0,
                unchanged: 0,
                conflicts: Vec::new(),
                error: Some("management token environment variable is not configured".to_owned()),
            });
            continue;
        };
        let response = client
            .post(format!("{}/api/v1/fleet/import", peer.url))
            .bearer_auth(token)
            .json(&FleetImportRequest {
                bundle: bundle.clone(),
                dry_run: request.dry_run,
            })
            .send()
            .await;
        match response {
            Ok(response) if response.status().is_success() => {
                match response.json::<FleetImportResult>().await {
                    Ok(imported) => results.push(FleetPeerSyncResult {
                        peer_id: peer.id,
                        peer_name: peer.name,
                        created: imported.created,
                        unchanged: imported.unchanged,
                        conflicts: imported.conflicts,
                        error: None,
                    }),
                    Err(error) => results.push(FleetPeerSyncResult {
                        peer_id: peer.id,
                        peer_name: peer.name,
                        created: 0,
                        unchanged: 0,
                        conflicts: Vec::new(),
                        error: Some(format!("invalid peer response: {error}")),
                    }),
                }
            }
            Ok(response) => results.push(FleetPeerSyncResult {
                peer_id: peer.id,
                peer_name: peer.name,
                created: 0,
                unchanged: 0,
                conflicts: Vec::new(),
                error: Some(format!("peer returned HTTP {}", response.status())),
            }),
            Err(error) => results.push(FleetPeerSyncResult {
                peer_id: peer.id,
                peer_name: peer.name,
                created: 0,
                unchanged: 0,
                conflicts: Vec::new(),
                error: Some(error.to_string()),
            }),
        }
    }
    record_audit(
        &state,
        if request.dry_run {
            "fleet.policy_sync.previewed"
        } else {
            "fleet.policy_sync.applied"
        },
        "fleet",
        &format!("actor={}; peers={}", principal.username, results.len()),
    );
    Ok(Json(results))
}

async fn get_traffic_control(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((kind, policy_id)): Path<(String, Uuid)>,
) -> Result<Json<traffic_control::TrafficControlRecord>, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    let kind = TrafficPolicyKind::parse(&kind).map_err(coded_traffic_control_error)?;
    state
        .traffic_controls
        .lock()
        .expect("traffic control catalog lock poisoned")
        .get(kind, policy_id, unix_seconds())
        .map_err(coded_traffic_control_error)?
        .map(Json)
        .ok_or(CodedApiError(
            StatusCode::NOT_FOUND,
            "traffic_control_not_configured",
            "traffic control is not configured for this policy",
        ))
}

async fn upsert_traffic_control(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((kind, policy_id)): Path<(String, Uuid)>,
    Json(request): Json<UpsertTrafficControl>,
) -> Result<Json<traffic_control::TrafficControlRecord>, CodedApiError> {
    let principal = require_administrator(&state, &headers)?;
    let kind = TrafficPolicyKind::parse(&kind).map_err(coded_traffic_control_error)?;
    let record = state
        .traffic_controls
        .lock()
        .expect("traffic control catalog lock poisoned")
        .upsert(kind, policy_id, request, unix_seconds())
        .map_err(coded_traffic_control_error)?;
    record_audit(
        &state,
        "traffic_control.updated",
        &policy_id.to_string(),
        &format!("actor={}; kind={}", principal.username, kind.as_str()),
    );
    Ok(Json(record))
}

async fn delete_traffic_control(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((kind, policy_id)): Path<(String, Uuid)>,
) -> Result<StatusCode, CodedApiError> {
    let principal = require_administrator(&state, &headers)?;
    let kind = TrafficPolicyKind::parse(&kind).map_err(coded_traffic_control_error)?;
    if !state
        .traffic_controls
        .lock()
        .expect("traffic control catalog lock poisoned")
        .delete(kind, policy_id)
        .map_err(coded_traffic_control_error)?
    {
        return Err(CodedApiError(
            StatusCode::NOT_FOUND,
            "traffic_control_not_configured",
            "traffic control is not configured for this policy",
        ));
    }
    record_audit(
        &state,
        "traffic_control.deleted",
        &policy_id.to_string(),
        &format!("actor={}; kind={}", principal.username, kind.as_str()),
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn probe_fleet_peer(client: &reqwest::Client, peer: FleetPeer) -> FleetPeerStatus {
    let started = Instant::now();
    if !peer.enabled {
        return FleetPeerStatus {
            peer,
            online: false,
            latency_millis: None,
            error: Some("peer disabled".to_owned()),
            active_connections: 0,
            bytes_total: 0,
            clients: 0,
            policies: 0,
        };
    }
    let Some(token) = std::env::var_os(&peer.token_env).and_then(|value| value.into_string().ok())
    else {
        return FleetPeerStatus {
            peer,
            online: false,
            latency_millis: None,
            error: Some("management token environment variable is not configured".to_owned()),
            active_connections: 0,
            bytes_total: 0,
            clients: 0,
            policies: 0,
        };
    };
    let status_request = client
        .get(format!("{}/api/v1/status", peer.url))
        .bearer_auth(&token)
        .send();
    let metrics_request = client
        .get(format!("{}/api/v1/metrics", peer.url))
        .bearer_auth(&token)
        .send();
    let (status, metrics) = tokio::join!(status_request, metrics_request);
    let result = async {
        let status = status?
            .error_for_status()?
            .json::<serde_json::Value>()
            .await?;
        let metrics = metrics?
            .error_for_status()?
            .json::<serde_json::Value>()
            .await?;
        Ok::<_, reqwest::Error>((status, metrics))
    }
    .await;
    match result {
        Ok((status, metrics)) => {
            let active_connections = [
                "tcp_active_connections",
                "udp_active_sessions",
                "http_active_connections",
                "sni_active_connections",
                "socks5_active_connections",
                "http_proxy_active_connections",
            ]
            .iter()
            .map(|key| metrics[*key].as_u64().unwrap_or(0))
            .sum();
            let bytes_total = metrics
                .as_object()
                .into_iter()
                .flat_map(|value| value.iter())
                .filter(|(key, _)| {
                    key.contains("bytes_from_public") || key.contains("bytes_to_public")
                })
                .map(|(_, value)| value.as_u64().unwrap_or(0))
                .sum();
            let policies = [
                "tunnels",
                "udp_tunnels",
                "http_routes",
                "secret_tunnels",
                "socks5_proxies",
                "http_proxies",
                "port_groups",
                "sni_routes",
            ]
            .iter()
            .map(|key| status[*key].as_u64().unwrap_or(0))
            .sum();
            FleetPeerStatus {
                clients: status["clients"].as_u64().unwrap_or(0),
                peer,
                online: true,
                latency_millis: Some(started.elapsed().as_millis() as u64),
                error: None,
                active_connections,
                bytes_total,
                policies,
            }
        }
        Err(error) => FleetPeerStatus {
            peer,
            online: false,
            latency_millis: Some(started.elapsed().as_millis() as u64),
            error: Some(error.to_string()),
            active_connections: 0,
            bytes_total: 0,
            clients: 0,
            policies: 0,
        },
    }
}

async fn list_tcp_tunnels(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<TcpTunnelView>>, ApiError> {
    authorize_management(&state, &headers)?;
    let policies = state
        .tunnel_catalog
        .lock()
        .expect("tunnel catalog lock poisoned")
        .list()
        .map_err(|_| {
            ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not read tunnel policies",
            )
        })?;
    let online_ports = state
        .tunnels
        .lock()
        .expect("tunnel registry lock poisoned")
        .keys()
        .copied()
        .collect::<HashSet<_>>();
    let statistics = state
        .tunnel_statistics
        .lock()
        .expect("tunnel statistics lock poisoned");
    let views = policies
        .into_iter()
        .map(|policy| {
            let statistics = statistics.get(&policy.public_port);
            TcpTunnelView {
                online: online_ports.contains(&policy.public_port),
                active_connections: statistics.map_or(0, |tunnel| {
                    tunnel
                        .active_connections
                        .load(std::sync::atomic::Ordering::Relaxed)
                }),
                rejected_connections: statistics.map_or(0, |tunnel| {
                    tunnel
                        .rejected_connections
                        .load(std::sync::atomic::Ordering::Relaxed)
                }),
                bytes_from_public: statistics.map_or(0, |tunnel| {
                    tunnel
                        .bytes_from_public
                        .load(std::sync::atomic::Ordering::Relaxed)
                }),
                bytes_to_public: statistics.map_or(0, |tunnel| {
                    tunnel
                        .bytes_to_public
                        .load(std::sync::atomic::Ordering::Relaxed)
                }),
                failed_connections: statistics.map_or(0, |tunnel| {
                    tunnel
                        .failed_connections
                        .load(std::sync::atomic::Ordering::Relaxed)
                }),
                rejected_policy_limit: statistics.map_or(0, |tunnel| {
                    tunnel.rejected_policy_limit.load(Ordering::Relaxed)
                }),
                rejected_global_limit: statistics.map_or(0, |tunnel| {
                    tunnel.rejected_global_limit.load(Ordering::Relaxed)
                }),
                rejected_pending_limit: statistics.map_or(0, |tunnel| {
                    tunnel.rejected_pending_limit.load(Ordering::Relaxed)
                }),
                pairing_timeouts: statistics
                    .map_or(0, |tunnel| tunnel.pairing_timeouts.load(Ordering::Relaxed)),
                transfer_errors: statistics
                    .map_or(0, |tunnel| tunnel.transfer_errors.load(Ordering::Relaxed)),
                lifetime_timeouts: statistics
                    .map_or(0, |tunnel| tunnel.lifetime_timeouts.load(Ordering::Relaxed)),
                policy,
            }
        })
        .collect();
    Ok(Json(views))
}

async fn create_tcp_tunnel(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<CreateTcpTunnelPolicy>,
) -> Result<Json<TcpTunnelPolicy>, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    if !state
        .clients
        .lock()
        .expect("client registry lock poisoned")
        .contains(request.client_id)
    {
        return Err(CodedApiError(
            StatusCode::BAD_REQUEST,
            "unknown_client",
            "unknown client for tunnel policy",
        ));
    }
    let policy = state
        .tunnel_catalog
        .lock()
        .expect("tunnel catalog lock poisoned")
        .create(request)
        .map_err(coded_tcp_policy_error)?;
    record_audit(
        &state,
        "tcp_tunnel.policy.created",
        &policy.id.to_string(),
        &format!(
            "client={}; port={}; name={}",
            policy.client_id, policy.public_port, policy.name
        ),
    );
    Ok(Json(policy))
}

async fn update_tcp_tunnel(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(tunnel_id): Path<Uuid>,
    Json(request): Json<UpdateTcpTunnelPolicy>,
) -> Result<Json<TcpTunnelPolicy>, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    if !state
        .clients
        .lock()
        .expect("client registry lock poisoned")
        .contains(request.client_id)
    {
        return Err(CodedApiError(
            StatusCode::BAD_REQUEST,
            "unknown_client",
            "unknown client for tunnel policy",
        ));
    }
    let (old_policy, policy) = {
        let mut catalog = state
            .tunnel_catalog
            .lock()
            .expect("tunnel catalog lock poisoned");
        let old = catalog.policy_by_id(tunnel_id).map_err(|_| {
            CodedApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "tcp_policy_storage_error",
                "could not read tunnel policy",
            )
        })?;
        let updated = catalog
            .update(tunnel_id, request)
            .map_err(coded_tcp_policy_error)?;
        let old = old.ok_or(CodedApiError(
            StatusCode::NOT_FOUND,
            "unknown_policy",
            "unknown tunnel policy",
        ))?;
        let updated = updated.ok_or(CodedApiError(
            StatusCode::NOT_FOUND,
            "unknown_policy",
            "unknown tunnel policy",
        ))?;
        (old, updated)
    };
    // 更新后强制旧注册重新配对，使目标地址、端口和限流参数立即生效。
    tcp_tunnel::stop_public_port(&state, old_policy.public_port);
    record_audit(
        &state,
        "tcp_tunnel.policy.updated",
        &tunnel_id.to_string(),
        &format!(
            "client={}; port={}; target={}; name={}",
            policy.client_id, policy.public_port, policy.target_addr, policy.name
        ),
    );
    Ok(Json(policy))
}

async fn set_tcp_tunnel_enabled(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(tunnel_id): Path<Uuid>,
    Json(request): Json<EnableTunnelRequest>,
) -> Result<StatusCode, ApiError> {
    authorize_management(&state, &headers)?;
    let public_port = state
        .tunnel_catalog
        .lock()
        .expect("tunnel catalog lock poisoned")
        .list()
        .map_err(|_| {
            ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not read tunnel policy",
            )
        })?
        .into_iter()
        .find(|policy| policy.id == tunnel_id)
        .map(|policy| policy.public_port);
    let updated = state
        .tunnel_catalog
        .lock()
        .expect("tunnel catalog lock poisoned")
        .set_enabled(tunnel_id, request.enabled)
        .map_err(|_| {
            ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not update tunnel policy",
            )
        })?;
    if !updated {
        return Err(ApiError(StatusCode::NOT_FOUND, "unknown tunnel policy"));
    }
    if !request.enabled {
        if let Some(public_port) = public_port {
            tcp_tunnel::stop_public_port(&state, public_port);
        }
    }
    record_audit(
        &state,
        "tcp_tunnel.policy.updated",
        &tunnel_id.to_string(),
        if request.enabled {
            "enabled"
        } else {
            "disabled"
        },
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_tcp_tunnel(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(tunnel_id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    authorize_management(&state, &headers)?;
    let public_port = state
        .tunnel_catalog
        .lock()
        .expect("tunnel catalog lock poisoned")
        .list()
        .map_err(|_| {
            ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not read tunnel policy",
            )
        })?
        .into_iter()
        .find(|policy| policy.id == tunnel_id)
        .map(|policy| policy.public_port);
    let deleted = state
        .tunnel_catalog
        .lock()
        .expect("tunnel catalog lock poisoned")
        .delete(tunnel_id)
        .map_err(|_| {
            ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not delete tunnel policy",
            )
        })?;
    if !deleted {
        return Err(ApiError(StatusCode::NOT_FOUND, "unknown tunnel policy"));
    }
    if let Some(public_port) = public_port {
        tcp_tunnel::stop_public_port(&state, public_port);
        state
            .tunnel_statistics
            .lock()
            .expect("tunnel statistics lock poisoned")
            .remove(&public_port);
    }
    record_audit(
        &state,
        "tcp_tunnel.policy.deleted",
        &tunnel_id.to_string(),
        "policy deleted",
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn list_secret_tunnels(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<SecretTunnelView>>, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    let policies = state
        .secret_tunnel_catalog
        .lock()
        .expect("secret tunnel catalog lock poisoned")
        .list()
        .map_err(coded_secret_policy_error)?;
    let online = state
        .secret_tunnels
        .lock()
        .expect("secret tunnel registry lock poisoned");
    let statistics = state
        .secret_tunnel_statistics
        .lock()
        .expect("secret tunnel statistics lock poisoned");
    Ok(Json(
        policies
            .into_iter()
            .map(|policy| {
                let current = statistics.get(&policy.id);
                SecretTunnelView {
                    online: online.contains_key(&policy.id),
                    active_connections: current
                        .map_or(0, |value| value.active_connections.load(Ordering::Relaxed)),
                    connections_total: current
                        .map_or(0, |value| value.connections_total.load(Ordering::Relaxed)),
                    rejected_connections: current.map_or(0, |value| {
                        value.rejected_connections.load(Ordering::Relaxed)
                    }),
                    bytes_from_visitor: current
                        .map_or(0, |value| value.bytes_from_visitor.load(Ordering::Relaxed)),
                    bytes_to_visitor: current
                        .map_or(0, |value| value.bytes_to_visitor.load(Ordering::Relaxed)),
                    pairing_timeouts: current
                        .map_or(0, |value| value.pairing_timeouts.load(Ordering::Relaxed)),
                    transfer_errors: current
                        .map_or(0, |value| value.transfer_errors.load(Ordering::Relaxed)),
                    lifetime_timeouts: current
                        .map_or(0, |value| value.lifetime_timeouts.load(Ordering::Relaxed)),
                    policy,
                }
            })
            .collect(),
    ))
}

async fn create_secret_tunnel(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<CreateSecretTunnelPolicy>,
) -> Result<(StatusCode, Json<CreatedSecretTunnelPolicy>), CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    let clients = state.clients.lock().expect("client registry lock poisoned");
    if !clients.contains(request.provider_client_id)
        || request
            .allowed_client_id
            .is_some_and(|client_id| !clients.contains(client_id))
    {
        return Err(CodedApiError(
            StatusCode::BAD_REQUEST,
            "unknown_client",
            "unknown provider or allowed visitor client",
        ));
    }
    drop(clients);
    let created = state
        .secret_tunnel_catalog
        .lock()
        .expect("secret tunnel catalog lock poisoned")
        .create(request)
        .map_err(coded_secret_policy_error)?;
    record_audit(
        &state,
        "secret_tunnel.policy.created",
        &created.policy.id.to_string(),
        &format!(
            "provider={}; visitor={}; name={}",
            created.policy.provider_client_id,
            created.policy.allowed_client_id.map_or_else(
                || "any-authenticated-client".to_owned(),
                |value| value.to_string()
            ),
            created.policy.name
        ),
    );
    Ok((StatusCode::CREATED, Json(created)))
}

async fn update_secret_tunnel(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(tunnel_id): Path<Uuid>,
    Json(request): Json<UpdateSecretTunnelPolicy>,
) -> Result<Json<SecretTunnelPolicy>, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    let clients = state.clients.lock().expect("client registry lock poisoned");
    if !clients.contains(request.provider_client_id)
        || request
            .allowed_client_id
            .is_some_and(|client_id| !clients.contains(client_id))
    {
        return Err(CodedApiError(
            StatusCode::BAD_REQUEST,
            "unknown_client",
            "unknown provider or allowed visitor client",
        ));
    }
    drop(clients);
    let (old_policy, policy) = {
        let mut catalog = state
            .secret_tunnel_catalog
            .lock()
            .expect("secret tunnel catalog lock poisoned");
        let old = catalog
            .policy_by_id(tunnel_id)
            .map_err(coded_secret_policy_error)?;
        let updated = catalog
            .update(tunnel_id, request)
            .map_err(coded_secret_policy_error)?;
        let old = old.ok_or(CodedApiError(
            StatusCode::NOT_FOUND,
            "unknown_secret_tunnel",
            "secret tunnel policy does not exist",
        ))?;
        let updated = updated.ok_or(CodedApiError(
            StatusCode::NOT_FOUND,
            "unknown_secret_tunnel",
            "secret tunnel policy does not exist",
        ))?;
        (old, updated)
    };
    secret_tunnel::stop_policy(&state, old_policy.id);
    record_audit(
        &state,
        "secret_tunnel.policy.updated",
        &tunnel_id.to_string(),
        &format!(
            "provider={}; visitor={}; target={}; name={}",
            policy.provider_client_id,
            policy.allowed_client_id.map_or_else(
                || "any-authenticated-client".to_owned(),
                |id| id.to_string()
            ),
            policy.target_addr,
            policy.name
        ),
    );
    Ok(Json(policy))
}

async fn set_secret_tunnel_enabled(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(tunnel_id): Path<Uuid>,
    Json(request): Json<EnableTunnelRequest>,
) -> Result<StatusCode, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    let updated = state
        .secret_tunnel_catalog
        .lock()
        .expect("secret tunnel catalog lock poisoned")
        .set_enabled(tunnel_id, request.enabled)
        .map_err(coded_secret_policy_error)?;
    if !updated {
        return Err(CodedApiError(
            StatusCode::NOT_FOUND,
            "unknown_secret_tunnel",
            "secret tunnel policy does not exist",
        ));
    }
    if !request.enabled {
        secret_tunnel::stop_policy(&state, tunnel_id);
    }
    record_audit(
        &state,
        "secret_tunnel.policy.updated",
        &tunnel_id.to_string(),
        if request.enabled {
            "enabled"
        } else {
            "disabled"
        },
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_secret_tunnel(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(tunnel_id): Path<Uuid>,
) -> Result<StatusCode, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    let deleted = state
        .secret_tunnel_catalog
        .lock()
        .expect("secret tunnel catalog lock poisoned")
        .delete(tunnel_id)
        .map_err(coded_secret_policy_error)?;
    if deleted.is_none() {
        return Err(CodedApiError(
            StatusCode::NOT_FOUND,
            "unknown_secret_tunnel",
            "secret tunnel policy does not exist",
        ));
    }
    secret_tunnel::stop_policy(&state, tunnel_id);
    state
        .secret_tunnel_statistics
        .lock()
        .expect("secret tunnel statistics lock poisoned")
        .remove(&tunnel_id);
    record_audit(
        &state,
        "secret_tunnel.policy.deleted",
        &tunnel_id.to_string(),
        "policy deleted",
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn list_socks5_proxies(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<Socks5ProxyView>>, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    let policies = state
        .tunnel_catalog
        .lock()
        .expect("tunnel catalog lock poisoned")
        .list_socks5()
        .map_err(coded_socks5_policy_error)?;
    let online = state
        .socks5_proxies
        .lock()
        .expect("SOCKS5 proxy registry lock poisoned");
    let statistics = state
        .socks5_proxy_statistics
        .lock()
        .expect("SOCKS5 statistics lock poisoned");
    let capabilities = Socks5CapabilitiesView::new(state.udp_data_plane.is_some());
    Ok(Json(
        policies
            .into_iter()
            .map(|policy| {
                let current = statistics.get(&policy.id);
                Socks5ProxyView {
                    online: online.get(&policy.id).is_some_and(|registration| {
                        socks5_tunnel::online_public_port(registration) == policy.public_port
                    }),
                    capabilities,
                    active_connections: current
                        .map_or(0, |value| value.active_connections.load(Ordering::Relaxed)),
                    connections_total: current
                        .map_or(0, |value| value.connections_total.load(Ordering::Relaxed)),
                    requests_total: current
                        .map_or(0, |value| value.requests_total.load(Ordering::Relaxed)),
                    authentication_failures: current.map_or(0, |value| {
                        value.authentication_failures.load(Ordering::Relaxed)
                    }),
                    rejected_connections: current.map_or(0, |value| {
                        value.rejected_connections.load(Ordering::Relaxed)
                    }),
                    unsupported_commands: current.map_or(0, |value| {
                        value.unsupported_commands.load(Ordering::Relaxed)
                    }),
                    bind_rejected_total: current
                        .map_or(0, |value| value.bind_rejected_total.load(Ordering::Relaxed)),
                    handshake_errors: current
                        .map_or(0, |value| value.handshake_errors.load(Ordering::Relaxed)),
                    handshake_timeouts: current
                        .map_or(0, |value| value.handshake_timeouts.load(Ordering::Relaxed)),
                    bytes_from_public: current
                        .map_or(0, |value| value.bytes_from_public.load(Ordering::Relaxed)),
                    bytes_to_public: current
                        .map_or(0, |value| value.bytes_to_public.load(Ordering::Relaxed)),
                    pairing_timeouts: current
                        .map_or(0, |value| value.pairing_timeouts.load(Ordering::Relaxed)),
                    connect_failures: current
                        .map_or(0, |value| value.connect_failures.load(Ordering::Relaxed)),
                    transfer_errors: current
                        .map_or(0, |value| value.transfer_errors.load(Ordering::Relaxed)),
                    lifetime_timeouts: current
                        .map_or(0, |value| value.lifetime_timeouts.load(Ordering::Relaxed)),
                    udp_active_associations: current.map_or(0, |value| {
                        value.udp_active_associations.load(Ordering::Relaxed)
                    }),
                    udp_datagrams_from_public: current.map_or(0, |value| {
                        value.udp_datagrams_from_public.load(Ordering::Relaxed)
                    }),
                    udp_datagrams_to_public: current.map_or(0, |value| {
                        value.udp_datagrams_to_public.load(Ordering::Relaxed)
                    }),
                    udp_bytes_from_public: current.map_or(0, |value| {
                        value.udp_bytes_from_public.load(Ordering::Relaxed)
                    }),
                    udp_bytes_to_public: current
                        .map_or(0, |value| value.udp_bytes_to_public.load(Ordering::Relaxed)),
                    udp_dropped_datagrams: current.map_or(0, |value| {
                        value.udp_dropped_datagrams.load(Ordering::Relaxed)
                    }),
                    udp_dropped_bandwidth_limit: current.map_or(0, |value| {
                        value.udp_dropped_bandwidth_limit.load(Ordering::Relaxed)
                    }),
                    udp_fragmentation_unsupported_total: current.map_or(0, |value| {
                        value
                            .udp_fragmentation_unsupported_total
                            .load(Ordering::Relaxed)
                    }),
                    policy,
                }
            })
            .collect(),
    ))
}

async fn create_socks5_proxy(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<CreateSocks5ProxyPolicy>,
) -> Result<(StatusCode, Json<CreatedSocks5ProxyPolicy>), CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    if !state
        .clients
        .lock()
        .expect("client registry lock poisoned")
        .contains(request.client_id)
    {
        return Err(CodedApiError(
            StatusCode::BAD_REQUEST,
            "unknown_client",
            "unknown SOCKS5 exit client",
        ));
    }
    let created = state
        .tunnel_catalog
        .lock()
        .expect("tunnel catalog lock poisoned")
        .create_socks5(request)
        .map_err(coded_socks5_policy_error)?;
    record_audit(
        &state,
        "socks5_proxy.policy.created",
        &created.policy.id.to_string(),
        &format!(
            "client={}; port={}; name={}; username={}",
            created.policy.client_id,
            created.policy.public_port,
            created.policy.name,
            created.policy.username
        ),
    );
    Ok((StatusCode::CREATED, Json(created)))
}

async fn update_socks5_proxy(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(proxy_id): Path<Uuid>,
    Json(request): Json<UpdateSocks5ProxyPolicy>,
) -> Result<Json<Socks5ProxyPolicy>, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    if !state
        .clients
        .lock()
        .expect("client registry lock poisoned")
        .contains(request.client_id)
    {
        return Err(CodedApiError(
            StatusCode::BAD_REQUEST,
            "unknown_client",
            "unknown SOCKS5 exit client",
        ));
    }
    let (old_policy, policy) = {
        let mut catalog = state
            .tunnel_catalog
            .lock()
            .expect("tunnel catalog lock poisoned");
        let old = catalog
            .socks5_policy_by_id(proxy_id)
            .map_err(coded_socks5_policy_error)?;
        let updated = catalog
            .update_socks5(proxy_id, request)
            .map_err(coded_socks5_policy_error)?;
        let old = old.ok_or(CodedApiError(
            StatusCode::NOT_FOUND,
            "unknown_socks5_proxy",
            "SOCKS5 proxy policy does not exist",
        ))?;
        let updated = updated.ok_or(CodedApiError(
            StatusCode::NOT_FOUND,
            "unknown_socks5_proxy",
            "SOCKS5 proxy policy does not exist",
        ))?;
        (old, updated)
    };
    socks5_tunnel::stop_policy(&state, old_policy.id);
    record_audit(
        &state,
        "socks5_proxy.policy.updated",
        &proxy_id.to_string(),
        &format!(
            "client={}; port={}; name={}; username={}",
            policy.client_id, policy.public_port, policy.name, policy.username
        ),
    );
    Ok(Json(policy))
}

async fn set_socks5_proxy_enabled(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(proxy_id): Path<Uuid>,
    Json(request): Json<EnableTunnelRequest>,
) -> Result<StatusCode, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    let updated = state
        .tunnel_catalog
        .lock()
        .expect("tunnel catalog lock poisoned")
        .set_socks5_enabled(proxy_id, request.enabled)
        .map_err(coded_socks5_policy_error)?;
    if !updated {
        return Err(CodedApiError(
            StatusCode::NOT_FOUND,
            "unknown_socks5_proxy",
            "SOCKS5 proxy policy does not exist",
        ));
    }
    if !request.enabled {
        socks5_tunnel::stop_policy(&state, proxy_id);
    }
    record_audit(
        &state,
        "socks5_proxy.policy.updated",
        &proxy_id.to_string(),
        if request.enabled {
            "enabled"
        } else {
            "disabled"
        },
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_socks5_proxy(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(proxy_id): Path<Uuid>,
) -> Result<StatusCode, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    let deleted = state
        .tunnel_catalog
        .lock()
        .expect("tunnel catalog lock poisoned")
        .delete_socks5(proxy_id)
        .map_err(coded_socks5_policy_error)?;
    if deleted.is_none() {
        return Err(CodedApiError(
            StatusCode::NOT_FOUND,
            "unknown_socks5_proxy",
            "SOCKS5 proxy policy does not exist",
        ));
    }
    socks5_tunnel::stop_policy(&state, proxy_id);
    state
        .socks5_proxy_statistics
        .lock()
        .expect("SOCKS5 statistics lock poisoned")
        .remove(&proxy_id);
    record_audit(
        &state,
        "socks5_proxy.policy.deleted",
        &proxy_id.to_string(),
        "policy deleted",
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn list_http_proxies(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<HttpProxyView>>, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    let policies = state
        .tunnel_catalog
        .lock()
        .expect("tunnel catalog lock poisoned")
        .list_http_proxies()
        .map_err(coded_http_proxy_policy_error)?;
    let online = state
        .http_proxies
        .lock()
        .expect("HTTP proxy registry lock poisoned");
    let statistics = state
        .http_proxy_statistics
        .lock()
        .expect("HTTP proxy statistics lock poisoned");
    Ok(Json(
        policies
            .into_iter()
            .map(|policy| {
                let current = statistics.get(&policy.id);
                HttpProxyView {
                    online: online.get(&policy.id).is_some_and(|registration| {
                        http_proxy_tunnel::online_public_port(registration) == policy.public_port
                    }),
                    active_connections: current
                        .map_or(0, |value| value.active_connections.load(Ordering::Relaxed)),
                    connections_total: current
                        .map_or(0, |value| value.connections_total.load(Ordering::Relaxed)),
                    requests_total: current
                        .map_or(0, |value| value.requests_total.load(Ordering::Relaxed)),
                    connect_requests: current
                        .map_or(0, |value| value.connect_requests.load(Ordering::Relaxed)),
                    authentication_failures: current.map_or(0, |value| {
                        value.authentication_failures.load(Ordering::Relaxed)
                    }),
                    rejected_connections: current.map_or(0, |value| {
                        value.rejected_connections.load(Ordering::Relaxed)
                    }),
                    malformed_requests: current
                        .map_or(0, |value| value.malformed_requests.load(Ordering::Relaxed)),
                    bytes_from_public: current
                        .map_or(0, |value| value.bytes_from_public.load(Ordering::Relaxed)),
                    bytes_to_public: current
                        .map_or(0, |value| value.bytes_to_public.load(Ordering::Relaxed)),
                    pairing_timeouts: current
                        .map_or(0, |value| value.pairing_timeouts.load(Ordering::Relaxed)),
                    connect_failures: current
                        .map_or(0, |value| value.connect_failures.load(Ordering::Relaxed)),
                    transfer_errors: current
                        .map_or(0, |value| value.transfer_errors.load(Ordering::Relaxed)),
                    lifetime_timeouts: current
                        .map_or(0, |value| value.lifetime_timeouts.load(Ordering::Relaxed)),
                    policy,
                }
            })
            .collect(),
    ))
}

async fn create_http_proxy(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<CreateHttpProxyPolicy>,
) -> Result<(StatusCode, Json<CreatedHttpProxyPolicy>), CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    if !state
        .clients
        .lock()
        .expect("client registry lock poisoned")
        .contains(request.client_id)
    {
        return Err(CodedApiError(
            StatusCode::BAD_REQUEST,
            "unknown_client",
            "unknown HTTP proxy exit client",
        ));
    }
    let created = state
        .tunnel_catalog
        .lock()
        .expect("tunnel catalog lock poisoned")
        .create_http_proxy(request)
        .map_err(coded_http_proxy_policy_error)?;
    record_audit(
        &state,
        "http_proxy.policy.created",
        &created.policy.id.to_string(),
        &format!(
            "client={}; port={}; name={}; username={}",
            created.policy.client_id,
            created.policy.public_port,
            created.policy.name,
            created.policy.username
        ),
    );
    Ok((StatusCode::CREATED, Json(created)))
}

async fn update_http_proxy(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(proxy_id): Path<Uuid>,
    Json(request): Json<UpdateHttpProxyPolicy>,
) -> Result<Json<HttpProxyPolicy>, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    if !state
        .clients
        .lock()
        .expect("client registry lock poisoned")
        .contains(request.client_id)
    {
        return Err(CodedApiError(
            StatusCode::BAD_REQUEST,
            "unknown_client",
            "unknown HTTP proxy exit client",
        ));
    }
    let (old_policy, policy) = {
        let mut catalog = state
            .tunnel_catalog
            .lock()
            .expect("tunnel catalog lock poisoned");
        let old = catalog
            .http_proxy_policy_by_id(proxy_id)
            .map_err(coded_http_proxy_policy_error)?;
        let updated = catalog
            .update_http_proxy(proxy_id, request)
            .map_err(coded_http_proxy_policy_error)?;
        let old = old.ok_or(CodedApiError(
            StatusCode::NOT_FOUND,
            "unknown_http_proxy",
            "HTTP proxy policy does not exist",
        ))?;
        let updated = updated.ok_or(CodedApiError(
            StatusCode::NOT_FOUND,
            "unknown_http_proxy",
            "HTTP proxy policy does not exist",
        ))?;
        (old, updated)
    };
    http_proxy_tunnel::stop_policy(&state, old_policy.id);
    record_audit(
        &state,
        "http_proxy.policy.updated",
        &proxy_id.to_string(),
        &format!(
            "client={}; port={}; name={}; username={}",
            policy.client_id, policy.public_port, policy.name, policy.username
        ),
    );
    Ok(Json(policy))
}

async fn set_http_proxy_enabled(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(proxy_id): Path<Uuid>,
    Json(request): Json<EnableTunnelRequest>,
) -> Result<StatusCode, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    let updated = state
        .tunnel_catalog
        .lock()
        .expect("tunnel catalog lock poisoned")
        .set_http_proxy_enabled(proxy_id, request.enabled)
        .map_err(coded_http_proxy_policy_error)?;
    if !updated {
        return Err(CodedApiError(
            StatusCode::NOT_FOUND,
            "unknown_http_proxy",
            "HTTP proxy policy does not exist",
        ));
    }
    if !request.enabled {
        http_proxy_tunnel::stop_policy(&state, proxy_id);
    }
    record_audit(
        &state,
        "http_proxy.policy.updated",
        &proxy_id.to_string(),
        if request.enabled {
            "enabled"
        } else {
            "disabled"
        },
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_http_proxy(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(proxy_id): Path<Uuid>,
) -> Result<StatusCode, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    let deleted = state
        .tunnel_catalog
        .lock()
        .expect("tunnel catalog lock poisoned")
        .delete_http_proxy(proxy_id)
        .map_err(coded_http_proxy_policy_error)?;
    if deleted.is_none() {
        return Err(CodedApiError(
            StatusCode::NOT_FOUND,
            "unknown_http_proxy",
            "HTTP proxy policy does not exist",
        ));
    }
    http_proxy_tunnel::stop_policy(&state, proxy_id);
    state
        .http_proxy_statistics
        .lock()
        .expect("HTTP proxy statistics lock poisoned")
        .remove(&proxy_id);
    record_audit(
        &state,
        "http_proxy.policy.deleted",
        &proxy_id.to_string(),
        "policy deleted",
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn list_udp_tunnels(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<UdpTunnelView>>, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    let policies = state
        .tunnel_catalog
        .lock()
        .expect("tunnel catalog lock poisoned")
        .list_udp()
        .map_err(coded_udp_policy_error)?;
    let online = state
        .udp_tunnels
        .lock()
        .expect("UDP tunnel registry lock poisoned");
    let statistics = state
        .udp_tunnel_statistics
        .lock()
        .expect("UDP tunnel statistics lock poisoned");
    Ok(Json(
        policies
            .into_iter()
            .map(|policy| {
                let tunnel_statistics = statistics
                    .get(&policy.id)
                    .map(|value| value.snapshot())
                    .unwrap_or_default();
                let is_online = online
                    .get(&policy.public_port)
                    .is_some_and(|registration| registration.policy_id == policy.id);
                UdpTunnelView {
                    online: is_online,
                    active_sessions: tunnel_statistics.active_sessions,
                    packets_from_public: tunnel_statistics.packets_from_public,
                    packets_to_public: tunnel_statistics.packets_to_public,
                    bytes_from_public: tunnel_statistics.bytes_from_public,
                    bytes_to_public: tunnel_statistics.bytes_to_public,
                    dropped_packets: tunnel_statistics.dropped_packets,
                    dropped_bandwidth_limit: tunnel_statistics.dropped_bandwidth_limit,
                    dropped_policy_session_limit: tunnel_statistics.dropped_policy_limit,
                    dropped_global_session_limit: tunnel_statistics.dropped_global_limit,
                    dropped_oversized: tunnel_statistics.dropped_oversized,
                    dropped_malformed: tunnel_statistics.dropped_malformed,
                    dropped_unknown_session: tunnel_statistics.dropped_unknown_session,
                    dropped_queue_full: tunnel_statistics.dropped_queue_full,
                    reassembly_timeouts: tunnel_statistics.reassembly_timeouts,
                    session_timeouts: tunnel_statistics.session_timeouts,
                    attach_timeouts: tunnel_statistics.attach_timeouts,
                    transport_errors: tunnel_statistics.transport_errors,
                    policy,
                }
            })
            .collect(),
    ))
}

async fn create_udp_tunnel(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<CreateUdpTunnelPolicy>,
) -> Result<(StatusCode, Json<UdpTunnelPolicy>), CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    if state.udp_data_plane.is_none() {
        return Err(CodedApiError(
            StatusCode::CONFLICT,
            "udp_relay_disabled",
            "UDP relay is not configured on this server",
        ));
    }
    if !state
        .clients
        .lock()
        .expect("client registry lock poisoned")
        .contains(request.client_id)
    {
        return Err(CodedApiError(
            StatusCode::BAD_REQUEST,
            "unknown_client",
            "unknown client for UDP tunnel policy",
        ));
    }
    let policy = state
        .tunnel_catalog
        .lock()
        .expect("tunnel catalog lock poisoned")
        .create_udp(request)
        .map_err(coded_udp_policy_error)?;
    record_audit(
        &state,
        "udp_tunnel.policy.created",
        &policy.id.to_string(),
        &format!(
            "client={}; port={}; name={}",
            policy.client_id, policy.public_port, policy.name
        ),
    );
    Ok((StatusCode::CREATED, Json(policy)))
}

async fn update_udp_tunnel(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(tunnel_id): Path<Uuid>,
    Json(request): Json<UpdateUdpTunnelPolicy>,
) -> Result<Json<UdpTunnelPolicy>, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    if state.udp_data_plane.is_none() {
        return Err(CodedApiError(
            StatusCode::CONFLICT,
            "udp_relay_disabled",
            "UDP relay is not configured on this server",
        ));
    }
    if !state
        .clients
        .lock()
        .expect("client registry lock poisoned")
        .contains(request.client_id)
    {
        return Err(CodedApiError(
            StatusCode::BAD_REQUEST,
            "unknown_client",
            "unknown client for UDP tunnel policy",
        ));
    }
    let (old_policy, policy) = {
        let mut catalog = state
            .tunnel_catalog
            .lock()
            .expect("tunnel catalog lock poisoned");
        let old = catalog
            .udp_policy_by_id(tunnel_id)
            .map_err(coded_udp_policy_error)?;
        let updated = catalog
            .update_udp(tunnel_id, request)
            .map_err(coded_udp_policy_error)?;
        let old = old.ok_or(CodedApiError(
            StatusCode::NOT_FOUND,
            "unknown_udp_tunnel",
            "UDP tunnel policy does not exist",
        ))?;
        let updated = updated.ok_or(CodedApiError(
            StatusCode::NOT_FOUND,
            "unknown_udp_tunnel",
            "UDP tunnel policy does not exist",
        ))?;
        (old, updated)
    };
    udp_tunnel::stop_public_port(&state, old_policy.public_port);
    record_audit(
        &state,
        "udp_tunnel.policy.updated",
        &tunnel_id.to_string(),
        &format!(
            "client={}; port={}; target={}; name={}",
            policy.client_id, policy.public_port, policy.target_addr, policy.name
        ),
    );
    Ok(Json(policy))
}

async fn set_udp_tunnel_enabled(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(tunnel_id): Path<Uuid>,
    Json(request): Json<EnableTunnelRequest>,
) -> Result<StatusCode, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    let policy = state
        .tunnel_catalog
        .lock()
        .expect("tunnel catalog lock poisoned")
        .list_udp()
        .map_err(coded_udp_policy_error)?
        .into_iter()
        .find(|policy| policy.id == tunnel_id)
        .ok_or(CodedApiError(
            StatusCode::NOT_FOUND,
            "unknown_udp_tunnel",
            "UDP tunnel policy does not exist",
        ))?;
    let updated = state
        .tunnel_catalog
        .lock()
        .expect("tunnel catalog lock poisoned")
        .set_udp_enabled(tunnel_id, request.enabled)
        .map_err(coded_udp_policy_error)?;
    if !updated {
        return Err(CodedApiError(
            StatusCode::NOT_FOUND,
            "unknown_udp_tunnel",
            "UDP tunnel policy does not exist",
        ));
    }
    if !request.enabled {
        udp_tunnel::stop_public_port(&state, policy.public_port);
    }
    record_audit(
        &state,
        "udp_tunnel.policy.updated",
        &tunnel_id.to_string(),
        if request.enabled {
            "enabled"
        } else {
            "disabled"
        },
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_udp_tunnel(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(tunnel_id): Path<Uuid>,
) -> Result<StatusCode, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    let policy = state
        .tunnel_catalog
        .lock()
        .expect("tunnel catalog lock poisoned")
        .list_udp()
        .map_err(coded_udp_policy_error)?
        .into_iter()
        .find(|policy| policy.id == tunnel_id)
        .ok_or(CodedApiError(
            StatusCode::NOT_FOUND,
            "unknown_udp_tunnel",
            "UDP tunnel policy does not exist",
        ))?;
    if !state
        .tunnel_catalog
        .lock()
        .expect("tunnel catalog lock poisoned")
        .delete_udp(tunnel_id)
        .map_err(coded_udp_policy_error)?
    {
        return Err(CodedApiError(
            StatusCode::NOT_FOUND,
            "unknown_udp_tunnel",
            "UDP tunnel policy does not exist",
        ));
    }
    udp_tunnel::stop_public_port(&state, policy.public_port);
    state
        .udp_tunnel_statistics
        .lock()
        .expect("UDP tunnel statistics lock poisoned")
        .remove(&policy.id);
    record_audit(
        &state,
        "udp_tunnel.policy.deleted",
        &tunnel_id.to_string(),
        "policy deleted",
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn list_port_groups(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<PortGroupView>>, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    let groups = {
        let catalog = state
            .tunnel_catalog
            .lock()
            .expect("tunnel catalog lock poisoned");
        catalog
            .list_port_groups()
            .map_err(coded_port_group_policy_error)?
            .into_iter()
            .map(|policy| {
                let mappings = catalog
                    .port_group_mappings(policy.id)
                    .map_err(coded_port_group_policy_error)?;
                Ok((policy, mappings))
            })
            .collect::<Result<Vec<_>, CodedApiError>>()?
    };
    let tcp_online = state.tunnels.lock().expect("tunnel registry lock poisoned");
    let tcp_statistics = state
        .tunnel_statistics
        .lock()
        .expect("tunnel statistics lock poisoned");
    let udp_online = state
        .udp_tunnels
        .lock()
        .expect("UDP tunnel registry lock poisoned");
    let udp_statistics = state
        .udp_tunnel_statistics
        .lock()
        .expect("UDP tunnel statistics lock poisoned");

    Ok(Json(
        groups
            .into_iter()
            .map(|(policy, mappings)| match policy.protocol {
                PortGroupProtocol::Tcp => {
                    let online_mappings = mappings
                        .iter()
                        .filter(|mapping| tcp_online.contains_key(&mapping.public_port))
                        .count();
                    let active_connections = mappings
                        .iter()
                        .filter_map(|mapping| tcp_statistics.get(&mapping.public_port))
                        .map(|statistics| statistics.active_connections.load(Ordering::Relaxed))
                        .sum();
                    let bytes_from_public = mappings
                        .iter()
                        .filter_map(|mapping| tcp_statistics.get(&mapping.public_port))
                        .map(|statistics| statistics.bytes_from_public.load(Ordering::Relaxed))
                        .sum();
                    let bytes_to_public = mappings
                        .iter()
                        .filter_map(|mapping| tcp_statistics.get(&mapping.public_port))
                        .map(|statistics| statistics.bytes_to_public.load(Ordering::Relaxed))
                        .sum();
                    PortGroupView {
                        policy,
                        mappings,
                        online_mappings,
                        active_connections,
                        active_sessions: 0,
                        bytes_from_public,
                        bytes_to_public,
                        packets_from_public: 0,
                        packets_to_public: 0,
                    }
                }
                PortGroupProtocol::Udp => {
                    let online_mappings = mappings
                        .iter()
                        .filter(|mapping| {
                            udp_online
                                .get(&mapping.public_port)
                                .is_some_and(|registration| registration.policy_id == policy.id)
                        })
                        .count();
                    let statistics = udp_statistics
                        .get(&policy.id)
                        .map(|statistics| statistics.snapshot())
                        .unwrap_or_default();
                    PortGroupView {
                        policy,
                        mappings,
                        online_mappings,
                        active_connections: 0,
                        active_sessions: statistics.active_sessions,
                        bytes_from_public: statistics.bytes_from_public,
                        bytes_to_public: statistics.bytes_to_public,
                        packets_from_public: statistics.packets_from_public,
                        packets_to_public: statistics.packets_to_public,
                    }
                }
            })
            .collect(),
    ))
}

async fn create_port_group(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<CreatePortGroupPolicy>,
) -> Result<(StatusCode, Json<PortGroupPolicy>), CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    if request.protocol == PortGroupProtocol::Udp && state.udp_data_plane.is_none() {
        return Err(CodedApiError(
            StatusCode::CONFLICT,
            "udp_relay_disabled",
            "UDP relay is not configured on this server",
        ));
    }
    if !state
        .clients
        .lock()
        .expect("client registry lock poisoned")
        .contains(request.client_id)
    {
        return Err(CodedApiError(
            StatusCode::BAD_REQUEST,
            "unknown_client",
            "unknown client for port group policy",
        ));
    }
    let policy = state
        .tunnel_catalog
        .lock()
        .expect("tunnel catalog lock poisoned")
        .create_port_group(request)
        .map_err(coded_port_group_policy_error)?;
    record_audit(
        &state,
        "port_group.policy.created",
        &policy.id.to_string(),
        &format!(
            "client={}; protocol={:?}; public_ports={}; target={}:{}; name={}",
            policy.client_id,
            policy.protocol,
            policy.public_ports,
            policy.target_host,
            policy.target_ports,
            policy.name
        ),
    );
    Ok((StatusCode::CREATED, Json(policy)))
}

async fn update_port_group(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(group_id): Path<Uuid>,
    Json(request): Json<UpdatePortGroupPolicy>,
) -> Result<Json<PortGroupPolicy>, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    if request.protocol == PortGroupProtocol::Udp && state.udp_data_plane.is_none() {
        return Err(CodedApiError(
            StatusCode::CONFLICT,
            "udp_relay_disabled",
            "UDP relay is not configured on this server",
        ));
    }
    if !state
        .clients
        .lock()
        .expect("client registry lock poisoned")
        .contains(request.client_id)
    {
        return Err(CodedApiError(
            StatusCode::BAD_REQUEST,
            "unknown_client",
            "unknown client for port group policy",
        ));
    }
    let (old_policy, old_mappings, policy) = {
        let mut catalog = state
            .tunnel_catalog
            .lock()
            .expect("tunnel catalog lock poisoned");
        let old = catalog
            .port_group_by_id(group_id)
            .map_err(coded_port_group_policy_error)?
            .ok_or(CodedApiError(
                StatusCode::NOT_FOUND,
                "unknown_port_group",
                "port group policy does not exist",
            ))?;
        let old_mappings = catalog
            .port_group_mappings(group_id)
            .map_err(coded_port_group_policy_error)?;
        let updated = catalog
            .update_port_group(group_id, request)
            .map_err(coded_port_group_policy_error)?
            .ok_or(CodedApiError(
                StatusCode::NOT_FOUND,
                "unknown_port_group",
                "port group policy does not exist",
            ))?;
        (old, old_mappings, updated)
    };
    stop_port_group(&state, old_policy.protocol, &old_mappings);
    match old_policy.protocol {
        PortGroupProtocol::Tcp => {
            let mut statistics = state
                .tunnel_statistics
                .lock()
                .expect("tunnel statistics lock poisoned");
            for mapping in &old_mappings {
                statistics.remove(&mapping.public_port);
            }
        }
        PortGroupProtocol::Udp => {
            state
                .udp_tunnel_statistics
                .lock()
                .expect("UDP tunnel statistics lock poisoned")
                .remove(&group_id);
        }
    }
    record_audit(
        &state,
        "port_group.policy.updated",
        &group_id.to_string(),
        &format!(
            "client={}; protocol={:?}; public_ports={}; target={}:{}; name={}",
            policy.client_id,
            policy.protocol,
            policy.public_ports,
            policy.target_host,
            policy.target_ports,
            policy.name
        ),
    );
    Ok(Json(policy))
}

async fn set_port_group_enabled(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(group_id): Path<Uuid>,
    Json(request): Json<EnableTunnelRequest>,
) -> Result<StatusCode, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    let (policy, mappings) = {
        let mut catalog = state
            .tunnel_catalog
            .lock()
            .expect("tunnel catalog lock poisoned");
        let policy = catalog
            .port_group_by_id(group_id)
            .map_err(coded_port_group_policy_error)?
            .ok_or(CodedApiError(
                StatusCode::NOT_FOUND,
                "unknown_port_group",
                "port group policy does not exist",
            ))?;
        let mappings = catalog
            .port_group_mappings(group_id)
            .map_err(coded_port_group_policy_error)?;
        catalog
            .set_port_group_enabled(group_id, request.enabled)
            .map_err(coded_port_group_policy_error)?;
        (policy, mappings)
    };
    if !request.enabled {
        stop_port_group(&state, policy.protocol, &mappings);
    }
    record_audit(
        &state,
        "port_group.policy.updated",
        &group_id.to_string(),
        if request.enabled {
            "enabled"
        } else {
            "disabled"
        },
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_port_group(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(group_id): Path<Uuid>,
) -> Result<StatusCode, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    let (policy, mappings) = {
        let mut catalog = state
            .tunnel_catalog
            .lock()
            .expect("tunnel catalog lock poisoned");
        let mappings = catalog
            .port_group_mappings(group_id)
            .map_err(coded_port_group_policy_error)?;
        let policy = catalog
            .delete_port_group(group_id)
            .map_err(coded_port_group_policy_error)?
            .ok_or(CodedApiError(
                StatusCode::NOT_FOUND,
                "unknown_port_group",
                "port group policy does not exist",
            ))?;
        (policy, mappings)
    };
    stop_port_group(&state, policy.protocol, &mappings);
    match policy.protocol {
        PortGroupProtocol::Tcp => {
            let mut statistics = state
                .tunnel_statistics
                .lock()
                .expect("tunnel statistics lock poisoned");
            for mapping in &mappings {
                statistics.remove(&mapping.public_port);
            }
        }
        PortGroupProtocol::Udp => {
            state
                .udp_tunnel_statistics
                .lock()
                .expect("UDP tunnel statistics lock poisoned")
                .remove(&group_id);
        }
    }
    record_audit(
        &state,
        "port_group.policy.deleted",
        &group_id.to_string(),
        "policy deleted",
    );
    Ok(StatusCode::NO_CONTENT)
}

fn stop_port_group(
    state: &Arc<AppState>,
    protocol: PortGroupProtocol,
    mappings: &[PortGroupMapping],
) {
    for mapping in mappings {
        match protocol {
            PortGroupProtocol::Tcp => tcp_tunnel::stop_public_port(state, mapping.public_port),
            PortGroupProtocol::Udp => udp_tunnel::stop_public_port(state, mapping.public_port),
        }
    }
}

async fn list_http_routes(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<HttpRouteView>>, ApiError> {
    authorize_management(&state, &headers)?;
    let policies = state
        .http_route_catalog
        .lock()
        .expect("HTTP route catalog lock poisoned")
        .list()
        .map_err(|_| {
            ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not read HTTP route policies",
            )
        })?;
    let online = state
        .http_routes
        .lock()
        .expect("HTTP route registry lock poisoned")
        .keys()
        .cloned()
        .collect::<HashSet<_>>();
    let statistics = state
        .http_route_statistics
        .lock()
        .expect("HTTP route statistics lock poisoned");
    let certificate_catalog = state
        .certificate_catalog
        .lock()
        .expect("certificate catalog lock poisoned");
    Ok(Json(
        policies
            .into_iter()
            .map(|policy| {
                let route_statistics = statistics.get(&policy.hostname);
                let tls_policy = certificate_catalog.get_route_tls(policy.id).unwrap_or(None);
                let certificate = certificate_catalog
                    .get_certificate_state(policy.id)
                    .unwrap_or(None);
                let http2_backend = route_statistics.map(|value| value.http2_backend.clone());
                HttpRouteView {
                    online: online.contains(&policy.hostname),
                    active_connections: route_statistics
                        .map_or(0, |value| value.active_connections.load(Ordering::Relaxed)),
                    requests_total: route_statistics
                        .map_or(0, |value| value.requests_total.load(Ordering::Relaxed)),
                    failed_requests: route_statistics
                        .map_or(0, |value| value.failed_requests.load(Ordering::Relaxed)),
                    bytes_from_public: route_statistics
                        .map_or(0, |value| value.bytes_from_public.load(Ordering::Relaxed)),
                    bytes_to_public: route_statistics
                        .map_or(0, |value| value.bytes_to_public.load(Ordering::Relaxed)),
                    pairing_timeouts: route_statistics
                        .map_or(0, |value| value.pairing_timeouts.load(Ordering::Relaxed)),
                    capabilities: HttpTransportCapabilitiesView::default(),
                    http2_active_streams: route_statistics.map_or(0, |value| {
                        value.http2_active_streams.load(Ordering::Relaxed)
                    }),
                    http2_requests_total: route_statistics.map_or(0, |value| {
                        value.http2_requests_total.load(Ordering::Relaxed)
                    }),
                    grpc_active_streams: route_statistics
                        .map_or(0, |value| value.grpc_active_streams.load(Ordering::Relaxed)),
                    grpc_requests_total: route_statistics
                        .map_or(0, |value| value.grpc_requests_total.load(Ordering::Relaxed)),
                    grpc_trailers_total: route_statistics
                        .map_or(0, |value| value.grpc_trailers_total.load(Ordering::Relaxed)),
                    grpc_failures_total: route_statistics
                        .map_or(0, |value| value.grpc_failures_total.load(Ordering::Relaxed)),
                    grpc_cancellations_total: route_statistics.map_or(0, |value| {
                        value.grpc_cancellations_total.load(Ordering::Relaxed)
                    }),
                    http2_backend_active_connections: http2_backend
                        .as_ref()
                        .map_or(0, |value| value.active_connections.load(Ordering::Relaxed)),
                    http2_backend_active_streams: http2_backend
                        .as_ref()
                        .map_or(0, |value| value.active_streams.load(Ordering::Relaxed)),
                    http2_backend_connections_total: http2_backend
                        .as_ref()
                        .map_or(0, |value| value.connections_total.load(Ordering::Relaxed)),
                    http2_backend_reused_total: http2_backend
                        .as_ref()
                        .map_or(0, |value| value.reused_total.load(Ordering::Relaxed)),
                    http2_backend_reconnects_total: http2_backend
                        .as_ref()
                        .map_or(0, |value| value.reconnects_total.load(Ordering::Relaxed)),
                    http2_backend_goaway_total: http2_backend
                        .as_ref()
                        .map_or(0, |value| value.goaway_total.load(Ordering::Relaxed)),
                    http2_backend_failures_total: http2_backend
                        .as_ref()
                        .map_or(0, |value| value.failures_total.load(Ordering::Relaxed)),
                    http2_backend_pool_exhausted_total: http2_backend.as_ref().map_or(0, |value| {
                        value.pool_exhausted_total.load(Ordering::Relaxed)
                    }),
                    tls: route_tls_view(&state, &policy.hostname, tls_policy, certificate),
                    policy,
                }
            })
            .collect(),
    ))
}

async fn list_sni_routes(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<SniRouteView>>, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    let policies = state
        .sni_route_catalog
        .lock()
        .expect("SNI route catalog lock poisoned")
        .list()
        .map_err(coded_sni_route_policy_error)?;
    let online = state
        .sni_routes
        .lock()
        .expect("SNI route registry lock poisoned");
    let statistics = state
        .sni_route_statistics
        .lock()
        .expect("SNI route statistics lock poisoned");
    Ok(Json(
        policies
            .into_iter()
            .map(|policy| {
                let current = statistics.get(&policy.hostname);
                SniRouteView {
                    online: online.contains_key(&policy.hostname),
                    active_connections: current
                        .map_or(0, |value| value.active_connections.load(Ordering::Relaxed)),
                    connections_total: current
                        .map_or(0, |value| value.connections_total.load(Ordering::Relaxed)),
                    rejected_connections: current.map_or(0, |value| {
                        value.rejected_connections.load(Ordering::Relaxed)
                    }),
                    client_hello_errors: current
                        .map_or(0, |value| value.client_hello_errors.load(Ordering::Relaxed)),
                    unknown_sni: current
                        .map_or(0, |value| value.unknown_sni.load(Ordering::Relaxed)),
                    bytes_from_public: current
                        .map_or(0, |value| value.bytes_from_public.load(Ordering::Relaxed)),
                    bytes_to_public: current
                        .map_or(0, |value| value.bytes_to_public.load(Ordering::Relaxed)),
                    pairing_timeouts: current
                        .map_or(0, |value| value.pairing_timeouts.load(Ordering::Relaxed)),
                    transfer_errors: current
                        .map_or(0, |value| value.transfer_errors.load(Ordering::Relaxed)),
                    lifetime_timeouts: current
                        .map_or(0, |value| value.lifetime_timeouts.load(Ordering::Relaxed)),
                    policy,
                }
            })
            .collect(),
    ))
}

async fn create_sni_route(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<CreateSniRoutePolicy>,
) -> Result<(StatusCode, Json<SniRoutePolicy>), CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    if !state
        .clients
        .lock()
        .expect("client registry lock poisoned")
        .contains(request.client_id)
    {
        return Err(CodedApiError(
            StatusCode::BAD_REQUEST,
            "unknown_client",
            "unknown client for TLS SNI route",
        ));
    }
    let policy = state
        .sni_route_catalog
        .lock()
        .expect("SNI route catalog lock poisoned")
        .create(request)
        .map_err(coded_sni_route_policy_error)?;
    record_audit(
        &state,
        "sni_route.policy.created",
        &policy.id.to_string(),
        &format!(
            "client={}; hostname={}; target={}; name={}",
            policy.client_id, policy.hostname, policy.target_addr, policy.name
        ),
    );
    Ok((StatusCode::CREATED, Json(policy)))
}

async fn update_sni_route(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(route_id): Path<Uuid>,
    Json(request): Json<UpdateSniRoutePolicy>,
) -> Result<Json<SniRoutePolicy>, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    if !state
        .clients
        .lock()
        .expect("client registry lock poisoned")
        .contains(request.client_id)
    {
        return Err(CodedApiError(
            StatusCode::BAD_REQUEST,
            "unknown_client",
            "unknown client for TLS SNI route",
        ));
    }
    let (old_policy, policy) = {
        let mut catalog = state
            .sni_route_catalog
            .lock()
            .expect("SNI route catalog lock poisoned");
        let old = catalog
            .policy_by_id(route_id)
            .map_err(coded_sni_route_policy_error)?
            .ok_or(CodedApiError(
                StatusCode::NOT_FOUND,
                "unknown_sni_route",
                "TLS SNI route does not exist",
            ))?;
        let updated = catalog
            .update(route_id, request)
            .map_err(coded_sni_route_policy_error)?
            .ok_or(CodedApiError(
                StatusCode::NOT_FOUND,
                "unknown_sni_route",
                "TLS SNI route does not exist",
            ))?;
        (old, updated)
    };
    sni_tunnel::stop_hostname(&state, &old_policy.hostname);
    record_audit(
        &state,
        "sni_route.policy.updated",
        &route_id.to_string(),
        &format!(
            "client={}; hostname={}; target={}; name={}",
            policy.client_id, policy.hostname, policy.target_addr, policy.name
        ),
    );
    Ok(Json(policy))
}

async fn set_sni_route_enabled(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(route_id): Path<Uuid>,
    Json(request): Json<EnableTunnelRequest>,
) -> Result<StatusCode, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    let policy = state
        .sni_route_catalog
        .lock()
        .expect("SNI route catalog lock poisoned")
        .policy_by_id(route_id)
        .map_err(coded_sni_route_policy_error)?
        .ok_or(CodedApiError(
            StatusCode::NOT_FOUND,
            "unknown_sni_route",
            "TLS SNI route does not exist",
        ))?;
    state
        .sni_route_catalog
        .lock()
        .expect("SNI route catalog lock poisoned")
        .set_enabled(route_id, request.enabled)
        .map_err(coded_sni_route_policy_error)?;
    if !request.enabled {
        sni_tunnel::stop_hostname(&state, &policy.hostname);
    }
    record_audit(
        &state,
        "sni_route.policy.updated",
        &route_id.to_string(),
        if request.enabled {
            "enabled"
        } else {
            "disabled"
        },
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_sni_route(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(route_id): Path<Uuid>,
) -> Result<StatusCode, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    let policy = state
        .sni_route_catalog
        .lock()
        .expect("SNI route catalog lock poisoned")
        .delete(route_id)
        .map_err(coded_sni_route_policy_error)?
        .ok_or(CodedApiError(
            StatusCode::NOT_FOUND,
            "unknown_sni_route",
            "TLS SNI route does not exist",
        ))?;
    sni_tunnel::stop_hostname(&state, &policy.hostname);
    state
        .sni_route_statistics
        .lock()
        .expect("SNI route statistics lock poisoned")
        .remove(&policy.hostname);
    record_audit(
        &state,
        "sni_route.policy.deleted",
        &route_id.to_string(),
        "policy deleted",
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn create_http_route(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<CreateHttpRoutePolicy>,
) -> Result<Json<HttpRoutePolicy>, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    if !state
        .clients
        .lock()
        .expect("client registry lock poisoned")
        .contains(request.client_id)
    {
        return Err(CodedApiError(
            StatusCode::BAD_REQUEST,
            "unknown_client",
            "unknown client for HTTP route",
        ));
    }
    let certificate_jobs = state
        .certificate_jobs
        .lock()
        .expect("certificate jobs lock poisoned");
    let policy = state
        .http_route_catalog
        .lock()
        .expect("HTTP route catalog lock poisoned")
        .create(request)
        .map_err(coded_http_route_creation_error)?;
    drop(certificate_jobs);
    record_audit(
        &state,
        "http_route.policy.created",
        &policy.id.to_string(),
        &format!(
            "client={}; hostname={}; name={}",
            policy.client_id, policy.hostname, policy.name
        ),
    );
    Ok(Json(policy))
}

async fn update_http_route(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(route_id): Path<Uuid>,
    Json(request): Json<UpdateHttpRoutePolicy>,
) -> Result<Json<HttpRoutePolicy>, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    if !state
        .clients
        .lock()
        .expect("client registry lock poisoned")
        .contains(request.client_id)
    {
        return Err(CodedApiError(
            StatusCode::BAD_REQUEST,
            "unknown_client",
            "unknown client for HTTP route",
        ));
    }
    let certificate_jobs = state
        .certificate_jobs
        .lock()
        .expect("certificate jobs lock poisoned");
    let (old_policy, tls_policy) = {
        let catalog = state
            .http_route_catalog
            .lock()
            .expect("HTTP route catalog lock poisoned");
        let old = catalog
            .policy_by_id(route_id)
            .map_err(coded_http_route_creation_error)?
            .ok_or(CodedApiError(
                StatusCode::NOT_FOUND,
                "unknown_http_route",
                "unknown HTTP route",
            ))?;
        if certificate_jobs.contains_key(&old.hostname) {
            return Err(CodedApiError(
                StatusCode::CONFLICT,
                "certificate_operation_in_progress",
                "certificate operation is already in progress",
            ));
        }
        let tls_policy = state
            .certificate_catalog
            .lock()
            .expect("certificate catalog lock poisoned")
            .get_route_tls(route_id)
            .map_err(coded_certificate_catalog_error)?;
        (old, tls_policy)
    };
    let policy = state
        .http_route_catalog
        .lock()
        .expect("HTTP route catalog lock poisoned")
        .update(route_id, request)
        .map_err(coded_http_route_creation_error)?
        .ok_or(CodedApiError(
            StatusCode::NOT_FOUND,
            "unknown_http_route",
            "unknown HTTP route",
        ))?;
    drop(certificate_jobs);

    // 无论是否更换主机名，都停止旧注册以应用新的目标和连接限制。
    http_tunnel::stop_hostname(&state, &old_policy.hostname);
    if old_policy.hostname != policy.hostname {
        state
            .http_route_statistics
            .lock()
            .expect("HTTP route statistics lock poisoned")
            .remove(&old_policy.hostname);
        state
            .https_redirect_hosts
            .lock()
            .expect("HTTPS redirect registry lock poisoned")
            .remove(&old_policy.hostname);
        if let Some(manager) = &state.certificate_manager {
            if let Err(error) = manager.delete_certificate(&old_policy.hostname) {
                tracing::warn!(
                    "could not delete certificate files for {}: {error}",
                    old_policy.hostname
                );
            }
        }
        state
            .certificate_catalog
            .lock()
            .expect("certificate catalog lock poisoned")
            .delete_certificate_state(route_id)
            .map_err(coded_certificate_catalog_error)?;
    }
    // 主机名未更换时保留现有证书；更换主机名后由证书维护任务重新签发。
    if old_policy.hostname != policy.hostname
        && tls_policy.is_some_and(|tls| tls.mode == RouteTlsMode::Disabled)
    {
        state
            .https_redirect_hosts
            .lock()
            .expect("HTTPS redirect registry lock poisoned")
            .remove(&policy.hostname);
    }
    record_audit(
        &state,
        "http_route.policy.updated",
        &route_id.to_string(),
        &format!(
            "client={}; hostname={}; target={}; name={}",
            policy.client_id, policy.hostname, policy.target_addr, policy.name
        ),
    );
    Ok(Json(policy))
}

async fn set_http_route_enabled(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(route_id): Path<Uuid>,
    Json(request): Json<EnableTunnelRequest>,
) -> Result<StatusCode, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    let hostname = state
        .http_route_catalog
        .lock()
        .expect("HTTP route catalog lock poisoned")
        .hostname_for_id(route_id)
        .map_err(|_| {
            CodedApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "could not read HTTP route policy",
            )
        })?;
    let certificate_jobs = state
        .certificate_jobs
        .lock()
        .expect("certificate jobs lock poisoned");
    if !request.enabled
        && hostname
            .as_deref()
            .is_some_and(|hostname| certificate_jobs.contains_key(hostname))
    {
        return Err(CodedApiError(
            StatusCode::CONFLICT,
            "certificate_operation_in_progress",
            "certificate operation is already in progress",
        ));
    }
    let updated = state
        .http_route_catalog
        .lock()
        .expect("HTTP route catalog lock poisoned")
        .set_enabled(route_id, request.enabled)
        .map_err(|_| {
            CodedApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "could not update HTTP route policy",
            )
        })?;
    if !updated {
        return Err(CodedApiError(
            StatusCode::NOT_FOUND,
            "unknown_http_route",
            "unknown HTTP route",
        ));
    }
    if !request.enabled {
        if let Some(hostname) = hostname.as_deref() {
            http_tunnel::stop_hostname(&state, hostname);
            state
                .https_redirect_hosts
                .lock()
                .expect("HTTPS redirect registry lock poisoned")
                .remove(hostname);
            if let Some(manager) = &state.certificate_manager {
                manager.remove_certificate(hostname);
            }
        }
    } else if let Some(hostname) = hostname.as_deref() {
        let should_load = {
            let catalog = state
                .certificate_catalog
                .lock()
                .expect("certificate catalog lock poisoned");
            catalog
                .get_route_tls(route_id)
                .ok()
                .flatten()
                .is_some_and(|policy| policy.mode == RouteTlsMode::Acme)
                && catalog
                    .get_certificate_state(route_id)
                    .ok()
                    .flatten()
                    .is_some_and(|certificate| !certificate.expired_at(unix_seconds() as i64))
        };
        if should_load {
            if let Some(manager) = &state.certificate_manager {
                if let Err(error) = manager.load_certificate(hostname) {
                    tracing::warn!("could not reload certificate for {hostname}: {error}");
                }
            }
        }
        let should_redirect = state
            .certificate_catalog
            .lock()
            .expect("certificate catalog lock poisoned")
            .get_route_tls(route_id)
            .ok()
            .flatten()
            .is_some_and(|policy| {
                policy.mode == RouteTlsMode::Acme && policy.redirect_http_to_https
            });
        if should_redirect {
            state
                .https_redirect_hosts
                .lock()
                .expect("HTTPS redirect registry lock poisoned")
                .insert(hostname.to_owned());
        }
    }
    drop(certificate_jobs);
    record_audit(
        &state,
        "http_route.policy.updated",
        &route_id.to_string(),
        if request.enabled {
            "enabled"
        } else {
            "disabled"
        },
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_http_route(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(route_id): Path<Uuid>,
) -> Result<StatusCode, CodedApiError> {
    authorize_management(&state, &headers).map_err(coded_management_error)?;
    let hostname = state
        .http_route_catalog
        .lock()
        .expect("HTTP route catalog lock poisoned")
        .hostname_for_id(route_id)
        .map_err(|_| {
            CodedApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "could not read HTTP route policy",
            )
        })?;
    let certificate_jobs = state
        .certificate_jobs
        .lock()
        .expect("certificate jobs lock poisoned");
    if hostname
        .as_deref()
        .is_some_and(|hostname| certificate_jobs.contains_key(hostname))
    {
        return Err(CodedApiError(
            StatusCode::CONFLICT,
            "certificate_operation_in_progress",
            "certificate operation is already in progress",
        ));
    }
    let deleted = state
        .http_route_catalog
        .lock()
        .expect("HTTP route catalog lock poisoned")
        .delete(route_id)
        .map_err(|_| {
            CodedApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "could not delete HTTP route policy",
            )
        })?;
    if !deleted {
        return Err(CodedApiError(
            StatusCode::NOT_FOUND,
            "unknown_http_route",
            "unknown HTTP route",
        ));
    }
    if let Some(hostname) = hostname {
        http_tunnel::stop_hostname(&state, &hostname);
        state
            .http_route_statistics
            .lock()
            .expect("HTTP route statistics lock poisoned")
            .remove(&hostname);
        state
            .https_redirect_hosts
            .lock()
            .expect("HTTPS redirect registry lock poisoned")
            .remove(&hostname);
        if let Some(manager) = &state.certificate_manager {
            if let Err(error) = manager.delete_certificate(&hostname) {
                tracing::warn!("could not delete certificate files for {hostname}: {error}");
            }
        }
    }
    {
        let mut certificate_catalog = state
            .certificate_catalog
            .lock()
            .expect("certificate catalog lock poisoned");
        certificate_catalog
            .delete_route_tls(route_id)
            .map_err(coded_certificate_catalog_error)?;
        certificate_catalog
            .delete_certificate_state(route_id)
            .map_err(coded_certificate_catalog_error)?;
    }
    drop(certificate_jobs);
    record_audit(
        &state,
        "http_route.policy.deleted",
        &route_id.to_string(),
        "policy deleted",
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn enroll_client(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<ClientEnrollmentRequest>,
) -> Result<Json<ClientEnrollmentResponse>, ApiError> {
    if !state.lifecycle.accepts_new_work() {
        return Err(ApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "server is not accepting new client enrollments",
        ));
    }
    authorize(&headers, &state.enrollment_token)?;
    request
        .validate()
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "invalid client registration"))?;

    let client_name = request.name.clone();
    let platform = request.platform.clone();
    let (client_id, client_token) = state
        .clients
        .lock()
        .expect("client registry lock poisoned")
        .enroll(request.name, request.platform)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "could not store client"))?;
    record_audit(
        &state,
        "client.enrolled",
        &client_id.to_string(),
        &format!("name={client_name}; platform={platform}"),
    );
    Ok(Json(ClientEnrollmentResponse {
        client_id,
        client_token,
    }))
}

async fn login(
    State(state): State<Arc<AppState>>,
    ConnectInfo(remote_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(request): Json<LoginRequest>,
) -> Result<Response, CodedApiError> {
    let LoginRequest {
        username,
        password,
        totp_code,
    } = request;
    let throttle_identity = login_throttle_identity(&username);
    let hash_permit = state
        .login_hash_permits
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| {
            CodedApiError(
                StatusCode::SERVICE_UNAVAILABLE,
                "login_unavailable",
                "administrator login is unavailable",
            )
        })?;
    // 获取唯一密码哈希许可后重新读取退避时间，避免排队请求绕过前一次失败刚设置的节流。
    let throttle_delay = state
        .login_throttle
        .lock()
        .expect("login throttle lock poisoned")
        .delay(&throttle_identity, Instant::now());
    if !throttle_delay.is_zero() {
        tokio::time::sleep(throttle_delay).await;
    }
    let auth_state = state.clone();
    let login_username = username.clone();
    let login_remote_addr = remote_addr.ip().to_string();
    let login_user_agent = headers
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let session = tokio::task::spawn_blocking(move || {
        let _hash_permit = hash_permit;
        auth_state
            .admin_auth
            .lock()
            .expect("administrator registry lock poisoned")
            .login_with_context(
                &login_username,
                &password,
                totp_code.as_deref(),
                Some(&login_remote_addr),
                login_user_agent.as_deref(),
            )
    })
    .await
    .map_err(|_| {
        CodedApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "login_execution_failed",
            "could not execute administrator login",
        )
    })?
    .map_err(|_| {
        CodedApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "session_creation_failed",
            "could not create session",
        )
    })?;
    let session = match session {
        LoginAttempt::Success(session) => session,
        LoginAttempt::TotpRequired => {
            return Err(CodedApiError(
                StatusCode::UNAUTHORIZED,
                "totp_required",
                "a TOTP verification code is required",
            ));
        }
        LoginAttempt::InvalidCredentials => {
            state
                .login_throttle
                .lock()
                .expect("login throttle lock poisoned")
                .record_failure(&throttle_identity, Instant::now());
            state
                .metrics
                .authentication_failures_total
                .fetch_add(1, Ordering::Relaxed);
            record_audit(
                &state,
                "management.login.failed",
                "unknown",
                "invalid credentials",
            );
            return Err(CodedApiError(
                StatusCode::UNAUTHORIZED,
                "invalid_credentials",
                "invalid username or password",
            ));
        }
    };
    state
        .login_throttle
        .lock()
        .expect("login throttle lock poisoned")
        .record_success(&throttle_identity);
    record_audit(&state, "management.login", &username, "session created");
    let mut response = Json(LoginResponse {
        session_id: session.session_id,
        username,
        display_name: session.display_name,
        role: session.role,
        authentication_type: SESSION_AUTHENTICATION_TYPE,
        expires_unix_seconds: session.expires_unix_seconds,
        password_change_required: session.password_change_required,
        totp_enabled: session.totp_enabled,
    })
    .into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        session_cookie_header(
            &session.cookie_value,
            state.management_cookies_secure,
            false,
        ),
    );
    Ok(response)
}

fn login_throttle_identity(username: &str) -> String {
    if (3..=64).contains(&username.len())
        && username.bytes().all(|character| {
            character.is_ascii_alphanumeric() || character == b'_' || character == b'-'
        })
    {
        username.to_ascii_lowercase()
    } else {
        "__invalid__".to_owned()
    }
}

async fn auth_me(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<AuthMeResponse>, ApiError> {
    let session = management_session_cookie(&headers).ok_or(ApiError(
        StatusCode::UNAUTHORIZED,
        "missing management session",
    ))?;
    let identity = state
        .admin_auth
        .lock()
        .expect("administrator registry lock poisoned")
        .authenticate_session(&session)
        .map_err(|_| {
            ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not verify session",
            )
        })?
        .ok_or(ApiError(
            StatusCode::UNAUTHORIZED,
            "invalid management session",
        ))?;
    Ok(Json(auth_me_response(identity)))
}

fn auth_me_response(identity: SessionIdentity) -> AuthMeResponse {
    AuthMeResponse {
        session_id: identity.session_id,
        username: identity.username,
        display_name: identity.display_name,
        role: identity.role,
        authentication_type: SESSION_AUTHENTICATION_TYPE,
        expires_unix_seconds: identity.expires_unix_seconds,
        password_change_required: identity.password_change_required,
        totp_enabled: identity.totp_enabled,
    }
}

async fn setup_totp(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<TotpSetupResponse>, CodedApiError> {
    let principal = require_interactive_session(&state, &headers)?;
    let secret = state
        .admin_auth
        .lock()
        .expect("administrator registry lock poisoned")
        .begin_totp(&principal.username)
        .map_err(user_management_error)?
        .ok_or(CodedApiError(
            StatusCode::NOT_FOUND,
            "unknown_user",
            "user does not exist",
        ))?;
    let provisioning_uri = format!(
        "otpauth://totp/LinkLake:{}?secret={}&issuer=LinkLake&algorithm=SHA1&digits=6&period=30",
        principal.username, secret
    );
    record_audit(
        &state,
        "management.totp.setup_started",
        &principal.username,
        "TOTP setup secret generated",
    );
    Ok(Json(TotpSetupResponse {
        secret,
        provisioning_uri,
    }))
}

async fn enable_totp(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<TotpCodeRequest>,
) -> Result<StatusCode, CodedApiError> {
    let principal = require_interactive_session(&state, &headers)?;
    let session_id = principal.session_id.expect("interactive session has an id");
    let enabled = state
        .admin_auth
        .lock()
        .expect("administrator registry lock poisoned")
        .enable_totp(&principal.username, session_id, &request.code)
        .map_err(user_management_error)?;
    if !enabled {
        return Err(CodedApiError(
            StatusCode::BAD_REQUEST,
            "invalid_totp_code",
            "the TOTP verification code is invalid",
        ));
    }
    record_audit(
        &state,
        "management.totp.enabled",
        &principal.username,
        "TOTP enabled",
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn disable_totp(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<TotpCodeRequest>,
) -> Result<StatusCode, CodedApiError> {
    let principal = require_interactive_session(&state, &headers)?;
    let disabled = state
        .admin_auth
        .lock()
        .expect("administrator registry lock poisoned")
        .disable_totp(&principal.username, &request.code)
        .map_err(user_management_error)?;
    if !disabled {
        return Err(CodedApiError(
            StatusCode::BAD_REQUEST,
            "invalid_totp_code",
            "the TOTP verification code is invalid or TOTP is not enabled",
        ));
    }
    record_audit(
        &state,
        "management.totp.disabled",
        &principal.username,
        "TOTP disabled",
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn list_users(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<UserRecord>>, CodedApiError> {
    require_administrator(&state, &headers)?;
    state
        .admin_auth
        .lock()
        .expect("administrator registry lock poisoned")
        .list_users()
        .map(Json)
        .map_err(user_management_error)
}

async fn create_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<CreateUser>,
) -> Result<(StatusCode, Json<UserRecord>), CodedApiError> {
    let principal = require_administrator(&state, &headers)?;
    let username = request.username.clone();
    let role = request.role;
    let user = state
        .admin_auth
        .lock()
        .expect("administrator registry lock poisoned")
        .create_user(request)
        .map_err(user_management_error)?;
    record_audit(
        &state,
        "management.user.created",
        &username,
        &format!("actor={}; role={}", principal.username, role.as_str()),
    );
    Ok((StatusCode::CREATED, Json(user)))
}

async fn update_user(
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
    headers: HeaderMap,
    Json(request): Json<UpdateUser>,
) -> Result<Json<UserRecord>, CodedApiError> {
    let principal = require_administrator(&state, &headers)?;
    let user = state
        .admin_auth
        .lock()
        .expect("administrator registry lock poisoned")
        .update_user(&principal.username, &username, request)
        .map_err(user_management_error)?
        .ok_or(CodedApiError(
            StatusCode::NOT_FOUND,
            "unknown_user",
            "user does not exist",
        ))?;
    record_audit(
        &state,
        "management.user.updated",
        &username,
        &format!("actor={}", principal.username),
    );
    Ok(Json(user))
}

async fn delete_user(
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, CodedApiError> {
    let principal = require_administrator(&state, &headers)?;
    let deleted = state
        .admin_auth
        .lock()
        .expect("administrator registry lock poisoned")
        .delete_user(&principal.username, &username)
        .map_err(user_management_error)?;
    if !deleted {
        return Err(CodedApiError(
            StatusCode::NOT_FOUND,
            "unknown_user",
            "user does not exist",
        ));
    }
    record_audit(
        &state,
        "management.user.deleted",
        &username,
        &format!("actor={}", principal.username),
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn reset_user_password(
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
    headers: HeaderMap,
    Json(request): Json<ResetUserPasswordRequest>,
) -> Result<StatusCode, CodedApiError> {
    let principal = require_administrator(&state, &headers)?;
    let reset = state
        .admin_auth
        .lock()
        .expect("administrator registry lock poisoned")
        .reset_user_password(
            &username,
            &request.new_password,
            request.force_password_change,
        )
        .map_err(user_management_error)?;
    if !reset {
        return Err(CodedApiError(
            StatusCode::NOT_FOUND,
            "unknown_user",
            "user does not exist",
        ));
    }
    record_audit(
        &state,
        "management.user.password_reset",
        &username,
        &format!("actor={}", principal.username),
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn revoke_user_sessions(
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
    headers: HeaderMap,
) -> Result<StatusCode, CodedApiError> {
    let principal = require_administrator(&state, &headers)?;
    let revoked = state
        .admin_auth
        .lock()
        .expect("administrator registry lock poisoned")
        .revoke_user_sessions(&username)
        .map_err(user_management_error)?;
    if !revoked {
        return Err(CodedApiError(
            StatusCode::NOT_FOUND,
            "unknown_user",
            "user does not exist",
        ));
    }
    record_audit(
        &state,
        "management.user.sessions_revoked",
        &username,
        &format!("actor={}", principal.username),
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn list_sessions(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<SessionRecord>>, CodedApiError> {
    require_administrator(&state, &headers)?;
    state
        .admin_auth
        .lock()
        .expect("administrator registry lock poisoned")
        .list_sessions()
        .map(Json)
        .map_err(user_management_error)
}

async fn list_api_tokens(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<api_tokens::ApiTokenRecord>>, CodedApiError> {
    require_administrator(&state, &headers)?;
    state
        .api_tokens
        .lock()
        .expect("API token catalog lock poisoned")
        .list()
        .map(Json)
        .map_err(coded_api_token_error)
}

async fn create_api_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<CreateApiToken>,
) -> Result<(StatusCode, Json<CreatedApiToken>), CodedApiError> {
    let principal = require_administrator(&state, &headers)?;
    let created = state
        .api_tokens
        .lock()
        .expect("API token catalog lock poisoned")
        .create(request, unix_seconds())
        .map_err(coded_api_token_error)?;
    record_audit(
        &state,
        "management.api_token.created",
        &created.record.id.to_string(),
        &format!(
            "actor={}; scope={}",
            principal.username, created.record.scope
        ),
    );
    Ok((StatusCode::CREATED, Json(created)))
}

async fn revoke_api_token(
    State(state): State<Arc<AppState>>,
    Path(token_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<StatusCode, CodedApiError> {
    let principal = require_administrator(&state, &headers)?;
    if !state
        .api_tokens
        .lock()
        .expect("API token catalog lock poisoned")
        .revoke(token_id)
        .map_err(coded_api_token_error)?
    {
        return Err(CodedApiError(
            StatusCode::NOT_FOUND,
            "unknown_api_token",
            "API token does not exist",
        ));
    }
    record_audit(
        &state,
        "management.api_token.revoked",
        &token_id.to_string(),
        &format!("actor={}", principal.username),
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn revoke_session(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<StatusCode, CodedApiError> {
    let principal = require_administrator(&state, &headers)?;
    let current_session_id = principal.session_id.ok_or(CodedApiError(
        StatusCode::FORBIDDEN,
        "session_authentication_required",
        "session management requires an interactive administrator login",
    ))?;
    let revoked = state
        .admin_auth
        .lock()
        .expect("administrator registry lock poisoned")
        .revoke_session(current_session_id, session_id)
        .map_err(user_management_error)?;
    if !revoked {
        return Err(CodedApiError(
            StatusCode::NOT_FOUND,
            "unknown_session",
            "session does not exist",
        ));
    }
    record_audit(
        &state,
        "management.session.revoked",
        &session_id.to_string(),
        &format!("actor={}", principal.username),
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn change_password(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<ChangePasswordRequest>,
) -> Result<StatusCode, ApiError> {
    let session = management_session_cookie(&headers).ok_or(ApiError(
        StatusCode::UNAUTHORIZED,
        "missing management session",
    ))?;
    let changed = state
        .admin_auth
        .lock()
        .expect("administrator registry lock poisoned")
        .change_password(&session, &request.new_password)
        .map_err(|error| {
            if error.to_string().contains("at least 12 characters") {
                ApiError(
                    StatusCode::BAD_REQUEST,
                    "new password must contain at least 12 characters",
                )
            } else {
                ApiError(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "could not change password",
                )
            }
        })?;
    if !changed {
        return Err(ApiError(
            StatusCode::UNAUTHORIZED,
            "invalid management session",
        ));
    }
    record_audit(
        &state,
        "management.password.changed",
        "administrator",
        "password updated",
    );
    Ok(StatusCode::NO_CONTENT)
}

async fn logout(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let session = management_session_cookie(&headers).ok_or(ApiError(
        StatusCode::UNAUTHORIZED,
        "missing management session",
    ))?;
    let mut admin_auth = state
        .admin_auth
        .lock()
        .expect("administrator registry lock poisoned");
    let authenticated = admin_auth.authenticate_session(&session).map_err(|_| {
        ApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "could not verify session",
        )
    })?;
    if authenticated.is_none() {
        return Err(ApiError(
            StatusCode::UNAUTHORIZED,
            "invalid management session",
        ));
    }
    admin_auth
        .logout(&session)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "could not end session"))?;
    drop(admin_auth);
    record_audit(
        &state,
        "management.logout",
        "administrator",
        "session ended",
    );
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        session_cookie_header("", state.management_cookies_secure, true),
    );
    Ok(response)
}

async fn heartbeat(
    State(state): State<Arc<AppState>>,
    Path(client_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<HeartbeatResponse>, ApiError> {
    let token =
        bearer_token(&headers).ok_or(ApiError(StatusCode::UNAUTHORIZED, "missing bearer token"))?;
    let authentication = state
        .clients
        .lock()
        .expect("client registry lock poisoned")
        .authenticate_and_touch(client_id, token)
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "could not update client"))?;
    match authentication {
        Authentication::Authenticated => {}
        Authentication::UnknownClient => {
            state
                .metrics
                .authentication_failures_total
                .fetch_add(1, Ordering::Relaxed);
            return Err(ApiError(StatusCode::NOT_FOUND, "unknown client"));
        }
        Authentication::DisabledClient => {
            state
                .metrics
                .authentication_failures_total
                .fetch_add(1, Ordering::Relaxed);
            return Err(ApiError(
                StatusCode::FORBIDDEN,
                "client identity is disabled",
            ));
        }
        Authentication::InvalidToken => {
            state
                .metrics
                .authentication_failures_total
                .fetch_add(1, Ordering::Relaxed);
            return Err(ApiError(StatusCode::UNAUTHORIZED, "invalid client token"));
        }
    }
    Ok(Json(HeartbeatResponse {
        server_time_unix_seconds: unix_seconds(),
    }))
}

fn authorize(headers: &HeaderMap, expected_token: &str) -> Result<(), ApiError> {
    let token =
        bearer_token(headers).ok_or(ApiError(StatusCode::UNAUTHORIZED, "missing bearer token"))?;
    if token == expected_token {
        Ok(())
    } else {
        Err(ApiError(
            StatusCode::UNAUTHORIZED,
            "invalid enrollment token",
        ))
    }
}

#[derive(Clone)]
struct ManagementPrincipal {
    username: String,
    role: UserRole,
    session_id: Option<Uuid>,
}

fn management_principal(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<ManagementPrincipal, ApiError> {
    if state
        .management_token
        .as_deref()
        .is_some_and(|token| bearer_token(headers) == Some(token))
    {
        return Ok(ManagementPrincipal {
            username: "management-token".to_owned(),
            role: UserRole::Administrator,
            session_id: None,
        });
    }
    if let Some(token) = bearer_token(headers) {
        let record = state
            .api_tokens
            .lock()
            .expect("API token catalog lock poisoned")
            .authenticate(token, unix_seconds())
            .map_err(|_| {
                ApiError(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "could not verify API token",
                )
            })?;
        if let Some(record) = record {
            let role = match record.scope {
                ApiTokenScope::Read => UserRole::Auditor,
                ApiTokenScope::Write => UserRole::Operator,
                ApiTokenScope::Administrator => UserRole::Administrator,
            };
            return Ok(ManagementPrincipal {
                username: format!("api-token:{}", record.name),
                role,
                session_id: None,
            });
        }
    }
    let identity = management_session_cookie(headers)
        .map(|session| {
            state
                .admin_auth
                .lock()
                .expect("administrator registry lock poisoned")
                .authenticate_session(&session)
        })
        .transpose()
        .map_err(|_| {
            ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not verify session",
            )
        })?
        .flatten();
    let Some(identity) = identity else {
        tracing::warn!("Management API authorization failed");
        return Err(ApiError(
            StatusCode::UNAUTHORIZED,
            "management login required",
        ));
    };
    if identity.password_change_required {
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            "password change required before management access",
        ));
    }
    Ok(ManagementPrincipal {
        username: identity.username,
        role: identity.role,
        session_id: Some(identity.session_id),
    })
}

fn require_administrator(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<ManagementPrincipal, CodedApiError> {
    let principal = management_principal(state, headers).map_err(coded_management_error)?;
    if principal.role != UserRole::Administrator {
        return Err(CodedApiError(
            StatusCode::FORBIDDEN,
            "administrator_required",
            "administrator role is required",
        ));
    }
    Ok(principal)
}

fn require_interactive_session(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<ManagementPrincipal, CodedApiError> {
    let principal = management_principal(state, headers).map_err(coded_management_error)?;
    if principal.session_id.is_none() {
        return Err(CodedApiError(
            StatusCode::FORBIDDEN,
            "session_authentication_required",
            "this operation requires an interactive login",
        ));
    }
    Ok(principal)
}

async fn enforce_management_role(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    let public = path == "/"
        || path == "/api/v1/health"
        || path == "/livez"
        || path == "/readyz"
        || path == "/startupz"
        || path == "/api/v1/health/live"
        || path == "/api/v1/health/ready"
        || path == "/api/v1/health/startup"
        || path == "/api/v1/auth/login"
        || path == "/api/v1/auth/me"
        || path == "/api/v1/auth/logout"
        || path == "/api/v1/auth/change-password"
        || path == "/api/v1/clients/enroll"
        || (path.starts_with("/api/v1/clients/") && path.ends_with("/heartbeat"));
    if public || !path.starts_with("/api/v1/") {
        return next.run(request).await;
    }

    let users_or_sessions = path == "/api/v1/users"
        || path.starts_with("/api/v1/users/")
        || path == "/api/v1/sessions"
        || path.starts_with("/api/v1/sessions/");
    let write = !matches!(
        *request.method(),
        Method::GET | Method::HEAD | Method::OPTIONS
    );
    if write
        && management_session_cookie(request.headers()).is_some()
        && bearer_token(request.headers()).is_none()
        && request
            .headers()
            .get("x-linklake-csrf")
            .and_then(|value| value.to_str().ok())
            != Some("1")
    {
        return CodedApiError(
            StatusCode::FORBIDDEN,
            "csrf_check_failed",
            "state-changing session requests require the LinkLake CSRF header",
        )
        .into_response();
    }
    if users_or_sessions || write {
        match management_principal(&state, request.headers()) {
            Ok(principal)
                if principal.role == UserRole::Administrator
                    || (!users_or_sessions && principal.role == UserRole::Operator) => {}
            Ok(_) => {
                return CodedApiError(
                    StatusCode::FORBIDDEN,
                    "insufficient_role",
                    "the current role cannot perform this operation",
                )
                .into_response();
            }
            Err(error) => return coded_management_error(error).into_response(),
        }
    }
    next.run(request).await
}

fn authorize_management(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    management_principal(state, headers).map(|_| ())
}

fn user_management_error(error: anyhow::Error) -> CodedApiError {
    let message = error.to_string();
    if message.contains("username must")
        || (message.contains("username") && message.contains("invalid"))
    {
        CodedApiError(
            StatusCode::BAD_REQUEST,
            "invalid_username",
            "username is invalid",
        )
    } else if message.contains("display name") {
        CodedApiError(
            StatusCode::BAD_REQUEST,
            "invalid_display_name",
            "display name is invalid",
        )
    } else if message.contains("at least 12 characters") {
        CodedApiError(
            StatusCode::BAD_REQUEST,
            "invalid_password",
            "password must contain at least 12 characters",
        )
    } else if message.contains("already exists") {
        CodedApiError(
            StatusCode::CONFLICT,
            "duplicate_username",
            "username already exists",
        )
    } else if message.contains("current user") || message.contains("current session") {
        CodedApiError(
            StatusCode::CONFLICT,
            "current_user_protected",
            "the current user or session is protected",
        )
    } else if message.contains("last administrator") {
        CodedApiError(
            StatusCode::CONFLICT,
            "last_administrator_protected",
            "the last enabled administrator is protected",
        )
    } else {
        tracing::error!("User registry operation failed: {message}");
        CodedApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "user_storage_error",
            "user registry operation failed",
        )
    }
}

fn coded_alert_error(error: anyhow::Error) -> CodedApiError {
    let message = error.to_string();
    if message.contains("alert rule name")
        || message.contains("alert threshold")
        || message.contains("alert evaluation window")
        || message.contains("alert cooldown")
        || message.contains("alert target")
    {
        CodedApiError(
            StatusCode::BAD_REQUEST,
            "invalid_alert_rule",
            "alert rule is invalid",
        )
    } else {
        tracing::error!("Alert catalog operation failed: {message}");
        CodedApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "alert_storage_error",
            "alert catalog operation failed",
        )
    }
}

fn coded_fleet_error(error: anyhow::Error) -> CodedApiError {
    let message = error.to_string();
    if message.contains("fleet peer") || message.contains("UNIQUE constraint") {
        CodedApiError(
            StatusCode::BAD_REQUEST,
            "invalid_fleet_peer",
            "fleet peer configuration is invalid or duplicated",
        )
    } else {
        tracing::error!("Fleet catalog operation failed: {message}");
        CodedApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "fleet_storage_error",
            "fleet catalog operation failed",
        )
    }
}

fn coded_traffic_control_error(error: anyhow::Error) -> CodedApiError {
    let message = error.to_string();
    if message.contains("invalid")
        || message.contains("CIDR")
        || message.contains("schedule")
        || message.contains("quota")
        || message.contains("rate")
        || message.contains("weekday")
        || message.contains("too many")
    {
        CodedApiError(
            StatusCode::BAD_REQUEST,
            "invalid_traffic_control",
            "traffic control configuration is invalid",
        )
    } else {
        tracing::error!("Traffic control operation failed: {message}");
        CodedApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "traffic_control_storage_error",
            "traffic control operation failed",
        )
    }
}

fn coded_api_token_error(error: anyhow::Error) -> CodedApiError {
    let message = error.to_string();
    if message.contains("API token") || message.contains("UNIQUE constraint") {
        CodedApiError(
            StatusCode::BAD_REQUEST,
            "invalid_api_token",
            "API token configuration is invalid or duplicated",
        )
    } else {
        tracing::error!("API token catalog operation failed: {message}");
        CodedApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "api_token_storage_error",
            "API token catalog operation failed",
        )
    }
}

fn coded_client_management_error(error: anyhow::Error) -> CodedApiError {
    let message = error.to_string();
    if message.contains("client name") {
        CodedApiError(
            StatusCode::BAD_REQUEST,
            "invalid_client_name",
            "client name is invalid",
        )
    } else if message.contains("client group") {
        CodedApiError(
            StatusCode::BAD_REQUEST,
            "invalid_client_group",
            "client group is invalid",
        )
    } else if message.contains("client notes") {
        CodedApiError(
            StatusCode::BAD_REQUEST,
            "invalid_client_notes",
            "client notes are invalid",
        )
    } else if message.contains("client tag") {
        CodedApiError(
            StatusCode::BAD_REQUEST,
            "invalid_client_tags",
            "client tags are invalid",
        )
    } else {
        tracing::error!("Client registry operation failed: {message}");
        CodedApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "client_storage_error",
            "client registry operation failed",
        )
    }
}

pub(crate) fn record_audit(state: &AppState, action: &str, subject: &str, detail: &str) {
    if let Err(error) = state
        .audit
        .lock()
        .expect("audit log lock poisoned")
        .record(action, subject, detail)
    {
        tracing::error!("Could not record audit event: {error}");
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

fn management_session_cookie(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .map(str::trim)
        .find_map(|item| item.strip_prefix("linklake_session="))
        .map(ToOwned::to_owned)
}

fn session_cookie_header(value: &str, secure: bool, expired: bool) -> axum::http::HeaderValue {
    let expiration = if expired {
        "Max-Age=0"
    } else {
        "Max-Age=28800"
    };
    let secure = if secure { "; Secure" } else { "" };
    axum::http::HeaderValue::from_str(&format!(
        "linklake_session={value}; Path=/; HttpOnly; SameSite=Strict; {expiration}{secure}"
    ))
    .expect("generated session cookie must be a valid header")
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn load_control_tls(cert_path: &str, key_path: &str) -> anyhow::Result<TlsAcceptor> {
    let mut cert_file = BufReader::new(File::open(cert_path)?);
    let certificates = rustls_pemfile::certs(&mut cert_file).collect::<Result<Vec<_>, _>>()?;
    anyhow::ensure!(
        !certificates.is_empty(),
        "control certificate file contains no certificates"
    );
    let mut key_file = BufReader::new(File::open(key_path)?);
    let private_key = rustls_pemfile::private_key(&mut key_file)?
        .ok_or_else(|| anyhow::anyhow!("control key file contains no private key"))?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

#[cfg(windows)]
mod windows_service_host {
    use std::{
        ffi::OsString,
        sync::{Arc, Mutex},
        time::Duration,
    };
    use tokio::sync::oneshot;
    use windows_service::{
        define_windows_service,
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher, Result,
    };

    const SERVICE_NAME: &str = "LinkLakeServer";
    const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

    define_windows_service!(ffi_service_main, service_main);

    pub(super) fn run() -> Result<()> {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
    }

    fn service_main(_arguments: Vec<OsString>) {
        if let Err(error) = run_service() {
            tracing::error!("Windows service host failed: {error}");
        }
    }

    fn run_service() -> Result<()> {
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let shutdown_tx = Arc::new(Mutex::new(Some(shutdown_tx)));
        let event_sender = shutdown_tx.clone();
        let event_handler = move |control| match control {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            ServiceControl::Stop | ServiceControl::Shutdown => {
                if let Some(sender) = event_sender
                    .lock()
                    .expect("Windows service shutdown lock poisoned")
                    .take()
                {
                    let _ = sender.send(());
                }
                ServiceControlHandlerResult::NoError
            }
            _ => ServiceControlHandlerResult::NotImplemented,
        };
        let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;
        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;

        let exit_code = match tokio::runtime::Runtime::new() {
            Ok(runtime) => match runtime.block_on(super::run_server(Some(shutdown_rx))) {
                Ok(()) => 0,
                Err(error) => {
                    tracing::error!("LinkLake server stopped with an error: {error}");
                    1
                }
            },
            Err(error) => {
                tracing::error!("Could not create the service runtime: {error}");
                1
            }
        };
        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(exit_code),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        apply_cache_control, auth_me_response, build_metrics_history_response,
        certificate_target_matches, coded_http_route_creation_error, coded_tcp_policy_error,
        login_throttle_identity, management_session_cookie, normalize_metrics_history_step,
        parse_metrics_history_range, release_certificate_job_slot, render_prometheus_metrics,
        reserve_certificate_job_slot, select_certificate_maintenance_operation,
        session_cookie_header, tcp_history_error_total, udp_history_error_total,
        udp_metrics_response, CertificateOperation, HistoryCounters, HttpTransportCapabilitiesView,
        LoginResponse, LoginThrottle, MetricsHistory, MetricsHistoryProtocol, MetricsHistorySample,
        Socks5CapabilitiesView, UserRole, LOGIN_THROTTLE_MAX_IDENTITIES, MANAGEMENT_UI,
        METRICS_HISTORY_ARCHIVE_CAPACITY, METRICS_HISTORY_ARCHIVE_SAMPLE_INTERVAL_SECONDS,
        METRICS_HISTORY_CAPACITY, METRICS_HISTORY_RECENT_RETENTION_SECONDS,
        METRICS_HISTORY_RETENTION_SECONDS, METRICS_HISTORY_SAMPLE_INTERVAL_SECONDS,
    };
    use crate::{
        admin_auth::SessionIdentity,
        certificate_catalog::{CertificateState, CertificateStatus, RouteTlsMode, RouteTlsPolicy},
        http_route_catalog::{CreateHttpRouteError, HttpRoutePolicy},
        tcp_tunnel::TunnelStatistics,
        udp_tunnel::UdpTunnelStatisticsSnapshot,
    };
    use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
    use std::{
        collections::HashMap,
        fs,
        sync::atomic::Ordering,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };
    use uuid::Uuid;

    fn http_route(id: Uuid, hostname: &str, enabled: bool) -> HttpRoutePolicy {
        HttpRoutePolicy {
            id,
            client_id: Uuid::new_v4(),
            name: "site".to_owned(),
            hostname: hostname.to_owned(),
            target_addr: "127.0.0.1:8080".to_owned(),
            max_connections: 64,
            enabled,
        }
    }

    fn certificate_state(
        status: CertificateStatus,
        last_attempt: Option<i64>,
        failure_count: u32,
        not_after: Option<i64>,
        next_renewal: Option<i64>,
    ) -> CertificateState {
        CertificateState {
            route_id: Uuid::new_v4(),
            status,
            issuer: Some("test issuer".to_owned()),
            not_before: Some(1),
            not_after,
            next_renewal,
            last_attempt,
            last_success: None,
            failure_count,
            last_error_code: Some("test_error".to_owned()),
            last_error_message: Some("test error".to_owned()),
        }
    }

    fn history_sample(
        timestamp_unix_seconds: u64,
        tcp: HistoryCounters,
        proxy: HistoryCounters,
    ) -> MetricsHistorySample {
        MetricsHistorySample {
            timestamp_unix_seconds,
            authentication_failures_total: 0,
            tcp,
            udp: HistoryCounters::default(),
            web: HistoryCounters::default(),
            proxy,
            secret: HistoryCounters::default(),
            policies: HashMap::new(),
        }
    }

    #[test]
    fn management_session_cookie_is_parsed_without_accepting_other_cookies() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("other=value; linklake_session=session-value"),
        );
        assert_eq!(
            management_session_cookie(&headers).as_deref(),
            Some("session-value")
        );
        let header = session_cookie_header("session-value", true, false);
        let cookie = header.to_str().expect("cookie must be valid");
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("SameSite=Strict"));
    }

    #[test]
    fn cache_control_contract_covers_management_html_and_all_api_responses() {
        let mut html_headers = HeaderMap::new();
        apply_cache_control("/", &mut html_headers);
        assert_eq!(
            html_headers
                .get(header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-cache")
        );

        for path in [
            "/api/v1/auth/login",
            "/api/v1/auth/me",
            "/api/v1/metrics/history",
            "/api/v1/unknown",
        ] {
            let mut headers = HeaderMap::new();
            apply_cache_control(path, &mut headers);
            assert_eq!(
                headers
                    .get(header::CACHE_CONTROL)
                    .and_then(|value| value.to_str().ok()),
                Some("no-store, private")
            );
        }
    }

    #[test]
    fn prometheus_metrics_preserve_integer_precision_and_skip_non_numbers() {
        let output = render_prometheus_metrics(&serde_json::json!({
            "large-counter": u64::MAX,
            "active_connections": 3,
            "optional": null,
            "label": "ignored"
        }));
        assert!(output.contains("# TYPE linklake_large_counter gauge\n"));
        assert!(output.contains("linklake_large_counter 18446744073709551615\n"));
        assert!(output.contains("linklake_active_connections 3\n"));
        assert!(!output.contains("optional"));
        assert!(!output.contains("label"));
    }

    #[test]
    fn socks5_capabilities_are_explicit_and_follow_udp_relay_availability() {
        let tcp_only = serde_json::to_value(Socks5CapabilitiesView::new(false))
            .expect("SOCKS5 capabilities should serialize");
        assert_eq!(tcp_only["connect"], true);
        assert_eq!(tcp_only["udp_associate"], false);
        assert_eq!(tcp_only["bind"], false);
        assert_eq!(tcp_only["udp_fragmentation"], false);

        let tcp_and_udp = serde_json::to_value(Socks5CapabilitiesView::new(true))
            .expect("SOCKS5 capabilities should serialize");
        assert_eq!(tcp_and_udp["connect"], true);
        assert_eq!(tcp_and_udp["udp_associate"], true);
        assert_eq!(tcp_and_udp["bind"], false);
        assert_eq!(tcp_and_udp["udp_fragmentation"], false);
    }

    #[test]
    fn authenticated_identity_response_has_a_fixed_account_type_without_session_secrets() {
        let response = auth_me_response(SessionIdentity {
            session_id: Uuid::nil(),
            username: "admin".to_owned(),
            display_name: "LinkLake Admin".to_owned(),
            role: UserRole::Administrator,
            expires_unix_seconds: 123_456,
            password_change_required: false,
            totp_enabled: false,
        });
        let json = serde_json::to_value(response).expect("identity response should serialize");
        assert_eq!(json["username"], "admin");
        assert_eq!(json["role"], "administrator");
        assert_eq!(json["authentication_type"], "session");
        assert_eq!(json["expires_unix_seconds"], 123_456);
        assert_eq!(json["password_change_required"], false);
        assert!(json.get("cookie_value").is_none());
        assert!(json.get("session_secret").is_none());
        assert!(json.get("password_hash").is_none());

        let login = serde_json::to_value(LoginResponse {
            session_id: Uuid::nil(),
            username: "admin".to_owned(),
            display_name: "LinkLake Admin".to_owned(),
            role: UserRole::Administrator,
            authentication_type: "session",
            expires_unix_seconds: 123_456,
            password_change_required: false,
            totp_enabled: false,
        })
        .expect("login response should serialize");
        assert_eq!(login["username"], json["username"]);
        assert_eq!(login["role"], json["role"]);
        assert_eq!(login["authentication_type"], json["authentication_type"]);
    }

    #[test]
    fn login_throttle_applies_global_and_identity_backoff() {
        let mut throttle = LoginThrottle::default();
        let identity = login_throttle_identity("Admin");
        assert_eq!(identity, "admin");
        assert_eq!(login_throttle_identity("bad name"), "__invalid__");
        let now = Instant::now();
        assert_eq!(throttle.delay(&identity, now), Duration::ZERO);
        assert_eq!(
            throttle.record_failure(&identity, now),
            Duration::from_millis(250)
        );
        assert_eq!(throttle.delay(&identity, now), Duration::from_millis(250));
        let second = now + Duration::from_millis(250);
        assert_eq!(
            throttle.record_failure(&identity, second),
            Duration::from_millis(500)
        );
        assert_eq!(
            throttle.delay(&identity, second),
            Duration::from_millis(500)
        );
        throttle.record_success(&identity);
        assert_eq!(
            throttle.delay(&identity, second),
            Duration::from_millis(250)
        );

        let mut bounded = LoginThrottle::default();
        for index in 0..LOGIN_THROTTLE_MAX_IDENTITIES {
            bounded.record_failure(&format!("user-{index}"), now);
        }
        bounded.record_failure("one-more-user", now);
        assert!(bounded.identities.len() <= LOGIN_THROTTLE_MAX_IDENTITIES);
        assert!(bounded.identities.contains_key("__overflow__"));
    }

    #[test]
    fn history_error_totals_do_not_double_count_breakdowns() {
        let tcp = TunnelStatistics::default();
        tcp.rejected_connections.store(2, Ordering::Relaxed);
        tcp.failed_connections.store(5, Ordering::Relaxed);
        tcp.pairing_timeouts.store(3, Ordering::Relaxed);
        tcp.transfer_errors.store(1, Ordering::Relaxed);
        tcp.lifetime_timeouts.store(1, Ordering::Relaxed);
        assert_eq!(tcp_history_error_total(&tcp), 7);

        let udp = UdpTunnelStatisticsSnapshot {
            dropped_packets: 10,
            dropped_oversized: 2,
            dropped_malformed: 3,
            dropped_unknown_session: 4,
            dropped_queue_full: 1,
            dropped_policy_limit: 2,
            dropped_global_limit: 1,
            dropped_bandwidth_limit: 1,
            session_timeouts: 2,
            reassembly_timeouts: 3,
            attach_timeouts: 4,
            transport_errors: 5,
            ..UdpTunnelStatisticsSnapshot::default()
        };
        assert_eq!(udp_history_error_total(&udp), 24);
    }

    #[test]
    fn metrics_history_range_and_step_contract_is_bounded() {
        assert_eq!(parse_metrics_history_range(None), Some(("1h", 3_600, 15)));
        assert_eq!(
            parse_metrics_history_range(Some("30d")),
            Some(("30d", 2_592_000, 9_000))
        );
        assert_eq!(
            parse_metrics_history_range(Some("7d")),
            Some(("7d", 604_800, 2_100))
        );
        assert_eq!(normalize_metrics_history_step(Some(1), 300, 5, 5), Some(5));
        assert_eq!(normalize_metrics_history_step(Some(7), 300, 5, 5), Some(10));
        assert_eq!(
            normalize_metrics_history_step(Some(5), 86_400, 300, 60),
            Some(300)
        );
        assert!(normalize_metrics_history_step(Some(0), 300, 5, 5).is_none());
        assert!(normalize_metrics_history_step(Some(301), 300, 5, 5).is_none());
        assert!(
            METRICS_HISTORY_CAPACITY
                >= (METRICS_HISTORY_RECENT_RETENTION_SECONDS
                    / METRICS_HISTORY_SAMPLE_INTERVAL_SECONDS) as usize
        );
        assert!(
            METRICS_HISTORY_ARCHIVE_CAPACITY
                >= (METRICS_HISTORY_RETENTION_SECONDS
                    / METRICS_HISTORY_ARCHIVE_SAMPLE_INTERVAL_SECONDS) as usize
        );
    }

    #[test]
    fn metrics_history_ring_replaces_same_timestamp_and_evicts_oldest_sample() {
        let mut history = MetricsHistory::new(3, 3);
        for timestamp in [10, 15, 20] {
            history.push(history_sample(
                timestamp,
                HistoryCounters {
                    bytes_from_public: timestamp,
                    ..HistoryCounters::default()
                },
                HistoryCounters::default(),
            ));
        }
        history.push(history_sample(
            20,
            HistoryCounters {
                bytes_from_public: 200,
                ..HistoryCounters::default()
            },
            HistoryCounters::default(),
        ));
        assert_eq!(history.samples.len(), 3);
        assert_eq!(history.samples.back().unwrap().tcp.bytes_from_public, 200);
        history.push(history_sample(
            25,
            HistoryCounters::default(),
            HistoryCounters::default(),
        ));
        assert_eq!(history.samples.len(), 3);
        assert_eq!(history.samples.front().unwrap().timestamp_unix_seconds, 15);

        history.push(history_sample(
            5,
            HistoryCounters {
                bytes_from_public: 5,
                ..HistoryCounters::default()
            },
            HistoryCounters::default(),
        ));
        assert_eq!(history.samples.len(), 1);
        assert_eq!(history.samples.front().unwrap().timestamp_unix_seconds, 5);
    }

    #[test]
    fn metrics_history_survives_restart_and_ignores_corrupted_rows() {
        let directory =
            std::env::temp_dir().join(format!("linklake-metrics-history-{}", Uuid::new_v4()));
        fs::create_dir_all(&directory).expect("temporary directory should be created");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        {
            let mut history =
                MetricsHistory::open(Some(&directory), 8, 8).expect("history should open");
            history.push(history_sample(
                now,
                HistoryCounters {
                    bytes_from_public: 123,
                    bytes_to_public: 45,
                    ..HistoryCounters::default()
                },
                HistoryCounters::default(),
            ));
        }
        let database = rusqlite::Connection::open(directory.join("linklake.sqlite3"))
            .expect("database should open");
        database
            .execute(
                "INSERT INTO metrics_history_recent (timestamp_unix_seconds, sample_json) VALUES (?1, ?2)",
                rusqlite::params![now as i64 + 1, "{broken-json"],
            )
            .expect("corrupted test row should be inserted");
        drop(database);

        let history = MetricsHistory::open(Some(&directory), 8, 8)
            .expect("corrupted history row must not prevent restart");
        assert_eq!(history.samples.len(), 1);
        assert_eq!(history.samples[0].tcp.bytes_from_public, 123);
        assert_eq!(history.archive_samples.len(), 1);
        drop(history);
        fs::remove_dir_all(&directory).expect("temporary directory should be removed");
    }

    #[test]
    fn metrics_history_hard_limits_thirty_days_to_three_hundred_points() {
        let mut history =
            MetricsHistory::new(METRICS_HISTORY_CAPACITY, METRICS_HISTORY_ARCHIVE_CAPACITY);
        for timestamp in (0..=METRICS_HISTORY_RETENTION_SECONDS)
            .step_by(METRICS_HISTORY_ARCHIVE_SAMPLE_INTERVAL_SECONDS as usize)
        {
            history.push(history_sample(
                timestamp,
                HistoryCounters {
                    bytes_from_public: timestamp * 10,
                    bytes_to_public: timestamp * 5,
                    active_connections: timestamp % 7,
                    requests_total: timestamp,
                    errors_total: timestamp / 10,
                    ..HistoryCounters::default()
                },
                HistoryCounters::default(),
            ));
        }
        let response = build_metrics_history_response(
            &history,
            METRICS_HISTORY_RETENTION_SECONDS,
            "30d",
            METRICS_HISTORY_RETENTION_SECONDS,
            9_000,
            MetricsHistoryProtocol::Total,
        );
        assert!(response.points.len() <= 300);
        assert!(response.step_seconds >= 8_640);
    }

    #[test]
    fn metrics_history_downsamples_counters_and_keeps_protocols_isolated() {
        let mut history = MetricsHistory::new(8, 8);
        history.push(history_sample(
            100,
            HistoryCounters {
                bytes_from_public: 100,
                bytes_to_public: 100,
                active_connections: 2,
                requests_total: 10,
                errors_total: 1,
                ..HistoryCounters::default()
            },
            HistoryCounters {
                bytes_from_public: 1_000,
                bytes_to_public: 2_000,
                active_connections: 20,
                requests_total: 100,
                errors_total: 10,
                ..HistoryCounters::default()
            },
        ));
        history.push(history_sample(
            105,
            HistoryCounters {
                bytes_from_public: 150,
                bytes_to_public: 130,
                active_connections: 4,
                requests_total: 15,
                errors_total: 2,
                ..HistoryCounters::default()
            },
            HistoryCounters {
                bytes_from_public: 2_000,
                bytes_to_public: 3_000,
                active_connections: 30,
                requests_total: 200,
                errors_total: 20,
                ..HistoryCounters::default()
            },
        ));
        history.push(history_sample(
            110,
            HistoryCounters {
                bytes_from_public: 200,
                bytes_to_public: 160,
                active_connections: 6,
                requests_total: 25,
                errors_total: 4,
                ..HistoryCounters::default()
            },
            HistoryCounters {
                bytes_from_public: 3_000,
                bytes_to_public: 4_000,
                active_connections: 40,
                requests_total: 300,
                errors_total: 30,
                ..HistoryCounters::default()
            },
        ));

        let response = build_metrics_history_response(
            &history,
            120,
            "test",
            20,
            10,
            MetricsHistoryProtocol::Tcp,
        );
        assert_eq!(response.protocol, MetricsHistoryProtocol::Tcp);
        assert_eq!(response.points.len(), 1);
        let point = &response.points[0];
        assert_eq!(point.timestamp_unix_seconds, 110);
        assert_eq!(point.inbound_bps, 10.0);
        assert_eq!(point.outbound_bps, 6.0);
        assert_eq!(point.active_connections, 5);
        assert_eq!(point.active_sessions, 0);
        assert_eq!(point.requests_per_second, 1.5);
        assert_eq!(point.errors_per_second, 0.3);
        assert_eq!(point.requests_total, 25);
        assert_eq!(point.errors_total, 4);
    }

    #[test]
    fn secret_history_is_separate_from_tcp_and_included_in_total() {
        let mut history = MetricsHistory::new(4, 4);
        let mut first = history_sample(100, HistoryCounters::default(), HistoryCounters::default());
        first.secret = HistoryCounters {
            bytes_from_public: 100,
            bytes_to_public: 50,
            active_connections: 1,
            requests_total: 10,
            errors_total: 2,
            ..HistoryCounters::default()
        };
        history.push(first);
        let mut second =
            history_sample(105, HistoryCounters::default(), HistoryCounters::default());
        second.secret = HistoryCounters {
            bytes_from_public: 200,
            bytes_to_public: 100,
            active_connections: 3,
            requests_total: 20,
            errors_total: 3,
            ..HistoryCounters::default()
        };
        history.push(second);

        let secret = build_metrics_history_response(
            &history,
            110,
            "test",
            10,
            5,
            MetricsHistoryProtocol::Secret,
        );
        let total = build_metrics_history_response(
            &history,
            110,
            "test",
            10,
            5,
            MetricsHistoryProtocol::Total,
        );
        let tcp = build_metrics_history_response(
            &history,
            110,
            "test",
            10,
            5,
            MetricsHistoryProtocol::Tcp,
        );
        assert_eq!(secret.points[0].inbound_bps, 20.0);
        assert_eq!(total.points[0].inbound_bps, 20.0);
        assert_eq!(tcp.points[0].inbound_bps, 0.0);
        assert_eq!(secret.points[0].active_connections, 3);
    }

    #[test]
    fn udp_metrics_api_and_web_ui_share_the_same_fields() {
        let response = udp_metrics_response(UdpTunnelStatisticsSnapshot {
            dropped_packets: 11,
            dropped_oversized: 12,
            dropped_malformed: 13,
            dropped_unknown_session: 14,
            dropped_queue_full: 15,
            dropped_policy_limit: 16,
            dropped_global_limit: 17,
            dropped_bandwidth_limit: 18,
            attach_timeouts: 19,
            ..UdpTunnelStatisticsSnapshot::default()
        });
        let json = serde_json::to_value(response).expect("UDP metrics should serialize");
        let expected = [
            ("udp_dropped_packets", 11),
            ("udp_dropped_oversized", 12),
            ("udp_dropped_malformed", 13),
            ("udp_dropped_unknown_session", 14),
            ("udp_dropped_queue_full", 15),
            ("udp_dropped_policy_session_limit", 16),
            ("udp_dropped_global_session_limit", 17),
            ("udp_dropped_bandwidth_limit", 18),
            ("udp_attach_timeouts", 19),
        ];
        for (field, value) in expected {
            assert_eq!(json[field], value);
            assert!(
                MANAGEMENT_UI.contains(&format!("dashboard.metrics.{field}")),
                "Web UI does not consume UDP metric field {field}"
            );
        }
        for field in [
            "dropped_packets",
            "dropped_oversized",
            "dropped_malformed",
            "dropped_unknown_session",
            "dropped_queue_full",
            "attach_timeouts",
        ] {
            assert!(
                MANAGEMENT_UI.contains(&format!("policy.{field}")),
                "Web UI does not consume per-policy UDP field {field}"
            );
        }
    }

    #[test]
    fn web_ui_displays_managed_client_configuration_state() {
        for field in ["config_mode", "config_sync_status", "config_sync_error"] {
            assert!(
                MANAGEMENT_UI.contains(field),
                "Web UI does not consume client configuration field {field}"
            );
        }
    }

    #[test]
    fn web_ui_displays_tls_sni_and_p2p_runtime_state() {
        for field in [
            "sni_connections_total",
            "sni_unknown_hostname",
            "p2p_session_offers_total",
            "p2p_direct_connections_total",
            "p2p_relay_fallbacks_total",
            "age_seconds",
            "fresh",
        ] {
            assert!(
                MANAGEMENT_UI.contains(field),
                "Web UI does not consume SNI/P2P field {field}"
            );
        }
        assert!(MANAGEMENT_UI.contains("/api/v1/p2p/nodes"));
    }

    #[test]
    fn http_transport_capabilities_are_explicit_and_read_only() {
        let capabilities = serde_json::to_value(HttpTransportCapabilitiesView::default())
            .expect("HTTP transport capabilities should serialize");
        assert_eq!(capabilities["http1"], true);
        assert_eq!(capabilities["http2"], true);
        assert_eq!(capabilities["grpc"], true);
        assert_eq!(capabilities["tls_alpn"], true);
        assert_eq!(capabilities["h2c_prior_knowledge"], true);
        assert_eq!(capabilities["grpc_backend_transport"], "h2c");
    }

    #[test]
    fn web_ui_displays_http2_grpc_capabilities_without_fake_switches() {
        for marker in [
            "httpTransportCapabilities",
            "http2_active_streams",
            "http2_requests_total",
            "grpc_requests_total",
            "grpc_failures_total",
            "http2_backend_reused_total",
            "http2_backend_connections_total",
        ] {
            assert!(
                MANAGEMENT_UI.contains(marker),
                "Web UI does not consume HTTP/2 or gRPC field {marker}"
            );
        }
        assert!(!MANAGEMENT_UI.contains("{ name: 'http2'"));
        assert!(!MANAGEMENT_UI.contains("{ name: 'grpc'"));
        assert!(!MANAGEMENT_UI.contains("{ name: 'grpc_backend_transport'"));
    }

    #[test]
    fn web_ui_supports_editing_every_forwarding_policy() {
        assert!(
            MANAGEMENT_UI.contains("savePolicy(elements."),
            "Web UI does not contain the shared policy save flow"
        );
        for resource in [
            "tcp-tunnels",
            "udp-tunnels",
            "port-groups",
            "http-routes",
            "sni-routes",
            "secret-tunnels",
            "socks5-proxies",
            "http-proxies",
        ] {
            assert!(
                MANAGEMENT_UI.contains(&format!("'{resource}'")),
                "Web UI does not expose editing for {resource}"
            );
        }
        assert!(MANAGEMENT_UI.contains("method: editingId ? 'PUT' : 'POST'"));
        assert!(MANAGEMENT_UI.contains("cancelEdit"));
        assert!(MANAGEMENT_UI.contains("beginPolicyEdit"));
        assert!(MANAGEMENT_UI.contains("'edit-policy'"));
        assert!(MANAGEMENT_UI.contains("actionButton(t('editPolicy')"));
        assert!(MANAGEMENT_UI.contains("beginPolicyEdit(type, policy)"));
    }

    #[test]
    fn web_ui_explains_socks5_capabilities_without_unsupported_controls() {
        assert!(MANAGEMENT_UI.contains("socks5CapabilityText"));
        assert!(MANAGEMENT_UI.contains("socks5CapabilitiesWithUdp"));
        assert!(MANAGEMENT_UI.contains("socks5CapabilitiesTcpOnly"));
        assert!(MANAGEMENT_UI.contains("BIND and UDP FRAG are intentionally unsupported"));
        assert!(!MANAGEMENT_UI.contains("{ name: 'bind'"));
        assert!(!MANAGEMENT_UI.contains("{ name: 'udp_fragmentation'"));
    }

    #[test]
    fn web_ui_registers_visualizations_and_complete_themes() {
        let registry_start = MANAGEMENT_UI
            .find("const elements = Object.fromEntries([")
            .expect("Web UI element registry should exist");
        let registry_end = MANAGEMENT_UI[registry_start..]
            .find("].map(id =>")
            .map(|offset| registry_start + offset)
            .expect("Web UI element registry should have an end");
        let registry = &MANAGEMENT_UI[registry_start..registry_end];
        for id in [
            "overview-alert-more",
            "service-insights",
            "service-trend-title",
            "service-insight-kpis",
            "service-trend-chart",
            "service-status-chart",
            "client-insight-kpis",
            "client-status-chart",
            "client-platform-chart",
        ] {
            assert!(
                registry.contains(&format!("'{id}'")),
                "Web UI does not register element {id}"
            );
        }
        for marker in [
            "data-palette-choice=\"contrast\"",
            "html[data-scheme=\"dark\"][data-palette=\"contrast\"]",
            "html[data-scheme=\"light\"][data-palette=\"contrast\"]",
            "['lake', 'ocean', 'jade', 'violet', 'contrast']",
            "--on-primary:#000",
            "--material-name: aurora-glass",
            "--material-name: minimal-solid",
            "--material-name: jade-paper",
            "--material-name: neon-space",
            "--material-name: industrial-panel",
            "--topbar-material:",
            "--sidebar-material:",
            "--dialog-material:",
            "--menu-material:",
            "--input-material:",
            "--table-heading-material:",
            "--chart-material:",
            "--chart-grid-dash:",
            "--chart-stroke-width:",
            "--on-danger:",
            "@supports not (color: color-mix",
            "@supports not ((-webkit-backdrop-filter:",
            "@supports not (background: linear-gradient",
            "@media (prefers-reduced-transparency: reduce)",
            "-webkit-backdrop-filter:",
            "data-preview=\"lake\"",
            "class=\"preview-chart\"",
            "cssDash('--chart-grid-dash')",
            "cssNumber('--chart-stroke-width', 2)",
        ] {
            assert!(
                MANAGEMENT_UI.contains(marker),
                "Web UI is missing complete theme marker {marker}"
            );
        }
        assert!(MANAGEMENT_UI.contains("renderServiceInsights(type, visible)"));
        assert!(MANAGEMENT_UI.contains("renderClientInsights(visible)"));
        assert!(MANAGEMENT_UI.contains("drawServiceTrendChart()"));
        assert!(MANAGEMENT_UI.contains("drawClientInsightCharts()"));
        assert!(MANAGEMENT_UI.contains("drawGroupedHorizontalChart"));
        assert!(MANAGEMENT_UI.contains("data-i18n-aria-label"));
        assert!(MANAGEMENT_UI
            .contains("requestAnimationFrame(() => { resizeFrame = null; drawCharts(); })"));
        assert!(!MANAGEMENT_UI.contains("resizeTimer = setTimeout(drawCharts"));
        for id in [
            "workspace-service-actions",
            "workspace-fleet-actions",
            "workspace-user-actions",
            "workspace-alert-actions",
        ] {
            assert!(MANAGEMENT_UI.contains(&format!("id=\"{id}\"")));
        }
    }

    #[test]
    fn web_ui_limits_overview_alerts_and_links_to_alert_management() {
        let overview_start = MANAGEMENT_UI
            .find("function renderOverview()")
            .expect("overview renderer should exist");
        let overview_end = MANAGEMENT_UI[overview_start..]
            .find("function canvasSetup")
            .map(|offset| overview_start + offset)
            .expect("overview renderer should have an end");
        let overview = &MANAGEMENT_UI[overview_start..overview_end];
        assert!(overview.contains("updated_unix_seconds"));
        assert!(overview.contains(".slice(0, 5).forEach"));
        assert!(!overview.contains("alertValues.forEach"));
        assert!(MANAGEMENT_UI.contains("id=\"overview-alert-more\""));
        assert!(MANAGEMENT_UI.contains("elements.overview_alert_more.addEventListener"));
        assert!(MANAGEMENT_UI.contains("location.hash = '#/alerts'"));
    }

    #[test]
    fn web_ui_history_switching_is_cached_and_cancels_stale_requests() {
        for marker in [
            "historyCache: new Map()",
            "historyRequestGeneration",
            "historyActiveKey",
            "function loadHistory(",
            "abortActiveRequests('history')",
            "scope: 'history'",
            "state.historyCache.get(key)",
            "state.historyCache.set(key",
            "generation !== state.historyRequestGeneration",
        ] {
            assert!(
                MANAGEMENT_UI.contains(marker),
                "Web UI history loader is missing {marker}"
            );
        }
        let range_start = MANAGEMENT_UI
            .find("document.querySelectorAll('[data-trend-range]')")
            .expect("traffic range handler should exist");
        let range_end = MANAGEMENT_UI[range_start..]
            .find("document.querySelectorAll('[data-service-range]')")
            .map(|offset| range_start + offset)
            .expect("service range handler should follow traffic range handler");
        let range_handler = &MANAGEMENT_UI[range_start..range_end];
        assert!(range_handler.contains("loadHistory("));
        assert!(!range_handler.contains("loadManagementData("));
    }

    #[test]
    fn http_route_creation_errors_have_stable_api_codes() {
        let cases = [
            (
                CreateHttpRouteError::InvalidName,
                StatusCode::BAD_REQUEST,
                "invalid_name",
            ),
            (
                CreateHttpRouteError::InvalidHostname,
                StatusCode::BAD_REQUEST,
                "invalid_hostname",
            ),
            (
                CreateHttpRouteError::DuplicateHostname,
                StatusCode::CONFLICT,
                "duplicate_hostname",
            ),
            (
                CreateHttpRouteError::InvalidTarget,
                StatusCode::BAD_REQUEST,
                "invalid_target",
            ),
            (
                CreateHttpRouteError::InvalidConnectionLimit,
                StatusCode::BAD_REQUEST,
                "invalid_connection_limit",
            ),
        ];
        for (error, expected_status, expected_code) in cases {
            let response = coded_http_route_creation_error(error);
            assert_eq!(response.0, expected_status);
            assert_eq!(response.1, expected_code);
        }
    }

    #[test]
    fn tcp_policy_errors_have_stable_api_codes() {
        let cases = [
            (
                "public port is outside the permitted range",
                StatusCode::BAD_REQUEST,
                "invalid_public_port",
            ),
            (
                "public port is already assigned",
                StatusCode::CONFLICT,
                "duplicate_public_port",
            ),
            (
                "target address is invalid",
                StatusCode::BAD_REQUEST,
                "invalid_target",
            ),
        ];
        for (message, expected_status, expected_code) in cases {
            let error = coded_tcp_policy_error(anyhow::anyhow!(message));
            assert_eq!(error.0, expected_status);
            assert_eq!(error.1, expected_code);
        }
    }

    #[test]
    fn certificate_target_requires_the_same_enabled_route_and_acme_policy() {
        let route_id = Uuid::new_v4();
        let expected = http_route(route_id, "secure.example.com", true);
        let current = expected.clone();
        let policy = RouteTlsPolicy {
            route_id,
            mode: RouteTlsMode::Acme,
            redirect_http_to_https: true,
            updated_at: 1,
        };
        assert!(certificate_target_matches(
            &expected,
            Some(&current),
            Some(&policy)
        ));

        let disabled = http_route(route_id, "secure.example.com", false);
        assert!(!certificate_target_matches(
            &expected,
            Some(&disabled),
            Some(&policy)
        ));

        let replacement = http_route(Uuid::new_v4(), "secure.example.com", true);
        assert!(!certificate_target_matches(
            &expected,
            Some(&replacement),
            Some(&policy)
        ));

        let disabled_tls = RouteTlsPolicy {
            mode: RouteTlsMode::Disabled,
            ..policy
        };
        assert!(!certificate_target_matches(
            &expected,
            Some(&current),
            Some(&disabled_tls)
        ));
    }

    #[test]
    fn hostname_job_owner_blocks_recreated_route_until_old_job_releases() {
        let hostname = "secure.example.com";
        let old_route = Uuid::new_v4();
        let new_route = Uuid::new_v4();
        let mut jobs = HashMap::new();

        assert!(reserve_certificate_job_slot(&mut jobs, hostname, old_route));
        assert!(!reserve_certificate_job_slot(
            &mut jobs, hostname, new_route
        ));
        release_certificate_job_slot(&mut jobs, hostname, new_route);
        assert_eq!(jobs.get(hostname), Some(&old_route));
        release_certificate_job_slot(&mut jobs, hostname, old_route);
        assert!(reserve_certificate_job_slot(&mut jobs, hostname, new_route));
    }

    #[test]
    fn renewal_error_strictly_obeys_retry_backoff() {
        let now = 10_000;
        let certificate = certificate_state(
            CertificateStatus::Error,
            Some(now - 60),
            4,
            Some(now - 1),
            Some(now - 10_000),
        );
        assert!(certificate.renewal_due(now));
        assert_eq!(
            select_certificate_maintenance_operation(Some(&certificate), true, now),
            None
        );

        let retry_time = now + 60 * 60;
        assert_eq!(
            select_certificate_maintenance_operation(Some(&certificate), true, retry_time),
            Some(CertificateOperation::Renew)
        );
        assert_eq!(
            select_certificate_maintenance_operation(Some(&certificate), false, retry_time),
            Some(CertificateOperation::Issue)
        );
    }
}
