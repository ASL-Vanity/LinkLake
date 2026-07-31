mod admin_auth;
mod audit_log;
mod certificate_catalog;
mod certificate_manager;
mod client_registry;
mod database_migrations;
mod database_tools;
mod http_proxy_tunnel;
mod http_route_catalog;
mod http_tunnel;
mod p2p_control;
mod p2p_node_catalog;
mod secret_tunnel;
mod secret_tunnel_catalog;
mod sni_route_catalog;
mod sni_tunnel;
mod socks5_tunnel;
mod tcp_tunnel;
mod tunnel_catalog;
mod udp_data_plane;
mod udp_tunnel;

use admin_auth::{AdminAuth, BootstrapCredentials};
use audit_log::{AuditEvent, AuditLog};
use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
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
use client_registry::{Authentication, ClientRegistry};
use http_route_catalog::{
    CreateHttpRouteError, CreateHttpRoutePolicy, HttpRouteCatalog, HttpRoutePolicy,
};
use linklake_core::{
    managed_config_revision, BoxedIo, ClientEnrollmentRequest, ClientEnrollmentResponse,
    ManagedClientConfig, ManagedHttpProxy, ManagedHttpRoute, ManagedSecretTunnel,
    ManagedSocks5Proxy, ManagedTcpTunnel, ManagedTlsRoute, ManagedUdpTunnel, API_VERSION,
    PRODUCT_NAME,
};
use p2p_node_catalog::{P2pNodeCatalog, P2pNodeRecord};
use secret_tunnel_catalog::{
    CreateSecretTunnelPolicy, CreatedSecretTunnelPolicy, SecretPolicyError, SecretTunnelCatalog,
    SecretTunnelPolicy,
};
use serde::{Deserialize, Serialize};
use sni_route_catalog::{
    CreateSniRoutePolicy, SniRouteCatalog, SniRoutePolicy, SniRoutePolicyError,
};
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::BufReader,
    net::SocketAddr,
    path::PathBuf,
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
use tunnel_catalog::{
    CreateHttpProxyPolicy, CreatePortGroupPolicy, CreateSocks5ProxyPolicy, CreateTcpTunnelPolicy,
    CreateUdpTunnelPolicy, CreatedHttpProxyPolicy, CreatedSocks5ProxyPolicy, HttpProxyPolicy,
    HttpProxyPolicyError, PortGroupMapping, PortGroupPolicy, PortGroupPolicyError,
    PortGroupProtocol, Socks5PolicyError, Socks5ProxyPolicy, TcpTunnelPolicy, TunnelCatalog,
    UdpPolicyError, UdpTunnelPolicy,
};
use udp_data_plane::{UdpDataPlane, UdpDataPlaneConfig};
use uuid::Uuid;

const MANAGEMENT_UI: &str = include_str!("../web/index.html");
const GLOBAL_CONNECTION_LIMIT: usize = 1024;
const PENDING_CONNECTION_LIMIT: usize = 256;
const GLOBAL_UDP_SESSION_LIMIT: usize = 16_384;

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
    started_at: Instant,
    instance_id: String,
    enrollment_token: String,
    management_token: Option<String>,
    admin_auth: Mutex<AdminAuth>,
    audit: Mutex<AuditLog>,
    management_cookies_secure: bool,
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
}

#[derive(Serialize)]
struct HealthResponse {
    product: &'static str,
    api_version: &'static str,
    status: &'static str,
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
    socks5_active_connections: usize,
    socks5_requests_total: u64,
    socks5_authentication_failures: u64,
    socks5_rejected_connections: u64,
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
    control_connections_total: u64,
    control_protocol_errors_total: u64,
    tls_handshake_failures_total: u64,
    tunnel_registrations_total: u64,
    tunnel_reconnects_total: u64,
    registration_rejections_total: u64,
    authentication_failures_total: u64,
    http_active_connections: usize,
    http_requests_total: u64,
    http_failed_requests: u64,
    http_bytes_from_public: u64,
    http_bytes_to_public: u64,
    http_pairing_timeouts: u64,
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
}

#[derive(Serialize)]
struct LoginResponse {
    expires_unix_seconds: u64,
    password_change_required: bool,
}

#[derive(Deserialize)]
struct ChangePasswordRequest {
    new_password: String,
}

#[derive(Deserialize)]
struct AuditQuery {
    limit: Option<usize>,
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

#[derive(Serialize)]
struct Socks5ProxyView {
    #[serde(flatten)]
    policy: Socks5ProxyPolicy,
    online: bool,
    active_connections: usize,
    connections_total: u64,
    requests_total: u64,
    authentication_failures: u64,
    rejected_connections: u64,
    unsupported_commands: u64,
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
    let migration_plan = data_dir
        .as_deref()
        .map(database_migrations::prepare)
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
        started_at: Instant::now(),
        instance_id: uuid::Uuid::new_v4().to_string(),
        enrollment_token,
        management_token: configured_management_token,
        admin_auth: Mutex::new(AdminAuth::open(data_dir.as_deref(), bootstrap_admin)?),
        audit: Mutex::new(AuditLog::open(data_dir.as_deref())?),
        management_cookies_secure,
        clients: Mutex::new(ClientRegistry::open(data_dir.as_deref())?),
        tunnel_catalog: Mutex::new(TunnelCatalog::open(data_dir.as_deref())?),
        tunnels: Mutex::new(HashMap::new()),
        tunnel_statistics: Mutex::new(HashMap::new()),
        seen_tunnel_registrations: Mutex::new(HashSet::new()),
        udp_data_plane,
        udp_tunnels: Mutex::new(HashMap::new()),
        udp_tunnel_statistics: Mutex::new(HashMap::new()),
        seen_udp_tunnel_registrations: Mutex::new(HashSet::new()),
        http_route_catalog: Mutex::new(HttpRouteCatalog::open(data_dir.as_deref())?),
        http_routes: Mutex::new(HashMap::new()),
        http_route_statistics: Mutex::new(HashMap::new()),
        seen_http_route_registrations: Mutex::new(HashSet::new()),
        sni_route_catalog: Mutex::new(SniRouteCatalog::open(data_dir.as_deref())?),
        sni_routes: Mutex::new(HashMap::new()),
        sni_route_statistics: Mutex::new(HashMap::new()),
        p2p_node_catalog: Mutex::new(P2pNodeCatalog::open(data_dir.as_deref())?),
        p2p_sessions: Mutex::new(HashMap::new()),
        secret_tunnel_catalog: Mutex::new(SecretTunnelCatalog::open(data_dir.as_deref())?),
        secret_tunnels: Mutex::new(HashMap::new()),
        secret_tunnel_statistics: Mutex::new(HashMap::new()),
        socks5_proxies: Mutex::new(HashMap::new()),
        socks5_proxy_statistics: Mutex::new(HashMap::new()),
        http_proxies: Mutex::new(HashMap::new()),
        http_proxy_statistics: Mutex::new(HashMap::new()),
        certificate_catalog: Mutex::new(CertificateCatalog::open(data_dir.as_deref())?),
        certificate_manager,
        certificate_jobs: Mutex::new(HashMap::new()),
        https_redirect_hosts: Mutex::new(HashSet::new()),
        pending_connections: AsyncMutex::new(HashMap::new()),
        global_connection_permits: Arc::new(Semaphore::new(GLOBAL_CONNECTION_LIMIT)),
        pending_connection_permits: Arc::new(Semaphore::new(PENDING_CONNECTION_LIMIT)),
        global_udp_session_permits: Arc::new(Semaphore::new(GLOBAL_UDP_SESSION_LIMIT)),
        metrics: ServerCounters::default(),
    });
    if let Some(plan) = migration_plan {
        plan.finish()?;
    }
    restore_managed_certificates(&state)?;
    let app = Router::new()
        .route("/", get(management_ui))
        .route("/api/v1/health", get(health))
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/logout", post(logout))
        .route("/api/v1/auth/change-password", post(change_password))
        .route("/api/v1/status", get(status))
        .route("/api/v1/metrics", get(metrics))
        .route(
            "/api/v1/acme/config",
            get(get_acme_config).put(update_acme_config),
        )
        .route("/api/v1/clients", get(list_clients))
        .route("/api/v1/audit", get(list_audit_events))
        .route(
            "/api/v1/tcp-tunnels",
            get(list_tcp_tunnels).post(create_tcp_tunnel),
        )
        .route(
            "/api/v1/tcp-tunnels/:tunnel_id",
            axum::routing::delete(delete_tcp_tunnel),
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
            axum::routing::delete(delete_udp_tunnel),
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
            axum::routing::delete(delete_port_group),
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
            axum::routing::delete(delete_http_route),
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
            axum::routing::delete(delete_sni_route),
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
            axum::routing::delete(delete_secret_tunnel),
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
            axum::routing::delete(delete_socks5_proxy),
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
            axum::routing::delete(delete_http_proxy),
        )
        .route(
            "/api/v1/http-proxies/:proxy_id/enabled",
            post(set_http_proxy_enabled),
        )
        .route("/api/v1/clients/enroll", post(enroll_client))
        .route("/api/v1/clients/:client_id/heartbeat", post(heartbeat))
        .with_state(state.clone())
        .layer(TraceLayer::new_for_http());

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
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
    let control_listener = TcpListener::bind(control_address).await?;
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
    if let Some(http_address) = http_address {
        let http_listener = TcpListener::bind(http_address).await?;
        tracing::info!("{PRODUCT_NAME} HTTP route listener active on {http_address}");
        tokio::spawn(http_tunnel::run_http_listener(
            state.clone(),
            http_listener,
            shutdown_rx.clone(),
        ));
    }
    if let Some(https_address) = https_address {
        let certificate_manager = state
            .certificate_manager
            .as_ref()
            .expect("HTTPS requires a certificate manager");
        let https_listener = TcpListener::bind(https_address).await?;
        tracing::info!("{PRODUCT_NAME} HTTPS route listener active on {https_address}");
        tokio::spawn(http_tunnel::run_https_listener(
            state.clone(),
            https_listener,
            TlsAcceptor::from(certificate_manager.tls_config()),
            shutdown_rx.clone(),
        ));
    }
    if let Some(sni_address) = sni_address {
        let sni_listener = TcpListener::bind(sni_address).await?;
        tracing::info!("{PRODUCT_NAME} TLS SNI pass-through listener active on {sni_address}");
        tokio::spawn(sni_tunnel::run_listener(
            state.clone(),
            sni_listener,
            shutdown_rx.clone(),
        ));
    }
    if let Some(config) = management_tls {
        tracing::info!("{PRODUCT_NAME} HTTPS management listening on https://{address}");
        let handle = axum_server::Handle::new();
        let shutdown_handle = handle.clone();
        let management_shutdown = shutdown_rx.clone();
        tokio::spawn(async move {
            wait_for_shutdown(management_shutdown).await;
            shutdown_handle.graceful_shutdown(Some(std::time::Duration::from_secs(10)));
        });
        axum_server::bind_rustls(address, config)
            .handle(handle)
            .serve(app.into_make_service())
            .await?;
    } else {
        let listener = TcpListener::bind(address).await?;
        tracing::info!("{PRODUCT_NAME} development HTTP management listening on http://{address}");
        axum::serve(listener, app)
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

async fn management_ui() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        Html(MANAGEMENT_UI),
    )
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        product: PRODUCT_NAME,
        api_version: API_VERSION,
        status: "ok",
    })
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
) -> Result<Json<TcpTunnelPolicy>, ApiError> {
    authorize_management(&state, &headers)?;
    if !state
        .clients
        .lock()
        .expect("client registry lock poisoned")
        .contains(request.client_id)
    {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "unknown client for tunnel policy",
        ));
    }
    let policy = state
        .tunnel_catalog
        .lock()
        .expect("tunnel catalog lock poisoned")
        .create(request)
        .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "could not create tunnel policy"))?;
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
    Ok(Json(
        policies
            .into_iter()
            .map(|policy| {
                let current = statistics.get(&policy.id);
                Socks5ProxyView {
                    online: online.get(&policy.id).is_some_and(|registration| {
                        socks5_tunnel::online_public_port(registration) == policy.public_port
                    }),
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
    Json(request): Json<LoginRequest>,
) -> Result<Response, ApiError> {
    let session = state
        .admin_auth
        .lock()
        .expect("administrator registry lock poisoned")
        .login(&request.username, &request.password)
        .map_err(|_| {
            ApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "could not create session",
            )
        })?;
    let Some(session) = session else {
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
        return Err(ApiError(
            StatusCode::UNAUTHORIZED,
            "invalid username or password",
        ));
    };
    record_audit(
        &state,
        "management.login",
        &request.username,
        "session created",
    );
    let mut response = Json(LoginResponse {
        expires_unix_seconds: session.expires_unix_seconds,
        password_change_required: session.password_change_required,
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

fn authorize_management(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    if state
        .management_token
        .as_deref()
        .is_some_and(|token| bearer_token(headers) == Some(token))
    {
        return Ok(());
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
    if let Some(identity) = identity {
        if identity.password_change_required {
            return Err(ApiError(
                StatusCode::FORBIDDEN,
                "password change required before management access",
            ));
        }
        Ok(())
    } else {
        tracing::warn!("Management API authorization failed");
        Err(ApiError(
            StatusCode::UNAUTHORIZED,
            "management login required",
        ))
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
        certificate_target_matches, coded_http_route_creation_error, management_session_cookie,
        release_certificate_job_slot, reserve_certificate_job_slot,
        select_certificate_maintenance_operation, session_cookie_header, udp_metrics_response,
        CertificateOperation, MANAGEMENT_UI,
    };
    use crate::{
        certificate_catalog::{CertificateState, CertificateStatus, RouteTlsMode, RouteTlsPolicy},
        http_route_catalog::{CreateHttpRouteError, HttpRoutePolicy},
        udp_tunnel::UdpTunnelStatisticsSnapshot,
    };
    use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
    use std::collections::HashMap;
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
