mod admin_auth;
mod audit_log;
mod client_registry;
mod database_tools;
mod tcp_tunnel;
mod tunnel_catalog;

use admin_auth::{AdminAuth, BootstrapCredentials};
use audit_log::{AuditEvent, AuditLog};
use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use axum_server::tls_rustls::RustlsConfig as ManagementTlsConfig;
use client_registry::{Authentication, ClientRegistry};
use linklake_core::{
    BoxedIo, ClientEnrollmentRequest, ClientEnrollmentResponse, API_VERSION, PRODUCT_NAME,
};
use serde::{Deserialize, Serialize};
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
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tokio::net::TcpListener;
use tokio::sync::{watch, Mutex as AsyncMutex, Semaphore};
use tokio_rustls::{
    rustls::{self, ServerConfig},
    TlsAcceptor,
};
use tower_http::trace::TraceLayer;
use tunnel_catalog::{CreateTcpTunnelPolicy, TcpTunnelPolicy, TunnelCatalog};
use uuid::Uuid;

const MANAGEMENT_UI: &str = include_str!("../web/index.html");
const GLOBAL_CONNECTION_LIMIT: usize = 1024;
const PENDING_CONNECTION_LIMIT: usize = 256;

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
    pending_connections: AsyncMutex<HashMap<Uuid, (Uuid, tokio::sync::oneshot::Sender<BoxedIo>)>>,
    global_connection_permits: Arc<Semaphore>,
    pending_connection_permits: Arc<Semaphore>,
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
    clients: usize,
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
    control_connections_total: u64,
    control_protocol_errors_total: u64,
    tls_handshake_failures_total: u64,
    tunnel_registrations_total: u64,
    tunnel_reconnects_total: u64,
    registration_rejections_total: u64,
    authentication_failures_total: u64,
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

struct ApiError(StatusCode, &'static str);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({ "error": self.1 }))).into_response()
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
    let control_tls = match (control_cert, control_key) {
        (Some(cert), Some(key)) => Some(load_control_tls(&cert, &key)?),
        (None, None) if control_address.ip().is_loopback() => None,
        (None, None) => anyhow::bail!("LINKLAKE_CONTROL_CERT_PATH and LINKLAKE_CONTROL_KEY_PATH are required for remote TCP control"),
        _ => anyhow::bail!("both TLS certificate and key paths are required for TCP control"),
    };
    let enrollment_token = configured_token.unwrap_or_else(|| {
        let token = Uuid::new_v4().to_string();
        tracing::warn!("Generated local development enrollment token: {token}");
        token
    });
    if data_dir.is_none() && !address.ip().is_loopback() {
        anyhow::bail!("LINKLAKE_DATA_DIR is required for remote management");
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
        pending_connections: AsyncMutex::new(HashMap::new()),
        global_connection_permits: Arc::new(Semaphore::new(GLOBAL_CONNECTION_LIMIT)),
        pending_connection_permits: Arc::new(Semaphore::new(PENDING_CONNECTION_LIMIT)),
        metrics: ServerCounters::default(),
    });
    let app = Router::new()
        .route("/", get(management_ui))
        .route("/api/v1/health", get(health))
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/logout", post(logout))
        .route("/api/v1/auth/change-password", post(change_password))
        .route("/api/v1/status", get(status))
        .route("/api/v1/metrics", get(metrics))
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
        .route("/api/v1/clients/enroll", post(enroll_client))
        .route("/api/v1/clients/:client_id/heartbeat", post(heartbeat))
        .with_state(state.clone())
        .layer(TraceLayer::new_for_http());

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
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
    Ok(Json(StatusResponse {
        product: PRODUCT_NAME,
        api_version: API_VERSION,
        instance_id: state.instance_id.clone(),
        tunnels: tunnels.len(),
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
    }))
}

async fn list_clients(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<linklake_core::ClientSummary>>, ApiError> {
    authorize_management(&state, &headers)?;
    let clients = state.clients.lock().expect("client registry lock poisoned");
    Ok(Json(clients.summaries()))
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
    use super::{management_session_cookie, session_cookie_header};
    use axum::http::{header, HeaderMap, HeaderValue};

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
}
