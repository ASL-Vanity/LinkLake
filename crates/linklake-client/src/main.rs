use clap::{Parser, Subcommand};
use linklake_core::port_mapping::{parse_port_mappings, MAX_PORT_MAPPINGS};
use linklake_core::{
    managed_config_revision, read_control_frame, write_control_frame, BoxedIo,
    ClientEnrollmentRequest, ClientEnrollmentResponse, ControlFrame, ManagedClientConfig,
    ManagedConfigMode, ManagedConfigStatus, ManagedHttpProxy, ManagedHttpRoute,
    ManagedSecretTunnel, ManagedSocks5Proxy, ManagedTcpTunnel, ManagedTlsRoute, ManagedUdpTunnel,
    PRODUCT_NAME,
};
use serde::Deserialize;
use std::{
    collections::{HashMap, HashSet},
    fs::{read_to_string, File, OpenOptions},
    io::{BufReader, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{copy_bidirectional, split, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    net::{TcpListener, TcpStream},
    task::{JoinHandle, JoinSet},
    time::{interval, timeout, MissedTickBehavior},
};
use tokio_rustls::{
    rustls::{self, pki_types::ServerName, ClientConfig, RootCertStore},
    TlsConnector,
};
use uuid::Uuid;

mod p2p_iroh;
mod p2p_noise;
mod socks5_udp_agent;
mod udp_agent;

const CONTROL_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
const CONTROL_HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(30);
const TARGET_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MANAGED_CONFIG_POLL_INTERVAL: Duration = Duration::from_secs(5);
const CURRENT_CLIENT_CONFIG_VERSION: u32 = 2;

fn default_true() -> bool {
    true
}

#[derive(Parser)]
#[command(name = "linklake-client", about = "LinkLake client control utility")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 检查 LinkLake 服务端管理 API 是否可访问。
    Check {
        #[arg(long, default_value = "http://127.0.0.1:32100")]
        server: String,
    },
    /// 注册本机，并且仅输出一次客户端凭据。
    Enroll {
        #[arg(long, default_value = "http://127.0.0.1:32100")]
        server: String,
        #[arg(long)]
        token: String,
        #[arg(long)]
        name: String,
        #[arg(long, default_value = std::env::consts::OS)]
        platform: String,
    },
    /// 向已注册客户端发送控制平面心跳。
    Heartbeat {
        #[arg(long, default_value = "http://127.0.0.1:32100")]
        server: String,
        #[arg(long)]
        client_id: Uuid,
        #[arg(long)]
        token: String,
    },
    /// 运行开发用 TCP 隧道代理；明文控制通道仅允许回环地址。
    Agent {
        #[arg(long, default_value = "127.0.0.1:32101")]
        control: String,
        #[arg(long)]
        control_ca_cert: Option<PathBuf>,
        #[arg(long)]
        control_server_name: Option<String>,
        #[arg(long)]
        client_id: Uuid,
        #[arg(long)]
        token: String,
        #[arg(long)]
        public_port: u16,
        #[arg(long)]
        target: String,
        #[arg(long, default_value = "development-tcp")]
        name: String,
    },
    /// 运行开发用 HTTP 域名路由代理。
    HttpAgent {
        #[arg(long, default_value = "127.0.0.1:32101")]
        control: String,
        #[arg(long)]
        control_ca_cert: Option<PathBuf>,
        #[arg(long)]
        control_server_name: Option<String>,
        #[arg(long)]
        client_id: Uuid,
        #[arg(long)]
        token: String,
        #[arg(long)]
        hostname: String,
        #[arg(long)]
        target: String,
        #[arg(long, default_value = "development-http")]
        name: String,
    },
    /// 运行开发用 UDP 隧道代理。
    UdpAgent {
        #[arg(long, default_value = "127.0.0.1:32101")]
        control: String,
        #[arg(long)]
        control_ca_cert: Option<PathBuf>,
        #[arg(long)]
        control_server_name: Option<String>,
        #[arg(long)]
        client_id: Uuid,
        #[arg(long)]
        token: String,
        #[arg(long)]
        public_port: u16,
        #[arg(long)]
        target: String,
        #[arg(long, default_value = "development-udp")]
        name: String,
    },
    /// 运行 TOML 配置文件中声明的全部 TCP、UDP 隧道和 HTTP 路由代理。
    Run {
        #[arg(long, default_value = "linklake-client.toml")]
        config: PathBuf,
    },
    /// 把旧版 TOML 配置迁移为当前格式；输出文件必须不存在。
    MigrateConfig {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Deserialize)]
struct HealthResponse {
    product: String,
    api_version: String,
    status: String,
}

#[derive(Clone, Deserialize)]
struct ClientConfigFile {
    #[serde(default)]
    config_version: u32,
    client: Option<ClientIdentityConfig>,
    #[serde(default)]
    servers: Vec<ClientIdentityConfig>,
    #[serde(default)]
    tcp_tunnels: Vec<TcpTunnelConfig>,
    #[serde(default)]
    udp_tunnels: Vec<UdpTunnelConfig>,
    #[serde(default)]
    http_routes: Vec<HttpRouteConfig>,
    #[serde(default)]
    tls_routes: Vec<TlsRouteConfig>,
    #[serde(default)]
    secret_tunnels: Vec<SecretTunnelConfig>,
    #[serde(default)]
    secret_visitors: Vec<SecretVisitorConfig>,
    #[serde(default)]
    socks5_proxies: Vec<Socks5ProxyConfig>,
    #[serde(default)]
    http_proxies: Vec<HttpProxyConfig>,
    #[serde(default)]
    port_groups: Vec<PortGroupConfig>,
}

#[derive(Clone, Deserialize)]
struct ClientIdentityConfig {
    name: Option<String>,
    control: String,
    control_ca_cert: Option<PathBuf>,
    control_server_name: Option<String>,
    client_id: Uuid,
    client_token: String,
    #[serde(default)]
    config_mode: ManagedConfigMode,
    managed_config_path: Option<PathBuf>,
    p2p_bind: Option<String>,
    p2p_endpoint: Option<String>,
    p2p_relay_url: Option<String>,
    #[serde(default = "default_true")]
    p2p_tcp_enabled: bool,
    #[serde(default = "default_true")]
    p2p_iroh_enabled: bool,
}

#[derive(Clone)]
struct P2pProviderConfig {
    bind: String,
    endpoint: String,
    relay_url: Option<String>,
    tcp_enabled: bool,
    iroh_enabled: bool,
}

#[derive(Clone, Deserialize)]
struct TcpTunnelConfig {
    control: Option<String>,
    control_ca_cert: Option<PathBuf>,
    control_server_name: Option<String>,
    client_id: Option<Uuid>,
    client_token: Option<String>,
    public_port: u16,
    target: String,
    name: String,
}

#[derive(Clone, Deserialize)]
struct UdpTunnelConfig {
    control: Option<String>,
    control_ca_cert: Option<PathBuf>,
    control_server_name: Option<String>,
    client_id: Option<Uuid>,
    client_token: Option<String>,
    public_port: u16,
    target: String,
    name: String,
}

#[derive(Clone, Deserialize)]
struct HttpRouteConfig {
    control: Option<String>,
    control_ca_cert: Option<PathBuf>,
    control_server_name: Option<String>,
    client_id: Option<Uuid>,
    client_token: Option<String>,
    hostname: String,
    target: String,
    name: String,
}

#[derive(Clone, Deserialize)]
struct TlsRouteConfig {
    hostname: String,
    target: String,
    name: String,
}

#[derive(Clone, Deserialize)]
struct SecretTunnelConfig {
    name: String,
    target: String,
}

#[derive(Clone, Deserialize)]
struct SecretVisitorConfig {
    server: Option<String>,
    name: String,
    local_bind: String,
    access_key: String,
    #[serde(default = "default_true")]
    prefer_direct: bool,
}

#[derive(Clone, Deserialize)]
struct Socks5ProxyConfig {
    name: String,
    public_port: u16,
}

#[derive(Clone, Deserialize)]
struct HttpProxyConfig {
    name: String,
    public_port: u16,
}

#[derive(Clone, Copy, Deserialize, Hash, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum PortGroupConfigProtocol {
    Tcp,
    Udp,
}

#[derive(Clone, Deserialize)]
struct PortGroupConfig {
    name: String,
    protocol: PortGroupConfigProtocol,
    public_ports: String,
    target_host: String,
    target_ports: String,
}

#[derive(Clone, Hash, PartialEq, Eq)]
enum AgentKey {
    Tcp(String, u16),
    Udp(String, u16),
    Http(String),
    Tls(String),
    SecretTarget(String),
    SecretVisitor(String),
    Socks5(String, u16),
    HttpProxy(String, u16),
}

#[derive(Clone, PartialEq, Eq)]
enum AgentSpec {
    Tcp {
        name: String,
        public_port: u16,
        target: String,
    },
    Udp {
        name: String,
        public_port: u16,
        target: String,
    },
    Http {
        name: String,
        hostname: String,
        target: String,
    },
    Tls {
        name: String,
        hostname: String,
        target: String,
    },
    SecretTarget {
        name: String,
        target: String,
    },
    SecretVisitor {
        name: String,
        local_bind: String,
        access_key: String,
        prefer_direct: bool,
    },
    Socks5 {
        name: String,
        public_port: u16,
    },
    HttpProxy {
        name: String,
        public_port: u16,
    },
}

struct RunningAgent {
    spec: AgentSpec,
    task: JoinHandle<()>,
}

fn main() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let _log_guard = init_logging()?;
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("--windows-service")) {
        #[cfg(windows)]
        {
            let config = std::env::args_os()
                .nth(2)
                .map(PathBuf::from)
                .ok_or_else(|| anyhow::anyhow!("--windows-service requires a TOML config path"))?;
            return windows_service_host::run(config).map_err(Into::into);
        }
        #[cfg(not(windows))]
        anyhow::bail!("--windows-service is available only on Windows");
    }
    tokio::runtime::Runtime::new()?.block_on(run_cli())
}

async fn run_cli() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Check { server } => {
            let endpoint = format!("{}/api/v1/health", server.trim_end_matches('/'));
            let health: HealthResponse = reqwest::get(endpoint)
                .await?
                .error_for_status()?
                .json()
                .await?;
            anyhow::ensure!(
                health.product == PRODUCT_NAME && health.status == "ok",
                "unexpected server response"
            );
            println!(
                "{} server is healthy (API {}).",
                health.product, health.api_version
            );
        }
        Command::Enroll {
            server,
            token,
            name,
            platform,
        } => {
            let endpoint = format!("{}/api/v1/clients/enroll", server.trim_end_matches('/'));
            let registration = ClientEnrollmentRequest { name, platform };
            let response: ClientEnrollmentResponse = reqwest::Client::new()
                .post(endpoint)
                .bearer_auth(token)
                .json(&registration)
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            println!("client_id={}", response.client_id);
            println!("client_token={}", response.client_token);
            println!("Store client_token securely; it will not be returned again.");
        }
        Command::Heartbeat {
            server,
            client_id,
            token,
        } => {
            let endpoint = format!(
                "{}/api/v1/clients/{client_id}/heartbeat",
                server.trim_end_matches('/')
            );
            reqwest::Client::new()
                .post(endpoint)
                .bearer_auth(token)
                .send()
                .await?
                .error_for_status()?;
            println!("Heartbeat accepted.");
        }
        Command::Agent {
            control,
            control_ca_cert,
            control_server_name,
            client_id,
            token,
            public_port,
            target,
            name,
        } => {
            run_tcp_agent(
                ControlTransport::new(control, control_ca_cert, control_server_name)?,
                client_id,
                token,
                public_port,
                target,
                name,
            )
            .await?;
        }
        Command::HttpAgent {
            control,
            control_ca_cert,
            control_server_name,
            client_id,
            token,
            hostname,
            target,
            name,
        } => {
            run_http_agent(
                ControlTransport::new(control, control_ca_cert, control_server_name)?,
                client_id,
                token,
                hostname,
                target,
                name,
            )
            .await?;
        }
        Command::UdpAgent {
            control,
            control_ca_cert,
            control_server_name,
            client_id,
            token,
            public_port,
            target,
            name,
        } => {
            udp_agent::run_udp_agent(
                ControlTransport::new(control, control_ca_cert, control_server_name)?,
                client_id,
                token,
                public_port,
                target,
                name,
                Arc::new(tokio::sync::Semaphore::new(
                    udp_agent::UDP_QUEUE_BUDGET_BYTES,
                )),
            )
            .await?;
        }
        Command::Run { config } => run_configured_agents(config, None).await?,
        Command::MigrateConfig { input, output } => {
            migrate_client_config(&input, &output)?;
            println!(
                "Migrated LinkLake client configuration: {}",
                output.display()
            );
        }
    }
    Ok(())
}

async fn run_configured_agents(
    path: PathBuf,
    shutdown: Option<tokio::sync::oneshot::Receiver<()>>,
) -> anyhow::Result<()> {
    let content = read_to_string(&path)?;
    let config = parse_client_config(&content)?;
    if !config.servers.is_empty() {
        return run_multi_server_agents(path, config, shutdown).await;
    }
    if let Some(identity) = config.client.clone() {
        return run_supervised_agents(path, config, identity, shutdown).await;
    }
    run_legacy_agents(config, shutdown).await
}

async fn run_multi_server_agents(
    bootstrap_path: PathBuf,
    config: ClientConfigFile,
    shutdown: Option<tokio::sync::oneshot::Receiver<()>>,
) -> anyhow::Result<()> {
    let mut tasks = JoinSet::new();
    let mut shutdown_senders = Vec::new();
    for identity in config.servers.clone() {
        let server_name = identity
            .name
            .clone()
            .expect("multi-server identity name validated");
        let mut server_config = config.clone();
        server_config.client = Some(identity.clone());
        server_config.servers.clear();
        server_config
            .secret_visitors
            .retain(|visitor| visitor.server.as_deref() == Some(server_name.as_str()));
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        shutdown_senders.push(shutdown_tx);
        let path = bootstrap_path.clone();
        tasks.spawn(async move {
            tracing::info!(server = %server_name, "Starting cloud entry supervisor");
            let result =
                run_supervised_agents(path, server_config, identity, Some(shutdown_rx)).await;
            if let Err(error) = &result {
                tracing::error!(server = %server_name, "Cloud entry supervisor stopped: {error}");
            }
            result
        });
    }

    match shutdown {
        Some(shutdown) => {
            let _ = shutdown.await;
        }
        None => wait_for_os_shutdown().await,
    }
    for sender in shutdown_senders {
        let _ = sender.send(());
    }
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => tracing::warn!("Cloud entry stopped with an error: {error}"),
            Err(error) => tracing::warn!("Cloud entry task failed: {error}"),
        }
    }
    tracing::info!("All LinkLake cloud entry supervisors stopped.");
    Ok(())
}

async fn run_legacy_agents(
    config: ClientConfigFile,
    shutdown: Option<tokio::sync::oneshot::Receiver<()>>,
) -> anyhow::Result<()> {
    // 同一份配置中的所有 UDP 隧道共享队列字节预算，避免多个策略叠加占满客户端内存。
    let udp_queue_budget = Arc::new(tokio::sync::Semaphore::new(
        udp_agent::UDP_QUEUE_BUDGET_BYTES,
    ));
    for tunnel in config.tcp_tunnels {
        let transport = ControlTransport::new(
            tunnel.control.expect("legacy TCP control validated"),
            tunnel.control_ca_cert,
            tunnel.control_server_name,
        )?;
        let client_id = tunnel.client_id.expect("legacy TCP client ID validated");
        let client_token = tunnel
            .client_token
            .expect("legacy TCP client token validated");
        tokio::spawn(async move {
            if let Err(error) = run_tcp_agent(
                transport,
                client_id,
                client_token,
                tunnel.public_port,
                tunnel.target,
                tunnel.name,
            )
            .await
            {
                tracing::error!("Configured TCP tunnel failed permanently: {error}");
            }
        });
    }
    for tunnel in config.udp_tunnels {
        let transport = ControlTransport::new(
            tunnel.control.expect("legacy UDP control validated"),
            tunnel.control_ca_cert,
            tunnel.control_server_name,
        )?;
        let client_id = tunnel.client_id.expect("legacy UDP client ID validated");
        let client_token = tunnel
            .client_token
            .expect("legacy UDP client token validated");
        let udp_queue_budget = udp_queue_budget.clone();
        tokio::spawn(async move {
            if let Err(error) = udp_agent::run_udp_agent(
                transport,
                client_id,
                client_token,
                tunnel.public_port,
                tunnel.target,
                tunnel.name,
                udp_queue_budget,
            )
            .await
            {
                tracing::error!("Configured UDP tunnel failed permanently: {error}");
            }
        });
    }
    for route in config.http_routes {
        let transport = ControlTransport::new(
            route.control.expect("legacy HTTP control validated"),
            route.control_ca_cert,
            route.control_server_name,
        )?;
        let client_id = route.client_id.expect("legacy HTTP client ID validated");
        let client_token = route
            .client_token
            .expect("legacy HTTP client token validated");
        tokio::spawn(async move {
            if let Err(error) = run_http_agent(
                transport,
                client_id,
                client_token,
                route.hostname,
                route.target,
                route.name,
            )
            .await
            {
                tracing::error!("Configured HTTP route failed permanently: {error}");
            }
        });
    }
    match shutdown {
        Some(shutdown) => {
            let _ = shutdown.await;
            tracing::info!("LinkLake client service received a shutdown request.");
        }
        None => wait_for_os_shutdown().await,
    }
    Ok(())
}

async fn run_supervised_agents(
    bootstrap_path: PathBuf,
    config: ClientConfigFile,
    identity: ClientIdentityConfig,
    shutdown: Option<tokio::sync::oneshot::Receiver<()>>,
) -> anyhow::Result<()> {
    let transport = ControlTransport::new(
        identity.control.clone(),
        identity.control_ca_cert.clone(),
        identity.control_server_name.clone(),
    )?;
    let p2p_task = match (&identity.p2p_bind, &identity.p2p_endpoint) {
        (Some(bind), Some(endpoint)) => Some(tokio::spawn(supervise_p2p_provider(
            transport.clone(),
            identity.client_id,
            identity.client_token.clone(),
            P2pProviderConfig {
                bind: bind.clone(),
                endpoint: endpoint.clone(),
                relay_url: identity.p2p_relay_url.clone(),
                tcp_enabled: identity.p2p_tcp_enabled,
                iroh_enabled: identity.p2p_iroh_enabled,
            },
        ))),
        (None, None) => None,
        _ => anyhow::bail!("p2p_bind and p2p_endpoint must be configured together"),
    };
    let managed_path = managed_config_path(&bootstrap_path, &identity);
    let local_config = local_managed_config(&config);
    let local_secret_visitors = config.secret_visitors.clone();
    let udp_queue_budget = Arc::new(tokio::sync::Semaphore::new(
        udp_agent::UDP_QUEUE_BUDGET_BYTES,
    ));
    let mut agents = HashMap::<AgentKey, RunningAgent>::new();
    let mut applied_revision = None;
    let mut sync_status = ManagedConfigStatus::Unknown;
    let mut sync_error = None;

    match identity.config_mode {
        ManagedConfigMode::ServerManaged => {
            match load_managed_config(&managed_path)
                .and_then(|saved| validate_managed_config(&saved).map(|()| saved))
            {
                Ok(saved) => {
                    reconcile_agents(
                        &mut agents,
                        &saved,
                        &identity,
                        &transport,
                        &udp_queue_budget,
                        &local_secret_visitors,
                    );
                    applied_revision = Some(saved.revision);
                    sync_status = ManagedConfigStatus::Synchronized;
                }
                Err(error) if managed_path.exists() => {
                    sync_status = ManagedConfigStatus::ApplyFailed;
                    sync_error = Some(error.to_string());
                    tracing::warn!(
                        "Saved managed configuration is invalid; waiting for server repair: {error}"
                    );
                }
                Err(_) => {}
            }
        }
        ManagedConfigMode::Local | ManagedConfigMode::ReportOnly => reconcile_agents(
            &mut agents,
            &local_config,
            &identity,
            &transport,
            &udp_queue_budget,
            &local_secret_visitors,
        ),
    }

    let shutdown_future = async move {
        match shutdown {
            Some(shutdown) => {
                let _ = shutdown.await;
            }
            None => wait_for_os_shutdown().await,
        }
    };
    tokio::pin!(shutdown_future);
    let mut poll = interval(MANAGED_CONFIG_POLL_INTERVAL);
    poll.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = &mut shutdown_future => break,
            _ = poll.tick() => {
                match request_managed_config(
                    &transport,
                    &identity,
                    applied_revision.clone(),
                    sync_status,
                    sync_error.clone(),
                ).await {
                    Ok(desired) => match identity.config_mode {
                        ManagedConfigMode::ServerManaged => {
                            if applied_revision.as_deref() != Some(desired.revision.as_str())
                                || !managed_file_matches(&managed_path, &desired)
                            {
                                match apply_managed_config(
                                    &managed_path,
                                    &desired,
                                    &mut agents,
                                    &identity,
                                    &transport,
                                    &udp_queue_budget,
                                    &local_secret_visitors,
                                ) {
                                    Ok(()) => {
                                        applied_revision = Some(desired.revision.clone());
                                        sync_status = ManagedConfigStatus::Synchronized;
                                        sync_error = None;
                                        tracing::info!("Applied managed configuration {}.", desired.revision);
                                    }
                                    Err(error) => {
                                        sync_status = ManagedConfigStatus::ApplyFailed;
                                        sync_error = Some(error.to_string());
                                        tracing::error!("Managed configuration apply failed: {error}");
                                    }
                                }
                            } else {
                                sync_status = ManagedConfigStatus::Synchronized;
                                sync_error = None;
                            }
                        }
                        ManagedConfigMode::Local | ManagedConfigMode::ReportOnly => {
                            if managed_shapes_equal(&local_config, &desired) {
                                applied_revision = Some(desired.revision);
                                sync_status = ManagedConfigStatus::Synchronized;
                                sync_error = None;
                            } else {
                                applied_revision = None;
                                sync_status = ManagedConfigStatus::Conflict;
                                sync_error = Some("local tunnel configuration differs from the server policy".to_owned());
                            }
                        }
                    },
                    Err(error) => tracing::warn!("Managed configuration check failed: {error}"),
                }
            }
        }
    }
    for (_, agent) in agents {
        agent.task.abort();
    }
    if let Some(task) = p2p_task {
        task.abort();
    }
    tracing::info!("LinkLake client configuration supervisor stopped.");
    Ok(())
}

async fn request_managed_config(
    transport: &ControlTransport,
    identity: &ClientIdentityConfig,
    applied_revision: Option<String>,
    status: ManagedConfigStatus,
    error: Option<String>,
) -> anyhow::Result<ManagedClientConfig> {
    let mut stream = connect_control(transport).await?;
    write_control_frame(
        &mut stream,
        &ControlFrame::RequestManagedConfig {
            client_id: identity.client_id,
            client_token: identity.client_token.clone(),
            mode: identity.config_mode,
            applied_revision,
            status,
            error,
        },
    )
    .await?;
    match timeout(CONTROL_HEARTBEAT_TIMEOUT, read_control_frame(&mut stream)).await?? {
        ControlFrame::ManagedConfig { config } => Ok(config),
        ControlFrame::Error { message } => {
            anyhow::bail!("server rejected config request: {message}")
        }
        frame => anyhow::bail!("unexpected managed config response: {frame:?}"),
    }
}

fn apply_managed_config(
    path: &Path,
    desired: &ManagedClientConfig,
    agents: &mut HashMap<AgentKey, RunningAgent>,
    identity: &ClientIdentityConfig,
    transport: &ControlTransport,
    udp_queue_budget: &Arc<tokio::sync::Semaphore>,
    secret_visitors: &[SecretVisitorConfig],
) -> anyhow::Result<()> {
    validate_managed_config(desired)?;
    persist_managed_config(path, desired)?;
    reconcile_agents(
        agents,
        desired,
        identity,
        transport,
        udp_queue_budget,
        secret_visitors,
    );
    Ok(())
}

fn reconcile_agents(
    agents: &mut HashMap<AgentKey, RunningAgent>,
    desired: &ManagedClientConfig,
    identity: &ClientIdentityConfig,
    transport: &ControlTransport,
    udp_queue_budget: &Arc<tokio::sync::Semaphore>,
    secret_visitors: &[SecretVisitorConfig],
) {
    let desired = agent_specs(desired, secret_visitors);
    agents.retain(|key, running| {
        let keep = desired.get(key).is_some_and(|spec| spec == &running.spec);
        if !keep {
            running.task.abort();
        }
        keep
    });
    for (key, spec) in desired {
        if agents.contains_key(&key) {
            continue;
        }
        let task = spawn_agent_task(
            spec.clone(),
            identity.clone(),
            transport.clone(),
            udp_queue_budget.clone(),
        );
        agents.insert(key, RunningAgent { spec, task });
    }
}

fn spawn_agent_task(
    spec: AgentSpec,
    identity: ClientIdentityConfig,
    transport: ControlTransport,
    udp_queue_budget: Arc<tokio::sync::Semaphore>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let result = match spec {
            AgentSpec::Tcp {
                name,
                public_port,
                target,
            } => {
                run_tcp_agent(
                    transport,
                    identity.client_id,
                    identity.client_token,
                    public_port,
                    target,
                    name,
                )
                .await
            }
            AgentSpec::Udp {
                name,
                public_port,
                target,
            } => {
                udp_agent::run_udp_agent(
                    transport,
                    identity.client_id,
                    identity.client_token,
                    public_port,
                    target,
                    name,
                    udp_queue_budget,
                )
                .await
            }
            AgentSpec::Http {
                name,
                hostname,
                target,
            } => {
                run_http_agent(
                    transport,
                    identity.client_id,
                    identity.client_token,
                    hostname,
                    target,
                    name,
                )
                .await
            }
            AgentSpec::Tls {
                name,
                hostname,
                target,
            } => {
                run_tls_route_agent(
                    transport,
                    identity.client_id,
                    identity.client_token,
                    hostname,
                    target,
                    name,
                )
                .await
            }
            AgentSpec::SecretTarget { name, target } => {
                run_secret_target_agent(
                    transport,
                    identity.client_id,
                    identity.client_token,
                    target,
                    name,
                )
                .await
            }
            AgentSpec::SecretVisitor {
                name,
                local_bind,
                access_key,
                prefer_direct,
            } => {
                run_secret_visitor(
                    transport,
                    identity.client_id,
                    identity.client_token,
                    local_bind,
                    access_key,
                    name,
                    prefer_direct,
                )
                .await
            }
            AgentSpec::Socks5 { name, public_port } => {
                run_socks5_agent(
                    transport,
                    identity.client_id,
                    identity.client_token,
                    public_port,
                    name,
                    udp_queue_budget,
                )
                .await
            }
            AgentSpec::HttpProxy { name, public_port } => {
                run_http_proxy_agent(
                    transport,
                    identity.client_id,
                    identity.client_token,
                    public_port,
                    name,
                )
                .await
            }
        };
        if let Err(error) = result {
            tracing::error!("Managed agent stopped permanently: {error}");
        }
    })
}

fn agent_specs(
    config: &ManagedClientConfig,
    secret_visitors: &[SecretVisitorConfig],
) -> HashMap<AgentKey, AgentSpec> {
    let mut specs = HashMap::new();
    for tunnel in config.tcp_tunnels.iter().filter(|tunnel| tunnel.enabled) {
        let spec = AgentSpec::Tcp {
            name: tunnel.name.clone(),
            public_port: tunnel.public_port,
            target: tunnel.target_addr.clone(),
        };
        specs.insert(AgentKey::Tcp(tunnel.name.clone(), tunnel.public_port), spec);
    }
    for tunnel in config.udp_tunnels.iter().filter(|tunnel| tunnel.enabled) {
        let spec = AgentSpec::Udp {
            name: tunnel.name.clone(),
            public_port: tunnel.public_port,
            target: tunnel.target_addr.clone(),
        };
        specs.insert(AgentKey::Udp(tunnel.name.clone(), tunnel.public_port), spec);
    }
    for route in config.http_routes.iter().filter(|route| route.enabled) {
        let hostname = route.hostname.to_ascii_lowercase();
        let spec = AgentSpec::Http {
            name: route.name.clone(),
            hostname: hostname.clone(),
            target: route.target_addr.clone(),
        };
        specs.insert(AgentKey::Http(hostname), spec);
    }
    for route in config.tls_routes.iter().filter(|route| route.enabled) {
        let hostname = route.hostname.to_ascii_lowercase();
        specs.insert(
            AgentKey::Tls(hostname.clone()),
            AgentSpec::Tls {
                name: route.name.clone(),
                hostname,
                target: route.target_addr.clone(),
            },
        );
    }
    for tunnel in config.secret_tunnels.iter().filter(|tunnel| tunnel.enabled) {
        specs.insert(
            AgentKey::SecretTarget(tunnel.name.clone()),
            AgentSpec::SecretTarget {
                name: tunnel.name.clone(),
                target: tunnel.target_addr.clone(),
            },
        );
    }
    for visitor in secret_visitors {
        specs.insert(
            AgentKey::SecretVisitor(visitor.name.clone()),
            AgentSpec::SecretVisitor {
                name: visitor.name.clone(),
                local_bind: visitor.local_bind.clone(),
                access_key: visitor.access_key.clone(),
                prefer_direct: visitor.prefer_direct,
            },
        );
    }
    for proxy in config.socks5_proxies.iter().filter(|proxy| proxy.enabled) {
        specs.insert(
            AgentKey::Socks5(proxy.name.clone(), proxy.public_port),
            AgentSpec::Socks5 {
                name: proxy.name.clone(),
                public_port: proxy.public_port,
            },
        );
    }
    for proxy in config.http_proxies.iter().filter(|proxy| proxy.enabled) {
        specs.insert(
            AgentKey::HttpProxy(proxy.name.clone(), proxy.public_port),
            AgentSpec::HttpProxy {
                name: proxy.name.clone(),
                public_port: proxy.public_port,
            },
        );
    }
    specs
}

fn local_managed_config(config: &ClientConfigFile) -> ManagedClientConfig {
    let mut tcp_tunnels = config
        .tcp_tunnels
        .iter()
        .map(|tunnel| ManagedTcpTunnel {
            name: tunnel.name.clone(),
            public_port: tunnel.public_port,
            target_addr: tunnel.target.clone(),
            enabled: true,
        })
        .collect::<Vec<_>>();
    let mut udp_tunnels = config
        .udp_tunnels
        .iter()
        .map(|tunnel| ManagedUdpTunnel {
            name: tunnel.name.clone(),
            public_port: tunnel.public_port,
            target_addr: tunnel.target.clone(),
            enabled: true,
        })
        .collect::<Vec<_>>();
    for group in &config.port_groups {
        let parsed = parse_port_mappings(
            &group.public_ports,
            &group.target_ports,
            1,
            u16::MAX,
            MAX_PORT_MAPPINGS,
        )
        .expect("local port group should already be validated");
        match group.protocol {
            PortGroupConfigProtocol::Tcp => {
                tcp_tunnels.extend(parsed.pairs.into_iter().map(|mapping| ManagedTcpTunnel {
                    name: group.name.clone(),
                    public_port: mapping.public_port,
                    target_addr: port_group_target_addr(&group.target_host, mapping.target_port),
                    enabled: true,
                }));
            }
            PortGroupConfigProtocol::Udp => {
                udp_tunnels.extend(parsed.pairs.into_iter().map(|mapping| ManagedUdpTunnel {
                    name: group.name.clone(),
                    public_port: mapping.public_port,
                    target_addr: port_group_target_addr(&group.target_host, mapping.target_port),
                    enabled: true,
                }));
            }
        }
    }
    let mut http_routes = config
        .http_routes
        .iter()
        .map(|route| ManagedHttpRoute {
            name: route.name.clone(),
            hostname: route.hostname.to_ascii_lowercase(),
            target_addr: route.target.clone(),
            enabled: true,
        })
        .collect::<Vec<_>>();
    let mut tls_routes = config
        .tls_routes
        .iter()
        .map(|route| ManagedTlsRoute {
            name: route.name.clone(),
            hostname: route.hostname.to_ascii_lowercase(),
            target_addr: route.target.clone(),
            enabled: true,
        })
        .collect::<Vec<_>>();
    let mut secret_tunnels = config
        .secret_tunnels
        .iter()
        .map(|tunnel| ManagedSecretTunnel {
            name: tunnel.name.clone(),
            target_addr: tunnel.target.clone(),
            enabled: true,
        })
        .collect::<Vec<_>>();
    let mut socks5_proxies = config
        .socks5_proxies
        .iter()
        .map(|proxy| ManagedSocks5Proxy {
            name: proxy.name.clone(),
            public_port: proxy.public_port,
            enabled: true,
        })
        .collect::<Vec<_>>();
    let mut http_proxies = config
        .http_proxies
        .iter()
        .map(|proxy| ManagedHttpProxy {
            name: proxy.name.clone(),
            public_port: proxy.public_port,
            enabled: true,
        })
        .collect::<Vec<_>>();
    tcp_tunnels.sort_by_key(|tunnel| tunnel.public_port);
    udp_tunnels.sort_by_key(|tunnel| tunnel.public_port);
    http_routes.sort_by(|left, right| left.hostname.cmp(&right.hostname));
    tls_routes.sort_by(|left, right| left.hostname.cmp(&right.hostname));
    secret_tunnels.sort_by(|left, right| left.name.cmp(&right.name));
    socks5_proxies.sort_by_key(|proxy| proxy.public_port);
    http_proxies.sort_by_key(|proxy| proxy.public_port);
    ManagedClientConfig {
        revision: "local".to_owned(),
        tcp_tunnels,
        udp_tunnels,
        http_routes,
        tls_routes,
        secret_tunnels,
        socks5_proxies,
        http_proxies,
    }
}

fn managed_shapes_equal(left: &ManagedClientConfig, right: &ManagedClientConfig) -> bool {
    left.tcp_tunnels == right.tcp_tunnels
        && left.udp_tunnels == right.udp_tunnels
        && left.http_routes == right.http_routes
        && left.tls_routes == right.tls_routes
        && left.secret_tunnels == right.secret_tunnels
        && left.socks5_proxies == right.socks5_proxies
        && left.http_proxies == right.http_proxies
}

fn managed_config_path(bootstrap_path: &Path, identity: &ClientIdentityConfig) -> PathBuf {
    let default_name = identity
        .name
        .as_deref()
        .map(safe_server_name)
        .map(|name| format!("managed.{name}.toml"))
        .unwrap_or_else(|| "managed.toml".to_owned());
    if identity.managed_config_path.is_none() {
        if let Some(state_dir) = std::env::var_os("LINKLAKE_STATE_DIR") {
            return PathBuf::from(state_dir).join(&default_name);
        }
    }
    let configured = identity
        .managed_config_path
        .clone()
        .unwrap_or_else(|| PathBuf::from(default_name));
    if configured.is_absolute() {
        configured
    } else {
        bootstrap_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(configured)
    }
}

fn safe_server_name(name: &str) -> String {
    name.chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn load_managed_config(path: &Path) -> anyhow::Result<ManagedClientConfig> {
    let content = read_to_string(path)?;
    Ok(toml::from_str(&content)?)
}

fn managed_file_matches(path: &Path, desired: &ManagedClientConfig) -> bool {
    load_managed_config(path)
        .and_then(|current| validate_managed_config(&current).map(|()| current))
        .is_ok_and(|current| current == *desired)
}

fn persist_managed_config(path: &Path, config: &ManagedClientConfig) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = toml::to_string_pretty(config)?;
    let parsed: ManagedClientConfig = toml::from_str(&content)?;
    validate_managed_config(&parsed)?;
    let temporary = PathBuf::from(format!("{}.tmp", path.display()));
    let backup = PathBuf::from(format!("{}.backup", path.display()));
    if temporary.exists() {
        std::fs::remove_file(&temporary)?;
    }
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)?;
    file.write_all(content.as_bytes())?;
    file.sync_all()?;
    drop(file);

    if path.exists() {
        let current_is_valid = load_managed_config(path)
            .and_then(|current| validate_managed_config(&current))
            .is_ok();
        if current_is_valid {
            if backup.exists() {
                std::fs::remove_file(&backup)?;
            }
            std::fs::rename(path, &backup)?;
        } else {
            // 人工损坏的托管文件不能覆盖最后一次有效备份。
            std::fs::remove_file(path)?;
        }
    }
    if let Err(error) = std::fs::rename(&temporary, path) {
        if backup.exists() {
            let _ = std::fs::rename(&backup, path);
        }
        return Err(error.into());
    }
    if !backup.exists() {
        std::fs::copy(path, &backup)?;
    }
    Ok(())
}

fn validate_managed_config(config: &ManagedClientConfig) -> anyhow::Result<()> {
    anyhow::ensure!(
        config.revision == managed_config_revision(config)?,
        "managed configuration revision does not match its contents"
    );
    let mut tcp_ports = HashSet::new();
    for tunnel in &config.tcp_tunnels {
        anyhow::ensure!(
            !tunnel.name.trim().is_empty()
                && tunnel.public_port != 0
                && !tunnel.target_addr.trim().is_empty()
                && tcp_ports.insert(tunnel.public_port),
            "managed TCP tunnel is invalid or duplicated"
        );
    }
    let mut udp_ports = HashSet::new();
    for tunnel in &config.udp_tunnels {
        anyhow::ensure!(
            !tunnel.name.trim().is_empty()
                && tunnel.public_port != 0
                && !tunnel.target_addr.trim().is_empty()
                && udp_ports.insert(tunnel.public_port),
            "managed UDP tunnel is invalid or duplicated"
        );
    }
    let mut hostnames = HashSet::new();
    for route in &config.http_routes {
        anyhow::ensure!(
            !route.name.trim().is_empty()
                && !route.hostname.trim().is_empty()
                && !route.target_addr.trim().is_empty()
                && hostnames.insert(route.hostname.to_ascii_lowercase()),
            "managed HTTP route is invalid or duplicated"
        );
    }
    let mut tls_hostnames = HashSet::new();
    for route in &config.tls_routes {
        anyhow::ensure!(
            !route.name.trim().is_empty()
                && !route.hostname.trim().is_empty()
                && !route.target_addr.trim().is_empty()
                && tls_hostnames.insert(route.hostname.to_ascii_lowercase()),
            "managed TLS SNI route is invalid or duplicated"
        );
    }
    let mut secret_names = HashSet::new();
    for tunnel in &config.secret_tunnels {
        anyhow::ensure!(
            !tunnel.name.trim().is_empty()
                && !tunnel.target_addr.trim().is_empty()
                && secret_names.insert(tunnel.name.clone()),
            "managed secret tunnel is invalid or duplicated"
        );
    }
    let mut socks5_names = HashSet::new();
    for proxy in &config.socks5_proxies {
        anyhow::ensure!(
            !proxy.name.trim().is_empty()
                && proxy.public_port != 0
                && tcp_ports.insert(proxy.public_port)
                && socks5_names.insert(proxy.name.clone()),
            "managed SOCKS5 proxy is invalid or duplicated"
        );
    }
    let mut http_proxy_names = HashSet::new();
    for proxy in &config.http_proxies {
        anyhow::ensure!(
            !proxy.name.trim().is_empty()
                && proxy.public_port != 0
                && tcp_ports.insert(proxy.public_port)
                && http_proxy_names.insert(proxy.name.clone()),
            "managed HTTP proxy is invalid or duplicated"
        );
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

fn validate_client_identity(identity: &ClientIdentityConfig) -> anyhow::Result<()> {
    anyhow::ensure!(
        !identity.control.trim().is_empty() && !identity.client_token.trim().is_empty(),
        "the client identity configuration is incomplete"
    );
    anyhow::ensure!(
        identity.p2p_bind.is_some() == identity.p2p_endpoint.is_some(),
        "p2p_bind and p2p_endpoint must be configured together"
    );
    if let (Some(bind), Some(endpoint)) = (&identity.p2p_bind, &identity.p2p_endpoint) {
        anyhow::ensure!(
            bind.parse::<std::net::SocketAddr>().is_ok()
                && endpoint.parse::<std::net::SocketAddr>().is_ok(),
            "p2p_bind and p2p_endpoint must be valid IP socket addresses"
        );
        anyhow::ensure!(
            identity.p2p_tcp_enabled || identity.p2p_iroh_enabled,
            "at least one P2P transport must be enabled"
        );
    }
    anyhow::ensure!(
        identity
            .p2p_relay_url
            .as_ref()
            .is_none_or(|value| value.starts_with("https://") && value.len() <= 512),
        "p2p_relay_url must be an HTTPS relay URL"
    );
    Ok(())
}

fn valid_server_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|value| value.is_ascii_alphanumeric() || matches!(value, b'-' | b'_'))
}

fn parse_client_config(content: &str) -> anyhow::Result<ClientConfigFile> {
    let config: ClientConfigFile = toml::from_str(content)?;
    anyhow::ensure!(
        config.config_version <= CURRENT_CLIENT_CONFIG_VERSION,
        "client config version {} is newer than this LinkLake build ({CURRENT_CLIENT_CONFIG_VERSION})",
        config.config_version
    );
    let mut port_group_names = HashSet::new();
    for group in &config.port_groups {
        anyhow::ensure!(
            !group.name.trim().is_empty()
                && group.name.len() <= 64
                && valid_port_group_target_host(group.target_host.trim())
                && port_group_names.insert((group.protocol, group.name.trim().to_owned())),
            "local port group name or target host is invalid or duplicated"
        );
        parse_port_mappings(
            &group.public_ports,
            &group.target_ports,
            1,
            u16::MAX,
            MAX_PORT_MAPPINGS,
        )
        .map_err(|error| anyhow::anyhow!("local port group is invalid: {error}"))?;
    }
    anyhow::ensure!(
        config.client.is_none() || config.servers.is_empty(),
        "use either [client] or [[servers]], not both"
    );
    let mut server_names = HashSet::new();
    let mut p2p_binds = HashSet::new();
    for identity in config.client.iter().chain(config.servers.iter()) {
        validate_client_identity(identity)?;
        if let Some(name) = identity.name.as_deref() {
            anyhow::ensure!(
                valid_server_name(name) && server_names.insert(name.to_owned()),
                "multi-server names must be unique and contain only letters, numbers, '-' or '_'"
            );
        }
        if let Some(bind) = identity.p2p_bind.as_deref() {
            anyhow::ensure!(
                p2p_binds.insert(bind.to_owned()),
                "multi-server P2P bind addresses must be unique"
            );
        }
    }
    if !config.servers.is_empty() {
        anyhow::ensure!(
            config
                .servers
                .iter()
                .all(|identity| identity.name.is_some()),
            "every [[servers]] entry requires a unique name"
        );
        for visitor in &config.secret_visitors {
            anyhow::ensure!(
                visitor
                    .server
                    .as_ref()
                    .is_some_and(|name| server_names.contains(name)),
                "each secret visitor in multi-server mode must reference an existing server"
            );
        }
        let mut managed_paths = HashSet::new();
        for identity in &config.servers {
            let name = identity.name.as_deref().expect("server name validated");
            let path = identity.managed_config_path.clone().unwrap_or_else(|| {
                PathBuf::from(format!("managed.{}.toml", safe_server_name(name)))
            });
            anyhow::ensure!(
                managed_paths.insert(path),
                "multi-server managed_config_path values must be unique"
            );
        }
    }
    if config.client.is_some() || !config.servers.is_empty() {
        for tunnel in &config.secret_tunnels {
            anyhow::ensure!(
                !tunnel.name.trim().is_empty() && !tunnel.target.trim().is_empty(),
                "local secret tunnel target is invalid"
            );
        }
        let mut tls_names = HashSet::new();
        for route in &config.tls_routes {
            anyhow::ensure!(
                !route.name.trim().is_empty()
                    && !route.hostname.trim().is_empty()
                    && !route.target.trim().is_empty()
                    && tls_names.insert(route.hostname.to_ascii_lowercase()),
                "local TLS SNI route is invalid or duplicated"
            );
        }
        let mut visitor_names = HashSet::new();
        for visitor in &config.secret_visitors {
            anyhow::ensure!(
                !visitor.name.trim().is_empty()
                    && visitor.local_bind.parse::<std::net::SocketAddr>().is_ok()
                    && visitor.access_key.len() == 68
                    && visitor.access_key.starts_with("lls_")
                    && visitor.access_key[4..]
                        .bytes()
                        .all(|value| value.is_ascii_hexdigit())
                    && visitor_names.insert(visitor.name.clone()),
                "local secret visitor is invalid or duplicated"
            );
        }
        let mut socks5_names = HashSet::new();
        let mut socks5_ports = HashSet::new();
        for proxy in &config.socks5_proxies {
            anyhow::ensure!(
                !proxy.name.trim().is_empty()
                    && proxy.public_port != 0
                    && socks5_names.insert(proxy.name.clone())
                    && socks5_ports.insert(proxy.public_port),
                "local SOCKS5 proxy is invalid or duplicated"
            );
        }
        let mut http_proxy_names = HashSet::new();
        let mut http_proxy_ports = HashSet::new();
        for proxy in &config.http_proxies {
            anyhow::ensure!(
                !proxy.name.trim().is_empty()
                    && proxy.public_port != 0
                    && http_proxy_names.insert(proxy.name.clone())
                    && http_proxy_ports.insert(proxy.public_port),
                "local HTTP proxy is invalid or duplicated"
            );
        }
        let mut local = local_managed_config(&config);
        local.revision = managed_config_revision(&local)?;
        validate_managed_config(&local)?;
    } else {
        anyhow::ensure!(
            !config.tcp_tunnels.is_empty()
                || !config.udp_tunnels.is_empty()
                || !config.http_routes.is_empty(),
            "the configuration has no legacy tunnel entries"
        );
        anyhow::ensure!(
            config.secret_tunnels.is_empty()
                && config.secret_visitors.is_empty()
                && config.socks5_proxies.is_empty()
                && config.http_proxies.is_empty()
                && config.port_groups.is_empty()
                && config.tls_routes.is_empty(),
            "secret tunnels, proxies, port groups, and TLS routes require a global [client] identity section"
        );
        for complete in config
            .tcp_tunnels
            .iter()
            .map(|value| {
                value.control.is_some() && value.client_id.is_some() && value.client_token.is_some()
            })
            .chain(config.udp_tunnels.iter().map(|value| {
                value.control.is_some() && value.client_id.is_some() && value.client_token.is_some()
            }))
            .chain(config.http_routes.iter().map(|value| {
                value.control.is_some() && value.client_id.is_some() && value.client_token.is_some()
            }))
        {
            anyhow::ensure!(
                complete,
                "legacy tunnel entries must include control and client credentials"
            );
        }
    }
    Ok(config)
}

fn migrate_client_config(input: &Path, output: &Path) -> anyhow::Result<()> {
    anyhow::ensure!(input != output, "migration output must differ from input");
    anyhow::ensure!(!output.exists(), "migration output already exists");
    let content = read_to_string(input)?;
    let mut value: toml::Value = toml::from_str(&content)?;
    let current = value
        .get("config_version")
        .and_then(toml::Value::as_integer)
        .unwrap_or(0);
    anyhow::ensure!(
        current >= 0 && current as u32 <= CURRENT_CLIENT_CONFIG_VERSION,
        "client config version {current} is unsupported"
    );
    value
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("client configuration root must be a TOML table"))?
        .insert(
            "config_version".to_owned(),
            toml::Value::Integer(CURRENT_CLIENT_CONFIG_VERSION.into()),
        );
    let migrated = toml::to_string_pretty(&value)?;
    parse_client_config(&migrated)?;
    if let Some(parent) = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)?;
    file.write_all(migrated.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

fn port_group_target_addr(host: &str, port: u16) -> String {
    let host = host.trim();
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn valid_port_group_target_host(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 253
        || value.bytes().any(|byte| byte.is_ascii_whitespace())
        || value.contains('/')
        || value.contains('[')
        || value.contains(']')
    {
        return false;
    }
    if value.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    if value.contains(':') {
        return false;
    }
    value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

#[cfg(test)]
mod tests {
    use super::{
        load_managed_config, local_managed_config, managed_config_path, migrate_client_config,
        p2p_candidates, parse_client_config, persist_managed_config, run_configured_agents,
        validate_managed_config, CURRENT_CLIENT_CONFIG_VERSION,
    };
    use linklake_core::{
        managed_config_revision, read_control_frame, write_control_frame, ControlFrame,
        ManagedClientConfig, ManagedConfigMode, ManagedHttpProxy, ManagedSecretTunnel,
        ManagedSocks5Proxy, ManagedTcpTunnel, ManagedTlsRoute,
    };
    use uuid::Uuid;

    #[test]
    fn parses_tcp_tunnel_configuration() {
        let config = parse_client_config(
            r#"
                [[tcp_tunnels]]
                name = "game-server"
                control = "tunnel.example.com:32101"
                control_ca_cert = "C:\\LinkLake\\control-ca.pem"
                control_server_name = "tunnel.example.com"
                client_id = "00000000-0000-0000-0000-000000000001"
                client_token = "test-token"
                public_port = 32001
                target = "127.0.0.1:2333"
            "#,
        )
        .expect("configuration should parse");

        assert_eq!(config.tcp_tunnels.len(), 1);
        assert_eq!(config.tcp_tunnels[0].name, "game-server");
        assert_eq!(config.tcp_tunnels[0].public_port, 32001);
    }

    #[test]
    fn parses_http_route_configuration() {
        let config = parse_client_config(
            r#"
                [[http_routes]]
                name = "website"
                control = "tunnel.example.com:32101"
                control_ca_cert = "C:\\LinkLake\\control-ca.pem"
                control_server_name = "tunnel.example.com"
                client_id = "00000000-0000-0000-0000-000000000001"
                client_token = "test-token"
                hostname = "site.example.com"
                target = "127.0.0.1:8080"
            "#,
        )
        .expect("configuration should parse");

        assert_eq!(config.http_routes.len(), 1);
        assert_eq!(config.http_routes[0].name, "website");
        assert_eq!(config.http_routes[0].hostname, "site.example.com");
    }

    #[test]
    fn parses_udp_tunnel_configuration() {
        let config = parse_client_config(
            r#"
                [[udp_tunnels]]
                name = "game-udp"
                control = "tunnel.example.com:32101"
                control_ca_cert = "C:\\LinkLake\\control-ca.pem"
                control_server_name = "tunnel.example.com"
                client_id = "00000000-0000-0000-0000-000000000001"
                client_token = "test-token"
                public_port = 32002
                target = "127.0.0.1:2333"
            "#,
        )
        .expect("UDP configuration should parse");

        assert_eq!(config.udp_tunnels.len(), 1);
        assert_eq!(config.udp_tunnels[0].name, "game-udp");
        assert_eq!(config.udp_tunnels[0].public_port, 32002);
        assert_eq!(config.udp_tunnels[0].target, "127.0.0.1:2333");
    }

    #[test]
    fn parses_and_expands_local_tcp_and_udp_port_groups() {
        let config = parse_client_config(
            r#"
                [client]
                control = "127.0.0.1:32101"
                client_id = "00000000-0000-0000-0000-000000000001"
                client_token = "test-token"

                [[port_groups]]
                name = "game-tcp"
                protocol = "tcp"
                public_ports = "32001,32010-32012"
                target_host = "127.0.0.1"
                target_ports = "2333,2400-2402"

                [[port_groups]]
                name = "game-udp"
                protocol = "udp"
                public_ports = "32020-32021"
                target_host = "2001:db8::1"
                target_ports = "2500-2501"
            "#,
        )
        .expect("port group configuration should parse");

        let managed = local_managed_config(&config);
        assert_eq!(managed.tcp_tunnels.len(), 4);
        assert_eq!(managed.tcp_tunnels[0].target_addr, "127.0.0.1:2333");
        assert_eq!(managed.tcp_tunnels[3].target_addr, "127.0.0.1:2402");
        assert_eq!(managed.udp_tunnels.len(), 2);
        assert_eq!(managed.udp_tunnels[0].target_addr, "[2001:db8::1]:2500");
    }

    #[test]
    fn rejects_invalid_or_conflicting_local_port_groups() {
        assert!(parse_client_config(
            r#"
                [client]
                control = "127.0.0.1:32101"
                client_id = "00000000-0000-0000-0000-000000000001"
                client_token = "test-token"

                [[port_groups]]
                name = "bad-count"
                protocol = "tcp"
                public_ports = "32001-32002"
                target_host = "127.0.0.1"
                target_ports = "2333"
            "#,
        )
        .is_err());

        assert!(parse_client_config(
            r#"
                [client]
                control = "127.0.0.1:32101"
                client_id = "00000000-0000-0000-0000-000000000001"
                client_token = "test-token"

                [[tcp_tunnels]]
                name = "single"
                public_port = 32001
                target = "127.0.0.1:80"

                [[port_groups]]
                name = "conflict"
                protocol = "tcp"
                public_ports = "32001"
                target_host = "127.0.0.1"
                target_ports = "2333"
            "#,
        )
        .is_err());
    }

    #[test]
    fn rejects_configuration_without_tunnels() {
        assert!(parse_client_config("").is_err());
    }

    #[test]
    fn server_managed_bootstrap_does_not_require_local_tunnels() {
        let config = parse_client_config(
            r#"
                [client]
                control = "127.0.0.1:32101"
                client_id = "00000000-0000-0000-0000-000000000001"
                client_token = "test-token"
                config_mode = "server_managed"
            "#,
        )
        .expect("server-managed bootstrap should parse");
        assert_eq!(
            config.client.expect("identity should exist").config_mode,
            ManagedConfigMode::ServerManaged
        );
    }

    #[test]
    fn multi_server_configuration_replicates_local_service_and_separates_state_files() {
        let config = parse_client_config(
            r#"
                config_version = 2

                [[servers]]
                name = "cloud-a"
                control = "a.example.test:32101"
                client_id = "00000000-0000-0000-0000-000000000001"
                client_token = "token-a"
                config_mode = "local"

                [[servers]]
                name = "cloud-b"
                control = "b.example.test:32101"
                client_id = "00000000-0000-0000-0000-000000000002"
                client_token = "token-b"
                config_mode = "local"

                [[tcp_tunnels]]
                name = "game-server"
                public_port = 443
                target = "127.0.0.1:2333"
            "#,
        )
        .expect("multi-server configuration should parse");
        assert_eq!(config.servers.len(), 2);
        assert_eq!(config.tcp_tunnels[0].public_port, 443);
        let bootstrap = std::path::Path::new("C:/LinkLake/linklake-client.toml");
        assert_ne!(
            managed_config_path(bootstrap, &config.servers[0]),
            managed_config_path(bootstrap, &config.servers[1])
        );
    }

    #[test]
    fn multi_server_configuration_rejects_duplicate_names() {
        assert!(parse_client_config(
            r#"
                config_version = 2
                [[servers]]
                name = "cloud"
                control = "a.example.test:32101"
                client_id = "00000000-0000-0000-0000-000000000001"
                client_token = "token-a"
                config_mode = "server_managed"
                [[servers]]
                name = "cloud"
                control = "b.example.test:32101"
                client_id = "00000000-0000-0000-0000-000000000002"
                client_token = "token-b"
                config_mode = "server_managed"
            "#,
        )
        .is_err());
    }

    #[tokio::test]
    async fn multi_server_runtime_polls_both_cloud_entries() {
        async fn serve_managed_config_once(
            listener: tokio::net::TcpListener,
            expected_client_id: Uuid,
        ) {
            let (mut stream, _) = listener.accept().await.unwrap();
            match read_control_frame(&mut stream).await.unwrap() {
                ControlFrame::RequestManagedConfig { client_id, .. } => {
                    assert_eq!(client_id, expected_client_id);
                }
                frame => panic!("unexpected frame: {frame:?}"),
            }
            let mut config = ManagedClientConfig {
                revision: String::new(),
                tcp_tunnels: Vec::new(),
                udp_tunnels: Vec::new(),
                http_routes: Vec::new(),
                tls_routes: Vec::new(),
                secret_tunnels: Vec::new(),
                socks5_proxies: Vec::new(),
                http_proxies: Vec::new(),
            };
            config.revision = managed_config_revision(&config).unwrap();
            write_control_frame(&mut stream, &ControlFrame::ManagedConfig { config })
                .await
                .unwrap();
        }

        let listener_a = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener_b = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address_a = listener_a.local_addr().unwrap();
        let address_b = listener_b.local_addr().unwrap();
        let client_a = Uuid::new_v4();
        let client_b = Uuid::new_v4();
        let server_a = tokio::spawn(serve_managed_config_once(listener_a, client_a));
        let server_b = tokio::spawn(serve_managed_config_once(listener_b, client_b));

        let root = std::env::temp_dir().join(format!("linklake-multi-server-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let bootstrap = root.join("client.toml");
        std::fs::write(
            &bootstrap,
            format!(
                r#"
                    config_version = 2
                    [[servers]]
                    name = "cloud-a"
                    control = "{address_a}"
                    client_id = "{client_a}"
                    client_token = "token-a"
                    config_mode = "server_managed"
                    managed_config_path = "managed-a.toml"
                    [[servers]]
                    name = "cloud-b"
                    control = "{address_b}"
                    client_id = "{client_b}"
                    client_token = "token-b"
                    config_mode = "server_managed"
                    managed_config_path = "managed-b.toml"
                "#
            ),
        )
        .unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let runner = tokio::spawn(run_configured_agents(bootstrap, Some(shutdown_rx)));
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            server_a.await.unwrap();
            server_b.await.unwrap();
        })
        .await
        .expect("both cloud entries should receive a managed-config request");
        shutdown_tx.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), runner)
            .await
            .expect("multi-server client should stop")
            .unwrap()
            .unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn parses_local_tls_sni_route() {
        let config = parse_client_config(
            r#"
                [client]
                control = "127.0.0.1:32101"
                client_id = "00000000-0000-0000-0000-000000000001"
                client_token = "test-token"

                [[tls_routes]]
                name = "mail-tls"
                hostname = "mail.example.test"
                target = "127.0.0.1:465"
            "#,
        )
        .expect("TLS SNI route should parse");
        let managed = local_managed_config(&config);
        assert_eq!(managed.tls_routes.len(), 1);
        assert_eq!(managed.tls_routes[0].hostname, "mail.example.test");
        assert_eq!(managed.tls_routes[0].target_addr, "127.0.0.1:465");
    }

    #[test]
    fn p2p_bind_and_endpoint_must_be_valid_and_configured_together() {
        assert!(parse_client_config(
            r#"
                [client]
                control = "127.0.0.1:32101"
                client_id = "00000000-0000-0000-0000-000000000001"
                client_token = "test-token"
                config_mode = "server_managed"
                p2p_bind = "0.0.0.0:40000"
            "#,
        )
        .is_err());
        assert!(parse_client_config(
            r#"
                [client]
                control = "127.0.0.1:32101"
                client_id = "00000000-0000-0000-0000-000000000001"
                client_token = "test-token"
                config_mode = "server_managed"
                p2p_bind = "0.0.0.0:40000"
                p2p_endpoint = "public.example.test:40000"
            "#,
        )
        .is_err());
        parse_client_config(
            r#"
                [client]
                control = "127.0.0.1:32101"
                client_id = "00000000-0000-0000-0000-000000000001"
                client_token = "test-token"
                config_mode = "server_managed"
                p2p_bind = "0.0.0.0:40000"
                p2p_endpoint = "203.0.113.10:40000"
            "#,
        )
        .expect("paired P2P socket addresses should parse");
        assert!(parse_client_config(
            r#"
                [client]
                control = "127.0.0.1:32101"
                client_id = "00000000-0000-0000-0000-000000000001"
                client_token = "test-token"
                config_mode = "server_managed"
                p2p_bind = "0.0.0.0:40000"
                p2p_endpoint = "203.0.113.10:40000"
                p2p_tcp_enabled = false
                p2p_iroh_enabled = false
            "#,
        )
        .is_err());
    }

    #[tokio::test]
    async fn tcp_candidate_remains_available_while_iroh_is_starting() {
        let candidates = p2p_candidates(None, "192.0.2.10:40000", true, true)
            .await
            .expect("TCP candidate generation should not depend on Iroh readiness");
        assert_eq!(candidates.len(), 1);
        assert_eq!(
            candidates[0].transport,
            linklake_core::p2p_protocol::P2pTransport::Tcp
        );
        assert_eq!(candidates[0].endpoint, "192.0.2.10:40000");
    }

    #[tokio::test]
    async fn iroh_only_configuration_waits_without_publishing_empty_candidates() {
        let candidates = p2p_candidates(None, "192.0.2.10:40000", false, true)
            .await
            .expect("Iroh startup delay should be treated as a transient state");
        assert!(candidates.is_empty());
    }

    #[test]
    fn client_config_migration_versions_and_validates_output() {
        let root = std::env::temp_dir().join(format!("linklake-config-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&root).expect("temporary directory should exist");
        let input = root.join("legacy.toml");
        let output = root.join("current.toml");
        std::fs::write(
            &input,
            r#"
                [client]
                control = "127.0.0.1:32101"
                client_id = "00000000-0000-0000-0000-000000000001"
                client_token = "test-token"
            "#,
        )
        .expect("legacy config should write");
        migrate_client_config(&input, &output).expect("config should migrate");
        let migrated = std::fs::read_to_string(&output).expect("migrated config should read");
        assert!(migrated.contains(&format!("config_version = {CURRENT_CLIENT_CONFIG_VERSION}")));
        assert_eq!(
            parse_client_config(&migrated)
                .expect("migrated config should validate")
                .config_version,
            CURRENT_CLIENT_CONFIG_VERSION
        );
        assert!(migrate_client_config(&input, &output).is_err());
        std::fs::remove_dir_all(root).expect("temporary directory should clean up");
    }

    #[test]
    fn parses_secret_target_and_visitor_configuration() {
        let access_key = format!("lls_{}", "a".repeat(64));
        let config = parse_client_config(&format!(
            r#"
                [client]
                control = "127.0.0.1:32101"
                client_id = "00000000-0000-0000-0000-000000000001"
                client_token = "test-token"
                config_mode = "server_managed"

                [[secret_tunnels]]
                name = "private-rdp"
                target = "127.0.0.1:3389"

                [[secret_visitors]]
                name = "private-rdp-access"
                local_bind = "127.0.0.1:13389"
                access_key = "{access_key}"
            "#
        ))
        .expect("secret configuration should parse");

        assert_eq!(config.secret_tunnels.len(), 1);
        assert_eq!(config.secret_tunnels[0].name, "private-rdp");
        assert_eq!(config.secret_tunnels[0].target, "127.0.0.1:3389");
        assert_eq!(config.secret_visitors.len(), 1);
        assert_eq!(config.secret_visitors[0].local_bind, "127.0.0.1:13389");
        assert_eq!(config.secret_visitors[0].access_key, access_key);
    }

    #[test]
    fn rejects_invalid_secret_visitor_access_key() {
        assert!(parse_client_config(
            r#"
                [client]
                control = "127.0.0.1:32101"
                client_id = "00000000-0000-0000-0000-000000000001"
                client_token = "test-token"

                [[secret_visitors]]
                name = "private-rdp-access"
                local_bind = "127.0.0.1:13389"
                access_key = "lls_invalid"
            "#
        )
        .is_err());
    }

    #[test]
    fn managed_revision_changes_with_secret_tunnel_policy() {
        let mut config = managed_config('s', 32_004);
        let original_revision = config.revision.clone();
        config.secret_tunnels.push(ManagedSecretTunnel {
            name: "private-rdp".to_owned(),
            target_addr: "127.0.0.1:3389".to_owned(),
            enabled: true,
        });
        config.revision = linklake_core::managed_config_revision(&config)
            .expect("managed revision should calculate");

        assert_ne!(config.revision, original_revision);
        validate_managed_config(&config).expect("managed secret tunnel should validate");
    }

    #[test]
    fn managed_revision_and_validation_include_tls_routes() {
        let mut config = managed_config('t', 32_005);
        let original_revision = config.revision.clone();
        config.tls_routes.push(ManagedTlsRoute {
            name: "mail-tls".to_owned(),
            hostname: "mail.example.test".to_owned(),
            target_addr: "127.0.0.1:465".to_owned(),
            enabled: true,
        });
        config.revision = linklake_core::managed_config_revision(&config)
            .expect("managed revision should calculate");
        assert_ne!(config.revision, original_revision);
        validate_managed_config(&config).expect("managed TLS route should validate");

        config.tls_routes.push(ManagedTlsRoute {
            name: "duplicate".to_owned(),
            hostname: "MAIL.EXAMPLE.TEST".to_owned(),
            target_addr: "127.0.0.1:8465".to_owned(),
            enabled: true,
        });
        config.revision = linklake_core::managed_config_revision(&config)
            .expect("managed revision should calculate");
        assert!(validate_managed_config(&config).is_err());
    }

    #[test]
    fn parses_socks5_proxy_configuration() {
        let config = parse_client_config(
            r#"
                [client]
                control = "127.0.0.1:32101"
                client_id = "00000000-0000-0000-0000-000000000001"
                client_token = "test-token"

                [[socks5_proxies]]
                name = "office-exit"
                public_port = 32020
            "#,
        )
        .expect("SOCKS5 configuration should parse");

        assert_eq!(config.socks5_proxies.len(), 1);
        assert_eq!(config.socks5_proxies[0].name, "office-exit");
        assert_eq!(config.socks5_proxies[0].public_port, 32020);
    }

    #[test]
    fn parses_http_proxy_configuration() {
        let config = parse_client_config(
            r#"
                [client]
                control = "127.0.0.1:32101"
                client_id = "00000000-0000-0000-0000-000000000001"
                client_token = "test-token"

                [[http_proxies]]
                name = "web-exit"
                public_port = 32022
            "#,
        )
        .expect("HTTP proxy configuration should parse");

        assert_eq!(config.http_proxies.len(), 1);
        assert_eq!(config.http_proxies[0].name, "web-exit");
        assert_eq!(config.http_proxies[0].public_port, 32022);
    }

    #[test]
    fn managed_revision_changes_with_http_proxy_and_rejects_tcp_port_conflict() {
        let mut config = managed_config('h', 32_022);
        let original_revision = config.revision.clone();
        config.http_proxies.push(ManagedHttpProxy {
            name: "web-exit".to_owned(),
            public_port: 32_023,
            enabled: true,
        });
        config.revision = linklake_core::managed_config_revision(&config)
            .expect("managed revision should calculate");
        assert_ne!(config.revision, original_revision);
        validate_managed_config(&config).expect("HTTP proxy should validate");

        config.http_proxies[0].public_port = 32_022;
        config.revision = linklake_core::managed_config_revision(&config)
            .expect("managed revision should calculate");
        assert!(validate_managed_config(&config).is_err());
    }

    #[test]
    fn managed_revision_changes_with_socks5_policy_and_rejects_tcp_port_conflict() {
        let mut config = managed_config('p', 32_020);
        let original_revision = config.revision.clone();
        config.socks5_proxies.push(ManagedSocks5Proxy {
            name: "office-exit".to_owned(),
            public_port: 32_021,
            enabled: true,
        });
        config.revision = linklake_core::managed_config_revision(&config)
            .expect("managed revision should calculate");
        assert_ne!(config.revision, original_revision);
        validate_managed_config(&config).expect("SOCKS5 policy should validate");

        config.socks5_proxies[0].public_port = 32_020;
        config.revision = linklake_core::managed_config_revision(&config)
            .expect("managed revision should calculate");
        assert!(validate_managed_config(&config).is_err());
    }

    #[test]
    fn managed_configuration_is_backed_up_before_replacement() {
        let directory = std::env::temp_dir().join(format!(
            "linklake-managed-config-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&directory).expect("test directory should be created");
        let path = directory.join("managed.toml");
        let first = managed_config('a', 32_001);
        let second = managed_config('b', 32_002);
        persist_managed_config(&path, &first).expect("first config should persist");
        persist_managed_config(&path, &second).expect("second config should persist");

        assert_eq!(
            load_managed_config(&path)
                .expect("current config should load")
                .revision,
            second.revision
        );
        assert_eq!(
            load_managed_config(&std::path::PathBuf::from(format!(
                "{}.backup",
                path.display()
            )))
            .expect("backup config should load")
            .revision,
            first.revision
        );
        std::fs::remove_dir_all(directory).expect("test directory should be removed");
    }

    #[test]
    fn managed_configuration_rejects_duplicate_ports() {
        let mut config = managed_config('c', 32_003);
        config.tcp_tunnels.push(ManagedTcpTunnel {
            name: "duplicate".to_owned(),
            public_port: 32_003,
            target_addr: "127.0.0.1:2".to_owned(),
            enabled: true,
        });
        config.revision = linklake_core::managed_config_revision(&config)
            .expect("managed revision should calculate");
        assert!(validate_managed_config(&config).is_err());
    }

    fn managed_config(_marker: char, public_port: u16) -> ManagedClientConfig {
        let mut config = ManagedClientConfig {
            revision: String::new(),
            tcp_tunnels: vec![ManagedTcpTunnel {
                name: "managed".to_owned(),
                public_port,
                target_addr: "127.0.0.1:1".to_owned(),
                enabled: true,
            }],
            udp_tunnels: Vec::new(),
            http_routes: Vec::new(),
            tls_routes: Vec::new(),
            secret_tunnels: Vec::new(),
            socks5_proxies: Vec::new(),
            http_proxies: Vec::new(),
        };
        config.revision = linklake_core::managed_config_revision(&config)
            .expect("managed revision should calculate");
        config
    }
}

#[derive(Clone)]
struct ControlTransport {
    endpoint: String,
    tls: Option<ControlTls>,
    quic: Option<quinn::ClientConfig>,
}

#[derive(Clone)]
struct ControlTls {
    connector: TlsConnector,
    server_name: ServerName<'static>,
}

impl ControlTransport {
    fn new(
        endpoint: String,
        ca_cert: Option<PathBuf>,
        server_name: Option<String>,
    ) -> anyhow::Result<Self> {
        let Some(ca_cert) = ca_cert else {
            anyhow::ensure!(
                is_loopback_control(&endpoint),
                "--control-ca-cert is required for remote TCP control"
            );
            return Ok(Self {
                endpoint,
                tls: None,
                quic: None,
            });
        };

        let mut cert_file = BufReader::new(File::open(ca_cert)?);
        let certificates = rustls_pemfile::certs(&mut cert_file).collect::<Result<Vec<_>, _>>()?;
        anyhow::ensure!(
            !certificates.is_empty(),
            "control CA certificate file contains no certificates"
        );
        let mut roots = RootCertStore::empty();
        for certificate in certificates {
            roots.add(certificate)?;
        }
        let quic = udp_agent::build_quic_client_config(roots.clone())?;
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let server_name = server_name.unwrap_or_else(|| {
            endpoint
                .rsplit_once(':')
                .map(|(host, _)| host.to_owned())
                .unwrap_or_else(|| endpoint.clone())
        });
        let server_name = ServerName::try_from(server_name)?.to_owned();
        Ok(Self {
            endpoint,
            tls: Some(ControlTls {
                connector: TlsConnector::from(Arc::new(config)),
                server_name,
            }),
            quic: Some(quic),
        })
    }
}

async fn run_tcp_agent(
    transport: ControlTransport,
    client_id: Uuid,
    token: String,
    public_port: u16,
    target: String,
    name: String,
) -> anyhow::Result<()> {
    let mut retry_seconds = 1_u64;
    loop {
        let session_started = std::time::Instant::now();
        let result = run_tcp_agent_session(
            transport.clone(),
            client_id,
            token.clone(),
            public_port,
            target.clone(),
            name.clone(),
        )
        .await;
        if session_started.elapsed() >= std::time::Duration::from_secs(30) {
            retry_seconds = 1;
        }
        let jitter_millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_millis() as u64
            % 750;
        let retry_delay = std::time::Duration::from_millis(retry_seconds * 1000 + jitter_millis);
        match result {
            Ok(()) => {
                tracing::warn!("TCP control session ended; reconnecting in {retry_delay:?}.")
            }
            Err(error) => {
                tracing::warn!(
                    "TCP control session lost: {error}; reconnecting in {retry_delay:?}."
                )
            }
        }
        tokio::time::sleep(retry_delay).await;
        retry_seconds = (retry_seconds * 2).min(30);
    }
}

async fn run_tcp_agent_session(
    transport: ControlTransport,
    client_id: Uuid,
    token: String,
    public_port: u16,
    target: String,
    name: String,
) -> anyhow::Result<()> {
    let mut stream = connect_control(&transport).await?;
    write_control_frame(
        &mut stream,
        &ControlFrame::RegisterTcpTunnel {
            client_id,
            client_token: token.clone(),
            name,
            public_port,
            target_addr: target.clone(),
        },
    )
    .await?;
    match read_control_frame(&mut stream).await? {
        ControlFrame::TcpTunnelRegistered { public_port } => {
            tracing::info!("TCP tunnel registered on public port {public_port}.")
        }
        ControlFrame::Error { message } => anyhow::bail!("server rejected TCP tunnel: {message}"),
        frame => anyhow::bail!("unexpected registration response: {frame:?}"),
    }
    let (reader, writer) = split(stream);
    let heartbeat = tokio::spawn(send_control_heartbeats(writer));
    let result = read_registered_control(reader, transport, target, client_id, token).await;
    heartbeat.abort();
    result
}

async fn run_http_agent(
    transport: ControlTransport,
    client_id: Uuid,
    token: String,
    hostname: String,
    target: String,
    name: String,
) -> anyhow::Result<()> {
    let mut retry_seconds = 1_u64;
    loop {
        let session_started = std::time::Instant::now();
        let result = run_http_agent_session(
            transport.clone(),
            client_id,
            token.clone(),
            hostname.clone(),
            target.clone(),
            name.clone(),
        )
        .await;
        if session_started.elapsed() >= std::time::Duration::from_secs(30) {
            retry_seconds = 1;
        }
        let jitter_millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_millis() as u64
            % 750;
        let retry_delay = std::time::Duration::from_millis(retry_seconds * 1000 + jitter_millis);
        match result {
            Ok(()) => {
                tracing::warn!("HTTP route control session ended; reconnecting in {retry_delay:?}.")
            }
            Err(error) => tracing::warn!(
                "HTTP route control session lost: {error}; reconnecting in {retry_delay:?}."
            ),
        }
        tokio::time::sleep(retry_delay).await;
        retry_seconds = (retry_seconds * 2).min(30);
    }
}

async fn run_http_agent_session(
    transport: ControlTransport,
    client_id: Uuid,
    token: String,
    hostname: String,
    target: String,
    name: String,
) -> anyhow::Result<()> {
    let mut stream = connect_control(&transport).await?;
    write_control_frame(
        &mut stream,
        &ControlFrame::RegisterHttpRoute {
            client_id,
            client_token: token.clone(),
            name,
            hostname,
            target_addr: target.clone(),
        },
    )
    .await?;
    match read_control_frame(&mut stream).await? {
        ControlFrame::HttpRouteRegistered { hostname } => {
            tracing::info!("HTTP route registered for hostname {hostname}.")
        }
        ControlFrame::Error { message } => {
            anyhow::bail!("server rejected HTTP route: {message}")
        }
        frame => anyhow::bail!("unexpected registration response: {frame:?}"),
    }
    let (reader, writer) = split(stream);
    let heartbeat = tokio::spawn(send_control_heartbeats(writer));
    let result = read_registered_control(reader, transport, target, client_id, token).await;
    heartbeat.abort();
    result
}

async fn run_tls_route_agent(
    transport: ControlTransport,
    client_id: Uuid,
    token: String,
    hostname: String,
    target: String,
    name: String,
) -> anyhow::Result<()> {
    let mut retry_seconds = 1_u64;
    loop {
        let started = std::time::Instant::now();
        let result = run_tls_route_agent_session(
            transport.clone(),
            client_id,
            token.clone(),
            hostname.clone(),
            target.clone(),
            name.clone(),
        )
        .await;
        if started.elapsed() >= Duration::from_secs(30) {
            retry_seconds = 1;
        }
        let delay = Duration::from_secs(retry_seconds);
        match result {
            Ok(()) => tracing::warn!("TLS SNI route ended; reconnecting in {delay:?}."),
            Err(error) => tracing::warn!("TLS SNI route lost: {error}; reconnecting in {delay:?}."),
        }
        tokio::time::sleep(delay).await;
        retry_seconds = (retry_seconds * 2).min(30);
    }
}

async fn run_tls_route_agent_session(
    transport: ControlTransport,
    client_id: Uuid,
    token: String,
    hostname: String,
    target: String,
    name: String,
) -> anyhow::Result<()> {
    let mut stream = connect_control(&transport).await?;
    write_control_frame(
        &mut stream,
        &ControlFrame::RegisterTlsRoute {
            client_id,
            client_token: token.clone(),
            name,
            hostname,
            target_addr: target.clone(),
        },
    )
    .await?;
    match read_control_frame(&mut stream).await? {
        ControlFrame::TlsRouteRegistered { hostname } => {
            tracing::info!("TLS SNI route registered for hostname {hostname}.")
        }
        ControlFrame::Error { message } => anyhow::bail!("server rejected TLS route: {message}"),
        frame => anyhow::bail!("unexpected TLS route registration response: {frame:?}"),
    }
    let (reader, writer) = split(stream);
    let heartbeat = tokio::spawn(send_control_heartbeats(writer));
    let result = read_registered_control(reader, transport, target, client_id, token).await;
    heartbeat.abort();
    result
}

async fn run_socks5_agent(
    transport: ControlTransport,
    client_id: Uuid,
    token: String,
    public_port: u16,
    name: String,
    udp_queue_budget: Arc<tokio::sync::Semaphore>,
) -> anyhow::Result<()> {
    let mut retry_seconds = 1_u64;
    loop {
        let session_started = std::time::Instant::now();
        let result = run_socks5_agent_session(
            transport.clone(),
            client_id,
            token.clone(),
            public_port,
            name.clone(),
            udp_queue_budget.clone(),
        )
        .await;
        if session_started.elapsed() >= Duration::from_secs(30) {
            retry_seconds = 1;
        }
        let jitter_millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_millis() as u64
            % 750;
        let retry_delay = Duration::from_millis(retry_seconds * 1_000 + jitter_millis);
        match result {
            Ok(()) => tracing::warn!(
                "SOCKS5 proxy control session ended; reconnecting in {retry_delay:?}."
            ),
            Err(error) => tracing::warn!(
                "SOCKS5 proxy control session lost: {error}; reconnecting in {retry_delay:?}."
            ),
        }
        tokio::time::sleep(retry_delay).await;
        retry_seconds = (retry_seconds * 2).min(30);
    }
}

async fn run_socks5_agent_session(
    transport: ControlTransport,
    client_id: Uuid,
    token: String,
    public_port: u16,
    name: String,
    udp_queue_budget: Arc<tokio::sync::Semaphore>,
) -> anyhow::Result<()> {
    let mut stream = connect_control(&transport).await?;
    write_control_frame(
        &mut stream,
        &ControlFrame::RegisterSocks5Proxy {
            client_id,
            client_token: token.clone(),
            name,
            public_port,
        },
    )
    .await?;
    let first = read_control_frame(&mut stream).await?;
    let (registered, udp_data_plane) = match first {
        ControlFrame::Socks5UdpDataPlaneOffer {
            registration_id,
            ticket,
            endpoint,
            server_name,
            max_datagram_size,
            session_idle_timeout_seconds,
        } => {
            let offer = udp_agent::UdpDataPlaneOffer {
                registration_id,
                ticket,
                endpoint,
                server_name,
                max_datagram_size: max_datagram_size as usize,
                session_idle_timeout: Duration::from_secs(u64::from(session_idle_timeout_seconds)),
            };
            let established =
                udp_agent::establish_data_plane(&transport, client_id, &offer).await?;
            (
                read_control_frame(&mut stream).await?,
                Some((established, offer.session_idle_timeout)),
            )
        }
        frame => (frame, None),
    };
    match registered {
        ControlFrame::Socks5ProxyRegistered {
            public_port,
            udp_associate,
            ..
        } => {
            tracing::info!("SOCKS5 proxy registered on public port {public_port}.");
            anyhow::ensure!(
                udp_associate == udp_data_plane.is_some(),
                "SOCKS5 UDP negotiation state mismatch"
            );
        }
        ControlFrame::Error { message } => {
            anyhow::bail!("server rejected SOCKS5 proxy: {message}")
        }
        frame => anyhow::bail!("unexpected SOCKS5 registration response: {frame:?}"),
    }
    let (reader, writer) = split(stream);
    let heartbeat = tokio::spawn(send_control_heartbeats(writer));
    let control = read_socks5_registered_control(reader, transport, client_id, token);
    let result = if let Some((data_plane, idle_timeout)) = udp_data_plane {
        tokio::select! {
            result = control => result,
            result = socks5_udp_agent::run(data_plane, idle_timeout, udp_queue_budget) => result,
        }
    } else {
        control.await
    };
    heartbeat.abort();
    result
}

async fn read_socks5_registered_control(
    mut reader: ReadHalf<BoxedIo>,
    transport: ControlTransport,
    client_id: Uuid,
    token: String,
) -> anyhow::Result<()> {
    loop {
        let frame = timeout(CONTROL_HEARTBEAT_TIMEOUT, read_control_frame(&mut reader))
            .await
            .map_err(|_| anyhow::anyhow!("control heartbeat acknowledgement timed out"))??;
        match frame {
            ControlFrame::OpenSocks5Connection {
                connection_id,
                target_host,
                target_port,
            } => {
                let transport = transport.clone();
                let token = token.clone();
                tokio::spawn(async move {
                    if let Err(error) = open_socks5_data_connection(
                        transport,
                        target_host,
                        target_port,
                        client_id,
                        token,
                        connection_id,
                    )
                    .await
                    {
                        tracing::warn!("SOCKS5 connection {connection_id} failed: {error}");
                    }
                });
            }
            ControlFrame::ControlHeartbeatAck { .. } => {}
            ControlFrame::Error { message } => anyhow::bail!("server closed proxy: {message}"),
            frame => anyhow::bail!("unexpected SOCKS5 control frame: {frame:?}"),
        }
    }
}

async fn open_socks5_data_connection(
    transport: ControlTransport,
    target_host: String,
    target_port: u16,
    client_id: Uuid,
    client_token: String,
    connection_id: Uuid,
) -> anyhow::Result<()> {
    let mut target_stream = timeout(
        TARGET_CONNECT_TIMEOUT,
        TcpStream::connect((target_host.as_str(), target_port)),
    )
    .await
    .map_err(|_| anyhow::anyhow!("SOCKS5 target connection timed out"))??;
    let mut data_stream = connect_control(&transport).await?;
    write_control_frame(
        &mut data_stream,
        &ControlFrame::TcpDataConnection {
            client_id,
            client_token,
            connection_id,
        },
    )
    .await?;
    copy_bidirectional(&mut data_stream, &mut target_stream).await?;
    Ok(())
}

async fn run_http_proxy_agent(
    transport: ControlTransport,
    client_id: Uuid,
    token: String,
    public_port: u16,
    name: String,
) -> anyhow::Result<()> {
    let mut retry_seconds = 1_u64;
    loop {
        let session_started = std::time::Instant::now();
        let result = run_http_proxy_agent_session(
            transport.clone(),
            client_id,
            token.clone(),
            public_port,
            name.clone(),
        )
        .await;
        if session_started.elapsed() >= Duration::from_secs(30) {
            retry_seconds = 1;
        }
        let jitter_millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_millis() as u64
            % 750;
        let retry_delay = Duration::from_millis(retry_seconds * 1_000 + jitter_millis);
        match result {
            Ok(()) => tracing::warn!(
                "HTTP forward proxy control session ended; reconnecting in {retry_delay:?}."
            ),
            Err(error) => tracing::warn!(
                "HTTP forward proxy control session lost: {error}; reconnecting in {retry_delay:?}."
            ),
        }
        tokio::time::sleep(retry_delay).await;
        retry_seconds = (retry_seconds * 2).min(30);
    }
}

async fn run_http_proxy_agent_session(
    transport: ControlTransport,
    client_id: Uuid,
    token: String,
    public_port: u16,
    name: String,
) -> anyhow::Result<()> {
    let mut stream = connect_control(&transport).await?;
    write_control_frame(
        &mut stream,
        &ControlFrame::RegisterHttpProxy {
            client_id,
            client_token: token.clone(),
            name,
            public_port,
        },
    )
    .await?;
    match read_control_frame(&mut stream).await? {
        ControlFrame::HttpProxyRegistered { public_port, .. } => {
            tracing::info!("HTTP forward proxy registered on public port {public_port}.");
        }
        ControlFrame::Error { message } => {
            anyhow::bail!("server rejected HTTP forward proxy: {message}")
        }
        frame => anyhow::bail!("unexpected HTTP proxy registration response: {frame:?}"),
    }
    let (reader, writer) = split(stream);
    let heartbeat = tokio::spawn(send_control_heartbeats(writer));
    let result = read_http_proxy_registered_control(reader, transport, client_id, token).await;
    heartbeat.abort();
    result
}

async fn read_http_proxy_registered_control(
    mut reader: ReadHalf<BoxedIo>,
    transport: ControlTransport,
    client_id: Uuid,
    token: String,
) -> anyhow::Result<()> {
    loop {
        let frame = timeout(CONTROL_HEARTBEAT_TIMEOUT, read_control_frame(&mut reader))
            .await
            .map_err(|_| anyhow::anyhow!("control heartbeat acknowledgement timed out"))??;
        match frame {
            ControlFrame::OpenHttpProxyConnection {
                connection_id,
                target_host,
                target_port,
            } => {
                let transport = transport.clone();
                let token = token.clone();
                tokio::spawn(async move {
                    if let Err(error) = open_http_proxy_data_connection(
                        transport,
                        target_host,
                        target_port,
                        client_id,
                        token,
                        connection_id,
                    )
                    .await
                    {
                        tracing::warn!("HTTP proxy connection {connection_id} failed: {error}");
                    }
                });
            }
            ControlFrame::ControlHeartbeatAck { .. } => {}
            ControlFrame::Error { message } => anyhow::bail!("server closed proxy: {message}"),
            frame => anyhow::bail!("unexpected HTTP proxy control frame: {frame:?}"),
        }
    }
}

async fn open_http_proxy_data_connection(
    transport: ControlTransport,
    target_host: String,
    target_port: u16,
    client_id: Uuid,
    client_token: String,
    connection_id: Uuid,
) -> anyhow::Result<()> {
    let mut target_stream = timeout(
        TARGET_CONNECT_TIMEOUT,
        TcpStream::connect((target_host.as_str(), target_port)),
    )
    .await
    .map_err(|_| anyhow::anyhow!("HTTP proxy target connection timed out"))??;
    let mut data_stream = connect_control(&transport).await?;
    write_control_frame(
        &mut data_stream,
        &ControlFrame::TcpDataConnection {
            client_id,
            client_token,
            connection_id,
        },
    )
    .await?;
    copy_bidirectional(&mut data_stream, &mut target_stream).await?;
    Ok(())
}

async fn run_secret_target_agent(
    transport: ControlTransport,
    client_id: Uuid,
    token: String,
    target: String,
    name: String,
) -> anyhow::Result<()> {
    let mut retry_seconds = 1_u64;
    loop {
        let session_started = std::time::Instant::now();
        let result = run_secret_target_session(
            transport.clone(),
            client_id,
            token.clone(),
            target.clone(),
            name.clone(),
        )
        .await;
        if session_started.elapsed() >= Duration::from_secs(30) {
            retry_seconds = 1;
        }
        let jitter_millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_millis() as u64
            % 750;
        let retry_delay = Duration::from_millis(retry_seconds * 1_000 + jitter_millis);
        match result {
            Ok(()) => tracing::warn!(
                "Secret tunnel target control session ended; reconnecting in {retry_delay:?}."
            ),
            Err(error) => tracing::warn!(
                "Secret tunnel target control session lost: {error}; reconnecting in {retry_delay:?}."
            ),
        }
        tokio::time::sleep(retry_delay).await;
        retry_seconds = (retry_seconds * 2).min(30);
    }
}

async fn run_secret_target_session(
    transport: ControlTransport,
    client_id: Uuid,
    token: String,
    target: String,
    name: String,
) -> anyhow::Result<()> {
    let mut stream = connect_control(&transport).await?;
    write_control_frame(
        &mut stream,
        &ControlFrame::RegisterSecretTunnel {
            client_id,
            client_token: token.clone(),
            name,
            target_addr: target.clone(),
        },
    )
    .await?;
    match read_control_frame(&mut stream).await? {
        ControlFrame::SecretTunnelRegistered { tunnel_id } => {
            tracing::info!("Secret tunnel target registered as {tunnel_id}.");
        }
        ControlFrame::Error { message } => {
            anyhow::bail!("server rejected secret tunnel target: {message}")
        }
        frame => anyhow::bail!("unexpected secret tunnel registration response: {frame:?}"),
    }
    let (reader, writer) = split(stream);
    let heartbeat = tokio::spawn(send_control_heartbeats(writer));
    let result = read_registered_control(reader, transport, target, client_id, token).await;
    heartbeat.abort();
    result
}

async fn run_secret_visitor(
    transport: ControlTransport,
    client_id: Uuid,
    token: String,
    local_bind: String,
    access_key: String,
    name: String,
    prefer_direct: bool,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&local_bind).await?;
    tracing::info!("Secret visitor {name} listening on {local_bind}.");
    loop {
        let (local, _) = listener.accept().await?;
        let transport = transport.clone();
        let token = token.clone();
        let access_key = access_key.clone();
        tokio::spawn(async move {
            if let Err(error) = run_secret_visitor_connection(
                transport,
                client_id,
                token,
                access_key,
                local,
                prefer_direct,
            )
            .await
            {
                tracing::warn!("Secret visitor connection failed: {error}");
            }
        });
    }
}

async fn run_secret_visitor_connection(
    transport: ControlTransport,
    client_id: Uuid,
    token: String,
    access_key: String,
    mut local: TcpStream,
    prefer_direct: bool,
) -> anyhow::Result<()> {
    let fallback_reason = if prefer_direct {
        try_p2p_direct(&transport, client_id, &token, &access_key, &mut local).await?
    } else {
        None
    };
    if prefer_direct && fallback_reason.is_none() {
        return Ok(());
    }
    if let Some(reason) = fallback_reason {
        let mut report = connect_control(&transport).await?;
        write_control_frame(
            &mut report,
            &ControlFrame::ReportP2pFallback {
                client_id,
                client_token: token.clone(),
                reason,
            },
        )
        .await?;
        match timeout(CONTROL_HEARTBEAT_TIMEOUT, read_control_frame(&mut report)).await?? {
            ControlFrame::P2pFallbackRecorded => {}
            ControlFrame::Error { message } => {
                anyhow::bail!("P2P fallback report rejected: {message}")
            }
            frame => anyhow::bail!("unexpected P2P fallback response: {frame:?}"),
        }
    }
    let mut remote = connect_control(&transport).await?;
    write_control_frame(
        &mut remote,
        &ControlFrame::ConnectSecretTunnel {
            client_id,
            client_token: token,
            access_key,
        },
    )
    .await?;
    match timeout(CONTROL_HEARTBEAT_TIMEOUT, read_control_frame(&mut remote)).await?? {
        ControlFrame::SecretTunnelConnected { .. } => {}
        ControlFrame::Error { message } => anyhow::bail!("secret tunnel rejected: {message}"),
        frame => anyhow::bail!("unexpected secret tunnel connection response: {frame:?}"),
    }
    copy_bidirectional(&mut local, &mut remote).await?;
    Ok(())
}

async fn try_p2p_direct(
    transport: &ControlTransport,
    client_id: Uuid,
    token: &str,
    access_key: &str,
    local: &mut TcpStream,
) -> anyhow::Result<Option<linklake_core::p2p_protocol::P2pFallbackReason>> {
    let mut control = connect_control(transport).await?;
    write_control_frame(
        &mut control,
        &ControlFrame::RequestP2pSession {
            client_id,
            client_token: token.to_owned(),
            access_key: access_key.to_owned(),
        },
    )
    .await?;
    let (ticket, noise_psk, candidates) = match read_control_frame(&mut control).await? {
        ControlFrame::P2pSessionOffer {
            ticket,
            noise_psk,
            candidates,
            ..
        } => (ticket, noise_psk, candidates),
        ControlFrame::Error { .. } => {
            return Ok(Some(
                linklake_core::p2p_protocol::P2pFallbackReason::AuthenticationFailed,
            ))
        }
        _ => {
            return Ok(Some(
                linklake_core::p2p_protocol::P2pFallbackReason::ProtocolError,
            ))
        }
    };
    if candidates.is_empty() {
        return Ok(Some(
            linklake_core::p2p_protocol::P2pFallbackReason::NoCandidate,
        ));
    }
    if ticket.len() > 16 * 1024 {
        return Ok(Some(
            linklake_core::p2p_protocol::P2pFallbackReason::ProtocolError,
        ));
    }

    // 只竞速传输层建连；票据仅发送给胜出的候选，避免单次票据被败选连接消费。
    let mut attempts = JoinSet::new();
    for candidate in candidates {
        let token = token.to_owned();
        attempts.spawn(async move { dial_p2p_candidate(candidate, token).await });
    }
    let mut fallback = linklake_core::p2p_protocol::P2pFallbackReason::DirectRefused;
    let winner = loop {
        match attempts.join_next().await {
            Some(Ok(Ok(direct))) => break Some(direct),
            Some(Ok(Err(reason))) => fallback = reason,
            Some(Err(_)) => {
                fallback = linklake_core::p2p_protocol::P2pFallbackReason::ProtocolError
            }
            None => break None,
        }
    };
    attempts.abort_all();
    let Some(winner) = winner else {
        return Ok(Some(fallback));
    };

    let result = match winner {
        P2pDial::Tcp(mut direct) => {
            direct.write_u32(ticket.len() as u32).await?;
            direct.write_all(ticket.as_bytes()).await?;
            let noise = timeout(
                Duration::from_secs(5),
                p2p_noise::initiate(&mut direct, &noise_psk),
            )
            .await
            .map_err(|_| anyhow::anyhow!("P2P Noise handshake timed out"))??;
            p2p_noise::relay_encrypted(local, &mut direct, noise).await
        }
        P2pDial::Iroh {
            endpoint,
            connection,
        } => finish_iroh_direct(endpoint, connection, &ticket, local).await,
    };
    match result {
        Ok(()) => Ok(None),
        Err(error) => {
            tracing::debug!("P2P winner failed authentication or relay: {error}");
            Ok(Some(
                linklake_core::p2p_protocol::P2pFallbackReason::AuthenticationFailed,
            ))
        }
    }
}

enum P2pDial {
    Tcp(TcpStream),
    Iroh {
        endpoint: iroh::Endpoint,
        connection: iroh::endpoint::Connection,
    },
}

async fn dial_p2p_candidate(
    candidate: linklake_core::p2p_protocol::P2pCandidate,
    token: String,
) -> Result<P2pDial, linklake_core::p2p_protocol::P2pFallbackReason> {
    use linklake_core::p2p_protocol::{P2pFallbackReason, P2pTransport};
    match candidate.transport {
        P2pTransport::Tcp => match timeout(
            Duration::from_secs(2),
            TcpStream::connect(&candidate.endpoint),
        )
        .await
        {
            Ok(Ok(stream)) => Ok(P2pDial::Tcp(stream)),
            Ok(Err(_)) => Err(P2pFallbackReason::DirectRefused),
            Err(_) => Err(P2pFallbackReason::DirectTimeout),
        },
        P2pTransport::IrohQuic => {
            match timeout(
                Duration::from_secs(15),
                p2p_iroh::connect(&candidate, &token),
            )
            .await
            {
                Ok(Ok((endpoint, connection))) => Ok(P2pDial::Iroh {
                    endpoint,
                    connection,
                }),
                Ok(Err(_)) | Err(_) => Err(P2pFallbackReason::DirectTimeout),
            }
        }
    }
}

async fn finish_iroh_direct(
    endpoint: iroh::Endpoint,
    connection: iroh::endpoint::Connection,
    ticket: &str,
    local: &mut TcpStream,
) -> anyhow::Result<()> {
    let (mut send, mut receive) = connection.open_bi().await?;
    send.write_u32(ticket.len() as u32).await?;
    send.write_all(ticket.as_bytes()).await?;
    send.flush().await?;
    anyhow::ensure!(
        receive.read_u8().await? == 1,
        "Iroh P2P target rejected the session"
    );
    let result = p2p_iroh::relay_tcp_quic(local, send, receive).await;
    endpoint.close().await;
    result
}

async fn run_p2p_provider(
    transport: ControlTransport,
    client_id: Uuid,
    token: String,
    config: P2pProviderConfig,
) -> anyhow::Result<()> {
    let bind_address: SocketAddr = config.bind.parse()?;
    let listener = if config.tcp_enabled {
        Some(TcpListener::bind(bind_address).await?)
    } else {
        None
    };
    let mut iroh = None;
    let mut iroh_builder = config
        .iroh_enabled
        .then(|| spawn_p2p_iroh_builder(bind_address, config.relay_url.clone(), token.clone()));

    // TCP 候选不应因为 Iroh 会合服务暂时不可用而消失。
    if let Err(error) = refresh_p2p_registration(
        &transport,
        client_id,
        &token,
        iroh.as_ref(),
        &config.endpoint,
        config.tcp_enabled,
        config.iroh_enabled,
    )
    .await
    {
        tracing::warn!("Initial P2P candidate registration failed: {error}");
    }
    let mut refresh = interval(Duration::from_secs(30));
    refresh.set_missed_tick_behavior(MissedTickBehavior::Delay);
    refresh.tick().await;
    let mut iroh_retry = interval(Duration::from_secs(30));
    iroh_retry.set_missed_tick_behavior(MissedTickBehavior::Delay);
    iroh_retry.tick().await;
    loop {
        tokio::select! {
            built = async {
                iroh_builder
                    .as_mut()
                    .expect("Iroh builder branch must be guarded")
                    .await
            }, if iroh_builder.is_some() => {
                iroh_builder = None;
                match built {
                    Ok(Ok(endpoint_handle)) => {
                        tracing::info!("Iroh P2P endpoint is ready.");
                        iroh = Some(endpoint_handle);
                        if let Err(error) = refresh_p2p_registration(
                            &transport,
                            client_id,
                            &token,
                            iroh.as_ref(),
                            &config.endpoint,
                            config.tcp_enabled,
                            config.iroh_enabled,
                        ).await {
                            tracing::warn!("P2P candidate registration after Iroh startup failed: {error}");
                        }
                    }
                    Ok(Err(error)) => tracing::warn!(
                        "Iroh P2P initialization failed; TCP P2P remains available: {error}"
                    ),
                    Err(error) => tracing::warn!(
                        "Iroh P2P initialization task stopped; TCP P2P remains available: {error}"
                    ),
                }
            }
            _ = iroh_retry.tick(), if config.iroh_enabled && iroh.is_none() && iroh_builder.is_none() => {
                iroh_builder = Some(spawn_p2p_iroh_builder(
                    bind_address,
                    config.relay_url.clone(),
                    token.clone(),
                ));
            }
            _ = refresh.tick() => {
                if let Err(error) = refresh_p2p_registration(
                    &transport,
                    client_id,
                    &token,
                    iroh.as_ref(),
                    &config.endpoint,
                    config.tcp_enabled,
                    config.iroh_enabled,
                ).await {
                    tracing::warn!("P2P candidate refresh failed: {error}");
                }
            }
            accepted = async {
                listener
                    .as_ref()
                    .expect("TCP listener branch must be guarded")
                    .accept()
                    .await
            }, if listener.is_some() => {
                match accepted {
                    Ok((direct, _)) => {
                        let transport = transport.clone();
                        let token = token.clone();
                        tokio::spawn(async move {
                            if let Err(error) = handle_p2p_direct(direct, transport, client_id, token).await {
                                tracing::warn!("P2P direct connection rejected: {error}");
                            }
                        });
                    }
                    Err(error) => tracing::warn!("P2P TCP accept failed: {error}"),
                }
            }
            incoming = async {
                iroh.as_ref()
                    .expect("Iroh accept branch must be guarded")
                    .accept()
                    .await
            }, if iroh.is_some() => {
                match incoming {
                    Some(incoming) => {
                        let endpoint_handle = iroh.as_ref().expect("Iroh endpoint should exist").clone();
                        let transport = transport.clone();
                        let token = token.clone();
                        tokio::spawn(async move {
                            if let Err(error) = handle_p2p_iroh(incoming, endpoint_handle, transport, client_id, token).await {
                                tracing::warn!("Iroh P2P direct connection rejected: {error}");
                            }
                        });
                    }
                    None => {
                        tracing::warn!("Iroh P2P endpoint closed; scheduling a restart.");
                        iroh = None;
                    }
                }
            }
        }
    }
}

async fn supervise_p2p_provider(
    transport: ControlTransport,
    client_id: Uuid,
    token: String,
    config: P2pProviderConfig,
) {
    loop {
        let result =
            run_p2p_provider(transport.clone(), client_id, token.clone(), config.clone()).await;
        match result {
            Ok(()) => tracing::warn!("P2P provider stopped; restarting in 5 seconds."),
            Err(error) => tracing::warn!("P2P provider failed: {error}; restarting in 5 seconds."),
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

fn spawn_p2p_iroh_builder(
    bind: SocketAddr,
    relay_url: Option<String>,
    token: String,
) -> JoinHandle<anyhow::Result<iroh::Endpoint>> {
    tokio::spawn(
        async move { p2p_iroh::build_endpoint(bind, relay_url.as_deref(), &token, true).await },
    )
}

async fn p2p_candidates(
    iroh: Option<&iroh::Endpoint>,
    tcp_endpoint: &str,
    tcp_enabled: bool,
    iroh_enabled: bool,
) -> anyhow::Result<Vec<linklake_core::p2p_protocol::P2pCandidate>> {
    let mut candidates = Vec::with_capacity(2);
    if let (true, Some(iroh)) = (iroh_enabled, iroh) {
        match p2p_iroh::candidate(iroh, 0).await {
            Ok(candidate) => candidates.push(candidate),
            Err(error) if tcp_enabled => {
                tracing::warn!("Iroh candidate discovery failed; publishing TCP only: {error}");
            }
            Err(error) => return Err(error),
        }
    }
    if tcp_enabled {
        candidates.push(linklake_core::p2p_protocol::P2pCandidate {
            transport: linklake_core::p2p_protocol::P2pTransport::Tcp,
            endpoint: tcp_endpoint.to_owned(),
            priority: 10,
        });
    }
    Ok(candidates)
}

async fn refresh_p2p_registration(
    transport: &ControlTransport,
    client_id: Uuid,
    token: &str,
    iroh: Option<&iroh::Endpoint>,
    tcp_endpoint: &str,
    tcp_enabled: bool,
    iroh_enabled: bool,
) -> anyhow::Result<()> {
    let candidates = p2p_candidates(iroh, tcp_endpoint, tcp_enabled, iroh_enabled).await?;
    if candidates.is_empty() {
        return Ok(());
    }
    register_p2p_candidates(transport, client_id, token, candidates).await
}

async fn register_p2p_candidates(
    transport: &ControlTransport,
    client_id: Uuid,
    token: &str,
    candidates: Vec<linklake_core::p2p_protocol::P2pCandidate>,
) -> anyhow::Result<()> {
    let mut registration = connect_control(transport).await?;
    write_control_frame(
        &mut registration,
        &ControlFrame::RegisterP2pNode {
            client_id,
            client_token: token.to_owned(),
            candidates,
        },
    )
    .await?;
    match read_control_frame(&mut registration).await? {
        ControlFrame::P2pNodeRegistered => {}
        ControlFrame::Error { message } => anyhow::bail!("P2P node rejected: {message}"),
        frame => anyhow::bail!("unexpected P2P registration response: {frame:?}"),
    }
    Ok(())
}

async fn handle_p2p_direct(
    mut direct: TcpStream,
    transport: ControlTransport,
    client_id: Uuid,
    token: String,
) -> anyhow::Result<()> {
    let ticket = timeout(Duration::from_secs(5), read_p2p_ticket(&mut direct)).await??;
    let (session_id, visitor_client_id, target, noise_psk) =
        validate_p2p_ticket(&transport, client_id, &token, ticket).await?;
    let mut target = timeout(TARGET_CONNECT_TIMEOUT, TcpStream::connect(target)).await??;
    let noise = timeout(
        Duration::from_secs(5),
        p2p_noise::respond(&mut direct, &noise_psk),
    )
    .await
    .map_err(|_| anyhow::anyhow!("P2P Noise handshake timed out"))??;
    if let Err(error) =
        report_p2p_direct_success(&transport, client_id, &token, session_id, visitor_client_id)
            .await
    {
        tracing::warn!("P2P direct-success report failed: {error}");
    }
    p2p_noise::relay_encrypted(&mut target, &mut direct, noise).await?;
    Ok(())
}

async fn handle_p2p_iroh(
    incoming: iroh::endpoint::Incoming,
    endpoint: iroh::Endpoint,
    transport: ControlTransport,
    client_id: Uuid,
    token: String,
) -> anyhow::Result<()> {
    let connection = incoming.accept()?.await?;
    p2p_iroh::wait_for_direct(&endpoint, connection.remote_node_id()?).await?;
    let (mut send, mut receive) = connection.accept_bi().await?;
    let ticket = timeout(Duration::from_secs(5), read_p2p_ticket(&mut receive)).await??;
    let (session_id, visitor_client_id, target, _) =
        validate_p2p_ticket(&transport, client_id, &token, ticket).await?;
    let mut target = timeout(TARGET_CONNECT_TIMEOUT, TcpStream::connect(target)).await??;
    send.write_u8(1).await?;
    send.flush().await?;
    if let Err(error) =
        report_p2p_direct_success(&transport, client_id, &token, session_id, visitor_client_id)
            .await
    {
        tracing::warn!("Iroh P2P direct-success report failed: {error}");
    }
    p2p_iroh::relay_tcp_quic(&mut target, send, receive).await
}

async fn read_p2p_ticket<R>(reader: &mut R) -> anyhow::Result<String>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let length = reader.read_u32().await? as usize;
    anyhow::ensure!(
        length != 0 && length <= 16 * 1024,
        "invalid P2P ticket length"
    );
    let mut ticket = vec![0_u8; length];
    reader.read_exact(&mut ticket).await?;
    String::from_utf8(ticket).map_err(Into::into)
}

async fn validate_p2p_ticket(
    transport: &ControlTransport,
    client_id: Uuid,
    token: &str,
    ticket: String,
) -> anyhow::Result<(Uuid, Uuid, String, [u8; 32])> {
    let mut control = connect_control(transport).await?;
    write_control_frame(
        &mut control,
        &ControlFrame::ValidateP2pTicket {
            client_id,
            client_token: token.to_owned(),
            ticket,
        },
    )
    .await?;
    match read_control_frame(&mut control).await? {
        ControlFrame::P2pTicketValid {
            session_id,
            visitor_client_id,
            target_addr,
            noise_psk,
        } => Ok((session_id, visitor_client_id, target_addr, noise_psk)),
        ControlFrame::Error { message } => anyhow::bail!("ticket rejected: {message}"),
        frame => anyhow::bail!("unexpected P2P validation response: {frame:?}"),
    }
}

async fn report_p2p_direct_success(
    transport: &ControlTransport,
    client_id: Uuid,
    token: &str,
    session_id: Uuid,
    visitor_client_id: Uuid,
) -> anyhow::Result<()> {
    let mut report = connect_control(transport).await?;
    write_control_frame(
        &mut report,
        &ControlFrame::ReportP2pDirectSuccess {
            client_id,
            client_token: token.to_owned(),
            session_id,
            visitor_client_id,
        },
    )
    .await?;
    match timeout(CONTROL_HEARTBEAT_TIMEOUT, read_control_frame(&mut report)).await?? {
        ControlFrame::P2pDirectSuccessRecorded => Ok(()),
        ControlFrame::Error { message } => {
            anyhow::bail!("P2P direct-success report rejected: {message}")
        }
        frame => anyhow::bail!("unexpected P2P direct-success response: {frame:?}"),
    }
}

async fn send_control_heartbeats(mut writer: WriteHalf<BoxedIo>) -> anyhow::Result<()> {
    let mut heartbeat = interval(CONTROL_HEARTBEAT_INTERVAL);
    heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut nonce = 0_u64;
    loop {
        heartbeat.tick().await;
        nonce = nonce.wrapping_add(1);
        write_control_frame(&mut writer, &ControlFrame::ControlHeartbeat { nonce }).await?;
    }
}

async fn read_registered_control(
    mut reader: ReadHalf<BoxedIo>,
    transport: ControlTransport,
    target: String,
    client_id: Uuid,
    token: String,
) -> anyhow::Result<()> {
    loop {
        let frame = timeout(CONTROL_HEARTBEAT_TIMEOUT, read_control_frame(&mut reader))
            .await
            .map_err(|_| anyhow::anyhow!("control heartbeat acknowledgement timed out"))??;
        match frame {
            ControlFrame::OpenTcpConnection { connection_id }
            | ControlFrame::OpenSecretConnection { connection_id } => {
                let transport = transport.clone();
                let target = target.clone();
                let token = token.clone();
                tokio::spawn(async move {
                    if let Err(error) =
                        open_tcp_data_connection(transport, target, client_id, token, connection_id)
                            .await
                    {
                        tracing::warn!("TCP tunnel connection {connection_id} failed: {error}");
                    }
                });
            }
            ControlFrame::ControlHeartbeatAck { .. } => {}
            ControlFrame::Error { message } => anyhow::bail!("server closed tunnel: {message}"),
            frame => anyhow::bail!("unexpected control frame: {frame:?}"),
        }
    }
}

async fn open_tcp_data_connection(
    transport: ControlTransport,
    target: String,
    client_id: Uuid,
    client_token: String,
    connection_id: Uuid,
) -> anyhow::Result<()> {
    let mut data_stream = connect_control(&transport).await?;
    write_control_frame(
        &mut data_stream,
        &ControlFrame::TcpDataConnection {
            client_id,
            client_token,
            connection_id,
        },
    )
    .await?;
    let mut target_stream = timeout(TARGET_CONNECT_TIMEOUT, TcpStream::connect(target))
        .await
        .map_err(|_| anyhow::anyhow!("target connection timed out"))??;
    copy_bidirectional(&mut data_stream, &mut target_stream).await?;
    Ok(())
}

async fn connect_control(transport: &ControlTransport) -> anyhow::Result<BoxedIo> {
    let tcp_stream = TcpStream::connect(&transport.endpoint).await?;
    let Some(tls) = &transport.tls else {
        return Ok(Box::new(tcp_stream));
    };
    let tls_stream = tls
        .connector
        .connect(tls.server_name.clone(), tcp_stream)
        .await?;
    Ok(Box::new(tls_stream))
}

fn is_loopback_control(endpoint: &str) -> bool {
    endpoint.starts_with("127.")
        || endpoint.starts_with("[::1]")
        || endpoint.starts_with("localhost:")
}

fn init_logging() -> anyhow::Result<Option<tracing_appender::non_blocking::WorkerGuard>> {
    use tracing_appender::rolling::{RollingFileAppender, Rotation};
    use tracing_subscriber::EnvFilter;

    let Some(log_directory) = std::env::var_os("LINKLAKE_LOG_DIR").map(PathBuf::from) else {
        tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
            )
            .with_ansi(true)
            .try_init()
            .map_err(|error| anyhow::anyhow!("could not initialize console logging: {error}"))?;
        return Ok(None);
    };
    std::fs::create_dir_all(&log_directory)?;
    let appender = RollingFileAppender::builder()
        .rotation(Rotation::HOURLY)
        .filename_prefix("linklake-client.log")
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
    Ok(Some(guard))
}

#[cfg(windows)]
mod windows_service_host {
    use super::PathBuf;
    use std::{
        ffi::OsString,
        sync::{Arc, Mutex, OnceLock},
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

    const SERVICE_NAME: &str = "LinkLakeClient";
    const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;
    static CONFIG_PATH: OnceLock<PathBuf> = OnceLock::new();

    define_windows_service!(ffi_service_main, service_main);

    pub(super) fn run(config: PathBuf) -> Result<()> {
        let _ = CONFIG_PATH.set(config);
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
    }

    fn service_main(_arguments: Vec<OsString>) {
        if let Err(error) = run_service() {
            tracing::error!("Windows client service host failed: {error}");
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
                    .expect("Windows client service shutdown lock poisoned")
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

        let exit_code = match (tokio::runtime::Runtime::new(), CONFIG_PATH.get().cloned()) {
            (Ok(runtime), Some(config)) => {
                match runtime.block_on(super::run_configured_agents(config, Some(shutdown_rx))) {
                    Ok(()) => 0,
                    Err(error) => {
                        tracing::error!("LinkLake client stopped with an error: {error}");
                        1
                    }
                }
            }
            (Err(error), _) => {
                tracing::error!("Could not create the client service runtime: {error}");
                1
            }
            (_, None) => {
                tracing::error!("The client service config path was not provided.");
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
