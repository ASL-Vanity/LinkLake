use clap::{Parser, Subcommand};
use linklake_core::{
    read_control_frame, write_control_frame, BoxedIo, ClientEnrollmentRequest,
    ClientEnrollmentResponse, ControlFrame, PRODUCT_NAME,
};
use serde::Deserialize;
use std::{
    fs::{read_to_string, File},
    io::BufReader,
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{copy_bidirectional, split, ReadHalf, WriteHalf},
    net::TcpStream,
    time::{interval, timeout, MissedTickBehavior},
};
use tokio_rustls::{
    rustls::{self, pki_types::ServerName, ClientConfig, RootCertStore},
    TlsConnector,
};
use uuid::Uuid;

mod udp_agent;

const CONTROL_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
const CONTROL_HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(30);
const TARGET_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

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
}

#[derive(Deserialize)]
struct HealthResponse {
    product: String,
    api_version: String,
    status: String,
}

#[derive(Deserialize)]
struct ClientConfigFile {
    #[serde(default)]
    tcp_tunnels: Vec<TcpTunnelConfig>,
    #[serde(default)]
    udp_tunnels: Vec<UdpTunnelConfig>,
    #[serde(default)]
    http_routes: Vec<HttpRouteConfig>,
}

#[derive(Deserialize)]
struct TcpTunnelConfig {
    control: String,
    control_ca_cert: Option<PathBuf>,
    control_server_name: Option<String>,
    client_id: Uuid,
    client_token: String,
    public_port: u16,
    target: String,
    name: String,
}

#[derive(Deserialize)]
struct UdpTunnelConfig {
    control: String,
    control_ca_cert: Option<PathBuf>,
    control_server_name: Option<String>,
    client_id: Uuid,
    client_token: String,
    public_port: u16,
    target: String,
    name: String,
}

#[derive(Deserialize)]
struct HttpRouteConfig {
    control: String,
    control_ca_cert: Option<PathBuf>,
    control_server_name: Option<String>,
    client_id: Uuid,
    client_token: String,
    hostname: String,
    target: String,
    name: String,
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
    }
    Ok(())
}

async fn run_configured_agents(
    path: PathBuf,
    shutdown: Option<tokio::sync::oneshot::Receiver<()>>,
) -> anyhow::Result<()> {
    let content = read_to_string(&path)?;
    let config = parse_client_config(&content)?;
    // 同一份配置中的所有 UDP 隧道共享队列字节预算，避免多个策略叠加占满客户端内存。
    let udp_queue_budget = Arc::new(tokio::sync::Semaphore::new(
        udp_agent::UDP_QUEUE_BUDGET_BYTES,
    ));
    for tunnel in config.tcp_tunnels {
        let transport = ControlTransport::new(
            tunnel.control,
            tunnel.control_ca_cert,
            tunnel.control_server_name,
        )?;
        tokio::spawn(async move {
            if let Err(error) = run_tcp_agent(
                transport,
                tunnel.client_id,
                tunnel.client_token,
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
            tunnel.control,
            tunnel.control_ca_cert,
            tunnel.control_server_name,
        )?;
        let udp_queue_budget = udp_queue_budget.clone();
        tokio::spawn(async move {
            if let Err(error) = udp_agent::run_udp_agent(
                transport,
                tunnel.client_id,
                tunnel.client_token,
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
            route.control,
            route.control_ca_cert,
            route.control_server_name,
        )?;
        tokio::spawn(async move {
            if let Err(error) = run_http_agent(
                transport,
                route.client_id,
                route.client_token,
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

fn parse_client_config(content: &str) -> anyhow::Result<ClientConfigFile> {
    let config: ClientConfigFile = toml::from_str(content)?;
    anyhow::ensure!(
        !config.tcp_tunnels.is_empty()
            || !config.udp_tunnels.is_empty()
            || !config.http_routes.is_empty(),
        "the configuration has no tcp_tunnels, udp_tunnels, or http_routes entries"
    );
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::parse_client_config;

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
    fn rejects_configuration_without_tunnels() {
        assert!(parse_client_config("").is_err());
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
            ControlFrame::OpenTcpConnection { connection_id } => {
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
