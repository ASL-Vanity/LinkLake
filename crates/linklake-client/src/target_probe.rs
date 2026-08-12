//! 客户端目标健康探针与仅健康目标选择。

use super::CONTROL_HEARTBEAT_INTERVAL;
use linklake_core::target_pool::{parse_target_pool, WeightedTarget};
use linklake_core::{
    write_control_frame, BoxedIo, ControlFrame, TargetHealthProbeKind, TargetHealthProbeRequest,
    TargetHealthProbeResult,
};
use std::{
    collections::{HashMap, HashSet},
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, WriteHalf},
    net::{lookup_host, TcpStream, UdpSocket},
    sync::{mpsc, Semaphore},
    task::JoinHandle,
    time::{interval, timeout, MissedTickBehavior},
};
use tokio_rustls::{
    rustls::{
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        crypto::{ring, verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms},
        pki_types::{CertificateDer, ServerName, UnixTime},
        ClientConfig, DigitallySignedStruct, Error as RustlsError, SignatureScheme,
    },
    TlsConnector,
};
use uuid::Uuid;

const CONTROL_COMMAND_CAPACITY: usize = 64;
const MAX_CONCURRENT_PROBES: usize = 16;
const MAX_PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_ERROR_SUMMARY_BYTES: usize = 96;
const LOCAL_HEALTH_TTL: Duration = Duration::from_secs(25);

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum TargetProbePolicy {
    Tcp,
    Secret,
    Http { server_name: String },
    Tls { server_name: String },
    Udp,
}

impl TargetProbePolicy {
    fn key_kind(&self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Secret => "secret",
            Self::Http { .. } => "http",
            Self::Tls { .. } => "sni",
            Self::Udp => "udp",
        }
    }

    fn probe_kind(&self) -> TargetHealthProbeKind {
        match self {
            Self::Tcp | Self::Secret => TargetHealthProbeKind::Tcp,
            Self::Http { .. } => TargetHealthProbeKind::Http,
            Self::Tls { .. } => TargetHealthProbeKind::Tls,
            Self::Udp => TargetHealthProbeKind::Udp,
        }
    }

    fn server_name(&self) -> Option<&str> {
        match self {
            Self::Http { server_name } | Self::Tls { server_name } => Some(server_name),
            Self::Tcp | Self::Secret | Self::Udp => None,
        }
    }
}

#[derive(Default)]
struct ProbeState {
    health: HashMap<String, TargetStatus>,
    latest_revision: HashMap<String, u64>,
}

#[derive(Clone, Copy)]
struct TargetStatus {
    healthy: bool,
    observed_at: Instant,
}

#[derive(Clone)]
pub(super) struct TargetProbeSession {
    policy_id: Uuid,
    policy: TargetProbePolicy,
    targets: Arc<Vec<WeightedTarget>>,
    target_addresses: Arc<HashSet<String>>,
    state: Arc<Mutex<ProbeState>>,
    probe_limit: Arc<Semaphore>,
}

impl TargetProbeSession {
    pub(super) fn new(
        policy_id: Uuid,
        policy: TargetProbePolicy,
        target_pool: &str,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !policy_id.is_nil(),
            "target probe policy identity is missing"
        );
        let targets = parse_target_pool(target_pool)?;
        let target_addresses = targets
            .iter()
            .map(|target| target.address.clone())
            .collect::<HashSet<_>>();
        anyhow::ensure!(!target_addresses.is_empty(), "target probe pool is empty");
        anyhow::ensure!(
            target_addresses.len() == targets.len(),
            "target probe pool contains a duplicate address"
        );
        if let Some(server_name) = policy.server_name() {
            anyhow::ensure!(
                valid_server_name(server_name),
                "target probe server name is invalid"
            );
        }
        Ok(Self {
            policy_id,
            policy,
            targets: Arc::new(targets),
            target_addresses: Arc::new(target_addresses),
            state: Arc::new(Mutex::new(ProbeState::default())),
            probe_limit: Arc::new(Semaphore::new(MAX_CONCURRENT_PROBES)),
        })
    }

    pub(super) fn targets(&self) -> Arc<Vec<WeightedTarget>> {
        self.targets.clone()
    }

    pub(super) fn select_target(&self, sequence: u64) -> Option<String> {
        let state = self.state.lock().expect("target probe state lock poisoned");
        let now = Instant::now();
        let total = self
            .targets
            .iter()
            .filter(|target| target_is_healthy(&state, &target.address, now))
            .map(|target| u64::from(target.weight))
            .sum::<u64>();
        if total == 0 {
            return None;
        }
        let mut slot = sequence % total;
        for target in self
            .targets
            .iter()
            .filter(|target| target_is_healthy(&state, &target.address, now))
        {
            let weight = u64::from(target.weight);
            if slot < weight {
                return Some(target.address.clone());
            }
            slot -= weight;
        }
        None
    }

    pub(super) fn is_healthy(&self, target_addr: &str) -> bool {
        let state = self.state.lock().expect("target probe state lock poisoned");
        target_is_healthy(&state, target_addr, Instant::now())
    }

    pub(super) fn handle_probe(
        &self,
        request: TargetHealthProbeRequest,
        command_tx: mpsc::Sender<ControlFrame>,
    ) -> anyhow::Result<()> {
        self.validate_request(&request)?;
        {
            let mut state = self.state.lock().expect("target probe state lock poisoned");
            if state
                .latest_revision
                .get(&request.target_addr)
                .is_some_and(|revision| request.revision <= *revision)
            {
                anyhow::bail!("target probe revision is stale");
            }
            state
                .latest_revision
                .insert(request.target_addr.clone(), request.revision);
        }
        let permit = self
            .probe_limit
            .clone()
            .try_acquire_owned()
            .map_err(|_| anyhow::anyhow!("too many concurrent target probes"))?;
        let session = self.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let outcome = timeout(
                Duration::from_millis(u64::from(request.timeout_millis)),
                execute_probe(&session.policy, &request.target_addr),
            )
            .await;
            let (healthy, error_summary) = match outcome {
                Ok(Ok(())) => (true, None),
                Ok(Err(summary)) => (false, Some(bounded_error_summary(summary))),
                Err(_) => (false, Some(bounded_error_summary("probe_timed_out"))),
            };
            session.record_health_if_current(&request, healthy);
            let result = TargetHealthProbeResult {
                probe_id: request.probe_id,
                target_key: request.target_key,
                target_addr: request.target_addr,
                revision: request.revision,
                healthy,
                error_summary,
            };
            let _ = command_tx
                .send(ControlFrame::TargetHealthProbeResult { result })
                .await;
        });
        Ok(())
    }

    fn validate_request(&self, request: &TargetHealthProbeRequest) -> anyhow::Result<()> {
        anyhow::ensure!(
            !request.probe_id.is_nil(),
            "target probe identity is missing"
        );
        anyhow::ensure!(request.revision > 0, "target probe revision is invalid");
        anyhow::ensure!(
            request.timeout_millis > 0
                && Duration::from_millis(u64::from(request.timeout_millis)) <= MAX_PROBE_TIMEOUT,
            "target probe timeout exceeds the client limit"
        );
        anyhow::ensure!(
            self.target_addresses.contains(&request.target_addr),
            "target probe address is not part of this policy"
        );
        let expected_key = format!(
            "{}:{}:{}",
            self.policy.key_kind(),
            self.policy_id,
            request.target_addr
        );
        anyhow::ensure!(
            request.target_key == expected_key,
            "target probe key does not match this policy"
        );
        anyhow::ensure!(
            request.kind == self.policy.probe_kind(),
            "target probe kind does not match this policy"
        );
        anyhow::ensure!(
            request.server_name.as_deref() == self.policy.server_name(),
            "target probe server name does not match this policy"
        );
        Ok(())
    }

    fn record_health_if_current(&self, request: &TargetHealthProbeRequest, healthy: bool) {
        let mut state = self.state.lock().expect("target probe state lock poisoned");
        if state.latest_revision.get(&request.target_addr) == Some(&request.revision) {
            state.health.insert(
                request.target_addr.clone(),
                TargetStatus {
                    healthy,
                    observed_at: Instant::now(),
                },
            );
        }
    }

    #[cfg(test)]
    fn record_health_for_test(&self, target_addr: &str, healthy: bool) {
        self.record_health_at_for_test(target_addr, healthy, Instant::now());
    }

    #[cfg(test)]
    fn record_health_at_for_test(&self, target_addr: &str, healthy: bool, observed_at: Instant) {
        self.state
            .lock()
            .expect("target probe state lock poisoned")
            .health
            .insert(
                target_addr.to_owned(),
                TargetStatus {
                    healthy,
                    observed_at,
                },
            );
    }
}

fn target_is_healthy(state: &ProbeState, target_addr: &str, now: Instant) -> bool {
    state.health.get(target_addr).is_some_and(|status| {
        status.healthy
            && now
                .checked_duration_since(status.observed_at)
                .unwrap_or_default()
                < LOCAL_HEALTH_TTL
    })
}

pub(super) fn spawn_control_writer(
    writer: WriteHalf<BoxedIo>,
) -> (mpsc::Sender<ControlFrame>, JoinHandle<anyhow::Result<()>>) {
    let (command_tx, command_rx) = mpsc::channel(CONTROL_COMMAND_CAPACITY);
    let task = tokio::spawn(run_control_writer(writer, command_rx));
    (command_tx, task)
}

async fn run_control_writer(
    mut writer: WriteHalf<BoxedIo>,
    mut command_rx: mpsc::Receiver<ControlFrame>,
) -> anyhow::Result<()> {
    let mut heartbeat = interval(CONTROL_HEARTBEAT_INTERVAL);
    heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut nonce = 1_u64;
    loop {
        tokio::select! {
            _ = heartbeat.tick() => {
                write_control_frame(&mut writer, &ControlFrame::ControlHeartbeat { nonce }).await?;
                nonce = nonce.wrapping_add(1);
            }
            command = command_rx.recv() => {
                let Some(command) = command else {
                    anyhow::bail!("target probe control writer stopped");
                };
                write_control_frame(&mut writer, &command).await?;
            }
        }
    }
}

async fn execute_probe(policy: &TargetProbePolicy, target_addr: &str) -> Result<(), &'static str> {
    match policy {
        TargetProbePolicy::Tcp | TargetProbePolicy::Secret => probe_tcp(target_addr).await,
        TargetProbePolicy::Http { server_name } => probe_http(target_addr, server_name).await,
        TargetProbePolicy::Tls { server_name } => probe_tls(target_addr, server_name).await,
        TargetProbePolicy::Udp => probe_udp(target_addr).await,
    }
}

async fn probe_tcp(target_addr: &str) -> Result<(), &'static str> {
    TcpStream::connect(target_addr)
        .await
        .map(|_| ())
        .map_err(|_| "tcp_connect_failed")
}

async fn probe_http(target_addr: &str, server_name: &str) -> Result<(), &'static str> {
    if probe_http1(target_addr, server_name).await.is_ok() {
        return Ok(());
    }
    probe_http2(target_addr).await
}

async fn probe_http1(target_addr: &str, server_name: &str) -> Result<(), &'static str> {
    let mut stream = TcpStream::connect(target_addr)
        .await
        .map_err(|_| "http_connect_failed")?;
    let request = format!(
        "GET / HTTP/1.1\r\nHost: {server_name}\r\nConnection: close\r\nUser-Agent: LinkLake-Health-Probe\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|_| "http_write_failed")?;
    let mut prefix = [0_u8; 5];
    stream
        .read_exact(&mut prefix)
        .await
        .map_err(|_| "http_response_missing")?;
    if prefix == *b"HTTP/" {
        Ok(())
    } else {
        Err("http_response_invalid")
    }
}

async fn probe_http2(target_addr: &str) -> Result<(), &'static str> {
    const HTTP2_PREFACE_AND_SETTINGS: &[u8] =
        b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\0\0\0\x04\0\0\0\0\0";
    let mut stream = TcpStream::connect(target_addr)
        .await
        .map_err(|_| "http2_connect_failed")?;
    stream
        .write_all(HTTP2_PREFACE_AND_SETTINGS)
        .await
        .map_err(|_| "http2_write_failed")?;
    let mut header = [0_u8; 9];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|_| "http2_settings_missing")?;
    let frame_length = u32::from_be_bytes([0, header[0], header[1], header[2]]);
    let stream_id = u32::from_be_bytes([header[5], header[6], header[7], header[8]]) & 0x7fff_ffff;
    if header[3] == 0x04 && stream_id == 0 && frame_length <= 16_384 {
        Ok(())
    } else {
        Err("http2_settings_invalid")
    }
}

async fn probe_tls(target_addr: &str, server_name: &str) -> Result<(), &'static str> {
    let stream = TcpStream::connect(target_addr)
        .await
        .map_err(|_| "tls_connect_failed")?;
    let server_name =
        ServerName::try_from(server_name.to_owned()).map_err(|_| "tls_server_name_invalid")?;
    let connector = TlsConnector::from(tls_probe_config());
    connector
        .connect(server_name, stream)
        .await
        .map(|_| ())
        .map_err(|_| "tls_handshake_failed")
}

async fn probe_udp(target_addr: &str) -> Result<(), &'static str> {
    let remote = preferred_address(
        lookup_host(target_addr)
            .await
            .map_err(|_| "udp_resolve_failed")?,
    )
    .ok_or("udp_resolve_failed")?;
    let bind_address = if remote.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    };
    let socket = UdpSocket::bind(bind_address)
        .await
        .map_err(|_| "udp_bind_failed")?;
    socket
        .connect(remote)
        .await
        .map_err(|_| "udp_connect_failed")?;
    socket.send(&[]).await.map_err(|_| "udp_send_failed")?;
    tokio::task::yield_now().await;
    if socket
        .take_error()
        .map_err(|_| "udp_status_failed")?
        .is_some()
    {
        Err("udp_target_unreachable")
    } else {
        Ok(())
    }
}

fn preferred_address(addresses: impl Iterator<Item = SocketAddr>) -> Option<SocketAddr> {
    let addresses = addresses.collect::<Vec<_>>();
    addresses
        .iter()
        .copied()
        .find(SocketAddr::is_ipv4)
        .or_else(|| addresses.first().copied())
}

fn valid_server_name(server_name: &str) -> bool {
    !server_name.is_empty()
        && server_name.len() <= 253
        && server_name.is_ascii()
        && !server_name
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
}

fn bounded_error_summary(summary: &str) -> String {
    let mut summary = summary.to_owned();
    summary.truncate(MAX_ERROR_SUMMARY_BYTES);
    summary
}

fn tls_probe_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let config = ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(ProbeCertificateVerifier::new()))
                .with_no_client_auth();
            Arc::new(config)
        })
        .clone()
}

struct ProbeCertificateVerifier {
    supported: WebPkiSupportedAlgorithms,
}

impl ProbeCertificateVerifier {
    fn new() -> Self {
        Self {
            supported: ring::default_provider().signature_verification_algorithms,
        }
    }
}

impl fmt::Debug for ProbeCertificateVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProbeCertificateVerifier")
    }
}

impl ServerCertVerifier for ProbeCertificateVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        // 健康探针验证 TLS 握手与 SNI 可达性，不把目标证书当作信任凭据。
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls12_signature(message, certificate, signature, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature(message, certificate, signature, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::{TargetProbePolicy, TargetProbeSession, LOCAL_HEALTH_TTL};
    use linklake_core::{TargetHealthProbeKind, TargetHealthProbeRequest};
    use std::time::{Duration, Instant};
    use uuid::Uuid;

    fn request(
        policy_id: Uuid,
        key_kind: &str,
        target_addr: &str,
        kind: TargetHealthProbeKind,
        server_name: Option<&str>,
    ) -> TargetHealthProbeRequest {
        TargetHealthProbeRequest {
            probe_id: Uuid::new_v4(),
            target_key: format!("{key_kind}:{policy_id}:{target_addr}"),
            target_addr: target_addr.to_owned(),
            kind,
            server_name: server_name.map(str::to_owned),
            timeout_millis: 3_000,
            revision: 1,
        }
    }

    #[test]
    fn unknown_target_is_rejected() {
        let policy_id = Uuid::new_v4();
        let session =
            TargetProbeSession::new(policy_id, TargetProbePolicy::Tcp, "127.0.0.1:8000").unwrap();
        let request = request(
            policy_id,
            "tcp",
            "127.0.0.1:9000",
            TargetHealthProbeKind::Tcp,
            None,
        );
        assert!(session.validate_request(&request).is_err());
    }

    #[test]
    fn forged_target_key_is_rejected() {
        let policy_id = Uuid::new_v4();
        let session =
            TargetProbeSession::new(policy_id, TargetProbePolicy::Tcp, "127.0.0.1:8000").unwrap();
        let request = request(
            Uuid::new_v4(),
            "tcp",
            "127.0.0.1:8000",
            TargetHealthProbeKind::Tcp,
            None,
        );
        assert!(session.validate_request(&request).is_err());
    }

    #[test]
    fn wrong_probe_kind_is_rejected() {
        let policy_id = Uuid::new_v4();
        let session =
            TargetProbeSession::new(policy_id, TargetProbePolicy::Tcp, "127.0.0.1:8000").unwrap();
        let request = request(
            policy_id,
            "tcp",
            "127.0.0.1:8000",
            TargetHealthProbeKind::Udp,
            None,
        );
        assert!(session.validate_request(&request).is_err());
    }

    #[test]
    fn secret_probe_is_bound_to_the_secret_policy_namespace() {
        let policy_id = Uuid::new_v4();
        let session =
            TargetProbeSession::new(policy_id, TargetProbePolicy::Secret, "127.0.0.1:3389")
                .unwrap();
        let request = request(
            policy_id,
            "tcp",
            "127.0.0.1:3389",
            TargetHealthProbeKind::Tcp,
            None,
        );
        assert!(session.validate_request(&request).is_err());

        let request = TargetHealthProbeRequest {
            target_key: format!("secret:{policy_id}:127.0.0.1:3389"),
            ..request
        };
        assert!(session.validate_request(&request).is_ok());
    }

    #[test]
    fn wrong_server_name_is_rejected() {
        let policy_id = Uuid::new_v4();
        let session = TargetProbeSession::new(
            policy_id,
            TargetProbePolicy::Http {
                server_name: "service.example.test".to_owned(),
            },
            "127.0.0.1:8000",
        )
        .unwrap();
        let request = request(
            policy_id,
            "http",
            "127.0.0.1:8000",
            TargetHealthProbeKind::Http,
            Some("other.example.test"),
        );
        assert!(session.validate_request(&request).is_err());
    }

    #[test]
    fn targets_fail_closed_before_the_first_probe() {
        let session = TargetProbeSession::new(
            Uuid::new_v4(),
            TargetProbePolicy::Tcp,
            "127.0.0.1:8000@2,127.0.0.1:8001@1",
        )
        .unwrap();
        assert_eq!(session.select_target(0), None);
        assert_eq!(session.select_target(100), None);
    }

    #[test]
    fn healthy_subset_preserves_original_weights() {
        let session = TargetProbeSession::new(
            Uuid::new_v4(),
            TargetProbePolicy::Tcp,
            "127.0.0.1:8000@2,127.0.0.1:8001@3,127.0.0.1:8002@1",
        )
        .unwrap();
        session.record_health_for_test("127.0.0.1:8000", true);
        session.record_health_for_test("127.0.0.1:8001", false);
        session.record_health_for_test("127.0.0.1:8002", true);

        assert_eq!(session.select_target(0).as_deref(), Some("127.0.0.1:8000"));
        assert_eq!(session.select_target(1).as_deref(), Some("127.0.0.1:8000"));
        assert_eq!(session.select_target(2).as_deref(), Some("127.0.0.1:8002"));
        assert_eq!(session.select_target(3).as_deref(), Some("127.0.0.1:8000"));
    }

    #[test]
    fn stale_health_fails_closed_locally() {
        let session =
            TargetProbeSession::new(Uuid::new_v4(), TargetProbePolicy::Tcp, "127.0.0.1:8000")
                .unwrap();
        let stale_at = Instant::now()
            .checked_sub(LOCAL_HEALTH_TTL + Duration::from_secs(1))
            .unwrap();
        session.record_health_at_for_test("127.0.0.1:8000", true, stale_at);
        assert!(!session.is_healthy("127.0.0.1:8000"));
        assert_eq!(session.select_target(0), None);
    }
}
