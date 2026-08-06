//! gRPC 本地目标的 TLS、SNI、ALPN 与信任根装配。

use crate::{
    http_backend_pool::{BackendSecurity, BackendTrustKey},
    http_route_catalog::{GrpcBackendRuntimeTransport, GrpcBackendTlsPolicy, GrpcBackendTrust},
};
use linklake_core::BoxedIo;
use rustls_pki_types::{pem::PemObject, CertificateDer, ServerName};
use std::{
    error::Error,
    fmt,
    fs::File,
    io::BufReader,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::time::timeout;
use tokio_rustls::{
    rustls::{ClientConfig, RootCertStore},
    TlsConnector,
};

const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const TRUST_PROFILE_DIRECTORY_ENV: &str = "LINKLAKE_GRPC_TRUST_PROFILE_DIR";

#[derive(Default)]
pub(crate) struct GrpcBackendTlsCounters {
    pub(crate) handshakes_total: AtomicU64,
    pub(crate) handshake_failures_total: AtomicU64,
    pub(crate) alpn_failures_total: AtomicU64,
    pub(crate) system_trust_connections_total: AtomicU64,
    pub(crate) profile_trust_connections_total: AtomicU64,
}

#[derive(Debug)]
pub(crate) enum GrpcBackendTlsError {
    InvalidServerName,
    SystemTrustUnavailable,
    TrustProfileDirectoryMissing,
    TrustProfileUnreadable,
    TrustProfileEmpty,
    InvalidTrustCertificate,
    HandshakeTimeout,
    Handshake,
    AlpnMismatch,
}

impl fmt::Display for GrpcBackendTlsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidServerName => "gRPC backend TLS server name is invalid",
            Self::SystemTrustUnavailable => "system TLS trust store is unavailable",
            Self::TrustProfileDirectoryMissing => "gRPC trust profile directory is not configured",
            Self::TrustProfileUnreadable => "gRPC trust profile cannot be read",
            Self::TrustProfileEmpty => "gRPC trust profile contains no certificates",
            Self::InvalidTrustCertificate => "gRPC trust profile contains an invalid certificate",
            Self::HandshakeTimeout => "gRPC backend TLS handshake timed out",
            Self::Handshake => "gRPC backend TLS handshake failed",
            Self::AlpnMismatch => "gRPC backend did not negotiate ALPN h2",
        })
    }
}

impl Error for GrpcBackendTlsError {}

#[derive(Clone)]
pub(crate) enum GrpcBackendConnector {
    H2c,
    Tls(Arc<GrpcTlsConnector>),
}

impl GrpcBackendConnector {
    pub(crate) fn from_policy(
        policy: &GrpcBackendRuntimeTransport,
        counters: Arc<GrpcBackendTlsCounters>,
    ) -> Result<Self, GrpcBackendTlsError> {
        match policy {
            GrpcBackendRuntimeTransport::H2c => Ok(Self::H2c),
            GrpcBackendRuntimeTransport::Tls(policy) => Ok(Self::Tls(Arc::new(
                GrpcTlsConnector::new(policy, counters)?,
            ))),
        }
    }

    pub(crate) fn security(&self) -> BackendSecurity {
        match self {
            Self::H2c => BackendSecurity::Plaintext,
            Self::Tls(connector) => connector.security.clone(),
        }
    }

    pub(crate) async fn connect(&self, stream: BoxedIo) -> Result<BoxedIo, GrpcBackendTlsError> {
        match self {
            Self::H2c => Ok(stream),
            Self::Tls(connector) => connector.connect(stream).await,
        }
    }

    pub(crate) fn transport_name(&self) -> &'static str {
        match self {
            Self::H2c => "h2c",
            Self::Tls(_) => "tls",
        }
    }

    pub(crate) fn is_tls(&self) -> bool {
        matches!(self, Self::Tls(_))
    }
}

pub(crate) struct GrpcTlsConnector {
    connector: TlsConnector,
    server_name: ServerName<'static>,
    security: BackendSecurity,
    counters: Arc<GrpcBackendTlsCounters>,
    profile_trust: bool,
}

impl GrpcTlsConnector {
    fn new(
        policy: &GrpcBackendTlsPolicy,
        counters: Arc<GrpcBackendTlsCounters>,
    ) -> Result<Self, GrpcBackendTlsError> {
        let server_name = ServerName::try_from(policy.server_name.clone())
            .map_err(|_| GrpcBackendTlsError::InvalidServerName)?;
        let (roots, trust, profile_trust) = match &policy.trust {
            GrpcBackendTrust::System => (system_roots()?, BackendTrustKey::System, false),
            GrpcBackendTrust::Profile(profile) => (
                profile_roots(profile)?,
                BackendTrustKey::Profile(profile.clone().into_boxed_str()),
                true,
            ),
        };
        let mut config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec()];
        Ok(Self {
            connector: TlsConnector::from(Arc::new(config)),
            server_name,
            security: BackendSecurity::tls_with_trust(&policy.server_name, trust)
                .map_err(|_| GrpcBackendTlsError::InvalidServerName)?,
            counters,
            profile_trust,
        })
    }

    async fn connect(&self, stream: BoxedIo) -> Result<BoxedIo, GrpcBackendTlsError> {
        self.counters
            .handshakes_total
            .fetch_add(1, Ordering::Relaxed);
        let handshake = timeout(
            TLS_HANDSHAKE_TIMEOUT,
            self.connector.connect(self.server_name.clone(), stream),
        )
        .await;
        let tls = match handshake {
            Ok(Ok(tls)) => tls,
            Ok(Err(_)) => {
                self.counters
                    .handshake_failures_total
                    .fetch_add(1, Ordering::Relaxed);
                return Err(GrpcBackendTlsError::Handshake);
            }
            Err(_) => {
                self.counters
                    .handshake_failures_total
                    .fetch_add(1, Ordering::Relaxed);
                return Err(GrpcBackendTlsError::HandshakeTimeout);
            }
        };
        if tls.get_ref().1.alpn_protocol() != Some(b"h2") {
            self.counters
                .alpn_failures_total
                .fetch_add(1, Ordering::Relaxed);
            return Err(GrpcBackendTlsError::AlpnMismatch);
        }
        let trust_counter = if self.profile_trust {
            &self.counters.profile_trust_connections_total
        } else {
            &self.counters.system_trust_connections_total
        };
        trust_counter.fetch_add(1, Ordering::Relaxed);
        Ok(Box::new(tls))
    }
}

fn system_roots() -> Result<RootCertStore, GrpcBackendTlsError> {
    let native = rustls_native_certs::load_native_certs();
    let mut roots = RootCertStore::empty();
    for certificate in native.certs {
        roots
            .add(certificate)
            .map_err(|_| GrpcBackendTlsError::InvalidTrustCertificate)?;
    }
    if roots.is_empty() {
        return Err(GrpcBackendTlsError::SystemTrustUnavailable);
    }
    Ok(roots)
}

fn profile_roots(profile: &str) -> Result<RootCertStore, GrpcBackendTlsError> {
    let directory = std::env::var_os(TRUST_PROFILE_DIRECTORY_ENV)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or(GrpcBackendTlsError::TrustProfileDirectoryMissing)?;
    let path = directory.join(format!("{profile}.pem"));
    let file = File::open(path).map_err(|_| GrpcBackendTlsError::TrustProfileUnreadable)?;
    let certificates = CertificateDer::pem_reader_iter(BufReader::new(file))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| GrpcBackendTlsError::TrustProfileUnreadable)?;
    if certificates.is_empty() {
        return Err(GrpcBackendTlsError::TrustProfileEmpty);
    }
    let mut roots = RootCertStore::empty();
    for certificate in certificates {
        roots
            .add(certificate)
            .map_err(|_| GrpcBackendTlsError::InvalidTrustCertificate)?;
    }
    Ok(roots)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_route_catalog::{GrpcBackendTlsPolicy, GrpcBackendTrust};

    #[test]
    fn h2c_connector_is_plaintext_and_does_not_load_trust() {
        let connector = GrpcBackendConnector::from_policy(
            &GrpcBackendRuntimeTransport::H2c,
            Arc::new(GrpcBackendTlsCounters::default()),
        )
        .unwrap();
        assert_eq!(connector.transport_name(), "h2c");
        assert_eq!(connector.security(), BackendSecurity::Plaintext);
    }

    #[test]
    fn missing_profile_directory_fails_closed() {
        std::env::remove_var(TRUST_PROFILE_DIRECTORY_ENV);
        let result = GrpcBackendConnector::from_policy(
            &GrpcBackendRuntimeTransport::Tls(GrpcBackendTlsPolicy {
                server_name: "grpc.example.test".to_owned(),
                trust: GrpcBackendTrust::Profile("private-ca".to_owned()),
            }),
            Arc::new(GrpcBackendTlsCounters::default()),
        );
        assert!(matches!(
            result,
            Err(GrpcBackendTlsError::TrustProfileDirectoryMissing)
        ));
    }
}
