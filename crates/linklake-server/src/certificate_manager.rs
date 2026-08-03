use crate::{
    certificate_catalog::{normalize_certificate_identifier, AcmeChallengeType},
    cloudflare_dns::CloudflareDnsClient,
    http_route_catalog::normalize_hostname,
};
use arc_swap::ArcSwap;
use instant_acme::{
    Account, AccountBuilder, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier,
    NewAccount, NewOrder, OrderStatus, RetryPolicy,
};
use rustls::{
    crypto::ring::sign::any_supported_type,
    pki_types::{CertificateDer, PrivateKeyDer},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
    ServerConfig,
};
use std::{
    collections::HashMap,
    fmt, fs,
    hash::{DefaultHasher, Hash, Hasher},
    io::{BufReader, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Mutex as AsyncMutex, Semaphore};
use x509_parser::{extensions::GeneralName, parse_x509_certificate};

const CHALLENGE_TTL: Duration = Duration::from_secs(10 * 60);
const ACME_OPERATION_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_PARALLEL_ORDERS: usize = 2;
const CERTIFICATE_GENERATIONS_DIRECTORY: &str = "generations";
const CERTIFICATE_COMMIT_MARKER: &[u8] = b"linklake-certificate-generation-v1\n";
const RETAINED_CERTIFICATE_GENERATIONS: usize = 3;

#[derive(Clone, Debug)]
pub(crate) struct AcmeIssueConfig {
    pub(crate) directory_url: String,
    pub(crate) contact_email: String,
    pub(crate) challenge_type: AcmeChallengeType,
    pub(crate) root_ca_path: Option<PathBuf>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CertificateMetadata {
    pub(crate) issuer: String,
    pub(crate) not_before_unix_seconds: u64,
    pub(crate) not_after_unix_seconds: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CertificateIssueResult {
    pub(crate) metadata: CertificateMetadata,
    pub(crate) http01_challenges_completed: u64,
    pub(crate) dns01_challenges_completed: u64,
}

#[derive(Clone)]
pub(crate) struct CertificateManager {
    data_dir: PathBuf,
    resolver: Arc<DynamicCertResolver>,
    challenges: Arc<Http01ChallengeStore>,
    cloudflare_dns: Option<CloudflareDnsClient>,
    account_lock: Arc<AsyncMutex<()>>,
    order_permits: Arc<Semaphore>,
}

impl CertificateManager {
    pub(crate) fn new(data_dir: PathBuf) -> anyhow::Result<Self> {
        fs::create_dir_all(data_dir.join("certificates"))?;
        fs::create_dir_all(data_dir.join("acme"))?;
        let cloudflare_dns = CloudflareDnsClient::from_environment(&data_dir)?;
        Ok(Self {
            data_dir,
            resolver: Arc::new(DynamicCertResolver::default()),
            challenges: Arc::new(Http01ChallengeStore::default()),
            cloudflare_dns,
            account_lock: Arc::new(AsyncMutex::new(())),
            order_permits: Arc::new(Semaphore::new(MAX_PARALLEL_ORDERS)),
        })
    }

    pub(crate) fn challenges(&self) -> Arc<Http01ChallengeStore> {
        self.challenges.clone()
    }

    pub(crate) fn tls_config(&self) -> Arc<ServerConfig> {
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(self.resolver.clone());
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(config)
    }

    pub(crate) fn has_certificate(&self, hostname: &str) -> bool {
        self.resolver.contains(hostname)
    }

    pub(crate) fn certificate_count(&self) -> usize {
        self.resolver.len()
    }

    pub(crate) fn account_registered(&self, directory_url: &str) -> bool {
        self.account_credentials_path(directory_url).is_file()
    }

    pub(crate) fn cloudflare_token_configured(&self) -> bool {
        self.cloudflare_dns.is_some()
    }

    pub(crate) fn remove_certificate(&self, hostname: &str) {
        self.resolver.remove(hostname);
    }

    pub(crate) fn delete_certificate(&self, hostname: &str) -> anyhow::Result<()> {
        let hostname = normalize_certificate_identifier(hostname)?;
        self.resolver.remove(&hostname);
        let directory = self.certificate_directory(&hostname);
        if directory.is_dir() {
            fs::remove_dir_all(directory)?;
        }
        Ok(())
    }

    pub(crate) fn load_certificate(&self, hostname: &str) -> anyhow::Result<CertificateMetadata> {
        let hostname = normalize_certificate_identifier(hostname)?;
        let directory = self.certificate_directory(&hostname);
        let mut last_error = None;
        for (certificate_pem, private_key_pem) in committed_certificate_pairs(&directory)? {
            match self.install_certificate(&hostname, &certificate_pem, &private_key_pem) {
                Ok(metadata) => return Ok(metadata),
                Err(error) => last_error = Some(error),
            }
        }

        // 兼容早期直接保存两个 PEM 文件的目录。新写入始终使用代目录作为权威数据，
        // 因此即使兼容副本在崩溃时只更新了一半，也不会覆盖已提交的有效证书对。
        let legacy_certificate = fs::read(directory.join("fullchain.pem"));
        let legacy_private_key = fs::read(directory.join("private-key.pem"));
        if let (Ok(certificate_pem), Ok(private_key_pem)) = (legacy_certificate, legacy_private_key)
        {
            return self.install_certificate(&hostname, &certificate_pem, &private_key_pem);
        }

        match last_error {
            Some(error) => Err(error.context("no valid committed certificate generation")),
            None => anyhow::bail!("no persisted certificate exists for {hostname}"),
        }
    }

    pub(crate) async fn issue_certificate(
        &self,
        hostname: &str,
        config: &AcmeIssueConfig,
    ) -> anyhow::Result<CertificateIssueResult> {
        let hostname = normalize_certificate_identifier(hostname)?;
        anyhow::ensure!(
            !hostname.starts_with("*.") || config.challenge_type == AcmeChallengeType::Dns01,
            "wildcard certificates require DNS-01"
        );
        anyhow::ensure!(
            config.challenge_type != AcmeChallengeType::Dns01 || self.cloudflare_dns.is_some(),
            "Cloudflare DNS-01 credentials are not configured"
        );
        self.issue_certificate_with_timeout(&hostname, config, ACME_OPERATION_TIMEOUT)
            .await
    }

    async fn issue_certificate_with_timeout(
        &self,
        hostname: &str,
        config: &AcmeIssueConfig,
        operation_timeout: Duration,
    ) -> anyhow::Result<CertificateIssueResult> {
        tokio::time::timeout(
            operation_timeout,
            self.issue_certificate_inner(hostname, config),
        )
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "ACME operation timed out after {} seconds",
                operation_timeout.as_secs_f64()
            )
        })?
    }

    async fn issue_certificate_inner(
        &self,
        hostname: &str,
        config: &AcmeIssueConfig,
    ) -> anyhow::Result<CertificateIssueResult> {
        let _permit = self.order_permits.clone().acquire_owned().await?;
        let account = self.load_or_create_account(config).await?;
        let identifiers = [Identifier::Dns(hostname.to_owned())];
        let mut order = account.new_order(&NewOrder::new(&identifiers)).await?;
        let mut http01_guards = Vec::new();
        let mut dns01_guards = Vec::new();
        let mut http01_challenges_completed = 0_u64;
        let mut dns01_challenges_completed = 0_u64;
        let order_result = async {
            let mut authorizations = order.authorizations();
            while let Some(result) = authorizations.next().await {
                let mut authorization = result?;
                match authorization.status {
                    AuthorizationStatus::Valid => continue,
                    AuthorizationStatus::Pending => {}
                    status => {
                        anyhow::bail!("ACME authorization entered unexpected status: {status:?}")
                    }
                }
                match config.challenge_type {
                    AcmeChallengeType::Http01 => {
                        let mut challenge = authorization
                            .challenge(ChallengeType::Http01)
                            .ok_or_else(|| anyhow::anyhow!("ACME server did not offer HTTP-01"))?;
                        let token = challenge.token.clone();
                        let key_authorization = challenge.key_authorization().as_str().to_owned();
                        let guard = self
                            .challenges
                            .publish(hostname, &token, key_authorization)?;
                        http01_guards.push(guard);
                        challenge.set_ready().await?;
                        http01_challenges_completed = http01_challenges_completed.saturating_add(1);
                    }
                    AcmeChallengeType::Dns01 => {
                        let client = self.cloudflare_dns.as_ref().ok_or_else(|| {
                            anyhow::anyhow!("Cloudflare DNS-01 credentials are not configured")
                        })?;
                        let mut challenge = authorization
                            .challenge(ChallengeType::Dns01)
                            .ok_or_else(|| anyhow::anyhow!("ACME server did not offer DNS-01"))?;
                        let value = challenge.key_authorization().dns_value();
                        let guard = client.publish(hostname, value).await?;
                        dns01_guards.push(guard);
                        dns01_guards
                            .last()
                            .expect("DNS-01 guard was just appended")
                            .wait_for_propagation()
                            .await?;
                        challenge.set_ready().await?;
                        dns01_challenges_completed = dns01_challenges_completed.saturating_add(1);
                    }
                }
            }
            let retry = RetryPolicy::default().timeout(ACME_OPERATION_TIMEOUT);
            let status = order.poll_ready(&retry).await?;
            if status != OrderStatus::Ready {
                anyhow::bail!("ACME order did not become ready: {status:?}");
            }
            let private_key_pem = order.finalize().await?;
            let certificate_pem = order.poll_certificate(&retry).await?;
            Ok::<_, anyhow::Error>((certificate_pem, private_key_pem))
        }
        .await;
        drop(http01_guards);
        for guard in dns01_guards {
            if let Err(error) = guard.cleanup().await {
                tracing::warn!("could not clean up a Cloudflare DNS-01 TXT record: {error}");
            }
        }
        let (certificate_pem, private_key_pem) = order_result?;
        let metadata = validate_certificate(
            hostname,
            certificate_pem.as_bytes(),
            private_key_pem.as_bytes(),
        )?
        .1;
        self.persist_certificate(
            hostname,
            certificate_pem.as_bytes(),
            private_key_pem.as_bytes(),
        )?;
        self.install_certificate(
            hostname,
            certificate_pem.as_bytes(),
            private_key_pem.as_bytes(),
        )?;
        Ok(CertificateIssueResult {
            metadata,
            http01_challenges_completed,
            dns01_challenges_completed,
        })
    }

    fn install_certificate(
        &self,
        hostname: &str,
        certificate_pem: &[u8],
        private_key_pem: &[u8],
    ) -> anyhow::Result<CertificateMetadata> {
        let (certified_key, metadata) =
            validate_certificate(hostname, certificate_pem, private_key_pem)?;
        self.resolver.install(hostname, certified_key);
        Ok(metadata)
    }

    async fn load_or_create_account(&self, config: &AcmeIssueConfig) -> anyhow::Result<Account> {
        let _guard = self.account_lock.lock().await;
        let credentials_path = self.account_credentials_path(&config.directory_url);
        if let Ok(serialized) = fs::read(&credentials_path) {
            let credentials: AccountCredentials = serde_json::from_slice(&serialized)?;
            return Ok(account_builder(config)?
                .from_credentials(credentials)
                .await?);
        }
        let contact = format!("mailto:{}", config.contact_email);
        let contacts = [contact.as_str()];
        let (account, credentials) = account_builder(config)?
            .create(
                &NewAccount {
                    contact: &contacts,
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                config.directory_url.clone(),
                None,
            )
            .await?;
        write_secret_file(&credentials_path, &serde_json::to_vec(&credentials)?)?;
        Ok(account)
    }

    fn persist_certificate(
        &self,
        hostname: &str,
        certificate_pem: &[u8],
        private_key_pem: &[u8],
    ) -> anyhow::Result<()> {
        let directory = self.certificate_directory(hostname);
        let generations = directory.join(CERTIFICATE_GENERATIONS_DIRECTORY);
        fs::create_dir_all(&generations)?;
        let generation_name = format!(
            "{:020}-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
            uuid::Uuid::new_v4()
        );
        let staging = generations.join(format!(".{generation_name}.tmp"));
        let committed = generations.join(&generation_name);
        fs::create_dir(&staging)?;

        let result = (|| -> anyhow::Result<()> {
            write_secret_file(&staging.join("fullchain.pem"), certificate_pem)?;
            write_secret_file(&staging.join("private-key.pem"), private_key_pem)?;
            write_secret_file(&staging.join("committed"), CERTIFICATE_COMMIT_MARKER)?;
            sync_directory(&staging)?;

            // 继续维护原文件名，供运维脚本读取；恢复逻辑不会把它们当作新格式的
            // 权威证书对，因此跨文件更新中断不会造成新旧证书混装。
            write_secret_file(&directory.join("fullchain.pem"), certificate_pem)?;
            write_secret_file(&directory.join("private-key.pem"), private_key_pem)?;

            fs::rename(&staging, &committed)?;
            sync_directory(&generations)?;
            let _ = cleanup_old_certificate_generations(&generations);
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&staging);
        }
        result?;
        Ok(())
    }

    fn certificate_directory(&self, hostname: &str) -> PathBuf {
        let directory_name = hostname.strip_prefix("*.").map_or_else(
            || hostname.to_owned(),
            |suffix| format!("_wildcard_.{suffix}"),
        );
        self.data_dir.join("certificates").join(directory_name)
    }

    fn account_credentials_path(&self, directory_url: &str) -> PathBuf {
        let mut hasher = DefaultHasher::new();
        directory_url.hash(&mut hasher);
        self.data_dir
            .join("acme")
            .join(format!("account-{:016x}.json", hasher.finish()))
    }
}

fn account_builder(config: &AcmeIssueConfig) -> anyhow::Result<AccountBuilder> {
    match &config.root_ca_path {
        Some(path) => Ok(Account::builder_with_root(path)?),
        None => Ok(Account::builder()?),
    }
}

pub(crate) struct DynamicCertResolver {
    certificates: ArcSwap<HashMap<String, Arc<CertifiedKey>>>,
    update_lock: Mutex<()>,
}

impl Default for DynamicCertResolver {
    fn default() -> Self {
        Self {
            certificates: ArcSwap::from_pointee(HashMap::new()),
            update_lock: Mutex::new(()),
        }
    }
}

impl fmt::Debug for DynamicCertResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DynamicCertResolver")
            .field("certificate_count", &self.certificates.load().len())
            .finish()
    }
}

impl DynamicCertResolver {
    fn install(&self, hostname: &str, certificate: Arc<CertifiedKey>) {
        let _guard = self
            .update_lock
            .lock()
            .expect("dynamic certificate resolver update lock poisoned");
        let mut updated = self.certificates.load().as_ref().clone();
        updated.insert(hostname.to_owned(), certificate);
        self.certificates.store(Arc::new(updated));
    }

    fn remove(&self, hostname: &str) {
        let Ok(hostname) = normalize_certificate_identifier(hostname) else {
            return;
        };
        let _guard = self
            .update_lock
            .lock()
            .expect("dynamic certificate resolver update lock poisoned");
        let mut updated = self.certificates.load().as_ref().clone();
        updated.remove(&hostname);
        self.certificates.store(Arc::new(updated));
    }

    fn contains(&self, hostname: &str) -> bool {
        let Ok(identifier) = normalize_certificate_identifier(hostname) else {
            return false;
        };
        let certificates = self.certificates.load();
        if certificates.contains_key(&identifier) {
            return true;
        }
        if identifier.starts_with("*.") {
            return false;
        }
        wildcard_identifier_for_hostname(&identifier)
            .is_some_and(|wildcard| certificates.contains_key(&wildcard))
    }

    fn len(&self) -> usize {
        self.certificates.load().len()
    }
}

impl ResolvesServerCert for DynamicCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let hostname = normalize_hostname(client_hello.server_name()?).ok()?;
        let certificates = self.certificates.load();
        certificates.get(&hostname).cloned().or_else(|| {
            wildcard_identifier_for_hostname(&hostname)
                .and_then(|wildcard| certificates.get(&wildcard).cloned())
        })
    }
}

fn wildcard_identifier_for_hostname(hostname: &str) -> Option<String> {
    let (_, suffix) = hostname.split_once('.')?;
    Some(format!("*.{suffix}"))
}

#[derive(Default)]
pub(crate) struct Http01ChallengeStore {
    entries: Mutex<HashMap<(String, String), Http01ChallengeEntry>>,
}

struct Http01ChallengeEntry {
    key_authorization: String,
    expires_at: Instant,
}

impl Http01ChallengeStore {
    fn publish(
        self: &Arc<Self>,
        hostname: &str,
        token: &str,
        key_authorization: String,
    ) -> anyhow::Result<Http01ChallengeGuard> {
        let hostname = normalize_hostname(hostname)?;
        validate_challenge_token(token)?;
        self.entries
            .lock()
            .expect("HTTP-01 challenge store lock poisoned")
            .insert(
                (hostname.clone(), token.to_owned()),
                Http01ChallengeEntry {
                    key_authorization,
                    expires_at: Instant::now() + CHALLENGE_TTL,
                },
            );
        Ok(Http01ChallengeGuard {
            store: self.clone(),
            hostname,
            token: token.to_owned(),
        })
    }

    pub(crate) fn lookup(&self, hostname: &str, token: &str) -> Option<String> {
        let hostname = normalize_hostname(hostname).ok()?;
        validate_challenge_token(token).ok()?;
        let mut entries = self
            .entries
            .lock()
            .expect("HTTP-01 challenge store lock poisoned");
        entries.retain(|_, entry| entry.expires_at > Instant::now());
        entries
            .get(&(hostname, token.to_owned()))
            .map(|entry| entry.key_authorization.clone())
    }

    fn remove(&self, hostname: &str, token: &str) {
        self.entries
            .lock()
            .expect("HTTP-01 challenge store lock poisoned")
            .remove(&(hostname.to_owned(), token.to_owned()));
    }
}

struct Http01ChallengeGuard {
    store: Arc<Http01ChallengeStore>,
    hostname: String,
    token: String,
}

impl Drop for Http01ChallengeGuard {
    fn drop(&mut self) {
        self.store.remove(&self.hostname, &self.token);
    }
}

fn validate_challenge_token(token: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        (1..=256).contains(&token.len())
            && token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'),
        "HTTP-01 challenge token is invalid"
    );
    Ok(())
}

fn validate_certificate(
    hostname: &str,
    certificate_pem: &[u8],
    private_key_pem: &[u8],
) -> anyhow::Result<(Arc<CertifiedKey>, CertificateMetadata)> {
    let mut certificate_reader = BufReader::new(certificate_pem);
    let certificates = rustls_pemfile::certs(&mut certificate_reader)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()?;
    anyhow::ensure!(!certificates.is_empty(), "certificate chain is empty");
    let mut key_reader = BufReader::new(private_key_pem);
    let private_key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)?
        .ok_or_else(|| anyhow::anyhow!("certificate private key is missing"))?;
    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates.clone(), private_key.clone_key())?;
    let signing_key = any_supported_type(&private_key)?;
    let certified_key = Arc::new(CertifiedKey::new(certificates.clone(), signing_key));
    let (_, parsed) = parse_x509_certificate(certificates[0].as_ref())
        .map_err(|_| anyhow::anyhow!("could not parse leaf certificate"))?;
    let hostname = normalize_certificate_identifier(hostname)?;
    let matches_hostname = parsed.subject_alternative_name()?.is_some_and(|extension| {
        extension.value.general_names.iter().any(|name| {
                matches!(name, GeneralName::DNSName(value) if value.trim_end_matches('.').eq_ignore_ascii_case(&hostname))
            })
    });
    anyhow::ensure!(
        matches_hostname,
        "certificate does not cover route hostname"
    );
    let not_before = parsed.validity().not_before.timestamp();
    let not_after = parsed.validity().not_after.timestamp();
    anyhow::ensure!(
        not_before >= 0 && not_after >= 0,
        "certificate validity is invalid"
    );
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    anyhow::ensure!(not_after > now, "certificate is expired");
    anyhow::ensure!(
        not_before <= now.saturating_add(300),
        "certificate is not valid yet"
    );
    let metadata = CertificateMetadata {
        issuer: parsed.issuer().to_string(),
        not_before_unix_seconds: not_before as u64,
        not_after_unix_seconds: not_after as u64,
    };
    Ok((certified_key, metadata))
}

fn committed_certificate_pairs(directory: &Path) -> anyhow::Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let generations = directory.join(CERTIFICATE_GENERATIONS_DIRECTORY);
    let entries = match fs::read_dir(&generations) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
    };
    let mut directories = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            entry
                .file_type()
                .ok()
                .filter(|file_type| file_type.is_dir())
                .map(|_| entry.path())
        })
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| !name.starts_with('.'))
        })
        .collect::<Vec<_>>();
    directories.sort_by(|left, right| right.file_name().cmp(&left.file_name()));

    let mut pairs = Vec::new();
    for generation in directories {
        let marker_is_valid = fs::read(generation.join("committed"))
            .is_ok_and(|marker| marker == CERTIFICATE_COMMIT_MARKER);
        if !marker_is_valid {
            continue;
        }
        let certificate_pem = fs::read(generation.join("fullchain.pem"));
        let private_key_pem = fs::read(generation.join("private-key.pem"));
        if let (Ok(certificate_pem), Ok(private_key_pem)) = (certificate_pem, private_key_pem) {
            pairs.push((certificate_pem, private_key_pem));
        }
    }
    Ok(pairs)
}

fn cleanup_old_certificate_generations(generations: &Path) -> anyhow::Result<()> {
    let mut directories = fs::read_dir(generations)?
        .filter_map(Result::ok)
        .filter_map(|entry| {
            entry
                .file_type()
                .ok()
                .filter(|file_type| file_type.is_dir())
                .map(|_| entry.path())
        })
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| !name.starts_with('.'))
        })
        .collect::<Vec<_>>();
    directories.sort_by(|left, right| right.file_name().cmp(&left.file_name()));
    for obsolete in directories
        .into_iter()
        .skip(RETAINED_CERTIFICATE_GENERATIONS)
    {
        let _ = fs::remove_dir_all(obsolete);
    }
    Ok(())
}

#[cfg(unix)]
fn sync_directory(directory: &Path) -> anyhow::Result<()> {
    fs::File::open(directory)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Path) -> anyhow::Result<()> {
    Ok(())
}

pub(crate) fn write_secret_file(path: &Path, contents: &[u8]) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("secret file has no parent directory"))?;
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name().unwrap().to_string_lossy(),
        uuid::Uuid::new_v4()
    ));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut temporary_file = options.open(&temporary)?;
    temporary_file.write_all(contents)?;
    temporary_file.sync_all()?;
    drop(temporary_file);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))?;
    }
    if path.exists() {
        let backup = parent.join(format!(
            ".{}.{}.backup",
            path.file_name().unwrap().to_string_lossy(),
            uuid::Uuid::new_v4()
        ));
        fs::rename(path, &backup)?;
        if let Err(error) = fs::rename(&temporary, path) {
            let _ = fs::rename(&backup, path);
            let _ = fs::remove_file(&temporary);
            return Err(error.into());
        }
        let _ = fs::remove_file(backup);
    } else {
        fs::rename(&temporary, path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        validate_certificate, validate_challenge_token, AcmeChallengeType, AcmeIssueConfig,
        CertificateManager, DynamicCertResolver, Http01ChallengeStore, CERTIFICATE_COMMIT_MARKER,
        CERTIFICATE_GENERATIONS_DIRECTORY, MAX_PARALLEL_ORDERS,
    };
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use std::{
        fs,
        sync::{Arc, Barrier},
        thread,
        time::Duration,
    };

    #[test]
    fn challenge_tokens_accept_only_base64url_characters() {
        assert!(validate_challenge_token("abc_DEF-123").is_ok());
        assert!(validate_challenge_token("").is_err());
        assert!(validate_challenge_token("bad/token").is_err());
        assert!(validate_challenge_token(&"a".repeat(257)).is_err());
    }

    #[test]
    fn challenge_store_matches_host_and_removes_on_guard_drop() {
        let store = Arc::new(Http01ChallengeStore::default());
        let guard = store
            .publish(
                "Site.Example.com",
                "token_1",
                "token_1.authorization".to_owned(),
            )
            .expect("challenge should publish");
        assert_eq!(
            store.lookup("site.example.com:80", "token_1").as_deref(),
            Some("token_1.authorization")
        );
        assert!(store.lookup("other.example.com", "token_1").is_none());
        drop(guard);
        assert!(store.lookup("site.example.com", "token_1").is_none());
    }

    #[test]
    fn empty_dynamic_resolver_rejects_unknown_names() {
        let resolver = DynamicCertResolver::default();
        assert!(!resolver.contains("unknown.example.com"));
    }

    #[test]
    fn concurrent_resolver_updates_do_not_lose_certificates() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["seed.example.com".to_owned()])
                .expect("test certificate should generate");
        let (certificate, _) = validate_certificate(
            "seed.example.com",
            cert.pem().as_bytes(),
            signing_key.serialize_pem().as_bytes(),
        )
        .expect("test certificate should validate");
        let resolver = Arc::new(DynamicCertResolver::default());
        let hostnames = (0..32)
            .map(|index| format!("site-{index}.example.com"))
            .collect::<Vec<_>>();
        let barrier = Arc::new(Barrier::new(hostnames.len()));
        let workers = hostnames
            .iter()
            .cloned()
            .map(|hostname| {
                let resolver = resolver.clone();
                let certificate = certificate.clone();
                let barrier = barrier.clone();
                thread::spawn(move || {
                    barrier.wait();
                    resolver.install(&hostname, certificate);
                })
            })
            .collect::<Vec<_>>();
        for worker in workers {
            worker.join().expect("resolver update worker should finish");
        }
        assert_eq!(resolver.len(), hostnames.len());
        assert!(hostnames.iter().all(|hostname| resolver.contains(hostname)));

        for index in 0..32 {
            let removed = format!("remove-{index}.example.com");
            let added = format!("add-{index}.example.com");
            resolver.install(&removed, certificate.clone());
            let barrier = Arc::new(Barrier::new(2));
            let remove_worker = {
                let resolver = resolver.clone();
                let barrier = barrier.clone();
                thread::spawn(move || {
                    barrier.wait();
                    resolver.remove(&removed);
                })
            };
            let install_worker = {
                let resolver = resolver.clone();
                let certificate = certificate.clone();
                thread::spawn(move || {
                    barrier.wait();
                    resolver.install(&added, certificate);
                })
            };
            remove_worker
                .join()
                .expect("resolver remove worker should finish");
            install_worker
                .join()
                .expect("resolver install worker should finish");
            assert!(!resolver.contains(&format!("remove-{index}.example.com")));
            assert!(resolver.contains(&format!("add-{index}.example.com")));
        }
    }

    #[test]
    fn certificate_is_validated_persisted_and_reloaded() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let directory = std::env::temp_dir().join(format!(
            "linklake-certificate-test-{}",
            uuid::Uuid::new_v4()
        ));
        let hostname = "secure.example.com";
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec![hostname.to_owned()])
                .expect("test certificate should generate");
        let manager = CertificateManager::new(directory.clone()).expect("manager should open");
        let metadata = manager
            .install_certificate(
                hostname,
                cert.pem().as_bytes(),
                signing_key.serialize_pem().as_bytes(),
            )
            .expect("certificate should install");
        assert!(metadata.not_after_unix_seconds > metadata.not_before_unix_seconds);
        assert!(manager.has_certificate(hostname));
        manager
            .persist_certificate(
                hostname,
                cert.pem().as_bytes(),
                signing_key.serialize_pem().as_bytes(),
            )
            .expect("certificate should persist");

        let restored = CertificateManager::new(directory.clone()).expect("manager should reopen");
        restored
            .load_certificate(hostname)
            .expect("certificate should reload");
        assert!(restored.has_certificate(hostname));
        restored
            .delete_certificate(hostname)
            .expect("certificate should delete");
        assert!(!restored.has_certificate(hostname));
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn wildcard_certificate_is_persisted_and_matches_only_one_label() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let directory = std::env::temp_dir().join(format!(
            "linklake-wildcard-certificate-test-{}",
            uuid::Uuid::new_v4()
        ));
        let identifier = "*.example.com";
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec![identifier.to_owned()])
                .expect("wildcard test certificate should generate");
        let manager = CertificateManager::new(directory.clone()).expect("manager should open");
        manager
            .install_certificate(
                identifier,
                cert.pem().as_bytes(),
                signing_key.serialize_pem().as_bytes(),
            )
            .expect("wildcard certificate should install");
        assert!(manager.has_certificate(identifier));
        assert!(manager.has_certificate("node.example.com"));
        assert!(!manager.has_certificate("nested.node.example.com"));
        manager
            .persist_certificate(
                identifier,
                cert.pem().as_bytes(),
                signing_key.serialize_pem().as_bytes(),
            )
            .expect("wildcard certificate should persist");

        let restored = CertificateManager::new(directory.clone()).expect("manager should reopen");
        restored
            .load_certificate(identifier)
            .expect("wildcard certificate should reload");
        assert!(restored.has_certificate("node.example.com"));
        restored
            .delete_certificate(identifier)
            .expect("wildcard certificate should delete");
        assert!(!restored.has_certificate("node.example.com"));
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn certificate_for_another_hostname_is_rejected() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["other.example.com".to_owned()])
                .expect("test certificate should generate");
        let directory = std::env::temp_dir().join(format!(
            "linklake-certificate-test-{}",
            uuid::Uuid::new_v4()
        ));
        let manager = CertificateManager::new(directory.clone()).expect("manager should open");
        assert!(manager
            .install_certificate(
                "secure.example.com",
                cert.pem().as_bytes(),
                signing_key.serialize_pem().as_bytes(),
            )
            .is_err());
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn certificate_recovery_uses_only_complete_consistent_generations() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let directory = std::env::temp_dir().join(format!(
            "linklake-certificate-recovery-test-{}",
            uuid::Uuid::new_v4()
        ));
        let hostname = "recovery.example.com";
        let CertifiedKey {
            cert: old_cert,
            signing_key: old_key,
        } = generate_simple_self_signed(vec![hostname.to_owned()])
            .expect("old test certificate should generate");
        let CertifiedKey {
            cert: new_cert,
            signing_key: _,
        } = generate_simple_self_signed(vec![hostname.to_owned()])
            .expect("new test certificate should generate");
        let manager = CertificateManager::new(directory.clone()).expect("manager should open");
        manager
            .persist_certificate(
                hostname,
                old_cert.pem().as_bytes(),
                old_key.serialize_pem().as_bytes(),
            )
            .expect("old certificate generation should persist");

        let generations = directory
            .join("certificates")
            .join(hostname)
            .join(CERTIFICATE_GENERATIONS_DIRECTORY);
        let old_generation = fs::read_dir(&generations)
            .expect("generation directory should exist")
            .filter_map(Result::ok)
            .find(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
            .expect("committed generation should exist")
            .path();

        let interrupted = generations.join(".99999999999999999999-interrupted.tmp");
        fs::create_dir(&interrupted).expect("interrupted generation should create");
        fs::write(interrupted.join("fullchain.pem"), new_cert.pem())
            .expect("interrupted certificate should write");
        fs::write(interrupted.join("private-key.pem"), old_key.serialize_pem())
            .expect("interrupted private key should write");

        let corrupt = generations.join("99999999999999999999-corrupt");
        fs::create_dir(&corrupt).expect("corrupt generation should create");
        fs::write(corrupt.join("fullchain.pem"), new_cert.pem())
            .expect("corrupt certificate should write");
        fs::write(corrupt.join("private-key.pem"), old_key.serialize_pem())
            .expect("corrupt private key should write");
        fs::write(corrupt.join("committed"), CERTIFICATE_COMMIT_MARKER)
            .expect("corrupt commit marker should write");

        let legacy = directory.join("certificates").join(hostname);
        fs::write(legacy.join("fullchain.pem"), new_cert.pem())
            .expect("legacy certificate should write");
        fs::write(legacy.join("private-key.pem"), old_key.serialize_pem())
            .expect("legacy private key should write");

        let restored = CertificateManager::new(directory.clone()).expect("manager should reopen");
        restored
            .load_certificate(hostname)
            .expect("manager should fall back to the last consistent committed generation");
        assert!(restored.has_certificate(hostname));

        fs::remove_dir_all(old_generation).expect("old generation should remove");
        let no_valid_generation =
            CertificateManager::new(directory.clone()).expect("manager should reopen again");
        assert!(no_valid_generation.load_certificate(hostname).is_err());
        let _ = fs::remove_dir_all(directory);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn acme_total_timeout_covers_permit_and_account_lock_waits() {
        let directory = std::env::temp_dir().join(format!(
            "linklake-acme-timeout-test-{}",
            uuid::Uuid::new_v4()
        ));
        let manager = CertificateManager::new(directory.clone()).expect("manager should open");
        let config = AcmeIssueConfig {
            directory_url: "https://unused.invalid/directory".to_owned(),
            contact_email: "test@example.com".to_owned(),
            challenge_type: AcmeChallengeType::Http01,
            root_ca_path: None,
        };
        let held_permits = manager
            .order_permits
            .clone()
            .acquire_many_owned(MAX_PARALLEL_ORDERS as u32)
            .await
            .expect("all order permits should be held");
        let permit_error = manager
            .issue_certificate_with_timeout(
                "timeout.example.com",
                &config,
                Duration::from_millis(25),
            )
            .await
            .expect_err("waiting for an order permit should time out");
        assert!(permit_error
            .to_string()
            .contains("ACME operation timed out"));
        drop(held_permits);
        assert_eq!(
            manager.order_permits.available_permits(),
            MAX_PARALLEL_ORDERS
        );

        let account_guard = manager.account_lock.lock().await;
        let account_error = manager
            .issue_certificate_with_timeout(
                "timeout.example.com",
                &config,
                Duration::from_millis(25),
            )
            .await
            .expect_err("waiting for the account lock should time out");
        assert!(account_error
            .to_string()
            .contains("ACME operation timed out"));
        assert_eq!(
            manager.order_permits.available_permits(),
            MAX_PARALLEL_ORDERS
        );
        drop(account_guard);
        let _ = fs::remove_dir_all(directory);
    }
}
