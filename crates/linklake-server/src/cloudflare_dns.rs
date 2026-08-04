use crate::{
    certificate_catalog::normalize_certificate_identifier, certificate_manager::write_secret_file,
};
use reqwest::{Method, StatusCode, Url};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    env, fmt, fs,
    io::Read,
    net::IpAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};
use zeroize::Zeroizing;

const DEFAULT_API_BASE_URL: &str = "https://api.cloudflare.com/client/v4/";
const DEFAULT_DNS_LOOKUP_URL: &str = "https://cloudflare-dns.com/dns-query";
const DEFAULT_PROPAGATION_TIMEOUT: Duration = Duration::from_secs(60);
const DEFAULT_PROPAGATION_INTERVAL: Duration = Duration::from_secs(1);
const API_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_JOURNAL_ENTRIES: usize = 256;
const JOURNAL_DIRECTORY: &str = "dns01-records";

#[derive(Clone)]
struct CloudflareApiToken(Arc<Zeroizing<String>>);

impl CloudflareApiToken {
    fn new(value: String) -> anyhow::Result<Self> {
        let value = Zeroizing::new(value);
        let value = value.trim();
        anyhow::ensure!(
            (8..=1024).contains(&value.len())
                && value.is_ascii()
                && !value
                    .bytes()
                    .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control()),
            "Cloudflare API token is invalid"
        );
        Ok(Self(Arc::new(Zeroizing::new(value.to_owned()))))
    }

    fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for CloudflareApiToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CloudflareApiToken([REDACTED])")
    }
}

#[derive(Clone)]
pub(crate) struct CloudflareDnsClient {
    http: reqwest::Client,
    api_base_url: Url,
    dns_lookup_url: Url,
    token: CloudflareApiToken,
    journal_dir: PathBuf,
    propagation_timeout: Duration,
    propagation_interval: Duration,
    operation_lock: Arc<AsyncMutex<()>>,
}

impl fmt::Debug for CloudflareDnsClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CloudflareDnsClient")
            .field("api_base_url", &self.api_base_url)
            .field("dns_lookup_url", &self.dns_lookup_url)
            .field("journal_dir", &self.journal_dir)
            .field("propagation_timeout", &self.propagation_timeout)
            .field("propagation_interval", &self.propagation_interval)
            .finish_non_exhaustive()
    }
}

impl CloudflareDnsClient {
    pub(crate) fn from_environment(data_dir: &Path) -> anyhow::Result<Option<Self>> {
        let Some(token) = load_token_from_environment()? else {
            return Ok(None);
        };
        let api_base_url =
            environment_api_base_url("LINKLAKE_CLOUDFLARE_API_BASE_URL", DEFAULT_API_BASE_URL)?;
        let dns_lookup_url =
            environment_url("LINKLAKE_ACME_DNS_LOOKUP_URL", DEFAULT_DNS_LOOKUP_URL, true)?;
        let propagation_timeout = environment_duration(
            "LINKLAKE_ACME_DNS_PROPAGATION_TIMEOUT_SECONDS",
            DEFAULT_PROPAGATION_TIMEOUT,
            Duration::from_secs(1),
            Duration::from_secs(300),
            1000,
        )?;
        let propagation_interval = environment_duration(
            "LINKLAKE_ACME_DNS_PROPAGATION_INTERVAL_MILLISECONDS",
            DEFAULT_PROPAGATION_INTERVAL,
            Duration::from_millis(50),
            Duration::from_secs(10),
            1,
        )?;
        anyhow::ensure!(
            propagation_interval <= propagation_timeout,
            "DNS propagation interval exceeds its timeout"
        );
        let http = reqwest::Client::builder()
            .timeout(API_REQUEST_TIMEOUT)
            .user_agent(concat!("LinkLake/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Some(Self {
            http,
            api_base_url,
            dns_lookup_url,
            token,
            journal_dir: data_dir.join("acme").join(JOURNAL_DIRECTORY),
            propagation_timeout,
            propagation_interval,
            operation_lock: Arc::new(AsyncMutex::new(())),
        }))
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        data_dir: &Path,
        api_base_url: &str,
        dns_lookup_url: &str,
        token: &str,
        propagation_timeout: Duration,
        propagation_interval: Duration,
    ) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(API_REQUEST_TIMEOUT)
            .build()?;
        Ok(Self {
            http,
            api_base_url: normalized_api_base_url(api_base_url)?,
            dns_lookup_url: validated_url(dns_lookup_url, true)?,
            token: CloudflareApiToken::new(token.to_owned())?,
            journal_dir: data_dir.join("acme").join(JOURNAL_DIRECTORY),
            propagation_timeout,
            propagation_interval,
            operation_lock: Arc::new(AsyncMutex::new(())),
        })
    }

    pub(crate) async fn publish(
        &self,
        certificate_identifier: &str,
        value: String,
    ) -> anyhow::Result<Dns01ChallengeGuard> {
        let operation_guard = self.operation_lock.clone().lock_owned().await;
        self.recover_orphaned_records().await?;
        let certificate_identifier = normalize_certificate_identifier(certificate_identifier)?;
        let dns_name = certificate_identifier
            .strip_prefix("*.")
            .unwrap_or(&certificate_identifier);
        let record_name = format!("_acme-challenge.{dns_name}");
        let zone = self.discover_zone(dns_name).await?;
        let record = self
            .create_txt_record(&zone.id, &record_name, &value)
            .await?;
        let journal = Dns01Journal {
            zone_id: zone.id,
            record_id: record.id,
        };
        let journal_path = self
            .journal_dir
            .join(format!("{}.json", uuid::Uuid::new_v4()));
        if let Err(error) = write_secret_file(&journal_path, &serde_json::to_vec(&journal)?) {
            let _ = self
                .delete_txt_record(&journal.zone_id, &journal.record_id)
                .await;
            return Err(error.context("could not persist DNS-01 cleanup journal"));
        }
        Ok(Dns01ChallengeGuard {
            client: self.clone(),
            operation_guard: Some(operation_guard),
            record: Some(PublishedDns01Record {
                journal,
                journal_path,
                record_name,
                value,
            }),
        })
    }

    async fn recover_orphaned_records(&self) -> anyhow::Result<()> {
        let entries = match fs::read_dir(&self.journal_dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        let mut paths = Vec::new();
        for entry in entries {
            let entry = entry?;
            if entry.file_type()?.is_file()
                && entry.path().extension().and_then(|value| value.to_str()) == Some("json")
            {
                paths.push(entry.path());
                anyhow::ensure!(
                    paths.len() <= MAX_JOURNAL_ENTRIES,
                    "too many pending DNS-01 cleanup journals"
                );
            }
        }
        paths.sort();
        for path in paths {
            let serialized = fs::read(&path)?;
            anyhow::ensure!(
                serialized.len() <= 4096,
                "DNS-01 cleanup journal is too large"
            );
            let journal: Dns01Journal = serde_json::from_slice(&serialized)?;
            validate_cloudflare_id(&journal.zone_id)?;
            validate_cloudflare_id(&journal.record_id)?;
            self.delete_txt_record(&journal.zone_id, &journal.record_id)
                .await?;
            remove_journal(&path)?;
        }
        Ok(())
    }

    async fn discover_zone(&self, dns_name: &str) -> anyhow::Result<CloudflareZone> {
        let labels = dns_name.split('.').collect::<Vec<_>>();
        anyhow::ensure!(
            labels.len() >= 2,
            "DNS-01 name does not contain a registrable zone"
        );
        for offset in 0..labels.len() - 1 {
            let candidate = labels[offset..].join(".");
            let mut url = self.api_url("zones")?;
            url.query_pairs_mut()
                .append_pair("name", &candidate)
                .append_pair("per_page", "50");
            let zones: Vec<CloudflareZone> = self
                .request_json(Method::GET, url, Option::<&()>::None)
                .await?;
            if let Some(zone) = zones
                .into_iter()
                .find(|zone| zone.name.eq_ignore_ascii_case(&candidate))
            {
                validate_cloudflare_id(&zone.id)?;
                return Ok(zone);
            }
        }
        anyhow::bail!("Cloudflare zone was not found for the DNS-01 name")
    }

    async fn create_txt_record(
        &self,
        zone_id: &str,
        record_name: &str,
        value: &str,
    ) -> anyhow::Result<CloudflareDnsRecord> {
        validate_cloudflare_id(zone_id)?;
        let url = self.api_url(&format!("zones/{zone_id}/dns_records"))?;
        let request = CreateDnsRecordRequest {
            record_type: "TXT",
            name: record_name,
            content: value,
            ttl: 120,
            comment: "LinkLake ACME DNS-01 challenge",
        };
        let record: CloudflareDnsRecord =
            self.request_json(Method::POST, url, Some(&request)).await?;
        validate_cloudflare_id(&record.id)?;
        anyhow::ensure!(
            record
                .name
                .trim_end_matches('.')
                .eq_ignore_ascii_case(record_name)
                && record.content == value,
            "Cloudflare returned an unexpected DNS record"
        );
        Ok(record)
    }

    async fn delete_txt_record(&self, zone_id: &str, record_id: &str) -> anyhow::Result<()> {
        validate_cloudflare_id(zone_id)?;
        validate_cloudflare_id(record_id)?;
        let url = self.api_url(&format!("zones/{zone_id}/dns_records/{record_id}"))?;
        let response = self
            .http
            .request(Method::DELETE, url)
            .bearer_auth(self.token.expose())
            .send()
            .await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(());
        }
        let _: serde_json::Value = decode_cloudflare_response(response).await?;
        Ok(())
    }

    async fn request_json<B, T>(
        &self,
        method: Method,
        url: Url,
        body: Option<&B>,
    ) -> anyhow::Result<T>
    where
        B: Serialize + ?Sized,
        T: DeserializeOwned,
    {
        let mut request = self
            .http
            .request(method, url)
            .bearer_auth(self.token.expose());
        if let Some(body) = body {
            request = request.json(body);
        }
        decode_cloudflare_response(request.send().await?).await
    }

    fn api_url(&self, path: &str) -> anyhow::Result<Url> {
        Ok(self.api_base_url.join(path)?)
    }

    async fn dns_value_is_visible(&self, name: &str, value: &str) -> anyhow::Result<bool> {
        let mut url = self.dns_lookup_url.clone();
        url.query_pairs_mut()
            .append_pair("name", name)
            .append_pair("type", "TXT");
        let response = self
            .http
            .get(url)
            .header(reqwest::header::ACCEPT, "application/dns-json")
            .send()
            .await?;
        let status = response.status();
        let bytes = limited_response_bytes(response).await?;
        anyhow::ensure!(status.is_success(), "DNS propagation probe failed");
        let lookup: DnsJsonResponse = serde_json::from_slice(&bytes)?;
        if lookup.status != 0 {
            return Ok(false);
        }
        Ok(lookup
            .answer
            .unwrap_or_default()
            .into_iter()
            .any(|answer| answer.record_type == 16 && normalize_txt_answer(&answer.data) == value))
    }
}

pub(crate) struct Dns01ChallengeGuard {
    client: CloudflareDnsClient,
    operation_guard: Option<OwnedMutexGuard<()>>,
    record: Option<PublishedDns01Record>,
}

impl Dns01ChallengeGuard {
    pub(crate) async fn wait_for_propagation(&self) -> anyhow::Result<()> {
        let record = self
            .record
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("DNS-01 record was already cleaned up"))?;
        let deadline = Instant::now() + self.client.propagation_timeout;
        loop {
            if self
                .client
                .dns_value_is_visible(&record.record_name, &record.value)
                .await
                .unwrap_or(false)
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                anyhow::bail!("DNS-01 TXT record did not propagate before the timeout");
            }
            tokio::time::sleep(self.client.propagation_interval).await;
        }
    }

    pub(crate) async fn cleanup(mut self) -> anyhow::Result<()> {
        let result = match self.record.take() {
            Some(record) => self.client.cleanup_published_record(record).await,
            None => Ok(()),
        };
        self.operation_guard.take();
        result
    }
}

impl Drop for Dns01ChallengeGuard {
    fn drop(&mut self) {
        let Some(record) = self.record.take() else {
            return;
        };
        let client = self.client.clone();
        let operation_guard = self.operation_guard.take();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _operation_guard = operation_guard;
                let _ = client.cleanup_published_record(record).await;
            });
        }
    }
}

impl CloudflareDnsClient {
    async fn cleanup_published_record(&self, record: PublishedDns01Record) -> anyhow::Result<()> {
        self.delete_txt_record(&record.journal.zone_id, &record.journal.record_id)
            .await?;
        remove_journal(&record.journal_path)
    }
}

struct PublishedDns01Record {
    journal: Dns01Journal,
    journal_path: PathBuf,
    record_name: String,
    value: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Dns01Journal {
    zone_id: String,
    record_id: String,
}

#[derive(Debug, Deserialize)]
struct CloudflareEnvelope<T> {
    success: bool,
    #[serde(default)]
    errors: Vec<CloudflareError>,
    result: Option<T>,
}

#[derive(Debug, Deserialize)]
struct CloudflareError {
    code: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct CloudflareZone {
    id: String,
    name: String,
}

#[derive(Debug, Deserialize)]
struct CloudflareDnsRecord {
    id: String,
    name: String,
    content: String,
}

#[derive(Serialize)]
struct CreateDnsRecordRequest<'a> {
    #[serde(rename = "type")]
    record_type: &'static str,
    name: &'a str,
    content: &'a str,
    ttl: u32,
    comment: &'static str,
}

#[derive(Debug, Deserialize)]
struct DnsJsonResponse {
    #[serde(rename = "Status")]
    status: u16,
    #[serde(rename = "Answer")]
    answer: Option<Vec<DnsJsonAnswer>>,
}

#[derive(Debug, Deserialize)]
struct DnsJsonAnswer {
    #[serde(rename = "type")]
    record_type: u16,
    data: String,
}

async fn decode_cloudflare_response<T: DeserializeOwned>(
    response: reqwest::Response,
) -> anyhow::Result<T> {
    let status = response.status();
    let bytes = limited_response_bytes(response).await?;
    let envelope: CloudflareEnvelope<T> = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("Cloudflare API returned an invalid response"))?;
    if !status.is_success() || !envelope.success {
        let summary = envelope
            .errors
            .first()
            .map(|error| {
                let code = error
                    .code
                    .map_or_else(|| "unknown".to_owned(), |value| value.to_string());
                format!("code {code}")
            })
            .unwrap_or_else(|| "request rejected".to_owned());
        anyhow::bail!("Cloudflare API request failed ({status}; {summary})");
    }
    envelope
        .result
        .ok_or_else(|| anyhow::anyhow!("Cloudflare API response did not contain a result"))
}

async fn limited_response_bytes(mut response: reqwest::Response) -> anyhow::Result<bytes::Bytes> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        anyhow::bail!("remote response is too large");
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        anyhow::ensure!(
            bytes.len().saturating_add(chunk.len()) <= MAX_RESPONSE_BYTES,
            "remote response is too large"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes.into())
}

fn load_token_from_environment() -> anyhow::Result<Option<CloudflareApiToken>> {
    let inline = env::var("LINKLAKE_CLOUDFLARE_API_TOKEN")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let file = env::var_os("LINKLAKE_CLOUDFLARE_API_TOKEN_FILE")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    anyhow::ensure!(
        inline.is_none() || file.is_none(),
        "Cloudflare API token source is ambiguous"
    );
    let value = match (inline, file) {
        (Some(value), None) => value,
        (None, Some(path)) => read_token_file(&path)?,
        (None, None) => return Ok(None),
        (Some(_), Some(_)) => unreachable!("ambiguous token source was rejected"),
    };
    Ok(Some(CloudflareApiToken::new(value)?))
}

fn read_token_file(path: &Path) -> anyhow::Result<String> {
    let file = fs::File::open(path)?;
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file(),
        "Cloudflare API token path is not a file"
    );
    anyhow::ensure!(
        metadata.len() <= 4096,
        "Cloudflare API token file is too large"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        anyhow::ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "Cloudflare API token file permissions must not allow group or other access"
        );
    }
    let mut bytes = Vec::with_capacity(metadata.len().min(4096) as usize);
    file.take(4097).read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() <= 4096,
        "Cloudflare API token file is too large"
    );
    String::from_utf8(bytes)
        .map_err(|_| anyhow::anyhow!("Cloudflare API token file is not valid UTF-8"))
}

fn environment_url(name: &str, default: &str, allow_loopback_http: bool) -> anyhow::Result<Url> {
    let value = env::var(name).unwrap_or_else(|_| default.to_owned());
    validated_url(&value, allow_loopback_http)
}

fn environment_api_base_url(name: &str, default: &str) -> anyhow::Result<Url> {
    let value = env::var(name).unwrap_or_else(|_| default.to_owned());
    normalized_api_base_url(&value)
}

fn normalized_api_base_url(value: &str) -> anyhow::Result<Url> {
    let mut url = validated_url(value, true)?;
    if !url.path().ends_with('/') {
        let path = format!("{}/", url.path().trim_end_matches('/'));
        url.set_path(&path);
    }
    Ok(url)
}

fn validated_url(value: &str, allow_loopback_http: bool) -> anyhow::Result<Url> {
    let url = Url::parse(value)?;
    let secure = url.scheme() == "https";
    let loopback_http = allow_loopback_http
        && url.scheme() == "http"
        && url.host_str().is_some_and(|host| {
            host.eq_ignore_ascii_case("localhost")
                || host
                    .parse::<IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
        });
    anyhow::ensure!(
        secure || loopback_http,
        "Cloudflare and DNS lookup URLs must use HTTPS except for loopback tests"
    );
    anyhow::ensure!(
        url.username().is_empty() && url.password().is_none(),
        "URL credentials are not allowed"
    );
    anyhow::ensure!(
        url.query().is_none() && url.fragment().is_none(),
        "URL query and fragment are not allowed"
    );
    Ok(url)
}

fn environment_duration(
    name: &str,
    default: Duration,
    minimum: Duration,
    maximum: Duration,
    unit_milliseconds: u64,
) -> anyhow::Result<Duration> {
    let Some(value) = env::var(name).ok() else {
        return Ok(default);
    };
    let units = value
        .parse::<u64>()
        .map_err(|_| anyhow::anyhow!("{name} is invalid"))?;
    let duration = Duration::from_millis(
        units
            .checked_mul(unit_milliseconds)
            .ok_or_else(|| anyhow::anyhow!("{name} is too large"))?,
    );
    anyhow::ensure!(
        (minimum..=maximum).contains(&duration),
        "{name} is outside the supported range"
    );
    Ok(duration)
}

fn validate_cloudflare_id(value: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        (1..=128).contains(&value.len())
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'),
        "Cloudflare resource identifier is invalid"
    );
    Ok(())
}

fn normalize_txt_answer(value: &str) -> String {
    let value = value.trim();
    value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(value)
        .replace("\" \"", "")
}

fn remove_journal(path: &Path) -> anyhow::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        normalize_txt_answer, validate_cloudflare_id, validated_url, CloudflareApiToken,
        CloudflareDnsClient,
    };
    use std::time::Duration;

    #[test]
    fn response_helpers_reject_unsafe_inputs() {
        assert_eq!(normalize_txt_answer("\"dns-value\""), "dns-value");
        assert!(validate_cloudflare_id("zone_123").is_ok());
        assert!(validate_cloudflare_id("../zone").is_err());
        assert!(validated_url("https://api.cloudflare.com/client/v4/", true).is_ok());
        assert!(validated_url("http://api.cloudflare.com/client/v4/", true).is_err());
        assert!(validated_url("http://127.0.0.1:8055/", true).is_ok());
        assert!(validated_url("https://user:secret@example.com/", true).is_err());
        assert!(validated_url("https://example.com/?token=secret", true).is_err());
        let token = CloudflareApiToken::new("cloudflare-secret-token".to_owned())
            .expect("test token should be accepted");
        let debug = format!("{token:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("cloudflare-secret-token"));
        let root = std::env::temp_dir().join(format!(
            "linklake-cloudflare-client-test-{}",
            uuid::Uuid::new_v4()
        ));
        let client = CloudflareDnsClient::for_test(
            &root,
            "http://127.0.0.1:8055/client/v4",
            "http://127.0.0.1:8056/dns-query",
            "test-token-value",
            Duration::from_secs(1),
            Duration::from_millis(50),
        )
        .expect("test Cloudflare client should build");
        assert!(client.api_base_url.path().ends_with('/'));
    }
}
