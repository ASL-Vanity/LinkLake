//! LinkLake 客户端的可信下载、原子升级和回滚实现。

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use clap::ValueEnum;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use flate2::read::GzDecoder;
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io::{Cursor, Read, Write},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    thread::sleep,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tar::Archive;
use uuid::Uuid;
use zip::ZipArchive;

mod manager;
pub use manager::{
    manager_apply, manager_download, manager_rollback, manager_status, run_manager_helper,
    ManagerSchedule, ManagerStagedUpdate, ManagerStatus,
};

pub const UPDATE_SCHEMA_VERSION: u32 = 2;
pub const SIGNED_MANIFEST_NAME: &str = "linklake-release-manifest-v1.json";
pub const SIGNATURE_NAME: &str = "linklake-release-manifest-v1.sig";
const MAX_ARCHIVE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_CHECKSUM_BYTES: u64 = 16 * 1024;
const MAX_BINARY_BYTES: u64 = 128 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const UPDATE_TIMEOUT: Duration = Duration::from_secs(120);
const HELPER_RETRY_TIMEOUT: Duration = Duration::from_secs(60);
const SERVICE_WAIT_TIMEOUT: Duration = Duration::from_secs(30);
const SERVICE_STABLE_POLLS: usize = 6;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, ValueEnum, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UpdateChannel {
    Auto,
    Stable,
    Prerelease,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, ValueEnum, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UpdateProduct {
    Client,
    Server,
    Manager,
}

impl UpdateProduct {
    pub fn component(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Server => "server",
            Self::Manager => "manager",
        }
    }

    fn executable_name(self) -> &'static str {
        match (self, cfg!(windows)) {
            (Self::Client, true) => "linklake-client.exe",
            (Self::Client, false) => "linklake-client",
            (Self::Server, true) => "linklake-server.exe",
            (Self::Server, false) => "linklake-server",
            (Self::Manager, true) => "linklake_manager.exe",
            (Self::Manager, false) => "linklake_manager",
        }
    }

    #[cfg(windows)]
    fn service_name(self) -> &'static str {
        match self {
            Self::Client => "LinkLakeClient",
            Self::Server => "LinkLakeServer",
            Self::Manager => "LinkLakeManager",
        }
    }

    #[allow(dead_code)]
    fn systemd_unit(self) -> &'static str {
        match self {
            Self::Client => "linklake-client.service",
            Self::Server => "linklake-server.service",
            Self::Manager => "linklake-manager.service",
        }
    }

    #[allow(dead_code)]
    fn launchd_label(self) -> &'static str {
        match self {
            Self::Client => "com.linklake.client",
            Self::Server => "com.linklake.server",
            Self::Manager => "com.linklake.manager",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, ValueEnum, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SignaturePolicy {
    Production,
    Development,
}

impl UpdateChannel {
    fn resolve(self, current: &Version) -> Self {
        match self {
            Self::Auto if current.pre.is_empty() => Self::Stable,
            Self::Auto => Self::Prerelease,
            value => value,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct UpdateCheck {
    pub current_version: String,
    pub latest_version: String,
    pub update_available: bool,
    pub channel: UpdateChannel,
    pub release_url: Option<String>,
    pub asset_name: String,
    pub asset_size: u64,
    pub github_digest: String,
    pub signature_key_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StagedUpdate {
    schema_version: u32,
    product: UpdateProduct,
    pub current_version: String,
    pub version: String,
    pub channel: UpdateChannel,
    pub release_url: Option<String>,
    pub archive_name: String,
    pub archive_sha256: String,
    pub binary_sha256: String,
    pub staged_executable: PathBuf,
    pub staged_manifest: PathBuf,
    pub signature_key_id: String,
    pub downloaded_unix_seconds: u64,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum UpdateOperation {
    Apply,
    Rollback,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct HelperPlan {
    schema_version: u32,
    operation: UpdateOperation,
    product: UpdateProduct,
    state_directory: PathBuf,
    target_executable: PathBuf,
    staged_executable: PathBuf,
    expected_target_sha256: String,
    staged_sha256: String,
    from_version: String,
    to_version: String,
    service_installed: bool,
    service_was_running: bool,
    created_unix_seconds: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct BackupMetadata {
    schema_version: u32,
    version: String,
    sha256: String,
    target_executable: PathBuf,
    created_unix_seconds: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UpdateStatus {
    schema_version: u32,
    pub state: String,
    pub operation: Option<String>,
    pub from_version: Option<String>,
    pub to_version: Option<String>,
    pub message: String,
    pub error: Option<String>,
    pub backup: Option<PathBuf>,
    pub updated_unix_seconds: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct UpdateSchedule {
    pub state: String,
    pub operation: String,
    pub from_version: String,
    pub to_version: String,
    pub status_file: PathBuf,
    pub helper_process_id: u32,
}

#[derive(Clone, Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
    html_url: Option<String>,
    draft: bool,
    prerelease: bool,
    assets: Vec<GithubAsset>,
}

#[derive(Clone, Debug, Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
    size: u64,
    digest: Option<String>,
    state: String,
}

#[derive(Clone, Debug, Deserialize)]
struct ReleaseManifest {
    product: String,
    version: String,
    target: String,
    built_unix_seconds: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ServiceRuntime {
    NotInstalled,
    Stopped,
    Running,
}

struct SelectedRelease<'a> {
    release: &'a GithubRelease,
    version: Version,
    package: &'a GithubAsset,
    checksum: &'a GithubAsset,
    signed_manifest: &'a GithubAsset,
    signature: &'a GithubAsset,
    channel: UpdateChannel,
}

struct CurrentInstallation {
    target: PathBuf,
    version: Option<Version>,
}

struct StagedMetadata {
    current_version: String,
    channel: UpdateChannel,
    release_url: Option<String>,
    archive_sha256: String,
    signature_key_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedReleaseManifest {
    pub schema_version: u32,
    pub release_version: String,
    pub key_id: String,
    pub minimum_updater_version: String,
    pub created_unix_seconds: u64,
    pub assets: Vec<SignedAsset>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAsset {
    pub component: String,
    pub target: String,
    pub name: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedKeys {
    schema_version: u32,
    keys: Vec<TrustedKey>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedKey {
    key_id: String,
    public_key_base64: String,
    purpose: String,
    not_before_version: String,
    not_after_version: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DetachedSignature {
    pub schema_version: u32,
    pub key_id: String,
    pub algorithm: String,
    pub signature_base64: String,
}

pub fn canonical_signed_manifest_bytes(
    manifest: &SignedReleaseManifest,
) -> anyhow::Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(manifest)?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub fn default_state_directory(product: UpdateProduct) -> PathBuf {
    #[cfg(windows)]
    {
        std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join("LinkLake")
            .join("updates")
            .join(product.component())
    }
    #[cfg(target_os = "macos")]
    {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join("Library")
            .join("Application Support")
            .join("LinkLake")
            .join("updates")
            .join(product.component())
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(path) = std::env::var_os("XDG_STATE_HOME") {
            return PathBuf::from(path)
                .join("linklake")
                .join("updates")
                .join(product.component());
        }
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join(".local")
            .join("state")
            .join("linklake")
            .join("updates")
            .join(product.component())
    }
}

pub async fn check(
    product: UpdateProduct,
    repository: &str,
    requested_channel: UpdateChannel,
    signature_policy: SignaturePolicy,
) -> anyhow::Result<UpdateCheck> {
    let installation = current_installation(product)?;
    let updater_version = Version::parse(env!("CARGO_PKG_VERSION"))?;
    let channel_version = installation.version.as_ref().unwrap_or(&updater_version);
    let releases = fetch_releases(repository).await?;
    let selected = select_release(product, &releases, requested_channel, channel_version)?;
    let digest = required_github_digest(selected.package)?;
    let (_, signed) =
        fetch_and_verify_signed_manifest(repository, &selected, product, signature_policy).await?;
    Ok(UpdateCheck {
        current_version: installation
            .version
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|| "unknown".to_owned()),
        latest_version: selected.release.tag_name.clone(),
        update_available: installation
            .version
            .as_ref()
            .is_none_or(|current| selected.version > *current),
        channel: selected.channel,
        release_url: selected.release.html_url.clone(),
        asset_name: selected.package.name.clone(),
        asset_size: selected.package.size,
        github_digest: digest.to_owned(),
        signature_key_id: signed.key_id,
    })
}

pub async fn download(
    product: UpdateProduct,
    repository: &str,
    requested_channel: UpdateChannel,
    state_directory: &Path,
    allow_downgrade: bool,
    signature_policy: SignaturePolicy,
) -> anyhow::Result<StagedUpdate> {
    let installation = current_installation(product)?;
    let updater_version = Version::parse(env!("CARGO_PKG_VERSION"))?;
    let channel_version = installation.version.as_ref().unwrap_or(&updater_version);
    let releases = fetch_releases(repository).await?;
    let selected = select_release(product, &releases, requested_channel, channel_version)?;
    if let Some(current) = installation.version.as_ref() {
        ensure_network_update_allowed(
            current,
            &selected.version,
            allow_downgrade,
            signature_policy,
        )?;
    }

    let state_directory = prepare_state_directory(state_directory)?;
    let downloads = state_directory
        .join("downloads")
        .join(selected.version.to_string());
    fs::create_dir_all(&downloads)?;
    secure_directory(&downloads)?;
    let package_path = downloads.join(&selected.package.name);
    let checksum_path = downloads.join(&selected.checksum.name);
    let client = update_http_client()?;

    let (signed_manifest_bytes, signed_manifest) =
        fetch_and_verify_signed_manifest(repository, &selected, product, signature_policy).await?;
    let signed_asset = matching_signed_asset(
        &signed_manifest,
        product,
        &selected.version,
        platform_target()?,
        &selected.package.name,
    )?;

    let checksum_bytes =
        download_asset(&client, repository, selected.checksum, MAX_CHECKSUM_BYTES).await?;
    write_download_atomically(&checksum_path, &checksum_bytes)?;
    let package_bytes =
        download_asset(&client, repository, selected.package, MAX_ARCHIVE_BYTES).await?;
    let package_hash = verify_downloaded_package(
        &package_bytes,
        &checksum_bytes,
        &selected.package.name,
        &required_github_digest(selected.package)?,
        signed_asset,
    )?;
    write_download_atomically(&package_path, &package_bytes)?;
    write_download_atomically(
        &downloads.join(SIGNED_MANIFEST_NAME),
        &signed_manifest_bytes,
    )?;

    let staged = extract_and_validate(
        product,
        &state_directory,
        &package_path,
        &package_bytes,
        &selected.version,
        StagedMetadata {
            current_version: installation
                .version
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_else(|| "unknown".to_owned()),
            channel: selected.channel,
            release_url: selected.release.html_url.clone(),
            archive_sha256: package_hash,
            signature_key_id: signed_manifest.key_id,
        },
    )?;
    let staged_path = state_directory
        .join("staging")
        .join(&staged.version)
        .join("staged.json");
    write_json_atomically(&staged_path, &staged)?;
    Ok(staged)
}

pub async fn apply(
    product: UpdateProduct,
    repository: &str,
    requested_channel: UpdateChannel,
    state_directory: &Path,
    allow_downgrade: bool,
    confirmed: bool,
    signature_policy: SignaturePolicy,
) -> anyhow::Result<UpdateSchedule> {
    anyhow::ensure!(
        confirmed,
        "pass --yes to confirm the LinkLake executable replacement"
    );
    let staged = download(
        product,
        repository,
        requested_channel,
        state_directory,
        allow_downgrade,
        signature_policy,
    )
    .await?;
    schedule_update(product, state_directory, UpdateOperation::Apply, staged)
}

pub fn rollback(
    product: UpdateProduct,
    state_directory: &Path,
    confirmed: bool,
) -> anyhow::Result<UpdateSchedule> {
    anyhow::ensure!(confirmed, "pass --yes to confirm rollback");
    let state_directory = prepare_state_directory(state_directory)?;
    let target = current_installation(product)?.target;
    validate_target_executable(product, &target)?;
    let current_hash = sha256_file(&target)?;
    let (metadata, executable) = latest_rollback_backup(&state_directory, &target, &current_hash)?;
    let staged = StagedUpdate {
        schema_version: UPDATE_SCHEMA_VERSION,
        product,
        current_version: executable_version(&target)
            .map(|version| version.to_string())
            .unwrap_or_else(|| "unknown".to_owned()),
        version: metadata.version,
        channel: UpdateChannel::Auto,
        release_url: None,
        archive_name: "local-backup".to_owned(),
        archive_sha256: metadata.sha256.clone(),
        binary_sha256: metadata.sha256,
        staged_executable: executable,
        staged_manifest: PathBuf::new(),
        signature_key_id: "local-backup".to_owned(),
        downloaded_unix_seconds: metadata.created_unix_seconds,
    };
    schedule_update(product, &state_directory, UpdateOperation::Rollback, staged)
}

pub fn status(product: UpdateProduct, state_directory: &Path) -> anyhow::Result<UpdateStatus> {
    let path = absolute_path(state_directory)?.join("status.json");
    if !path.exists() {
        return Ok(UpdateStatus {
            schema_version: UPDATE_SCHEMA_VERSION,
            state: "idle".to_owned(),
            operation: None,
            from_version: current_installation(product)
                .ok()
                .and_then(|installation| installation.version)
                .map(|version| version.to_string())
                .or_else(|| Some("unknown".to_owned())),
            to_version: None,
            message: "no update operation has been scheduled".to_owned(),
            error: None,
            backup: None,
            updated_unix_seconds: unix_seconds(),
        });
    }
    read_json_limited(&path, MAX_MANIFEST_BYTES)
}

pub fn run_helper(plan_path: &Path, expected_plan_sha256: &str) -> anyhow::Result<()> {
    let plan_bytes = fs::read(plan_path)?;
    anyhow::ensure!(
        sha256_bytes(&plan_bytes) == normalize_sha256(expected_plan_sha256)?,
        "update helper plan digest mismatch"
    );
    let mut plan: HelperPlan = serde_json::from_slice(&plan_bytes)?;
    if let Err(error) = validate_helper_plan(plan_path, &mut plan) {
        write_helper_validation_failure(plan_path, &plan, &error);
        return Err(error);
    }
    sleep(Duration::from_millis(1_500));
    execute_helper(plan)
}

fn write_helper_validation_failure(plan_path: &Path, plan: &HelperPlan, error: &anyhow::Error) {
    let Ok(state) = fs::canonicalize(&plan.state_directory) else {
        return;
    };
    if ensure_within(plan_path, &state).is_err() {
        return;
    }
    let _ = write_status(
        &state,
        UpdateStatus {
            schema_version: UPDATE_SCHEMA_VERSION,
            state: "failed".to_owned(),
            operation: Some(operation_name(plan.operation).to_owned()),
            from_version: Some(plan.from_version.clone()),
            to_version: Some(plan.to_version.clone()),
            message: "the update plan or installation changed before replacement".to_owned(),
            error: Some(error.to_string()),
            backup: None,
            updated_unix_seconds: unix_seconds(),
        },
    );
}

async fn fetch_releases(repository: &str) -> anyhow::Result<Vec<GithubRelease>> {
    validate_repository(repository)?;
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .redirect(trusted_redirect_policy(&["api.github.com"]))
        .build()?
        .get(format!(
            "https://api.github.com/repos/{repository}/releases?per_page=30"
        ))
        .header(
            "User-Agent",
            format!("LinkLake-Client/{}", env!("CARGO_PKG_VERSION")),
        )
        .send()
        .await?
        .error_for_status()?;
    anyhow::ensure!(
        is_trusted_https_url(response.url(), &["api.github.com"]),
        "GitHub release metadata redirected to an untrusted URL"
    );
    let bytes = read_response_limited(response, 2 * 1024 * 1024).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn update_http_client() -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(UPDATE_TIMEOUT)
        .redirect(trusted_redirect_policy(&[
            "github.com",
            "objects.githubusercontent.com",
            "release-assets.githubusercontent.com",
        ]))
        .build()?)
}

fn trusted_redirect_policy(trusted_hosts: &'static [&'static str]) -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(move |attempt| {
        if attempt.previous().len() >= 5 {
            attempt.error("too many update redirects")
        } else if is_trusted_https_url(attempt.url(), trusted_hosts) {
            attempt.follow()
        } else {
            attempt.error("update redirect left the trusted HTTPS hosts")
        }
    })
}

fn is_trusted_https_url(url: &reqwest::Url, trusted_hosts: &[&str]) -> bool {
    url.scheme() == "https"
        && url.port_or_known_default() == Some(443)
        && url.username().is_empty()
        && url.password().is_none()
        && url
            .host_str()
            .is_some_and(|host| trusted_hosts.contains(&host))
}

async fn read_response_limited(
    mut response: reqwest::Response,
    maximum_bytes: u64,
) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(
        response
            .content_length()
            .is_none_or(|size| size <= maximum_bytes),
        "HTTP response exceeds the configured size limit"
    );
    let initial_capacity = response
        .content_length()
        .unwrap_or_default()
        .min(maximum_bytes)
        .min(1024 * 1024) as usize;
    let mut bytes = Vec::with_capacity(initial_capacity);
    while let Some(chunk) = response.chunk().await? {
        let new_size = bytes
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| anyhow::anyhow!("HTTP response size overflow"))?;
        anyhow::ensure!(
            new_size as u64 <= maximum_bytes,
            "HTTP response exceeds the configured size limit"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn validate_repository(repository: &str) -> anyhow::Result<()> {
    let mut parts = repository.split('/');
    let owner = parts.next().unwrap_or_default();
    let name = parts.next().unwrap_or_default();
    anyhow::ensure!(
        !owner.is_empty()
            && !name.is_empty()
            && parts.next().is_none()
            && owner
                .bytes()
                .all(|value| value.is_ascii_alphanumeric() || matches!(value, b'-' | b'_' | b'.'))
            && name
                .bytes()
                .all(|value| value.is_ascii_alphanumeric() || matches!(value, b'-' | b'_' | b'.')),
        "repository must use a safe owner/name value"
    );
    Ok(())
}

fn select_release<'a>(
    product: UpdateProduct,
    releases: &'a [GithubRelease],
    requested_channel: UpdateChannel,
    current: &Version,
) -> anyhow::Result<SelectedRelease<'a>> {
    let channel = requested_channel.resolve(current);
    let target = platform_target()?;
    releases
        .iter()
        .filter(|release| !release.draft)
        .filter_map(|release| {
            Version::parse(release.tag_name.trim_start_matches('v'))
                .ok()
                .map(|version| (release, version))
        })
        .filter(|(release, version)| {
            channel == UpdateChannel::Prerelease || (!release.prerelease && version.pre.is_empty())
        })
        .filter_map(|(release, version)| {
            let package_name = package_asset_name(product, &version, target);
            let checksum_name = format!("{package_name}.sha256");
            let package = release
                .assets
                .iter()
                .find(|asset| asset.name == package_name && asset.state == "uploaded")?;
            let checksum = release
                .assets
                .iter()
                .find(|asset| asset.name == checksum_name && asset.state == "uploaded")?;
            let signed_manifest = release
                .assets
                .iter()
                .find(|asset| asset.name == SIGNED_MANIFEST_NAME && asset.state == "uploaded")?;
            let signature = release
                .assets
                .iter()
                .find(|asset| asset.name == SIGNATURE_NAME && asset.state == "uploaded")?;
            Some(SelectedRelease {
                release,
                version,
                package,
                checksum,
                signed_manifest,
                signature,
                channel,
            })
        })
        .max_by(|left, right| left.version.cmp(&right.version))
        .ok_or_else(|| {
            anyhow::anyhow!("no compatible release exists for this platform and channel")
        })
}

fn ensure_network_update_allowed(
    current: &Version,
    selected: &Version,
    allow_downgrade: bool,
    signature_policy: SignaturePolicy,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        selected != current,
        "the selected release is already installed"
    );
    anyhow::ensure!(
        selected > current
            || (allow_downgrade && signature_policy == SignaturePolicy::Development),
        "signed network downgrades are disabled; use local rollback, or the explicit development policy"
    );
    Ok(())
}

fn matching_signed_asset<'a>(
    manifest: &'a SignedReleaseManifest,
    product: UpdateProduct,
    release_version: &Version,
    target: &str,
    expected_name: &str,
) -> anyhow::Result<&'a SignedAsset> {
    anyhow::ensure!(
        Version::parse(&manifest.release_version)? == *release_version,
        "signed manifest release version does not match the selected release"
    );
    let mut matches = manifest.assets.iter().filter(|asset| {
        asset.component == product.component()
            && asset.target == target
            && asset.name == expected_name
    });
    let asset = matches
        .next()
        .ok_or_else(|| anyhow::anyhow!("signed manifest has no matching component asset"))?;
    anyhow::ensure!(
        matches.next().is_none(),
        "signed manifest contains duplicate matching component assets"
    );
    Ok(asset)
}

async fn fetch_and_verify_signed_manifest(
    repository: &str,
    selected: &SelectedRelease<'_>,
    product: UpdateProduct,
    policy: SignaturePolicy,
) -> anyhow::Result<(Vec<u8>, SignedReleaseManifest)> {
    let client = update_http_client()?;
    let manifest_bytes = download_asset(
        &client,
        repository,
        selected.signed_manifest,
        MAX_MANIFEST_BYTES,
    )
    .await?;
    let signature_bytes =
        download_asset(&client, repository, selected.signature, MAX_CHECKSUM_BYTES).await?;
    let manifest = verify_signed_manifest_bytes(&manifest_bytes, &signature_bytes, policy)?;
    let target = platform_target()?;
    let expected_name = package_asset_name(product, &selected.version, target);
    matching_signed_asset(
        &manifest,
        product,
        &selected.version,
        target,
        &expected_name,
    )?;
    Ok((manifest_bytes, manifest))
}

pub fn verify_signed_manifest_bytes(
    manifest_bytes: &[u8],
    signature_bytes: &[u8],
    policy: SignaturePolicy,
) -> anyhow::Result<SignedReleaseManifest> {
    let trusted: TrustedKeys =
        serde_json::from_str(include_str!("../../../security/release-keys.json"))?;
    verify_signed_manifest_bytes_with_trust(
        manifest_bytes,
        signature_bytes,
        policy,
        &trusted,
        &Version::parse(env!("CARGO_PKG_VERSION"))?,
    )
}

fn verify_signed_manifest_bytes_with_trust(
    manifest_bytes: &[u8],
    signature_bytes: &[u8],
    policy: SignaturePolicy,
    trusted: &TrustedKeys,
    running_updater: &Version,
) -> anyhow::Result<SignedReleaseManifest> {
    anyhow::ensure!(
        manifest_bytes.len() as u64 <= MAX_MANIFEST_BYTES,
        "signed manifest exceeds the size limit"
    );
    anyhow::ensure!(
        signature_bytes.len() as u64 <= MAX_CHECKSUM_BYTES,
        "detached signature exceeds the size limit"
    );
    let manifest: SignedReleaseManifest = serde_json::from_slice(manifest_bytes)?;
    let detached: DetachedSignature = serde_json::from_slice(signature_bytes)?;
    anyhow::ensure!(
        manifest_bytes == canonical_signed_manifest_bytes(&manifest)?,
        "signed manifest is not encoded using the canonical LinkLake JSON bytes"
    );
    anyhow::ensure!(
        manifest.schema_version == 1,
        "unsupported signed manifest schema"
    );
    anyhow::ensure!(detached.schema_version == 1, "unsupported signature schema");
    anyhow::ensure!(
        detached.algorithm == "Ed25519",
        "unsupported signature algorithm"
    );
    anyhow::ensure!(
        detached.key_id == manifest.key_id,
        "signature key ID mismatch"
    );

    anyhow::ensure!(
        trusted.schema_version == 1,
        "unsupported trusted key schema"
    );
    let key = trusted
        .keys
        .iter()
        .find(|key| key.key_id == manifest.key_id)
        .ok_or_else(|| anyhow::anyhow!("signed manifest uses an unknown key"))?;
    anyhow::ensure!(
        key.purpose == "production"
            || (policy == SignaturePolicy::Development && key.purpose == "development"),
        "development signing keys are disabled by the production signature policy"
    );
    let public_key: [u8; 32] = BASE64
        .decode(&key.public_key_base64)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("trusted Ed25519 public key must be 32 bytes"))?;
    let signature_bytes: [u8; 64] = BASE64
        .decode(&detached.signature_base64)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Ed25519 signature must be 64 bytes"))?;
    VerifyingKey::from_bytes(&public_key)?
        .verify(manifest_bytes, &Signature::from_bytes(&signature_bytes))?;

    let release_version = Version::parse(&manifest.release_version)?;
    anyhow::ensure!(
        release_version >= Version::parse(&key.not_before_version)?,
        "signing key is not valid for this release version"
    );
    if let Some(not_after) = &key.not_after_version {
        anyhow::ensure!(
            release_version <= Version::parse(not_after)?,
            "signing key has expired for this release version"
        );
    }
    let minimum_updater = Version::parse(&manifest.minimum_updater_version)?;
    anyhow::ensure!(
        running_updater >= &minimum_updater,
        "this release requires updater version {minimum_updater} or newer"
    );
    anyhow::ensure!(
        !manifest.assets.is_empty(),
        "signed manifest contains no assets"
    );
    let mut identities = std::collections::HashSet::new();
    let mut previous_identity: Option<(&str, &str, &str)> = None;
    for asset in &manifest.assets {
        anyhow::ensure!(
            !asset.component.is_empty()
                && !asset.target.is_empty()
                && !asset.name.is_empty()
                && asset.size > 0,
            "signed manifest contains an incomplete asset"
        );
        normalize_sha256(&asset.sha256)?;
        let identity = (
            asset.component.as_str(),
            asset.target.as_str(),
            asset.name.as_str(),
        );
        anyhow::ensure!(
            previous_identity.is_none_or(|previous| previous < identity),
            "signed manifest assets must be strictly sorted by component, target, and name"
        );
        previous_identity = Some(identity);
        anyhow::ensure!(
            identities.insert((
                asset.component.clone(),
                asset.target.clone(),
                asset.name.clone()
            )),
            "signed manifest contains a duplicate asset identity"
        );
    }
    Ok(manifest)
}

async fn download_asset(
    client: &reqwest::Client,
    repository: &str,
    asset: &GithubAsset,
    maximum_bytes: u64,
) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(
        asset.size > 0 && asset.size <= maximum_bytes,
        "asset size is invalid"
    );
    let digest = required_github_digest(asset)?;
    let url = reqwest::Url::parse(&asset.browser_download_url)?;
    anyhow::ensure!(
        is_trusted_https_url(&url, &["github.com"]),
        "release asset URL must use the trusted GitHub HTTPS endpoint"
    );
    let expected_prefix = format!("/{repository}/releases/download/");
    anyhow::ensure!(
        url.path().starts_with(&expected_prefix),
        "release asset URL does not belong to the configured repository"
    );
    let response = client
        .get(url)
        .header(
            "User-Agent",
            format!("LinkLake-Client/{}", env!("CARGO_PKG_VERSION")),
        )
        .send()
        .await?
        .error_for_status()?;
    anyhow::ensure!(
        is_trusted_https_url(
            response.url(),
            &[
                "github.com",
                "objects.githubusercontent.com",
                "release-assets.githubusercontent.com",
            ],
        ),
        "release asset redirected to an untrusted URL"
    );
    let bytes = read_response_limited(response, maximum_bytes).await?;
    anyhow::ensure!(
        bytes.len() as u64 == asset.size,
        "release asset size changed during download"
    );
    anyhow::ensure!(
        sha256_bytes(&bytes) == digest,
        "GitHub asset digest mismatch"
    );
    Ok(bytes)
}

fn required_github_digest(asset: &GithubAsset) -> anyhow::Result<String> {
    let value = asset
        .digest
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("GitHub did not provide a digest for {}", asset.name))?;
    let digest = value
        .strip_prefix("sha256:")
        .ok_or_else(|| anyhow::anyhow!("GitHub asset digest is not SHA-256"))?;
    Ok(normalize_sha256(digest)?.to_ascii_lowercase())
}

fn parse_checksum(bytes: &[u8], expected_name: &str) -> anyhow::Result<String> {
    let value = std::str::from_utf8(bytes)?.trim();
    let mut parts = value.split_whitespace();
    let digest = parts.next().unwrap_or_default();
    let name = parts.next().unwrap_or_default().trim_start_matches('*');
    anyhow::ensure!(
        parts.next().is_none(),
        "checksum file must contain exactly one entry"
    );
    anyhow::ensure!(
        name == expected_name,
        "checksum file references an unexpected asset"
    );
    Ok(normalize_sha256(digest)?.to_ascii_lowercase())
}

fn verify_downloaded_package(
    package_bytes: &[u8],
    checksum_bytes: &[u8],
    package_name: &str,
    github_digest: &str,
    signed_asset: &SignedAsset,
) -> anyhow::Result<String> {
    let package_hash = sha256_bytes(package_bytes);
    anyhow::ensure!(
        package_hash == parse_checksum(checksum_bytes, package_name)?,
        "release checksum does not match the downloaded package"
    );
    anyhow::ensure!(
        package_hash == normalize_sha256(github_digest)?.to_ascii_lowercase(),
        "GitHub asset digest does not match the downloaded package"
    );
    anyhow::ensure!(
        signed_asset.sha256 == package_hash && signed_asset.size == package_bytes.len() as u64,
        "signed manifest does not match the downloaded package"
    );
    Ok(package_hash)
}

fn required_archive_entry(
    product: UpdateProduct,
    path: &Path,
) -> anyhow::Result<Option<&'static str>> {
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => parts.push(value.to_string_lossy().into_owned()),
            _ => anyhow::bail!("archive contains an unsafe path"),
        }
    }
    if parts
        .first()
        .is_some_and(|value| value.starts_with("linklake-"))
    {
        parts.remove(0);
    }
    let joined = parts.join("/");
    let binary = format!("bin/{}", product.executable_name());
    Ok(match joined.as_str() {
        value if value == binary => Some("binary"),
        "release.json" => Some("manifest"),
        _ => None,
    })
}

fn extract_and_validate(
    product: UpdateProduct,
    state_directory: &Path,
    package_path: &Path,
    package_bytes: &[u8],
    version: &Version,
    metadata: StagedMetadata,
) -> anyhow::Result<StagedUpdate> {
    let staging_root = state_directory.join("staging");
    fs::create_dir_all(&staging_root)?;
    secure_directory(&staging_root)?;
    for entry in fs::read_dir(&staging_root)? {
        let entry = entry?;
        if entry.file_type()?.is_dir()
            && entry
                .file_name()
                .to_string_lossy()
                .starts_with(&format!(".{version}.partial-"))
        {
            fs::remove_dir_all(entry.path())?;
        }
    }
    let final_directory = staging_root.join(version.to_string());
    let temporary_directory =
        staging_root.join(format!(".{}.partial-{}", version, Uuid::new_v4().simple()));
    fs::create_dir_all(&temporary_directory)?;
    secure_directory(&temporary_directory)?;
    let binary_name = product.executable_name();
    let binary_path = temporary_directory.join(binary_name);
    let manifest_path = temporary_directory.join("release.json");
    let validation = (|| -> anyhow::Result<String> {
        if package_path.extension() == Some(OsStr::new("zip")) {
            extract_zip_entries(product, package_bytes, &binary_path, &manifest_path)?;
        } else {
            extract_tar_entries(product, package_bytes, &binary_path, &manifest_path)?;
        }
        let manifest: ReleaseManifest = read_json_limited(&manifest_path, MAX_MANIFEST_BYTES)?;
        anyhow::ensure!(
            manifest.product == "LinkLake",
            "release manifest product is invalid"
        );
        anyhow::ensure!(
            manifest.version == version.to_string(),
            "release manifest version mismatch"
        );
        anyhow::ensure!(
            manifest.target == platform_target()?,
            "release manifest target mismatch"
        );
        anyhow::ensure!(
            manifest.built_unix_seconds > 0,
            "release manifest timestamp is invalid"
        );
        anyhow::ensure!(
            binary_path.is_file(),
            "release archive does not contain the selected LinkLake executable"
        );
        set_executable_permissions(&binary_path)?;
        verify_installed_version(&binary_path, &version.to_string())?;
        sha256_file(&binary_path)
    })();
    let binary_sha256 = match validation {
        Ok(value) => value,
        Err(error) => {
            let _ = fs::remove_dir_all(&temporary_directory);
            return Err(error);
        }
    };
    if final_directory.exists() {
        fs::remove_dir_all(&final_directory)?;
    }
    fs::rename(&temporary_directory, &final_directory)?;
    let staged = StagedUpdate {
        schema_version: UPDATE_SCHEMA_VERSION,
        product,
        current_version: metadata.current_version,
        version: version.to_string(),
        channel: metadata.channel,
        release_url: metadata.release_url,
        archive_name: package_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned(),
        archive_sha256: metadata.archive_sha256,
        binary_sha256,
        staged_executable: final_directory.join(binary_name),
        staged_manifest: final_directory.join("release.json"),
        signature_key_id: metadata.signature_key_id,
        downloaded_unix_seconds: unix_seconds(),
    };
    Ok(staged)
}

fn extract_zip_entries(
    product: UpdateProduct,
    package_bytes: &[u8],
    binary_path: &Path,
    manifest_path: &Path,
) -> anyhow::Result<()> {
    let mut archive = ZipArchive::new(Cursor::new(package_bytes))?;
    let mut binary_found = false;
    let mut manifest_found = false;
    for index in 0..archive.len() {
        let mut entry = archive.by_index(index)?;
        let Some(path) = entry.enclosed_name() else {
            anyhow::bail!("ZIP archive contains an unsafe path");
        };
        match required_archive_entry(product, &path)? {
            Some("binary") => {
                anyhow::ensure!(
                    !binary_found,
                    "ZIP archive contains duplicate component binaries"
                );
                copy_limited(&mut entry, binary_path, MAX_BINARY_BYTES)?;
                binary_found = true;
            }
            Some("manifest") => {
                anyhow::ensure!(!manifest_found, "ZIP archive contains duplicate manifests");
                copy_limited(&mut entry, manifest_path, MAX_MANIFEST_BYTES)?;
                manifest_found = true;
            }
            _ => {}
        }
    }
    anyhow::ensure!(
        binary_found && manifest_found,
        "ZIP archive is missing required entries"
    );
    Ok(())
}

fn extract_tar_entries(
    product: UpdateProduct,
    package_bytes: &[u8],
    binary_path: &Path,
    manifest_path: &Path,
) -> anyhow::Result<()> {
    let decoder = GzDecoder::new(Cursor::new(package_bytes));
    let mut archive = Archive::new(decoder);
    let mut binary_found = false;
    let mut manifest_found = false;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        match required_archive_entry(product, &path)? {
            Some("binary") => {
                anyhow::ensure!(
                    !binary_found,
                    "TAR archive contains duplicate component binaries"
                );
                copy_limited(&mut entry, binary_path, MAX_BINARY_BYTES)?;
                binary_found = true;
            }
            Some("manifest") => {
                anyhow::ensure!(!manifest_found, "TAR archive contains duplicate manifests");
                copy_limited(&mut entry, manifest_path, MAX_MANIFEST_BYTES)?;
                manifest_found = true;
            }
            _ => {}
        }
    }
    anyhow::ensure!(
        binary_found && manifest_found,
        "TAR archive is missing required entries"
    );
    Ok(())
}

fn copy_limited(reader: &mut impl Read, destination: &Path, maximum: u64) -> anyhow::Result<()> {
    let mut limited = reader.take(maximum + 1);
    let mut output = File::create(destination)?;
    let copied = std::io::copy(&mut limited, &mut output)?;
    anyhow::ensure!(
        copied <= maximum,
        "archive entry exceeds the configured size limit"
    );
    output.sync_all()?;
    Ok(())
}

fn schedule_update(
    product: UpdateProduct,
    state_directory: &Path,
    operation: UpdateOperation,
    staged: StagedUpdate,
) -> anyhow::Result<UpdateSchedule> {
    let state_directory = prepare_state_directory(state_directory)?;
    cleanup_old_helpers(&state_directory);
    anyhow::ensure!(staged.product == product, "staged update product mismatch");
    let installation = current_installation(product)?;
    let target = installation.target;
    validate_target_executable(product, &target)?;
    ensure_within(&staged.staged_executable, &state_directory)?;
    anyhow::ensure!(
        sha256_file(&staged.staged_executable)? == staged.binary_sha256,
        "staged component binary digest changed"
    );
    let service = service_runtime_for_target(product, &target)?;
    let plan = HelperPlan {
        schema_version: UPDATE_SCHEMA_VERSION,
        operation,
        product,
        state_directory: state_directory.clone(),
        target_executable: target.clone(),
        staged_executable: fs::canonicalize(&staged.staged_executable)?,
        expected_target_sha256: sha256_file(&target)?,
        staged_sha256: staged.binary_sha256,
        from_version: installation
            .version
            .map(|version| version.to_string())
            .unwrap_or_else(|| staged.current_version.clone()),
        to_version: staged.version,
        service_installed: service != ServiceRuntime::NotInstalled,
        service_was_running: service == ServiceRuntime::Running,
        created_unix_seconds: unix_seconds(),
    };
    let plans = state_directory.join("plans");
    let helpers = state_directory.join("helpers");
    fs::create_dir_all(&plans)?;
    fs::create_dir_all(&helpers)?;
    secure_directory(&plans)?;
    secure_directory(&helpers)?;
    let identifier = Uuid::new_v4().simple().to_string();
    let plan_path = plans.join(format!("{identifier}.json"));
    let plan_bytes = serde_json::to_vec_pretty(&plan)?;
    write_bytes_atomically(&plan_path, &plan_bytes)?;
    let plan_sha256 = sha256_bytes(&plan_bytes);
    let helper_name = if cfg!(windows) {
        format!("linklake-update-helper-{identifier}.exe")
    } else {
        format!("linklake-update-helper-{identifier}")
    };
    let helper_path = helpers.join(helper_name);
    let updater_executable = fs::canonicalize(std::env::current_exe()?)?;
    fs::copy(&updater_executable, &helper_path)?;
    set_executable_permissions(&helper_path)?;
    anyhow::ensure!(
        sha256_file(&helper_path)? == sha256_file(&updater_executable)?,
        "update helper copy is incomplete"
    );
    let operation_name = operation_name(operation).to_owned();
    write_status(
        &state_directory,
        UpdateStatus {
            schema_version: UPDATE_SCHEMA_VERSION,
            state: "scheduled".to_owned(),
            operation: Some(operation_name.clone()),
            from_version: Some(plan.from_version.clone()),
            to_version: Some(plan.to_version.clone()),
            message: "the detached update helper has been scheduled".to_owned(),
            error: None,
            backup: None,
            updated_unix_seconds: unix_seconds(),
        },
    )?;
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .open(state_directory.join("helper.log"))?;
    let error_log = log.try_clone()?;
    let mut command = Command::new(&helper_path);
    command
        .arg("__update-helper")
        .arg("--plan")
        .arg(&plan_path)
        .arg("--plan-sha256")
        .arg(&plan_sha256)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(error_log));
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000 | 0x0000_0008 | 0x0000_0200);
    }
    #[cfg(windows)]
    let inheritance_guard = disable_standard_handle_inheritance()?;
    let child_result = command.spawn();
    #[cfg(windows)]
    drop(inheritance_guard);
    let child = match child_result {
        Ok(child) => child,
        Err(error) => {
            write_status(
                &state_directory,
                UpdateStatus {
                    schema_version: UPDATE_SCHEMA_VERSION,
                    state: "failed".to_owned(),
                    operation: Some(operation_name.clone()),
                    from_version: Some(plan.from_version.clone()),
                    to_version: Some(plan.to_version.clone()),
                    message: "the detached update helper could not be started".to_owned(),
                    error: Some(error.to_string()),
                    backup: None,
                    updated_unix_seconds: unix_seconds(),
                },
            )?;
            return Err(error.into());
        }
    };
    Ok(UpdateSchedule {
        state: "scheduled".to_owned(),
        operation: operation_name,
        from_version: plan.from_version,
        to_version: plan.to_version,
        status_file: state_directory.join("status.json"),
        helper_process_id: child.id(),
    })
}

fn validate_helper_plan(plan_path: &Path, plan: &mut HelperPlan) -> anyhow::Result<()> {
    anyhow::ensure!(
        plan.schema_version == UPDATE_SCHEMA_VERSION,
        "unsupported update plan version"
    );
    let state = fs::canonicalize(&plan.state_directory)?;
    ensure_within(plan_path, &state)?;
    ensure_within(&plan.staged_executable, &state)?;
    plan.state_directory = state;
    plan.staged_executable = fs::canonicalize(&plan.staged_executable)?;
    plan.target_executable = fs::canonicalize(&plan.target_executable)?;
    validate_target_executable(plan.product, &plan.target_executable)?;
    anyhow::ensure!(
        sha256_file(&plan.staged_executable)? == plan.staged_sha256,
        "staged binary digest changed before installation"
    );
    anyhow::ensure!(
        sha256_file(&plan.target_executable)? == plan.expected_target_sha256,
        "installed binary changed after the update was scheduled"
    );
    Ok(())
}

fn execute_helper(plan: HelperPlan) -> anyhow::Result<()> {
    write_status(
        &plan.state_directory,
        UpdateStatus {
            schema_version: UPDATE_SCHEMA_VERSION,
            state: "installing".to_owned(),
            operation: Some(operation_name(plan.operation).to_owned()),
            from_version: Some(plan.from_version.clone()),
            to_version: Some(plan.to_version.clone()),
            message: "verifying and replacing the LinkLake component binary".to_owned(),
            error: None,
            backup: None,
            updated_unix_seconds: unix_seconds(),
        },
    )?;
    let result = execute_helper_inner(&plan);
    match result {
        Ok(backup) => {
            write_status(
                &plan.state_directory,
                UpdateStatus {
                    schema_version: UPDATE_SCHEMA_VERSION,
                    state: if plan.operation == UpdateOperation::Rollback {
                        "rolled_back".to_owned()
                    } else {
                        "succeeded".to_owned()
                    },
                    operation: Some(operation_name(plan.operation).to_owned()),
                    from_version: Some(plan.from_version),
                    to_version: Some(plan.to_version),
                    message: "component binary and service state were verified".to_owned(),
                    error: None,
                    backup: Some(backup),
                    updated_unix_seconds: unix_seconds(),
                },
            )?;
            Ok(())
        }
        Err((error, backup)) => {
            let error_message = error.to_string();
            let rollback = backup
                .as_ref()
                .map(|path| restore_after_failure(&plan, path))
                .transpose();
            let (state, message, final_error) = match rollback {
                Ok(Some(())) => (
                    "rolled_back",
                    "the update failed and the previous component was restored",
                    error_message,
                ),
                Ok(None) => (
                    "failed",
                    "the update failed before replacement",
                    error_message,
                ),
                Err(rollback_error) => (
                    "failed",
                    "the update and automatic rollback both failed",
                    format!("{error_message}; rollback: {rollback_error}"),
                ),
            };
            write_status(
                &plan.state_directory,
                UpdateStatus {
                    schema_version: UPDATE_SCHEMA_VERSION,
                    state: state.to_owned(),
                    operation: Some(operation_name(plan.operation).to_owned()),
                    from_version: Some(plan.from_version),
                    to_version: Some(plan.to_version),
                    message: message.to_owned(),
                    error: Some(final_error.clone()),
                    backup,
                    updated_unix_seconds: unix_seconds(),
                },
            )?;
            anyhow::bail!(final_error)
        }
    }
}

fn execute_helper_inner(plan: &HelperPlan) -> Result<PathBuf, (anyhow::Error, Option<PathBuf>)> {
    if let Err(error) = stop_service_for_update(plan) {
        return Err((error, None));
    }
    let backup = match create_backup(plan) {
        Ok(path) => path,
        Err(error) => {
            let _ = restart_service_after_update(plan);
            return Err((error, None));
        }
    };
    let result = (|| -> anyhow::Result<()> {
        atomic_replace_with_retry(&plan.target_executable, &plan.staged_executable)?;
        anyhow::ensure!(
            sha256_file(&plan.target_executable)? == plan.staged_sha256,
            "installed binary digest mismatch"
        );
        verify_installed_version(&plan.target_executable, &plan.to_version)?;
        #[cfg(debug_assertions)]
        anyhow::ensure!(
            std::env::var_os("LINKLAKE_UPDATE_TEST_FAIL_SERVICE_RECOVERY").is_none(),
            "test fixture simulated component service recovery failure"
        );
        restart_service_after_update(plan)?;
        Ok(())
    })();
    result
        .map(|()| backup.clone())
        .map_err(|error| (error, Some(backup)))
}

fn create_backup(plan: &HelperPlan) -> anyhow::Result<PathBuf> {
    let directory = plan.state_directory.join("backups").join(format!(
        "{}-{}-{}",
        safe_version_component(&plan.from_version),
        unix_seconds(),
        Uuid::new_v4().simple()
    ));
    fs::create_dir_all(&directory)?;
    secure_directory(&directory)?;
    let name = plan
        .target_executable
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("installed binary has no file name"))?;
    let executable = directory.join(name);
    fs::copy(&plan.target_executable, &executable)?;
    set_executable_permissions(&executable)?;
    let hash = sha256_file(&executable)?;
    anyhow::ensure!(
        hash == plan.expected_target_sha256,
        "backup digest mismatch"
    );
    write_json_atomically(
        &directory.join("metadata.json"),
        &BackupMetadata {
            schema_version: UPDATE_SCHEMA_VERSION,
            version: plan.from_version.clone(),
            sha256: hash,
            target_executable: plan.target_executable.clone(),
            created_unix_seconds: unix_seconds(),
        },
    )?;
    Ok(directory)
}

fn restore_after_failure(plan: &HelperPlan, backup_directory: &Path) -> anyhow::Result<()> {
    let name = plan
        .target_executable
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("installed binary has no file name"))?;
    let backup = backup_directory.join(name);
    anyhow::ensure!(backup.is_file(), "rollback backup is missing");
    let _ = stop_service_best_effort(plan.product, plan.service_installed);
    atomic_replace_with_retry(&plan.target_executable, &backup)?;
    anyhow::ensure!(
        sha256_file(&plan.target_executable)? == plan.expected_target_sha256,
        "restored binary digest mismatch"
    );
    verify_installed_version(&plan.target_executable, &plan.from_version)?;
    restart_service_after_update(plan)
}

fn latest_rollback_backup(
    state_directory: &Path,
    target: &Path,
    current_hash: &str,
) -> anyhow::Result<(BackupMetadata, PathBuf)> {
    let root = state_directory.join("backups");
    anyhow::ensure!(root.is_dir(), "no rollback backup exists");
    let mut candidates = Vec::new();
    for entry in fs::read_dir(&root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let metadata_path = entry.path().join("metadata.json");
        if !metadata_path.is_file() {
            continue;
        }
        let metadata: BackupMetadata = match read_json_limited(&metadata_path, MAX_MANIFEST_BYTES) {
            Ok(value) => value,
            Err(_) => continue,
        };
        if metadata.schema_version != UPDATE_SCHEMA_VERSION
            || metadata.target_executable != target
            || metadata.sha256 == current_hash
        {
            continue;
        }
        let executable = entry.path().join(
            target
                .file_name()
                .ok_or_else(|| anyhow::anyhow!("installed binary has no file name"))?,
        );
        if executable.is_file()
            && sha256_file(&executable).ok().as_deref() == Some(&metadata.sha256)
        {
            candidates.push((metadata, executable));
        }
    }
    candidates
        .into_iter()
        .max_by_key(|(metadata, _)| metadata.created_unix_seconds)
        .ok_or_else(|| anyhow::anyhow!("no valid rollback backup exists for this installation"))
}

fn atomic_replace_with_retry(target: &Path, source: &Path) -> anyhow::Result<()> {
    let parent = target
        .parent()
        .ok_or_else(|| anyhow::anyhow!("installed binary has no parent directory"))?;
    let identifier = Uuid::new_v4().simple().to_string();
    let incoming = parent.join(format!(".linklake-incoming-{identifier}"));
    let replaced = parent.join(format!(".linklake-replaced-{identifier}"));
    fs::copy(source, &incoming)?;
    set_executable_permissions(&incoming)?;
    let expected = sha256_file(source)?;
    anyhow::ensure!(
        sha256_file(&incoming)? == expected,
        "incoming binary copy is incomplete"
    );
    let deadline = std::time::Instant::now() + HELPER_RETRY_TIMEOUT;
    loop {
        let attempt = (|| -> anyhow::Result<()> {
            if replaced.exists() {
                fs::remove_file(&replaced)?;
            }
            fs::rename(target, &replaced)?;
            if let Err(error) = fs::rename(&incoming, target) {
                let _ = fs::rename(&replaced, target);
                return Err(error.into());
            }
            fs::remove_file(&replaced)?;
            Ok(())
        })();
        match attempt {
            Ok(()) => return Ok(()),
            Err(error) if std::time::Instant::now() < deadline => {
                sleep(Duration::from_millis(500));
                if !incoming.exists() {
                    fs::copy(source, &incoming)?;
                    set_executable_permissions(&incoming)?;
                }
                if !target.exists() && replaced.exists() {
                    let _ = fs::rename(&replaced, target);
                }
                let _ = error;
            }
            Err(error) => {
                let _ = fs::remove_file(&incoming);
                if !target.exists() && replaced.exists() {
                    let _ = fs::rename(&replaced, target);
                }
                return Err(error);
            }
        }
    }
}

fn verify_installed_version(executable: &Path, expected: &str) -> anyhow::Result<()> {
    if expected == "unknown" {
        return Ok(());
    }
    let output = Command::new(executable).arg("--version").output()?;
    anyhow::ensure!(
        output.status.success(),
        "component version verification failed; automatic installation targets must support --version"
    );
    let stdout = String::from_utf8(output.stdout)?;
    let actual = version_from_output(&stdout)
        .ok_or_else(|| anyhow::anyhow!("new component returned an invalid version"))?;
    anyhow::ensure!(
        actual == Version::parse(expected)?,
        "new client version {actual} does not match {expected}"
    );
    Ok(())
}

fn current_installation(product: UpdateProduct) -> anyhow::Result<CurrentInstallation> {
    let current = fs::canonicalize(std::env::current_exe()?)?;
    let standard = standard_installation(product);
    let target = if standard.is_file()
        && service_runtime_for_target(product, &fs::canonicalize(&standard)?)?
            != ServiceRuntime::NotInstalled
    {
        fs::canonicalize(standard)?
    } else {
        current
    };
    validate_target_executable(product, &target)?;
    Ok(CurrentInstallation {
        version: executable_version(&target),
        target,
    })
}

fn executable_version(executable: &Path) -> Option<Version> {
    let output = Command::new(executable).arg("--version").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8(output.stdout).ok()?;
    version_from_output(&stdout)
}

fn version_from_output(output: &str) -> Option<Version> {
    output.split_whitespace().find_map(|token| {
        let token = token
            .trim_matches(|character: char| {
                !character.is_ascii_alphanumeric()
                    && character != '.'
                    && character != '-'
                    && character != '+'
            })
            .trim_start_matches('v');
        Version::parse(token).ok()
    })
}

fn standard_installation(product: UpdateProduct) -> PathBuf {
    #[cfg(windows)]
    {
        std::env::var_os("ProgramFiles")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("C:\\Program Files"))
            .join("LinkLake")
            .join(product.executable_name())
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        PathBuf::from("/usr/local/bin").join(product.executable_name())
    }
}

fn service_runtime_for_target(
    product: UpdateProduct,
    target: &Path,
) -> anyhow::Result<ServiceRuntime> {
    #[cfg(windows)]
    {
        let configuration = Command::new("sc.exe")
            .args(["qc", product.service_name()])
            .output()?;
        if !configuration.status.success()
            || !command_output_references_target(&configuration.stdout, target)
        {
            return Ok(ServiceRuntime::NotInstalled);
        }
        let output = Command::new("sc.exe")
            .args(["query", product.service_name()])
            .output()?;
        let value = String::from_utf8_lossy(&output.stdout);
        Ok(if value.contains(": 4 ") {
            ServiceRuntime::Running
        } else {
            ServiceRuntime::Stopped
        })
    }
    #[cfg(target_os = "linux")]
    {
        let configuration = Command::new("systemctl")
            .args([
                "show",
                "--property=ExecStart",
                "--value",
                product.systemd_unit(),
            ])
            .output()?;
        if !configuration.status.success()
            || !command_output_references_target(&configuration.stdout, target)
        {
            return Ok(ServiceRuntime::NotInstalled);
        }
        Ok(
            if Command::new("systemctl")
                .args(["is-active", "--quiet", product.systemd_unit()])
                .status()?
                .success()
            {
                ServiceRuntime::Running
            } else {
                ServiceRuntime::Stopped
            },
        )
    }
    #[cfg(target_os = "macos")]
    {
        let plist_path = format!("/Library/LaunchDaemons/{}.plist", product.launchd_label());
        let plist = Path::new(&plist_path);
        if !plist.is_file() || !command_output_references_target(&fs::read(plist)?, target) {
            return Ok(ServiceRuntime::NotInstalled);
        }
        Ok(
            if Command::new("launchctl")
                .args(["print", &format!("system/{}", product.launchd_label())])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()?
                .success()
            {
                ServiceRuntime::Running
            } else {
                ServiceRuntime::Stopped
            },
        )
    }
}

fn command_output_references_target(output: &[u8], target: &Path) -> bool {
    let output = String::from_utf8_lossy(output);
    let target = target.to_string_lossy();
    if cfg!(windows) {
        output
            .to_ascii_lowercase()
            .contains(&target.to_ascii_lowercase())
    } else {
        output.contains(target.as_ref())
    }
}

fn stop_service_for_update(plan: &HelperPlan) -> anyhow::Result<()> {
    if !plan.service_installed || !plan.service_was_running {
        return Ok(());
    }
    anyhow::ensure!(
        service_runtime_for_target(plan.product, &plan.target_executable)?
            != ServiceRuntime::NotInstalled,
        "component service no longer references the scheduled target executable"
    );
    stop_service_best_effort(plan.product, true)?;
    let deadline = std::time::Instant::now() + SERVICE_WAIT_TIMEOUT;
    while service_runtime_for_target(plan.product, &plan.target_executable)?
        == ServiceRuntime::Running
    {
        anyhow::ensure!(
            std::time::Instant::now() < deadline,
            "component service did not stop"
        );
        sleep(Duration::from_millis(500));
    }
    Ok(())
}

fn stop_service_best_effort(product: UpdateProduct, installed: bool) -> anyhow::Result<()> {
    if !installed {
        return Ok(());
    }
    #[cfg(windows)]
    let _ = Command::new("sc.exe")
        .args(["stop", product.service_name()])
        .status()?;
    #[cfg(target_os = "linux")]
    let _ = Command::new("systemctl")
        .args(["stop", product.systemd_unit()])
        .status()?;
    #[cfg(target_os = "macos")]
    let _ = Command::new("launchctl")
        .args([
            "kill",
            "SIGTERM",
            &format!("system/{}", product.launchd_label()),
        ])
        .status()?;
    Ok(())
}

fn restart_service_after_update(plan: &HelperPlan) -> anyhow::Result<()> {
    if !plan.service_installed || !plan.service_was_running {
        return Ok(());
    }
    anyhow::ensure!(
        service_runtime_for_target(plan.product, &plan.target_executable)?
            != ServiceRuntime::NotInstalled,
        "component service no longer references the scheduled target executable"
    );
    #[cfg(windows)]
    let status = Command::new("sc.exe")
        .args(["start", plan.product.service_name()])
        .status()?;
    #[cfg(target_os = "linux")]
    let status = Command::new("systemctl")
        .args(["start", plan.product.systemd_unit()])
        .status()?;
    #[cfg(target_os = "macos")]
    let status = Command::new("launchctl")
        .args([
            "kickstart",
            "-k",
            &format!("system/{}", plan.product.launchd_label()),
        ])
        .status()?;
    anyhow::ensure!(status.success(), "component service could not be restarted");
    let deadline = std::time::Instant::now() + SERVICE_WAIT_TIMEOUT;
    let mut stable_polls = 0;
    loop {
        if service_runtime_for_target(plan.product, &plan.target_executable)?
            == ServiceRuntime::Running
        {
            stable_polls += 1;
            if stable_polls >= SERVICE_STABLE_POLLS {
                return Ok(());
            }
        } else {
            stable_polls = 0;
        }
        anyhow::ensure!(
            std::time::Instant::now() < deadline,
            "component service did not become active"
        );
        sleep(Duration::from_millis(500));
    }
}

fn prepare_state_directory(path: &Path) -> anyhow::Result<PathBuf> {
    let path = absolute_path(path)?;
    fs::create_dir_all(&path)?;
    secure_directory(&path)?;
    Ok(fs::canonicalize(path)?)
}

fn absolute_path(path: &Path) -> anyhow::Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_owned())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

fn ensure_within(path: &Path, root: &Path) -> anyhow::Result<()> {
    let path = fs::canonicalize(path)?;
    let root = fs::canonicalize(root)?;
    anyhow::ensure!(
        path.starts_with(&root),
        "update path escapes the state directory"
    );
    Ok(())
}

fn validate_target_executable(product: UpdateProduct, path: &Path) -> anyhow::Result<()> {
    anyhow::ensure!(
        path.is_absolute() && path.is_file(),
        "installed component path is invalid"
    );
    let expected = product.executable_name();
    anyhow::ensure!(
        path.file_name() == Some(OsStr::new(expected)),
        "the updater can only replace the selected LinkLake executable"
    );
    Ok(())
}

fn platform_target() -> anyhow::Result<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("windows", "x86_64") => Ok("windows-x86_64"),
        ("linux", "x86_64") => Ok("linux-x86_64"),
        ("macos", "aarch64") => Ok("macos-arm64"),
        (os, architecture) => {
            anyhow::bail!("automatic updates are not published for {os}/{architecture}")
        }
    }
}

fn package_asset_name(product: UpdateProduct, version: &Version, target: &str) -> String {
    let suffix = if target.starts_with("windows-") {
        "zip"
    } else {
        "tar.gz"
    };
    let prefix = if product == UpdateProduct::Manager {
        "linklake-manager"
    } else {
        "linklake"
    };
    format!("{prefix}-{version}-{target}.{suffix}")
}

fn write_download_atomically(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    write_bytes_atomically(path, bytes)
}

fn write_json_atomically(path: &Path, value: &impl Serialize) -> anyhow::Result<()> {
    write_bytes_atomically(path, &serde_json::to_vec_pretty(value)?)
}

fn write_bytes_atomically(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("update file has no parent directory"))?;
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(
        ".{}.tmp-{}",
        path.file_name().unwrap_or_default().to_string_lossy(),
        Uuid::new_v4().simple()
    ));
    let mut file = File::create(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    if path.exists() {
        fs::remove_file(path)?;
    }
    fs::rename(temporary, path)?;
    Ok(())
}

fn write_status(state_directory: &Path, value: UpdateStatus) -> anyhow::Result<()> {
    write_json_atomically(&state_directory.join("status.json"), &value)
}

fn read_json_limited<T: for<'de> Deserialize<'de>>(
    path: &Path,
    maximum_bytes: u64,
) -> anyhow::Result<T> {
    let metadata = fs::metadata(path)?;
    anyhow::ensure!(
        metadata.len() <= maximum_bytes,
        "JSON file exceeds the size limit"
    );
    let bytes = fs::read(path)?;
    let value = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(&bytes);
    Ok(serde_json::from_slice(value)?)
}

fn sha256_file(path: &Path) -> anyhow::Result<String> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn normalize_sha256(value: &str) -> anyhow::Result<&str> {
    anyhow::ensure!(
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "SHA-256 digest must contain 64 hexadecimal characters"
    );
    Ok(value)
}

fn safe_version_component(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '+') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn operation_name(operation: UpdateOperation) -> &'static str {
    match operation {
        UpdateOperation::Apply => "apply",
        UpdateOperation::Rollback => "rollback",
    }
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn cleanup_old_helpers(state_directory: &Path) {
    let directory = state_directory.join("helpers");
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        let Ok(modified) = metadata.modified() else {
            continue;
        };
        if SystemTime::now()
            .duration_since(modified)
            .unwrap_or_default()
            > Duration::from_secs(24 * 60 * 60)
        {
            let _ = fs::remove_file(entry.path());
        }
    }
}

#[cfg(unix)]
fn secure_directory(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(windows)]
fn secure_directory(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_executable_permissions(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
    Ok(())
}

#[cfg(windows)]
fn set_executable_permissions(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(windows)]
struct StandardHandleInheritanceGuard(Vec<(windows_sys::Win32::Foundation::HANDLE, u32)>);

#[cfg(windows)]
impl Drop for StandardHandleInheritanceGuard {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::{SetHandleInformation, HANDLE_FLAG_INHERIT};

        for (handle, flags) in &self.0 {
            unsafe {
                SetHandleInformation(*handle, HANDLE_FLAG_INHERIT, *flags & HANDLE_FLAG_INHERIT);
            }
        }
    }
}

#[cfg(windows)]
fn disable_standard_handle_inheritance() -> anyhow::Result<StandardHandleInheritanceGuard> {
    use windows_sys::Win32::Foundation::{
        GetHandleInformation, SetHandleInformation, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::System::Console::{
        GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };

    let mut changed = Vec::new();
    for standard in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        let handle = unsafe { GetStdHandle(standard) };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            continue;
        }
        let mut flags = 0_u32;
        if unsafe { GetHandleInformation(handle, &mut flags) } == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if flags & HANDLE_FLAG_INHERIT != 0 {
            anyhow::ensure!(
                unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) } != 0,
                "could not isolate detached updater standard handles"
            );
            changed.push((handle, flags));
        }
    }
    Ok(StandardHandleInheritanceGuard(changed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn signing_fixture(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn trusted_key_fixture(
        key_id: &str,
        signing_key: &SigningKey,
        purpose: &str,
        not_before: &str,
        not_after: Option<&str>,
    ) -> TrustedKey {
        TrustedKey {
            key_id: key_id.to_owned(),
            public_key_base64: BASE64.encode(signing_key.verifying_key().to_bytes()),
            purpose: purpose.to_owned(),
            not_before_version: not_before.to_owned(),
            not_after_version: not_after.map(str::to_owned),
        }
    }

    fn manifest_fixture(
        key_id: &str,
        release_version: &str,
        minimum_updater_version: &str,
    ) -> SignedReleaseManifest {
        let version = Version::parse(release_version).unwrap();
        SignedReleaseManifest {
            schema_version: 1,
            release_version: release_version.to_owned(),
            key_id: key_id.to_owned(),
            minimum_updater_version: minimum_updater_version.to_owned(),
            created_unix_seconds: 1,
            assets: vec![SignedAsset {
                component: "client".to_owned(),
                target: platform_target().unwrap().to_owned(),
                name: package_asset_name(
                    UpdateProduct::Client,
                    &version,
                    platform_target().unwrap(),
                ),
                sha256: "a".repeat(64),
                size: 1,
            }],
        }
    }

    fn sign_manifest_fixture(
        manifest: &SignedReleaseManifest,
        signing_key: &SigningKey,
    ) -> (Vec<u8>, Vec<u8>) {
        let bytes = canonical_signed_manifest_bytes(manifest).unwrap();
        let signature = signing_key.sign(&bytes);
        let detached = serde_json::to_vec_pretty(&DetachedSignature {
            schema_version: 1,
            key_id: manifest.key_id.clone(),
            algorithm: "Ed25519".to_owned(),
            signature_base64: BASE64.encode(signature.to_bytes()),
        })
        .unwrap();
        (bytes, detached)
    }

    fn github_asset(name: &str) -> GithubAsset {
        GithubAsset {
            name: name.to_owned(),
            browser_download_url: format!(
                "https://github.com/ASL-Vanity/LinkLake/releases/download/v1.0.0/{name}"
            ),
            size: 10,
            digest: Some(format!("sha256:{}", "a".repeat(64))),
            state: "uploaded".to_owned(),
        }
    }

    fn github_release(tag: &str, prerelease: bool, target: &str) -> GithubRelease {
        let version = Version::parse(tag.trim_start_matches('v')).unwrap();
        let package = package_asset_name(UpdateProduct::Client, &version, target);
        GithubRelease {
            tag_name: tag.to_owned(),
            html_url: None,
            draft: false,
            prerelease,
            assets: vec![
                github_asset(&package),
                github_asset(&format!("{package}.sha256")),
                github_asset(SIGNED_MANIFEST_NAME),
                github_asset(SIGNATURE_NAME),
            ],
        }
    }

    #[test]
    fn checksum_parser_requires_one_exact_asset() {
        let hash = "1".repeat(64);
        assert_eq!(
            parse_checksum(format!("{hash}  package.zip\n").as_bytes(), "package.zip").unwrap(),
            hash
        );
        assert!(parse_checksum(b"invalid package.zip", "package.zip").is_err());
        assert!(parse_checksum(
            format!("{}  other.zip\n", "1".repeat(64)).as_bytes(),
            "package.zip"
        )
        .is_err());
    }

    #[test]
    fn verified_archive_bytes_reject_post_download_tampering() {
        let package_name = "linklake-fixture.zip";
        let original = b"verified archive";
        let digest = sha256_bytes(original);
        let checksum = format!("{digest}  {package_name}\n");
        let signed_asset = SignedAsset {
            component: "client".to_owned(),
            target: platform_target().unwrap().to_owned(),
            name: package_name.to_owned(),
            sha256: digest.clone(),
            size: original.len() as u64,
        };
        assert!(verify_downloaded_package(
            original,
            checksum.as_bytes(),
            package_name,
            &digest,
            &signed_asset,
        )
        .is_ok());
        assert!(verify_downloaded_package(
            b"tampered archive",
            checksum.as_bytes(),
            package_name,
            &digest,
            &signed_asset,
        )
        .is_err());
    }

    #[test]
    fn release_selection_respects_channel_and_platform_assets() {
        let target = platform_target().unwrap();
        let releases = vec![
            github_release("v1.1.0-rc.1", true, target),
            github_release("v1.0.0", false, target),
        ];
        let current = Version::parse("0.9.0").unwrap();
        assert_eq!(
            select_release(
                UpdateProduct::Client,
                &releases,
                UpdateChannel::Stable,
                &current,
            )
            .unwrap()
            .version,
            Version::parse("1.0.0").unwrap()
        );
        assert_eq!(
            select_release(
                UpdateProduct::Client,
                &releases,
                UpdateChannel::Prerelease,
                &current,
            )
            .unwrap()
            .version,
            Version::parse("1.1.0-rc.1").unwrap()
        );
    }

    #[test]
    fn archive_paths_allow_only_required_normalized_entries() {
        assert_eq!(
            required_archive_entry(
                UpdateProduct::Client,
                Path::new("linklake-1.0.0/release.json"),
            )
            .unwrap(),
            Some("manifest")
        );
        assert!(
            required_archive_entry(UpdateProduct::Client, Path::new("../release.json")).is_err()
        );
        assert_eq!(
            required_archive_entry(UpdateProduct::Client, Path::new("linklake-1.0.0/README.md"),)
                .unwrap(),
            None
        );
    }

    #[test]
    fn limited_copy_rejects_decompression_overflow() {
        let root = std::env::temp_dir().join(format!("linklake-updater-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let destination = root.join("value");
        assert!(copy_limited(&mut Cursor::new(vec![1_u8; 17]), &destination, 16).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn helper_plan_hash_and_repository_validation_are_strict() {
        assert!(validate_repository("ASL-Vanity/LinkLake").is_ok());
        assert!(validate_repository("owner/repo/extra").is_err());
        assert!(validate_repository("owner/../../repo").is_err());
        assert!(normalize_sha256(&"a".repeat(64)).is_ok());
        assert!(normalize_sha256(&"z".repeat(64)).is_err());
    }

    #[test]
    fn production_network_downgrades_are_never_enabled() {
        let current = Version::parse("1.0.0").unwrap();
        let older = Version::parse("0.9.0").unwrap();
        assert!(
            ensure_network_update_allowed(&current, &older, true, SignaturePolicy::Production,)
                .is_err()
        );
        assert!(ensure_network_update_allowed(
            &current,
            &older,
            false,
            SignaturePolicy::Development,
        )
        .is_err());
        assert!(ensure_network_update_allowed(
            &current,
            &older,
            true,
            SignaturePolicy::Development,
        )
        .is_ok());
    }

    #[test]
    fn update_urls_require_trusted_https_hosts_and_standard_ports() {
        let github = reqwest::Url::parse(
            "https://github.com/ASL-Vanity/LinkLake/releases/download/v1.0.0/client.zip",
        )
        .unwrap();
        let redirected = reqwest::Url::parse(
            "https://release-assets.githubusercontent.com/github-production-release-asset",
        )
        .unwrap();
        assert!(is_trusted_https_url(&github, &["github.com"]));
        assert!(is_trusted_https_url(
            &redirected,
            &["release-assets.githubusercontent.com"]
        ));
        assert!(!is_trusted_https_url(
            &reqwest::Url::parse("http://github.com/release.zip").unwrap(),
            &["github.com"]
        ));
        assert!(!is_trusted_https_url(
            &reqwest::Url::parse("https://github.com:8443/release.zip").unwrap(),
            &["github.com"]
        ));
        assert!(!is_trusted_https_url(
            &reqwest::Url::parse("https://example.com/release.zip").unwrap(),
            &["github.com"]
        ));
    }

    #[test]
    fn atomic_replace_uses_the_verified_source_bytes() {
        let root = std::env::temp_dir().join(format!("linklake-replace-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let target = root.join(if cfg!(windows) {
            "linklake-client.exe"
        } else {
            "linklake-client"
        });
        let source = root.join("source-client");
        fs::write(&target, b"old-client").unwrap();
        fs::write(&source, b"new-client").unwrap();
        atomic_replace_with_retry(&target, &source).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"new-client");
        assert_eq!(fs::read(&source).unwrap(), b"new-client");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn release_json_accepts_legacy_utf8_bom_only_at_the_start() {
        let root = std::env::temp_dir().join(format!("linklake-json-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("release.json");
        fs::write(
            &path,
            b"\xEF\xBB\xBF{\"product\":\"LinkLake\",\"version\":\"1.0.0\",\"target\":\"windows-x86_64\",\"built_unix_seconds\":1}",
        )
        .unwrap();
        let manifest: ReleaseManifest = read_json_limited(&path, MAX_MANIFEST_BYTES).unwrap();
        assert_eq!(manifest.version, "1.0.0");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn ed25519_manifest_is_fail_closed_and_development_is_explicit() {
        let manifest = SignedReleaseManifest {
            schema_version: 1,
            release_version: "0.8.0-rc.1".to_owned(),
            key_id: "linklake-development-rfc8032-1".to_owned(),
            minimum_updater_version: "0.8.0-rc.1".to_owned(),
            created_unix_seconds: 1,
            assets: vec![SignedAsset {
                component: "client".to_owned(),
                target: platform_target().unwrap().to_owned(),
                name: package_asset_name(
                    UpdateProduct::Client,
                    &Version::parse("0.8.0-rc.1").unwrap(),
                    platform_target().unwrap(),
                ),
                sha256: "a".repeat(64),
                size: 1,
            }],
        };
        let bytes = canonical_signed_manifest_bytes(&manifest).unwrap();
        let seed: [u8; 32] = BASE64
            .decode("nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=")
            .unwrap()
            .try_into()
            .unwrap();
        let signature = SigningKey::from_bytes(&seed).sign(&bytes);
        let detached = serde_json::to_vec_pretty(&DetachedSignature {
            schema_version: 1,
            key_id: manifest.key_id.clone(),
            algorithm: "Ed25519".to_owned(),
            signature_base64: BASE64.encode(signature.to_bytes()),
        })
        .unwrap();
        assert!(
            verify_signed_manifest_bytes(&bytes, &detached, SignaturePolicy::Development).is_ok()
        );
        assert!(
            verify_signed_manifest_bytes(&bytes, &detached, SignaturePolicy::Production).is_err()
        );
        let mut tampered = bytes;
        tampered.push(b' ');
        assert!(
            verify_signed_manifest_bytes(&tampered, &detached, SignaturePolicy::Development)
                .is_err()
        );
    }

    #[test]
    fn signed_manifest_rejects_unknown_key_and_wrong_signature() {
        let trusted_signer = signing_fixture(7);
        let wrong_signer = signing_fixture(8);
        let trusted = TrustedKeys {
            schema_version: 1,
            keys: vec![trusted_key_fixture(
                "production-a",
                &trusted_signer,
                "production",
                "0.8.0-rc.1",
                None,
            )],
        };
        let unknown = manifest_fixture("unknown", "0.8.0", "0.8.0-rc.1");
        let (bytes, detached) = sign_manifest_fixture(&unknown, &wrong_signer);
        assert!(verify_signed_manifest_bytes_with_trust(
            &bytes,
            &detached,
            SignaturePolicy::Production,
            &trusted,
            &Version::parse("0.8.0-rc.1").unwrap(),
        )
        .is_err());

        let known = manifest_fixture("production-a", "0.8.0", "0.8.0-rc.1");
        let (bytes, detached) = sign_manifest_fixture(&known, &wrong_signer);
        assert!(verify_signed_manifest_bytes_with_trust(
            &bytes,
            &detached,
            SignaturePolicy::Production,
            &trusted,
            &Version::parse("0.8.0-rc.1").unwrap(),
        )
        .is_err());
    }

    #[test]
    fn signing_key_ranges_minimum_updater_and_rotation_are_enforced() {
        let old_signer = signing_fixture(9);
        let new_signer = signing_fixture(10);
        let trusted = TrustedKeys {
            schema_version: 1,
            keys: vec![
                trusted_key_fixture(
                    "production-old",
                    &old_signer,
                    "production",
                    "0.8.0-rc.1",
                    Some("0.8.0"),
                ),
                trusted_key_fixture("production-new", &new_signer, "production", "0.8.0", None),
            ],
        };
        let running = Version::parse("0.8.0").unwrap();
        for (key_id, release, signer) in [
            ("production-old", "0.8.0-rc.1", &old_signer),
            ("production-new", "0.8.0", &new_signer),
        ] {
            let manifest = manifest_fixture(key_id, release, "0.8.0-rc.1");
            let (bytes, detached) = sign_manifest_fixture(&manifest, signer);
            verify_signed_manifest_bytes_with_trust(
                &bytes,
                &detached,
                SignaturePolicy::Production,
                &trusted,
                &running,
            )
            .unwrap();
        }

        let expired = manifest_fixture("production-old", "0.8.1", "0.8.0-rc.1");
        let (bytes, detached) = sign_manifest_fixture(&expired, &old_signer);
        assert!(verify_signed_manifest_bytes_with_trust(
            &bytes,
            &detached,
            SignaturePolicy::Production,
            &trusted,
            &running,
        )
        .is_err());

        let too_early = manifest_fixture("production-new", "0.8.0-rc.1", "0.8.0-rc.1");
        let (bytes, detached) = sign_manifest_fixture(&too_early, &new_signer);
        assert!(verify_signed_manifest_bytes_with_trust(
            &bytes,
            &detached,
            SignaturePolicy::Production,
            &trusted,
            &running,
        )
        .is_err());

        let minimum = manifest_fixture("production-new", "0.8.1", "0.9.0");
        let (bytes, detached) = sign_manifest_fixture(&minimum, &new_signer);
        assert!(verify_signed_manifest_bytes_with_trust(
            &bytes,
            &detached,
            SignaturePolicy::Production,
            &trusted,
            &running,
        )
        .is_err());
    }

    #[test]
    fn signed_asset_binding_rejects_wrong_platform_and_release_version() {
        let version = Version::parse("0.8.0").unwrap();
        let manifest = manifest_fixture("fixture", "0.8.0", "0.8.0-rc.1");
        let name = package_asset_name(UpdateProduct::Client, &version, platform_target().unwrap());
        assert!(matching_signed_asset(
            &manifest,
            UpdateProduct::Client,
            &version,
            "wrong-platform",
            &name,
        )
        .is_err());
        assert!(matching_signed_asset(
            &manifest,
            UpdateProduct::Client,
            &Version::parse("0.8.1").unwrap(),
            platform_target().unwrap(),
            &name,
        )
        .is_err());
    }
}
