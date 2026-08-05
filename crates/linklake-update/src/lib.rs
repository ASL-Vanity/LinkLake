//! LinkLake 客户端的可信下载、原子升级和回滚实现。

use anyhow::Context;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use clap::ValueEnum;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use flate2::read::GzDecoder;
use hmac::{Hmac, Mac};
use semver::Version;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::ffi::CString;
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

mod durable;
mod manager;
mod server_database;
use durable::{
    read_limited_bytes, read_limited_json as read_durable_json, remove_durable_file,
    write_durable_bytes, write_durable_json, write_journal_json, UpdateLock,
};
pub use manager::{
    manager_apply, manager_download, manager_rollback, manager_status, run_manager_helper,
    ManagerSchedule, ManagerStagedUpdate, ManagerStatus,
};
use server_database::{
    authorize_manual_database_rollback, backup_server_database, inspect_server_database,
    preflight_server_database, prepare_server_update_context, read_snapshot_metadata,
    restore_server_database, validate_snapshot_metadata, write_snapshot_metadata,
};
pub use server_database::{
    ManualDatabaseRollbackConsent, ManualDatabaseRollbackDecision, ServerDatabaseInspectReport,
    ServerDatabasePreflightReport, ServerDatabaseSnapshotMetadata, ServerUpdateContext,
};

pub const UPDATE_SCHEMA_VERSION: u32 = 3;
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
const SERVER_READY_TIMEOUT: Duration = Duration::from_secs(60);
const SERVER_READY_POLL_INTERVAL: Duration = Duration::from_millis(500);
const SERVER_READY_STABLE_POLLS: usize = 6;
const MAX_UPDATE_STATE_BYTES: u64 = 128 * 1024;
const UPDATE_JOURNAL_SCHEMA_VERSION: u32 = 1;
const SERVER_STATE_AUTH_SCHEMA_VERSION: u32 = 1;
const SERVER_STATE_AUTH_KEY_NAME: &str = ".linklake-server-update-auth.key";
const SERVER_STATE_AUTH_PREFIX: &[u8] = b"linklake-server-update-state/v1\0";
const SERVER_READY_REQUEST_NAME: &str = ".linklake-server-update-ready-request.json";
const SERVER_READY_RECEIPT_NAME: &str = ".linklake-server-update-ready-receipt.json";
const SERVER_READY_PROTOCOL_VERSION: u32 = 1;
#[cfg(target_os = "linux")]
const OFFICIAL_LINKLAKE_SERVER_SYSTEMD_UNIT_PATHS: &[&str] = &[
    "/etc/systemd/system/linklake-server.service",
    "/usr/lib/systemd/system/linklake-server.service",
    "/lib/systemd/system/linklake-server.service",
];
#[cfg(target_os = "linux")]
const OFFICIAL_LINKLAKE_SERVER_ENVIRONMENT_PATH: &str = "/etc/linklake/server.env";
#[cfg(unix)]
const MAX_SERVER_SERVICE_CONTRACT_BYTES: u64 = 64 * 1024;
type HmacSha256 = Hmac<Sha256>;

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

/// 候选服务在真正完成启动后写入的受认证就绪请求。请求和回执均位于服务端数据
/// 目录，并使用同一更新认证密钥做 HMAC；不能写入数据目录认证密钥的用户无法伪造
/// 一个可把候选服务标记为成功的回执。
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerReadinessRequest {
    protocol_version: u32,
    operation_id: Uuid,
    expected_executable_sha256: String,
    expected_version: String,
    nonce: String,
    created_unix_seconds: u64,
}

/// 服务端只会在数据库、配置和静态监听器均已就绪后写入该回执。更新 helper 还会
/// 持续确认服务管理器保持 Running，避免把崩溃后残留的旧回执误判为候选成功。
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerReadinessReceipt {
    protocol_version: u32,
    operation_id: Uuid,
    nonce: String,
    executable_sha256: String,
    version: String,
    ready_unix_seconds: u64,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum UpdateOperation {
    Apply,
    Rollback,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HelperPlan {
    schema_version: u32,
    operation_id: Uuid,
    operation_directory: PathBuf,
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
    server_database: Option<ServerDatabaseTransaction>,
    created_unix_seconds: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupMetadata {
    schema_version: u32,
    #[serde(default)]
    operation_id: Option<Uuid>,
    version: String,
    sha256: String,
    target_executable: PathBuf,
    #[serde(default)]
    database_snapshot_metadata: Option<PathBuf>,
    created_unix_seconds: u64,
}

/// 服务端更新额外携带的数据库事务上下文。客户端和管理器永远不接受该字段。
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum ServerDatabaseTransaction {
    Apply { context: ServerUpdateContext },
    Rollback { context: ServerRollbackContext },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerRollbackContext {
    canonical_data_dir: PathBuf,
    snapshot_metadata_path: PathBuf,
    snapshot_operation_id: Uuid,
    snapshot_plan_sha256: String,
    expected_schema: u32,
    expected_ledger_sha256: String,
    restore_snapshot: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActiveUpdate {
    schema_version: u32,
    operation_id: Uuid,
    product: UpdateProduct,
    plan_path: PathBuf,
    plan_sha256: String,
    created_unix_seconds: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateJournal {
    schema_version: u32,
    operation_id: Uuid,
    plan_sha256: String,
    product: UpdateProduct,
    operation: UpdateOperation,
    stage: String,
    backup_directory: Option<PathBuf>,
    error: Option<String>,
    updated_unix_seconds: u64,
}

/// 服务端更新状态不能只依赖同一可写目录内的 SHA-256。此记录把状态文件的
/// 原始字节与服务端数据目录中单独保存的随机密钥做 HMAC 绑定；因此，能够写入
/// state-dir 的低权限用户无法伪造可被 `update recover` 接受的事务。
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerStateAuthentication {
    schema_version: u32,
    purpose: String,
    payload_sha256: String,
    hmac_sha256: String,
}

#[derive(Clone)]
struct ServerStateAuthenticator {
    key: [u8; 32],
    canonical_data_directory: PathBuf,
}

/// Unix 上服务端更新认证根必须绑定到可信的运行身份，不能仅凭目录与密钥
/// “彼此同属一个用户”就建立信任。否则提权 helper 会接受攻击者自建目录中的已知密钥。
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct UnixServerStateIdentity {
    uid: libc::uid_t,
    gid: libc::gid_t,
}

/// 在 detached helper 真正启动前，任何本地准备失败都不应遗留一个看似可恢复的
/// active marker。成功调度后显式解除该守卫，后续由 helper/recover 接管 marker。
struct ActiveMarkerGuard {
    state_directory: PathBuf,
    operation_id: Uuid,
    server_authenticator: Option<ServerStateAuthenticator>,
    armed: bool,
}

impl ActiveMarkerGuard {
    fn new(
        state_directory: PathBuf,
        operation_id: Uuid,
        server_authenticator: Option<ServerStateAuthenticator>,
    ) -> Self {
        Self {
            state_directory,
            operation_id,
            server_authenticator,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ActiveMarkerGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = clear_active_marker(
                &self.state_directory,
                self.operation_id,
                self.server_authenticator.as_ref(),
            );
        }
    }
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

/// 候选服务已进入交接窗口后，恢复旧数据库可能会丢弃候选服务已经接受的写入。
/// 因此除了 `--yes`，调用方还必须同时明确请求恢复并确认该数据风险。
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServerRecoveryConsent {
    pub restore_after_candidate_handoff: bool,
    pub confirm_data_loss: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct UpdateSchedule {
    pub state: String,
    pub operation_id: Uuid,
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
    Transitioning,
    Unknown,
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
        if product == UpdateProduct::Server {
            return std::env::var_os("ProgramData")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
                .join("LinkLake")
                .join("updates")
                .join("server");
        }
        std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join("LinkLake")
            .join("updates")
            .join(product.component())
    }
    #[cfg(target_os = "macos")]
    {
        if product == UpdateProduct::Server {
            return PathBuf::from("/Library/Application Support/LinkLake/updates/server");
        }
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
        if product == UpdateProduct::Server {
            return PathBuf::from("/var/lib/linklake-updater/server");
        }
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
        product != UpdateProduct::Server,
        "server updates require the server-specific update command with an explicit data directory"
    );
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
    schedule_update(
        product,
        state_directory,
        UpdateOperation::Apply,
        staged,
        None,
    )
}

/// 下载并调度服务端更新。服务端必须显式传入数据目录，确保二进制替换永远与
/// SQLite 快照、候选迁移预演和失败回滚处于同一事务链中。
pub async fn server_apply(
    repository: &str,
    requested_channel: UpdateChannel,
    state_directory: &Path,
    data_directory: &Path,
    allow_downgrade: bool,
    confirmed: bool,
    signature_policy: SignaturePolicy,
) -> anyhow::Result<UpdateSchedule> {
    anyhow::ensure!(
        confirmed,
        "pass --yes to confirm the LinkLake server replacement"
    );
    let staged = download(
        UpdateProduct::Server,
        repository,
        requested_channel,
        state_directory,
        allow_downgrade,
        signature_policy,
    )
    .await?;
    schedule_server_apply(state_directory, data_directory, staged)
}

pub fn rollback(
    product: UpdateProduct,
    state_directory: &Path,
    confirmed: bool,
) -> anyhow::Result<UpdateSchedule> {
    anyhow::ensure!(
        product != UpdateProduct::Server,
        "server rollback requires the server-specific rollback command with an explicit data directory"
    );
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
    schedule_update(
        product,
        &state_directory,
        UpdateOperation::Rollback,
        staged,
        None,
    )
}

/// 调度带数据库兼容性约束的服务端人工回滚。跨 schema/账本回滚默认拒绝，只有
/// 同时显式请求快照恢复和确认数据丢失时才允许继续。
pub fn server_rollback(
    state_directory: &Path,
    data_directory: &Path,
    confirmed: bool,
    consent: ManualDatabaseRollbackConsent,
) -> anyhow::Result<UpdateSchedule> {
    anyhow::ensure!(confirmed, "pass --yes to confirm server rollback");
    let state_directory = prepare_state_directory(state_directory)?;
    let target = current_installation(UpdateProduct::Server)?.target;
    validate_target_executable(UpdateProduct::Server, &target)?;
    let current = inspect_server_database(&target, data_directory)?;
    let authenticator = load_server_state_authenticator(&current.canonical_data_dir, false)?;
    let current_hash = sha256_file(&target)?;
    let (selected_metadata, executable) =
        latest_rollback_backup(&state_directory, &target, &current_hash)?;
    let metadata_path = executable
        .parent()
        .ok_or_else(|| anyhow::anyhow!("server rollback backup has no parent directory"))?
        .join("metadata.json");
    let metadata: BackupMetadata =
        read_server_authenticated_json(&authenticator, &metadata_path, "backup-metadata")?;
    anyhow::ensure!(
        metadata.operation_id == selected_metadata.operation_id
            && metadata.sha256 == selected_metadata.sha256
            && metadata.target_executable == selected_metadata.target_executable,
        "server rollback backup metadata authentication does not match the selected backup"
    );
    let snapshot_metadata_path = metadata.database_snapshot_metadata.ok_or_else(|| {
        anyhow::anyhow!(
            "legacy or binary-only rollback backup has no database snapshot; server rollback is disabled"
        )
    })?;
    let _: ServerDatabaseSnapshotMetadata = read_server_authenticated_json(
        &authenticator,
        &snapshot_metadata_path,
        "database-snapshot",
    )?;
    let snapshot = read_snapshot_metadata(&snapshot_metadata_path)?;
    let staged_executable = canonicalize_update_path(&executable)?;
    anyhow::ensure!(
        snapshot.rollback_binary_path == staged_executable
            && snapshot.rollback_binary_sha256 == metadata.sha256,
        "server rollback backup does not match its database snapshot metadata"
    );
    anyhow::ensure!(
        metadata.operation_id == Some(snapshot.operation_id),
        "server rollback backup metadata is not bound to its database snapshot operation"
    );
    let decision = authorize_manual_database_rollback(
        current.observed_schema,
        &current.ledger_sha256,
        Some(&snapshot),
        consent,
    )?;
    let transaction = ServerDatabaseTransaction::Rollback {
        context: ServerRollbackContext {
            canonical_data_dir: current.canonical_data_dir,
            snapshot_metadata_path,
            snapshot_operation_id: snapshot.operation_id,
            snapshot_plan_sha256: snapshot.plan_sha256,
            expected_schema: current.observed_schema,
            expected_ledger_sha256: current.ledger_sha256,
            restore_snapshot: decision == ManualDatabaseRollbackDecision::RestoreSnapshot,
        },
    };
    let staged = StagedUpdate {
        schema_version: UPDATE_SCHEMA_VERSION,
        product: UpdateProduct::Server,
        current_version: executable_version(&target)
            .map(|version| version.to_string())
            .unwrap_or_else(|| "unknown".to_owned()),
        version: metadata.version,
        channel: UpdateChannel::Auto,
        release_url: None,
        archive_name: "local-backup".to_owned(),
        archive_sha256: metadata.sha256.clone(),
        binary_sha256: metadata.sha256,
        staged_executable,
        staged_manifest: PathBuf::new(),
        signature_key_id: "local-backup".to_owned(),
        downloaded_unix_seconds: metadata.created_unix_seconds,
    };
    schedule_update(
        UpdateProduct::Server,
        &state_directory,
        UpdateOperation::Rollback,
        staged,
        Some(transaction),
    )
}

/// 恢复因断电、崩溃或被终止而遗留的服务端更新事务。只有带有经过认证的
/// active marker、plan 和 journal 的事务才会被处理；任何缺失或不一致都会
/// 失败关闭并保留 marker，避免在未知状态下覆盖数据库。
pub fn server_recover(
    state_directory: &Path,
    data_directory: &Path,
    confirmed: bool,
    consent: ServerRecoveryConsent,
) -> anyhow::Result<UpdateStatus> {
    anyhow::ensure!(confirmed, "pass --yes to confirm server update recovery");
    let authenticator = load_server_state_authenticator(data_directory, false)?;
    let state_directory = prepare_state_directory(state_directory)?;
    let _update_lock = UpdateLock::acquire(&state_directory)?;
    let active_path = state_directory.join("active.json");
    if !active_path.exists() {
        return status(UpdateProduct::Server, &state_directory);
    }
    let active: ActiveUpdate =
        read_server_authenticated_json(&authenticator, &active_path, "active-marker")?;
    anyhow::ensure!(
        active.schema_version == UPDATE_SCHEMA_VERSION && active.product == UpdateProduct::Server,
        "active update marker is not a supported server update"
    );
    ensure_within(&active.plan_path, &state_directory)?;
    let plan_bytes = read_limited_bytes(&active.plan_path, MAX_UPDATE_STATE_BYTES)?;
    anyhow::ensure!(
        sha256_bytes(&plan_bytes) == normalize_sha256(&active.plan_sha256)?,
        "active server update plan digest mismatch"
    );
    let plan: HelperPlan =
        read_server_authenticated_json(&authenticator, &active.plan_path, "helper-plan")?;
    anyhow::ensure!(
        plan.schema_version == UPDATE_SCHEMA_VERSION
            && plan.operation_id == active.operation_id
            && plan.product == UpdateProduct::Server
            && canonicalize_update_path(&plan.state_directory)? == state_directory
            && canonicalize_update_path(&plan.operation_directory)?
                == active
                    .plan_path
                    .parent()
                    .ok_or_else(|| anyhow::anyhow!("active plan has no operation directory"))?,
        "active server update plan is not bound to its marker"
    );
    let transaction = plan.server_database.as_ref().ok_or_else(|| {
        anyhow::anyhow!("active server update has no database transaction context")
    })?;
    let expected_data = match transaction {
        ServerDatabaseTransaction::Apply { context } => &context.canonical_data_dir,
        ServerDatabaseTransaction::Rollback { context } => &context.canonical_data_dir,
    };
    anyhow::ensure!(
        authenticator.canonical_data_directory == *expected_data,
        "recovery data directory does not match the active server update"
    );
    let expected_target = match current_installation(UpdateProduct::Server) {
        Ok(installation) => installation.target,
        // `cargo test` 的测试宿主不是 linklake-server，无法使用生产安装发现逻辑。
        // 该回退只会编译进单元测试，不会削弱发布二进制的恢复路径绑定。
        Err(_) if cfg!(test) => plan.target_executable.clone(),
        Err(error) => return Err(error),
    };
    anyhow::ensure!(
        plan.target_executable == expected_target,
        "recovery plan target does not match the currently installed server executable"
    );
    let journal: UpdateJournal = read_server_authenticated_json(
        &authenticator,
        &plan.operation_directory.join("journal.json"),
        "operation-journal",
    )?;
    anyhow::ensure!(
        journal.schema_version == UPDATE_JOURNAL_SCHEMA_VERSION
            && journal.operation_id == plan.operation_id
            && journal.product == UpdateProduct::Server
            && journal.operation == plan.operation
            && journal.plan_sha256 == active.plan_sha256,
        "active server update journal is not bound to its plan"
    );
    if matches!(
        journal.stage.as_str(),
        "candidate_starting" | "candidate_started" | "candidate_ready" | "recovery_required"
    ) {
        anyhow::ensure!(
            consent.restore_after_candidate_handoff && consent.confirm_data_loss,
            "candidate service handoff may have accepted writes; pass --restore-after-candidate-handoff and --confirm-data-loss to restore the previous database"
        );
    }
    if matches!(
        journal.stage.as_str(),
        "completed"
            | "rolled_back"
            | "recovered"
            | "failed_before_replacement"
            | "helper_spawn_failed"
    ) {
        clear_server_readiness_contract(&authenticator)?;
        clear_active_marker(&state_directory, plan.operation_id, Some(&authenticator))?;
        return status(UpdateProduct::Server, &state_directory);
    }
    let Some(backup_directory) = journal.backup_directory else {
        anyhow::ensure!(
            sha256_file(&plan.target_executable)? == plan.expected_target_sha256,
            "interrupted update has no authenticated backup and the installed binary changed; manual recovery is required"
        );
        let recovered = UpdateStatus {
            schema_version: UPDATE_SCHEMA_VERSION,
            state: "failed".to_owned(),
            operation: Some(operation_name(plan.operation).to_owned()),
            from_version: Some(plan.from_version.clone()),
            to_version: Some(plan.to_version.clone()),
            message: "interrupted update stopped before creating a replacement backup".to_owned(),
            error: Some("no executable or database replacement was recovered".to_owned()),
            backup: None,
            updated_unix_seconds: unix_seconds(),
        };
        write_status(&state_directory, recovered)?;
        write_operation_journal(
            &plan,
            &active.plan_sha256,
            "failed_before_replacement",
            None,
            Some("recovery found no authenticated replacement backup".to_owned()),
        )?;
        clear_active_marker(&state_directory, plan.operation_id, Some(&authenticator))?;
        return status(UpdateProduct::Server, &state_directory);
    };
    ensure_within(&backup_directory, &state_directory)?;
    match restore_after_failure(
        &plan,
        &backup_directory,
        &active.plan_sha256,
        Some(&authenticator),
    ) {
        Ok(()) => {
            write_status(
                &state_directory,
                UpdateStatus {
                    schema_version: UPDATE_SCHEMA_VERSION,
                    state: "rolled_back".to_owned(),
                    operation: Some(operation_name(plan.operation).to_owned()),
                    from_version: Some(plan.from_version.clone()),
                    to_version: Some(plan.to_version.clone()),
                    message: "interrupted update was recovered to the authenticated previous server and database snapshot".to_owned(),
                    error: None,
                    backup: Some(backup_directory.clone()),
                    updated_unix_seconds: unix_seconds(),
                },
            )?;
            write_operation_journal(
                &plan,
                &active.plan_sha256,
                "recovered",
                Some(&backup_directory),
                None,
            )?;
            clear_active_marker(&state_directory, plan.operation_id, Some(&authenticator))?;
            status(UpdateProduct::Server, &state_directory)
        }
        Err(error) => {
            let error_message = error.to_string();
            let _ = write_operation_journal(
                &plan,
                &active.plan_sha256,
                "recovery_required",
                Some(&backup_directory),
                Some(error_message.clone()),
            );
            let _ = write_status(
                &state_directory,
                UpdateStatus {
                    schema_version: UPDATE_SCHEMA_VERSION,
                    state: "failed".to_owned(),
                    operation: Some(operation_name(plan.operation).to_owned()),
                    from_version: Some(plan.from_version),
                    to_version: Some(plan.to_version),
                    message: "interrupted update could not be restored automatically".to_owned(),
                    error: Some(error_message.clone()),
                    backup: Some(backup_directory),
                    updated_unix_seconds: unix_seconds(),
                },
            );
            anyhow::bail!("server update recovery failed: {error_message}")
        }
    }
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
    read_durable_json(&path, MAX_UPDATE_STATE_BYTES)
}

pub fn run_helper(plan_path: &Path, expected_plan_sha256: &str) -> anyhow::Result<()> {
    let expected_plan_sha256 = normalize_sha256(expected_plan_sha256)?.to_owned();
    let plan_bytes = read_limited_bytes(plan_path, MAX_UPDATE_STATE_BYTES)?;
    anyhow::ensure!(
        sha256_bytes(&plan_bytes) == expected_plan_sha256,
        "update helper plan digest mismatch"
    );
    let mut plan: HelperPlan = serde_json::from_slice(&plan_bytes)?;
    if plan.product == UpdateProduct::Server {
        let authenticator = server_authenticator_for_plan(&plan)?.ok_or_else(|| {
            anyhow::anyhow!("server update helper is missing its state authenticator")
        })?;
        plan = read_server_authenticated_json(&authenticator, plan_path, "helper-plan")?;
    }
    if let Err(error) = validate_helper_plan(plan_path, &mut plan) {
        write_helper_validation_failure(plan_path, &plan, &error);
        return Err(error);
    }
    let _update_lock = UpdateLock::acquire(&plan.state_directory)?;
    sleep(Duration::from_millis(1_500));
    execute_helper(plan, &expected_plan_sha256)
}

fn write_helper_validation_failure(plan_path: &Path, plan: &HelperPlan, error: &anyhow::Error) {
    let Ok(state) = canonicalize_update_path(&plan.state_directory) else {
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

fn schedule_server_apply(
    state_directory: &Path,
    data_directory: &Path,
    staged: StagedUpdate,
) -> anyhow::Result<UpdateSchedule> {
    let installation = current_installation(UpdateProduct::Server)?;
    let context = prepare_server_update_context(
        &installation.target,
        &staged.staged_executable,
        data_directory,
    )?;
    anyhow::ensure!(
        context.installed_executable == installation.target
            && context.staged_executable == canonicalize_update_path(&staged.staged_executable)?,
        "server update database inspection is not bound to the scheduled executables"
    );
    schedule_update(
        UpdateProduct::Server,
        state_directory,
        UpdateOperation::Apply,
        staged,
        Some(ServerDatabaseTransaction::Apply { context }),
    )
}

fn schedule_update(
    product: UpdateProduct,
    state_directory: &Path,
    operation: UpdateOperation,
    staged: StagedUpdate,
    server_database: Option<ServerDatabaseTransaction>,
) -> anyhow::Result<UpdateSchedule> {
    let state_directory = prepare_state_directory(state_directory)?;
    let _schedule_lock = UpdateLock::acquire(&state_directory)?;
    anyhow::ensure!(
        !state_directory.join("active.json").exists(),
        "another update is active or requires recovery; run server update recover before scheduling a new update"
    );
    cleanup_old_helpers(&state_directory);
    anyhow::ensure!(staged.product == product, "staged update product mismatch");
    anyhow::ensure!(
        (product == UpdateProduct::Server) == server_database.is_some(),
        "only server updates may carry a database transaction context"
    );
    let server_authenticator = server_database
        .as_ref()
        .map(prepare_server_authenticator_for_transaction)
        .transpose()?;
    let installation = current_installation(product)?;
    let target = installation.target;
    validate_target_executable(product, &target)?;
    ensure_within(&staged.staged_executable, &state_directory)?;
    anyhow::ensure!(
        sha256_file(&staged.staged_executable)? == staged.binary_sha256,
        "staged component binary digest changed"
    );
    let service = service_runtime_for_target(product, &target)?;
    match service {
        ServiceRuntime::Transitioning => anyhow::bail!(
            "component service is transitioning; wait for it to become running or stopped before scheduling an update"
        ),
        ServiceRuntime::Unknown => anyhow::bail!(
            "cannot determine the component service state; refusing to schedule an update"
        ),
        ServiceRuntime::NotInstalled | ServiceRuntime::Stopped | ServiceRuntime::Running => {}
    }
    let operation_id = Uuid::new_v4();
    let operations = state_directory.join("operations");
    fs::create_dir_all(&operations)?;
    secure_directory(&operations)?;
    let operation_directory = operations.join(operation_id.to_string());
    fs::create_dir(&operation_directory)?;
    secure_directory(&operation_directory)?;
    let operation_directory = canonicalize_update_path(&operation_directory)?;
    ensure_within(&operation_directory, &state_directory)?;
    validate_server_transaction_at_schedule(
        product,
        &target,
        &staged.staged_executable,
        server_database.as_ref(),
    )?;
    let plan = HelperPlan {
        schema_version: UPDATE_SCHEMA_VERSION,
        operation_id,
        operation_directory: operation_directory.clone(),
        operation,
        product,
        state_directory: state_directory.clone(),
        target_executable: target.clone(),
        staged_executable: canonicalize_update_path(&staged.staged_executable)?,
        expected_target_sha256: sha256_file(&target)?,
        staged_sha256: staged.binary_sha256,
        from_version: installation
            .version
            .map(|version| version.to_string())
            .unwrap_or_else(|| staged.current_version.clone()),
        to_version: staged.version,
        service_installed: service != ServiceRuntime::NotInstalled,
        service_was_running: service == ServiceRuntime::Running,
        server_database,
        created_unix_seconds: unix_seconds(),
    };
    let helpers = state_directory.join("helpers");
    fs::create_dir_all(&helpers)?;
    secure_directory(&helpers)?;
    let identifier = operation_id.simple().to_string();
    let plan_path = operation_directory.join("plan.json");
    let plan_bytes = serde_json::to_vec(&plan)?;
    let plan_sha256 = sha256_bytes(&plan_bytes);
    if let Some(authenticator) = server_authenticator.as_ref() {
        write_server_authenticated_json(authenticator, &plan_path, "helper-plan", &plan)?;
    } else {
        write_durable_json(&plan_path, &plan, MAX_UPDATE_STATE_BYTES)?;
    }
    // journal 在 active marker 前落盘。断电若发生在此之前，尚未出现可恢复 marker；
    // 因而不会留下旧顺序中 marker 已存在而 journal 缺失的永久阻塞状态。
    write_operation_journal(&plan, &plan_sha256, "scheduled", None, None)?;
    let active = ActiveUpdate {
        schema_version: UPDATE_SCHEMA_VERSION,
        operation_id,
        product,
        plan_path: plan_path.clone(),
        plan_sha256: plan_sha256.clone(),
        created_unix_seconds: unix_seconds(),
    };
    if let Some(authenticator) = server_authenticator.as_ref() {
        write_server_authenticated_json(
            authenticator,
            &state_directory.join("active.json"),
            "active-marker",
            &active,
        )?;
    } else {
        write_durable_json(
            &state_directory.join("active.json"),
            &active,
            MAX_UPDATE_STATE_BYTES,
        )?;
    }
    let mut active_marker_guard = ActiveMarkerGuard::new(
        state_directory.clone(),
        operation_id,
        server_authenticator.clone(),
    );
    let helper_name = if cfg!(windows) {
        format!("linklake-update-helper-{identifier}.exe")
    } else {
        format!("linklake-update-helper-{identifier}")
    };
    let helper_path = helpers.join(helper_name);
    let updater_executable = canonicalize_update_path(&std::env::current_exe()?)?;
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
            let _ = write_operation_journal(
                &plan,
                &plan_sha256,
                "helper_spawn_failed",
                None,
                Some(error.to_string()),
            );
            let _ = clear_active_marker(
                &state_directory,
                operation_id,
                server_authenticator.as_ref(),
            );
            return Err(error.into());
        }
    };
    active_marker_guard.disarm();
    Ok(UpdateSchedule {
        state: "scheduled".to_owned(),
        operation_id,
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
    let state = canonicalize_update_path(&plan.state_directory)?;
    ensure_within(plan_path, &state)?;
    ensure_within(&plan.staged_executable, &state)?;
    ensure_within(&plan.operation_directory, &state)?;
    plan.state_directory = state;
    plan.staged_executable = canonicalize_update_path(&plan.staged_executable)?;
    plan.target_executable = canonicalize_update_path(&plan.target_executable)?;
    plan.operation_directory = canonicalize_update_path(&plan.operation_directory)?;
    anyhow::ensure!(
        plan.operation_directory.parent()
            == Some(plan.state_directory.join("operations").as_path()),
        "update operation directory is not a direct child of the managed operations directory"
    );
    anyhow::ensure!(
        plan.operation_directory
            .file_name()
            .is_some_and(|value| value == OsStr::new(&plan.operation_id.to_string())),
        "update operation directory does not match the plan operation ID"
    );
    validate_target_executable(plan.product, &plan.target_executable)?;
    anyhow::ensure!(
        sha256_file(&plan.staged_executable)? == plan.staged_sha256,
        "staged binary digest changed before installation"
    );
    anyhow::ensure!(
        sha256_file(&plan.target_executable)? == plan.expected_target_sha256,
        "installed binary changed after the update was scheduled"
    );
    validate_server_transaction_at_schedule(
        plan.product,
        &plan.target_executable,
        &plan.staged_executable,
        plan.server_database.as_ref(),
    )?;
    let server_authenticator = server_authenticator_for_plan(plan)?;
    let active: ActiveUpdate = match server_authenticator.as_ref() {
        Some(authenticator) => read_server_authenticated_json(
            authenticator,
            &plan.state_directory.join("active.json"),
            "active-marker",
        )?,
        None => read_durable_json(
            &plan.state_directory.join("active.json"),
            MAX_UPDATE_STATE_BYTES,
        )?,
    };
    anyhow::ensure!(
        active.schema_version == UPDATE_SCHEMA_VERSION
            && active.operation_id == plan.operation_id
            && active.product == plan.product
            && active.plan_path == canonicalize_update_path(plan_path)?,
        "active update marker does not match the helper plan"
    );
    Ok(())
}

fn execute_helper(plan: HelperPlan, plan_sha256: &str) -> anyhow::Result<()> {
    let server_authenticator = server_authenticator_for_plan(&plan)?;
    write_operation_journal(&plan, plan_sha256, "helper_started", None, None)?;
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
    let result = execute_helper_inner(&plan, plan_sha256);
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
                    from_version: Some(plan.from_version.clone()),
                    to_version: Some(plan.to_version.clone()),
                    message: "component binary and service state were verified".to_owned(),
                    error: None,
                    backup: Some(backup.clone()),
                    updated_unix_seconds: unix_seconds(),
                },
            )?;
            write_operation_journal(&plan, plan_sha256, "completed", Some(&backup), None)?;
            if let Some(authenticator) = server_authenticator.as_ref() {
                clear_server_readiness_contract(authenticator)?;
            }
            let _ = clear_active_marker(
                &plan.state_directory,
                plan.operation_id,
                server_authenticator.as_ref(),
            );
            Ok(())
        }
        Err((error, backup)) => {
            let error_message = error.to_string();
            if server_handoff_failure_route_with(&plan, server_authenticator.as_ref(), || {
                stop_candidate_service_after_failed_handoff(&plan)
            })? == ServerHandoffFailureRoute::ManualRecoveryRequired
            {
                let stop_failure = stop_candidate_service_after_failed_handoff(&plan)
                    .err()
                    .map(|stop_error| format!("; candidate stop failed: {stop_error}"))
                    .unwrap_or_default();
                let final_error = format!(
                    "{error_message}{stop_failure}; the candidate server may have accepted writes, so automatic database rollback is disabled and manual recovery is required"
                );
                write_status(
                    &plan.state_directory,
                    UpdateStatus {
                        schema_version: UPDATE_SCHEMA_VERSION,
                        state: "failed".to_owned(),
                        operation: Some(operation_name(plan.operation).to_owned()),
                        from_version: Some(plan.from_version.clone()),
                        to_version: Some(plan.to_version.clone()),
                        message: "candidate service handoff was interrupted; automatic rollback is intentionally disabled".to_owned(),
                        error: Some(final_error.clone()),
                        backup: backup.clone(),
                        updated_unix_seconds: unix_seconds(),
                    },
                )?;
                write_operation_journal(
                    &plan,
                    plan_sha256,
                    "recovery_required",
                    backup.as_deref(),
                    Some(final_error.clone()),
                )?;
                anyhow::bail!(final_error)
            }
            let rollback = backup
                .as_ref()
                .map(|path| {
                    restore_after_failure(&plan, path, plan_sha256, server_authenticator.as_ref())
                })
                .transpose();
            let (state, message, final_error, terminal_stage, clear_active) = match rollback {
                Ok(Some(())) => (
                    "rolled_back",
                    "the update failed and the previous component was restored",
                    error_message,
                    "rolled_back",
                    true,
                ),
                Ok(None) => (
                    "failed",
                    "the update failed before replacement",
                    error_message,
                    "failed_before_replacement",
                    true,
                ),
                Err(rollback_error) => (
                    "failed",
                    "the update and automatic rollback both failed; recovery is required",
                    format!("{error_message}; rollback: {rollback_error}"),
                    "recovery_required",
                    false,
                ),
            };
            write_status(
                &plan.state_directory,
                UpdateStatus {
                    schema_version: UPDATE_SCHEMA_VERSION,
                    state: state.to_owned(),
                    operation: Some(operation_name(plan.operation).to_owned()),
                    from_version: Some(plan.from_version.clone()),
                    to_version: Some(plan.to_version.clone()),
                    message: message.to_owned(),
                    error: Some(final_error.clone()),
                    backup: backup.clone(),
                    updated_unix_seconds: unix_seconds(),
                },
            )?;
            write_operation_journal(
                &plan,
                plan_sha256,
                terminal_stage,
                backup.as_deref(),
                Some(final_error.clone()),
            )?;
            if clear_active {
                let _ = clear_active_marker(
                    &plan.state_directory,
                    plan.operation_id,
                    server_authenticator.as_ref(),
                );
            }
            anyhow::bail!(final_error)
        }
    }
}

fn server_candidate_handoff_started(
    plan: &HelperPlan,
    authenticator: &ServerStateAuthenticator,
) -> anyhow::Result<bool> {
    let journal: UpdateJournal = read_server_authenticated_json(
        authenticator,
        &plan.operation_directory.join("journal.json"),
        "operation-journal",
    )?;
    anyhow::ensure!(
        journal.operation_id == plan.operation_id
            && journal.product == UpdateProduct::Server
            && journal.operation == plan.operation,
        "server update handoff journal is not bound to its plan"
    );
    Ok(is_server_candidate_handoff_stage(&journal.stage))
}

fn is_server_candidate_handoff_stage(stage: &str) -> bool {
    matches!(
        stage,
        "candidate_starting" | "candidate_started" | "candidate_ready"
    )
}

fn server_candidate_service_handoff_required(plan: &HelperPlan) -> bool {
    plan.product == UpdateProduct::Server && plan.service_installed && plan.service_was_running
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ServerHandoffFailureRoute {
    AutomaticRollbackEligible,
    ManualRecoveryRequired,
}

/// 候选服务已进入启动交接窗口后，绝不自动执行数据库回滚；否则维持原有的
/// 自动回滚路径。把决策单独抽出后，生产调用和带 fake service controller 的
/// 回归测试共享同一条分支。
fn server_handoff_failure_route_with<F>(
    plan: &HelperPlan,
    authenticator: Option<&ServerStateAuthenticator>,
    mut stop_candidate: F,
) -> anyhow::Result<ServerHandoffFailureRoute>
where
    F: FnMut() -> anyhow::Result<()>,
{
    if plan.product != UpdateProduct::Server {
        return Ok(ServerHandoffFailureRoute::AutomaticRollbackEligible);
    }
    let authenticator = authenticator
        .ok_or_else(|| anyhow::anyhow!("server update is missing its state authenticator"))?;
    if !server_candidate_handoff_started(plan, authenticator)? {
        return Ok(ServerHandoffFailureRoute::AutomaticRollbackEligible);
    }
    stop_candidate()?;
    Ok(ServerHandoffFailureRoute::ManualRecoveryRequired)
}

fn execute_helper_inner(
    plan: &HelperPlan,
    plan_sha256: &str,
) -> Result<PathBuf, (anyhow::Error, Option<PathBuf>)> {
    if let Err(error) = stop_service_for_update(plan) {
        return Err((error, None));
    }
    if let Err(error) = write_operation_journal(plan, plan_sha256, "service_stopped", None, None) {
        let _ = restart_service_after_update(plan);
        return Err((error, None));
    }
    let backup = match create_backup(plan, plan_sha256) {
        Ok(path) => path,
        Err(error) => {
            let _ = restart_service_after_update(plan);
            return Err((error, None));
        }
    };
    if let Err(error) =
        write_operation_journal(plan, plan_sha256, "backup_created", Some(&backup), None)
    {
        return Err((error, Some(backup)));
    }
    let result = (|| -> anyhow::Result<()> {
        prepare_server_database_transition(plan, &backup, plan_sha256)?;
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
        if server_candidate_service_handoff_required(plan) {
            execute_server_candidate_handoff(plan, plan_sha256, &backup)?;
        } else {
            restart_service_after_update(plan)?;
        }
        Ok(())
    })();
    result
        .map(|()| backup.clone())
        .map_err(|error| (error, Some(backup)))
}

fn create_backup(plan: &HelperPlan, plan_sha256: &str) -> anyhow::Result<PathBuf> {
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
    let database_snapshot_metadata =
        create_server_database_snapshot(plan, &executable, &directory, plan_sha256)?;
    let metadata = BackupMetadata {
        schema_version: UPDATE_SCHEMA_VERSION,
        operation_id: Some(plan.operation_id),
        version: plan.from_version.clone(),
        sha256: hash,
        target_executable: plan.target_executable.clone(),
        database_snapshot_metadata: database_snapshot_metadata.clone(),
        created_unix_seconds: unix_seconds(),
    };
    let metadata_path = directory.join("metadata.json");
    if let Some(authenticator) = server_authenticator_for_plan(plan)? {
        if let Some(snapshot_metadata_path) = database_snapshot_metadata.as_ref() {
            let snapshot = read_snapshot_metadata(snapshot_metadata_path)?;
            write_server_authenticated_json(
                &authenticator,
                snapshot_metadata_path,
                "database-snapshot",
                &snapshot,
            )?;
        }
        write_server_authenticated_json(
            &authenticator,
            &metadata_path,
            "backup-metadata",
            &metadata,
        )?;
    } else {
        write_durable_json(&metadata_path, &metadata, MAX_UPDATE_STATE_BYTES)?;
    }
    Ok(directory)
}

fn restore_after_failure(
    plan: &HelperPlan,
    backup_directory: &Path,
    plan_sha256: &str,
    server_authenticator: Option<&ServerStateAuthenticator>,
) -> anyhow::Result<()> {
    let name = plan
        .target_executable
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("installed binary has no file name"))?;
    let backup = backup_directory.join(name);
    anyhow::ensure!(backup.is_file(), "rollback backup is missing");
    // 在触碰运行中的服务前完成状态 HMAC、快照和旧二进制绑定验证。篡改状态目录
    // 最多会使恢复失败，不会先把正常服务停掉再变成可用性攻击。
    let server_snapshot = if plan.product == UpdateProduct::Server {
        let authenticator = server_authenticator
            .ok_or_else(|| anyhow::anyhow!("server rollback is missing its state authenticator"))?;
        let metadata: BackupMetadata = read_server_authenticated_json(
            authenticator,
            &backup_directory.join("metadata.json"),
            "backup-metadata",
        )?;
        anyhow::ensure!(
            metadata.operation_id == Some(plan.operation_id),
            "rollback backup does not belong to this update operation"
        );
        let snapshot_metadata_path = metadata.database_snapshot_metadata.ok_or_else(|| {
            anyhow::anyhow!("server rollback backup is missing its database snapshot metadata")
        })?;
        let _: ServerDatabaseSnapshotMetadata = read_server_authenticated_json(
            authenticator,
            &snapshot_metadata_path,
            "database-snapshot",
        )?;
        let snapshot = read_snapshot_metadata(&snapshot_metadata_path)?;
        validate_snapshot_metadata(&snapshot, plan.operation_id, plan_sha256)?;
        Some(snapshot)
    } else {
        None
    };
    if plan.service_installed {
        stop_candidate_service_after_failed_handoff(plan)?;
    }
    if let Some(authenticator) = server_authenticator {
        clear_server_readiness_contract(authenticator)?;
    }
    if let Some(snapshot) = server_snapshot {
        restore_server_database(&backup, &snapshot)?;
        write_operation_journal(
            plan,
            plan_sha256,
            "database_restored_for_rollback",
            Some(backup_directory),
            None,
        )?;
    }
    atomic_restore_with_retry(&plan.target_executable, &backup)?;
    anyhow::ensure!(
        sha256_file(&plan.target_executable)? == plan.expected_target_sha256,
        "restored binary digest mismatch"
    );
    verify_installed_version(&plan.target_executable, &plan.from_version)?;
    restart_service_after_update(plan)
}

fn create_server_database_snapshot(
    plan: &HelperPlan,
    rollback_binary: &Path,
    backup_directory: &Path,
    plan_sha256: &str,
) -> anyhow::Result<Option<PathBuf>> {
    let Some(transaction) = plan.server_database.as_ref() else {
        return Ok(None);
    };
    anyhow::ensure!(
        plan.product == UpdateProduct::Server,
        "only a server update may create a database snapshot"
    );
    let context = match transaction {
        ServerDatabaseTransaction::Apply { context } => context.clone(),
        ServerDatabaseTransaction::Rollback { context } => {
            let current =
                inspect_server_database(&plan.target_executable, &context.canonical_data_dir)?;
            anyhow::ensure!(
                current.observed_schema == context.expected_schema
                    && current.ledger_sha256 == context.expected_ledger_sha256,
                "server database schema or migration ledger changed after rollback scheduling"
            );
            prepare_server_update_context(
                &plan.target_executable,
                &plan.target_executable,
                &context.canonical_data_dir,
            )?
        }
    };
    let snapshot = backup_server_database(
        rollback_binary,
        &context,
        &backup_directory.join("database.sqlite3"),
        plan.operation_id,
        plan_sha256,
    )?;
    let metadata_path =
        write_snapshot_metadata(&backup_directory.join("database-snapshot.json"), &snapshot)?;
    Ok(Some(metadata_path))
}

fn prepare_server_database_transition(
    plan: &HelperPlan,
    backup_directory: &Path,
    plan_sha256: &str,
) -> anyhow::Result<()> {
    let Some(transaction) = plan.server_database.as_ref() else {
        return Ok(());
    };
    let authenticator = server_authenticator_for_plan(plan)?.ok_or_else(|| {
        anyhow::anyhow!("server database transition is missing its state authenticator")
    })?;
    let backup: BackupMetadata = read_server_authenticated_json(
        &authenticator,
        &backup_directory.join("metadata.json"),
        "backup-metadata",
    )?;
    anyhow::ensure!(
        backup.operation_id == Some(plan.operation_id),
        "backup metadata does not belong to this update operation"
    );
    match transaction {
        ServerDatabaseTransaction::Apply { context } => {
            let snapshot_path = backup.database_snapshot_metadata.as_ref().ok_or_else(|| {
                anyhow::anyhow!("server update backup is missing its database snapshot metadata")
            })?;
            let _: ServerDatabaseSnapshotMetadata =
                read_server_authenticated_json(&authenticator, snapshot_path, "database-snapshot")?;
            let snapshot = read_snapshot_metadata(snapshot_path)?;
            validate_snapshot_metadata(&snapshot, plan.operation_id, plan_sha256)?;
            let scratch = plan.operation_directory.join("database-preflight");
            fs::create_dir(&scratch)?;
            secure_directory(&scratch)?;
            preflight_server_database(
                &plan.staged_executable,
                context,
                &snapshot,
                &scratch,
                &plan.operation_directory,
            )?;
            write_operation_journal(
                plan,
                plan_sha256,
                "database_preflighted",
                Some(backup_directory),
                None,
            )?;
        }
        ServerDatabaseTransaction::Rollback { context } => {
            let current =
                inspect_server_database(&plan.target_executable, &context.canonical_data_dir)?;
            anyhow::ensure!(
                current.observed_schema == context.expected_schema
                    && current.ledger_sha256 == context.expected_ledger_sha256,
                "server database schema or migration ledger changed after rollback scheduling"
            );
            if context.restore_snapshot {
                let _: ServerDatabaseSnapshotMetadata = read_server_authenticated_json(
                    &authenticator,
                    &context.snapshot_metadata_path,
                    "database-snapshot",
                )?;
                let snapshot = read_snapshot_metadata(&context.snapshot_metadata_path)?;
                validate_snapshot_metadata(
                    &snapshot,
                    context.snapshot_operation_id,
                    &context.snapshot_plan_sha256,
                )?;
                anyhow::ensure!(
                    snapshot.rollback_binary_path == plan.staged_executable,
                    "manual rollback binary does not match the selected database snapshot"
                );
                restore_server_database(&plan.staged_executable, &snapshot)?;
                write_operation_journal(
                    plan,
                    plan_sha256,
                    "database_restored_for_manual_rollback",
                    Some(backup_directory),
                    None,
                )?;
            }
        }
    }
    Ok(())
}

fn validate_server_transaction_at_schedule(
    product: UpdateProduct,
    target: &Path,
    staged: &Path,
    transaction: Option<&ServerDatabaseTransaction>,
) -> anyhow::Result<()> {
    match (product, transaction) {
        (UpdateProduct::Server, Some(ServerDatabaseTransaction::Apply { context })) => {
            anyhow::ensure!(
                context.installed_executable == canonicalize_update_path(target)?
                    && context.staged_executable == canonicalize_update_path(staged)?,
                "server update context is not bound to the scheduled binaries"
            );
        }
        (UpdateProduct::Server, Some(ServerDatabaseTransaction::Rollback { context })) => {
            anyhow::ensure!(
                canonicalize_update_path(&context.canonical_data_dir)?
                    == context.canonical_data_dir,
                "server rollback data directory changed after scheduling"
            );
            let authenticator =
                load_server_state_authenticator(&context.canonical_data_dir, false)?;
            let _: ServerDatabaseSnapshotMetadata = read_server_authenticated_json(
                &authenticator,
                &context.snapshot_metadata_path,
                "database-snapshot",
            )?;
            let snapshot = read_snapshot_metadata(&context.snapshot_metadata_path)?;
            anyhow::ensure!(
                snapshot.operation_id == context.snapshot_operation_id
                    && snapshot.plan_sha256 == context.snapshot_plan_sha256
                    && snapshot.rollback_binary_path == canonicalize_update_path(staged)?,
                "server rollback snapshot is not bound to the scheduled rollback binary"
            );
        }
        (UpdateProduct::Server, None) => {
            anyhow::bail!("server update is missing a database transaction")
        }
        (_, Some(_)) => anyhow::bail!("non-server update contains a database transaction"),
        (_, None) => {}
    }
    Ok(())
}

fn write_operation_journal(
    plan: &HelperPlan,
    plan_sha256: &str,
    stage: &str,
    backup_directory: Option<&Path>,
    error: Option<String>,
) -> anyhow::Result<()> {
    let journal = UpdateJournal {
        schema_version: UPDATE_JOURNAL_SCHEMA_VERSION,
        operation_id: plan.operation_id,
        plan_sha256: normalize_sha256(plan_sha256)?.to_owned(),
        product: plan.product,
        operation: plan.operation,
        stage: stage.to_owned(),
        backup_directory: backup_directory.map(Path::to_path_buf),
        error,
        updated_unix_seconds: unix_seconds(),
    };
    let path = plan.operation_directory.join("journal.json");
    if plan.product == UpdateProduct::Server {
        let transaction = plan.server_database.as_ref().ok_or_else(|| {
            anyhow::anyhow!("server update journal is missing its database transaction")
        })?;
        let authenticator = server_authenticator_from_transaction(transaction)?;
        write_server_authenticated_json(&authenticator, &path, "operation-journal", &journal)
    } else {
        write_journal_json(&path, &journal, MAX_UPDATE_STATE_BYTES)
    }
}

fn clear_active_marker(
    state_directory: &Path,
    operation_id: Uuid,
    server_authenticator: Option<&ServerStateAuthenticator>,
) -> anyhow::Result<()> {
    let path = state_directory.join("active.json");
    let active: ActiveUpdate = match server_authenticator {
        Some(authenticator) => {
            read_server_authenticated_json(authenticator, &path, "active-marker")?
        }
        None => read_durable_json(&path, MAX_UPDATE_STATE_BYTES)?,
    };
    anyhow::ensure!(
        active.schema_version == UPDATE_SCHEMA_VERSION && active.operation_id == operation_id,
        "active update marker belongs to another operation"
    );
    match server_authenticator {
        Some(_) => remove_server_authenticated_state(&path),
        None => remove_durable_file(&path),
    }
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
        let metadata: BackupMetadata =
            match read_durable_json(&metadata_path, MAX_UPDATE_STATE_BYTES) {
                Ok(value) => value,
                Err(_) => continue,
            };
        if !matches!(metadata.schema_version, 2 | UPDATE_SCHEMA_VERSION)
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
    atomic_replace_with_retry_inner(target, source, false)
}

/// 恢复路径允许目标文件在断电窗口中缺失：例如旧文件已经改名为临时 replaced
/// 名称、但候选文件尚未改回目标名称。常规安装仍必须要求目标存在。
fn atomic_restore_with_retry(target: &Path, source: &Path) -> anyhow::Result<()> {
    atomic_replace_with_retry_inner(target, source, true)
}

fn atomic_replace_with_retry_inner(
    target: &Path,
    source: &Path,
    allow_missing_target: bool,
) -> anyhow::Result<()> {
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
            let had_target = target.exists();
            anyhow::ensure!(
                had_target || allow_missing_target,
                "installed binary is missing before replacement"
            );
            if had_target {
                fs::rename(target, &replaced)?;
            }
            if let Err(error) = fs::rename(&incoming, target) {
                if had_target {
                    let _ = fs::rename(&replaced, target);
                }
                return Err(error.into());
            }
            if had_target {
                fs::remove_file(&replaced)?;
            }
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
    let current = canonicalize_update_path(&std::env::current_exe()?)?;
    let standard = standard_installation(product);
    let target = if standard.is_file()
        && service_runtime_for_target(product, &canonicalize_update_path(&standard)?)?
            != ServiceRuntime::NotInstalled
    {
        canonicalize_update_path(&standard)?
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
        if !configuration.status.success() {
            return Ok(
                if windows_sc_reports_missing_service(&configuration.stdout, &configuration.stderr)
                {
                    ServiceRuntime::NotInstalled
                } else {
                    ServiceRuntime::Unknown
                },
            );
        }
        if !windows_sc_configuration_has_binary_path(&configuration.stdout) {
            return Ok(ServiceRuntime::Unknown);
        }
        if !command_output_references_target(&configuration.stdout, target) {
            return Ok(ServiceRuntime::NotInstalled);
        }
        let output = Command::new("sc.exe")
            .args(["query", product.service_name()])
            .output()?;
        if !output.status.success() {
            return Ok(ServiceRuntime::Unknown);
        }
        Ok(parse_windows_sc_query_runtime(&output.stdout))
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
        if !configuration.status.success() {
            return Ok(
                if systemd_reports_missing_unit(&configuration.stdout, &configuration.stderr) {
                    ServiceRuntime::NotInstalled
                } else {
                    ServiceRuntime::Unknown
                },
            );
        }
        if configuration.stdout.is_empty() {
            return Ok(ServiceRuntime::Unknown);
        }
        if !command_output_references_target(&configuration.stdout, target) {
            return Ok(ServiceRuntime::NotInstalled);
        }
        let output = Command::new("systemctl")
            .args(["is-active", product.systemd_unit()])
            .output()?;
        Ok(parse_systemd_active_runtime(&output.stdout))
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

/// 仅接受 `sc.exe query` 明确报告的 SCM 状态。任何未知状态、非标准输出或
/// 本地化后无法可靠识别的文本都必须关闭更新流程，不能被当作已停止。
#[cfg(any(windows, test))]
fn parse_windows_sc_query_runtime(output: &[u8]) -> ServiceRuntime {
    let output = String::from_utf8_lossy(output);
    for line in output.lines() {
        let Some((label, value)) = line.split_once(':') else {
            continue;
        };
        if !label.trim().eq_ignore_ascii_case("STATE") {
            continue;
        }
        return match value.split_ascii_whitespace().next() {
            Some("1") => ServiceRuntime::Stopped,
            Some("2") | Some("3") => ServiceRuntime::Transitioning,
            Some("4") => ServiceRuntime::Running,
            _ => ServiceRuntime::Unknown,
        };
    }
    ServiceRuntime::Unknown
}

#[cfg(windows)]
fn windows_sc_reports_missing_service(stdout: &[u8], stderr: &[u8]) -> bool {
    let mut output = String::from_utf8_lossy(stdout).into_owned();
    output.push_str(&String::from_utf8_lossy(stderr));
    output.contains("1060")
}

#[cfg(any(windows, test))]
fn windows_sc_configuration_has_binary_path(output: &[u8]) -> bool {
    String::from_utf8_lossy(output).lines().any(|line| {
        line.split_once(':')
            .is_some_and(|(label, _)| label.trim().eq_ignore_ascii_case("BINARY_PATH_NAME"))
    })
}

/// `systemctl is-active` 即便成功返回状态字符串时也会以非零状态退出（例如
/// inactive）。因此必须解析其 stdout，只有明确 `inactive` 才视为已停止。
#[cfg(any(target_os = "linux", test))]
fn parse_systemd_active_runtime(output: &[u8]) -> ServiceRuntime {
    match String::from_utf8_lossy(output).trim() {
        "active" => ServiceRuntime::Running,
        "inactive" => ServiceRuntime::Stopped,
        "activating" | "deactivating" | "reloading" => ServiceRuntime::Transitioning,
        _ => ServiceRuntime::Unknown,
    }
}

#[cfg(target_os = "linux")]
fn systemd_reports_missing_unit(stdout: &[u8], stderr: &[u8]) -> bool {
    let mut output = String::from_utf8_lossy(stdout).into_owned();
    output.push_str(&String::from_utf8_lossy(stderr));
    output.contains("not-found") || output.contains("could not be found")
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
    if !plan.service_installed {
        return Ok(());
    }
    wait_for_service_stopped_with(
        SERVICE_WAIT_TIMEOUT,
        Duration::from_millis(500),
        plan.service_was_running,
        || service_runtime_for_target(plan.product, &plan.target_executable),
        || stop_service_best_effort(plan.product, true),
        "component service did not stop",
    )
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

/// 候选服务在交接窗口内未能证明业务就绪时，先尽力停止它以阻止继续处理请求。
/// 此处绝不自动替换回数据库和二进制：候选进程可能已经写入数据，回滚必须转由
/// 显式恢复流程处理。
fn stop_candidate_service_after_failed_handoff(plan: &HelperPlan) -> anyhow::Result<()> {
    if !plan.service_installed {
        return Ok(());
    }
    wait_for_service_stopped_with(
        SERVICE_WAIT_TIMEOUT,
        Duration::from_millis(500),
        true,
        || service_runtime_for_target(plan.product, &plan.target_executable),
        || stop_service_best_effort(plan.product, true),
        "candidate service did not stop after failed business-readiness validation",
    )
}

fn restart_service_after_update(plan: &HelperPlan) -> anyhow::Result<()> {
    if !plan.service_installed || !plan.service_was_running {
        return Ok(());
    }
    let start_required =
        wait_for_service_startable_with(SERVICE_WAIT_TIMEOUT, Duration::from_millis(500), || {
            service_runtime_for_target(plan.product, &plan.target_executable)
        })?;
    if start_required {
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
    }
    wait_for_service_running_with(
        SERVICE_WAIT_TIMEOUT,
        Duration::from_millis(500),
        SERVICE_STABLE_POLLS,
        || service_runtime_for_target(plan.product, &plan.target_executable),
    )
}

/// 返回前只接受明确的停止状态，保证数据库快照、二进制替换和数据库恢复不会
/// 与仍在运行或状态未知的服务并发执行。过渡状态只会等待到超时；未知状态立即
/// 失败关闭。
fn wait_for_service_stopped_with<F, G>(
    timeout: Duration,
    poll_interval: Duration,
    may_request_stop: bool,
    mut runtime: F,
    mut request_stop: G,
    timeout_message: &str,
) -> anyhow::Result<()>
where
    F: FnMut() -> anyhow::Result<ServiceRuntime>,
    G: FnMut() -> anyhow::Result<()>,
{
    let deadline = std::time::Instant::now() + timeout;
    let mut stop_requested = false;
    loop {
        match runtime()? {
            ServiceRuntime::Stopped => return Ok(()),
            ServiceRuntime::Running if may_request_stop => {
                if !stop_requested {
                    request_stop()?;
                    stop_requested = true;
                }
            }
            ServiceRuntime::Running => anyhow::bail!(
                "component service started after scheduling; refusing to stop a service that was scheduled stopped"
            ),
            ServiceRuntime::Transitioning => {}
            ServiceRuntime::NotInstalled => anyhow::bail!(
                "component service no longer references the scheduled target executable"
            ),
            ServiceRuntime::Unknown => anyhow::bail!(
                "cannot determine the component service state; refusing to continue the update"
            ),
        }
        anyhow::ensure!(std::time::Instant::now() < deadline, "{timeout_message}");
        sleep(poll_interval);
    }
}

/// 在启动前等待服务退出 START_PENDING/STOP_PENDING 等中间状态。返回 `true`
/// 表示服务已明确停止且需要执行启动命令；`false` 表示它已经运行，后续只需做
/// 稳定性确认。
fn wait_for_service_startable_with<F>(
    timeout: Duration,
    poll_interval: Duration,
    mut runtime: F,
) -> anyhow::Result<bool>
where
    F: FnMut() -> anyhow::Result<ServiceRuntime>,
{
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match runtime()? {
            ServiceRuntime::Stopped => return Ok(true),
            ServiceRuntime::Running => return Ok(false),
            ServiceRuntime::Transitioning => {}
            ServiceRuntime::NotInstalled => anyhow::bail!(
                "component service no longer references the scheduled target executable"
            ),
            ServiceRuntime::Unknown => anyhow::bail!(
                "cannot determine the component service state; refusing to restart it"
            ),
        }
        anyhow::ensure!(
            std::time::Instant::now() < deadline,
            "component service did not settle before restart"
        );
        sleep(poll_interval);
    }
}

/// 启动请求完成后只有连续观察到 Running 才会返回成功。Stopped 或过渡状态不
/// 会被当作成功；Unknown/NotInstalled 立即失败关闭。
fn wait_for_service_running_with<F>(
    timeout: Duration,
    poll_interval: Duration,
    stable_polls_required: usize,
    mut runtime: F,
) -> anyhow::Result<()>
where
    F: FnMut() -> anyhow::Result<ServiceRuntime>,
{
    anyhow::ensure!(
        stable_polls_required > 0,
        "service stability polling requires at least one observation"
    );
    let deadline = std::time::Instant::now() + timeout;
    let mut stable_polls = 0;
    loop {
        match runtime()? {
            ServiceRuntime::Running => {
                stable_polls += 1;
                if stable_polls >= stable_polls_required {
                    return Ok(());
                }
            }
            ServiceRuntime::Stopped | ServiceRuntime::Transitioning => stable_polls = 0,
            ServiceRuntime::NotInstalled => anyhow::bail!(
                "component service no longer references the scheduled target executable"
            ),
            ServiceRuntime::Unknown => anyhow::bail!(
                "cannot determine the component service state; refusing to mark it restarted"
            ),
        }
        anyhow::ensure!(
            std::time::Instant::now() < deadline,
            "component service did not become active"
        );
        sleep(poll_interval);
    }
}

/// 服务端更新的认证密钥只放在实际数据目录，而不放在可通过 `--state-dir`
/// 指定的事务目录。服务端数据目录是已经由服务账户保护的持久化边界；因此状态
/// 目录即使被低权限用户写入，也无法伪造恢复操作所需的 HMAC。
fn prepare_server_state_authenticator(
    data_directory: &Path,
) -> anyhow::Result<ServerStateAuthenticator> {
    load_server_state_authenticator(data_directory, true)
}

fn load_server_state_authenticator(
    data_directory: &Path,
    create_if_missing: bool,
) -> anyhow::Result<ServerStateAuthenticator> {
    let canonical_data_directory = canonicalize_update_path(data_directory)?;
    anyhow::ensure!(
        canonical_data_directory.is_dir(),
        "server update authentication data directory is not a directory"
    );
    // 在检查认证密钥是否存在前，先验证目录的可信身份。特权 helper 不能因为
    // 目录内“恰好有一个密钥”就对任意用户目录建立认证根。
    validate_server_state_authentication_boundary(&canonical_data_directory, None)?;
    #[cfg(debug_assertions)]
    if let Some(key) = test_server_update_authentication_key()? {
        return Ok(ServerStateAuthenticator {
            key,
            canonical_data_directory,
        });
    }
    let key_path = canonical_data_directory.join(SERVER_STATE_AUTH_KEY_NAME);
    let key = match fs::symlink_metadata(&key_path) {
        Ok(_) => {
            // 绝不能先读取一个预置密钥、再尝试收紧其 ACL。这样会把攻击者已知的
            // HMAC 密钥当作可信根。已有密钥及其父数据目录必须在读取前已受保护。
            validate_server_state_authentication_boundary(
                &canonical_data_directory,
                Some(&key_path),
            )?;
            let key = read_limited_bytes(&key_path, 32)
                .context("cannot read the server update authentication key")?;
            anyhow::ensure!(
                key.len() == 32,
                "server update authentication key has an invalid length"
            );
            let mut value = [0_u8; 32];
            value.copy_from_slice(&key);
            value
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && create_if_missing => {
            // 先验证服务数据目录是已建立的可信边界，再生成密钥。这里不自动修复
            // 自定义目录的 ACL：错误的目录应由安装器/管理员显式修复，而不是在
            // 更新路径中悄悄接管。
            let mut value = [0_u8; 32];
            getrandom::fill(&mut value)
                .context("cannot generate the server update authentication key")?;
            write_durable_bytes(&key_path, &value, 32)
                .context("cannot create the server update authentication key")?;
            if let Err(error) =
                secure_server_authentication_key(&key_path, &canonical_data_directory)
            {
                // 只有当前调用创建的密钥会被移除；已有密钥永远不因权限检查失败而删除。
                let _ = remove_durable_file(&key_path);
                return Err(error);
            }
            if let Err(error) = validate_server_state_authentication_boundary(
                &canonical_data_directory,
                Some(&key_path),
            ) {
                let _ = remove_durable_file(&key_path);
                return Err(error);
            }
            value
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            anyhow::bail!(
                "server update authentication key is missing; do not recover untrusted update state"
            )
        }
        Err(error) => {
            return Err(error).context("cannot inspect the server update authentication key");
        }
    };
    Ok(ServerStateAuthenticator {
        key,
        canonical_data_directory,
    })
}

/// 端到端夹具可以在 debug 构建中注入固定 HMAC 密钥，避免测试脚本把任何密钥
/// 写进服务数据目录。release 构建不会编译或读取该环境变量。
#[cfg(debug_assertions)]
fn test_server_update_authentication_key() -> anyhow::Result<Option<[u8; 32]>> {
    let Some(value) = std::env::var_os("LINKLAKE_UPDATE_TEST_SERVER_AUTH_KEY_HEX") else {
        return Ok(None);
    };
    let value = value.to_string_lossy();
    anyhow::ensure!(
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "test server update authentication key must be 64 hexadecimal characters"
    );
    let mut key = [0_u8; 32];
    for (index, output) in key.iter_mut().enumerate() {
        *output = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .expect("validated hexadecimal test authentication key");
    }
    Ok(Some(key))
}

fn server_authenticator_from_transaction(
    transaction: &ServerDatabaseTransaction,
) -> anyhow::Result<ServerStateAuthenticator> {
    let data_directory = match transaction {
        ServerDatabaseTransaction::Apply { context } => &context.canonical_data_dir,
        ServerDatabaseTransaction::Rollback { context } => &context.canonical_data_dir,
    };
    load_server_state_authenticator(data_directory, false)
}

fn prepare_server_authenticator_for_transaction(
    transaction: &ServerDatabaseTransaction,
) -> anyhow::Result<ServerStateAuthenticator> {
    let data_directory = match transaction {
        ServerDatabaseTransaction::Apply { context } => &context.canonical_data_dir,
        ServerDatabaseTransaction::Rollback { context } => &context.canonical_data_dir,
    };
    prepare_server_state_authenticator(data_directory)
}

fn server_authenticator_for_plan(
    plan: &HelperPlan,
) -> anyhow::Result<Option<ServerStateAuthenticator>> {
    if plan.product != UpdateProduct::Server {
        return Ok(None);
    }
    let transaction = plan
        .server_database
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("server update plan is missing its database transaction"))?;
    Ok(Some(server_authenticator_from_transaction(transaction)?))
}

fn server_state_authentication_path(payload_path: &Path) -> anyhow::Result<PathBuf> {
    let parent = payload_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("server authenticated state has no parent directory"))?;
    let name = payload_path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("server authenticated state has no file name"))?
        .to_string_lossy();
    Ok(parent.join(format!(".{name}.auth")))
}

fn server_state_hmac(
    authenticator: &ServerStateAuthenticator,
    purpose: &str,
    bytes: &[u8],
) -> String {
    let mut mac = HmacSha256::new_from_slice(&authenticator.key)
        .expect("HMAC-SHA256 accepts the fixed server state key length");
    mac.update(SERVER_STATE_AUTH_PREFIX);
    mac.update(purpose.as_bytes());
    mac.update(&[0]);
    mac.update(bytes);
    format!("{:x}", mac.finalize().into_bytes())
}

fn write_server_authenticated_json<T: Serialize>(
    authenticator: &ServerStateAuthenticator,
    payload_path: &Path,
    purpose: &str,
    value: &T,
) -> anyhow::Result<()> {
    let bytes =
        serde_json::to_vec(value).context("cannot serialize authenticated server update state")?;
    write_durable_bytes(payload_path, &bytes, MAX_UPDATE_STATE_BYTES)?;
    let authentication = ServerStateAuthentication {
        schema_version: SERVER_STATE_AUTH_SCHEMA_VERSION,
        purpose: purpose.to_owned(),
        payload_sha256: sha256_bytes(&bytes),
        hmac_sha256: server_state_hmac(authenticator, purpose, &bytes),
    };
    write_durable_json(
        &server_state_authentication_path(payload_path)?,
        &authentication,
        MAX_UPDATE_STATE_BYTES,
    )
}

fn read_server_authenticated_json<T: for<'de> Deserialize<'de>>(
    authenticator: &ServerStateAuthenticator,
    payload_path: &Path,
    purpose: &str,
) -> anyhow::Result<T> {
    let bytes = read_limited_bytes(payload_path, MAX_UPDATE_STATE_BYTES)?;
    let authentication: ServerStateAuthentication = read_durable_json(
        &server_state_authentication_path(payload_path)?,
        MAX_UPDATE_STATE_BYTES,
    )?;
    anyhow::ensure!(
        authentication.schema_version == SERVER_STATE_AUTH_SCHEMA_VERSION
            && authentication.purpose == purpose
            && authentication.payload_sha256 == sha256_bytes(&bytes),
        "server update state authentication metadata is invalid"
    );
    let tag = normalize_sha256(&authentication.hmac_sha256)?;
    let expected = server_state_hmac(authenticator, purpose, &bytes);
    anyhow::ensure!(
        tag == expected,
        "server update state authentication tag mismatch"
    );
    serde_json::from_slice(&bytes).context("authenticated server update state is malformed")
}

fn remove_server_authenticated_state(payload_path: &Path) -> anyhow::Result<()> {
    remove_durable_file(payload_path)?;
    remove_durable_file(&server_state_authentication_path(payload_path)?)
}

fn server_readiness_request_path(authenticator: &ServerStateAuthenticator) -> PathBuf {
    authenticator
        .canonical_data_directory
        .join(SERVER_READY_REQUEST_NAME)
}

fn server_readiness_receipt_path(authenticator: &ServerStateAuthenticator) -> PathBuf {
    authenticator
        .canonical_data_directory
        .join(SERVER_READY_RECEIPT_NAME)
}

fn managed_file_exists(path: &Path) -> anyhow::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error)
            .with_context(|| format!("cannot inspect managed update file {}", path.display())),
    }
}

fn remove_server_authenticated_state_if_present(payload_path: &Path) -> anyhow::Result<()> {
    let authentication_path = server_state_authentication_path(payload_path)?;
    for path in [payload_path, authentication_path.as_path()] {
        if managed_file_exists(path)? {
            remove_durable_file(path)?;
        }
    }
    Ok(())
}

fn server_readiness_nonce() -> anyhow::Result<String> {
    let mut value = [0_u8; 32];
    getrandom::fill(&mut value).context("cannot generate server readiness nonce")?;
    Ok(BASE64.encode(value))
}

fn validate_server_readiness_request(
    request: &ServerReadinessRequest,
    operation_id: Uuid,
    expected_executable_sha256: &str,
    expected_version: &str,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        request.protocol_version == SERVER_READY_PROTOCOL_VERSION
            && request.operation_id == operation_id
            && request.expected_executable_sha256 == normalize_sha256(expected_executable_sha256)?
            && request.expected_version == expected_version
            && BASE64
                .decode(&request.nonce)
                .is_ok_and(|value| value.len() == 32),
        "server readiness request is not bound to the candidate update"
    );
    Ok(())
}

fn prepare_server_readiness_request(plan: &HelperPlan) -> anyhow::Result<ServerReadinessRequest> {
    anyhow::ensure!(
        plan.product == UpdateProduct::Server,
        "only a server update may prepare a readiness request"
    );
    let authenticator = server_authenticator_for_plan(plan)?.ok_or_else(|| {
        anyhow::anyhow!("server update is missing its state authenticator for readiness")
    })?;
    let request = ServerReadinessRequest {
        protocol_version: SERVER_READY_PROTOCOL_VERSION,
        operation_id: plan.operation_id,
        expected_executable_sha256: normalize_sha256(&plan.staged_sha256)?.to_owned(),
        expected_version: plan.to_version.clone(),
        nonce: server_readiness_nonce()?,
        created_unix_seconds: unix_seconds(),
    };
    let receipt_path = server_readiness_receipt_path(&authenticator);
    remove_server_authenticated_state_if_present(&receipt_path)?;
    write_server_authenticated_json(
        &authenticator,
        &server_readiness_request_path(&authenticator),
        "server-readiness-request",
        &request,
    )?;
    Ok(request)
}

fn clear_server_readiness_contract(authenticator: &ServerStateAuthenticator) -> anyhow::Result<()> {
    remove_server_authenticated_state_if_present(&server_readiness_request_path(authenticator))?;
    remove_server_authenticated_state_if_present(&server_readiness_receipt_path(authenticator))
}

/// 服务端仅在完成数据目录打开、数据库恢复、配置校验和静态监听器绑定后调用此函数。
/// 没有等待中的更新请求时返回 `Ok(false)`；一旦发现请求，则必须完成全部认证和
/// 二进制绑定校验，任何错误都会让服务启动失败而不是发布伪造的就绪状态。
pub fn publish_server_update_readiness(
    data_directory: &Path,
    executable: &Path,
    version: &str,
) -> anyhow::Result<bool> {
    let canonical_data_directory = canonicalize_update_path(data_directory)?;
    let request_path = canonical_data_directory.join(SERVER_READY_REQUEST_NAME);
    if !managed_file_exists(&request_path)? {
        return Ok(false);
    }
    let authenticator = load_server_state_authenticator(&canonical_data_directory, false)?;
    let request: ServerReadinessRequest =
        read_server_authenticated_json(&authenticator, &request_path, "server-readiness-request")?;
    let executable = canonicalize_update_path(executable)?;
    let executable_sha256 = sha256_file(&executable)?;
    let version = version.trim();
    anyhow::ensure!(
        !version.is_empty() && version.len() <= 128,
        "server readiness version is invalid"
    );
    validate_server_readiness_request(&request, request.operation_id, &executable_sha256, version)?;
    let receipt = ServerReadinessReceipt {
        protocol_version: SERVER_READY_PROTOCOL_VERSION,
        operation_id: request.operation_id,
        nonce: request.nonce,
        executable_sha256,
        version: version.to_owned(),
        ready_unix_seconds: unix_seconds(),
    };
    write_server_authenticated_json(
        &authenticator,
        &server_readiness_receipt_path(&authenticator),
        "server-readiness-receipt",
        &receipt,
    )?;
    Ok(true)
}

fn validate_server_readiness_receipt(
    request: &ServerReadinessRequest,
    receipt: &ServerReadinessReceipt,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        receipt.protocol_version == SERVER_READY_PROTOCOL_VERSION
            && receipt.operation_id == request.operation_id
            && receipt.nonce == request.nonce
            && receipt.executable_sha256 == request.expected_executable_sha256
            && receipt.version == request.expected_version,
        "server readiness receipt is not bound to the candidate update"
    );
    Ok(())
}

fn wait_for_server_business_readiness_with<F, G>(
    request: &ServerReadinessRequest,
    timeout: Duration,
    poll_interval: Duration,
    stable_polls_required: usize,
    mut service_runtime: F,
    mut receipt: G,
) -> anyhow::Result<()>
where
    F: FnMut() -> anyhow::Result<ServiceRuntime>,
    G: FnMut() -> anyhow::Result<Option<ServerReadinessReceipt>>,
{
    anyhow::ensure!(
        stable_polls_required > 0,
        "server readiness stable-poll count must be positive"
    );
    let deadline = std::time::Instant::now() + timeout;
    let mut stable_polls = 0;
    loop {
        anyhow::ensure!(
            service_runtime()? == ServiceRuntime::Running,
            "candidate service stopped before publishing an authenticated readiness receipt"
        );
        if let Some(receipt) = receipt()? {
            validate_server_readiness_receipt(request, &receipt)?;
            stable_polls += 1;
            if stable_polls >= stable_polls_required {
                return Ok(());
            }
        } else {
            stable_polls = 0;
        }
        anyhow::ensure!(
            std::time::Instant::now() < deadline,
            "candidate server did not publish an authenticated business-readiness receipt within {} seconds",
            timeout.as_secs()
        );
        sleep(poll_interval);
    }
}

/// 将候选服务交接的时间参数和可替换的系统调用收拢为单一上下文，避免测试辅助函数
/// 的参数列表扩张后掩盖交接阶段真正依赖的边界。
struct ServerCandidateHandoffContext<R, S, P> {
    timeout: Duration,
    poll_interval: Duration,
    stable_polls_required: usize,
    restart_service: R,
    service_runtime: S,
    receipt: P,
}

fn execute_server_candidate_handoff_with<R, S, P>(
    plan: &HelperPlan,
    plan_sha256: &str,
    backup: &Path,
    context: ServerCandidateHandoffContext<R, S, P>,
) -> anyhow::Result<()>
where
    R: FnMut() -> anyhow::Result<()>,
    S: FnMut() -> anyhow::Result<ServiceRuntime>,
    P: FnMut() -> anyhow::Result<Option<ServerReadinessReceipt>>,
{
    let ServerCandidateHandoffContext {
        timeout,
        poll_interval,
        stable_polls_required,
        mut restart_service,
        service_runtime,
        receipt,
    } = context;
    anyhow::ensure!(
        server_candidate_service_handoff_required(plan),
        "server candidate handoff requires an installed service that was running before the update"
    );
    // 服务一旦启动就可能开始接收写请求。先写入已认证的业务就绪请求和不确定性
    // 交接阶段；任何断电或就绪超时都会转为人工恢复，而不是把候选写入自动回滚掉。
    let request = prepare_server_readiness_request(plan)?;
    write_operation_journal(plan, plan_sha256, "candidate_starting", Some(backup), None)?;
    restart_service()?;
    write_operation_journal(plan, plan_sha256, "candidate_started", Some(backup), None)?;
    wait_for_server_business_readiness_with(
        &request,
        timeout,
        poll_interval,
        stable_polls_required,
        service_runtime,
        receipt,
    )?;
    write_operation_journal(plan, plan_sha256, "candidate_ready", Some(backup), None)
}

fn execute_server_candidate_handoff(
    plan: &HelperPlan,
    plan_sha256: &str,
    backup: &Path,
) -> anyhow::Result<()> {
    let authenticator = server_authenticator_for_plan(plan)?.ok_or_else(|| {
        anyhow::anyhow!("server update is missing its state authenticator for readiness")
    })?;
    let receipt_path = server_readiness_receipt_path(&authenticator);
    execute_server_candidate_handoff_with(
        plan,
        plan_sha256,
        backup,
        ServerCandidateHandoffContext {
            timeout: SERVER_READY_TIMEOUT,
            poll_interval: SERVER_READY_POLL_INTERVAL,
            stable_polls_required: SERVER_READY_STABLE_POLLS,
            restart_service: || restart_service_after_update(plan),
            service_runtime: || service_runtime_for_target(plan.product, &plan.target_executable),
            receipt: || {
                if !managed_file_exists(&receipt_path)? {
                    return Ok(None);
                }
                Ok(Some(read_server_authenticated_json(
                    &authenticator,
                    &receipt_path,
                    "server-readiness-receipt",
                )?))
            },
        },
    )
}

/// 验证服务数据目录和既有认证密钥已经处于可证明的受保护边界内。既有密钥
/// 不会被“先读取、后修复权限”：一旦边界不可信，必须拒绝该更新/恢复事务。
#[cfg(unix)]
fn validate_server_state_authentication_boundary(
    data_directory: &Path,
    key_path: Option<&Path>,
) -> anyhow::Result<()> {
    let expected_identity = trusted_unix_server_state_identity(data_directory)?;
    validate_server_state_authentication_boundary_with_identity(
        data_directory,
        key_path,
        expected_identity,
    )
}

/// 所有 Unix 路径都必须显式绑定一个可信身份，而不是只验证目录和密钥恰好属于同一个
/// 用户。生产中的 systemd 服务固定绑定到安装器创建的 `linklake:linklake`；便携式
/// 运行则绑定到当前有效 UID/GID，特权 helper 因此只能信任 root:root 的认证根。
#[cfg(unix)]
fn trusted_unix_server_state_identity(
    data_directory: &Path,
) -> anyhow::Result<UnixServerStateIdentity> {
    #[cfg(target_os = "linux")]
    if let Some(identity) = registered_linux_server_state_identity(data_directory)? {
        return Ok(identity);
    }

    Ok(UnixServerStateIdentity {
        uid: unsafe { libc::geteuid() },
        gid: unsafe { libc::getegid() },
    })
}

/// 只有标准安装器落盘的 systemd 契约才会把认证根绑定到 `linklake:linklake`。服务
/// 单元、EnvironmentFile 及其父目录都必须是不可由普通用户改写的 root 边界；配置
/// 的数据目录还必须与本次操作的目录相同，避免把同一主机上的便携式实例误判为服务。
#[cfg(target_os = "linux")]
fn registered_linux_server_state_identity(
    data_directory: &Path,
) -> anyhow::Result<Option<UnixServerStateIdentity>> {
    let Some(unit) = read_registered_linklake_server_systemd_unit()? else {
        return Ok(None);
    };
    if !is_official_linklake_server_systemd_unit(&unit) {
        return Ok(None);
    }

    let service_identity = UnixServerStateIdentity {
        uid: lookup_unix_user_id("linklake")?,
        gid: lookup_unix_group_id("linklake")?,
    };
    let caller_uid = unsafe { libc::geteuid() };
    // systemd 在仍为 root 时读取 0600 的 EnvironmentFile，再切换到 linklake 运行
    // 服务。候选服务进程没有权限重新读取该文件；它只接受已验证的静态服务身份，
    // 并继续对 data-dir/key 施加该身份的严格 UID/GID 校验。
    if caller_uid == service_identity.uid {
        return Ok(Some(service_identity));
    }
    anyhow::ensure!(
        caller_uid == 0,
        "registered LinkLakeServer authentication state may only be accessed by the linklake service identity or a root update helper"
    );

    let environment_path = Path::new(OFFICIAL_LINKLAKE_SERVER_ENVIRONMENT_PATH);
    let environment = read_trusted_root_owned_linux_file(
        environment_path,
        "LinkLakeServer systemd EnvironmentFile",
    )?
    .ok_or_else(|| {
        anyhow::anyhow!(
            "official LinkLakeServer systemd unit is installed but its required EnvironmentFile is missing"
        )
    })?;
    let configured_data_directory = parse_official_linklake_server_data_directory(&environment)?;
    let configured_data_directory = canonicalize_update_path(&configured_data_directory)
        .with_context(|| {
            format!(
                "cannot resolve the trusted LinkLakeServer data directory {}",
                configured_data_directory.display()
            )
        })?;
    select_registered_linux_server_state_identity(
        data_directory,
        caller_uid,
        service_identity,
        Some(&configured_data_directory),
    )
    .map(Some)
}

/// 标准 shell 安装器使用 `/etc/systemd/system`，原生 DEB/RPM 包使用
/// `/lib/systemd/system`；按 systemd 的静态覆盖优先级只采用首个已存在的受信任单元。
#[cfg(target_os = "linux")]
fn read_registered_linklake_server_systemd_unit() -> anyhow::Result<Option<String>> {
    for path in OFFICIAL_LINKLAKE_SERVER_SYSTEMD_UNIT_PATHS {
        if let Some(unit) =
            read_trusted_root_owned_linux_file(Path::new(path), "LinkLakeServer systemd unit")?
        {
            return Ok(Some(unit));
        }
    }
    Ok(None)
}

/// 已注册服务的 root helper 必须核对生效数据目录；候选服务则只能以安装器固定的
/// `linklake` 身份发布回执，不会因无法读取 root-only EnvironmentFile 而退化为
/// “信任目录当前 owner”。
#[cfg(target_os = "linux")]
fn select_registered_linux_server_state_identity(
    data_directory: &Path,
    caller_uid: libc::uid_t,
    service_identity: UnixServerStateIdentity,
    configured_data_directory: Option<&Path>,
) -> anyhow::Result<UnixServerStateIdentity> {
    if caller_uid == service_identity.uid {
        return Ok(service_identity);
    }
    anyhow::ensure!(
        caller_uid == 0,
        "registered LinkLakeServer authentication state may only be accessed by the linklake service identity or a root update helper"
    );
    let configured_data_directory = configured_data_directory.ok_or_else(|| {
        anyhow::anyhow!(
            "root LinkLakeServer update helper did not obtain the trusted service data directory"
        )
    })?;
    anyhow::ensure!(
        configured_data_directory == data_directory,
        "trusted LinkLakeServer LINKLAKE_DATA_DIR does not match the update data directory"
    );
    Ok(service_identity)
}

#[cfg(target_os = "linux")]
fn read_trusted_root_owned_linux_file(
    path: &Path,
    resource: &str,
) -> anyhow::Result<Option<String>> {
    use std::os::unix::fs::MetadataExt;

    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("cannot inspect {resource} {}", path.display()))
        }
    };
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{resource} has no parent directory"))?;
    validate_trusted_root_owned_linux_directory(parent, resource)?;
    anyhow::ensure!(
        metadata.file_type().is_file() && metadata.nlink() == 1,
        "{resource} must be a non-linked regular file"
    );
    anyhow::ensure!(
        metadata.uid() == 0 && metadata.gid() == 0 && metadata.mode() & 0o022 == 0,
        "{resource} must be root-owned and inaccessible to group or other writers"
    );
    let contents = read_limited_bytes(path, MAX_SERVER_SERVICE_CONTRACT_BYTES)
        .with_context(|| format!("cannot read {resource} {}", path.display()))?;
    String::from_utf8(contents)
        .with_context(|| format!("{resource} {} is not valid UTF-8", path.display()))
        .map(Some)
}

#[cfg(target_os = "linux")]
fn validate_trusted_root_owned_linux_directory(path: &Path, resource: &str) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt;

    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("cannot inspect the parent directory of {resource}"))?;
    anyhow::ensure!(
        metadata.file_type().is_dir()
            && metadata.uid() == 0
            && metadata.gid() == 0
            && metadata.mode() & 0o022 == 0,
        "the parent directory of {resource} must be a root-owned directory without group or other write access"
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn is_official_linklake_server_systemd_unit(unit: &str) -> bool {
    let mut in_service_section = false;
    let mut user = None;
    let mut group = None;
    let mut environment_file = None;
    for line in unit.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            in_service_section = line == "[Service]";
            continue;
        }
        if !in_service_section {
            continue;
        }
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        let duplicate = match name.trim() {
            "User" => user.replace(value).is_some(),
            "Group" => group.replace(value).is_some(),
            "EnvironmentFile" => environment_file.replace(value).is_some(),
            _ => false,
        };
        if duplicate {
            return false;
        }
    }
    user == Some("linklake")
        && group == Some("linklake")
        && environment_file == Some(OFFICIAL_LINKLAKE_SERVER_ENVIRONMENT_PATH)
}

#[cfg(target_os = "linux")]
fn parse_official_linklake_server_data_directory(environment: &str) -> anyhow::Result<PathBuf> {
    let mut data_directory = None;
    for line in environment.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let Some((name, value)) = line.split_once('=') else {
            continue;
        };
        if name.trim() != "LINKLAKE_DATA_DIR" {
            continue;
        }
        anyhow::ensure!(
            data_directory.is_none(),
            "trusted LinkLakeServer EnvironmentFile declares LINKLAKE_DATA_DIR more than once"
        );
        let value = parse_systemd_environment_literal(value)?;
        anyhow::ensure!(
            !value.is_empty() && !value.contains('\0'),
            "trusted LinkLakeServer LINKLAKE_DATA_DIR is invalid"
        );
        let value = PathBuf::from(value);
        anyhow::ensure!(
            value.is_absolute(),
            "trusted LinkLakeServer LINKLAKE_DATA_DIR must be an absolute path"
        );
        data_directory = Some(value);
    }
    data_directory.ok_or_else(|| {
        anyhow::anyhow!("trusted LinkLakeServer EnvironmentFile has no LINKLAKE_DATA_DIR")
    })
}

#[cfg(target_os = "linux")]
fn parse_systemd_environment_literal(value: &str) -> anyhow::Result<String> {
    let value = value.trim();
    let Some(quote) = value
        .chars()
        .next()
        .filter(|quote| matches!(quote, '\'' | '\"'))
    else {
        return Ok(value.to_owned());
    };
    anyhow::ensure!(
        value.len() >= quote.len_utf8() * 2 && value.ends_with(quote),
        "trusted LinkLakeServer EnvironmentFile has an unterminated quoted value"
    );
    Ok(value[quote.len_utf8()..value.len() - quote.len_utf8()].to_owned())
}

#[cfg(unix)]
fn lookup_unix_user_id(name: &str) -> anyhow::Result<libc::uid_t> {
    let name = CString::new(name).context("trusted Unix account name contains an embedded NUL")?;
    let mut buffer_size = 1024;
    loop {
        let mut entry = unsafe { std::mem::zeroed::<libc::passwd>() };
        let mut result = std::ptr::null_mut();
        let mut buffer = vec![0_i8; buffer_size];
        let status = unsafe {
            libc::getpwnam_r(
                name.as_ptr(),
                &mut entry,
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut result,
            )
        };
        if status == libc::ERANGE && buffer_size < MAX_SERVER_SERVICE_CONTRACT_BYTES as usize {
            buffer_size *= 2;
            continue;
        }
        anyhow::ensure!(
            status == 0,
            "cannot resolve trusted Unix user linklake: {}",
            std::io::Error::from_raw_os_error(status)
        );
        anyhow::ensure!(
            !result.is_null(),
            "trusted Unix user linklake does not exist"
        );
        return Ok(entry.pw_uid);
    }
}

#[cfg(unix)]
fn lookup_unix_group_id(name: &str) -> anyhow::Result<libc::gid_t> {
    let name = CString::new(name).context("trusted Unix group name contains an embedded NUL")?;
    let mut buffer_size = 1024;
    loop {
        let mut entry = unsafe { std::mem::zeroed::<libc::group>() };
        let mut result = std::ptr::null_mut();
        let mut buffer = vec![0_i8; buffer_size];
        let status = unsafe {
            libc::getgrnam_r(
                name.as_ptr(),
                &mut entry,
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut result,
            )
        };
        if status == libc::ERANGE && buffer_size < MAX_SERVER_SERVICE_CONTRACT_BYTES as usize {
            buffer_size *= 2;
            continue;
        }
        anyhow::ensure!(
            status == 0,
            "cannot resolve trusted Unix group linklake: {}",
            std::io::Error::from_raw_os_error(status)
        );
        anyhow::ensure!(
            !result.is_null(),
            "trusted Unix group linklake does not exist"
        );
        return Ok(entry.gr_gid);
    }
}

#[cfg(unix)]
fn validate_server_state_authentication_boundary_with_identity(
    data_directory: &Path,
    key_path: Option<&Path>,
    expected_identity: UnixServerStateIdentity,
) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt;

    let directory = fs::symlink_metadata(data_directory).with_context(|| {
        format!(
            "cannot inspect the server update authentication data directory {}",
            data_directory.display()
        )
    })?;
    anyhow::ensure!(
        directory.file_type().is_dir(),
        "server update authentication data directory is not a regular directory"
    );
    anyhow::ensure!(
        directory.uid() == expected_identity.uid && directory.gid() == expected_identity.gid,
        "server update authentication data directory must be owned by the trusted server identity {}:{}",
        expected_identity.uid,
        expected_identity.gid
    );
    anyhow::ensure!(
        directory.mode() & 0o022 == 0,
        "server update authentication data directory grants group or other write access; repair its ownership and mode before updating"
    );

    let Some(key_path) = key_path else {
        return Ok(());
    };
    let key = fs::symlink_metadata(key_path).with_context(|| {
        format!(
            "cannot inspect the server update authentication key {}",
            key_path.display()
        )
    })?;
    anyhow::ensure!(
        key.file_type().is_file() && key.nlink() == 1,
        "server update authentication key must be a non-linked regular file"
    );
    anyhow::ensure!(
        key.uid() == expected_identity.uid && key.gid() == expected_identity.gid,
        "server update authentication key must be owned by the trusted server identity {}:{}",
        expected_identity.uid,
        expected_identity.gid
    );
    anyhow::ensure!(
        key.mode() & 0o7777 == 0o600,
        "server update authentication key must have mode 0600"
    );
    Ok(())
}

/// Windows 安装器将服务数据目录设为 Administrator 所有、受保护 DACL，并只授权
/// SYSTEM、Administrators 和 LocalService。自定义目录若不满足同一边界，更新器
/// 会拒绝预置密钥，而不是在读取后悄悄收紧 ACL。
#[cfg(windows)]
fn validate_server_state_authentication_boundary(
    data_directory: &Path,
    key_path: Option<&Path>,
) -> anyhow::Result<()> {
    #[cfg(test)]
    {
        // 单元测试在非提升桌面会话中运行，无法安全模拟服务安装器的所有者转换。
        // 生产构建绝不会编译这条测试专用分支。
        let _ = (data_directory, key_path);
        Ok(())
    }

    #[cfg(not(test))]
    {
        validate_windows_server_security_descriptor(
            data_directory,
            WINDOWS_SERVER_DATA_DIRECTORY_SECURITY_DESCRIPTOR,
            "server update authentication data directory",
        )?;
        if let Some(key_path) = key_path {
            validate_windows_server_security_descriptor(
                key_path,
                WINDOWS_SERVER_AUTHENTICATION_KEY_SECURITY_DESCRIPTOR,
                "server update authentication key",
            )?;
        }
        Ok(())
    }
}

#[cfg(not(any(unix, windows)))]
fn validate_server_state_authentication_boundary(
    _data_directory: &Path,
    _key_path: Option<&Path>,
) -> anyhow::Result<()> {
    anyhow::bail!(
        "server update authentication requires a platform with verifiable local file permissions"
    )
}

#[cfg(unix)]
fn secure_server_authentication_key(path: &Path, data_directory: &Path) -> anyhow::Result<()> {
    use std::os::unix::{
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        io::AsRawFd,
    };

    let directory = fs::symlink_metadata(data_directory)?;
    anyhow::ensure!(
        directory.file_type().is_dir(),
        "server update authentication data directory is not a regular directory"
    );
    let key = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| {
            format!(
                "cannot open the new server update authentication key {}",
                path.display()
            )
        })?;
    let metadata = key.metadata()?;
    anyhow::ensure!(
        metadata.file_type().is_file() && metadata.nlink() == 1,
        "new server update authentication key must be a non-linked regular file"
    );
    let changed = unsafe {
        libc::fchown(
            key.as_raw_fd(),
            directory.uid() as libc::uid_t,
            directory.gid() as libc::gid_t,
        )
    };
    let error = std::io::Error::last_os_error();
    anyhow::ensure!(
        changed == 0,
        "cannot assign the server update authentication key to the data-directory owner: {error}"
    );
    key.set_permissions(fs::Permissions::from_mode(0o600))?;
    key.sync_all()?;
    Ok(())
}

#[cfg(windows)]
fn secure_server_authentication_key(path: &Path, _data_directory: &Path) -> anyhow::Result<()> {
    #[cfg(test)]
    {
        let _ = path;
        Ok(())
    }

    #[cfg(not(test))]
    {
        anyhow::ensure!(
            windows_process_is_elevated()?,
            "creating a server update authentication key requires an elevated Windows administrator"
        );
        apply_windows_update_dacl(path)?;
        validate_windows_server_security_descriptor(
            path,
            WINDOWS_SERVER_AUTHENTICATION_KEY_SECURITY_DESCRIPTOR,
            "server update authentication key",
        )
    }
}

#[cfg(not(any(unix, windows)))]
fn secure_server_authentication_key(_path: &Path, _data_directory: &Path) -> anyhow::Result<()> {
    anyhow::bail!(
        "server update authentication requires a platform with verifiable local file permissions"
    )
}

#[cfg(windows)]
const WINDOWS_SERVER_DATA_DIRECTORY_SECURITY_DESCRIPTOR: &str =
    "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;0x1301bf;;;LS)(A;OICI;FA;;;BA)";
#[cfg(windows)]
const WINDOWS_SERVER_AUTHENTICATION_KEY_SECURITY_DESCRIPTOR: &str =
    "O:BAD:P(A;;FA;;;SY)(A;;FA;;;LS)(A;;FA;;;BA)";

#[cfg(windows)]
#[cfg_attr(test, allow(dead_code))]
fn validate_windows_server_security_descriptor(
    path: &Path,
    expected: &str,
    resource: &str,
) -> anyhow::Result<()> {
    let observed = windows_security_descriptor_sddl(path)?;
    anyhow::ensure!(
        windows_security_descriptor_matches(&observed, expected)?,
        "{resource} does not have the LinkLake protected ownership and DACL; repair it with the server installer before updating"
    );
    Ok(())
}

#[cfg(windows)]
fn windows_security_descriptor_matches(observed: &str, expected: &str) -> anyhow::Result<bool> {
    Ok(canonicalize_windows_security_descriptor_sddl(observed)?
        == canonicalize_windows_security_descriptor_sddl(expected)?)
}

#[cfg(windows)]
#[cfg_attr(test, allow(dead_code))]
fn windows_security_descriptor_sddl(path: &Path) -> anyhow::Result<String> {
    use std::{ffi::c_void, os::windows::ffi::OsStrExt, ptr::null_mut};
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{
            Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT},
            DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        },
    };

    let canonical = fs::canonicalize(path)
        .with_context(|| format!("cannot resolve Windows security path {}", path.display()))?;
    let encoded_path = canonical
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut descriptor: *mut c_void = null_mut();
    let status = unsafe {
        GetNamedSecurityInfoW(
            encoded_path.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        )
    };
    anyhow::ensure!(
        status == 0,
        "cannot inspect Windows security descriptor for {}: {}",
        path.display(),
        std::io::Error::from_raw_os_error(status as i32)
    );
    let result = windows_security_descriptor_to_sddl(descriptor);
    unsafe {
        LocalFree(descriptor);
    }
    result
}

#[cfg(windows)]
fn canonicalize_windows_security_descriptor_sddl(sddl: &str) -> anyhow::Result<String> {
    use std::{ffi::c_void, ptr::null_mut};
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        },
    };

    let encoded = sddl
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut descriptor: *mut c_void = null_mut();
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            encoded.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    };
    anyhow::ensure!(
        converted != 0,
        "cannot parse Windows security descriptor: {}",
        std::io::Error::last_os_error()
    );
    let result = windows_security_descriptor_to_sddl(descriptor);
    unsafe {
        LocalFree(descriptor);
    }
    result
}

#[cfg(windows)]
fn windows_security_descriptor_to_sddl(
    descriptor: *mut std::ffi::c_void,
) -> anyhow::Result<String> {
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{
            Authorization::{
                ConvertSecurityDescriptorToStringSecurityDescriptorW, SDDL_REVISION_1,
            },
            DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        },
    };

    let mut value = std::ptr::null_mut();
    let mut length = 0_u32;
    let converted = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            SDDL_REVISION_1,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut value,
            &mut length,
        )
    };
    let error = std::io::Error::last_os_error();
    let result = (|| {
        anyhow::ensure!(
            converted != 0 && !value.is_null() && length > 0,
            "cannot serialize Windows security descriptor: {error}"
        );
        let units = unsafe { std::slice::from_raw_parts(value, length as usize) };
        let used = units
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(units.len());
        String::from_utf16(&units[..used]).context("Windows security descriptor is not UTF-16")
    })();
    if !value.is_null() {
        unsafe {
            LocalFree(value.cast());
        }
    }
    result
}

fn prepare_state_directory(path: &Path) -> anyhow::Result<PathBuf> {
    let path = absolute_path(path)?;
    reject_windows_remote_update_path(&path)?;
    fs::create_dir_all(&path)?;
    secure_directory(&path)?;
    canonicalize_update_path(&path)
}

#[cfg(windows)]
fn reject_windows_remote_update_path(path: &Path) -> anyhow::Result<()> {
    let value = path.as_os_str().to_string_lossy().replace('/', "\\");
    anyhow::ensure!(
        !value.starts_with(r"\\") && !value.starts_with(r"\\?\") && !value.starts_with(r"\\.\"),
        "server update state must use a local Windows drive, not a UNC, verbatim, or device path"
    );
    Ok(())
}

#[cfg(not(windows))]
fn reject_windows_remote_update_path(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

fn absolute_path(path: &Path) -> anyhow::Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_owned())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

/// Rust 在 Windows 上经常为 `canonicalize` 返回 `\\?\` 形式。该形式只在内部
/// 解析阶段出现；在写入 durable 状态前必须还原为普通 Win32 绝对路径，避免把
/// 不可信的 verbatim/device 输入与可信的解析结果混为一谈。
fn canonicalize_update_path(path: &Path) -> anyhow::Result<PathBuf> {
    let canonical = fs::canonicalize(path)?;
    normalize_windows_canonical_path(canonical)
}

#[cfg(windows)]
fn normalize_windows_canonical_path(path: PathBuf) -> anyhow::Result<PathBuf> {
    use std::{
        ffi::OsString,
        os::windows::ffi::{OsStrExt, OsStringExt},
    };

    let units = path.as_os_str().encode_wide().collect::<Vec<_>>();
    const VERBATIM_PREFIX: [u16; 4] = [b'\\' as u16, b'\\' as u16, b'?' as u16, b'\\' as u16];
    const UNC_PREFIX: [u16; 4] = [b'U' as u16, b'N' as u16, b'C' as u16, b'\\' as u16];
    if !units.starts_with(&VERBATIM_PREFIX) {
        return Ok(path);
    }
    let suffix = &units[VERBATIM_PREFIX.len()..];
    let regular = if suffix.starts_with(&UNC_PREFIX) {
        let mut value = vec![b'\\' as u16, b'\\' as u16];
        value.extend_from_slice(&suffix[UNC_PREFIX.len()..]);
        value
    } else {
        suffix.to_vec()
    };
    anyhow::ensure!(
        !regular.is_empty(),
        "canonical Windows update path has an empty verbatim suffix"
    );
    Ok(PathBuf::from(OsString::from_wide(&regular)))
}

#[cfg(not(windows))]
fn normalize_windows_canonical_path(path: PathBuf) -> anyhow::Result<PathBuf> {
    Ok(path)
}

fn ensure_within(path: &Path, root: &Path) -> anyhow::Result<()> {
    let path = canonicalize_update_path(path)?;
    let root = canonicalize_update_path(root)?;
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
        ("macos", _) => anyhow::bail!(
            "official macOS automatic updates are unavailable because this build is not Developer ID signed"
        ),
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
    write_durable_json(
        &state_directory.join("status.json"),
        &value,
        MAX_UPDATE_STATE_BYTES,
    )
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
fn secure_directory(path: &Path) -> anyhow::Result<()> {
    apply_windows_update_dacl(path)
}

/// 对特权服务端的更新状态、帮助程序和认证密钥使用受保护 DACL。只有 SYSTEM、
/// 内置管理员和 LocalService 可访问；非提升的开发进程保留本地测试权限，但不能把
/// 该路径用于已安装服务的特权更新。
#[cfg(windows)]
fn apply_windows_update_dacl(path: &Path) -> anyhow::Result<()> {
    if !windows_process_is_elevated()? {
        return Ok(());
    }
    use std::{ffi::c_void, os::windows::ffi::OsStrExt, ptr::null_mut};
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            },
            SetFileSecurityW, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
            PROTECTED_DACL_SECURITY_INFORMATION,
        },
    };

    let canonical = fs::canonicalize(path)
        .with_context(|| format!("cannot resolve Windows update path {}", path.display()))?;
    let encoded_path = canonical
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    // SYSTEM/Administrators 执行服务生命周期操作，LocalService 负责服务启动后的
    // 更新恢复。受保护 DACL 不继承潜在的低权限父目录规则。
    let sddl = WINDOWS_SERVER_AUTHENTICATION_KEY_SECURITY_DESCRIPTOR;
    let encoded_sddl = sddl
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut descriptor: *mut c_void = null_mut();
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            encoded_sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    };
    anyhow::ensure!(
        converted != 0,
        "cannot build Windows updater DACL: {}",
        std::io::Error::last_os_error()
    );
    let applied = unsafe {
        SetFileSecurityW(
            encoded_path.as_ptr(),
            OWNER_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor,
        )
    };
    let error = std::io::Error::last_os_error();
    unsafe {
        LocalFree(descriptor);
    }
    anyhow::ensure!(
        applied != 0,
        "cannot apply Windows updater DACL to {}: {error}",
        path.display()
    );
    Ok(())
}

#[cfg(windows)]
fn windows_process_is_elevated() -> anyhow::Result<bool> {
    use std::mem::{size_of, zeroed};
    use windows_sys::Win32::{
        Foundation::CloseHandle,
        Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY},
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    let mut token = std::ptr::null_mut();
    anyhow::ensure!(
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } != 0,
        "cannot open the current process token: {}",
        std::io::Error::last_os_error()
    );
    let mut elevation: TOKEN_ELEVATION = unsafe { zeroed() };
    let mut returned = 0_u32;
    let result = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    };
    let error = std::io::Error::last_os_error();
    unsafe {
        CloseHandle(token);
    }
    anyhow::ensure!(
        result != 0 && returned == size_of::<TOKEN_ELEVATION>() as u32,
        "cannot inspect the current process token elevation: {error}"
    );
    Ok(elevation.TokenIsElevated != 0)
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

    struct ServerHandoffFixture {
        _root: tempfile::TempDir,
        state: PathBuf,
        data: PathBuf,
        database_path: PathBuf,
        plan: HelperPlan,
        plan_sha256: String,
        authenticator: ServerStateAuthenticator,
        backup: PathBuf,
    }

    fn server_handoff_fixture() -> ServerHandoffFixture {
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("state");
        let data = root.path().join("data");
        fs::create_dir_all(&state).unwrap();
        fs::create_dir_all(&data).unwrap();
        let state = canonicalize_update_path(&state).unwrap();
        let data = canonicalize_update_path(&data).unwrap();
        let database_path = data.join("linklake.sqlite3");
        fs::write(&database_path, b"handoff-candidate-database").unwrap();
        let authenticator = prepare_server_state_authenticator(&data).unwrap();
        let target_executable = root.path().join(UpdateProduct::Server.executable_name());
        fs::write(&target_executable, b"current-server-binary").unwrap();
        let target_executable = canonicalize_update_path(&target_executable).unwrap();
        let operation_id = Uuid::new_v4();
        let operation_directory = state.join("operations").join(operation_id.to_string());
        fs::create_dir_all(&operation_directory).unwrap();
        let operation_directory = canonicalize_update_path(&operation_directory).unwrap();
        let backup = state.join("backups").join("handoff-fixture");
        fs::create_dir_all(&backup).unwrap();
        let plan = HelperPlan {
            schema_version: UPDATE_SCHEMA_VERSION,
            operation_id,
            operation_directory: operation_directory.clone(),
            operation: UpdateOperation::Apply,
            product: UpdateProduct::Server,
            state_directory: state.clone(),
            target_executable,
            staged_executable: state.join("candidate-server"),
            expected_target_sha256: "a".repeat(64),
            staged_sha256: "b".repeat(64),
            from_version: "1.0.0-rc.1".to_owned(),
            to_version: "1.0.0-rc.2".to_owned(),
            service_installed: true,
            service_was_running: true,
            server_database: Some(ServerDatabaseTransaction::Rollback {
                context: ServerRollbackContext {
                    canonical_data_dir: data.clone(),
                    snapshot_metadata_path: root.path().join("missing-snapshot.json"),
                    snapshot_operation_id: Uuid::new_v4(),
                    snapshot_plan_sha256: "c".repeat(64),
                    expected_schema: 13,
                    expected_ledger_sha256: "d".repeat(64),
                    restore_snapshot: true,
                },
            }),
            created_unix_seconds: 1,
        };
        let plan_path = operation_directory.join("plan.json");
        let plan_sha256 = sha256_bytes(&serde_json::to_vec(&plan).unwrap());
        write_server_authenticated_json(&authenticator, &plan_path, "helper-plan", &plan).unwrap();
        write_server_authenticated_json(
            &authenticator,
            &state.join("active.json"),
            "active-marker",
            &ActiveUpdate {
                schema_version: UPDATE_SCHEMA_VERSION,
                operation_id,
                product: UpdateProduct::Server,
                plan_path,
                plan_sha256: plan_sha256.clone(),
                created_unix_seconds: 1,
            },
        )
        .unwrap();
        ServerHandoffFixture {
            _root: root,
            state,
            data,
            database_path,
            plan,
            plan_sha256,
            authenticator,
            backup,
        }
    }

    fn matching_server_readiness_receipt(
        authenticator: &ServerStateAuthenticator,
    ) -> anyhow::Result<ServerReadinessReceipt> {
        let request: ServerReadinessRequest = read_server_authenticated_json(
            authenticator,
            &server_readiness_request_path(authenticator),
            "server-readiness-request",
        )?;
        Ok(ServerReadinessReceipt {
            protocol_version: SERVER_READY_PROTOCOL_VERSION,
            operation_id: request.operation_id,
            nonce: request.nonce,
            executable_sha256: request.expected_executable_sha256,
            version: request.expected_version,
            ready_unix_seconds: 1,
        })
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
    fn service_runtime_parsers_preserve_transitional_states() {
        assert_eq!(
            parse_windows_sc_query_runtime(b"STATE              : 1  STOPPED\r\n"),
            ServiceRuntime::Stopped
        );
        assert_eq!(
            parse_windows_sc_query_runtime(b"STATE              : 2  START_PENDING\r\n"),
            ServiceRuntime::Transitioning
        );
        assert_eq!(
            parse_windows_sc_query_runtime(b"STATE              : 3  STOP_PENDING\r\n"),
            ServiceRuntime::Transitioning
        );
        assert_eq!(
            parse_windows_sc_query_runtime(b"STATE              : 4  RUNNING\r\n"),
            ServiceRuntime::Running
        );
        assert_eq!(
            parse_windows_sc_query_runtime(b"STATE              : 7  PAUSED\r\n"),
            ServiceRuntime::Unknown
        );
        assert_eq!(
            parse_windows_sc_query_runtime(b"malformed query output"),
            ServiceRuntime::Unknown
        );
        assert!(windows_sc_configuration_has_binary_path(
            b"BINARY_PATH_NAME   : C:\\Program Files\\LinkLake\\linklake-server.exe\r\n"
        ));
        assert!(!windows_sc_configuration_has_binary_path(
            b"malformed configuration output"
        ));

        assert_eq!(
            parse_systemd_active_runtime(b"activating\n"),
            ServiceRuntime::Transitioning
        );
        assert_eq!(
            parse_systemd_active_runtime(b"deactivating\n"),
            ServiceRuntime::Transitioning
        );
        assert_eq!(
            parse_systemd_active_runtime(b"inactive\n"),
            ServiceRuntime::Stopped
        );
        assert_eq!(
            parse_systemd_active_runtime(b"failed\n"),
            ServiceRuntime::Unknown
        );
    }

    #[test]
    fn service_lifecycle_waits_for_transitioning_and_fails_closed_for_unknown() {
        let mut stop_states = [
            ServiceRuntime::Transitioning,
            ServiceRuntime::Running,
            ServiceRuntime::Stopped,
        ]
        .into_iter();
        let mut stop_requests = 0;
        wait_for_service_stopped_with(
            Duration::from_secs(1),
            Duration::ZERO,
            true,
            || Ok(stop_states.next().unwrap_or(ServiceRuntime::Stopped)),
            || {
                stop_requests += 1;
                Ok(())
            },
            "fixture service did not stop",
        )
        .unwrap();
        assert_eq!(stop_requests, 1);

        let transition_timeout = wait_for_service_stopped_with(
            Duration::ZERO,
            Duration::ZERO,
            true,
            || Ok(ServiceRuntime::Transitioning),
            || Ok(()),
            "fixture service did not stop",
        )
        .expect_err("a transitional service must wait until timeout, never count as stopped");
        assert!(transition_timeout
            .to_string()
            .contains("fixture service did not stop"));

        let unknown = wait_for_service_stopped_with(
            Duration::from_secs(1),
            Duration::ZERO,
            true,
            || Ok(ServiceRuntime::Unknown),
            || Ok(()),
            "fixture service did not stop",
        )
        .expect_err("an unknown service state must fail closed immediately");
        assert!(unknown
            .to_string()
            .contains("cannot determine the component service state"));

        let started_after_schedule = wait_for_service_stopped_with(
            Duration::from_secs(1),
            Duration::ZERO,
            false,
            || Ok(ServiceRuntime::Running),
            || Ok(()),
            "fixture service did not stop",
        )
        .expect_err(
            "a service scheduled stopped must not be stopped after it was externally started",
        );
        assert!(started_after_schedule
            .to_string()
            .contains("started after scheduling"));

        let mut startable_states =
            [ServiceRuntime::Transitioning, ServiceRuntime::Stopped].into_iter();
        assert!(
            wait_for_service_startable_with(Duration::from_secs(1), Duration::ZERO, || Ok(
                startable_states.next().unwrap_or(ServiceRuntime::Stopped)
            ),)
            .unwrap()
        );

        let mut running_states = [
            ServiceRuntime::Transitioning,
            ServiceRuntime::Running,
            ServiceRuntime::Running,
        ]
        .into_iter();
        wait_for_service_running_with(Duration::from_secs(1), Duration::ZERO, 2, || {
            Ok(running_states.next().unwrap_or(ServiceRuntime::Running))
        })
        .unwrap();
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
    fn recovery_restore_recreates_a_target_missing_in_the_power_loss_window() {
        let root = std::env::temp_dir().join(format!("linklake-restore-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let target = root.join(if cfg!(windows) {
            "linklake-client.exe"
        } else {
            "linklake-client"
        });
        let backup = root.join("authenticated-backup");
        fs::write(&backup, b"old-client").unwrap();
        assert!(!target.exists());
        atomic_restore_with_retry(&target, &backup).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"old-client");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn server_readiness_receipt_is_bound_to_the_candidate_binary_and_version() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        let executable = root.path().join(UpdateProduct::Server.executable_name());
        fs::create_dir_all(&data).unwrap();
        fs::write(&executable, b"candidate-server").unwrap();
        let data = canonicalize_update_path(&data).unwrap();
        let executable = canonicalize_update_path(&executable).unwrap();
        let authenticator = prepare_server_state_authenticator(&data).unwrap();
        let request = ServerReadinessRequest {
            protocol_version: SERVER_READY_PROTOCOL_VERSION,
            operation_id: Uuid::new_v4(),
            expected_executable_sha256: sha256_file(&executable).unwrap(),
            expected_version: "1.0.0-rc.2".to_owned(),
            nonce: server_readiness_nonce().unwrap(),
            created_unix_seconds: 1,
        };
        let request_path = server_readiness_request_path(&authenticator);
        write_server_authenticated_json(
            &authenticator,
            &request_path,
            "server-readiness-request",
            &request,
        )
        .unwrap();

        assert!(publish_server_update_readiness(&data, &executable, "1.0.0-rc.2").unwrap());
        let receipt: ServerReadinessReceipt = read_server_authenticated_json(
            &authenticator,
            &server_readiness_receipt_path(&authenticator),
            "server-readiness-receipt",
        )
        .unwrap();
        validate_server_readiness_receipt(&request, &receipt).unwrap();
        assert!(publish_server_update_readiness(&data, &executable, "1.0.0-rc.3").is_err());

        let authentication_path = server_state_authentication_path(&request_path).unwrap();
        let mut authentication: ServerStateAuthentication =
            read_durable_json(&authentication_path, MAX_UPDATE_STATE_BYTES).unwrap();
        authentication.hmac_sha256 = "0".repeat(64);
        write_durable_json(
            &authentication_path,
            &authentication,
            MAX_UPDATE_STATE_BYTES,
        )
        .unwrap();
        let error = publish_server_update_readiness(&data, &executable, "1.0.0-rc.2")
            .expect_err("a forged readiness HMAC must be rejected");
        assert!(error.to_string().contains("authentication tag mismatch"));
    }

    #[cfg(unix)]
    #[test]
    fn server_authentication_refuses_preseeded_or_insecure_key_before_reading_it() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        fs::create_dir_all(&data).unwrap();
        fs::set_permissions(&data, fs::Permissions::from_mode(0o700)).unwrap();
        let key_path = data.join(SERVER_STATE_AUTH_KEY_NAME);
        fs::write(&key_path, [0x5a_u8; 32]).unwrap();
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644)).unwrap();

        let error = match load_server_state_authenticator(&data, false) {
            Ok(_) => panic!("a preseeded key readable by another user must be rejected before use"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("mode 0600"));
        assert_eq!(
            fs::symlink_metadata(&key_path).unwrap().mode() & 0o777,
            0o644,
            "the updater must not silently tighten a preexisting key after it may have been trusted"
        );

        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(load_server_state_authenticator(&data, false).is_ok());

        fs::set_permissions(&data, fs::Permissions::from_mode(0o770)).unwrap();
        let error = match load_server_state_authenticator(&data, false) {
            Ok(_) => {
                panic!("a group-writable data directory must not become an authentication root")
            }
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains("grants group or other write access"));
    }

    #[cfg(unix)]
    #[test]
    fn server_authentication_rejects_a_private_tree_owned_by_the_wrong_identity() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        fs::create_dir_all(&data).unwrap();
        fs::set_permissions(&data, fs::Permissions::from_mode(0o700)).unwrap();
        let key_path = data.join(SERVER_STATE_AUTH_KEY_NAME);
        fs::write(&key_path, [0x5a_u8; 32]).unwrap();
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();

        let directory = fs::symlink_metadata(&data).unwrap();
        let expected_identity = UnixServerStateIdentity {
            uid: directory.uid(),
            gid: directory.gid(),
        };
        let wrong_identity = UnixServerStateIdentity {
            uid: if expected_identity.uid == 0 { 1 } else { 0 },
            gid: expected_identity.gid,
        };
        let error = validate_server_state_authentication_boundary_with_identity(
            &data,
            Some(&key_path),
            wrong_identity,
        )
        .expect_err("a private but attacker-owned data tree must not self-authenticate");
        assert!(error
            .to_string()
            .contains("must be owned by the trusted server identity"));
    }

    #[cfg(unix)]
    #[test]
    fn root_helper_refuses_an_attacker_owned_private_data_directory_and_key() {
        use std::{
            ffi::CString,
            os::unix::{ffi::OsStrExt, fs::PermissionsExt},
        };

        if unsafe { libc::geteuid() } != 0 {
            return;
        }

        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("attacker-data");
        fs::create_dir_all(&data).unwrap();
        let key_path = data.join(SERVER_STATE_AUTH_KEY_NAME);
        fs::write(&key_path, [0x5a_u8; 32]).unwrap();
        fs::set_permissions(&data, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();

        let attacker_uid: libc::uid_t = 65_534;
        let attacker_gid: libc::gid_t = 65_534;
        for path in [&data, &key_path] {
            let path = CString::new(path.as_os_str().as_bytes()).unwrap();
            assert_eq!(
                unsafe { libc::chown(path.as_ptr(), attacker_uid, attacker_gid) },
                0,
                "test fixture must become an attacker-owned private tree"
            );
        }

        let error = match load_server_state_authenticator(&data, false) {
            Ok(_) => {
                panic!("a root helper must not trust an attacker-owned 0700 directory and key")
            }
            Err(error) => error,
        };
        assert!(error.to_string().contains("trusted server identity 0:0"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn official_systemd_contract_requires_the_static_linklake_identity_and_environment_file() {
        assert_eq!(
            OFFICIAL_LINKLAKE_SERVER_SYSTEMD_UNIT_PATHS,
            [
                "/etc/systemd/system/linklake-server.service",
                "/usr/lib/systemd/system/linklake-server.service",
                "/lib/systemd/system/linklake-server.service",
            ]
        );
        assert!(is_official_linklake_server_systemd_unit(
            "[Service]\nUser=linklake\nGroup=linklake\nEnvironmentFile=/etc/linklake/server.env\n"
        ));
        assert!(!is_official_linklake_server_systemd_unit(
            "[Service]\nUser=attacker\nGroup=linklake\nEnvironmentFile=/etc/linklake/server.env\n"
        ));
        assert!(!is_official_linklake_server_systemd_unit(
            "[Service]\nUser=linklake\nGroup=linklake\nEnvironmentFile=-/etc/linklake/server.env\n"
        ));
        assert_eq!(
            parse_official_linklake_server_data_directory(
                "LINKLAKE_DATA_DIR='/var/lib/linklake data'\n"
            )
            .unwrap(),
            PathBuf::from("/var/lib/linklake data")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn registered_service_candidate_uses_static_identity_without_reading_root_only_environment() {
        let data_directory = PathBuf::from("/var/lib/linklake");
        let other_directory = PathBuf::from("/srv/other-linklake");
        let service_identity = UnixServerStateIdentity {
            uid: 4242,
            gid: 4343,
        };

        assert_eq!(
            select_registered_linux_server_state_identity(
                &data_directory,
                service_identity.uid,
                service_identity,
                None,
            )
            .unwrap(),
            service_identity,
            "the non-root candidate service must not need to read the root-only EnvironmentFile"
        );
        assert!(select_registered_linux_server_state_identity(
            &data_directory,
            1000,
            service_identity,
            None,
        )
        .is_err());
        assert!(select_registered_linux_server_state_identity(
            &data_directory,
            0,
            service_identity,
            Some(&other_directory),
        )
        .is_err());
        assert_eq!(
            select_registered_linux_server_state_identity(
                &data_directory,
                0,
                service_identity,
                Some(&data_directory),
            )
            .unwrap(),
            service_identity
        );
    }

    #[cfg(unix)]
    #[test]
    fn newly_created_server_authentication_key_matches_the_data_directory_identity() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("data");
        fs::create_dir_all(&data).unwrap();
        fs::set_permissions(&data, fs::Permissions::from_mode(0o700)).unwrap();
        let authenticator = prepare_server_state_authenticator(&data).unwrap();
        let directory = fs::symlink_metadata(&data).unwrap();
        let key = fs::symlink_metadata(data.join(SERVER_STATE_AUTH_KEY_NAME)).unwrap();

        assert_eq!(
            authenticator.canonical_data_directory,
            canonicalize_update_path(&data).unwrap()
        );
        assert_eq!(key.uid(), directory.uid());
        assert_eq!(key.gid(), directory.gid());
        assert_eq!(key.mode() & 0o777, 0o600);
    }

    #[cfg(windows)]
    #[test]
    fn windows_server_authentication_acl_requires_protected_installer_templates() {
        assert!(windows_security_descriptor_matches(
            WINDOWS_SERVER_AUTHENTICATION_KEY_SECURITY_DESCRIPTOR,
            "O:BAD:P(A;;FA;;;SY)(A;;FA;;;LS)(A;;FA;;;BA)",
        )
        .unwrap());
        assert!(!windows_security_descriptor_matches(
            WINDOWS_SERVER_AUTHENTICATION_KEY_SECURITY_DESCRIPTOR,
            "O:BAD:(A;;FA;;;SY)(A;;FA;;;LS)(A;;FA;;;BA)",
        )
        .unwrap());
        assert!(!windows_security_descriptor_matches(
            WINDOWS_SERVER_AUTHENTICATION_KEY_SECURITY_DESCRIPTOR,
            "O:SYD:P(A;;FA;;;SY)(A;;FA;;;LS)(A;;FA;;;BA)",
        )
        .unwrap());
        assert!(!windows_security_descriptor_matches(
            WINDOWS_SERVER_DATA_DIRECTORY_SECURITY_DESCRIPTOR,
            WINDOWS_SERVER_AUTHENTICATION_KEY_SECURITY_DESCRIPTOR,
        )
        .unwrap());
    }

    #[test]
    fn server_readiness_wait_requires_stable_matching_receipts_and_times_out_closed() {
        let request = ServerReadinessRequest {
            protocol_version: SERVER_READY_PROTOCOL_VERSION,
            operation_id: Uuid::new_v4(),
            expected_executable_sha256: "a".repeat(64),
            expected_version: "1.0.0-rc.2".to_owned(),
            nonce: server_readiness_nonce().unwrap(),
            created_unix_seconds: 1,
        };
        let matching = ServerReadinessReceipt {
            protocol_version: SERVER_READY_PROTOCOL_VERSION,
            operation_id: request.operation_id,
            nonce: request.nonce.clone(),
            executable_sha256: request.expected_executable_sha256.clone(),
            version: request.expected_version.clone(),
            ready_unix_seconds: 1,
        };
        let mut running = [ServiceRuntime::Running, ServiceRuntime::Running].into_iter();
        let mut receipts = [Some(matching.clone()), Some(matching.clone())].into_iter();
        wait_for_server_business_readiness_with(
            &request,
            Duration::from_secs(1),
            Duration::ZERO,
            2,
            || Ok(running.next().unwrap_or(ServiceRuntime::Running)),
            || Ok(receipts.next().unwrap_or(None)),
        )
        .unwrap();

        for receipt in [
            ServerReadinessReceipt {
                nonce: "forged-nonce".to_owned(),
                ..matching.clone()
            },
            ServerReadinessReceipt {
                version: "1.0.0-rc.3".to_owned(),
                ..matching.clone()
            },
            ServerReadinessReceipt {
                executable_sha256: "b".repeat(64),
                ..matching.clone()
            },
        ] {
            assert!(wait_for_server_business_readiness_with(
                &request,
                Duration::ZERO,
                Duration::ZERO,
                1,
                || Ok(ServiceRuntime::Running),
                || Ok(Some(receipt.clone())),
            )
            .is_err());
        }

        let timeout = wait_for_server_business_readiness_with(
            &request,
            Duration::ZERO,
            Duration::ZERO,
            1,
            || Ok(ServiceRuntime::Running),
            || Ok(None),
        )
        .expect_err("a missing receipt must time out instead of accepting Running alone");
        assert!(timeout.to_string().contains("within 0 seconds"));
        assert!(wait_for_server_business_readiness_with(
            &request,
            Duration::ZERO,
            Duration::ZERO,
            1,
            || Ok(ServiceRuntime::Stopped),
            || Ok(Some(matching.clone())),
        )
        .is_err());
    }

    #[test]
    fn service_handoff_receipt_failures_require_manual_recovery_without_database_rollback() {
        for failure in [
            "missing",
            "forged",
            "wrong_nonce",
            "wrong_hash",
            "wrong_version",
        ] {
            let fixture = server_handoff_fixture();
            let database_sha256 = sha256_file(&fixture.database_path).unwrap();
            let authenticator = fixture.authenticator.clone();
            let receipt_path = server_readiness_receipt_path(&authenticator);
            let mut starts = 0;
            let error = execute_server_candidate_handoff_with(
                &fixture.plan,
                &fixture.plan_sha256,
                &fixture.backup,
                ServerCandidateHandoffContext {
                    timeout: Duration::ZERO,
                    poll_interval: Duration::ZERO,
                    stable_polls_required: 1,
                    restart_service: || {
                        starts += 1;
                        Ok(())
                    },
                    service_runtime: || Ok(ServiceRuntime::Running),
                    receipt: || {
                        if failure == "missing" {
                            return Ok(None);
                        }
                        let mut receipt = matching_server_readiness_receipt(&authenticator)?;
                        match failure {
                            "forged" => {
                                write_server_authenticated_json(
                                    &authenticator,
                                    &receipt_path,
                                    "server-readiness-receipt",
                                    &receipt,
                                )?;
                                let authentication_path =
                                    server_state_authentication_path(&receipt_path)?;
                                let mut authentication: ServerStateAuthentication =
                                    read_durable_json(
                                        &authentication_path,
                                        MAX_UPDATE_STATE_BYTES,
                                    )?;
                                authentication.hmac_sha256 = "0".repeat(64);
                                write_durable_json(
                                    &authentication_path,
                                    &authentication,
                                    MAX_UPDATE_STATE_BYTES,
                                )?;
                            }
                            "wrong_nonce" => receipt.nonce = "wrong-nonce".to_owned(),
                            "wrong_hash" => receipt.executable_sha256 = "c".repeat(64),
                            "wrong_version" => receipt.version = "1.0.0-rc.3".to_owned(),
                            _ => unreachable!("covered failure kind"),
                        }
                        if failure != "forged" {
                            write_server_authenticated_json(
                                &authenticator,
                                &receipt_path,
                                "server-readiness-receipt",
                                &receipt,
                            )?;
                        }
                        Ok(Some(read_server_authenticated_json(
                            &authenticator,
                            &receipt_path,
                            "server-readiness-receipt",
                        )?))
                    },
                },
            )
            .expect_err("each invalid candidate receipt must fail the real handoff path");
            assert_eq!(starts, 1, "candidate service must have been started once");
            match failure {
                "missing" => assert!(error.to_string().contains("within 0 seconds")),
                "forged" => assert!(error.to_string().contains("authentication tag mismatch")),
                _ => assert!(error
                    .to_string()
                    .contains("receipt is not bound to the candidate update")),
            }
            let journal: UpdateJournal = read_server_authenticated_json(
                &fixture.authenticator,
                &fixture.plan.operation_directory.join("journal.json"),
                "operation-journal",
            )
            .unwrap();
            assert_eq!(journal.stage, "candidate_started");

            let mut candidate_stops = 0;
            assert_eq!(
                server_handoff_failure_route_with(
                    &fixture.plan,
                    Some(&fixture.authenticator),
                    || {
                        candidate_stops += 1;
                        Ok(())
                    },
                )
                .unwrap(),
                ServerHandoffFailureRoute::ManualRecoveryRequired,
            );
            assert_eq!(candidate_stops, 1);
            assert_eq!(
                sha256_file(&fixture.database_path).unwrap(),
                database_sha256
            );

            // 生产 helper 会在候选停止后把事务推进为 recovery_required；默认恢复
            // 对这一最终人工恢复状态也必须保持数据库不变。
            write_operation_journal(
                &fixture.plan,
                &fixture.plan_sha256,
                "recovery_required",
                Some(&fixture.backup),
                Some("candidate readiness validation failed".to_owned()),
            )
            .unwrap();

            let recovery = server_recover(
                &fixture.state,
                &fixture.data,
                true,
                ServerRecoveryConsent::default(),
            )
            .expect_err("candidate handoff recovery must require explicit data-loss consent");
            assert!(recovery
                .to_string()
                .contains("restore-after-candidate-handoff"));
            assert!(fixture.state.join("active.json").exists());
            assert_eq!(
                sha256_file(&fixture.database_path).unwrap(),
                database_sha256
            );
        }
    }

    #[test]
    fn pre_handoff_failure_remains_eligible_for_automatic_rollback() {
        let fixture = server_handoff_fixture();
        write_operation_journal(
            &fixture.plan,
            &fixture.plan_sha256,
            "backup_created",
            Some(&fixture.backup),
            None,
        )
        .unwrap();
        let mut candidate_stops = 0;
        let route =
            server_handoff_failure_route_with(&fixture.plan, Some(&fixture.authenticator), || {
                candidate_stops += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(route, ServerHandoffFailureRoute::AutomaticRollbackEligible);
        assert_eq!(candidate_stops, 0);
    }

    #[test]
    fn candidate_handoff_gate_keeps_pre_handoff_failures_eligible_for_automatic_rollback() {
        assert!(!is_server_candidate_handoff_stage("backup_created"));
        assert!(!is_server_candidate_handoff_stage("database_preflight"));
        assert!(is_server_candidate_handoff_stage("candidate_starting"));
        assert!(is_server_candidate_handoff_stage("candidate_started"));
        assert!(is_server_candidate_handoff_stage("candidate_ready"));
    }

    #[test]
    fn candidate_handoff_recovery_requires_explicit_data_loss_consent() {
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("state");
        let data = root.path().join("data");
        fs::create_dir_all(&state).unwrap();
        fs::create_dir_all(&data).unwrap();
        let state = canonicalize_update_path(&state).unwrap();
        let data = canonicalize_update_path(&data).unwrap();
        let database_path = data.join("linklake.sqlite3");
        fs::write(
            &database_path,
            b"candidate-handoff-database-before-recovery",
        )
        .unwrap();
        let database_sha256 = sha256_file(&database_path).unwrap();
        let authenticator = prepare_server_state_authenticator(&data).unwrap();
        let target_executable = root.path().join(UpdateProduct::Server.executable_name());
        fs::write(&target_executable, b"test-server").unwrap();
        let target_executable = canonicalize_update_path(&target_executable).unwrap();
        let operation_id = Uuid::new_v4();
        let operation_directory = state.join("operations").join(operation_id.to_string());
        fs::create_dir_all(&operation_directory).unwrap();
        let operation_directory = canonicalize_update_path(&operation_directory).unwrap();
        let plan = HelperPlan {
            schema_version: UPDATE_SCHEMA_VERSION,
            operation_id,
            operation_directory: operation_directory.clone(),
            operation: UpdateOperation::Apply,
            product: UpdateProduct::Server,
            state_directory: state.clone(),
            target_executable,
            staged_executable: state.join("staging-server.exe"),
            expected_target_sha256: "a".repeat(64),
            staged_sha256: "b".repeat(64),
            from_version: "1.0.0-rc.1".to_owned(),
            to_version: "1.0.0-rc.2".to_owned(),
            service_installed: true,
            service_was_running: true,
            server_database: Some(ServerDatabaseTransaction::Rollback {
                context: ServerRollbackContext {
                    canonical_data_dir: data.clone(),
                    snapshot_metadata_path: root.path().join("snapshot.json"),
                    snapshot_operation_id: Uuid::new_v4(),
                    snapshot_plan_sha256: "c".repeat(64),
                    expected_schema: 13,
                    expected_ledger_sha256: "d".repeat(64),
                    restore_snapshot: true,
                },
            }),
            created_unix_seconds: 1,
        };
        let plan_path = operation_directory.join("plan.json");
        let plan_sha256 = sha256_bytes(&serde_json::to_vec(&plan).unwrap());
        write_server_authenticated_json(&authenticator, &plan_path, "helper-plan", &plan).unwrap();
        write_server_authenticated_json(
            &authenticator,
            &state.join("active.json"),
            "active-marker",
            &ActiveUpdate {
                schema_version: UPDATE_SCHEMA_VERSION,
                operation_id,
                product: UpdateProduct::Server,
                plan_path,
                plan_sha256: plan_sha256.clone(),
                created_unix_seconds: 1,
            },
        )
        .unwrap();
        assert!(server_candidate_service_handoff_required(&plan));
        let mut stopped_plan = plan.clone();
        stopped_plan.service_was_running = false;
        assert!(!server_candidate_service_handoff_required(&stopped_plan));
        write_operation_journal(&plan, &plan_sha256, "backup_created", None, None).unwrap();
        assert!(
            !server_candidate_handoff_started(&plan, &authenticator).unwrap(),
            "failures before the candidate handoff remain eligible for automatic rollback"
        );
        write_operation_journal(&plan, &plan_sha256, "candidate_started", None, None).unwrap();
        assert!(server_candidate_handoff_started(&plan, &authenticator).unwrap());

        let error = server_recover(&state, &data, true, ServerRecoveryConsent::default())
            .expect_err("candidate handoff recovery must require explicit data-loss consent");
        assert!(error
            .to_string()
            .contains("restore-after-candidate-handoff"));
        assert!(state.join("active.json").exists());
        assert_eq!(sha256_file(&database_path).unwrap(), database_sha256);
        let explicit = server_recover(
            &state,
            &data,
            true,
            ServerRecoveryConsent {
                restore_after_candidate_handoff: true,
                confirm_data_loss: true,
            },
        )
        .expect_err(
            "fixture has no authenticated backup, but explicit consent must pass the handoff gate",
        );
        assert!(!explicit
            .to_string()
            .contains("restore-after-candidate-handoff"));
    }

    #[test]
    fn server_recovery_clears_only_an_authenticated_terminal_marker() {
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("state");
        let data = root.path().join("data");
        fs::create_dir_all(&state).unwrap();
        fs::create_dir_all(&data).unwrap();
        let state = canonicalize_update_path(&state).unwrap();
        let data = canonicalize_update_path(&data).unwrap();
        let authenticator = prepare_server_state_authenticator(&data).unwrap();
        let target_executable = root.path().join(UpdateProduct::Server.executable_name());
        fs::write(&target_executable, b"test-server").unwrap();
        let target_executable = canonicalize_update_path(&target_executable).unwrap();
        let operation_id = Uuid::new_v4();
        let operations = state.join("operations");
        fs::create_dir_all(&operations).unwrap();
        let operation_directory = operations.join(operation_id.to_string());
        fs::create_dir(&operation_directory).unwrap();
        let operation_directory = canonicalize_update_path(&operation_directory).unwrap();
        let plan = HelperPlan {
            schema_version: UPDATE_SCHEMA_VERSION,
            operation_id,
            operation_directory: operation_directory.clone(),
            operation: UpdateOperation::Apply,
            product: UpdateProduct::Server,
            state_directory: state.clone(),
            target_executable,
            staged_executable: state.join("staging-server.exe"),
            expected_target_sha256: "a".repeat(64),
            staged_sha256: "b".repeat(64),
            from_version: "1.0.0-rc.1".to_owned(),
            to_version: "1.0.0-rc.2".to_owned(),
            service_installed: false,
            service_was_running: false,
            server_database: Some(ServerDatabaseTransaction::Rollback {
                context: ServerRollbackContext {
                    canonical_data_dir: data.clone(),
                    snapshot_metadata_path: root.path().join("snapshot.json"),
                    snapshot_operation_id: Uuid::new_v4(),
                    snapshot_plan_sha256: "c".repeat(64),
                    expected_schema: 13,
                    expected_ledger_sha256: "d".repeat(64),
                    restore_snapshot: true,
                },
            }),
            created_unix_seconds: 1,
        };
        let plan_path = operation_directory.join("plan.json");
        let plan_bytes = serde_json::to_vec(&plan).unwrap();
        let plan_sha256 = sha256_bytes(&plan_bytes);
        write_server_authenticated_json(&authenticator, &plan_path, "helper-plan", &plan).unwrap();
        write_server_authenticated_json(
            &authenticator,
            &state.join("active.json"),
            "active-marker",
            &ActiveUpdate {
                schema_version: UPDATE_SCHEMA_VERSION,
                operation_id,
                product: UpdateProduct::Server,
                plan_path: plan_path.clone(),
                plan_sha256: plan_sha256.clone(),
                created_unix_seconds: 1,
            },
        )
        .unwrap();
        write_operation_journal(&plan, &plan_sha256, "completed", None, None).unwrap();

        let recovered =
            server_recover(&state, &data, true, ServerRecoveryConsent::default()).unwrap();
        assert_eq!(recovered.state, "idle");
        assert!(!state.join("active.json").exists());
    }

    #[test]
    fn server_recovery_keeps_an_unauthenticated_interrupted_marker_for_manual_repair() {
        let root = tempfile::tempdir().unwrap();
        let state = root.path().join("state");
        let data = root.path().join("data");
        fs::create_dir_all(&state).unwrap();
        fs::create_dir_all(&data).unwrap();
        let state = canonicalize_update_path(&state).unwrap();
        let data = canonicalize_update_path(&data).unwrap();
        let _authenticator = prepare_server_state_authenticator(&data).unwrap();
        let operation_id = Uuid::new_v4();
        let operation_directory = state.join("operations").join(operation_id.to_string());
        fs::create_dir_all(&operation_directory).unwrap();
        let operation_directory = canonicalize_update_path(&operation_directory).unwrap();
        let plan = HelperPlan {
            schema_version: UPDATE_SCHEMA_VERSION,
            operation_id,
            operation_directory: operation_directory.clone(),
            operation: UpdateOperation::Apply,
            product: UpdateProduct::Server,
            state_directory: state.clone(),
            target_executable: root.path().join("missing-linklake-server.exe"),
            staged_executable: state.join("staging-server.exe"),
            expected_target_sha256: "a".repeat(64),
            staged_sha256: "b".repeat(64),
            from_version: "1.0.0-rc.1".to_owned(),
            to_version: "1.0.0-rc.2".to_owned(),
            service_installed: false,
            service_was_running: false,
            server_database: Some(ServerDatabaseTransaction::Rollback {
                context: ServerRollbackContext {
                    canonical_data_dir: data.clone(),
                    snapshot_metadata_path: root.path().join("snapshot.json"),
                    snapshot_operation_id: Uuid::new_v4(),
                    snapshot_plan_sha256: "c".repeat(64),
                    expected_schema: 13,
                    expected_ledger_sha256: "d".repeat(64),
                    restore_snapshot: true,
                },
            }),
            created_unix_seconds: 1,
        };
        let plan_path = operation_directory.join("plan.json");
        let plan_bytes = serde_json::to_vec(&plan).unwrap();
        let plan_sha256 = sha256_bytes(&plan_bytes);
        write_durable_json(&plan_path, &plan, MAX_UPDATE_STATE_BYTES).unwrap();
        write_durable_json(
            &state.join("active.json"),
            &ActiveUpdate {
                schema_version: UPDATE_SCHEMA_VERSION,
                operation_id,
                product: UpdateProduct::Server,
                plan_path,
                plan_sha256: plan_sha256.clone(),
                created_unix_seconds: 1,
            },
            MAX_UPDATE_STATE_BYTES,
        )
        .unwrap();
        write_operation_journal(&plan, &plan_sha256, "scheduled", None, None).unwrap();

        assert!(server_recover(&state, &data, true, ServerRecoveryConsent::default()).is_err());
        assert!(state.join("active.json").exists());
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
