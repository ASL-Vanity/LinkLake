//! LinkLake 服务端的完整灾难恢复实现。
//!
//! 完整备份只包含 SQLite 在线快照、ACME 状态和托管证书。备份先生成受限 TAR，
//! 再使用 Argon2id 和分块 XChaCha20-Poly1305 加密；恢复在完全认证、解包和校验后
//! 才会替换当前数据，并始终要求独占服务端数据库锁。

use anyhow::{Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chacha20poly1305::{
    aead::{AeadInOut, KeyInit},
    Tag, XChaCha20Poly1305, XNonce,
};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{database_migrations, database_tools};

const MAGIC: &[u8; 8] = b"LLBKUP01";
const FORMAT_NAME: &str = "linklake-full-backup";
const FORMAT_VERSION: u16 = 1;
const MANIFEST_NAME: &str = "linklake-full-backup-manifest";
const MANIFEST_VERSION: u16 = 1;
const KDF_NAME: &str = "argon2id";
const KDF_VERSION: u32 = 0x13;
const KDF_MEMORY_KIB: u32 = 19_456;
const KDF_ITERATIONS: u32 = 2;
const KDF_PARALLELISM: u32 = 1;
const CIPHER_NAME: &str = "xchacha20poly1305-chunked";
const SALT_LEN: usize = 16;
const NONCE_PREFIX_LEN: usize = 20;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;
const CHUNK_SIZE: usize = 64 * 1024;
const HEADER_MAX_BYTES: usize = 64 * 1024;
const MANIFEST_MAX_BYTES: u64 = 4 * 1024 * 1024;
const MAX_FILE_COUNT: usize = 10_000;
const MAX_DIRECTORY_COUNT: usize = 10_000;
const MAX_TAR_ENTRY_COUNT: usize = 1 + MAX_FILE_COUNT + MAX_DIRECTORY_COUNT;
const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_ARCHIVE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_CERTIFICATE_CHAIN_BYTES: u64 = 4 * 1024 * 1024;
const MAX_PRIVATE_KEY_BYTES: u64 = 1024 * 1024;
const MAX_LOGICAL_PATH_BYTES: usize = 1024;
const MAX_PATH_DEPTH: usize = 64;
const MAX_COMPONENT_BYTES: usize = 255;
const MAX_SOURCE_VERSION_BYTES: usize = 128;
const RECORD_DATA: u8 = 1;
const RECORD_END: u8 = 0;
const RECORD_HEADER_LEN: usize = 1 + 4 + 4;
const RESTORE_JOURNAL_NAME: &str = "linklake.restore-journal";
const MAINTENANCE_LOCK_NAME: &str = "linklake.backup-restore.lock";
const RESTORE_JOURNAL_MAGIC: &[u8; 8] = b"LLRSTJ01";
const RESTORE_JOURNAL_VERSION: u16 = 1;
const RESTORE_COMMIT_MARKER: &[u8; 4] = b"CMT1";
const RESTORE_ROLLED_BACK_MARKER: &[u8; 4] = b"RBK1";
const BACKUP_STAGING_PREFIX: &str = ".linklake-backup-staging-";
const RESTORE_STAGING_PREFIX: &str = ".linklake-restore-staging-";
#[cfg(windows)]
const WINDOWS_MANAGED_FILE_SDDL: &str = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;LS)(A;;FA;;;OW)";
#[cfg(windows)]
const WINDOWS_EXTERNAL_FILE_SDDL: &str = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)";
#[cfg(windows)]
const WINDOWS_MANAGED_DIRECTORY_SDDL: &str =
    "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;LS)(A;OICI;FA;;;OW)";
pub(crate) const MIN_PASSWORD_BYTES: usize = 16;
pub(crate) const MAX_PASSWORD_BYTES: usize = 4096;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupHeader {
    format: String,
    format_version: u16,
    created_at_unix_seconds: u64,
    source_version: String,
    kdf: KdfHeader,
    cipher: CipherHeader,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KdfHeader {
    algorithm: String,
    version: u32,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    salt_base64: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CipherHeader {
    algorithm: String,
    chunk_size: u32,
    nonce_prefix_base64: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupManifest {
    format: String,
    format_version: u16,
    source_version: String,
    created_at_unix_seconds: u64,
    directories: Vec<String>,
    files: Vec<ManifestFile>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestFile {
    path: String,
    length: u64,
    sha256: String,
}

#[derive(Debug)]
struct ExtractedFile {
    length: u64,
    sha256: String,
}

#[derive(Debug)]
struct ValidatedPayload {
    root: PathBuf,
    source_version: String,
    file_count: usize,
    total_bytes: u64,
    has_acme: bool,
    has_certificates: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreJournal {
    format_version: u16,
    operation_id: String,
    staging_directory: String,
    preserved_directory: String,
    #[serde(default = "default_true")]
    manage_acme: bool,
    #[serde(default = "default_true")]
    manage_certificates: bool,
    has_acme: bool,
    has_certificates: bool,
}

const fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RestoreJournalState {
    Prepared,
    Committed,
    RolledBack,
}

#[derive(Debug)]
pub(crate) struct FullBackupReport {
    pub(crate) output: PathBuf,
    pub(crate) file_count: usize,
    pub(crate) plaintext_bytes: u64,
}

#[derive(Debug)]
pub(crate) struct FullRestoreReport {
    pub(crate) input: PathBuf,
    pub(crate) source_version: String,
    pub(crate) file_count: usize,
    pub(crate) plaintext_bytes: u64,
    pub(crate) preserved_paths: Vec<PathBuf>,
}

/// 持有此值期间，其他 LinkLake 服务端不能打开同一个持久化数据库。
pub(crate) struct OfflineDataDirectory {
    path: PathBuf,
    _lock: File,
}

pub(crate) struct MaintenanceGuard {
    _lock: File,
    exclusive: bool,
}

impl OfflineDataDirectory {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

struct TemporaryDirectory {
    path: PathBuf,
    activity_lock: Option<File>,
    cleanup_on_drop: bool,
}

struct PendingFile {
    path: PathBuf,
    armed: bool,
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy)]
struct ManagedOwnership {
    uid: u32,
    gid: u32,
}

#[cfg(not(unix))]
#[derive(Debug, Clone, Copy)]
struct ManagedOwnership;

impl PendingFile {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for PendingFile {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

impl TemporaryDirectory {
    fn create_in(parent: &Path, prefix: &str) -> Result<Self> {
        fs::create_dir_all(parent)
            .with_context(|| format!("cannot create temporary parent {}", parent.display()))?;
        for _ in 0..16 {
            let path = parent.join(format!(".{prefix}-{}", Uuid::new_v4()));
            match fs::create_dir(&path) {
                Ok(()) => {
                    restrict_directory_permissions(&path)?;
                    let activity_path = path.join(".active.lock");
                    let activity_lock = create_managed_new_file(&activity_path)?;
                    activity_lock.try_lock_exclusive()?;
                    return Ok(Self {
                        path,
                        activity_lock: Some(activity_lock),
                        cleanup_on_drop: true,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("cannot create temporary directory {}", path.display())
                    });
                }
            }
        }
        anyhow::bail!("cannot allocate a unique temporary directory")
    }

    fn preserve_on_drop(&mut self) {
        self.cleanup_on_drop = false;
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        self.activity_lock.take();
        if self.cleanup_on_drop {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

pub(crate) fn acquire_offline_data_directory(data_dir: &Path) -> Result<OfflineDataDirectory> {
    let path = resolve_existing_data_directory(data_dir)?;

    let lock_path = path.join("linklake.sqlite3.lock");
    let mut lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .with_context(|| format!("cannot open LinkLake process lock {}", lock_path.display()))?;
    restrict_file_permissions(&lock_path)?;
    lock.try_lock_exclusive().map_err(|error| {
        anyhow::anyhow!(
            "LinkLake server must be stopped before restore; {} is locked: {error}",
            path.join("linklake.sqlite3").display()
        )
    })?;
    lock.set_len(0)?;
    writeln!(lock, "maintenance_pid={}", std::process::id())?;
    lock.sync_data()?;
    Ok(OfflineDataDirectory { path, _lock: lock })
}

pub(crate) fn acquire_backup_maintenance(data_dir: &Path) -> Result<MaintenanceGuard> {
    let guard = acquire_maintenance(data_dir, false)?;
    anyhow::ensure!(
        !data_dir.join(RESTORE_JOURNAL_NAME).exists(),
        "cannot start LinkLake backup while an interrupted or unfinalized restore journal exists"
    );
    Ok(guard)
}

pub(crate) fn acquire_restore_maintenance(data_dir: &Path) -> Result<MaintenanceGuard> {
    acquire_maintenance(data_dir, true)
}

fn acquire_maintenance(data_dir: &Path, exclusive: bool) -> Result<MaintenanceGuard> {
    let path = data_dir.join(MAINTENANCE_LOCK_NAME);
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)
        .with_context(|| format!("cannot open backup/restore lock {}", path.display()))?;
    restrict_file_permissions(&path)?;
    let result = if exclusive {
        FileExt::try_lock_exclusive(&lock)
    } else {
        FileExt::try_lock_shared(&lock)
    };
    result.map_err(|error| {
        let operation = if exclusive { "restore" } else { "backup" };
        anyhow::anyhow!(
            "cannot start LinkLake {operation} while another backup or restore is active: {error}"
        )
    })?;
    Ok(MaintenanceGuard {
        _lock: lock,
        exclusive,
    })
}

pub(crate) fn backup_full(
    data_dir: &Path,
    output_path: &Path,
    password: &[u8],
) -> Result<FullBackupReport> {
    require_password(password)?;
    let data_dir = resolve_existing_data_directory(data_dir)?;
    let _maintenance = acquire_backup_maintenance(&data_dir)?;
    let output_path = prepare_output_path(&data_dir, output_path)?;
    cleanup_stale_staging(&data_dir, BACKUP_STAGING_PREFIX)?;
    let temporary_root = TemporaryDirectory::create_in(&data_dir, "linklake-backup-staging")?;
    let payload_root = temporary_root.path.join("payload");
    fs::create_dir(&payload_root)?;
    restrict_directory_permissions(&payload_root)?;

    let created_at = unix_seconds();
    let mut directories = Vec::new();
    let mut files = Vec::new();
    let mut total_bytes = 0_u64;
    let mut portable_paths = BTreeSet::new();
    let mut enumerated_entries = 0_usize;

    let database = data_dir.join("linklake.sqlite3");
    let database_metadata = safe_symlink_metadata(&database)?;
    reject_reparse_point(&database, &database_metadata)?;
    anyhow::ensure!(
        database_metadata.is_file(),
        "LinkLake database is not a regular file: {}",
        database.display()
    );
    reject_hard_link(&database, &database_metadata)?;
    let database_snapshot = payload_root.join("linklake.sqlite3");
    database_tools::backup_managed(&database, &database_snapshot)?;
    let (length, sha256) = hash_file(&database_snapshot)?;
    validate_single_file_length(length)?;
    add_total_bytes(&mut total_bytes, length)?;
    files.push(ManifestFile {
        path: "linklake.sqlite3".into(),
        length,
        sha256,
    });

    {
        let mut collection = ManagedCollection {
            directories: &mut directories,
            files: &mut files,
            total_bytes: &mut total_bytes,
            portable_paths: &mut portable_paths,
            enumerated_entries: &mut enumerated_entries,
        };
        for root_name in ["acme", "certificates"] {
            let source = data_dir.join(root_name);
            match fs::symlink_metadata(&source) {
                Ok(_) => {
                    collect_directory(&source, root_name, &payload_root, &mut collection)?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("cannot inspect managed path {}", source.display())
                    });
                }
            }
        }
    }
    normalize_certificate_snapshot(&payload_root, &mut directories, &mut files)?;
    total_bytes = files.iter().try_fold(0_u64, |total, file| {
        total
            .checked_add(file.length)
            .ok_or_else(|| anyhow::anyhow!("backup payload is too large"))
    })?;
    anyhow::ensure!(
        total_bytes <= MAX_ARCHIVE_BYTES,
        "backup payload is too large"
    );
    anyhow::ensure!(
        files.len() <= MAX_FILE_COUNT,
        "backup contains too many files"
    );
    anyhow::ensure!(
        directories.len() <= MAX_DIRECTORY_COUNT,
        "backup contains too many directories"
    );
    directories.sort();
    files.sort_by(|left, right| left.path.cmp(&right.path));

    let manifest = BackupManifest {
        format: MANIFEST_NAME.into(),
        format_version: MANIFEST_VERSION,
        source_version: env!("CARGO_PKG_VERSION").into(),
        created_at_unix_seconds: created_at,
        directories,
        files,
    };
    let manifest_path = payload_root.join("manifest.json");
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    anyhow::ensure!(
        manifest_bytes.len() as u64 <= MANIFEST_MAX_BYTES,
        "backup manifest is too large"
    );
    write_new_file(&manifest_path, &manifest_bytes)?;

    let tar_path = temporary_root.path.join("payload.tar");
    create_tar_archive(&payload_root, &manifest, &tar_path)?;
    let tar_length = fs::metadata(&tar_path)?.len();
    anyhow::ensure!(
        tar_length <= MAX_ARCHIVE_BYTES,
        "backup archive is too large"
    );

    encrypt_and_install_archive(&tar_path, &output_path, password, created_at)?;

    Ok(FullBackupReport {
        output: output_path,
        file_count: manifest.files.len(),
        plaintext_bytes: total_bytes,
    })
}

fn encrypt_and_install_archive(
    input_path: &Path,
    output_path: &Path,
    password: &[u8],
    created_at: u64,
) -> Result<()> {
    let encrypted_temporary = temporary_sibling(output_path, "encrypt");
    let mut pending_encrypted = PendingFile::new(encrypted_temporary.clone());
    encrypt_archive(input_path, &encrypted_temporary, password, created_at)?;
    install_no_replace(&encrypted_temporary, output_path)?;
    pending_encrypted.disarm();
    restrict_external_backup_permissions(output_path)?;
    sync_parent(output_path.parent().unwrap_or_else(|| Path::new(".")))?;
    Ok(())
}

pub(crate) fn backup_database(data_dir: &Path, output_path: &Path) -> Result<PathBuf> {
    let data_dir = resolve_existing_data_directory(data_dir)?;
    let _maintenance = acquire_backup_maintenance(&data_dir)?;
    let output_path = prepare_output_path(&data_dir, output_path)?;
    database_tools::backup(&data_dir.join("linklake.sqlite3"), &output_path)?;
    Ok(output_path)
}

struct ManagedCollection<'a> {
    directories: &'a mut Vec<String>,
    files: &'a mut Vec<ManifestFile>,
    total_bytes: &'a mut u64,
    portable_paths: &'a mut BTreeSet<String>,
    enumerated_entries: &'a mut usize,
}

fn collect_directory(
    source: &Path,
    logical: &str,
    payload_root: &Path,
    collection: &mut ManagedCollection<'_>,
) -> Result<()> {
    let metadata = safe_symlink_metadata(source)?;
    anyhow::ensure!(
        metadata.is_dir(),
        "managed path is not a directory: {}",
        source.display()
    );
    reject_reparse_point(source, &metadata)?;
    anyhow::ensure!(
        collection.directories.len() < MAX_DIRECTORY_COUNT,
        "backup contains too many directories"
    );
    anyhow::ensure!(
        collection
            .portable_paths
            .insert(logical.to_ascii_lowercase()),
        "managed state contains paths that collide on a case-insensitive platform"
    );
    collection.directories.push(logical.to_owned());
    let destination_directory = logical_destination(payload_root, logical)?;
    fs::create_dir_all(&destination_directory)?;
    restrict_directory_permissions(&destination_directory)?;

    let mut entries = Vec::new();
    for entry in fs::read_dir(source)
        .with_context(|| format!("cannot enumerate managed directory {}", source.display()))?
    {
        *collection.enumerated_entries = collection
            .enumerated_entries
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("managed state contains too many entries"))?;
        anyhow::ensure!(
            *collection.enumerated_entries <= MAX_TAR_ENTRY_COUNT,
            "managed state contains too many entries"
        );
        entries.push(entry?);
    }
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("managed path contains a non-UTF-8 file name"))?;
        validate_component(&name)?;
        // 证书和 ACME 写入使用点号前缀的暂存/回滚文件；它们不是已提交托管状态。
        if name.starts_with('.') {
            continue;
        }
        let child_source = entry.path();
        let child_logical = format!("{logical}/{name}");
        let child_metadata = safe_symlink_metadata(&child_source)?;
        reject_reparse_point(&child_source, &child_metadata)?;
        if child_metadata.is_dir() {
            if is_certificate_generations_directory(logical)
                && !committed_certificate_generation_is_valid(&child_source)?
            {
                continue;
            }
            collect_directory(&child_source, &child_logical, payload_root, collection)?;
        } else if child_metadata.is_file() {
            anyhow::ensure!(
                collection.files.len() < MAX_FILE_COUNT,
                "backup contains too many files"
            );
            validate_single_file_length(child_metadata.len()).with_context(|| {
                format!("managed file is too large: {}", child_source.display())
            })?;
            anyhow::ensure!(
                collection
                    .portable_paths
                    .insert(child_logical.to_ascii_lowercase()),
                "managed state contains paths that collide on a case-insensitive platform"
            );
            reject_hard_link(&child_source, &child_metadata)?;
            let destination = logical_destination(payload_root, &child_logical)?;
            let remaining = MAX_ARCHIVE_BYTES
                .checked_sub(*collection.total_bytes)
                .ok_or_else(|| anyhow::anyhow!("backup payload is too large"))?;
            let (length, sha256) =
                copy_file_and_hash(&child_source, &destination, remaining.min(MAX_FILE_BYTES))?;
            add_total_bytes(collection.total_bytes, length)?;
            collection.files.push(ManifestFile {
                path: child_logical,
                length,
                sha256,
            });
        } else {
            anyhow::bail!(
                "managed path is not a regular file or directory: {}",
                child_source.display()
            );
        }
    }
    Ok(())
}

fn is_certificate_generations_directory(logical: &str) -> bool {
    let mut components = logical.split('/');
    components.next() == Some("certificates")
        && components.next().is_some()
        && components.next() == Some(crate::certificate_manager::CERTIFICATE_GENERATIONS_DIRECTORY)
        && components.next().is_none()
}

fn committed_certificate_generation_is_valid(directory: &Path) -> Result<bool> {
    let marker = read_bounded_managed_file(
        &directory.join("committed"),
        crate::certificate_manager::CERTIFICATE_COMMIT_MARKER.len() as u64,
    )?;
    if marker.as_deref() != Some(crate::certificate_manager::CERTIFICATE_COMMIT_MARKER) {
        return Ok(false);
    }
    let Some(certificate) = read_bounded_managed_file(
        &directory.join("fullchain.pem"),
        MAX_CERTIFICATE_CHAIN_BYTES,
    )?
    else {
        return Ok(false);
    };
    let Some(private_key) =
        read_bounded_managed_file(&directory.join("private-key.pem"), MAX_PRIVATE_KEY_BYTES)?
    else {
        return Ok(false);
    };
    Ok(
        crate::certificate_manager::validate_certificate_key_pair(&certificate, &private_key)
            .is_ok(),
    )
}

fn read_bounded_managed_file(path: &Path, limit: u64) -> Result<Option<Vec<u8>>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("cannot inspect managed file {}", path.display()));
        }
    };
    reject_reparse_point(path, &metadata)?;
    if !metadata.is_file() || metadata.len() > limit {
        return Ok(None);
    }
    reject_hard_link(path, &metadata)?;
    let mut contents = Vec::with_capacity(metadata.len() as usize);
    File::open(path)?
        .take(limit.saturating_add(1))
        .read_to_end(&mut contents)?;
    if contents.len() as u64 != metadata.len() {
        return Ok(None);
    }
    Ok(Some(contents))
}

fn normalize_certificate_snapshot(
    payload_root: &Path,
    directories: &mut Vec<String>,
    files: &mut Vec<ManifestFile>,
) -> Result<()> {
    let certificates = payload_root.join("certificates");
    let host_entries = match fs::read_dir(&certificates) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("cannot inspect staged certificates"),
    };

    for host_entry in host_entries {
        let host_entry = host_entry?;
        if !host_entry.file_type()?.is_dir() {
            continue;
        }
        let hostname = host_entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("certificate hostname is not UTF-8"))?;
        let host_directory = host_entry.path();
        let generations =
            host_directory.join(crate::certificate_manager::CERTIFICATE_GENERATIONS_DIRECTORY);
        let mut valid_generation_count = 0_usize;
        if let Ok(generation_entries) = fs::read_dir(&generations) {
            for generation_entry in generation_entries {
                let generation_entry = generation_entry?;
                let generation_name = generation_entry
                    .file_name()
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("certificate generation name is not UTF-8"))?;
                let generation_path = generation_entry.path();
                let logical = format!(
                    "certificates/{hostname}/{}/{}",
                    crate::certificate_manager::CERTIFICATE_GENERATIONS_DIRECTORY,
                    generation_name
                );
                if generation_entry.file_type()?.is_dir()
                    && committed_certificate_generation_is_valid(&generation_path)?
                {
                    valid_generation_count = valid_generation_count.saturating_add(1);
                    continue;
                }
                if generation_entry.file_type()?.is_dir() {
                    fs::remove_dir_all(&generation_path)?;
                } else {
                    fs::remove_file(&generation_path)?;
                }
                remove_manifest_prefix(directories, files, &logical);
            }
        }

        let certificate_path = host_directory.join("fullchain.pem");
        let private_key_path = host_directory.join("private-key.pem");
        if valid_generation_count > 0 {
            for (path, logical) in [
                (
                    &certificate_path,
                    format!("certificates/{hostname}/fullchain.pem"),
                ),
                (
                    &private_key_path,
                    format!("certificates/{hostname}/private-key.pem"),
                ),
            ] {
                match fs::remove_file(path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
                remove_manifest_prefix(directories, files, &logical);
            }
            continue;
        }

        let certificate =
            read_bounded_managed_file(&certificate_path, MAX_CERTIFICATE_CHAIN_BYTES)?;
        let private_key = read_bounded_managed_file(&private_key_path, MAX_PRIVATE_KEY_BYTES)?;
        match (certificate, private_key) {
            (None, None) => {}
            (Some(certificate), Some(private_key)) => {
                crate::certificate_manager::validate_certificate_key_pair(
                    &certificate,
                    &private_key,
                )
                .with_context(|| {
                    format!("legacy certificate and private key do not match for {hostname}")
                })?;
            }
            _ => anyhow::bail!("legacy certificate state is incomplete for {hostname}"),
        }
    }
    Ok(())
}

fn remove_manifest_prefix(
    directories: &mut Vec<String>,
    files: &mut Vec<ManifestFile>,
    prefix: &str,
) {
    let nested_prefix = format!("{prefix}/");
    directories.retain(|path| path != prefix && !path.starts_with(&nested_prefix));
    files.retain(|file| file.path != prefix && !file.path.starts_with(&nested_prefix));
}

fn create_tar_archive(
    payload_root: &Path,
    manifest: &BackupManifest,
    tar_path: &Path,
) -> Result<()> {
    let tar_file = create_managed_new_file(tar_path)?;
    let writer = BufWriter::new(tar_file);
    let mut builder = tar::Builder::new(writer);

    append_tar_file(
        &mut builder,
        &payload_root.join("manifest.json"),
        "manifest.json",
        manifest.created_at_unix_seconds,
    )?;
    for directory in &manifest.directories {
        append_tar_directory(&mut builder, directory, manifest.created_at_unix_seconds)?;
    }
    for file in &manifest.files {
        append_tar_file(
            &mut builder,
            &logical_destination(payload_root, &file.path)?,
            &file.path,
            manifest.created_at_unix_seconds,
        )?;
    }
    builder.finish()?;
    let mut writer = builder.into_inner()?;
    writer.flush()?;
    writer.get_ref().sync_all()?;
    Ok(())
}

fn append_tar_directory<W: Write>(
    builder: &mut tar::Builder<W>,
    logical: &str,
    modified: u64,
) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Directory);
    header.set_size(0);
    header.set_mode(0o700);
    header.set_mtime(modified);
    header.set_cksum();
    builder.append_data(&mut header, logical, std::io::empty())?;
    Ok(())
}

fn append_tar_file<W: Write>(
    builder: &mut tar::Builder<W>,
    source: &Path,
    logical: &str,
    modified: u64,
) -> Result<()> {
    let mut source_file = File::open(source)?;
    let metadata = source_file.metadata()?;
    anyhow::ensure!(metadata.is_file(), "TAR source is not a regular file");
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_size(metadata.len());
    header.set_mode(0o600);
    header.set_mtime(modified);
    header.set_cksum();
    builder.append_data(&mut header, logical, &mut source_file)?;
    Ok(())
}

fn encrypt_archive(
    input_path: &Path,
    output_path: &Path,
    password: &[u8],
    created_at: u64,
) -> Result<()> {
    let mut salt = [0_u8; SALT_LEN];
    let mut nonce_prefix = [0_u8; NONCE_PREFIX_LEN];
    getrandom::fill(&mut salt).map_err(|_| anyhow::anyhow!("secure randomness unavailable"))?;
    getrandom::fill(&mut nonce_prefix)
        .map_err(|_| anyhow::anyhow!("secure randomness unavailable"))?;
    let header = BackupHeader {
        format: FORMAT_NAME.into(),
        format_version: FORMAT_VERSION,
        created_at_unix_seconds: created_at,
        source_version: env!("CARGO_PKG_VERSION").into(),
        kdf: KdfHeader {
            algorithm: KDF_NAME.into(),
            version: KDF_VERSION,
            memory_kib: KDF_MEMORY_KIB,
            iterations: KDF_ITERATIONS,
            parallelism: KDF_PARALLELISM,
            salt_base64: STANDARD.encode(salt),
        },
        cipher: CipherHeader {
            algorithm: CIPHER_NAME.into(),
            chunk_size: CHUNK_SIZE as u32,
            nonce_prefix_base64: STANDARD.encode(nonce_prefix),
        },
    };
    let header_bytes = serde_json::to_vec(&header)?;
    anyhow::ensure!(
        header_bytes.len() <= HEADER_MAX_BYTES,
        "backup header is too large"
    );
    let header_length = u32::try_from(header_bytes.len())?;
    let aad_prefix = associated_data_prefix(header_length, &header_bytes);
    let key = derive_key(password, &salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| anyhow::anyhow!("unsupported backup cipher"))?;

    let input = File::open(input_path)?;
    let mut reader = BufReader::new(input);
    let output = create_external_backup_new_file(output_path)?;
    let mut writer = BufWriter::new(output);
    writer.write_all(MAGIC)?;
    writer.write_all(&header_length.to_le_bytes())?;
    writer.write_all(&header_bytes)?;

    let mut counter = 0_u32;
    let mut buffer = vec![0_u8; CHUNK_SIZE];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let plaintext_length = u32::try_from(read)?;
        let record_header = record_header(RECORD_DATA, counter, plaintext_length);
        let aad = record_associated_data(&aad_prefix, &record_header);
        let nonce_bytes = chunk_nonce(&nonce_prefix, counter);
        let nonce = XNonce::try_from(nonce_bytes.as_slice()).expect("fixed nonce length");
        let tag = cipher
            .encrypt_inout_detached(&nonce, &aad, (&mut buffer[..read]).into())
            .map_err(|_| anyhow::anyhow!("backup encryption failed"))?;
        writer.write_all(&record_header)?;
        writer.write_all(&buffer[..read])?;
        writer.write_all(tag.as_ref())?;
        counter = counter
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("backup contains too many encrypted chunks"))?;
    }

    let record_header = record_header(RECORD_END, counter, 0);
    let aad = record_associated_data(&aad_prefix, &record_header);
    let nonce_bytes = chunk_nonce(&nonce_prefix, counter);
    let nonce = XNonce::try_from(nonce_bytes.as_slice()).expect("fixed nonce length");
    let mut empty = [];
    let tag = cipher
        .encrypt_inout_detached(&nonce, &aad, (&mut empty[..]).into())
        .map_err(|_| anyhow::anyhow!("backup encryption failed"))?;
    writer.write_all(&record_header)?;
    writer.write_all(tag.as_ref())?;
    writer.flush()?;
    writer.get_ref().sync_all()?;
    Ok(())
}

pub(crate) fn restore_full(
    data_dir: &Path,
    input_path: &Path,
    password: &[u8],
) -> Result<FullRestoreReport> {
    require_password(password)?;
    let offline = acquire_offline_data_directory(data_dir)?;
    let maintenance = acquire_restore_maintenance(offline.path())?;
    recover_interrupted_restore(offline.path(), &maintenance)?;
    let input_path = resolve_external_archive_path(offline.path(), input_path, true)?;
    let mut temporary_root =
        TemporaryDirectory::create_in(offline.path(), "linklake-restore-staging")?;
    let tar_path = temporary_root.path.join("payload.tar");
    let header = decrypt_archive(&input_path, &tar_path, password)?;
    let unpacked = temporary_root.path.join("unpacked");
    fs::create_dir(&unpacked)?;
    restrict_directory_permissions(&unpacked)?;
    let payload = extract_and_validate_tar(&tar_path, &unpacked, &header)?;
    let preserved_paths =
        match apply_validated_payload(offline.path(), &temporary_root.path, &payload, true, true) {
            Ok(paths) => paths,
            Err(error) => {
                if offline.path().join(RESTORE_JOURNAL_NAME).exists() {
                    temporary_root.preserve_on_drop();
                }
                return Err(error);
            }
        };

    Ok(FullRestoreReport {
        input: input_path,
        source_version: payload.source_version,
        file_count: payload.file_count,
        plaintext_bytes: payload.total_bytes,
        preserved_paths,
    })
}

pub(crate) fn restore_database(data_dir: &Path, input_path: &Path) -> Result<Option<PathBuf>> {
    let offline = acquire_offline_data_directory(data_dir)?;
    let maintenance = acquire_restore_maintenance(offline.path())?;
    recover_interrupted_restore(offline.path(), &maintenance)?;
    let input_path = resolve_external_archive_path(offline.path(), input_path, true)?;
    let mut temporary_root =
        TemporaryDirectory::create_in(offline.path(), "linklake-restore-staging")?;
    let unpacked = temporary_root.path.join("unpacked");
    fs::create_dir(&unpacked)?;
    restrict_directory_permissions(&unpacked)?;
    let database_path = unpacked.join("linklake.sqlite3");
    database_tools::stage_restore(&input_path, &database_path)?;
    database_migrations::migrate_restore_candidate(&unpacked)?;
    let database_bytes = fs::metadata(&database_path)?.len();
    validate_single_file_length(database_bytes)?;
    let payload = ValidatedPayload {
        root: unpacked,
        source_version: env!("CARGO_PKG_VERSION").into(),
        file_count: 1,
        total_bytes: database_bytes,
        has_acme: false,
        has_certificates: false,
    };
    let preserved =
        match apply_validated_payload(offline.path(), &temporary_root.path, &payload, false, false)
        {
            Ok(paths) => paths,
            Err(error) => {
                if offline.path().join(RESTORE_JOURNAL_NAME).exists() {
                    temporary_root.preserve_on_drop();
                }
                return Err(error);
            }
        };
    Ok(preserved
        .first()
        .map(|directory| directory.join("linklake.sqlite3")))
}

fn decrypt_archive(input_path: &Path, output_path: &Path, password: &[u8]) -> Result<BackupHeader> {
    let encrypted_length = fs::metadata(input_path)?.len();
    anyhow::ensure!(
        encrypted_length <= MAX_ARCHIVE_BYTES + 64 * 1024 * 1024,
        "encrypted backup is too large"
    );
    let input = File::open(input_path)?;
    let mut reader = BufReader::new(input);
    let mut magic = [0_u8; MAGIC.len()];
    read_exact_backup(&mut reader, &mut magic)?;
    anyhow::ensure!(magic == *MAGIC, "backup format is invalid or unsupported");

    let mut header_length_bytes = [0_u8; 4];
    read_exact_backup(&mut reader, &mut header_length_bytes)?;
    let header_length = u32::from_le_bytes(header_length_bytes);
    anyhow::ensure!(
        header_length > 0 && header_length as usize <= HEADER_MAX_BYTES,
        "backup header is malformed"
    );
    let mut header_bytes = vec![0_u8; header_length as usize];
    read_exact_backup(&mut reader, &mut header_bytes)?;
    let header: BackupHeader =
        serde_json::from_slice(&header_bytes).context("backup header is malformed")?;
    validate_header(&header)?;
    let salt = decode_fixed::<SALT_LEN>(&header.kdf.salt_base64, "salt")?;
    let nonce_prefix =
        decode_fixed::<NONCE_PREFIX_LEN>(&header.cipher.nonce_prefix_base64, "nonce prefix")?;
    let key = derive_key(password, &salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| anyhow::anyhow!("unsupported backup cipher"))?;
    let aad_prefix = associated_data_prefix(header_length, &header_bytes);

    let output = create_managed_new_file(output_path)?;
    let mut writer = BufWriter::new(output);
    let mut expected_counter = 0_u32;
    let mut total_plaintext = 0_u64;
    loop {
        let mut record = [0_u8; RECORD_HEADER_LEN];
        read_exact_backup(&mut reader, &mut record)?;
        let record_type = record[0];
        let counter = u32::from_le_bytes(record[1..5].try_into().expect("fixed counter slice"));
        let length = u32::from_le_bytes(record[5..9].try_into().expect("fixed length slice"));
        anyhow::ensure!(
            counter == expected_counter,
            "backup chunk sequence is invalid"
        );
        anyhow::ensure!(length as usize <= CHUNK_SIZE, "backup chunk is too large");
        let aad = record_associated_data(&aad_prefix, &record);
        let nonce_bytes = chunk_nonce(&nonce_prefix, counter);
        let nonce = XNonce::try_from(nonce_bytes.as_slice()).expect("fixed nonce length");

        match record_type {
            RECORD_DATA => {
                anyhow::ensure!(length > 0, "backup data chunk is empty");
                let mut ciphertext = vec![0_u8; length as usize];
                let mut tag_bytes = [0_u8; TAG_LEN];
                read_exact_backup(&mut reader, &mut ciphertext)?;
                read_exact_backup(&mut reader, &mut tag_bytes)?;
                let tag = Tag::try_from(tag_bytes.as_slice()).expect("fixed tag length");
                cipher
                    .decrypt_inout_detached(&nonce, &aad, (&mut ciphertext[..]).into(), &tag)
                    .map_err(|_| anyhow::anyhow!("backup authentication failed"))?;
                total_plaintext = total_plaintext
                    .checked_add(length as u64)
                    .ok_or_else(|| anyhow::anyhow!("decrypted backup is too large"))?;
                anyhow::ensure!(
                    total_plaintext <= MAX_ARCHIVE_BYTES,
                    "decrypted backup is too large"
                );
                writer.write_all(&ciphertext)?;
                expected_counter = expected_counter
                    .checked_add(1)
                    .ok_or_else(|| anyhow::anyhow!("backup contains too many chunks"))?;
            }
            RECORD_END => {
                anyhow::ensure!(length == 0, "backup terminator is malformed");
                let tag_bytes = read_tag(&mut reader)?;
                let tag = Tag::try_from(tag_bytes.as_slice()).expect("fixed tag length");
                let mut empty = [];
                cipher
                    .decrypt_inout_detached(&nonce, &aad, (&mut empty[..]).into(), &tag)
                    .map_err(|_| anyhow::anyhow!("backup authentication failed"))?;
                let mut trailing = [0_u8; 1];
                anyhow::ensure!(
                    reader.read(&mut trailing)? == 0,
                    "backup contains trailing bytes"
                );
                break;
            }
            _ => anyhow::bail!("backup contains an unknown record type"),
        }
    }
    writer.flush()?;
    writer.get_ref().sync_all()?;
    Ok(header)
}

fn validate_header(header: &BackupHeader) -> Result<()> {
    anyhow::ensure!(
        header.format == FORMAT_NAME,
        "backup format is invalid or unsupported"
    );
    anyhow::ensure!(
        header.format_version == FORMAT_VERSION,
        "unsupported backup format version {}",
        header.format_version
    );
    validate_source_version(&header.source_version)?;
    anyhow::ensure!(
        header.kdf.algorithm == KDF_NAME
            && header.kdf.version == KDF_VERSION
            && header.kdf.memory_kib == KDF_MEMORY_KIB
            && header.kdf.iterations == KDF_ITERATIONS
            && header.kdf.parallelism == KDF_PARALLELISM,
        "backup uses an unsupported key derivation configuration"
    );
    anyhow::ensure!(
        header.cipher.algorithm == CIPHER_NAME && header.cipher.chunk_size == CHUNK_SIZE as u32,
        "backup uses an unsupported cipher configuration"
    );
    Ok(())
}

fn validate_source_version(value: &str) -> Result<semver::Version> {
    anyhow::ensure!(
        !value.is_empty() && value.len() <= MAX_SOURCE_VERSION_BYTES && value == value.trim(),
        "backup source version is malformed"
    );
    let source = semver::Version::parse(value).context("backup source version is malformed")?;
    let current = semver::Version::parse(env!("CARGO_PKG_VERSION"))
        .expect("the LinkLake package version must be valid semantic versioning");
    anyhow::ensure!(
        source <= current,
        "backup was created by newer LinkLake version {source}; current version is {current}"
    );
    Ok(source)
}

fn extract_and_validate_tar(
    tar_path: &Path,
    unpacked: &Path,
    header: &BackupHeader,
) -> Result<ValidatedPayload> {
    let tar_file = File::open(tar_path)?;
    let mut archive = tar::Archive::new(BufReader::new(tar_file));
    let mut seen = BTreeSet::new();
    let mut extracted_directories = BTreeSet::new();
    let mut extracted_files = BTreeMap::new();
    let mut manifest_path = None;
    let mut total_bytes = 0_u64;
    let mut entry_count = 0_usize;

    for entry in archive.entries()? {
        let mut entry = entry?;
        entry_count += 1;
        anyhow::ensure!(
            entry_count <= MAX_TAR_ENTRY_COUNT,
            "backup contains too many entries"
        );
        let path = entry.path()?.into_owned();
        let logical = normalize_archive_path(&path)?;
        let collision_key = logical.to_ascii_lowercase();
        anyhow::ensure!(
            seen.insert(collision_key),
            "backup contains duplicate paths"
        );
        let entry_type = entry.header().entry_type();

        if entry_type.is_dir() {
            anyhow::ensure!(
                is_allowed_directory(&logical),
                "backup contains a forbidden directory"
            );
            anyhow::ensure!(entry.size() == 0, "backup directory entry has data");
            let destination = logical_destination(unpacked, &logical)?;
            fs::create_dir_all(&destination)?;
            restrict_directory_permissions(&destination)?;
            extracted_directories.insert(logical);
            continue;
        }

        anyhow::ensure!(
            entry_type.is_file(),
            "backup contains links or special files"
        );
        let is_manifest = logical == "manifest.json";
        anyhow::ensure!(
            is_manifest || is_allowed_file(&logical),
            "backup contains a forbidden file"
        );
        let length = entry.size();
        if is_manifest {
            anyhow::ensure!(length <= MANIFEST_MAX_BYTES, "backup manifest is too large");
        } else {
            validate_single_file_length(length)?;
        }
        total_bytes = total_bytes
            .checked_add(length)
            .ok_or_else(|| anyhow::anyhow!("backup payload is too large"))?;
        anyhow::ensure!(
            total_bytes <= MAX_ARCHIVE_BYTES,
            "backup payload is too large"
        );

        let destination = logical_destination(unpacked, &logical)?;
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
            restrict_directory_permissions(parent)?;
        }
        let (actual_length, sha256) = write_tar_entry(&mut entry, &destination)?;
        anyhow::ensure!(
            actual_length == length,
            "backup file length is inconsistent"
        );
        if is_manifest {
            manifest_path = Some(destination);
        } else {
            extracted_files.insert(
                logical,
                ExtractedFile {
                    length: actual_length,
                    sha256,
                },
            );
        }
    }

    let manifest_path =
        manifest_path.ok_or_else(|| anyhow::anyhow!("backup manifest is missing"))?;
    let manifest_bytes = fs::read(&manifest_path)?;
    let manifest: BackupManifest =
        serde_json::from_slice(&manifest_bytes).context("backup manifest is malformed")?;
    validate_manifest(&manifest, header, &extracted_directories, &extracted_files)?;
    let database_path = unpacked.join("linklake.sqlite3");
    database_tools::validate_database(&database_path)?;
    database_migrations::validate_restore_database(&database_path)?;
    database_migrations::migrate_restore_candidate(unpacked)?;

    let payload_bytes = extracted_files.values().try_fold(0_u64, |total, file| {
        total
            .checked_add(file.length)
            .ok_or_else(|| anyhow::anyhow!("backup payload is too large"))
    })?;
    Ok(ValidatedPayload {
        root: unpacked.to_path_buf(),
        source_version: manifest.source_version,
        file_count: extracted_files.len(),
        total_bytes: payload_bytes,
        has_acme: extracted_directories.contains("acme"),
        has_certificates: extracted_directories.contains("certificates"),
    })
}

fn validate_manifest(
    manifest: &BackupManifest,
    header: &BackupHeader,
    extracted_directories: &BTreeSet<String>,
    extracted_files: &BTreeMap<String, ExtractedFile>,
) -> Result<()> {
    anyhow::ensure!(
        manifest.format == MANIFEST_NAME,
        "backup manifest format is invalid"
    );
    anyhow::ensure!(
        manifest.format_version == MANIFEST_VERSION,
        "unsupported backup manifest version {}",
        manifest.format_version
    );
    anyhow::ensure!(
        manifest.source_version == header.source_version
            && manifest.created_at_unix_seconds == header.created_at_unix_seconds,
        "backup manifest does not match its authenticated header"
    );
    anyhow::ensure!(
        manifest.files.len() <= MAX_FILE_COUNT,
        "backup contains too many files"
    );
    anyhow::ensure!(
        manifest.directories.len() <= MAX_DIRECTORY_COUNT,
        "backup contains too many directories"
    );

    let mut manifest_directories = BTreeSet::new();
    let mut portable_directories = BTreeSet::new();
    for directory in &manifest.directories {
        anyhow::ensure!(
            normalize_logical_path(directory)? == *directory,
            "manifest path is not normalized"
        );
        anyhow::ensure!(
            is_allowed_directory(directory),
            "manifest contains a forbidden directory"
        );
        anyhow::ensure!(
            portable_directories.insert(directory.to_ascii_lowercase()),
            "manifest contains duplicate directories"
        );
        manifest_directories.insert(directory.clone());
    }
    anyhow::ensure!(
        &manifest_directories == extracted_directories,
        "backup directory manifest does not match the archive"
    );

    let mut manifest_files = BTreeSet::new();
    let mut portable_files = BTreeSet::new();
    for file in &manifest.files {
        anyhow::ensure!(
            normalize_logical_path(&file.path)? == file.path,
            "manifest path is not normalized"
        );
        anyhow::ensure!(
            is_allowed_file(&file.path),
            "manifest contains a forbidden file"
        );
        validate_single_file_length(file.length)?;
        anyhow::ensure!(
            is_lower_hex_sha256(&file.sha256),
            "manifest contains an invalid SHA-256"
        );
        anyhow::ensure!(
            portable_files.insert(file.path.to_ascii_lowercase()),
            "manifest contains duplicate files"
        );
        let extracted = extracted_files
            .get(&file.path)
            .ok_or_else(|| anyhow::anyhow!("manifest references a missing file"))?;
        anyhow::ensure!(
            extracted.length == file.length && extracted.sha256 == file.sha256,
            "backup file digest or length does not match the manifest"
        );
        ensure_parent_directories_recorded(&file.path, &manifest_directories)?;
        manifest_files.insert(file.path.clone());
    }
    anyhow::ensure!(
        manifest_files.len() == extracted_files.len()
            && manifest_files
                .iter()
                .all(|path| extracted_files.contains_key(path)),
        "backup file manifest does not match the archive"
    );
    anyhow::ensure!(
        manifest_files.contains("linklake.sqlite3"),
        "backup database is missing"
    );
    Ok(())
}

fn apply_validated_payload(
    data_dir: &Path,
    staging_root: &Path,
    payload: &ValidatedPayload,
    manage_acme: bool,
    manage_certificates: bool,
) -> Result<Vec<PathBuf>> {
    anyhow::ensure!(
        manage_acme || !payload.has_acme,
        "restore payload contains unmanaged ACME state"
    );
    anyhow::ensure!(
        manage_certificates || !payload.has_certificates,
        "restore payload contains unmanaged certificate state"
    );
    let database_source = payload.root.join("linklake.sqlite3");
    ensure_regular_file(&database_source)?;
    if payload.has_acme {
        ensure_directory(&payload.root.join("acme"))?;
    }
    if payload.has_certificates {
        ensure_directory(&payload.root.join("certificates"))?;
    }

    let database_target = data_dir.join("linklake.sqlite3");
    let acme_target = data_dir.join("acme");
    let certificates_target = data_dir.join("certificates");
    validate_existing_target(&database_target, false)?;
    validate_existing_target(&suffixed_path(&database_target, "-wal"), false)?;
    validate_existing_target(&suffixed_path(&database_target, "-shm"), false)?;
    if manage_acme {
        validate_existing_target(&acme_target, true)?;
    }
    if manage_certificates {
        validate_existing_target(&certificates_target, true)?;
    }

    let database_ownership = capture_restore_ownership(&database_target, data_dir)?;
    let acme_ownership = capture_restore_ownership(&acme_target, data_dir)?;
    let certificates_ownership = capture_restore_ownership(&certificates_target, data_dir)?;

    let staging_name = staging_root
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("restore staging path has no portable file name"))?;
    let operation_id = staging_name
        .strip_prefix(RESTORE_STAGING_PREFIX)
        .ok_or_else(|| anyhow::anyhow!("restore staging path is invalid"))?;
    Uuid::parse_str(operation_id).context("restore staging operation ID is invalid")?;
    let preserved_name = format!(".pre-restore-{}-{operation_id}", unix_seconds());
    let preserved = data_dir.join(&preserved_name);
    fs::create_dir(&preserved)?;
    restrict_directory_permissions(&preserved)?;
    let journal = RestoreJournal {
        format_version: RESTORE_JOURNAL_VERSION,
        operation_id: operation_id.to_owned(),
        staging_directory: staging_name.to_owned(),
        preserved_directory: preserved_name,
        manage_acme,
        manage_certificates,
        has_acme: payload.has_acme,
        has_certificates: payload.has_certificates,
    };
    create_restore_journal(data_dir, &journal)?;

    let operation = (|| -> Result<()> {
        for (target, name) in [
            (&database_target, "linklake.sqlite3"),
            (
                &suffixed_path(&database_target, "-wal"),
                "linklake.sqlite3-wal",
            ),
            (
                &suffixed_path(&database_target, "-shm"),
                "linklake.sqlite3-shm",
            ),
        ] {
            if path_exists_without_following(target)? {
                let destination = preserved.join(name);
                durable_rename(target, &destination).with_context(|| {
                    format!("cannot preserve existing managed path {}", target.display())
                })?;
            }
        }
        if manage_acme && path_exists_without_following(&acme_target)? {
            durable_rename(&acme_target, &preserved.join("acme"))
                .context("cannot preserve existing managed path acme")?;
        }
        if manage_certificates && path_exists_without_following(&certificates_target)? {
            durable_rename(&certificates_target, &preserved.join("certificates"))
                .context("cannot preserve existing managed path certificates")?;
        }
        sync_parent(data_dir)?;

        durable_rename(&database_source, &database_target)
            .context("cannot install restored SQLite database")?;
        apply_restore_ownership(&database_target, database_ownership)?;
        if manage_acme && payload.has_acme {
            durable_rename(&payload.root.join("acme"), &acme_target)
                .context("cannot install restored ACME state")?;
            apply_restore_ownership(&acme_target, acme_ownership)?;
        }
        if manage_certificates && payload.has_certificates {
            durable_rename(&payload.root.join("certificates"), &certificates_target)
                .context("cannot install restored certificates")?;
            apply_restore_ownership(&certificates_target, certificates_ownership)?;
        }
        database_tools::validate_database(&database_target)
            .context("installed SQLite database failed integrity validation")?;
        sync_restored_state(
            &database_target,
            (manage_acme && payload.has_acme).then_some(acme_target.as_path()),
            (manage_certificates && payload.has_certificates)
                .then_some(certificates_target.as_path()),
        )
        .context("cannot durably synchronize restored state")?;
        sync_parent(data_dir).context("cannot synchronize restored data directory")?;
        Ok(())
    })();

    if let Err(error) = operation {
        match rollback_prepared_restore(data_dir, &journal) {
            Ok(()) => {
                mark_restore_rolled_back(data_dir)?;
                cleanup_rolled_back_restore(data_dir, &journal, false)?;
                remove_restore_journal(data_dir)?;
                return Err(error).context("full restore failed; original data was restored");
            }
            Err(rollback_error) => {
                return Err(anyhow::anyhow!(
                    "full restore failed and durable rollback is incomplete: {error}; {rollback_error}"
                ));
            }
        }
    }

    if let Err(error) = commit_restore_journal(data_dir) {
        anyhow::bail!(
            "restored state was installed but the durable commit result is uncertain; keep the service stopped and rerun it so journal recovery can decide from the on-disk marker: {error}"
        );
    }

    if directory_is_empty(&preserved)? {
        fs::remove_dir(&preserved)?;
        Ok(Vec::new())
    } else {
        sync_parent(data_dir)?;
        Ok(vec![preserved])
    }
}

fn create_restore_journal(data_dir: &Path, journal: &RestoreJournal) -> Result<()> {
    validate_restore_journal(journal)?;
    let journal_path = data_dir.join(RESTORE_JOURNAL_NAME);
    anyhow::ensure!(
        !journal_path.exists(),
        "an unfinished LinkLake restore journal already exists"
    );
    let encoded = serde_json::to_vec(journal)?;
    anyhow::ensure!(
        encoded.len() <= HEADER_MAX_BYTES,
        "restore journal is too large"
    );
    let mut bytes = Vec::with_capacity(RESTORE_JOURNAL_MAGIC.len() + 4 + encoded.len());
    bytes.extend_from_slice(RESTORE_JOURNAL_MAGIC);
    bytes.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&encoded);
    let temporary = temporary_sibling(&journal_path, "prepare");
    write_new_file(&temporary, &bytes)?;
    install_no_replace(&temporary, &journal_path)?;
    restrict_file_permissions(&journal_path)?;
    sync_parent(data_dir)?;
    Ok(())
}

fn commit_restore_journal(data_dir: &Path) -> Result<()> {
    let path = data_dir.join(RESTORE_JOURNAL_NAME);
    let mut file = OpenOptions::new().append(true).open(&path)?;
    file.write_all(RESTORE_COMMIT_MARKER)?;
    file.sync_all()?;
    #[cfg(debug_assertions)]
    if std::env::var("LINKLAKE_TEST_RESTORE_FAILPOINT")
        .ok()
        .as_deref()
        == Some("commit-after-sync-error")
    {
        anyhow::bail!("injected restore commit result uncertainty after durable sync");
    }
    Ok(())
}

fn mark_restore_rolled_back(data_dir: &Path) -> Result<()> {
    let path = data_dir.join(RESTORE_JOURNAL_NAME);
    let bytes = fs::read(&path)?;
    let prepared_length = restore_journal_prepared_length(&bytes)?;
    let mut file = OpenOptions::new().read(true).write(true).open(&path)?;
    file.set_len(prepared_length as u64)?;
    file.seek(SeekFrom::Start(prepared_length as u64))?;
    file.write_all(RESTORE_ROLLED_BACK_MARKER)?;
    file.sync_all()?;
    Ok(())
}

fn restore_journal_prepared_length(bytes: &[u8]) -> Result<usize> {
    anyhow::ensure!(
        bytes.len() >= RESTORE_JOURNAL_MAGIC.len() + 4,
        "restore journal is malformed or truncated"
    );
    anyhow::ensure!(
        &bytes[..RESTORE_JOURNAL_MAGIC.len()] == RESTORE_JOURNAL_MAGIC,
        "restore journal has an unsupported format"
    );
    let length_offset = RESTORE_JOURNAL_MAGIC.len();
    let encoded_length = u32::from_le_bytes(
        bytes[length_offset..length_offset + 4]
            .try_into()
            .expect("fixed journal length"),
    ) as usize;
    anyhow::ensure!(
        encoded_length > 0 && encoded_length <= HEADER_MAX_BYTES,
        "restore journal header length is invalid"
    );
    let prepared_length = length_offset
        .checked_add(4)
        .and_then(|value| value.checked_add(encoded_length))
        .ok_or_else(|| anyhow::anyhow!("restore journal length overflow"))?;
    anyhow::ensure!(
        prepared_length <= bytes.len(),
        "restore journal is malformed or truncated"
    );
    Ok(prepared_length)
}

fn read_restore_journal(data_dir: &Path) -> Result<Option<(RestoreJournal, RestoreJournalState)>> {
    let path = data_dir.join(RESTORE_JOURNAL_NAME);
    let file = match File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let mut bytes = Vec::new();
    file.take((HEADER_MAX_BYTES + 64) as u64)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() >= RESTORE_JOURNAL_MAGIC.len() + 4,
        "restore journal is malformed or truncated"
    );
    anyhow::ensure!(
        &bytes[..RESTORE_JOURNAL_MAGIC.len()] == RESTORE_JOURNAL_MAGIC,
        "restore journal has an unsupported format"
    );
    let encoded_end = restore_journal_prepared_length(&bytes)?;
    let encoded_start = RESTORE_JOURNAL_MAGIC.len() + 4;
    let journal: RestoreJournal = serde_json::from_slice(&bytes[encoded_start..encoded_end])
        .context("restore journal JSON is malformed")?;
    validate_restore_journal(&journal)?;
    let state = match &bytes[encoded_end..] {
        [] => RestoreJournalState::Prepared,
        marker if marker == RESTORE_COMMIT_MARKER => RestoreJournalState::Committed,
        marker if marker == RESTORE_ROLLED_BACK_MARKER => RestoreJournalState::RolledBack,
        // 提交标记若因断电只写入一部分，必须按未提交处理并回滚。
        _ => RestoreJournalState::Prepared,
    };
    Ok(Some((journal, state)))
}

fn validate_restore_journal(journal: &RestoreJournal) -> Result<()> {
    anyhow::ensure!(
        journal.format_version == RESTORE_JOURNAL_VERSION,
        "unsupported restore journal version {}",
        journal.format_version
    );
    let operation_id = Uuid::parse_str(&journal.operation_id)
        .context("restore journal operation ID is invalid")?;
    anyhow::ensure!(
        journal.staging_directory == format!("{RESTORE_STAGING_PREFIX}{operation_id}"),
        "restore journal staging directory is invalid"
    );
    validate_component(&journal.staging_directory)?;
    validate_component(&journal.preserved_directory)?;
    anyhow::ensure!(
        journal.preserved_directory.starts_with(".pre-restore-")
            && journal
                .preserved_directory
                .ends_with(&operation_id.to_string()),
        "restore journal preserved directory is invalid"
    );
    anyhow::ensure!(
        journal.manage_acme || !journal.has_acme,
        "restore journal contains unmanaged ACME state"
    );
    anyhow::ensure!(
        journal.manage_certificates || !journal.has_certificates,
        "restore journal contains unmanaged certificate state"
    );
    Ok(())
}

pub(crate) fn recover_interrupted_restore(
    data_dir: &Path,
    maintenance: &MaintenanceGuard,
) -> Result<()> {
    anyhow::ensure!(
        maintenance.exclusive,
        "restore journal recovery requires the exclusive maintenance lock"
    );
    if let Some((journal, state)) = read_restore_journal(data_dir)? {
        match state {
            RestoreJournalState::Prepared => {
                rollback_prepared_restore(data_dir, &journal)?;
                mark_restore_rolled_back(data_dir)?;
                cleanup_rolled_back_restore(data_dir, &journal, true)?;
                remove_restore_journal(data_dir)?;
            }
            RestoreJournalState::Committed => {
                validate_committed_restore(data_dir, &journal)?;
                let staging = data_dir.join(&journal.staging_directory);
                if path_exists_without_following(&staging)? {
                    remove_managed_path(&staging)?;
                }
                remove_restore_journal(data_dir)?;
            }
            RestoreJournalState::RolledBack => {
                cleanup_rolled_back_restore(data_dir, &journal, true)?;
                remove_restore_journal(data_dir)?;
            }
        }
    }
    cleanup_restore_journal_temporaries(data_dir)?;
    cleanup_stale_staging(data_dir, BACKUP_STAGING_PREFIX)?;
    cleanup_stale_staging(data_dir, RESTORE_STAGING_PREFIX)?;
    Ok(())
}

fn rollback_prepared_restore(data_dir: &Path, journal: &RestoreJournal) -> Result<()> {
    validate_restore_journal(journal)?;
    let staging = data_dir.join(&journal.staging_directory);
    let payload = staging.join("unpacked");
    let preserved = data_dir.join(&journal.preserved_directory);
    ensure_directory(&staging).context("restore staging directory is missing or unsafe")?;
    ensure_directory(&preserved).context("restore preserved directory is missing or unsafe")?;
    rollback_installable_item(
        &data_dir.join("linklake.sqlite3"),
        &preserved.join("linklake.sqlite3"),
        &payload.join("linklake.sqlite3"),
        true,
    )?;
    rollback_old_only_item(
        &data_dir.join("linklake.sqlite3-wal"),
        &preserved.join("linklake.sqlite3-wal"),
    )?;
    rollback_old_only_item(
        &data_dir.join("linklake.sqlite3-shm"),
        &preserved.join("linklake.sqlite3-shm"),
    )?;
    if journal.manage_acme {
        rollback_installable_item(
            &data_dir.join("acme"),
            &preserved.join("acme"),
            &payload.join("acme"),
            journal.has_acme,
        )?;
    }
    if journal.manage_certificates {
        rollback_installable_item(
            &data_dir.join("certificates"),
            &preserved.join("certificates"),
            &payload.join("certificates"),
            journal.has_certificates,
        )?;
    }
    sync_parent(data_dir)?;
    Ok(())
}

fn rollback_installable_item(
    target: &Path,
    preserved: &Path,
    staged: &Path,
    install_expected: bool,
) -> Result<()> {
    let target_exists = path_exists_without_following(target)?;
    let preserved_exists = path_exists_without_following(preserved)?;
    let staged_exists = path_exists_without_following(staged)?;
    if preserved_exists {
        if target_exists {
            anyhow::ensure!(
                install_expected && !staged_exists,
                "restore rollback found conflicting managed paths"
            );
            if let Some(parent) = staged.parent() {
                fs::create_dir_all(parent)?;
            }
            durable_rename(target, staged)?;
        }
        durable_rename(preserved, target)?;
    } else if install_expected && !staged_exists && target_exists {
        if let Some(parent) = staged.parent() {
            fs::create_dir_all(parent)?;
        }
        durable_rename(target, staged)?;
    }
    Ok(())
}

fn cleanup_rolled_back_restore(
    data_dir: &Path,
    journal: &RestoreJournal,
    remove_staging: bool,
) -> Result<()> {
    let preserved = data_dir.join(&journal.preserved_directory);
    if path_exists_without_following(&preserved)? {
        anyhow::ensure!(
            directory_is_empty(&preserved)?,
            "rolled-back restore still contains preserved entries"
        );
        fs::remove_dir(&preserved)?;
    }
    let staging = data_dir.join(&journal.staging_directory);
    if remove_staging && path_exists_without_following(&staging)? {
        remove_managed_path(&staging)?;
    }
    sync_parent(data_dir)?;
    Ok(())
}

fn rollback_old_only_item(target: &Path, preserved: &Path) -> Result<()> {
    let target_exists = path_exists_without_following(target)?;
    let preserved_exists = path_exists_without_following(preserved)?;
    anyhow::ensure!(
        !(target_exists && preserved_exists),
        "restore rollback found conflicting old-only paths"
    );
    if preserved_exists {
        durable_rename(preserved, target)?;
    }
    Ok(())
}

fn validate_committed_restore(data_dir: &Path, journal: &RestoreJournal) -> Result<()> {
    let database = data_dir.join("linklake.sqlite3");
    ensure_regular_file(&database)?;
    database_tools::validate_database(&database)?;
    database_migrations::validate_restore_database(&database)?;
    if journal.manage_acme {
        validate_committed_directory(&data_dir.join("acme"), journal.has_acme)?;
    }
    if journal.manage_certificates {
        validate_committed_directory(&data_dir.join("certificates"), journal.has_certificates)?;
    }
    Ok(())
}

fn validate_committed_directory(path: &Path, expected: bool) -> Result<()> {
    if expected {
        ensure_directory(path)
    } else {
        anyhow::ensure!(
            !path_exists_without_following(path)?,
            "committed restore contains an unexpected managed directory"
        );
        Ok(())
    }
}

fn remove_restore_journal(data_dir: &Path) -> Result<()> {
    let path = data_dir.join(RESTORE_JOURNAL_NAME);
    match fs::remove_file(&path) {
        Ok(()) => sync_parent(data_dir),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn sync_restored_state(
    database: &Path,
    acme: Option<&Path>,
    certificates: Option<&Path>,
) -> Result<()> {
    sync_regular_file(database)?;
    if let Some(acme) = acme {
        sync_tree(acme)?;
    }
    if let Some(certificates) = certificates {
        sync_tree(certificates)?;
    }
    Ok(())
}

fn sync_tree(path: &Path) -> Result<()> {
    let metadata = safe_symlink_metadata(path)?;
    reject_reparse_point(path, &metadata)?;
    if metadata.is_file() {
        sync_regular_file(path)?;
        return Ok(());
    }
    anyhow::ensure!(metadata.is_dir(), "managed sync path is not regular");
    for entry in fs::read_dir(path)? {
        sync_tree(&entry?.path())?;
    }
    sync_parent(path)
}

fn sync_regular_file(path: &Path) -> Result<()> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)?
        .sync_all()?;
    Ok(())
}

fn directory_is_empty(path: &Path) -> Result<bool> {
    Ok(fs::read_dir(path)?.next().transpose()?.is_none())
}

fn write_tar_entry<R: Read>(reader: &mut R, destination: &Path) -> Result<(u64, String)> {
    let output = create_managed_new_file(destination)?;
    let mut writer = BufWriter::new(output);
    let mut digest = Sha256::new();
    let mut length = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        length = length
            .checked_add(read as u64)
            .ok_or_else(|| anyhow::anyhow!("backup file is too large"))?;
        anyhow::ensure!(length <= MAX_FILE_BYTES, "backup file is too large");
        digest.update(&buffer[..read]);
        writer.write_all(&buffer[..read])?;
    }
    writer.flush()?;
    writer.get_ref().sync_all()?;
    Ok((length, hex_digest(digest.finalize().as_slice())))
}

fn validate_existing_target(path: &Path, directory: bool) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            reject_reparse_point(path, &metadata)?;
            if directory {
                anyhow::ensure!(
                    metadata.is_dir(),
                    "managed target is not a directory: {}",
                    path.display()
                );
            } else {
                anyhow::ensure!(
                    metadata.is_file(),
                    "managed target is not a regular file: {}",
                    path.display()
                );
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("cannot inspect {}", path.display())),
    }
}

#[cfg(unix)]
fn capture_restore_ownership(target: &Path, data_dir: &Path) -> Result<ManagedOwnership> {
    use std::os::unix::fs::MetadataExt;

    let metadata = match fs::symlink_metadata(target) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => fs::metadata(data_dir)
            .with_context(|| {
                format!(
                    "cannot inspect fallback restore ownership for {}",
                    data_dir.display()
                )
            })?,
        Err(error) => {
            return Err(error)
                .with_context(|| format!("cannot inspect restore owner for {}", target.display()));
        }
    };
    Ok(ManagedOwnership {
        uid: metadata.uid(),
        gid: metadata.gid(),
    })
}

#[cfg(not(unix))]
fn capture_restore_ownership(_target: &Path, _data_dir: &Path) -> Result<ManagedOwnership> {
    Ok(ManagedOwnership)
}

#[cfg(unix)]
fn apply_restore_ownership(path: &Path, ownership: ManagedOwnership) -> Result<()> {
    use std::os::{fd::AsRawFd, unix::fs::MetadataExt};

    let metadata = safe_symlink_metadata(path)?;
    reject_reparse_point(path, &metadata)?;
    let file = File::open(path)
        .with_context(|| format!("cannot open restored path {}", path.display()))?;
    let actual = file.metadata()?;
    if actual.uid() != ownership.uid || actual.gid() != ownership.gid {
        // SAFETY: fd remains valid for the call and uid/gid were captured from a validated
        // pre-restore managed target or from the already-open data directory.
        let result = unsafe { libc::fchown(file.as_raw_fd(), ownership.uid, ownership.gid) };
        anyhow::ensure!(
            result == 0,
            "cannot restore managed ownership for {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        );
    }
    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            apply_restore_ownership(&entry?.path(), ownership)?;
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn apply_restore_ownership(_path: &Path, _ownership: ManagedOwnership) -> Result<()> {
    Ok(())
}

fn ensure_regular_file(path: &Path) -> Result<()> {
    let metadata = safe_symlink_metadata(path)?;
    reject_reparse_point(path, &metadata)?;
    anyhow::ensure!(metadata.is_file(), "restored path is not a regular file");
    Ok(())
}

fn ensure_directory(path: &Path) -> Result<()> {
    let metadata = safe_symlink_metadata(path)?;
    reject_reparse_point(path, &metadata)?;
    anyhow::ensure!(metadata.is_dir(), "restored path is not a directory");
    Ok(())
}

fn path_exists_without_following(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn remove_managed_path(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            fs::remove_dir_all(path)?;
        }
        Ok(_) => fs::remove_file(path)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn cleanup_stale_staging(data_dir: &Path, prefix: &str) -> Result<()> {
    for entry in fs::read_dir(data_dir)? {
        let entry = entry?;
        let name = match entry.file_name().into_string() {
            Ok(name) => name,
            Err(_) => continue,
        };
        let Some(operation_id) = name.strip_prefix(prefix) else {
            continue;
        };
        if Uuid::parse_str(operation_id).is_err() {
            continue;
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        reject_reparse_point(&path, &metadata)?;
        anyhow::ensure!(
            metadata.is_dir(),
            "reserved staging path is not a directory"
        );
        let activity_path = path.join(".active.lock");
        let activity = match OpenOptions::new()
            .create(false)
            .read(true)
            .write(true)
            .open(&activity_path)
        {
            Ok(file) => Some(file),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        if let Some(activity) = activity {
            match activity.try_lock_exclusive() {
                Ok(()) => drop(activity),
                Err(error) if lock_is_busy(&error) => continue,
                Err(error) => return Err(error.into()),
            }
        }
        fs::remove_dir_all(&path)
            .with_context(|| format!("cannot remove stale staging directory {}", path.display()))?;
    }
    Ok(())
}

fn lock_is_busy(error: &std::io::Error) -> bool {
    if error.kind() == std::io::ErrorKind::WouldBlock {
        return true;
    }
    #[cfg(windows)]
    {
        // ERROR_SHARING_VIOLATION / ERROR_LOCK_VIOLATION。
        matches!(error.raw_os_error(), Some(32 | 33))
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn cleanup_restore_journal_temporaries(data_dir: &Path) -> Result<()> {
    let prefix = format!("{RESTORE_JOURNAL_NAME}.");
    for entry in fs::read_dir(data_dir)? {
        let entry = entry?;
        let name = match entry.file_name().into_string() {
            Ok(name) => name,
            Err(_) => continue,
        };
        if !name.starts_with(&prefix) || !name.ends_with(".tmp") {
            continue;
        }
        let path = entry.path();
        let metadata = safe_symlink_metadata(&path)?;
        reject_reparse_point(&path, &metadata)?;
        anyhow::ensure!(
            metadata.is_file(),
            "restore journal temporary is not a file"
        );
        fs::remove_file(path)?;
    }
    Ok(())
}

fn resolve_existing_data_directory(path: &Path) -> Result<PathBuf> {
    let requested = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let requested_metadata = fs::symlink_metadata(&requested).with_context(|| {
        format!(
            "data directory must already exist and be secured: {}",
            requested.display()
        )
    })?;
    anyhow::ensure!(
        !requested_metadata.file_type().is_symlink(),
        "data directory must not be a symbolic link or reparse point: {}",
        requested.display()
    );
    reject_reparse_point(&requested, &requested_metadata)?;
    anyhow::ensure!(
        requested_metadata.is_dir(),
        "data directory is not a directory: {}",
        requested.display()
    );
    let resolved = resolve_path_with_missing_components(path)?;
    anyhow::ensure!(
        resolved.is_dir(),
        "data directory does not exist: {}",
        resolved.display()
    );
    fs::canonicalize(&resolved)
        .with_context(|| format!("cannot resolve data directory {}", resolved.display()))
}

fn prepare_output_path(data_dir: &Path, output_path: &Path) -> Result<PathBuf> {
    let first = resolve_path_with_missing_components(output_path)?;
    ensure_external_to_data_directory(data_dir, &first)?;
    let parent = first
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("cannot create backup output directory {}", parent.display()))?;
    let resolved = resolve_path_with_missing_components(&first)?;
    ensure_external_to_data_directory(data_dir, &resolved)?;
    anyhow::ensure!(
        !resolved.exists(),
        "backup output already exists: {}",
        resolved.display()
    );
    Ok(resolved)
}

fn resolve_external_archive_path(
    data_dir: &Path,
    archive_path: &Path,
    must_exist: bool,
) -> Result<PathBuf> {
    let resolved = resolve_path_with_missing_components(archive_path)?;
    ensure_external_to_data_directory(data_dir, &resolved)?;
    if must_exist {
        anyhow::ensure!(
            resolved.is_file(),
            "backup input does not exist: {}",
            resolved.display()
        );
    }
    Ok(resolved)
}

pub(crate) fn resolve_external_password_file(
    data_dir: &Path,
    password_file: &Path,
) -> Result<PathBuf> {
    let data_dir = resolve_existing_data_directory(data_dir)?;
    let password_file = resolve_path_with_missing_components(password_file)?;
    ensure_external_to_data_directory(&data_dir, &password_file)?;
    anyhow::ensure!(
        password_file.is_file(),
        "password file does not exist: {}",
        password_file.display()
    );
    Ok(password_file)
}

fn ensure_external_to_data_directory(data_dir: &Path, path: &Path) -> Result<()> {
    anyhow::ensure!(
        !path_is_within(path, data_dir),
        "backup input or output must be outside the LinkLake data directory"
    );
    Ok(())
}

/// 解析不存在组件下的点号和父目录，同时 canonicalize 每个已存在组件。
/// 返回值必须用于实际 I/O，不能只作为检查结果。
fn resolve_path_with_missing_components(path: &Path) -> Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut resolved = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::Prefix(prefix) => resolved.push(prefix.as_os_str()),
            Component::RootDir => resolved.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                resolved.pop();
            }
            Component::Normal(name) => {
                let candidate = resolved.join(name);
                match fs::symlink_metadata(&candidate) {
                    Ok(_) => {
                        resolved = fs::canonicalize(&candidate).with_context(|| {
                            format!(
                                "cannot resolve existing path component {}",
                                candidate.display()
                            )
                        })?;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        resolved.push(name);
                    }
                    Err(error) => {
                        return Err(error).with_context(|| {
                            format!("cannot inspect path component {}", candidate.display())
                        });
                    }
                }
            }
        }
    }
    Ok(resolved)
}

#[cfg(windows)]
fn path_is_within(path: &Path, directory: &Path) -> bool {
    let path = path
        .as_os_str()
        .to_string_lossy()
        .replace('/', "\\")
        .to_ascii_lowercase();
    let mut directory = directory
        .as_os_str()
        .to_string_lossy()
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase();
    if path == directory {
        return true;
    }
    directory.push('\\');
    path.starts_with(&directory)
}

#[cfg(not(windows))]
fn path_is_within(path: &Path, directory: &Path) -> bool {
    path.starts_with(directory)
}

fn logical_destination(root: &Path, logical: &str) -> Result<PathBuf> {
    let normalized = normalize_logical_path(logical)?;
    anyhow::ensure!(normalized == logical, "managed path is not normalized");
    let mut destination = root.to_path_buf();
    for component in logical.split('/') {
        destination.push(component);
    }
    Ok(destination)
}

fn normalize_archive_path(path: &Path) -> Result<String> {
    let mut components = Vec::new();
    for component in path.components() {
        let Component::Normal(name) = component else {
            anyhow::bail!("backup contains an absolute or traversing path");
        };
        let name = name
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("backup path is not UTF-8"))?;
        validate_component(name)?;
        components.push(name);
    }
    anyhow::ensure!(!components.is_empty(), "backup path is empty");
    validate_logical_shape(&components)?;
    Ok(components.join("/"))
}

fn normalize_logical_path(path: &str) -> Result<String> {
    anyhow::ensure!(!path.is_empty(), "managed path is empty");
    let mut components = Vec::new();
    for component in path.split('/') {
        validate_component(component)?;
        components.push(component);
    }
    validate_logical_shape(&components)?;
    Ok(components.join("/"))
}

fn validate_component(component: &str) -> Result<()> {
    let bytes = component.as_bytes();
    anyhow::ensure!(
        !component.is_empty()
            && component != "."
            && component != ".."
            && bytes.len() <= MAX_COMPONENT_BYTES
            && !bytes.iter().any(|byte| *byte < 0x20)
            && !component.contains('\\')
            && !component.contains('/')
            && !component.contains(':')
            && !component.ends_with('.')
            && !component.ends_with(' ')
            && !is_windows_device_name(component),
        "managed path contains an unsafe component"
    );
    Ok(())
}

fn validate_logical_shape(components: &[&str]) -> Result<()> {
    anyhow::ensure!(
        components.len() <= MAX_PATH_DEPTH,
        "managed path exceeds the maximum depth"
    );
    let logical_bytes = components.iter().map(|part| part.len()).sum::<usize>()
        + components.len().saturating_sub(1);
    anyhow::ensure!(
        logical_bytes <= MAX_LOGICAL_PATH_BYTES,
        "managed path is too long"
    );
    Ok(())
}

fn is_windows_device_name(component: &str) -> bool {
    let stem = component.split('.').next().unwrap_or(component);
    let upper = stem.to_ascii_uppercase();
    matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || upper
            .strip_prefix("COM")
            .or_else(|| upper.strip_prefix("LPT"))
            .is_some_and(|number| number.len() == 1 && matches!(number.as_bytes()[0], b'1'..=b'9'))
}

fn is_allowed_file(path: &str) -> bool {
    path == "linklake.sqlite3" || path.starts_with("acme/") || path.starts_with("certificates/")
}

fn is_allowed_directory(path: &str) -> bool {
    path == "acme"
        || path.starts_with("acme/")
        || path == "certificates"
        || path.starts_with("certificates/")
}

fn ensure_parent_directories_recorded(path: &str, directories: &BTreeSet<String>) -> Result<()> {
    let components = path.split('/').collect::<Vec<_>>();
    if components.len() <= 1 {
        return Ok(());
    }
    for end in 1..components.len() {
        let parent = components[..end].join("/");
        anyhow::ensure!(
            directories.contains(&parent),
            "manifest omits a parent directory"
        );
    }
    Ok(())
}

fn require_password(password: &[u8]) -> Result<()> {
    anyhow::ensure!(
        password.len() >= MIN_PASSWORD_BYTES,
        "backup password must contain at least {MIN_PASSWORD_BYTES} bytes"
    );
    anyhow::ensure!(
        password.len() <= MAX_PASSWORD_BYTES,
        "backup password exceeds the maximum supported length"
    );
    Ok(())
}

fn derive_key(password: &[u8], salt: &[u8; SALT_LEN]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let params = Params::new(
        KDF_MEMORY_KIB,
        KDF_ITERATIONS,
        KDF_PARALLELISM,
        Some(KEY_LEN),
    )
    .map_err(|_| anyhow::anyhow!("invalid backup key derivation configuration"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0_u8; KEY_LEN]);
    argon2
        .hash_password_into(password, salt, key.as_mut())
        .map_err(|_| anyhow::anyhow!("backup key derivation failed"))?;
    Ok(key)
}

fn decode_fixed<const N: usize>(value: &str, field: &str) -> Result<[u8; N]> {
    STANDARD
        .decode(value)
        .with_context(|| format!("backup {field} is malformed"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("backup {field} has an invalid length"))
}

fn associated_data_prefix(header_length: u32, header: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(MAGIC.len() + 4 + header.len());
    aad.extend_from_slice(MAGIC);
    aad.extend_from_slice(&header_length.to_le_bytes());
    aad.extend_from_slice(header);
    aad
}

fn record_header(record_type: u8, counter: u32, length: u32) -> [u8; RECORD_HEADER_LEN] {
    let mut header = [0_u8; RECORD_HEADER_LEN];
    header[0] = record_type;
    header[1..5].copy_from_slice(&counter.to_le_bytes());
    header[5..9].copy_from_slice(&length.to_le_bytes());
    header
}

fn record_associated_data(prefix: &[u8], record: &[u8; RECORD_HEADER_LEN]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(prefix.len() + record.len());
    aad.extend_from_slice(prefix);
    aad.extend_from_slice(record);
    aad
}

fn chunk_nonce(prefix: &[u8; NONCE_PREFIX_LEN], counter: u32) -> [u8; NONCE_LEN] {
    let mut nonce = [0_u8; NONCE_LEN];
    nonce[..NONCE_PREFIX_LEN].copy_from_slice(prefix);
    nonce[NONCE_PREFIX_LEN..].copy_from_slice(&counter.to_le_bytes());
    nonce
}

fn read_exact_backup(reader: &mut impl Read, buffer: &mut [u8]) -> Result<()> {
    reader.read_exact(buffer).map_err(|error| {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            anyhow::anyhow!("backup is malformed or truncated")
        } else {
            error.into()
        }
    })
}

fn read_tag(reader: &mut impl Read) -> Result<[u8; TAG_LEN]> {
    let mut tag = [0_u8; TAG_LEN];
    read_exact_backup(reader, &mut tag)?;
    Ok(tag)
}

fn safe_symlink_metadata(path: &Path) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("cannot inspect managed path {}", path.display()))?;
    anyhow::ensure!(
        !metadata.file_type().is_symlink(),
        "managed paths must not contain symbolic links: {}",
        path.display()
    );
    Ok(metadata)
}

#[cfg(windows)]
fn reject_reparse_point(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    anyhow::ensure!(
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "managed paths must not contain reparse points: {}",
        path.display()
    );
    Ok(())
}

#[cfg(not(windows))]
fn reject_reparse_point(_path: &Path, _metadata: &fs::Metadata) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn reject_hard_link(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    anyhow::ensure!(
        metadata.nlink() <= 1,
        "managed paths must not contain hard-linked files: {}",
        path.display()
    );
    Ok(())
}

#[cfg(windows)]
fn reject_hard_link(path: &Path, _metadata: &fs::Metadata) -> Result<()> {
    use std::{mem::zeroed, os::windows::io::AsRawHandle};
    use windows_sys::Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION},
    };

    let file = File::open(path)?;
    // SAFETY: info 指向有效且可写的结构体，句柄由仍然存活的 File 提供。
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
    // SAFETY: GetFileInformationByHandle 不接管句柄，输出缓冲区大小与 API 定义一致。
    let succeeded =
        unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut info) };
    anyhow::ensure!(
        succeeded != 0,
        "cannot inspect hard-link count for {}: {}",
        path.display(),
        std::io::Error::last_os_error()
    );
    anyhow::ensure!(
        info.nNumberOfLinks <= 1,
        "managed paths must not contain hard-linked files: {}",
        path.display()
    );
    Ok(())
}

fn copy_file_and_hash(
    source: &Path,
    destination: &Path,
    maximum_bytes: u64,
) -> Result<(u64, String)> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
        restrict_directory_permissions(parent)?;
    }
    let input = File::open(source)?;
    anyhow::ensure!(
        input.metadata()?.len() <= maximum_bytes,
        "managed file exceeds the remaining backup budget"
    );
    let output = create_managed_new_file(destination)?;
    let mut reader = BufReader::new(input);
    let mut writer = BufWriter::new(output);
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| anyhow::anyhow!("managed file is too large"))?;
        anyhow::ensure!(
            total <= maximum_bytes,
            "managed file exceeds the remaining backup budget"
        );
        digest.update(&buffer[..read]);
        writer.write_all(&buffer[..read])?;
    }
    writer.flush()?;
    writer.get_ref().sync_all()?;
    Ok((total, hex_digest(&digest.finalize())))
}

fn hash_file(path: &Path) -> Result<(u64, String)> {
    let input = File::open(path)?;
    let mut reader = BufReader::new(input);
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| anyhow::anyhow!("file is too large"))?;
        digest.update(&buffer[..read]);
    }
    Ok((total, hex_digest(&digest.finalize())))
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn is_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn add_total_bytes(total: &mut u64, value: u64) -> Result<()> {
    *total = total
        .checked_add(value)
        .ok_or_else(|| anyhow::anyhow!("backup payload is too large"))?;
    anyhow::ensure!(*total <= MAX_ARCHIVE_BYTES, "backup payload is too large");
    Ok(())
}

fn validate_single_file_length(length: u64) -> Result<()> {
    anyhow::ensure!(length <= MAX_FILE_BYTES, "backup file is too large");
    Ok(())
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = create_managed_new_file(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn temporary_sibling(path: &Path, purpose: &str) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("linklake-full-backup");
    path.with_file_name(format!("{name}.{purpose}-{}.tmp", Uuid::new_v4()))
}

fn suffixed_path(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

#[cfg(unix)]
pub(crate) fn install_no_replace(temporary: &Path, destination: &Path) -> Result<()> {
    let temporary_parent = temporary.parent().unwrap_or_else(|| Path::new("."));
    let destination_parent = destination.parent().unwrap_or_else(|| Path::new("."));
    fs::hard_link(temporary, destination).with_context(|| {
        format!(
            "cannot install backup without replacing an existing file at {}",
            destination.display()
        )
    })?;
    fs::remove_file(temporary)?;
    sync_parent(temporary_parent)?;
    if temporary_parent != destination_parent {
        sync_parent(destination_parent)?;
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) fn install_no_replace(temporary: &Path, destination: &Path) -> Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_WRITE_THROUGH};

    let source = encode_existing_windows_path(temporary)?;
    let target = encode_destination_windows_path(destination)?;
    // SAFETY: 两个 UTF-16 缓冲区均以 NUL 结尾并在调用期间保持有效；未设置
    // REPLACE_EXISTING，因此并发预占目标会失败；WRITE_THROUGH 要求元数据落盘。
    let succeeded =
        unsafe { MoveFileExW(source.as_ptr(), target.as_ptr(), MOVEFILE_WRITE_THROUGH) };
    anyhow::ensure!(
        succeeded != 0,
        "cannot install backup without replacing an existing file at {}: {}",
        destination.display(),
        std::io::Error::last_os_error()
    );
    Ok(())
}

#[cfg(windows)]
pub(crate) fn durable_rename(source: &Path, destination: &Path) -> Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_WRITE_THROUGH};

    let source = encode_existing_windows_path(source)?;
    let destination = encode_destination_windows_path(destination)?;
    // SAFETY: 路径缓冲区在调用期间有效且以 NUL 结尾；目标必须预先不存在。
    let succeeded = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    };
    anyhow::ensure!(
        succeeded != 0,
        "durable managed-path rename failed: {}",
        std::io::Error::last_os_error()
    );
    Ok(())
}

#[cfg(unix)]
pub(crate) fn durable_rename(source: &Path, destination: &Path) -> Result<()> {
    let source_parent = source.parent().unwrap_or_else(|| Path::new("."));
    let destination_parent = destination.parent().unwrap_or_else(|| Path::new("."));
    fs::rename(source, destination)?;
    sync_parent(source_parent)?;
    if source_parent != destination_parent {
        sync_parent(destination_parent)?;
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn restrict_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    inherit_parent_ownership(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(unix)]
pub(crate) fn restrict_external_backup_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn restrict_file_permissions(path: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        apply_windows_dacl(path, WINDOWS_MANAGED_FILE_SDDL)
    }
    #[cfg(not(windows))]
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn restrict_external_backup_permissions(path: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        apply_windows_dacl(path, WINDOWS_EXTERNAL_FILE_SDDL)
    }
    #[cfg(not(windows))]
    Ok(())
}

#[cfg(unix)]
pub(crate) fn restrict_directory_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    inherit_parent_ownership(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn restrict_directory_permissions(_path: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        apply_windows_dacl(_path, WINDOWS_MANAGED_DIRECTORY_SDDL)
    }
    #[cfg(not(windows))]
    Ok(())
}

#[cfg(unix)]
fn inherit_parent_ownership(path: &Path) -> Result<()> {
    use std::os::{fd::AsRawFd, unix::fs::MetadataExt};

    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("managed path has no parent directory"))?;
    let expected = fs::metadata(parent)
        .with_context(|| format!("cannot inspect managed parent {}", parent.display()))?;
    let file =
        File::open(path).with_context(|| format!("cannot open managed path {}", path.display()))?;
    let actual = file.metadata()?;
    if actual.uid() == expected.uid() && actual.gid() == expected.gid() {
        return Ok(());
    }
    // SAFETY: fd 在调用期间有效；uid/gid 来自已打开父目录的元数据。
    let result = unsafe { libc::fchown(file.as_raw_fd(), expected.uid(), expected.gid()) };
    anyhow::ensure!(
        result == 0,
        "cannot inherit managed ownership for {}: {}",
        path.display(),
        std::io::Error::last_os_error()
    );
    Ok(())
}

#[cfg(unix)]
pub(crate) fn create_managed_new_file(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    let file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    restrict_file_permissions(path)?;
    Ok(file)
}

#[cfg(unix)]
pub(crate) fn create_external_backup_new_file(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    let file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    restrict_external_backup_permissions(path)?;
    Ok(file)
}

#[cfg(windows)]
pub(crate) fn create_managed_new_file(path: &Path) -> Result<File> {
    create_windows_file_with_dacl(path, WINDOWS_MANAGED_FILE_SDDL)
}

#[cfg(windows)]
pub(crate) fn create_external_backup_new_file(path: &Path) -> Result<File> {
    create_windows_file_with_dacl(path, WINDOWS_EXTERNAL_FILE_SDDL)
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn create_managed_new_file(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(path)?;
    restrict_file_permissions(path)?;
    Ok(file)
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn create_external_backup_new_file(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(path)?;
    restrict_external_backup_permissions(path)?;
    Ok(file)
}

#[cfg(windows)]
fn create_windows_file_with_dacl(path: &Path, sddl: &str) -> Result<File> {
    use std::{ffi::c_void, mem::size_of, os::windows::io::FromRawHandle, ptr::null_mut};
    use windows_sys::Win32::{
        Foundation::{LocalFree, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE},
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            },
            SECURITY_ATTRIBUTES,
        },
        Storage::FileSystem::{
            CreateFileW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ,
            FILE_SHARE_WRITE,
        },
    };

    let encoded_path = encode_destination_windows_path(path)?;
    let encoded_sddl = sddl
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut descriptor: *mut c_void = null_mut();
    // SAFETY: 输入字符串以 NUL 结尾，输出描述符由 LocalFree 释放。
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
        "cannot build secure Windows DACL: {}",
        std::io::Error::last_os_error()
    );
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    // SAFETY: 路径与 SECURITY_ATTRIBUTES 在调用期间有效；CREATE_NEW 禁止覆盖现有目标。
    let handle = unsafe {
        CreateFileW(
            encoded_path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        )
    };
    let error = std::io::Error::last_os_error();
    // SAFETY: descriptor 由 ConvertStringSecurityDescriptorToSecurityDescriptorW 分配。
    unsafe {
        LocalFree(descriptor);
    }
    anyhow::ensure!(
        handle != INVALID_HANDLE_VALUE,
        "cannot securely create {}: {error}",
        path.display()
    );
    // SAFETY: CreateFileW 成功后返回唯一拥有的有效句柄，所有权转交给 File。
    Ok(unsafe { File::from_raw_handle(handle) })
}

#[cfg(windows)]
fn apply_windows_dacl(path: &Path, sddl: &str) -> Result<()> {
    use std::{ffi::c_void, ptr::null_mut};
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            },
            SetFileSecurityW, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        },
    };

    let encoded_path = encode_existing_windows_path(path)?;
    let encoded_sddl = sddl
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut descriptor: *mut c_void = null_mut();
    // SAFETY: 输入字符串以 NUL 结尾，输出指针由 LocalFree 释放。
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
        "cannot build secure Windows DACL: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: 路径和安全描述符在调用期间有效，描述符包含受保护 DACL。
    let applied = unsafe {
        SetFileSecurityW(
            encoded_path.as_ptr(),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor,
        )
    };
    let error = std::io::Error::last_os_error();
    // SAFETY: descriptor 由 ConvertStringSecurityDescriptorToSecurityDescriptorW 分配。
    unsafe {
        LocalFree(descriptor);
    }
    anyhow::ensure!(
        applied != 0,
        "cannot apply secure Windows DACL to {}: {error}",
        path.display()
    );
    Ok(())
}

#[cfg(windows)]
pub(crate) fn encode_existing_windows_path(path: &Path) -> Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;

    let canonical = fs::canonicalize(path)
        .with_context(|| format!("cannot resolve existing Windows path {}", path.display()))?;
    Ok(canonical
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect())
}

#[cfg(windows)]
pub(crate) fn encode_destination_windows_path(path: &Path) -> Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;

    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("Windows destination path has no file name"))?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let canonical_parent = fs::canonicalize(parent).with_context(|| {
        format!(
            "cannot resolve Windows destination parent {}",
            parent.display()
        )
    })?;
    Ok(canonical_parent
        .join(file_name)
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect())
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> Result<()> {
    Ok(())
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use rusqlite::Connection;

    const PASSWORD: &[u8] = b"correct horse battery staple";

    fn test_root(name: &str) -> TemporaryDirectory {
        let path = std::env::temp_dir().join(format!("linklake-{name}-test-{}", Uuid::new_v4()));
        fs::create_dir(&path).expect("temporary test directory should be created");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        #[cfg(not(unix))]
        restrict_directory_permissions(&path).unwrap();
        TemporaryDirectory {
            path,
            activity_lock: None,
            cleanup_on_drop: true,
        }
    }

    fn create_database(path: &Path, value: &str) {
        let connection = Connection::open(path).expect("test database should open");
        connection
            .execute_batch("CREATE TABLE sample(value TEXT NOT NULL);")
            .expect("test schema should be created");
        connection
            .execute("INSERT INTO sample(value) VALUES (?1)", [value])
            .expect("test value should be inserted");
    }

    fn read_database_value(path: &Path) -> String {
        Connection::open(path)
            .expect("test database should open")
            .query_row("SELECT value FROM sample", [], |row| row.get(0))
            .expect("test value should exist")
    }

    fn test_certificate_pair(hostname: &str) -> (Vec<u8>, Vec<u8>) {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec![hostname.to_owned()]).unwrap();
        (
            cert.pem().into_bytes(),
            signing_key.serialize_pem().into_bytes(),
        )
    }

    #[cfg(windows)]
    fn windows_dacl_sddl(path: &Path) -> String {
        use std::{ffi::c_void, ptr::null_mut, slice};
        use windows_sys::Win32::{
            Foundation::LocalFree,
            Security::{
                Authorization::{
                    ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW,
                    SDDL_REVISION_1, SE_FILE_OBJECT,
                },
                DACL_SECURITY_INFORMATION,
            },
        };

        let encoded = encode_existing_windows_path(path).unwrap();
        let mut descriptor: *mut c_void = null_mut();
        // SAFETY: 路径缓冲区有效，安全描述符由 LocalFree 释放。
        let status = unsafe {
            GetNamedSecurityInfoW(
                encoded.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                &mut descriptor,
            )
        };
        assert_eq!(status, 0, "GetNamedSecurityInfoW failed: {status}");

        let mut encoded_sddl = null_mut();
        let mut encoded_length = 0_u32;
        // SAFETY: descriptor 来自 GetNamedSecurityInfoW，输出字符串由 LocalFree 释放。
        let converted = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut encoded_sddl,
                &mut encoded_length,
            )
        };
        let error = std::io::Error::last_os_error();
        let value = if converted != 0 {
            // SAFETY: API 返回 encoded_length 个有效 UTF-16 单元。
            String::from_utf16_lossy(unsafe {
                slice::from_raw_parts(encoded_sddl, encoded_length as usize)
            })
        } else {
            String::new()
        };
        // SAFETY: 两个缓冲区均由 Windows 本地堆分配。
        unsafe {
            LocalFree(encoded_sddl.cast());
            LocalFree(descriptor);
        }
        assert!(converted != 0, "cannot convert Windows DACL: {error}");
        value.trim_end_matches('\0').to_owned()
    }

    fn staged_restore(
        data_dir: &Path,
        old_value: &str,
        new_value: &str,
    ) -> (TemporaryDirectory, RestoreJournal) {
        fs::create_dir_all(data_dir.join("acme")).unwrap();
        fs::create_dir_all(data_dir.join("certificates")).unwrap();
        create_database(&data_dir.join("linklake.sqlite3"), old_value);
        fs::write(data_dir.join("acme/state"), format!("old-{old_value}")).unwrap();
        fs::write(
            data_dir.join("certificates/key"),
            format!("old-{old_value}"),
        )
        .unwrap();

        let staging = TemporaryDirectory::create_in(data_dir, "linklake-restore-staging").unwrap();
        let payload = staging.path.join("unpacked");
        fs::create_dir_all(payload.join("acme")).unwrap();
        fs::create_dir_all(payload.join("certificates")).unwrap();
        create_database(&payload.join("linklake.sqlite3"), new_value);
        fs::write(payload.join("acme/state"), format!("new-{new_value}")).unwrap();
        fs::write(payload.join("certificates/key"), format!("new-{new_value}")).unwrap();

        let staging_name = staging.path.file_name().unwrap().to_str().unwrap();
        let operation_id = staging_name.strip_prefix(RESTORE_STAGING_PREFIX).unwrap();
        let preserved_name = format!(".pre-restore-1-{operation_id}");
        fs::create_dir(data_dir.join(&preserved_name)).unwrap();
        let journal = RestoreJournal {
            format_version: RESTORE_JOURNAL_VERSION,
            operation_id: operation_id.into(),
            staging_directory: staging_name.into(),
            preserved_directory: preserved_name,
            manage_acme: true,
            manage_certificates: true,
            has_acme: true,
            has_certificates: true,
        };
        create_restore_journal(data_dir, &journal).unwrap();
        (staging, journal)
    }

    #[test]
    fn encrypted_archive_is_chunked_authenticated_and_strictly_terminated() {
        let root = test_root("crypto");
        let plaintext_path = root.path.join("payload.tar");
        let encrypted_path = root.path.join("payload.llb");
        let mut plaintext = vec![0_u8; CHUNK_SIZE * 2 + 137];
        for (index, byte) in plaintext.iter_mut().enumerate() {
            *byte = (index % 251) as u8;
        }
        fs::write(&plaintext_path, &plaintext).unwrap();
        encrypt_archive(&plaintext_path, &encrypted_path, PASSWORD, 42).unwrap();

        let decrypted_path = root.path.join("decrypted.tar");
        let header = decrypt_archive(&encrypted_path, &decrypted_path, PASSWORD).unwrap();
        assert_eq!(header.created_at_unix_seconds, 42);
        assert_eq!(fs::read(&decrypted_path).unwrap(), plaintext);

        let wrong_output = root.path.join("wrong.tar");
        let wrong = decrypt_archive(
            &encrypted_path,
            &wrong_output,
            b"this is the wrong password",
        )
        .unwrap_err();
        assert!(wrong.to_string().contains("authentication failed"));

        let encrypted = fs::read(&encrypted_path).unwrap();
        let mut tampered = encrypted.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x80;
        let tampered_path = root.path.join("tampered.llb");
        fs::write(&tampered_path, tampered).unwrap();
        let error =
            decrypt_archive(&tampered_path, &root.path.join("tampered.tar"), PASSWORD).unwrap_err();
        assert!(error.to_string().contains("authentication failed"));

        let truncated_path = root.path.join("truncated.llb");
        fs::write(&truncated_path, &encrypted[..encrypted.len() - 1]).unwrap();
        let error = decrypt_archive(&truncated_path, &root.path.join("truncated.tar"), PASSWORD)
            .unwrap_err();
        assert!(error.to_string().contains("malformed or truncated"));

        let mut trailing = encrypted.clone();
        trailing.push(0);
        let trailing_path = root.path.join("trailing.llb");
        fs::write(&trailing_path, trailing).unwrap();
        let error =
            decrypt_archive(&trailing_path, &root.path.join("trailing.tar"), PASSWORD).unwrap_err();
        assert!(error.to_string().contains("trailing bytes"));
    }

    #[test]
    fn encrypted_archive_rejects_unknown_header_version_before_kdf() {
        let root = test_root("unknown-version");
        let plaintext_path = root.path.join("payload.tar");
        let encrypted_path = root.path.join("payload.llb");
        fs::write(&plaintext_path, b"small authenticated payload").unwrap();
        encrypt_archive(&plaintext_path, &encrypted_path, PASSWORD, 42).unwrap();

        let encrypted = fs::read(&encrypted_path).unwrap();
        let old_length = u32::from_le_bytes(encrypted[8..12].try_into().unwrap()) as usize;
        let mut header: BackupHeader =
            serde_json::from_slice(&encrypted[12..12 + old_length]).unwrap();
        header.format_version = FORMAT_VERSION + 1;
        let new_header = serde_json::to_vec(&header).unwrap();
        let mut unknown = Vec::new();
        unknown.extend_from_slice(MAGIC);
        unknown.extend_from_slice(&(new_header.len() as u32).to_le_bytes());
        unknown.extend_from_slice(&new_header);
        unknown.extend_from_slice(&encrypted[12 + old_length..]);
        let unknown_path = root.path.join("unknown.llb");
        fs::write(&unknown_path, unknown).unwrap();

        let error =
            decrypt_archive(&unknown_path, &root.path.join("unknown.tar"), PASSWORD).unwrap_err();
        assert!(error
            .to_string()
            .contains("unsupported backup format version"));
    }

    #[test]
    fn source_version_is_bounded_semver_and_cannot_come_from_a_newer_build() {
        assert!(validate_source_version(env!("CARGO_PKG_VERSION")).is_ok());
        assert!(validate_source_version(" 0.8.0").is_err());
        assert!(validate_source_version("not-a-version").is_err());
        assert!(validate_source_version(&"1".repeat(MAX_SOURCE_VERSION_BYTES + 1)).is_err());
        let error = validate_source_version("9999.0.0").unwrap_err();
        assert!(error.to_string().contains("newer LinkLake version"));
    }

    #[test]
    fn full_backup_restore_round_trip_is_atomic_and_preserves_previous_state() {
        let root = test_root("round-trip");
        let data_dir = root.path.join("data");
        let archives = root.path.join("archives");
        fs::create_dir_all(data_dir.join("acme/empty")).unwrap();
        fs::create_dir_all(data_dir.join("certificates/example.test")).unwrap();
        create_database(&data_dir.join("linklake.sqlite3"), "before");
        fs::write(data_dir.join("acme/account.json"), b"original-account").unwrap();
        let (certificate, private_key) = test_certificate_pair("example.test");
        fs::write(
            data_dir.join("certificates/example.test/fullchain.pem"),
            &certificate,
        )
        .unwrap();
        fs::write(
            data_dir.join("certificates/example.test/private-key.pem"),
            &private_key,
        )
        .unwrap();
        fs::write(data_dir.join("acme/.account-write.tmp"), b"transient").unwrap();
        fs::create_dir_all(data_dir.join("certificates/example.test/generations/.incomplete.tmp"))
            .unwrap();
        fs::write(
            data_dir.join("certificates/example.test/generations/.incomplete.tmp/private-key.pem"),
            b"partial-secret",
        )
        .unwrap();

        let archive = archives.join("server.llb");
        let backup = backup_full(&data_dir, &archive, PASSWORD).unwrap();
        assert_eq!(backup.file_count, 4);
        assert!(archive.is_file());

        let connection = Connection::open(data_dir.join("linklake.sqlite3")).unwrap();
        connection
            .execute("UPDATE sample SET value = 'after'", [])
            .unwrap();
        drop(connection);
        fs::write(data_dir.join("acme/account.json"), b"mutated-account").unwrap();
        fs::write(
            data_dir.join("certificates/example.test/private-key.pem"),
            b"mutated-private-key",
        )
        .unwrap();
        fs::write(data_dir.join("acme/extra.json"), b"must disappear").unwrap();

        let restore = restore_full(&data_dir, &archive, PASSWORD).unwrap();
        assert_eq!(restore.file_count, 4);
        assert_eq!(
            read_database_value(&data_dir.join("linklake.sqlite3")),
            "before"
        );
        assert_eq!(
            fs::read(data_dir.join("acme/account.json")).unwrap(),
            b"original-account"
        );
        assert_eq!(
            fs::read(data_dir.join("certificates/example.test/private-key.pem")).unwrap(),
            private_key
        );
        assert!(!data_dir.join("acme/extra.json").exists());
        assert!(data_dir.join("acme/empty").is_dir());
        assert!(!data_dir.join("acme/.account-write.tmp").exists());
        assert!(!data_dir
            .join("certificates/example.test/generations/.incomplete.tmp")
            .exists());
        assert_eq!(restore.preserved_paths.len(), 1);
        assert_eq!(
            fs::read(restore.preserved_paths[0].join("acme/account.json")).unwrap(),
            b"mutated-account"
        );
    }

    #[test]
    fn committed_certificate_generation_excludes_legacy_and_invalid_copies() {
        let root = test_root("committed-certificate-snapshot");
        let data_dir = root.path.join("data");
        let hostname = "committed.example.test";
        let certificate_directory = data_dir.join("certificates").join(hostname);
        let generations = certificate_directory
            .join(crate::certificate_manager::CERTIFICATE_GENERATIONS_DIRECTORY);
        let committed = generations.join("00000000000000000001-valid");
        let invalid = generations.join("00000000000000000002-invalid");
        fs::create_dir_all(&committed).unwrap();
        fs::create_dir_all(&invalid).unwrap();
        create_database(&data_dir.join("linklake.sqlite3"), "committed");
        let (certificate, private_key) = test_certificate_pair(hostname);
        fs::write(committed.join("fullchain.pem"), &certificate).unwrap();
        fs::write(committed.join("private-key.pem"), &private_key).unwrap();
        fs::write(
            committed.join("committed"),
            crate::certificate_manager::CERTIFICATE_COMMIT_MARKER,
        )
        .unwrap();
        fs::write(invalid.join("fullchain.pem"), b"not-a-certificate").unwrap();
        fs::write(invalid.join("private-key.pem"), b"not-a-private-key").unwrap();
        fs::write(
            invalid.join("committed"),
            crate::certificate_manager::CERTIFICATE_COMMIT_MARKER,
        )
        .unwrap();
        fs::write(
            certificate_directory.join("fullchain.pem"),
            b"mixed-legacy-cert",
        )
        .unwrap();
        fs::write(
            certificate_directory.join("private-key.pem"),
            b"mixed-legacy-key",
        )
        .unwrap();

        let archive = root.path.join("committed.llb");
        let report = backup_full(&data_dir, &archive, PASSWORD).unwrap();
        assert_eq!(report.file_count, 4);
        fs::remove_dir_all(data_dir.join("certificates")).unwrap();
        let restored = restore_full(&data_dir, &archive, PASSWORD).unwrap();
        assert_eq!(restored.file_count, 4);

        let restored_directory = data_dir.join("certificates").join(hostname);
        assert_eq!(
            fs::read(
                restored_directory
                    .join(crate::certificate_manager::CERTIFICATE_GENERATIONS_DIRECTORY)
                    .join("00000000000000000001-valid/fullchain.pem")
            )
            .unwrap(),
            certificate
        );
        assert!(!restored_directory.join("fullchain.pem").exists());
        assert!(!restored_directory.join("private-key.pem").exists());
        assert!(!restored_directory
            .join(crate::certificate_manager::CERTIFICATE_GENERATIONS_DIRECTORY)
            .join("00000000000000000002-invalid")
            .exists());
    }

    #[test]
    fn legacy_certificate_backup_rejects_a_mismatched_private_key() {
        let root = test_root("legacy-certificate-mismatch");
        let data_dir = root.path.join("data");
        let certificate_directory = data_dir.join("certificates/legacy.example.test");
        fs::create_dir_all(&certificate_directory).unwrap();
        create_database(&data_dir.join("linklake.sqlite3"), "legacy");
        let (certificate, _) = test_certificate_pair("legacy.example.test");
        let (_, unrelated_key) = test_certificate_pair("unrelated.example.test");
        fs::write(certificate_directory.join("fullchain.pem"), certificate).unwrap();
        fs::write(certificate_directory.join("private-key.pem"), unrelated_key).unwrap();

        let archive = root.path.join("legacy-mismatch.llb");
        let error = backup_full(&data_dir, &archive, PASSWORD).unwrap_err();
        assert!(error
            .to_string()
            .contains("legacy certificate and private key do not match"));
        assert!(!archive.exists());
    }

    #[test]
    fn restore_refuses_a_running_server_lock_and_internal_archive_aliases() {
        let root = test_root("locking");
        let data_dir = root.path.join("data");
        fs::create_dir_all(&data_dir).unwrap();
        create_database(&data_dir.join("linklake.sqlite3"), "value");
        let archive = root.path.join("server.llb");
        backup_full(&data_dir, &archive, PASSWORD).unwrap();

        let guard = acquire_offline_data_directory(&data_dir).unwrap();
        let error = restore_full(&data_dir, &archive, PASSWORD).unwrap_err();
        assert!(error.to_string().contains("must be stopped"));
        drop(guard);

        let internal_alias = data_dir.join("missing/../internal.llb");
        let error = backup_full(&data_dir, &internal_alias, PASSWORD).unwrap_err();
        assert!(error
            .to_string()
            .contains("outside the LinkLake data directory"));
    }

    #[cfg(unix)]
    #[test]
    fn final_data_directory_symlink_is_rejected_before_backup_or_restore() {
        use std::os::unix::fs::symlink;

        let root = test_root("data-dir-symlink");
        let real = root.path.join("real-data");
        let alias = root.path.join("data-alias");
        fs::create_dir(&real).unwrap();
        create_database(&real.join("linklake.sqlite3"), "value");
        symlink(&real, &alias).unwrap();

        let error = backup_full(&alias, &root.path.join("alias.llb"), PASSWORD).unwrap_err();
        assert!(error.to_string().contains("symbolic link"));
        assert!(acquire_offline_data_directory(&alias).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn final_data_directory_junction_is_rejected_before_backup_or_restore() {
        let root = test_root("data-dir-junction");
        let real = root.path.join("real-data");
        let alias = root.path.join("data-alias");
        fs::create_dir(&real).unwrap();
        create_database(&real.join("linklake.sqlite3"), "value");
        let status = std::process::Command::new("cmd")
            .args(["/d", "/c", "mklink", "/J"])
            .arg(&alias)
            .arg(&real)
            .status()
            .unwrap();
        assert!(
            status.success(),
            "could not create a test directory junction"
        );

        let error = backup_full(&alias, &root.path.join("alias.llb"), PASSWORD).unwrap_err();
        assert!(error.to_string().contains("reparse point"));
        assert!(acquire_offline_data_directory(&alias).is_err());
        fs::remove_dir(&alias).unwrap();
    }

    #[test]
    fn maintenance_lock_allows_parallel_backups_and_excludes_restore() {
        let root = test_root("maintenance-lock");
        let data_dir = root.path.join("data");
        fs::create_dir_all(&data_dir).unwrap();

        let first_backup = acquire_backup_maintenance(&data_dir).unwrap();
        let second_backup = acquire_backup_maintenance(&data_dir)
            .expect("multiple backups should share the maintenance lock");
        assert!(acquire_restore_maintenance(&data_dir).is_err());
        drop(second_backup);
        drop(first_backup);

        let restore = acquire_restore_maintenance(&data_dir).unwrap();
        assert!(acquire_backup_maintenance(&data_dir).is_err());
        assert!(acquire_restore_maintenance(&data_dir).is_err());
        drop(restore);
        acquire_backup_maintenance(&data_dir)
            .expect("maintenance lock should be reusable after release");
    }

    #[cfg(windows)]
    #[test]
    fn windows_managed_and_external_dacls_are_protected_and_least_privilege() {
        let root = test_root("windows-dacl");
        let managed_directory = root.path.join("managed");
        let managed_file = managed_directory.join("secret.bin");
        let external_file = root.path.join("external.llb");
        fs::create_dir(&managed_directory).unwrap();
        restrict_directory_permissions(&managed_directory).unwrap();
        let mut managed = create_managed_new_file(&managed_file).unwrap();
        managed.write_all(b"managed").unwrap();
        managed.sync_all().unwrap();
        drop(managed);
        let mut external = create_external_backup_new_file(&external_file).unwrap();
        external.write_all(b"external").unwrap();
        external.sync_all().unwrap();
        drop(external);

        let directory_sddl = windows_dacl_sddl(&managed_directory);
        let managed_sddl = windows_dacl_sddl(&managed_file);
        let external_sddl = windows_dacl_sddl(&external_file);
        for sddl in [&directory_sddl, &managed_sddl] {
            assert!(sddl.starts_with("D:P"), "DACL is not protected: {sddl}");
            for trustee in ["SY", "BA", "LS", "OW"] {
                assert!(sddl.contains(&format!(";;;{trustee})")), "{sddl}");
            }
            assert!(
                !sddl.contains(";;;WD)"),
                "Everyone must not have access: {sddl}"
            );
            assert!(
                !sddl.contains(";;;BU)"),
                "Users must not have access: {sddl}"
            );
        }
        assert!(external_sddl.starts_with("D:P"));
        for trustee in ["SY", "BA", "OW"] {
            assert!(external_sddl.contains(&format!(";;;{trustee})")));
        }
        assert!(!external_sddl.contains(";;;LS)"));
        assert!(!external_sddl.contains(";;;WD)"));
        assert!(!external_sddl.contains(";;;BU)"));

        fs::write(&managed_file, b"owner-can-maintain").unwrap();
        assert_eq!(fs::read(&managed_file).unwrap(), b"owner-can-maintain");
    }

    #[cfg(unix)]
    #[test]
    fn unix_plaintext_staging_and_encrypted_outputs_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let root = test_root("unix-permissions");
        let staging = TemporaryDirectory::create_in(&root.path, "plaintext").unwrap();
        let staging_mode = fs::metadata(&staging.path).unwrap().permissions().mode() & 0o777;
        let activity_mode = fs::metadata(staging.path.join(".active.lock"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(staging_mode, 0o700);
        assert_eq!(activity_mode, 0o600);
        drop(staging);

        let data_dir = root.path.join("data");
        fs::create_dir(&data_dir).unwrap();
        create_database(&data_dir.join("linklake.sqlite3"), "permissions");
        let archive = root.path.join("managed-state.llb");
        backup_full(&data_dir, &archive, PASSWORD).unwrap();
        let archive_mode = fs::metadata(&archive).unwrap().permissions().mode() & 0o777;
        assert_eq!(archive_mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn root_database_restore_preserves_database_owner_and_uses_data_owner_when_missing() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        if unsafe { libc::geteuid() } != 0 {
            return;
        }

        fn change_owner(path: &Path, uid: u32, gid: u32) {
            use std::{ffi::CString, os::unix::ffi::OsStrExt};

            let encoded = CString::new(path.as_os_str().as_bytes()).unwrap();
            // SAFETY: encoded 以 NUL 结尾并在调用期间有效；测试以 root 运行。
            let result = unsafe { libc::chown(encoded.as_ptr(), uid, gid) };
            assert_eq!(
                result,
                0,
                "could not chown {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            );
        }

        fn assert_owner(path: &Path, uid: u32, gid: u32) {
            let metadata = fs::symlink_metadata(path).unwrap();
            assert_eq!(metadata.uid(), uid, "unexpected uid for {}", path.display());
            assert_eq!(metadata.gid(), gid, "unexpected gid for {}", path.display());
        }

        const DATA_UID: u32 = 42_400;
        const DATA_GID: u32 = 42_401;
        const DATABASE_UID: u32 = 42_410;
        const DATABASE_GID: u32 = 42_411;
        let root = test_root("root-database-restore-ownership");
        let data_dir = root.path.join("data");
        fs::create_dir(&data_dir).unwrap();
        create_database(&data_dir.join("linklake.sqlite3"), "before");
        change_owner(&data_dir, DATA_UID, DATA_GID);
        change_owner(
            &data_dir.join("linklake.sqlite3"),
            DATABASE_UID,
            DATABASE_GID,
        );
        fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700)).unwrap();

        let archive = root.path.join("database.sqlite3");
        backup_database(&data_dir, &archive).unwrap();
        restore_database(&data_dir, &archive).unwrap();
        assert_owner(
            &data_dir.join("linklake.sqlite3"),
            DATABASE_UID,
            DATABASE_GID,
        );

        let missing_data_dir = root.path.join("missing-data");
        fs::create_dir(&missing_data_dir).unwrap();
        change_owner(&missing_data_dir, DATA_UID, DATA_GID);
        fs::set_permissions(&missing_data_dir, fs::Permissions::from_mode(0o700)).unwrap();
        restore_database(&missing_data_dir, &archive).unwrap();
        assert_owner(
            &missing_data_dir.join("linklake.sqlite3"),
            DATA_UID,
            DATA_GID,
        );
        assert_owner(
            &missing_data_dir.join(MAINTENANCE_LOCK_NAME),
            DATA_UID,
            DATA_GID,
        );
        assert_owner(
            &missing_data_dir.join("linklake.sqlite3.lock"),
            DATA_UID,
            DATA_GID,
        );
    }

    #[cfg(unix)]
    #[test]
    fn root_full_restore_preserves_each_managed_owner_for_nested_files() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        if unsafe { libc::geteuid() } != 0 {
            return;
        }

        fn change_owner(path: &Path, uid: u32, gid: u32) {
            use std::{ffi::CString, os::unix::ffi::OsStrExt};

            let encoded = CString::new(path.as_os_str().as_bytes()).unwrap();
            // SAFETY: the path is NUL-terminated and this test only mutates its temporary tree.
            let result = unsafe { libc::chown(encoded.as_ptr(), uid, gid) };
            assert_eq!(
                result,
                0,
                "could not chown {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            );
        }

        fn change_tree_owner(path: &Path, uid: u32, gid: u32) {
            let metadata = fs::symlink_metadata(path).unwrap();
            if metadata.is_dir() {
                for entry in fs::read_dir(path).unwrap() {
                    change_tree_owner(&entry.unwrap().path(), uid, gid);
                }
            }
            change_owner(path, uid, gid);
        }

        fn assert_tree_owner(path: &Path, uid: u32, gid: u32) {
            let metadata = fs::symlink_metadata(path).unwrap();
            assert_eq!(metadata.uid(), uid, "unexpected uid for {}", path.display());
            assert_eq!(metadata.gid(), gid, "unexpected gid for {}", path.display());
            if metadata.is_dir() {
                for entry in fs::read_dir(path).unwrap() {
                    assert_tree_owner(&entry.unwrap().path(), uid, gid);
                }
            }
        }

        const DATA_OWNER: (u32, u32) = (42_500, 42_501);
        const DATABASE_OWNER: (u32, u32) = (42_510, 42_511);
        const ACME_OWNER: (u32, u32) = (42_520, 42_521);
        const CERTIFICATES_OWNER: (u32, u32) = (42_530, 42_531);
        let root = test_root("root-full-restore-ownership");
        let data_dir = root.path.join("data");
        let acme = data_dir.join("acme");
        let certificates = data_dir.join("certificates");
        fs::create_dir_all(acme.join("accounts/production")).unwrap();
        fs::create_dir_all(certificates.join("example.com/generations/1")).unwrap();
        create_database(&data_dir.join("linklake.sqlite3"), "before");
        fs::write(acme.join("accounts/production/account.json"), b"account").unwrap();
        let (fullchain, private_key) = test_certificate_pair("example.com");
        fs::write(
            certificates.join("example.com/generations/1/fullchain.pem"),
            fullchain,
        )
        .unwrap();
        fs::write(
            certificates.join("example.com/generations/1/private-key.pem"),
            private_key,
        )
        .unwrap();
        fs::write(certificates.join("example.com/current"), b"1\n").unwrap();

        change_owner(&data_dir, DATA_OWNER.0, DATA_OWNER.1);
        change_owner(
            &data_dir.join("linklake.sqlite3"),
            DATABASE_OWNER.0,
            DATABASE_OWNER.1,
        );
        change_tree_owner(&acme, ACME_OWNER.0, ACME_OWNER.1);
        change_tree_owner(&certificates, CERTIFICATES_OWNER.0, CERTIFICATES_OWNER.1);
        fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700)).unwrap();

        let archive = root.path.join("managed-state.llb");
        backup_full(&data_dir, &archive, PASSWORD).unwrap();
        fs::write(acme.join("accounts/production/account.json"), b"mutated").unwrap();
        restore_full(&data_dir, &archive, PASSWORD).unwrap();

        assert_tree_owner(
            &data_dir.join("linklake.sqlite3"),
            DATABASE_OWNER.0,
            DATABASE_OWNER.1,
        );
        assert_tree_owner(&data_dir.join("acme"), ACME_OWNER.0, ACME_OWNER.1);
        assert_tree_owner(
            &data_dir.join("certificates"),
            CERTIFICATES_OWNER.0,
            CERTIFICATES_OWNER.1,
        );
        assert_tree_owner(
            &data_dir.join(MAINTENANCE_LOCK_NAME),
            DATA_OWNER.0,
            DATA_OWNER.1,
        );
        assert_tree_owner(
            &data_dir.join("linklake.sqlite3.lock"),
            DATA_OWNER.0,
            DATA_OWNER.1,
        );
    }

    #[test]
    fn prepared_restore_journal_rolls_back_a_partial_multi_path_install() {
        let root = test_root("journal-rollback");
        let data_dir = root.path.join("data");
        fs::create_dir(&data_dir).unwrap();
        let (mut staging, journal) = staged_restore(&data_dir, "old", "new");
        let preserved = data_dir.join(&journal.preserved_directory);
        let payload = staging.path.join("unpacked");

        for name in ["linklake.sqlite3", "acme", "certificates"] {
            fs::rename(data_dir.join(name), preserved.join(name)).unwrap();
        }
        fs::rename(
            payload.join("linklake.sqlite3"),
            data_dir.join("linklake.sqlite3"),
        )
        .unwrap();
        fs::rename(payload.join("acme"), data_dir.join("acme")).unwrap();
        staging.preserve_on_drop();
        drop(staging);

        // 模拟回滚完成但 journal 删除前再次断电；第二次恢复必须保持幂等。
        rollback_prepared_restore(&data_dir, &journal).unwrap();
        let maintenance = acquire_restore_maintenance(&data_dir).unwrap();
        recover_interrupted_restore(&data_dir, &maintenance).unwrap();
        drop(maintenance);
        assert_eq!(
            read_database_value(&data_dir.join("linklake.sqlite3")),
            "old"
        );
        assert_eq!(
            fs::read_to_string(data_dir.join("acme/state")).unwrap(),
            "old-old"
        );
        assert_eq!(
            fs::read_to_string(data_dir.join("certificates/key")).unwrap(),
            "old-old"
        );
        assert!(!data_dir.join(RESTORE_JOURNAL_NAME).exists());
        assert!(!data_dir.join(&journal.staging_directory).exists());
        assert!(!preserved.exists());
    }

    #[test]
    fn committed_restore_journal_finishes_cleanup_without_rolling_back() {
        let root = test_root("journal-commit");
        let data_dir = root.path.join("data");
        fs::create_dir(&data_dir).unwrap();
        let (mut staging, journal) = staged_restore(&data_dir, "old", "new");
        let preserved = data_dir.join(&journal.preserved_directory);
        let payload = staging.path.join("unpacked");

        for name in ["linklake.sqlite3", "acme", "certificates"] {
            fs::rename(data_dir.join(name), preserved.join(name)).unwrap();
            fs::rename(payload.join(name), data_dir.join(name)).unwrap();
        }
        commit_restore_journal(&data_dir).unwrap();
        staging.preserve_on_drop();
        drop(staging);

        let maintenance = acquire_restore_maintenance(&data_dir).unwrap();
        recover_interrupted_restore(&data_dir, &maintenance).unwrap();
        drop(maintenance);
        assert_eq!(
            read_database_value(&data_dir.join("linklake.sqlite3")),
            "new"
        );
        assert_eq!(
            fs::read_to_string(data_dir.join("acme/state")).unwrap(),
            "new-new"
        );
        assert_eq!(
            fs::read_to_string(data_dir.join("certificates/key")).unwrap(),
            "new-new"
        );
        assert_eq!(
            read_database_value(&preserved.join("linklake.sqlite3")),
            "old"
        );
        assert!(!data_dir.join(RESTORE_JOURNAL_NAME).exists());
        assert!(!data_dir.join(&journal.staging_directory).exists());
    }

    #[test]
    fn rolled_back_marker_allows_recovery_after_staging_was_already_removed() {
        let root = test_root("journal-rolled-back-marker");
        let data_dir = root.path.join("data");
        fs::create_dir(&data_dir).unwrap();
        let (mut staging, journal) = staged_restore(&data_dir, "old", "new");
        let preserved = data_dir.join(&journal.preserved_directory);
        let payload = staging.path.join("unpacked");

        for name in ["linklake.sqlite3", "acme", "certificates"] {
            fs::rename(data_dir.join(name), preserved.join(name)).unwrap();
        }
        fs::rename(
            payload.join("linklake.sqlite3"),
            data_dir.join("linklake.sqlite3"),
        )
        .unwrap();
        staging.preserve_on_drop();
        drop(staging);

        rollback_prepared_restore(&data_dir, &journal).unwrap();
        mark_restore_rolled_back(&data_dir).unwrap();
        cleanup_rolled_back_restore(&data_dir, &journal, true).unwrap();
        assert!(data_dir.join(RESTORE_JOURNAL_NAME).exists());
        assert!(!data_dir.join(&journal.staging_directory).exists());
        assert!(!preserved.exists());

        let maintenance = acquire_restore_maintenance(&data_dir).unwrap();
        recover_interrupted_restore(&data_dir, &maintenance).unwrap();
        drop(maintenance);
        assert_eq!(
            read_database_value(&data_dir.join("linklake.sqlite3")),
            "old"
        );
        assert!(!data_dir.join(RESTORE_JOURNAL_NAME).exists());
    }

    #[test]
    fn partial_rolled_back_marker_is_replayed_as_prepared_state() {
        let root = test_root("journal-partial-rolled-back-marker");
        let data_dir = root.path.join("data");
        fs::create_dir(&data_dir).unwrap();
        let (_staging, _journal) = staged_restore(&data_dir, "old", "new");
        let journal_path = data_dir.join(RESTORE_JOURNAL_NAME);
        OpenOptions::new()
            .append(true)
            .open(&journal_path)
            .unwrap()
            .write_all(&RESTORE_ROLLED_BACK_MARKER[..2])
            .unwrap();

        let maintenance = acquire_restore_maintenance(&data_dir).unwrap();
        recover_interrupted_restore(&data_dir, &maintenance).unwrap();
        drop(maintenance);
        assert_eq!(
            read_database_value(&data_dir.join("linklake.sqlite3")),
            "old"
        );
        assert!(!journal_path.exists());
    }

    #[test]
    fn backup_fails_closed_for_prepared_and_committed_restore_journals() {
        let root = test_root("journal-backup-exclusion");
        let data_dir = root.path.join("data");
        fs::create_dir(&data_dir).unwrap();
        let (_staging, _journal) = staged_restore(&data_dir, "old", "new");

        assert!(acquire_backup_maintenance(&data_dir).is_err());
        commit_restore_journal(&data_dir).unwrap();
        assert!(acquire_backup_maintenance(&data_dir).is_err());
    }

    #[test]
    fn path_and_archive_validation_rejects_traversal_links_and_hard_links() {
        assert!(normalize_archive_path(Path::new("../escape")).is_err());
        assert!(normalize_archive_path(Path::new("/absolute")).is_err());
        assert!(normalize_logical_path("acme/../../escape").is_err());
        assert!(normalize_logical_path("acme/CON").is_err());
        assert!(normalize_logical_path("certificates/key.pem.").is_err());

        let root = test_root("archive-links");
        let tar_path = root.path.join("link.tar");
        let file = File::create(&tar_path).unwrap();
        let mut builder = tar::Builder::new(file);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        header.set_link_name("../../escape").unwrap();
        header.set_cksum();
        builder
            .append_data(&mut header, "acme/unsafe", std::io::empty())
            .unwrap();
        builder.finish().unwrap();
        let unpacked = root.path.join("unpacked");
        fs::create_dir(&unpacked).unwrap();
        let header = BackupHeader {
            format: FORMAT_NAME.into(),
            format_version: FORMAT_VERSION,
            created_at_unix_seconds: 1,
            source_version: env!("CARGO_PKG_VERSION").into(),
            kdf: KdfHeader {
                algorithm: KDF_NAME.into(),
                version: KDF_VERSION,
                memory_kib: KDF_MEMORY_KIB,
                iterations: KDF_ITERATIONS,
                parallelism: KDF_PARALLELISM,
                salt_base64: STANDARD.encode([0_u8; SALT_LEN]),
            },
            cipher: CipherHeader {
                algorithm: CIPHER_NAME.into(),
                chunk_size: CHUNK_SIZE as u32,
                nonce_prefix_base64: STANDARD.encode([0_u8; NONCE_PREFIX_LEN]),
            },
        };
        let error = extract_and_validate_tar(&tar_path, &unpacked, &header).unwrap_err();
        assert!(error.to_string().contains("links or special files"));

        let data_dir = root.path.join("hardlink-data");
        fs::create_dir_all(data_dir.join("certificates")).unwrap();
        create_database(&data_dir.join("linklake.sqlite3"), "value");
        let first = data_dir.join("certificates/key.pem");
        let second = data_dir.join("certificates/key-copy.pem");
        fs::write(&first, b"private key").unwrap();
        fs::hard_link(&first, &second).unwrap();
        let error = backup_full(&data_dir, &root.path.join("hardlink.llb"), PASSWORD).unwrap_err();
        assert!(error.to_string().contains("hard-linked"));
    }

    #[cfg(unix)]
    #[test]
    fn backup_rejects_case_fold_collisions_before_creating_an_archive() {
        use std::os::unix::fs::MetadataExt;

        let root = test_root("case-fold-collision");
        let data_dir = root.path.join("data");
        fs::create_dir_all(data_dir.join("acme")).unwrap();
        create_database(&data_dir.join("linklake.sqlite3"), "portable");
        let upper = data_dir.join("acme/Foo");
        let lower = data_dir.join("acme/foo");
        fs::write(&upper, b"first").unwrap();
        fs::write(&lower, b"second").unwrap();
        let archive = root.path.join("collision.llb");

        // 默认 APFS 不区分大小写，无法构造两个独立目录项，此时跳过该场景。
        let upper_metadata = fs::metadata(&upper).unwrap();
        let lower_metadata = fs::metadata(&lower).unwrap();
        if upper_metadata.dev() == lower_metadata.dev()
            && upper_metadata.ino() == lower_metadata.ino()
        {
            assert!(!archive.exists());
            return;
        }

        let error = backup_full(&data_dir, &archive, PASSWORD).unwrap_err();
        assert!(error.to_string().contains("case-insensitive platform"));
        assert!(!archive.exists());
    }

    #[test]
    fn managed_file_copy_stops_before_exceeding_the_remaining_budget() {
        let root = test_root("copy-budget");
        let source = root.path.join("source.bin");
        let destination = root.path.join("payload/destination.bin");
        fs::write(&source, vec![0x5a; 128]).unwrap();

        let error = copy_file_and_hash(&source, &destination, 64).unwrap_err();
        assert!(error.to_string().contains("remaining backup budget"));
        assert!(!destination.exists());
    }

    #[test]
    fn short_passwords_are_rejected_without_echoing_secret_material() {
        let error = require_password(b"too-short").unwrap_err();
        let message = error.to_string();
        assert!(message.contains("at least"));
        assert!(!message.contains("too-short"));
    }

    #[test]
    fn producer_and_consumer_share_file_directory_and_entry_limits() {
        assert!(validate_single_file_length(MAX_FILE_BYTES).is_ok());
        assert!(validate_single_file_length(MAX_FILE_BYTES + 1).is_err());
        assert_eq!(
            MAX_TAR_ENTRY_COUNT,
            1 + MAX_FILE_COUNT + MAX_DIRECTORY_COUNT
        );

        let manifest = BackupManifest {
            format: MANIFEST_NAME.into(),
            format_version: MANIFEST_VERSION,
            source_version: env!("CARGO_PKG_VERSION").into(),
            created_at_unix_seconds: 1,
            directories: (0..=MAX_DIRECTORY_COUNT)
                .map(|index| format!("acme/d{index}"))
                .collect(),
            files: Vec::new(),
        };
        let header = BackupHeader {
            format: FORMAT_NAME.into(),
            format_version: FORMAT_VERSION,
            created_at_unix_seconds: 1,
            source_version: env!("CARGO_PKG_VERSION").into(),
            kdf: KdfHeader {
                algorithm: KDF_NAME.into(),
                version: KDF_VERSION,
                memory_kib: KDF_MEMORY_KIB,
                iterations: KDF_ITERATIONS,
                parallelism: KDF_PARALLELISM,
                salt_base64: STANDARD.encode([0_u8; SALT_LEN]),
            },
            cipher: CipherHeader {
                algorithm: CIPHER_NAME.into(),
                chunk_size: CHUNK_SIZE as u32,
                nonce_prefix_base64: STANDARD.encode([0_u8; NONCE_PREFIX_LEN]),
            },
        };
        let error =
            validate_manifest(&manifest, &header, &BTreeSet::new(), &BTreeMap::new()).unwrap_err();
        assert!(error.to_string().contains("too many directories"));
    }

    #[test]
    fn no_replace_install_rejects_preexisting_and_concurrent_destinations() {
        use std::sync::{Arc, Barrier};

        let root = test_root("no-replace");
        let temporary = root.path.join("temporary");
        let destination = root.path.join("destination");
        fs::write(&temporary, b"new").unwrap();
        fs::write(&destination, b"old").unwrap();
        assert!(install_no_replace(&temporary, &destination).is_err());
        assert_eq!(fs::read(&destination).unwrap(), b"old");
        assert_eq!(fs::read(&temporary).unwrap(), b"new");

        let first = root.path.join("first");
        let second = root.path.join("second");
        let concurrent_destination = root.path.join("concurrent");
        fs::write(&first, b"first").unwrap();
        fs::write(&second, b"second").unwrap();
        let barrier = Arc::new(Barrier::new(3));
        let first_thread = {
            let barrier = Arc::clone(&barrier);
            let destination = concurrent_destination.clone();
            std::thread::spawn(move || {
                barrier.wait();
                install_no_replace(&first, &destination)
            })
        };
        let second_thread = {
            let barrier = Arc::clone(&barrier);
            let destination = concurrent_destination.clone();
            std::thread::spawn(move || {
                barrier.wait();
                install_no_replace(&second, &destination)
            })
        };
        barrier.wait();
        let results = [first_thread.join().unwrap(), second_thread.join().unwrap()];
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        let installed = fs::read(&concurrent_destination).unwrap();
        assert!(installed == b"first" || installed == b"second");
    }

    #[test]
    fn encrypted_output_collision_removes_its_temporary_file() {
        let root = test_root("encrypted-output-cleanup");
        let plaintext = root.path.join("payload.tar");
        let output = root.path.join("archive.llb");
        fs::write(&plaintext, b"authenticated plaintext").unwrap();
        fs::write(&output, b"preexisting archive").unwrap();

        let error = encrypt_and_install_archive(&plaintext, &output, PASSWORD, 1).unwrap_err();
        assert!(error
            .to_string()
            .contains("without replacing an existing file"));
        assert_eq!(fs::read(&output).unwrap(), b"preexisting archive");
        assert!(!fs::read_dir(&root.path)
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| entry.file_name().to_string_lossy().contains(".encrypt-")));
    }

    #[test]
    fn stale_plaintext_staging_is_cleaned_without_touching_an_active_backup() {
        let root = test_root("staging-cleanup");
        let data_dir = root.path.join("data");
        fs::create_dir(&data_dir).unwrap();
        let active = TemporaryDirectory::create_in(&data_dir, "linklake-backup-staging").unwrap();
        fs::write(active.path.join("private-key"), b"active-secret").unwrap();

        let stale = data_dir.join(format!("{BACKUP_STAGING_PREFIX}{}", Uuid::new_v4()));
        fs::create_dir(&stale).unwrap();
        fs::write(stale.join("private-key"), b"stale-secret").unwrap();
        cleanup_stale_staging(&data_dir, BACKUP_STAGING_PREFIX).unwrap();

        assert!(active.path.exists());
        assert!(!stale.exists());
    }
}
