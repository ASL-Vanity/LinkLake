//! 更新状态、计划和恢复 journal 的持久化原语。
//!
//! 本模块把“写入成功”定义为：同目录临时文件已经落盘、目录项已经原子替换，
//! 并且父目录已经完成平台可提供的持久化同步。所有读取都限制大小并拒绝符号
//! 链接或 Windows reparse point，避免更新器在高权限环境中越过状态目录边界。

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
};
use uuid::Uuid;

pub(crate) const UPDATE_LOCK_NAME: &str = "update.lock";
const JOURNAL_SCHEMA_VERSION: u32 = 1;
const JOURNAL_ENVELOPE_OVERHEAD: u64 = 4 * 1024;

/// 持有更新状态目录的排他进程锁。
///
/// 锁文件不会在释放时删除，避免“删除旧 inode 后另一进程锁住新 inode”的竞态。
/// Unix 使用 `flock`，Windows 使用禁止共享的文件句柄；`Drop` 会释放对应的内核锁。
pub(crate) struct UpdateLock {
    file: File,
}

impl UpdateLock {
    pub(crate) fn acquire(state_directory: &Path) -> Result<Self> {
        let state_directory = validate_existing_directory(state_directory)?;
        let lock_path = validate_managed_file_path(&state_directory.join(UPDATE_LOCK_NAME), true)?;

        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        configure_lock_open_options(&mut options);
        let mut file = options
            .open(&lock_path)
            .with_context(|| format!("cannot open update lock {}", lock_path.display()))?;
        validate_open_regular_file(&lock_path, &file)?;
        lock_file_exclusive(&file, &lock_path)?;

        // 诊断内容不参与加锁语义；它只帮助管理员确认最后一个持锁进程。
        if let Err(error) = (|| -> Result<()> {
            file.set_len(0)?;
            file.seek(SeekFrom::Start(0))?;
            writeln!(file, "pid={}", std::process::id())?;
            file.sync_all()?;
            sync_parent_directory(&state_directory)?;
            Ok(())
        })() {
            unlock_file(&file);
            return Err(error).context("cannot persist update lock metadata");
        }

        Ok(Self { file })
    }
}

impl Drop for UpdateLock {
    fn drop(&mut self) {
        unlock_file(&self.file);
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalEnvelope {
    schema_version: u32,
    payload_length: u64,
    payload_sha256: String,
    payload_base64: String,
}

/// 以同目录临时文件、文件同步、原子替换和父目录同步写入字节。
pub(crate) fn write_durable_bytes(path: &Path, bytes: &[u8], max_bytes: u64) -> Result<()> {
    ensure_length_within_limit(bytes.len(), max_bytes, "durable payload")?;
    let target = validate_managed_file_path(path, true)?;
    let parent = target
        .parent()
        .ok_or_else(|| anyhow::anyhow!("durable target has no parent directory"))?;
    let file_name = target
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("durable target has no file name"))?
        .to_string_lossy();
    let temporary = parent.join(format!(
        ".{file_name}.tmp-{}-{}",
        std::process::id(),
        Uuid::new_v4().simple()
    ));
    let mut cleanup = TemporaryFileGuard::new(temporary.clone());

    let mut options = OpenOptions::new();
    options.write(true).read(true).create_new(true);
    configure_new_file_open_options(&mut options);
    let mut file = options
        .open(&temporary)
        .with_context(|| format!("cannot create durable temporary {}", temporary.display()))?;
    validate_open_regular_file(&temporary, &file)?;
    file.write_all(bytes)?;
    file.flush()?;
    file.sync_all()?;
    drop(file);

    // 在替换前再次检查父目录与目标，缩小检查和使用之间的竞态窗口。
    validate_existing_directory(parent)?;
    validate_managed_file_path(&target, true)?;
    atomic_replace(&temporary, &target)?;
    cleanup.disarm();
    sync_parent_directory(parent)?;
    Ok(())
}

/// 紧凑序列化 JSON 后使用持久化字节写入流程。
pub(crate) fn write_durable_json<T: Serialize>(
    path: &Path,
    value: &T,
    max_bytes: u64,
) -> Result<()> {
    let encoded = serde_json::to_vec(value).context("cannot serialize durable JSON")?;
    write_durable_bytes(path, &encoded, max_bytes)
}

/// 读取普通文件，并在分配和读取两个阶段都执行大小限制。
pub(crate) fn read_limited_bytes(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    anyhow::ensure!(
        max_bytes < u64::MAX && usize::try_from(max_bytes).is_ok(),
        "durable read limit exceeds this platform's address space"
    );
    let path = validate_managed_file_path(path, false)?;
    let file = open_regular_file_no_follow(&path)?;
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.len() <= max_bytes,
        "durable file exceeds the configured size limit: {}",
        path.display()
    );

    let capacity = usize::try_from(metadata.len())
        .context("durable file length exceeds this platform's address space")?;
    let mut bytes = Vec::with_capacity(capacity);
    file.take(max_bytes + 1).read_to_end(&mut bytes)?;
    ensure_length_within_limit(bytes.len(), max_bytes, "durable file")?;
    Ok(bytes)
}

pub(crate) fn read_limited_json<T: DeserializeOwned>(path: &Path, max_bytes: u64) -> Result<T> {
    let bytes = read_limited_bytes(path, max_bytes)?;
    serde_json::from_slice(&bytes).context("durable JSON is malformed")
}

/// 删除由更新器管理的常规文件，并在可用的平台上同步父目录。
/// 此函数拒绝符号链接和重解析点；调用方只能用它清理已认证的状态标记。
pub(crate) fn remove_durable_file(path: &Path) -> Result<()> {
    let path = validate_managed_file_path(path, false)?;
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("durable target has no parent directory"))?;
    fs::remove_file(&path)
        .with_context(|| format!("cannot remove durable file {}", path.display()))?;
    sync_parent_directory(parent)?;
    Ok(())
}

/// 把任意 payload 封装成带长度和 SHA-256 的 JSON journal。
pub(crate) fn write_journal_bytes(
    path: &Path,
    payload: &[u8],
    max_payload_bytes: u64,
) -> Result<()> {
    ensure_length_within_limit(payload.len(), max_payload_bytes, "journal payload")?;
    let payload_length = u64::try_from(payload.len())
        .context("journal payload length exceeds the supported range")?;
    let envelope = JournalEnvelope {
        schema_version: JOURNAL_SCHEMA_VERSION,
        payload_length,
        payload_sha256: sha256_bytes(payload),
        payload_base64: BASE64_STANDARD.encode(payload),
    };
    write_durable_json(path, &envelope, journal_envelope_limit(max_payload_bytes)?)
}

/// 读取 journal 时先限制 envelope，再核对版本、长度、Base64 和 payload SHA-256。
#[allow(dead_code)]
pub(crate) fn read_journal_bytes(path: &Path, max_payload_bytes: u64) -> Result<Vec<u8>> {
    let envelope: JournalEnvelope =
        read_limited_json(path, journal_envelope_limit(max_payload_bytes)?)?;
    anyhow::ensure!(
        envelope.schema_version == JOURNAL_SCHEMA_VERSION,
        "unsupported durable journal schema version {}",
        envelope.schema_version
    );
    anyhow::ensure!(
        envelope.payload_length <= max_payload_bytes,
        "journal payload exceeds the configured size limit"
    );
    anyhow::ensure!(
        is_lower_hex_sha256(&envelope.payload_sha256),
        "journal payload SHA-256 is malformed"
    );
    let expected_encoded_length = base64_encoded_length(envelope.payload_length)?;
    anyhow::ensure!(
        u64::try_from(envelope.payload_base64.len()).ok() == Some(expected_encoded_length),
        "journal payload Base64 length does not match its declared size"
    );

    let payload = BASE64_STANDARD
        .decode(envelope.payload_base64.as_bytes())
        .context("journal payload Base64 is malformed")?;
    anyhow::ensure!(
        u64::try_from(payload.len()).ok() == Some(envelope.payload_length),
        "journal payload length does not match its declaration"
    );
    anyhow::ensure!(
        sha256_bytes(&payload) == envelope.payload_sha256,
        "journal payload SHA-256 mismatch"
    );
    Ok(payload)
}

pub(crate) fn write_journal_json<T: Serialize>(
    path: &Path,
    payload: &T,
    max_payload_bytes: u64,
) -> Result<()> {
    let payload = serde_json::to_vec(payload).context("cannot serialize journal payload")?;
    write_journal_bytes(path, &payload, max_payload_bytes)
}

#[allow(dead_code)]
pub(crate) fn read_journal_json<T: DeserializeOwned>(
    path: &Path,
    max_payload_bytes: u64,
) -> Result<T> {
    let payload = read_journal_bytes(path, max_payload_bytes)?;
    serde_json::from_slice(&payload).context("journal payload JSON is malformed")
}

struct TemporaryFileGuard {
    path: PathBuf,
    armed: bool,
}

impl TemporaryFileGuard {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TemporaryFileGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn ensure_length_within_limit(length: usize, limit: u64, label: &str) -> Result<()> {
    anyhow::ensure!(
        u64::try_from(length).is_ok_and(|length| length <= limit),
        "{label} exceeds the configured size limit"
    );
    Ok(())
}

fn journal_envelope_limit(max_payload_bytes: u64) -> Result<u64> {
    base64_encoded_length(max_payload_bytes)?
        .checked_add(JOURNAL_ENVELOPE_OVERHEAD)
        .ok_or_else(|| anyhow::anyhow!("journal size limit overflow"))
}

fn base64_encoded_length(length: u64) -> Result<u64> {
    length
        .checked_add(2)
        .and_then(|value| value.checked_div(3))
        .and_then(|value| value.checked_mul(4))
        .ok_or_else(|| anyhow::anyhow!("journal payload size overflow"))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[allow(dead_code)]
fn is_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .as_bytes()
            .iter()
            .all(|value| value.is_ascii_digit() || (b'a'..=b'f').contains(value))
}

fn normalize_absolute_path(path: &Path) -> Result<PathBuf> {
    anyhow::ensure!(
        !path.as_os_str().is_empty(),
        "managed path must not be empty"
    );
    reject_windows_namespace(path)?;
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::ParentDir => {
                anyhow::bail!(
                    "managed paths must not contain parent traversal: {}",
                    path.display()
                )
            }
            Component::CurDir => {}
            Component::Normal(value) => {
                validate_platform_component(value, path)?;
                normalized.push(value);
            }
            Component::Prefix(_) | Component::RootDir => normalized.push(component.as_os_str()),
        }
    }
    anyhow::ensure!(
        normalized.is_absolute(),
        "managed path could not be resolved absolutely: {}",
        path.display()
    );
    Ok(normalized)
}

/// `\\\\?\\` 与 `\\\\.\\` 会绕开 Win32 的常规路径归一化和设备名规则。
/// 更新状态目录可能由高权限服务读取，因此必须在任何文件系统 I/O 之前拒绝它们。
#[cfg(windows)]
fn reject_windows_namespace(path: &Path) -> Result<()> {
    let value = path.as_os_str().to_string_lossy().replace('/', "\\");
    anyhow::ensure!(
        !value.starts_with(r"\\?\") && !value.starts_with(r"\\.\"),
        "managed path must not use a Windows verbatim or device namespace: {}",
        path.display()
    );
    Ok(())
}

#[cfg(not(windows))]
fn reject_windows_namespace(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(windows)]
fn validate_platform_component(value: &std::ffi::OsStr, full_path: &Path) -> Result<()> {
    let value = value.to_string_lossy();
    anyhow::ensure!(
        !value.contains(':') && !value.ends_with('.') && !value.ends_with(' '),
        "managed path contains a Windows alias or stream component: {}",
        full_path.display()
    );
    let stem = value
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    let reserved = matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || stem.strip_prefix("COM").is_some_and(|suffix| {
        matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
    }) || stem.strip_prefix("LPT").is_some_and(|suffix| {
        matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
    });
    anyhow::ensure!(
        !reserved,
        "managed path contains a reserved Windows device component: {}",
        full_path.display()
    );
    Ok(())
}

#[cfg(not(windows))]
fn validate_platform_component(_value: &std::ffi::OsStr, _full_path: &Path) -> Result<()> {
    Ok(())
}

fn validate_existing_directory(path: &Path) -> Result<PathBuf> {
    let path = normalize_absolute_path(path)?;
    validate_existing_components(&path, false)?;
    let metadata = safe_symlink_metadata(&path)?;
    reject_reparse_point(&path, &metadata)?;
    anyhow::ensure!(
        metadata.is_dir(),
        "managed directory is not a directory: {}",
        path.display()
    );
    Ok(path)
}

fn validate_managed_file_path(path: &Path, allow_missing: bool) -> Result<PathBuf> {
    let path = normalize_absolute_path(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("managed file has no parent directory"))?;
    validate_existing_directory(parent)?;
    validate_existing_components(&path, allow_missing)?;
    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            reject_link_like_path(&path, &metadata)?;
            anyhow::ensure!(
                metadata.is_file(),
                "managed path is not a regular file: {}",
                path.display()
            );
        }
        Err(error) if allow_missing && error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("cannot inspect managed file {}", path.display()))
        }
    }
    Ok(path)
}

fn validate_existing_components(path: &Path, allow_missing_leaf: bool) -> Result<()> {
    let components = path.components().collect::<Vec<_>>();
    let mut current = PathBuf::new();
    for (index, component) in components.iter().enumerate() {
        current.push(component.as_os_str());
        if matches!(component, Component::Prefix(_)) {
            continue;
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                reject_link_like_path(&current, &metadata)?;
                if index + 1 < components.len() {
                    anyhow::ensure!(
                        metadata.is_dir(),
                        "managed path ancestor is not a directory: {}",
                        current.display()
                    );
                }
            }
            Err(error)
                if allow_missing_leaf
                    && index + 1 == components.len()
                    && error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "cannot inspect managed path component {}",
                        current.display()
                    )
                })
            }
        }
    }
    Ok(())
}

fn safe_symlink_metadata(path: &Path) -> Result<Metadata> {
    fs::symlink_metadata(path)
        .with_context(|| format!("cannot inspect managed path {}", path.display()))
}

fn reject_link_like_path(path: &Path, metadata: &Metadata) -> Result<()> {
    anyhow::ensure!(
        !metadata.file_type().is_symlink(),
        "managed paths must not contain symbolic links: {}",
        path.display()
    );
    reject_reparse_point(path, metadata)
}

#[cfg(windows)]
fn reject_reparse_point(path: &Path, metadata: &Metadata) -> Result<()> {
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
fn reject_reparse_point(_path: &Path, _metadata: &Metadata) -> Result<()> {
    Ok(())
}

fn open_regular_file_no_follow(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    configure_no_follow_open_options(&mut options);
    let file = options
        .open(path)
        .with_context(|| format!("cannot open managed file {}", path.display()))?;
    validate_open_regular_file(path, &file)?;
    Ok(file)
}

fn validate_open_regular_file(path: &Path, file: &File) -> Result<()> {
    let metadata = file.metadata()?;
    reject_reparse_point(path, &metadata)?;
    anyhow::ensure!(
        metadata.is_file(),
        "managed path is not a regular file: {}",
        path.display()
    );
    Ok(())
}

#[cfg(unix)]
fn configure_no_follow_open_options(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
}

#[cfg(windows)]
fn configure_no_follow_open_options(options: &mut OpenOptions) {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
}

#[cfg(not(any(unix, windows)))]
fn configure_no_follow_open_options(_options: &mut OpenOptions) {}

#[cfg(unix)]
fn configure_new_file_open_options(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
}

#[cfg(windows)]
fn configure_new_file_open_options(options: &mut OpenOptions) {
    configure_no_follow_open_options(options);
}

#[cfg(not(any(unix, windows)))]
fn configure_new_file_open_options(_options: &mut OpenOptions) {}

#[cfg(unix)]
fn configure_lock_open_options(options: &mut OpenOptions) {
    configure_new_file_open_options(options);
}

#[cfg(windows)]
fn configure_lock_open_options(options: &mut OpenOptions) {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    options
        .share_mode(0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
}

#[cfg(not(any(unix, windows)))]
fn configure_lock_open_options(_options: &mut OpenOptions) {}

#[cfg(unix)]
fn lock_file_exclusive(file: &File, path: &Path) -> Result<()> {
    use std::os::fd::AsRawFd;
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::WouldBlock {
        anyhow::bail!("another update process holds {}", path.display());
    }
    Err(error).with_context(|| format!("cannot lock {}", path.display()))
}

#[cfg(windows)]
fn lock_file_exclusive(_file: &File, _path: &Path) -> Result<()> {
    // `share_mode(0)` 已在打开句柄时完成排他加锁。
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn lock_file_exclusive(_file: &File, path: &Path) -> Result<()> {
    anyhow::bail!(
        "process-level update locking is unsupported on this platform: {}",
        path.display()
    )
}

#[cfg(unix)]
fn unlock_file(file: &File) {
    use std::os::fd::AsRawFd;
    let _ = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
}

#[cfg(not(unix))]
fn unlock_file(_file: &File) {
    // Windows 由 `File` 的 Drop 关闭禁止共享的句柄并释放锁。
}

#[cfg(unix)]
fn atomic_replace(source: &Path, target: &Path) -> Result<()> {
    fs::rename(source, target).with_context(|| {
        format!(
            "cannot atomically replace {} with {}",
            target.display(),
            source.display()
        )
    })
}

#[cfg(windows)]
fn atomic_replace(source: &Path, target: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(existing: *const u16, replacement: *const u16, flags: u32) -> i32;
    }

    fn wide_path(path: &Path) -> Result<Vec<u16>> {
        let mut encoded = path.as_os_str().encode_wide().collect::<Vec<_>>();
        anyhow::ensure!(
            !encoded.contains(&0),
            "managed Windows path contains an embedded NUL"
        );
        encoded.push(0);
        Ok(encoded)
    }

    let source_wide = wide_path(source)?;
    let target_wide = wide_path(target)?;
    let result = unsafe {
        MoveFileExW(
            source_wide.as_ptr(),
            target_wide.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "cannot atomically replace {} with {}",
                target.display(),
                source.display()
            )
        });
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn atomic_replace(source: &Path, target: &Path) -> Result<()> {
    fs::rename(source, target).with_context(|| {
        format!(
            "cannot atomically replace {} with {}",
            target.display(),
            source.display()
        )
    })
}

#[cfg(unix)]
fn sync_parent_directory(parent: &Path) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(parent)
        .with_context(|| format!("cannot open parent directory {}", parent.display()))?;
    directory
        .sync_all()
        .with_context(|| format!("cannot sync parent directory {}", parent.display()))
}

#[cfg(windows)]
fn sync_parent_directory(parent: &Path) -> Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_SHARE_DELETE: u32 = 0x0000_0004;

    validate_existing_directory(parent)?;
    let directory = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(parent)
        .with_context(|| format!("cannot open parent directory {}", parent.display()))?;
    let metadata = directory.metadata()?;
    reject_reparse_point(parent, &metadata)?;

    // Windows 的原子替换已经使用 MOVEFILE_WRITE_THROUGH。部分文件系统仍允许
    // FlushFileBuffers 目录句柄；已知不支持目录 flush 时由 write-through 提供保证。
    match directory.sync_all() {
        Ok(()) => Ok(()),
        Err(error) if matches!(error.raw_os_error(), Some(1 | 5 | 6 | 50)) => Ok(()),
        Err(error) => {
            Err(error).with_context(|| format!("cannot sync parent directory {}", parent.display()))
        }
    }
}

#[cfg(not(any(unix, windows)))]
fn sync_parent_directory(_parent: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use tempfile::tempdir;

    /// macOS 的 `/var` 是指向 `/private/var` 的系统符号链接。生产代码必须拒绝
    /// 这类未经解析的受管路径；测试则先将临时目录解析为真实路径，以覆盖后续逻辑。
    fn managed_test_root(path: &Path) -> PathBuf {
        #[cfg(target_os = "macos")]
        {
            fs::canonicalize(path).expect("temporary test directory must resolve")
        }
        #[cfg(not(target_os = "macos"))]
        {
            path.to_path_buf()
        }
    }

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct ExampleJournal {
        operation: String,
        generation: u64,
    }

    #[test]
    fn durable_bytes_replace_in_place_without_temporary_residue() {
        let root = tempdir().unwrap();
        let root_path = managed_test_root(root.path());
        let path = root_path.join("state.bin");
        write_durable_bytes(&path, b"first", 64).unwrap();
        write_durable_bytes(&path, b"second", 64).unwrap();
        assert_eq!(read_limited_bytes(&path, 64).unwrap(), b"second");
        let names = fs::read_dir(root_path)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(names, vec![std::ffi::OsString::from("state.bin")]);
    }

    #[test]
    fn durable_json_round_trips() {
        let root = tempdir().unwrap();
        let path = managed_test_root(root.path()).join("state.json");
        let expected = ExampleJournal {
            operation: "install".into(),
            generation: 7,
        };
        write_durable_json(&path, &expected, 1024).unwrap();
        assert_eq!(
            read_limited_json::<ExampleJournal>(&path, 1024).unwrap(),
            expected
        );
    }

    #[test]
    fn read_and_write_limits_fail_closed() {
        let root = tempdir().unwrap();
        let path = managed_test_root(root.path()).join("bounded.bin");
        assert!(write_durable_bytes(&path, b"too large", 3).is_err());
        fs::write(&path, b"too large").unwrap();
        let error = read_limited_bytes(&path, 3).unwrap_err();
        assert!(error.to_string().contains("size limit"));
    }

    #[test]
    fn journal_round_trips_and_detects_payload_tampering() {
        let root = tempdir().unwrap();
        let path = managed_test_root(root.path()).join("update.journal");
        let expected = ExampleJournal {
            operation: "rollback".into(),
            generation: 9,
        };
        write_journal_json(&path, &expected, 1024).unwrap();
        assert_eq!(
            read_journal_json::<ExampleJournal>(&path, 1024).unwrap(),
            expected
        );

        let mut envelope: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let encoded = envelope["payload_base64"].as_str().unwrap();
        let mut payload = BASE64_STANDARD.decode(encoded).unwrap();
        payload[0] ^= 1;
        envelope["payload_base64"] = serde_json::Value::String(BASE64_STANDARD.encode(payload));
        fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();
        let error = read_journal_bytes(&path, 1024).unwrap_err();
        assert!(error.to_string().contains("SHA-256 mismatch"));
    }

    #[test]
    fn journal_rejects_unknown_fields_and_oversized_declarations() {
        let root = tempdir().unwrap();
        let path = managed_test_root(root.path()).join("update.journal");
        let payload = br#"{"operation":"install","generation":1}"#;
        write_journal_bytes(&path, payload, 1024).unwrap();

        let mut envelope: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        envelope["unexpected"] = serde_json::Value::Bool(true);
        fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();
        assert!(read_journal_bytes(&path, 1024).is_err());

        write_journal_bytes(&path, payload, 1024).unwrap();
        let mut envelope: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        envelope["payload_length"] = serde_json::Value::from(2048_u64);
        fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();
        let error = read_journal_bytes(&path, 1024).unwrap_err();
        assert!(error.to_string().contains("size limit"));
    }

    #[test]
    fn update_lock_is_exclusive_and_drop_releases_it() {
        let root = tempdir().unwrap();
        let root_path = managed_test_root(root.path());
        let first = UpdateLock::acquire(&root_path).unwrap();
        assert!(UpdateLock::acquire(&root_path).is_err());
        drop(first);
        drop(UpdateLock::acquire(&root_path).unwrap());
        assert!(root_path.join(UPDATE_LOCK_NAME).is_file());
    }

    #[test]
    fn parent_traversal_is_rejected_before_io() {
        let root = tempdir().unwrap();
        let root_path = managed_test_root(root.path());
        let missing = root_path.join("missing");
        let path = missing.join("..").join("state.json");
        let error = write_durable_bytes(&path, b"state", 64).unwrap_err();
        assert!(error.to_string().contains("parent traversal"));
        assert!(!missing.exists());
        assert!(!root_path.join("state.json").exists());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_parent_and_file_are_rejected() {
        use std::os::unix::fs::symlink;

        let root = tempdir().unwrap();
        let root_path = managed_test_root(root.path());
        let real = root_path.join("real");
        fs::create_dir(&real).unwrap();
        let linked_directory = root_path.join("linked-directory");
        symlink(&real, &linked_directory).unwrap();
        let directory_error =
            write_durable_bytes(&linked_directory.join("state"), b"x", 8).unwrap_err();
        assert!(directory_error.to_string().contains("linked-directory"));

        let real_file = real.join("real-state");
        fs::write(&real_file, b"x").unwrap();
        let linked_file = root_path.join("linked-state");
        symlink(&real_file, &linked_file).unwrap();
        let file_error = read_limited_bytes(&linked_file, 8).unwrap_err();
        assert!(file_error.to_string().contains("linked-state"));
    }

    #[cfg(windows)]
    #[test]
    fn reparse_point_file_is_rejected_when_symlink_creation_is_available() {
        use std::os::windows::fs::symlink_file;

        let root = tempdir().unwrap();
        let root_path = managed_test_root(root.path());
        let real = root_path.join("real-state");
        fs::write(&real, b"x").unwrap();
        let linked = root_path.join("linked-state");
        if symlink_file(&real, &linked).is_err() {
            // 未启用 Developer Mode 的普通 CI 用户可能没有创建 symlink 的权限。
            return;
        }
        assert!(read_limited_bytes(&linked, 8).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn windows_verbatim_and_device_namespace_paths_are_rejected_before_io() {
        // `\\?\` 与 `\\.\` 会绕过 Win32 的常规路径归一化。更新状态目录若接受
        // 这些前缀，后续的 ACL、重解析点和保留设备名检查都不再是可靠边界。
        for path in [
            Path::new(r"\\?\C:\LinkLake\state.json"),
            Path::new(r"\\.\NUL"),
        ] {
            assert!(
                normalize_absolute_path(path).is_err(),
                "managed state path must reject the Windows namespace: {}",
                path.display()
            );
        }
    }
}
