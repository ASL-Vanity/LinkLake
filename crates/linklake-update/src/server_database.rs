//! 服务端数据库感知更新的可复用事务辅助。
//!
//! 本模块不直接决定二进制切换时机。调用方负责先停止服务、创建旧二进制副本，
//! 然后使用这里的 API 生成一致性快照、让候选二进制在隔离目录预演迁移，并在
//! 失败时先恢复数据库、确认源 schema 与账本，再恢复旧二进制。

use anyhow::{Context, Result};
use semver::Version;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

pub const SERVER_DATABASE_PROTOCOL_VERSION: u32 = 1;
pub const SERVER_DATABASE_SNAPSHOT_METADATA_VERSION: u32 = 1;
const MAX_REPORT_BYTES: usize = 64 * 1024;
const MAX_COMMAND_ERROR_BYTES: usize = 4 * 1024;

/// 当前或候选服务端对真实数据库进行只读检查后返回的稳定 JSON 契约。
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServerDatabaseInspectReport {
    pub schema_version: u32,
    pub product: String,
    pub version: String,
    pub executable_sha256: String,
    pub canonical_data_dir: PathBuf,
    pub canonical_database_path: PathBuf,
    pub observed_schema: u32,
    pub ledger_sha256: String,
    pub min_readable_schema: u32,
    pub max_readable_schema: u32,
    pub target_schema: u32,
    pub migration_contract_sha256: String,
    pub can_migrate: bool,
}

/// 候选服务端在快照副本上完成真实迁移预演后返回的稳定 JSON 契约。
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServerDatabasePreflightReport {
    pub schema_version: u32,
    pub product: String,
    pub version: String,
    pub executable_sha256: String,
    pub snapshot_path: PathBuf,
    pub snapshot_sha256: String,
    pub source_schema: u32,
    pub source_ledger_sha256: String,
    pub target_schema: u32,
    pub target_ledger_sha256: String,
    pub migration_contract_sha256: String,
    pub integrity_ok: bool,
    pub catalogs_ok: bool,
}

/// 调度服务端更新时需要写入不可变 helper plan 的数据库兼容性数据。
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServerUpdateContext {
    pub schema_version: u32,
    pub canonical_data_dir: PathBuf,
    pub canonical_database_path: PathBuf,
    pub installed_executable: PathBuf,
    pub installed_executable_sha256: String,
    pub installed_version: String,
    pub staged_executable: PathBuf,
    pub staged_executable_sha256: String,
    pub staged_version: String,
    pub source_schema: u32,
    pub source_ledger_sha256: String,
    pub candidate_min_schema: u32,
    pub candidate_max_schema: u32,
    pub candidate_target_schema: u32,
    pub migration_contract_sha256: String,
}

/// 停止服务后生成的数据库快照及旧二进制绑定信息。
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServerDatabaseSnapshotMetadata {
    pub schema_version: u32,
    pub operation_id: Uuid,
    pub plan_sha256: String,
    pub canonical_data_dir: PathBuf,
    pub canonical_database_path: PathBuf,
    pub source_schema: u32,
    pub source_ledger_sha256: String,
    pub snapshot_path: PathBuf,
    pub snapshot_sha256: String,
    pub rollback_binary_path: PathBuf,
    pub rollback_binary_sha256: String,
    pub rollback_binary_version: String,
    pub candidate_target_schema: u32,
    pub migration_contract_sha256: String,
    pub created_unix_seconds: u64,
}

/// 人工回滚数据库时必须由上层 CLI 明确传入的双重确认。
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManualDatabaseRollbackConsent {
    pub restore_database_snapshot: bool,
    pub confirm_data_loss: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManualDatabaseRollbackDecision {
    /// 当前数据库仍与旧备份的源 schema/账本一致，只需要切换二进制。
    BinaryOnly,
    /// 数据库已发生 schema 或账本变化，必须先恢复绑定快照。
    RestoreSnapshot,
}

/// 分别调用已安装服务端和候选服务端的只读检查命令，生成可序列化上下文。
pub fn prepare_server_update_context(
    installed_server: &Path,
    staged_server: &Path,
    data_dir: &Path,
) -> Result<ServerUpdateContext> {
    let installed = inspect_server_database(installed_server, data_dir)
        .context("installed LinkLake server database inspection failed")?;
    let staged = inspect_server_database(staged_server, data_dir)
        .context("staged LinkLake server database inspection failed")?;
    validate_compatible_inspections(installed_server, staged_server, &installed, &staged)
}

/// 调用服务端的隐藏只读探测接口，并绑定真实可执行文件、数据目录和数据库路径。
pub fn inspect_server_database(
    server_executable: &Path,
    data_dir: &Path,
) -> Result<ServerDatabaseInspectReport> {
    let executable = canonical_existing_file(server_executable, "server executable")?;
    let executable_sha256 = sha256_file(&executable)?;
    let canonical_data_dir = canonical_existing_directory(data_dir, "server data directory")?;
    let canonical_database_path = canonical_existing_file(
        &canonical_data_dir.join("linklake.sqlite3"),
        "server database",
    )?;
    let report: ServerDatabaseInspectReport = run_json_command(
        &executable,
        [
            OsStr::new("__update-db-inspect"),
            OsStr::new("--data-dir"),
            canonical_data_dir.as_os_str(),
        ],
    )?;
    validate_inspect_report(
        &report,
        &executable_sha256,
        &canonical_data_dir,
        &canonical_database_path,
    )?;
    Ok(report)
}

/// 使用旧二进制副本创建数据库快照，并把快照、路径和摘要写入元数据。
///
/// 调用方必须先停止服务。`rollback_binary` 应当是目标二进制的已校验副本，不能
/// 指向稍后会被候选版本覆盖的安装路径。
pub fn backup_server_database(
    rollback_binary: &Path,
    context: &ServerUpdateContext,
    snapshot_path: &Path,
    operation_id: Uuid,
    plan_sha256: &str,
) -> Result<ServerDatabaseSnapshotMetadata> {
    validate_update_context(context)?;
    let plan_sha256 = normalize_sha256(plan_sha256, "update plan SHA-256")?;
    let rollback_binary = canonical_existing_file(rollback_binary, "rollback server binary")?;
    let rollback_binary_sha256 = sha256_file(&rollback_binary)?;
    anyhow::ensure!(
        rollback_binary_sha256 == context.installed_executable_sha256,
        "rollback server binary digest does not match the installed server"
    );

    // 停服后再次检查源 schema 与账本，拒绝调度后被其他维护动作改变的数据库。
    let stopped_inspection =
        inspect_server_database(&rollback_binary, &context.canonical_data_dir)?;
    anyhow::ensure!(
        stopped_inspection.observed_schema == context.source_schema
            && stopped_inspection.ledger_sha256 == context.source_ledger_sha256,
        "server database schema or migration ledger changed after the update was scheduled"
    );

    let snapshot_path = canonical_new_external_file_path(
        snapshot_path,
        &context.canonical_data_dir,
        "database snapshot",
    )?;
    run_checked_command(
        &rollback_binary,
        [
            OsStr::new("backup"),
            OsStr::new("--data-dir"),
            context.canonical_data_dir.as_os_str(),
            OsStr::new("--output"),
            snapshot_path.as_os_str(),
        ],
        "server database backup",
    )?;
    let snapshot_path = canonical_existing_file(&snapshot_path, "database snapshot")?;
    let snapshot_sha256 = sha256_file(&snapshot_path)?;

    Ok(ServerDatabaseSnapshotMetadata {
        schema_version: SERVER_DATABASE_SNAPSHOT_METADATA_VERSION,
        operation_id,
        plan_sha256,
        canonical_data_dir: context.canonical_data_dir.clone(),
        canonical_database_path: context.canonical_database_path.clone(),
        source_schema: context.source_schema,
        source_ledger_sha256: context.source_ledger_sha256.clone(),
        snapshot_path,
        snapshot_sha256,
        rollback_binary_path: rollback_binary,
        rollback_binary_sha256,
        rollback_binary_version: context.installed_version.clone(),
        candidate_target_schema: context.candidate_target_schema,
        migration_contract_sha256: context.migration_contract_sha256.clone(),
        created_unix_seconds: unix_seconds(),
    })
}

/// 让候选服务端在隔离 scratch 目录中迁移绑定快照，并严格核对返回报告。
pub fn preflight_server_database(
    staged_server: &Path,
    context: &ServerUpdateContext,
    snapshot: &ServerDatabaseSnapshotMetadata,
    scratch_dir: &Path,
    operation_directory: &Path,
) -> Result<ServerDatabasePreflightReport> {
    validate_update_context(context)?;
    validate_snapshot_metadata(snapshot, snapshot.operation_id, &snapshot.plan_sha256)?;
    anyhow::ensure!(
        snapshot.canonical_data_dir == context.canonical_data_dir
            && snapshot.canonical_database_path == context.canonical_database_path
            && snapshot.source_schema == context.source_schema
            && snapshot.source_ledger_sha256 == context.source_ledger_sha256,
        "database snapshot metadata does not belong to this update context"
    );

    let staged_server = canonical_existing_file(staged_server, "staged server executable")?;
    anyhow::ensure!(
        staged_server == context.staged_executable,
        "staged server path changed after update scheduling"
    );
    anyhow::ensure!(
        sha256_file(&staged_server)? == context.staged_executable_sha256,
        "staged server digest changed before database preflight"
    );
    let operation_directory =
        canonical_existing_directory(operation_directory, "update operation directory")?;
    let scratch_dir = canonical_empty_directory_within(
        scratch_dir,
        &operation_directory,
        &context.canonical_data_dir,
        snapshot.snapshot_path.parent(),
    )?;

    let report: ServerDatabasePreflightReport = run_json_command(
        &staged_server,
        [
            OsStr::new("__update-db-preflight"),
            OsStr::new("--snapshot"),
            snapshot.snapshot_path.as_os_str(),
            OsStr::new("--snapshot-sha256"),
            OsStr::new(&snapshot.snapshot_sha256),
            OsStr::new("--scratch-dir"),
            scratch_dir.as_os_str(),
        ],
    )?;
    validate_preflight_report(&report, context, snapshot)?;
    Ok(report)
}

/// 使用摘要绑定的旧二进制恢复数据库快照，并在返回前重新验证源 schema 与账本。
///
/// 调用方只有在本函数成功后，才可以把安装路径切换回旧二进制。
pub fn restore_server_database(
    rollback_binary: &Path,
    snapshot: &ServerDatabaseSnapshotMetadata,
) -> Result<ServerDatabaseInspectReport> {
    validate_snapshot_metadata(snapshot, snapshot.operation_id, &snapshot.plan_sha256)?;
    let rollback_binary = canonical_existing_file(rollback_binary, "rollback server binary")?;
    anyhow::ensure!(
        rollback_binary == snapshot.rollback_binary_path,
        "rollback server binary path does not match snapshot metadata"
    );
    anyhow::ensure!(
        sha256_file(&rollback_binary)? == snapshot.rollback_binary_sha256,
        "rollback server binary digest changed before database restore"
    );
    run_checked_command(
        &rollback_binary,
        [
            OsStr::new("restore"),
            OsStr::new("--data-dir"),
            snapshot.canonical_data_dir.as_os_str(),
            OsStr::new("--input"),
            snapshot.snapshot_path.as_os_str(),
        ],
        "server database restore",
    )?;
    let restored = inspect_server_database(&rollback_binary, &snapshot.canonical_data_dir)?;
    anyhow::ensure!(
        restored.observed_schema == snapshot.source_schema,
        "restored database schema does not match the rollback snapshot"
    );
    anyhow::ensure!(
        restored.ledger_sha256 == snapshot.source_ledger_sha256,
        "restored database migration ledger does not match the rollback snapshot"
    );
    Ok(restored)
}

/// 判断人工回滚是否必须恢复数据库，并强制双重数据丢失确认。
///
/// 旧 v2 二进制备份没有数据库快照和账本绑定，不能被推断为可安全跨 schema 回滚。
pub fn authorize_manual_database_rollback(
    current_schema: u32,
    current_ledger_sha256: &str,
    snapshot: Option<&ServerDatabaseSnapshotMetadata>,
    consent: ManualDatabaseRollbackConsent,
) -> Result<ManualDatabaseRollbackDecision> {
    let current_ledger_sha256 =
        normalize_sha256(current_ledger_sha256, "current migration ledger SHA-256")?;
    let snapshot = snapshot.ok_or_else(|| {
        anyhow::anyhow!(
            "legacy or binary-only rollback metadata has no database snapshot; cross-schema server rollback is disabled"
        )
    })?;
    validate_snapshot_metadata(snapshot, snapshot.operation_id, &snapshot.plan_sha256)?;
    if current_schema == snapshot.source_schema
        && current_ledger_sha256 == snapshot.source_ledger_sha256
    {
        return Ok(ManualDatabaseRollbackDecision::BinaryOnly);
    }
    anyhow::ensure!(
        consent.restore_database_snapshot,
        "manual server rollback crosses a database schema or ledger boundary; explicitly request database snapshot restore"
    );
    anyhow::ensure!(
        consent.confirm_data_loss,
        "database snapshot restore discards writes committed after the snapshot; explicit data-loss confirmation is required"
    );
    Ok(ManualDatabaseRollbackDecision::RestoreSnapshot)
}

/// 将快照元数据写入一个尚不存在的文件，并同步文件与父目录。
pub fn write_snapshot_metadata(
    path: &Path,
    metadata: &ServerDatabaseSnapshotMetadata,
) -> Result<PathBuf> {
    validate_snapshot_metadata(metadata, metadata.operation_id, &metadata.plan_sha256)?;
    let path = canonical_new_file_path(path, "database snapshot metadata")?;
    let bytes = serde_json::to_vec_pretty(metadata)?;
    write_new_file_durably(&path, &bytes)?;
    Ok(path)
}

/// 读取并重新验证快照元数据。旧 v2 或缺字段 JSON 会失败关闭。
pub fn read_snapshot_metadata(path: &Path) -> Result<ServerDatabaseSnapshotMetadata> {
    let path = canonical_existing_file(path, "database snapshot metadata")?;
    let metadata = fs::metadata(&path)?;
    anyhow::ensure!(
        metadata.len() <= MAX_REPORT_BYTES as u64,
        "database snapshot metadata exceeds the size limit"
    );
    let value: ServerDatabaseSnapshotMetadata = serde_json::from_slice(&fs::read(path)?)?;
    validate_snapshot_metadata(&value, value.operation_id, &value.plan_sha256)?;
    Ok(value)
}

pub fn validate_snapshot_metadata(
    metadata: &ServerDatabaseSnapshotMetadata,
    expected_operation_id: Uuid,
    expected_plan_sha256: &str,
) -> Result<()> {
    anyhow::ensure!(
        metadata.schema_version == SERVER_DATABASE_SNAPSHOT_METADATA_VERSION,
        "unsupported server database snapshot metadata version"
    );
    anyhow::ensure!(
        metadata.operation_id == expected_operation_id,
        "database snapshot operation ID mismatch"
    );
    anyhow::ensure!(
        metadata.plan_sha256
            == normalize_sha256(expected_plan_sha256, "expected update plan SHA-256")?,
        "database snapshot update plan digest mismatch"
    );
    validate_sha256(&metadata.plan_sha256, "snapshot plan SHA-256")?;
    validate_sha256(
        &metadata.source_ledger_sha256,
        "source migration ledger SHA-256",
    )?;
    validate_sha256(&metadata.snapshot_sha256, "database snapshot SHA-256")?;
    validate_sha256(&metadata.rollback_binary_sha256, "rollback binary SHA-256")?;
    validate_sha256(
        &metadata.migration_contract_sha256,
        "migration contract SHA-256",
    )?;
    Version::parse(&metadata.rollback_binary_version)
        .context("rollback server version is invalid")?;
    let canonical_data_dir =
        canonical_existing_directory(&metadata.canonical_data_dir, "snapshot data directory")?;
    let canonical_database_path =
        canonical_existing_file(&metadata.canonical_database_path, "snapshot database path")?;
    anyhow::ensure!(
        canonical_data_dir == metadata.canonical_data_dir
            && canonical_database_path == metadata.canonical_database_path
            && canonical_database_path == canonical_data_dir.join("linklake.sqlite3"),
        "database snapshot live path binding changed"
    );
    let snapshot_path = canonical_existing_file(&metadata.snapshot_path, "database snapshot")?;
    anyhow::ensure!(
        snapshot_path == metadata.snapshot_path,
        "database snapshot path binding changed"
    );
    anyhow::ensure!(
        !paths_overlap(&snapshot_path, &canonical_data_dir),
        "database snapshot must remain outside the live data directory"
    );
    anyhow::ensure!(
        sha256_file(&snapshot_path)? == metadata.snapshot_sha256,
        "database snapshot digest changed"
    );
    let rollback_binary =
        canonical_existing_file(&metadata.rollback_binary_path, "rollback server binary")?;
    anyhow::ensure!(
        rollback_binary == metadata.rollback_binary_path
            && sha256_file(&rollback_binary)? == metadata.rollback_binary_sha256,
        "rollback server binary path or digest changed"
    );
    Ok(())
}

fn validate_compatible_inspections(
    installed_server: &Path,
    staged_server: &Path,
    installed: &ServerDatabaseInspectReport,
    staged: &ServerDatabaseInspectReport,
) -> Result<ServerUpdateContext> {
    let installed_executable = canonical_existing_file(installed_server, "installed server")?;
    let staged_executable = canonical_existing_file(staged_server, "staged server")?;
    validate_inspect_report(
        installed,
        &sha256_file(&installed_executable)?,
        &installed.canonical_data_dir,
        &installed.canonical_database_path,
    )?;
    validate_inspect_report(
        staged,
        &sha256_file(&staged_executable)?,
        &installed.canonical_data_dir,
        &installed.canonical_database_path,
    )?;
    anyhow::ensure!(
        installed.canonical_data_dir == staged.canonical_data_dir
            && installed.canonical_database_path == staged.canonical_database_path,
        "installed and staged servers inspected different database paths"
    );
    anyhow::ensure!(
        installed.observed_schema == staged.observed_schema
            && installed.ledger_sha256 == staged.ledger_sha256,
        "installed and staged servers disagree about the source database"
    );
    anyhow::ensure!(
        staged.can_migrate,
        "staged server cannot migrate the source database"
    );
    anyhow::ensure!(
        staged.target_schema >= staged.observed_schema,
        "automatic server updates cannot downgrade the database schema"
    );
    anyhow::ensure!(
        staged.target_schema >= staged.min_readable_schema
            && staged.target_schema <= staged.max_readable_schema,
        "staged server target schema is outside its declared readable range"
    );
    Ok(ServerUpdateContext {
        schema_version: SERVER_DATABASE_PROTOCOL_VERSION,
        canonical_data_dir: installed.canonical_data_dir.clone(),
        canonical_database_path: installed.canonical_database_path.clone(),
        installed_executable,
        installed_executable_sha256: installed.executable_sha256.clone(),
        installed_version: installed.version.clone(),
        staged_executable,
        staged_executable_sha256: staged.executable_sha256.clone(),
        staged_version: staged.version.clone(),
        source_schema: installed.observed_schema,
        source_ledger_sha256: installed.ledger_sha256.clone(),
        candidate_min_schema: staged.min_readable_schema,
        candidate_max_schema: staged.max_readable_schema,
        candidate_target_schema: staged.target_schema,
        migration_contract_sha256: staged.migration_contract_sha256.clone(),
    })
}

fn validate_update_context(context: &ServerUpdateContext) -> Result<()> {
    anyhow::ensure!(
        context.schema_version == SERVER_DATABASE_PROTOCOL_VERSION,
        "unsupported server update context version"
    );
    validate_sha256(
        &context.installed_executable_sha256,
        "installed executable SHA-256",
    )?;
    validate_sha256(
        &context.staged_executable_sha256,
        "staged executable SHA-256",
    )?;
    validate_sha256(&context.source_ledger_sha256, "source ledger SHA-256")?;
    validate_sha256(
        &context.migration_contract_sha256,
        "migration contract SHA-256",
    )?;
    Version::parse(&context.installed_version).context("installed server version is invalid")?;
    Version::parse(&context.staged_version).context("staged server version is invalid")?;
    anyhow::ensure!(
        context.candidate_target_schema >= context.source_schema
            && context.candidate_target_schema >= context.candidate_min_schema
            && context.candidate_target_schema <= context.candidate_max_schema,
        "server update context contains an invalid schema range"
    );
    let data_dir =
        canonical_existing_directory(&context.canonical_data_dir, "context data directory")?;
    let database =
        canonical_existing_file(&context.canonical_database_path, "context database path")?;
    anyhow::ensure!(
        data_dir == context.canonical_data_dir
            && database == context.canonical_database_path
            && database == data_dir.join("linklake.sqlite3"),
        "server update context database path binding changed"
    );
    let installed = canonical_existing_file(&context.installed_executable, "installed server")?;
    let staged = canonical_existing_file(&context.staged_executable, "staged server")?;
    anyhow::ensure!(
        installed == context.installed_executable
            && staged == context.staged_executable
            && sha256_file(&installed)? == context.installed_executable_sha256
            && sha256_file(&staged)? == context.staged_executable_sha256,
        "server update context executable path or digest changed"
    );
    Ok(())
}

fn validate_inspect_report(
    report: &ServerDatabaseInspectReport,
    expected_executable_sha256: &str,
    expected_data_dir: &Path,
    expected_database_path: &Path,
) -> Result<()> {
    anyhow::ensure!(
        report.schema_version == SERVER_DATABASE_PROTOCOL_VERSION,
        "unsupported server database inspection protocol"
    );
    anyhow::ensure!(
        report.product == "server",
        "database inspection product mismatch"
    );
    Version::parse(&report.version).context("inspected server version is invalid")?;
    anyhow::ensure!(
        normalize_sha256(&report.executable_sha256, "reported executable SHA-256")?
            == normalize_sha256(expected_executable_sha256, "expected executable SHA-256")?,
        "database inspection executable digest mismatch"
    );
    validate_sha256(&report.ledger_sha256, "reported migration ledger SHA-256")?;
    validate_sha256(
        &report.migration_contract_sha256,
        "reported migration contract SHA-256",
    )?;
    let data_dir =
        canonical_existing_directory(&report.canonical_data_dir, "reported data directory")?;
    let database =
        canonical_existing_file(&report.canonical_database_path, "reported database path")?;
    anyhow::ensure!(
        data_dir == expected_data_dir
            && database == expected_database_path
            && database == data_dir.join("linklake.sqlite3"),
        "database inspection path binding mismatch"
    );
    anyhow::ensure!(
        report.min_readable_schema <= report.max_readable_schema
            && report.target_schema >= report.min_readable_schema
            && report.target_schema <= report.max_readable_schema,
        "database inspection reported an invalid schema range"
    );
    Ok(())
}

fn validate_preflight_report(
    report: &ServerDatabasePreflightReport,
    context: &ServerUpdateContext,
    snapshot: &ServerDatabaseSnapshotMetadata,
) -> Result<()> {
    anyhow::ensure!(
        report.schema_version == SERVER_DATABASE_PROTOCOL_VERSION,
        "unsupported server database preflight protocol"
    );
    anyhow::ensure!(
        report.product == "server",
        "database preflight product mismatch"
    );
    anyhow::ensure!(
        report.version == context.staged_version,
        "database preflight server version mismatch"
    );
    anyhow::ensure!(
        normalize_sha256(&report.executable_sha256, "preflight executable SHA-256")?
            == context.staged_executable_sha256,
        "database preflight executable digest mismatch"
    );
    let report_snapshot = canonical_existing_file(&report.snapshot_path, "preflight snapshot")?;
    anyhow::ensure!(
        report_snapshot == snapshot.snapshot_path
            && normalize_sha256(&report.snapshot_sha256, "preflight snapshot SHA-256")?
                == snapshot.snapshot_sha256,
        "database preflight snapshot binding mismatch"
    );
    anyhow::ensure!(
        report.source_schema == snapshot.source_schema
            && report.source_ledger_sha256 == snapshot.source_ledger_sha256,
        "database preflight source schema or ledger mismatch"
    );
    anyhow::ensure!(
        report.target_schema == context.candidate_target_schema
            && report.migration_contract_sha256 == context.migration_contract_sha256,
        "database preflight target schema or migration contract mismatch"
    );
    validate_sha256(
        &report.target_ledger_sha256,
        "preflight target migration ledger SHA-256",
    )?;
    anyhow::ensure!(
        report.target_ledger_sha256 == context.migration_contract_sha256,
        "database preflight target migration ledger does not match the candidate migration contract"
    );
    anyhow::ensure!(
        report.integrity_ok && report.catalogs_ok,
        "database preflight did not prove integrity and runtime catalog compatibility"
    );
    Ok(())
}

fn run_json_command<T, I, S>(executable: &Path, arguments: I) -> Result<T>
where
    T: DeserializeOwned,
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = Command::new(executable).args(arguments).output()?;
    ensure_command_success(executable, &output, "server database helper command")?;
    anyhow::ensure!(
        output.stdout.len() <= MAX_REPORT_BYTES,
        "server database helper JSON exceeds the size limit"
    );
    let bytes = output
        .stdout
        .strip_prefix(&[0xEF, 0xBB, 0xBF])
        .unwrap_or(&output.stdout);
    serde_json::from_slice(bytes).context("server database helper returned invalid JSON")
}

fn run_checked_command<I, S>(executable: &Path, arguments: I, operation: &str) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = Command::new(executable).args(arguments).output()?;
    ensure_command_success(executable, &output, operation)
}

fn ensure_command_success(executable: &Path, output: &Output, operation: &str) -> Result<()> {
    if output.status.success() {
        return Ok(());
    }
    let stderr = sanitized_command_error(&output.stderr);
    anyhow::bail!(
        "{operation} failed using {} with status {}{}",
        executable.display(),
        output.status,
        if stderr.is_empty() {
            String::new()
        } else {
            format!(": {stderr}")
        }
    )
}

fn sanitized_command_error(bytes: &[u8]) -> String {
    String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_COMMAND_ERROR_BYTES)])
        .chars()
        .map(|character| {
            if character.is_control() && !matches!(character, '\n' | '\r' | '\t') {
                '\u{FFFD}'
            } else {
                character
            }
        })
        .collect::<String>()
        .trim()
        .to_owned()
}

fn canonical_existing_file(path: &Path, label: &str) -> Result<PathBuf> {
    reject_unsafe_components(path, label)?;
    reject_link_components(path, label)?;
    let canonical =
        canonicalize_server_update_path(path).with_context(|| format!("{label} does not exist"))?;
    let metadata = fs::metadata(&canonical)?;
    anyhow::ensure!(metadata.is_file(), "{label} is not a regular file");
    reject_reparse_metadata(&metadata, label)?;
    Ok(canonical)
}

fn canonical_existing_directory(path: &Path, label: &str) -> Result<PathBuf> {
    reject_unsafe_components(path, label)?;
    reject_link_components(path, label)?;
    let canonical =
        canonicalize_server_update_path(path).with_context(|| format!("{label} does not exist"))?;
    let metadata = fs::metadata(&canonical)?;
    anyhow::ensure!(metadata.is_dir(), "{label} is not a directory");
    reject_reparse_metadata(&metadata, label)?;
    Ok(canonical)
}

fn canonical_new_external_file_path(path: &Path, data_dir: &Path, label: &str) -> Result<PathBuf> {
    let path = canonical_new_file_path(path, label)?;
    anyhow::ensure!(
        !paths_overlap(&path, data_dir),
        "{label} must be outside the live data directory"
    );
    Ok(path)
}

fn canonical_new_file_path(path: &Path, label: &str) -> Result<PathBuf> {
    reject_unsafe_components(path, label)?;
    anyhow::ensure!(!path.exists(), "{label} already exists");
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("{label} has no file name"))?;
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{label} has no parent directory"))?;
    let parent = canonical_existing_directory(parent, &format!("{label} parent"))?;
    Ok(parent.join(file_name))
}

fn canonical_empty_directory_within(
    path: &Path,
    root: &Path,
    data_dir: &Path,
    snapshot_parent: Option<&Path>,
) -> Result<PathBuf> {
    let path = canonical_existing_directory(path, "database preflight scratch directory")?;
    anyhow::ensure!(
        path.starts_with(root) && path != root,
        "database preflight scratch directory escapes the update operation directory"
    );
    anyhow::ensure!(
        !paths_overlap(&path, data_dir),
        "database preflight scratch directory overlaps the live data directory"
    );
    if let Some(snapshot_parent) = snapshot_parent {
        anyhow::ensure!(
            !paths_overlap(&path, snapshot_parent),
            "database preflight scratch directory overlaps the snapshot directory"
        );
    }
    anyhow::ensure!(
        fs::read_dir(&path)?.next().is_none(),
        "database preflight scratch directory must be empty"
    );
    Ok(path)
}

fn reject_unsafe_components(path: &Path, label: &str) -> Result<()> {
    anyhow::ensure!(path.is_absolute(), "{label} must be an absolute path");
    reject_windows_namespace(path, label)?;
    for component in path.components() {
        anyhow::ensure!(
            !matches!(component, Component::CurDir | Component::ParentDir),
            "{label} contains a non-normalized path component"
        );
    }
    Ok(())
}

#[cfg(windows)]
fn reject_windows_namespace(path: &Path, label: &str) -> Result<()> {
    let value = path.as_os_str().to_string_lossy().replace('/', "\\");
    anyhow::ensure!(
        !value.starts_with(r"\\?\") && !value.starts_with(r"\\.\"),
        "{label} must not use a Windows verbatim or device namespace"
    );
    Ok(())
}

#[cfg(not(windows))]
fn reject_windows_namespace(_path: &Path, _label: &str) -> Result<()> {
    Ok(())
}

fn canonicalize_server_update_path(path: &Path) -> Result<PathBuf> {
    let canonical = fs::canonicalize(path)?;
    normalize_windows_canonical_path(canonical)
}

#[cfg(windows)]
fn normalize_windows_canonical_path(path: PathBuf) -> Result<PathBuf> {
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
        "canonical server update path has an empty verbatim suffix"
    );
    Ok(PathBuf::from(OsString::from_wide(&regular)))
}

#[cfg(not(windows))]
fn normalize_windows_canonical_path(path: PathBuf) -> Result<PathBuf> {
    Ok(path)
}

fn reject_link_components(path: &Path, label: &str) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        // Windows 的 `C:` 前缀本身是盘符相对路径，只有随后加入根目录分隔符后
        // 才能安全查询元数据；Unix 根目录同样无需单独检查。
        if matches!(component, Component::Prefix(_) | Component::RootDir) {
            continue;
        }
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        anyhow::ensure!(
            !metadata.file_type().is_symlink(),
            "{label} contains a symbolic link"
        );
        reject_reparse_metadata(&metadata, label)?;
    }
    Ok(())
}

#[cfg(windows)]
fn reject_reparse_metadata(metadata: &fs::Metadata, label: &str) -> Result<()> {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    anyhow::ensure!(
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "{label} contains a Windows reparse point"
    );
    Ok(())
}

#[cfg(not(windows))]
fn reject_reparse_metadata(_metadata: &fs::Metadata, _label: &str) -> Result<()> {
    Ok(())
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn validate_sha256(value: &str, label: &str) -> Result<()> {
    let normalized = normalize_sha256(value, label)?;
    anyhow::ensure!(
        normalized == value,
        "{label} must use lowercase hexadecimal"
    );
    Ok(())
}

fn normalize_sha256(value: &str, label: &str) -> Result<String> {
    anyhow::ensure!(
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "{label} must contain 64 hexadecimal characters"
    );
    Ok(value.to_ascii_lowercase())
}

fn sha256_file(path: &Path) -> Result<String> {
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

fn write_new_file_durably(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("durable output has no parent directory"))?;
    let temporary = parent.join(format!(
        ".{}.tmp-{}",
        path.file_name().unwrap_or_default().to_string_lossy(),
        Uuid::new_v4().simple()
    ));
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)?;
        sync_parent_directory(parent)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(unix)]
fn sync_parent_directory(parent: &Path) -> Result<()> {
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(windows)]
fn sync_parent_directory(parent: &Path) -> Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(parent)?;
    match directory.sync_all() {
        Ok(()) => Ok(()),
        // Windows 的目录句柄在部分文件系统上不支持 FlushFileBuffers；同目录 rename
        // 仍保持原子性，调用方可依赖上层事务日志重新验证完整文件。
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::InvalidInput | std::io::ErrorKind::Unsupported
            ) || matches!(error.raw_os_error(), Some(1 | 5 | 6)) =>
        {
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
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
    use tempfile::TempDir;

    struct Fixture {
        _root: TempDir,
        data_dir: PathBuf,
        database: PathBuf,
        installed: PathBuf,
        staged: PathBuf,
        rollback: PathBuf,
        snapshot: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let data_dir = root.path().join("data");
            let state = root.path().join("state");
            fs::create_dir_all(&data_dir).unwrap();
            fs::create_dir_all(&state).unwrap();
            let database = data_dir.join("linklake.sqlite3");
            let installed = root.path().join(executable_name("installed"));
            let staged = root.path().join(executable_name("staged"));
            let rollback = state.join(executable_name("rollback"));
            let snapshot = state.join("source.sqlite3");
            fs::write(&database, b"database-v9").unwrap();
            fs::write(&installed, b"installed-server").unwrap();
            fs::write(&staged, b"staged-server").unwrap();
            fs::write(&rollback, b"installed-server").unwrap();
            fs::write(&snapshot, b"snapshot-v9").unwrap();
            Self {
                _root: root,
                data_dir: canonicalize_server_update_path(&data_dir).unwrap(),
                database: canonicalize_server_update_path(&database).unwrap(),
                installed: canonicalize_server_update_path(&installed).unwrap(),
                staged: canonicalize_server_update_path(&staged).unwrap(),
                rollback: canonicalize_server_update_path(&rollback).unwrap(),
                snapshot: canonicalize_server_update_path(&snapshot).unwrap(),
            }
        }

        fn snapshot_metadata(&self) -> ServerDatabaseSnapshotMetadata {
            ServerDatabaseSnapshotMetadata {
                schema_version: SERVER_DATABASE_SNAPSHOT_METADATA_VERSION,
                operation_id: Uuid::new_v4(),
                plan_sha256: "1".repeat(64),
                canonical_data_dir: self.data_dir.clone(),
                canonical_database_path: self.database.clone(),
                source_schema: 9,
                source_ledger_sha256: "2".repeat(64),
                snapshot_path: self.snapshot.clone(),
                snapshot_sha256: sha256_file(&self.snapshot).unwrap(),
                rollback_binary_path: self.rollback.clone(),
                rollback_binary_sha256: sha256_file(&self.rollback).unwrap(),
                rollback_binary_version: "0.9.0".into(),
                candidate_target_schema: 13,
                migration_contract_sha256: "3".repeat(64),
                created_unix_seconds: 1,
            }
        }

        fn update_context(&self) -> ServerUpdateContext {
            ServerUpdateContext {
                schema_version: SERVER_DATABASE_PROTOCOL_VERSION,
                canonical_data_dir: self.data_dir.clone(),
                canonical_database_path: self.database.clone(),
                installed_executable: self.installed.clone(),
                installed_executable_sha256: sha256_file(&self.installed).unwrap(),
                installed_version: "0.9.0".into(),
                staged_executable: self.staged.clone(),
                staged_executable_sha256: sha256_file(&self.staged).unwrap(),
                staged_version: "1.0.0".into(),
                source_schema: 9,
                source_ledger_sha256: "2".repeat(64),
                candidate_min_schema: 9,
                candidate_max_schema: 13,
                candidate_target_schema: 13,
                migration_contract_sha256: "3".repeat(64),
            }
        }
    }

    #[cfg(windows)]
    fn executable_name(prefix: &str) -> String {
        format!("{prefix}.exe")
    }

    #[cfg(not(windows))]
    fn executable_name(prefix: &str) -> String {
        prefix.to_owned()
    }

    #[test]
    fn manual_cross_schema_rollback_requires_both_confirmations() {
        let fixture = Fixture::new();
        let metadata = fixture.snapshot_metadata();
        let denied = authorize_manual_database_rollback(
            13,
            &"4".repeat(64),
            Some(&metadata),
            ManualDatabaseRollbackConsent::default(),
        )
        .unwrap_err();
        assert!(denied.to_string().contains("explicitly request"));

        let denied = authorize_manual_database_rollback(
            13,
            &"4".repeat(64),
            Some(&metadata),
            ManualDatabaseRollbackConsent {
                restore_database_snapshot: true,
                confirm_data_loss: false,
            },
        )
        .unwrap_err();
        assert!(denied.to_string().contains("data-loss confirmation"));

        assert_eq!(
            authorize_manual_database_rollback(
                13,
                &"4".repeat(64),
                Some(&metadata),
                ManualDatabaseRollbackConsent {
                    restore_database_snapshot: true,
                    confirm_data_loss: true,
                },
            )
            .unwrap(),
            ManualDatabaseRollbackDecision::RestoreSnapshot
        );
    }

    #[test]
    fn unchanged_schema_and_ledger_allows_binary_only_rollback() {
        let fixture = Fixture::new();
        let metadata = fixture.snapshot_metadata();
        assert_eq!(
            authorize_manual_database_rollback(
                metadata.source_schema,
                &metadata.source_ledger_sha256,
                Some(&metadata),
                ManualDatabaseRollbackConsent::default(),
            )
            .unwrap(),
            ManualDatabaseRollbackDecision::BinaryOnly
        );
    }

    #[test]
    fn legacy_v2_metadata_is_not_treated_as_a_database_snapshot() {
        let fixture = Fixture::new();
        let legacy = serde_json::json!({
            "schema_version": 2,
            "version": "0.9.0",
            "sha256": sha256_file(&fixture.rollback).unwrap(),
            "target_executable": fixture.installed,
            "created_unix_seconds": 1
        });
        let error = serde_json::from_value::<ServerDatabaseSnapshotMetadata>(legacy).unwrap_err();
        assert!(error.is_data());
        let error = authorize_manual_database_rollback(
            13,
            &"4".repeat(64),
            None,
            ManualDatabaseRollbackConsent {
                restore_database_snapshot: true,
                confirm_data_loss: true,
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("legacy or binary-only"));
    }

    #[test]
    fn snapshot_and_rollback_binary_tampering_is_rejected() {
        let fixture = Fixture::new();
        let metadata = fixture.snapshot_metadata();
        validate_snapshot_metadata(&metadata, metadata.operation_id, &metadata.plan_sha256)
            .unwrap();
        fs::write(&fixture.snapshot, b"tampered snapshot").unwrap();
        let error =
            validate_snapshot_metadata(&metadata, metadata.operation_id, &metadata.plan_sha256)
                .unwrap_err();
        assert!(error.to_string().contains("snapshot digest changed"));

        fs::write(&fixture.snapshot, b"snapshot-v9").unwrap();
        fs::write(&fixture.rollback, b"tampered binary").unwrap();
        let error =
            validate_snapshot_metadata(&metadata, metadata.operation_id, &metadata.plan_sha256)
                .unwrap_err();
        assert!(error.to_string().contains("rollback server binary"));
    }

    #[test]
    fn snapshot_metadata_rejects_wrong_operation_or_plan_binding() {
        let fixture = Fixture::new();
        let metadata = fixture.snapshot_metadata();
        let wrong_operation =
            validate_snapshot_metadata(&metadata, Uuid::new_v4(), &metadata.plan_sha256)
                .unwrap_err();
        assert!(wrong_operation
            .to_string()
            .contains("operation ID mismatch"));

        let wrong_plan =
            validate_snapshot_metadata(&metadata, metadata.operation_id, &"4".repeat(64))
                .unwrap_err();
        assert!(wrong_plan.to_string().contains("plan digest mismatch"));
    }

    #[test]
    fn preflight_target_ledger_must_match_candidate_migration_contract() {
        let fixture = Fixture::new();
        let context = fixture.update_context();
        let snapshot = fixture.snapshot_metadata();
        let report = ServerDatabasePreflightReport {
            schema_version: SERVER_DATABASE_PROTOCOL_VERSION,
            product: "server".into(),
            version: context.staged_version.clone(),
            executable_sha256: context.staged_executable_sha256.clone(),
            snapshot_path: snapshot.snapshot_path.clone(),
            snapshot_sha256: snapshot.snapshot_sha256.clone(),
            source_schema: snapshot.source_schema,
            source_ledger_sha256: snapshot.source_ledger_sha256.clone(),
            target_schema: context.candidate_target_schema,
            // 形状合法但不属于候选二进制声明的迁移合同，必须拒绝。
            target_ledger_sha256: "4".repeat(64),
            migration_contract_sha256: context.migration_contract_sha256.clone(),
            integrity_ok: true,
            catalogs_ok: true,
        };

        let error = validate_preflight_report(&report, &context, &snapshot)
            .expect_err("a preflight report with an unrelated target ledger must fail closed");
        assert!(error.to_string().contains("target migration ledger"));
    }

    #[test]
    fn snapshot_path_inside_live_data_directory_is_rejected() {
        let fixture = Fixture::new();
        let path = fixture.data_dir.join("unsafe-snapshot.sqlite3");
        let error =
            canonical_new_external_file_path(&path, &fixture.data_dir, "snapshot").unwrap_err();
        assert!(error
            .to_string()
            .contains("outside the live data directory"));
    }

    #[test]
    fn inspection_mismatch_rejects_candidate_context() {
        let fixture = Fixture::new();
        let installed_hash = sha256_file(&fixture.installed).unwrap();
        let staged_hash = sha256_file(&fixture.staged).unwrap();
        let installed = ServerDatabaseInspectReport {
            schema_version: 1,
            product: "server".into(),
            version: "0.9.0".into(),
            executable_sha256: installed_hash,
            canonical_data_dir: fixture.data_dir.clone(),
            canonical_database_path: fixture.database.clone(),
            observed_schema: 9,
            ledger_sha256: "2".repeat(64),
            min_readable_schema: 0,
            max_readable_schema: 9,
            target_schema: 9,
            migration_contract_sha256: "5".repeat(64),
            can_migrate: true,
        };
        let mut staged = installed.clone();
        staged.version = "1.0.0".into();
        staged.executable_sha256 = staged_hash;
        staged.observed_schema = 10;
        staged.max_readable_schema = 13;
        staged.target_schema = 13;
        staged.migration_contract_sha256 = "3".repeat(64);
        let error = validate_compatible_inspections(
            &fixture.installed,
            &fixture.staged,
            &installed,
            &staged,
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("disagree about the source database"));
    }

    #[test]
    fn metadata_round_trip_is_durable_and_strict() {
        let fixture = Fixture::new();
        let metadata = fixture.snapshot_metadata();
        // `Fixture::snapshot` 已解析为受管目录的真实路径；不能从 TempDir 原始
        // `/var/...` 路径派生，否则 macOS 的系统 `/var` 链接会被安全检查拒绝。
        let path = fixture.snapshot.with_file_name("snapshot.json");
        write_snapshot_metadata(&path, &metadata).unwrap();
        assert_eq!(read_snapshot_metadata(&path).unwrap(), metadata);

        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["unexpected"] = serde_json::json!(true);
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(read_snapshot_metadata(&path).is_err());
    }
}
