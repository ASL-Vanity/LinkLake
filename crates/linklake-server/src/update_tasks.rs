//! 远程更新任务的持久状态机。
//!
//! `update_tasks` 保存当前快照，`update_task_events` 只允许追加。独立部署使用 SQLite
//! `IMMEDIATE` 事务避免两个服务端线程把同一个任务同时交给不同 worker。API 与后台
//! 维护只依赖 [`UpdateTaskCoordinationStorage`]，HA 集成必须注入 PostgreSQL/共享账本
//! 实现，并且只有 leader 可以返回维护权限；绝不能让每个实例各自打开本地目录。

use crate::database::Database;
use linklake_core::remote_update::{
    validate_non_nil_uuid, CancelRemoteUpdateTaskRequest, CreateRemoteUpdateTaskRequest,
    RemoteUpdateAction, RemoteUpdateClaim, RemoteUpdateClaimRequest, RemoteUpdateContractError,
    RemoteUpdateErrorCode, RemoteUpdateEventKind, RemoteUpdateLeaseRenewRequest,
    RemoteUpdateLeaseRenewResponse, RemoteUpdateRecoveryState, RemoteUpdateReportRequest,
    RemoteUpdateRestartBinding, RemoteUpdateStage, RemoteUpdateTask, RemoteUpdateTaskDetail,
    RemoteUpdateTaskEvent, RemoteUpdateTaskState, RemoteUpdateWorkerReport,
    REMOTE_UPDATE_CONTRACT_VERSION, REMOTE_UPDATE_RESTART_RESUME_SECONDS,
};
use rusqlite::{params, OptionalExtension, Transaction};
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};
use std::{error::Error, fmt};
use uuid::Uuid;

const MAX_REQUESTED_BY_BYTES: usize = 128;
const MAX_TASK_LIST_LIMIT: usize = 500;
const MAX_RETAINED_TASKS: i64 = 100_000;
const MAX_EVENTS_PER_TASK: i64 = 128;
const MAX_CLAIM_ATTEMPTS: u32 = 16;
const MAX_LEASE_EVENTS_PER_TASK: i64 = 8;
const MAX_REPLAY_EVENTS_PER_TASK: i64 = 4;
const MAX_RESTART_EVENTS_PER_TASK: i64 = 4;

const UPDATE_TASK_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS update_tasks (
    task_id TEXT PRIMARY KEY NOT NULL,
    target_client_id TEXT NOT NULL,
    action TEXT NOT NULL CHECK(action IN ('check', 'download', 'apply', 'status', 'recover', 'rollback')),
    state TEXT NOT NULL CHECK(state IN ('queued', 'claimed', 'running', 'cancel_requested', 'succeeded', 'failed', 'cancelled')),
    stage TEXT NOT NULL CHECK(stage IN ('queued', 'claimed', 'checking', 'downloading', 'applying', 'inspecting', 'recovering', 'rolling_back', 'awaiting_restart', 'completed', 'failed', 'cancelled')),
    recovery_state TEXT NOT NULL CHECK(recovery_state IN ('none', 'retryable', 'status_required', 'rollback_required', 'recovered', 'failed_closed')),
    requested_by TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_fingerprint TEXT NOT NULL,
    attempt INTEGER NOT NULL CHECK(attempt >= 0),
    cancel_requested INTEGER NOT NULL CHECK(cancel_requested IN (0, 1)),
    lease_owner TEXT,
    lease_token_sha256 TEXT,
    lease_deadline_unix_seconds INTEGER,
    restart_binding_json TEXT,
    terminal_worker_instance_id TEXT,
    terminal_lease_token_sha256 TEXT,
    terminal_report_sha256 TEXT,
    result_json TEXT,
    error_code TEXT CHECK(error_code IS NULL OR error_code IN (
        'client_disabled', 'invalid_request', 'confirmation_required', 'task_not_found',
        'target_busy', 'idempotency_conflict', 'lease_conflict', 'lease_expired',
        'invalid_transition', 'insecure_control_channel', 'local_update_busy',
        'signature_verification_failed', 'stable_channel_required', 'downgrade_forbidden',
        'artifact_rejected', 'check_failed', 'download_failed', 'apply_failed',
        'status_failed', 'recovery_failed', 'rollback_failed', 'cancelled',
        'failed_closed', 'internal'
    )),
    created_unix_seconds INTEGER NOT NULL,
    updated_unix_seconds INTEGER NOT NULL,
    completed_unix_seconds INTEGER,
    FOREIGN KEY(target_client_id) REFERENCES clients(client_id) ON DELETE RESTRICT,
    UNIQUE(requested_by, idempotency_key),
    CHECK(
        (lease_owner IS NULL AND lease_token_sha256 IS NULL AND lease_deadline_unix_seconds IS NULL)
        OR
        (lease_owner IS NOT NULL AND lease_token_sha256 IS NOT NULL AND lease_deadline_unix_seconds IS NOT NULL
         AND LENGTH(lease_token_sha256) = 64 AND lease_token_sha256 NOT GLOB '*[^0-9a-f]*')
    ),
    CHECK(
        (stage = 'awaiting_restart' AND restart_binding_json IS NOT NULL)
        OR (stage != 'awaiting_restart' AND restart_binding_json IS NULL)
    ),
    CHECK(
        (terminal_worker_instance_id IS NULL AND terminal_lease_token_sha256 IS NULL AND terminal_report_sha256 IS NULL)
        OR
        (state IN ('succeeded', 'failed', 'cancelled')
         AND terminal_worker_instance_id IS NOT NULL
         AND terminal_lease_token_sha256 IS NOT NULL
         AND LENGTH(terminal_lease_token_sha256) = 64
         AND terminal_lease_token_sha256 NOT GLOB '*[^0-9a-f]*'
         AND terminal_report_sha256 IS NOT NULL
         AND LENGTH(terminal_report_sha256) = 64
         AND terminal_report_sha256 NOT GLOB '*[^0-9a-f]*')
    ),
    CHECK(
        (state = 'queued' AND stage = 'queued')
        OR (state = 'claimed' AND stage = 'claimed')
        OR (state = 'running' AND stage IN ('checking', 'downloading', 'applying', 'inspecting', 'recovering', 'rolling_back', 'awaiting_restart'))
        OR (state = 'cancel_requested' AND stage IN ('claimed', 'checking', 'downloading', 'applying', 'inspecting', 'recovering', 'rolling_back', 'awaiting_restart'))
        OR (state = 'succeeded' AND stage = 'completed')
        OR (state = 'failed' AND stage = 'failed')
        OR (state = 'cancelled' AND stage = 'cancelled')
    ),
    CHECK(
        stage IN ('queued', 'claimed', 'awaiting_restart', 'completed', 'failed', 'cancelled')
        OR (action = 'check' AND stage = 'checking')
        OR (action = 'download' AND stage = 'downloading')
        OR (action = 'apply' AND stage = 'applying')
        OR (action = 'status' AND stage = 'inspecting')
        OR (action = 'recover' AND stage = 'recovering')
        OR (action = 'rollback' AND stage = 'rolling_back')
    ),
    CHECK(
        (state IN ('queued', 'succeeded', 'failed', 'cancelled') AND lease_owner IS NULL)
        OR (state IN ('claimed', 'running', 'cancel_requested') AND lease_owner IS NOT NULL)
    ),
    CHECK(
        (state IN ('queued', 'claimed', 'running', 'cancel_requested')
         AND completed_unix_seconds IS NULL AND result_json IS NULL AND error_code IS NULL)
        OR (state = 'succeeded' AND completed_unix_seconds IS NOT NULL AND result_json IS NOT NULL AND error_code IS NULL)
        OR (state = 'failed' AND completed_unix_seconds IS NOT NULL AND result_json IS NULL AND error_code IS NOT NULL AND error_code != 'cancelled')
        OR (state = 'cancelled' AND completed_unix_seconds IS NOT NULL AND result_json IS NULL AND error_code = 'cancelled')
    )
);
CREATE UNIQUE INDEX IF NOT EXISTS update_tasks_one_active_target
    ON update_tasks(target_client_id)
    WHERE state IN ('queued', 'claimed', 'running', 'cancel_requested');
CREATE INDEX IF NOT EXISTS update_tasks_target_created
    ON update_tasks(target_client_id, created_unix_seconds DESC);
CREATE INDEX IF NOT EXISTS update_tasks_claim_queue
    ON update_tasks(target_client_id, state, created_unix_seconds ASC);
CREATE INDEX IF NOT EXISTS update_tasks_active_lease_deadline
    ON update_tasks(lease_deadline_unix_seconds)
    WHERE state IN ('claimed', 'running', 'cancel_requested');

CREATE TABLE IF NOT EXISTS update_task_events (
    event_id TEXT PRIMARY KEY NOT NULL,
    task_id TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK(sequence > 0),
    kind TEXT NOT NULL CHECK(kind IN ('created', 'idempotent_replay', 'claimed', 'lease_renewed', 'stage_reported', 'cancel_requested', 'cancelled', 'succeeded', 'failed', 'lease_expired_requeued', 'lease_expired_failed_closed', 'restart_reconciled')),
    state TEXT NOT NULL,
    stage TEXT NOT NULL,
    recovery_state TEXT NOT NULL,
    error_code TEXT,
    created_unix_seconds INTEGER NOT NULL,
    FOREIGN KEY(task_id) REFERENCES update_tasks(task_id) ON DELETE RESTRICT,
    UNIQUE(task_id, sequence)
);
CREATE INDEX IF NOT EXISTS update_task_events_task_sequence
    ON update_task_events(task_id, sequence ASC);
CREATE TRIGGER IF NOT EXISTS update_task_events_no_update
BEFORE UPDATE ON update_task_events
BEGIN
    SELECT RAISE(ABORT, 'update_task_events is append-only');
END;
CREATE TRIGGER IF NOT EXISTS update_task_events_no_delete
BEFORE DELETE ON update_task_events
BEGIN
    SELECT RAISE(ABORT, 'update_task_events is append-only');
END;
"#;

fn ensure_update_task_replay_columns(connection: &rusqlite::Connection) -> anyhow::Result<()> {
    let table_sql: Option<String> = connection
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'update_tasks'",
            [],
            |row| row.get(0),
        )
        .optional()?;
    let Some(table_sql) = table_sql else {
        return Ok(());
    };
    let mut columns = std::collections::HashSet::new();
    let mut statement = connection.prepare("PRAGMA table_info(update_tasks)")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        columns.insert(row.get::<_, String>(1)?);
    }
    drop(rows);
    drop(statement);
    if table_sql.contains("restart_binding_json IS NOT NULL")
        && columns.contains("terminal_worker_instance_id")
        && columns.contains("terminal_lease_token_sha256")
        && columns.contains("terminal_report_sha256")
    {
        return Ok(());
    }
    anyhow::ensure!(
        columns.contains("task_id")
            && columns.contains("target_client_id")
            && columns.contains("action")
            && columns.contains("state")
            && columns.contains("stage")
            && columns.contains("recovery_state")
            && columns.contains("requested_by")
            && columns.contains("idempotency_key")
            && columns.contains("request_fingerprint")
            && columns.contains("attempt")
            && columns.contains("cancel_requested")
            && columns.contains("lease_owner")
            && columns.contains("lease_token_sha256")
            && columns.contains("lease_deadline_unix_seconds")
            && columns.contains("result_json")
            && columns.contains("error_code")
            && columns.contains("created_unix_seconds")
            && columns.contains("updated_unix_seconds")
            && columns.contains("completed_unix_seconds"),
        "remote update task table is missing required columns"
    );
    let restart_expression = if columns.contains("restart_binding_json") {
        "restart_binding_json"
    } else {
        "NULL"
    };
    let terminal_worker_expression = if columns.contains("terminal_worker_instance_id") {
        "terminal_worker_instance_id"
    } else {
        "NULL"
    };
    let terminal_lease_expression = if columns.contains("terminal_lease_token_sha256") {
        "terminal_lease_token_sha256"
    } else {
        "NULL"
    };
    let terminal_report_expression = if columns.contains("terminal_report_sha256") {
        "terminal_report_sha256"
    } else {
        "NULL"
    };
    let foreign_keys: i64 = connection.query_row("PRAGMA foreign_keys", [], |row| row.get(0))?;
    let legacy_alter_table: i64 =
        connection.query_row("PRAGMA legacy_alter_table", [], |row| row.get(0))?;
    // PRAGMA foreign_keys 不能在事务中切换。迁移连接在 BEGIN IMMEDIATE 前暂时关闭
    // 自动约束执行，复制完数据后仍会用 foreign_key_check 做全量验证，并恢复原设置。
    connection.pragma_update(None, "foreign_keys", false)?;
    // SQLite 3.26+ 会在重命名父表时同步改写子表的外键目标。这里必须暂时启用旧式
    // ALTER TABLE 语义，让 update_task_events 始终指向即将创建的新 update_tasks，
    // 否则已有事件的数据库会把外键改到 update_tasks_legacy，导致旧表无法删除。
    if let Err(error) = connection.pragma_update(None, "legacy_alter_table", true) {
        let _ = connection.pragma_update(None, "foreign_keys", foreign_keys != 0);
        return Err(error.into());
    }
    let result = (|| -> anyhow::Result<()> {
        connection.execute_batch("BEGIN IMMEDIATE")?;
        connection.execute_batch(
            "DROP INDEX IF EXISTS update_tasks_one_active_target;
             DROP INDEX IF EXISTS update_tasks_target_created;
             DROP INDEX IF EXISTS update_tasks_claim_queue;
             DROP INDEX IF EXISTS update_tasks_active_lease_deadline;
             ALTER TABLE update_tasks RENAME TO update_tasks_legacy;",
        )?;
        connection.execute_batch(UPDATE_TASK_SCHEMA)?;
        connection.execute(
            &format!(
                "INSERT INTO update_tasks (
                    task_id, target_client_id, action, state, stage, recovery_state,
                    requested_by, idempotency_key, request_fingerprint, attempt,
                    cancel_requested, lease_owner, lease_token_sha256,
                    lease_deadline_unix_seconds, restart_binding_json,
                    terminal_worker_instance_id, terminal_lease_token_sha256,
                    terminal_report_sha256, result_json, error_code,
                    created_unix_seconds, updated_unix_seconds, completed_unix_seconds
                 ) SELECT task_id, target_client_id, action, state, stage, recovery_state,
                    requested_by, idempotency_key, request_fingerprint, attempt,
                    cancel_requested, lease_owner, lease_token_sha256,
                    lease_deadline_unix_seconds, {restart_expression},
                    {terminal_worker_expression}, {terminal_lease_expression},
                    {terminal_report_expression}, result_json, error_code,
                    created_unix_seconds, updated_unix_seconds, completed_unix_seconds
                 FROM update_tasks_legacy"
            ),
            [],
        )?;
        connection.execute_batch("DROP TABLE update_tasks_legacy")?;
        let event_parent: Option<String> = connection
            .query_row(
                "SELECT \"table\" FROM pragma_foreign_key_list('update_task_events')
                 WHERE \"from\" = 'task_id' LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        anyhow::ensure!(
            event_parent.as_deref() == Some("update_tasks"),
            "remote update event foreign key does not reference the rebuilt task table"
        );
        let foreign_key_violation: Option<String> = connection
            .query_row(
                "SELECT \"table\" FROM pragma_foreign_key_check LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        anyhow::ensure!(
            foreign_key_violation.is_none(),
            "remote update task migration left a foreign key violation"
        );
        connection.execute_batch("COMMIT")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = connection.execute_batch("ROLLBACK");
    }
    let restore_result =
        connection.pragma_update(None, "legacy_alter_table", legacy_alter_table != 0);
    let restore_foreign_keys = connection.pragma_update(None, "foreign_keys", foreign_keys != 0);
    match (result, restore_result, restore_foreign_keys) {
        (Err(error), _, _) => Err(error),
        (Ok(()), Err(error), _) | (Ok(()), Ok(()), Err(error)) => Err(error.into()),
        (Ok(()), Ok(()), Ok(())) => Ok(()),
    }
}

#[derive(Clone)]
pub(crate) struct UpdateTaskCatalog {
    database: Database,
}

#[derive(Debug)]
pub(crate) enum UpdateTaskError {
    Contract(RemoteUpdateContractError),
    TargetNotFound,
    InvalidRequester,
    TaskNotFound,
    TargetBusy,
    IdempotencyConflict,
    LeaseConflict,
    LeaseExpired,
    InvalidTransition,
    CapacityExceeded,
    Storage(anyhow::Error),
}

#[derive(Clone, Debug)]
struct TerminalReportReplay {
    worker_instance_id: Uuid,
    lease_token_sha256: String,
    report_sha256: String,
}

impl TerminalReportReplay {
    fn from_request(request: &RemoteUpdateReportRequest) -> anyhow::Result<Self> {
        Ok(Self {
            worker_instance_id: request.worker_instance_id,
            lease_token_sha256: lease_token_sha256(request.lease_token),
            report_sha256: worker_report_sha256(&request.report)?,
        })
    }
}

/// 远程更新 API 与 worker 使用的协调存储边界。
///
/// HA 实现必须在共享事务中维持幂等键、单目标活动任务、lease CAS、追加事件序列和
/// restart binding；`is_maintenance_leader` 只允许当前 leader 驱动启动恢复与 sweep。
pub(crate) trait UpdateTaskCoordinationStorage: Send {
    fn is_maintenance_leader(&self) -> bool;

    fn create(
        &self,
        request: &CreateRemoteUpdateTaskRequest,
        requested_by: &str,
        now: u64,
    ) -> Result<RemoteUpdateTask, UpdateTaskError>;

    fn list(
        &self,
        target_client_id: Option<Uuid>,
        requested_limit: usize,
        now: u64,
    ) -> Result<Vec<RemoteUpdateTask>, UpdateTaskError>;

    fn detail(&self, task_id: Uuid, now: u64) -> Result<RemoteUpdateTaskDetail, UpdateTaskError>;

    fn reconcile_after_restart(&self, now: u64) -> Result<(), UpdateTaskError>;

    fn sweep(&self, now: u64) -> Result<(), UpdateTaskError>;

    fn claim(
        &self,
        target_client_id: Uuid,
        request: &RemoteUpdateClaimRequest,
        now: u64,
    ) -> Result<Option<RemoteUpdateClaim>, UpdateTaskError>;

    fn renew(
        &self,
        target_client_id: Uuid,
        task_id: Uuid,
        request: &RemoteUpdateLeaseRenewRequest,
        now: u64,
    ) -> Result<RemoteUpdateLeaseRenewResponse, UpdateTaskError>;

    fn report(
        &self,
        target_client_id: Uuid,
        task_id: Uuid,
        request: &RemoteUpdateReportRequest,
        now: u64,
    ) -> Result<RemoteUpdateTask, UpdateTaskError>;

    fn cancel(
        &self,
        task_id: Uuid,
        request: &CancelRemoteUpdateTaskRequest,
        now: u64,
    ) -> Result<RemoteUpdateTask, UpdateTaskError>;
}

impl fmt::Display for UpdateTaskError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(error) => write!(formatter, "invalid remote update contract: {error}"),
            Self::TargetNotFound => formatter.write_str("remote update target was not found"),
            Self::InvalidRequester => formatter.write_str("remote update requester is invalid"),
            Self::TaskNotFound => formatter.write_str("remote update task was not found"),
            Self::TargetBusy => {
                formatter.write_str("remote update target already has an active task")
            }
            Self::IdempotencyConflict => {
                formatter.write_str("remote update idempotency key conflicts with another request")
            }
            Self::LeaseConflict => {
                formatter.write_str("remote update lease does not belong to this worker")
            }
            Self::LeaseExpired => formatter.write_str("remote update lease has expired"),
            Self::InvalidTransition => {
                formatter.write_str("remote update task transition is invalid")
            }
            Self::CapacityExceeded => {
                formatter.write_str("remote update task retention capacity was reached")
            }
            Self::Storage(error) => {
                write!(formatter, "remote update task storage failed: {error:#}")
            }
        }
    }
}

impl Error for UpdateTaskError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Contract(error) => Some(error),
            Self::Storage(error) => Some(error.as_ref()),
            _ => None,
        }
    }
}

impl From<RemoteUpdateContractError> for UpdateTaskError {
    fn from(error: RemoteUpdateContractError) -> Self {
        Self::Contract(error)
    }
}

impl UpdateTaskCatalog {
    pub(crate) fn open(database: &Database) -> Result<Self, UpdateTaskError> {
        let storage_backend = std::env::var("LINKLAKE_STORAGE_BACKEND")
            .unwrap_or_else(|_| "sqlite".to_owned())
            .trim()
            .to_ascii_lowercase();
        if matches!(storage_backend.as_str(), "postgres" | "postgresql") {
            return Err(UpdateTaskError::Storage(anyhow::anyhow!(
                "remote update tasks require shared PostgreSQL coordination storage; refusing a local SQLite catalog in HA mode"
            )));
        }
        database
            .with_connection(|connection| {
                connection.execute_batch(UPDATE_TASK_SCHEMA)?;
                ensure_update_task_replay_columns(connection)?;
                Ok(())
            })
            .map_err(UpdateTaskError::Storage)?;
        Ok(Self {
            database: database.clone(),
        })
    }

    pub(crate) fn create(
        &self,
        request: &CreateRemoteUpdateTaskRequest,
        requested_by: &str,
        now: u64,
    ) -> Result<RemoteUpdateTask, UpdateTaskError> {
        request.validate()?;
        validate_requested_by(requested_by)?;
        let requested_by = requested_by.to_owned();
        let request = request.clone();
        let fingerprint = request_fingerprint(&request, &requested_by);
        map_database_result(self.database.with_transaction(|transaction| {
            let target_exists: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM clients WHERE client_id = ?1)",
                [request.target_client_id.to_string()],
                |row| row.get(0),
            )?;
            if !target_exists {
                return Err(domain_error(UpdateTaskError::TargetNotFound));
            }

            let existing = task_by_idempotency_key(
                transaction,
                &requested_by,
                &request.idempotency_key,
            )?;
            if let Some(existing) = existing {
                let existing_fingerprint: String = transaction.query_row(
                    "SELECT request_fingerprint FROM update_tasks WHERE task_id = ?1",
                    [existing.task_id.to_string()],
                    |row| row.get(0),
                )?;
                if existing_fingerprint != fingerprint {
                    return Err(domain_error(UpdateTaskError::IdempotencyConflict));
                }
                reconcile_expired_leases(
                    transaction,
                    Some(existing.target_client_id),
                    now,
                )?;
                let existing = task_by_id(transaction, existing.task_id)?
                    .ok_or_else(|| domain_error(UpdateTaskError::TaskNotFound))?;
                append_event(
                    transaction,
                    &existing,
                    RemoteUpdateEventKind::IdempotentReplay,
                    now,
                )?;
                return Ok(existing);
            }

            reconcile_expired_leases(transaction, Some(request.target_client_id), now)?;

            let active_exists: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM update_tasks WHERE target_client_id = ?1 AND state IN ('queued', 'claimed', 'running', 'cancel_requested'))",
                [request.target_client_id.to_string()],
                |row| row.get(0),
            )?;
            if active_exists {
                return Err(domain_error(UpdateTaskError::TargetBusy));
            }
            let retained_tasks: i64 =
                transaction.query_row("SELECT COUNT(*) FROM update_tasks", [], |row| row.get(0))?;
            if retained_tasks >= MAX_RETAINED_TASKS {
                return Err(domain_error(UpdateTaskError::CapacityExceeded));
            }

            let task = RemoteUpdateTask {
                schema_version: REMOTE_UPDATE_CONTRACT_VERSION,
                task_id: Uuid::new_v4(),
                target_client_id: request.target_client_id,
                action: request.action,
                state: RemoteUpdateTaskState::Queued,
                stage: RemoteUpdateStage::Queued,
                recovery_state: RemoteUpdateRecoveryState::None,
                requested_by,
                idempotency_key: request.idempotency_key,
                attempt: 0,
                cancel_requested: false,
                lease_owner: None,
                lease_deadline_unix_seconds: None,
                restart: None,
                result: None,
                error_code: None,
                created_unix_seconds: now,
                updated_unix_seconds: now,
                completed_unix_seconds: None,
            };
            let affected = transaction.execute(
                "INSERT INTO update_tasks (
                    task_id, target_client_id, action, state, stage, recovery_state,
                    requested_by, idempotency_key, request_fingerprint, attempt,
                    cancel_requested, created_unix_seconds, updated_unix_seconds
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0, 0, ?10, ?10)",
                params![
                    task.task_id.to_string(),
                    task.target_client_id.to_string(),
                    enum_text(task.action)?,
                    enum_text(task.state)?,
                    enum_text(task.stage)?,
                    enum_text(task.recovery_state)?,
                    task.requested_by,
                    task.idempotency_key,
                    fingerprint,
                    now_i64(now)?,
                ],
            )?;
            ensure_one_row(affected, "create remote update task")?;
            append_event(transaction, &task, RemoteUpdateEventKind::Created, now)?;
            Ok(task)
        }))
    }

    pub(crate) fn list(
        &self,
        target_client_id: Option<Uuid>,
        requested_limit: usize,
        now: u64,
    ) -> Result<Vec<RemoteUpdateTask>, UpdateTaskError> {
        if let Some(target_client_id) = target_client_id {
            validate_non_nil_uuid(target_client_id)?;
        }
        let limit = requested_limit.clamp(1, MAX_TASK_LIST_LIMIT) as i64;
        map_database_result(self.database.with_transaction(|transaction| {
            reconcile_expired_leases(transaction, target_client_id, now)?;
            let mut tasks = Vec::new();
            match target_client_id {
                Some(target_client_id) => {
                    let mut statement = transaction.prepare(&format!(
                        "{} WHERE target_client_id = ?1 ORDER BY created_unix_seconds DESC, task_id DESC LIMIT ?2",
                        TASK_SELECT
                    ))?;
                    let rows = statement.query_map(
                        params![target_client_id.to_string(), limit],
                        read_task,
                    )?;
                    for row in rows {
                        tasks.push(row?);
                    }
                }
                None => {
                    let mut statement = transaction.prepare(&format!(
                        "{} ORDER BY created_unix_seconds DESC, task_id DESC LIMIT ?1",
                        TASK_SELECT
                    ))?;
                    let rows = statement.query_map([limit], read_task)?;
                    for row in rows {
                        tasks.push(row?);
                    }
                }
            }
            Ok(tasks)
        }))
    }

    pub(crate) fn detail(
        &self,
        task_id: Uuid,
        now: u64,
    ) -> Result<RemoteUpdateTaskDetail, UpdateTaskError> {
        validate_non_nil_uuid(task_id)?;
        map_database_result(self.database.with_transaction(|transaction| {
            let task = task_by_id(transaction, task_id)?
                .ok_or_else(|| domain_error(UpdateTaskError::TaskNotFound))?;
            reconcile_expired_leases(transaction, Some(task.target_client_id), now)?;
            let task = task_by_id(transaction, task_id)?
                .ok_or_else(|| domain_error(UpdateTaskError::TaskNotFound))?;
            let mut statement = transaction.prepare(
                "SELECT event_id, task_id, sequence, kind, state, stage, recovery_state, error_code, created_unix_seconds
                 FROM (
                    SELECT event_id, task_id, sequence, kind, state, stage, recovery_state, error_code, created_unix_seconds
                    FROM update_task_events WHERE task_id = ?1
                    ORDER BY sequence DESC LIMIT ?2
                 ) ORDER BY sequence ASC",
            )?;
            let rows = statement.query_map(
                params![task_id.to_string(), MAX_EVENTS_PER_TASK],
                read_event,
            )?;
            let mut events = Vec::new();
            for row in rows {
                events.push(row?);
            }
            let detail = RemoteUpdateTaskDetail { task, events };
            detail
                .validate(task_id)
                .map_err(|error| anyhow::anyhow!("invalid remote update task detail: {error}"))?;
            Ok(detail)
        }))
    }

    /// 服务端启动时执行一次。有效租约保持不变；缺失或过期租约按动作类型确定性处理。
    pub(crate) fn reconcile_after_restart(&self, now: u64) -> Result<(), UpdateTaskError> {
        map_database_result(self.database.with_transaction(|transaction| {
            let tasks = active_leased_tasks(transaction, None)?;
            for task in tasks {
                let lease_valid = task
                    .lease_deadline_unix_seconds
                    .is_some_and(|deadline| deadline > now)
                    && task.lease_owner.is_some();
                if lease_valid {
                    append_event(
                        transaction,
                        &task,
                        RemoteUpdateEventKind::RestartReconciled,
                        now,
                    )?;
                } else {
                    reconcile_lost_lease(transaction, task, now)?;
                }
            }
            Ok(())
        }))
    }

    pub(crate) fn sweep(&self, now: u64) -> Result<(), UpdateTaskError> {
        map_database_result(
            self.database
                .with_transaction(|transaction| reconcile_expired_leases(transaction, None, now)),
        )
    }

    pub(crate) fn claim(
        &self,
        target_client_id: Uuid,
        request: &RemoteUpdateClaimRequest,
        now: u64,
    ) -> Result<Option<RemoteUpdateClaim>, UpdateTaskError> {
        validate_non_nil_uuid(target_client_id)?;
        request.validate()?;
        let request = request.clone();
        map_database_result(self.database.with_transaction(|transaction| {
            reconcile_expired_leases(transaction, Some(target_client_id), now)?;
            let task = oldest_queued_task(transaction, target_client_id)?;
            let Some(mut task) = task else {
                return Ok(None);
            };
            if task.attempt >= MAX_CLAIM_ATTEMPTS {
                task.state = RemoteUpdateTaskState::Failed;
                task.stage = RemoteUpdateStage::Failed;
                task.recovery_state = RemoteUpdateRecoveryState::FailedClosed;
                task.error_code = Some(RemoteUpdateErrorCode::FailedClosed);
                task.updated_unix_seconds = now;
                task.completed_unix_seconds = Some(now);
                persist_task_after_report(transaction, &task, None)?;
                append_event(transaction, &task, RemoteUpdateEventKind::Failed, now)?;
                return Ok(None);
            }
            let lease_token = Uuid::new_v4();
            let lease_deadline = checked_deadline(now, request.requested_lease_seconds)?;
            task.state = RemoteUpdateTaskState::Claimed;
            task.stage = RemoteUpdateStage::Claimed;
            task.recovery_state = RemoteUpdateRecoveryState::None;
            task.restart = None;
            task.attempt = task
                .attempt
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("remote update task attempt counter overflowed"))?;
            task.lease_owner = Some(request.worker_instance_id);
            task.lease_deadline_unix_seconds = Some(lease_deadline);
            task.updated_unix_seconds = now;
            let affected = transaction.execute(
                "UPDATE update_tasks SET state = ?1, stage = ?2, recovery_state = ?3,
                    attempt = ?4, lease_owner = ?5, lease_token_sha256 = ?6,
                    lease_deadline_unix_seconds = ?7, updated_unix_seconds = ?8
                 WHERE task_id = ?9 AND state = 'queued'",
                params![
                    enum_text(task.state)?,
                    enum_text(task.stage)?,
                    enum_text(task.recovery_state)?,
                    i64::from(task.attempt),
                    request.worker_instance_id.to_string(),
                    lease_token_sha256(lease_token),
                    now_i64(lease_deadline)?,
                    now_i64(now)?,
                    task.task_id.to_string(),
                ],
            )?;
            ensure_one_row(affected, "claim remote update task")?;
            append_event(transaction, &task, RemoteUpdateEventKind::Claimed, now)?;
            Ok(Some(RemoteUpdateClaim {
                task,
                lease_token,
                lease_deadline_unix_seconds: lease_deadline,
            }))
        }))
    }

    pub(crate) fn renew(
        &self,
        target_client_id: Uuid,
        task_id: Uuid,
        request: &RemoteUpdateLeaseRenewRequest,
        now: u64,
    ) -> Result<RemoteUpdateLeaseRenewResponse, UpdateTaskError> {
        validate_non_nil_uuid(target_client_id)?;
        validate_non_nil_uuid(task_id)?;
        let request = request.clone();
        map_database_result(self.database.with_transaction(|transaction| {
            let mut task = task_by_id(transaction, task_id)?
                .ok_or_else(|| domain_error(UpdateTaskError::TaskNotFound))?;
            if task.target_client_id != target_client_id {
                return Err(domain_error(UpdateTaskError::TaskNotFound));
            }
            request
                .validate(task.action)
                .map_err(|error| domain_error(UpdateTaskError::Contract(error)))?;
            authorize_lease(
                transaction,
                &task,
                &request.worker_instance_id,
                request.lease_token,
                now,
            )?;
            if !valid_renew_transition(task.stage, request.stage, task.action) {
                return Err(domain_error(UpdateTaskError::InvalidTransition));
            }
            let requested_deadline = checked_deadline(now, request.requested_lease_seconds)?;
            let deadline = if task.stage == RemoteUpdateStage::AwaitingRestart
                || request.stage == RemoteUpdateStage::AwaitingRestart
            {
                let binding = task
                    .restart
                    .as_ref()
                    .ok_or_else(|| domain_error(UpdateTaskError::InvalidTransition))?;
                requested_deadline.min(binding.resume_deadline_unix_seconds)
            } else {
                requested_deadline
            };
            if deadline <= now {
                return Err(domain_error(UpdateTaskError::LeaseExpired));
            }
            task.stage = request.stage;
            task.state = if task.cancel_requested {
                RemoteUpdateTaskState::CancelRequested
            } else if request.stage == RemoteUpdateStage::Claimed {
                RemoteUpdateTaskState::Claimed
            } else {
                RemoteUpdateTaskState::Running
            };
            task.lease_deadline_unix_seconds = Some(deadline);
            task.updated_unix_seconds = now;
            let affected = transaction.execute(
                "UPDATE update_tasks SET state = ?1, stage = ?2,
                    lease_deadline_unix_seconds = ?3, updated_unix_seconds = ?4
                 WHERE task_id = ?5",
                params![
                    enum_text(task.state)?,
                    enum_text(task.stage)?,
                    now_i64(deadline)?,
                    now_i64(now)?,
                    task.task_id.to_string(),
                ],
            )?;
            ensure_one_row(affected, "renew remote update task lease")?;
            append_event(transaction, &task, RemoteUpdateEventKind::LeaseRenewed, now)?;
            Ok(RemoteUpdateLeaseRenewResponse {
                task_id,
                lease_deadline_unix_seconds: deadline,
                cancel_requested: task.cancel_requested,
            })
        }))
    }

    pub(crate) fn report(
        &self,
        target_client_id: Uuid,
        task_id: Uuid,
        request: &RemoteUpdateReportRequest,
        now: u64,
    ) -> Result<RemoteUpdateTask, UpdateTaskError> {
        validate_non_nil_uuid(target_client_id)?;
        validate_non_nil_uuid(task_id)?;
        let request = request.clone();
        map_database_result(self.database.with_transaction(|transaction| {
            let mut task = task_by_id(transaction, task_id)?
                .ok_or_else(|| domain_error(UpdateTaskError::TaskNotFound))?;
            if task.target_client_id != target_client_id {
                return Err(domain_error(UpdateTaskError::TaskNotFound));
            }
            request
                .validate(task.action)
                .map_err(|error| domain_error(UpdateTaskError::Contract(error)))?;
            if task.state.is_terminal() {
                return replay_terminal_report(transaction, &task, &request, now);
            }
            request
                .report
                .validate_for_task(task.action, task.stage, task.cancel_requested)
                .map_err(|error| domain_error(UpdateTaskError::Contract(error)))?;
            authorize_lease(
                transaction,
                &task,
                &request.worker_instance_id,
                request.lease_token,
                now,
            )?;
            let event_kind = apply_worker_report(&mut task, &request.report, now)?;
            let terminal_replay = task
                .state
                .is_terminal()
                .then(|| TerminalReportReplay::from_request(&request))
                .transpose()?;
            persist_task_after_report(transaction, &task, terminal_replay.as_ref())?;
            append_event(transaction, &task, event_kind, now)?;
            Ok(task)
        }))
    }

    pub(crate) fn cancel(
        &self,
        task_id: Uuid,
        request: &CancelRemoteUpdateTaskRequest,
        now: u64,
    ) -> Result<RemoteUpdateTask, UpdateTaskError> {
        validate_non_nil_uuid(task_id)?;
        request.validate()?;
        map_database_result(self.database.with_transaction(|transaction| {
            let task = task_by_id(transaction, task_id)?
                .ok_or_else(|| domain_error(UpdateTaskError::TaskNotFound))?;
            reconcile_expired_leases(transaction, Some(task.target_client_id), now)?;
            let mut task = task_by_id(transaction, task_id)?
                .ok_or_else(|| domain_error(UpdateTaskError::TaskNotFound))?;
            if task.state.is_terminal() || task.cancel_requested {
                return Ok(task);
            }
            task.cancel_requested = true;
            task.updated_unix_seconds = now;
            let event_kind = if task.state == RemoteUpdateTaskState::Queued {
                task.state = RemoteUpdateTaskState::Cancelled;
                task.stage = RemoteUpdateStage::Cancelled;
                task.recovery_state = RemoteUpdateRecoveryState::None;
                task.error_code = Some(RemoteUpdateErrorCode::Cancelled);
                task.completed_unix_seconds = Some(now);
                clear_task_lease(&mut task);
                RemoteUpdateEventKind::Cancelled
            } else {
                task.state = RemoteUpdateTaskState::CancelRequested;
                RemoteUpdateEventKind::CancelRequested
            };
            persist_task_after_report(transaction, &task, None)?;
            append_event(transaction, &task, event_kind, now)?;
            Ok(task)
        }))
    }
}

impl UpdateTaskCoordinationStorage for UpdateTaskCatalog {
    fn is_maintenance_leader(&self) -> bool {
        // SQLite 持久库由 Database 的进程排他锁保护，因此该进程是唯一维护者。
        true
    }

    fn create(
        &self,
        request: &CreateRemoteUpdateTaskRequest,
        requested_by: &str,
        now: u64,
    ) -> Result<RemoteUpdateTask, UpdateTaskError> {
        UpdateTaskCatalog::create(self, request, requested_by, now)
    }

    fn list(
        &self,
        target_client_id: Option<Uuid>,
        requested_limit: usize,
        now: u64,
    ) -> Result<Vec<RemoteUpdateTask>, UpdateTaskError> {
        UpdateTaskCatalog::list(self, target_client_id, requested_limit, now)
    }

    fn detail(&self, task_id: Uuid, now: u64) -> Result<RemoteUpdateTaskDetail, UpdateTaskError> {
        UpdateTaskCatalog::detail(self, task_id, now)
    }

    fn reconcile_after_restart(&self, now: u64) -> Result<(), UpdateTaskError> {
        UpdateTaskCatalog::reconcile_after_restart(self, now)
    }

    fn sweep(&self, now: u64) -> Result<(), UpdateTaskError> {
        UpdateTaskCatalog::sweep(self, now)
    }

    fn claim(
        &self,
        target_client_id: Uuid,
        request: &RemoteUpdateClaimRequest,
        now: u64,
    ) -> Result<Option<RemoteUpdateClaim>, UpdateTaskError> {
        UpdateTaskCatalog::claim(self, target_client_id, request, now)
    }

    fn renew(
        &self,
        target_client_id: Uuid,
        task_id: Uuid,
        request: &RemoteUpdateLeaseRenewRequest,
        now: u64,
    ) -> Result<RemoteUpdateLeaseRenewResponse, UpdateTaskError> {
        UpdateTaskCatalog::renew(self, target_client_id, task_id, request, now)
    }

    fn report(
        &self,
        target_client_id: Uuid,
        task_id: Uuid,
        request: &RemoteUpdateReportRequest,
        now: u64,
    ) -> Result<RemoteUpdateTask, UpdateTaskError> {
        UpdateTaskCatalog::report(self, target_client_id, task_id, request, now)
    }

    fn cancel(
        &self,
        task_id: Uuid,
        request: &CancelRemoteUpdateTaskRequest,
        now: u64,
    ) -> Result<RemoteUpdateTask, UpdateTaskError> {
        UpdateTaskCatalog::cancel(self, task_id, request, now)
    }
}

const TASK_SELECT: &str = "SELECT task_id, target_client_id, action, state, stage,
    recovery_state, requested_by, idempotency_key, attempt, cancel_requested,
    lease_owner, lease_deadline_unix_seconds, restart_binding_json, result_json, error_code,
    created_unix_seconds, updated_unix_seconds, completed_unix_seconds FROM update_tasks";

fn task_by_id(
    connection: &rusqlite::Connection,
    task_id: Uuid,
) -> anyhow::Result<Option<RemoteUpdateTask>> {
    let mut statement = connection.prepare(&format!("{TASK_SELECT} WHERE task_id = ?1"))?;
    Ok(statement
        .query_row([task_id.to_string()], read_task)
        .optional()?)
}

fn task_by_idempotency_key(
    transaction: &Transaction<'_>,
    requested_by: &str,
    idempotency_key: &str,
) -> anyhow::Result<Option<RemoteUpdateTask>> {
    let mut statement = transaction.prepare(&format!(
        "{TASK_SELECT} WHERE requested_by = ?1 AND idempotency_key = ?2"
    ))?;
    Ok(statement
        .query_row(params![requested_by, idempotency_key], read_task)
        .optional()?)
}

fn oldest_queued_task(
    transaction: &Transaction<'_>,
    target_client_id: Uuid,
) -> anyhow::Result<Option<RemoteUpdateTask>> {
    let mut statement = transaction.prepare(&format!(
        "{TASK_SELECT} WHERE target_client_id = ?1 AND state = 'queued'
         ORDER BY created_unix_seconds ASC, task_id ASC LIMIT 1"
    ))?;
    Ok(statement
        .query_row([target_client_id.to_string()], read_task)
        .optional()?)
}

fn active_leased_tasks(
    transaction: &Transaction<'_>,
    target_client_id: Option<Uuid>,
) -> anyhow::Result<Vec<RemoteUpdateTask>> {
    let sql = match target_client_id {
        Some(_) => format!(
            "{TASK_SELECT} WHERE target_client_id = ?1 AND state IN ('claimed', 'running', 'cancel_requested')
             ORDER BY created_unix_seconds ASC, task_id ASC"
        ),
        None => format!(
            "{TASK_SELECT} WHERE state IN ('claimed', 'running', 'cancel_requested')
             ORDER BY created_unix_seconds ASC, task_id ASC"
        ),
    };
    let mut statement = transaction.prepare(&sql)?;
    let mut rows = match target_client_id {
        Some(target_client_id) => statement.query([target_client_id.to_string()])?,
        None => statement.query([])?,
    };
    let mut tasks = Vec::new();
    while let Some(row) = rows.next()? {
        tasks.push(read_task(row)?);
    }
    Ok(tasks)
}

fn expired_leased_tasks(
    transaction: &Transaction<'_>,
    target_client_id: Option<Uuid>,
    now: u64,
) -> anyhow::Result<Vec<RemoteUpdateTask>> {
    let sql = match target_client_id {
        Some(_) => format!(
            "{TASK_SELECT} WHERE target_client_id = ?1
             AND state IN ('claimed', 'running', 'cancel_requested')
             AND (lease_deadline_unix_seconds IS NULL OR lease_deadline_unix_seconds <= ?2)
             ORDER BY lease_deadline_unix_seconds ASC, task_id ASC"
        ),
        None => format!(
            "{TASK_SELECT} WHERE state IN ('claimed', 'running', 'cancel_requested')
             AND (lease_deadline_unix_seconds IS NULL OR lease_deadline_unix_seconds <= ?1)
             ORDER BY lease_deadline_unix_seconds ASC, task_id ASC"
        ),
    };
    let mut statement = transaction.prepare(&sql)?;
    let mut rows = match target_client_id {
        Some(target_client_id) => {
            statement.query(params![target_client_id.to_string(), now_i64(now)?])?
        }
        None => statement.query([now_i64(now)?])?,
    };
    let mut tasks = Vec::new();
    while let Some(row) = rows.next()? {
        tasks.push(read_task(row)?);
    }
    Ok(tasks)
}

fn read_task(row: &rusqlite::Row<'_>) -> rusqlite::Result<RemoteUpdateTask> {
    let restart_json: Option<String> = row.get(12)?;
    let restart: Option<linklake_core::remote_update::RemoteUpdateRestartBinding> = restart_json
        .map(|value| parse_json(value, 12))
        .transpose()?;
    let result_json: Option<String> = row.get(13)?;
    let result: Option<linklake_core::remote_update::RemoteUpdateResult> =
        result_json.map(|value| parse_json(value, 13)).transpose()?;
    if let Some(result) = result.as_ref() {
        result.validate().map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                13,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?;
    }
    let task = RemoteUpdateTask {
        schema_version: REMOTE_UPDATE_CONTRACT_VERSION,
        task_id: parse_non_nil_uuid(row.get::<_, String>(0)?, 0)?,
        target_client_id: parse_non_nil_uuid(row.get::<_, String>(1)?, 1)?,
        action: parse_enum(row.get::<_, String>(2)?, 2)?,
        state: parse_enum(row.get::<_, String>(3)?, 3)?,
        stage: parse_enum(row.get::<_, String>(4)?, 4)?,
        recovery_state: parse_enum(row.get::<_, String>(5)?, 5)?,
        requested_by: row.get(6)?,
        idempotency_key: row.get(7)?,
        attempt: parse_u32(row.get::<_, i64>(8)?, 8)?,
        cancel_requested: row.get::<_, i64>(9)? != 0,
        lease_owner: row
            .get::<_, Option<String>>(10)?
            .map(|value| parse_non_nil_uuid(value, 10))
            .transpose()?,
        lease_deadline_unix_seconds: row
            .get::<_, Option<i64>>(11)?
            .map(|value| parse_u64(value, 11))
            .transpose()?,
        restart,
        result,
        error_code: row
            .get::<_, Option<String>>(14)?
            .map(|value| parse_enum(value, 14))
            .transpose()?,
        created_unix_seconds: parse_u64(row.get(15)?, 15)?,
        updated_unix_seconds: parse_u64(row.get(16)?, 16)?,
        completed_unix_seconds: row
            .get::<_, Option<i64>>(17)?
            .map(|value| parse_u64(value, 17))
            .transpose()?,
    };
    validate_loaded_task(&task).map_err(|message| {
        rusqlite::Error::FromSqlConversionFailure(
            3,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                message,
            )),
        )
    })?;
    Ok(task)
}

fn validate_loaded_task(task: &RemoteUpdateTask) -> Result<(), &'static str> {
    if task.attempt > MAX_CLAIM_ATTEMPTS {
        return Err("remote update task counters or timestamps are inconsistent");
    }
    task.validate()
        .map_err(|_| "remote update task state fields are inconsistent")
}

fn read_event(row: &rusqlite::Row<'_>) -> rusqlite::Result<RemoteUpdateTaskEvent> {
    Ok(RemoteUpdateTaskEvent {
        schema_version: REMOTE_UPDATE_CONTRACT_VERSION,
        event_id: parse_non_nil_uuid(row.get::<_, String>(0)?, 0)?,
        task_id: parse_non_nil_uuid(row.get::<_, String>(1)?, 1)?,
        sequence: parse_u64(row.get(2)?, 2)?,
        kind: parse_enum(row.get::<_, String>(3)?, 3)?,
        state: parse_enum(row.get::<_, String>(4)?, 4)?,
        stage: parse_enum(row.get::<_, String>(5)?, 5)?,
        recovery_state: parse_enum(row.get::<_, String>(6)?, 6)?,
        error_code: row
            .get::<_, Option<String>>(7)?
            .map(|value| parse_enum(value, 7))
            .transpose()?,
        created_unix_seconds: parse_u64(row.get(8)?, 8)?,
    })
}

fn append_event(
    transaction: &Transaction<'_>,
    task: &RemoteUpdateTask,
    kind: RemoteUpdateEventKind,
    now: u64,
) -> anyhow::Result<()> {
    let kind_text = enum_text(kind)?;
    let sampled_limit = match kind {
        RemoteUpdateEventKind::LeaseRenewed => Some(MAX_LEASE_EVENTS_PER_TASK),
        RemoteUpdateEventKind::IdempotentReplay => Some(MAX_REPLAY_EVENTS_PER_TASK),
        RemoteUpdateEventKind::RestartReconciled => Some(MAX_RESTART_EVENTS_PER_TASK),
        _ => None,
    };
    if let Some(limit) = sampled_limit {
        let recorded: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM update_task_events WHERE task_id = ?1 AND kind = ?2",
            params![task.task_id.to_string(), kind_text],
            |row| row.get(0),
        )?;
        if recorded >= limit {
            return Ok(());
        }
    }
    let total: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM update_task_events WHERE task_id = ?1",
        [task.task_id.to_string()],
        |row| row.get(0),
    )?;
    if total >= MAX_EVENTS_PER_TASK {
        return Err(domain_error(UpdateTaskError::CapacityExceeded));
    }
    let sequence: i64 = transaction.query_row(
        "SELECT COALESCE(MAX(sequence), 0) + 1 FROM update_task_events WHERE task_id = ?1",
        [task.task_id.to_string()],
        |row| row.get(0),
    )?;
    let affected = transaction.execute(
        "INSERT INTO update_task_events (
            event_id, task_id, sequence, kind, state, stage, recovery_state, error_code,
            created_unix_seconds
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            Uuid::new_v4().to_string(),
            task.task_id.to_string(),
            sequence,
            kind_text,
            enum_text(task.state)?,
            enum_text(task.stage)?,
            enum_text(task.recovery_state)?,
            task.error_code.map(enum_text).transpose()?,
            now_i64(now)?,
        ],
    )?;
    ensure_one_row(affected, "append remote update task event")?;
    Ok(())
}

fn reconcile_expired_leases(
    transaction: &Transaction<'_>,
    target_client_id: Option<Uuid>,
    now: u64,
) -> anyhow::Result<()> {
    let tasks = expired_leased_tasks(transaction, target_client_id, now)?;
    for task in tasks {
        reconcile_lost_lease(transaction, task, now)?;
    }
    Ok(())
}

fn reconcile_lost_lease(
    transaction: &Transaction<'_>,
    mut task: RemoteUpdateTask,
    now: u64,
) -> anyhow::Result<()> {
    let cancellation_is_known_safe =
        task.stage == RemoteUpdateStage::Claimed || task.action.safe_to_requeue_after_lease_loss();
    let event_kind = if task.cancel_requested && cancellation_is_known_safe {
        task.state = RemoteUpdateTaskState::Cancelled;
        task.stage = RemoteUpdateStage::Cancelled;
        task.recovery_state = RemoteUpdateRecoveryState::None;
        task.error_code = Some(RemoteUpdateErrorCode::Cancelled);
        task.completed_unix_seconds = Some(now);
        RemoteUpdateEventKind::Cancelled
    } else if task.action.safe_to_requeue_after_lease_loss() {
        task.state = RemoteUpdateTaskState::Queued;
        task.stage = RemoteUpdateStage::Queued;
        task.recovery_state = RemoteUpdateRecoveryState::Retryable;
        task.error_code = None;
        RemoteUpdateEventKind::LeaseExpiredRequeued
    } else {
        task.state = RemoteUpdateTaskState::Failed;
        task.stage = RemoteUpdateStage::Failed;
        task.recovery_state = RemoteUpdateRecoveryState::FailedClosed;
        task.error_code = Some(RemoteUpdateErrorCode::FailedClosed);
        task.completed_unix_seconds = Some(now);
        RemoteUpdateEventKind::LeaseExpiredFailedClosed
    };
    task.updated_unix_seconds = now;
    task.restart = None;
    clear_task_lease(&mut task);
    persist_task_after_report(transaction, &task, None)?;
    append_event(transaction, &task, event_kind, now)
}

fn replay_terminal_report(
    transaction: &Transaction<'_>,
    task: &RemoteUpdateTask,
    request: &RemoteUpdateReportRequest,
    now: u64,
) -> anyhow::Result<RemoteUpdateTask> {
    let stored = terminal_report_replay(transaction, task.task_id)?
        .ok_or_else(|| domain_error(UpdateTaskError::InvalidTransition))?;
    let presented_lease = lease_token_sha256(request.lease_token);
    if stored.worker_instance_id != request.worker_instance_id
        || !constant_time_equal(
            stored.lease_token_sha256.as_bytes(),
            presented_lease.as_bytes(),
        )
    {
        return Err(domain_error(UpdateTaskError::LeaseConflict));
    }
    let presented_report = worker_report_sha256(&request.report)?;
    if !constant_time_equal(stored.report_sha256.as_bytes(), presented_report.as_bytes()) {
        return Err(domain_error(UpdateTaskError::InvalidTransition));
    }
    append_event(
        transaction,
        task,
        RemoteUpdateEventKind::IdempotentReplay,
        now,
    )?;
    Ok(task.clone())
}

fn terminal_report_replay(
    transaction: &Transaction<'_>,
    task_id: Uuid,
) -> anyhow::Result<Option<TerminalReportReplay>> {
    let stored = transaction
        .query_row(
            "SELECT terminal_worker_instance_id, terminal_lease_token_sha256, terminal_report_sha256
             FROM update_tasks WHERE task_id = ?1",
            [task_id.to_string()],
            |row| {
                let worker = row.get::<_, Option<String>>(0)?;
                let lease = row.get::<_, Option<String>>(1)?;
                let report = row.get::<_, Option<String>>(2)?;
                match (worker, lease, report) {
                    (None, None, None) => Ok(None),
                    (Some(worker), Some(lease_token_sha256), Some(report_sha256)) => {
                        Ok(Some(TerminalReportReplay {
                            worker_instance_id: parse_non_nil_uuid(worker, 0)?,
                            lease_token_sha256,
                            report_sha256,
                        }))
                    }
                    _ => Err(rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "remote update terminal replay proof is incomplete",
                        )),
                    )),
                }
            },
        )
        .optional()?;
    Ok(stored.flatten())
}

fn authorize_lease(
    transaction: &Transaction<'_>,
    task: &RemoteUpdateTask,
    worker_instance_id: &Uuid,
    lease_token: Uuid,
    now: u64,
) -> anyhow::Result<()> {
    if !matches!(
        task.state,
        RemoteUpdateTaskState::Claimed
            | RemoteUpdateTaskState::Running
            | RemoteUpdateTaskState::CancelRequested
    ) || task.lease_owner != Some(*worker_instance_id)
    {
        return Err(domain_error(UpdateTaskError::LeaseConflict));
    }
    if task
        .lease_deadline_unix_seconds
        .is_none_or(|deadline| deadline <= now)
    {
        return Err(domain_error(UpdateTaskError::LeaseExpired));
    }
    let stored: Option<String> = transaction.query_row(
        "SELECT lease_token_sha256 FROM update_tasks WHERE task_id = ?1",
        [task.task_id.to_string()],
        |row| row.get(0),
    )?;
    let presented = lease_token_sha256(lease_token);
    if !stored
        .as_deref()
        .is_some_and(|stored| constant_time_equal(stored.as_bytes(), presented.as_bytes()))
    {
        return Err(domain_error(UpdateTaskError::LeaseConflict));
    }
    Ok(())
}

fn valid_renew_transition(
    current: RemoteUpdateStage,
    requested: RemoteUpdateStage,
    action: RemoteUpdateAction,
) -> bool {
    (current == RemoteUpdateStage::Claimed
        && (requested == RemoteUpdateStage::Claimed || requested == action.execution_stage()))
        || (current == action.execution_stage()
            && (requested == current
                || (requested == RemoteUpdateStage::AwaitingRestart
                    && action.changes_installation())))
        || (current == RemoteUpdateStage::AwaitingRestart && requested == current)
}

fn apply_worker_report(
    task: &mut RemoteUpdateTask,
    report: &RemoteUpdateWorkerReport,
    now: u64,
) -> anyhow::Result<RemoteUpdateEventKind> {
    match report {
        RemoteUpdateWorkerReport::Started { stage }
            if !task.cancel_requested
                && task.stage == RemoteUpdateStage::Claimed
                && *stage == task.action.execution_stage() =>
        {
            task.state = RemoteUpdateTaskState::Running;
            task.stage = *stage;
            task.updated_unix_seconds = now;
            Ok(RemoteUpdateEventKind::StageReported)
        }
        RemoteUpdateWorkerReport::AwaitingRestart { plan }
            if !task.cancel_requested
                && task.action.requires_restart()
                && task.stage == task.action.execution_stage() =>
        {
            let resume_deadline = now
                .checked_add(REMOTE_UPDATE_RESTART_RESUME_SECONDS)
                .ok_or_else(|| {
                    domain_error(UpdateTaskError::Storage(anyhow::anyhow!(
                        "remote update restart resume deadline overflowed"
                    )))
                })?;
            plan.validate(task.action)
                .map_err(|error| domain_error(UpdateTaskError::Contract(error)))?;
            task.state = RemoteUpdateTaskState::Running;
            task.stage = RemoteUpdateStage::AwaitingRestart;
            task.lease_deadline_unix_seconds = Some(resume_deadline);
            task.restart = Some(RemoteUpdateRestartBinding {
                operation_id: plan.operation_id,
                operation: plan.operation,
                from_version: plan.from_version.clone(),
                to_version: plan.to_version.clone(),
                prepared_unix_seconds: now,
                resume_deadline_unix_seconds: resume_deadline,
            });
            task.updated_unix_seconds = now;
            Ok(RemoteUpdateEventKind::StageReported)
        }
        RemoteUpdateWorkerReport::AwaitingRestart { plan }
            if task.action.requires_restart()
                && task.stage == RemoteUpdateStage::AwaitingRestart
                && task.restart.as_ref().is_some_and(|binding| {
                    binding.operation_id == plan.operation_id
                        && binding.operation == plan.operation
                        && binding.from_version == plan.from_version
                        && binding.to_version == plan.to_version
                }) =>
        {
            task.updated_unix_seconds = now;
            Ok(RemoteUpdateEventKind::RestartReconciled)
        }
        RemoteUpdateWorkerReport::Succeeded { result }
            if matches!(
                task.state,
                RemoteUpdateTaskState::Running | RemoteUpdateTaskState::CancelRequested
            ) && matches!(
                task.stage,
                RemoteUpdateStage::Checking
                    | RemoteUpdateStage::Downloading
                    | RemoteUpdateStage::Applying
                    | RemoteUpdateStage::Inspecting
                    | RemoteUpdateStage::Recovering
                    | RemoteUpdateStage::RollingBack
                    | RemoteUpdateStage::AwaitingRestart
            ) =>
        {
            task.state = RemoteUpdateTaskState::Succeeded;
            task.stage = RemoteUpdateStage::Completed;
            task.recovery_state = if task.action == RemoteUpdateAction::Recover {
                RemoteUpdateRecoveryState::Recovered
            } else {
                RemoteUpdateRecoveryState::None
            };
            task.result = Some(result.clone());
            task.error_code = None;
            task.updated_unix_seconds = now;
            task.completed_unix_seconds = Some(now);
            task.restart = None;
            clear_task_lease(task);
            Ok(RemoteUpdateEventKind::Succeeded)
        }
        RemoteUpdateWorkerReport::Failed {
            error_code,
            recovery_state,
        } if matches!(
            task.state,
            RemoteUpdateTaskState::Running | RemoteUpdateTaskState::CancelRequested
        ) =>
        {
            task.state = RemoteUpdateTaskState::Failed;
            task.stage = RemoteUpdateStage::Failed;
            task.recovery_state = *recovery_state;
            task.error_code = Some(*error_code);
            task.result = None;
            task.updated_unix_seconds = now;
            task.completed_unix_seconds = Some(now);
            task.restart = None;
            clear_task_lease(task);
            Ok(RemoteUpdateEventKind::Failed)
        }
        RemoteUpdateWorkerReport::Cancelled
            if task.cancel_requested
                && (task.stage == RemoteUpdateStage::Claimed
                    || task.action.safe_to_requeue_after_lease_loss()) =>
        {
            task.state = RemoteUpdateTaskState::Cancelled;
            task.stage = RemoteUpdateStage::Cancelled;
            task.recovery_state = RemoteUpdateRecoveryState::None;
            task.error_code = Some(RemoteUpdateErrorCode::Cancelled);
            task.result = None;
            task.updated_unix_seconds = now;
            task.completed_unix_seconds = Some(now);
            task.restart = None;
            clear_task_lease(task);
            Ok(RemoteUpdateEventKind::Cancelled)
        }
        _ => Err(domain_error(UpdateTaskError::InvalidTransition)),
    }
}

fn persist_task_after_report(
    transaction: &Transaction<'_>,
    task: &RemoteUpdateTask,
    terminal_replay: Option<&TerminalReportReplay>,
) -> anyhow::Result<()> {
    let affected = transaction.execute(
        "UPDATE update_tasks SET state = ?1, stage = ?2, recovery_state = ?3,
            cancel_requested = ?4, lease_owner = ?5, lease_token_sha256 = CASE WHEN ?5 IS NULL THEN NULL ELSE lease_token_sha256 END,
            lease_deadline_unix_seconds = ?6, restart_binding_json = ?7,
            terminal_worker_instance_id = ?8, terminal_lease_token_sha256 = ?9,
            terminal_report_sha256 = ?10, result_json = ?11, error_code = ?12,
            updated_unix_seconds = ?13, completed_unix_seconds = ?14
         WHERE task_id = ?15",
        params![
            enum_text(task.state)?,
            enum_text(task.stage)?,
            enum_text(task.recovery_state)?,
            i64::from(task.cancel_requested),
            task.lease_owner.map(|value| value.to_string()),
            task.lease_deadline_unix_seconds.map(now_i64).transpose()?,
            task.restart
                .as_ref()
                .map(serde_json::to_string)
                .transpose()?,
            terminal_replay.map(|replay| replay.worker_instance_id.to_string()),
            terminal_replay.map(|replay| replay.lease_token_sha256.as_str()),
            terminal_replay.map(|replay| replay.report_sha256.as_str()),
            task.result.as_ref().map(serde_json::to_string).transpose()?,
            task.error_code.map(enum_text).transpose()?,
            now_i64(task.updated_unix_seconds)?,
            task.completed_unix_seconds.map(now_i64).transpose()?,
            task.task_id.to_string(),
        ],
    )?;
    ensure_one_row(affected, "persist remote update task transition")?;
    Ok(())
}

fn clear_task_lease(task: &mut RemoteUpdateTask) {
    task.lease_owner = None;
    task.lease_deadline_unix_seconds = None;
    task.restart = None;
}

fn validate_requested_by(value: &str) -> Result<(), UpdateTaskError> {
    if value.is_empty()
        || value.len() > MAX_REQUESTED_BY_BYTES
        || value.chars().any(char::is_control)
    {
        Err(UpdateTaskError::InvalidRequester)
    } else {
        Ok(())
    }
}

fn request_fingerprint(request: &CreateRemoteUpdateTaskRequest, requested_by: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"linklake-remote-update-request-v1\0");
    digest.update(request.target_client_id.as_bytes());
    digest.update(enum_text(request.action).expect("closed update action must serialize"));
    digest.update([0]);
    digest.update(requested_by.as_bytes());
    hex_lower(&digest.finalize())
}

fn lease_token_sha256(token: Uuid) -> String {
    let mut digest = Sha256::new();
    digest.update(b"linklake-remote-update-lease-v1\0");
    digest.update(token.as_bytes());
    hex_lower(&digest.finalize())
}

fn worker_report_sha256(report: &RemoteUpdateWorkerReport) -> anyhow::Result<String> {
    let encoded = serde_json::to_vec(report)?;
    let mut digest = Sha256::new();
    digest.update(b"linklake-remote-update-terminal-report-v1\0");
    digest.update(encoded);
    Ok(hex_lower(&digest.finalize()))
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use fmt::Write as _;
        write!(output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn enum_text(value: impl Serialize) -> anyhow::Result<String> {
    let value = serde_json::to_value(value)?;
    value
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow::anyhow!("remote update enum did not serialize as a string"))
}

fn parse_enum<T: DeserializeOwned>(value: String, column: usize) -> rusqlite::Result<T> {
    serde_json::from_value(serde_json::Value::String(value)).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })
}

fn parse_json<T: DeserializeOwned>(value: String, column: usize) -> rusqlite::Result<T> {
    serde_json::from_str(&value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })
}

fn parse_uuid(value: String, column: usize) -> rusqlite::Result<Uuid> {
    Uuid::parse_str(&value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })
}

fn parse_non_nil_uuid(value: String, column: usize) -> rusqlite::Result<Uuid> {
    let value = parse_uuid(value, column)?;
    if value.is_nil() {
        Err(rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "remote update UUID is nil",
            )),
        ))
    } else {
        Ok(value)
    }
}

fn parse_u64(value: i64, column: usize) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })
}

fn parse_u32(value: i64, column: usize) -> rusqlite::Result<u32> {
    u32::try_from(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })
}

fn now_i64(value: u64) -> anyhow::Result<i64> {
    i64::try_from(value).map_err(Into::into)
}

fn checked_deadline(now: u64, lease_seconds: u32) -> anyhow::Result<u64> {
    now.checked_add(u64::from(lease_seconds))
        .ok_or_else(|| anyhow::anyhow!("remote update lease deadline overflowed"))
}

fn ensure_one_row(affected: usize, operation: &'static str) -> anyhow::Result<()> {
    anyhow::ensure!(
        affected == 1,
        "{operation} affected {affected} rows instead of exactly one"
    );
    Ok(())
}

fn domain_error(error: UpdateTaskError) -> anyhow::Error {
    anyhow::Error::new(error)
}

fn map_database_result<T>(result: anyhow::Result<T>) -> Result<T, UpdateTaskError> {
    match result {
        Ok(value) => Ok(value),
        Err(error) => match error.downcast::<UpdateTaskError>() {
            Ok(error) => Err(error),
            Err(error) => Err(UpdateTaskError::Storage(error)),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use linklake_core::remote_update::{
        RemoteLocalUpdateState, RemoteUpdateLeaseRenewRequest, RemoteUpdateReportRequest,
        RemoteUpdateResult, RemoteUpdateWorkerReport, REMOTE_UPDATE_DEFAULT_LEASE_SECONDS,
    };

    fn catalog_with_client(client_id: Uuid) -> UpdateTaskCatalog {
        let database = Database::memory().unwrap();
        database
            .with_connection(|connection| {
                connection
                    .execute_batch("CREATE TABLE clients(client_id TEXT PRIMARY KEY NOT NULL);")?;
                connection.execute(
                    "INSERT INTO clients(client_id) VALUES (?1)",
                    [client_id.to_string()],
                )?;
                Ok(())
            })
            .unwrap();
        UpdateTaskCatalog::open(&database).unwrap()
    }

    #[test]
    fn replay_column_migration_preserves_existing_event_foreign_keys() {
        let database = Database::memory().unwrap();
        let client_id = Uuid::new_v4();
        let task_id = Uuid::new_v4();
        let event_id = Uuid::new_v4();
        database
            .with_connection(|connection| {
                connection.execute_batch(
                    "CREATE TABLE clients(client_id TEXT PRIMARY KEY NOT NULL);
                     CREATE TABLE update_tasks (
                         task_id TEXT PRIMARY KEY NOT NULL,
                         target_client_id TEXT NOT NULL,
                         action TEXT NOT NULL,
                         state TEXT NOT NULL,
                         stage TEXT NOT NULL,
                         recovery_state TEXT NOT NULL,
                         requested_by TEXT NOT NULL,
                         idempotency_key TEXT NOT NULL,
                         request_fingerprint TEXT NOT NULL,
                         attempt INTEGER NOT NULL,
                         cancel_requested INTEGER NOT NULL,
                         lease_owner TEXT,
                         lease_token_sha256 TEXT,
                         lease_deadline_unix_seconds INTEGER,
                         restart_binding_json TEXT,
                         result_json TEXT,
                         error_code TEXT,
                         created_unix_seconds INTEGER NOT NULL,
                         updated_unix_seconds INTEGER NOT NULL,
                         completed_unix_seconds INTEGER,
                         FOREIGN KEY(target_client_id) REFERENCES clients(client_id) ON DELETE RESTRICT,
                         UNIQUE(requested_by, idempotency_key)
                     );
                     CREATE TABLE update_task_events (
                         event_id TEXT PRIMARY KEY NOT NULL,
                         task_id TEXT NOT NULL,
                         sequence INTEGER NOT NULL,
                         kind TEXT NOT NULL,
                         state TEXT NOT NULL,
                         stage TEXT NOT NULL,
                         recovery_state TEXT NOT NULL,
                         error_code TEXT,
                         created_unix_seconds INTEGER NOT NULL,
                         FOREIGN KEY(task_id) REFERENCES update_tasks(task_id) ON DELETE RESTRICT,
                         UNIQUE(task_id, sequence)
                     );",
                )?;
                connection.execute(
                    "INSERT INTO clients(client_id) VALUES (?1)",
                    [client_id.to_string()],
                )?;
                connection.execute(
                    "INSERT INTO update_tasks (
                        task_id, target_client_id, action, state, stage, recovery_state,
                        requested_by, idempotency_key, request_fingerprint, attempt,
                        cancel_requested, lease_owner, lease_token_sha256,
                        lease_deadline_unix_seconds, restart_binding_json, result_json,
                        error_code, created_unix_seconds, updated_unix_seconds,
                        completed_unix_seconds
                     ) VALUES (?1, ?2, 'check', 'queued', 'queued', 'none',
                        'admin', 'legacy-task-1', 'fingerprint', 0, 0, NULL, NULL,
                        NULL, NULL, NULL, NULL, 1, 1, NULL)",
                    params![task_id.to_string(), client_id.to_string()],
                )?;
                connection.execute(
                    "INSERT INTO update_task_events (
                        event_id, task_id, sequence, kind, state, stage,
                        recovery_state, error_code, created_unix_seconds
                     ) VALUES (?1, ?2, 1, 'created', 'queued', 'queued',
                        'none', NULL, 1)",
                    params![event_id.to_string(), task_id.to_string()],
                )?;
                Ok(())
            })
            .unwrap();

        UpdateTaskCatalog::open(&database).unwrap();
        database
            .with_connection(|connection| {
                let parent: String = connection.query_row(
                    "SELECT \"table\" FROM pragma_foreign_key_list('update_task_events')
                     WHERE \"from\" = 'task_id'",
                    [],
                    |row| row.get(0),
                )?;
                let event_count: i64 = connection.query_row(
                    "SELECT COUNT(*) FROM update_task_events WHERE task_id = ?1",
                    [task_id.to_string()],
                    |row| row.get(0),
                )?;
                let violations: i64 = connection.query_row(
                    "SELECT COUNT(*) FROM pragma_foreign_key_check",
                    [],
                    |row| row.get(0),
                )?;
                assert_eq!(parent, "update_tasks");
                assert_eq!(event_count, 1);
                assert_eq!(violations, 0);
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn idempotency_and_single_active_target_are_transactional() {
        let client_id = Uuid::new_v4();
        let catalog = catalog_with_client(client_id);
        let request = CreateRemoteUpdateTaskRequest {
            target_client_id: client_id,
            action: RemoteUpdateAction::Check,
            idempotency_key: "check-client-release-1".to_owned(),
            confirmation: "CHECK".to_owned(),
        };
        let first = catalog.create(&request, "admin", 10).unwrap();
        let replay = catalog.create(&request, "admin", 11).unwrap();
        assert_eq!(first.task_id, replay.task_id);
        let mut conflicting = request.clone();
        conflicting.idempotency_key = "check-client-release-2".to_owned();
        assert!(matches!(
            catalog.create(&conflicting, "admin", 12),
            Err(UpdateTaskError::TargetBusy)
        ));
    }

    #[test]
    fn lease_loss_requeues_safe_tasks_and_fails_apply_closed() {
        let client_id = Uuid::new_v4();
        let catalog = catalog_with_client(client_id);
        let create = |action, key: &str, confirmation: &str| CreateRemoteUpdateTaskRequest {
            target_client_id: client_id,
            action,
            idempotency_key: key.to_owned(),
            confirmation: confirmation.to_owned(),
        };
        let claim_request = RemoteUpdateClaimRequest {
            worker_instance_id: Uuid::new_v4(),
            requested_lease_seconds: REMOTE_UPDATE_DEFAULT_LEASE_SECONDS,
        };

        catalog
            .create(
                &create(RemoteUpdateAction::Check, "safe-task", "CHECK"),
                "admin",
                1,
            )
            .unwrap();
        let safe = catalog
            .claim(client_id, &claim_request, 2)
            .unwrap()
            .unwrap();
        catalog
            .reconcile_after_restart(safe.lease_deadline_unix_seconds + 1)
            .unwrap();
        assert_eq!(
            catalog
                .detail(safe.task.task_id, safe.lease_deadline_unix_seconds + 1)
                .unwrap()
                .task
                .state,
            RemoteUpdateTaskState::Queued
        );

        catalog
            .cancel(
                safe.task.task_id,
                &CancelRemoteUpdateTaskRequest {
                    confirmation: "CANCEL".to_owned(),
                },
                100,
            )
            .unwrap();
        catalog
            .create(
                &create(RemoteUpdateAction::Apply, "apply-task", "UPDATE"),
                "admin",
                101,
            )
            .unwrap();
        let apply = catalog
            .claim(client_id, &claim_request, 102)
            .unwrap()
            .unwrap();
        catalog
            .reconcile_after_restart(apply.lease_deadline_unix_seconds + 1)
            .unwrap();
        let failed = catalog
            .detail(apply.task.task_id, apply.lease_deadline_unix_seconds + 1)
            .unwrap()
            .task;
        assert_eq!(failed.state, RemoteUpdateTaskState::Failed);
        assert_eq!(
            failed.recovery_state,
            RemoteUpdateRecoveryState::FailedClosed
        );
    }

    #[test]
    fn worker_must_start_before_reporting_a_terminal_result() {
        let client_id = Uuid::new_v4();
        let catalog = catalog_with_client(client_id);
        let task = catalog
            .create(
                &CreateRemoteUpdateTaskRequest {
                    target_client_id: client_id,
                    action: RemoteUpdateAction::Status,
                    idempotency_key: "status-before-terminal".to_owned(),
                    confirmation: "STATUS".to_owned(),
                },
                "admin",
                10,
            )
            .unwrap();
        let worker = Uuid::new_v4();
        let claim = catalog
            .claim(
                client_id,
                &RemoteUpdateClaimRequest {
                    worker_instance_id: worker,
                    requested_lease_seconds: REMOTE_UPDATE_DEFAULT_LEASE_SECONDS,
                },
                11,
            )
            .unwrap()
            .unwrap();
        let report = RemoteUpdateReportRequest {
            worker_instance_id: worker,
            lease_token: claim.lease_token,
            report: RemoteUpdateWorkerReport::Cancelled,
        };
        assert!(matches!(
            catalog.report(client_id, task.task_id, &report, 12),
            Err(UpdateTaskError::InvalidTransition)
        ));
        let renew = RemoteUpdateLeaseRenewRequest {
            worker_instance_id: worker,
            lease_token: claim.lease_token,
            requested_lease_seconds: REMOTE_UPDATE_DEFAULT_LEASE_SECONDS,
            stage: RemoteUpdateStage::Completed,
        };
        assert!(matches!(
            catalog.renew(client_id, task.task_id, &renew, 12),
            Err(UpdateTaskError::Contract(_))
        ));
    }

    #[test]
    fn terminal_worker_reports_are_idempotent_only_for_the_original_lease_and_digest() {
        let client_id = Uuid::new_v4();
        let catalog = catalog_with_client(client_id);
        let worker = Uuid::new_v4();
        let task = catalog
            .create(
                &CreateRemoteUpdateTaskRequest {
                    target_client_id: client_id,
                    action: RemoteUpdateAction::Status,
                    idempotency_key: "terminal-report-replay-success".to_owned(),
                    confirmation: "STATUS".to_owned(),
                },
                "admin",
                1,
            )
            .unwrap();
        let claim = catalog
            .claim(
                client_id,
                &RemoteUpdateClaimRequest {
                    worker_instance_id: worker,
                    requested_lease_seconds: REMOTE_UPDATE_DEFAULT_LEASE_SECONDS,
                },
                2,
            )
            .unwrap()
            .unwrap();
        catalog
            .report(
                client_id,
                task.task_id,
                &RemoteUpdateReportRequest {
                    worker_instance_id: worker,
                    lease_token: claim.lease_token,
                    report: RemoteUpdateWorkerReport::Started {
                        stage: RemoteUpdateStage::Inspecting,
                    },
                },
                3,
            )
            .unwrap();
        let success = RemoteUpdateReportRequest {
            worker_instance_id: worker,
            lease_token: claim.lease_token,
            report: RemoteUpdateWorkerReport::Succeeded {
                result: RemoteUpdateResult::Status {
                    state: RemoteLocalUpdateState::Idle,
                    operation: None,
                    from_version: None,
                    to_version: None,
                    has_error: false,
                    updated_unix_seconds: 4,
                },
            },
        };
        let completed = catalog
            .report(client_id, task.task_id, &success, 4)
            .unwrap();
        assert_eq!(completed.state, RemoteUpdateTaskState::Succeeded);
        assert_eq!(
            catalog
                .report(client_id, task.task_id, &success, 5)
                .unwrap(),
            completed
        );

        let mut changed = success.clone();
        changed.report = RemoteUpdateWorkerReport::Succeeded {
            result: RemoteUpdateResult::Status {
                state: RemoteLocalUpdateState::Idle,
                operation: None,
                from_version: None,
                to_version: None,
                has_error: false,
                updated_unix_seconds: 6,
            },
        };
        assert!(matches!(
            catalog.report(client_id, task.task_id, &changed, 6),
            Err(UpdateTaskError::InvalidTransition)
        ));
        let mut wrong_lease = success.clone();
        wrong_lease.lease_token = Uuid::new_v4();
        assert!(matches!(
            catalog.report(client_id, task.task_id, &wrong_lease, 6),
            Err(UpdateTaskError::LeaseConflict)
        ));

        let failed_task = catalog
            .create(
                &CreateRemoteUpdateTaskRequest {
                    target_client_id: client_id,
                    action: RemoteUpdateAction::Check,
                    idempotency_key: "terminal-report-replay-failure".to_owned(),
                    confirmation: "CHECK".to_owned(),
                },
                "admin",
                7,
            )
            .unwrap();
        let failed_claim = catalog
            .claim(
                client_id,
                &RemoteUpdateClaimRequest {
                    worker_instance_id: worker,
                    requested_lease_seconds: REMOTE_UPDATE_DEFAULT_LEASE_SECONDS,
                },
                8,
            )
            .unwrap()
            .unwrap();
        catalog
            .report(
                client_id,
                failed_task.task_id,
                &RemoteUpdateReportRequest {
                    worker_instance_id: worker,
                    lease_token: failed_claim.lease_token,
                    report: RemoteUpdateWorkerReport::Started {
                        stage: RemoteUpdateStage::Checking,
                    },
                },
                9,
            )
            .unwrap();
        let failure = RemoteUpdateReportRequest {
            worker_instance_id: worker,
            lease_token: failed_claim.lease_token,
            report: RemoteUpdateWorkerReport::Failed {
                error_code: RemoteUpdateErrorCode::CheckFailed,
                recovery_state: RemoteUpdateRecoveryState::Retryable,
            },
        };
        let failed = catalog
            .report(client_id, failed_task.task_id, &failure, 10)
            .unwrap();
        assert_eq!(failed.state, RemoteUpdateTaskState::Failed);
        assert_eq!(
            catalog
                .report(client_id, failed_task.task_id, &failure, 11)
                .unwrap(),
            failed
        );
    }

    #[test]
    fn mutating_cancel_after_start_fails_closed_when_the_lease_is_lost() {
        let client_id = Uuid::new_v4();
        let catalog = catalog_with_client(client_id);
        let task = catalog
            .create(
                &CreateRemoteUpdateTaskRequest {
                    target_client_id: client_id,
                    action: RemoteUpdateAction::Apply,
                    idempotency_key: "apply-cancel-fail-closed".to_owned(),
                    confirmation: "UPDATE".to_owned(),
                },
                "admin",
                1,
            )
            .unwrap();
        let worker = Uuid::new_v4();
        let claim = catalog
            .claim(
                client_id,
                &RemoteUpdateClaimRequest {
                    worker_instance_id: worker,
                    requested_lease_seconds: REMOTE_UPDATE_DEFAULT_LEASE_SECONDS,
                },
                2,
            )
            .unwrap()
            .unwrap();
        catalog
            .report(
                client_id,
                task.task_id,
                &RemoteUpdateReportRequest {
                    worker_instance_id: worker,
                    lease_token: claim.lease_token,
                    report: RemoteUpdateWorkerReport::Started {
                        stage: RemoteUpdateStage::Applying,
                    },
                },
                3,
            )
            .unwrap();
        catalog
            .cancel(
                task.task_id,
                &CancelRemoteUpdateTaskRequest {
                    confirmation: "CANCEL".to_owned(),
                },
                4,
            )
            .unwrap();
        catalog
            .sweep(claim.lease_deadline_unix_seconds + 1)
            .unwrap();
        let task = catalog
            .detail(task.task_id, claim.lease_deadline_unix_seconds + 1)
            .unwrap()
            .task;
        assert_eq!(task.state, RemoteUpdateTaskState::Failed);
        assert_eq!(task.recovery_state, RemoteUpdateRecoveryState::FailedClosed);
        assert_eq!(task.error_code, Some(RemoteUpdateErrorCode::FailedClosed));
    }

    #[test]
    fn noisy_events_are_sampled_with_a_fixed_per_task_budget() {
        let client_id = Uuid::new_v4();
        let catalog = catalog_with_client(client_id);
        let request = CreateRemoteUpdateTaskRequest {
            target_client_id: client_id,
            action: RemoteUpdateAction::Check,
            idempotency_key: "bounded-replay-events".to_owned(),
            confirmation: "CHECK".to_owned(),
        };
        let task = catalog.create(&request, "admin", 1).unwrap();
        for now in 2..32 {
            let replay = catalog.create(&request, "admin", now).unwrap();
            assert_eq!(replay.task_id, task.task_id);
        }
        let detail = catalog.detail(task.task_id, 32).unwrap();
        assert_eq!(
            detail
                .events
                .iter()
                .filter(|event| event.kind == RemoteUpdateEventKind::IdempotentReplay)
                .count(),
            MAX_REPLAY_EVENTS_PER_TASK as usize
        );
        assert!(detail.events.len() <= MAX_EVENTS_PER_TASK as usize);
    }
}
