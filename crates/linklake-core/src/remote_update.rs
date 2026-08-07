//! 远程更新控制面的稳定契约。
//!
//! 这里故意不提供命令、脚本、自由参数、仓库名或下载 URL 字段。服务端只能创建
//! 六种封闭动作，客户端也只能把动作映射到内置的安全更新器。

use semver::Version;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

pub const REMOTE_UPDATE_CONTRACT_VERSION: u32 = 1;
pub const REMOTE_UPDATE_CANCEL_CONFIRMATION: &str = "CANCEL";
pub const REMOTE_UPDATE_MIN_LEASE_SECONDS: u32 = 15;
pub const REMOTE_UPDATE_MAX_LEASE_SECONDS: u32 = 300;
pub const REMOTE_UPDATE_DEFAULT_LEASE_SECONDS: u32 = 60;
/// 安装替换进入等待重启后，服务端只在这个固定窗口内保留原租约身份。
/// 该窗口不能由客户端请求延长，过期后必须关闭任务，避免未知安装结果被重试。
pub const REMOTE_UPDATE_RESTART_RESUME_SECONDS: u64 = 30 * 60;
pub const REMOTE_UPDATE_MAX_CLAIM_ATTEMPTS: u32 = 16;
pub const REMOTE_UPDATE_MAX_EVENTS_PER_TASK: usize = 128;
pub const REMOTE_UPDATE_MAX_IDEMPOTENCY_KEY_BYTES: usize = 128;
const REMOTE_UPDATE_MIN_IDEMPOTENCY_KEY_BYTES: usize = 8;
const REMOTE_UPDATE_MAX_REQUESTED_BY_BYTES: usize = 128;
const REMOTE_UPDATE_MAX_VERSION_BYTES: usize = 64;
const REMOTE_UPDATE_MAX_KEY_ID_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum RemoteUpdateAction {
    Check,
    Download,
    Apply,
    Status,
    Recover,
    Rollback,
}

impl RemoteUpdateAction {
    pub const fn confirmation_phrase(self) -> &'static str {
        match self {
            Self::Check => "CHECK",
            Self::Download => "DOWNLOAD",
            Self::Apply => "UPDATE",
            Self::Status => "STATUS",
            Self::Recover => "RECOVER",
            Self::Rollback => "ROLLBACK",
        }
    }

    pub const fn execution_stage(self) -> RemoteUpdateStage {
        match self {
            Self::Check => RemoteUpdateStage::Checking,
            Self::Download => RemoteUpdateStage::Downloading,
            Self::Apply => RemoteUpdateStage::Applying,
            Self::Status => RemoteUpdateStage::Inspecting,
            Self::Recover => RemoteUpdateStage::Recovering,
            Self::Rollback => RemoteUpdateStage::RollingBack,
        }
    }

    /// 租约丢失后只有只读动作和可重复下载动作可以自动重新排队。
    pub const fn safe_to_requeue_after_lease_loss(self) -> bool {
        matches!(self, Self::Check | Self::Download | Self::Status)
    }

    pub const fn changes_installation(self) -> bool {
        matches!(self, Self::Apply | Self::Recover | Self::Rollback)
    }

    pub const fn requires_restart(self) -> bool {
        matches!(self, Self::Apply | Self::Rollback)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum RemoteUpdateTaskState {
    Queued,
    Claimed,
    Running,
    CancelRequested,
    Succeeded,
    Failed,
    Cancelled,
}

impl RemoteUpdateTaskState {
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Cancelled)
    }

    pub const fn is_active(self) -> bool {
        !self.is_terminal()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum RemoteUpdateStage {
    Queued,
    Claimed,
    Checking,
    Downloading,
    Applying,
    Inspecting,
    Recovering,
    RollingBack,
    AwaitingRestart,
    Completed,
    Failed,
    Cancelled,
}

impl RemoteUpdateStage {
    pub fn valid_for_active_lease(self, action: RemoteUpdateAction) -> bool {
        self == Self::Claimed
            || self == action.execution_stage()
            || (self == Self::AwaitingRestart && action.requires_restart())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum RemoteUpdateRecoveryState {
    None,
    Retryable,
    StatusRequired,
    RollbackRequired,
    Recovered,
    FailedClosed,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum RemoteUpdateEventKind {
    Created,
    IdempotentReplay,
    Claimed,
    LeaseRenewed,
    StageReported,
    CancelRequested,
    Cancelled,
    Succeeded,
    Failed,
    LeaseExpiredRequeued,
    LeaseExpiredFailedClosed,
    RestartReconciled,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, Hash, Error)]
#[serde(rename_all = "snake_case")]
pub enum RemoteUpdateErrorCode {
    #[error("remote updates are disabled on the client")]
    ClientDisabled,
    #[error("the remote update request is invalid")]
    InvalidRequest,
    #[error("the exact confirmation phrase is required")]
    ConfirmationRequired,
    #[error("the update task was not found")]
    TaskNotFound,
    #[error("the target already has an active update task")]
    TargetBusy,
    #[error("the idempotency key conflicts with another request")]
    IdempotencyConflict,
    #[error("the update task lease conflicts with another worker")]
    LeaseConflict,
    #[error("the update task lease expired")]
    LeaseExpired,
    #[error("the update task transition is invalid")]
    InvalidTransition,
    #[error("the update control channel is not trusted HTTPS")]
    InsecureControlChannel,
    #[error("another local update operation is active")]
    LocalUpdateBusy,
    #[error("the production signature verification failed")]
    SignatureVerificationFailed,
    #[error("the release is not in the stable channel")]
    StableChannelRequired,
    #[error("network downgrade is forbidden")]
    DowngradeForbidden,
    #[error("the downloaded update artifact was rejected")]
    ArtifactRejected,
    #[error("the update check failed")]
    CheckFailed,
    #[error("the update download failed")]
    DownloadFailed,
    #[error("the update apply operation failed")]
    ApplyFailed,
    #[error("the local update status could not be inspected")]
    StatusFailed,
    #[error("the interrupted update could not be recovered")]
    RecoveryFailed,
    #[error("the rollback operation failed")]
    RollbackFailed,
    #[error("the task was cancelled")]
    Cancelled,
    #[error("the server failed closed because completion is unknown")]
    FailedClosed,
    #[error("an internal update task error occurred")]
    Internal,
}

impl RemoteUpdateErrorCode {
    pub const fn as_code(self) -> &'static str {
        match self {
            Self::ClientDisabled => "remote_update_client_disabled",
            Self::InvalidRequest => "remote_update_invalid_request",
            Self::ConfirmationRequired => "remote_update_confirmation_required",
            Self::TaskNotFound => "remote_update_task_not_found",
            Self::TargetBusy => "remote_update_target_busy",
            Self::IdempotencyConflict => "remote_update_idempotency_conflict",
            Self::LeaseConflict => "remote_update_lease_conflict",
            Self::LeaseExpired => "remote_update_lease_expired",
            Self::InvalidTransition => "remote_update_invalid_transition",
            Self::InsecureControlChannel => "remote_update_insecure_control_channel",
            Self::LocalUpdateBusy => "remote_update_local_update_busy",
            Self::SignatureVerificationFailed => "remote_update_signature_verification_failed",
            Self::StableChannelRequired => "remote_update_stable_channel_required",
            Self::DowngradeForbidden => "remote_update_downgrade_forbidden",
            Self::ArtifactRejected => "remote_update_artifact_rejected",
            Self::CheckFailed => "remote_update_check_failed",
            Self::DownloadFailed => "remote_update_download_failed",
            Self::ApplyFailed => "remote_update_apply_failed",
            Self::StatusFailed => "remote_update_status_failed",
            Self::RecoveryFailed => "remote_update_recovery_failed",
            Self::RollbackFailed => "remote_update_rollback_failed",
            Self::Cancelled => "remote_update_cancelled",
            Self::FailedClosed => "remote_update_failed_closed",
            Self::Internal => "remote_update_internal",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RemoteLocalUpdateState {
    Idle,
    Scheduled,
    Installing,
    Succeeded,
    RolledBack,
    Failed,
    RecoveryRequired,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RemoteLocalUpdateOperation {
    Apply,
    Rollback,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RemoteUpdateResult {
    Check {
        current_version: String,
        latest_version: String,
        update_available: bool,
        signature_key_id: String,
    },
    Downloaded {
        version: String,
        archive_sha256: String,
        binary_sha256: String,
        signature_key_id: String,
    },
    Installed {
        operation_id: Uuid,
        operation: RemoteLocalUpdateOperation,
        from_version: String,
        to_version: String,
        installed_sha256: String,
        backup_sha256: String,
        verified_unix_seconds: u64,
    },
    Status {
        state: RemoteLocalUpdateState,
        operation: Option<RemoteLocalUpdateOperation>,
        from_version: Option<String>,
        to_version: Option<String>,
        has_error: bool,
        updated_unix_seconds: u64,
    },
}

impl RemoteUpdateResult {
    pub const fn matches_action(&self, action: RemoteUpdateAction) -> bool {
        matches!(
            (self, action),
            (Self::Check { .. }, RemoteUpdateAction::Check)
                | (Self::Downloaded { .. }, RemoteUpdateAction::Download)
                | (
                    Self::Installed {
                        operation: RemoteLocalUpdateOperation::Apply,
                        ..
                    },
                    RemoteUpdateAction::Apply
                )
                | (
                    Self::Status { .. },
                    RemoteUpdateAction::Status | RemoteUpdateAction::Recover
                )
                | (
                    Self::Installed {
                        operation: RemoteLocalUpdateOperation::Rollback,
                        ..
                    },
                    RemoteUpdateAction::Rollback
                )
        )
    }

    pub fn validate(&self) -> Result<(), RemoteUpdateContractError> {
        match self {
            Self::Check {
                current_version,
                latest_version,
                signature_key_id,
                ..
            } => {
                validate_version(current_version)?;
                validate_version(latest_version)?;
                validate_key_id(signature_key_id)
            }
            Self::Downloaded {
                version,
                archive_sha256,
                binary_sha256,
                signature_key_id,
            } => {
                validate_version(version)?;
                validate_sha256(archive_sha256)?;
                validate_sha256(binary_sha256)?;
                validate_key_id(signature_key_id)
            }
            Self::Installed {
                operation_id,
                from_version,
                to_version,
                installed_sha256,
                backup_sha256,
                verified_unix_seconds,
                ..
            } => {
                validate_non_nil_uuid(*operation_id)?;
                validate_version(from_version)?;
                validate_version(to_version)?;
                validate_sha256(installed_sha256)?;
                validate_sha256(backup_sha256)?;
                if *verified_unix_seconds == 0 {
                    return Err(RemoteUpdateContractError::InvalidTimestamp);
                }
                Ok(())
            }
            Self::Status {
                state,
                operation,
                from_version,
                to_version,
                has_error,
                updated_unix_seconds,
            } => {
                if let Some(version) = from_version {
                    validate_version(version)?;
                }
                if let Some(version) = to_version {
                    validate_version(version)?;
                }
                if *updated_unix_seconds == 0 {
                    return Err(RemoteUpdateContractError::InvalidTimestamp);
                }
                let fields_valid = match state {
                    RemoteLocalUpdateState::Idle => {
                        operation.is_none() && to_version.is_none() && !has_error
                    }
                    RemoteLocalUpdateState::Scheduled
                    | RemoteLocalUpdateState::Installing
                    | RemoteLocalUpdateState::Succeeded
                    | RemoteLocalUpdateState::RolledBack => {
                        operation.is_some()
                            && from_version.is_some()
                            && to_version.is_some()
                            && !has_error
                    }
                    RemoteLocalUpdateState::Failed | RemoteLocalUpdateState::RecoveryRequired => {
                        operation.is_some()
                            && from_version.is_some()
                            && to_version.is_some()
                            && *has_error
                    }
                };
                if !fields_valid {
                    return Err(RemoteUpdateContractError::InvalidLocalStatus);
                }
                Ok(())
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CreateRemoteUpdateTaskRequest {
    pub target_client_id: Uuid,
    pub action: RemoteUpdateAction,
    pub idempotency_key: String,
    pub confirmation: String,
}

impl CreateRemoteUpdateTaskRequest {
    pub fn validate(&self) -> Result<(), RemoteUpdateContractError> {
        validate_non_nil_uuid(self.target_client_id)?;
        validate_idempotency_key(&self.idempotency_key)?;
        if self.confirmation != self.action.confirmation_phrase() {
            return Err(RemoteUpdateContractError::ConfirmationMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CancelRemoteUpdateTaskRequest {
    pub confirmation: String,
}

impl CancelRemoteUpdateTaskRequest {
    pub fn validate(&self) -> Result<(), RemoteUpdateContractError> {
        if self.confirmation == REMOTE_UPDATE_CANCEL_CONFIRMATION {
            Ok(())
        } else {
            Err(RemoteUpdateContractError::ConfirmationMismatch)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RemoteUpdateTask {
    pub schema_version: u32,
    pub task_id: Uuid,
    pub target_client_id: Uuid,
    pub action: RemoteUpdateAction,
    pub state: RemoteUpdateTaskState,
    pub stage: RemoteUpdateStage,
    pub recovery_state: RemoteUpdateRecoveryState,
    pub requested_by: String,
    pub idempotency_key: String,
    pub attempt: u32,
    pub cancel_requested: bool,
    pub lease_owner: Option<Uuid>,
    pub lease_deadline_unix_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restart: Option<RemoteUpdateRestartBinding>,
    pub result: Option<RemoteUpdateResult>,
    pub error_code: Option<RemoteUpdateErrorCode>,
    pub created_unix_seconds: u64,
    pub updated_unix_seconds: u64,
    pub completed_unix_seconds: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RemoteUpdateRestartPlan {
    pub operation_id: Uuid,
    pub operation: RemoteLocalUpdateOperation,
    pub from_version: String,
    pub to_version: String,
}

impl RemoteUpdateRestartPlan {
    pub fn validate(&self, action: RemoteUpdateAction) -> Result<(), RemoteUpdateContractError> {
        validate_non_nil_uuid(self.operation_id)?;
        let expected = match action {
            RemoteUpdateAction::Apply => RemoteLocalUpdateOperation::Apply,
            RemoteUpdateAction::Rollback => RemoteLocalUpdateOperation::Rollback,
            _ => return Err(RemoteUpdateContractError::InvalidTransition),
        };
        if self.operation != expected {
            return Err(RemoteUpdateContractError::ResultActionMismatch);
        }
        validate_version(&self.from_version)?;
        validate_version(&self.to_version)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RemoteUpdateRestartBinding {
    pub operation_id: Uuid,
    pub operation: RemoteLocalUpdateOperation,
    pub from_version: String,
    pub to_version: String,
    pub prepared_unix_seconds: u64,
    pub resume_deadline_unix_seconds: u64,
}

impl RemoteUpdateRestartBinding {
    pub fn validate(
        &self,
        action: RemoteUpdateAction,
        lease_deadline_unix_seconds: Option<u64>,
        now: Option<u64>,
    ) -> Result<(), RemoteUpdateContractError> {
        let plan = RemoteUpdateRestartPlan {
            operation_id: self.operation_id,
            operation: self.operation,
            from_version: self.from_version.clone(),
            to_version: self.to_version.clone(),
        };
        plan.validate(action)?;
        if self.resume_deadline_unix_seconds == 0
            || self.prepared_unix_seconds == 0
            || self.resume_deadline_unix_seconds <= self.prepared_unix_seconds
            || self
                .resume_deadline_unix_seconds
                .saturating_sub(self.prepared_unix_seconds)
                > REMOTE_UPDATE_RESTART_RESUME_SECONDS
            || lease_deadline_unix_seconds != Some(self.resume_deadline_unix_seconds)
            || now.is_some_and(|value| self.resume_deadline_unix_seconds <= value)
        {
            return Err(RemoteUpdateContractError::InvalidTimestamp);
        }
        Ok(())
    }
}

impl RemoteUpdateTask {
    pub fn validate(&self) -> Result<(), RemoteUpdateContractError> {
        if self.schema_version != REMOTE_UPDATE_CONTRACT_VERSION {
            return Err(RemoteUpdateContractError::UnsupportedSchema);
        }
        validate_non_nil_uuid(self.task_id)?;
        validate_non_nil_uuid(self.target_client_id)?;
        validate_idempotency_key(&self.idempotency_key)?;
        if self.attempt > REMOTE_UPDATE_MAX_CLAIM_ATTEMPTS {
            return Err(RemoteUpdateContractError::InvalidTaskSnapshot);
        }
        if self.requested_by.is_empty()
            || self.requested_by.len() > REMOTE_UPDATE_MAX_REQUESTED_BY_BYTES
            || self.requested_by.chars().any(char::is_control)
        {
            return Err(RemoteUpdateContractError::InvalidRequester);
        }
        if self.created_unix_seconds == 0
            || self.updated_unix_seconds < self.created_unix_seconds
            || self
                .completed_unix_seconds
                .is_some_and(|completed| completed < self.updated_unix_seconds)
        {
            return Err(RemoteUpdateContractError::InvalidTimestamp);
        }
        let lease_present =
            self.lease_owner.is_some() && self.lease_deadline_unix_seconds.is_some();
        if let Some(owner) = self.lease_owner {
            validate_non_nil_uuid(owner)?;
        }
        if self.lease_deadline_unix_seconds == Some(0) {
            return Err(RemoteUpdateContractError::InvalidTimestamp);
        }
        let restart_required = self.stage == RemoteUpdateStage::AwaitingRestart;
        if let Some(restart) = self.restart.as_ref() {
            restart.validate(
                self.action,
                self.lease_deadline_unix_seconds,
                Some(self.updated_unix_seconds),
            )?;
        }
        if restart_required != self.restart.is_some() {
            return Err(RemoteUpdateContractError::InvalidTaskSnapshot);
        }
        let active_payload_empty = self.result.is_none()
            && self.error_code.is_none()
            && self.completed_unix_seconds.is_none();
        let valid = match self.state {
            RemoteUpdateTaskState::Queued => {
                self.stage == RemoteUpdateStage::Queued
                    && !lease_present
                    && self.restart.is_none()
                    && !self.cancel_requested
                    && active_payload_empty
            }
            RemoteUpdateTaskState::Claimed => {
                self.stage == RemoteUpdateStage::Claimed
                    && lease_present
                    && self.restart.is_none()
                    && !self.cancel_requested
                    && active_payload_empty
            }
            RemoteUpdateTaskState::Running => {
                (self.stage == self.action.execution_stage()
                    || (self.stage == RemoteUpdateStage::AwaitingRestart
                        && self.action.requires_restart()))
                    && lease_present
                    && (self.stage == RemoteUpdateStage::AwaitingRestart || self.restart.is_none())
                    && !self.cancel_requested
                    && active_payload_empty
            }
            RemoteUpdateTaskState::CancelRequested => {
                (self.stage == RemoteUpdateStage::Claimed
                    || self.stage == self.action.execution_stage()
                    || (self.stage == RemoteUpdateStage::AwaitingRestart
                        && self.action.requires_restart()))
                    && lease_present
                    && (self.stage == RemoteUpdateStage::AwaitingRestart || self.restart.is_none())
                    && self.cancel_requested
                    && active_payload_empty
            }
            RemoteUpdateTaskState::Succeeded => {
                self.stage == RemoteUpdateStage::Completed
                    && !lease_present
                    && self.restart.is_none()
                    && self.completed_unix_seconds.is_some()
                    && self.error_code.is_none()
                    && self.result.as_ref().is_some_and(|result| {
                        result.matches_action(self.action) && result.validate().is_ok()
                    })
                    && self.recovery_state
                        == if self.action == RemoteUpdateAction::Recover {
                            RemoteUpdateRecoveryState::Recovered
                        } else {
                            RemoteUpdateRecoveryState::None
                        }
            }
            RemoteUpdateTaskState::Failed => {
                self.stage == RemoteUpdateStage::Failed
                    && !lease_present
                    && self.restart.is_none()
                    && self.completed_unix_seconds.is_some()
                    && self.result.is_none()
                    && self.error_code.is_some_and(|error_code| {
                        RemoteUpdateWorkerReport::Failed {
                            error_code,
                            recovery_state: self.recovery_state,
                        }
                        .validate(self.action)
                        .is_ok()
                    })
            }
            RemoteUpdateTaskState::Cancelled => {
                self.stage == RemoteUpdateStage::Cancelled
                    && !lease_present
                    && self.restart.is_none()
                    && self.cancel_requested
                    && self.completed_unix_seconds.is_some()
                    && self.result.is_none()
                    && self.error_code == Some(RemoteUpdateErrorCode::Cancelled)
                    && self.recovery_state == RemoteUpdateRecoveryState::None
            }
        };
        if valid {
            Ok(())
        } else {
            Err(RemoteUpdateContractError::InvalidTaskSnapshot)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RemoteUpdateTaskEvent {
    pub schema_version: u32,
    pub event_id: Uuid,
    pub task_id: Uuid,
    pub sequence: u64,
    pub kind: RemoteUpdateEventKind,
    pub state: RemoteUpdateTaskState,
    pub stage: RemoteUpdateStage,
    pub recovery_state: RemoteUpdateRecoveryState,
    pub error_code: Option<RemoteUpdateErrorCode>,
    pub created_unix_seconds: u64,
}

impl RemoteUpdateTaskEvent {
    pub fn validate(&self, expected_task_id: Uuid) -> Result<(), RemoteUpdateContractError> {
        if self.schema_version != REMOTE_UPDATE_CONTRACT_VERSION {
            return Err(RemoteUpdateContractError::UnsupportedSchema);
        }
        validate_non_nil_uuid(self.event_id)?;
        validate_non_nil_uuid(self.task_id)?;
        if self.task_id != expected_task_id || self.sequence == 0 || self.created_unix_seconds == 0
        {
            return Err(RemoteUpdateContractError::InvalidTaskEvent);
        }
        let stage_valid = match self.state {
            RemoteUpdateTaskState::Queued => self.stage == RemoteUpdateStage::Queued,
            RemoteUpdateTaskState::Claimed => self.stage == RemoteUpdateStage::Claimed,
            RemoteUpdateTaskState::Running => matches!(
                self.stage,
                RemoteUpdateStage::Checking
                    | RemoteUpdateStage::Downloading
                    | RemoteUpdateStage::Applying
                    | RemoteUpdateStage::Inspecting
                    | RemoteUpdateStage::Recovering
                    | RemoteUpdateStage::RollingBack
                    | RemoteUpdateStage::AwaitingRestart
            ),
            RemoteUpdateTaskState::CancelRequested => matches!(
                self.stage,
                RemoteUpdateStage::Claimed
                    | RemoteUpdateStage::Checking
                    | RemoteUpdateStage::Downloading
                    | RemoteUpdateStage::Applying
                    | RemoteUpdateStage::Inspecting
                    | RemoteUpdateStage::Recovering
                    | RemoteUpdateStage::RollingBack
                    | RemoteUpdateStage::AwaitingRestart
            ),
            RemoteUpdateTaskState::Succeeded => self.stage == RemoteUpdateStage::Completed,
            RemoteUpdateTaskState::Failed => self.stage == RemoteUpdateStage::Failed,
            RemoteUpdateTaskState::Cancelled => self.stage == RemoteUpdateStage::Cancelled,
        };
        if stage_valid {
            Ok(())
        } else {
            Err(RemoteUpdateContractError::InvalidTaskEvent)
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RemoteUpdateTaskDetail {
    pub task: RemoteUpdateTask,
    pub events: Vec<RemoteUpdateTaskEvent>,
}

impl RemoteUpdateTaskDetail {
    pub fn validate(&self, expected_task_id: Uuid) -> Result<(), RemoteUpdateContractError> {
        self.task.validate()?;
        if self.task.task_id != expected_task_id
            || self.events.is_empty()
            || self.events.len() > REMOTE_UPDATE_MAX_EVENTS_PER_TASK
        {
            return Err(RemoteUpdateContractError::InvalidTaskEvent);
        }
        let mut previous_sequence = 0;
        for event in &self.events {
            event.validate(expected_task_id)?;
            if event.sequence <= previous_sequence {
                return Err(RemoteUpdateContractError::InvalidTaskEvent);
            }
            previous_sequence = event.sequence;
        }
        let last = self
            .events
            .last()
            .ok_or(RemoteUpdateContractError::InvalidTaskEvent)?;
        if last.state != self.task.state
            || last.stage != self.task.stage
            || last.recovery_state != self.task.recovery_state
            || last.error_code != self.task.error_code
        {
            return Err(RemoteUpdateContractError::InvalidTaskEvent);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RemoteUpdateTaskList {
    pub tasks: Vec<RemoteUpdateTask>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RemoteUpdateClaimRequest {
    pub worker_instance_id: Uuid,
    pub requested_lease_seconds: u32,
}

impl RemoteUpdateClaimRequest {
    pub fn validate(&self) -> Result<(), RemoteUpdateContractError> {
        validate_non_nil_uuid(self.worker_instance_id)?;
        validate_lease_seconds(self.requested_lease_seconds)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RemoteUpdateClaim {
    pub task: RemoteUpdateTask,
    pub lease_token: Uuid,
    pub lease_deadline_unix_seconds: u64,
}

impl RemoteUpdateClaim {
    pub fn validate(
        &self,
        expected_client_id: Uuid,
        expected_worker_instance_id: Uuid,
        now: u64,
    ) -> Result<(), RemoteUpdateContractError> {
        self.task.validate()?;
        validate_non_nil_uuid(self.lease_token)?;
        if self.task.target_client_id != expected_client_id
            || self.task.lease_owner != Some(expected_worker_instance_id)
            || self.task.state != RemoteUpdateTaskState::Claimed
            || self.task.stage != RemoteUpdateStage::Claimed
            || self.task.lease_deadline_unix_seconds != Some(self.lease_deadline_unix_seconds)
            || self.lease_deadline_unix_seconds <= now
        {
            return Err(RemoteUpdateContractError::InvalidClaim);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RemoteUpdateClaimResponse {
    pub claim: Option<RemoteUpdateClaim>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RemoteUpdateLeaseRenewRequest {
    pub worker_instance_id: Uuid,
    pub lease_token: Uuid,
    pub requested_lease_seconds: u32,
    pub stage: RemoteUpdateStage,
}

impl RemoteUpdateLeaseRenewRequest {
    pub fn validate(&self, action: RemoteUpdateAction) -> Result<(), RemoteUpdateContractError> {
        validate_non_nil_uuid(self.worker_instance_id)?;
        validate_non_nil_uuid(self.lease_token)?;
        validate_lease_seconds(self.requested_lease_seconds)?;
        if !self.stage.valid_for_active_lease(action) {
            return Err(RemoteUpdateContractError::InvalidStage);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RemoteUpdateLeaseRenewResponse {
    pub task_id: Uuid,
    pub lease_deadline_unix_seconds: u64,
    pub cancel_requested: bool,
}

impl RemoteUpdateLeaseRenewResponse {
    pub fn validate(
        &self,
        expected_task_id: Uuid,
        now: u64,
        maximum_deadline: Option<u64>,
    ) -> Result<(), RemoteUpdateContractError> {
        validate_non_nil_uuid(self.task_id)?;
        if self.task_id != expected_task_id
            || self.lease_deadline_unix_seconds <= now
            || maximum_deadline.is_some_and(|maximum| self.lease_deadline_unix_seconds > maximum)
        {
            return Err(RemoteUpdateContractError::InvalidClaim);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RemoteUpdateWorkerReport {
    Started {
        stage: RemoteUpdateStage,
    },
    AwaitingRestart {
        plan: RemoteUpdateRestartPlan,
    },
    Succeeded {
        result: RemoteUpdateResult,
    },
    Failed {
        error_code: RemoteUpdateErrorCode,
        recovery_state: RemoteUpdateRecoveryState,
    },
    Cancelled,
}

impl RemoteUpdateWorkerReport {
    pub fn validate(&self, action: RemoteUpdateAction) -> Result<(), RemoteUpdateContractError> {
        match self {
            Self::Started { stage } if *stage == action.execution_stage() => Ok(()),
            Self::Started { .. } => Err(RemoteUpdateContractError::InvalidStage),
            Self::AwaitingRestart { plan } if action.requires_restart() => plan.validate(action),
            Self::AwaitingRestart { .. } => Err(RemoteUpdateContractError::InvalidTransition),
            Self::Succeeded { result } if result.matches_action(action) => result.validate(),
            Self::Succeeded { .. } => Err(RemoteUpdateContractError::ResultActionMismatch),
            Self::Failed {
                error_code,
                recovery_state,
            } => validate_failure_report(action, *error_code, *recovery_state),
            Self::Cancelled => Ok(()),
        }
    }

    /// 结合服务端持久阶段验证取消语义。安装变更一旦进入执行阶段，就不能再把
    /// 未知完成状态报告为“已取消”；worker 必须上报成功或带恢复状态的失败。
    pub fn validate_for_task(
        &self,
        action: RemoteUpdateAction,
        current_stage: RemoteUpdateStage,
        cancel_requested: bool,
    ) -> Result<(), RemoteUpdateContractError> {
        self.validate(action)?;
        if matches!(self, Self::Cancelled)
            && (!cancel_requested
                || (current_stage != RemoteUpdateStage::Claimed
                    && !action.safe_to_requeue_after_lease_loss()))
        {
            return Err(RemoteUpdateContractError::InvalidTransition);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RemoteUpdateReportRequest {
    pub worker_instance_id: Uuid,
    pub lease_token: Uuid,
    pub report: RemoteUpdateWorkerReport,
}

impl RemoteUpdateReportRequest {
    pub fn validate(&self, action: RemoteUpdateAction) -> Result<(), RemoteUpdateContractError> {
        validate_non_nil_uuid(self.worker_instance_id)?;
        validate_non_nil_uuid(self.lease_token)?;
        self.report.validate(action)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RemoteUpdateReportResponse {
    pub task: RemoteUpdateTask,
}

impl RemoteUpdateReportResponse {
    pub fn validate(
        &self,
        expected_task_id: Uuid,
        expected_client_id: Uuid,
        expected_action: RemoteUpdateAction,
        expected_report: &RemoteUpdateWorkerReport,
    ) -> Result<(), RemoteUpdateContractError> {
        self.task.validate()?;
        validate_non_nil_uuid(expected_client_id)?;
        if self.task.task_id != expected_task_id
            || self.task.target_client_id != expected_client_id
            || self.task.action != expected_action
        {
            return Err(RemoteUpdateContractError::InvalidTaskSnapshot);
        }
        let response_matches = match expected_report {
            RemoteUpdateWorkerReport::Started { stage } => {
                self.task.state == RemoteUpdateTaskState::Running && self.task.stage == *stage
            }
            RemoteUpdateWorkerReport::AwaitingRestart { plan } => {
                matches!(
                    self.task.state,
                    RemoteUpdateTaskState::Running | RemoteUpdateTaskState::CancelRequested
                ) && self.task.stage == RemoteUpdateStage::AwaitingRestart
                    && self.task.restart.as_ref().is_some_and(|binding| {
                        binding.operation_id == plan.operation_id
                            && binding.operation == plan.operation
                            && binding.from_version == plan.from_version
                            && binding.to_version == plan.to_version
                    })
            }
            RemoteUpdateWorkerReport::Succeeded { result } => {
                self.task.state == RemoteUpdateTaskState::Succeeded
                    && self.task.result.as_ref() == Some(result)
            }
            RemoteUpdateWorkerReport::Failed {
                error_code,
                recovery_state,
            } => {
                self.task.state == RemoteUpdateTaskState::Failed
                    && self.task.error_code == Some(*error_code)
                    && self.task.recovery_state == *recovery_state
            }
            RemoteUpdateWorkerReport::Cancelled => {
                self.task.state == RemoteUpdateTaskState::Cancelled
            }
        };
        if !response_matches {
            return Err(RemoteUpdateContractError::InvalidTaskSnapshot);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum RemoteUpdateContractError {
    #[error("idempotency key length is invalid")]
    InvalidIdempotencyKeyLength,
    #[error("idempotency key contains an invalid character")]
    InvalidIdempotencyKeyCharacter,
    #[error("lease duration is outside the supported range")]
    InvalidLeaseDuration,
    #[error("the exact confirmation phrase does not match")]
    ConfirmationMismatch,
    #[error("the update stage does not match the action")]
    InvalidStage,
    #[error("the update result does not match the action")]
    ResultActionMismatch,
    #[error("the recovery state is invalid for this report")]
    InvalidRecoveryState,
    #[error("the update transition is invalid")]
    InvalidTransition,
    #[error("a required UUID is nil")]
    NilUuid,
    #[error("a reported version is not a bounded semantic version")]
    InvalidVersion,
    #[error("a reported signing key ID is invalid")]
    InvalidKeyId,
    #[error("a reported SHA-256 digest is invalid")]
    InvalidSha256,
    #[error("a reported timestamp is invalid")]
    InvalidTimestamp,
    #[error("the local update status fields are inconsistent")]
    InvalidLocalStatus,
    #[error("the remote update contract schema is unsupported")]
    UnsupportedSchema,
    #[error("the remote update requester is invalid")]
    InvalidRequester,
    #[error("the remote update task snapshot is inconsistent")]
    InvalidTaskSnapshot,
    #[error("the remote update claim is inconsistent")]
    InvalidClaim,
    #[error("the remote update task event stream is inconsistent")]
    InvalidTaskEvent,
}

pub fn validate_idempotency_key(value: &str) -> Result<(), RemoteUpdateContractError> {
    if !(REMOTE_UPDATE_MIN_IDEMPOTENCY_KEY_BYTES..=REMOTE_UPDATE_MAX_IDEMPOTENCY_KEY_BYTES)
        .contains(&value.len())
    {
        return Err(RemoteUpdateContractError::InvalidIdempotencyKeyLength);
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(RemoteUpdateContractError::InvalidIdempotencyKeyCharacter);
    }
    Ok(())
}

pub fn validate_lease_seconds(value: u32) -> Result<(), RemoteUpdateContractError> {
    if (REMOTE_UPDATE_MIN_LEASE_SECONDS..=REMOTE_UPDATE_MAX_LEASE_SECONDS).contains(&value) {
        Ok(())
    } else {
        Err(RemoteUpdateContractError::InvalidLeaseDuration)
    }
}

pub fn validate_non_nil_uuid(value: Uuid) -> Result<(), RemoteUpdateContractError> {
    if value.is_nil() {
        Err(RemoteUpdateContractError::NilUuid)
    } else {
        Ok(())
    }
}

fn validate_version(value: &str) -> Result<(), RemoteUpdateContractError> {
    if value.is_empty() || value.len() > REMOTE_UPDATE_MAX_VERSION_BYTES {
        return Err(RemoteUpdateContractError::InvalidVersion);
    }
    let normalized = value.strip_prefix('v').unwrap_or(value);
    Version::parse(normalized)
        .map(|_| ())
        .map_err(|_| RemoteUpdateContractError::InvalidVersion)
}

fn validate_key_id(value: &str) -> Result<(), RemoteUpdateContractError> {
    if value.is_empty()
        || value.len() > REMOTE_UPDATE_MAX_KEY_ID_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        Err(RemoteUpdateContractError::InvalidKeyId)
    } else {
        Ok(())
    }
}

fn validate_sha256(value: &str) -> Result<(), RemoteUpdateContractError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(RemoteUpdateContractError::InvalidSha256)
    }
}

fn validate_failure_report(
    action: RemoteUpdateAction,
    error_code: RemoteUpdateErrorCode,
    recovery_state: RemoteUpdateRecoveryState,
) -> Result<(), RemoteUpdateContractError> {
    if error_code == RemoteUpdateErrorCode::Cancelled
        || matches!(
            recovery_state,
            RemoteUpdateRecoveryState::None | RemoteUpdateRecoveryState::Recovered
        )
    {
        return Err(RemoteUpdateContractError::InvalidRecoveryState);
    }
    if error_code == RemoteUpdateErrorCode::FailedClosed
        && recovery_state != RemoteUpdateRecoveryState::FailedClosed
    {
        return Err(RemoteUpdateContractError::InvalidRecoveryState);
    }
    let valid = if action.changes_installation() {
        matches!(
            recovery_state,
            RemoteUpdateRecoveryState::StatusRequired
                | RemoteUpdateRecoveryState::RollbackRequired
                | RemoteUpdateRecoveryState::FailedClosed
        )
    } else {
        matches!(
            recovery_state,
            RemoteUpdateRecoveryState::Retryable | RemoteUpdateRecoveryState::FailedClosed
        )
    };
    if valid {
        Ok(())
    } else {
        Err(RemoteUpdateContractError::InvalidRecoveryState)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contract_has_no_command_script_argument_or_url_field() {
        let request = CreateRemoteUpdateTaskRequest {
            target_client_id: Uuid::nil(),
            action: RemoteUpdateAction::Apply,
            idempotency_key: "release-1.1.0-client-a".to_owned(),
            confirmation: "UPDATE".to_owned(),
        };
        let value = serde_json::to_value(request).unwrap();
        for forbidden in [
            "command",
            "script",
            "args",
            "arguments",
            "url",
            "repository",
        ] {
            assert!(value.get(forbidden).is_none());
        }
    }

    #[test]
    fn exact_confirmation_is_action_specific() {
        let mut request = CreateRemoteUpdateTaskRequest {
            target_client_id: Uuid::from_u128(1),
            action: RemoteUpdateAction::Rollback,
            idempotency_key: "rollback-client-a".to_owned(),
            confirmation: "ROLLBACK".to_owned(),
        };
        assert!(request.validate().is_ok());
        request.confirmation = "rollback".to_owned();
        assert_eq!(
            request.validate(),
            Err(RemoteUpdateContractError::ConfirmationMismatch)
        );
    }

    #[test]
    fn only_non_mutating_or_download_tasks_are_automatically_retryable() {
        for action in [
            RemoteUpdateAction::Check,
            RemoteUpdateAction::Download,
            RemoteUpdateAction::Status,
        ] {
            assert!(action.safe_to_requeue_after_lease_loss());
        }
        for action in [
            RemoteUpdateAction::Apply,
            RemoteUpdateAction::Recover,
            RemoteUpdateAction::Rollback,
        ] {
            assert!(!action.safe_to_requeue_after_lease_loss());
        }
    }

    #[test]
    fn active_lease_rejects_terminal_and_impossible_stages() {
        for stage in [
            RemoteUpdateStage::AwaitingRestart,
            RemoteUpdateStage::Completed,
            RemoteUpdateStage::Failed,
            RemoteUpdateStage::Cancelled,
        ] {
            assert!(!stage.valid_for_active_lease(RemoteUpdateAction::Check));
        }
        assert!(
            RemoteUpdateStage::AwaitingRestart.valid_for_active_lease(RemoteUpdateAction::Apply)
        );
    }

    #[test]
    fn request_identifiers_must_not_be_nil() {
        let claim = RemoteUpdateClaimRequest {
            worker_instance_id: Uuid::nil(),
            requested_lease_seconds: REMOTE_UPDATE_DEFAULT_LEASE_SECONDS,
        };
        assert_eq!(claim.validate(), Err(RemoteUpdateContractError::NilUuid));
    }

    #[test]
    fn worker_results_are_bounded_and_typed() {
        let invalid = RemoteUpdateResult::Downloaded {
            version: "not-semver".to_owned(),
            archive_sha256: "a".repeat(64),
            binary_sha256: "b".repeat(64),
            signature_key_id: "production-2026".to_owned(),
        };
        assert_eq!(
            invalid.validate(),
            Err(RemoteUpdateContractError::InvalidVersion)
        );
        let invalid_digest = RemoteUpdateResult::Downloaded {
            version: "1.1.0".to_owned(),
            archive_sha256: "A".repeat(64),
            binary_sha256: "b".repeat(64),
            signature_key_id: "production-2026".to_owned(),
        };
        assert_eq!(
            invalid_digest.validate(),
            Err(RemoteUpdateContractError::InvalidSha256)
        );
    }

    #[test]
    fn failed_reports_require_a_fail_closed_recovery_state() {
        let invalid = RemoteUpdateWorkerReport::Failed {
            error_code: RemoteUpdateErrorCode::ApplyFailed,
            recovery_state: RemoteUpdateRecoveryState::None,
        };
        assert_eq!(
            invalid.validate(RemoteUpdateAction::Apply),
            Err(RemoteUpdateContractError::InvalidRecoveryState)
        );
    }

    #[test]
    fn failed_local_status_requires_bound_versions_operation_and_error() {
        let valid = RemoteUpdateResult::Status {
            state: RemoteLocalUpdateState::Failed,
            operation: Some(RemoteLocalUpdateOperation::Apply),
            from_version: Some("1.0.0".to_owned()),
            to_version: Some("1.1.0".to_owned()),
            has_error: true,
            updated_unix_seconds: 1,
        };
        assert!(valid.validate().is_ok());
        let contradictory = RemoteUpdateResult::Status {
            state: RemoteLocalUpdateState::Failed,
            operation: Some(RemoteLocalUpdateOperation::Apply),
            from_version: Some("1.0.0".to_owned()),
            to_version: Some("1.1.0".to_owned()),
            has_error: false,
            updated_unix_seconds: 1,
        };
        assert_eq!(
            contradictory.validate(),
            Err(RemoteUpdateContractError::InvalidLocalStatus)
        );
    }

    #[test]
    fn mutating_task_cannot_claim_cancellation_after_execution_started() {
        let cancelled = RemoteUpdateWorkerReport::Cancelled;
        assert!(cancelled
            .validate_for_task(RemoteUpdateAction::Apply, RemoteUpdateStage::Claimed, true,)
            .is_ok());
        assert_eq!(
            cancelled.validate_for_task(
                RemoteUpdateAction::Apply,
                RemoteUpdateStage::Applying,
                true,
            ),
            Err(RemoteUpdateContractError::InvalidTransition)
        );
        assert!(cancelled
            .validate_for_task(
                RemoteUpdateAction::Download,
                RemoteUpdateStage::Downloading,
                true,
            )
            .is_ok());
    }
}
