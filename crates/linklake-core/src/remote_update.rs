//! 远程更新控制面的稳定契约。
//!
//! 这里故意不提供命令、脚本、自由参数、仓库名或下载 URL 字段。服务端只能创建
//! 六种封闭动作，客户端也只能把动作映射到内置的安全更新器。

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

pub const REMOTE_UPDATE_CONTRACT_VERSION: u32 = 1;
pub const REMOTE_UPDATE_CANCEL_CONFIRMATION: &str = "CANCEL";
pub const REMOTE_UPDATE_MIN_LEASE_SECONDS: u32 = 15;
pub const REMOTE_UPDATE_MAX_LEASE_SECONDS: u32 = 300;
pub const REMOTE_UPDATE_DEFAULT_LEASE_SECONDS: u32 = 60;
pub const REMOTE_UPDATE_MAX_IDEMPOTENCY_KEY_BYTES: usize = 128;
const REMOTE_UPDATE_MIN_IDEMPOTENCY_KEY_BYTES: usize = 8;

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
    pub fn valid_for(self, action: RemoteUpdateAction) -> bool {
        matches!(
            self,
            Self::Queued
                | Self::Claimed
                | Self::AwaitingRestart
                | Self::Completed
                | Self::Failed
                | Self::Cancelled
        ) || self == action.execution_stage()
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
    Scheduled {
        operation_id: Uuid,
        operation: RemoteLocalUpdateOperation,
        from_version: String,
        to_version: String,
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
                    Self::Scheduled {
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
                    Self::Scheduled {
                        operation: RemoteLocalUpdateOperation::Rollback,
                        ..
                    },
                    RemoteUpdateAction::Rollback
                )
        )
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
    pub result: Option<RemoteUpdateResult>,
    pub error_code: Option<RemoteUpdateErrorCode>,
    pub created_unix_seconds: u64,
    pub updated_unix_seconds: u64,
    pub completed_unix_seconds: Option<u64>,
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

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RemoteUpdateTaskDetail {
    pub task: RemoteUpdateTask,
    pub events: Vec<RemoteUpdateTaskEvent>,
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
        validate_lease_seconds(self.requested_lease_seconds)?;
        if !self.stage.valid_for(action) {
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

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RemoteUpdateWorkerReport {
    Started {
        stage: RemoteUpdateStage,
    },
    AwaitingRestart,
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
            Self::AwaitingRestart if action.changes_installation() => Ok(()),
            Self::AwaitingRestart => Err(RemoteUpdateContractError::InvalidTransition),
            Self::Succeeded { result } if result.matches_action(action) => Ok(()),
            Self::Succeeded { .. } => Err(RemoteUpdateContractError::ResultActionMismatch),
            Self::Failed {
                recovery_state: RemoteUpdateRecoveryState::Recovered,
                ..
            } => Err(RemoteUpdateContractError::InvalidRecoveryState),
            Self::Failed { .. } | Self::Cancelled => Ok(()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RemoteUpdateReportRequest {
    pub worker_instance_id: Uuid,
    pub lease_token: Uuid,
    pub report: RemoteUpdateWorkerReport,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RemoteUpdateReportResponse {
    pub task: RemoteUpdateTask,
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
            target_client_id: Uuid::nil(),
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
}
