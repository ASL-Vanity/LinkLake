//! 管理员远程更新任务 API。
//!
//! 这些处理器只接受交互式管理员 Cookie 会话。创建与取消继续复用服务端更新的
//! same-origin、CSRF 和精确确认词边界；Bearer/API Token 即使拥有管理员 scope
//! 也不能调用。

use crate::{
    record_audit, require_interactive_server_update_administrator,
    require_interactive_update_administrator, unix_seconds, AppState, CodedApiError,
    ManagementRequestHost, ServerUpdateOperation,
};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use linklake_core::remote_update::{
    CancelRemoteUpdateTaskRequest, CreateRemoteUpdateTaskRequest, RemoteUpdateAction,
    RemoteUpdateContractError, RemoteUpdateTask, RemoteUpdateTaskDetail, RemoteUpdateTaskList,
};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

use crate::update_tasks::UpdateTaskError;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ListRemoteUpdateTasksQuery {
    target_client_id: Option<Uuid>,
    #[serde(default = "default_task_list_limit")]
    limit: usize,
}

fn default_task_list_limit() -> usize {
    100
}

pub(crate) async fn list_remote_update_tasks(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<ListRemoteUpdateTasksQuery>,
) -> Result<Json<RemoteUpdateTaskList>, CodedApiError> {
    require_interactive_server_update_administrator(
        &state,
        &headers,
        ServerUpdateOperation::RemoteList,
    )?;
    let tasks = state
        .update_tasks
        .list(query.target_client_id, query.limit, unix_seconds())
        .await
        .map_err(update_task_api_error)?;
    Ok(Json(RemoteUpdateTaskList { tasks }))
}

pub(crate) async fn create_remote_update_task(
    State(state): State<Arc<AppState>>,
    ManagementRequestHost(request_host): ManagementRequestHost,
    headers: HeaderMap,
    Json(request): Json<CreateRemoteUpdateTaskRequest>,
) -> Result<(StatusCode, Json<RemoteUpdateTask>), CodedApiError> {
    let principal = require_interactive_update_administrator(
        &state,
        &headers,
        &request_host,
        ServerUpdateOperation::RemoteCreate,
    )?;
    let now = unix_seconds();
    let task = state
        .update_tasks
        .create(&request, &principal.username, now)
        .await
        .map_err(update_task_api_error)?;
    record_audit(
        &state,
        "client.update.task.requested",
        &task.task_id.to_string(),
        &format!(
            "actor={}; target_client_id={}; action={}; channel=stable; signature_policy=production",
            principal.username,
            task.target_client_id,
            action_name(task.action)
        ),
    );
    let status = if task.created_unix_seconds == now {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(task)))
}

pub(crate) async fn get_remote_update_task(
    State(state): State<Arc<AppState>>,
    Path(task_id): Path<Uuid>,
    headers: HeaderMap,
) -> Result<Json<RemoteUpdateTaskDetail>, CodedApiError> {
    require_interactive_server_update_administrator(
        &state,
        &headers,
        ServerUpdateOperation::RemoteDetail,
    )?;
    let detail = state
        .update_tasks
        .detail(task_id, unix_seconds())
        .await
        .map_err(update_task_api_error)?;
    Ok(Json(detail))
}

pub(crate) async fn cancel_remote_update_task(
    State(state): State<Arc<AppState>>,
    ManagementRequestHost(request_host): ManagementRequestHost,
    Path(task_id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<CancelRemoteUpdateTaskRequest>,
) -> Result<Json<RemoteUpdateTask>, CodedApiError> {
    let principal = require_interactive_update_administrator(
        &state,
        &headers,
        &request_host,
        ServerUpdateOperation::RemoteCancel,
    )?;
    let task = state
        .update_tasks
        .cancel(task_id, &request, unix_seconds())
        .await
        .map_err(update_task_api_error)?;
    record_audit(
        &state,
        "client.update.task.cancel_requested",
        &task.task_id.to_string(),
        &format!(
            "actor={}; target_client_id={}; action={}; state={:?}",
            principal.username,
            task.target_client_id,
            action_name(task.action),
            task.state
        ),
    );
    Ok(Json(task))
}

fn action_name(action: RemoteUpdateAction) -> &'static str {
    match action {
        RemoteUpdateAction::Check => "check",
        RemoteUpdateAction::Download => "download",
        RemoteUpdateAction::Apply => "apply",
        RemoteUpdateAction::Status => "status",
        RemoteUpdateAction::Recover => "recover",
        RemoteUpdateAction::Rollback => "rollback",
    }
}

pub(crate) fn update_task_api_error(error: UpdateTaskError) -> CodedApiError {
    match error {
        UpdateTaskError::Contract(RemoteUpdateContractError::ConfirmationMismatch) => {
            CodedApiError(
                StatusCode::BAD_REQUEST,
                "remote_update_confirmation_required",
                "the exact remote update confirmation phrase is required",
            )
        }
        UpdateTaskError::Contract(_) => CodedApiError(
            StatusCode::BAD_REQUEST,
            "remote_update_invalid_request",
            "the remote update request is invalid",
        ),
        UpdateTaskError::TargetNotFound => CodedApiError(
            StatusCode::NOT_FOUND,
            "remote_update_target_not_found",
            "the remote update target was not found",
        ),
        UpdateTaskError::TaskNotFound => CodedApiError(
            StatusCode::NOT_FOUND,
            "remote_update_task_not_found",
            "the remote update task was not found",
        ),
        UpdateTaskError::TargetBusy => CodedApiError(
            StatusCode::CONFLICT,
            "remote_update_target_busy",
            "the target already has an active remote update task",
        ),
        UpdateTaskError::IdempotencyConflict => CodedApiError(
            StatusCode::CONFLICT,
            "remote_update_idempotency_conflict",
            "the idempotency key belongs to a different remote update request",
        ),
        UpdateTaskError::LeaseConflict => CodedApiError(
            StatusCode::CONFLICT,
            "remote_update_lease_conflict",
            "the remote update task lease conflicts with another worker",
        ),
        UpdateTaskError::LeaseExpired => CodedApiError(
            StatusCode::CONFLICT,
            "remote_update_lease_expired",
            "the remote update task lease expired",
        ),
        UpdateTaskError::InvalidTransition => CodedApiError(
            StatusCode::CONFLICT,
            "remote_update_invalid_transition",
            "the remote update task transition is invalid",
        ),
        UpdateTaskError::CapacityExceeded => CodedApiError(
            StatusCode::INSUFFICIENT_STORAGE,
            "remote_update_capacity_exceeded",
            "the bounded remote update task retention capacity was reached",
        ),
        UpdateTaskError::InvalidRequester => CodedApiError(
            StatusCode::INTERNAL_SERVER_ERROR,
            "remote_update_requester_invalid",
            "the authenticated requester cannot be persisted safely",
        ),
        UpdateTaskError::NotLeader => CodedApiError(
            StatusCode::SERVICE_UNAVAILABLE,
            "remote_update_not_leader",
            "the active HA leader must handle this remote update operation",
        ),
        UpdateTaskError::Storage(error) => {
            tracing::error!(%error, "Remote update task storage failed");
            CodedApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "remote_update_storage_failed",
                "the remote update task could not be persisted",
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confirmation_errors_have_a_stable_public_code() {
        let error = update_task_api_error(UpdateTaskError::Contract(
            RemoteUpdateContractError::ConfirmationMismatch,
        ));
        assert_eq!(error.1, "remote_update_confirmation_required");
    }
}
