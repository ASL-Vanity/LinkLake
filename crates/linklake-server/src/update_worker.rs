//! 客户端主动拉取远程更新任务的 API。
//!
//! 服务端不会连接客户端，也不会把任意命令推给客户端。worker 必须使用自身的
//! client bearer token 主动 claim，并持续续租和上报封闭阶段。

use crate::{client_registry::Authentication, unix_seconds, AppState, CodedApiError};
use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    Json,
};
use linklake_core::remote_update::{
    RemoteUpdateClaimRequest, RemoteUpdateClaimResponse, RemoteUpdateLeaseRenewRequest,
    RemoteUpdateLeaseRenewResponse, RemoteUpdateReconcileRequest, RemoteUpdateReconcileResponse,
    RemoteUpdateReportRequest, RemoteUpdateReportResponse,
};
use std::sync::{atomic::Ordering, Arc};
use std::time::Duration;
use tokio::time::{interval, MissedTickBehavior};
use uuid::Uuid;

use crate::update_api::update_task_api_error;

pub(crate) fn is_remote_update_worker_path(path: &str) -> bool {
    let parts = path.split('/').collect::<Vec<_>>();
    match parts.as_slice() {
        ["", "api", "v1", "clients", client_id, "update-tasks", "claim"] => non_nil_uuid(client_id),
        ["", "api", "v1", "clients", client_id, "update-tasks", task_id, operation]
            if matches!(*operation, "renew" | "reconcile" | "report") =>
        {
            non_nil_uuid(client_id) && non_nil_uuid(task_id)
        }
        _ => false,
    }
}

fn non_nil_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|value| !value.is_nil())
}

pub(crate) fn spawn_update_task_sweeper(state: Arc<AppState>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(30));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            if !state.update_tasks.is_maintenance_leader() {
                continue;
            }
            let result = state.update_tasks.sweep(unix_seconds()).await;
            if let Err(error) = result {
                tracing::error!(%error, "Remote update task lease sweep failed");
            }
        }
    })
}

pub(crate) async fn claim_remote_update_task(
    State(state): State<Arc<AppState>>,
    Path(client_id): Path<Uuid>,
    headers: HeaderMap,
    Json(request): Json<RemoteUpdateClaimRequest>,
) -> Result<Json<RemoteUpdateClaimResponse>, CodedApiError> {
    authenticate_worker(&state, client_id, &headers)?;
    let claim = state
        .update_tasks
        .claim(client_id, &request, unix_seconds())
        .await
        .map_err(update_task_api_error)?;
    Ok(Json(RemoteUpdateClaimResponse { claim }))
}

pub(crate) async fn renew_remote_update_task(
    State(state): State<Arc<AppState>>,
    Path((client_id, task_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(request): Json<RemoteUpdateLeaseRenewRequest>,
) -> Result<Json<RemoteUpdateLeaseRenewResponse>, CodedApiError> {
    authenticate_worker(&state, client_id, &headers)?;
    let response = state
        .update_tasks
        .renew(client_id, task_id, &request, unix_seconds())
        .await
        .map_err(update_task_api_error)?;
    Ok(Json(response))
}

pub(crate) async fn report_remote_update_task(
    State(state): State<Arc<AppState>>,
    Path((client_id, task_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(request): Json<RemoteUpdateReportRequest>,
) -> Result<Json<RemoteUpdateReportResponse>, CodedApiError> {
    authenticate_worker(&state, client_id, &headers)?;
    let task = state
        .update_tasks
        .report(client_id, task_id, &request, unix_seconds())
        .await
        .map_err(update_task_api_error)?;
    Ok(Json(RemoteUpdateReportResponse { task }))
}

pub(crate) async fn reconcile_remote_update_task(
    State(state): State<Arc<AppState>>,
    Path((client_id, task_id)): Path<(Uuid, Uuid)>,
    headers: HeaderMap,
    Json(request): Json<RemoteUpdateReconcileRequest>,
) -> Result<Json<RemoteUpdateReconcileResponse>, CodedApiError> {
    authenticate_worker(&state, client_id, &headers)?;
    let response = state
        .update_tasks
        .lock()
        .expect("remote update task catalog lock poisoned")
        .reconcile(client_id, task_id, &request, unix_seconds())
        .map_err(update_task_api_error)?;
    Ok(Json(response))
}

fn authenticate_worker(
    state: &AppState,
    client_id: Uuid,
    headers: &HeaderMap,
) -> Result<(), CodedApiError> {
    let token = strict_bearer_token(headers).ok_or(CodedApiError(
        StatusCode::UNAUTHORIZED,
        "remote_update_client_authentication_required",
        "a single valid client bearer token is required",
    ))?;
    let authentication = state
        .clients
        .lock()
        .expect("client registry lock poisoned")
        .authenticate_and_touch(client_id, token)
        .map_err(|error| {
            tracing::error!(%error, "Remote update worker authentication failed");
            CodedApiError(
                StatusCode::INTERNAL_SERVER_ERROR,
                "remote_update_client_authentication_failed",
                "the client identity could not be verified",
            )
        })?;
    match authentication {
        Authentication::Authenticated => Ok(()),
        Authentication::UnknownClient => {
            record_worker_authentication_failure(state);
            Err(CodedApiError(
                StatusCode::NOT_FOUND,
                "remote_update_target_not_found",
                "the remote update target was not found",
            ))
        }
        Authentication::DisabledClient => {
            record_worker_authentication_failure(state);
            Err(CodedApiError(
                StatusCode::FORBIDDEN,
                "remote_update_client_disabled",
                "the client identity is disabled",
            ))
        }
        Authentication::InvalidToken => {
            record_worker_authentication_failure(state);
            Err(CodedApiError(
                StatusCode::UNAUTHORIZED,
                "remote_update_client_authentication_invalid",
                "the client bearer token is invalid",
            ))
        }
    }
}

fn strict_bearer_token(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    let token = value.to_str().ok()?.strip_prefix("Bearer ")?;
    (!token.is_empty()).then_some(token)
}

fn record_worker_authentication_failure(state: &AppState) {
    state
        .metrics
        .authentication_failures_total
        .fetch_add(1, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn worker_authentication_rejects_duplicate_authorization_headers() {
        let mut headers = HeaderMap::new();
        headers.append(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer first"),
        );
        headers.append(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer second"),
        );
        assert!(strict_bearer_token(&headers).is_none());
    }

    #[test]
    fn only_fixed_worker_routes_bypass_management_authentication() {
        let client_id = Uuid::new_v4();
        let task_id = Uuid::new_v4();
        assert!(is_remote_update_worker_path(&format!(
            "/api/v1/clients/{client_id}/update-tasks/claim"
        )));
        assert!(is_remote_update_worker_path(&format!(
            "/api/v1/clients/{client_id}/update-tasks/{task_id}/renew"
        )));
        assert!(is_remote_update_worker_path(&format!(
            "/api/v1/clients/{client_id}/update-tasks/{task_id}/reconcile"
        )));
        assert!(!is_remote_update_worker_path(&format!(
            "/api/v1/clients/{client_id}/update-tasks/{task_id}/command"
        )));
    }
}
