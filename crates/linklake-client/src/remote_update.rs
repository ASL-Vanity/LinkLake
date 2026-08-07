//! 客户端主动拉取远程更新任务的 opt-in worker。
//!
//! worker 默认关闭；开启后只连接配置中的 HTTPS 管理源，并把六种封闭动作映射到
//! `linklake-update`。仓库、Stable 通道、Production Ed25519 和禁止降级均为编译期
//! 固定值，服务端任务无法覆盖。

use anyhow::Context;
use linklake_core::remote_update::{
    RemoteLocalUpdateOperation, RemoteLocalUpdateState, RemoteUpdateAction, RemoteUpdateClaim,
    RemoteUpdateClaimRequest, RemoteUpdateClaimResponse, RemoteUpdateErrorCode,
    RemoteUpdateLeaseRenewRequest, RemoteUpdateLeaseRenewResponse, RemoteUpdateRecoveryState,
    RemoteUpdateReportRequest, RemoteUpdateReportResponse, RemoteUpdateResult, RemoteUpdateStage,
    RemoteUpdateWorkerReport, REMOTE_UPDATE_DEFAULT_LEASE_SECONDS,
};
use linklake_update as updater;
use linklake_update::{SignaturePolicy, UpdateChannel, UpdateProduct};
use reqwest::{Method, StatusCode, Url};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{pin::pin, time::Duration};
use tokio::time::{interval, sleep, MissedTickBehavior};
use uuid::Uuid;

const UPDATE_REPOSITORY: &str = "ASL-Vanity/LinkLake";
const MIN_POLL_INTERVAL_SECONDS: u32 = 5;
const MAX_POLL_INTERVAL_SECONDS: u32 = 300;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_API_RESPONSE_BYTES: u64 = 256 * 1024;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RemoteUpdateWorkerConfig {
    #[serde(default)]
    pub(crate) enabled: bool,
    pub(crate) api_base_url: Option<String>,
    #[serde(default = "default_poll_interval_seconds")]
    pub(crate) poll_interval_seconds: u32,
    #[serde(default = "default_lease_seconds")]
    pub(crate) lease_seconds: u32,
}

impl Default for RemoteUpdateWorkerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            api_base_url: None,
            poll_interval_seconds: default_poll_interval_seconds(),
            lease_seconds: default_lease_seconds(),
        }
    }
}

fn default_poll_interval_seconds() -> u32 {
    30
}

fn default_lease_seconds() -> u32 {
    REMOTE_UPDATE_DEFAULT_LEASE_SECONDS
}

pub(crate) fn validate_config(config: &RemoteUpdateWorkerConfig) -> anyhow::Result<()> {
    if !config.enabled {
        return Ok(());
    }
    anyhow::ensure!(
        (MIN_POLL_INTERVAL_SECONDS..=MAX_POLL_INTERVAL_SECONDS)
            .contains(&config.poll_interval_seconds),
        "remote update poll interval must be between {MIN_POLL_INTERVAL_SECONDS} and {MAX_POLL_INTERVAL_SECONDS} seconds"
    );
    linklake_core::remote_update::validate_lease_seconds(config.lease_seconds)?;
    let base = config
        .api_base_url
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("remote update api_base_url is required when enabled"))?;
    validate_api_base_url(base)?;
    Ok(())
}

pub(crate) fn spawn(
    config: RemoteUpdateWorkerConfig,
    client_id: Uuid,
    client_token: String,
) -> anyhow::Result<Option<tokio::task::JoinHandle<()>>> {
    validate_config(&config)?;
    if !config.enabled {
        return Ok(None);
    }
    let worker = RemoteUpdateWorker::new(config, client_id, client_token)?;
    Ok(Some(tokio::spawn(async move {
        if let Err(error) = worker.run().await {
            tracing::error!(%error, "Remote update worker stopped");
        }
    })))
}

struct RemoteUpdateWorker {
    api: WorkerApi,
    worker_instance_id: Uuid,
    poll_interval: Duration,
    lease_seconds: u32,
}

impl RemoteUpdateWorker {
    fn new(
        config: RemoteUpdateWorkerConfig,
        client_id: Uuid,
        client_token: String,
    ) -> anyhow::Result<Self> {
        validate_config(&config)?;
        let base = validate_api_base_url(
            config
                .api_base_url
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("remote update api_base_url is missing"))?,
        )?;
        let client = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .https_only(true)
            .build()?;
        Ok(Self {
            api: WorkerApi {
                client,
                base,
                client_id,
                client_token,
            },
            worker_instance_id: Uuid::new_v4(),
            poll_interval: Duration::from_secs(u64::from(config.poll_interval_seconds)),
            lease_seconds: config.lease_seconds,
        })
    }

    async fn run(self) -> anyhow::Result<()> {
        tracing::info!(
            client_id = %self.api.client_id,
            "Remote update worker enabled with Stable/Production policy"
        );
        loop {
            match self.claim().await {
                Ok(Some(claim)) => {
                    if let Err(error) = self.execute_claim(claim).await {
                        tracing::error!(%error, "Remote update task execution failed");
                    }
                }
                Ok(None) => sleep(self.poll_interval).await,
                Err(error) => {
                    tracing::warn!(%error, "Remote update claim failed; retrying");
                    sleep(self.poll_interval).await;
                }
            }
        }
    }

    async fn claim(&self) -> anyhow::Result<Option<RemoteUpdateClaim>> {
        let request = RemoteUpdateClaimRequest {
            worker_instance_id: self.worker_instance_id,
            requested_lease_seconds: self.lease_seconds,
        };
        request.validate()?;
        Ok(self.api.claim(&request).await?.claim)
    }

    async fn execute_claim(&self, claim: RemoteUpdateClaim) -> anyhow::Result<()> {
        anyhow::ensure!(
            claim.task.target_client_id == self.api.client_id
                && claim.task.lease_owner == Some(self.worker_instance_id)
                && claim.task.stage == RemoteUpdateStage::Claimed,
            "server returned a remote update claim with an invalid target or lease owner"
        );
        let action = claim.task.action;
        let task_id = claim.task.task_id;
        let lease_token = claim.lease_token;
        let stage = action.execution_stage();
        self.report(
            task_id,
            lease_token,
            action,
            RemoteUpdateWorkerReport::Started { stage },
        )
        .await?;

        let operation = execute_action(action);
        let mut operation = pin!(operation);
        let renewal_period = Duration::from_secs(u64::from((self.lease_seconds / 3).max(5)));
        let mut renewal = interval(renewal_period);
        renewal.set_missed_tick_behavior(MissedTickBehavior::Delay);
        renewal.tick().await;
        let mut cancellation_deferred = false;

        let outcome = loop {
            tokio::select! {
                result = &mut operation => break result,
                _ = renewal.tick() => {
                    let renewed = self.renew(task_id, lease_token, action, stage).await?;
                    if renewed.cancel_requested {
                        if action.changes_installation() {
                            cancellation_deferred = true;
                        } else {
                            self.report(
                                task_id,
                                lease_token,
                                action,
                                RemoteUpdateWorkerReport::Cancelled,
                            ).await?;
                            return Ok(());
                        }
                    }
                }
            }
        };

        match outcome {
            Ok(outcome) => {
                if outcome.awaiting_restart && !cancellation_deferred {
                    self.report(
                        task_id,
                        lease_token,
                        action,
                        RemoteUpdateWorkerReport::AwaitingRestart,
                    )
                    .await?;
                }
                self.report(
                    task_id,
                    lease_token,
                    action,
                    RemoteUpdateWorkerReport::Succeeded {
                        result: outcome.result,
                    },
                )
                .await?;
            }
            Err(error) => {
                let error_code = classify_update_error(action, &error);
                tracing::error!(%error, ?action, "Local secure update operation failed");
                self.report(
                    task_id,
                    lease_token,
                    action,
                    RemoteUpdateWorkerReport::Failed {
                        error_code,
                        recovery_state: failure_recovery_state(action),
                    },
                )
                .await?;
            }
        }
        Ok(())
    }

    async fn renew(
        &self,
        task_id: Uuid,
        lease_token: Uuid,
        action: RemoteUpdateAction,
        stage: RemoteUpdateStage,
    ) -> anyhow::Result<RemoteUpdateLeaseRenewResponse> {
        let request = RemoteUpdateLeaseRenewRequest {
            worker_instance_id: self.worker_instance_id,
            lease_token,
            requested_lease_seconds: self.lease_seconds,
            stage,
        };
        request.validate(action)?;
        self.api.renew(task_id, &request).await
    }

    async fn report(
        &self,
        task_id: Uuid,
        lease_token: Uuid,
        action: RemoteUpdateAction,
        report: RemoteUpdateWorkerReport,
    ) -> anyhow::Result<RemoteUpdateReportResponse> {
        let request = RemoteUpdateReportRequest {
            worker_instance_id: self.worker_instance_id,
            lease_token,
            report,
        };
        request.validate(action)?;
        self.api.report(task_id, &request).await
    }
}

struct CompletedOperation {
    result: RemoteUpdateResult,
    awaiting_restart: bool,
}

async fn execute_action(action: RemoteUpdateAction) -> anyhow::Result<CompletedOperation> {
    let state_directory = updater::default_state_directory(UpdateProduct::Client);
    let (result, awaiting_restart) = match action {
        RemoteUpdateAction::Check => {
            anyhow::ensure!(
                !updater::update_operation_active(&state_directory)?,
                "another local update operation is active"
            );
            let checked = updater::check(
                UpdateProduct::Client,
                UPDATE_REPOSITORY,
                UpdateChannel::Stable,
                SignaturePolicy::Production,
            )
            .await?;
            (
                RemoteUpdateResult::Check {
                    current_version: checked.current_version,
                    latest_version: checked.latest_version,
                    update_available: checked.update_available,
                    signature_key_id: checked.signature_key_id,
                },
                false,
            )
        }
        RemoteUpdateAction::Download => {
            let downloaded = updater::download(
                UpdateProduct::Client,
                UPDATE_REPOSITORY,
                UpdateChannel::Stable,
                &state_directory,
                false,
                SignaturePolicy::Production,
            )
            .await?;
            (
                RemoteUpdateResult::Downloaded {
                    version: downloaded.version,
                    archive_sha256: downloaded.archive_sha256,
                    binary_sha256: downloaded.binary_sha256,
                    signature_key_id: downloaded.signature_key_id,
                },
                false,
            )
        }
        RemoteUpdateAction::Apply => {
            let scheduled = updater::apply(
                UpdateProduct::Client,
                UPDATE_REPOSITORY,
                UpdateChannel::Stable,
                &state_directory,
                false,
                true,
                SignaturePolicy::Production,
            )
            .await?;
            (
                schedule_result(scheduled, RemoteLocalUpdateOperation::Apply)?,
                true,
            )
        }
        RemoteUpdateAction::Status => (
            status_result(updater::status(UpdateProduct::Client, &state_directory)?)?,
            false,
        ),
        RemoteUpdateAction::Recover => (
            status_result(updater::recover(
                UpdateProduct::Client,
                &state_directory,
                true,
            )?)?,
            false,
        ),
        RemoteUpdateAction::Rollback => {
            let scheduled = updater::rollback(UpdateProduct::Client, &state_directory, true)?;
            (
                schedule_result(scheduled, RemoteLocalUpdateOperation::Rollback)?,
                true,
            )
        }
    };
    result.validate()?;
    Ok(CompletedOperation {
        result,
        awaiting_restart,
    })
}

fn schedule_result(
    scheduled: updater::UpdateSchedule,
    expected_operation: RemoteLocalUpdateOperation,
) -> anyhow::Result<RemoteUpdateResult> {
    let observed_operation = match scheduled.operation.as_str() {
        "apply" => RemoteLocalUpdateOperation::Apply,
        "rollback" => RemoteLocalUpdateOperation::Rollback,
        _ => anyhow::bail!("secure updater returned an unknown scheduled operation"),
    };
    anyhow::ensure!(
        observed_operation == expected_operation,
        "secure updater scheduled a different operation"
    );
    Ok(RemoteUpdateResult::Scheduled {
        operation_id: scheduled.operation_id,
        operation: observed_operation,
        from_version: scheduled.from_version,
        to_version: scheduled.to_version,
    })
}

fn status_result(status: updater::UpdateStatus) -> anyhow::Result<RemoteUpdateResult> {
    let state = match status.state.as_str() {
        "idle" => RemoteLocalUpdateState::Idle,
        "scheduled" => RemoteLocalUpdateState::Scheduled,
        "installing" => RemoteLocalUpdateState::Installing,
        "succeeded" => RemoteLocalUpdateState::Succeeded,
        "rolled_back" => RemoteLocalUpdateState::RolledBack,
        "failed" => RemoteLocalUpdateState::Failed,
        "recovery_required" => RemoteLocalUpdateState::RecoveryRequired,
        _ => anyhow::bail!("secure updater returned an unknown local status"),
    };
    let operation = match status.operation.as_deref() {
        Some("apply") => Some(RemoteLocalUpdateOperation::Apply),
        Some("rollback") => Some(RemoteLocalUpdateOperation::Rollback),
        None => None,
        Some(_) => anyhow::bail!("secure updater returned an unknown local operation"),
    };
    let result = RemoteUpdateResult::Status {
        state,
        operation,
        from_version: status.from_version,
        to_version: status.to_version,
        has_error: status.error.is_some(),
        updated_unix_seconds: status.updated_unix_seconds,
    };
    result.validate()?;
    Ok(result)
}

fn classify_update_error(
    action: RemoteUpdateAction,
    error: &anyhow::Error,
) -> RemoteUpdateErrorCode {
    let text = format!("{error:#}").to_ascii_lowercase();
    if text.contains("another update") || text.contains("update lock") || text.contains(" active") {
        RemoteUpdateErrorCode::LocalUpdateBusy
    } else if text.contains("signature") || text.contains("ed25519") {
        RemoteUpdateErrorCode::SignatureVerificationFailed
    } else if text.contains("stable") || text.contains("prerelease") {
        RemoteUpdateErrorCode::StableChannelRequired
    } else if text.contains("downgrade") || text.contains("must be newer") {
        RemoteUpdateErrorCode::DowngradeForbidden
    } else if text.contains("digest")
        || text.contains("checksum")
        || text.contains("manifest")
        || text.contains("archive")
    {
        RemoteUpdateErrorCode::ArtifactRejected
    } else {
        match action {
            RemoteUpdateAction::Check => RemoteUpdateErrorCode::CheckFailed,
            RemoteUpdateAction::Download => RemoteUpdateErrorCode::DownloadFailed,
            RemoteUpdateAction::Apply => RemoteUpdateErrorCode::ApplyFailed,
            RemoteUpdateAction::Status => RemoteUpdateErrorCode::StatusFailed,
            RemoteUpdateAction::Recover => RemoteUpdateErrorCode::RecoveryFailed,
            RemoteUpdateAction::Rollback => RemoteUpdateErrorCode::RollbackFailed,
        }
    }
}

fn failure_recovery_state(action: RemoteUpdateAction) -> RemoteUpdateRecoveryState {
    match action {
        RemoteUpdateAction::Check | RemoteUpdateAction::Download | RemoteUpdateAction::Status => {
            RemoteUpdateRecoveryState::Retryable
        }
        RemoteUpdateAction::Apply => RemoteUpdateRecoveryState::StatusRequired,
        RemoteUpdateAction::Recover | RemoteUpdateAction::Rollback => {
            RemoteUpdateRecoveryState::FailedClosed
        }
    }
}

struct WorkerApi {
    client: reqwest::Client,
    base: Url,
    client_id: Uuid,
    client_token: String,
}

impl WorkerApi {
    async fn claim(
        &self,
        request: &RemoteUpdateClaimRequest,
    ) -> anyhow::Result<RemoteUpdateClaimResponse> {
        self.send(
            Method::POST,
            &format!("api/v1/clients/{}/update-tasks/claim", self.client_id),
            request,
        )
        .await
    }

    async fn renew(
        &self,
        task_id: Uuid,
        request: &RemoteUpdateLeaseRenewRequest,
    ) -> anyhow::Result<RemoteUpdateLeaseRenewResponse> {
        self.send(
            Method::POST,
            &format!(
                "api/v1/clients/{}/update-tasks/{task_id}/renew",
                self.client_id
            ),
            request,
        )
        .await
    }

    async fn report(
        &self,
        task_id: Uuid,
        request: &RemoteUpdateReportRequest,
    ) -> anyhow::Result<RemoteUpdateReportResponse> {
        self.send(
            Method::POST,
            &format!(
                "api/v1/clients/{}/update-tasks/{task_id}/report",
                self.client_id
            ),
            request,
        )
        .await
    }

    async fn send<Request, Response>(
        &self,
        method: Method,
        path: &str,
        request: &Request,
    ) -> anyhow::Result<Response>
    where
        Request: Serialize + ?Sized,
        Response: DeserializeOwned,
    {
        let url = self.base.join(path)?;
        anyhow::ensure!(
            same_trusted_origin(&self.base, &url),
            "remote update API URL left its configured HTTPS origin"
        );
        let response = self
            .client
            .request(method, url)
            .bearer_auth(&self.client_token)
            .json(request)
            .send()
            .await?;
        let status = response.status();
        anyhow::ensure!(
            status == StatusCode::OK,
            "remote update API returned HTTP status {status}"
        );
        anyhow::ensure!(
            response
                .content_length()
                .is_none_or(|length| length <= MAX_API_RESPONSE_BYTES),
            "remote update API response exceeds the size limit"
        );
        let bytes = response.bytes().await?;
        anyhow::ensure!(
            bytes.len() as u64 <= MAX_API_RESPONSE_BYTES,
            "remote update API response exceeds the size limit"
        );
        serde_json::from_slice::<Response>(&bytes)
            .context("remote update API returned an invalid bounded response")
    }
}

fn validate_api_base_url(value: &str) -> anyhow::Result<Url> {
    let mut url = Url::parse(value)?;
    anyhow::ensure!(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && (url.path().is_empty() || url.path() == "/"),
        "remote update api_base_url must be an HTTPS origin without credentials, path, query, or fragment"
    );
    url.set_path("/");
    Ok(url)
}

fn same_trusted_origin(base: &Url, candidate: &Url) -> bool {
    candidate.scheme() == "https"
        && candidate.username().is_empty()
        && candidate.password().is_none()
        && candidate.host_str() == base.host_str()
        && candidate.port_or_known_default() == base.port_or_known_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_updates_are_disabled_by_default() {
        assert!(!RemoteUpdateWorkerConfig::default().enabled);
    }

    #[test]
    fn worker_requires_a_plain_https_origin() {
        for invalid in [
            "http://example.com/",
            "https://user@example.com/",
            "https://example.com/path",
            "https://example.com/?source=other",
        ] {
            assert!(validate_api_base_url(invalid).is_err(), "{invalid}");
        }
        assert!(validate_api_base_url("https://example.com:9443/").is_ok());
    }
}
