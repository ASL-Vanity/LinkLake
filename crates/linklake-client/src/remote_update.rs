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
    RemoteUpdateReportRequest, RemoteUpdateReportResponse, RemoteUpdateRestartPlan,
    RemoteUpdateResult, RemoteUpdateStage, RemoteUpdateTask, RemoteUpdateWorkerReport,
    REMOTE_UPDATE_DEFAULT_LEASE_SECONDS, REMOTE_UPDATE_MAX_LEASE_SECONDS,
    REMOTE_UPDATE_RESTART_RESUME_SECONDS,
};
use linklake_update as updater;
use linklake_update::{SignaturePolicy, UpdateChannel, UpdateProduct};
use reqwest::{Method, StatusCode, Url};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{pin::pin, sync::OnceLock, time::Duration};
use tokio::sync::{watch, Mutex};
use tokio::time::{interval, sleep, MissedTickBehavior};
use uuid::Uuid;

const UPDATE_REPOSITORY: &str = "ASL-Vanity/LinkLake";
const MIN_POLL_INTERVAL_SECONDS: u32 = 5;
const MAX_POLL_INTERVAL_SECONDS: u32 = 300;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_API_RESPONSE_BYTES: u64 = 256 * 1024;
const RESUME_SCHEMA_VERSION: u32 = 1;
const MAX_RESUME_STATE_BYTES: usize = 8 * 1024;
const COMPLETION_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// 同一客户端进程中的所有云入口共享这一把锁。
///
/// 它避免多个 supervisor 同时 claim 或执行本地更新；更新器自己的跨进程锁仍是
/// 第二层边界，用于防止另一个 LinkLake 进程或本地管理员命令并发替换安装目录。
static INSTALLATION_SINGLE_FLIGHT: OnceLock<Mutex<()>> = OnceLock::new();

fn installation_single_flight() -> &'static Mutex<()> {
    INSTALLATION_SINGLE_FLIGHT.get_or_init(|| Mutex::new(()))
}

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
    /// 服务或外部 supervisor 必须把退出码 75 解释为安全重启请求。
    #[serde(default)]
    pub(crate) restart_supervisor_enabled: bool,
}

impl Default for RemoteUpdateWorkerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            api_base_url: None,
            poll_interval_seconds: default_poll_interval_seconds(),
            lease_seconds: default_lease_seconds(),
            restart_supervisor_enabled: false,
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PendingRestartVerification {
    schema_version: u32,
    client_id: Uuid,
    task_id: Uuid,
    action: RemoteUpdateAction,
    worker_instance_id: Uuid,
    lease_token: Uuid,
    operation_id: Uuid,
    operation: RemoteLocalUpdateOperation,
    from_version: String,
    to_version: String,
    api_origin_sha256: String,
    created_unix_seconds: u64,
    resume_not_after_unix_seconds: u64,
}

struct RestartPlan {
    operation_id: Uuid,
    operation: RemoteLocalUpdateOperation,
    from_version: String,
    to_version: String,
    staged: updater::StagedUpdate,
}

#[derive(Clone, Copy)]
struct LeaseIdentity {
    task_id: Uuid,
    lease_token: Uuid,
    action: RemoteUpdateAction,
    worker_instance_id: Uuid,
}

#[derive(Clone, Copy)]
struct RenewContext {
    identity: LeaseIdentity,
    stage: RemoteUpdateStage,
    lease_seconds: u32,
    maximum_deadline: Option<u64>,
}

enum CompletedOperation {
    Final(RemoteUpdateResult),
    RestartScheduled(RestartPlan),
}

fn default_poll_interval_seconds() -> u32 {
    30
}

fn default_lease_seconds() -> u32 {
    REMOTE_UPDATE_DEFAULT_LEASE_SECONDS
}

fn stop_requested(stop_rx: &watch::Receiver<bool>) -> bool {
    *stop_rx.borrow()
}

async fn wait_for_idle_or_stop(duration: Duration, stop_rx: &mut watch::Receiver<bool>) -> bool {
    if stop_requested(stop_rx) {
        return true;
    }
    tokio::select! {
        _ = sleep(duration) => false,
        changed = stop_rx.changed() => changed.is_err() || stop_requested(stop_rx),
    }
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
    anyhow::ensure!(
        config.restart_supervisor_enabled,
        "remote updates require a service manager or external supervisor that restarts exit code 75"
    );
    let base = config
        .api_base_url
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("remote update api_base_url is required when enabled"))?;
    validate_api_base_url(base)?;
    Ok(())
}

pub(crate) struct RemoteUpdateWorkerHandle {
    stop_tx: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl RemoteUpdateWorkerHandle {
    /// 只在 worker 的空闲边界请求停止；已经 claim 的任务会先完成关键持久化与上报。
    pub(crate) async fn shutdown(self) -> anyhow::Result<()> {
        let _ = self.stop_tx.send(true);
        self.task
            .await
            .context("remote update worker task failed while stopping")?;
        Ok(())
    }
}

pub(crate) fn spawn(
    config: RemoteUpdateWorkerConfig,
    client_id: Uuid,
    client_token: String,
    restart_tx: watch::Sender<bool>,
) -> anyhow::Result<Option<RemoteUpdateWorkerHandle>> {
    validate_config(&config)?;
    if !config.enabled {
        return Ok(None);
    }
    let worker = RemoteUpdateWorker::new(config, client_id, client_token, restart_tx)?;
    let (stop_tx, stop_rx) = watch::channel(false);
    let task = tokio::spawn(async move {
        if let Err(error) = worker.run(stop_rx).await {
            tracing::error!(%error, "Remote update worker stopped");
        }
    });
    Ok(Some(RemoteUpdateWorkerHandle { stop_tx, task }))
}

struct RemoteUpdateWorker {
    api: WorkerApi,
    worker_instance_id: Uuid,
    poll_interval: Duration,
    lease_seconds: u32,
    restart_tx: watch::Sender<bool>,
    resume_origin_sha256: String,
}

impl RemoteUpdateWorker {
    fn new(
        config: RemoteUpdateWorkerConfig,
        client_id: Uuid,
        client_token: String,
        restart_tx: watch::Sender<bool>,
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
        let resume_origin_sha256 = sha256_hex(base.as_str().as_bytes());
        updater::remote_update_resume_path(
            UpdateProduct::Client,
            &updater::default_state_directory(UpdateProduct::Client),
            client_id,
            &resume_origin_sha256,
        )?;
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
            restart_tx,
            resume_origin_sha256,
        })
    }

    async fn run(self, mut stop_rx: watch::Receiver<bool>) -> anyhow::Result<()> {
        tracing::info!(
            client_id = %self.api.client_id,
            "Remote update worker enabled with Stable/Production policy"
        );
        loop {
            if stop_requested(&stop_rx) {
                return Ok(());
            }

            let single_flight = tokio::select! {
                guard = installation_single_flight().lock() => guard,
                changed = stop_rx.changed() => {
                    if changed.is_err() || stop_requested(&stop_rx) {
                        return Ok(());
                    }
                    continue;
                }
            };
            if stop_requested(&stop_rx) {
                drop(single_flight);
                return Ok(());
            }

            if self.has_resume_receipt()? {
                match self.resume_pending_restart().await {
                    Ok(true) => return Ok(()),
                    Ok(false) => {
                        drop(single_flight);
                        continue;
                    }
                    Err(error) => {
                        tracing::error!(%error, "Remote update restart verification is pending");
                        drop(single_flight);
                        if wait_for_idle_or_stop(self.poll_interval, &mut stop_rx).await {
                            return Ok(());
                        }
                        continue;
                    }
                }
            }

            match updater::any_remote_update_resume_receipt_exists(
                UpdateProduct::Client,
                &updater::default_state_directory(UpdateProduct::Client),
            ) {
                Ok(true) => {
                    tracing::debug!(
                        client_id = %self.api.client_id,
                        "Another cloud identity owns a pending remote update receipt"
                    );
                    drop(single_flight);
                    if wait_for_idle_or_stop(self.poll_interval, &mut stop_rx).await {
                        return Ok(());
                    }
                    continue;
                }
                Ok(false) => {}
                Err(error) => {
                    tracing::error!(%error, "Remote update receipt inventory is unsafe; refusing to claim");
                    drop(single_flight);
                    if wait_for_idle_or_stop(self.poll_interval, &mut stop_rx).await {
                        return Ok(());
                    }
                    continue;
                }
            }

            match self.claim().await {
                Ok(Some(claim)) => match self.execute_claim(claim).await {
                    Ok(true) => return Ok(()),
                    Ok(false) => {}
                    Err(error) => {
                        tracing::error!(%error, "Remote update task execution failed");
                    }
                },
                Ok(None) => {}
                Err(error) => {
                    tracing::warn!(%error, "Remote update claim failed; retrying");
                }
            }
            drop(single_flight);
            if wait_for_idle_or_stop(self.poll_interval, &mut stop_rx).await {
                return Ok(());
            }
        }
    }

    fn has_resume_receipt(&self) -> anyhow::Result<bool> {
        updater::remote_update_resume_receipt_exists(
            UpdateProduct::Client,
            &updater::default_state_directory(UpdateProduct::Client),
            self.api.client_id,
            &self.resume_origin_sha256,
        )
    }

    async fn claim(&self) -> anyhow::Result<Option<RemoteUpdateClaim>> {
        let request = RemoteUpdateClaimRequest {
            worker_instance_id: self.worker_instance_id,
            requested_lease_seconds: self.lease_seconds,
        };
        request.validate()?;
        let response = self.api.claim(&request).await?;
        if let Some(claim) = response.claim.as_ref() {
            claim.validate(self.api.client_id, self.worker_instance_id, unix_seconds())?;
        }
        Ok(response.claim)
    }

    async fn execute_claim(&self, claim: RemoteUpdateClaim) -> anyhow::Result<bool> {
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

        let (stage_tx, stage_rx) = watch::channel(stage);
        let worker = self;
        let operation = async move {
            if action.requires_restart() {
                let plan = worker.prepare_restart(action).await?;
                worker
                    .execute_restart_operation(task_id, lease_token, action, plan, &stage_tx)
                    .await
            } else {
                execute_action(action).await
            }
        };
        let mut operation = pin!(operation);
        let renewal_period = Duration::from_secs(u64::from((self.lease_seconds / 3).max(5)));
        let mut renewal = interval(renewal_period);
        renewal.set_missed_tick_behavior(MissedTickBehavior::Delay);
        renewal.tick().await;
        let outcome = loop {
            tokio::select! {
                result = &mut operation => break result,
                _ = renewal.tick() => {
                    let current_stage = *stage_rx.borrow();
                    let renewed = self.renew(task_id, lease_token, action, current_stage).await?;
                    if renewed.cancel_requested && !action.changes_installation() {
                        self.report(
                            task_id,
                            lease_token,
                            action,
                            RemoteUpdateWorkerReport::Cancelled,
                        ).await?;
                        return Ok(false);
                    }
                }
            }
        };

        match outcome {
            Ok(CompletedOperation::Final(result)) => {
                self.report(
                    task_id,
                    lease_token,
                    action,
                    RemoteUpdateWorkerReport::Succeeded { result },
                )
                .await?;
            }
            Ok(CompletedOperation::RestartScheduled(_restart)) => {
                let _ = self.restart_tx.send(true);
                tracing::info!(
                    task_id = %task_id,
                    "Remote update helper scheduled; requesting a graceful client process exit"
                );
                return Ok(true);
            }
            Err(error) => {
                let error_code = classify_update_error(action, &error);
                tracing::error!(%error, ?action, "Local secure update operation failed");
                let report_result = self
                    .report(
                        task_id,
                        lease_token,
                        action,
                        RemoteUpdateWorkerReport::Failed {
                            error_code,
                            recovery_state: failure_recovery_state(action),
                        },
                    )
                    .await;
                if report_result.is_ok() && action.requires_restart() {
                    let _ = self.remove_resume_receipt();
                }
                report_result?;
            }
        }
        Ok(false)
    }

    async fn prepare_restart(&self, action: RemoteUpdateAction) -> anyhow::Result<RestartPlan> {
        let state_directory = updater::default_state_directory(UpdateProduct::Client);
        let operation_id = Uuid::new_v4();
        anyhow::ensure!(
            !operation_id.is_nil(),
            "generated remote update operation ID is nil"
        );
        let (operation, staged) = match action {
            RemoteUpdateAction::Apply => (
                RemoteLocalUpdateOperation::Apply,
                updater::download(
                    UpdateProduct::Client,
                    UPDATE_REPOSITORY,
                    UpdateChannel::Stable,
                    &state_directory,
                    false,
                    SignaturePolicy::Production,
                )
                .await?,
            ),
            RemoteUpdateAction::Rollback => (
                RemoteLocalUpdateOperation::Rollback,
                updater::prepare_rollback(UpdateProduct::Client, &state_directory, true)?,
            ),
            _ => anyhow::bail!("remote update action does not require a restart"),
        };
        anyhow::ensure!(
            staged.current_version != "unknown",
            "remote update requires a detectable current component version"
        );
        Ok(RestartPlan {
            operation_id,
            operation,
            from_version: staged.current_version.clone(),
            to_version: staged.version.clone(),
            staged,
        })
    }

    async fn execute_restart_operation(
        &self,
        task_id: Uuid,
        lease_token: Uuid,
        action: RemoteUpdateAction,
        plan: RestartPlan,
        stage_tx: &watch::Sender<RemoteUpdateStage>,
    ) -> anyhow::Result<CompletedOperation> {
        let created_unix_seconds = unix_seconds();
        let resume_not_after_unix_seconds = created_unix_seconds
            .checked_add(REMOTE_UPDATE_RESTART_RESUME_SECONDS)
            .ok_or_else(|| anyhow::anyhow!("remote update restart resume deadline overflowed"))?;
        let receipt = PendingRestartVerification {
            schema_version: RESUME_SCHEMA_VERSION,
            client_id: self.api.client_id,
            task_id,
            action,
            worker_instance_id: self.worker_instance_id,
            lease_token,
            operation_id: plan.operation_id,
            operation: plan.operation,
            from_version: plan.from_version.clone(),
            to_version: plan.to_version.clone(),
            api_origin_sha256: self.api.origin_sha256(),
            created_unix_seconds,
            resume_not_after_unix_seconds,
        };
        validate_resume_receipt(&receipt, &self.api)?;
        self.write_resume_receipt(&receipt)?;
        let response = self
            .report(
                task_id,
                lease_token,
                action,
                RemoteUpdateWorkerReport::AwaitingRestart {
                    plan: RemoteUpdateRestartPlan {
                        operation_id: plan.operation_id,
                        operation: plan.operation,
                        from_version: plan.from_version.clone(),
                        to_version: plan.to_version.clone(),
                    },
                },
            )
            .await?;
        validate_restart_binding(&response.task, self.api.client_id, action, &plan)?;
        stage_tx.send(RemoteUpdateStage::AwaitingRestart).ok();
        let scheduled = match plan.operation {
            RemoteLocalUpdateOperation::Apply => updater::apply_staged_with_operation_id(
                UpdateProduct::Client,
                &updater::default_state_directory(UpdateProduct::Client),
                plan.staged.clone(),
                plan.operation_id,
                true,
            )?,
            RemoteLocalUpdateOperation::Rollback => updater::rollback_staged_with_operation_id(
                UpdateProduct::Client,
                &updater::default_state_directory(UpdateProduct::Client),
                plan.staged.clone(),
                plan.operation_id,
                true,
            )?,
        };
        anyhow::ensure!(
            scheduled.operation_id == plan.operation_id
                && scheduled.from_version == plan.from_version
                && scheduled.to_version == plan.to_version,
            "secure updater schedule does not match the persisted remote update receipt"
        );
        Ok(CompletedOperation::RestartScheduled(plan))
    }

    async fn resume_pending_restart(&self) -> anyhow::Result<bool> {
        let receipt = self.read_resume_receipt()?;
        validate_resume_receipt(&receipt, &self.api)?;
        let lease_identity = LeaseIdentity {
            task_id: receipt.task_id,
            lease_token: receipt.lease_token,
            action: receipt.action,
            worker_instance_id: receipt.worker_instance_id,
        };
        let state_directory = updater::default_state_directory(UpdateProduct::Client);
        let expected_terminal = match receipt.action {
            RemoteUpdateAction::Apply => "succeeded",
            RemoteUpdateAction::Rollback => "rolled_back",
            _ => anyhow::bail!("restart verification receipt contains a non-restart action"),
        };
        loop {
            if updater::update_operation_active(&state_directory)? {
                self.renew_as(RenewContext {
                    identity: lease_identity,
                    stage: RemoteUpdateStage::AwaitingRestart,
                    lease_seconds: REMOTE_UPDATE_MAX_LEASE_SECONDS,
                    maximum_deadline: Some(receipt.resume_not_after_unix_seconds),
                })
                .await?;
                sleep(COMPLETION_POLL_INTERVAL).await;
                continue;
            }
            let status = updater::status(UpdateProduct::Client, &state_directory)?;
            if matches!(status.state.as_str(), "scheduled" | "installing") {
                self.renew_as(RenewContext {
                    identity: lease_identity,
                    stage: RemoteUpdateStage::AwaitingRestart,
                    lease_seconds: REMOTE_UPDATE_MAX_LEASE_SECONDS,
                    maximum_deadline: Some(receipt.resume_not_after_unix_seconds),
                })
                .await?;
                sleep(COMPLETION_POLL_INTERVAL).await;
                continue;
            }
            if status.state == "idle" {
                let plan = self.prepare_resume_plan(&receipt).await?;
                let response = self
                    .report_as(
                        receipt.task_id,
                        receipt.lease_token,
                        receipt.action,
                        RemoteUpdateWorkerReport::AwaitingRestart {
                            plan: RemoteUpdateRestartPlan {
                                operation_id: plan.operation_id,
                                operation: plan.operation,
                                from_version: plan.from_version.clone(),
                                to_version: plan.to_version.clone(),
                            },
                        },
                        receipt.worker_instance_id,
                    )
                    .await?;
                validate_restart_binding(
                    &response.task,
                    self.api.client_id,
                    receipt.action,
                    &plan,
                )?;
                let scheduled = self.schedule_restart(plan)?;
                anyhow::ensure!(
                    scheduled.operation_id == receipt.operation_id,
                    "resumed updater operation ID does not match the protected receipt"
                );
                let _ = self.restart_tx.send(true);
                return Ok(true);
            }
            self.renew_as(RenewContext {
                identity: lease_identity,
                stage: RemoteUpdateStage::AwaitingRestart,
                lease_seconds: REMOTE_UPDATE_MAX_LEASE_SECONDS,
                maximum_deadline: Some(receipt.resume_not_after_unix_seconds),
            })
            .await?;
            if status.state == expected_terminal {
                let verified = updater::verify_completed_update(
                    UpdateProduct::Client,
                    &state_directory,
                    receipt.operation_id,
                )
                .map_err(|error| {
                    anyhow::anyhow!("remote update completion verification failed: {error:#}")
                })?;
                anyhow::ensure!(
                    verified.operation_id == receipt.operation_id
                        && verified.operation == operation_name(receipt.operation)
                        && verified.from_version == receipt.from_version
                        && verified.to_version == receipt.to_version,
                    "completed update verification does not match the persisted remote task receipt"
                );
                let result = RemoteUpdateResult::Installed {
                    operation_id: verified.operation_id,
                    operation: receipt.operation,
                    from_version: verified.from_version,
                    to_version: verified.to_version,
                    installed_sha256: verified.installed_sha256,
                    backup_sha256: verified.backup_sha256,
                    verified_unix_seconds: verified.verified_unix_seconds,
                };
                result.validate()?;
                self.report_as(
                    receipt.task_id,
                    receipt.lease_token,
                    receipt.action,
                    RemoteUpdateWorkerReport::Succeeded { result },
                    receipt.worker_instance_id,
                )
                .await?;
                self.remove_resume_receipt()?;
                return Ok(false);
            }
            let error_code = match receipt.action {
                RemoteUpdateAction::Apply => RemoteUpdateErrorCode::ApplyFailed,
                RemoteUpdateAction::Rollback => RemoteUpdateErrorCode::RollbackFailed,
                _ => RemoteUpdateErrorCode::FailedClosed,
            };
            self.report_as(
                receipt.task_id,
                receipt.lease_token,
                receipt.action,
                RemoteUpdateWorkerReport::Failed {
                    error_code,
                    recovery_state: failure_recovery_state(receipt.action),
                },
                receipt.worker_instance_id,
            )
            .await?;
            self.remove_resume_receipt()?;
            return Ok(false);
        }
    }

    async fn prepare_resume_plan(
        &self,
        receipt: &PendingRestartVerification,
    ) -> anyhow::Result<RestartPlan> {
        let state_directory = updater::default_state_directory(UpdateProduct::Client);
        let staged = match receipt.action {
            RemoteUpdateAction::Apply => {
                updater::download(
                    UpdateProduct::Client,
                    UPDATE_REPOSITORY,
                    UpdateChannel::Stable,
                    &state_directory,
                    false,
                    SignaturePolicy::Production,
                )
                .await?
            }
            RemoteUpdateAction::Rollback => {
                updater::prepare_rollback(UpdateProduct::Client, &state_directory, true)?
            }
            _ => anyhow::bail!("restart receipt action is not restartable"),
        };
        anyhow::ensure!(
            staged.current_version == receipt.from_version && staged.version == receipt.to_version,
            "resumed update artifact does not match the protected receipt"
        );
        Ok(RestartPlan {
            operation_id: receipt.operation_id,
            operation: receipt.operation,
            from_version: receipt.from_version.clone(),
            to_version: receipt.to_version.clone(),
            staged,
        })
    }

    fn schedule_restart(&self, plan: RestartPlan) -> anyhow::Result<updater::UpdateSchedule> {
        let state_directory = updater::default_state_directory(UpdateProduct::Client);
        match plan.operation {
            RemoteLocalUpdateOperation::Apply => updater::apply_staged_with_operation_id(
                UpdateProduct::Client,
                &state_directory,
                plan.staged,
                plan.operation_id,
                true,
            ),
            RemoteLocalUpdateOperation::Rollback => updater::rollback_staged_with_operation_id(
                UpdateProduct::Client,
                &state_directory,
                plan.staged,
                plan.operation_id,
                true,
            ),
        }
    }

    fn write_resume_receipt(&self, receipt: &PendingRestartVerification) -> anyhow::Result<()> {
        let bytes = serde_json::to_vec(receipt)?;
        anyhow::ensure!(
            bytes.len() <= MAX_RESUME_STATE_BYTES,
            "remote update restart receipt exceeds the size limit"
        );
        updater::write_remote_update_resume_receipt(
            UpdateProduct::Client,
            &updater::default_state_directory(UpdateProduct::Client),
            self.api.client_id,
            &self.resume_origin_sha256,
            &bytes,
        )?;
        Ok(())
    }

    fn read_resume_receipt(&self) -> anyhow::Result<PendingRestartVerification> {
        let bytes = updater::read_remote_update_resume_receipt(
            UpdateProduct::Client,
            &updater::default_state_directory(UpdateProduct::Client),
            self.api.client_id,
            &self.resume_origin_sha256,
        )?;
        anyhow::ensure!(
            bytes.len() <= MAX_RESUME_STATE_BYTES,
            "remote update restart receipt exceeds the size limit"
        );
        Ok(serde_json::from_slice(&bytes)?)
    }

    fn remove_resume_receipt(&self) -> anyhow::Result<()> {
        updater::remove_remote_update_resume_receipt(
            UpdateProduct::Client,
            &updater::default_state_directory(UpdateProduct::Client),
            self.api.client_id,
            &self.resume_origin_sha256,
        )?;
        Ok(())
    }

    async fn renew(
        &self,
        task_id: Uuid,
        lease_token: Uuid,
        action: RemoteUpdateAction,
        stage: RemoteUpdateStage,
    ) -> anyhow::Result<RemoteUpdateLeaseRenewResponse> {
        self.renew_as(RenewContext {
            identity: LeaseIdentity {
                task_id,
                lease_token,
                action,
                worker_instance_id: self.worker_instance_id,
            },
            stage,
            lease_seconds: self.lease_seconds,
            maximum_deadline: None,
        })
        .await
    }

    async fn renew_as(
        &self,
        context: RenewContext,
    ) -> anyhow::Result<RemoteUpdateLeaseRenewResponse> {
        let request = RemoteUpdateLeaseRenewRequest {
            worker_instance_id: context.identity.worker_instance_id,
            lease_token: context.identity.lease_token,
            requested_lease_seconds: context.lease_seconds,
            stage: context.stage,
        };
        request.validate(context.identity.action)?;
        let response = self.api.renew(context.identity.task_id, &request).await?;
        response.validate(
            context.identity.task_id,
            unix_seconds(),
            context.maximum_deadline,
        )?;
        Ok(response)
    }

    async fn report(
        &self,
        task_id: Uuid,
        lease_token: Uuid,
        action: RemoteUpdateAction,
        report: RemoteUpdateWorkerReport,
    ) -> anyhow::Result<RemoteUpdateReportResponse> {
        self.report_as(
            task_id,
            lease_token,
            action,
            report,
            self.worker_instance_id,
        )
        .await
    }

    async fn report_as(
        &self,
        task_id: Uuid,
        lease_token: Uuid,
        action: RemoteUpdateAction,
        report: RemoteUpdateWorkerReport,
        worker_instance_id: Uuid,
    ) -> anyhow::Result<RemoteUpdateReportResponse> {
        let request = RemoteUpdateReportRequest {
            worker_instance_id,
            lease_token,
            report,
        };
        request.validate(action)?;
        let response = self.api.report(task_id, &request).await?;
        response.validate(task_id, self.api.client_id, action, &request.report)?;
        Ok(response)
    }
}

async fn execute_action(action: RemoteUpdateAction) -> anyhow::Result<CompletedOperation> {
    let state_directory = updater::default_state_directory(UpdateProduct::Client);
    let outcome =
        match action {
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
                CompletedOperation::Final(RemoteUpdateResult::Check {
                    current_version: checked.current_version,
                    latest_version: checked.latest_version,
                    update_available: checked.update_available,
                    signature_key_id: checked.signature_key_id,
                })
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
                CompletedOperation::Final(RemoteUpdateResult::Downloaded {
                    version: downloaded.version,
                    archive_sha256: downloaded.archive_sha256,
                    binary_sha256: downloaded.binary_sha256,
                    signature_key_id: downloaded.signature_key_id,
                })
            }
            RemoteUpdateAction::Apply => {
                anyhow::bail!("apply must use the persisted remote restart scheduling path")
            }
            RemoteUpdateAction::Status => CompletedOperation::Final(status_result(
                updater::status(UpdateProduct::Client, &state_directory)?,
            )?),
            RemoteUpdateAction::Recover => CompletedOperation::Final(status_result(
                updater::recover(UpdateProduct::Client, &state_directory, true)?,
            )?),
            RemoteUpdateAction::Rollback => {
                anyhow::bail!("rollback must use the persisted remote restart scheduling path")
            }
        };
    if let CompletedOperation::Final(result) = &outcome {
        result.validate()?;
    }
    Ok(outcome)
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

fn operation_name(operation: RemoteLocalUpdateOperation) -> &'static str {
    match operation {
        RemoteLocalUpdateOperation::Apply => "apply",
        RemoteLocalUpdateOperation::Rollback => "rollback",
    }
}

fn validate_resume_receipt(
    receipt: &PendingRestartVerification,
    api: &WorkerApi,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        receipt.schema_version == RESUME_SCHEMA_VERSION
            && receipt.client_id == api.client_id
            && !receipt.client_id.is_nil()
            && !receipt.task_id.is_nil()
            && !receipt.worker_instance_id.is_nil()
            && !receipt.lease_token.is_nil()
            && !receipt.operation_id.is_nil()
            && receipt.created_unix_seconds > 0
            && receipt.resume_not_after_unix_seconds > receipt.created_unix_seconds
            && receipt
                .resume_not_after_unix_seconds
                .saturating_sub(receipt.created_unix_seconds)
                <= REMOTE_UPDATE_RESTART_RESUME_SECONDS
            && receipt.api_origin_sha256 == api.origin_sha256(),
        "remote update restart receipt identity is invalid"
    );
    let expected_operation = match receipt.action {
        RemoteUpdateAction::Apply => RemoteLocalUpdateOperation::Apply,
        RemoteUpdateAction::Rollback => RemoteLocalUpdateOperation::Rollback,
        _ => anyhow::bail!("remote update restart receipt action is invalid"),
    };
    anyhow::ensure!(
        receipt.operation == expected_operation,
        "remote update restart receipt operation mismatch"
    );
    for version in [&receipt.from_version, &receipt.to_version] {
        anyhow::ensure!(version.len() <= 64, "restart receipt version is too long");
        semver::Version::parse(version.strip_prefix('v').unwrap_or(version))?;
    }
    Ok(())
}

fn validate_restart_binding(
    task: &RemoteUpdateTask,
    client_id: Uuid,
    action: RemoteUpdateAction,
    plan: &RestartPlan,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        task.target_client_id == client_id
            && task.action == action
            && task.stage == RemoteUpdateStage::AwaitingRestart,
        "remote update restart response has an invalid task identity or stage"
    );
    let binding = task
        .restart
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("remote update restart response has no binding"))?;
    anyhow::ensure!(
        binding.operation_id == plan.operation_id
            && binding.operation == plan.operation
            && binding.from_version == plan.from_version
            && binding.to_version == plan.to_version
            && binding.resume_deadline_unix_seconds > unix_seconds(),
        "remote update restart response does not match the prepared operation"
    );
    Ok(())
}

fn sha256_hex(value: &[u8]) -> String {
    let digest = Sha256::digest(value);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}

struct WorkerApi {
    client: reqwest::Client,
    base: Url,
    client_id: Uuid,
    client_token: String,
}

impl WorkerApi {
    fn origin_sha256(&self) -> String {
        sha256_hex(self.base.as_str().as_bytes())
    }
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
        let mut response = self
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
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            let next_len = bytes
                .len()
                .checked_add(chunk.len())
                .ok_or_else(|| anyhow::anyhow!("remote update API response size overflowed"))?;
            anyhow::ensure!(
                next_len as u64 <= MAX_API_RESPONSE_BYTES,
                "remote update API response exceeds the size limit"
            );
            bytes.extend_from_slice(&chunk);
        }
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

fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
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
