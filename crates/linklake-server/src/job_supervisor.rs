//! 需要全局单执行者的后台任务监督器。
//!
//! 每个后台任务先取得带 fencing token 的 JobLease，再由本模块负责续租、监听
//! Leader 变化以及在租约失效时立即取消 worker。worker 不应自行决定 Leader，所有
//! 具有外部副作用的循环都必须通过这里启动。

use crate::{
    ha_coordination::LeadershipLease,
    job_leases::{JobLease, JobLeases},
    AppState,
};
use std::{future::Future, sync::Arc, time::Duration};
use tokio::{sync::watch, task::JoinHandle, time::MissedTickBehavior};
use uuid::Uuid;

const RETRY_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StopReason {
    Shutdown,
    LeadershipLost,
    LeaseExpired,
    LeaseRenewalFailed,
    WorkerExited,
}

enum RenewalOutcome {
    Renewed(anyhow::Result<Option<JobLease>>),
    LeadershipUnchanged,
    LeadershipLost,
    Shutdown,
}

/// 启动一个由 JobLease 保护的后台任务。
pub(crate) fn spawn_leased_job<F, Fut>(
    state: Arc<AppState>,
    shutdown: watch::Receiver<bool>,
    job_key: &'static str,
    job_kind: &'static str,
    worker: F,
) -> JoinHandle<()>
where
    F: Fn(Arc<AppState>, watch::Receiver<bool>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
{
    tokio::spawn(supervise(state, shutdown, job_key, job_kind, worker))
}

async fn supervise<F, Fut>(
    state: Arc<AppState>,
    mut shutdown: watch::Receiver<bool>,
    job_key: &'static str,
    job_kind: &'static str,
    worker: F,
) where
    F: Fn(Arc<AppState>, watch::Receiver<bool>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = anyhow::Result<()>> + Send + 'static,
{
    let jobs = state.ha_runtime.jobs();
    let renewal_interval = jobs.renewal_interval();
    let mut leadership = state.ha_runtime.subscribe_leadership();

    loop {
        let Some(leader) = wait_for_leader(&mut leadership, &mut shutdown).await else {
            tracing::debug!(job_key, job_kind, "后台任务 supervisor 已停止");
            return;
        };
        let fencing_token = leader.fencing_token;

        let lease = tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { return; }
                continue;
            }
            changed = leadership.changed() => {
                if changed.is_err() { return; }
                continue;
            }
            result = jobs.acquire(job_key, job_kind, fencing_token) => {
                match result {
                    Ok(lease) => lease,
                    Err(error) => {
                        tracing::warn!(job_key, job_kind, %error, "后台任务租约获取失败");
                        None
                    }
                }
            }
        };
        let Some(lease) = lease else {
            wait_before_retry(&mut leadership, &mut shutdown, fencing_token).await;
            continue;
        };
        if !same_leadership(&leadership, fencing_token)
            || state.ha_runtime.fencing_token().ok() != Some(fencing_token)
        {
            // 取得租约后立即发现 fencing term 已变化，不能启动任何副作用。
            continue;
        }

        let lease_id = lease.lease_id;
        tracing::info!(
            job_key,
            job_kind,
            lease_id = %lease_id,
            fencing_token,
            "后台任务取得租约"
        );
        let (stop_tx, stop_rx) = watch::channel(false);
        let mut worker_task = tokio::spawn(worker(state.clone(), stop_rx));
        let mut renew = tokio::time::interval(renewal_interval);
        renew.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut worker_result = None;

        let reason = loop {
            tokio::select! {
                result = &mut worker_task => {
                    worker_result = Some(result);
                    break StopReason::WorkerExited;
                }
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break StopReason::Shutdown;
                    }
                }
                changed = leadership.changed() => {
                    if changed.is_err() || !same_leadership(&leadership, fencing_token) {
                        break StopReason::LeadershipLost;
                    }
                }
                _ = renew.tick() => {
                    if !same_leadership(&leadership, fencing_token)
                        || state.ha_runtime.fencing_token().ok() != Some(fencing_token)
                    {
                        break StopReason::LeadershipLost;
                    }
                    match renew_with_interrupt(
                        jobs,
                        job_key,
                        job_kind,
                        lease_id,
                        fencing_token,
                        &mut leadership,
                        &mut shutdown,
                    ).await {
                        RenewalOutcome::LeadershipUnchanged => continue,
                        RenewalOutcome::LeadershipLost => {
                            break StopReason::LeadershipLost;
                        }
                        RenewalOutcome::Shutdown => {
                            break StopReason::Shutdown;
                        }
                        RenewalOutcome::Renewed(Ok(Some(_))) => {
                            tracing::debug!(job_key, job_kind, lease_id = %lease_id, "后台任务租约已续期");
                        }
                        RenewalOutcome::Renewed(Ok(None)) => {
                            break StopReason::LeaseExpired;
                        }
                        RenewalOutcome::Renewed(Err(error)) => {
                            tracing::warn!(job_key, job_kind, lease_id = %lease_id, %error, "后台任务租约续期失败");
                            break StopReason::LeaseRenewalFailed;
                        }
                    }
                }
            }
        };

        // 先广播取消，再立即 abort，确保网络请求和 JoinSet 子任务不会继续产生副作用。
        let _ = stop_tx.send(true);
        if reason != StopReason::WorkerExited {
            worker_task.abort();
        }
        if worker_result.is_none() {
            worker_result = Some(worker_task.await);
        }
        if matches!(worker_result.as_ref(), Some(Ok(Err(_))) | Some(Err(_))) {
            tracing::warn!(job_key, job_kind, "后台任务 worker 退出并带有错误");
        }

        match reason {
            StopReason::WorkerExited => {
                if same_leadership(&leadership, fencing_token)
                    && state.ha_runtime.fencing_token().ok() == Some(fencing_token)
                {
                    let completion = match worker_result {
                        Some(Ok(Ok(()))) => {
                            jobs.complete(job_key, job_kind, lease_id, fencing_token)
                                .await
                        }
                        Some(Ok(Err(error))) => jobs
                            .fail(
                                job_key,
                                job_kind,
                                lease_id,
                                fencing_token,
                                &safe_error_code(&error),
                            )
                            .await
                            .map(|_| true),
                        Some(Err(error)) => jobs
                            .fail(
                                job_key,
                                job_kind,
                                lease_id,
                                fencing_token,
                                "worker_join_failed",
                            )
                            .await
                            .map(|_| true)
                            .map_err(|finish| {
                                anyhow::anyhow!(
                                    "worker join failed ({error}); lease finish failed ({finish})"
                                )
                            }),
                        None => Ok(false),
                    };
                    if let Err(error) = completion {
                        tracing::warn!(job_key, job_kind, %error, "后台任务租约完成状态写入失败");
                    }
                }
            }
            StopReason::Shutdown => {
                if state.ha_runtime.fencing_token().ok() == Some(fencing_token) {
                    let _ = jobs
                        .complete(job_key, job_kind, lease_id, fencing_token)
                        .await;
                }
                return;
            }
            StopReason::LeadershipLost
            | StopReason::LeaseExpired
            | StopReason::LeaseRenewalFailed => {
                tracing::warn!(job_key, job_kind, lease_id = %lease_id, ?reason, "后台任务已停止副作用并放弃旧租约");
            }
        }

        wait_before_retry(&mut leadership, &mut shutdown, fencing_token).await;
    }
}

async fn renew_with_interrupt(
    jobs: &JobLeases,
    job_key: &str,
    job_kind: &str,
    lease_id: Uuid,
    fencing_token: u64,
    leadership: &mut watch::Receiver<Option<LeadershipLease>>,
    shutdown: &mut watch::Receiver<bool>,
) -> RenewalOutcome {
    tokio::select! {
        result = jobs.renew(job_key, job_kind, lease_id, fencing_token) => RenewalOutcome::Renewed(result),
        changed = leadership.changed() => {
            if changed.is_err() || !same_leadership(leadership, fencing_token) {
                RenewalOutcome::LeadershipLost
            } else {
                RenewalOutcome::LeadershipUnchanged
            }
        }
        changed = shutdown.changed() => {
            if changed.is_err() || *shutdown.borrow() {
                RenewalOutcome::Shutdown
            } else {
                RenewalOutcome::LeadershipUnchanged
            }
        }
    }
}

async fn wait_for_leader(
    leadership: &mut watch::Receiver<Option<LeadershipLease>>,
    shutdown: &mut watch::Receiver<bool>,
) -> Option<LeadershipLease> {
    loop {
        if *shutdown.borrow() {
            return None;
        }
        if let Some(leader) = leadership.borrow().clone() {
            return Some(leader);
        }
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { return None; }
            }
            changed = leadership.changed() => {
                if changed.is_err() { return None; }
            }
            _ = tokio::time::sleep(RETRY_INTERVAL) => {}
        }
    }
}

async fn wait_before_retry(
    leadership: &mut watch::Receiver<Option<LeadershipLease>>,
    shutdown: &mut watch::Receiver<bool>,
    fencing_token: u64,
) {
    tokio::select! {
        changed = shutdown.changed() => {
            let _ = changed;
        }
        changed = leadership.changed() => {
            let _ = changed;
        }
        _ = tokio::time::sleep(RETRY_INTERVAL) => {}
    }
    if !same_leadership(leadership, fencing_token) {
        tracing::debug!(fencing_token, "后台任务等待新的 Leader term");
    }
}

fn same_leadership(
    leadership: &watch::Receiver<Option<LeadershipLease>>,
    fencing_token: u64,
) -> bool {
    leadership
        .borrow()
        .as_ref()
        .is_some_and(|lease| lease.fencing_token == fencing_token)
}

fn safe_error_code(_error: &anyhow::Error) -> String {
    // 租约账本只保存稳定的机器码，避免把异常文本、路径或凭据写入共享存储。
    "worker_failed".to_owned()
}
