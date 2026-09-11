//! 单次证书任务的续租和取消边界，手动签发与维护任务使用同一保护。

use crate::{ha_runtime::HaRuntime, job_leases::JobLease};
use std::{future::Future, sync::Arc, time::Duration};
use tokio::{
    sync::watch,
    time::{Instant, MissedTickBehavior},
};

pub(crate) async fn run<T>(
    runtime: Arc<HaRuntime>,
    lease: JobLease,
    mut stop: Option<watch::Receiver<bool>>,
    operation: impl Future<Output = T>,
) -> anyhow::Result<T> {
    let mut leadership = runtime.subscribe_leadership();
    let jobs = runtime.jobs();
    let mut renew_tick = tokio::time::interval(jobs.renewal_interval());
    renew_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    tokio::pin!(operation);
    // 初次轮询前必须向共享库确认并续租；准备阶段的审计等待可能已消耗租约。
    let mut deadline = None;
    loop {
        anyhow::ensure!(
            !stop.as_ref().is_some_and(|stop| *stop.borrow()),
            "certificate operation stopped"
        );
        anyhow::ensure!(
            runtime.fencing_token().ok() == Some(lease.fencing_token),
            "certificate leadership changed"
        );
        if deadline.is_none() {
            let started = Instant::now();
            let renewed = tokio::select! {
                biased;
                _ = cancelled(&mut stop) => anyhow::bail!("certificate operation stopped"),
                changed = leadership.changed() => {
                    anyhow::ensure!(changed.is_ok(), "certificate leadership channel closed");
                    continue;
                },
                result = jobs.renew(&lease.job_key, &lease.job_kind, lease.lease_id, lease.fencing_token) => result?,
            }.ok_or_else(|| anyhow::anyhow!("certificate job lease expired"))?;
            deadline = Some(started + remaining_lease_duration(&renewed));
        }
        let expires = deadline.expect("lease was renewed");
        tokio::select! {
            biased;
            _ = cancelled(&mut stop) => anyhow::bail!("certificate operation stopped"),
            _ = tokio::time::sleep_until(expires) => anyhow::bail!("certificate job lease expired"),
            changed = leadership.changed() => {
                anyhow::ensure!(changed.is_ok(), "certificate leadership channel closed");
            }
            _ = renew_tick.tick() => {
                let started = Instant::now();
                let renewed = tokio::select! {
                    biased;
                    _ = cancelled(&mut stop) => anyhow::bail!("certificate operation stopped"),
                    _ = tokio::time::sleep_until(expires) => anyhow::bail!("certificate job lease expired"),
                    changed = leadership.changed() => {
                        anyhow::ensure!(changed.is_ok(), "certificate leadership channel closed");
                        continue;
                    }
                    result = jobs.renew(&lease.job_key, &lease.job_kind, lease.lease_id, lease.fencing_token) => result?,
                }.ok_or_else(|| anyhow::anyhow!("certificate job lease expired"))?;
                deadline = Some(started + remaining_lease_duration(&renewed));
            }
            result = &mut operation => return Ok(result),
        }
    }
}

fn remaining_lease_duration(lease: &JobLease) -> Duration {
    // 数据库租约按整秒保存，扣去一秒避免本地截止时间超过真实租约边界。
    Duration::from_secs(
        lease
            .lease_until_unix_seconds
            .saturating_sub(lease.renewed_unix_seconds)
            .saturating_sub(1),
    )
}

async fn cancelled(stop: &mut Option<watch::Receiver<bool>>) {
    let Some(stop) = stop else {
        std::future::pending::<()>().await;
        return;
    };
    loop {
        if *stop.borrow() {
            return;
        }
        if stop.changed().await.is_err() {
            return;
        }
    }
}
