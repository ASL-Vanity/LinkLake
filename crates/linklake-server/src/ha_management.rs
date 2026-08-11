//! HA 管理平面只读快照与脱敏视图。
//!
//! 该模块只读取协调存储和运行时状态，不提供任何写操作。对外返回的成员
//! metadata、目标错误文本和连接凭据均不会暴露；管理界面只需要租约、状态
//! 和固定错误代码即可完成诊断。

use crate::{
    ha_coordination::{HaMember, LeadershipLease},
    ha_runtime::{HaRuntime, HaRuntimeEvent},
    job_leases::JobLease,
    public_port_ownership::PublicPortLease,
    storage::StorageBackend,
    target_health::TargetHealth,
};
use serde::Serialize;

const RECENT_EVENT_LIMIT: usize = 24;

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HaMode {
    SqliteSingleInstance,
    PostgresHa,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct HaOverview {
    pub(crate) mode: HaMode,
    pub(crate) backend: StorageBackend,
    pub(crate) replicated_state: bool,
    pub(crate) generated_unix_seconds: u64,
    pub(crate) instance_id: String,
    pub(crate) incarnation_id: String,
    pub(crate) local_is_leader: bool,
    pub(crate) local_fencing_token: Option<u64>,
    pub(crate) member_lease: Option<HaMemberView>,
    pub(crate) current_leader: Option<LeadershipLeaseView>,
    pub(crate) members: Vec<HaMemberView>,
    pub(crate) job_leases: Vec<JobLeaseView>,
    pub(crate) port_ownership: Vec<PublicPortLeaseView>,
    pub(crate) target_health: TargetHealthSummary,
    pub(crate) recent_events: Vec<HaEventView>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct HaMemberView {
    pub(crate) instance_id: String,
    pub(crate) incarnation_id: String,
    pub(crate) started_unix_seconds: u64,
    pub(crate) last_seen_unix_seconds: u64,
    pub(crate) lease_until_unix_seconds: u64,
    pub(crate) lease_remaining_seconds: u64,
    pub(crate) is_current_instance: bool,
    pub(crate) is_leader: bool,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct LeadershipLeaseView {
    pub(crate) instance_id: String,
    pub(crate) incarnation_id: String,
    pub(crate) fencing_token: u64,
    pub(crate) acquired_unix_seconds: u64,
    pub(crate) renewed_unix_seconds: u64,
    pub(crate) lease_until_unix_seconds: u64,
    pub(crate) lease_remaining_seconds: u64,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct JobLeaseView {
    pub(crate) job_key: String,
    pub(crate) job_kind: String,
    pub(crate) lease_id: String,
    pub(crate) owner_instance_id: String,
    pub(crate) owner_incarnation_id: String,
    pub(crate) fencing_token: u64,
    pub(crate) acquired_unix_seconds: u64,
    pub(crate) renewed_unix_seconds: u64,
    pub(crate) lease_until_unix_seconds: u64,
    pub(crate) lease_remaining_seconds: u64,
    pub(crate) last_completed_unix_seconds: Option<u64>,
    pub(crate) last_error_code: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct PublicPortLeaseView {
    pub(crate) protocol: String,
    pub(crate) public_port: u16,
    pub(crate) lease_id: String,
    pub(crate) owner_instance_id: String,
    pub(crate) owner_incarnation_id: String,
    pub(crate) fencing_token: u64,
    pub(crate) policy_id: String,
    pub(crate) acquired_unix_seconds: u64,
    pub(crate) renewed_unix_seconds: u64,
    pub(crate) lease_until_unix_seconds: u64,
    pub(crate) lease_remaining_seconds: u64,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct TargetHealthView {
    pub(crate) target_key: String,
    pub(crate) member_alive: bool,
    pub(crate) control_channel_healthy: bool,
    pub(crate) application_healthy: bool,
    pub(crate) effective_healthy: bool,
    pub(crate) consecutive_successes: u32,
    pub(crate) consecutive_failures: u32,
    pub(crate) weight: u32,
    pub(crate) revision: u64,
    pub(crate) last_probe_unix_seconds: Option<u64>,
    pub(crate) last_transition_unix_seconds: u64,
    pub(crate) has_error: bool,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct TargetHealthSummary {
    pub(crate) total: usize,
    pub(crate) healthy: usize,
    pub(crate) unhealthy: usize,
    pub(crate) with_errors: usize,
    pub(crate) targets: Vec<TargetHealthView>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct HaEventView {
    pub(crate) at_unix_seconds: u64,
    pub(crate) code: String,
    pub(crate) severity: String,
    pub(crate) message: String,
    pub(crate) fencing_token: Option<u64>,
}

pub(crate) async fn collect(runtime: &HaRuntime) -> anyhow::Result<HaOverview> {
    let now = runtime
        .coordinator()
        .storage()
        .database_unix_seconds()
        .await?;
    let members = runtime.coordinator().active_members().await?;
    let leader = runtime.coordinator().current_leader().await?;
    let jobs = runtime.jobs().active().await?;
    let ports = runtime.public_ports().active().await?;
    let targets = runtime.target_health().list().await?;
    let current_instance_id = runtime.coordinator().instance_id().to_owned();
    let current_incarnation_id = runtime.coordinator().incarnation_id().to_owned();
    let local_is_leader = runtime.is_leader();
    let local_fencing_token = runtime.leadership().map(|lease| lease.fencing_token);
    let members = members
        .iter()
        .map(|member| {
            member_view(
                member,
                now,
                &current_instance_id,
                &current_incarnation_id,
                &leader,
            )
        })
        .collect::<Vec<_>>();
    let member_lease = members
        .iter()
        .find(|member| member.is_current_instance)
        .cloned();
    let target_views = targets.iter().map(target_view).collect::<Vec<_>>();
    let healthy = target_views
        .iter()
        .filter(|target| target.effective_healthy)
        .count();
    let with_errors = target_views
        .iter()
        .filter(|target| target.has_error)
        .count();
    Ok(HaOverview {
        mode: match runtime.coordinator().backend() {
            StorageBackend::Sqlite => HaMode::SqliteSingleInstance,
            StorageBackend::Postgres => HaMode::PostgresHa,
        },
        backend: runtime.coordinator().backend(),
        replicated_state: runtime.coordinator().backend() == StorageBackend::Postgres,
        generated_unix_seconds: now,
        instance_id: current_instance_id,
        incarnation_id: current_incarnation_id,
        local_is_leader,
        local_fencing_token,
        member_lease,
        current_leader: leader.as_ref().map(|lease| leadership_view(lease, now)),
        members,
        job_leases: jobs
            .iter()
            .map(|job| job_view(job, now))
            .collect::<Vec<_>>(),
        port_ownership: ports
            .iter()
            .map(|port| port_view(port, now))
            .collect::<Vec<_>>(),
        target_health: TargetHealthSummary {
            total: target_views.len(),
            healthy,
            unhealthy: target_views.len().saturating_sub(healthy),
            with_errors,
            targets: target_views,
        },
        recent_events: runtime
            .recent_events(RECENT_EVENT_LIMIT)
            .into_iter()
            .map(event_view)
            .collect(),
    })
}

fn member_view(
    member: &HaMember,
    now: u64,
    current_instance_id: &str,
    current_incarnation_id: &str,
    leader: &Option<LeadershipLease>,
) -> HaMemberView {
    HaMemberView {
        instance_id: member.instance_id.clone(),
        incarnation_id: member.incarnation_id.clone(),
        started_unix_seconds: member.started_unix_seconds,
        last_seen_unix_seconds: member.last_seen_unix_seconds,
        lease_until_unix_seconds: member.lease_until_unix_seconds,
        lease_remaining_seconds: member.lease_until_unix_seconds.saturating_sub(now),
        is_current_instance: member.instance_id == current_instance_id
            && member.incarnation_id == current_incarnation_id,
        is_leader: leader.as_ref().is_some_and(|current| {
            current.instance_id == member.instance_id
                && current.incarnation_id == member.incarnation_id
        }),
    }
}

fn leadership_view(lease: &LeadershipLease, now: u64) -> LeadershipLeaseView {
    LeadershipLeaseView {
        instance_id: lease.instance_id.clone(),
        incarnation_id: lease.incarnation_id.clone(),
        fencing_token: lease.fencing_token,
        acquired_unix_seconds: lease.acquired_unix_seconds,
        renewed_unix_seconds: lease.renewed_unix_seconds,
        lease_until_unix_seconds: lease.lease_until_unix_seconds,
        lease_remaining_seconds: lease.lease_until_unix_seconds.saturating_sub(now),
    }
}

fn job_view(job: &JobLease, now: u64) -> JobLeaseView {
    JobLeaseView {
        job_key: job.job_key.clone(),
        job_kind: job.job_kind.clone(),
        lease_id: job.lease_id.to_string(),
        owner_instance_id: job.owner_instance_id.clone(),
        owner_incarnation_id: job.owner_incarnation_id.clone(),
        fencing_token: job.fencing_token,
        acquired_unix_seconds: job.acquired_unix_seconds,
        renewed_unix_seconds: job.renewed_unix_seconds,
        lease_until_unix_seconds: job.lease_until_unix_seconds,
        lease_remaining_seconds: job.lease_until_unix_seconds.saturating_sub(now),
        last_completed_unix_seconds: job.last_completed_unix_seconds,
        last_error_code: job.last_error_code.clone(),
    }
}

fn port_view(port: &PublicPortLease, now: u64) -> PublicPortLeaseView {
    PublicPortLeaseView {
        protocol: port.protocol.as_str().to_owned(),
        public_port: port.public_port,
        lease_id: port.lease_id.to_string(),
        owner_instance_id: port.owner_instance_id.clone(),
        owner_incarnation_id: port.owner_incarnation_id.clone(),
        fencing_token: port.fencing_token,
        policy_id: port.policy_id.to_string(),
        acquired_unix_seconds: port.acquired_unix_seconds,
        renewed_unix_seconds: port.renewed_unix_seconds,
        lease_until_unix_seconds: port.lease_until_unix_seconds,
        lease_remaining_seconds: port.lease_until_unix_seconds.saturating_sub(now),
    }
}

fn target_view(target: &TargetHealth) -> TargetHealthView {
    TargetHealthView {
        target_key: target.target_key.clone(),
        member_alive: target.member_alive,
        control_channel_healthy: target.control_channel_healthy,
        application_healthy: target.application_healthy,
        effective_healthy: target.effective_healthy,
        consecutive_successes: target.consecutive_successes,
        consecutive_failures: target.consecutive_failures,
        weight: target.weight,
        revision: target.revision,
        last_probe_unix_seconds: target.last_probe_unix_seconds,
        last_transition_unix_seconds: target.last_transition_unix_seconds,
        has_error: target.last_error_summary.is_some(),
    }
}

fn event_view(event: HaRuntimeEvent) -> HaEventView {
    HaEventView {
        at_unix_seconds: event.at_unix_seconds,
        code: event.code,
        severity: event.severity,
        message: event.message,
        fencing_token: event.fencing_token,
    }
}
