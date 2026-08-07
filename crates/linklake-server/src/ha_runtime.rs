//! HA 运行时配置、成员心跳与 Leader 租约状态。

use crate::{
    fleet_coordination::FleetCoordination,
    ha_coordination::{HaCoordinator, HaMember, LeadershipLease},
    job_leases::JobLeases,
    public_port_ownership::PublicPortOwnership,
    storage::CoordinationStorage,
    target_health::TargetHealthCatalog,
};
use std::{
    env,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    sync::watch,
    time::{interval_at, timeout, Instant, MissedTickBehavior},
};

pub(crate) const HA_INSTANCE_ID_ENV: &str = "LINKLAKE_HA_INSTANCE_ID";
pub(crate) const HA_METADATA_JSON_ENV: &str = "LINKLAKE_HA_METADATA_JSON";
pub(crate) const HA_MEMBER_LEASE_ENV: &str = "LINKLAKE_HA_MEMBER_LEASE_SECONDS";
pub(crate) const HA_LEADER_LEASE_ENV: &str = "LINKLAKE_HA_LEADER_LEASE_SECONDS";
pub(crate) const HA_HEARTBEAT_ENV: &str = "LINKLAKE_HA_HEARTBEAT_SECONDS";
pub(crate) const HA_RESOURCE_LEASE_ENV: &str = "LINKLAKE_HA_RESOURCE_LEASE_SECONDS";
pub(crate) const HA_JOB_LEASE_ENV: &str = "LINKLAKE_HA_JOB_LEASE_SECONDS";
pub(crate) const TARGET_SUCCESS_THRESHOLD_ENV: &str = "LINKLAKE_TARGET_HEALTH_SUCCESS_THRESHOLD";
pub(crate) const TARGET_FAILURE_THRESHOLD_ENV: &str = "LINKLAKE_TARGET_HEALTH_FAILURE_THRESHOLD";
pub(crate) const TARGET_STALE_AFTER_ENV: &str = "LINKLAKE_TARGET_HEALTH_STALE_SECONDS";

const DEFAULT_MEMBER_LEASE_SECONDS: u64 = 30;
const DEFAULT_LEADER_LEASE_SECONDS: u64 = 15;
const DEFAULT_HEARTBEAT_SECONDS: u64 = 5;
const DEFAULT_RESOURCE_LEASE_SECONDS: u64 = 15;
const DEFAULT_JOB_LEASE_SECONDS: u64 = 30;
const DEFAULT_TARGET_SUCCESS_THRESHOLD: u32 = 2;
const DEFAULT_TARGET_FAILURE_THRESHOLD: u32 = 3;
const DEFAULT_TARGET_STALE_AFTER_SECONDS: u64 = 30;

#[derive(Clone, Debug)]
pub(crate) struct HaRuntimeConfig {
    instance_id: String,
    metadata_json: String,
    member_lease: Duration,
    leader_lease: Duration,
    heartbeat: Duration,
    resource_lease: Duration,
    job_lease: Duration,
    target_success_threshold: u32,
    target_failure_threshold: u32,
    target_stale_after: Duration,
}

impl HaRuntimeConfig {
    pub(crate) fn from_environment(default_instance_id: &str) -> anyhow::Result<Self> {
        let instance_id = env::var(HA_INSTANCE_ID_ENV)
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| default_instance_id.to_owned());
        let metadata_json = env::var(HA_METADATA_JSON_ENV)
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "{}".to_owned());
        let member_lease =
            parse_duration(HA_MEMBER_LEASE_ENV, DEFAULT_MEMBER_LEASE_SECONDS, 5, 300)?;
        let leader_lease =
            parse_duration(HA_LEADER_LEASE_ENV, DEFAULT_LEADER_LEASE_SECONDS, 3, 120)?;
        let heartbeat = parse_duration(HA_HEARTBEAT_ENV, DEFAULT_HEARTBEAT_SECONDS, 1, 60)?;
        let resource_lease = parse_duration(
            HA_RESOURCE_LEASE_ENV,
            DEFAULT_RESOURCE_LEASE_SECONDS,
            2,
            300,
        )?;
        let job_lease = parse_duration(HA_JOB_LEASE_ENV, DEFAULT_JOB_LEASE_SECONDS, 2, 300)?;
        anyhow::ensure!(
            leader_lease <= member_lease,
            "HA leader lease must not exceed member lease"
        );
        anyhow::ensure!(
            heartbeat < leader_lease
                && heartbeat < member_lease
                && heartbeat < resource_lease
                && heartbeat < job_lease,
            "HA heartbeat must be shorter than member, leader, resource, and job leases"
        );
        let target_success_threshold = parse_u32(
            TARGET_SUCCESS_THRESHOLD_ENV,
            DEFAULT_TARGET_SUCCESS_THRESHOLD,
            1,
            1_000,
        )?;
        let target_failure_threshold = parse_u32(
            TARGET_FAILURE_THRESHOLD_ENV,
            DEFAULT_TARGET_FAILURE_THRESHOLD,
            1,
            1_000,
        )?;
        let target_stale_after = parse_duration(
            TARGET_STALE_AFTER_ENV,
            DEFAULT_TARGET_STALE_AFTER_SECONDS,
            1,
            86_400,
        )?;
        Ok(Self {
            instance_id,
            metadata_json,
            member_lease,
            leader_lease,
            heartbeat,
            resource_lease,
            job_lease,
            target_success_threshold,
            target_failure_threshold,
            target_stale_after,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LeadershipTransition {
    Gained,
    Retained,
    Lost,
    Follower,
}

#[derive(Clone)]
pub(crate) struct HaRuntime {
    coordinator: HaCoordinator,
    public_ports: PublicPortOwnership,
    jobs: JobLeases,
    target_health: TargetHealthCatalog,
    fleet: FleetCoordination,
    leadership_tx: watch::Sender<Option<LeadershipLease>>,
    leader: Arc<AtomicBool>,
    fencing_token: Arc<AtomicU64>,
    heartbeat: Duration,
}

impl HaRuntime {
    pub(crate) fn open(
        storage: CoordinationStorage,
        config: HaRuntimeConfig,
    ) -> anyhow::Result<Self> {
        let coordinator = HaCoordinator::open(
            storage,
            config.instance_id,
            config.metadata_json,
            config.member_lease,
            config.leader_lease,
        )?;
        let public_ports = PublicPortOwnership::open(coordinator.clone(), config.resource_lease)?;
        let jobs = JobLeases::open(coordinator.clone(), config.job_lease)?;
        let target_health = TargetHealthCatalog::open(
            coordinator.clone(),
            config.target_success_threshold,
            config.target_failure_threshold,
            config.target_stale_after,
        )?;
        let fleet = FleetCoordination::open(coordinator.clone())?;
        let (leadership_tx, _) = watch::channel(None);
        Ok(Self {
            coordinator,
            public_ports,
            jobs,
            target_health,
            fleet,
            leadership_tx,
            leader: Arc::new(AtomicBool::new(false)),
            fencing_token: Arc::new(AtomicU64::new(0)),
            heartbeat: config.heartbeat,
        })
    }

    pub(crate) async fn bootstrap(&self) -> anyhow::Result<(HaMember, LeadershipTransition)> {
        let member = self.coordinator.register_or_renew_member().await?;
        let leadership = self.coordinator.try_acquire_leadership().await?;
        let transition = if leadership.is_some() {
            LeadershipTransition::Gained
        } else {
            LeadershipTransition::Follower
        };
        self.publish_leadership(leadership);
        Ok((member, transition))
    }

    pub(crate) async fn refresh(&self) -> anyhow::Result<LeadershipTransition> {
        self.coordinator.register_or_renew_member().await?;
        let previous = self.leadership();
        let next = match previous.as_ref() {
            Some(lease) => {
                self.coordinator
                    .renew_leadership(lease.fencing_token)
                    .await?
            }
            None => self.coordinator.try_acquire_leadership().await?,
        };
        let transition = match (previous.is_some(), next.is_some()) {
            (false, false) => LeadershipTransition::Follower,
            (false, true) => LeadershipTransition::Gained,
            (true, false) => LeadershipTransition::Lost,
            (true, true) => LeadershipTransition::Retained,
        };
        self.publish_leadership(next);
        Ok(transition)
    }

    pub(crate) async fn supervise(&self, mut shutdown: watch::Receiver<bool>) {
        let mut heartbeat = interval_at(Instant::now() + self.heartbeat, self.heartbeat);
        heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        self.clear_leadership();
                        break;
                    }
                }
                _ = heartbeat.tick() => {
                    match timeout(self.heartbeat, self.refresh()).await {
                        Ok(Ok(transition)) => {
                            if matches!(transition, LeadershipTransition::Gained | LeadershipTransition::Lost) {
                                tracing::info!(?transition, "HA leadership changed");
                            }
                        }
                        Ok(Err(error)) => {
                            let lost = self.clear_leadership();
                            tracing::warn!(lost_leadership = lost, "HA heartbeat failed closed: {error}");
                        }
                        Err(_) => {
                            let lost = self.clear_leadership();
                            tracing::warn!(lost_leadership = lost, "HA heartbeat timed out and leadership was cleared");
                        }
                    }
                }
            }
        }
    }

    pub(crate) fn clear_leadership(&self) -> bool {
        let had_leadership = self.leader.swap(false, Ordering::AcqRel);
        self.fencing_token.store(0, Ordering::Release);
        self.leadership_tx.send_replace(None);
        had_leadership
    }

    pub(crate) fn subscribe_leadership(&self) -> watch::Receiver<Option<LeadershipLease>> {
        self.leadership_tx.subscribe()
    }

    pub(crate) fn is_leader(&self) -> bool {
        self.leader.load(Ordering::Acquire)
    }

    pub(crate) fn leadership(&self) -> Option<LeadershipLease> {
        self.leadership_tx.borrow().clone()
    }

    pub(crate) fn fencing_token(&self) -> anyhow::Result<u64> {
        let token = self.fencing_token.load(Ordering::Acquire);
        anyhow::ensure!(
            self.is_leader() && token > 0,
            "this LinkLake instance is not the active HA leader"
        );
        Ok(token)
    }

    pub(crate) fn heartbeat(&self) -> Duration {
        self.heartbeat
    }

    pub(crate) fn coordinator(&self) -> &HaCoordinator {
        &self.coordinator
    }

    pub(crate) fn public_ports(&self) -> &PublicPortOwnership {
        &self.public_ports
    }

    pub(crate) fn jobs(&self) -> &JobLeases {
        &self.jobs
    }

    pub(crate) fn target_health(&self) -> &TargetHealthCatalog {
        &self.target_health
    }

    pub(crate) fn fleet(&self) -> &FleetCoordination {
        &self.fleet
    }

    fn publish_leadership(&self, leadership: Option<LeadershipLease>) {
        match leadership {
            Some(lease) => {
                let fencing_token = lease.fencing_token;
                self.leadership_tx.send_replace(Some(lease));
                self.fencing_token.store(fencing_token, Ordering::Release);
                self.leader.store(true, Ordering::Release);
            }
            None => {
                self.clear_leadership();
            }
        }
    }
}

fn parse_duration(
    name: &str,
    default_seconds: u64,
    minimum_seconds: u64,
    maximum_seconds: u64,
) -> anyhow::Result<Duration> {
    let seconds = env::var(name)
        .ok()
        .map(|value| value.trim().parse::<u64>())
        .transpose()
        .map_err(|_| anyhow::anyhow!("{name} must be an integer"))?
        .unwrap_or(default_seconds);
    anyhow::ensure!(
        (minimum_seconds..=maximum_seconds).contains(&seconds),
        "{name} must be between {minimum_seconds} and {maximum_seconds} seconds"
    );
    Ok(Duration::from_secs(seconds))
}

fn parse_u32(name: &str, default_value: u32, minimum: u32, maximum: u32) -> anyhow::Result<u32> {
    let value = env::var(name)
        .ok()
        .map(|value| value.trim().parse::<u32>())
        .transpose()
        .map_err(|_| anyhow::anyhow!("{name} must be an integer"))?
        .unwrap_or(default_value);
    anyhow::ensure!(
        (minimum..=maximum).contains(&value),
        "{name} must be between {minimum} and {maximum}"
    );
    Ok(value)
}
