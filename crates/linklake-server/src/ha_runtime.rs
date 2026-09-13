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
    collections::VecDeque,
    env,
    future::Future,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
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
const RUNTIME_EVENT_CAPACITY: usize = 64;
const EXPIRED_LEASE_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Clone, Debug)]
pub(crate) struct HaRuntimeEvent {
    pub(crate) at_unix_seconds: u64,
    pub(crate) code: String,
    pub(crate) severity: String,
    pub(crate) message: String,
    pub(crate) fencing_token: Option<u64>,
}

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
    events: Arc<Mutex<VecDeque<HaRuntimeEvent>>>,
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
            events: Arc::new(Mutex::new(VecDeque::with_capacity(RUNTIME_EVENT_CAPACITY))),
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
        if let Some(lease) = self.leadership() {
            self.record_event(
                "leader_acquired",
                "info",
                "HA leadership acquired",
                Some(lease.fencing_token),
            );
        } else {
            self.record_event(
                "follower_started",
                "info",
                "HA instance is a follower",
                None,
            );
        }
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
        match transition {
            LeadershipTransition::Gained => {
                self.record_event(
                    "leader_acquired",
                    "info",
                    "HA leadership acquired",
                    self.leadership().map(|lease| lease.fencing_token),
                );
            }
            LeadershipTransition::Lost => {
                self.record_event(
                    "leader_lost",
                    "warning",
                    "HA leadership was lost and mutating work is fenced",
                    previous.map(|lease| lease.fencing_token),
                );
            }
            LeadershipTransition::Retained | LeadershipTransition::Follower => {}
        }
        Ok(transition)
    }

    pub(crate) async fn supervise(&self, shutdown: watch::Receiver<bool>) {
        self.supervise_with_maintenance(
            shutdown.clone(),
            self.maintain_expired_leases(shutdown, EXPIRED_LEASE_MAINTENANCE_INTERVAL),
        )
        .await;
    }

    async fn supervise_with_maintenance(
        &self,
        shutdown: watch::Receiver<bool>,
        maintenance: impl Future<Output = ()>,
    ) {
        // 两条分支独立推进；join 保证停机时收尾维护，不遗留后台数据库写入。
        tokio::join!(self.supervise_heartbeats(shutdown), maintenance);
    }

    async fn supervise_heartbeats(&self, shutdown: watch::Receiver<bool>) {
        tokio::select! {
            biased;
            _ = wait_for_shutdown(shutdown) => {}
            _ = self.run_heartbeats() => {}
        }
        // 先退出租约状态，再由外层 join 等待当前有界维护批次完成。
        self.clear_leadership();
    }

    async fn run_heartbeats(&self) {
        let mut heartbeat = interval_at(Instant::now() + self.heartbeat, self.heartbeat);
        heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            heartbeat.tick().await;
            match timeout(self.heartbeat, self.refresh()).await {
                Ok(Ok(transition)) => {
                    if matches!(
                        transition,
                        LeadershipTransition::Gained | LeadershipTransition::Lost
                    ) {
                        tracing::info!(?transition, "HA leadership changed");
                    }
                }
                Ok(Err(error)) => {
                    let lost = self.clear_leadership();
                    self.record_event(
                        "heartbeat_failed",
                        "warning",
                        "HA heartbeat failed; leadership was cleared",
                        None,
                    );
                    tracing::warn!(
                        lost_leadership = lost,
                        "HA heartbeat failed closed: {error}"
                    );
                }
                Err(_) => {
                    let lost = self.clear_leadership();
                    self.record_event(
                        "heartbeat_timeout",
                        "warning",
                        "HA heartbeat timed out; leadership was cleared",
                        None,
                    );
                    tracing::warn!(
                        lost_leadership = lost,
                        "HA heartbeat timed out and leadership was cleared"
                    );
                }
            }
        }
    }

    async fn maintain_expired_leases(&self, shutdown: watch::Receiver<bool>, period: Duration) {
        let mut maintenance = interval_at(Instant::now() + period, period);
        maintenance.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                biased;
                _ = wait_for_shutdown(shutdown.clone()) => break,
                _ = maintenance.tick() => {}
            }
            if !self.is_leader() {
                continue;
            }
            if self.coordinator.prune_expired_members().await.is_err() {
                self.record_maintenance_failure("members");
            }
            // 停机或失去 Leader 后不再启动下一批；正在运行的批次必须完成收尾。
            if shutdown_requested(&shutdown) {
                break;
            }
            if self.is_leader() && self.public_ports.prune_expired().await.is_err() {
                self.record_maintenance_failure("public_ports");
            }
        }
    }

    fn record_maintenance_failure(&self, resource: &'static str) {
        self.record_event(
            "lease_maintenance_failed",
            "warning",
            "Expired HA lease maintenance batch failed",
            None,
        );
        // 不记录数据库错误正文，避免泄露连接信息或存储路径。
        tracing::warn!(resource, "Expired HA lease maintenance batch failed");
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

    pub(crate) fn recent_events(&self, limit: usize) -> Vec<HaRuntimeEvent> {
        self.events
            .lock()
            .expect("HA runtime event history lock poisoned")
            .iter()
            .take(limit)
            .cloned()
            .collect()
    }

    fn record_event(&self, code: &str, severity: &str, message: &str, fencing_token: Option<u64>) {
        let mut events = self
            .events
            .lock()
            .expect("HA runtime event history lock poisoned");
        events.push_front(HaRuntimeEvent {
            at_unix_seconds: unix_seconds(),
            code: code.to_owned(),
            severity: severity.to_owned(),
            message: message.to_owned(),
            fencing_token,
        });
        while events.len() > RUNTIME_EVENT_CAPACITY {
            events.pop_back();
        }
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

fn shutdown_requested(shutdown: &watch::Receiver<bool>) -> bool {
    *shutdown.borrow() || shutdown.has_changed().is_err()
}

async fn wait_for_shutdown(mut shutdown: watch::Receiver<bool>) {
    while !shutdown_requested(&shutdown) {
        if shutdown.changed().await.is_err() {
            break;
        }
    }
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
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

#[cfg(test)]
mod maintenance_tests {
    use super::*;
    use crate::database::Database;
    use tokio::sync::oneshot;

    async fn runtime_fixture() -> (Database, HaRuntime) {
        let database = Database::memory().expect("database should open");
        let runtime = HaRuntime::open(
            CoordinationStorage::Sqlite(database.clone()),
            HaRuntimeConfig {
                instance_id: "maintenance-runtime".to_owned(),
                metadata_json: "{}".to_owned(),
                member_lease: Duration::from_secs(300),
                leader_lease: Duration::from_secs(120),
                // 心跳刷新会同步执行 SQLite 写事务；测试使用更宽的专用期限，
                // 避免正常调度和写锁抖动被误判为租约丢失。
                heartbeat: Duration::from_millis(250),
                resource_lease: Duration::from_secs(60),
                job_lease: Duration::from_secs(60),
                target_success_threshold: 2,
                target_failure_threshold: 3,
                target_stale_after: Duration::from_secs(30),
            },
        )
        .expect("runtime should open");
        runtime.bootstrap().await.expect("runtime should bootstrap");
        assert!(runtime.is_leader());
        database
            .with_connection(|connection| {
                connection.execute_batch(
                    "CREATE TABLE maintenance_heartbeat_probe (renewals INTEGER NOT NULL);
                     INSERT INTO maintenance_heartbeat_probe VALUES (0);
                     CREATE TRIGGER maintenance_heartbeat_probe_count
                     AFTER UPDATE ON ha_members BEGIN
                         UPDATE maintenance_heartbeat_probe SET renewals = renewals + 1;
                     END;",
                )?;
                Ok(())
            })
            .expect("heartbeat probe should install");
        (database, runtime)
    }

    async fn wait_for_heartbeats(database: &Database) {
        timeout(Duration::from_secs(5), async {
            loop {
                let renewals: i64 = database
                    .with_connection(|connection| {
                        Ok(connection.query_row(
                            "SELECT renewals FROM maintenance_heartbeat_probe",
                            [],
                            |row| row.get(0),
                        )?)
                    })
                    .expect("heartbeat probe should read");
                if renewals >= 2 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("heartbeats should continue during maintenance");
    }

    #[tokio::test]
    async fn slow_maintenance_does_not_block_heartbeats_or_leadership_exit() {
        let (database, runtime) = runtime_fixture().await;
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (started_tx, started_rx) = oneshot::channel();
        let (finish_tx, finish_rx) = oneshot::channel();
        let completed = Arc::new(AtomicBool::new(false));
        let worker = runtime.clone();
        let worker_completed = completed.clone();
        let supervision = tokio::spawn(async move {
            worker
                .supervise_with_maintenance(shutdown_rx, async move {
                    started_tx
                        .send(())
                        .expect("maintenance should announce start");
                    finish_rx
                        .await
                        .expect("maintenance should finish its batch");
                    worker_completed.store(true, Ordering::SeqCst);
                })
                .await;
        });
        started_rx.await.expect("maintenance should start");
        wait_for_heartbeats(&database).await;
        assert!(runtime.is_leader());
        let mut leadership = runtime.subscribe_leadership();
        shutdown_tx.send(true).expect("shutdown should signal");
        drop(
            timeout(
                Duration::from_secs(2),
                leadership.wait_for(|lease| lease.is_none()),
            )
            .await
            .expect("leadership should exit before maintenance finishes")
            .expect("leadership channel should stay open"),
        );
        assert!(runtime.fencing_token().is_err());
        assert!(!supervision.is_finished());
        assert!(!completed.load(Ordering::SeqCst));
        finish_tx
            .send(())
            .expect("maintenance should be allowed to finish");
        timeout(Duration::from_secs(2), supervision)
            .await
            .expect("shutdown should join completed maintenance")
            .expect("supervision should finish cleanly");
        assert!(completed.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn maintenance_failure_keeps_heartbeats_and_does_not_clear_leadership() {
        let (database, runtime) = runtime_fixture().await;
        database
            .with_connection(|connection| {
                connection.execute_batch(
                    "INSERT INTO ha_members(instance_id, incarnation_id,
                         started_unix_seconds, last_seen_unix_seconds,
                         lease_until_unix_seconds, metadata_json)
                     VALUES ('expired-maintenance', 'expired-incarnation', 0, 0, 0, '{}');
                     DROP TABLE public_port_ownership;",
                )?;
                Ok(())
            })
            .expect("maintenance success and failure cases should seed");
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let worker = runtime.clone();
        let supervision = tokio::spawn(async move {
            worker
                .supervise_with_maintenance(
                    shutdown_rx.clone(),
                    worker.maintain_expired_leases(shutdown_rx, Duration::from_millis(100)),
                )
                .await;
        });
        timeout(Duration::from_secs(5), async {
            while !runtime
                .recent_events(64)
                .iter()
                .any(|event| event.code == "lease_maintenance_failed")
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("maintenance should record its failure");
        wait_for_heartbeats(&database).await;
        assert!(runtime.is_leader());
        assert!(!runtime
            .recent_events(64)
            .iter()
            .any(|event| event.code == "heartbeat_failed" || event.code == "heartbeat_timeout"));
        let members: i64 =
            database
                .with_connection(|connection| {
                    Ok(connection
                        .query_row("SELECT COUNT(*) FROM ha_members", [], |row| row.get(0))?)
                })
                .expect("members should count");
        assert_eq!(
            members, 1,
            "the working cleanup batch should remove the expired member"
        );
        shutdown_tx.send(true).expect("shutdown should signal");
        timeout(Duration::from_secs(2), supervision)
            .await
            .expect("maintenance should stop on shutdown")
            .expect("supervision should finish cleanly");
        assert!(!runtime.is_leader());
    }

    #[tokio::test]
    async fn already_requested_shutdown_starts_no_maintenance() {
        let (database, runtime) = runtime_fixture().await;
        let (_shutdown_tx, shutdown_rx) = watch::channel(true);
        timeout(Duration::from_secs(2), runtime.supervise(shutdown_rx))
            .await
            .expect("existing shutdown should be observed immediately");
        assert!(!runtime.is_leader());
        let renewals: i64 = database
            .with_connection(|connection| {
                Ok(connection.query_row(
                    "SELECT renewals FROM maintenance_heartbeat_probe",
                    [],
                    |row| row.get(0),
                )?)
            })
            .expect("heartbeat probe should read");
        assert_eq!(renewals, 0);
    }
}
