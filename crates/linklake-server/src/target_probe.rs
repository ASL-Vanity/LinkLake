//! 由服务端编排、客户端就地执行的目标健康探针。

use crate::{target_health::TargetHealthObservation, AppState};
use linklake_core::{
    target_pool::parse_target_pool, ControlFrame, TargetHealthProbeKind, TargetHealthProbeRequest,
    TargetHealthProbeResult,
};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::{mpsc, watch},
    time::{interval, timeout, MissedTickBehavior},
};
use uuid::Uuid;

const TARGET_PROBE_INTERVAL: Duration = Duration::from_secs(10);
const TARGET_PROBE_TIMEOUT_MILLIS: u32 = 3_000;
const TARGET_PROBE_SEND_TIMEOUT: Duration = Duration::from_secs(2);
const TARGET_PROBE_RESULT_GRACE: Duration = Duration::from_secs(2);
const TARGET_PROBE_RECORD_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_COORDINATION_REVISION: u64 = i64::MAX as u64;

static NEXT_PROBE_REVISION: AtomicU64 = AtomicU64::new(0);

#[derive(Clone)]
pub(crate) struct TargetProbeSet {
    policy_id: Uuid,
    policy_kind: &'static str,
    kind: TargetHealthProbeKind,
    server_name: Option<String>,
    targets: Arc<HashMap<String, ProbeTarget>>,
    outstanding: Arc<Mutex<HashMap<Uuid, OutstandingProbe>>>,
    expected_fencing_token: Arc<AtomicU64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProbeTarget {
    address: String,
    weight: u32,
}

#[derive(Clone, Debug)]
struct OutstandingProbe {
    target_key: String,
    target_addr: String,
    revision: u64,
    expires_at: Instant,
}

impl TargetProbeSet {
    pub(crate) fn new(
        policy_id: Uuid,
        policy_kind: &'static str,
        target_pool: &str,
        kind: TargetHealthProbeKind,
        server_name: Option<String>,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !policy_id.is_nil(),
            "target probe policy id must not be nil"
        );
        validate_probe_semantics(policy_kind, kind, server_name.as_deref())?;
        let mut targets = HashMap::new();
        for target in parse_target_pool(target_pool)? {
            let key = format!("{policy_kind}:{policy_id}:{}", target.address);
            anyhow::ensure!(key.len() <= 256, "target health key is too long");
            anyhow::ensure!(
                targets
                    .insert(
                        key,
                        ProbeTarget {
                            address: target.address,
                            weight: target.weight,
                        },
                    )
                    .is_none(),
                "target pool contains a duplicate address"
            );
        }
        anyhow::ensure!(!targets.is_empty(), "target probe set is empty");
        Ok(Self {
            policy_id,
            policy_kind,
            kind,
            server_name,
            targets: Arc::new(targets),
            outstanding: Arc::new(Mutex::new(HashMap::new())),
            expected_fencing_token: Arc::new(AtomicU64::new(0)),
        })
    }

    pub(crate) fn spawn_scheduler(
        &self,
        state: Arc<AppState>,
        command_tx: mpsc::Sender<ControlFrame>,
        stop: watch::Receiver<()>,
    ) -> anyhow::Result<tokio::task::JoinHandle<()>> {
        let fencing_token = state.ha_runtime.fencing_token()?;
        self.expected_fencing_token
            .compare_exchange(0, fencing_token, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| anyhow::anyhow!("target probe scheduler was already started"))?;
        let probe_set = self.clone();
        Ok(tokio::spawn(async move {
            if let Err(error) = probe_set
                .run_scheduler(state, command_tx, stop, fencing_token)
                .await
            {
                tracing::warn!(
                    policy_id = %probe_set.policy_id,
                    policy_kind = probe_set.policy_kind,
                    "Target health probe scheduler stopped: {error}"
                );
            }
        }))
    }

    async fn run_scheduler(
        &self,
        state: Arc<AppState>,
        command_tx: mpsc::Sender<ControlFrame>,
        mut stop: watch::Receiver<()>,
        fencing_token: u64,
    ) -> anyhow::Result<()> {
        let mut leadership = state.ha_runtime.subscribe_leadership();
        anyhow::ensure!(
            leadership
                .borrow()
                .as_ref()
                .is_some_and(|lease| lease.fencing_token == fencing_token),
            "target probe scheduler lost HA leadership before startup"
        );
        let mut revision_floors = HashMap::with_capacity(self.targets.len());
        for target_key in self.targets.keys() {
            let current = state
                .ha_runtime
                .target_health()
                .get(target_key)
                .await?
                .map(|health| health.revision)
                .unwrap_or(0);
            revision_floors.insert(target_key.clone(), current);
        }

        let mut ticker = interval(TARGET_PROBE_INTERVAL);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = stop.changed() => return Ok(()),
                changed = leadership.changed() => {
                    if changed.is_err()
                        || leadership
                            .borrow()
                            .as_ref()
                            .is_none_or(|lease| lease.fencing_token != fencing_token)
                    {
                        return Ok(());
                    }
                }
                _ = ticker.tick() => {
                    anyhow::ensure!(
                        state.ha_runtime.fencing_token().ok() == Some(fencing_token),
                        "target probe scheduler lost HA leadership"
                    );
                    self.expire_outstanding(Instant::now());
                    for (target_key, target) in self.targets.iter() {
                        let floor = revision_floors
                            .get(target_key)
                            .copied()
                            .unwrap_or(0);
                        let revision = allocate_revision(floor)?;
                        revision_floors.insert(target_key.clone(), revision);
                        let probe = TargetHealthProbeRequest {
                            probe_id: Uuid::new_v4(),
                            target_key: target_key.clone(),
                            target_addr: target.address.clone(),
                            kind: self.kind,
                            server_name: self.server_name.clone(),
                            timeout_millis: TARGET_PROBE_TIMEOUT_MILLIS,
                            revision,
                        };
                        self.track_probe(&probe, Instant::now())?;
                        let probe_id = probe.probe_id;
                        let sent = timeout(
                            TARGET_PROBE_SEND_TIMEOUT,
                            command_tx.send(ControlFrame::TargetHealthProbe { probe }),
                        )
                        .await;
                        if !matches!(sent, Ok(Ok(()))) {
                            self.cancel_probe(probe_id);
                            anyhow::bail!("target probe control queue is unavailable");
                        }
                    }
                }
            }
        }
    }

    pub(crate) async fn record_result(
        &self,
        state: &AppState,
        result: TargetHealthProbeResult,
    ) -> anyhow::Result<()> {
        let target = self.take_result(&result, Instant::now())?;
        let fencing_token = self.expected_fencing_token.load(Ordering::Acquire);
        anyhow::ensure!(
            fencing_token > 0 && state.ha_runtime.fencing_token().ok() == Some(fencing_token),
            "target health result belongs to a stale HA leadership term"
        );
        timeout(
            TARGET_PROBE_RECORD_TIMEOUT,
            state.ha_runtime.target_health().observe(
                TargetHealthObservation {
                    target_key: result.target_key,
                    member_alive: true,
                    control_channel_healthy: true,
                    application_healthy: result.healthy,
                    weight: target.weight,
                    revision: result.revision,
                    error_summary: result.error_summary,
                },
                fencing_token,
            ),
        )
        .await
        .map_err(|_| anyhow::anyhow!("target health persistence timed out"))??;
        Ok(())
    }

    pub(crate) fn policy_id(&self) -> Uuid {
        self.policy_id
    }

    fn track_probe(&self, probe: &TargetHealthProbeRequest, now: Instant) -> anyhow::Result<()> {
        let target = self
            .targets
            .get(&probe.target_key)
            .filter(|target| target.address == probe.target_addr)
            .ok_or_else(|| anyhow::anyhow!("target probe does not belong to this policy"))?;
        anyhow::ensure!(target.weight > 0, "target probe weight must be positive");
        anyhow::ensure!(
            probe.kind == self.kind,
            "target probe kind does not match policy"
        );
        anyhow::ensure!(
            probe.server_name == self.server_name,
            "target probe server name does not match policy"
        );
        anyhow::ensure!(probe.revision > 0, "target probe revision must be positive");
        let lifetime = Duration::from_millis(u64::from(probe.timeout_millis))
            .saturating_add(TARGET_PROBE_RESULT_GRACE);
        let outstanding = OutstandingProbe {
            target_key: probe.target_key.clone(),
            target_addr: probe.target_addr.clone(),
            revision: probe.revision,
            expires_at: now + lifetime,
        };
        let previous = self
            .outstanding
            .lock()
            .expect("target probe lock poisoned")
            .insert(probe.probe_id, outstanding);
        anyhow::ensure!(previous.is_none(), "target probe id was reused");
        Ok(())
    }

    fn take_result(
        &self,
        result: &TargetHealthProbeResult,
        now: Instant,
    ) -> anyhow::Result<ProbeTarget> {
        let expected = self
            .outstanding
            .lock()
            .expect("target probe lock poisoned")
            .remove(&result.probe_id)
            .ok_or_else(|| anyhow::anyhow!("target health result is unknown or was replayed"))?;
        anyhow::ensure!(
            now <= expected.expires_at,
            "target health result arrived after its deadline"
        );
        anyhow::ensure!(
            result.target_key == expected.target_key
                && result.target_addr == expected.target_addr
                && result.revision == expected.revision,
            "target health result does not match the outstanding probe"
        );
        self.targets
            .get(&expected.target_key)
            .filter(|target| target.address == expected.target_addr)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("target health result does not belong to this policy"))
    }

    fn expire_outstanding(&self, now: Instant) {
        self.outstanding
            .lock()
            .expect("target probe lock poisoned")
            .retain(|_, probe| probe.expires_at > now);
    }

    fn cancel_probe(&self, probe_id: Uuid) {
        self.outstanding
            .lock()
            .expect("target probe lock poisoned")
            .remove(&probe_id);
    }
}

fn validate_probe_semantics(
    policy_kind: &str,
    kind: TargetHealthProbeKind,
    server_name: Option<&str>,
) -> anyhow::Result<()> {
    let valid = match (policy_kind, kind, server_name) {
        ("tcp", TargetHealthProbeKind::Tcp, None) | ("udp", TargetHealthProbeKind::Udp, None) => {
            true
        }
        ("http", TargetHealthProbeKind::Http, Some(name))
        | ("sni", TargetHealthProbeKind::Tls, Some(name)) => !name.trim().is_empty(),
        _ => false,
    };
    anyhow::ensure!(valid, "target probe semantics do not match policy kind");
    Ok(())
}

fn allocate_revision(floor: u64) -> anyhow::Result<u64> {
    anyhow::ensure!(
        floor < MAX_COORDINATION_REVISION,
        "target health revision space is exhausted"
    );
    let wall_clock_floor = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(MAX_COORDINATION_REVISION)) as u64;
    let required = floor.saturating_add(1).max(wall_clock_floor).max(1);
    let mut current = NEXT_PROBE_REVISION.load(Ordering::Acquire);
    loop {
        let next = current.saturating_add(1).max(required);
        anyhow::ensure!(
            next <= MAX_COORDINATION_REVISION,
            "target health revision space is exhausted"
        );
        match NEXT_PROBE_REVISION.compare_exchange_weak(
            current,
            next,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return Ok(next),
            Err(observed) => current = observed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp_set() -> TargetProbeSet {
        TargetProbeSet::new(
            Uuid::parse_str("9bbfc6bd-78fc-4a75-a0cf-6a81d7cfa001").unwrap(),
            "tcp",
            "127.0.0.1:2333@2,127.0.0.1:2444",
            TargetHealthProbeKind::Tcp,
            None,
        )
        .unwrap()
    }

    fn tracked_probe(set: &TargetProbeSet) -> TargetHealthProbeRequest {
        let (target_key, target) = set.targets.iter().next().unwrap();
        let probe = TargetHealthProbeRequest {
            probe_id: Uuid::new_v4(),
            target_key: target_key.clone(),
            target_addr: target.address.clone(),
            kind: TargetHealthProbeKind::Tcp,
            server_name: None,
            timeout_millis: 3_000,
            revision: 41,
        };
        set.track_probe(&probe, Instant::now()).unwrap();
        probe
    }

    #[test]
    fn result_must_match_one_outstanding_probe_and_cannot_replay() {
        let set = tcp_set();
        let probe = tracked_probe(&set);
        let result = TargetHealthProbeResult {
            probe_id: probe.probe_id,
            target_key: probe.target_key,
            target_addr: probe.target_addr,
            revision: probe.revision,
            healthy: true,
            error_summary: None,
        };
        assert!(set.take_result(&result, Instant::now()).is_ok());
        assert!(set.take_result(&result, Instant::now()).is_err());
    }

    #[test]
    fn forged_result_consumes_and_invalidates_the_probe() {
        let set = tcp_set();
        let probe = tracked_probe(&set);
        let mut forged = TargetHealthProbeResult {
            probe_id: probe.probe_id,
            target_key: probe.target_key.clone(),
            target_addr: probe.target_addr.clone(),
            revision: probe.revision,
            healthy: true,
            error_summary: None,
        };
        forged.target_addr = "127.0.0.1:65535".to_owned();
        assert!(set.take_result(&forged, Instant::now()).is_err());
        forged.target_addr = probe.target_addr;
        assert!(set.take_result(&forged, Instant::now()).is_err());
    }

    #[test]
    fn policy_kind_probe_kind_and_server_name_are_bound() {
        let policy_id = Uuid::new_v4();
        assert!(TargetProbeSet::new(
            policy_id,
            "tcp",
            "127.0.0.1:80",
            TargetHealthProbeKind::Http,
            Some("example.com".to_owned()),
        )
        .is_err());
        assert!(TargetProbeSet::new(
            policy_id,
            "sni",
            "127.0.0.1:443",
            TargetHealthProbeKind::Tls,
            None,
        )
        .is_err());
        assert!(TargetProbeSet::new(
            policy_id,
            "sni",
            "127.0.0.1:443",
            TargetHealthProbeKind::Tls,
            Some("example.com".to_owned()),
        )
        .is_ok());
    }

    #[test]
    fn duplicate_targets_are_rejected_instead_of_silently_overwriting_weights() {
        assert!(TargetProbeSet::new(
            Uuid::new_v4(),
            "udp",
            "127.0.0.1:53@2,127.0.0.1:53@3",
            TargetHealthProbeKind::Udp,
            None,
        )
        .is_err());
    }
}
