//! Fleet 节点健康状态、探测迟滞与 DNS 故障切换。

use anyhow::Context;
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    net::{Ipv4Addr, Ipv6Addr},
    path::Path,
};
use uuid::Uuid;

use crate::database::Database;
use crate::fleet::FleetPeer;

const DEFAULT_SUCCESS_THRESHOLD: u16 = 2;
const DEFAULT_FAILURE_THRESHOLD: u16 = 3;
const DEFAULT_HEALTH_COOLDOWN_SECONDS: u32 = 30;
const DEFAULT_DNS_COOLDOWN_SECONDS: u32 = 60;
const DNS_OPERATION_LEASE_SECONDS: u64 = 30;
const MAX_ERROR_SUMMARY_CHARS: usize = 320;
const MAX_PROBE_EVENTS_PER_PEER: u64 = 16_384;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FleetHealthState {
    Unknown,
    Healthy,
    Degraded,
    Unhealthy,
    Recovering,
}

impl FleetHealthState {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Unhealthy => "unhealthy",
            Self::Recovering => "recovering",
        }
    }

    fn parse(value: &str) -> anyhow::Result<Self> {
        match value {
            "unknown" => Ok(Self::Unknown),
            "healthy" => Ok(Self::Healthy),
            "degraded" => Ok(Self::Degraded),
            "unhealthy" => Ok(Self::Unhealthy),
            "recovering" => Ok(Self::Recovering),
            _ => anyhow::bail!("unknown fleet health state"),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpdateFleetHealthConfig {
    #[serde(default = "default_success_threshold")]
    pub(crate) success_threshold: u16,
    #[serde(default = "default_failure_threshold")]
    pub(crate) failure_threshold: u16,
    #[serde(default = "default_health_cooldown")]
    pub(crate) cooldown_seconds: u32,
}

fn default_success_threshold() -> u16 {
    DEFAULT_SUCCESS_THRESHOLD
}

fn default_failure_threshold() -> u16 {
    DEFAULT_FAILURE_THRESHOLD
}

fn default_health_cooldown() -> u32 {
    DEFAULT_HEALTH_COOLDOWN_SECONDS
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct FleetHealthConfig {
    pub(crate) peer_id: Uuid,
    pub(crate) success_threshold: u16,
    pub(crate) failure_threshold: u16,
    pub(crate) cooldown_seconds: u32,
    pub(crate) updated_unix_seconds: u64,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct FleetPeerHealth {
    pub(crate) peer_id: Uuid,
    pub(crate) state: FleetHealthState,
    pub(crate) consecutive_successes: u16,
    pub(crate) consecutive_failures: u16,
    pub(crate) last_probe_unix_seconds: Option<u64>,
    pub(crate) last_success_unix_seconds: Option<u64>,
    pub(crate) last_failure_unix_seconds: Option<u64>,
    pub(crate) last_latency_millis: Option<u64>,
    pub(crate) last_error_summary: Option<String>,
    pub(crate) state_changed_unix_seconds: u64,
    pub(crate) cooldown_until_unix_seconds: u64,
    pub(crate) last_transition_reason: String,
    pub(crate) revision: u64,
    pub(crate) active_connections: u64,
    pub(crate) bytes_total: u64,
    pub(crate) clients: u64,
    pub(crate) policies: u64,
}

impl FleetPeerHealth {
    pub(crate) fn dns_eligible(&self, enabled: bool, now: u64) -> bool {
        enabled
            && self.state == FleetHealthState::Healthy
            && now >= self.cooldown_until_unix_seconds
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct FleetHealthSnapshot {
    pub(crate) config: FleetHealthConfig,
    pub(crate) health: FleetPeerHealth,
}

#[derive(Clone, Debug)]
pub(crate) struct FleetProbeObservation {
    pub(crate) event_id: Uuid,
    pub(crate) observed_unix_seconds: u64,
    pub(crate) success: bool,
    pub(crate) latency_millis: Option<u64>,
    pub(crate) error_summary: Option<String>,
    pub(crate) active_connections: u64,
    pub(crate) bytes_total: u64,
    pub(crate) clients: u64,
    pub(crate) policies: u64,
}

#[derive(Clone, Debug)]
pub(crate) struct FleetProbeResult {
    pub(crate) peer_id: Uuid,
    pub(crate) accepted: bool,
    pub(crate) duplicate: bool,
    pub(crate) previous_state: FleetHealthState,
    pub(crate) health: FleetPeerHealth,
    pub(crate) transition_reason: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) enum FleetDnsRecordType {
    #[serde(rename = "A")]
    A,
    #[serde(rename = "AAAA")]
    Aaaa,
    #[serde(rename = "CNAME")]
    Cname,
}

impl FleetDnsRecordType {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
            Self::Cname => "CNAME",
        }
    }

    fn parse(value: &str) -> anyhow::Result<Self> {
        match value {
            "A" => Ok(Self::A),
            "AAAA" => Ok(Self::Aaaa),
            "CNAME" => Ok(Self::Cname),
            _ => anyhow::bail!("fleet DNS record type is invalid"),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct FleetDnsPeerTarget {
    pub(crate) peer_id: Uuid,
    pub(crate) value: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpsertFleetDnsFailover {
    pub(crate) name: String,
    pub(crate) hostname: String,
    pub(crate) record_type: FleetDnsRecordType,
    pub(crate) zone_id: String,
    pub(crate) record_id: String,
    pub(crate) token_env: String,
    #[serde(default = "default_dns_ttl")]
    pub(crate) ttl: u32,
    #[serde(default)]
    pub(crate) proxied: bool,
    #[serde(default = "default_true")]
    pub(crate) enabled: bool,
    #[serde(default = "default_dns_cooldown")]
    pub(crate) cooldown_seconds: u32,
    pub(crate) targets: Vec<FleetDnsPeerTarget>,
}

fn default_dns_ttl() -> u32 {
    60
}

fn default_dns_cooldown() -> u32 {
    DEFAULT_DNS_COOLDOWN_SECONDS
}

fn default_true() -> bool {
    true
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct FleetDnsFailover {
    pub(crate) id: Uuid,
    pub(crate) name: String,
    pub(crate) hostname: String,
    pub(crate) record_type: FleetDnsRecordType,
    pub(crate) zone_id: String,
    pub(crate) record_id: String,
    pub(crate) token_env: String,
    pub(crate) token_configured: bool,
    pub(crate) ttl: u32,
    pub(crate) proxied: bool,
    pub(crate) enabled: bool,
    pub(crate) reconcile_required: bool,
    pub(crate) cooldown_seconds: u32,
    pub(crate) frozen: bool,
    pub(crate) freeze_reason: Option<String>,
    pub(crate) current_peer_id: Option<Uuid>,
    pub(crate) current_target: Option<String>,
    pub(crate) last_switch_unix_seconds: Option<u64>,
    pub(crate) next_change_not_before_unix_seconds: u64,
    pub(crate) last_switch_reason: Option<String>,
    pub(crate) last_error_summary: Option<String>,
    pub(crate) pending_operation_id: Option<Uuid>,
    pub(crate) pending_peer_id: Option<Uuid>,
    pub(crate) pending_target: Option<String>,
    pub(crate) pending_reason: Option<String>,
    pub(crate) pending_started_unix_seconds: Option<u64>,
    pub(crate) pending_lease_until_unix_seconds: Option<u64>,
    pub(crate) targets: Vec<FleetDnsPeerTarget>,
    pub(crate) created_unix_seconds: u64,
    pub(crate) updated_unix_seconds: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FreezeFleetDnsFailover {
    pub(crate) reason: String,
}

#[derive(Clone, Debug)]
pub(crate) struct FleetDnsChangePlan {
    pub(crate) operation_id: Uuid,
    pub(crate) failover_id: Uuid,
    pub(crate) failover_name: String,
    pub(crate) hostname: String,
    pub(crate) record_type: FleetDnsRecordType,
    pub(crate) zone_id: String,
    pub(crate) record_id: String,
    pub(crate) token_env: String,
    pub(crate) ttl: u32,
    pub(crate) proxied: bool,
    pub(crate) peer_id: Uuid,
    pub(crate) peer_name: String,
    pub(crate) target: String,
    pub(crate) reason: String,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct FleetDnsChangeResult {
    pub(crate) operation_id: Uuid,
    pub(crate) failover_id: Uuid,
    pub(crate) peer_id: Uuid,
    pub(crate) target: String,
    pub(crate) reason: String,
    pub(crate) applied: bool,
    pub(crate) duplicate: bool,
    pub(crate) error_summary: Option<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct FleetDnsSwitchEvent {
    pub(crate) operation_id: Uuid,
    pub(crate) failover_id: Uuid,
    pub(crate) peer_id: Uuid,
    pub(crate) target: String,
    pub(crate) reason: String,
    pub(crate) applied: bool,
    pub(crate) error_summary: Option<String>,
    pub(crate) completed_unix_seconds: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub(crate) struct FleetHealthMetrics {
    #[serde(rename = "fleet_peers_unknown")]
    pub(crate) peers_unknown: u64,
    #[serde(rename = "fleet_peers_healthy")]
    pub(crate) peers_healthy: u64,
    #[serde(rename = "fleet_peers_degraded")]
    pub(crate) peers_degraded: u64,
    #[serde(rename = "fleet_peers_unhealthy")]
    pub(crate) peers_unhealthy: u64,
    #[serde(rename = "fleet_peers_recovering")]
    pub(crate) peers_recovering: u64,
    #[serde(rename = "fleet_probe_events_total")]
    pub(crate) probe_events_total: u64,
    #[serde(rename = "fleet_probe_failures_total")]
    pub(crate) probe_failures_total: u64,
    #[serde(rename = "fleet_health_transitions_total")]
    pub(crate) health_transitions_total: u64,
    #[serde(rename = "fleet_dns_failovers_total")]
    pub(crate) dns_failovers_total: u64,
    #[serde(rename = "fleet_dns_failovers_frozen")]
    pub(crate) dns_failovers_frozen: u64,
    #[serde(rename = "fleet_dns_switches_total")]
    pub(crate) dns_switches_total: u64,
    #[serde(rename = "fleet_dns_switch_failures_total")]
    pub(crate) dns_switch_failures_total: u64,
    #[serde(rename = "fleet_dns_operations_pending")]
    pub(crate) dns_operations_pending: u64,
}

pub(crate) struct FleetHealthCatalog {
    database: Connection,
}

impl FleetHealthCatalog {
    #[allow(dead_code)]
    pub(crate) fn open(data_dir: Option<&Path>) -> anyhow::Result<Self> {
        let database = Database::open(data_dir)?;
        Self::open_with_database(&database)
    }

    pub(crate) fn open_with_database(database: &Database) -> anyhow::Result<Self> {
        let database = database.connect()?;
        database.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS fleet_peer_health_config (
                peer_id TEXT PRIMARY KEY NOT NULL REFERENCES fleet_peers(id) ON DELETE CASCADE,
                success_threshold INTEGER NOT NULL,
                failure_threshold INTEGER NOT NULL,
                cooldown_seconds INTEGER NOT NULL,
                updated_unix_seconds INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS fleet_peer_health_state (
                peer_id TEXT PRIMARY KEY NOT NULL REFERENCES fleet_peers(id) ON DELETE CASCADE,
                state TEXT NOT NULL,
                consecutive_successes INTEGER NOT NULL,
                consecutive_failures INTEGER NOT NULL,
                last_probe_unix_seconds INTEGER,
                last_success_unix_seconds INTEGER,
                last_failure_unix_seconds INTEGER,
                last_latency_millis INTEGER,
                last_error_summary TEXT,
                state_changed_unix_seconds INTEGER NOT NULL,
                cooldown_until_unix_seconds INTEGER NOT NULL,
                last_transition_reason TEXT NOT NULL,
                revision INTEGER NOT NULL,
                active_connections INTEGER NOT NULL,
                bytes_total INTEGER NOT NULL,
                clients INTEGER NOT NULL,
                policies INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS fleet_probe_events (
                event_id TEXT PRIMARY KEY NOT NULL,
                peer_id TEXT NOT NULL REFERENCES fleet_peers(id) ON DELETE CASCADE,
                observed_unix_seconds INTEGER NOT NULL,
                success INTEGER NOT NULL,
                accepted INTEGER NOT NULL,
                latency_millis INTEGER,
                error_summary TEXT,
                previous_state TEXT NOT NULL,
                resulting_state TEXT NOT NULL,
                transition_reason TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS fleet_probe_events_peer_time
                ON fleet_probe_events(peer_id, observed_unix_seconds DESC);
            CREATE TABLE IF NOT EXISTS fleet_health_counters (
                name TEXT PRIMARY KEY NOT NULL,
                value INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS fleet_dns_failovers (
                id TEXT PRIMARY KEY NOT NULL,
                name TEXT NOT NULL UNIQUE,
                hostname TEXT NOT NULL UNIQUE,
                record_type TEXT NOT NULL,
                zone_id TEXT NOT NULL,
                record_id TEXT NOT NULL,
                token_env TEXT NOT NULL,
                ttl INTEGER NOT NULL,
                proxied INTEGER NOT NULL,
                enabled INTEGER NOT NULL,
                reconcile_required INTEGER NOT NULL DEFAULT 1,
                cooldown_seconds INTEGER NOT NULL,
                frozen INTEGER NOT NULL,
                freeze_reason TEXT,
                current_peer_id TEXT REFERENCES fleet_peers(id) ON DELETE SET NULL,
                current_target TEXT,
                last_switch_unix_seconds INTEGER,
                next_change_not_before_unix_seconds INTEGER NOT NULL,
                last_switch_reason TEXT,
                last_error_summary TEXT,
                pending_operation_id TEXT,
                pending_peer_id TEXT REFERENCES fleet_peers(id) ON DELETE SET NULL,
                pending_target TEXT,
                pending_reason TEXT,
                pending_started_unix_seconds INTEGER,
                pending_lease_until_unix_seconds INTEGER,
                created_unix_seconds INTEGER NOT NULL,
                updated_unix_seconds INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS fleet_dns_targets (
                failover_id TEXT NOT NULL REFERENCES fleet_dns_failovers(id) ON DELETE CASCADE,
                peer_id TEXT NOT NULL REFERENCES fleet_peers(id) ON DELETE CASCADE,
                target_value TEXT NOT NULL,
                PRIMARY KEY(failover_id, peer_id)
            );
            CREATE TABLE IF NOT EXISTS fleet_dns_switch_events (
                operation_id TEXT PRIMARY KEY NOT NULL,
                failover_id TEXT NOT NULL REFERENCES fleet_dns_failovers(id) ON DELETE CASCADE,
                peer_id TEXT NOT NULL,
                target_value TEXT NOT NULL,
                reason TEXT NOT NULL,
                applied INTEGER NOT NULL,
                error_summary TEXT,
                completed_unix_seconds INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS fleet_dns_switch_events_failover_time
                ON fleet_dns_switch_events(failover_id, completed_unix_seconds DESC);
            ",
        )?;
        let reconcile_required_column: bool = database.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('fleet_dns_failovers') WHERE name = 'reconcile_required')",
            [],
            |row| row.get(0),
        )?;
        if !reconcile_required_column {
            database.execute(
                "ALTER TABLE fleet_dns_failovers ADD COLUMN reconcile_required INTEGER NOT NULL DEFAULT 1",
                [],
            )?;
        }
        initialize_persistent_counters(&database)?;
        let now = crate::unix_seconds();
        ensure_all_peers(&database, now)?;
        Ok(Self { database })
    }

    pub(crate) fn ensure_peer(&self, peer_id: Uuid, now: u64) -> anyhow::Result<()> {
        ensure_peer_rows(&self.database, peer_id, now)
    }

    pub(crate) fn update_health_config(
        &mut self,
        peer_id: Uuid,
        request: UpdateFleetHealthConfig,
        now: u64,
    ) -> anyhow::Result<Option<FleetHealthSnapshot>> {
        validate_health_config(&request)?;
        let transaction = self
            .database
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_peer_rows(&transaction, peer_id, now)?;
        let changed = transaction.execute(
            "UPDATE fleet_peer_health_config
             SET success_threshold = ?2, failure_threshold = ?3, cooldown_seconds = ?4, updated_unix_seconds = ?5
             WHERE peer_id = ?1",
            params![
                peer_id.to_string(),
                request.success_threshold,
                request.failure_threshold,
                request.cooldown_seconds,
                now as i64,
            ],
        )?;
        if changed == 0 {
            transaction.commit()?;
            return Ok(None);
        }
        transaction.execute(
            "UPDATE fleet_peer_health_state
             SET cooldown_until_unix_seconds = state_changed_unix_seconds + ?2
             WHERE peer_id = ?1",
            params![peer_id.to_string(), request.cooldown_seconds],
        )?;
        let snapshot = read_snapshot(&transaction, peer_id)?;
        transaction.commit()?;
        Ok(snapshot)
    }

    pub(crate) fn snapshot(&self, peer_id: Uuid) -> anyhow::Result<Option<FleetHealthSnapshot>> {
        read_snapshot(&self.database, peer_id)
    }

    pub(crate) fn snapshots(&self) -> anyhow::Result<HashMap<Uuid, FleetHealthSnapshot>> {
        let mut statement = self.database.prepare(
            "SELECT c.peer_id, c.success_threshold, c.failure_threshold, c.cooldown_seconds,
                    c.updated_unix_seconds, s.state, s.consecutive_successes,
                    s.consecutive_failures, s.last_probe_unix_seconds,
                    s.last_success_unix_seconds, s.last_failure_unix_seconds,
                    s.last_latency_millis, s.last_error_summary, s.state_changed_unix_seconds,
                    s.cooldown_until_unix_seconds, s.last_transition_reason, s.revision,
                    s.active_connections, s.bytes_total, s.clients, s.policies
             FROM fleet_peer_health_config c
             JOIN fleet_peer_health_state s ON s.peer_id = c.peer_id",
        )?;
        let rows = statement.query_map([], read_snapshot_row)?;
        let mut snapshots = HashMap::new();
        for row in rows {
            let snapshot = row?;
            snapshots.insert(snapshot.health.peer_id, snapshot);
        }
        Ok(snapshots)
    }

    pub(crate) fn record_probe(
        &mut self,
        peer_id: Uuid,
        observation: FleetProbeObservation,
    ) -> anyhow::Result<FleetProbeResult> {
        let transaction = self
            .database
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_peer_rows(&transaction, peer_id, observation.observed_unix_seconds)?;
        let duplicate = transaction
            .query_row(
                "SELECT peer_id, observed_unix_seconds, success
                 FROM fleet_probe_events WHERE event_id = ?1",
                [observation.event_id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        nonnegative(row.get(1)?),
                        row.get::<_, i64>(2)? != 0,
                    ))
                },
            )
            .optional()?;
        let current = read_snapshot(&transaction, peer_id)?
            .ok_or_else(|| anyhow::anyhow!("fleet peer does not exist"))?;
        if let Some((stored_peer_id, stored_at, stored_success)) = duplicate {
            anyhow::ensure!(
                stored_peer_id == peer_id.to_string()
                    && stored_at == observation.observed_unix_seconds
                    && stored_success == observation.success,
                "fleet probe event ID conflicts with an existing event"
            );
            transaction.commit()?;
            return Ok(FleetProbeResult {
                peer_id,
                accepted: false,
                duplicate: true,
                previous_state: current.health.state,
                transition_reason: "duplicate_event_ignored".to_owned(),
                health: current.health,
            });
        }

        if current
            .health
            .last_probe_unix_seconds
            .is_some_and(|last| observation.observed_unix_seconds < last)
        {
            insert_probe_event(
                &transaction,
                peer_id,
                &observation,
                false,
                current.health.state,
                current.health.state,
                "stale_event_ignored",
            )?;
            transaction.commit()?;
            return Ok(FleetProbeResult {
                peer_id,
                accepted: false,
                duplicate: false,
                previous_state: current.health.state,
                transition_reason: "stale_event_ignored".to_owned(),
                health: current.health,
            });
        }

        let previous_state = current.health.state;
        let (next_state, successes, failures, transition_reason) = next_health_state(
            previous_state,
            current.health.consecutive_successes,
            current.health.consecutive_failures,
            observation.success,
            current.config.success_threshold,
            current.config.failure_threshold,
        );
        let state_changed = next_state != previous_state;
        let state_changed_at = if state_changed {
            observation.observed_unix_seconds
        } else {
            current.health.state_changed_unix_seconds
        };
        let cooldown_until = if state_changed {
            observation
                .observed_unix_seconds
                .saturating_add(current.config.cooldown_seconds as u64)
        } else {
            current.health.cooldown_until_unix_seconds
        };
        let error_summary = observation
            .error_summary
            .as_deref()
            .map(summarize_error)
            .filter(|value| !value.is_empty());
        let last_success = if observation.success {
            Some(observation.observed_unix_seconds)
        } else {
            current.health.last_success_unix_seconds
        };
        let last_failure = if observation.success {
            current.health.last_failure_unix_seconds
        } else {
            Some(observation.observed_unix_seconds)
        };
        let last_error = if observation.success {
            None
        } else {
            error_summary
                .clone()
                .or_else(|| Some("probe failed".to_owned()))
        };
        let revision = current.health.revision.saturating_add(1);
        transaction.execute(
            "UPDATE fleet_peer_health_state SET
                state = ?2, consecutive_successes = ?3, consecutive_failures = ?4,
                last_probe_unix_seconds = ?5, last_success_unix_seconds = ?6,
                last_failure_unix_seconds = ?7, last_latency_millis = ?8,
                last_error_summary = ?9, state_changed_unix_seconds = ?10,
                cooldown_until_unix_seconds = ?11, last_transition_reason = ?12,
                revision = ?13, active_connections = ?14, bytes_total = ?15,
                clients = ?16, policies = ?17
             WHERE peer_id = ?1",
            params![
                peer_id.to_string(),
                next_state.as_str(),
                successes,
                failures,
                observation.observed_unix_seconds as i64,
                last_success.map(|value| value as i64),
                last_failure.map(|value| value as i64),
                observation.latency_millis.map(|value| value as i64),
                last_error,
                state_changed_at as i64,
                cooldown_until as i64,
                transition_reason,
                revision as i64,
                observation.active_connections as i64,
                observation.bytes_total as i64,
                observation.clients as i64,
                observation.policies as i64,
            ],
        )?;
        insert_probe_event(
            &transaction,
            peer_id,
            &observation,
            true,
            previous_state,
            next_state,
            transition_reason,
        )?;
        let health = read_snapshot(&transaction, peer_id)?
            .ok_or_else(|| anyhow::anyhow!("fleet peer disappeared during health update"))?
            .health;
        transaction.commit()?;
        Ok(FleetProbeResult {
            peer_id,
            accepted: true,
            duplicate: false,
            previous_state,
            health,
            transition_reason: transition_reason.to_owned(),
        })
    }

    pub(crate) fn create_dns_failover(
        &mut self,
        request: UpsertFleetDnsFailover,
        peers: &[FleetPeer],
        now: u64,
    ) -> anyhow::Result<FleetDnsFailover> {
        let request = validate_dns_failover(request, peers)?;
        let id = Uuid::new_v4();
        let transaction = self
            .database
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO fleet_dns_failovers (
                id, name, hostname, record_type, zone_id, record_id, token_env, ttl,
                proxied, enabled, reconcile_required, cooldown_seconds, frozen, freeze_reason,
                current_peer_id, current_target, last_switch_unix_seconds,
                next_change_not_before_unix_seconds, last_switch_reason,
                last_error_summary, pending_operation_id, pending_peer_id,
                pending_target, pending_reason, pending_started_unix_seconds,
                pending_lease_until_unix_seconds, created_unix_seconds, updated_unix_seconds
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 1, ?11, 0, NULL,
                       NULL, NULL, NULL, ?12, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
                       NULL, ?12, ?12)",
            params![
                id.to_string(),
                request.name,
                request.hostname,
                request.record_type.as_str(),
                request.zone_id,
                request.record_id,
                request.token_env,
                request.ttl,
                i64::from(request.proxied),
                i64::from(request.enabled),
                request.cooldown_seconds,
                now as i64,
            ],
        )?;
        replace_dns_targets(&transaction, id, &request.targets)?;
        transaction.commit()?;
        self.get_dns_failover(id)?
            .ok_or_else(|| anyhow::anyhow!("created fleet DNS failover is missing"))
    }

    pub(crate) fn update_dns_failover(
        &mut self,
        id: Uuid,
        request: UpsertFleetDnsFailover,
        peers: &[FleetPeer],
        now: u64,
    ) -> anyhow::Result<Option<FleetDnsFailover>> {
        let request = validate_dns_failover(request, peers)?;
        let transaction = self
            .database
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let pending: Option<Option<String>> = transaction
            .query_row(
                "SELECT pending_operation_id FROM fleet_dns_failovers WHERE id = ?1",
                [id.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        let Some(pending) = pending else {
            transaction.commit()?;
            return Ok(None);
        };
        anyhow::ensure!(pending.is_none(), "fleet DNS failover operation is pending");
        transaction.execute(
            "UPDATE fleet_dns_failovers SET
                name = ?2, hostname = ?3, record_type = ?4, zone_id = ?5,
                record_id = ?6, token_env = ?7, ttl = ?8, proxied = ?9,
                enabled = ?10, reconcile_required = 1, cooldown_seconds = ?11,
                updated_unix_seconds = ?12
             WHERE id = ?1",
            params![
                id.to_string(),
                request.name,
                request.hostname,
                request.record_type.as_str(),
                request.zone_id,
                request.record_id,
                request.token_env,
                request.ttl,
                i64::from(request.proxied),
                i64::from(request.enabled),
                request.cooldown_seconds,
                now as i64,
            ],
        )?;
        replace_dns_targets(&transaction, id, &request.targets)?;
        transaction.commit()?;
        self.get_dns_failover(id)
    }

    pub(crate) fn delete_dns_failover(&mut self, id: Uuid) -> anyhow::Result<bool> {
        let pending = self
            .database
            .query_row(
                "SELECT pending_operation_id FROM fleet_dns_failovers WHERE id = ?1",
                [id.to_string()],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?;
        let Some(pending) = pending else {
            return Ok(false);
        };
        anyhow::ensure!(pending.is_none(), "fleet DNS failover operation is pending");
        Ok(self.database.execute(
            "DELETE FROM fleet_dns_failovers WHERE id = ?1",
            [id.to_string()],
        )? > 0)
    }

    pub(crate) fn list_dns_failovers(&self) -> anyhow::Result<Vec<FleetDnsFailover>> {
        let mut statement = self.database.prepare(
            "SELECT id, name, hostname, record_type, zone_id, record_id, token_env,
                    ttl, proxied, enabled, reconcile_required, cooldown_seconds, frozen, freeze_reason,
                    current_peer_id, current_target, last_switch_unix_seconds,
                    next_change_not_before_unix_seconds, last_switch_reason,
                    last_error_summary, pending_operation_id, pending_peer_id,
                    pending_target, pending_reason, pending_started_unix_seconds,
                    pending_lease_until_unix_seconds, created_unix_seconds, updated_unix_seconds
             FROM fleet_dns_failovers ORDER BY name",
        )?;
        let rows = statement.query_map([], read_dns_failover_row)?;
        let mut failovers = Vec::new();
        for row in rows {
            let mut failover = row?;
            failover.targets = read_dns_targets(&self.database, failover.id)?;
            failovers.push(failover);
        }
        Ok(failovers)
    }

    pub(crate) fn get_dns_failover(&self, id: Uuid) -> anyhow::Result<Option<FleetDnsFailover>> {
        let mut failover = self
            .database
            .query_row(
                "SELECT id, name, hostname, record_type, zone_id, record_id, token_env,
                        ttl, proxied, enabled, reconcile_required, cooldown_seconds, frozen, freeze_reason,
                        current_peer_id, current_target, last_switch_unix_seconds,
                        next_change_not_before_unix_seconds, last_switch_reason,
                        last_error_summary, pending_operation_id, pending_peer_id,
                        pending_target, pending_reason, pending_started_unix_seconds,
                        pending_lease_until_unix_seconds, created_unix_seconds, updated_unix_seconds
                 FROM fleet_dns_failovers WHERE id = ?1",
                [id.to_string()],
                read_dns_failover_row,
            )
            .optional()?;
        if let Some(value) = &mut failover {
            value.targets = read_dns_targets(&self.database, value.id)?;
        }
        Ok(failover)
    }

    pub(crate) fn list_dns_switch_events(
        &self,
        failover_id: Uuid,
        limit: usize,
    ) -> anyhow::Result<Vec<FleetDnsSwitchEvent>> {
        let mut statement = self.database.prepare(
            "SELECT operation_id, failover_id, peer_id, target_value, reason,
                    applied, error_summary, completed_unix_seconds
             FROM fleet_dns_switch_events WHERE failover_id = ?1
             ORDER BY completed_unix_seconds DESC, operation_id DESC LIMIT ?2",
        )?;
        let rows = statement.query_map(
            params![failover_id.to_string(), limit.clamp(1, 500)],
            |row| {
                Ok(FleetDnsSwitchEvent {
                    operation_id: parse_uuid(&row.get::<_, String>(0)?, 0)?,
                    failover_id: parse_uuid(&row.get::<_, String>(1)?, 1)?,
                    peer_id: parse_uuid(&row.get::<_, String>(2)?, 2)?,
                    target: row.get(3)?,
                    reason: row.get(4)?,
                    applied: row.get::<_, i64>(5)? != 0,
                    error_summary: row.get(6)?,
                    completed_unix_seconds: nonnegative(row.get(7)?),
                })
            },
        )?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub(crate) fn set_dns_frozen(
        &mut self,
        id: Uuid,
        frozen: bool,
        reason: Option<&str>,
        now: u64,
    ) -> anyhow::Result<Option<FleetDnsFailover>> {
        let reason = if frozen {
            let reason = summarize_error(reason.unwrap_or("manual freeze"));
            anyhow::ensure!(!reason.is_empty(), "fleet DNS freeze reason is required");
            Some(reason)
        } else {
            None
        };
        let changed = self.database.execute(
            "UPDATE fleet_dns_failovers
             SET frozen = ?2, freeze_reason = ?3, updated_unix_seconds = ?4
             WHERE id = ?1",
            params![id.to_string(), i64::from(frozen), reason, now as i64],
        )?;
        if changed == 0 {
            return Ok(None);
        }
        self.get_dns_failover(id)
    }

    pub(crate) fn plan_dns_changes(
        &mut self,
        now: u64,
        only: Option<Uuid>,
    ) -> anyhow::Result<Vec<FleetDnsChangePlan>> {
        let transaction = self
            .database
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut ids = Vec::new();
        {
            let mut statement = if only.is_some() {
                transaction.prepare(
                    "SELECT id FROM fleet_dns_failovers WHERE id = ?1 AND enabled = 1 AND frozen = 0",
                )?
            } else {
                transaction.prepare(
                    "SELECT id FROM fleet_dns_failovers WHERE enabled = 1 AND frozen = 0 ORDER BY name",
                )?
            };
            if let Some(id) = only {
                let rows = statement.query_map([id.to_string()], |row| row.get::<_, String>(0))?;
                ids.extend(rows.collect::<Result<Vec<_>, _>>()?);
            } else {
                let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
                ids.extend(rows.collect::<Result<Vec<_>, _>>()?);
            }
        }
        let mut plans = Vec::new();
        for id in ids {
            let id = parse_uuid(&id, 0)?;
            let Some(mut failover) = read_dns_failover(&transaction, id)? else {
                continue;
            };
            failover.targets = read_dns_targets(&transaction, id)?;
            let pending_any = failover.pending_operation_id.is_some()
                || failover.pending_peer_id.is_some()
                || failover.pending_target.is_some()
                || failover.pending_reason.is_some();
            let pending_complete = failover.pending_operation_id.is_some()
                && failover.pending_peer_id.is_some()
                && failover.pending_target.is_some()
                && failover.pending_reason.is_some();
            if pending_any && !pending_complete {
                let error_summary = "incomplete pending DNS operation was cleared";
                increment_counter(&transaction, "dns_switch_failures_total")?;
                transaction.execute(
                    "UPDATE fleet_dns_failovers SET last_error_summary = ?2,
                        pending_operation_id = NULL, pending_peer_id = NULL,
                        pending_target = NULL, pending_reason = NULL,
                        pending_started_unix_seconds = NULL,
                        pending_lease_until_unix_seconds = NULL,
                        updated_unix_seconds = ?3 WHERE id = ?1",
                    params![id.to_string(), error_summary, now as i64],
                )?;
                failover.pending_operation_id = None;
                failover.pending_peer_id = None;
                failover.pending_target = None;
                failover.pending_reason = None;
                failover.pending_started_unix_seconds = None;
                failover.pending_lease_until_unix_seconds = None;
                failover.last_error_summary = Some(error_summary.to_owned());
                failover.updated_unix_seconds = now;
            }
            if let (Some(operation_id), Some(peer_id), Some(target), Some(reason)) = (
                failover.pending_operation_id,
                failover.pending_peer_id,
                failover.pending_target.clone(),
                failover.pending_reason.clone(),
            ) {
                if failover
                    .pending_lease_until_unix_seconds
                    .is_some_and(|lease| lease > now)
                {
                    continue;
                }
                let still_eligible = read_dns_candidates(&transaction, &failover, now)?
                    .iter()
                    .any(|candidate| candidate.peer_id == peer_id && candidate.target == target);
                if still_eligible {
                    let peer_name = read_peer_name(&transaction, peer_id)?
                        .unwrap_or_else(|| peer_id.to_string());
                    transaction.execute(
                        "UPDATE fleet_dns_failovers SET pending_lease_until_unix_seconds = ?2,
                            updated_unix_seconds = ?3 WHERE id = ?1 AND pending_operation_id = ?4",
                        params![
                            id.to_string(),
                            now.saturating_add(DNS_OPERATION_LEASE_SECONDS) as i64,
                            now as i64,
                            operation_id.to_string(),
                        ],
                    )?;
                    plans.push(change_plan(
                        &failover,
                        operation_id,
                        peer_id,
                        peer_name,
                        target,
                        reason,
                    ));
                    continue;
                }
                let error_summary = "pending DNS target no longer satisfies health and cooldown";
                transaction.execute(
                    "INSERT INTO fleet_dns_switch_events (
                        operation_id, failover_id, peer_id, target_value, reason,
                        applied, error_summary, completed_unix_seconds
                     ) VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, ?7)",
                    params![
                        operation_id.to_string(),
                        id.to_string(),
                        peer_id.to_string(),
                        target,
                        reason,
                        error_summary,
                        now as i64,
                    ],
                )?;
                increment_counter(&transaction, "dns_switch_failures_total")?;
                transaction.execute(
                    "UPDATE fleet_dns_failovers SET last_error_summary = ?2,
                        pending_operation_id = NULL, pending_peer_id = NULL,
                        pending_target = NULL, pending_reason = NULL,
                        pending_started_unix_seconds = NULL,
                        pending_lease_until_unix_seconds = NULL,
                        updated_unix_seconds = ?3 WHERE id = ?1",
                    params![id.to_string(), error_summary, now as i64],
                )?;
                failover.pending_operation_id = None;
                failover.pending_peer_id = None;
                failover.pending_target = None;
                failover.pending_reason = None;
                failover.pending_started_unix_seconds = None;
                failover.pending_lease_until_unix_seconds = None;
                failover.last_error_summary = Some(error_summary.to_owned());
            }
            if now < failover.next_change_not_before_unix_seconds {
                continue;
            }
            if should_hold_current_dns_peer(&transaction, &failover, now)? {
                continue;
            }
            let candidates = read_dns_candidates(&transaction, &failover, now)?;
            let Some(candidate) = candidates.first() else {
                continue;
            };
            if failover.current_peer_id == Some(candidate.peer_id)
                && failover.current_target.as_deref() == Some(candidate.target.as_str())
                && !failover.reconcile_required
            {
                continue;
            }
            let reason = dns_switch_reason(
                &transaction,
                &failover,
                candidate.peer_id,
                &candidate.target,
            )?;
            let operation_id = Uuid::new_v4();
            let reserved = transaction.execute(
                "UPDATE fleet_dns_failovers SET pending_operation_id = ?2,
                    pending_peer_id = ?3, pending_target = ?4, pending_reason = ?5,
                    pending_started_unix_seconds = ?6, pending_lease_until_unix_seconds = ?7,
                    updated_unix_seconds = ?6 WHERE id = ?1 AND pending_operation_id IS NULL",
                params![
                    id.to_string(),
                    operation_id.to_string(),
                    candidate.peer_id.to_string(),
                    candidate.target,
                    reason,
                    now as i64,
                    now.saturating_add(DNS_OPERATION_LEASE_SECONDS) as i64,
                ],
            )?;
            anyhow::ensure!(reserved == 1, "fleet DNS operation reservation conflicted");
            plans.push(change_plan(
                &failover,
                operation_id,
                candidate.peer_id,
                candidate.peer_name.clone(),
                candidate.target.clone(),
                reason.to_owned(),
            ));
        }
        transaction.commit()?;
        Ok(plans)
    }

    pub(crate) fn complete_dns_change(
        &mut self,
        plan: &FleetDnsChangePlan,
        result: Result<(), &str>,
        now: u64,
    ) -> anyhow::Result<FleetDnsChangeResult> {
        let transaction = self
            .database
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = transaction
            .query_row(
                "SELECT failover_id, peer_id, target_value, reason, applied, error_summary
                 FROM fleet_dns_switch_events WHERE operation_id = ?1",
                [plan.operation_id.to_string()],
                |row| {
                    Ok((
                        parse_uuid(&row.get::<_, String>(0)?, 0)?,
                        parse_uuid(&row.get::<_, String>(1)?, 1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)? != 0,
                        row.get::<_, Option<String>>(5)?,
                    ))
                },
            )
            .optional()?;
        if let Some((failover_id, peer_id, target, reason, applied, error_summary)) = existing {
            anyhow::ensure!(
                failover_id == plan.failover_id
                    && peer_id == plan.peer_id
                    && target == plan.target
                    && reason == plan.reason,
                "fleet DNS operation is stale"
            );
            transaction.commit()?;
            return Ok(FleetDnsChangeResult {
                operation_id: plan.operation_id,
                failover_id,
                peer_id,
                target,
                reason,
                applied,
                duplicate: true,
                error_summary,
            });
        }
        let pending = transaction
            .query_row(
                "SELECT pending_operation_id, pending_peer_id, pending_target,
                        pending_reason, cooldown_seconds
                 FROM fleet_dns_failovers WHERE id = ?1",
                [plan.failover_id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, Option<String>>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, u32>(4)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| anyhow::anyhow!("fleet DNS failover does not exist"))?;
        anyhow::ensure!(
            pending.0.as_deref() == Some(plan.operation_id.to_string().as_str())
                && pending.1.as_deref() == Some(plan.peer_id.to_string().as_str())
                && pending.2.as_deref() == Some(plan.target.as_str())
                && pending.3.as_deref() == Some(plan.reason.as_str()),
            "fleet DNS operation is stale"
        );
        let (applied, error_summary) = match result {
            Ok(()) => (true, None),
            Err(error) => (false, Some(summarize_error(error))),
        };
        transaction.execute(
            "INSERT INTO fleet_dns_switch_events (
                operation_id, failover_id, peer_id, target_value, reason,
                applied, error_summary, completed_unix_seconds
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                plan.operation_id.to_string(),
                plan.failover_id.to_string(),
                plan.peer_id.to_string(),
                plan.target,
                plan.reason,
                i64::from(applied),
                error_summary,
                now as i64,
            ],
        )?;
        increment_counter(
            &transaction,
            if applied {
                "dns_switches_total"
            } else {
                "dns_switch_failures_total"
            },
        )?;
        if applied {
            transaction.execute(
                "UPDATE fleet_dns_failovers SET
                    current_peer_id = ?2, current_target = ?3,
                    last_switch_unix_seconds = ?4,
                    next_change_not_before_unix_seconds = ?5,
                    last_switch_reason = ?6, last_error_summary = NULL,
                    reconcile_required = 0,
                    pending_operation_id = NULL, pending_peer_id = NULL,
                    pending_target = NULL, pending_reason = NULL,
                    pending_started_unix_seconds = NULL,
                    pending_lease_until_unix_seconds = NULL,
                    updated_unix_seconds = ?4
                 WHERE id = ?1",
                params![
                    plan.failover_id.to_string(),
                    plan.peer_id.to_string(),
                    plan.target,
                    now as i64,
                    now.saturating_add(pending.4 as u64) as i64,
                    plan.reason,
                ],
            )?;
        } else {
            transaction.execute(
                "UPDATE fleet_dns_failovers SET
                    next_change_not_before_unix_seconds = ?2,
                    last_error_summary = ?3,
                    pending_operation_id = NULL, pending_peer_id = NULL,
                    pending_target = NULL, pending_reason = NULL,
                    pending_started_unix_seconds = NULL,
                    pending_lease_until_unix_seconds = NULL,
                    updated_unix_seconds = ?4
                 WHERE id = ?1",
                params![
                    plan.failover_id.to_string(),
                    now.saturating_add(pending.4 as u64) as i64,
                    error_summary,
                    now as i64,
                ],
            )?;
        }
        transaction.commit()?;
        Ok(FleetDnsChangeResult {
            operation_id: plan.operation_id,
            failover_id: plan.failover_id,
            peer_id: plan.peer_id,
            target: plan.target.clone(),
            reason: plan.reason.clone(),
            applied,
            duplicate: false,
            error_summary,
        })
    }

    pub(crate) fn metrics(&self) -> anyhow::Result<FleetHealthMetrics> {
        let mut result = FleetHealthMetrics::default();
        let mut statement = self.database.prepare(
            "SELECT h.state, COUNT(*) FROM fleet_peer_health_state h
                 JOIN fleet_peers p ON p.id = h.peer_id
                 WHERE p.enabled = 1 GROUP BY h.state",
        )?;
        for row in statement.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?))
        })? {
            let (state, count) = row?;
            match FleetHealthState::parse(&state)? {
                FleetHealthState::Unknown => result.peers_unknown = count,
                FleetHealthState::Healthy => result.peers_healthy = count,
                FleetHealthState::Degraded => result.peers_degraded = count,
                FleetHealthState::Unhealthy => result.peers_unhealthy = count,
                FleetHealthState::Recovering => result.peers_recovering = count,
            }
        }
        result.probe_events_total = counter_value(&self.database, "probe_events_total")?;
        result.probe_failures_total = counter_value(&self.database, "probe_failures_total")?;
        result.health_transitions_total =
            counter_value(&self.database, "health_transitions_total")?;
        result.dns_failovers_total =
            count_query(&self.database, "SELECT COUNT(*) FROM fleet_dns_failovers")?;
        result.dns_failovers_frozen = count_query(
            &self.database,
            "SELECT COUNT(*) FROM fleet_dns_failovers WHERE frozen = 1",
        )?;
        result.dns_switches_total = counter_value(&self.database, "dns_switches_total")?;
        result.dns_switch_failures_total =
            counter_value(&self.database, "dns_switch_failures_total")?;
        result.dns_operations_pending = count_query(
            &self.database,
            "SELECT COUNT(*) FROM fleet_dns_failovers WHERE pending_operation_id IS NOT NULL",
        )?;
        Ok(result)
    }
}

#[derive(Clone)]
struct DnsCandidate {
    peer_id: Uuid,
    peer_name: String,
    priority: u16,
    weight: u16,
    target: String,
}

pub(crate) async fn apply_cloudflare_dns_change(
    client: &reqwest::Client,
    plan: &FleetDnsChangePlan,
) -> anyhow::Result<()> {
    let token = std::env::var(&plan.token_env)
        .with_context(|| format!("{} is not configured", plan.token_env))?;
    anyhow::ensure!(
        !token.trim().is_empty(),
        "{} is not configured",
        plan.token_env
    );
    let endpoint = format!(
        "https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}",
        plan.zone_id, plan.record_id
    );
    let response = client
        .put(endpoint)
        .bearer_auth(token)
        .json(&serde_json::json!({
            "type": plan.record_type.as_str(),
            "name": plan.hostname,
            "content": plan.target,
            "ttl": plan.ttl,
            "proxied": plan.proxied,
        }))
        .send()
        .await
        .context("Cloudflare DNS request failed")?;
    let status = response.status();
    let body = response
        .json::<CloudflareResponse>()
        .await
        .context("Cloudflare DNS response was invalid")?;
    anyhow::ensure!(
        status.is_success() && body.success,
        "Cloudflare DNS update failed with HTTP {}{}",
        status.as_u16(),
        body.error_suffix()
    );
    Ok(())
}

#[derive(Deserialize)]
struct CloudflareResponse {
    success: bool,
    #[serde(default)]
    errors: Vec<CloudflareError>,
}

impl CloudflareResponse {
    fn error_suffix(&self) -> String {
        self.errors.first().map_or_else(String::new, |error| {
            format!(" ({}: {})", error.code, summarize_error(&error.message))
        })
    }
}

#[derive(Deserialize)]
struct CloudflareError {
    code: u64,
    message: String,
}

fn initialize_persistent_counters(connection: &Connection) -> anyhow::Result<()> {
    connection.execute_batch(
        "INSERT OR IGNORE INTO fleet_health_counters(name, value)
             SELECT 'probe_events_total', COUNT(*) FROM fleet_probe_events;
         INSERT OR IGNORE INTO fleet_health_counters(name, value)
             SELECT 'probe_failures_total', COUNT(*) FROM fleet_probe_events
             WHERE accepted = 1 AND success = 0;
         INSERT OR IGNORE INTO fleet_health_counters(name, value)
             SELECT 'health_transitions_total', COUNT(*) FROM fleet_probe_events
             WHERE accepted = 1 AND previous_state <> resulting_state;
         INSERT OR IGNORE INTO fleet_health_counters(name, value)
             SELECT 'dns_switches_total', COUNT(*) FROM fleet_dns_switch_events
             WHERE applied = 1;
         INSERT OR IGNORE INTO fleet_health_counters(name, value)
             SELECT 'dns_switch_failures_total', COUNT(*) FROM fleet_dns_switch_events
             WHERE applied = 0;",
    )?;
    Ok(())
}

fn increment_counter(connection: &Connection, name: &str) -> rusqlite::Result<()> {
    let changed = connection.execute(
        "UPDATE fleet_health_counters SET value = value + 1 WHERE name = ?1",
        [name],
    )?;
    if changed == 1 {
        Ok(())
    } else {
        Err(rusqlite::Error::InvalidQuery)
    }
}

fn counter_value(connection: &Connection, name: &str) -> anyhow::Result<u64> {
    Ok(connection.query_row(
        "SELECT value FROM fleet_health_counters WHERE name = ?1",
        [name],
        |row| row.get::<_, u64>(0),
    )?)
}

fn ensure_all_peers(connection: &Connection, now: u64) -> anyhow::Result<()> {
    connection.execute(
        "INSERT OR IGNORE INTO fleet_peer_health_config (
            peer_id, success_threshold, failure_threshold, cooldown_seconds, updated_unix_seconds
         ) SELECT id, ?1, ?2, ?3, ?4 FROM fleet_peers",
        params![
            DEFAULT_SUCCESS_THRESHOLD,
            DEFAULT_FAILURE_THRESHOLD,
            DEFAULT_HEALTH_COOLDOWN_SECONDS,
            now as i64,
        ],
    )?;
    connection.execute(
        "INSERT OR IGNORE INTO fleet_peer_health_state (
            peer_id, state, consecutive_successes, consecutive_failures,
            last_probe_unix_seconds, last_success_unix_seconds, last_failure_unix_seconds,
            last_latency_millis, last_error_summary, state_changed_unix_seconds,
            cooldown_until_unix_seconds, last_transition_reason, revision,
            active_connections, bytes_total, clients, policies
         ) SELECT id, 'unknown', 0, 0, NULL, NULL, NULL, NULL, NULL, ?1, ?1,
                  'awaiting_first_probe', 0, 0, 0, 0, 0 FROM fleet_peers",
        [now as i64],
    )?;
    Ok(())
}

fn ensure_peer_rows(connection: &Connection, peer_id: Uuid, now: u64) -> anyhow::Result<()> {
    let exists = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM fleet_peers WHERE id = ?1)",
        [peer_id.to_string()],
        |row| row.get::<_, bool>(0),
    )?;
    anyhow::ensure!(exists, "fleet peer does not exist");
    connection.execute(
        "INSERT OR IGNORE INTO fleet_peer_health_config (
            peer_id, success_threshold, failure_threshold, cooldown_seconds, updated_unix_seconds
         ) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            peer_id.to_string(),
            DEFAULT_SUCCESS_THRESHOLD,
            DEFAULT_FAILURE_THRESHOLD,
            DEFAULT_HEALTH_COOLDOWN_SECONDS,
            now as i64,
        ],
    )?;
    connection.execute(
        "INSERT OR IGNORE INTO fleet_peer_health_state (
            peer_id, state, consecutive_successes, consecutive_failures,
            last_probe_unix_seconds, last_success_unix_seconds, last_failure_unix_seconds,
            last_latency_millis, last_error_summary, state_changed_unix_seconds,
            cooldown_until_unix_seconds, last_transition_reason, revision,
            active_connections, bytes_total, clients, policies
         ) VALUES (?1, 'unknown', 0, 0, NULL, NULL, NULL, NULL, NULL, ?2, ?2,
                   'awaiting_first_probe', 0, 0, 0, 0, 0)",
        params![peer_id.to_string(), now as i64],
    )?;
    Ok(())
}

fn validate_health_config(request: &UpdateFleetHealthConfig) -> anyhow::Result<()> {
    anyhow::ensure!(
        (1..=20).contains(&request.success_threshold),
        "fleet health success threshold must be between 1 and 20"
    );
    anyhow::ensure!(
        (1..=20).contains(&request.failure_threshold),
        "fleet health failure threshold must be between 1 and 20"
    );
    anyhow::ensure!(
        request.cooldown_seconds <= 86_400,
        "fleet health cooldown must not exceed 86400 seconds"
    );
    Ok(())
}

fn next_health_state(
    current: FleetHealthState,
    current_successes: u16,
    current_failures: u16,
    success: bool,
    success_threshold: u16,
    failure_threshold: u16,
) -> (FleetHealthState, u16, u16, &'static str) {
    if success {
        let successes = current_successes.saturating_add(1);
        if current == FleetHealthState::Healthy {
            return (FleetHealthState::Healthy, successes, 0, "probe_succeeded");
        }
        if successes >= success_threshold {
            return (
                FleetHealthState::Healthy,
                successes,
                0,
                "success_threshold_met",
            );
        }
        return match current {
            FleetHealthState::Degraded => (
                FleetHealthState::Degraded,
                successes,
                0,
                "health_confirmation_in_progress",
            ),
            FleetHealthState::Unknown => (
                FleetHealthState::Unknown,
                successes,
                0,
                "initial_health_confirmation_in_progress",
            ),
            _ => (
                FleetHealthState::Recovering,
                successes,
                0,
                "recovery_in_progress",
            ),
        };
    }
    let failures = current_failures.saturating_add(1);
    if current == FleetHealthState::Unhealthy {
        return (
            FleetHealthState::Unhealthy,
            0,
            failures,
            "probe_still_failing",
        );
    }
    if current == FleetHealthState::Recovering {
        return (FleetHealthState::Unhealthy, 0, failures, "recovery_failed");
    }
    if failures >= failure_threshold {
        return (
            FleetHealthState::Unhealthy,
            0,
            failures,
            "failure_threshold_met",
        );
    }
    (
        FleetHealthState::Degraded,
        0,
        failures,
        "failure_below_threshold",
    )
}

fn insert_probe_event(
    transaction: &Transaction<'_>,
    peer_id: Uuid,
    observation: &FleetProbeObservation,
    accepted: bool,
    previous: FleetHealthState,
    resulting: FleetHealthState,
    reason: &str,
) -> rusqlite::Result<()> {
    transaction.execute(
        "INSERT INTO fleet_probe_events (
            event_id, peer_id, observed_unix_seconds, success, accepted,
            latency_millis, error_summary, previous_state, resulting_state,
            transition_reason
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            observation.event_id.to_string(),
            peer_id.to_string(),
            observation.observed_unix_seconds as i64,
            i64::from(observation.success),
            i64::from(accepted),
            observation.latency_millis.map(|value| value as i64),
            observation.error_summary.as_deref().map(summarize_error),
            previous.as_str(),
            resulting.as_str(),
            reason,
        ],
    )?;
    increment_counter(transaction, "probe_events_total")?;
    if accepted && !observation.success {
        increment_counter(transaction, "probe_failures_total")?;
    }
    if accepted && previous != resulting {
        increment_counter(transaction, "health_transitions_total")?;
    }
    transaction.execute(
        "DELETE FROM fleet_probe_events
         WHERE peer_id = ?1 AND event_id IN (
             SELECT event_id FROM fleet_probe_events WHERE peer_id = ?1
             ORDER BY observed_unix_seconds DESC, rowid DESC LIMIT -1 OFFSET ?2
         )",
        params![peer_id.to_string(), MAX_PROBE_EVENTS_PER_PEER],
    )?;
    Ok(())
}

fn read_snapshot(
    connection: &Connection,
    peer_id: Uuid,
) -> anyhow::Result<Option<FleetHealthSnapshot>> {
    Ok(connection
        .query_row(
            "SELECT c.peer_id, c.success_threshold, c.failure_threshold, c.cooldown_seconds,
                    c.updated_unix_seconds, s.state, s.consecutive_successes,
                    s.consecutive_failures, s.last_probe_unix_seconds,
                    s.last_success_unix_seconds, s.last_failure_unix_seconds,
                    s.last_latency_millis, s.last_error_summary, s.state_changed_unix_seconds,
                    s.cooldown_until_unix_seconds, s.last_transition_reason, s.revision,
                    s.active_connections, s.bytes_total, s.clients, s.policies
             FROM fleet_peer_health_config c
             JOIN fleet_peer_health_state s ON s.peer_id = c.peer_id
             WHERE c.peer_id = ?1",
            [peer_id.to_string()],
            read_snapshot_row,
        )
        .optional()?)
}

fn read_snapshot_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<FleetHealthSnapshot> {
    let peer_id = parse_uuid(&row.get::<_, String>(0)?, 0)?;
    let state_text = row.get::<_, String>(5)?;
    let state = FleetHealthState::parse(&state_text).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            5,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                error.to_string(),
            )),
        )
    })?;
    Ok(FleetHealthSnapshot {
        config: FleetHealthConfig {
            peer_id,
            success_threshold: row.get(1)?,
            failure_threshold: row.get(2)?,
            cooldown_seconds: row.get(3)?,
            updated_unix_seconds: nonnegative(row.get(4)?),
        },
        health: FleetPeerHealth {
            peer_id,
            state,
            consecutive_successes: row.get(6)?,
            consecutive_failures: row.get(7)?,
            last_probe_unix_seconds: optional_nonnegative(row.get(8)?),
            last_success_unix_seconds: optional_nonnegative(row.get(9)?),
            last_failure_unix_seconds: optional_nonnegative(row.get(10)?),
            last_latency_millis: optional_nonnegative(row.get(11)?),
            last_error_summary: row.get(12)?,
            state_changed_unix_seconds: nonnegative(row.get(13)?),
            cooldown_until_unix_seconds: nonnegative(row.get(14)?),
            last_transition_reason: row.get(15)?,
            revision: nonnegative(row.get(16)?),
            active_connections: nonnegative(row.get(17)?),
            bytes_total: nonnegative(row.get(18)?),
            clients: nonnegative(row.get(19)?),
            policies: nonnegative(row.get(20)?),
        },
    })
}

fn validate_dns_failover(
    mut request: UpsertFleetDnsFailover,
    peers: &[FleetPeer],
) -> anyhow::Result<UpsertFleetDnsFailover> {
    request.name = request.name.trim().to_owned();
    request.hostname = request
        .hostname
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    request.zone_id = request.zone_id.trim().to_owned();
    request.record_id = request.record_id.trim().to_owned();
    request.token_env = request.token_env.trim().to_owned();
    anyhow::ensure!(
        !request.name.is_empty() && request.name.chars().count() <= 80,
        "fleet DNS failover name is invalid"
    );
    anyhow::ensure!(
        valid_dns_name(&request.hostname),
        "fleet DNS hostname is invalid"
    );
    anyhow::ensure!(
        valid_provider_id(&request.zone_id),
        "Cloudflare zone ID is invalid"
    );
    anyhow::ensure!(
        valid_provider_id(&request.record_id),
        "Cloudflare record ID is invalid"
    );
    anyhow::ensure!(
        valid_secret_env(&request.token_env),
        "Cloudflare token environment variable is invalid"
    );
    anyhow::ensure!(
        request.ttl == 1 || (60..=86_400).contains(&request.ttl),
        "fleet DNS TTL must be 1 or between 60 and 86400 seconds"
    );
    anyhow::ensure!(
        (1..=86_400).contains(&request.cooldown_seconds),
        "fleet DNS cooldown must be between 1 and 86400 seconds"
    );
    anyhow::ensure!(
        !request.targets.is_empty(),
        "fleet DNS targets are required"
    );
    let known = peers.iter().map(|peer| peer.id).collect::<HashSet<_>>();
    let mut seen = HashSet::new();
    for target in &mut request.targets {
        target.value = target.value.trim().trim_end_matches('.').to_owned();
        if request.record_type == FleetDnsRecordType::Cname {
            target.value.make_ascii_lowercase();
        }
        anyhow::ensure!(
            known.contains(&target.peer_id),
            "fleet DNS target peer does not exist"
        );
        anyhow::ensure!(
            seen.insert(target.peer_id),
            "fleet DNS target peer is duplicated"
        );
        validate_dns_target(request.record_type, &target.value)?;
    }
    request.targets.sort_by_key(|target| target.peer_id);
    Ok(request)
}

fn validate_dns_target(record_type: FleetDnsRecordType, value: &str) -> anyhow::Result<()> {
    match record_type {
        FleetDnsRecordType::A => {
            value
                .parse::<Ipv4Addr>()
                .context("fleet DNS A target is invalid")?;
        }
        FleetDnsRecordType::Aaaa => {
            value
                .parse::<Ipv6Addr>()
                .context("fleet DNS AAAA target is invalid")?;
        }
        FleetDnsRecordType::Cname => {
            anyhow::ensure!(valid_dns_name(value), "fleet DNS CNAME target is invalid");
        }
    }
    Ok(())
}

fn valid_provider_id(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|value| value.is_ascii_hexdigit())
}

fn valid_secret_env(value: &str) -> bool {
    value.starts_with("LINKLAKE_CLOUDFLARE_")
        && value.ends_with("_TOKEN")
        && value.len() <= 128
        && value
            .bytes()
            .all(|value| value.is_ascii_uppercase() || value.is_ascii_digit() || value == b'_')
}

fn valid_dns_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|value| value.is_ascii_alphanumeric() || value == b'-')
        })
}

fn replace_dns_targets(
    transaction: &Transaction<'_>,
    failover_id: Uuid,
    targets: &[FleetDnsPeerTarget],
) -> rusqlite::Result<()> {
    transaction.execute(
        "DELETE FROM fleet_dns_targets WHERE failover_id = ?1",
        [failover_id.to_string()],
    )?;
    for target in targets {
        transaction.execute(
            "INSERT INTO fleet_dns_targets (failover_id, peer_id, target_value)
             VALUES (?1, ?2, ?3)",
            params![
                failover_id.to_string(),
                target.peer_id.to_string(),
                target.value,
            ],
        )?;
    }
    Ok(())
}

fn read_dns_targets(
    connection: &Connection,
    failover_id: Uuid,
) -> anyhow::Result<Vec<FleetDnsPeerTarget>> {
    let mut statement = connection.prepare(
        "SELECT peer_id, target_value FROM fleet_dns_targets
         WHERE failover_id = ?1 ORDER BY peer_id",
    )?;
    let rows = statement.query_map([failover_id.to_string()], |row| {
        Ok(FleetDnsPeerTarget {
            peer_id: parse_uuid(&row.get::<_, String>(0)?, 0)?,
            value: row.get(1)?,
        })
    })?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

fn read_dns_failover(
    connection: &Connection,
    id: Uuid,
) -> anyhow::Result<Option<FleetDnsFailover>> {
    Ok(connection
        .query_row(
            "SELECT id, name, hostname, record_type, zone_id, record_id, token_env,
                    ttl, proxied, enabled, reconcile_required, cooldown_seconds, frozen, freeze_reason,
                    current_peer_id, current_target, last_switch_unix_seconds,
                    next_change_not_before_unix_seconds, last_switch_reason,
                    last_error_summary, pending_operation_id, pending_peer_id,
                    pending_target, pending_reason, pending_started_unix_seconds,
                    pending_lease_until_unix_seconds, created_unix_seconds, updated_unix_seconds
             FROM fleet_dns_failovers WHERE id = ?1",
            [id.to_string()],
            read_dns_failover_row,
        )
        .optional()?)
}

fn read_dns_failover_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<FleetDnsFailover> {
    let id = parse_uuid(&row.get::<_, String>(0)?, 0)?;
    let record_type_text = row.get::<_, String>(3)?;
    let record_type = FleetDnsRecordType::parse(&record_type_text).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            3,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                error.to_string(),
            )),
        )
    })?;
    let token_env = row.get::<_, String>(6)?;
    Ok(FleetDnsFailover {
        id,
        name: row.get(1)?,
        hostname: row.get(2)?,
        record_type,
        zone_id: row.get(4)?,
        record_id: row.get(5)?,
        token_configured: std::env::var(&token_env).is_ok_and(|value| !value.trim().is_empty()),
        token_env,
        ttl: row.get(7)?,
        proxied: row.get::<_, i64>(8)? != 0,
        enabled: row.get::<_, i64>(9)? != 0,
        reconcile_required: row.get::<_, i64>(10)? != 0,
        cooldown_seconds: row.get(11)?,
        frozen: row.get::<_, i64>(12)? != 0,
        freeze_reason: row.get(13)?,
        current_peer_id: optional_uuid(row.get(14)?, 14)?,
        current_target: row.get(15)?,
        last_switch_unix_seconds: optional_nonnegative(row.get(16)?),
        next_change_not_before_unix_seconds: nonnegative(row.get(17)?),
        last_switch_reason: row.get(18)?,
        last_error_summary: row.get(19)?,
        pending_operation_id: optional_uuid(row.get(20)?, 20)?,
        pending_peer_id: optional_uuid(row.get(21)?, 21)?,
        pending_target: row.get(22)?,
        pending_reason: row.get(23)?,
        pending_started_unix_seconds: optional_nonnegative(row.get(24)?),
        pending_lease_until_unix_seconds: optional_nonnegative(row.get(25)?),
        targets: Vec::new(),
        created_unix_seconds: nonnegative(row.get(26)?),
        updated_unix_seconds: nonnegative(row.get(27)?),
    })
}

fn read_dns_candidates(
    connection: &Connection,
    failover: &FleetDnsFailover,
    now: u64,
) -> anyhow::Result<Vec<DnsCandidate>> {
    let mut statement = connection.prepare(
        "SELECT p.id, p.name, p.priority, p.weight, t.target_value
         FROM fleet_dns_targets t
         JOIN fleet_peers p ON p.id = t.peer_id
         JOIN fleet_peer_health_state h ON h.peer_id = p.id
         WHERE t.failover_id = ?1 AND p.enabled = 1 AND h.state = 'healthy'
               AND h.cooldown_until_unix_seconds <= ?2
         ORDER BY p.priority ASC, p.weight DESC, p.name ASC",
    )?;
    let rows = statement.query_map(params![failover.id.to_string(), now as i64], |row| {
        Ok(DnsCandidate {
            peer_id: parse_uuid(&row.get::<_, String>(0)?, 0)?,
            peer_name: row.get(1)?,
            priority: row.get(2)?,
            weight: row.get(3)?,
            target: row.get(4)?,
        })
    })?;
    let mut candidates = rows.collect::<Result<Vec<_>, _>>()?;
    candidates
        .retain(|candidate| validate_dns_target(failover.record_type, &candidate.target).is_ok());
    candidates.sort_by_key(|candidate| {
        (
            candidate.priority,
            std::cmp::Reverse(candidate.weight),
            candidate.peer_name.clone(),
        )
    });
    Ok(candidates)
}

fn should_hold_current_dns_peer(
    connection: &Connection,
    failover: &FleetDnsFailover,
    now: u64,
) -> anyhow::Result<bool> {
    let (Some(current_peer_id), Some(current_target)) =
        (failover.current_peer_id, failover.current_target.as_deref())
    else {
        return Ok(false);
    };
    let current = connection
        .query_row(
            "SELECT p.enabled, h.state, h.cooldown_until_unix_seconds,
                    EXISTS(
                        SELECT 1 FROM fleet_dns_targets t
                        WHERE t.failover_id = ?2 AND t.peer_id = p.id
                              AND t.target_value = ?3
                    )
             FROM fleet_peers p
             LEFT JOIN fleet_peer_health_state h ON h.peer_id = p.id
             WHERE p.id = ?1",
            params![
                current_peer_id.to_string(),
                failover.id.to_string(),
                current_target,
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)? != 0,
                    row.get::<_, Option<String>>(1)?,
                    optional_nonnegative(row.get(2)?),
                    row.get::<_, i64>(3)? != 0,
                ))
            },
        )
        .optional()?;
    let Some((enabled, state, cooldown_until, target_still_configured)) = current else {
        return Ok(false);
    };
    if !enabled || !target_still_configured {
        return Ok(false);
    }
    Ok(match state.as_deref() {
        Some("degraded") => true,
        Some("healthy") => cooldown_until.is_some_and(|cooldown| cooldown > now),
        _ => false,
    })
}

fn dns_switch_reason(
    connection: &Connection,
    failover: &FleetDnsFailover,
    candidate_peer_id: Uuid,
    candidate_target: &str,
) -> anyhow::Result<&'static str> {
    let Some(current_peer_id) = failover.current_peer_id else {
        return Ok("initial_activation");
    };
    if current_peer_id == candidate_peer_id {
        return Ok(
            if failover.current_target.as_deref() == Some(candidate_target)
                && failover.reconcile_required
            {
                "configuration_updated"
            } else {
                "target_value_changed"
            },
        );
    }
    let current = connection
        .query_row(
            "SELECT p.enabled, h.state,
                    EXISTS(
                        SELECT 1 FROM fleet_dns_targets t
                        WHERE t.failover_id = ?2 AND t.peer_id = p.id
                              AND t.target_value = ?3
                    )
             FROM fleet_peers p
             LEFT JOIN fleet_peer_health_state h ON h.peer_id = p.id
             WHERE p.id = ?1",
            params![
                current_peer_id.to_string(),
                failover.id.to_string(),
                failover.current_target.as_deref().unwrap_or(""),
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)? != 0,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, i64>(2)? != 0,
                ))
            },
        )
        .optional()?;
    match current {
        None => Ok("current_peer_removed"),
        Some((false, _, _)) => Ok("current_peer_disabled"),
        Some((true, _, false)) => Ok("current_target_removed"),
        Some((true, Some(state), true)) if state == FleetHealthState::Unhealthy.as_str() => {
            Ok("current_peer_unhealthy")
        }
        Some((true, Some(state), true)) if state == FleetHealthState::Recovering.as_str() => {
            Ok("current_peer_recovering")
        }
        Some((true, Some(state), true)) if state == FleetHealthState::Unknown.as_str() => {
            Ok("current_peer_unknown")
        }
        Some((true, Some(state), true)) if state == FleetHealthState::Degraded.as_str() => {
            Ok("current_peer_degraded")
        }
        Some(_) => Ok("preferred_peer_recovered"),
    }
}

fn change_plan(
    failover: &FleetDnsFailover,
    operation_id: Uuid,
    peer_id: Uuid,
    peer_name: String,
    target: String,
    reason: String,
) -> FleetDnsChangePlan {
    FleetDnsChangePlan {
        operation_id,
        failover_id: failover.id,
        failover_name: failover.name.clone(),
        hostname: failover.hostname.clone(),
        record_type: failover.record_type,
        zone_id: failover.zone_id.clone(),
        record_id: failover.record_id.clone(),
        token_env: failover.token_env.clone(),
        ttl: failover.ttl,
        proxied: failover.proxied,
        peer_id,
        peer_name,
        target,
        reason,
    }
}

fn read_peer_name(connection: &Connection, peer_id: Uuid) -> anyhow::Result<Option<String>> {
    Ok(connection
        .query_row(
            "SELECT name FROM fleet_peers WHERE id = ?1",
            [peer_id.to_string()],
            |row| row.get(0),
        )
        .optional()?)
}

fn count_query(connection: &Connection, sql: &str) -> anyhow::Result<u64> {
    Ok(connection.query_row(sql, [], |row| row.get::<_, u64>(0))?)
}

fn summarize_error(value: &str) -> String {
    let mut output = String::new();
    for character in value.chars() {
        if output.chars().count() >= MAX_ERROR_SUMMARY_CHARS {
            break;
        }
        if character.is_control() {
            if !output.ends_with(' ') {
                output.push(' ');
            }
        } else {
            output.push(character);
        }
    }
    output.trim().to_owned()
}

fn parse_uuid(value: &str, column: usize) -> rusqlite::Result<Uuid> {
    Uuid::parse_str(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })
}

fn optional_uuid(value: Option<String>, column: usize) -> rusqlite::Result<Option<Uuid>> {
    value.map(|value| parse_uuid(&value, column)).transpose()
}

fn nonnegative(value: i64) -> u64 {
    value.max(0) as u64
}

fn optional_nonnegative(value: Option<i64>) -> Option<u64> {
    value.map(nonnegative)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fleet::{FleetCatalog, UpsertFleetPeer};
    use std::sync::{Arc, Barrier};

    fn create_peer(fleet: &mut FleetCatalog, name: &str, priority: u16, now: u64) -> FleetPeer {
        fleet
            .create(
                UpsertFleetPeer {
                    name: name.to_owned(),
                    url: format!("https://{}.example.com", name.to_ascii_lowercase()),
                    region: "test".to_owned(),
                    weight: 100,
                    priority,
                    token_env: format!("LINKLAKE_FLEET_{}_TOKEN", name.to_ascii_uppercase()),
                    enabled: true,
                },
                now,
            )
            .unwrap()
    }

    fn observation(peer: Uuid, at: u64, success: bool) -> FleetProbeObservation {
        FleetProbeObservation {
            event_id: Uuid::new_v4(),
            observed_unix_seconds: at,
            success,
            latency_millis: Some(10),
            error_summary: (!success).then(|| format!("peer {peer} failed\nwithout secrets")),
            active_connections: u64::from(success),
            bytes_total: if success { 100 } else { 0 },
            clients: u64::from(success),
            policies: u64::from(success),
        }
    }

    fn setup() -> (
        Database,
        FleetCatalog,
        FleetHealthCatalog,
        FleetPeer,
        FleetPeer,
    ) {
        let database = Database::memory().unwrap();
        let mut fleet = FleetCatalog::open_with_database(&database).unwrap();
        let primary = create_peer(&mut fleet, "Primary", 10, 1);
        let secondary = create_peer(&mut fleet, "Secondary", 20, 1);
        let health = FleetHealthCatalog::open_with_database(&database).unwrap();
        (database, fleet, health, primary, secondary)
    }

    #[test]
    fn health_state_uses_success_and_failure_hysteresis() {
        let (_database, _fleet, mut catalog, primary, _) = setup();
        catalog
            .update_health_config(
                primary.id,
                UpdateFleetHealthConfig {
                    success_threshold: 2,
                    failure_threshold: 3,
                    cooldown_seconds: 10,
                },
                1,
            )
            .unwrap();
        assert_eq!(
            catalog
                .record_probe(primary.id, observation(primary.id, 2, true))
                .unwrap()
                .health
                .state,
            FleetHealthState::Unknown
        );
        let healthy = catalog
            .record_probe(primary.id, observation(primary.id, 3, true))
            .unwrap();
        assert_eq!(healthy.health.state, FleetHealthState::Healthy);
        assert_eq!(healthy.health.cooldown_until_unix_seconds, 13);
        assert_eq!(
            catalog
                .record_probe(primary.id, observation(primary.id, 4, false))
                .unwrap()
                .health
                .state,
            FleetHealthState::Degraded
        );
        assert_eq!(
            catalog
                .record_probe(primary.id, observation(primary.id, 5, true))
                .unwrap()
                .health
                .state,
            FleetHealthState::Degraded
        );
        assert_eq!(
            catalog
                .record_probe(primary.id, observation(primary.id, 6, true))
                .unwrap()
                .health
                .state,
            FleetHealthState::Healthy
        );
        for at in [7, 8] {
            assert_eq!(
                catalog
                    .record_probe(primary.id, observation(primary.id, at, false))
                    .unwrap()
                    .health
                    .state,
                FleetHealthState::Degraded
            );
        }
        let unhealthy = catalog
            .record_probe(primary.id, observation(primary.id, 9, false))
            .unwrap();
        assert_eq!(unhealthy.health.state, FleetHealthState::Unhealthy);
        assert_eq!(unhealthy.health.last_failure_unix_seconds, Some(9));
        assert!(unhealthy
            .health
            .last_error_summary
            .as_deref()
            .is_some_and(|value| !value.contains('\n')));
        assert_eq!(
            catalog
                .record_probe(primary.id, observation(primary.id, 10, true))
                .unwrap()
                .health
                .state,
            FleetHealthState::Recovering
        );
        assert_eq!(
            catalog
                .record_probe(primary.id, observation(primary.id, 11, false))
                .unwrap()
                .health
                .state,
            FleetHealthState::Unhealthy
        );
        assert_eq!(
            catalog
                .record_probe(primary.id, observation(primary.id, 12, true))
                .unwrap()
                .health
                .state,
            FleetHealthState::Recovering
        );
        assert_eq!(
            catalog
                .record_probe(primary.id, observation(primary.id, 13, true))
                .unwrap()
                .health
                .state,
            FleetHealthState::Healthy
        );
    }

    #[test]
    fn health_config_change_recalculates_the_persisted_cooldown() {
        let (_database, _fleet, mut catalog, primary, _) = setup();
        catalog
            .update_health_config(
                primary.id,
                UpdateFleetHealthConfig {
                    success_threshold: 1,
                    failure_threshold: 1,
                    cooldown_seconds: 5,
                },
                1,
            )
            .unwrap();
        let healthy = catalog
            .record_probe(primary.id, observation(primary.id, 10, true))
            .unwrap();
        assert_eq!(healthy.health.cooldown_until_unix_seconds, 15);
        let changed = catalog
            .update_health_config(
                primary.id,
                UpdateFleetHealthConfig {
                    success_threshold: 1,
                    failure_threshold: 1,
                    cooldown_seconds: 30,
                },
                12,
            )
            .unwrap()
            .unwrap();
        assert_eq!(changed.health.state_changed_unix_seconds, 10);
        assert_eq!(changed.health.cooldown_until_unix_seconds, 40);
        assert!(!changed.health.dns_eligible(true, 39));
        assert!(changed.health.dns_eligible(true, 40));
    }

    #[test]
    fn duplicate_and_stale_probe_events_are_idempotent() {
        let (_database, _fleet, mut catalog, primary, _) = setup();
        let mut first = observation(primary.id, 10, true);
        first.event_id = Uuid::new_v4();
        let event_id = first.event_id;
        let accepted = catalog.record_probe(primary.id, first.clone()).unwrap();
        assert!(accepted.accepted);
        let duplicate = catalog.record_probe(primary.id, first).unwrap();
        assert!(duplicate.duplicate);
        assert_eq!(duplicate.health.revision, accepted.health.revision);
        let mut conflicting = observation(primary.id, 10, false);
        conflicting.event_id = event_id;
        let error = catalog
            .record_probe(primary.id, conflicting)
            .expect_err("conflicting idempotency key must fail closed");
        assert!(error.to_string().contains("event ID conflicts"));
        let stale = catalog
            .record_probe(primary.id, observation(primary.id, 9, false))
            .unwrap();
        assert!(!stale.accepted);
        assert_eq!(stale.health.revision, accepted.health.revision);
        let metrics = catalog.metrics().unwrap();
        assert_eq!(metrics.probe_events_total, 2);
        assert_eq!(metrics.probe_failures_total, 0);
    }

    #[test]
    fn concurrent_duplicate_event_is_applied_once() {
        let root = std::env::temp_dir().join(format!("linklake-fleet-health-{}", Uuid::new_v4()));
        let database = Database::persistent(&root).unwrap();
        let mut fleet = FleetCatalog::open_with_database(&database).unwrap();
        let primary = create_peer(&mut fleet, "Primary", 10, 1);
        let _catalog = FleetHealthCatalog::open_with_database(&database).unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let event_id = Uuid::new_v4();
        let mut handles = Vec::new();
        for _ in 0..2 {
            let database = database.clone();
            let barrier = barrier.clone();
            handles.push(std::thread::spawn(move || {
                let mut catalog = FleetHealthCatalog::open_with_database(&database).unwrap();
                barrier.wait();
                let mut event = observation(primary.id, 10, true);
                event.event_id = event_id;
                catalog.record_probe(primary.id, event).unwrap()
            }));
        }
        let results = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|result| result.accepted).count(), 1);
        assert_eq!(results.iter().filter(|result| result.duplicate).count(), 1);
        assert_eq!(
            FleetHealthCatalog::open_with_database(&database)
                .unwrap()
                .snapshot(primary.id)
                .unwrap()
                .unwrap()
                .health
                .revision,
            1
        );
        drop(_catalog);
        drop(fleet);
        drop(database);
        std::fs::remove_dir_all(root).unwrap();
    }

    fn dns_request(primary: Uuid, secondary: Uuid) -> UpsertFleetDnsFailover {
        UpsertFleetDnsFailover {
            name: "Public entry".to_owned(),
            hostname: "link.example.com".to_owned(),
            record_type: FleetDnsRecordType::A,
            zone_id: "0123456789abcdef0123456789abcdef".to_owned(),
            record_id: "fedcba9876543210fedcba9876543210".to_owned(),
            token_env: "LINKLAKE_CLOUDFLARE_TOKEN".to_owned(),
            ttl: 60,
            proxied: false,
            enabled: true,
            cooldown_seconds: 20,
            targets: vec![
                FleetDnsPeerTarget {
                    peer_id: primary,
                    value: "203.0.113.10".to_owned(),
                },
                FleetDnsPeerTarget {
                    peer_id: secondary,
                    value: "203.0.113.20".to_owned(),
                },
            ],
        }
    }

    #[test]
    fn dns_failover_respects_health_and_cooldown_and_survives_reopen() {
        let (database, fleet, mut catalog, primary, secondary) = setup();
        for peer in [&primary, &secondary] {
            catalog
                .update_health_config(
                    peer.id,
                    UpdateFleetHealthConfig {
                        success_threshold: 1,
                        failure_threshold: 1,
                        cooldown_seconds: 5,
                    },
                    1,
                )
                .unwrap();
            catalog
                .record_probe(peer.id, observation(peer.id, 2, true))
                .unwrap();
        }
        let failover = catalog
            .create_dns_failover(
                dns_request(primary.id, secondary.id),
                &fleet.list().unwrap(),
                2,
            )
            .unwrap();
        assert!(catalog.plan_dns_changes(6, None).unwrap().is_empty());
        let plan = catalog.plan_dns_changes(7, None).unwrap().remove(0);
        assert_eq!(plan.peer_id, primary.id);
        catalog.complete_dns_change(&plan, Ok(()), 7).unwrap();
        drop(catalog);
        let mut reopened = FleetHealthCatalog::open_with_database(&database).unwrap();
        let health = reopened.snapshot(primary.id).unwrap().unwrap().health;
        assert_eq!(health.state, FleetHealthState::Healthy);
        assert_eq!(health.last_success_unix_seconds, Some(2));
        let persisted = reopened.get_dns_failover(failover.id).unwrap().unwrap();
        assert_eq!(persisted.current_peer_id, Some(primary.id));
        assert_eq!(
            persisted.last_switch_reason.as_deref(),
            Some("initial_activation")
        );
        assert!(reopened.plan_dns_changes(26, None).unwrap().is_empty());
    }

    #[test]
    fn dns_configuration_change_reconciles_the_same_target_once() {
        let (_database, fleet, mut catalog, primary, secondary) = setup();
        for peer in [&primary, &secondary] {
            catalog
                .update_health_config(
                    peer.id,
                    UpdateFleetHealthConfig {
                        success_threshold: 1,
                        failure_threshold: 1,
                        cooldown_seconds: 0,
                    },
                    1,
                )
                .unwrap();
            catalog
                .record_probe(peer.id, observation(peer.id, 2, true))
                .unwrap();
        }
        let failover = catalog
            .create_dns_failover(
                dns_request(primary.id, secondary.id),
                &fleet.list().unwrap(),
                2,
            )
            .unwrap();
        let initial = catalog.plan_dns_changes(2, None).unwrap().remove(0);
        catalog.complete_dns_change(&initial, Ok(()), 2).unwrap();
        assert!(
            !catalog
                .get_dns_failover(failover.id)
                .unwrap()
                .unwrap()
                .reconcile_required
        );

        let mut updated = dns_request(primary.id, secondary.id);
        updated.ttl = 120;
        updated.proxied = true;
        let updated = catalog
            .update_dns_failover(failover.id, updated, &fleet.list().unwrap(), 23)
            .unwrap()
            .unwrap();
        assert!(updated.reconcile_required);
        let reconcile = catalog.plan_dns_changes(23, None).unwrap().remove(0);
        assert_eq!(reconcile.peer_id, primary.id);
        assert_eq!(reconcile.target, "203.0.113.10");
        assert_eq!(reconcile.ttl, 120);
        assert!(reconcile.proxied);
        assert_eq!(reconcile.reason, "configuration_updated");
        catalog.complete_dns_change(&reconcile, Ok(()), 23).unwrap();

        let applied = catalog.get_dns_failover(failover.id).unwrap().unwrap();
        assert!(!applied.reconcile_required);
        assert_eq!(applied.ttl, 120);
        assert!(applied.proxied);
        assert!(catalog.plan_dns_changes(43, None).unwrap().is_empty());
    }

    #[test]
    fn deleted_pending_peer_is_cleared_and_replaced_by_a_healthy_peer() {
        let (_database, mut fleet, mut catalog, primary, secondary) = setup();
        for peer in [&primary, &secondary] {
            catalog
                .update_health_config(
                    peer.id,
                    UpdateFleetHealthConfig {
                        success_threshold: 1,
                        failure_threshold: 1,
                        cooldown_seconds: 0,
                    },
                    1,
                )
                .unwrap();
            catalog
                .record_probe(peer.id, observation(peer.id, 2, true))
                .unwrap();
        }
        let failover = catalog
            .create_dns_failover(
                dns_request(primary.id, secondary.id),
                &fleet.list().unwrap(),
                2,
            )
            .unwrap();
        let abandoned = catalog.plan_dns_changes(2, None).unwrap().remove(0);
        assert_eq!(abandoned.peer_id, primary.id);
        assert!(fleet.delete(primary.id).unwrap());

        let replacement = catalog.plan_dns_changes(3, None).unwrap().remove(0);
        assert_ne!(replacement.operation_id, abandoned.operation_id);
        assert_eq!(replacement.peer_id, secondary.id);
        assert_eq!(replacement.target, "203.0.113.20");
        assert_eq!(replacement.reason, "initial_activation");
        let pending = catalog.get_dns_failover(failover.id).unwrap().unwrap();
        assert_eq!(pending.pending_operation_id, Some(replacement.operation_id));
        assert_eq!(pending.pending_peer_id, Some(secondary.id));
        assert_eq!(catalog.metrics().unwrap().dns_switch_failures_total, 1);
    }

    #[test]
    fn pending_dns_operation_uses_a_lease_and_completion_is_idempotent() {
        let (database, fleet, mut catalog, primary, secondary) = setup();
        catalog
            .update_health_config(
                primary.id,
                UpdateFleetHealthConfig {
                    success_threshold: 1,
                    failure_threshold: 1,
                    cooldown_seconds: 0,
                },
                1,
            )
            .unwrap();
        catalog
            .record_probe(primary.id, observation(primary.id, 2, true))
            .unwrap();
        catalog
            .create_dns_failover(
                dns_request(primary.id, secondary.id),
                &fleet.list().unwrap(),
                2,
            )
            .unwrap();
        let first = catalog.plan_dns_changes(2, None).unwrap().remove(0);
        assert!(catalog
            .delete_dns_failover(first.failover_id)
            .unwrap_err()
            .to_string()
            .contains("operation is pending"));
        assert!(catalog.plan_dns_changes(31, None).unwrap().is_empty());
        drop(catalog);
        let mut reopened = FleetHealthCatalog::open_with_database(&database).unwrap();
        let retried = reopened.plan_dns_changes(32, None).unwrap().remove(0);
        assert_eq!(retried.operation_id, first.operation_id);
        assert_eq!(retried.peer_id, first.peer_id);
        let mut tampered = retried.clone();
        tampered.target = "203.0.113.99".to_owned();
        assert!(reopened
            .complete_dns_change(&tampered, Ok(()), 32)
            .unwrap_err()
            .to_string()
            .contains("operation is stale"));
        let applied = reopened.complete_dns_change(&retried, Ok(()), 32).unwrap();
        assert!(applied.applied);
        assert!(!applied.duplicate);
        let repeated = reopened.complete_dns_change(&retried, Ok(()), 33).unwrap();
        assert!(repeated.applied);
        assert!(repeated.duplicate);
        assert!(reopened
            .complete_dns_change(&tampered, Ok(()), 34)
            .unwrap_err()
            .to_string()
            .contains("operation is stale"));
        assert_eq!(reopened.metrics().unwrap().dns_switches_total, 1);
    }

    #[test]
    fn expired_pending_dns_operation_revalidates_health_before_retry() {
        let (_database, fleet, mut catalog, primary, secondary) = setup();
        for peer in [&primary, &secondary] {
            catalog
                .update_health_config(
                    peer.id,
                    UpdateFleetHealthConfig {
                        success_threshold: 1,
                        failure_threshold: 1,
                        cooldown_seconds: 0,
                    },
                    1,
                )
                .unwrap();
            catalog
                .record_probe(peer.id, observation(peer.id, 2, true))
                .unwrap();
        }
        catalog
            .create_dns_failover(
                dns_request(primary.id, secondary.id),
                &fleet.list().unwrap(),
                2,
            )
            .unwrap();
        let stale_plan = catalog.plan_dns_changes(2, None).unwrap().remove(0);
        assert_eq!(stale_plan.peer_id, primary.id);
        catalog
            .record_probe(primary.id, observation(primary.id, 3, false))
            .unwrap();
        let replacement = catalog.plan_dns_changes(32, None).unwrap().remove(0);
        assert_ne!(replacement.operation_id, stale_plan.operation_id);
        assert_eq!(replacement.peer_id, secondary.id);
        let metrics = catalog.metrics().unwrap();
        assert_eq!(metrics.dns_switch_failures_total, 1);
        assert_eq!(metrics.dns_operations_pending, 1);
    }

    #[test]
    fn dns_failure_rolls_back_and_freeze_blocks_new_changes() {
        let (_database, fleet, mut catalog, primary, secondary) = setup();
        for peer in [&primary, &secondary] {
            catalog
                .update_health_config(
                    peer.id,
                    UpdateFleetHealthConfig {
                        success_threshold: 1,
                        failure_threshold: 1,
                        cooldown_seconds: 0,
                    },
                    1,
                )
                .unwrap();
            catalog
                .record_probe(peer.id, observation(peer.id, 2, true))
                .unwrap();
        }
        let failover = catalog
            .create_dns_failover(
                dns_request(primary.id, secondary.id),
                &fleet.list().unwrap(),
                2,
            )
            .unwrap();
        let first = catalog.plan_dns_changes(2, None).unwrap().remove(0);
        catalog.complete_dns_change(&first, Ok(()), 2).unwrap();
        catalog
            .record_probe(primary.id, observation(primary.id, 23, false))
            .unwrap();
        let second = catalog.plan_dns_changes(23, None).unwrap().remove(0);
        assert_eq!(second.peer_id, secondary.id);
        let failed = catalog
            .complete_dns_change(&second, Err("provider rejected update\nsecret omitted"), 23)
            .unwrap();
        assert!(!failed.applied);
        let after_failure = catalog.get_dns_failover(failover.id).unwrap().unwrap();
        assert_eq!(after_failure.current_peer_id, Some(primary.id));
        assert_eq!(
            after_failure.current_target.as_deref(),
            Some("203.0.113.10")
        );
        assert!(after_failure
            .last_error_summary
            .as_deref()
            .is_some_and(|value| !value.contains('\n')));
        let events = catalog.list_dns_switch_events(failover.id, 100).unwrap();
        assert_eq!(events.len(), 2);
        assert!(!events[0].applied);
        assert_eq!(events[0].reason, "current_peer_unhealthy");
        assert!(events[1].applied);
        assert!(catalog.plan_dns_changes(42, None).unwrap().is_empty());
        catalog
            .set_dns_frozen(failover.id, true, Some("maintenance"), 43)
            .unwrap();
        assert!(catalog.plan_dns_changes(43, None).unwrap().is_empty());
        catalog
            .set_dns_frozen(failover.id, false, None, 44)
            .unwrap();
        let retry = catalog.plan_dns_changes(44, None).unwrap().remove(0);
        assert_eq!(retry.peer_id, secondary.id);
    }

    #[test]
    fn degraded_current_peer_is_held_until_the_failure_threshold() {
        let (_database, fleet, mut catalog, primary, secondary) = setup();
        catalog
            .update_health_config(
                primary.id,
                UpdateFleetHealthConfig {
                    success_threshold: 1,
                    failure_threshold: 3,
                    cooldown_seconds: 0,
                },
                1,
            )
            .unwrap();
        catalog
            .update_health_config(
                secondary.id,
                UpdateFleetHealthConfig {
                    success_threshold: 1,
                    failure_threshold: 1,
                    cooldown_seconds: 0,
                },
                1,
            )
            .unwrap();
        for peer in [&primary, &secondary] {
            catalog
                .record_probe(peer.id, observation(peer.id, 2, true))
                .unwrap();
        }
        catalog
            .create_dns_failover(
                dns_request(primary.id, secondary.id),
                &fleet.list().unwrap(),
                2,
            )
            .unwrap();
        let initial = catalog.plan_dns_changes(2, None).unwrap().remove(0);
        catalog.complete_dns_change(&initial, Ok(()), 2).unwrap();

        let first_failure = catalog
            .record_probe(primary.id, observation(primary.id, 23, false))
            .unwrap();
        assert_eq!(first_failure.health.state, FleetHealthState::Degraded);
        assert!(catalog.plan_dns_changes(23, None).unwrap().is_empty());
        let second_failure = catalog
            .record_probe(primary.id, observation(primary.id, 24, false))
            .unwrap();
        assert_eq!(second_failure.health.state, FleetHealthState::Degraded);
        assert!(catalog.plan_dns_changes(24, None).unwrap().is_empty());
        let threshold_failure = catalog
            .record_probe(primary.id, observation(primary.id, 25, false))
            .unwrap();
        assert_eq!(threshold_failure.health.state, FleetHealthState::Unhealthy);
        let failover = catalog.plan_dns_changes(25, None).unwrap().remove(0);
        assert_eq!(failover.peer_id, secondary.id);
        assert_eq!(failover.reason, "current_peer_unhealthy");
    }

    #[test]
    fn unrelated_peer_failure_does_not_disturb_the_current_dns_target() {
        let (_database, fleet, mut catalog, primary, secondary) = setup();
        for peer in [&primary, &secondary] {
            catalog
                .update_health_config(
                    peer.id,
                    UpdateFleetHealthConfig {
                        success_threshold: 1,
                        failure_threshold: 1,
                        cooldown_seconds: 0,
                    },
                    1,
                )
                .unwrap();
            catalog
                .record_probe(peer.id, observation(peer.id, 2, true))
                .unwrap();
        }
        let failover = catalog
            .create_dns_failover(
                dns_request(primary.id, secondary.id),
                &fleet.list().unwrap(),
                2,
            )
            .unwrap();
        let initial = catalog.plan_dns_changes(2, None).unwrap().remove(0);
        catalog.complete_dns_change(&initial, Ok(()), 2).unwrap();
        let primary_revision = catalog
            .snapshot(primary.id)
            .unwrap()
            .unwrap()
            .health
            .revision;

        let unrelated = catalog
            .record_probe(secondary.id, observation(secondary.id, 23, false))
            .unwrap();
        assert_eq!(unrelated.health.state, FleetHealthState::Unhealthy);
        assert!(catalog.plan_dns_changes(23, None).unwrap().is_empty());
        assert_eq!(
            catalog
                .get_dns_failover(failover.id)
                .unwrap()
                .unwrap()
                .current_peer_id,
            Some(primary.id)
        );
        assert_eq!(
            catalog
                .snapshot(primary.id)
                .unwrap()
                .unwrap()
                .health
                .revision,
            primary_revision
        );
    }

    #[test]
    fn recovered_preferred_peer_waits_for_health_cooldown_before_failback() {
        let (_database, fleet, mut catalog, primary, secondary) = setup();
        for peer in [&primary, &secondary] {
            catalog
                .update_health_config(
                    peer.id,
                    UpdateFleetHealthConfig {
                        success_threshold: 1,
                        failure_threshold: 1,
                        cooldown_seconds: 0,
                    },
                    1,
                )
                .unwrap();
            catalog
                .record_probe(peer.id, observation(peer.id, 2, true))
                .unwrap();
        }
        catalog
            .create_dns_failover(
                dns_request(primary.id, secondary.id),
                &fleet.list().unwrap(),
                2,
            )
            .unwrap();
        let initial = catalog.plan_dns_changes(2, None).unwrap().remove(0);
        catalog.complete_dns_change(&initial, Ok(()), 2).unwrap();
        catalog
            .update_health_config(
                primary.id,
                UpdateFleetHealthConfig {
                    success_threshold: 1,
                    failure_threshold: 1,
                    cooldown_seconds: 5,
                },
                3,
            )
            .unwrap();
        catalog
            .record_probe(primary.id, observation(primary.id, 23, false))
            .unwrap();
        let failover = catalog.plan_dns_changes(23, None).unwrap().remove(0);
        assert_eq!(failover.peer_id, secondary.id);
        catalog.complete_dns_change(&failover, Ok(()), 23).unwrap();

        let recovered = catalog
            .record_probe(primary.id, observation(primary.id, 44, true))
            .unwrap();
        assert_eq!(recovered.health.state, FleetHealthState::Healthy);
        assert_eq!(recovered.health.cooldown_until_unix_seconds, 49);
        assert!(catalog.plan_dns_changes(48, None).unwrap().is_empty());
        let failback = catalog.plan_dns_changes(49, None).unwrap().remove(0);
        assert_eq!(failback.peer_id, primary.id);
        assert_eq!(failback.reason, "preferred_peer_recovered");
    }

    #[test]
    fn token_value_is_never_persisted() {
        let (database, fleet, mut catalog, primary, secondary) = setup();
        let secret = format!("secret-{}", Uuid::new_v4());
        let previous = std::env::var_os("LINKLAKE_CLOUDFLARE_TOKEN");
        std::env::set_var("LINKLAKE_CLOUDFLARE_TOKEN", &secret);
        let failover = catalog
            .create_dns_failover(
                dns_request(primary.id, secondary.id),
                &fleet.list().unwrap(),
                2,
            )
            .unwrap();
        assert!(failover.token_configured);
        let found = database
            .with_connection(|connection| {
                let mut statement = connection.prepare(
                    "SELECT name, hostname, zone_id, record_id, token_env,
                            COALESCE(current_target, ''), COALESCE(last_error_summary, '')
                     FROM fleet_dns_failovers",
                )?;
                let mut rows = statement.query([])?;
                let mut found = false;
                while let Some(row) = rows.next()? {
                    for index in 0..7 {
                        let value = row.get::<_, String>(index)?;
                        found |= value.contains(&secret);
                    }
                }
                Ok(found)
            })
            .unwrap();
        if let Some(previous) = previous {
            std::env::set_var("LINKLAKE_CLOUDFLARE_TOKEN", previous);
        } else {
            std::env::remove_var("LINKLAKE_CLOUDFLARE_TOKEN");
        }
        assert!(!found);
    }

    #[test]
    fn dns_contract_rejects_raw_provider_secret_fields() {
        let request = serde_json::json!({
            "name": "Public entry",
            "hostname": "link.example.com",
            "record_type": "A",
            "zone_id": "0123456789abcdef0123456789abcdef",
            "record_id": "fedcba9876543210fedcba9876543210",
            "token_env": "LINKLAKE_CLOUDFLARE_TOKEN",
            "token": "must-not-be-accepted",
            "ttl": 60,
            "enabled": true,
            "cooldown_seconds": 30,
            "targets": [{
                "peer_id": Uuid::new_v4(),
                "value": "203.0.113.10"
            }]
        });
        assert!(serde_json::from_value::<UpsertFleetDnsFailover>(request).is_err());
    }

    #[test]
    fn cloudflare_token_environment_is_provider_scoped() {
        assert!(valid_secret_env("LINKLAKE_CLOUDFLARE_TOKEN"));
        assert!(valid_secret_env(
            "LINKLAKE_CLOUDFLARE_FLEET_HEALTH_E2E_TOKEN"
        ));
        assert!(!valid_secret_env("LINKLAKE_MANAGEMENT_TOKEN"));
        assert!(!valid_secret_env("LINKLAKE_ENROLLMENT_TOKEN"));
    }
}
