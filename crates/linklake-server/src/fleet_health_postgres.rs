//! PostgreSQL Fleet 健康与 DNS 状态；所有写入校验 Leader，并在共享事务内完成。

use super::*;
use crate::{ha_runtime::HaRuntime, storage::CoordinationStorage};
use std::sync::Arc;
use tokio_postgres::Transaction as PgTransaction;

pub(crate) struct PostgresFleetHealthCatalog {
    pub(crate) storage: CoordinationStorage,
    pub(crate) runtime: Arc<HaRuntime>,
}

impl PostgresFleetHealthCatalog {
    async fn fence(&self, transaction: &PgTransaction<'_>) -> anyhow::Result<()> {
        // 健康、DNS 选路与事件提交使用同一数据库锁，避免并发观察导致重复切换。
        transaction
            .query_one(
                "SELECT pg_advisory_xact_lock($1)",
                &[&crate::fleet_store::FLEET_STATE_LOCK],
            )
            .await?;
        let token = self.runtime.fencing_token()?;
        self.runtime
            .coordinator()
            .assert_postgres_transaction_fence(transaction, token)
            .await?;
        Ok(())
    }

    pub(crate) async fn ensure_peer(&self, peer_id: Uuid, now: u64) -> anyhow::Result<()> {
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        self.fence(&transaction).await?;
        ensure_peer(&transaction, peer_id, now).await?;
        transaction.commit().await?;
        Ok(())
    }

    pub(crate) async fn snapshot(
        &self,
        peer_id: Uuid,
    ) -> anyhow::Result<Option<FleetHealthSnapshot>> {
        let client = self.storage.postgres_client().await?;
        client
            .query_opt(
                "SELECT snapshot::text FROM linklake_fleet_health WHERE peer_id=$1",
                &[&peer_id.to_string()],
            )
            .await?
            .map(|row| serde_json::from_str(row.get::<_, &str>(0)).map_err(Into::into))
            .transpose()
    }

    pub(crate) async fn snapshots(&self) -> anyhow::Result<HashMap<Uuid, FleetHealthSnapshot>> {
        let client = self.storage.postgres_client().await?;
        let rows = client
            .query(
                "SELECT peer_id, snapshot::text FROM linklake_fleet_health",
                &[],
            )
            .await?;
        rows.iter()
            .map(|row| {
                Ok((
                    Uuid::parse_str(row.get(0))?,
                    serde_json::from_str(row.get(1))?,
                ))
            })
            .collect()
    }

    pub(crate) async fn update_health_config(
        &self,
        peer_id: Uuid,
        request: UpdateFleetHealthConfig,
        now: u64,
    ) -> anyhow::Result<Option<FleetHealthSnapshot>> {
        validate_health_config(&request)?;
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        self.fence(&transaction).await?;
        ensure_peer(&transaction, peer_id, now).await?;
        let mut snapshot = locked_snapshot(&transaction, peer_id).await?;
        snapshot.config = FleetHealthConfig {
            peer_id,
            success_threshold: request.success_threshold,
            failure_threshold: request.failure_threshold,
            cooldown_seconds: request.cooldown_seconds,
            updated_unix_seconds: now,
        };
        snapshot.health.cooldown_until_unix_seconds = snapshot
            .health
            .state_changed_unix_seconds
            .saturating_add(u64::from(request.cooldown_seconds));
        save_snapshot(&transaction, &snapshot).await?;
        transaction.commit().await?;
        Ok(Some(snapshot))
    }

    pub(crate) async fn record_probe(
        &self,
        peer_id: Uuid,
        observation: FleetProbeObservation,
    ) -> anyhow::Result<FleetProbeResult> {
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        self.fence(&transaction).await?;
        ensure_peer(&transaction, peer_id, observation.observed_unix_seconds).await?;
        let mut snapshot = locked_snapshot(&transaction, peer_id).await?;
        let previous_state = snapshot.health.state;
        if let Some(row) = transaction.query_opt(
            "SELECT peer_id, observed_unix_seconds, success FROM linklake_fleet_probe_events WHERE event_id=$1",
            &[&observation.event_id.to_string()],
        ).await? {
            anyhow::ensure!(row.get::<_, String>(0) == peer_id.to_string()
                && row.get::<_, i64>(1) == i64::try_from(observation.observed_unix_seconds)?
                && row.get::<_, bool>(2) == observation.success,
                "fleet probe event ID conflicts with an existing event");
            transaction.commit().await?;
            return Ok(FleetProbeResult { peer_id, accepted: false, duplicate: true,
                previous_state, health: snapshot.health, transition_reason: "duplicate_event_ignored".to_owned() });
        }
        let accepted = !snapshot
            .health
            .last_probe_unix_seconds
            .is_some_and(|last| observation.observed_unix_seconds < last);
        let transition_reason = if accepted {
            let (state, successes, failures, reason) = next_health_state(
                previous_state,
                snapshot.health.consecutive_successes,
                snapshot.health.consecutive_failures,
                observation.success,
                snapshot.config.success_threshold,
                snapshot.config.failure_threshold,
            );
            let health = &mut snapshot.health;
            health.state = state;
            health.consecutive_successes = successes;
            health.consecutive_failures = failures;
            if state != previous_state {
                health.state_changed_unix_seconds = observation.observed_unix_seconds;
                health.cooldown_until_unix_seconds = observation
                    .observed_unix_seconds
                    .saturating_add(u64::from(snapshot.config.cooldown_seconds));
            }
            health.last_probe_unix_seconds = Some(observation.observed_unix_seconds);
            if observation.success {
                health.last_success_unix_seconds = Some(observation.observed_unix_seconds);
                health.last_error_summary = None;
            } else {
                health.last_failure_unix_seconds = Some(observation.observed_unix_seconds);
                health.last_error_summary = Some(
                    observation
                        .error_summary
                        .as_deref()
                        .map(summarize_error)
                        .filter(|value| !value.is_empty())
                        .unwrap_or_else(|| "probe failed".to_owned()),
                );
            }
            health.last_latency_millis = observation.latency_millis;
            health.last_transition_reason = reason.to_owned();
            health.revision = health
                .revision
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("fleet health revision exhausted"))?;
            health.active_connections = observation.active_connections;
            health.bytes_total = observation.bytes_total;
            health.clients = observation.clients;
            health.policies = observation.policies;
            save_snapshot(&transaction, &snapshot).await?;
            reason
        } else {
            "stale_event_ignored"
        };
        transaction.execute(
            "INSERT INTO linklake_fleet_probe_events (event_id, peer_id, observed_unix_seconds, success, accepted, transition_reason) VALUES ($1,$2,$3,$4,$5,$6)",
            &[&observation.event_id.to_string(), &peer_id.to_string(), &i64::try_from(observation.observed_unix_seconds)?, &observation.success, &accepted, &transition_reason],
        ).await?;
        increment(&transaction, "probe_events_total").await?;
        if accepted && !observation.success {
            increment(&transaction, "probe_failures_total").await?;
        }
        if accepted && previous_state != snapshot.health.state {
            increment(&transaction, "health_transitions_total").await?;
        }
        transaction.execute(
            "DELETE FROM linklake_fleet_probe_events WHERE event_id IN (SELECT event_id FROM linklake_fleet_probe_events WHERE peer_id=$1 ORDER BY observed_unix_seconds DESC, sequence DESC OFFSET $2)",
            &[&peer_id.to_string(), &i64::try_from(MAX_PROBE_EVENTS_PER_PEER)?],
        ).await?;
        transaction.commit().await?;
        Ok(FleetProbeResult {
            peer_id,
            accepted,
            duplicate: false,
            previous_state,
            health: snapshot.health,
            transition_reason: transition_reason.to_owned(),
        })
    }
}

async fn ensure_peer(
    transaction: &PgTransaction<'_>,
    peer_id: Uuid,
    now: u64,
) -> anyhow::Result<()> {
    let exists = transaction
        .query_opt(
            "SELECT id FROM linklake_fleet_peers WHERE id=$1 FOR KEY SHARE",
            &[&peer_id.to_string()],
        )
        .await?;
    anyhow::ensure!(exists.is_some(), "fleet peer does not exist");
    let snapshot = FleetHealthSnapshot {
        config: FleetHealthConfig {
            peer_id,
            success_threshold: DEFAULT_SUCCESS_THRESHOLD,
            failure_threshold: DEFAULT_FAILURE_THRESHOLD,
            cooldown_seconds: DEFAULT_HEALTH_COOLDOWN_SECONDS,
            updated_unix_seconds: now,
        },
        health: FleetPeerHealth {
            peer_id,
            state: FleetHealthState::Unknown,
            consecutive_successes: 0,
            consecutive_failures: 0,
            last_probe_unix_seconds: None,
            last_success_unix_seconds: None,
            last_failure_unix_seconds: None,
            last_latency_millis: None,
            last_error_summary: None,
            state_changed_unix_seconds: now,
            cooldown_until_unix_seconds: now,
            last_transition_reason: "awaiting_first_probe".to_owned(),
            revision: 0,
            active_connections: 0,
            bytes_total: 0,
            clients: 0,
            policies: 0,
        },
    };
    transaction.execute("INSERT INTO linklake_fleet_health (peer_id, snapshot) VALUES ($1,$2::text::jsonb) ON CONFLICT (peer_id) DO NOTHING",
        &[&peer_id.to_string(), &serde_json::to_string(&snapshot)?]).await?;
    Ok(())
}

async fn locked_snapshot(
    transaction: &PgTransaction<'_>,
    peer_id: Uuid,
) -> anyhow::Result<FleetHealthSnapshot> {
    let row = transaction
        .query_one(
            "SELECT snapshot::text FROM linklake_fleet_health WHERE peer_id=$1 FOR UPDATE",
            &[&peer_id.to_string()],
        )
        .await?;
    Ok(serde_json::from_str(row.get(0))?)
}

async fn save_snapshot(
    transaction: &PgTransaction<'_>,
    snapshot: &FleetHealthSnapshot,
) -> anyhow::Result<()> {
    transaction
        .execute(
            "UPDATE linklake_fleet_health SET snapshot=$2::text::jsonb WHERE peer_id=$1",
            &[
                &snapshot.health.peer_id.to_string(),
                &serde_json::to_string(snapshot)?,
            ],
        )
        .await?;
    Ok(())
}

async fn increment(transaction: &PgTransaction<'_>, name: &str) -> anyhow::Result<()> {
    transaction.execute("INSERT INTO linklake_fleet_health_counters (name, value) VALUES ($1,1) ON CONFLICT (name) DO UPDATE SET value=linklake_fleet_health_counters.value+1", &[&name]).await?;
    Ok(())
}

impl PostgresFleetHealthCatalog {
    pub(crate) async fn list_dns_failovers(&self) -> anyhow::Result<Vec<FleetDnsFailover>> {
        let client = self.storage.postgres_client().await?;
        client
            .query(
                "SELECT snapshot::text FROM linklake_fleet_dns_failovers ORDER BY name",
                &[],
            )
            .await?
            .iter()
            .map(decode_dns)
            .collect()
    }

    pub(crate) async fn get_dns_failover(
        &self,
        id: Uuid,
    ) -> anyhow::Result<Option<FleetDnsFailover>> {
        let client = self.storage.postgres_client().await?;
        client
            .query_opt(
                "SELECT snapshot::text FROM linklake_fleet_dns_failovers WHERE id=$1",
                &[&id.to_string()],
            )
            .await?
            .as_ref()
            .map(decode_dns)
            .transpose()
    }

    pub(crate) async fn create_dns_failover(
        &self,
        request: UpsertFleetDnsFailover,
        peers: &[FleetPeer],
        now: u64,
    ) -> anyhow::Result<FleetDnsFailover> {
        let request = validate_dns_failover(request, peers)?;
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        self.fence(&transaction).await?;
        validate_shared_targets(&transaction, &request.targets).await?;
        let value = FleetDnsFailover {
            id: Uuid::new_v4(),
            name: request.name,
            hostname: request.hostname,
            record_type: request.record_type,
            zone_id: request.zone_id,
            record_id: request.record_id,
            token_configured: std::env::var(&request.token_env)
                .is_ok_and(|value| !value.trim().is_empty()),
            token_env: request.token_env,
            ttl: request.ttl,
            proxied: request.proxied,
            enabled: request.enabled,
            reconcile_required: true,
            cooldown_seconds: request.cooldown_seconds,
            frozen: false,
            freeze_reason: None,
            current_peer_id: None,
            current_target: None,
            last_switch_unix_seconds: None,
            next_change_not_before_unix_seconds: now,
            last_switch_reason: None,
            last_error_summary: None,
            pending_operation_id: None,
            pending_peer_id: None,
            pending_target: None,
            pending_reason: None,
            pending_started_unix_seconds: None,
            pending_lease_until_unix_seconds: None,
            targets: request.targets,
            created_unix_seconds: now,
            updated_unix_seconds: now,
        };
        transaction.execute("INSERT INTO linklake_fleet_dns_failovers (id,name,zone_id,record_id,snapshot) VALUES ($1,$2,$3,$4,$5::text::jsonb)",
            &[&value.id.to_string(), &value.name, &value.zone_id, &value.record_id, &serde_json::to_string(&value)?]).await?;
        transaction.commit().await?;
        Ok(value)
    }

    pub(crate) async fn update_dns_failover(
        &self,
        id: Uuid,
        request: UpsertFleetDnsFailover,
        peers: &[FleetPeer],
        now: u64,
    ) -> anyhow::Result<Option<FleetDnsFailover>> {
        let request = validate_dns_failover(request, peers)?;
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        self.fence(&transaction).await?;
        let Some(mut value) = locked_dns(&transaction, id).await? else {
            return Ok(None);
        };
        anyhow::ensure!(
            value.pending_operation_id.is_none(),
            "fleet DNS failover operation is pending"
        );
        validate_shared_targets(&transaction, &request.targets).await?;
        value.name = request.name;
        value.hostname = request.hostname;
        value.record_type = request.record_type;
        value.zone_id = request.zone_id;
        value.record_id = request.record_id;
        value.token_env = request.token_env;
        value.token_configured =
            std::env::var(&value.token_env).is_ok_and(|value| !value.trim().is_empty());
        value.ttl = request.ttl;
        value.proxied = request.proxied;
        value.enabled = request.enabled;
        value.cooldown_seconds = request.cooldown_seconds;
        value.targets = request.targets;
        value.reconcile_required = true;
        value.updated_unix_seconds = now;
        save_dns(&transaction, &value).await?;
        transaction.commit().await?;
        Ok(Some(value))
    }

    pub(crate) async fn delete_dns_failover(&self, id: Uuid) -> anyhow::Result<bool> {
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        self.fence(&transaction).await?;
        let Some(value) = locked_dns(&transaction, id).await? else {
            return Ok(false);
        };
        anyhow::ensure!(
            value.pending_operation_id.is_none(),
            "fleet DNS failover operation is pending"
        );
        let deleted = transaction
            .execute(
                "DELETE FROM linklake_fleet_dns_failovers WHERE id=$1",
                &[&id.to_string()],
            )
            .await?;
        transaction.commit().await?;
        Ok(deleted > 0)
    }

    pub(crate) async fn set_dns_frozen(
        &self,
        id: Uuid,
        frozen: bool,
        reason: Option<&str>,
        now: u64,
    ) -> anyhow::Result<Option<FleetDnsFailover>> {
        let reason = if frozen {
            let value = summarize_error(reason.unwrap_or("manual freeze"));
            anyhow::ensure!(!value.is_empty(), "fleet DNS freeze reason is required");
            Some(value)
        } else {
            None
        };
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        self.fence(&transaction).await?;
        let Some(mut value) = locked_dns(&transaction, id).await? else {
            return Ok(None);
        };
        value.frozen = frozen;
        value.freeze_reason = reason;
        value.updated_unix_seconds = now;
        save_dns(&transaction, &value).await?;
        transaction.commit().await?;
        Ok(Some(value))
    }

    pub(crate) async fn list_dns_switch_events(
        &self,
        id: Uuid,
        limit: usize,
    ) -> anyhow::Result<Vec<FleetDnsSwitchEvent>> {
        let client = self.storage.postgres_client().await?;
        let rows = client.query("SELECT snapshot::text FROM linklake_fleet_dns_events WHERE failover_id=$1 ORDER BY completed_unix_seconds DESC, operation_id DESC LIMIT $2", &[&id.to_string(), &(limit.clamp(1,500) as i64)]).await?;
        rows.iter()
            .map(|row| serde_json::from_str(row.get(0)).map_err(Into::into))
            .collect()
    }

    pub(crate) async fn complete_dns_change(
        &self,
        plan: &FleetDnsChangePlan,
        result: Result<(), &str>,
        now: u64,
    ) -> anyhow::Result<FleetDnsChangeResult> {
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        self.fence(&transaction).await?;
        if let Some(row) = transaction
            .query_opt(
                "SELECT snapshot::text FROM linklake_fleet_dns_events WHERE operation_id=$1",
                &[&plan.operation_id.to_string()],
            )
            .await?
        {
            let event: FleetDnsSwitchEvent = serde_json::from_str(row.get(0))?;
            anyhow::ensure!(
                event.failover_id == plan.failover_id
                    && event.peer_id == plan.peer_id
                    && event.target == plan.target
                    && event.reason == plan.reason,
                "fleet DNS operation is stale"
            );
            transaction.commit().await?;
            return Ok(FleetDnsChangeResult {
                operation_id: event.operation_id,
                failover_id: event.failover_id,
                peer_id: event.peer_id,
                target: event.target,
                reason: event.reason,
                applied: event.applied,
                duplicate: true,
                error_summary: event.error_summary,
            });
        }
        let mut value = locked_dns(&transaction, plan.failover_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("fleet DNS failover does not exist"))?;
        anyhow::ensure!(
            value.pending_operation_id == Some(plan.operation_id)
                && value.pending_peer_id == Some(plan.peer_id)
                && value.pending_target.as_deref() == Some(plan.target.as_str())
                && value.pending_reason.as_deref() == Some(plan.reason.as_str()),
            "fleet DNS operation is stale"
        );
        let applied = result.is_ok();
        let error_summary = result.err().map(summarize_error);
        record_dns_event(&transaction, plan, applied, error_summary.clone(), now).await?;
        if applied {
            value.current_peer_id = Some(plan.peer_id);
            value.current_target = Some(plan.target.clone());
            value.last_switch_unix_seconds = Some(now);
            value.last_switch_reason = Some(plan.reason.clone());
            value.reconcile_required = false;
        }
        value.last_error_summary = error_summary.clone();
        value.next_change_not_before_unix_seconds =
            now.saturating_add(u64::from(value.cooldown_seconds));
        value.updated_unix_seconds = now;
        clear_pending(&mut value);
        save_dns(&transaction, &value).await?;
        transaction.commit().await?;
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
}

fn decode_dns(row: &tokio_postgres::Row) -> anyhow::Result<FleetDnsFailover> {
    let mut value: FleetDnsFailover = serde_json::from_str(row.get(0))?;
    // Token 是否存在属于当前实例环境，不能沿用写入节点保存的结果。
    value.token_configured =
        std::env::var(&value.token_env).is_ok_and(|value| !value.trim().is_empty());
    Ok(value)
}

async fn locked_dns(
    transaction: &PgTransaction<'_>,
    id: Uuid,
) -> anyhow::Result<Option<FleetDnsFailover>> {
    transaction
        .query_opt(
            "SELECT snapshot::text FROM linklake_fleet_dns_failovers WHERE id=$1 FOR UPDATE",
            &[&id.to_string()],
        )
        .await?
        .as_ref()
        .map(decode_dns)
        .transpose()
}

async fn save_dns(transaction: &PgTransaction<'_>, value: &FleetDnsFailover) -> anyhow::Result<()> {
    transaction.execute("UPDATE linklake_fleet_dns_failovers SET name=$2,zone_id=$3,record_id=$4,snapshot=$5::text::jsonb WHERE id=$1",
        &[&value.id.to_string(), &value.name, &value.zone_id, &value.record_id, &serde_json::to_string(value)?]).await?;
    Ok(())
}

async fn validate_shared_targets(
    transaction: &PgTransaction<'_>,
    targets: &[FleetDnsPeerTarget],
) -> anyhow::Result<()> {
    for target in targets {
        let exists = transaction
            .query_opt(
                "SELECT id FROM linklake_fleet_peers WHERE id=$1 FOR KEY SHARE",
                &[&target.peer_id.to_string()],
            )
            .await?;
        anyhow::ensure!(exists.is_some(), "fleet DNS target peer does not exist");
    }
    Ok(())
}

fn clear_pending(value: &mut FleetDnsFailover) {
    value.pending_operation_id = None;
    value.pending_peer_id = None;
    value.pending_target = None;
    value.pending_reason = None;
    value.pending_started_unix_seconds = None;
    value.pending_lease_until_unix_seconds = None;
}

async fn record_dns_event(
    transaction: &PgTransaction<'_>,
    plan: &FleetDnsChangePlan,
    applied: bool,
    error_summary: Option<String>,
    now: u64,
) -> anyhow::Result<()> {
    let event = FleetDnsSwitchEvent {
        operation_id: plan.operation_id,
        failover_id: plan.failover_id,
        peer_id: plan.peer_id,
        target: plan.target.clone(),
        reason: plan.reason.clone(),
        applied,
        error_summary,
        completed_unix_seconds: now,
    };
    transaction.execute("INSERT INTO linklake_fleet_dns_events (operation_id,failover_id,completed_unix_seconds,snapshot) VALUES ($1,$2,$3,$4::text::jsonb)",
        &[&plan.operation_id.to_string(), &plan.failover_id.to_string(), &i64::try_from(now)?, &serde_json::to_string(&event)?]).await?;
    increment(
        transaction,
        if applied {
            "dns_switches_total"
        } else {
            "dns_switch_failures_total"
        },
    )
    .await
}

impl PostgresFleetHealthCatalog {
    pub(crate) async fn plan_dns_changes(
        &self,
        now: u64,
        only: Option<Uuid>,
    ) -> anyhow::Result<Vec<FleetDnsChangePlan>> {
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        self.fence(&transaction).await?;
        let peers = shared_peers(&transaction).await?;
        let only_text = only.map(|id| id.to_string());
        let rows = transaction.query("SELECT snapshot::text FROM linklake_fleet_dns_failovers WHERE ($1::text IS NULL OR id=$1) ORDER BY name FOR UPDATE", &[&only_text]).await?;
        let mut plans = Vec::new();
        for row in rows {
            let mut value = decode_dns(&row)?;
            if !value.enabled || value.frozen {
                continue;
            }
            let candidates = candidates(&value, &peers, now);
            let pending_any = value.pending_operation_id.is_some()
                || value.pending_peer_id.is_some()
                || value.pending_target.is_some()
                || value.pending_reason.is_some();
            let pending_complete = value.pending_operation_id.is_some()
                && value.pending_peer_id.is_some()
                && value.pending_target.is_some()
                && value.pending_reason.is_some();
            if pending_any && !pending_complete {
                increment(&transaction, "dns_switch_failures_total").await?;
                clear_pending(&mut value);
                value.last_error_summary =
                    Some("incomplete pending DNS operation was cleared".to_owned());
                value.updated_unix_seconds = now;
                save_dns(&transaction, &value).await?;
            }
            if let (Some(operation_id), Some(peer_id), Some(target), Some(reason)) = (
                value.pending_operation_id,
                value.pending_peer_id,
                value.pending_target.clone(),
                value.pending_reason.clone(),
            ) {
                if value
                    .pending_lease_until_unix_seconds
                    .is_some_and(|lease| lease > now)
                {
                    continue;
                }
                let peer_name = peers
                    .iter()
                    .find(|(peer, _)| peer.id == peer_id)
                    .map(|(peer, _)| peer.name.clone())
                    .unwrap_or_else(|| peer_id.to_string());
                let plan = change_plan(
                    &value,
                    operation_id,
                    peer_id,
                    peer_name,
                    target.clone(),
                    reason,
                );
                if candidates
                    .iter()
                    .any(|candidate| candidate.peer_id == peer_id && candidate.target == target)
                {
                    value.pending_lease_until_unix_seconds =
                        Some(now.saturating_add(DNS_OPERATION_LEASE_SECONDS));
                    value.updated_unix_seconds = now;
                    save_dns(&transaction, &value).await?;
                    plans.push(plan);
                    continue;
                }
                let error = "pending DNS target no longer satisfies health and cooldown".to_owned();
                record_dns_event(&transaction, &plan, false, Some(error.clone()), now).await?;
                clear_pending(&mut value);
                value.last_error_summary = Some(error);
                value.updated_unix_seconds = now;
                save_dns(&transaction, &value).await?;
            }
            if now < value.next_change_not_before_unix_seconds || hold_current(&value, &peers, now)
            {
                continue;
            }
            let Some(candidate) = candidates.first() else {
                continue;
            };
            if value.current_peer_id == Some(candidate.peer_id)
                && value.current_target.as_deref() == Some(candidate.target.as_str())
                && !value.reconcile_required
            {
                continue;
            }
            let reason = switch_reason(&value, &peers, candidate).to_owned();
            let operation_id = Uuid::new_v4();
            value.pending_operation_id = Some(operation_id);
            value.pending_peer_id = Some(candidate.peer_id);
            value.pending_target = Some(candidate.target.clone());
            value.pending_reason = Some(reason.clone());
            value.pending_started_unix_seconds = Some(now);
            value.pending_lease_until_unix_seconds =
                Some(now.saturating_add(DNS_OPERATION_LEASE_SECONDS));
            value.updated_unix_seconds = now;
            save_dns(&transaction, &value).await?;
            plans.push(change_plan(
                &value,
                operation_id,
                candidate.peer_id,
                candidate.peer_name.clone(),
                candidate.target.clone(),
                reason,
            ));
        }
        transaction.commit().await?;
        Ok(plans)
    }

    pub(crate) async fn metrics(&self) -> anyhow::Result<FleetHealthMetrics> {
        let mut client = self.storage.postgres_client().await?;
        let transaction = client
            .build_transaction()
            .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
            .read_only(true)
            .start()
            .await?;
        let mut result = FleetHealthMetrics::default();
        for (peer, snapshot) in shared_peers(&transaction).await? {
            if !peer.enabled {
                continue;
            }
            let Some(snapshot) = snapshot else {
                continue;
            };
            match snapshot.health.state {
                FleetHealthState::Unknown => result.peers_unknown += 1,
                FleetHealthState::Healthy => result.peers_healthy += 1,
                FleetHealthState::Degraded => result.peers_degraded += 1,
                FleetHealthState::Unhealthy => result.peers_unhealthy += 1,
                FleetHealthState::Recovering => result.peers_recovering += 1,
            }
        }
        for row in transaction
            .query(
                "SELECT name, value FROM linklake_fleet_health_counters",
                &[],
            )
            .await?
        {
            let count = u64::try_from(row.get::<_, i64>(1))?;
            match row.get::<_, &str>(0) {
                "probe_events_total" => result.probe_events_total = count,
                "probe_failures_total" => result.probe_failures_total = count,
                "health_transitions_total" => result.health_transitions_total = count,
                "dns_switches_total" => result.dns_switches_total = count,
                "dns_switch_failures_total" => result.dns_switch_failures_total = count,
                _ => (),
            }
        }
        for row in transaction
            .query(
                "SELECT snapshot::text FROM linklake_fleet_dns_failovers",
                &[],
            )
            .await?
        {
            let value = decode_dns(&row)?;
            result.dns_failovers_total += 1;
            result.dns_failovers_frozen += u64::from(value.frozen);
            result.dns_operations_pending += u64::from(value.pending_operation_id.is_some());
        }
        transaction.commit().await?;
        Ok(result)
    }
}

type SharedPeers = Vec<(FleetPeer, Option<FleetHealthSnapshot>)>;

async fn shared_peers(transaction: &PgTransaction<'_>) -> anyhow::Result<SharedPeers> {
    let rows = transaction.query("SELECT p.id,p.name,p.url,p.region,p.weight,p.priority,p.token_env,p.enabled,p.created_unix_seconds,p.updated_unix_seconds,h.snapshot::text FROM linklake_fleet_peers p LEFT JOIN linklake_fleet_health h ON h.peer_id=p.id", &[]).await?;
    rows.iter()
        .map(|row| {
            Ok((
                crate::fleet_store::read_peer(row)?,
                row.get::<_, Option<&str>>(10)
                    .map(serde_json::from_str)
                    .transpose()?,
            ))
        })
        .collect()
}

fn candidates(value: &FleetDnsFailover, peers: &SharedPeers, now: u64) -> Vec<DnsCandidate> {
    let mut candidates = Vec::new();
    for target in &value.targets {
        let Some((peer, Some(snapshot))) = peers.iter().find(|(peer, _)| peer.id == target.peer_id)
        else {
            continue;
        };
        if !snapshot.health.dns_eligible(peer.enabled, now)
            || validate_dns_target(value.record_type, &target.value).is_err()
        {
            continue;
        }
        candidates.push(DnsCandidate {
            peer_id: peer.id,
            peer_name: peer.name.clone(),
            priority: peer.priority,
            weight: peer.weight,
            target: target.value.clone(),
        });
    }
    candidates.sort_by_key(|candidate| {
        (
            candidate.priority,
            std::cmp::Reverse(candidate.weight),
            candidate.peer_name.clone(),
        )
    });
    candidates
}

fn current_is_configured(value: &FleetDnsFailover, peer_id: Uuid) -> bool {
    value.targets.iter().any(|target| {
        target.peer_id == peer_id && Some(target.value.as_str()) == value.current_target.as_deref()
    })
}

fn hold_current(value: &FleetDnsFailover, peers: &SharedPeers, now: u64) -> bool {
    let Some((peer, Some(snapshot))) = peers
        .iter()
        .find(|(peer, _)| Some(peer.id) == value.current_peer_id)
    else {
        return false;
    };
    if !peer.enabled || !current_is_configured(value, peer.id) {
        return false;
    }
    snapshot.health.state == FleetHealthState::Degraded
        || (snapshot.health.state == FleetHealthState::Healthy
            && now < snapshot.health.cooldown_until_unix_seconds)
}

fn switch_reason(
    value: &FleetDnsFailover,
    peers: &SharedPeers,
    candidate: &DnsCandidate,
) -> &'static str {
    let Some(id) = value.current_peer_id else {
        return "initial_activation";
    };
    if id == candidate.peer_id {
        return if value.current_target.as_deref() == Some(candidate.target.as_str())
            && value.reconcile_required
        {
            "configuration_updated"
        } else {
            "target_value_changed"
        };
    }
    let Some((peer, snapshot)) = peers.iter().find(|(peer, _)| peer.id == id) else {
        return "current_peer_removed";
    };
    if !peer.enabled {
        return "current_peer_disabled";
    }
    if !current_is_configured(value, id) {
        return "current_target_removed";
    }
    match snapshot.as_ref().map(|snapshot| snapshot.health.state) {
        Some(FleetHealthState::Unhealthy) => "current_peer_unhealthy",
        Some(FleetHealthState::Recovering) => "current_peer_recovering",
        Some(FleetHealthState::Unknown) => "current_peer_unknown",
        Some(FleetHealthState::Degraded) => "current_peer_degraded",
        _ => "preferred_peer_recovered",
    }
}

// 与 SQLite 外键的 SET NULL / CASCADE 保持一致，保留切换历史和待处理操作其余字段。
pub(crate) async fn remove_peer_references(
    transaction: &PgTransaction<'_>,
    peer_id: Uuid,
) -> anyhow::Result<()> {
    let rows = transaction
        .query(
            "SELECT snapshot::text FROM linklake_fleet_dns_failovers FOR UPDATE",
            &[],
        )
        .await?;
    for row in rows {
        let mut value = decode_dns(&row)?;
        let old_len = value.targets.len();
        value.targets.retain(|target| target.peer_id != peer_id);
        let changed = old_len != value.targets.len()
            || value.current_peer_id == Some(peer_id)
            || value.pending_peer_id == Some(peer_id);
        if value.current_peer_id == Some(peer_id) {
            value.current_peer_id = None;
        }
        if value.pending_peer_id == Some(peer_id) {
            value.pending_peer_id = None;
        }
        if changed {
            save_dns(transaction, &value).await?;
        }
    }
    Ok(())
}
