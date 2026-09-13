//! PostgreSQL 共享流量控制：精确策略锁串行授权/记账，热路径不取得 Fleet 全局目录锁。

use super::*;
use crate::{
    ha_runtime::HaRuntime,
    policy_service::{postgres::FleetPolicyTransaction, FleetPolicyKind},
    storage::CoordinationStorage,
};
use sha2::{Digest, Sha256};
use std::{fmt, sync::Arc};
use tokio_postgres::{GenericClient, Row, Transaction};

pub(crate) struct PostgresTrafficControlCatalog {
    pub(crate) storage: CoordinationStorage,
    pub(crate) runtime: Arc<HaRuntime>,
}

#[derive(Debug)]
pub(crate) struct ManagedTrafficPolicy;
impl fmt::Display for ManagedTrafficPolicy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("fleet_managed_policy")
    }
}
impl std::error::Error for ManagedTrafficPolicy {}

fn fleet_kind(kind: TrafficPolicyKind) -> FleetPolicyKind {
    match kind {
        TrafficPolicyKind::Tcp => FleetPolicyKind::Tcp,
        TrafficPolicyKind::Udp => FleetPolicyKind::Udp,
        TrafficPolicyKind::Http => FleetPolicyKind::HttpRoute,
        TrafficPolicyKind::Sni => FleetPolicyKind::SniRoute,
        TrafficPolicyKind::Secret => FleetPolicyKind::SecretTunnel,
        TrafficPolicyKind::Socks5 => FleetPolicyKind::Socks5Proxy,
        TrafficPolicyKind::HttpProxy => FleetPolicyKind::HttpProxy,
        TrafficPolicyKind::PortGroup => FleetPolicyKind::PortGroup,
    }
}

fn policy_lock_key(kind: TrafficPolicyKind, policy_id: Uuid) -> i64 {
    let mut hash = Sha256::new();
    hash.update(b"linklake-traffic-policy-v1\0");
    hash.update(kind.as_str().as_bytes());
    hash.update(policy_id.as_bytes());
    let digest = hash.finalize();
    let mut key = [0u8; 8];
    key[..2].copy_from_slice(b"TC");
    key[2..].copy_from_slice(&digest[..6]);
    i64::from_be_bytes(key)
}

async fn lock_policy(
    transaction: &Transaction<'_>,
    kind: TrafficPolicyKind,
    id: Uuid,
) -> anyhow::Result<()> {
    transaction
        .query_one(
            "SELECT pg_advisory_xact_lock($1)",
            &[&policy_lock_key(kind, id)],
        )
        .await?;
    Ok(())
}

async fn database_now(client: &(impl GenericClient + Sync)) -> anyhow::Result<u64> {
    let now: i64 = client
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp()))::bigint",
            &[],
        )
        .await?
        .try_get(0)?;
    Ok(u64::try_from(now)?)
}

fn read_record(row: &Row) -> anyhow::Result<TrafficControlRecord> {
    let kind: &str = row.try_get("kind")?;
    let policy_id: &str = row.try_get("policy_id")?;
    let json: &str = row.try_get("settings")?;
    let used: &str = row.try_get("used_today_bytes")?;
    decode_record(
        kind,
        policy_id,
        json,
        used,
        row.try_get("updated_unix_seconds")?,
    )
}

fn decode_record(
    kind: &str,
    policy_id: &str,
    json: &str,
    used: &str,
    updated: i64,
) -> anyhow::Result<TrafficControlRecord> {
    let parsed_kind = TrafficPolicyKind::parse(kind)?;
    anyhow::ensure!(
        parsed_kind.as_str() == kind,
        "Traffic control kind is not canonical"
    );
    let settings: UpsertTrafficControl = serde_json::from_str(json)?;
    anyhow::ensure!(
        serde_json::from_str::<serde_json::Value>(json)? == serde_json::to_value(&settings)?,
        "Traffic control settings contain missing or noncanonical fields"
    );
    anyhow::ensure!(
        normalized_settings(settings.clone())? == settings,
        "Traffic control settings are not canonical"
    );
    Ok(TrafficControlRecord {
        kind: parsed_kind,
        policy_id: Uuid::parse_str(policy_id)?,
        settings,
        used_today_bytes: used.parse()?,
        updated_unix_seconds: u64::try_from(updated)?,
    })
}

async fn read_at(
    client: &(impl GenericClient + Sync),
    kind: TrafficPolicyKind,
    id: Uuid,
    now: u64,
) -> anyhow::Result<Option<TrafficControlRecord>> {
    let day = i64::try_from(utc_day(now))?;
    client.query_opt(
        "SELECT control.kind,control.policy_id,control.settings::text,control.updated_unix_seconds,LEAST(18446744073709551615::numeric,COALESCE(usage.bytes,0)+COALESCE((SELECT SUM(event.bytes) FROM linklake_traffic_usage_events AS event WHERE event.kind=control.kind AND event.policy_id=control.policy_id AND event.utc_day=usage_day.day AND NOT event.applied),0))::text AS used_today_bytes
         FROM linklake_traffic_controls AS control CROSS JOIN (SELECT $3::bigint AS day) AS usage_day
         LEFT JOIN linklake_traffic_daily_usage AS usage ON usage.kind=control.kind AND usage.policy_id=control.policy_id AND usage.utc_day=$3
         WHERE control.kind=$1 AND control.policy_id=$2", &[&kind.as_str(), &id.to_string(), &day],
    ).await?.as_ref().map(read_record).transpose()
}

fn admission_decision(record: &TrafficControlRecord, source: IpAddr, now: u64) -> TrafficDecision {
    let settings = &record.settings;
    if !settings.enabled {
        return TrafficDecision::Allowed;
    }
    if settings
        .denied_cidrs
        .iter()
        .any(|cidr| cidr_matches(cidr, source))
        || (!settings.allowed_cidrs.is_empty()
            && !settings
                .allowed_cidrs
                .iter()
                .any(|cidr| cidr_matches(cidr, source)))
    {
        return TrafficDecision::SourceDenied;
    }
    if !schedule_allows(settings, now) {
        return TrafficDecision::OutsideSchedule;
    }
    if settings
        .daily_quota_bytes
        .is_some_and(|quota| record.used_today_bytes >= quota)
    {
        return TrafficDecision::QuotaExceeded;
    }
    TrafficDecision::Allowed
}

impl PostgresTrafficControlCatalog {
    async fn fence(&self, transaction: &Transaction<'_>, token: u64) -> anyhow::Result<()> {
        self.runtime
            .coordinator()
            .assert_postgres_transaction_fence(transaction, token)
            .await
    }

    pub(crate) async fn get(
        &self,
        kind: TrafficPolicyKind,
        id: Uuid,
    ) -> anyhow::Result<Option<TrafficControlRecord>> {
        let client = self.storage.postgres_client().await?;
        let now = database_now(&*client).await?;
        read_at(&*client, kind, id, now).await
    }

    pub(crate) async fn upsert(
        &self,
        kind: TrafficPolicyKind,
        id: Uuid,
        request: UpsertTrafficControl,
    ) -> anyhow::Result<TrafficControlRecord> {
        let settings = normalized_settings(request)?;
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        let guard = FleetPolicyTransaction::lock(&transaction, &self.runtime).await?;
        ensure_unmanaged(&guard, kind, id).await?;
        let record = transaction_put(&guard, kind, id, settings).await?;
        guard.assert_current().await?;
        transaction.commit().await?;
        Ok(record)
    }

    pub(crate) async fn delete(&self, kind: TrafficPolicyKind, id: Uuid) -> anyhow::Result<bool> {
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        let guard = FleetPolicyTransaction::lock(&transaction, &self.runtime).await?;
        ensure_unmanaged(&guard, kind, id).await?;
        let deleted = transaction_delete(&guard, kind, id).await?;
        guard.assert_current().await?;
        transaction.commit().await?;
        Ok(deleted)
    }

    pub(crate) async fn authorize(
        &self,
        kind: TrafficPolicyKind,
        id: Uuid,
        source: IpAddr,
    ) -> anyhow::Result<TrafficDecision> {
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        let token = self.runtime.fencing_token()?;
        // 先 Leader/member 共享行锁，再策略锁；与配置事务保持相同顺序。
        self.fence(&transaction, token).await?;
        lock_policy(&transaction, kind, id).await?;
        let now = database_now(&transaction).await?;
        let mut decision = TrafficDecision::Allowed;
        if let Some(record) = read_at(&transaction, kind, id, now).await? {
            decision = admission_decision(&record, source, now);
            if decision == TrafficDecision::Allowed && record.settings.enabled {
                if let Some(limit) = record.settings.max_connections_per_minute {
                    decision = reserve_connection(&transaction, kind, id, now, limit).await?;
                }
            }
        }
        self.fence(&transaction, token).await?;
        transaction.commit().await?;
        Ok(decision)
    }

    #[cfg(test)]
    pub(crate) async fn record_usage_event(&self, event: &TrafficUsageEvent) -> anyhow::Result<()> {
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        let token = self.runtime.fencing_token()?;
        self.fence(&transaction, token).await?;
        insert_event(&transaction, event).await?;
        apply_event(&transaction, event.event_id).await?;
        self.fence(&transaction, token).await?;
        transaction.commit().await?;
        Ok(())
    }

    /// 当前有效成员可以卸载旧Leader的最终账务；应用日账仅由当前Leader执行。
    pub(crate) async fn enqueue_usage_event(
        &self,
        event: &TrafficUsageEvent,
    ) -> anyhow::Result<()> {
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        self.assert_member(&transaction).await?;
        insert_event(&transaction, event).await?;
        self.assert_member(&transaction).await?;
        transaction.commit().await?;
        Ok(())
    }

    async fn assert_member(&self, transaction: &Transaction<'_>) -> anyhow::Result<()> {
        let coordinator = self.runtime.coordinator();
        let active = transaction.query_opt(
            "SELECT lease_until>clock_timestamp() FROM linklake_ha_members WHERE instance_id=$1 AND incarnation_id=$2 FOR SHARE",
            &[&coordinator.instance_id(), &coordinator.incarnation_id()],
        ).await?.is_some_and(|row| row.get::<_,bool>(0));
        anyhow::ensure!(active, "Traffic usage uploader membership expired");
        Ok(())
    }

    pub(crate) async fn drain_pending_usage(&self) -> anyhow::Result<usize> {
        // Follower上传后由集群Leader接管应用，无需在本机等待成为Leader。
        let Ok(token) = self.runtime.fencing_token() else {
            return Ok(0);
        };
        let ids: Vec<String> = self.storage.postgres_client().await?.query(
            "SELECT event_id FROM linklake_traffic_usage_events WHERE NOT applied ORDER BY received_unix_seconds,event_id LIMIT 64", &[],
        ).await?.iter().map(|row| row.try_get(0)).collect::<Result<_,_>>()?;
        let mut applied = 0;
        for id in ids {
            let mut client = self.storage.postgres_client().await?;
            let transaction = client.transaction().await?;
            self.fence(&transaction, token).await?;
            if apply_event(&transaction, Uuid::parse_str(&id)?).await? {
                applied += 1;
            }
            self.fence(&transaction, token).await?;
            transaction.commit().await?;
        }
        Ok(applied)
    }
    /// PG 没有进程内速率缓存；配置事务已清理所修改策略的窗口。
    /// 这里不得清空整个集群，否则一个 Fleet 应用会重置所有无关策略的速率限制。
    pub(crate) async fn reset_runtime_state(&self) -> anyhow::Result<()> {
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        self.fence(&transaction, self.runtime.fencing_token()?)
            .await?;
        transaction.commit().await?;
        Ok(())
    }
}

async fn insert_event(
    transaction: &Transaction<'_>,
    event: &TrafficUsageEvent,
) -> anyhow::Result<()> {
    anyhow::ensure!(!event.event_id.is_nil(), "Traffic usage event ID is nil");
    let now = database_now(transaction).await?;
    transaction.execute(
        "INSERT INTO linklake_traffic_usage_events(event_id,kind,policy_id,bytes,utc_day,received_unix_seconds,applied) VALUES($1,$2,$3,$4::text::numeric,$5,$6,false) ON CONFLICT(event_id) DO NOTHING",
        &[&event.event_id.to_string(), &event.kind.as_str(), &event.policy_id.to_string(), &event.bytes.to_string(), &i64::try_from(utc_day(now))?, &i64::try_from(now)?],
    ).await?;
    let row = transaction.query_one("SELECT kind,policy_id,bytes::text FROM linklake_traffic_usage_events WHERE event_id=$1 FOR UPDATE", &[&event.event_id.to_string()]).await?;
    anyhow::ensure!(
        row.try_get::<_, String>(0)? == event.kind.as_str()
            && row.try_get::<_, String>(1)? == event.policy_id.to_string()
            && row.try_get::<_, String>(2)? == event.bytes.to_string(),
        "Traffic usage event identity mismatch"
    );
    // 先事件行再策略锁，与应用器相同；授权查询在该锁下将pending计入配额。
    lock_policy(transaction, event.kind, event.policy_id).await?;
    Ok(())
}

async fn apply_event(transaction: &Transaction<'_>, event_id: Uuid) -> anyhow::Result<bool> {
    let row = transaction.query_one("SELECT kind,policy_id,bytes::text,utc_day,applied FROM linklake_traffic_usage_events WHERE event_id=$1 FOR UPDATE", &[&event_id.to_string()]).await?;
    if row.try_get::<_, bool>(4)? {
        return Ok(false);
    }
    let kind = TrafficPolicyKind::parse(row.try_get(0)?)?;
    let id = Uuid::parse_str(row.try_get(1)?)?;
    let bytes: u64 = row.try_get::<_, &str>(2)?.parse()?;
    let day: i64 = row.try_get(3)?;
    anyhow::ensure!(day >= 0, "Traffic usage event day is invalid");
    lock_policy(transaction, kind, id).await?;
    transaction.execute(
        "INSERT INTO linklake_traffic_daily_usage(kind,policy_id,utc_day,bytes) VALUES($1,$2,$3,$4::text::numeric)
         ON CONFLICT(kind,policy_id,utc_day) DO UPDATE SET bytes=LEAST(18446744073709551615::numeric,linklake_traffic_daily_usage.bytes+EXCLUDED.bytes)",
        &[&kind.as_str(), &id.to_string(), &day, &bytes.to_string()],
    ).await?;
    transaction
        .execute(
            "UPDATE linklake_traffic_usage_events SET applied=true WHERE event_id=$1",
            &[&event_id.to_string()],
        )
        .await?;
    Ok(true)
}

async fn reserve_connection(
    transaction: &Transaction<'_>,
    kind: TrafficPolicyKind,
    id: Uuid,
    now: u64,
    limit: u32,
) -> anyhow::Result<TrafficDecision> {
    let now = i64::try_from(now)?;
    let cutoff = now.saturating_sub(60);
    transaction.execute("DELETE FROM linklake_traffic_connection_windows WHERE kind=$1 AND policy_id=$2 AND unix_second<=$3", &[&kind.as_str(), &id.to_string(), &cutoff]).await?;
    // 数据库时钟倒退时保留未来桶，保守拒绝而不是借回拨绕过限制。
    let used: i64 = transaction.query_one("SELECT COALESCE(SUM(connections),0)::bigint FROM linklake_traffic_connection_windows WHERE kind=$1 AND policy_id=$2", &[&kind.as_str(), &id.to_string()]).await?.try_get(0)?;
    anyhow::ensure!(used >= 0, "Traffic connection window is invalid");
    if used >= i64::from(limit) {
        return Ok(TrafficDecision::RateLimited);
    }
    transaction.execute(
        "INSERT INTO linklake_traffic_connection_windows(kind,policy_id,unix_second,connections) VALUES($1,$2,$3,1)
         ON CONFLICT(kind,policy_id,unix_second) DO UPDATE SET connections=linklake_traffic_connection_windows.connections+1",
        &[&kind.as_str(), &id.to_string(), &now],
    ).await?;
    Ok(TrafficDecision::Allowed)
}

async fn ensure_unmanaged(
    guard: &FleetPolicyTransaction<'_, '_>,
    kind: TrafficPolicyKind,
    id: Uuid,
) -> anyhow::Result<()> {
    if guard.is_policy_managed(fleet_kind(kind), id).await? {
        return Err(ManagedTrafficPolicy.into());
    }
    Ok(())
}

pub(crate) async fn transaction_list(
    guard: &FleetPolicyTransaction<'_, '_>,
) -> anyhow::Result<Vec<TrafficControlRecord>> {
    guard.assert_current().await?;
    let transaction = guard.transaction();
    let day = i64::try_from(utc_day(database_now(transaction).await?))?;
    transaction.query(
        "SELECT control.kind,control.policy_id,control.settings::text,control.updated_unix_seconds,LEAST(18446744073709551615::numeric,COALESCE(usage.bytes,0)+COALESCE((SELECT SUM(event.bytes) FROM linklake_traffic_usage_events AS event WHERE event.kind=control.kind AND event.policy_id=control.policy_id AND event.utc_day=usage_day.day AND NOT event.applied),0))::text AS used_today_bytes
         FROM linklake_traffic_controls AS control CROSS JOIN (SELECT $1::bigint AS day) AS usage_day LEFT JOIN linklake_traffic_daily_usage AS usage
         ON usage.kind=control.kind AND usage.policy_id=control.policy_id AND usage.utc_day=$1 ORDER BY control.kind,control.policy_id", &[&day],
    ).await?.iter().map(read_record).collect()
}

pub(crate) async fn transaction_put(
    guard: &FleetPolicyTransaction<'_, '_>,
    kind: TrafficPolicyKind,
    id: Uuid,
    request: UpsertTrafficControl,
) -> anyhow::Result<TrafficControlRecord> {
    let settings = normalized_settings(request)?;
    guard.assert_current().await?;
    let transaction = guard.transaction();
    lock_policy(transaction, kind, id).await?;
    let now = database_now(transaction).await?;
    transaction.execute(
        "INSERT INTO linklake_traffic_controls(kind,policy_id,settings,updated_unix_seconds) VALUES($1,$2,$3::text::jsonb,$4)
         ON CONFLICT(kind,policy_id) DO UPDATE SET settings=EXCLUDED.settings,updated_unix_seconds=EXCLUDED.updated_unix_seconds",
        &[&kind.as_str(), &id.to_string(), &serde_json::to_string(&settings)?, &i64::try_from(now)?],
    ).await?;
    clear_connection_window(transaction, kind, id).await?;
    read_at(transaction, kind, id, now)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Traffic control disappeared during mutation"))
}

pub(crate) async fn transaction_delete(
    guard: &FleetPolicyTransaction<'_, '_>,
    kind: TrafficPolicyKind,
    id: Uuid,
) -> anyhow::Result<bool> {
    guard.assert_current().await?;
    let transaction = guard.transaction();
    lock_policy(transaction, kind, id).await?;
    clear_connection_window(transaction, kind, id).await?;
    // 删除控制规则保留日账务，与 SQLite 一致，重新创建不会重置已用配额。
    Ok(transaction
        .execute(
            "DELETE FROM linklake_traffic_controls WHERE kind=$1 AND policy_id=$2",
            &[&kind.as_str(), &id.to_string()],
        )
        .await?
        != 0)
}

async fn clear_connection_window(
    transaction: &Transaction<'_>,
    kind: TrafficPolicyKind,
    id: Uuid,
) -> anyhow::Result<()> {
    transaction
        .execute(
            "DELETE FROM linklake_traffic_connection_windows WHERE kind=$1 AND policy_id=$2",
            &[&kind.as_str(), &id.to_string()],
        )
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> UpsertTrafficControl {
        UpsertTrafficControl {
            allowed_cidrs: vec!["10.0.0.0/8".into()],
            denied_cidrs: vec!["10.1.0.0/16".into()],
            max_connections_per_minute: Some(2),
            daily_quota_bytes: Some(u64::MAX),
            active_weekdays_utc: vec![],
            start_minute_utc: None,
            end_minute_utc: None,
            enabled: true,
        }
    }

    fn record(settings: UpsertTrafficControl, used: u64) -> TrafficControlRecord {
        TrafficControlRecord {
            kind: TrafficPolicyKind::Http,
            policy_id: Uuid::new_v4(),
            settings,
            used_today_bytes: used,
            updated_unix_seconds: 1,
        }
    }

    #[test]
    fn shared_json_rejects_missing_defaults_invalid_ranges_and_noncanonical_cidrs() {
        let id = Uuid::new_v4().to_string();
        let settings = settings();
        let json = serde_json::to_value(&settings).unwrap();
        assert!(decode_record("http", &id, &json.to_string(), &u64::MAX.to_string(), 1).is_ok());
        let mut missing = json.clone();
        missing.as_object_mut().unwrap().remove("allowed_cidrs");
        assert!(decode_record("http", &id, &missing.to_string(), "0", 1).is_err());
        missing = json.clone();
        missing.as_object_mut().unwrap().remove("enabled");
        assert!(decode_record("http", &id, &missing.to_string(), "0", 1).is_err());
        let mut damaged = settings.clone();
        damaged.max_connections_per_minute = Some(0);
        assert!(decode_record(
            "http",
            &id,
            &serde_json::to_string(&damaged).unwrap(),
            "0",
            1
        )
        .is_err());
        damaged = settings.clone();
        damaged.allowed_cidrs = vec!["10.0.0.1".into()];
        assert!(decode_record(
            "http",
            &id,
            &serde_json::to_string(&damaged).unwrap(),
            "0",
            1
        )
        .is_err());
        assert!(decode_record("http-proxy", &id, &json.to_string(), "0", 1).is_err());
        assert!(decode_record("http", &id, &json.to_string(), "18446744073709551616", 1).is_err());
        assert!(decode_record("http", &id, &json.to_string(), "0", -1).is_err());
    }

    #[test]
    fn admission_uses_denial_precedence_schedule_and_full_u64_quota() {
        let policy = record(settings(), u64::MAX - 1);
        let allowed = "10.2.3.4".parse().unwrap();
        assert_eq!(
            admission_decision(&policy, allowed, 100),
            TrafficDecision::Allowed
        );
        assert_eq!(
            admission_decision(&policy, "10.1.2.3".parse().unwrap(), 100),
            TrafficDecision::SourceDenied
        );
        assert_eq!(
            admission_decision(&policy, "192.0.2.1".parse().unwrap(), 100),
            TrafficDecision::SourceDenied
        );
        let mut exhausted = policy;
        exhausted.used_today_bytes = u64::MAX;
        assert_eq!(
            admission_decision(&exhausted, allowed, 100),
            TrafficDecision::QuotaExceeded
        );
        exhausted.settings.start_minute_utc = Some(23 * 60);
        exhausted.settings.end_minute_utc = Some(60);
        assert_eq!(
            admission_decision(&exhausted, allowed, 12 * 3600),
            TrafficDecision::OutsideSchedule
        );
        exhausted.settings.enabled = false;
        assert_eq!(
            admission_decision(&exhausted, "192.0.2.1".parse().unwrap(), 12 * 3600),
            TrafficDecision::Allowed
        );
    }

    #[test]
    fn policy_locks_separate_protocols_and_identifiers() {
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        assert_eq!(
            policy_lock_key(TrafficPolicyKind::Tcp, first),
            policy_lock_key(TrafficPolicyKind::Tcp, first)
        );
        assert_ne!(
            policy_lock_key(TrafficPolicyKind::Tcp, first),
            policy_lock_key(TrafficPolicyKind::Udp, first)
        );
        assert_ne!(
            policy_lock_key(TrafficPolicyKind::Tcp, first),
            policy_lock_key(TrafficPolicyKind::Tcp, second)
        );
    }
}
