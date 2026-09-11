//! DNS-01 发布意图与清理账本；必须先提交意图，再向外部服务创建记录。

use crate::{
    certificate_catalog::postgres::certificate_job_key, ha_runtime::HaRuntime,
    job_leases::JobLease, storage::CoordinationStorage,
};
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

const JOURNAL_LOCK: i64 = 0x4c4c_444e_5330_314a;
const MAX_INTENTS: i64 = 4096;
const SQLITE_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS dns01_intents (
    id TEXT PRIMARY KEY NOT NULL,
    provider TEXT NOT NULL,
    next_cleanup INTEGER NOT NULL,
    state TEXT NOT NULL CHECK(length(state)<=16384)
);
CREATE INDEX IF NOT EXISTS dns01_intents_due ON dns01_intents(provider,next_cleanup);
"#;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Dns01Intent {
    pub(crate) id: Uuid,
    pub(crate) identifier: String,
    pub(crate) provider: String,
    pub(crate) zone_id: String,
    pub(crate) record_name: String,
    pub(crate) value: String,
    pub(crate) record_id: Option<String>,
    pub(crate) creation_observed: bool,
    pub(crate) creation_rejected: bool,
    pub(crate) job_key: String,
    pub(crate) job_lease_id: String,
    pub(crate) cleanup_requested: bool,
    pub(crate) next_cleanup: i64,
}

impl Dns01Intent {
    pub(crate) fn comment(&self) -> String {
        format!("LinkLake DNS-01 {}", self.id)
    }

    pub(crate) fn cleanup_job_key(&self) -> String {
        format!("dns01_cleanup:{}", self.id)
    }
}

pub(crate) enum Dns01Mutation {
    Create(Dns01Intent),
    Published(String),
    Rejected,
    RequestCleanup,
    AuthorizeCleanup,
    ObservedCreation,
    RetryCleanup,
    CompleteCleanup,
}

impl Dns01Mutation {
    fn cleanup(&self) -> bool {
        matches!(
            self,
            Self::AuthorizeCleanup
                | Self::ObservedCreation
                | Self::RetryCleanup
                | Self::CompleteCleanup
        )
    }
}

pub(crate) struct Dns01JournalStore {
    storage: CoordinationStorage,
    pub(crate) runtime: Arc<HaRuntime>,
}

impl Dns01JournalStore {
    pub(crate) fn open(
        storage: CoordinationStorage,
        runtime: Arc<HaRuntime>,
    ) -> anyhow::Result<Self> {
        if let CoordinationStorage::Sqlite(database) = &storage {
            database.with_transaction(|transaction| {
                transaction.execute_batch(SQLITE_SCHEMA)?;
                Ok(())
            })?;
        }
        Ok(Self { storage, runtime })
    }

    pub(crate) async fn apply(
        &self,
        id: Uuid,
        lease: &JobLease,
        mutation: Dns01Mutation,
    ) -> anyhow::Result<Option<Dns01Intent>> {
        match &self.storage {
            CoordinationStorage::Sqlite(database) => database.with_transaction(|transaction| {
                self.runtime.jobs().assert_sqlite_transaction_lease(transaction, lease)?;
                let now: i64 = transaction.query_row("SELECT unixepoch('now')", [], |row| row.get(0))?;
                let current = transaction.query_row("SELECT state FROM dns01_intents WHERE id=?1", [id.to_string()], |row| row.get::<_,String>(0)).optional()?
                    .map(|text| serde_json::from_str::<Dns01Intent>(&text)).transpose()?;
                if matches!(&mutation, Dns01Mutation::Create(_)) {
                    let count: i64 = transaction.query_row("SELECT count(*) FROM dns01_intents", [], |row| row.get(0))?;
                    anyhow::ensure!(count < MAX_INTENTS, "DNS-01 cleanup journal capacity reached");
                }
                let owner_active = if let Some(intent) = &current {
                    transaction.query_row("SELECT EXISTS(
                        SELECT 1 FROM job_leases AS job
                        JOIN ha_leader AS leader ON leader.instance_id=job.owner_instance_id AND leader.incarnation_id=job.owner_incarnation_id AND leader.fencing_token=job.fencing_token
                        JOIN ha_members AS member ON member.instance_id=job.owner_instance_id AND member.incarnation_id=job.owner_incarnation_id
                        WHERE job.job_key=?1 AND job.lease_id=?2 AND job.job_kind='certificate'
                        AND job.lease_until_unix_seconds>?3 AND leader.lease_until_unix_seconds>?3 AND member.lease_until_unix_seconds>?3)",
                        params![intent.job_key,intent.job_lease_id,now], |row| row.get::<_,bool>(0))?
                } else { false };
                let next = transition(id, lease, current, mutation, owner_active, now)?;
                match &next {
                    Some(intent) => { transaction.execute("INSERT INTO dns01_intents(id,provider,next_cleanup,state) VALUES(?1,?2,?3,?4)
                        ON CONFLICT(id) DO UPDATE SET provider=excluded.provider,next_cleanup=excluded.next_cleanup,state=excluded.state",
                        params![id.to_string(),intent.provider,intent.next_cleanup,serde_json::to_string(intent)?])?; }
                    None => { transaction.execute("DELETE FROM dns01_intents WHERE id=?1", [id.to_string()])?; }
                }
                Ok(next)
            }),
            CoordinationStorage::Postgres(_) => {
                let mut client = self.storage.postgres_client().await?;
                let transaction = client.transaction().await?;
                transaction.query_one("SELECT pg_advisory_xact_lock($1)", &[&JOURNAL_LOCK]).await?;
                self.runtime.jobs().assert_postgres_transaction_lease(&transaction, lease).await?;
                let now: i64 = transaction.query_one("SELECT floor(EXTRACT(EPOCH FROM clock_timestamp()))::bigint", &[]).await?.get(0);
                let current = transaction.query_opt("SELECT state::text FROM linklake_dns01_intents WHERE id=$1 FOR UPDATE", &[&id.to_string()]).await?
                    .map(|row| serde_json::from_str::<Dns01Intent>(row.get(0))).transpose()?;
                if matches!(&mutation, Dns01Mutation::Create(_)) {
                    let count: i64 = transaction.query_one("SELECT count(*) FROM linklake_dns01_intents", &[]).await?.get(0);
                    anyhow::ensure!(count < MAX_INTENTS, "DNS-01 cleanup journal capacity reached");
                }
                let owner_active = if let Some(intent) = &current {
                    self.runtime.jobs().lock_postgres_transaction_job(&transaction, &intent.job_key).await?;
                    transaction.query_one("SELECT EXISTS(
                        SELECT 1 FROM linklake_job_leases AS job
                        JOIN linklake_ha_leader AS leader ON leader.instance_id=job.owner_instance_id AND leader.incarnation_id=job.owner_incarnation_id AND leader.fencing_token=job.fencing_token
                        JOIN linklake_ha_members AS member ON member.instance_id=job.owner_instance_id AND member.incarnation_id=job.owner_incarnation_id
                        WHERE job.job_key=$1 AND job.lease_id=$2 AND job.job_kind='certificate'
                        AND job.lease_until>clock_timestamp() AND leader.lease_until>clock_timestamp() AND member.lease_until>clock_timestamp())",
                        &[&intent.job_key,&intent.job_lease_id]).await?.get::<_,bool>(0)
                } else { false };
                let next = transition(id, lease, current, mutation, owner_active, now)?;
                match &next {
                    Some(intent) => { transaction.execute("INSERT INTO linklake_dns01_intents(id,provider,next_cleanup,state) VALUES($1,$2,$3,$4::text::jsonb)
                        ON CONFLICT(id) DO UPDATE SET provider=excluded.provider,next_cleanup=excluded.next_cleanup,state=excluded.state",
                        &[&id.to_string(),&intent.provider,&intent.next_cleanup,&serde_json::to_string(intent)?]).await?; }
                    None => { transaction.execute("DELETE FROM linklake_dns01_intents WHERE id=$1", &[&id.to_string()]).await?; }
                }
                transaction.commit().await?;
                Ok(next)
            }
        }
    }

    pub(crate) async fn due(&self, provider: &str) -> anyhow::Result<Vec<Dns01Intent>> {
        let rows = match &self.storage {
            CoordinationStorage::Sqlite(database) => database.with_connection(|connection| {
                // 在 LIMIT 前排除仍在签发的意图，避免前 32 条活动订单饿死后面的清理。
                let mut statement = connection.prepare("SELECT intent.state FROM dns01_intents AS intent
                    WHERE intent.provider=?1 AND intent.next_cleanup<=unixepoch('now')
                    AND (json_extract(intent.state,'$.cleanup_requested')=1 OR NOT EXISTS (
                        SELECT 1 FROM job_leases AS job
                        JOIN ha_leader AS leader ON leader.instance_id=job.owner_instance_id AND leader.incarnation_id=job.owner_incarnation_id AND leader.fencing_token=job.fencing_token
                        JOIN ha_members AS member ON member.instance_id=job.owner_instance_id AND member.incarnation_id=job.owner_incarnation_id
                        WHERE job.job_key=json_extract(intent.state,'$.job_key')
                        AND job.lease_id=json_extract(intent.state,'$.job_lease_id') AND job.job_kind='certificate'
                        AND job.lease_until_unix_seconds>unixepoch('now')
                        AND leader.lease_until_unix_seconds>unixepoch('now')
                        AND member.lease_until_unix_seconds>unixepoch('now')))
                    ORDER BY intent.next_cleanup,intent.id LIMIT 32")?;
                let rows = statement.query_map([provider], |row| row.get::<_,String>(0))?;
                Ok(rows.collect::<Result<Vec<_>,_>>()?)
            })?,
            CoordinationStorage::Postgres(_) => self.storage.postgres_client().await?.query(
                "SELECT intent.state::text FROM linklake_dns01_intents AS intent
                    WHERE intent.provider=$1 AND intent.next_cleanup<=floor(EXTRACT(EPOCH FROM clock_timestamp()))::bigint
                    AND (intent.state->>'cleanup_requested'='true' OR NOT EXISTS (
                        SELECT 1 FROM linklake_job_leases AS job
                        JOIN linklake_ha_leader AS leader ON leader.instance_id=job.owner_instance_id AND leader.incarnation_id=job.owner_incarnation_id AND leader.fencing_token=job.fencing_token
                        JOIN linklake_ha_members AS member ON member.instance_id=job.owner_instance_id AND member.incarnation_id=job.owner_incarnation_id
                        WHERE job.job_key=intent.state->>'job_key'
                        AND job.lease_id=intent.state->>'job_lease_id' AND job.job_kind='certificate'
                        AND job.lease_until>clock_timestamp() AND leader.lease_until>clock_timestamp()
                        AND member.lease_until>clock_timestamp()))
                    ORDER BY intent.next_cleanup,intent.id LIMIT 32", &[&provider],
            ).await?.iter().map(|row| row.get::<_,String>(0)).collect(),
        };
        rows.iter()
            .map(|text| Ok(serde_json::from_str(text)?))
            .collect()
    }
}

fn transition(
    id: Uuid,
    lease: &JobLease,
    current: Option<Dns01Intent>,
    mutation: Dns01Mutation,
    owner_active: bool,
    now: i64,
) -> anyhow::Result<Option<Dns01Intent>> {
    if mutation.cleanup() {
        anyhow::ensure!(
            lease.job_kind == "dns01_cleanup" && lease.job_key == format!("dns01_cleanup:{id}"),
            "DNS-01 cleanup job does not match intent"
        );
        let Some(mut intent) = current else {
            return Ok(None);
        };
        anyhow::ensure!(
            intent.id == id && (intent.cleanup_requested || !owner_active),
            "DNS-01 issuance is still active; refusing cleanup"
        );
        if matches!(mutation, Dns01Mutation::CompleteCleanup) {
            anyhow::ensure!(
                intent.creation_observed || intent.creation_rejected,
                "DNS-01 creation is unresolved; retain the cleanup intent"
            );
            return Ok(None);
        }
        intent.cleanup_requested = true;
        if matches!(mutation, Dns01Mutation::ObservedCreation) {
            intent.creation_observed = true;
        }
        intent.next_cleanup = now.saturating_add(60);
        return Ok(Some(intent));
    }
    let mut intent = match &mutation {
        Dns01Mutation::Create(intent) => {
            anyhow::ensure!(
                current.is_none()
                    && intent.id == id
                    && intent.record_id.is_none()
                    && !intent.cleanup_requested
                    && !intent.creation_observed
                    && !intent.creation_rejected,
                "DNS-01 intent already exists or is invalid"
            );
            let mut intent = intent.clone();
            let normalized =
                crate::certificate_catalog::normalize_certificate_identifier(&intent.identifier)?;
            let dns_name = normalized.strip_prefix("*.").unwrap_or(&normalized);
            anyhow::ensure!(
                normalized == intent.identifier
                    && intent.record_name == format!("_acme-challenge.{dns_name}")
                    && intent.record_name.len() <= 253,
                "DNS-01 intent domain does not match certificate identifier"
            );
            crate::cloudflare_dns::validate_cloudflare_id(&intent.zone_id)?;
            anyhow::ensure!(
                intent.provider.len() <= 4096
                    && intent.value.len() == 43
                    && intent
                        .value
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
                "DNS-01 publication context is invalid"
            );
            intent.next_cleanup = now.saturating_add(30);
            intent
        }
        _ => current.ok_or_else(|| anyhow::anyhow!("DNS-01 intent does not exist"))?,
    };
    anyhow::ensure!(
        lease.job_kind == "certificate"
            && lease.job_key == certificate_job_key(&intent.identifier)?
            && intent.job_key == lease.job_key
            && intent.job_lease_id == lease.lease_id.to_string(),
        "DNS-01 intent does not match issuing job"
    );
    anyhow::ensure!(
        intent.id == id,
        "DNS-01 intent identity differs from its row"
    );
    match mutation {
        Dns01Mutation::Published(record_id) => {
            crate::cloudflare_dns::validate_cloudflare_id(&record_id)?;
            anyhow::ensure!(
                !intent.cleanup_requested
                    && intent
                        .record_id
                        .as_ref()
                        .is_none_or(|current| current == &record_id),
                "DNS-01 publication is no longer current"
            );
            intent.record_id = Some(record_id);
            intent.creation_observed = true;
        }
        Dns01Mutation::Rejected => {
            anyhow::ensure!(
                !intent.creation_observed,
                "DNS-01 creation was already observed"
            );
            intent.creation_rejected = true;
            intent.cleanup_requested = true;
            intent.next_cleanup = now;
        }
        Dns01Mutation::RequestCleanup => {
            intent.cleanup_requested = true;
            intent.next_cleanup = now;
        }
        Dns01Mutation::Create(_) => {}
        _ => unreachable!("cleanup mutations are handled before issuing mutations"),
    }
    Ok(Some(intent))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lease(kind: &str, key: String) -> JobLease {
        JobLease {
            job_key: key,
            job_kind: kind.to_owned(),
            lease_id: Uuid::new_v4(),
            owner_instance_id: "test".to_owned(),
            owner_incarnation_id: "session".to_owned(),
            fencing_token: 1,
            acquired_unix_seconds: 10,
            renewed_unix_seconds: 10,
            lease_until_unix_seconds: 40,
            last_completed_unix_seconds: None,
            last_error_code: None,
        }
    }

    fn pending() -> (Dns01Intent, JobLease) {
        let issuer = lease(
            "certificate",
            certificate_job_key("site.example.com").unwrap(),
        );
        let intent = Dns01Intent {
            id: Uuid::new_v4(),
            identifier: "site.example.com".to_owned(),
            provider: "https://api.cloudflare.com/client/v4/".to_owned(),
            zone_id: "zone-1".to_owned(),
            record_name: "_acme-challenge.site.example.com".to_owned(),
            value: "A".repeat(43),
            record_id: None,
            creation_observed: false,
            creation_rejected: false,
            job_key: issuer.job_key.clone(),
            job_lease_id: issuer.lease_id.to_string(),
            cleanup_requested: false,
            next_cleanup: 0,
        };
        let intent = transition(
            intent.id,
            &issuer,
            None,
            Dns01Mutation::Create(intent.clone()),
            true,
            10,
        )
        .unwrap()
        .unwrap();
        (intent, issuer)
    }

    #[test]
    fn cleanup_cannot_interrupt_an_active_issuer_or_forget_unknown_creation() {
        let (intent, issuer) = pending();
        let cleanup = lease("dns01_cleanup", intent.cleanup_job_key());
        assert!(transition(
            intent.id,
            &cleanup,
            Some(intent.clone()),
            Dns01Mutation::AuthorizeCleanup,
            true,
            11
        )
        .is_err());
        let claimed = transition(
            intent.id,
            &cleanup,
            Some(intent.clone()),
            Dns01Mutation::AuthorizeCleanup,
            false,
            41,
        )
        .unwrap()
        .unwrap();
        assert!(claimed.cleanup_requested);
        assert!(transition(
            intent.id,
            &issuer,
            Some(claimed.clone()),
            Dns01Mutation::Published("record-1".to_owned()),
            false,
            42
        )
        .is_err());
        assert!(transition(
            intent.id,
            &cleanup,
            Some(claimed.clone()),
            Dns01Mutation::CompleteCleanup,
            false,
            42
        )
        .is_err());
        let observed = transition(
            intent.id,
            &cleanup,
            Some(claimed),
            Dns01Mutation::ObservedCreation,
            false,
            42,
        )
        .unwrap()
        .unwrap();
        assert!(transition(
            intent.id,
            &cleanup,
            Some(observed),
            Dns01Mutation::CompleteCleanup,
            false,
            43
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn normal_cleanup_requires_the_issuing_lease_and_explicit_release() {
        let (intent, issuer) = pending();
        let stale = lease("certificate", issuer.job_key.clone());
        assert!(transition(
            intent.id,
            &stale,
            Some(intent.clone()),
            Dns01Mutation::RequestCleanup,
            true,
            11
        )
        .is_err());
        let published = transition(
            intent.id,
            &issuer,
            Some(intent.clone()),
            Dns01Mutation::Published("record-1".to_owned()),
            true,
            11,
        )
        .unwrap()
        .unwrap();
        let released = transition(
            intent.id,
            &issuer,
            Some(published),
            Dns01Mutation::RequestCleanup,
            true,
            12,
        )
        .unwrap()
        .unwrap();
        let cleanup = lease("dns01_cleanup", intent.cleanup_job_key());
        assert!(transition(
            intent.id,
            &cleanup,
            Some(released),
            Dns01Mutation::AuthorizeCleanup,
            true,
            13
        )
        .is_ok());
        let other = lease("dns01_cleanup", format!("dns01_cleanup:{}", Uuid::new_v4()));
        assert!(transition(
            intent.id,
            &other,
            Some(intent),
            Dns01Mutation::AuthorizeCleanup,
            false,
            41
        )
        .is_err());
    }

    #[test]
    fn confirmed_rejection_can_retire_without_observing_a_record() {
        let (intent, issuer) = pending();
        let rejected = transition(
            intent.id,
            &issuer,
            Some(intent.clone()),
            Dns01Mutation::Rejected,
            true,
            11,
        )
        .unwrap()
        .unwrap();
        let cleanup = lease("dns01_cleanup", intent.cleanup_job_key());
        assert!(transition(
            intent.id,
            &cleanup,
            Some(rejected),
            Dns01Mutation::CompleteCleanup,
            true,
            12
        )
        .unwrap()
        .is_none());
    }
}
