//! 审计双后端。所有实例可记录事件，写入与全局保留上限在同一事务中提交。

use crate::{
    audit_log::{AuditEvent, AuditLog, MAX_AUDIT_EVENTS},
    database::Database,
    storage::{CoordinationStorage, StorageBackend},
};
use std::sync::Mutex;

pub(crate) enum AuditStore {
    Sqlite(Mutex<AuditLog>),
    Postgres(CoordinationStorage),
}

impl AuditStore {
    pub(crate) fn open(database: &Database, storage: CoordinationStorage) -> anyhow::Result<Self> {
        Ok(match storage.backend() {
            StorageBackend::Sqlite => {
                Self::Sqlite(Mutex::new(AuditLog::open_with_database(database)?))
            }
            StorageBackend::Postgres => Self::Postgres(storage),
        })
    }

    pub(crate) async fn record(
        &self,
        action: &str,
        subject: &str,
        detail: &str,
    ) -> anyhow::Result<()> {
        match self {
            Self::Sqlite(log) => log
                .lock()
                .map_err(|_| anyhow::anyhow!("audit log lock poisoned"))?
                .record(action, subject, detail),
            Self::Postgres(storage) => {
                let mut client = storage.postgres_client().await?;
                let transaction = client.transaction().await?;
                // 审计允许 Follower 写入（例如鉴权拒绝），不依赖业务 Leader 租约。
                transaction
                    .query_one("SELECT pg_advisory_xact_lock($1)", &[&0x4c4c_4155_4449_i64])
                    .await?;
                transaction.execute(
                    "INSERT INTO linklake_audit_events (occurred_unix_seconds,action,subject,detail)
                     VALUES (FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::bigint,$1,$2,$3)",
                    &[&action.chars().take(80).collect::<String>(), &subject.chars().take(160).collect::<String>(), &detail.chars().take(500).collect::<String>()],
                ).await?;
                let count: i64 = transaction.query_one(
                    "UPDATE linklake_audit_retention SET retained_events=retained_events+1 WHERE singleton_id=1 RETURNING retained_events", &[],
                ).await?.get(0);
                let excess = count.saturating_sub(MAX_AUDIT_EVENTS as i64).max(0);
                if excess > 0 {
                    let deleted = transaction.execute(
                        "DELETE FROM linklake_audit_events WHERE id IN (SELECT id FROM linklake_audit_events ORDER BY id LIMIT $1)", &[&excess],
                    ).await?;
                    anyhow::ensure!(
                        deleted == excess as u64,
                        "audit retention invariant could not be enforced"
                    );
                    transaction.execute("UPDATE linklake_audit_retention SET retained_events=$1 WHERE singleton_id=1", &[&(count - excess)]).await?;
                }
                transaction.commit().await?;
                Ok(())
            }
        }
    }

    pub(crate) async fn recent(&self, limit: usize) -> anyhow::Result<Vec<AuditEvent>> {
        match self {
            Self::Sqlite(log) => log
                .lock()
                .map_err(|_| anyhow::anyhow!("audit log lock poisoned"))?
                .recent(limit),
            Self::Postgres(_) => self.export(None, None, limit.clamp(1, 100)).await,
        }
    }

    pub(crate) async fn export(
        &self,
        from: Option<i64>,
        to: Option<i64>,
        limit: usize,
    ) -> anyhow::Result<Vec<AuditEvent>> {
        match self {
            Self::Sqlite(log) => log
                .lock()
                .map_err(|_| anyhow::anyhow!("audit log lock poisoned"))?
                .export(from, to, limit),
            Self::Postgres(storage) => {
                let rows = storage.postgres_client().await?.query(
                    "SELECT id,occurred_unix_seconds,action,subject,detail FROM linklake_audit_events
                     WHERE ($1::bigint IS NULL OR occurred_unix_seconds >= $1) AND ($2::bigint IS NULL OR occurred_unix_seconds <= $2)
                     ORDER BY id DESC LIMIT $3", &[&from,&to,&(limit.clamp(1,100_000) as i64)],
                ).await?;
                rows.iter()
                    .map(|row| {
                        Ok(AuditEvent {
                            id: row.try_get(0)?,
                            occurred_unix_seconds: row.try_get(1)?,
                            action: row.try_get(2)?,
                            subject: row.try_get(3)?,
                            detail: row.try_get(4)?,
                        })
                    })
                    .collect()
            }
        }
    }
}
