use anyhow::Context;
use rusqlite::{params, Connection, Transaction, TransactionBehavior};
use serde::Serialize;
use std::path::Path;

use crate::database::Database;

/// 审计表最多保留最近五万条记录，避免长期运行时数据库和 WAL 被正常审计无限推高。
pub(crate) const MAX_AUDIT_EVENTS: usize = 50_000;

#[derive(Serialize)]
pub(crate) struct AuditEvent {
    pub(crate) id: i64,
    pub(crate) occurred_unix_seconds: i64,
    pub(crate) action: String,
    pub(crate) subject: String,
    pub(crate) detail: String,
}

pub(crate) struct AuditLog {
    database: Connection,
    retained_events: usize,
}

impl AuditLog {
    #[allow(dead_code)]
    pub(crate) fn open(data_dir: Option<&Path>) -> anyhow::Result<Self> {
        let database = Database::open(data_dir)?;
        Self::open_with_database(&database)
    }

    pub(crate) fn open_with_database(database: &Database) -> anyhow::Result<Self> {
        let mut database = database.connect()?;
        database.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                occurred_unix_seconds INTEGER NOT NULL,
                action TEXT NOT NULL,
                subject TEXT NOT NULL,
                detail TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS audit_events_occurred ON audit_events(occurred_unix_seconds DESC);
            ",
        )?;
        let retained_events = enforce_retention_limit(&mut database, MAX_AUDIT_EVENTS)?;
        Ok(Self {
            database,
            retained_events,
        })
    }

    pub(crate) fn record(
        &mut self,
        action: &str,
        subject: &str,
        detail: &str,
    ) -> anyhow::Result<()> {
        self.record_with_retention_limit(action, subject, detail, MAX_AUDIT_EVENTS)
    }

    fn record_with_retention_limit(
        &mut self,
        action: &str,
        subject: &str,
        detail: &str,
        maximum_events: usize,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(maximum_events > 0, "audit retention limit must be positive");
        let transaction = self
            .database
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO audit_events (occurred_unix_seconds, action, subject, detail) VALUES (?1, ?2, ?3, ?4)",
            params![unix_seconds(), limit_text(action, 80), limit_text(subject, 160), limit_text(detail, 500)],
        )?;
        let next_count = self
            .retained_events
            .checked_add(1)
            .context("audit event count overflow")?;
        let excess = next_count.saturating_sub(maximum_events);
        if excess > 0 {
            delete_oldest_events(&transaction, excess)?;
        }
        transaction.commit()?;
        self.retained_events = next_count - excess;
        Ok(())
    }

    pub(crate) fn recent(&self, limit: usize) -> anyhow::Result<Vec<AuditEvent>> {
        let mut statement = self.database.prepare(
            "SELECT id, occurred_unix_seconds, action, subject, detail FROM audit_events ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = statement.query_map([limit.clamp(1, 100) as i64], |row| {
            Ok(AuditEvent {
                id: row.get(0)?,
                occurred_unix_seconds: row.get(1)?,
                action: row.get(2)?,
                subject: row.get(3)?,
                detail: row.get(4)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub(crate) fn export(
        &self,
        from_unix_seconds: Option<i64>,
        to_unix_seconds: Option<i64>,
        limit: usize,
    ) -> anyhow::Result<Vec<AuditEvent>> {
        let mut statement = self.database.prepare(
            "SELECT id, occurred_unix_seconds, action, subject, detail FROM audit_events WHERE (?1 IS NULL OR occurred_unix_seconds >= ?1) AND (?2 IS NULL OR occurred_unix_seconds <= ?2) ORDER BY id DESC LIMIT ?3",
        )?;
        let rows = statement.query_map(
            params![
                from_unix_seconds,
                to_unix_seconds,
                limit.clamp(1, 100_000) as i64
            ],
            |row| {
                Ok(AuditEvent {
                    id: row.get(0)?,
                    occurred_unix_seconds: row.get(1)?,
                    action: row.get(2)?,
                    subject: row.get(3)?,
                    detail: row.get(4)?,
                })
            },
        )?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }
}

fn enforce_retention_limit(
    database: &mut Connection,
    maximum_events: usize,
) -> anyhow::Result<usize> {
    anyhow::ensure!(maximum_events > 0, "audit retention limit must be positive");
    let transaction = database.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let retained_events = audit_event_count(&transaction)?;
    let excess = retained_events.saturating_sub(maximum_events);
    if excess > 0 {
        delete_oldest_events(&transaction, excess)?;
    }
    transaction.commit()?;
    Ok(retained_events - excess)
}

fn audit_event_count(database: &Connection) -> anyhow::Result<usize> {
    let count = database.query_row("SELECT COUNT(*) FROM audit_events", [], |row| {
        row.get::<_, i64>(0)
    })?;
    usize::try_from(count).context("audit event count is outside the supported range")
}

fn delete_oldest_events(transaction: &Transaction<'_>, count: usize) -> anyhow::Result<()> {
    let expected = count;
    let count = i64::try_from(expected).context("audit retention deletion count is too large")?;
    let deleted = transaction.execute(
        "DELETE FROM audit_events WHERE id IN (SELECT id FROM audit_events ORDER BY id ASC LIMIT ?1)",
        [count],
    )?;
    anyhow::ensure!(
        deleted == expected,
        "audit retention invariant could not be enforced"
    );
    Ok(())
}

fn limit_text(value: &str, maximum_bytes: usize) -> String {
    value.chars().take(maximum_bytes).collect()
}

fn unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::AuditLog;

    #[test]
    fn audit_events_are_listed_newest_first_without_storing_unbounded_text() {
        let mut log = AuditLog::open(None).expect("in-memory audit log should open");
        log.record("first", "client-a", "first event")
            .expect("event should be recorded");
        log.record("second", "client-b", &"x".repeat(600))
            .expect("event should be recorded");

        let events = log.recent(10).expect("events should be listed");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].action, "second");
        assert_eq!(events[0].detail.chars().count(), 500);
    }

    #[test]
    fn audit_retention_is_enforced_in_the_same_write_transaction() {
        let mut log = AuditLog::open(None).expect("in-memory audit log should open");
        for action in ["first", "second", "third"] {
            log.record_with_retention_limit(action, "server", "event", 2)
                .expect("bounded event should be recorded");
        }

        let events = log.recent(10).expect("events should be listed");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].action, "third");
        assert_eq!(events[1].action, "second");
    }
}
