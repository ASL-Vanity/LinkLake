use rusqlite::{params, Connection};
use serde::Serialize;
use std::path::Path;

use crate::database::Database;

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
}

impl AuditLog {
    #[allow(dead_code)]
    pub(crate) fn open(data_dir: Option<&Path>) -> anyhow::Result<Self> {
        let database = Database::open(data_dir)?;
        Self::open_with_database(&database)
    }

    pub(crate) fn open_with_database(database: &Database) -> anyhow::Result<Self> {
        let database = database.connect()?;
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
        Ok(Self { database })
    }

    pub(crate) fn record(
        &mut self,
        action: &str,
        subject: &str,
        detail: &str,
    ) -> anyhow::Result<()> {
        self.database.execute(
            "INSERT INTO audit_events (occurred_unix_seconds, action, subject, detail) VALUES (?1, ?2, ?3, ?4)",
            params![unix_seconds(), limit_text(action, 80), limit_text(subject, 160), limit_text(detail, 500)],
        )?;
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
}
