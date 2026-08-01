//! 持久化告警规则、活动状态与事件历史。

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::{fmt, fs, path::Path, str::FromStr};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AlertMetric {
    ClientOffline,
    PolicyUnavailable,
    AuthenticationFailures,
    TrafficBytesPerSecond,
    ActiveConnections,
    CertificateDaysRemaining,
}

impl fmt::Display for AlertMetric {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ClientOffline => "client_offline",
            Self::PolicyUnavailable => "policy_unavailable",
            Self::AuthenticationFailures => "authentication_failures",
            Self::TrafficBytesPerSecond => "traffic_bytes_per_second",
            Self::ActiveConnections => "active_connections",
            Self::CertificateDaysRemaining => "certificate_days_remaining",
        })
    }
}

impl FromStr for AlertMetric {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "client_offline" => Ok(Self::ClientOffline),
            "policy_unavailable" => Ok(Self::PolicyUnavailable),
            "authentication_failures" => Ok(Self::AuthenticationFailures),
            "traffic_bytes_per_second" => Ok(Self::TrafficBytesPerSecond),
            "active_connections" => Ok(Self::ActiveConnections),
            "certificate_days_remaining" => Ok(Self::CertificateDaysRemaining),
            _ => anyhow::bail!("unknown alert metric"),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AlertComparator {
    GreaterOrEqual,
    LessOrEqual,
}

impl AlertComparator {
    fn matches(self, value: f64, threshold: f64) -> bool {
        match self {
            Self::GreaterOrEqual => value >= threshold,
            Self::LessOrEqual => value <= threshold,
        }
    }
}

impl fmt::Display for AlertComparator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::GreaterOrEqual => "greater_or_equal",
            Self::LessOrEqual => "less_or_equal",
        })
    }
}

impl FromStr for AlertComparator {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "greater_or_equal" => Ok(Self::GreaterOrEqual),
            "less_or_equal" => Ok(Self::LessOrEqual),
            _ => anyhow::bail!("unknown alert comparator"),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

impl fmt::Display for AlertSeverity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Critical => "critical",
        })
    }
}

impl FromStr for AlertSeverity {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "info" => Ok(Self::Info),
            "warning" => Ok(Self::Warning),
            "critical" => Ok(Self::Critical),
            _ => anyhow::bail!("unknown alert severity"),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub(crate) struct AlertRule {
    pub(crate) id: Uuid,
    pub(crate) name: String,
    pub(crate) metric: AlertMetric,
    pub(crate) comparator: AlertComparator,
    pub(crate) threshold: f64,
    pub(crate) target: Option<String>,
    pub(crate) evaluation_window_seconds: u64,
    pub(crate) cooldown_seconds: u64,
    pub(crate) severity: AlertSeverity,
    pub(crate) notify_webhook: bool,
    pub(crate) notify_email: bool,
    pub(crate) enabled: bool,
    pub(crate) created_unix_seconds: u64,
    pub(crate) updated_unix_seconds: u64,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct CreateAlertRule {
    pub(crate) name: String,
    pub(crate) metric: AlertMetric,
    pub(crate) comparator: AlertComparator,
    pub(crate) threshold: f64,
    pub(crate) target: Option<String>,
    #[serde(default = "default_evaluation_window")]
    pub(crate) evaluation_window_seconds: u64,
    #[serde(default = "default_cooldown")]
    pub(crate) cooldown_seconds: u64,
    pub(crate) severity: AlertSeverity,
    #[serde(default)]
    pub(crate) notify_webhook: bool,
    #[serde(default)]
    pub(crate) notify_email: bool,
    #[serde(default = "default_true")]
    pub(crate) enabled: bool,
}

pub(crate) type UpdateAlertRule = CreateAlertRule;

fn default_evaluation_window() -> u64 {
    300
}

fn default_cooldown() -> u64 {
    900
}

fn default_true() -> bool {
    true
}

#[derive(Clone, Debug)]
pub(crate) struct AlertSignal {
    pub(crate) metric: AlertMetric,
    pub(crate) subject: String,
    pub(crate) value: f64,
    pub(crate) message: String,
    pub(crate) window_seconds: Option<u64>,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub(crate) struct AlertEvent {
    pub(crate) id: i64,
    pub(crate) rule_id: Uuid,
    pub(crate) rule_name: String,
    pub(crate) severity: AlertSeverity,
    pub(crate) subject: String,
    pub(crate) active: bool,
    pub(crate) value: f64,
    pub(crate) threshold: f64,
    pub(crate) message: String,
    pub(crate) started_unix_seconds: u64,
    pub(crate) updated_unix_seconds: u64,
    pub(crate) resolved_unix_seconds: Option<u64>,
    pub(crate) last_notified_unix_seconds: Option<u64>,
}

#[derive(Clone, Debug)]
pub(crate) struct AlertNotification {
    pub(crate) event: AlertEvent,
    pub(crate) resolved: bool,
    pub(crate) webhook: bool,
    pub(crate) email: bool,
}

pub(crate) struct AlertCatalog {
    database: Connection,
}

impl AlertCatalog {
    pub(crate) fn open(data_dir: Option<&Path>) -> anyhow::Result<Self> {
        let database = if let Some(data_dir) = data_dir {
            fs::create_dir_all(data_dir)?;
            Connection::open(data_dir.join("linklake.sqlite3"))?
        } else {
            Connection::open_in_memory()?
        };
        database.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS alert_rules (
                id TEXT PRIMARY KEY NOT NULL,
                name TEXT NOT NULL,
                metric TEXT NOT NULL,
                comparator TEXT NOT NULL,
                threshold REAL NOT NULL,
                target TEXT,
                evaluation_window_seconds INTEGER NOT NULL,
                cooldown_seconds INTEGER NOT NULL,
                severity TEXT NOT NULL,
                notify_webhook INTEGER NOT NULL,
                notify_email INTEGER NOT NULL,
                enabled INTEGER NOT NULL,
                created_unix_seconds INTEGER NOT NULL,
                updated_unix_seconds INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS alert_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id TEXT NOT NULL,
                rule_name TEXT NOT NULL,
                severity TEXT NOT NULL,
                subject TEXT NOT NULL,
                active INTEGER NOT NULL,
                value REAL NOT NULL,
                threshold REAL NOT NULL,
                message TEXT NOT NULL,
                started_unix_seconds INTEGER NOT NULL,
                updated_unix_seconds INTEGER NOT NULL,
                resolved_unix_seconds INTEGER,
                last_notified_unix_seconds INTEGER
            );
            CREATE UNIQUE INDEX IF NOT EXISTS alert_events_active_subject
                ON alert_events(rule_id, subject) WHERE active = 1;
            CREATE INDEX IF NOT EXISTS alert_events_updated
                ON alert_events(updated_unix_seconds DESC);
            ",
        )?;
        let mut catalog = Self { database };
        catalog.ensure_defaults()?;
        Ok(catalog)
    }

    pub(crate) fn list_rules(&self) -> anyhow::Result<Vec<AlertRule>> {
        let mut statement = self.database.prepare(
            "SELECT id, name, metric, comparator, threshold, target, evaluation_window_seconds, cooldown_seconds, severity, notify_webhook, notify_email, enabled, created_unix_seconds, updated_unix_seconds FROM alert_rules ORDER BY name",
        )?;
        let rules: Result<Vec<_>, rusqlite::Error> = statement.query_map([], parse_rule)?.collect();
        Ok(rules?)
    }

    pub(crate) fn create_rule(
        &mut self,
        request: CreateAlertRule,
        now: u64,
    ) -> anyhow::Result<AlertRule> {
        validate_rule(&request)?;
        let rule = AlertRule {
            id: Uuid::new_v4(),
            name: request.name.trim().to_owned(),
            metric: request.metric,
            comparator: request.comparator,
            threshold: request.threshold,
            target: normalize_target(request.target),
            evaluation_window_seconds: request.evaluation_window_seconds,
            cooldown_seconds: request.cooldown_seconds,
            severity: request.severity,
            notify_webhook: request.notify_webhook,
            notify_email: request.notify_email,
            enabled: request.enabled,
            created_unix_seconds: now,
            updated_unix_seconds: now,
        };
        self.persist_rule(&rule)?;
        Ok(rule)
    }

    pub(crate) fn update_rule(
        &mut self,
        id: Uuid,
        request: UpdateAlertRule,
        now: u64,
    ) -> anyhow::Result<Option<AlertRule>> {
        validate_rule(&request)?;
        let Some(existing) = self.rule(id)? else {
            return Ok(None);
        };
        let rule = AlertRule {
            id,
            name: request.name.trim().to_owned(),
            metric: request.metric,
            comparator: request.comparator,
            threshold: request.threshold,
            target: normalize_target(request.target),
            evaluation_window_seconds: request.evaluation_window_seconds,
            cooldown_seconds: request.cooldown_seconds,
            severity: request.severity,
            notify_webhook: request.notify_webhook,
            notify_email: request.notify_email,
            enabled: request.enabled,
            created_unix_seconds: existing.created_unix_seconds,
            updated_unix_seconds: now,
        };
        self.persist_rule(&rule)?;
        if !rule.enabled {
            self.resolve_rule_events(id, now, "rule disabled")?;
        }
        Ok(Some(rule))
    }

    pub(crate) fn delete_rule(&mut self, id: Uuid, now: u64) -> anyhow::Result<bool> {
        self.resolve_rule_events(id, now, "rule deleted")?;
        Ok(self
            .database
            .execute("DELETE FROM alert_rules WHERE id = ?1", [id.to_string()])?
            > 0)
    }

    pub(crate) fn list_events(
        &self,
        active_only: bool,
        limit: usize,
    ) -> anyhow::Result<Vec<AlertEvent>> {
        let sql = if active_only {
            "SELECT id, rule_id, rule_name, severity, subject, active, value, threshold, message, started_unix_seconds, updated_unix_seconds, resolved_unix_seconds, last_notified_unix_seconds FROM alert_events WHERE active = 1 ORDER BY severity DESC, updated_unix_seconds DESC LIMIT ?1"
        } else {
            "SELECT id, rule_id, rule_name, severity, subject, active, value, threshold, message, started_unix_seconds, updated_unix_seconds, resolved_unix_seconds, last_notified_unix_seconds FROM alert_events ORDER BY updated_unix_seconds DESC LIMIT ?1"
        };
        let mut statement = self.database.prepare(sql)?;
        let events: Result<Vec<_>, rusqlite::Error> = statement
            .query_map([limit.clamp(1, 1_000) as i64], parse_event)?
            .collect();
        Ok(events?)
    }

    pub(crate) fn evaluate(
        &mut self,
        signals: &[AlertSignal],
        now: u64,
    ) -> anyhow::Result<Vec<AlertNotification>> {
        let rules = self.list_rules()?;
        let transaction = self.database.transaction()?;
        let mut notifications = Vec::new();
        for rule in rules.into_iter().filter(|rule| rule.enabled) {
            let mut firing_subjects = Vec::new();
            for signal in signals.iter().filter(|signal| {
                signal.metric == rule.metric
                    && signal
                        .window_seconds
                        .is_none_or(|window| window == rule.evaluation_window_seconds)
                    && rule
                        .target
                        .as_ref()
                        .is_none_or(|target| target == &signal.subject)
                    && rule.comparator.matches(signal.value, rule.threshold)
            }) {
                firing_subjects.push(signal.subject.clone());
                let existing = transaction
                    .query_row(
                        "SELECT id, rule_id, rule_name, severity, subject, active, value, threshold, message, started_unix_seconds, updated_unix_seconds, resolved_unix_seconds, last_notified_unix_seconds FROM alert_events WHERE rule_id = ?1 AND subject = ?2 AND active = 1",
                        params![rule.id.to_string(), signal.subject],
                        parse_event,
                    )
                    .optional()?;
                let (event, should_notify) = if let Some(mut event) = existing {
                    let should_notify = event
                        .last_notified_unix_seconds
                        .is_none_or(|last| now.saturating_sub(last) >= rule.cooldown_seconds);
                    event.value = signal.value;
                    event.message = signal.message.clone();
                    event.updated_unix_seconds = now;
                    if should_notify {
                        event.last_notified_unix_seconds = Some(now);
                    }
                    transaction.execute(
                        "UPDATE alert_events SET value = ?2, message = ?3, updated_unix_seconds = ?4, last_notified_unix_seconds = ?5 WHERE id = ?1",
                        params![event.id, event.value, event.message, now as i64, event.last_notified_unix_seconds.map(|value| value as i64)],
                    )?;
                    (event, should_notify)
                } else {
                    transaction.execute(
                        "INSERT INTO alert_events (rule_id, rule_name, severity, subject, active, value, threshold, message, started_unix_seconds, updated_unix_seconds, last_notified_unix_seconds) VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6, ?7, ?8, ?8, ?8)",
                        params![rule.id.to_string(), rule.name, rule.severity.to_string(), signal.subject, signal.value, rule.threshold, signal.message, now as i64],
                    )?;
                    let id = transaction.last_insert_rowid();
                    (
                        AlertEvent {
                            id,
                            rule_id: rule.id,
                            rule_name: rule.name.clone(),
                            severity: rule.severity,
                            subject: signal.subject.clone(),
                            active: true,
                            value: signal.value,
                            threshold: rule.threshold,
                            message: signal.message.clone(),
                            started_unix_seconds: now,
                            updated_unix_seconds: now,
                            resolved_unix_seconds: None,
                            last_notified_unix_seconds: Some(now),
                        },
                        true,
                    )
                };
                if should_notify {
                    notifications.push(AlertNotification {
                        event,
                        resolved: false,
                        webhook: rule.notify_webhook,
                        email: rule.notify_email,
                    });
                }
            }

            let mut statement = transaction.prepare(
                "SELECT id, rule_id, rule_name, severity, subject, active, value, threshold, message, started_unix_seconds, updated_unix_seconds, resolved_unix_seconds, last_notified_unix_seconds FROM alert_events WHERE rule_id = ?1 AND active = 1",
            )?;
            let active_events = statement
                .query_map([rule.id.to_string()], parse_event)?
                .collect::<Result<Vec<_>, _>>()?;
            drop(statement);
            for mut event in active_events
                .into_iter()
                .filter(|event| !firing_subjects.contains(&event.subject))
            {
                event.active = false;
                event.updated_unix_seconds = now;
                event.resolved_unix_seconds = Some(now);
                event.message = format!("resolved: {}", event.message);
                transaction.execute(
                    "UPDATE alert_events SET active = 0, message = ?2, updated_unix_seconds = ?3, resolved_unix_seconds = ?3 WHERE id = ?1",
                    params![event.id, event.message, now as i64],
                )?;
                notifications.push(AlertNotification {
                    event,
                    resolved: true,
                    webhook: rule.notify_webhook,
                    email: rule.notify_email,
                });
            }
        }
        transaction.commit()?;
        Ok(notifications)
    }

    fn ensure_defaults(&mut self) -> anyhow::Result<()> {
        let count: u64 =
            self.database
                .query_row("SELECT COUNT(*) FROM alert_rules", [], |row| row.get(0))?;
        if count > 0 {
            return Ok(());
        }
        let now = crate::unix_seconds();
        for request in [
            CreateAlertRule {
                name: "Client offline".to_owned(),
                metric: AlertMetric::ClientOffline,
                comparator: AlertComparator::GreaterOrEqual,
                threshold: 1.0,
                target: None,
                evaluation_window_seconds: 120,
                cooldown_seconds: 900,
                severity: AlertSeverity::Warning,
                notify_webhook: true,
                notify_email: false,
                enabled: true,
            },
            CreateAlertRule {
                name: "Policy unavailable".to_owned(),
                metric: AlertMetric::PolicyUnavailable,
                comparator: AlertComparator::GreaterOrEqual,
                threshold: 1.0,
                target: None,
                evaluation_window_seconds: 60,
                cooldown_seconds: 900,
                severity: AlertSeverity::Critical,
                notify_webhook: true,
                notify_email: true,
                enabled: true,
            },
            CreateAlertRule {
                name: "Authentication failures".to_owned(),
                metric: AlertMetric::AuthenticationFailures,
                comparator: AlertComparator::GreaterOrEqual,
                threshold: 10.0,
                target: None,
                evaluation_window_seconds: 300,
                cooldown_seconds: 900,
                severity: AlertSeverity::Warning,
                notify_webhook: true,
                notify_email: false,
                enabled: true,
            },
            CreateAlertRule {
                name: "Certificate expiry".to_owned(),
                metric: AlertMetric::CertificateDaysRemaining,
                comparator: AlertComparator::LessOrEqual,
                threshold: 30.0,
                target: None,
                evaluation_window_seconds: 300,
                cooldown_seconds: 86_400,
                severity: AlertSeverity::Warning,
                notify_webhook: true,
                notify_email: true,
                enabled: true,
            },
        ] {
            self.create_rule(request, now)?;
        }
        Ok(())
    }

    fn rule(&self, id: Uuid) -> anyhow::Result<Option<AlertRule>> {
        self.database
            .query_row(
                "SELECT id, name, metric, comparator, threshold, target, evaluation_window_seconds, cooldown_seconds, severity, notify_webhook, notify_email, enabled, created_unix_seconds, updated_unix_seconds FROM alert_rules WHERE id = ?1",
                [id.to_string()],
                parse_rule,
            )
            .optional()
            .map_err(Into::into)
    }

    fn persist_rule(&self, rule: &AlertRule) -> anyhow::Result<()> {
        self.database.execute(
            "INSERT OR REPLACE INTO alert_rules (id, name, metric, comparator, threshold, target, evaluation_window_seconds, cooldown_seconds, severity, notify_webhook, notify_email, enabled, created_unix_seconds, updated_unix_seconds) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                rule.id.to_string(),
                rule.name,
                rule.metric.to_string(),
                rule.comparator.to_string(),
                rule.threshold,
                rule.target,
                rule.evaluation_window_seconds as i64,
                rule.cooldown_seconds as i64,
                rule.severity.to_string(),
                i64::from(rule.notify_webhook),
                i64::from(rule.notify_email),
                i64::from(rule.enabled),
                rule.created_unix_seconds as i64,
                rule.updated_unix_seconds as i64,
            ],
        )?;
        Ok(())
    }

    fn resolve_rule_events(&self, id: Uuid, now: u64, reason: &str) -> anyhow::Result<()> {
        self.database.execute(
            "UPDATE alert_events SET active = 0, updated_unix_seconds = ?2, resolved_unix_seconds = ?2, message = message || ?3 WHERE rule_id = ?1 AND active = 1",
            params![id.to_string(), now as i64, format!(" ({reason})")],
        )?;
        Ok(())
    }
}

fn validate_rule(rule: &CreateAlertRule) -> anyhow::Result<()> {
    let name = rule.name.trim();
    anyhow::ensure!(
        !name.is_empty() && name.chars().count() <= 96,
        "alert rule name is invalid"
    );
    anyhow::ensure!(rule.threshold.is_finite(), "alert threshold must be finite");
    anyhow::ensure!(
        (5..=86_400).contains(&rule.evaluation_window_seconds),
        "alert evaluation window must be between 5 and 86400 seconds"
    );
    anyhow::ensure!(
        (30..=604_800).contains(&rule.cooldown_seconds),
        "alert cooldown must be between 30 and 604800 seconds"
    );
    if let Some(target) = rule.target.as_deref() {
        anyhow::ensure!(
            target.trim().chars().count() <= 160,
            "alert target is too long"
        );
    }
    Ok(())
}

fn normalize_target(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let value = value.trim();
        (!value.is_empty()).then(|| value.to_owned())
    })
}

fn parse_rule(row: &rusqlite::Row<'_>) -> rusqlite::Result<AlertRule> {
    let id = row.get::<_, String>(0)?;
    let metric = row.get::<_, String>(2)?;
    let comparator = row.get::<_, String>(3)?;
    let severity = row.get::<_, String>(8)?;
    Ok(AlertRule {
        id: Uuid::parse_str(&id).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?,
        name: row.get(1)?,
        metric: metric.parse().map_err(conversion_error)?,
        comparator: comparator.parse().map_err(conversion_error)?,
        threshold: row.get(4)?,
        target: row.get(5)?,
        evaluation_window_seconds: row.get::<_, i64>(6)?.max(0) as u64,
        cooldown_seconds: row.get::<_, i64>(7)?.max(0) as u64,
        severity: severity.parse().map_err(conversion_error)?,
        notify_webhook: row.get::<_, i64>(9)? != 0,
        notify_email: row.get::<_, i64>(10)? != 0,
        enabled: row.get::<_, i64>(11)? != 0,
        created_unix_seconds: row.get::<_, i64>(12)?.max(0) as u64,
        updated_unix_seconds: row.get::<_, i64>(13)?.max(0) as u64,
    })
}

fn parse_event(row: &rusqlite::Row<'_>) -> rusqlite::Result<AlertEvent> {
    let rule_id = row.get::<_, String>(1)?;
    let severity = row.get::<_, String>(3)?;
    Ok(AlertEvent {
        id: row.get(0)?,
        rule_id: Uuid::parse_str(&rule_id).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                1,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?,
        rule_name: row.get(2)?,
        severity: severity.parse().map_err(conversion_error)?,
        subject: row.get(4)?,
        active: row.get::<_, i64>(5)? != 0,
        value: row.get(6)?,
        threshold: row.get(7)?,
        message: row.get(8)?,
        started_unix_seconds: row.get::<_, i64>(9)?.max(0) as u64,
        updated_unix_seconds: row.get::<_, i64>(10)?.max(0) as u64,
        resolved_unix_seconds: row
            .get::<_, Option<i64>>(11)?
            .map(|value| value.max(0) as u64),
        last_notified_unix_seconds: row
            .get::<_, Option<i64>>(12)?
            .map(|value| value.max(0) as u64),
    })
}

fn conversion_error(error: anyhow::Error) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, error.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alert_lifecycle_is_persistent_and_resolves() {
        let root = std::env::temp_dir().join(format!("linklake-alerts-{}", Uuid::new_v4()));
        let rule_id;
        {
            let mut catalog = AlertCatalog::open(Some(&root)).expect("catalog should open");
            let rule = catalog
                .create_rule(
                    CreateAlertRule {
                        name: "Test active connections".to_owned(),
                        metric: AlertMetric::ActiveConnections,
                        comparator: AlertComparator::GreaterOrEqual,
                        threshold: 2.0,
                        target: None,
                        evaluation_window_seconds: 60,
                        cooldown_seconds: 30,
                        severity: AlertSeverity::Critical,
                        notify_webhook: true,
                        notify_email: true,
                        enabled: true,
                    },
                    100,
                )
                .expect("rule should be created");
            rule_id = rule.id;
            let notifications = catalog
                .evaluate(
                    &[AlertSignal {
                        metric: AlertMetric::ActiveConnections,
                        subject: "global".to_owned(),
                        value: 3.0,
                        message: "three connections".to_owned(),
                        window_seconds: None,
                    }],
                    200,
                )
                .expect("signal should evaluate");
            assert!(notifications
                .iter()
                .any(|value| value.event.rule_id == rule_id));
            assert!(catalog
                .list_events(true, 100)
                .expect("events should list")
                .iter()
                .any(|event| event.rule_id == rule_id));
        }
        {
            let mut catalog = AlertCatalog::open(Some(&root)).expect("catalog should reopen");
            let notifications = catalog.evaluate(&[], 300).expect("alerts should resolve");
            assert!(notifications
                .iter()
                .any(|value| value.event.rule_id == rule_id && value.resolved));
            assert!(!catalog
                .list_events(true, 100)
                .expect("active events should list")
                .iter()
                .any(|event| event.rule_id == rule_id));
        }
        std::fs::remove_dir_all(root).expect("temporary directory should be removed");
    }
}
