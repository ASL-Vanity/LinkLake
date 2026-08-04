//! 持久化告警规则、活动状态与事件历史。

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::{fmt, path::Path, str::FromStr};
use uuid::Uuid;

use crate::database::Database;

const MAX_OUTSTANDING_NOTIFICATION_DELIVERIES: u64 = 10_000;
const NOTIFICATION_DELIVERY_LEASE_SECONDS: u64 = 60;
const NOTIFICATION_DELIVERY_MAX_ATTEMPTS: u32 = 10;
const NOTIFICATION_DELIVERY_BACKOFF_BASE_SECONDS: u64 = 5;
const NOTIFICATION_DELIVERY_BACKOFF_MAX_SECONDS: u64 = 3_600;
const NOTIFICATION_DELIVERY_PAYLOAD_MAX_BYTES: usize = 64 * 1024;
const NOTIFICATION_DELIVERY_RETENTION_SECONDS: u64 = 30 * 24 * 60 * 60;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AlertMetric {
    ClientOffline,
    PolicyUnavailable,
    AuthenticationFailures,
    TrafficBytesPerSecond,
    ActiveConnections,
    CertificateDaysRemaining,
    SloFastBurnRate,
    SloSlowBurnRate,
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
            Self::SloFastBurnRate => "slo_fast_burn_rate",
            Self::SloSlowBurnRate => "slo_slow_burn_rate",
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
            "slo_fast_burn_rate" => Ok(Self::SloFastBurnRate),
            "slo_slow_burn_rate" => Ok(Self::SloSlowBurnRate),
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

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
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

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct AlertNotification {
    pub(crate) event: AlertEvent,
    pub(crate) resolved: bool,
    pub(crate) webhook: bool,
    pub(crate) email: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NotificationChannel {
    Webhook,
    Email,
}

impl fmt::Display for NotificationChannel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Webhook => "webhook",
            Self::Email => "email",
        })
    }
}

impl FromStr for NotificationChannel {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "webhook" => Ok(Self::Webhook),
            "email" => Ok(Self::Email),
            _ => anyhow::bail!("unknown notification channel"),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NotificationDeliveryState {
    Pending,
    Delivering,
    Delivered,
    DeadLetter,
}

impl fmt::Display for NotificationDeliveryState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Pending => "pending",
            Self::Delivering => "delivering",
            Self::Delivered => "delivered",
            Self::DeadLetter => "dead_letter",
        })
    }
}

impl FromStr for NotificationDeliveryState {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "pending" => Ok(Self::Pending),
            "delivering" => Ok(Self::Delivering),
            "delivered" => Ok(Self::Delivered),
            "dead_letter" => Ok(Self::DeadLetter),
            _ => anyhow::bail!("unknown notification delivery state"),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct NotificationDelivery {
    pub(crate) id: i64,
    pub(crate) idempotency_key: String,
    pub(crate) lease_token: String,
    pub(crate) channel: NotificationChannel,
    pub(crate) notification: AlertNotification,
    pub(crate) attempts: u32,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct NotificationDeliveryView {
    pub(crate) id: i64,
    pub(crate) idempotency_key: String,
    pub(crate) event_id: i64,
    pub(crate) rule_name: String,
    pub(crate) subject: String,
    pub(crate) resolved: bool,
    pub(crate) channel: NotificationChannel,
    pub(crate) state: NotificationDeliveryState,
    pub(crate) attempts: u32,
    pub(crate) next_attempt_unix_seconds: u64,
    pub(crate) lease_expires_unix_seconds: Option<u64>,
    pub(crate) last_error: Option<String>,
    pub(crate) created_unix_seconds: u64,
    pub(crate) updated_unix_seconds: u64,
    pub(crate) delivered_unix_seconds: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum NotificationDeliveryRetryOutcome {
    Retried(NotificationDeliveryView),
    NotFound,
    NotDeadLetter(NotificationDeliveryState),
}

#[derive(Clone, Copy, Debug, Default, Serialize, PartialEq, Eq)]
pub(crate) struct NotificationDeliveryMetrics {
    pub(crate) notification_deliveries_pending: u64,
    pub(crate) notification_deliveries_retrying: u64,
    pub(crate) notification_deliveries_in_flight: u64,
    pub(crate) notification_deliveries_dead_letter: u64,
    pub(crate) notification_deliveries_delivered_total: u64,
    pub(crate) notification_delivery_failures_total: u64,
    pub(crate) notification_delivery_dead_letters_total: u64,
    pub(crate) notification_oldest_pending_age_seconds: u64,
    pub(crate) notification_webhook_pending: u64,
    pub(crate) notification_webhook_in_flight: u64,
    pub(crate) notification_webhook_dead_letter: u64,
    pub(crate) notification_email_pending: u64,
    pub(crate) notification_email_in_flight: u64,
    pub(crate) notification_email_dead_letter: u64,
}

pub(crate) struct AlertCatalog {
    database: Connection,
}

impl AlertCatalog {
    #[allow(dead_code)]
    pub(crate) fn open(data_dir: Option<&Path>) -> anyhow::Result<Self> {
        let database = Database::open(data_dir)?;
        Self::open_with_database(&database)
    }

    pub(crate) fn open_with_database(database: &Database) -> anyhow::Result<Self> {
        let database = database.connect()?;
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
            CREATE TABLE IF NOT EXISTS alert_notification_deliveries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                idempotency_key TEXT NOT NULL,
                event_id INTEGER NOT NULL,
                rule_name TEXT NOT NULL,
                subject TEXT NOT NULL,
                resolved INTEGER NOT NULL,
                channel TEXT NOT NULL CHECK(channel IN ('webhook', 'email')),
                payload_json TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('pending', 'delivering', 'delivered', 'dead_letter')),
                attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
                next_attempt_unix_seconds INTEGER NOT NULL,
                lease_expires_unix_seconds INTEGER,
                lease_token TEXT,
                last_error TEXT,
                created_unix_seconds INTEGER NOT NULL,
                updated_unix_seconds INTEGER NOT NULL,
                delivered_unix_seconds INTEGER
            );
            CREATE INDEX IF NOT EXISTS alert_notification_deliveries_due
                ON alert_notification_deliveries(state, next_attempt_unix_seconds, id);
            CREATE INDEX IF NOT EXISTS alert_notification_deliveries_updated
                ON alert_notification_deliveries(updated_unix_seconds DESC, id DESC);
            CREATE TABLE IF NOT EXISTS alert_notification_delivery_counters (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                delivered_total INTEGER NOT NULL,
                failed_attempts_total INTEGER NOT NULL,
                dead_letter_total INTEGER NOT NULL
            );
            INSERT OR IGNORE INTO alert_notification_delivery_counters
                (singleton, delivered_total, failed_attempts_total, dead_letter_total)
                VALUES (1, 0, 0, 0);
            ",
        )?;
        ensure_notification_delivery_columns(&database)?;
        database.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS alert_notification_deliveries_idempotency
             ON alert_notification_deliveries(idempotency_key)",
            [],
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
        for notification in &notifications {
            enqueue_notification_deliveries(&transaction, notification, now)?;
        }
        transaction.commit()?;
        Ok(notifications)
    }

    pub(crate) fn claim_notification_deliveries(
        &mut self,
        now: u64,
        limit: usize,
    ) -> anyhow::Result<Vec<NotificationDelivery>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let transaction = self.database.transaction()?;
        transaction.execute(
            "UPDATE alert_notification_deliveries
             SET state = 'pending', lease_expires_unix_seconds = NULL,
                 lease_token = NULL,
                 updated_unix_seconds = ?1,
                 last_error = COALESCE(last_error, 'notification_lease_expired')
             WHERE state = 'delivering'
               AND lease_expires_unix_seconds IS NOT NULL
               AND lease_expires_unix_seconds <= ?1",
            [now as i64],
        )?;
        transaction.execute(
            "DELETE FROM alert_notification_deliveries
             WHERE state IN ('delivered', 'dead_letter')
               AND updated_unix_seconds < ?1",
            [now.saturating_sub(NOTIFICATION_DELIVERY_RETENTION_SECONDS) as i64],
        )?;

        let ids = {
            let mut statement = transaction.prepare(
                "SELECT id FROM alert_notification_deliveries
                 WHERE state = 'pending' AND next_attempt_unix_seconds <= ?1
                 ORDER BY next_attempt_unix_seconds, id
                 LIMIT ?2",
            )?;
            let ids = statement
                .query_map(params![now as i64, limit.clamp(1, 64) as i64], |row| {
                    row.get::<_, i64>(0)
                })?
                .collect::<Result<Vec<_>, _>>()?;
            ids
        };

        let lease_expires = now.saturating_add(NOTIFICATION_DELIVERY_LEASE_SECONDS);
        let mut deliveries = Vec::with_capacity(ids.len());
        for id in ids {
            let lease_token = Uuid::new_v4().to_string();
            let updated = transaction.execute(
                "UPDATE alert_notification_deliveries
                 SET state = 'delivering', attempts = attempts + 1,
                     lease_expires_unix_seconds = ?2, lease_token = ?3,
                     updated_unix_seconds = ?4
                 WHERE id = ?1 AND state = 'pending'",
                params![id, lease_expires as i64, lease_token, now as i64],
            )?;
            if updated == 0 {
                continue;
            }
            deliveries.push(transaction.query_row(
                "SELECT id, idempotency_key, lease_token, channel, payload_json, attempts
                 FROM alert_notification_deliveries WHERE id = ?1",
                [id],
                parse_notification_delivery,
            )?);
        }
        transaction.commit()?;
        Ok(deliveries)
    }

    pub(crate) fn acknowledge_notification_delivery(
        &mut self,
        delivery: &NotificationDelivery,
        now: u64,
    ) -> anyhow::Result<bool> {
        let transaction = self.database.transaction()?;
        let updated = transaction.execute(
            "UPDATE alert_notification_deliveries
             SET state = 'delivered', lease_expires_unix_seconds = NULL,
                 lease_token = NULL, last_error = NULL,
                 updated_unix_seconds = ?3, delivered_unix_seconds = ?3
             WHERE id = ?1 AND state = 'delivering' AND lease_token = ?2",
            params![delivery.id, delivery.lease_token, now as i64],
        )?;
        if updated == 0 {
            transaction.commit()?;
            return Ok(false);
        }
        transaction.execute(
            "UPDATE alert_notification_delivery_counters
             SET delivered_total = delivered_total + 1 WHERE singleton = 1",
            [],
        )?;
        transaction.commit()?;
        Ok(true)
    }

    pub(crate) fn fail_notification_delivery(
        &mut self,
        delivery: &NotificationDelivery,
        now: u64,
        error: &str,
    ) -> anyhow::Result<Option<NotificationDeliveryState>> {
        let transaction = self.database.transaction()?;
        let attempts = transaction
            .query_row(
                "SELECT attempts FROM alert_notification_deliveries
             WHERE id = ?1 AND state = 'delivering' AND lease_token = ?2",
                params![delivery.id, delivery.lease_token],
                |row| Ok(row.get::<_, i64>(0)?.max(0) as u32),
            )
            .optional()?;
        let Some(attempts) = attempts else {
            transaction.commit()?;
            return Ok(None);
        };
        let dead_letter = attempts >= NOTIFICATION_DELIVERY_MAX_ATTEMPTS;
        let state = if dead_letter {
            NotificationDeliveryState::DeadLetter
        } else {
            NotificationDeliveryState::Pending
        };
        let next_attempt = if dead_letter {
            now
        } else {
            now.saturating_add(notification_retry_delay_seconds(attempts))
        };
        transaction.execute(
            "UPDATE alert_notification_deliveries
             SET state = ?2, next_attempt_unix_seconds = ?3,
                 lease_expires_unix_seconds = NULL, lease_token = NULL,
                 last_error = ?4, updated_unix_seconds = ?5
             WHERE id = ?1 AND state = 'delivering' AND lease_token = ?6",
            params![
                delivery.id,
                state.to_string(),
                next_attempt as i64,
                normalize_delivery_error_code(error),
                now as i64,
                delivery.lease_token,
            ],
        )?;
        transaction.execute(
            "UPDATE alert_notification_delivery_counters
             SET failed_attempts_total = failed_attempts_total + 1,
                 dead_letter_total = dead_letter_total + ?1
             WHERE singleton = 1",
            [i64::from(dead_letter)],
        )?;
        transaction.commit()?;
        Ok(Some(state))
    }

    pub(crate) fn retry_notification_delivery(
        &mut self,
        id: i64,
        now: u64,
    ) -> anyhow::Result<NotificationDeliveryRetryOutcome> {
        let transaction = self.database.transaction()?;
        let state = transaction
            .query_row(
                "SELECT state FROM alert_notification_deliveries WHERE id = ?1",
                [id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .map(|value| value.parse::<NotificationDeliveryState>())
            .transpose()?;
        let Some(state) = state else {
            transaction.commit()?;
            return Ok(NotificationDeliveryRetryOutcome::NotFound);
        };
        if state != NotificationDeliveryState::DeadLetter {
            transaction.commit()?;
            return Ok(NotificationDeliveryRetryOutcome::NotDeadLetter(state));
        }
        transaction.execute(
            "UPDATE alert_notification_deliveries
             SET state = 'pending', attempts = 0, next_attempt_unix_seconds = ?2,
                 lease_expires_unix_seconds = NULL, lease_token = NULL,
                 last_error = NULL,
                 updated_unix_seconds = ?2, delivered_unix_seconds = NULL
             WHERE id = ?1 AND state = 'dead_letter'",
            params![id, now as i64],
        )?;
        let delivery = query_notification_delivery_view(&transaction, id)?
            .ok_or_else(|| anyhow::anyhow!("notification delivery disappeared after retry"))?;
        transaction.commit()?;
        Ok(NotificationDeliveryRetryOutcome::Retried(delivery))
    }

    pub(crate) fn list_notification_deliveries(
        &self,
        limit: usize,
        state: Option<NotificationDeliveryState>,
        channel: Option<NotificationChannel>,
    ) -> anyhow::Result<Vec<NotificationDeliveryView>> {
        let mut statement = self.database.prepare(
            "SELECT id, idempotency_key, event_id, rule_name, subject, resolved, channel, state,
                    attempts, next_attempt_unix_seconds, lease_expires_unix_seconds,
                    last_error, created_unix_seconds, updated_unix_seconds,
                    delivered_unix_seconds
             FROM alert_notification_deliveries
             WHERE (?1 IS NULL OR state = ?1) AND (?2 IS NULL OR channel = ?2)
             ORDER BY updated_unix_seconds DESC, id DESC LIMIT ?3",
        )?;
        let state = state.map(|value| value.to_string());
        let channel = channel.map(|value| value.to_string());
        let deliveries = statement
            .query_map(
                params![state, channel, limit.clamp(1, 1_000) as i64],
                parse_notification_delivery_view,
            )?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(deliveries)
    }

    pub(crate) fn notification_delivery_metrics(
        &self,
        now: u64,
    ) -> anyhow::Result<NotificationDeliveryMetrics> {
        let (pending, retrying, in_flight, dead_letter, oldest_pending): (
            u64,
            u64,
            u64,
            u64,
            Option<u64>,
        ) = self.database.query_row(
            "SELECT
                 COALESCE(SUM(CASE WHEN state = 'pending' AND attempts = 0 THEN 1 ELSE 0 END), 0),
                 COALESCE(SUM(CASE WHEN state = 'pending' AND attempts > 0 THEN 1 ELSE 0 END), 0),
                 COALESCE(SUM(CASE WHEN state = 'delivering' THEN 1 ELSE 0 END), 0),
                 COALESCE(SUM(CASE WHEN state = 'dead_letter' THEN 1 ELSE 0 END), 0),
                 MIN(CASE WHEN state IN ('pending', 'delivering') THEN created_unix_seconds END)
             FROM alert_notification_deliveries",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?.max(0) as u64,
                    row.get::<_, i64>(1)?.max(0) as u64,
                    row.get::<_, i64>(2)?.max(0) as u64,
                    row.get::<_, i64>(3)?.max(0) as u64,
                    row.get::<_, Option<i64>>(4)?
                        .map(|value| value.max(0) as u64),
                ))
            },
        )?;
        let (delivered_total, failures_total, dead_letters_total): (u64, u64, u64) =
            self.database.query_row(
                "SELECT delivered_total, failed_attempts_total, dead_letter_total
                 FROM alert_notification_delivery_counters WHERE singleton = 1",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?.max(0) as u64,
                        row.get::<_, i64>(1)?.max(0) as u64,
                        row.get::<_, i64>(2)?.max(0) as u64,
                    ))
                },
            )?;
        let (
            webhook_pending,
            webhook_in_flight,
            webhook_dead_letter,
            email_pending,
            email_in_flight,
            email_dead_letter,
        ): (u64, u64, u64, u64, u64, u64) = self.database.query_row(
            "SELECT
                 COALESCE(SUM(CASE WHEN channel = 'webhook' AND state = 'pending' THEN 1 ELSE 0 END), 0),
                 COALESCE(SUM(CASE WHEN channel = 'webhook' AND state = 'delivering' THEN 1 ELSE 0 END), 0),
                 COALESCE(SUM(CASE WHEN channel = 'webhook' AND state = 'dead_letter' THEN 1 ELSE 0 END), 0),
                 COALESCE(SUM(CASE WHEN channel = 'email' AND state = 'pending' THEN 1 ELSE 0 END), 0),
                 COALESCE(SUM(CASE WHEN channel = 'email' AND state = 'delivering' THEN 1 ELSE 0 END), 0),
                 COALESCE(SUM(CASE WHEN channel = 'email' AND state = 'dead_letter' THEN 1 ELSE 0 END), 0)
             FROM alert_notification_deliveries",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?.max(0) as u64,
                    row.get::<_, i64>(1)?.max(0) as u64,
                    row.get::<_, i64>(2)?.max(0) as u64,
                    row.get::<_, i64>(3)?.max(0) as u64,
                    row.get::<_, i64>(4)?.max(0) as u64,
                    row.get::<_, i64>(5)?.max(0) as u64,
                ))
            },
        )?;
        Ok(NotificationDeliveryMetrics {
            notification_deliveries_pending: pending,
            notification_deliveries_retrying: retrying,
            notification_deliveries_in_flight: in_flight,
            notification_deliveries_dead_letter: dead_letter,
            notification_deliveries_delivered_total: delivered_total,
            notification_delivery_failures_total: failures_total,
            notification_delivery_dead_letters_total: dead_letters_total,
            notification_oldest_pending_age_seconds: oldest_pending
                .map_or(0, |created| now.saturating_sub(created)),
            notification_webhook_pending: webhook_pending,
            notification_webhook_in_flight: webhook_in_flight,
            notification_webhook_dead_letter: webhook_dead_letter,
            notification_email_pending: email_pending,
            notification_email_in_flight: email_in_flight,
            notification_email_dead_letter: email_dead_letter,
        })
    }

    fn ensure_defaults(&mut self) -> anyhow::Result<()> {
        let count: u64 =
            self.database
                .query_row("SELECT COUNT(*) FROM alert_rules", [], |row| row.get(0))?;
        let now = crate::unix_seconds();
        if count == 0 {
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
        }
        for request in [
            CreateAlertRule {
                name: "SLO fast burn (5m and 1h)".to_owned(),
                metric: AlertMetric::SloFastBurnRate,
                comparator: AlertComparator::GreaterOrEqual,
                threshold: 14.4,
                target: Some("global".to_owned()),
                evaluation_window_seconds: 300,
                cooldown_seconds: 3_600,
                severity: AlertSeverity::Critical,
                notify_webhook: true,
                notify_email: true,
                enabled: true,
            },
            CreateAlertRule {
                name: "SLO slow burn (6h and 24h)".to_owned(),
                metric: AlertMetric::SloSlowBurnRate,
                comparator: AlertComparator::GreaterOrEqual,
                threshold: 6.0,
                target: Some("global".to_owned()),
                evaluation_window_seconds: 21_600,
                cooldown_seconds: 21_600,
                severity: AlertSeverity::Warning,
                notify_webhook: true,
                notify_email: true,
                enabled: true,
            },
        ] {
            let exists: bool = self.database.query_row(
                "SELECT EXISTS(SELECT 1 FROM alert_rules WHERE metric = ?1)",
                [request.metric.to_string()],
                |row| row.get(0),
            )?;
            if !exists {
                self.create_rule(request, now)?;
            }
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

fn ensure_notification_delivery_columns(database: &Connection) -> anyhow::Result<()> {
    let has_idempotency_key: bool = database.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM pragma_table_info('alert_notification_deliveries')
             WHERE name = 'idempotency_key'
         )",
        [],
        |row| row.get(0),
    )?;
    if !has_idempotency_key {
        database.execute(
            "ALTER TABLE alert_notification_deliveries ADD COLUMN idempotency_key TEXT",
            [],
        )?;
    }
    let has_lease_token: bool = database.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM pragma_table_info('alert_notification_deliveries')
             WHERE name = 'lease_token'
         )",
        [],
        |row| row.get(0),
    )?;
    if !has_lease_token {
        database.execute(
            "ALTER TABLE alert_notification_deliveries ADD COLUMN lease_token TEXT",
            [],
        )?;
    }

    let missing_ids = {
        let mut statement = database.prepare(
            "SELECT id FROM alert_notification_deliveries
             WHERE idempotency_key IS NULL OR TRIM(idempotency_key) = ''",
        )?;
        let ids = statement
            .query_map([], |row| row.get::<_, i64>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        ids
    };
    for id in missing_ids {
        database.execute(
            "UPDATE alert_notification_deliveries SET idempotency_key = ?2 WHERE id = ?1",
            params![id, Uuid::new_v4().to_string()],
        )?;
    }
    Ok(())
}

fn enqueue_notification_deliveries(
    transaction: &rusqlite::Transaction<'_>,
    notification: &AlertNotification,
    now: u64,
) -> anyhow::Result<()> {
    let channels = [
        (NotificationChannel::Webhook, notification.webhook),
        (NotificationChannel::Email, notification.email),
    ]
    .into_iter()
    .filter_map(|(channel, enabled)| enabled.then_some(channel))
    .collect::<Vec<_>>();
    if channels.is_empty() {
        return Ok(());
    }
    let outstanding: u64 = transaction.query_row(
        "SELECT COUNT(*) FROM alert_notification_deliveries
         WHERE state IN ('pending', 'delivering')",
        [],
        |row| Ok(row.get::<_, i64>(0)?.max(0) as u64),
    )?;
    anyhow::ensure!(
        outstanding.saturating_add(channels.len() as u64)
            <= MAX_OUTSTANDING_NOTIFICATION_DELIVERIES,
        "notification delivery queue is full"
    );
    let payload = serde_json::to_string(notification)?;
    anyhow::ensure!(
        payload.len() <= NOTIFICATION_DELIVERY_PAYLOAD_MAX_BYTES,
        "notification delivery payload is too large"
    );
    for channel in channels {
        transaction.execute(
            "INSERT INTO alert_notification_deliveries
             (idempotency_key, event_id, rule_name, subject, resolved, channel, payload_json,
              state, attempts, next_attempt_unix_seconds,
              created_unix_seconds, updated_unix_seconds)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pending', 0, ?8, ?8, ?8)",
            params![
                Uuid::new_v4().to_string(),
                notification.event.id,
                notification.event.rule_name,
                notification.event.subject,
                i64::from(notification.resolved),
                channel.to_string(),
                payload,
                now as i64,
            ],
        )?;
    }
    Ok(())
}

fn notification_retry_delay_seconds(attempts: u32) -> u64 {
    let exponent = attempts.saturating_sub(1).min(31);
    NOTIFICATION_DELIVERY_BACKOFF_BASE_SECONDS
        .saturating_mul(1_u64 << exponent)
        .min(NOTIFICATION_DELIVERY_BACKOFF_MAX_SECONDS)
}

fn normalize_delivery_error_code(error: &str) -> String {
    match error {
        "webhook_invalid_configuration"
        | "webhook_timeout"
        | "webhook_transport"
        | "smtp_invalid_configuration"
        | "smtp_timeout"
        | "smtp_connect"
        | "smtp_tls"
        | "notification_lease_expired" => error.to_owned(),
        _ if valid_webhook_status_code(error) || valid_smtp_stage_code(error) => error.to_owned(),
        _ => "notification_delivery_failed".to_owned(),
    }
}

fn valid_webhook_status_code(error: &str) -> bool {
    error
        .strip_prefix("webhook_http_status_")
        .is_some_and(valid_status_code)
}

fn valid_smtp_stage_code(error: &str) -> bool {
    let valid_stage = |stage: &str| {
        matches!(
            stage,
            "greeting"
                | "ehlo"
                | "starttls"
                | "auth"
                | "mail_from"
                | "recipient"
                | "data"
                | "message"
                | "quit"
        )
    };
    if let Some(stage) = error
        .strip_prefix("smtp_io_")
        .or_else(|| error.strip_prefix("smtp_protocol_"))
    {
        return valid_stage(stage);
    }
    let Some(rest) = error.strip_prefix("smtp_status_") else {
        return false;
    };
    let Some((stage, status)) = rest.rsplit_once('_') else {
        return false;
    };
    valid_stage(stage) && valid_status_code(status)
}

fn valid_status_code(value: &str) -> bool {
    value.len() == 3 && value.bytes().all(|value| value.is_ascii_digit())
}

fn parse_notification_delivery(row: &rusqlite::Row<'_>) -> rusqlite::Result<NotificationDelivery> {
    let channel: String = row.get(3)?;
    let payload: String = row.get(4)?;
    Ok(NotificationDelivery {
        id: row.get(0)?,
        idempotency_key: row.get(1)?,
        lease_token: row.get(2)?,
        channel: channel.parse().map_err(conversion_error)?,
        notification: serde_json::from_str(&payload).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                4,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?,
        attempts: row.get::<_, i64>(5)?.max(0) as u32,
    })
}

fn parse_notification_delivery_view(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<NotificationDeliveryView> {
    let channel: String = row.get(6)?;
    let state: String = row.get(7)?;
    Ok(NotificationDeliveryView {
        id: row.get(0)?,
        idempotency_key: row.get(1)?,
        event_id: row.get(2)?,
        rule_name: row.get(3)?,
        subject: row.get(4)?,
        resolved: row.get::<_, i64>(5)? != 0,
        channel: channel.parse().map_err(conversion_error)?,
        state: state.parse().map_err(conversion_error)?,
        attempts: row.get::<_, i64>(8)?.max(0) as u32,
        next_attempt_unix_seconds: row.get::<_, i64>(9)?.max(0) as u64,
        lease_expires_unix_seconds: row
            .get::<_, Option<i64>>(10)?
            .map(|value| value.max(0) as u64),
        last_error: row.get(11)?,
        created_unix_seconds: row.get::<_, i64>(12)?.max(0) as u64,
        updated_unix_seconds: row.get::<_, i64>(13)?.max(0) as u64,
        delivered_unix_seconds: row
            .get::<_, Option<i64>>(14)?
            .map(|value| value.max(0) as u64),
    })
}

fn query_notification_delivery_view(
    database: &Connection,
    id: i64,
) -> anyhow::Result<Option<NotificationDeliveryView>> {
    database
        .query_row(
            "SELECT id, idempotency_key, event_id, rule_name, subject, resolved, channel, state,
                    attempts, next_attempt_unix_seconds, lease_expires_unix_seconds,
                    last_error, created_unix_seconds, updated_unix_seconds,
                    delivered_unix_seconds
             FROM alert_notification_deliveries WHERE id = ?1",
            [id],
            parse_notification_delivery_view,
        )
        .optional()
        .map_err(Into::into)
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
    fn notification_failure_codes_are_allowlisted_and_secret_safe() {
        assert_eq!(
            normalize_delivery_error_code("webhook_http_status_503"),
            "webhook_http_status_503"
        );
        assert_eq!(
            normalize_delivery_error_code("smtp_status_auth_535"),
            "smtp_status_auth_535"
        );
        assert_eq!(
            normalize_delivery_error_code("smtp_status_auth_535 supersecret raw response"),
            "notification_delivery_failed"
        );
        assert_eq!(
            normalize_delivery_error_code("https://user:supersecret@example.test/hook?token=1"),
            "notification_delivery_failed"
        );
    }

    fn create_notification_rule(
        catalog: &mut AlertCatalog,
        webhook: bool,
        email: bool,
        now: u64,
    ) -> Uuid {
        catalog
            .create_rule(
                CreateAlertRule {
                    name: "Notification delivery test".to_owned(),
                    metric: AlertMetric::ActiveConnections,
                    comparator: AlertComparator::GreaterOrEqual,
                    threshold: 1.0,
                    target: Some("delivery-test".to_owned()),
                    evaluation_window_seconds: 5,
                    cooldown_seconds: 30,
                    severity: AlertSeverity::Critical,
                    notify_webhook: webhook,
                    notify_email: email,
                    enabled: true,
                },
                now,
            )
            .expect("notification rule should be created")
            .id
    }

    fn enqueue_test_notification(catalog: &mut AlertCatalog, webhook: bool, email: bool, now: u64) {
        let rule_id = create_notification_rule(catalog, webhook, email, now);
        let notifications = catalog
            .evaluate(
                &[AlertSignal {
                    metric: AlertMetric::ActiveConnections,
                    subject: "delivery-test".to_owned(),
                    value: 2.0,
                    message: "test notification".to_owned(),
                    window_seconds: None,
                }],
                now + 1,
            )
            .expect("notification should enqueue");
        assert!(notifications
            .iter()
            .any(|notification| notification.event.rule_id == rule_id));
    }

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

    #[test]
    fn notification_delivery_is_persistent_and_acknowledged_once() {
        let root = std::env::temp_dir().join(format!("linklake-outbox-{}", Uuid::new_v4()));
        let (delivery_id, idempotency_key);
        {
            let mut catalog = AlertCatalog::open(Some(&root)).expect("catalog should open");
            enqueue_test_notification(&mut catalog, true, false, 100);
            let metrics = catalog
                .notification_delivery_metrics(102)
                .expect("metrics should read");
            assert_eq!(metrics.notification_deliveries_pending, 1);
            assert_eq!(metrics.notification_webhook_pending, 1);
            assert_eq!(metrics.notification_email_pending, 0);
            let deliveries = catalog
                .claim_notification_deliveries(102, 1)
                .expect("delivery should be claimed");
            assert_eq!(deliveries.len(), 1);
            delivery_id = deliveries[0].id;
            idempotency_key = deliveries[0].idempotency_key.clone();
        }
        {
            let mut catalog = AlertCatalog::open(Some(&root)).expect("catalog should reopen");
            assert!(catalog
                .claim_notification_deliveries(161, 1)
                .expect("unexpired lease should not be reclaimed")
                .is_empty());
            let delivery = catalog
                .claim_notification_deliveries(162, 1)
                .expect("expired lease should be reclaimed")
                .pop()
                .expect("one expired delivery should be reclaimed");
            assert_eq!(delivery.id, delivery_id);
            assert_eq!(delivery.idempotency_key, idempotency_key);
            assert_eq!(delivery.attempts, 2);
            assert!(catalog
                .acknowledge_notification_delivery(&delivery, 163)
                .expect("delivery should acknowledge"));
            assert!(!catalog
                .acknowledge_notification_delivery(&delivery, 164)
                .expect("duplicate acknowledgement should be ignored"));
            let metrics = catalog
                .notification_delivery_metrics(164)
                .expect("metrics should read");
            assert_eq!(metrics.notification_deliveries_delivered_total, 1);
            assert_eq!(metrics.notification_deliveries_pending, 0);
            assert_eq!(metrics.notification_webhook_pending, 0);
            assert_eq!(metrics.notification_webhook_in_flight, 0);
        }
        std::fs::remove_dir_all(root).expect("temporary directory should be removed");
    }

    #[test]
    fn stale_notification_lease_cannot_complete_a_reclaimed_delivery() {
        let mut catalog = AlertCatalog::open(None).expect("catalog should open");
        enqueue_test_notification(&mut catalog, true, false, 100);
        let first = catalog
            .claim_notification_deliveries(102, 1)
            .expect("delivery should claim")
            .pop()
            .expect("one delivery should exist");
        let second = catalog
            .claim_notification_deliveries(162, 1)
            .expect("expired delivery should reclaim")
            .pop()
            .expect("one delivery should be reclaimed");
        assert_eq!(first.id, second.id);
        assert_eq!(first.idempotency_key, second.idempotency_key);
        assert_ne!(first.lease_token, second.lease_token);
        assert!(!catalog
            .acknowledge_notification_delivery(&first, 163)
            .expect("stale acknowledgement should be ignored"));
        assert_eq!(
            catalog
                .fail_notification_delivery(&first, 163, "stale failure")
                .expect("stale failure should be ignored"),
            None
        );
        assert!(catalog
            .acknowledge_notification_delivery(&second, 164)
            .expect("current lease should acknowledge"));
    }

    #[test]
    fn notification_failures_back_off_then_dead_letter_and_retry_manually() {
        let mut catalog = AlertCatalog::open(None).expect("catalog should open");
        enqueue_test_notification(&mut catalog, true, false, 1_000);
        let mut now = 1_002;
        let mut idempotency_key = String::new();
        for attempt in 1..=NOTIFICATION_DELIVERY_MAX_ATTEMPTS {
            let delivery = catalog
                .claim_notification_deliveries(now, 1)
                .expect("delivery should claim")
                .pop()
                .expect("one delivery should be due");
            if idempotency_key.is_empty() {
                idempotency_key.clone_from(&delivery.idempotency_key);
            } else {
                assert_eq!(delivery.idempotency_key, idempotency_key);
            }
            assert_eq!(delivery.attempts, attempt);
            let state = catalog
                .fail_notification_delivery(
                    &delivery,
                    now,
                    "smtp_status_auth_535 supersecret\r\nraw response",
                )
                .expect("failure should persist")
                .expect("lease should be current");
            let view = catalog
                .list_notification_deliveries(1, None, None)
                .expect("delivery should list")
                .pop()
                .expect("one delivery should list");
            let last_error = view
                .last_error
                .as_deref()
                .expect("failure should be recorded");
            assert_eq!(last_error, "notification_delivery_failed");
            assert!(!last_error.contains("supersecret"));
            if attempt == NOTIFICATION_DELIVERY_MAX_ATTEMPTS {
                assert_eq!(state, NotificationDeliveryState::DeadLetter);
                let outcome = catalog
                    .retry_notification_delivery(delivery.id, now + 1)
                    .expect("dead-letter retry should succeed");
                let NotificationDeliveryRetryOutcome::Retried(retried) = outcome else {
                    panic!("dead-letter delivery should be retried")
                };
                assert_eq!(retried.state, NotificationDeliveryState::Pending);
                assert_eq!(retried.attempts, 0);
                assert_eq!(retried.idempotency_key, idempotency_key);
                let reclaimed = catalog
                    .claim_notification_deliveries(now + 1, 1)
                    .expect("manual retry should be immediately due")
                    .pop()
                    .expect("manual retry should claim");
                assert_eq!(reclaimed.attempts, 1);
                assert_eq!(reclaimed.idempotency_key, idempotency_key);
            } else {
                assert_eq!(state, NotificationDeliveryState::Pending);
                let delay = notification_retry_delay_seconds(attempt);
                assert!(catalog
                    .claim_notification_deliveries(now + delay - 1, 1)
                    .expect("early retry should not claim")
                    .is_empty());
                now = now.saturating_add(delay);
            }
        }
        let metrics = catalog
            .notification_delivery_metrics(now + 1)
            .expect("metrics should read");
        assert_eq!(
            metrics.notification_delivery_failures_total,
            NOTIFICATION_DELIVERY_MAX_ATTEMPTS as u64
        );
        assert_eq!(metrics.notification_delivery_dead_letters_total, 1);
    }

    #[test]
    fn retry_reports_missing_and_non_dead_letter_states() {
        let mut catalog = AlertCatalog::open(None).expect("catalog should open");
        assert_eq!(
            catalog
                .retry_notification_delivery(9_999, 1)
                .expect("missing retry should be classified"),
            NotificationDeliveryRetryOutcome::NotFound
        );
        enqueue_test_notification(&mut catalog, true, false, 10);
        let pending = catalog
            .list_notification_deliveries(1, None, None)
            .expect("delivery should list")
            .pop()
            .expect("one delivery should list");
        assert_eq!(
            catalog
                .retry_notification_delivery(pending.id, 12)
                .expect("pending retry should be classified"),
            NotificationDeliveryRetryOutcome::NotDeadLetter(NotificationDeliveryState::Pending)
        );
    }
}
