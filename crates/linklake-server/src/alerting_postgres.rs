//! 共享告警规则与事件；评估结果和通知发件箱在同一事务内提交。

use super::*;
use crate::{ha_runtime::HaRuntime, storage::CoordinationStorage};
use std::sync::Arc;
use tokio_postgres::Transaction as PgTransaction;

const ALERT_STATE_LOCK: i64 = 0x4c4c_414c_4552_5453;

pub(crate) struct PostgresAlertCatalog {
    pub(crate) storage: CoordinationStorage,
    pub(crate) runtime: Arc<HaRuntime>,
}

impl PostgresAlertCatalog {
    pub(crate) async fn ensure_defaults(&self) -> anyhow::Result<()> {
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        self.fence(&transaction).await?;
        // 初始化标记随共享库持久化；切换 Leader 或重启 worker 不复活已删除规则。
        let initialized: bool = transaction.query_one(
            "SELECT defaults_initialized FROM linklake_alert_delivery_counters WHERE singleton_id=1 FOR UPDATE", &[],
        ).await?.get(0);
        if initialized {
            transaction.commit().await?;
            return Ok(());
        }
        let now = database_now(&transaction).await?;
        let count: i64 = transaction
            .query_one("SELECT count(*) FROM linklake_alert_rules", &[])
            .await?
            .get(0);
        if count == 0 {
            for request in default_alert_rules() {
                save_rule(&transaction, &make_rule(Uuid::new_v4(), request, now, now)).await?;
            }
        }
        for request in default_slo_rules() {
            let exists: bool = transaction
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM linklake_alert_rules WHERE rule->>'metric'=$1)",
                    &[&request.metric.to_string()],
                )
                .await?
                .get(0);
            if !exists {
                save_rule(&transaction, &make_rule(Uuid::new_v4(), request, now, now)).await?;
            }
        }
        transaction.execute("UPDATE linklake_alert_delivery_counters SET defaults_initialized=TRUE WHERE singleton_id=1", &[]).await?;
        transaction.commit().await?;
        Ok(())
    }

    pub(crate) async fn claim_notification_deliveries(
        &self,
        _now: u64,
        limit: usize,
    ) -> anyhow::Result<Vec<NotificationDelivery>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        self.fence(&transaction).await?;
        let now = database_now(&transaction).await? as i64;
        transaction.execute(
            "UPDATE linklake_alert_deliveries SET state='pending',lease_token=NULL,lease_expires_unix_seconds=NULL,
             updated_unix_seconds=$1,last_error=COALESCE(last_error,'notification_lease_expired')
             WHERE state='delivering' AND lease_expires_unix_seconds <= $1", &[&now],
        ).await?;
        transaction.execute("DELETE FROM linklake_alert_deliveries WHERE state IN ('delivered','dead_letter') AND updated_unix_seconds < $1",
            &[&now.saturating_sub(NOTIFICATION_DELIVERY_RETENTION_SECONDS as i64)]).await?;
        let rows = transaction.query(
            "SELECT id FROM linklake_alert_deliveries WHERE state='pending' AND next_attempt_unix_seconds <= $1
             ORDER BY next_attempt_unix_seconds,id LIMIT $2 FOR UPDATE SKIP LOCKED", &[&now, &(limit.clamp(1,64) as i64)],
        ).await?;
        let mut deliveries = Vec::with_capacity(rows.len());
        for row in rows {
            let id: i64 = row.get(0);
            let token = Uuid::new_v4().to_string();
            let expires = now.saturating_add(NOTIFICATION_DELIVERY_LEASE_SECONDS as i64);
            let row = transaction.query_one(
                "UPDATE linklake_alert_deliveries SET state='delivering',attempts=attempts+1,lease_token=$2,
                 lease_expires_unix_seconds=$3,updated_unix_seconds=$4 WHERE id=$1
                 RETURNING idempotency_key,channel,payload::text,attempts", &[&id,&token,&expires,&now],
            ).await?;
            deliveries.push(NotificationDelivery {
                id,
                idempotency_key: row.get(0),
                lease_token: token,
                channel: row.get::<_, &str>(1).parse()?,
                notification: serde_json::from_str(row.get(2))?,
                attempts: u32::try_from(row.get::<_, i32>(3))?,
            });
        }
        transaction.commit().await?;
        Ok(deliveries)
    }

    pub(crate) async fn acknowledge_notification_delivery(
        &self,
        delivery: &NotificationDelivery,
        _now: u64,
    ) -> anyhow::Result<bool> {
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        self.fence(&transaction).await?;
        let now = database_now(&transaction).await? as i64;
        let updated = transaction.execute(
            "UPDATE linklake_alert_deliveries SET state='delivered',lease_token=NULL,lease_expires_unix_seconds=NULL,
             last_error=NULL,updated_unix_seconds=$3,delivered_unix_seconds=$3
             WHERE id=$1 AND state='delivering' AND lease_token=$2 AND lease_expires_unix_seconds > $3",
            &[&delivery.id,&delivery.lease_token,&now],
        ).await? > 0;
        if updated {
            transaction.execute("UPDATE linklake_alert_delivery_counters SET delivered_total=delivered_total+1 WHERE singleton_id=1", &[]).await?;
        }
        transaction.commit().await?;
        Ok(updated)
    }

    pub(crate) async fn fail_notification_delivery(
        &self,
        delivery: &NotificationDelivery,
        _now: u64,
        error: &str,
    ) -> anyhow::Result<Option<NotificationDeliveryState>> {
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        self.fence(&transaction).await?;
        let now = database_now(&transaction).await? as i64;
        let Some(row) = transaction.query_opt(
            "SELECT attempts FROM linklake_alert_deliveries WHERE id=$1 AND state='delivering' AND lease_token=$2
             AND lease_expires_unix_seconds > $3 FOR UPDATE", &[&delivery.id,&delivery.lease_token,&now],
        ).await? else {
            transaction.commit().await?;
            return Ok(None);
        };
        let attempts = u32::try_from(row.get::<_, i32>(0))?;
        let dead_letter = attempts >= NOTIFICATION_DELIVERY_MAX_ATTEMPTS;
        let state = if dead_letter {
            NotificationDeliveryState::DeadLetter
        } else {
            NotificationDeliveryState::Pending
        };
        let next = if dead_letter {
            now
        } else {
            now.saturating_add(notification_retry_delay_seconds(attempts) as i64)
        };
        transaction.execute(
            "UPDATE linklake_alert_deliveries SET state=$2,next_attempt_unix_seconds=$3,lease_token=NULL,
             lease_expires_unix_seconds=NULL,last_error=$4,updated_unix_seconds=$5 WHERE id=$1",
            &[&delivery.id,&state.to_string(),&next,&normalize_delivery_error_code(error),&now],
        ).await?;
        transaction.execute("UPDATE linklake_alert_delivery_counters SET failed_attempts_total=failed_attempts_total+1,
            dead_letter_total=dead_letter_total+$1 WHERE singleton_id=1", &[&i64::from(dead_letter)]).await?;
        transaction.commit().await?;
        Ok(Some(state))
    }

    pub(crate) async fn retry_notification_delivery(
        &self,
        id: i64,
        _now: u64,
    ) -> anyhow::Result<NotificationDeliveryRetryOutcome> {
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        self.fence(&transaction).await?;
        let Some(row) = transaction
            .query_opt(
                "SELECT state FROM linklake_alert_deliveries WHERE id=$1 FOR UPDATE",
                &[&id],
            )
            .await?
        else {
            transaction.commit().await?;
            return Ok(NotificationDeliveryRetryOutcome::NotFound);
        };
        let state: NotificationDeliveryState = row.get::<_, &str>(0).parse()?;
        if state != NotificationDeliveryState::DeadLetter {
            transaction.commit().await?;
            return Ok(NotificationDeliveryRetryOutcome::NotDeadLetter(state));
        }
        // 人工重试也必须遵守全局队列容量，不能绕过评估入队的预算。
        let outstanding: i64 = transaction.query_one("SELECT count(*) FROM linklake_alert_deliveries WHERE state IN ('pending','delivering')", &[]).await?.get(0);
        anyhow::ensure!(
            outstanding < MAX_OUTSTANDING_NOTIFICATION_DELIVERIES as i64,
            "notification delivery queue is full"
        );
        let now = database_now(&transaction).await? as i64;
        transaction.execute("UPDATE linklake_alert_deliveries SET state='pending',attempts=0,next_attempt_unix_seconds=$2,
            lease_token=NULL,lease_expires_unix_seconds=NULL,last_error=NULL,updated_unix_seconds=$2,delivered_unix_seconds=NULL WHERE id=$1", &[&id,&now]).await?;
        let row = transaction
            .query_one(
                &format!(
                    "SELECT {DELIVERY_VIEW_COLUMNS} FROM linklake_alert_deliveries WHERE id=$1"
                ),
                &[&id],
            )
            .await?;
        let view = delivery_view(&row)?;
        transaction.commit().await?;
        Ok(NotificationDeliveryRetryOutcome::Retried(view))
    }

    pub(crate) async fn list_notification_deliveries(
        &self,
        limit: usize,
        state: Option<NotificationDeliveryState>,
        channel: Option<NotificationChannel>,
    ) -> anyhow::Result<Vec<NotificationDeliveryView>> {
        let client = self.storage.postgres_client().await?;
        let state = state.map(|value| value.to_string());
        let channel = channel.map(|value| value.to_string());
        let sql = format!(
            "SELECT {DELIVERY_VIEW_COLUMNS} FROM linklake_alert_deliveries
            WHERE ($1::text IS NULL OR state=$1) AND ($2::text IS NULL OR channel=$2)
            ORDER BY updated_unix_seconds DESC,id DESC LIMIT $3"
        );
        client
            .query(&sql, &[&state, &channel, &(limit.clamp(1, 1000) as i64)])
            .await?
            .iter()
            .map(delivery_view)
            .collect()
    }

    pub(crate) async fn notification_delivery_metrics(
        &self,
        _now: u64,
    ) -> anyhow::Result<NotificationDeliveryMetrics> {
        let client = self.storage.postgres_client().await?;
        // 单条语句确保队列计数和累计计数使用同一 MVCC 快照。
        let row = client.query_one(
            "SELECT count(*) FILTER(WHERE state='pending' AND attempts=0),
             count(*) FILTER(WHERE state='pending' AND attempts>0),count(*) FILTER(WHERE state='delivering'),
             count(*) FILTER(WHERE state='dead_letter'),
             COALESCE((SELECT delivered_total FROM linklake_alert_delivery_counters WHERE singleton_id=1),0),
             COALESCE((SELECT failed_attempts_total FROM linklake_alert_delivery_counters WHERE singleton_id=1),0),
             COALESCE((SELECT dead_letter_total FROM linklake_alert_delivery_counters WHERE singleton_id=1),0),
             GREATEST(0,COALESCE(floor(extract(epoch FROM statement_timestamp()))::bigint - min(created_unix_seconds) FILTER(WHERE state IN ('pending','delivering')),0)),
             count(*) FILTER(WHERE channel='webhook' AND state='pending'),count(*) FILTER(WHERE channel='webhook' AND state='delivering'),
             count(*) FILTER(WHERE channel='webhook' AND state='dead_letter'),count(*) FILTER(WHERE channel='email' AND state='pending'),
             count(*) FILTER(WHERE channel='email' AND state='delivering'),count(*) FILTER(WHERE channel='email' AND state='dead_letter')
             FROM linklake_alert_deliveries", &[],
        ).await?;
        let count = |index: usize| row.get::<_, i64>(index).max(0) as u64;
        Ok(NotificationDeliveryMetrics {
            notification_deliveries_pending: count(0),
            notification_deliveries_retrying: count(1),
            notification_deliveries_in_flight: count(2),
            notification_deliveries_dead_letter: count(3),
            notification_deliveries_delivered_total: count(4),
            notification_delivery_failures_total: count(5),
            notification_delivery_dead_letters_total: count(6),
            notification_oldest_pending_age_seconds: count(7),
            notification_webhook_pending: count(8),
            notification_webhook_in_flight: count(9),
            notification_webhook_dead_letter: count(10),
            notification_email_pending: count(11),
            notification_email_in_flight: count(12),
            notification_email_dead_letter: count(13),
        })
    }

    async fn fence(&self, transaction: &PgTransaction<'_>) -> anyhow::Result<()> {
        // 先排队，再校验当前 Leader，避免等待锁后继续使用过期身份。
        transaction
            .query_one("SELECT pg_advisory_xact_lock($1)", &[&ALERT_STATE_LOCK])
            .await?;
        let token = self.runtime.fencing_token()?;
        self.runtime
            .coordinator()
            .assert_postgres_transaction_fence(transaction, token)
            .await?;
        Ok(())
    }

    pub(crate) async fn list_rules(&self) -> anyhow::Result<Vec<AlertRule>> {
        let client = self.storage.postgres_client().await?;
        client
            .query(
                "SELECT rule::text FROM linklake_alert_rules ORDER BY rule->>'name', id",
                &[],
            )
            .await?
            .iter()
            .map(|row| serde_json::from_str(row.get(0)).map_err(Into::into))
            .collect()
    }

    pub(crate) async fn create_rule(
        &self,
        request: CreateAlertRule,
        _now: u64,
    ) -> anyhow::Result<AlertRule> {
        validate_rule(&request)?;
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        self.fence(&transaction).await?;
        let now = database_now(&transaction).await?;
        let rule = make_rule(Uuid::new_v4(), request, now, now);
        save_rule(&transaction, &rule).await?;
        transaction.commit().await?;
        Ok(rule)
    }

    pub(crate) async fn update_rule(
        &self,
        id: Uuid,
        request: UpdateAlertRule,
        _now: u64,
    ) -> anyhow::Result<Option<AlertRule>> {
        validate_rule(&request)?;
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        self.fence(&transaction).await?;
        let Some(row) = transaction
            .query_opt(
                "SELECT rule::text FROM linklake_alert_rules WHERE id=$1 FOR UPDATE",
                &[&id.to_string()],
            )
            .await?
        else {
            transaction.commit().await?;
            return Ok(None);
        };
        let existing: AlertRule = serde_json::from_str(row.get(0))?;
        let now = database_now(&transaction).await?;
        let rule = make_rule(id, request, existing.created_unix_seconds, now);
        save_rule(&transaction, &rule).await?;
        if !rule.enabled {
            resolve_rule_events(&transaction, id, now, "rule disabled").await?;
        }
        transaction.commit().await?;
        Ok(Some(rule))
    }

    pub(crate) async fn delete_rule(&self, id: Uuid, _now: u64) -> anyhow::Result<bool> {
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        self.fence(&transaction).await?;
        let now = database_now(&transaction).await?;
        resolve_rule_events(&transaction, id, now, "rule deleted").await?;
        let deleted = transaction
            .execute(
                "DELETE FROM linklake_alert_rules WHERE id=$1",
                &[&id.to_string()],
            )
            .await?
            > 0;
        transaction.commit().await?;
        Ok(deleted)
    }

    pub(crate) async fn list_events(
        &self,
        active_only: bool,
        limit: usize,
    ) -> anyhow::Result<Vec<AlertEvent>> {
        let client = self.storage.postgres_client().await?;
        let sql = if active_only {
            "SELECT event::text FROM linklake_alert_events WHERE active ORDER BY event->>'severity' DESC, updated_unix_seconds DESC, id DESC LIMIT $1"
        } else {
            "SELECT event::text FROM linklake_alert_events ORDER BY updated_unix_seconds DESC, id DESC LIMIT $1"
        };
        client
            .query(sql, &[&(limit.clamp(1, 1000) as i64)])
            .await?
            .iter()
            .map(|row| serde_json::from_str(row.get(0)).map_err(Into::into))
            .collect()
    }

    pub(crate) async fn evaluate(
        &self,
        signals: &[AlertSignal],
        _now: u64,
    ) -> anyhow::Result<Vec<AlertNotification>> {
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        self.fence(&transaction).await?;
        let now = database_now(&transaction).await?;
        let rules: Vec<AlertRule> = transaction
            .query(
                "SELECT rule::text FROM linklake_alert_rules ORDER BY id",
                &[],
            )
            .await?
            .iter()
            .map(|row| serde_json::from_str(row.get(0)))
            .collect::<Result<_, _>>()?;
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
                let existing = transaction.query_opt(
                    "SELECT event::text FROM linklake_alert_events WHERE rule_id=$1 AND subject=$2 AND active FOR UPDATE",
                    &[&rule.id.to_string(), &signal.subject],
                ).await?;
                let (event, should_notify) = if let Some(row) = existing {
                    let mut event: AlertEvent = serde_json::from_str(row.get(0))?;
                    let notify = event
                        .last_notified_unix_seconds
                        .is_none_or(|last| now.saturating_sub(last) >= rule.cooldown_seconds);
                    event.value = signal.value;
                    event.message = signal.message.clone();
                    event.updated_unix_seconds = now;
                    if notify {
                        event.last_notified_unix_seconds = Some(now);
                    }
                    (event, notify)
                } else {
                    let id: i64 = transaction
                        .query_one("SELECT nextval('linklake_alert_events_id_seq')", &[])
                        .await?
                        .get(0);
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
                save_event(&transaction, &event).await?;
                if should_notify {
                    notifications.push(AlertNotification {
                        event,
                        resolved: false,
                        webhook: rule.notify_webhook,
                        email: rule.notify_email,
                    });
                }
            }
            let active: Vec<AlertEvent> = transaction
                .query(
                    "SELECT event::text FROM linklake_alert_events WHERE rule_id=$1 AND active",
                    &[&rule.id.to_string()],
                )
                .await?
                .iter()
                .map(|row| serde_json::from_str(row.get(0)))
                .collect::<Result<_, _>>()?;
            for mut event in active
                .into_iter()
                .filter(|event| !firing_subjects.contains(&event.subject))
            {
                event.active = false;
                event.updated_unix_seconds = now;
                event.resolved_unix_seconds = Some(now);
                event.message = format!("resolved: {}", event.message);
                save_event(&transaction, &event).await?;
                notifications.push(AlertNotification {
                    event,
                    resolved: true,
                    webhook: rule.notify_webhook,
                    email: rule.notify_email,
                });
            }
        }
        for notification in &notifications {
            enqueue(&transaction, notification, now).await?;
        }
        transaction.commit().await?;
        Ok(notifications)
    }
}

async fn database_now(transaction: &PgTransaction<'_>) -> anyhow::Result<u64> {
    let now: i64 = transaction
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp()))::bigint",
            &[],
        )
        .await?
        .get(0);
    Ok(u64::try_from(now)?)
}

const DELIVERY_VIEW_COLUMNS: &str = "id,idempotency_key,event_id,rule_name,subject,resolved,channel,state,attempts,next_attempt_unix_seconds,lease_expires_unix_seconds,last_error,created_unix_seconds,updated_unix_seconds,delivered_unix_seconds";

fn delivery_view(row: &tokio_postgres::Row) -> anyhow::Result<NotificationDeliveryView> {
    let timestamp =
        |index: usize| -> anyhow::Result<u64> { Ok(u64::try_from(row.get::<_, i64>(index))?) };
    let optional_timestamp = |index: usize| -> anyhow::Result<Option<u64>> {
        row.get::<_, Option<i64>>(index)
            .map(u64::try_from)
            .transpose()
            .map_err(Into::into)
    };
    Ok(NotificationDeliveryView {
        id: row.get(0),
        idempotency_key: row.get(1),
        event_id: row.get(2),
        rule_name: row.get(3),
        subject: row.get(4),
        resolved: row.get(5),
        channel: row.get::<_, &str>(6).parse()?,
        state: row.get::<_, &str>(7).parse()?,
        attempts: u32::try_from(row.get::<_, i32>(8))?,
        next_attempt_unix_seconds: timestamp(9)?,
        lease_expires_unix_seconds: optional_timestamp(10)?,
        last_error: row.get(11),
        created_unix_seconds: timestamp(12)?,
        updated_unix_seconds: timestamp(13)?,
        delivered_unix_seconds: optional_timestamp(14)?,
    })
}

fn make_rule(id: Uuid, request: CreateAlertRule, created: u64, now: u64) -> AlertRule {
    AlertRule {
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
        created_unix_seconds: created,
        updated_unix_seconds: now,
    }
}

async fn save_rule(transaction: &PgTransaction<'_>, rule: &AlertRule) -> anyhow::Result<()> {
    let payload = serde_json::to_string(rule)?;
    transaction.execute("INSERT INTO linklake_alert_rules(id,rule) VALUES($1,$2::text::jsonb) ON CONFLICT(id) DO UPDATE SET rule=EXCLUDED.rule", &[&rule.id.to_string(), &payload]).await?;
    Ok(())
}

async fn save_event(transaction: &PgTransaction<'_>, event: &AlertEvent) -> anyhow::Result<()> {
    let payload = serde_json::to_string(event)?;
    transaction.execute(
        "INSERT INTO linklake_alert_events(id,rule_id,subject,active,updated_unix_seconds,event) VALUES($1,$2,$3,$4,$5,$6::text::jsonb)
         ON CONFLICT(id) DO UPDATE SET active=EXCLUDED.active,updated_unix_seconds=EXCLUDED.updated_unix_seconds,event=EXCLUDED.event",
        &[&event.id, &event.rule_id.to_string(), &event.subject, &event.active, &(event.updated_unix_seconds as i64), &payload],
    ).await?;
    Ok(())
}

async fn resolve_rule_events(
    transaction: &PgTransaction<'_>,
    id: Uuid,
    now: u64,
    reason: &str,
) -> anyhow::Result<()> {
    let rows = transaction
        .query(
            "SELECT event::text FROM linklake_alert_events WHERE rule_id=$1 AND active FOR UPDATE",
            &[&id.to_string()],
        )
        .await?;
    for row in rows {
        let mut event: AlertEvent = serde_json::from_str(row.get(0))?;
        event.active = false;
        event.updated_unix_seconds = now;
        event.resolved_unix_seconds = Some(now);
        event.message.push_str(&format!(" ({reason})"));
        save_event(transaction, &event).await?;
    }
    Ok(())
}

async fn enqueue(
    transaction: &PgTransaction<'_>,
    notification: &AlertNotification,
    now: u64,
) -> anyhow::Result<()> {
    let channels: Vec<_> = [
        (NotificationChannel::Webhook, notification.webhook),
        (NotificationChannel::Email, notification.email),
    ]
    .into_iter()
    .filter_map(|(channel, enabled)| enabled.then_some(channel))
    .collect();
    if channels.is_empty() {
        return Ok(());
    }
    let outstanding: i64 = transaction.query_one("SELECT count(*) FROM linklake_alert_deliveries WHERE state IN ('pending','delivering')", &[]).await?.get(0);
    anyhow::ensure!(
        outstanding as u64 + channels.len() as u64 <= MAX_OUTSTANDING_NOTIFICATION_DELIVERIES,
        "notification delivery queue is full"
    );
    let payload = serde_json::to_string(notification)?;
    anyhow::ensure!(
        payload.len() <= NOTIFICATION_DELIVERY_PAYLOAD_MAX_BYTES,
        "notification delivery payload is too large"
    );
    for channel in channels {
        transaction.execute(
            "INSERT INTO linklake_alert_deliveries(idempotency_key,event_id,rule_name,subject,resolved,channel,payload,state,attempts,next_attempt_unix_seconds,created_unix_seconds,updated_unix_seconds)
             VALUES($1,$2,$3,$4,$5,$6,$7::text::jsonb,'pending',0,$8,$8,$8)",
            &[&Uuid::new_v4().to_string(), &notification.event.id, &notification.event.rule_name, &notification.event.subject,
              &notification.resolved, &channel.to_string(), &payload, &(now as i64)],
        ).await?;
    }
    Ok(())
}
