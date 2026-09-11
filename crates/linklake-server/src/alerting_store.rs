//! 告警双后端接口：同步 SQLite 锁不会跨越 PostgreSQL 的异步调用。

use crate::{
    alerting::{postgres::PostgresAlertCatalog, *},
    database::Database,
    ha_runtime::HaRuntime,
    storage::{CoordinationStorage, StorageBackend},
};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

pub(crate) enum AlertStore {
    Sqlite(Mutex<AlertCatalog>),
    Postgres(PostgresAlertCatalog),
}

macro_rules! delegate {
    ($name:ident ($($arg:ident : $kind:ty),*) -> $result:ty) => {
        pub(crate) async fn $name(&self, $($arg: $kind),*) -> anyhow::Result<$result> {
            match self {
                Self::Sqlite(catalog) => catalog.lock().map_err(|_| anyhow::anyhow!("alert catalog lock poisoned"))?.$name($($arg),*),
                Self::Postgres(catalog) => catalog.$name($($arg),*).await,
            }
        }
    };
}

impl AlertStore {
    pub(crate) fn open(
        database: &Database,
        storage: CoordinationStorage,
        runtime: Arc<HaRuntime>,
    ) -> anyhow::Result<Self> {
        Ok(match storage.backend() {
            StorageBackend::Sqlite => {
                Self::Sqlite(Mutex::new(AlertCatalog::open_with_database(database)?))
            }
            StorageBackend::Postgres => Self::Postgres(PostgresAlertCatalog { storage, runtime }),
        })
    }

    // SQLite 在打开时初始化，PostgreSQL 必须等待 Leader 接管后才允许写入。
    pub(crate) async fn ensure_defaults(&self) -> anyhow::Result<()> {
        match self {
            Self::Sqlite(_) => Ok(()),
            Self::Postgres(catalog) => catalog.ensure_defaults().await,
        }
    }

    delegate!(list_rules() -> Vec<AlertRule>);
    delegate!(create_rule(request: CreateAlertRule, now: u64) -> AlertRule);
    delegate!(update_rule(id: Uuid, request: UpdateAlertRule, now: u64) -> Option<AlertRule>);
    delegate!(delete_rule(id: Uuid, now: u64) -> bool);
    delegate!(list_events(active_only: bool, limit: usize) -> Vec<AlertEvent>);
    delegate!(evaluate(signals: &[AlertSignal], now: u64) -> Vec<AlertNotification>);
    delegate!(claim_notification_deliveries(now: u64, limit: usize) -> Vec<NotificationDelivery>);
    delegate!(acknowledge_notification_delivery(delivery: &NotificationDelivery, now: u64) -> bool);
    delegate!(fail_notification_delivery(delivery: &NotificationDelivery, now: u64, error: &str) -> Option<NotificationDeliveryState>);
    delegate!(retry_notification_delivery(id: i64, now: u64) -> NotificationDeliveryRetryOutcome);
    delegate!(list_notification_deliveries(limit: usize, state: Option<NotificationDeliveryState>, channel: Option<NotificationChannel>) -> Vec<NotificationDeliveryView>);
    delegate!(notification_delivery_metrics(now: u64) -> NotificationDeliveryMetrics);
}
