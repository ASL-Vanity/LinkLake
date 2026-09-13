//! 流量控制异步入口；PG 使用数据库时间与共享窗口，失败不得退回本机放行。

use super::traffic_control::{postgres::PostgresTrafficControlCatalog, *};
use crate::{database::Database, ha_runtime::HaRuntime, storage::CoordinationStorage};
use std::{
    net::IpAddr,
    sync::{Arc, Mutex},
};
use uuid::Uuid;

pub(crate) enum TrafficControlStore {
    Sqlite(Mutex<TrafficControlCatalog>),
    Postgres(PostgresTrafficControlCatalog),
}

impl TrafficControlStore {
    pub(crate) fn open(
        database: &Database,
        storage: CoordinationStorage,
        runtime: Arc<HaRuntime>,
    ) -> anyhow::Result<Self> {
        Ok(match storage {
            CoordinationStorage::Sqlite(_) => Self::Sqlite(Mutex::new(
                TrafficControlCatalog::open_with_database(database)?,
            )),
            storage @ CoordinationStorage::Postgres(_) => {
                Self::Postgres(PostgresTrafficControlCatalog { storage, runtime })
            }
        })
    }

    pub(crate) async fn get(
        &self,
        kind: TrafficPolicyKind,
        id: Uuid,
        now: u64,
    ) -> anyhow::Result<Option<TrafficControlRecord>> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("traffic control catalog lock poisoned")
                .get(kind, id, now),
            Self::Postgres(catalog) => catalog.get(kind, id).await,
        }
    }

    pub(crate) async fn upsert(
        &self,
        kind: TrafficPolicyKind,
        id: Uuid,
        settings: UpsertTrafficControl,
        now: u64,
    ) -> anyhow::Result<TrafficControlRecord> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("traffic control catalog lock poisoned")
                .upsert(kind, id, settings, now),
            Self::Postgres(catalog) => catalog.upsert(kind, id, settings).await,
        }
    }

    pub(crate) async fn delete(&self, kind: TrafficPolicyKind, id: Uuid) -> anyhow::Result<bool> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("traffic control catalog lock poisoned")
                .delete(kind, id),
            Self::Postgres(catalog) => catalog.delete(kind, id).await,
        }
    }

    pub(crate) async fn authorize(
        &self,
        kind: TrafficPolicyKind,
        id: Uuid,
        source: IpAddr,
        now: u64,
    ) -> anyhow::Result<TrafficDecision> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("traffic control catalog lock poisoned")
                .authorize(kind, id, source, now),
            Self::Postgres(catalog) => catalog.authorize(kind, id, source).await,
        }
    }

    pub(crate) async fn enqueue_usage_event(
        &self,
        event: &TrafficUsageEvent,
        now: u64,
    ) -> anyhow::Result<()> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("traffic control catalog lock poisoned")
                .record_usage_event(event, now),
            Self::Postgres(catalog) => catalog.enqueue_usage_event(event).await,
        }
    }

    pub(crate) async fn drain_pending_usage(&self) -> anyhow::Result<usize> {
        match self {
            Self::Sqlite(_) => Ok(0),
            Self::Postgres(catalog) => catalog.drain_pending_usage().await,
        }
    }

    pub(crate) async fn reset_runtime_state(&self) -> anyhow::Result<()> {
        match self {
            Self::Sqlite(catalog) => {
                catalog
                    .lock()
                    .expect("traffic control catalog lock poisoned")
                    .reset_runtime_state();
                Ok(())
            }
            Self::Postgres(catalog) => catalog.reset_runtime_state().await,
        }
    }
}
