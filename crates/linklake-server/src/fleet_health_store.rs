//! Fleet 健康/DNS 的异步双后端入口；SQLite 保留原有状态机和持久化语义。

use crate::{
    database::Database,
    fleet::FleetPeer,
    fleet_health::{postgres::PostgresFleetHealthCatalog, *},
    ha_runtime::HaRuntime,
    storage::{CoordinationStorage, StorageBackend},
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use uuid::Uuid;

pub(crate) enum FleetHealthStore {
    Sqlite(Mutex<FleetHealthCatalog>, Arc<HaRuntime>),
    Postgres(PostgresFleetHealthCatalog),
}

// 只在 SQLite 分支短暂持有同步锁，任何 PostgreSQL await 均不持有该锁。
macro_rules! delegate {
    ($name:ident ($($arg:ident : $kind:ty),*) -> $result:ty) => {
        pub(crate) async fn $name(&self, $($arg: $kind),*) -> anyhow::Result<$result> {
            match self {
                Self::Sqlite(catalog, _) => catalog.lock().map_err(|_| anyhow::anyhow!("Fleet health catalog lock poisoned"))?.$name($($arg),*),
                Self::Postgres(catalog) => catalog.$name($($arg),*).await,
            }
        }
    };
}

impl FleetHealthStore {
    pub(crate) fn open(
        database: &Database,
        storage: CoordinationStorage,
        runtime: Arc<HaRuntime>,
    ) -> anyhow::Result<Self> {
        Ok(match storage.backend() {
            StorageBackend::Sqlite => Self::Sqlite(
                Mutex::new(FleetHealthCatalog::open_with_database(database)?),
                runtime,
            ),
            StorageBackend::Postgres => {
                Self::Postgres(PostgresFleetHealthCatalog { storage, runtime })
            }
        })
    }

    delegate!(ensure_peer(peer_id: Uuid, now: u64) -> ());
    delegate!(snapshot(peer_id: Uuid) -> Option<FleetHealthSnapshot>);
    delegate!(snapshots() -> HashMap<Uuid, FleetHealthSnapshot>);
    delegate!(update_health_config(peer_id: Uuid, request: UpdateFleetHealthConfig, now: u64) -> Option<FleetHealthSnapshot>);
    delegate!(record_probe(peer_id: Uuid, observation: FleetProbeObservation) -> FleetProbeResult);
    delegate!(create_dns_failover(request: UpsertFleetDnsFailover, peers: &[FleetPeer], now: u64) -> FleetDnsFailover);
    delegate!(update_dns_failover(id: Uuid, request: UpsertFleetDnsFailover, peers: &[FleetPeer], now: u64) -> Option<FleetDnsFailover>);
    delegate!(delete_dns_failover(id: Uuid) -> bool);
    delegate!(list_dns_failovers() -> Vec<FleetDnsFailover>);
    delegate!(get_dns_failover(id: Uuid) -> Option<FleetDnsFailover>);
    delegate!(list_dns_switch_events(id: Uuid, limit: usize) -> Vec<FleetDnsSwitchEvent>);
    delegate!(set_dns_frozen(id: Uuid, frozen: bool, reason: Option<&str>, now: u64) -> Option<FleetDnsFailover>);
    delegate!(plan_dns_changes(now: u64, only: Option<Uuid>) -> Vec<FleetDnsChangePlan>);
    pub(crate) async fn validate_dns_execution(
        &self,
        plan: &FleetDnsChangePlan,
        lease: &crate::job_leases::JobLease,
    ) -> anyhow::Result<u64> {
        match self {
            Self::Sqlite(catalog, runtime) => catalog
                .lock()
                .map_err(|_| anyhow::anyhow!("Fleet health catalog lock poisoned"))?
                .validate_dns_execution(plan, runtime.jobs(), lease),
            Self::Postgres(catalog) => catalog.validate_dns_execution(plan, lease).await,
        }
    }

    pub(crate) async fn complete_dns_change(
        &self,
        plan: &FleetDnsChangePlan,
        result: Result<(), &str>,
        lease: &crate::job_leases::JobLease,
    ) -> anyhow::Result<FleetDnsChangeResult> {
        match self {
            Self::Sqlite(catalog, runtime) => catalog
                .lock()
                .map_err(|_| anyhow::anyhow!("Fleet health catalog lock poisoned"))?
                .complete_dns_change_with_lease(plan, result, runtime.jobs(), lease),
            Self::Postgres(catalog) => catalog.complete_dns_change(plan, result, lease).await,
        }
    }
    delegate!(metrics() -> FleetHealthMetrics);

    pub(crate) async fn mark_dns_drift(
        &self,
        plan: &FleetDnsChangePlan,
        lease: &crate::job_leases::JobLease,
    ) -> anyhow::Result<bool> {
        match self {
            Self::Sqlite(catalog, runtime) => catalog
                .lock()
                .map_err(|_| anyhow::anyhow!("Fleet health catalog lock poisoned"))?
                .mark_dns_drift(plan, runtime.jobs(), lease),
            Self::Postgres(catalog) => catalog.mark_dns_drift(plan, lease).await,
        }
    }
}
