//! SNI 路由异步双后端入口。

use crate::{
    database::Database,
    ha_runtime::HaRuntime,
    sni_route_catalog::{postgres::PostgresSniRouteCatalog, *},
    storage::CoordinationStorage,
};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

pub(crate) enum SniRouteStore {
    Sqlite(Mutex<SniRouteCatalog>),
    Postgres(PostgresSniRouteCatalog),
}

fn shared_error(error: anyhow::Error) -> SniRoutePolicyError {
    match error.downcast::<SniRoutePolicyError>() {
        Ok(error) => error,
        Err(error) => SniRoutePolicyError::Storage(error),
    }
}

macro_rules! delegate {
    ($name:ident ($($arg:ident : $kind:ty),*) -> $result:ty) => {
        pub(crate) async fn $name(&self, $($arg: $kind),*) -> Result<$result, SniRoutePolicyError> {
            match self {
                Self::Sqlite(catalog) => catalog.lock().expect("SNI route catalog lock poisoned").$name($($arg),*),
                Self::Postgres(catalog) => catalog.$name($($arg),*).await.map_err(shared_error),
            }
        }
    };
}

impl SniRouteStore {
    pub(crate) fn open(
        database: &Database,
        storage: CoordinationStorage,
        runtime: Arc<HaRuntime>,
    ) -> anyhow::Result<Self> {
        Ok(match storage {
            CoordinationStorage::Sqlite(_) => {
                Self::Sqlite(Mutex::new(SniRouteCatalog::open_with_database(database)?))
            }
            storage @ CoordinationStorage::Postgres(_) => {
                Self::Postgres(PostgresSniRouteCatalog { storage, runtime })
            }
        })
    }

    delegate!(list() -> Vec<SniRoutePolicy>);
    delegate!(policy_by_id(id: Uuid) -> Option<SniRoutePolicy>);
    delegate!(create(request: CreateSniRoutePolicy) -> SniRoutePolicy);
    delegate!(update(id: Uuid, request: UpdateSniRoutePolicy) -> Option<SniRoutePolicy>);
    delegate!(set_enabled(id: Uuid, enabled: bool) -> bool);
    delegate!(delete(id: Uuid) -> Option<SniRoutePolicy>);
    delegate!(runtime_policy(client_id: Uuid, name: &str, hostname: &str, target_addr: &str) -> Option<SniRouteRuntimePolicy>);
}
