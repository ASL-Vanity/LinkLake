//! Fleet 业务入口；PG 下所有策略、凭据引用和代际在共享事务中维护。
use crate::{
    database::Database,
    ha_runtime::HaRuntime,
    policy_service::{postgres::PostgresPolicyService, *},
    public_port_policy::PublicPortPolicy,
    storage::CoordinationStorage,
};
use linklake_core::{fleet_protocol::FleetBundleV2, ClientSummary};
use std::sync::Arc;
use uuid::Uuid;

pub(crate) enum PolicyStore {
    Sqlite(PolicyService),
    Postgres(PostgresPolicyService),
}

macro_rules! delegate {
    ($name:ident ($($arg:ident : $type:ty),*) -> $result:ty) => {
        pub(crate) async fn $name(&self, $($arg:$type),*) -> anyhow::Result<$result> {
            match self {
                Self::Sqlite(store) => store.$name($($arg),*),
                Self::Postgres(store) => store.$name($($arg),*).await,
            }
        }
    };
}

impl PolicyStore {
    pub(crate) fn open(
        database: &Database,
        storage: CoordinationStorage,
        runtime: Arc<HaRuntime>,
        public_port_policy: PublicPortPolicy,
    ) -> anyhow::Result<Self> {
        Ok(match storage {
            CoordinationStorage::Sqlite(_) => Self::Sqlite(PolicyService::open_with_database(
                database,
                public_port_policy,
            )?),
            storage @ CoordinationStorage::Postgres(_) => Self::Postgres(PostgresPolicyService {
                storage,
                runtime,
                public_port_policy,
            }),
        })
    }
    delegate!(list_sources() -> Vec<FleetSourceStatus>);
    delegate!(list_credential_bindings() -> Vec<FleetCredentialBinding>);
    delegate!(is_policy_managed(kind: FleetPolicyKind, id: Uuid) -> bool);
    delegate!(bind_credential(request: BindFleetCredential, now: u64) -> FleetCredentialBinding);
    delegate!(delete_credential_binding(source: Uuid, kind: FleetPolicyKind, credential: Uuid) -> bool);
    delegate!(reset_source_state(source: Uuid) -> bool);
    delegate!(export_bundle_with_clients(now: u64, clients: &[ClientSummary]) -> FleetBundleV2);
    delegate!(reconcile_with_clients(request: FleetReconcileRequest, now: u64, clients: &[ClientSummary]) -> FleetReconcileResult);
}
