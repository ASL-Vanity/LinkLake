//! Fleet 节点目录的双后端入口；HA 模式直接读取共享目录并在事务内校验写入租约。

use crate::{
    database::Database,
    fleet::{validate, FleetCatalog, FleetPeer, UpsertFleetPeer},
    ha_runtime::HaRuntime,
    storage::{CoordinationStorage, StorageBackend},
};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

pub(crate) enum FleetStore {
    Sqlite(Mutex<FleetCatalog>),
    Postgres {
        storage: CoordinationStorage,
        runtime: Arc<HaRuntime>,
    },
}

const PEER_COLUMNS: &str = "id, name, url, region, weight, priority, token_env, enabled, created_unix_seconds, updated_unix_seconds";
pub(crate) const FLEET_STATE_LOCK: i64 = 0x4c4c_4648_5354;

impl FleetStore {
    pub(crate) fn open(
        database: &Database,
        storage: CoordinationStorage,
        runtime: Arc<HaRuntime>,
    ) -> anyhow::Result<Self> {
        Ok(match storage.backend() {
            StorageBackend::Sqlite => {
                Self::Sqlite(Mutex::new(FleetCatalog::open_with_database(database)?))
            }
            StorageBackend::Postgres => Self::Postgres { storage, runtime },
        })
    }

    pub(crate) async fn list(&self) -> anyhow::Result<Vec<FleetPeer>> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .map_err(|_| anyhow::anyhow!("Fleet catalog lock poisoned"))?
                .list(),
            Self::Postgres { storage, .. } => {
                let rows = storage.postgres_client().await?.query(
                    &format!("SELECT {PEER_COLUMNS} FROM linklake_fleet_peers ORDER BY priority, name"), &[],
                ).await?;
                rows.iter().map(read_peer).collect()
            }
        }
    }

    pub(crate) async fn create(
        &self,
        request: UpsertFleetPeer,
        now: u64,
    ) -> anyhow::Result<FleetPeer> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .map_err(|_| anyhow::anyhow!("Fleet catalog lock poisoned"))?
                .create(request, now),
            Self::Postgres { storage, runtime } => {
                let request = validate(request)?;
                let mut client = storage.postgres_client().await?;
                let transaction = client.transaction().await?;
                assert_writer(runtime, &transaction).await?;
                let peer = transaction.query_one(
                    &format!("INSERT INTO linklake_fleet_peers (id, name, url, region, weight, priority, token_env, enabled, created_unix_seconds, updated_unix_seconds)
                    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9) RETURNING {PEER_COLUMNS}"),
                    &[&Uuid::new_v4().to_string(), &request.name, &request.url, &request.region,
                      &i32::from(request.weight), &i32::from(request.priority), &request.token_env,
                      &request.enabled, &i64::try_from(now)?],
                ).await?;
                let peer = read_peer(&peer)?;
                transaction.commit().await?;
                Ok(peer)
            }
        }
    }

    pub(crate) async fn update(
        &self,
        id: Uuid,
        request: UpsertFleetPeer,
        now: u64,
    ) -> anyhow::Result<Option<FleetPeer>> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .map_err(|_| anyhow::anyhow!("Fleet catalog lock poisoned"))?
                .update(id, request, now),
            Self::Postgres { storage, runtime } => {
                let request = validate(request)?;
                let mut client = storage.postgres_client().await?;
                let transaction = client.transaction().await?;
                assert_writer(runtime, &transaction).await?;
                let peer = transaction.query_opt(
                    &format!("UPDATE linklake_fleet_peers SET name=$2, url=$3, region=$4, weight=$5, priority=$6, token_env=$7, enabled=$8, updated_unix_seconds=$9 WHERE id=$1 RETURNING {PEER_COLUMNS}"),
                    &[&id.to_string(), &request.name, &request.url, &request.region,
                      &i32::from(request.weight), &i32::from(request.priority), &request.token_env,
                      &request.enabled, &i64::try_from(now)?],
                ).await?;
                let peer = peer.as_ref().map(read_peer).transpose()?;
                transaction.commit().await?;
                Ok(peer)
            }
        }
    }

    pub(crate) async fn delete(&self, id: Uuid) -> anyhow::Result<bool> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .map_err(|_| anyhow::anyhow!("Fleet catalog lock poisoned"))?
                .delete(id),
            Self::Postgres { storage, runtime } => {
                let mut client = storage.postgres_client().await?;
                let transaction = client.transaction().await?;
                assert_writer(runtime, &transaction).await?;
                crate::fleet_health::postgres::remove_peer_references(&transaction, id).await?;
                let deleted = transaction
                    .execute(
                        "DELETE FROM linklake_fleet_peers WHERE id=$1",
                        &[&id.to_string()],
                    )
                    .await?;
                transaction.commit().await?;
                Ok(deleted > 0)
            }
        }
    }
}

async fn assert_writer(
    runtime: &HaRuntime,
    transaction: &tokio_postgres::Transaction<'_>,
) -> anyhow::Result<()> {
    transaction
        .query_one("SELECT pg_advisory_xact_lock($1)", &[&FLEET_STATE_LOCK])
        .await?;
    let token = runtime.fencing_token()?;
    runtime
        .coordinator()
        .assert_postgres_transaction_fence(transaction, token)
        .await
}

pub(crate) fn read_peer(row: &tokio_postgres::Row) -> anyhow::Result<FleetPeer> {
    let token_env: String = row.try_get(6)?;
    Ok(FleetPeer {
        id: Uuid::parse_str(row.try_get::<_, &str>(0)?)?,
        name: row.try_get(1)?,
        url: row.try_get(2)?,
        region: row.try_get(3)?,
        weight: u16::try_from(row.try_get::<_, i32>(4)?)?,
        priority: u16::try_from(row.try_get::<_, i32>(5)?)?,
        token_configured: std::env::var_os(&token_env).is_some(),
        token_env,
        enabled: row.try_get(7)?,
        created_unix_seconds: u64::try_from(row.try_get::<_, i64>(8)?)?,
        updated_unix_seconds: u64::try_from(row.try_get::<_, i64>(9)?)?,
    })
}
