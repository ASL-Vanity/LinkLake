//! HTTP 路由异步存储入口；共享后端读取失败不回退本机目录。

use crate::{
    database::Database,
    ha_runtime::HaRuntime,
    http_route_catalog::{postgres::PostgresHttpRouteCatalog, *},
    storage::CoordinationStorage,
};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

pub(crate) enum HttpRouteStore {
    Sqlite(Mutex<HttpRouteCatalog>),
    Postgres(PostgresHttpRouteCatalog),
}

impl HttpRouteStore {
    pub(crate) async fn policy_versioned(
        &self,
        id: Uuid,
    ) -> anyhow::Result<(Option<HttpRoutePolicy>, Option<Uuid>)> {
        match self {
            Self::Sqlite(catalog) => Ok((
                catalog
                    .lock()
                    .expect("HTTP route catalog lock poisoned")
                    .policy_by_id(id)?,
                None,
            )),
            Self::Postgres(catalog) => Ok(match catalog.snapshot(id).await? {
                Some(snapshot) => (Some(snapshot.policy), Some(snapshot.revision)),
                None => (None, None),
            }),
        }
    }

    pub(crate) fn open(
        database: &Database,
        storage: CoordinationStorage,
        runtime: Arc<HaRuntime>,
    ) -> anyhow::Result<Self> {
        Ok(match storage {
            CoordinationStorage::Sqlite(_) => {
                Self::Sqlite(Mutex::new(HttpRouteCatalog::open_with_database(database)?))
            }
            storage @ CoordinationStorage::Postgres(_) => {
                Self::Postgres(PostgresHttpRouteCatalog { storage, runtime })
            }
        })
    }

    pub(crate) async fn list(&self) -> anyhow::Result<Vec<HttpRoutePolicy>> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("HTTP route catalog lock poisoned")
                .list(),
            Self::Postgres(catalog) => catalog.list().await,
        }
    }

    pub(crate) async fn policy_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<HttpRoutePolicy>, CreateHttpRouteError> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("HTTP route catalog lock poisoned")
                .policy_by_id(id),
            Self::Postgres(catalog) => catalog.policy_by_id(id).await,
        }
    }

    pub(crate) async fn create(
        &self,
        request: CreateHttpRoutePolicy,
    ) -> Result<HttpRoutePolicy, CreateHttpRouteError> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("HTTP route catalog lock poisoned")
                .create(request),
            Self::Postgres(catalog) => catalog.create(request).await,
        }
    }

    pub(crate) async fn update(
        &self,
        id: Uuid,
        request: UpdateHttpRoutePolicy,
    ) -> Result<Option<HttpRoutePolicy>, CreateHttpRouteError> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("HTTP route catalog lock poisoned")
                .update(id, request),
            Self::Postgres(catalog) => catalog.update(id, request).await,
        }
    }

    pub(crate) async fn set_enabled(&self, id: Uuid, enabled: bool) -> anyhow::Result<bool> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("HTTP route catalog lock poisoned")
                .set_enabled(id, enabled),
            Self::Postgres(catalog) => catalog.set_enabled(id, enabled).await,
        }
    }

    pub(crate) async fn delete(&self, id: Uuid) -> anyhow::Result<bool> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("HTTP route catalog lock poisoned")
                .delete(id),
            Self::Postgres(catalog) => catalog.delete(id).await,
        }
    }

    pub(crate) async fn enabled_hostname_exists(&self, hostname: &str) -> anyhow::Result<bool> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("HTTP route catalog lock poisoned")
                .enabled_hostname_exists(hostname),
            Self::Postgres(catalog) => catalog.enabled_hostname_exists(hostname).await,
        }
    }

    pub(crate) async fn runtime_policy(
        &self,
        client_id: Uuid,
        name: &str,
        hostname: &str,
        target_addr: &str,
    ) -> anyhow::Result<Option<HttpRouteRuntimePolicy>> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("HTTP route catalog lock poisoned")
                .runtime_policy(client_id, name, hostname, target_addr),
            Self::Postgres(catalog) => {
                catalog
                    .runtime_policy(client_id, name, hostname, target_addr)
                    .await
            }
        }
    }
}
