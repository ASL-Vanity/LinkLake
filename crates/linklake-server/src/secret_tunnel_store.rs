//! Secret 隧道异步双后端；PostgreSQL 失败不回退本机授权目录。

use crate::{
    database::Database,
    ha_runtime::HaRuntime,
    secret_tunnel_catalog::{postgres::PostgresSecretTunnelCatalog, *},
    storage::CoordinationStorage,
};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

pub(crate) enum SecretTunnelStore {
    Sqlite(Mutex<SecretTunnelCatalog>),
    Postgres(PostgresSecretTunnelCatalog),
}

impl SecretTunnelStore {
    pub(crate) fn open(
        database: &Database,
        storage: CoordinationStorage,
        runtime: Arc<HaRuntime>,
    ) -> anyhow::Result<Self> {
        Ok(match storage {
            CoordinationStorage::Sqlite(_) => Self::Sqlite(Mutex::new(
                SecretTunnelCatalog::open_with_database(database)?,
            )),
            storage @ CoordinationStorage::Postgres(_) => {
                Self::Postgres(PostgresSecretTunnelCatalog { storage, runtime })
            }
        })
    }

    pub(crate) async fn create(
        &self,
        request: CreateSecretTunnelPolicy,
    ) -> Result<CreatedSecretTunnelPolicy, SecretPolicyError> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("Secret tunnel catalog lock poisoned")
                .create(request),
            Self::Postgres(catalog) => catalog.create(request).await,
        }
    }

    pub(crate) async fn update(
        &self,
        id: Uuid,
        request: UpdateSecretTunnelPolicy,
    ) -> Result<Option<SecretTunnelPolicy>, SecretPolicyError> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("Secret tunnel catalog lock poisoned")
                .update(id, request),
            Self::Postgres(catalog) => catalog.update(id, request).await,
        }
    }

    pub(crate) async fn list(&self) -> Result<Vec<SecretTunnelPolicy>, SecretPolicyError> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("Secret tunnel catalog lock poisoned")
                .list(),
            Self::Postgres(catalog) => catalog.list().await,
        }
    }

    pub(crate) async fn policy_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<SecretTunnelPolicy>, SecretPolicyError> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("Secret tunnel catalog lock poisoned")
                .policy_by_id(id),
            Self::Postgres(catalog) => catalog.policy_by_id(id).await,
        }
    }

    pub(crate) async fn set_enabled(
        &self,
        id: Uuid,
        enabled: bool,
    ) -> Result<bool, SecretPolicyError> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("Secret tunnel catalog lock poisoned")
                .set_enabled(id, enabled),
            Self::Postgres(catalog) => catalog.set_enabled(id, enabled).await,
        }
    }

    pub(crate) async fn delete(
        &self,
        id: Uuid,
    ) -> Result<Option<SecretTunnelPolicy>, SecretPolicyError> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("Secret tunnel catalog lock poisoned")
                .delete(id),
            Self::Postgres(catalog) => catalog.delete(id).await,
        }
    }

    pub(crate) async fn provider_runtime_policy(
        &self,
        provider_client_id: Uuid,
        name: &str,
        target_addr: &str,
    ) -> Result<Option<SecretTunnelRuntimePolicy>, SecretPolicyError> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("Secret tunnel catalog lock poisoned")
                .provider_runtime_policy(provider_client_id, name, target_addr),
            Self::Postgres(catalog) => {
                catalog
                    .provider_runtime_policy(provider_client_id, name, target_addr)
                    .await
            }
        }
    }

    pub(crate) async fn access_runtime_policy(
        &self,
        visitor_client_id: Uuid,
        access_key: &str,
    ) -> Result<Option<SecretTunnelRuntimePolicy>, SecretPolicyError> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("Secret tunnel catalog lock poisoned")
                .access_runtime_policy(visitor_client_id, access_key),
            Self::Postgres(catalog) => {
                catalog
                    .access_runtime_policy(visitor_client_id, access_key)
                    .await
            }
        }
    }
}
