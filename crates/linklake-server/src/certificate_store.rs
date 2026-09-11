//! 证书目录的双后端接口；保留 API 校验错误码并隐藏底层连接信息。

use crate::{
    certificate_catalog::{postgres::PostgresCertificateCatalog, *},
    database::Database,
    ha_runtime::HaRuntime,
    storage::{CoordinationStorage, StorageBackend},
};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

pub(crate) enum CertificateStore {
    Sqlite(Mutex<CertificateCatalog>),
    Postgres(PostgresCertificateCatalog),
}

fn shared_error(error: anyhow::Error) -> CertificateCatalogError {
    match error.downcast::<CertificateCatalogError>() {
        Ok(validation) => validation,
        Err(storage) => CertificateCatalogError::SharedStorage(storage),
    }
}

macro_rules! delegate {
    ($name:ident ($($arg:ident : $kind:ty),*) -> $result:ty) => {
        pub(crate) async fn $name(&self, $($arg: $kind),*) -> Result<$result, CertificateCatalogError> {
            match self {
                Self::Sqlite(catalog) => catalog.lock().map_err(|_| CertificateCatalogError::InvalidStoredData("catalog_lock"))?.$name($($arg),*),
                Self::Postgres(catalog) => catalog.$name($($arg),*).await.map_err(shared_error),
            }
        }
    };
}

impl CertificateStore {
    pub(crate) async fn route_views(
        &self,
        route_ids: &[Uuid],
    ) -> Result<
        std::collections::HashMap<Uuid, (Option<RouteTlsPolicy>, Option<CertificateState>)>,
        CertificateCatalogError,
    > {
        match self {
            Self::Sqlite(catalog) => {
                let catalog = catalog
                    .lock()
                    .map_err(|_| CertificateCatalogError::InvalidStoredData("catalog_lock"))?;
                route_ids
                    .iter()
                    .map(|id| {
                        Ok((
                            *id,
                            (
                                catalog.get_route_tls(*id)?,
                                catalog.get_certificate_state(*id)?,
                            ),
                        ))
                    })
                    .collect()
            }
            Self::Postgres(catalog) => catalog.route_views(route_ids).await.map_err(shared_error),
        }
    }

    pub(crate) async fn get_route_tls_versioned(
        &self,
        route_id: Uuid,
    ) -> Result<(Option<RouteTlsPolicy>, Option<Uuid>), CertificateCatalogError> {
        match self {
            Self::Sqlite(catalog) => Ok((
                catalog
                    .lock()
                    .map_err(|_| CertificateCatalogError::InvalidStoredData("catalog_lock"))?
                    .get_route_tls(route_id)?,
                None,
            )),
            Self::Postgres(catalog) => Ok(
                match catalog
                    .get_route_tls_snapshot(route_id)
                    .await
                    .map_err(shared_error)?
                {
                    Some(snapshot) => (Some(snapshot.policy), Some(snapshot.revision)),
                    None => (None, None),
                },
            ),
        }
    }

    pub(crate) fn open(
        database: &Database,
        storage: CoordinationStorage,
        runtime: Arc<HaRuntime>,
    ) -> Result<Self, CertificateCatalogError> {
        Ok(match storage.backend() {
            StorageBackend::Sqlite => Self::Sqlite(Mutex::new(
                CertificateCatalog::open_with_database(database)?,
            )),
            StorageBackend::Postgres => {
                Self::Postgres(PostgresCertificateCatalog { storage, runtime })
            }
        })
    }

    delegate!(get_acme_config() -> AcmeConfig);
    delegate!(update_acme_config(request: UpdateAcmeConfig, now: i64) -> AcmeConfig);
    delegate!(get_route_tls(route_id: Uuid) -> Option<RouteTlsPolicy>);
    delegate!(set_route_tls(route_id: Uuid, request: UpdateRouteTlsPolicy, now: i64) -> RouteTlsPolicy);
    delegate!(delete_route_tls(route_id: Uuid) -> bool);
    delegate!(get_certificate_state(route_id: Uuid) -> Option<CertificateState>);
    delegate!(list_certificate_states() -> Vec<CertificateState>);
    delegate!(update_certificate_status(route_id: Uuid, expected_status: Option<CertificateStatus>, new_status: CertificateStatus, attempted_at: Option<i64>) -> bool);
    delegate!(record_certificate_success(route_id: Uuid, issuer: &str, not_before: i64, not_after: i64, completed_at: i64) -> CertificateState);
    delegate!(record_certificate_failure(route_id: Uuid, error_code: &str, error_message: &str, attempted_at: i64) -> CertificateState);
    delegate!(delete_certificate_state(route_id: Uuid) -> bool);
}
