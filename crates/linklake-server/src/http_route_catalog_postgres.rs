//! 共享 HTTP 路由目录；与证书提交共用事务锁，路由每次变更均刷新版本。

use super::*;
use crate::{
    certificate_catalog::postgres::CERTIFICATE_STATE_LOCK, ha_runtime::HaRuntime,
    storage::CoordinationStorage,
};
use std::sync::Arc;
use tokio_postgres::{Row, Transaction};

pub(crate) struct PostgresHttpRouteCatalog {
    pub(crate) storage: CoordinationStorage,
    pub(crate) runtime: Arc<HaRuntime>,
}

#[derive(Clone)]
pub(crate) struct HttpRouteSnapshot {
    pub(crate) policy: HttpRoutePolicy,
    pub(crate) revision: Uuid,
}

fn storage_error(error: impl Into<anyhow::Error>) -> CreateHttpRouteError {
    CreateHttpRouteError::Storage(error.into())
}

fn read_snapshot(row: &Row) -> anyhow::Result<HttpRouteSnapshot> {
    decode_snapshot(
        row.try_get("id")?,
        row.try_get("hostname")?,
        row.try_get("revision")?,
        row.try_get("policy")?,
    )
}

fn decode_snapshot(
    id: &str,
    hostname: &str,
    revision: &str,
    json: &str,
) -> anyhow::Result<HttpRouteSnapshot> {
    let id = Uuid::parse_str(id)?;
    let policy: HttpRoutePolicy = serde_json::from_str(json)?;
    anyhow::ensure!(
        policy.id == id && policy.hostname == hostname,
        "HTTP route row identity mismatch"
    );
    // 共享数据损坏时拒绝授权，不能把未校验 JSON 直接交给运行时。
    let normalized = requested_policy(
        id,
        policy.enabled,
        CreateHttpRoutePolicy {
            client_id: policy.client_id,
            name: policy.name.clone(),
            hostname: policy.hostname.clone(),
            target_addr: policy.target_addr.clone(),
            max_connections: Some(policy.max_connections),
            grpc_backend_transport: policy.grpc_backend_transport,
            grpc_backend_server_name: policy.grpc_backend_server_name.clone(),
            grpc_backend_trust_profile: policy.grpc_backend_trust_profile.clone(),
        },
    )?;
    anyhow::ensure!(normalized == policy, "HTTP route row is not canonical");
    Ok(HttpRouteSnapshot {
        policy,
        revision: Uuid::parse_str(revision)?,
    })
}

impl PostgresHttpRouteCatalog {
    async fn fence(&self, transaction: &Transaction<'_>) -> anyhow::Result<()> {
        transaction
            .query_one(
                "SELECT pg_advisory_xact_lock($1)",
                &[&CERTIFICATE_STATE_LOCK],
            )
            .await?;
        self.runtime
            .coordinator()
            .assert_postgres_transaction_fence(transaction, self.runtime.fencing_token()?)
            .await?;
        Ok(())
    }

    pub(crate) async fn list(&self) -> anyhow::Result<Vec<HttpRoutePolicy>> {
        self.storage.postgres_client().await?.query(
            "SELECT id,hostname,revision,policy::text FROM linklake_http_route_policies ORDER BY hostname", &[],
        ).await?.iter().map(|row| Ok(read_snapshot(row)?.policy)).collect()
    }

    pub(crate) async fn snapshot(&self, id: Uuid) -> anyhow::Result<Option<HttpRouteSnapshot>> {
        self.storage.postgres_client().await?.query_opt(
            "SELECT id,hostname,revision,policy::text FROM linklake_http_route_policies WHERE id=$1", &[&id.to_string()],
        ).await?.as_ref().map(read_snapshot).transpose()
    }

    pub(crate) async fn policy_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<HttpRoutePolicy>, CreateHttpRouteError> {
        Ok(self
            .snapshot(id)
            .await
            .map_err(storage_error)?
            .map(|snapshot| snapshot.policy))
    }

    pub(crate) async fn create(
        &self,
        request: CreateHttpRoutePolicy,
    ) -> Result<HttpRoutePolicy, CreateHttpRouteError> {
        let policy = requested_policy(Uuid::new_v4(), true, request)?;
        let mut client = self
            .storage
            .postgres_client()
            .await
            .map_err(storage_error)?;
        let transaction = client.transaction().await.map_err(storage_error)?;
        self.fence(&transaction).await.map_err(storage_error)?;
        ensure_hostname_available(&transaction, &policy).await?;
        transaction.execute(
            "INSERT INTO linklake_http_route_policies(id,hostname,revision,policy) VALUES($1,$2,$3,$4::text::jsonb)",
            &[&policy.id.to_string(), &policy.hostname, &Uuid::new_v4().to_string(),
              &serde_json::to_string(&policy).map_err(storage_error)?],
        ).await.map_err(storage_error)?;
        transaction.commit().await.map_err(storage_error)?;
        Ok(policy)
    }

    pub(crate) async fn update(
        &self,
        id: Uuid,
        request: UpdateHttpRoutePolicy,
    ) -> Result<Option<HttpRoutePolicy>, CreateHttpRouteError> {
        // 与 SQLite 一致：即使 ID 不存在也先校验请求。
        let mut policy = requested_policy(id, true, request)?;
        let mut client = self
            .storage
            .postgres_client()
            .await
            .map_err(storage_error)?;
        let transaction = client.transaction().await.map_err(storage_error)?;
        self.fence(&transaction).await.map_err(storage_error)?;
        let Some(current) = transaction_snapshot(&transaction, id)
            .await
            .map_err(storage_error)?
        else {
            transaction.commit().await.map_err(storage_error)?;
            return Ok(None);
        };
        policy.enabled = current.policy.enabled;
        ensure_hostname_available(&transaction, &policy).await?;
        write_policy(&transaction, &policy)
            .await
            .map_err(storage_error)?;
        transaction.commit().await.map_err(storage_error)?;
        Ok(Some(policy))
    }

    pub(crate) async fn set_enabled(&self, id: Uuid, enabled: bool) -> anyhow::Result<bool> {
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        self.fence(&transaction).await?;
        let Some(mut current) = transaction_snapshot(&transaction, id).await? else {
            transaction.commit().await?;
            return Ok(false);
        };
        current.policy.enabled = enabled;
        write_policy(&transaction, &current.policy).await?;
        transaction.commit().await?;
        Ok(true)
    }

    pub(crate) async fn delete(&self, id: Uuid) -> anyhow::Result<bool> {
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        self.fence(&transaction).await?;
        let deleted = transaction
            .execute(
                "DELETE FROM linklake_http_route_policies WHERE id=$1",
                &[&id.to_string()],
            )
            .await?
            != 0;
        transaction.commit().await?;
        Ok(deleted)
    }

    pub(crate) async fn enabled_hostname_exists(&self, hostname: &str) -> anyhow::Result<bool> {
        let hostname = normalize_hostname(hostname)?;
        let row = self.storage.postgres_client().await?.query_opt(
            "SELECT id,hostname,revision,policy::text FROM linklake_http_route_policies WHERE hostname=$1", &[&hostname],
        ).await?;
        Ok(row
            .as_ref()
            .map(read_snapshot)
            .transpose()?
            .is_some_and(|snapshot| snapshot.policy.enabled))
    }

    pub(crate) async fn runtime_policy(
        &self,
        client_id: Uuid,
        name: &str,
        hostname: &str,
        target_addr: &str,
    ) -> anyhow::Result<Option<HttpRouteRuntimePolicy>> {
        let hostname = normalize_hostname(hostname)?;
        let row = self.storage.postgres_client().await?.query_opt(
            "SELECT id,hostname,revision,policy::text FROM linklake_http_route_policies WHERE hostname=$1", &[&hostname],
        ).await?;
        let Some(snapshot) = row.as_ref().map(read_snapshot).transpose()? else {
            return Ok(None);
        };
        let policy = snapshot.policy;
        if !policy.enabled
            || policy.client_id != client_id
            || policy.name != name
            || policy.target_addr != target_addr
        {
            return Ok(None);
        }
        Ok(Some(HttpRouteRuntimePolicy {
            policy_id: policy.id,
            max_connections: usize::from(policy.max_connections),
            grpc_backend: grpc_backend_runtime(
                grpc_backend_transport_name(policy.grpc_backend_transport),
                policy.grpc_backend_server_name,
                policy.grpc_backend_trust_profile,
            )?,
        }))
    }
}

async fn ensure_hostname_available(
    transaction: &Transaction<'_>,
    policy: &HttpRoutePolicy,
) -> Result<(), CreateHttpRouteError> {
    if transaction
        .query_opt(
            "SELECT id FROM linklake_http_route_policies WHERE hostname=$1 AND id<>$2",
            &[&policy.hostname, &policy.id.to_string()],
        )
        .await
        .map_err(storage_error)?
        .is_some()
    {
        return Err(CreateHttpRouteError::DuplicateHostname);
    }
    Ok(())
}

async fn write_policy(
    transaction: &Transaction<'_>,
    policy: &HttpRoutePolicy,
) -> anyhow::Result<()> {
    let count = transaction.execute(
        "UPDATE linklake_http_route_policies SET hostname=$2,revision=$3,policy=$4::text::jsonb WHERE id=$1",
        &[&policy.id.to_string(), &policy.hostname, &Uuid::new_v4().to_string(), &serde_json::to_string(policy)?],
    ).await?;
    anyhow::ensure!(count == 1, "HTTP route disappeared during mutation");
    Ok(())
}

// 调用方必须先取得 CERTIFICATE_STATE_LOCK；证书结果提交在同一事务中使用该快照。
pub(crate) async fn transaction_snapshot(
    transaction: &Transaction<'_>,
    id: Uuid,
) -> anyhow::Result<Option<HttpRouteSnapshot>> {
    transaction.query_opt(
        "SELECT id,hostname,revision,policy::text FROM linklake_http_route_policies WHERE id=$1 FOR UPDATE", &[&id.to_string()],
    ).await?.as_ref().map(read_snapshot).transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> HttpRoutePolicy {
        requested_policy(
            Uuid::new_v4(),
            true,
            CreateHttpRoutePolicy {
                client_id: Uuid::new_v4(),
                name: "site".to_owned(),
                hostname: "site.example.com".to_owned(),
                target_addr: "127.0.0.1:8080".to_owned(),
                max_connections: Some(64),
                grpc_backend_transport: GrpcBackendTransport::H2c,
                grpc_backend_server_name: None,
                grpc_backend_trust_profile: None,
            },
        )
        .unwrap()
    }

    #[test]
    fn shared_snapshot_rejects_identity_and_revision_corruption() {
        let policy = policy();
        let json = serde_json::to_string(&policy).unwrap();
        let revision = Uuid::new_v4();
        let snapshot = decode_snapshot(
            &policy.id.to_string(),
            &policy.hostname,
            &revision.to_string(),
            &json,
        )
        .unwrap();
        assert!(snapshot.policy == policy);
        assert_eq!(snapshot.revision, revision);
        assert!(decode_snapshot(
            &Uuid::new_v4().to_string(),
            &policy.hostname,
            &revision.to_string(),
            &json
        )
        .is_err());
        assert!(decode_snapshot(
            &policy.id.to_string(),
            "other.example.com",
            &revision.to_string(),
            &json
        )
        .is_err());
        assert!(decode_snapshot(
            &policy.id.to_string(),
            &policy.hostname,
            "invalid-revision",
            &json
        )
        .is_err());
    }

    #[test]
    fn shared_snapshot_revalidates_runtime_authorization_fields() {
        let policy = policy();
        let revision = Uuid::new_v4().to_string();
        let original = serde_json::to_value(&policy).unwrap();
        for (field, value) in [
            ("max_connections", serde_json::json!(0)),
            ("target_addr", serde_json::json!("not-a-target")),
            ("name", serde_json::json!(" site ")),
            ("grpc_backend_transport", serde_json::json!("tls")),
            ("enabled", serde_json::json!("true")),
            ("unknown_policy_field", serde_json::json!(true)),
        ] {
            let mut corrupted = original.clone();
            corrupted[field] = value;
            assert!(
                decode_snapshot(
                    &policy.id.to_string(),
                    &policy.hostname,
                    &revision,
                    &corrupted.to_string()
                )
                .is_err(),
                "accepted invalid {field}"
            );
        }
    }
}
