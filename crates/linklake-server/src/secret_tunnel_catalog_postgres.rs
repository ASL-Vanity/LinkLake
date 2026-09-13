//! Secret 共享目录。密钥仅在创建响应中返回，数据库保存独立哈希列。

use super::*;
use crate::{
    ha_runtime::HaRuntime,
    policy_service::{postgres::FleetPolicyTransaction, FleetPolicyKind},
    storage::CoordinationStorage,
};
use std::sync::Arc;
use tokio_postgres::{Row, Transaction};

pub(crate) struct PostgresSecretTunnelCatalog {
    pub(crate) storage: CoordinationStorage,
    pub(crate) runtime: Arc<HaRuntime>,
}

// 不派生 Debug/Serialize，避免查询凭据时把哈希放入日志或管理响应。
pub(crate) struct SecretTunnelSnapshot {
    pub(crate) policy: SecretTunnelPolicy,
    pub(crate) access_key_hash: String,
}

fn storage_error(error: impl Into<anyhow::Error>) -> SecretPolicyError {
    SecretPolicyError::Storage(error.into())
}

fn read_snapshot(row: &Row) -> anyhow::Result<SecretTunnelSnapshot> {
    decode_snapshot(
        row.try_get("id")?,
        row.try_get("provider_client_id")?,
        row.try_get("name")?,
        row.try_get("access_key_hash")?,
        row.try_get("policy")?,
    )
}

fn decode_snapshot(
    id: &str,
    provider: &str,
    name: &str,
    access_key_hash: &str,
    json: &str,
) -> anyhow::Result<SecretTunnelSnapshot> {
    let policy: SecretTunnelPolicy = serde_json::from_str(json)?;
    anyhow::ensure!(
        serde_json::from_str::<serde_json::Value>(json)? == serde_json::to_value(&policy)?,
        "Stored policy fields are not canonical"
    );
    anyhow::ensure!(
        policy.id == Uuid::parse_str(id)?
            && policy.provider_client_id == Uuid::parse_str(provider)?
            && policy.name == name,
        "Secret tunnel row identity mismatch"
    );
    validate_stored_policy(&policy)?;
    anyhow::ensure!(
        valid_hash(access_key_hash),
        "Invalid Secret tunnel credential hash"
    );
    Ok(SecretTunnelSnapshot {
        policy,
        access_key_hash: access_key_hash.to_owned(),
    })
}

pub(crate) fn validate_stored_policy(policy: &SecretTunnelPolicy) -> anyhow::Result<()> {
    let canonical = requested_policy(
        policy.id,
        policy.enabled,
        CreateSecretTunnelPolicy {
            provider_client_id: policy.provider_client_id,
            allowed_client_id: policy.allowed_client_id,
            name: policy.name.clone(),
            target_addr: policy.target_addr.clone(),
            max_connections: Some(policy.max_connections),
            bandwidth_limit_bps: policy.bandwidth_limit_bps,
        },
    )?;
    anyhow::ensure!(canonical == *policy, "Secret tunnel row is not canonical");
    Ok(())
}

fn valid_hash(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|value| value.is_ascii_digit() || (b'a'..=b'f').contains(&value))
}

fn runtime_policy(policy: SecretTunnelPolicy) -> SecretTunnelRuntimePolicy {
    SecretTunnelRuntimePolicy {
        policy_id: policy.id,
        provider_client_id: policy.provider_client_id,
        target_addr: policy.target_addr,
        max_connections: usize::from(policy.max_connections),
        bandwidth_limit_bps: policy.bandwidth_limit_bps,
    }
}

impl PostgresSecretTunnelCatalog {
    pub(crate) async fn list(&self) -> Result<Vec<SecretTunnelPolicy>, SecretPolicyError> {
        async {
            self.storage.postgres_client().await?.query(
                "SELECT id,provider_client_id,name,access_key_hash,policy::text FROM linklake_secret_tunnel_policies ORDER BY name,id", &[],
            ).await?.iter().map(|row| Ok(read_snapshot(row)?.policy)).collect::<anyhow::Result<Vec<_>>>()
        }.await.map_err(storage_error)
    }

    pub(crate) async fn policy_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<SecretTunnelPolicy>, SecretPolicyError> {
        async {
            self.storage.postgres_client().await?.query_opt(
                "SELECT id,provider_client_id,name,access_key_hash,policy::text FROM linklake_secret_tunnel_policies WHERE id=$1", &[&id.to_string()],
            ).await?.as_ref().map(|row| Ok(read_snapshot(row)?.policy)).transpose()
        }.await.map_err(|error: anyhow::Error| storage_error(error))
    }

    pub(crate) async fn create(
        &self,
        request: CreateSecretTunnelPolicy,
    ) -> Result<CreatedSecretTunnelPolicy, SecretPolicyError> {
        let policy = requested_policy(Uuid::new_v4(), true, request)?;
        let access_key = format!("lls_{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let mut client = self
            .storage
            .postgres_client()
            .await
            .map_err(storage_error)?;
        let transaction = client.transaction().await.map_err(storage_error)?;
        let guard = FleetPolicyTransaction::lock(&transaction, &self.runtime)
            .await
            .map_err(storage_error)?;
        ensure_unmanaged(&guard, policy.id).await?;
        ensure_name_available(&transaction, &policy).await?;
        transaction_insert(&guard, &policy, &hash_access_key(&access_key))
            .await
            .map_err(storage_error)?;
        guard.assert_current().await.map_err(storage_error)?;
        transaction.commit().await.map_err(storage_error)?;
        Ok(CreatedSecretTunnelPolicy { policy, access_key })
    }

    pub(crate) async fn update(
        &self,
        id: Uuid,
        request: UpdateSecretTunnelPolicy,
    ) -> Result<Option<SecretTunnelPolicy>, SecretPolicyError> {
        let mut policy = requested_policy(id, true, request)?;
        let mut client = self
            .storage
            .postgres_client()
            .await
            .map_err(storage_error)?;
        let transaction = client.transaction().await.map_err(storage_error)?;
        let guard = FleetPolicyTransaction::lock(&transaction, &self.runtime)
            .await
            .map_err(storage_error)?;
        ensure_unmanaged(&guard, id).await?;
        let Some(current) = transaction_snapshot(&guard, id)
            .await
            .map_err(storage_error)?
        else {
            guard.assert_current().await.map_err(storage_error)?;
            transaction.commit().await.map_err(storage_error)?;
            return Ok(None);
        };
        policy.enabled = current.policy.enabled;
        ensure_name_available(&transaction, &policy).await?;
        transaction_update(&guard, &policy)
            .await
            .map_err(storage_error)?;
        guard.assert_current().await.map_err(storage_error)?;
        transaction.commit().await.map_err(storage_error)?;
        Ok(Some(policy))
    }

    pub(crate) async fn set_enabled(
        &self,
        id: Uuid,
        enabled: bool,
    ) -> Result<bool, SecretPolicyError> {
        let mut client = self
            .storage
            .postgres_client()
            .await
            .map_err(storage_error)?;
        let transaction = client.transaction().await.map_err(storage_error)?;
        let guard = FleetPolicyTransaction::lock(&transaction, &self.runtime)
            .await
            .map_err(storage_error)?;
        ensure_unmanaged(&guard, id).await?;
        let found = if let Some(mut current) = transaction_snapshot(&guard, id)
            .await
            .map_err(storage_error)?
        {
            current.policy.enabled = enabled;
            transaction_update(&guard, &current.policy)
                .await
                .map_err(storage_error)?;
            true
        } else {
            false
        };
        guard.assert_current().await.map_err(storage_error)?;
        transaction.commit().await.map_err(storage_error)?;
        Ok(found)
    }

    pub(crate) async fn delete(
        &self,
        id: Uuid,
    ) -> Result<Option<SecretTunnelPolicy>, SecretPolicyError> {
        let mut client = self
            .storage
            .postgres_client()
            .await
            .map_err(storage_error)?;
        let transaction = client.transaction().await.map_err(storage_error)?;
        let guard = FleetPolicyTransaction::lock(&transaction, &self.runtime)
            .await
            .map_err(storage_error)?;
        ensure_unmanaged(&guard, id).await?;
        let policy = transaction_snapshot(&guard, id)
            .await
            .map_err(storage_error)?
            .map(|value| value.policy);
        if policy.is_some() {
            transaction_delete(&guard, id)
                .await
                .map_err(storage_error)?;
        }
        guard.assert_current().await.map_err(storage_error)?;
        transaction.commit().await.map_err(storage_error)?;
        Ok(policy)
    }

    pub(crate) async fn provider_runtime_policy(
        &self,
        provider_client_id: Uuid,
        name: &str,
        target_addr: &str,
    ) -> Result<Option<SecretTunnelRuntimePolicy>, SecretPolicyError> {
        let result: anyhow::Result<_> = async {
            let row = self.storage.postgres_client().await?.query_opt(
                "SELECT id,provider_client_id,name,access_key_hash,policy::text FROM linklake_secret_tunnel_policies WHERE provider_client_id=$1 AND name=$2", &[&provider_client_id.to_string(), &name],
            ).await?;
            let Some(snapshot) = row.as_ref().map(read_snapshot).transpose()? else { return Ok(None); };
            Ok(authorize_provider(snapshot.policy, provider_client_id, name, target_addr))
        }.await;
        result.map_err(storage_error)
    }

    pub(crate) async fn access_runtime_policy(
        &self,
        visitor_client_id: Uuid,
        access_key: &str,
    ) -> Result<Option<SecretTunnelRuntimePolicy>, SecretPolicyError> {
        if !valid_access_key(access_key) {
            return Ok(None);
        }
        let hash = hash_access_key(access_key);
        let result: anyhow::Result<_> = async {
            let row = self.storage.postgres_client().await?.query_opt(
                "SELECT id,provider_client_id,name,access_key_hash,policy::text FROM linklake_secret_tunnel_policies WHERE access_key_hash=$1", &[&hash],
            ).await?;
            let Some(snapshot) = row.as_ref().map(read_snapshot).transpose()? else { return Ok(None); };
            anyhow::ensure!(snapshot.access_key_hash == hash, "Secret tunnel credential identity mismatch");
            Ok(authorize_visitor(snapshot.policy, visitor_client_id))
        }.await;
        result.map_err(storage_error)
    }
}

fn authorize_provider(
    policy: SecretTunnelPolicy,
    provider: Uuid,
    name: &str,
    target: &str,
) -> Option<SecretTunnelRuntimePolicy> {
    (policy.enabled
        && policy.provider_client_id == provider
        && policy.name == name
        && policy.target_addr == target)
        .then(|| runtime_policy(policy))
}

fn authorize_visitor(
    policy: SecretTunnelPolicy,
    visitor: Uuid,
) -> Option<SecretTunnelRuntimePolicy> {
    (policy.enabled
        && policy
            .allowed_client_id
            .is_none_or(|allowed| allowed == visitor))
    .then(|| runtime_policy(policy))
}

async fn ensure_unmanaged(
    guard: &FleetPolicyTransaction<'_, '_>,
    id: Uuid,
) -> Result<(), SecretPolicyError> {
    if guard
        .is_policy_managed(FleetPolicyKind::SecretTunnel, id)
        .await
        .map_err(storage_error)?
    {
        return Err(SecretPolicyError::ManagedPolicy);
    }
    Ok(())
}

pub(crate) async fn ensure_name_available(
    transaction: &Transaction<'_>,
    policy: &SecretTunnelPolicy,
) -> Result<(), SecretPolicyError> {
    if transaction.query_opt("SELECT id FROM linklake_secret_tunnel_policies WHERE provider_client_id=$1 AND name=$2 AND id<>$3", &[&policy.provider_client_id.to_string(), &policy.name, &policy.id.to_string()]).await.map_err(storage_error)?.is_some() {
        return Err(SecretPolicyError::DuplicateName);
    }
    Ok(())
}

// 内部 Fleet/迁移接口：调用方必须持有 FleetPolicyTransaction，并在提交前再次 assert_current。
pub(crate) async fn transaction_snapshot(
    guard: &FleetPolicyTransaction<'_, '_>,
    id: Uuid,
) -> anyhow::Result<Option<SecretTunnelSnapshot>> {
    guard.assert_current().await?;
    let transaction = guard.transaction();
    transaction.query_opt("SELECT id,provider_client_id,name,access_key_hash,policy::text FROM linklake_secret_tunnel_policies WHERE id=$1 FOR UPDATE", &[&id.to_string()]).await?.as_ref().map(read_snapshot).transpose()
}

pub(crate) async fn transaction_list(
    guard: &FleetPolicyTransaction<'_, '_>,
) -> anyhow::Result<Vec<SecretTunnelPolicy>> {
    guard.assert_current().await?;
    let transaction = guard.transaction();
    transaction.query("SELECT id,provider_client_id,name,access_key_hash,policy::text FROM linklake_secret_tunnel_policies ORDER BY name,id", &[]).await?.iter().map(|row| Ok(read_snapshot(row)?.policy)).collect()
}

pub(crate) async fn transaction_insert(
    guard: &FleetPolicyTransaction<'_, '_>,
    policy: &SecretTunnelPolicy,
    access_key_hash: &str,
) -> anyhow::Result<()> {
    guard.assert_current().await?;
    let transaction = guard.transaction();
    validate_stored_policy(policy)?;
    anyhow::ensure!(
        valid_hash(access_key_hash),
        "Invalid Secret tunnel credential hash"
    );
    transaction.execute("INSERT INTO linklake_secret_tunnel_policies(id,provider_client_id,name,access_key_hash,policy) VALUES($1,$2,$3,$4,$5::text::jsonb)", &[&policy.id.to_string(), &policy.provider_client_id.to_string(), &policy.name, &access_key_hash, &serde_json::to_string(policy)?]).await?;
    Ok(())
}

// 更新永不替换凭据哈希；Fleet 引用现有凭据时也使用该入口。
pub(crate) async fn transaction_update(
    guard: &FleetPolicyTransaction<'_, '_>,
    policy: &SecretTunnelPolicy,
) -> anyhow::Result<()> {
    guard.assert_current().await?;
    let transaction = guard.transaction();
    validate_stored_policy(policy)?;
    let count = transaction.execute("UPDATE linklake_secret_tunnel_policies SET provider_client_id=$2,name=$3,policy=$4::text::jsonb WHERE id=$1", &[&policy.id.to_string(), &policy.provider_client_id.to_string(), &policy.name, &serde_json::to_string(policy)?]).await?;
    anyhow::ensure!(count == 1, "Secret tunnel disappeared during mutation");
    Ok(())
}

pub(crate) async fn transaction_delete(
    guard: &FleetPolicyTransaction<'_, '_>,
    id: Uuid,
) -> anyhow::Result<bool> {
    guard.assert_current().await?;
    let transaction = guard.transaction();
    Ok(transaction
        .execute(
            "DELETE FROM linklake_secret_tunnel_policies WHERE id=$1",
            &[&id.to_string()],
        )
        .await?
        != 0)
}

// 凭据引用更新必须保留本地已经绑定的哈希；迁移或原子交换插入需显式提供原哈希。
pub(crate) async fn transaction_put(
    guard: &FleetPolicyTransaction<'_, '_>,
    policy: &SecretTunnelPolicy,
    access_key_hash: &str,
) -> anyhow::Result<()> {
    guard.assert_current().await?;
    anyhow::ensure!(
        valid_hash(access_key_hash),
        "Invalid Secret tunnel credential hash"
    );
    ensure_name_available(guard.transaction(), policy).await?;
    match transaction_snapshot(guard, policy.id).await? {
        Some(current) => {
            anyhow::ensure!(
                current.access_key_hash == access_key_hash,
                "Secret tunnel credential replacement is not allowed"
            );
            transaction_update(guard, policy).await
        }
        None => transaction_insert(guard, policy, access_key_hash).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> SecretTunnelPolicy {
        requested_policy(
            Uuid::new_v4(),
            true,
            CreateSecretTunnelPolicy {
                provider_client_id: Uuid::new_v4(),
                allowed_client_id: Some(Uuid::new_v4()),
                name: "private-rdp".into(),
                target_addr: "127.0.0.1:3389".into(),
                max_connections: Some(4),
                bandwidth_limit_bps: Some(4096),
            },
        )
        .unwrap()
    }

    #[test]
    fn shared_rows_reject_corrupt_identity_limits_and_hashes() {
        let original = policy();
        let hash = "a".repeat(64);
        let decode = |policy: &SecretTunnelPolicy, id: Uuid, hash: &str| {
            decode_snapshot(
                &id.to_string(),
                &original.provider_client_id.to_string(),
                &original.name,
                hash,
                &serde_json::to_string(policy).unwrap(),
            )
        };
        assert!(decode(&original, original.id, &hash).is_ok());
        assert!(decode(&original, Uuid::new_v4(), &hash).is_err());
        assert!(decode(&original, original.id, &"A".repeat(64)).is_err());
        assert!(decode(&original, original.id, "plaintext-key").is_err());
        let mut damaged = original.clone();
        damaged.max_connections = 0;
        assert!(decode(&damaged, original.id, &hash).is_err());
        damaged = original.clone();
        damaged.bandwidth_limit_bps = Some(u64::MAX);
        assert!(decode(&damaged, original.id, &hash).is_err());
        damaged = original.clone();
        damaged.name.push(' ');
        assert!(decode(&damaged, original.id, &hash).is_err());
        let mut payload = serde_json::to_value(&original).unwrap();
        payload["access_key"] = serde_json::json!("secret");
        assert!(decode_snapshot(
            &original.id.to_string(),
            &original.provider_client_id.to_string(),
            &original.name,
            &hash,
            &payload.to_string()
        )
        .is_err());
    }

    #[test]
    fn missing_visitor_constraint_is_rejected_instead_of_defaulting_to_unrestricted() {
        let policy = policy();
        let mut json = serde_json::to_value(&policy).unwrap();
        json.as_object_mut().unwrap().remove("allowed_client_id");
        assert!(decode_snapshot(
            &policy.id.to_string(),
            &policy.provider_client_id.to_string(),
            &policy.name,
            &"a".repeat(64),
            &json.to_string()
        )
        .is_err());
    }

    #[test]
    fn runtime_authorization_preserves_provider_target_visitor_and_enabled_constraints() {
        let policy = policy();
        let allowed = policy.allowed_client_id.unwrap();
        assert!(authorize_provider(
            policy.clone(),
            policy.provider_client_id,
            &policy.name,
            &policy.target_addr
        )
        .is_some());
        assert!(authorize_provider(
            policy.clone(),
            Uuid::new_v4(),
            &policy.name,
            &policy.target_addr
        )
        .is_none());
        assert!(authorize_provider(
            policy.clone(),
            policy.provider_client_id,
            "other",
            &policy.target_addr
        )
        .is_none());
        assert!(authorize_provider(
            policy.clone(),
            policy.provider_client_id,
            &policy.name,
            "127.0.0.1:3390"
        )
        .is_none());
        assert!(authorize_visitor(policy.clone(), allowed).is_some());
        assert!(authorize_visitor(policy.clone(), Uuid::new_v4()).is_none());
        let mut disabled = policy.clone();
        disabled.enabled = false;
        assert!(authorize_visitor(disabled.clone(), allowed).is_none());
        assert!(authorize_provider(
            disabled,
            policy.provider_client_id,
            &policy.name,
            &policy.target_addr
        )
        .is_none());
        let mut unrestricted = policy;
        unrestricted.allowed_client_id = None;
        assert!(authorize_visitor(unrestricted, Uuid::new_v4()).is_some());
    }

    #[test]
    fn shared_errors_keep_storage_details_out_of_public_codes() {
        assert_eq!(
            SecretPolicyError::ManagedPolicy.code(),
            "fleet_managed_policy"
        );
        assert_eq!(
            storage_error(anyhow::anyhow!("private database details")).to_string(),
            "secret_policy_storage_error"
        );
    }
}
