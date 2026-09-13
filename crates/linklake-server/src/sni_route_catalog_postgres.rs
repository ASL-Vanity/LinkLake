//! SNI 共享目录；公开写入受 Leader 和 Fleet 归属保护。

use super::*;
use crate::{
    ha_runtime::HaRuntime,
    policy_service::{postgres::FleetPolicyTransaction, FleetPolicyKind},
    storage::CoordinationStorage,
};
use std::sync::Arc;
use tokio_postgres::{Row, Transaction};

pub(crate) struct PostgresSniRouteCatalog {
    pub(crate) storage: CoordinationStorage,
    pub(crate) runtime: Arc<HaRuntime>,
}

pub(crate) fn decode_policy(
    id: &str,
    hostname: &str,
    json: &str,
) -> anyhow::Result<SniRoutePolicy> {
    let policy: SniRoutePolicy = serde_json::from_str(json)?;
    anyhow::ensure!(
        serde_json::from_str::<serde_json::Value>(json)? == serde_json::to_value(&policy)?,
        "Stored policy fields are not canonical"
    );
    anyhow::ensure!(
        policy.id == Uuid::parse_str(id)? && policy.hostname == hostname,
        "SNI route row identity mismatch"
    );
    let canonical = requested_policy(
        policy.id,
        policy.enabled,
        CreateSniRoutePolicy {
            client_id: policy.client_id,
            name: policy.name.clone(),
            hostname: policy.hostname.clone(),
            target_addr: policy.target_addr.clone(),
            max_connections: Some(policy.max_connections),
            bandwidth_limit_bps: policy.bandwidth_limit_bps,
        },
    )?;
    anyhow::ensure!(canonical == policy, "SNI route row is not canonical");
    Ok(policy)
}

fn read_policy(row: &Row) -> anyhow::Result<SniRoutePolicy> {
    decode_policy(
        row.try_get("id")?,
        row.try_get("hostname")?,
        row.try_get("policy")?,
    )
}

impl PostgresSniRouteCatalog {
    pub(crate) async fn list(&self) -> anyhow::Result<Vec<SniRoutePolicy>> {
        self.storage.postgres_client().await?.query("SELECT id,hostname,policy::text FROM linklake_sni_route_policies ORDER BY hostname", &[]).await?.iter().map(read_policy).collect()
    }

    pub(crate) async fn policy_by_id(&self, id: Uuid) -> anyhow::Result<Option<SniRoutePolicy>> {
        self.storage
            .postgres_client()
            .await?
            .query_opt(
                "SELECT id,hostname,policy::text FROM linklake_sni_route_policies WHERE id=$1",
                &[&id.to_string()],
            )
            .await?
            .as_ref()
            .map(read_policy)
            .transpose()
    }

    pub(crate) async fn create(
        &self,
        request: CreateSniRoutePolicy,
    ) -> anyhow::Result<SniRoutePolicy> {
        let policy = requested_policy(Uuid::new_v4(), true, request)?;
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        let ledger = FleetPolicyTransaction::lock(&transaction, &self.runtime).await?;
        ensure_unmanaged(&ledger, policy.id).await?;
        ensure_hostname_available(&transaction, &policy).await?;
        transaction.execute("INSERT INTO linklake_sni_route_policies(id,hostname,revision,policy) VALUES($1,$2,$3,$4::text::jsonb)",
            &[&policy.id.to_string(), &policy.hostname, &Uuid::new_v4().to_string(), &serde_json::to_string(&policy)?]).await?;
        ledger.assert_current().await?;
        transaction.commit().await?;
        Ok(policy)
    }

    pub(crate) async fn update(
        &self,
        id: Uuid,
        request: UpdateSniRoutePolicy,
    ) -> anyhow::Result<Option<SniRoutePolicy>> {
        let mut policy = requested_policy(id, true, request)?;
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        let ledger = FleetPolicyTransaction::lock(&transaction, &self.runtime).await?;
        ensure_unmanaged(&ledger, id).await?;
        let Some(current) = transaction_policy(&transaction, id).await? else {
            return Ok(None);
        };
        policy.enabled = current.enabled;
        ensure_hostname_available(&transaction, &policy).await?;
        write_policy(&transaction, &policy).await?;
        ledger.assert_current().await?;
        transaction.commit().await?;
        Ok(Some(policy))
    }

    pub(crate) async fn set_enabled(&self, id: Uuid, enabled: bool) -> anyhow::Result<bool> {
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        let ledger = FleetPolicyTransaction::lock(&transaction, &self.runtime).await?;
        ensure_unmanaged(&ledger, id).await?;
        let Some(mut policy) = transaction_policy(&transaction, id).await? else {
            return Ok(false);
        };
        policy.enabled = enabled;
        write_policy(&transaction, &policy).await?;
        ledger.assert_current().await?;
        transaction.commit().await?;
        Ok(true)
    }

    pub(crate) async fn delete(&self, id: Uuid) -> anyhow::Result<Option<SniRoutePolicy>> {
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        let ledger = FleetPolicyTransaction::lock(&transaction, &self.runtime).await?;
        ensure_unmanaged(&ledger, id).await?;
        let policy = transaction_policy(&transaction, id).await?;
        if policy.is_some() {
            transaction
                .execute(
                    "DELETE FROM linklake_sni_route_policies WHERE id=$1",
                    &[&id.to_string()],
                )
                .await?;
        }
        ledger.assert_current().await?;
        transaction.commit().await?;
        Ok(policy)
    }

    pub(crate) async fn runtime_policy(
        &self,
        client_id: Uuid,
        name: &str,
        hostname: &str,
        target_addr: &str,
    ) -> anyhow::Result<Option<SniRouteRuntimePolicy>> {
        let hostname =
            normalize_hostname(hostname).map_err(|_| SniRoutePolicyError::InvalidHostname)?;
        let row = self.storage.postgres_client().await?.query_opt("SELECT id,hostname,policy::text FROM linklake_sni_route_policies WHERE hostname=$1", &[&hostname]).await?;
        let Some(policy) = row.as_ref().map(read_policy).transpose()? else {
            return Ok(None);
        };
        if !policy.enabled
            || policy.client_id != client_id
            || policy.name != name
            || policy.target_addr != target_addr
        {
            return Ok(None);
        }
        Ok(Some(SniRouteRuntimePolicy {
            policy_id: policy.id,
            max_connections: usize::from(policy.max_connections),
            bandwidth_limit_bps: policy.bandwidth_limit_bps,
        }))
    }
}

pub(crate) async fn transaction_list(
    transaction: &Transaction<'_>,
) -> anyhow::Result<Vec<SniRoutePolicy>> {
    transaction
        .query(
            "SELECT id,hostname,policy::text FROM linklake_sni_route_policies ORDER BY hostname",
            &[],
        )
        .await?
        .iter()
        .map(read_policy)
        .collect()
}

pub(crate) async fn transaction_put(
    ledger: &FleetPolicyTransaction<'_, '_>,
    policy: &SniRoutePolicy,
) -> anyhow::Result<()> {
    ledger.assert_current().await?;
    let json = serde_json::to_string(policy)?;
    decode_policy(&policy.id.to_string(), &policy.hostname, &json)?;
    ledger.transaction().execute(
        "INSERT INTO linklake_sni_route_policies(id,hostname,revision,policy) VALUES($1,$2,$3,$4::text::jsonb)
         ON CONFLICT(id) DO UPDATE SET hostname=EXCLUDED.hostname,revision=EXCLUDED.revision,policy=EXCLUDED.policy",
        &[&policy.id.to_string(), &policy.hostname, &Uuid::new_v4().to_string(), &json],
    ).await?;
    Ok(())
}

pub(crate) async fn transaction_delete(
    ledger: &FleetPolicyTransaction<'_, '_>,
    id: Uuid,
) -> anyhow::Result<Option<SniRoutePolicy>> {
    ledger.assert_current().await?;
    let policy = transaction_policy(ledger.transaction(), id).await?;
    ledger
        .transaction()
        .execute(
            "DELETE FROM linklake_sni_route_policies WHERE id=$1",
            &[&id.to_string()],
        )
        .await?;
    Ok(policy)
}

async fn ensure_unmanaged(ledger: &FleetPolicyTransaction<'_, '_>, id: Uuid) -> anyhow::Result<()> {
    if ledger
        .is_policy_managed(FleetPolicyKind::SniRoute, id)
        .await?
    {
        return Err(SniRoutePolicyError::ManagedPolicy.into());
    }
    Ok(())
}

async fn ensure_hostname_available(
    transaction: &Transaction<'_>,
    policy: &SniRoutePolicy,
) -> anyhow::Result<()> {
    if transaction
        .query_opt(
            "SELECT id FROM linklake_sni_route_policies WHERE hostname=$1 AND id<>$2",
            &[&policy.hostname, &policy.id.to_string()],
        )
        .await?
        .is_some()
    {
        return Err(SniRoutePolicyError::DuplicateHostname.into());
    }
    Ok(())
}

// 调用方持有共享目录事务锁后使用；Fleet reconcile 复用同一表。
pub(crate) async fn transaction_policy(
    transaction: &Transaction<'_>,
    id: Uuid,
) -> anyhow::Result<Option<SniRoutePolicy>> {
    transaction.query_opt("SELECT id,hostname,policy::text FROM linklake_sni_route_policies WHERE id=$1 FOR UPDATE", &[&id.to_string()]).await?.as_ref().map(read_policy).transpose()
}

async fn write_policy(
    transaction: &Transaction<'_>,
    policy: &SniRoutePolicy,
) -> anyhow::Result<()> {
    let changed = transaction.execute("UPDATE linklake_sni_route_policies SET hostname=$2,revision=$3,policy=$4::text::jsonb WHERE id=$1",
        &[&policy.id.to_string(), &policy.hostname, &Uuid::new_v4().to_string(), &serde_json::to_string(policy)?]).await?;
    anyhow::ensure!(changed == 1, "SNI route disappeared during mutation");
    Ok(())
}
