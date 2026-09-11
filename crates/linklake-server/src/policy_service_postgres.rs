//! Fleet 共享账本。借用调用方事务，使业务策略、归属、代际一起提交或回滚。

use super::*;
use crate::{
    certificate_catalog::postgres::CERTIFICATE_STATE_LOCK, ha_runtime::HaRuntime,
    storage::CoordinationStorage,
};
use tokio_postgres::{Row, Transaction as PgTransaction};

pub(crate) struct FleetPolicyTransaction<'tx, 'connection> {
    transaction: &'tx PgTransaction<'connection>,
    runtime: &'tx HaRuntime,
    fencing_token: u64,
}

impl<'tx, 'connection> FleetPolicyTransaction<'tx, 'connection> {
    pub(crate) async fn lock(
        transaction: &'tx PgTransaction<'connection>,
        runtime: &'tx HaRuntime,
    ) -> anyhow::Result<Self> {
        // 与 HTTP 路由、证书使用相同锁；后续其他业务目录也必须参与该写入边界。
        transaction
            .query_one(
                "SELECT pg_advisory_xact_lock($1)",
                &[&CERTIFICATE_STATE_LOCK],
            )
            .await?;
        let current = Self {
            transaction,
            runtime,
            fencing_token: runtime.fencing_token()?,
        };
        current.assert_current().await?;
        Ok(current)
    }

    pub(crate) async fn assert_current(&self) -> anyhow::Result<()> {
        self.runtime
            .coordinator()
            .assert_postgres_transaction_fence(self.transaction, self.fencing_token)
            .await?;
        Ok(())
    }

    pub(crate) async fn local_instance_id(&self) -> anyhow::Result<Uuid> {
        self.assert_current().await?;
        self.transaction.execute(
            "INSERT INTO linklake_fleet_local_state(singleton_id,source_instance_id,generation) VALUES(1,$1,0) ON CONFLICT(singleton_id) DO NOTHING",
            &[&Uuid::new_v4().to_string()],
        ).await?;
        let row = self
            .transaction
            .query_one(
                "SELECT source_instance_id FROM linklake_fleet_local_state WHERE singleton_id=1",
                &[],
            )
            .await?;
        stored_id(row.try_get(0)?)
    }

    pub(crate) async fn reserve_generation(&self) -> anyhow::Result<(Uuid, u64)> {
        let id = self.local_instance_id().await?;
        let row = self.transaction.query_opt(
            "UPDATE linklake_fleet_local_state SET generation=generation+1 WHERE singleton_id=1 AND generation<9223372036854775807 RETURNING generation", &[],
        ).await?.ok_or_else(|| anyhow::anyhow!("Fleet generation is exhausted"))?;
        Ok((id, u64::try_from(row.try_get::<_, i64>(0)?)?))
    }

    pub(crate) async fn source_status(
        &self,
        source: Uuid,
    ) -> anyhow::Result<Option<FleetSourceStatus>> {
        self.transaction.query_opt(
            "SELECT source_instance_id,generation,revision,applied_unix_seconds,resource_count FROM linklake_fleet_source_states WHERE source_instance_id=$1 FOR UPDATE",
            &[&source.to_string()],
        ).await?.as_ref().map(read_source).transpose()
    }

    pub(crate) async fn check_precondition(
        &self,
        request: &FleetReconcileRequest,
    ) -> anyhow::Result<(Option<FleetSourceStatus>, bool)> {
        request.bundle.validate()?;
        let current = self
            .source_status(request.bundle.source_instance_id)
            .await?;
        let replay = validate_reconcile_precondition(request, current.as_ref())?;
        Ok((current, replay))
    }

    pub(super) async fn owned_resources(
        &self,
        source: Uuid,
    ) -> anyhow::Result<HashMap<Uuid, OwnedResource>> {
        self.transaction.query(
            "SELECT source_instance_id,resource_id,kind,policy_id,resource_sha256,credential_ref FROM linklake_fleet_resource_ownership WHERE source_instance_id=$1 FOR UPDATE",
            &[&source.to_string()],
        ).await?.iter().map(|row| {
            let resource = read_owned(row)?;
            Ok((resource.resource_id, resource))
        }).collect()
    }

    pub(crate) async fn credential_binding_policy(
        &self,
        source: Uuid,
        credential: Uuid,
        kind: FleetPolicyKind,
    ) -> anyhow::Result<Option<Uuid>> {
        self.transaction.query_opt(
            "SELECT policy_id FROM linklake_fleet_credential_bindings WHERE source_instance_id=$1 AND credential_ref=$2 AND kind=$3 FOR UPDATE",
            &[&source.to_string(), &credential.to_string(), &kind.as_str()],
        ).await?.map(|row| stored_id(row.try_get(0)?)).transpose()
    }

    pub(crate) async fn is_policy_managed(
        &self,
        kind: FleetPolicyKind,
        policy: Uuid,
    ) -> anyhow::Result<bool> {
        Ok(self.transaction.query_one(
            "SELECT EXISTS(SELECT 1 FROM linklake_fleet_resource_ownership WHERE kind=$1 AND policy_id=$2)",
            &[&kind.as_str(), &policy.to_string()],
        ).await?.try_get(0)?)
    }

    pub(super) async fn record_ownership(&self, resource: &OwnedResource) -> anyhow::Result<()> {
        self.assert_current().await?;
        anyhow::ensure!(
            !resource.source_instance_id.is_nil()
                && !resource.resource_id.is_nil()
                && !resource.policy_id.is_nil(),
            "Fleet ownership contains a nil ID"
        );
        anyhow::ensure!(
            resource.kind.requires_credential() == resource.credential_ref.is_some(),
            "Fleet ownership credential kind mismatch"
        );
        if let Some(credential) = resource.credential_ref {
            anyhow::ensure!(
                self.credential_binding_policy(
                    resource.source_instance_id,
                    credential,
                    resource.kind
                )
                .await?
                    == Some(resource.policy_id),
                "Fleet credential binding was revoked or changed"
            );
        } else {
            anyhow::ensure!(
                resource.policy_id
                    == deterministic_policy_id(
                        resource.source_instance_id,
                        resource.resource_id,
                        resource.kind
                    ),
                "Fleet derived policy identity mismatch"
            );
        }
        let previous = self.transaction.query_opt(
            "SELECT source_instance_id,resource_id,kind,policy_id,resource_sha256,credential_ref FROM linklake_fleet_resource_ownership WHERE source_instance_id=$1 AND resource_id=$2 FOR UPDATE",
            &[&resource.source_instance_id.to_string(), &resource.resource_id.to_string()],
        ).await?.as_ref().map(read_owned).transpose()?;
        if let Some(previous) = previous {
            anyhow::ensure!(
                previous.kind == resource.kind
                    && previous.policy_id == resource.policy_id
                    && previous.credential_ref == resource.credential_ref,
                "Fleet resource identity cannot change"
            );
        }
        self.transaction.execute(
            "INSERT INTO linklake_fleet_resource_ownership(source_instance_id,resource_id,kind,policy_id,resource_sha256,credential_ref) VALUES($1,$2,$3,$4,$5,$6)
             ON CONFLICT(source_instance_id,resource_id) DO UPDATE SET resource_sha256=EXCLUDED.resource_sha256",
            &[&resource.source_instance_id.to_string(), &resource.resource_id.to_string(), &resource.kind.as_str(), &resource.policy_id.to_string(), &resource.resource_sha256, &resource.credential_ref.map(|value| value.to_string())],
        ).await?;
        Ok(())
    }

    pub(super) async fn release_ownership(&self, resource: &OwnedResource) -> anyhow::Result<()> {
        self.assert_current().await?;
        let deleted = self.transaction.execute(
            "DELETE FROM linklake_fleet_resource_ownership WHERE source_instance_id=$1 AND resource_id=$2 AND kind=$3 AND policy_id=$4 AND resource_sha256=$5 AND credential_ref IS NOT DISTINCT FROM $6",
            &[&resource.source_instance_id.to_string(), &resource.resource_id.to_string(), &resource.kind.as_str(), &resource.policy_id.to_string(), &resource.resource_sha256, &resource.credential_ref.map(|value| value.to_string())],
        ).await?;
        anyhow::ensure!(deleted == 1, "Fleet ownership changed before removal");
        Ok(())
    }

    pub(crate) async fn record_source(
        &self,
        request: &FleetReconcileRequest,
    ) -> anyhow::Result<()> {
        self.assert_current().await?;
        anyhow::ensure!(!request.dry_run, "Fleet dry run cannot commit source state");
        self.check_precondition(request).await?;
        let owned = self
            .owned_resources(request.bundle.source_instance_id)
            .await?;
        anyhow::ensure!(
            owned.len() == request.bundle.resources.len(),
            "Fleet source resource count differs from ownership"
        );
        for resource in &request.bundle.resources {
            let owner = owned
                .get(&resource.resource_id)
                .ok_or_else(|| anyhow::anyhow!("Fleet source resource has no ownership"))?;
            anyhow::ensure!(
                owner.kind == resource_kind(resource)
                    && owner.resource_sha256 == resource_sha256(resource)?,
                "Fleet source resource differs from committed ownership"
            );
        }
        self.transaction.execute(
            "INSERT INTO linklake_fleet_source_states(source_instance_id,generation,revision,applied_unix_seconds,resource_count)
             VALUES($1,$2,$3,floor(EXTRACT(EPOCH FROM clock_timestamp()))::bigint,$4)
             ON CONFLICT(source_instance_id) DO UPDATE SET generation=EXCLUDED.generation,revision=EXCLUDED.revision,applied_unix_seconds=EXCLUDED.applied_unix_seconds,resource_count=EXCLUDED.resource_count",
            &[&request.bundle.source_instance_id.to_string(), &i64::try_from(request.bundle.generation)?, &request.bundle.revision, &i64::try_from(owned.len())?],
        ).await?;
        Ok(())
    }

    pub(crate) async fn reset_source_state(&self, source: Uuid) -> anyhow::Result<bool> {
        self.assert_current().await?;
        Ok(self
            .transaction
            .execute(
                "DELETE FROM linklake_fleet_source_states WHERE source_instance_id=$1",
                &[&source.to_string()],
            )
            .await?
            != 0)
    }

    pub(crate) async fn delete_credential_binding(
        &self,
        source: Uuid,
        kind: FleetPolicyKind,
        credential: Uuid,
    ) -> anyhow::Result<bool> {
        self.assert_current().await?;
        let Some(policy) = self
            .credential_binding_policy(source, credential, kind)
            .await?
        else {
            return Ok(false);
        };
        self.transaction.execute("DELETE FROM linklake_fleet_credential_bindings WHERE source_instance_id=$1 AND credential_ref=$2 AND kind=$3", &[&source.to_string(), &credential.to_string(), &kind.as_str()]).await?;
        // 保留业务策略，只解除完全匹配的来源、凭据和策略归属。
        self.transaction.execute("DELETE FROM linklake_fleet_resource_ownership WHERE source_instance_id=$1 AND kind=$2 AND policy_id=$3 AND credential_ref=$4",
            &[&source.to_string(), &kind.as_str(), &policy.to_string(), &credential.to_string()]).await?;
        Ok(true)
    }
}

pub(crate) async fn list_sources(
    storage: &CoordinationStorage,
) -> anyhow::Result<Vec<FleetSourceStatus>> {
    storage.postgres_client().await?.query(
        "SELECT source_instance_id,generation,revision,applied_unix_seconds,resource_count FROM linklake_fleet_source_states ORDER BY applied_unix_seconds DESC,source_instance_id", &[],
    ).await?.iter().map(read_source).collect()
}

pub(crate) async fn list_credential_bindings(
    storage: &CoordinationStorage,
) -> anyhow::Result<Vec<FleetCredentialBinding>> {
    storage.postgres_client().await?.query(
        "SELECT source_instance_id,credential_ref,kind,policy_id,created_unix_seconds FROM linklake_fleet_credential_bindings ORDER BY source_instance_id,kind,credential_ref", &[],
    ).await?.iter().map(|row| {
        let kind = FleetPolicyKind::parse(row.try_get(2)?)?;
        anyhow::ensure!(kind.requires_credential(), "Fleet binding has an invalid policy kind");
        Ok(FleetCredentialBinding {
            source_instance_id: stored_id(row.try_get(0)?)?, credential_ref: stored_id(row.try_get(1)?)?, kind,
            policy_id: stored_id(row.try_get(3)?)?, created_unix_seconds: u64::try_from(row.try_get::<_,i64>(4)?)?,
        })
    }).collect()
}

fn stored_id(value: &str) -> anyhow::Result<Uuid> {
    let id = Uuid::parse_str(value)?;
    anyhow::ensure!(!id.is_nil(), "Fleet ledger contains a nil identity");
    Ok(id)
}

fn read_source(row: &Row) -> anyhow::Result<FleetSourceStatus> {
    Ok(FleetSourceStatus {
        source_instance_id: stored_id(row.try_get(0)?)?,
        generation: u64::try_from(row.try_get::<_, i64>(1)?)?,
        revision: row.try_get(2)?,
        applied_unix_seconds: u64::try_from(row.try_get::<_, i64>(3)?)?,
        resource_count: usize::try_from(row.try_get::<_, i64>(4)?)?,
    })
}

fn read_owned(row: &Row) -> anyhow::Result<OwnedResource> {
    let kind = FleetPolicyKind::parse(row.try_get(2)?)?;
    let credential_ref = row
        .try_get::<_, Option<&str>>(5)?
        .map(stored_id)
        .transpose()?;
    anyhow::ensure!(
        kind.requires_credential() == credential_ref.is_some(),
        "Fleet ownership credential kind mismatch"
    );
    Ok(OwnedResource {
        source_instance_id: stored_id(row.try_get(0)?)?,
        resource_id: stored_id(row.try_get(1)?)?,
        kind,
        policy_id: stored_id(row.try_get(3)?)?,
        resource_sha256: row.try_get(4)?,
        credential_ref,
    })
}
