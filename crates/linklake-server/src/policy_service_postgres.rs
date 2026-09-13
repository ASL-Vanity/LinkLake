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
    /// 仅暴露已取得目录锁的事务借用，供业务目录参与同一次原子变更。
    pub(crate) fn transaction(&self) -> &PgTransaction<'connection> {
        self.transaction
    }

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

// 共享策略服务入口
#[path = "policy_service_postgres_resources.rs"]
mod resources;
use crate::traffic_control::{postgres as traffic_pg, UpsertTrafficControl};
use resources::{
    build_policy, delete_resource, desired_control, export_control, export_policy, load_catalog,
    traffic_kind, validate_final_plan, CatalogSnapshot, SharedPlan,
};
use std::sync::Arc;

pub(crate) struct PostgresPolicyService {
    pub(crate) storage: CoordinationStorage,
    pub(crate) runtime: Arc<HaRuntime>,
    pub(crate) public_port_policy: PublicPortPolicy,
}

type BindingMap = HashMap<(Uuid, FleetPolicyKind, Uuid), Uuid>;

async fn transaction_bindings(transaction: &PgTransaction<'_>) -> anyhow::Result<BindingMap> {
    transaction.query("SELECT source_instance_id,kind,credential_ref,policy_id FROM linklake_fleet_credential_bindings ORDER BY source_instance_id,kind,credential_ref FOR UPDATE",&[]).await?.iter().map(|row| {
        let kind=FleetPolicyKind::parse(row.try_get(1)?)?;
        anyhow::ensure!(kind.requires_credential(),"invalid Fleet credential binding kind");
        Ok(((stored_id(row.try_get(0)?)?,kind,stored_id(row.try_get(2)?)?),stored_id(row.try_get(3)?)?))
    }).collect()
}
async fn transaction_owners(transaction: &PgTransaction<'_>) -> anyhow::Result<Vec<OwnedResource>> {
    transaction.query("SELECT source_instance_id,resource_id,kind,policy_id,resource_sha256,credential_ref FROM linklake_fleet_resource_ownership ORDER BY source_instance_id,resource_id FOR UPDATE",&[]).await?.iter().map(read_owned).collect()
}
struct SharedClient {
    client_id: Uuid,
    reference: linklake_core::fleet_protocol::FleetClientRef,
    enabled: bool,
}
async fn transaction_clients(transaction: &PgTransaction<'_>) -> anyhow::Result<Vec<SharedClient>> {
    // 锁定身份/启用行直到策略事务完成；不信任调用方在另一事务里读取的摘要。
    transaction.query("SELECT client_id,agent_instance_id,name,agent_identity_public_key,enabled FROM linklake_clients ORDER BY client_id FOR SHARE",&[]).await?.iter().map(|row| Ok(SharedClient{
        client_id:stored_id(row.try_get(0)?)?,
        reference:linklake_core::fleet_protocol::FleetClientRef {agent_instance_id:stored_id(row.try_get(1)?)?,name:row.try_get(2)?,agent_identity_public_key:row.try_get(3)?},
        enabled:row.try_get(4)?,
    })).collect()
}
fn resolve_clients(
    bundle: &FleetBundleV2,
    local: &[SharedClient],
) -> anyhow::Result<HashMap<Uuid, Uuid>> {
    let mut result = HashMap::new();
    for agent in bundle
        .resources
        .iter()
        .flat_map(referenced_agent_ids)
        .collect::<HashSet<_>>()
    {
        let declared = bundle
            .clients
            .iter()
            .find(|c| c.agent_instance_id == agent)
            .ok_or_else(|| anyhow::anyhow!("Fleet resource references an undeclared client"))?;
        let expected = declared
            .agent_identity_public_key
            .as_deref()
            .ok_or_else(|| {
                anyhow::anyhow!("Fleet client identity is not cryptographically verified")
            })?;
        let stored = local
            .iter()
            .find(|c| c.reference.agent_instance_id == agent)
            .ok_or_else(|| {
                anyhow::anyhow!("Fleet client {agent} is not enrolled on this server")
            })?;
        anyhow::ensure!(stored.enabled, "Fleet client {agent} is disabled");
        anyhow::ensure!(
            stored.reference.agent_identity_public_key.as_deref() == Some(expected),
            "Fleet client identity public key does not match local enrollment"
        );
        result.insert(agent, stored.client_id);
    }
    Ok(result)
}
#[expect(
    clippy::too_many_arguments,
    reason = "Fleet规划使用同一事务取得的资源、凭据、归属及端口快照"
)]
fn plan_shared_resource(
    source: Uuid,
    resource: &FleetResource,
    old: Option<&OwnedResource>,
    clients: &HashMap<Uuid, Uuid>,
    catalog: &CatalogSnapshot,
    bindings: &BindingMap,
    owners: &[OwnedResource],
    ports: &PublicPortPolicy,
) -> anyhow::Result<SharedPlan> {
    let kind = resource_kind(resource);
    if let Some(old) = old {
        anyhow::ensure!(old.kind == kind, "Fleet resource kind cannot change");
    }
    let reference = credential_ref(resource);
    let id = if let Some(reference) = reference {
        if let Some(old) = old {
            anyhow::ensure!(
                old.credential_ref == Some(reference),
                "Fleet credential reference cannot change"
            );
        }
        let bound = *bindings.get(&(source, kind, reference)).ok_or_else(|| {
            anyhow::anyhow!(
                "credential_ref {reference} is not bound to a local {} policy",
                kind.as_str()
            )
        })?;
        if let Some(old) = old {
            anyhow::ensure!(
                bound == old.policy_id,
                "Fleet credential binding was revoked or changed"
            );
        }
        bound
    } else {
        let derived = deterministic_policy_id(source, resource.resource_id, kind);
        if let Some(old) = old {
            anyhow::ensure!(
                old.policy_id == derived,
                "Fleet derived policy identity mismatch"
            );
        } else {
            anyhow::ensure!(
                !catalog.keys().any(|(_, id)| *id == derived),
                "derived local policy ID collides with an existing policy"
            );
        }
        derived
    };
    if let Some(owner) = owners.iter().find(|o| o.kind == kind && o.policy_id == id) {
        anyhow::ensure!(
            owner.source_instance_id == source && owner.resource_id == resource.resource_id,
            "local policy is already owned by another Fleet resource"
        );
    }
    let current = catalog.get(&(kind, id));
    let hash = if kind.requires_credential() {
        Some(
            current
                .and_then(|p| p.credential())
                .ok_or_else(|| anyhow::anyhow!("bound Fleet credential policy does not exist"))?,
        )
    } else {
        None
    };
    let policy = build_policy(resource, id, clients, hash, ports)?;
    let hash = resource_sha256(resource)?;
    let write_required = old.is_none_or(|old| old.resource_sha256 != hash)
        || current.is_none_or(|current| !current.same(&policy));
    Ok(SharedPlan {
        resource: resource.clone(),
        policy,
        resource_sha256: hash,
        write_required,
    })
}

impl PostgresPolicyService {
    pub(crate) async fn list_sources(&self) -> anyhow::Result<Vec<FleetSourceStatus>> {
        list_sources(&self.storage).await
    }
    pub(crate) async fn list_credential_bindings(
        &self,
    ) -> anyhow::Result<Vec<FleetCredentialBinding>> {
        list_credential_bindings(&self.storage).await
    }
    pub(crate) async fn is_policy_managed(
        &self,
        kind: FleetPolicyKind,
        id: Uuid,
    ) -> anyhow::Result<bool> {
        Ok(self.storage.postgres_client().await?.query_one("SELECT EXISTS(SELECT 1 FROM linklake_fleet_resource_ownership WHERE kind=$1 AND policy_id=$2)",&[&kind.as_str(),&id.to_string()]).await?.try_get(0)?)
    }
    pub(crate) async fn bind_credential(
        &self,
        request: BindFleetCredential,
        _now: u64,
    ) -> anyhow::Result<FleetCredentialBinding> {
        anyhow::ensure!(
            !request.source_instance_id.is_nil()
                && !request.credential_ref.is_nil()
                && !request.policy_id.is_nil(),
            "Fleet credential binding contains a nil ID"
        );
        anyhow::ensure!(
            request.kind.requires_credential(),
            "only secret-bearing policies can use Fleet credential bindings"
        );
        let mut client = self.storage.postgres_client().await?;
        let tx = client.transaction().await?;
        let guard = FleetPolicyTransaction::lock(&tx, &self.runtime).await?;
        let catalog = load_catalog(&guard, &self.public_port_policy).await?;
        anyhow::ensure!(
            catalog
                .get(&(request.kind, request.policy_id))
                .and_then(|p| p.credential())
                .is_some(),
            "Fleet credential binding policy does not exist"
        );
        anyhow::ensure!(
            !guard
                .is_policy_managed(request.kind, request.policy_id)
                .await?,
            "Fleet credential binding policy is already managed"
        );
        let bindings = transaction_bindings(&tx).await?;
        if let Some(previous) = bindings.get(&(
            request.source_instance_id,
            request.kind,
            request.credential_ref,
        )) {
            anyhow::ensure!(
                !guard.is_policy_managed(request.kind, *previous).await?,
                "managed Fleet credential binding must be explicitly unbound before replacement"
            );
        }
        anyhow::ensure!(
            !bindings
                .iter()
                .any(|((source, kind, reference), id)| *kind == request.kind
                    && *id == request.policy_id
                    && (*source != request.source_instance_id
                        || *reference != request.credential_ref)),
            "policy is already bound to a different Fleet credential"
        );
        let row=tx.query_one("INSERT INTO linklake_fleet_credential_bindings(source_instance_id,credential_ref,kind,policy_id,created_unix_seconds) VALUES($1,$2,$3,$4,floor(extract(epoch FROM clock_timestamp()))::bigint) ON CONFLICT(source_instance_id,credential_ref,kind) DO UPDATE SET policy_id=excluded.policy_id,created_unix_seconds=excluded.created_unix_seconds RETURNING created_unix_seconds",&[&request.source_instance_id.to_string(),&request.credential_ref.to_string(),&request.kind.as_str(),&request.policy_id.to_string()]).await?;
        let created_unix_seconds = u64::try_from(row.try_get::<_, i64>(0)?)?;
        guard.assert_current().await?;
        tx.commit().await?;
        Ok(FleetCredentialBinding {
            source_instance_id: request.source_instance_id,
            credential_ref: request.credential_ref,
            kind: request.kind,
            policy_id: request.policy_id,
            created_unix_seconds,
        })
    }
    pub(crate) async fn delete_credential_binding(
        &self,
        source: Uuid,
        kind: FleetPolicyKind,
        credential: Uuid,
    ) -> anyhow::Result<bool> {
        let mut client = self.storage.postgres_client().await?;
        let tx = client.transaction().await?;
        let guard = FleetPolicyTransaction::lock(&tx, &self.runtime).await?;
        let deleted = guard
            .delete_credential_binding(source, kind, credential)
            .await?;
        guard.assert_current().await?;
        tx.commit().await?;
        Ok(deleted)
    }
    pub(crate) async fn reset_source_state(&self, source: Uuid) -> anyhow::Result<bool> {
        let mut client = self.storage.postgres_client().await?;
        let tx = client.transaction().await?;
        let guard = FleetPolicyTransaction::lock(&tx, &self.runtime).await?;
        let deleted = guard.reset_source_state(source).await?;
        guard.assert_current().await?;
        tx.commit().await?;
        Ok(deleted)
    }
    pub(crate) async fn export_bundle_with_clients(
        &self,
        _now: u64,
        _clients: &[linklake_core::ClientSummary],
    ) -> anyhow::Result<FleetBundleV2> {
        self.export_bundle().await
    }
    pub(crate) async fn export_bundle(&self) -> anyhow::Result<FleetBundleV2> {
        let mut client = self.storage.postgres_client().await?;
        let tx = client.transaction().await?;
        let guard = FleetPolicyTransaction::lock(&tx, &self.runtime).await?;
        let clients = transaction_clients(&tx).await?;
        let catalog = load_catalog(&guard, &self.public_port_policy).await?;
        let owners = transaction_owners(&tx).await?;
        let bindings = transaction_bindings(&tx).await?;
        let agents: HashMap<_, _> = clients
            .iter()
            .filter(|c| c.enabled && c.reference.agent_identity_public_key.is_some())
            .map(|c| (c.client_id, c.reference.agent_instance_id))
            .collect();
        let mut excluded: HashSet<_> = owners.iter().map(|o| (o.kind, o.policy_id)).collect();
        excluded.extend(bindings.into_iter().map(|((_, kind, _), id)| (kind, id)));
        let mut resources = Vec::new();
        for (key, policy) in &catalog {
            if !excluded.contains(key) {
                if let Some(resource) = export_policy(policy, &agents)? {
                    resources.push(resource);
                }
            }
        }
        let referenced: HashSet<_> = resources.iter().flat_map(referenced_agent_ids).collect();
        let client_refs = clients
            .into_iter()
            .filter(|c| referenced.contains(&c.reference.agent_instance_id))
            .map(|c| c.reference)
            .collect();
        let traffic = traffic_pg::transaction_list(&guard).await?;
        let mut controls = Vec::new();
        for resource in &resources {
            let kind = traffic_kind(resource_kind(resource))?;
            if let Some(record) = traffic
                .iter()
                .find(|c| c.kind == kind && c.policy_id == resource.resource_id)
            {
                controls.push(export_control(
                    resource.resource_id,
                    record.settings.clone(),
                ));
            }
        }
        let (source, generation) = guard.reserve_generation().await?;
        let now = u64::try_from(
            tx.query_one(
                "SELECT floor(extract(epoch FROM clock_timestamp()))::bigint",
                &[],
            )
            .await?
            .try_get::<_, i64>(0)?,
        )?;
        let bundle = FleetBundleV2::new(
            source,
            generation,
            now.max(1),
            client_refs,
            resources,
            controls,
        )?;
        guard.assert_current().await?;
        tx.commit().await?;
        Ok(bundle)
    }
}

impl PostgresPolicyService {
    pub(crate) async fn reconcile_with_clients(
        &self,
        request: FleetReconcileRequest,
        _now: u64,
        _clients: &[linklake_core::ClientSummary],
    ) -> anyhow::Result<FleetReconcileResult> {
        self.reconcile(request).await
    }
    pub(crate) async fn reconcile(
        &self,
        request: FleetReconcileRequest,
    ) -> anyhow::Result<FleetReconcileResult> {
        request.bundle.validate()?;
        let mut client = self.storage.postgres_client().await?;
        let tx = client.transaction().await?;
        let guard = FleetPolicyTransaction::lock(&tx, &self.runtime).await?;
        let (current, same_revision) = guard.check_precondition(&request).await?;
        let local_clients = transaction_clients(&tx).await?;
        let clients = resolve_clients(&request.bundle, &local_clients)?;
        let catalog = load_catalog(&guard, &self.public_port_policy).await?;
        let owners = transaction_owners(&tx).await?;
        let bindings = transaction_bindings(&tx).await?;
        let source = request.bundle.source_instance_id;
        let existing: HashMap<Uuid, OwnedResource> = owners
            .iter()
            .filter(|o| o.source_instance_id == source)
            .map(|o| (o.resource_id, o.clone()))
            .collect();
        let mut plan = Vec::with_capacity(request.bundle.resources.len());
        let mut conflicts = Vec::new();
        for resource in &request.bundle.resources {
            match plan_shared_resource(
                source,
                resource,
                existing.get(&resource.resource_id),
                &clients,
                &catalog,
                &bindings,
                &owners,
                &self.public_port_policy,
            ) {
                Ok(planned) => plan.push(planned),
                Err(error) => conflicts.push(FleetConflict {
                    code: "resource_conflict".into(),
                    resource_id: Some(resource.resource_id),
                    message: error.to_string(),
                }),
            }
        }
        validate_final_plan(&plan, &catalog, &existing, &mut conflicts)?;
        let mut desired_controls = HashMap::<Uuid, UpsertTrafficControl>::new();
        for control in &request.bundle.traffic_controls {
            if !plan
                .iter()
                .any(|p| p.resource.resource_id == control.resource_id)
            {
                conflicts.push(FleetConflict {
                    code: "unknown_traffic_control_resource".into(),
                    resource_id: Some(control.resource_id),
                    message: "traffic control references a missing Fleet resource".into(),
                });
                continue;
            }
            match desired_control(control) {
                Ok(settings) => {
                    desired_controls.insert(control.resource_id, settings);
                }
                Err(error) => conflicts.push(FleetConflict {
                    code: "invalid_traffic_control".into(),
                    resource_id: Some(control.resource_id),
                    message: error.to_string(),
                }),
            }
        }
        let mut result = FleetReconcileResult {
            source_instance_id: source,
            generation: request.bundle.generation,
            revision: request.bundle.revision.clone(),
            previous_generation: current.as_ref().map_or(0, |s| s.generation),
            previous_revision: current.as_ref().map(|s| s.revision.clone()),
            dry_run: request.dry_run,
            applied: false,
            idempotent: false,
            created: 0,
            updated: 0,
            deleted: 0,
            unchanged: 0,
            traffic_controls: 0,
            conflicts,
            runtime_invalidations: Vec::new(),
        };
        if !result.conflicts.is_empty() {
            return Ok(result);
        }
        let desired_ids: HashSet<_> = plan.iter().map(|p| p.resource.resource_id).collect();
        let obsolete: Vec<_> = existing
            .values()
            .filter(|o| !desired_ids.contains(&o.resource_id))
            .collect();
        result.created = plan
            .iter()
            .filter(|p| !existing.contains_key(&p.resource.resource_id))
            .count();
        result.updated = plan
            .iter()
            .filter(|p| existing.contains_key(&p.resource.resource_id) && p.write_required)
            .count();
        result.unchanged = plan.len().saturating_sub(result.created + result.updated);
        result.deleted = obsolete.len();
        result.traffic_controls = request.bundle.traffic_controls.len();
        let stored_controls = traffic_pg::transaction_list(&guard).await?;
        let mut changed_controls = Vec::new();
        for planned in &plan {
            let kind = traffic_kind(planned.policy.kind())?;
            let current = stored_controls
                .iter()
                .find(|c| c.kind == kind && c.policy_id == planned.policy.id())
                .map(|c| &c.settings);
            let desired = desired_controls.get(&planned.resource.resource_id);
            if current != desired {
                changed_controls.push((kind, planned.policy.id(), desired.cloned()));
            }
        }
        result.idempotent = same_revision
            && result.created == 0
            && result.updated == 0
            && obsolete.is_empty()
            && changed_controls.is_empty();
        if result.idempotent || request.dry_run {
            return Ok(result);
        }

        for old in &obsolete {
            if let Some(policy) = catalog.get(&(old.kind, old.policy_id)) {
                policy.invalidate(&mut result.runtime_invalidations)?;
            }
            delete_resource(&guard, old.kind, old.policy_id).await?;
            if old.kind == FleetPolicyKind::HttpRoute {
                // 仅最终移除资源时清理 TLS；上面的通用删除也用于 swap，不能在其中清理。
                let route_id = old.policy_id.to_string();
                tx.execute(
                    "DELETE FROM linklake_route_tls WHERE route_id=$1",
                    &[&route_id],
                )
                .await?;
                tx.execute(
                    "DELETE FROM linklake_certificate_materials WHERE route_id=$1",
                    &[&route_id],
                )
                .await?;
                tx.execute(
                    "DELETE FROM linklake_certificate_states WHERE route_id=$1",
                    &[&route_id],
                )
                .await?;
            }
            traffic_pg::transaction_delete(&guard, traffic_kind(old.kind)?, old.policy_id).await?;
            // 已删除资源解除凭据引用；保留历史用量/事件，不借删除重建清空累计配额。
            tx.execute("DELETE FROM linklake_fleet_credential_bindings WHERE source_instance_id=$1 AND kind=$2 AND policy_id=$3",&[&source.to_string(),&old.kind.as_str(),&old.policy_id.to_string()]).await?;
            guard.release_ownership(old).await?;
        }
        // 完整计划先校验；所有变更旧行先移除，再写入新行，支持任意资源交换。
        for planned in plan.iter().filter(|p| p.write_required) {
            if let Some(previous) = catalog.get(&planned.policy.key()) {
                previous.invalidate(&mut result.runtime_invalidations)?;
                delete_resource(&guard, planned.policy.kind(), planned.policy.id()).await?;
            }
        }
        for planned in plan.iter().filter(|p| p.write_required) {
            planned.policy.put(&guard, &self.public_port_policy).await?;
            guard
                .record_ownership(&OwnedResource {
                    source_instance_id: source,
                    resource_id: planned.resource.resource_id,
                    kind: planned.policy.kind(),
                    policy_id: planned.policy.id(),
                    resource_sha256: planned.resource_sha256.clone(),
                    credential_ref: credential_ref(&planned.resource),
                })
                .await?;
        }
        for (kind, id, desired) in changed_controls {
            match desired {
                Some(settings) => {
                    traffic_pg::transaction_put(&guard, kind, id, settings).await?;
                }
                None => {
                    traffic_pg::transaction_delete(&guard, kind, id).await?;
                }
            }
        }
        guard.record_source(&request).await?;
        guard.assert_current().await?;
        tx.commit().await?;
        result.applied = true;
        Ok(result)
    }
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
    let resource = OwnedResource {
        source_instance_id: stored_id(row.try_get(0)?)?,
        resource_id: stored_id(row.try_get(1)?)?,
        kind,
        policy_id: stored_id(row.try_get(3)?)?,
        resource_sha256: row.try_get(4)?,
        credential_ref,
    };
    anyhow::ensure!(
        resource.resource_sha256.len() == 64
            && resource
                .resource_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "Fleet resource digest is invalid"
    );
    if !kind.requires_credential() {
        anyhow::ensure!(
            resource.policy_id
                == deterministic_policy_id(resource.source_instance_id, resource.resource_id, kind),
            "Fleet derived policy identity mismatch"
        );
    }
    Ok(resource)
}

#[cfg(test)]
mod shared_resource_tests {
    use super::*;
    use serde_json::json;

    fn resource(kind: &str, id: Uuid, agent: Uuid, port: u16) -> FleetResource {
        let settings = match kind {
            "tcp" => {
                json!({"agent_instance_id":agent,"name":"tcp","public_port":port,"target_addr":"127.0.0.1:80","max_connections":32,"bandwidth_limit_bps":4096})
            }
            "udp" => {
                json!({"agent_instance_id":agent,"name":"udp","public_port":port,"target_addr":"127.0.0.1:80","max_sessions":256,"session_idle_timeout_seconds":120,"bandwidth_limit_bps":4096})
            }
            "port_group" => {
                json!({"agent_instance_id":agent,"name":"ports","protocol":"udp","public_ports":format!("{port},{}",port+2),"target_host":"::1","target_ports":"80,82","max_connections":32,"max_sessions":256,"session_idle_timeout_seconds":120,"bandwidth_limit_bps":4096})
            }
            "http_route" => {
                json!({"agent_instance_id":agent,"name":"http","hostname":"http.example.test","target_addr":"127.0.0.1:443","max_connections":32,"grpc_backend_transport":"tls","grpc_backend_server_name":"backend.example.test","grpc_backend_trust_profile":"internal-ca"})
            }
            "sni_route" => {
                json!({"agent_instance_id":agent,"name":"sni","hostname":"sni.example.test","target_addr":"127.0.0.1:443","max_connections":32,"bandwidth_limit_bps":4096})
            }
            "secret_tunnel" => {
                json!({"provider_agent_instance_id":agent,"allowed_agent_instance_id":agent,"credential_ref":id,"name":"secret","target_addr":"127.0.0.1:80","max_connections":32,"bandwidth_limit_bps":4096})
            }
            "socks5_proxy" | "http_proxy" => {
                json!({"agent_instance_id":agent,"credential_ref":id,"name":"proxy","public_port":port,"username":"lake","max_connections":32,"bandwidth_limit_bps":4096,"allow_private_networks":false})
            }
            _ => panic!("unknown test kind"),
        };
        FleetResource {
            resource_id: id,
            enabled: true,
            spec: serde_json::from_value(json!({"kind":kind,"settings":settings})).unwrap(),
        }
    }
    fn plan(resource: FleetResource, local: Uuid, agent: Uuid) -> SharedPlan {
        let clients = HashMap::from([(agent, local)]);
        let hash = "a".repeat(64);
        let policy = build_policy(
            &resource,
            resource.resource_id,
            &clients,
            resource_kind(&resource)
                .requires_credential()
                .then_some(hash.as_str()),
            &PublicPortPolicy::development_default(),
        )
        .unwrap();
        SharedPlan {
            resource_sha256: resource_sha256(&resource).unwrap(),
            resource,
            policy,
            write_required: true,
        }
    }
    #[test]
    fn eight_kinds_round_trip_through_shared_catalog_without_credentials() {
        let local = Uuid::new_v4();
        let agent = Uuid::new_v4();
        for kind in [
            "tcp",
            "udp",
            "port_group",
            "http_route",
            "sni_route",
            "secret_tunnel",
            "socks5_proxy",
            "http_proxy",
        ] {
            let planned = plan(resource(kind, Uuid::new_v4(), agent, 32001), local, agent);
            let exported = export_policy(&planned.policy, &HashMap::from([(local, agent)]))
                .unwrap()
                .unwrap();
            assert_eq!(exported, planned.resource);
            let wire = serde_json::to_string(&exported).unwrap();
            assert!(!wire.contains("password_hash"));
            assert!(!wire.contains("access_key_hash"));
            assert!(!wire.contains(&"a".repeat(64)));
        }
    }
    #[test]
    fn socks5_conflicts_with_unmanaged_udp_reservation() {
        let local = Uuid::new_v4();
        let agent = Uuid::new_v4();
        let udp = plan(resource("udp", Uuid::new_v4(), agent, 32001), local, agent);
        let socks = plan(
            resource("socks5_proxy", Uuid::new_v4(), agent, 32001),
            local,
            agent,
        );
        let mut catalog = CatalogSnapshot::new();
        catalog.insert(udp.policy.key(), udp.policy);
        let mut conflicts = Vec::new();
        validate_final_plan(&[socks], &catalog, &HashMap::new(), &mut conflicts).unwrap();
        assert!(conflicts.iter().any(|c| c.code == "local_policy_conflict"));
    }
    #[test]
    fn swapping_owned_ports_uses_final_state_but_duplicate_destinations_conflict() {
        let local = Uuid::new_v4();
        let agent = Uuid::new_v4();
        let source = Uuid::new_v4();
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let mut catalog = CatalogSnapshot::new();
        let mut owned = HashMap::new();
        for (id, port) in [(first, 32001), (second, 32002)] {
            let mut resource = resource("tcp", id, agent, port);
            if let FleetResourceSpec::Tcp(p) = &mut resource.spec {
                p.name = format!("tcp-{id}");
            }
            let planned = plan(resource, local, agent);
            owned.insert(
                id,
                OwnedResource {
                    source_instance_id: source,
                    resource_id: id,
                    kind: FleetPolicyKind::Tcp,
                    policy_id: id,
                    resource_sha256: planned.resource_sha256.clone(),
                    credential_ref: None,
                },
            );
            catalog.insert(planned.policy.key(), planned.policy);
        }
        let make = |id, port| {
            let mut resource = resource("tcp", id, agent, port);
            if let FleetResourceSpec::Tcp(p) = &mut resource.spec {
                p.name = format!("tcp-{id}");
            }
            plan(resource, local, agent)
        };
        let mut conflicts = Vec::new();
        validate_final_plan(
            &[make(first, 32002), make(second, 32001)],
            &catalog,
            &owned,
            &mut conflicts,
        )
        .unwrap();
        assert!(conflicts.is_empty());
        validate_final_plan(
            &[make(first, 32002), make(second, 32002)],
            &catalog,
            &owned,
            &mut conflicts,
        )
        .unwrap();
        assert!(!conflicts.is_empty());
    }
    #[test]
    fn same_resource_digest_does_not_hide_actual_policy_drift() {
        let source = Uuid::new_v4();
        let agent = Uuid::new_v4();
        let local = Uuid::new_v4();
        let id = Uuid::new_v4();
        let desired = resource("tcp", id, agent, 32001);
        let policy_id = deterministic_policy_id(source, id, FleetPolicyKind::Tcp);
        let old = OwnedResource {
            source_instance_id: source,
            resource_id: id,
            kind: FleetPolicyKind::Tcp,
            policy_id,
            resource_sha256: resource_sha256(&desired).unwrap(),
            credential_ref: None,
        };
        let mut drift = desired.clone();
        drift.enabled = false;
        let clients = HashMap::from([(agent, local)]);
        let policy = build_policy(
            &drift,
            policy_id,
            &clients,
            None,
            &PublicPortPolicy::development_default(),
        )
        .unwrap();
        let catalog = HashMap::from([(policy.key(), policy)]);
        let planned = plan_shared_resource(
            source,
            &desired,
            Some(&old),
            &clients,
            &catalog,
            &HashMap::new(),
            std::slice::from_ref(&old),
            &PublicPortPolicy::development_default(),
        )
        .unwrap();
        assert!(planned.write_required);
    }
    #[test]
    fn a_revoked_binding_never_reuses_an_in_memory_proxy_hash() {
        let source = Uuid::new_v4();
        let agent = Uuid::new_v4();
        let local = Uuid::new_v4();
        let id = Uuid::new_v4();
        let desired = resource("socks5_proxy", id, agent, 32001);
        let planned = plan(desired.clone(), local, agent);
        let old = OwnedResource {
            source_instance_id: source,
            resource_id: id,
            kind: FleetPolicyKind::Socks5Proxy,
            policy_id: id,
            resource_sha256: planned.resource_sha256,
            credential_ref: Some(id),
        };
        let catalog = HashMap::from([(planned.policy.key(), planned.policy)]);
        assert!(plan_shared_resource(
            source,
            &desired,
            Some(&old),
            &HashMap::from([(agent, local)]),
            &catalog,
            &HashMap::new(),
            std::slice::from_ref(&old),
            &PublicPortPolicy::development_default()
        )
        .is_err());
    }
    #[test]
    fn traffic_control_conversion_keeps_full_unsigned_quota() {
        let control = FleetTrafficControl {
            resource_id: Uuid::new_v4(),
            enabled: true,
            allowed_cidrs: vec![],
            denied_cidrs: vec![],
            max_connections_per_minute: None,
            daily_quota_bytes: Some(u64::MAX),
            active_weekdays_utc: vec![],
            start_minute_utc: None,
            end_minute_utc: None,
        };
        let settings = desired_control(&control).unwrap();
        assert_eq!(export_control(control.resource_id, settings), control);
    }
}
