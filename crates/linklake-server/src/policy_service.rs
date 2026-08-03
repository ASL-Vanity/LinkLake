//! Fleet v2 策略导出、条件同步和跨八类资源的原子 reconcile。

use crate::{database::Database, public_port_policy::PublicPortPolicy};
use linklake_core::{
    fleet_protocol::{
        FleetBundleV2, FleetHttpProxyResource, FleetHttpRouteResource, FleetPortGroupProtocol,
        FleetPortGroupResource, FleetResource, FleetResourceSpec, FleetSecretTunnelResource,
        FleetSniRouteResource, FleetSocks5ProxyResource, FleetTcpResource, FleetTrafficControl,
        FleetUdpResource,
    },
    port_mapping::{parse_port_mappings, MAX_PORT_MAPPINGS},
};
use rusqlite::{params, OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    net::Ipv6Addr,
};
use uuid::Uuid;

const MAX_FLEET_GENERATION_ADVANCE: u64 = 1_000_000;

const FLEET_SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS fleet_local_state (
    singleton_id INTEGER PRIMARY KEY NOT NULL CHECK(singleton_id = 1),
    source_instance_id TEXT NOT NULL UNIQUE,
    generation INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS fleet_source_states (
    source_instance_id TEXT PRIMARY KEY NOT NULL,
    generation INTEGER NOT NULL,
    revision TEXT NOT NULL,
    applied_unix_seconds INTEGER NOT NULL,
    resource_count INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS fleet_resource_ownership (
    source_instance_id TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    resource_sha256 TEXT NOT NULL,
    credential_ref TEXT,
    PRIMARY KEY(source_instance_id, resource_id),
    UNIQUE(kind, policy_id)
);
CREATE INDEX IF NOT EXISTS fleet_resource_ownership_policy
    ON fleet_resource_ownership(kind, policy_id);
CREATE TABLE IF NOT EXISTS fleet_credential_bindings (
    source_instance_id TEXT NOT NULL,
    credential_ref TEXT NOT NULL,
    kind TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    created_unix_seconds INTEGER NOT NULL,
    PRIMARY KEY(source_instance_id, credential_ref, kind),
    UNIQUE(kind, policy_id)
);
"#;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FleetPolicyKind {
    Tcp,
    Udp,
    PortGroup,
    HttpRoute,
    SniRoute,
    SecretTunnel,
    Socks5Proxy,
    HttpProxy,
}

impl FleetPolicyKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::PortGroup => "port_group",
            Self::HttpRoute => "http_route",
            Self::SniRoute => "sni_route",
            Self::SecretTunnel => "secret_tunnel",
            Self::Socks5Proxy => "socks5_proxy",
            Self::HttpProxy => "http_proxy",
        }
    }

    pub(crate) fn parse(value: &str) -> anyhow::Result<Self> {
        match value {
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            "port_group" => Ok(Self::PortGroup),
            "http_route" => Ok(Self::HttpRoute),
            "sni_route" => Ok(Self::SniRoute),
            "secret_tunnel" => Ok(Self::SecretTunnel),
            "socks5_proxy" => Ok(Self::Socks5Proxy),
            "http_proxy" => Ok(Self::HttpProxy),
            _ => anyhow::bail!("unknown Fleet policy kind"),
        }
    }

    fn traffic_kind(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::PortGroup => "port_group",
            Self::HttpRoute => "http",
            Self::SniRoute => "sni",
            Self::SecretTunnel => "secret",
            Self::Socks5Proxy => "socks5",
            Self::HttpProxy => "http_proxy",
        }
    }

    fn requires_credential(self) -> bool {
        matches!(
            self,
            Self::SecretTunnel | Self::Socks5Proxy | Self::HttpProxy
        )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FleetReconcileRequest {
    pub(crate) bundle: FleetBundleV2,
    #[serde(default)]
    pub(crate) dry_run: bool,
    #[serde(default)]
    pub(crate) expected_generation: Option<u64>,
    #[serde(default)]
    pub(crate) expected_revision: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct FleetConflict {
    pub(crate) code: String,
    pub(crate) resource_id: Option<Uuid>,
    pub(crate) message: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct FleetReconcileResult {
    pub(crate) source_instance_id: Uuid,
    pub(crate) generation: u64,
    pub(crate) revision: String,
    pub(crate) previous_generation: u64,
    pub(crate) previous_revision: Option<String>,
    pub(crate) dry_run: bool,
    pub(crate) applied: bool,
    pub(crate) idempotent: bool,
    pub(crate) created: usize,
    pub(crate) updated: usize,
    pub(crate) deleted: usize,
    pub(crate) unchanged: usize,
    pub(crate) traffic_controls: usize,
    pub(crate) conflicts: Vec<FleetConflict>,
    #[serde(skip)]
    pub(crate) runtime_invalidations: Vec<FleetRuntimeInvalidation>,
}

#[derive(Clone, Debug)]
pub(crate) enum FleetRuntimeInvalidation {
    TcpPort(u16),
    UdpPort(u16),
    HttpHostname(String),
    SniHostname(String),
    SecretTunnel(Uuid),
    Socks5Proxy(Uuid),
    HttpProxy(Uuid),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct FleetSourceStatus {
    pub(crate) source_instance_id: Uuid,
    pub(crate) generation: u64,
    pub(crate) revision: String,
    pub(crate) applied_unix_seconds: u64,
    pub(crate) resource_count: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BindFleetCredential {
    pub(crate) source_instance_id: Uuid,
    pub(crate) credential_ref: Uuid,
    pub(crate) kind: FleetPolicyKind,
    pub(crate) policy_id: Uuid,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct FleetCredentialBinding {
    pub(crate) source_instance_id: Uuid,
    pub(crate) credential_ref: Uuid,
    pub(crate) kind: FleetPolicyKind,
    pub(crate) policy_id: Uuid,
    pub(crate) created_unix_seconds: u64,
}

#[derive(Clone)]
pub(crate) struct PolicyService {
    database: Database,
    public_port_policy: PublicPortPolicy,
}

#[derive(Clone, Debug)]
struct OwnedResource {
    source_instance_id: Uuid,
    resource_id: Uuid,
    kind: FleetPolicyKind,
    policy_id: Uuid,
    resource_sha256: String,
    credential_ref: Option<Uuid>,
}

#[derive(Clone)]
struct PlannedResource {
    resource: FleetResource,
    kind: FleetPolicyKind,
    policy_id: Uuid,
    resource_sha256: String,
    credential_hash: Option<String>,
    write_required: bool,
}

#[derive(Clone, Copy)]
struct DesiredEndpoint {
    resource_id: Uuid,
    kind: FleetPolicyKind,
    policy_id: Uuid,
}

impl PolicyService {
    pub(crate) fn open_with_database(
        database: &Database,
        public_port_policy: PublicPortPolicy,
    ) -> anyhow::Result<Self> {
        let source_instance_id = Uuid::new_v4();
        database.with_connection(|connection| {
            if database.is_persistent() {
                for table in [
                    "fleet_local_state",
                    "fleet_source_states",
                    "fleet_resource_ownership",
                    "fleet_credential_bindings",
                ] {
                    let exists: bool = connection.query_row(
                        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
                        [table],
                        |row| row.get(0),
                    )?;
                    anyhow::ensure!(
                        exists,
                        "Fleet schema is missing after database migration: {table}"
                    );
                }
            } else {
                connection.execute_batch(FLEET_SCHEMA_SQL)?;
            }
            connection.execute(
                "INSERT OR IGNORE INTO fleet_local_state (singleton_id, source_instance_id, generation) VALUES (1, ?1, 0)",
                [source_instance_id.to_string()],
            )?;
            Ok(())
        })?;
        Ok(Self {
            database: database.clone(),
            public_port_policy,
        })
    }

    pub(crate) fn local_instance_id(&self) -> anyhow::Result<Uuid> {
        self.database.with_connection(|connection| {
            let value: String = connection.query_row(
                "SELECT source_instance_id FROM fleet_local_state WHERE singleton_id = 1",
                [],
                |row| row.get(0),
            )?;
            Ok(Uuid::parse_str(&value)?)
        })
    }

    pub(crate) fn list_sources(&self) -> anyhow::Result<Vec<FleetSourceStatus>> {
        self.database.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT source_instance_id, generation, revision, applied_unix_seconds, resource_count FROM fleet_source_states ORDER BY applied_unix_seconds DESC, source_instance_id",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, u64>(3)?,
                    row.get::<_, usize>(4)?,
                ))
            })?;
            rows.map(|row| {
                let (source, generation, revision, applied, resources) = row?;
                Ok(FleetSourceStatus {
                    source_instance_id: Uuid::parse_str(&source)?,
                    generation,
                    revision,
                    applied_unix_seconds: applied,
                    resource_count: resources,
                })
            })
            .collect()
        })
    }

    pub(crate) fn list_credential_bindings(&self) -> anyhow::Result<Vec<FleetCredentialBinding>> {
        self.database.with_connection(|connection| {
            let mut statement = connection.prepare(
                "SELECT source_instance_id, credential_ref, kind, policy_id, created_unix_seconds FROM fleet_credential_bindings ORDER BY source_instance_id, kind, credential_ref",
            )?;
            let rows = statement.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, u64>(4)?,
                ))
            })?;
            rows.map(|row| {
                let (source, credential, kind, policy, created) = row?;
                Ok(FleetCredentialBinding {
                    source_instance_id: Uuid::parse_str(&source)?,
                    credential_ref: Uuid::parse_str(&credential)?,
                    kind: FleetPolicyKind::parse(&kind)?,
                    policy_id: Uuid::parse_str(&policy)?,
                    created_unix_seconds: created,
                })
            })
            .collect()
        })
    }

    pub(crate) fn bind_credential(
        &self,
        request: BindFleetCredential,
        now: u64,
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
        self.database.with_transaction(|transaction| {
            anyhow::ensure!(
                policy_exists(transaction, request.kind, request.policy_id)?,
                "Fleet credential binding policy does not exist"
            );
            let owned: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM fleet_resource_ownership WHERE kind = ?1 AND policy_id = ?2)",
                params![request.kind.as_str(), request.policy_id.to_string()],
                |row| row.get(0),
            )?;
            anyhow::ensure!(!owned, "Fleet credential binding policy is already managed");
            transaction.execute(
                "INSERT INTO fleet_credential_bindings (source_instance_id, credential_ref, kind, policy_id, created_unix_seconds)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(source_instance_id, credential_ref, kind) DO UPDATE SET policy_id = excluded.policy_id, created_unix_seconds = excluded.created_unix_seconds",
                params![
                    request.source_instance_id.to_string(),
                    request.credential_ref.to_string(),
                    request.kind.as_str(),
                    request.policy_id.to_string(),
                    now,
                ],
            )?;
            Ok(FleetCredentialBinding {
                source_instance_id: request.source_instance_id,
                credential_ref: request.credential_ref,
                kind: request.kind,
                policy_id: request.policy_id,
                created_unix_seconds: now,
            })
        })
    }

    pub(crate) fn delete_credential_binding(
        &self,
        source_instance_id: Uuid,
        kind: FleetPolicyKind,
        credential_ref: Uuid,
    ) -> anyhow::Result<bool> {
        self.database.with_transaction(|transaction| {
            let policy_id: Option<String> = transaction
                .query_row(
                    "SELECT policy_id FROM fleet_credential_bindings WHERE source_instance_id = ?1 AND credential_ref = ?2 AND kind = ?3",
                    params![
                        source_instance_id.to_string(),
                        credential_ref.to_string(),
                        kind.as_str(),
                    ],
                    |row| row.get(0),
                )
                .optional()?;
            let Some(policy_id) = policy_id else {
                return Ok(false);
            };
            transaction.execute(
                "DELETE FROM fleet_credential_bindings WHERE source_instance_id = ?1 AND credential_ref = ?2 AND kind = ?3",
                params![
                    source_instance_id.to_string(),
                    credential_ref.to_string(),
                    kind.as_str(),
                ],
            )?;
            // 解绑后把策略留在本地，但立即解除远端 ownership；后续 bundle 必须重新显式绑定。
            transaction.execute(
                "DELETE FROM fleet_resource_ownership WHERE source_instance_id = ?1 AND kind = ?2 AND policy_id = ?3 AND credential_ref = ?4",
                params![
                    source_instance_id.to_string(),
                    kind.as_str(),
                    policy_id,
                    credential_ref.to_string(),
                ],
            )?;
            Ok(true)
        })
    }

    pub(crate) fn is_policy_managed(
        &self,
        kind: FleetPolicyKind,
        policy_id: Uuid,
    ) -> anyhow::Result<bool> {
        self.database.with_connection(|connection| {
            Ok(connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM fleet_resource_ownership WHERE kind = ?1 AND policy_id = ?2)",
                params![kind.as_str(), policy_id.to_string()],
                |row| row.get(0),
            )?)
        })
    }

    pub(crate) fn reset_source_state(&self, source_instance_id: Uuid) -> anyhow::Result<bool> {
        self.database.with_connection(|connection| {
            Ok(connection.execute(
                "DELETE FROM fleet_source_states WHERE source_instance_id = ?1",
                [source_instance_id.to_string()],
            )? > 0)
        })
    }

    pub(crate) fn export_bundle(&self, now: u64) -> anyhow::Result<FleetBundleV2> {
        self.database.with_transaction(|transaction| {
            let (source_instance_id, generation) = reserve_generation(transaction)?;
            let clients = load_fleet_clients(transaction)?;
            let agent_by_client = clients
                .iter()
                .map(|client| (client.0, client.1.agent_instance_id))
                .collect::<HashMap<_, _>>();
            let excluded = excluded_local_policies(transaction)?;
            let resources = export_resources(transaction, &agent_by_client, &excluded)?;
            let referenced_clients = resources
                .iter()
                .flat_map(referenced_agent_ids)
                .collect::<HashSet<_>>();
            let client_refs = clients
                .into_iter()
                .map(|(_, client)| client)
                .filter(|client| referenced_clients.contains(&client.agent_instance_id))
                .collect::<Vec<_>>();
            let traffic_controls = export_traffic_controls(transaction, &resources)?;
            Ok(FleetBundleV2::new(
                source_instance_id,
                generation,
                now.max(1),
                client_refs,
                resources,
                traffic_controls,
            )?)
        })
    }

    pub(crate) fn reconcile(
        &self,
        request: FleetReconcileRequest,
        now: u64,
    ) -> anyhow::Result<FleetReconcileResult> {
        request.bundle.validate()?;
        let source_instance_id = request.bundle.source_instance_id;
        let generation = request.bundle.generation;
        let revision = request.bundle.revision.clone();
        let public_port_policy = self.public_port_policy.clone();
        self.database.with_transaction(|transaction| {
            anyhow::ensure!(
                generation <= i64::MAX as u64,
                "Fleet bundle generation exceeds the persistent database range"
            );
            let current = read_source_status(transaction, source_instance_id)?;
            let previous_generation = current.as_ref().map_or(0, |state| state.generation);
            let previous_revision = current.as_ref().map(|state| state.revision.clone());
            if let Some(expected) = request.expected_generation {
                anyhow::ensure!(
                    expected == previous_generation,
                    "Fleet expected generation does not match current state"
                );
            }
            if let Some(expected) = request.expected_revision.as_deref() {
                anyhow::ensure!(
                    previous_revision.as_deref() == Some(expected),
                    "Fleet expected revision does not match current state"
                );
            }
            let same_revision_replay = if let Some(current) = &current {
                anyhow::ensure!(
                    generation >= current.generation,
                    "Fleet bundle generation is stale"
                );
                anyhow::ensure!(
                    generation.saturating_sub(current.generation)
                        <= MAX_FLEET_GENERATION_ADVANCE,
                    "Fleet bundle generation advances too far"
                );
                if generation == current.generation {
                    anyhow::ensure!(
                        revision == current.revision,
                        "Fleet generation was already used by another revision"
                    );
                }
                generation == current.generation
            } else {
                anyhow::ensure!(
                    generation <= MAX_FLEET_GENERATION_ADVANCE,
                    "Fleet bundle initial generation is unreasonably high"
                );
                false
            };

            let clients = resolve_bundle_clients(transaction, &request.bundle)?;
            let existing = load_owned_resources(transaction, source_instance_id)?;
            let mut plan = Vec::with_capacity(request.bundle.resources.len());
            let mut conflicts = Vec::new();
            for resource in &request.bundle.resources {
                match plan_resource(
                    transaction,
                    source_instance_id,
                    resource,
                    existing.get(&resource.resource_id),
                    &clients,
                ) {
                    Ok(planned) => plan.push(planned),
                    Err(error) => conflicts.push(FleetConflict {
                        code: "resource_conflict".to_owned(),
                        resource_id: Some(resource.resource_id),
                        message: error.to_string(),
                    }),
                }
            }
            validate_plan(
                transaction,
                &public_port_policy,
                source_instance_id,
                &request.bundle,
                &plan,
                &clients,
                &mut conflicts,
            )?;
            if !conflicts.is_empty() {
                return Ok(FleetReconcileResult {
                    source_instance_id,
                    generation,
                    revision,
                    previous_generation,
                    previous_revision,
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
                });
            }

            let desired_ids = plan
                .iter()
                .map(|resource| resource.resource.resource_id)
                .collect::<HashSet<_>>();
            let obsolete = existing
                .values()
                .filter(|resource| !desired_ids.contains(&resource.resource_id))
                .cloned()
                .collect::<Vec<_>>();
            let created = plan
                .iter()
                .filter(|resource| !existing.contains_key(&resource.resource.resource_id))
                .count();
            let updated = plan
                .iter()
                .filter(|resource| {
                    existing.contains_key(&resource.resource.resource_id)
                        && resource.write_required
                })
                .count();
            let unchanged = plan.len().saturating_sub(created + updated);
            let traffic_controls_unchanged = traffic_controls_match(
                transaction,
                &request.bundle.traffic_controls,
                &plan,
            )?;
            if same_revision_replay
                && created == 0
                && updated == 0
                && obsolete.is_empty()
                && traffic_controls_unchanged
            {
                return Ok(FleetReconcileResult {
                    source_instance_id,
                    generation,
                    revision,
                    previous_generation,
                    previous_revision,
                    dry_run: request.dry_run,
                    applied: false,
                    idempotent: true,
                    created: 0,
                    updated: 0,
                    deleted: 0,
                    unchanged,
                    traffic_controls: request.bundle.traffic_controls.len(),
                    conflicts: Vec::new(),
                    runtime_invalidations: Vec::new(),
                });
            }
            if request.dry_run {
                return Ok(FleetReconcileResult {
                    source_instance_id,
                    generation,
                    revision,
                    previous_generation,
                    previous_revision,
                    dry_run: true,
                    applied: false,
                    idempotent: false,
                    created,
                    updated,
                    deleted: obsolete.len(),
                    unchanged,
                    traffic_controls: request.bundle.traffic_controls.len(),
                    conflicts,
                    runtime_invalidations: Vec::new(),
                });
            }

            let mut runtime_invalidations = Vec::new();
            for old in &obsolete {
                delete_owned_policy(transaction, old, &mut runtime_invalidations)?;
            }
            // 先移除所有发生变化的旧行，再写入新值，允许两个资源在同一事务内交换端口或主机名。
            for planned in &plan {
                if !planned.write_required {
                    continue;
                }
                if let Some(old) = existing.get(&planned.resource.resource_id) {
                    collect_runtime_invalidation(transaction, old, &mut runtime_invalidations)?;
                    delete_policy_row(transaction, old.kind, old.policy_id)?;
                } else if planned.kind.requires_credential() {
                    // 新的密钥型资源会接管预绑定的本地策略；密钥哈希已在计划阶段保存在内存中。
                    delete_policy_row(transaction, planned.kind, planned.policy_id)?;
                }
            }
            for planned in &plan {
                if !planned.write_required {
                    continue;
                }
                upsert_planned_resource(
                    transaction,
                    source_instance_id,
                    planned,
                    &clients,
                    now,
                )?;
            }
            reconcile_traffic_controls(
                transaction,
                source_instance_id,
                &request.bundle.traffic_controls,
                &plan,
                now,
            )?;
            transaction.execute(
                "INSERT INTO fleet_source_states (source_instance_id, generation, revision, applied_unix_seconds, resource_count)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(source_instance_id) DO UPDATE SET generation = excluded.generation, revision = excluded.revision, applied_unix_seconds = excluded.applied_unix_seconds, resource_count = excluded.resource_count",
                params![
                    source_instance_id.to_string(),
                    generation,
                    revision,
                    now,
                    plan.len(),
                ],
            )?;
            Ok(FleetReconcileResult {
                source_instance_id,
                generation,
                revision: request.bundle.revision,
                previous_generation,
                previous_revision,
                dry_run: false,
                applied: true,
                idempotent: false,
                created,
                updated,
                deleted: obsolete.len(),
                unchanged,
                traffic_controls: request.bundle.traffic_controls.len(),
                conflicts,
                runtime_invalidations,
            })
        })
    }
}

fn read_source_status(
    transaction: &Transaction<'_>,
    source_instance_id: Uuid,
) -> anyhow::Result<Option<FleetSourceStatus>> {
    transaction
        .query_row(
            "SELECT generation, revision, applied_unix_seconds, resource_count FROM fleet_source_states WHERE source_instance_id = ?1",
            [source_instance_id.to_string()],
            |row| {
                Ok(FleetSourceStatus {
                    source_instance_id,
                    generation: row.get(0)?,
                    revision: row.get(1)?,
                    applied_unix_seconds: row.get(2)?,
                    resource_count: row.get(3)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
}

fn resolve_bundle_clients(
    transaction: &Transaction<'_>,
    bundle: &FleetBundleV2,
) -> anyhow::Result<HashMap<Uuid, Uuid>> {
    let referenced = bundle
        .resources
        .iter()
        .flat_map(referenced_agent_ids)
        .collect::<HashSet<_>>();
    let bundle_clients = bundle
        .clients
        .iter()
        .map(|client| (client.agent_instance_id, client))
        .collect::<HashMap<_, _>>();
    let mut clients = HashMap::new();
    for agent_instance_id in referenced {
        let client = bundle_clients
            .get(&agent_instance_id)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("Fleet resource references an undeclared client"))?;
        let expected_public_key = client.agent_identity_public_key.as_deref().ok_or_else(|| {
            anyhow::anyhow!("Fleet client identity is not cryptographically verified")
        })?;
        let local: Option<(String, i64, Option<String>)> = transaction
            .query_row(
                "SELECT client_id, enabled, agent_identity_public_key FROM clients WHERE agent_instance_id = ?1",
                [agent_instance_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((local_client_id, enabled, local_public_key)) = local else {
            anyhow::bail!(
                "Fleet client {} ({}) is not enrolled on this server",
                client.name,
                agent_instance_id
            );
        };
        anyhow::ensure!(enabled != 0, "Fleet client {} is disabled", client.name);
        anyhow::ensure!(
            local_public_key.as_deref() == Some(expected_public_key),
            "Fleet client identity public key does not match local enrollment"
        );
        clients.insert(agent_instance_id, Uuid::parse_str(&local_client_id)?);
    }
    Ok(clients)
}

fn load_owned_resources(
    transaction: &Transaction<'_>,
    source_instance_id: Uuid,
) -> anyhow::Result<HashMap<Uuid, OwnedResource>> {
    let mut statement = transaction.prepare(
        "SELECT resource_id, kind, policy_id, resource_sha256, credential_ref FROM fleet_resource_ownership WHERE source_instance_id = ?1",
    )?;
    let rows = statement.query_map([source_instance_id.to_string()], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, Option<String>>(4)?,
        ))
    })?;
    rows.map(|row| {
        let (resource_id, kind, policy_id, resource_sha256, credential_ref) = row?;
        let resource_id = Uuid::parse_str(&resource_id)?;
        Ok((
            resource_id,
            OwnedResource {
                source_instance_id,
                resource_id,
                kind: FleetPolicyKind::parse(&kind)?,
                policy_id: Uuid::parse_str(&policy_id)?,
                resource_sha256,
                credential_ref: credential_ref
                    .map(|value| Uuid::parse_str(&value))
                    .transpose()?,
            },
        ))
    })
    .collect()
}

fn plan_resource(
    transaction: &Transaction<'_>,
    source_instance_id: Uuid,
    resource: &FleetResource,
    existing: Option<&OwnedResource>,
    clients: &HashMap<Uuid, Uuid>,
) -> anyhow::Result<PlannedResource> {
    let kind = resource_kind(resource);
    if let Some(existing) = existing {
        anyhow::ensure!(existing.kind == kind, "Fleet resource kind cannot change");
    }
    let requested_credential = credential_ref(resource);
    let (policy_id, credential_hash) = if let Some(credential_ref) = requested_credential {
        if let Some(existing) = existing {
            anyhow::ensure!(
                existing.credential_ref == Some(credential_ref),
                "Fleet credential reference cannot change"
            );
            let binding =
                credential_binding_policy(transaction, source_instance_id, credential_ref, kind)?;
            anyhow::ensure!(
                binding == Some(existing.policy_id),
                "Fleet credential binding was revoked or changed"
            );
            (
                existing.policy_id,
                Some(read_credential_hash(transaction, kind, existing.policy_id)?),
            )
        } else {
            let policy_id =
                credential_binding_policy(transaction, source_instance_id, credential_ref, kind)?
                    .ok_or_else(|| {
                    anyhow::anyhow!(
                        "credential_ref {credential_ref} is not bound to a local {} policy",
                        kind.as_str()
                    )
                })?;
            (
                policy_id,
                Some(read_credential_hash(transaction, kind, policy_id)?),
            )
        }
    } else {
        let policy_id = if let Some(existing) = existing {
            existing.policy_id
        } else {
            let policy_id = deterministic_policy_id(source_instance_id, resource.resource_id, kind);
            anyhow::ensure!(
                !policy_exists(transaction, kind, policy_id)?,
                "derived local policy ID collides with an existing policy"
            );
            policy_id
        };
        (policy_id, None)
    };
    let resource_sha256 = resource_sha256(resource)?;
    let write_required = existing.is_none_or(|old| old.resource_sha256 != resource_sha256);
    let mut planned = PlannedResource {
        resource: resource.clone(),
        kind,
        policy_id,
        resource_sha256,
        credential_hash,
        write_required,
    };
    if existing.is_some() && !policy_matches_planned(transaction, &planned, clients)? {
        planned.write_required = true;
    }
    Ok(planned)
}

fn credential_binding_policy(
    transaction: &Transaction<'_>,
    source_instance_id: Uuid,
    credential_ref: Uuid,
    kind: FleetPolicyKind,
) -> anyhow::Result<Option<Uuid>> {
    transaction
        .query_row(
            "SELECT policy_id FROM fleet_credential_bindings WHERE source_instance_id = ?1 AND credential_ref = ?2 AND kind = ?3",
            params![
                source_instance_id.to_string(),
                credential_ref.to_string(),
                kind.as_str(),
            ],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .map(|value| Uuid::parse_str(&value).map_err(Into::into))
        .transpose()
}

fn read_credential_hash(
    transaction: &Transaction<'_>,
    kind: FleetPolicyKind,
    policy_id: Uuid,
) -> anyhow::Result<String> {
    let (table, column) = match kind {
        FleetPolicyKind::SecretTunnel => ("secret_tunnel_policies", "access_key_hash"),
        FleetPolicyKind::Socks5Proxy | FleetPolicyKind::HttpProxy => {
            if kind == FleetPolicyKind::Socks5Proxy {
                ("socks5_proxy_policies", "password_hash")
            } else {
                ("http_proxy_policies", "password_hash")
            }
        }
        _ => anyhow::bail!("Fleet resource kind does not carry credentials"),
    };
    transaction
        .query_row(
            &format!("SELECT {column} FROM {table} WHERE id = ?1"),
            [policy_id.to_string()],
            |row| row.get(0),
        )
        .optional()?
        .ok_or_else(|| anyhow::anyhow!("bound Fleet credential policy does not exist"))
}

fn policy_matches_planned(
    transaction: &Transaction<'_>,
    planned: &PlannedResource,
    clients: &HashMap<Uuid, Uuid>,
) -> anyhow::Result<bool> {
    let id = planned.policy_id.to_string();
    let matches = match &planned.resource.spec {
        FleetResourceSpec::Tcp(value) => {
            let client_id = local_client_id(clients, value.agent_instance_id)?.to_string();
            transaction
            .query_row(
                "SELECT client_id, name, public_port, target_addr, max_connections, bandwidth_limit_bps, enabled FROM tcp_tunnel_policies WHERE id = ?1",
                [&id],
                |row| {
                    Ok(row.get::<_, String>(0)? == client_id
                        && row.get::<_, String>(1)? == value.name
                        && row.get::<_, u16>(2)? == value.public_port
                        && row.get::<_, String>(3)? == value.target_addr
                        && row.get::<_, u16>(4)? == value.max_connections
                        && row.get::<_, Option<u64>>(5)? == value.bandwidth_limit_bps
                        && (row.get::<_, i64>(6)? != 0) == planned.resource.enabled)
                },
            )
            .optional()?
            .unwrap_or(false)
        }
        FleetResourceSpec::Udp(value) => {
            let client_id = local_client_id(clients, value.agent_instance_id)?.to_string();
            transaction
            .query_row(
                "SELECT client_id, name, public_port, target_addr, max_sessions, session_idle_timeout_seconds, bandwidth_limit_bps, enabled FROM udp_tunnel_policies WHERE id = ?1",
                [&id],
                |row| {
                    Ok(row.get::<_, String>(0)? == client_id
                        && row.get::<_, String>(1)? == value.name
                        && row.get::<_, u16>(2)? == value.public_port
                        && row.get::<_, String>(3)? == value.target_addr
                        && row.get::<_, u16>(4)? == value.max_sessions
                        && row.get::<_, u32>(5)? == value.session_idle_timeout_seconds
                        && row.get::<_, Option<u64>>(6)? == value.bandwidth_limit_bps
                        && (row.get::<_, i64>(7)? != 0) == planned.resource.enabled)
                },
            )
            .optional()?
            .unwrap_or(false)
        }
        FleetResourceSpec::PortGroup(value) => {
            let client_id = local_client_id(clients, value.agent_instance_id)?.to_string();
            let row_matches = transaction
                .query_row(
                    "SELECT client_id, name, protocol, public_ports, target_host, target_ports, max_connections, max_sessions, session_idle_timeout_seconds, bandwidth_limit_bps, enabled FROM port_group_policies WHERE id = ?1",
                    [&id],
                    |row| {
                        Ok(row.get::<_, String>(0)? == client_id
                            && row.get::<_, String>(1)? == value.name
                            && row.get::<_, String>(2)? == port_group_protocol(value.protocol)
                            && row.get::<_, String>(3)? == value.public_ports
                            && row.get::<_, String>(4)? == value.target_host
                            && row.get::<_, String>(5)? == value.target_ports
                            && row.get::<_, u16>(6)? == value.max_connections
                            && row.get::<_, u16>(7)? == value.max_sessions
                            && row.get::<_, u32>(8)? == value.session_idle_timeout_seconds
                            && row.get::<_, Option<u64>>(9)? == value.bandwidth_limit_bps
                            && (row.get::<_, i64>(10)? != 0) == planned.resource.enabled)
                    },
                )
                .optional()?
                .unwrap_or(false);
            if !row_matches {
                false
            } else {
                let parsed = parse_port_mappings(
                    &value.public_ports,
                    &value.target_ports,
                    1,
                    u16::MAX,
                    MAX_PORT_MAPPINGS,
                )?;
                let expected = parsed
                    .pairs
                    .into_iter()
                    .map(|mapping| {
                        (
                            mapping.public_port,
                            mapping.target_port,
                            target_addr(&value.target_host, mapping.target_port),
                        )
                    })
                    .collect::<Vec<_>>();
                let mut statement = transaction.prepare(
                    "SELECT public_port, target_port, target_addr FROM port_group_mappings WHERE policy_id = ?1 ORDER BY public_port",
                )?;
                let actual = statement
                    .query_map([&id], |row| {
                        Ok((
                            row.get::<_, u16>(0)?,
                            row.get::<_, u16>(1)?,
                            row.get::<_, String>(2)?,
                        ))
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                actual == expected
            }
        }
        FleetResourceSpec::HttpRoute(value) => {
            let client_id = local_client_id(clients, value.agent_instance_id)?.to_string();
            transaction
            .query_row(
                "SELECT client_id, name, hostname, target_addr, max_connections, enabled FROM http_route_policies WHERE id = ?1",
                [&id],
                |row| {
                    Ok(row.get::<_, String>(0)? == client_id
                        && row.get::<_, String>(1)? == value.name
                        && row.get::<_, String>(2)? == value.hostname
                        && row.get::<_, String>(3)? == value.target_addr
                        && row.get::<_, u16>(4)? == value.max_connections
                        && (row.get::<_, i64>(5)? != 0) == planned.resource.enabled)
                },
            )
            .optional()?
            .unwrap_or(false)
        }
        FleetResourceSpec::SniRoute(value) => {
            let client_id = local_client_id(clients, value.agent_instance_id)?.to_string();
            transaction
            .query_row(
                "SELECT client_id, name, hostname, target_addr, max_connections, bandwidth_limit_bps, enabled FROM sni_route_policies WHERE id = ?1",
                [&id],
                |row| {
                    Ok(row.get::<_, String>(0)? == client_id
                        && row.get::<_, String>(1)? == value.name
                        && row.get::<_, String>(2)? == value.hostname
                        && row.get::<_, String>(3)? == value.target_addr
                        && row.get::<_, u16>(4)? == value.max_connections
                        && row.get::<_, Option<u64>>(5)? == value.bandwidth_limit_bps
                        && (row.get::<_, i64>(6)? != 0) == planned.resource.enabled)
                },
            )
            .optional()?
            .unwrap_or(false)
        }
        FleetResourceSpec::SecretTunnel(value) => {
            let provider_id =
                local_client_id(clients, value.provider_agent_instance_id)?.to_string();
            let allowed_id = value
                .allowed_agent_instance_id
                .map(|agent| local_client_id(clients, agent).map(|client| client.to_string()))
                .transpose()?;
            transaction
            .query_row(
                "SELECT provider_client_id, allowed_client_id, name, target_addr, access_key_hash, max_connections, bandwidth_limit_bps, enabled FROM secret_tunnel_policies WHERE id = ?1",
                [&id],
                |row| {
                    Ok(row.get::<_, String>(0)? == provider_id
                        && row.get::<_, Option<String>>(1)? == allowed_id
                        && row.get::<_, String>(2)? == value.name
                        && row.get::<_, String>(3)? == value.target_addr
                        && row.get::<_, String>(4)? == planned.credential_hash.clone().unwrap_or_default()
                        && row.get::<_, u16>(5)? == value.max_connections
                        && row.get::<_, Option<u64>>(6)? == value.bandwidth_limit_bps
                        && (row.get::<_, i64>(7)? != 0) == planned.resource.enabled)
                },
            )
            .optional()?
            .unwrap_or(false)
        }
        FleetResourceSpec::Socks5Proxy(value) => {
            let client_id = local_client_id(clients, value.agent_instance_id)?.to_string();
            transaction
            .query_row(
                "SELECT client_id, name, public_port, username, password_hash, max_connections, bandwidth_limit_bps, enabled FROM socks5_proxy_policies WHERE id = ?1",
                [&id],
                |row| {
                    Ok(row.get::<_, String>(0)? == client_id
                        && row.get::<_, String>(1)? == value.name
                        && row.get::<_, u16>(2)? == value.public_port
                        && row.get::<_, String>(3)? == value.username
                        && row.get::<_, String>(4)? == planned.credential_hash.clone().unwrap_or_default()
                        && row.get::<_, u16>(5)? == value.max_connections
                        && row.get::<_, Option<u64>>(6)? == value.bandwidth_limit_bps
                        && (row.get::<_, i64>(7)? != 0) == planned.resource.enabled)
                },
            )
            .optional()?
            .unwrap_or(false)
        }
        FleetResourceSpec::HttpProxy(value) => {
            let client_id = local_client_id(clients, value.agent_instance_id)?.to_string();
            transaction
            .query_row(
                "SELECT client_id, name, public_port, username, password_hash, max_connections, bandwidth_limit_bps, enabled FROM http_proxy_policies WHERE id = ?1",
                [&id],
                |row| {
                    Ok(row.get::<_, String>(0)? == client_id
                        && row.get::<_, String>(1)? == value.name
                        && row.get::<_, u16>(2)? == value.public_port
                        && row.get::<_, String>(3)? == value.username
                        && row.get::<_, String>(4)? == planned.credential_hash.clone().unwrap_or_default()
                        && row.get::<_, u16>(5)? == value.max_connections
                        && row.get::<_, Option<u64>>(6)? == value.bandwidth_limit_bps
                        && (row.get::<_, i64>(7)? != 0) == planned.resource.enabled)
                },
            )
            .optional()?
            .unwrap_or(false)
        }
    };
    Ok(matches)
}

fn validate_plan(
    transaction: &Transaction<'_>,
    public_port_policy: &PublicPortPolicy,
    source_instance_id: Uuid,
    bundle: &FleetBundleV2,
    plan: &[PlannedResource],
    clients: &HashMap<Uuid, Uuid>,
    conflicts: &mut Vec<FleetConflict>,
) -> anyhow::Result<()> {
    let mut desired_tcp = HashMap::<u16, DesiredEndpoint>::new();
    let mut desired_udp = HashMap::<u16, DesiredEndpoint>::new();
    let mut desired_http = HashMap::<String, DesiredEndpoint>::new();
    let mut desired_sni = HashMap::<String, DesiredEndpoint>::new();
    let mut desired_names = HashSet::<(FleetPolicyKind, Uuid, String)>::new();
    let mut desired_credentials = HashMap::<(FleetPolicyKind, Uuid), Uuid>::new();
    let plan_by_resource = plan
        .iter()
        .map(|planned| (planned.resource.resource_id, planned))
        .collect::<HashMap<_, _>>();

    for planned in plan {
        let resource_id = planned.resource.resource_id;
        if let Some(reference) = credential_ref(&planned.resource) {
            if let Some(other) = desired_credentials.insert((planned.kind, reference), resource_id)
            {
                conflicts.push(FleetConflict {
                    code: "duplicate_credential_ref".to_owned(),
                    resource_id: Some(resource_id),
                    message: format!(
                        "credential_ref {reference} is also used by Fleet resource {other}"
                    ),
                });
            }
        }
        let endpoint = DesiredEndpoint {
            resource_id,
            kind: planned.kind,
            policy_id: planned.policy_id,
        };
        let add_port =
            |ports: &mut HashMap<u16, DesiredEndpoint>, port: u16| -> Result<(), String> {
                if let Some(other) = ports.insert(port, endpoint) {
                    Err(format!(
                        "public port {port} is also requested by Fleet resource {}",
                        other.resource_id
                    ))
                } else {
                    Ok(())
                }
            };
        let validation = match &planned.resource.spec {
            FleetResourceSpec::Tcp(value) => {
                let client = clients.get(&value.agent_instance_id).copied();
                client
                    .ok_or_else(|| "referenced client is not enrolled locally".to_owned())
                    .and_then(|client| {
                        if !public_port_policy.allows_tcp(value.public_port) {
                            Err("TCP public port is outside the server policy".to_owned())
                        } else if !desired_names.insert((planned.kind, client, value.name.clone()))
                        {
                            Err("duplicate Fleet TCP name for the same client".to_owned())
                        } else {
                            add_port(&mut desired_tcp, value.public_port)
                        }
                    })
            }
            FleetResourceSpec::Udp(value) => {
                let client = clients.get(&value.agent_instance_id).copied();
                client
                    .ok_or_else(|| "referenced client is not enrolled locally".to_owned())
                    .and_then(|client| {
                        if !public_port_policy.allows_udp(value.public_port) {
                            Err("UDP public port is outside the server policy".to_owned())
                        } else if !desired_names.insert((planned.kind, client, value.name.clone()))
                        {
                            Err("duplicate Fleet UDP name for the same client".to_owned())
                        } else {
                            add_port(&mut desired_udp, value.public_port)
                        }
                    })
            }
            FleetResourceSpec::PortGroup(value) => {
                let client = clients.get(&value.agent_instance_id).copied();
                client
                    .ok_or_else(|| "referenced client is not enrolled locally".to_owned())
                    .and_then(|client| {
                        if !desired_names.insert((
                            planned.kind,
                            client,
                            format!("{}:{}", port_group_protocol(value.protocol), value.name),
                        )) {
                            return Err(
                                "duplicate Fleet port-group name for the same client".to_owned()
                            );
                        }
                        let parsed = parse_port_mappings(
                            &value.public_ports,
                            &value.target_ports,
                            1,
                            u16::MAX,
                            MAX_PORT_MAPPINGS,
                        )
                        .map_err(|error| format!("invalid port-group mapping: {error}"))?;
                        for mapping in parsed.pairs {
                            let allowed = match value.protocol {
                                FleetPortGroupProtocol::Tcp => {
                                    public_port_policy.allows_tcp(mapping.public_port)
                                }
                                FleetPortGroupProtocol::Udp => {
                                    public_port_policy.allows_udp(mapping.public_port)
                                }
                            };
                            if !allowed {
                                return Err(format!(
                                    "port-group public port {} is outside the server policy",
                                    mapping.public_port
                                ));
                            }
                            match value.protocol {
                                FleetPortGroupProtocol::Tcp => {
                                    add_port(&mut desired_tcp, mapping.public_port)?
                                }
                                FleetPortGroupProtocol::Udp => {
                                    add_port(&mut desired_udp, mapping.public_port)?
                                }
                            }
                        }
                        Ok(())
                    })
            }
            FleetResourceSpec::HttpRoute(value) => clients
                .get(&value.agent_instance_id)
                .copied()
                .ok_or_else(|| "referenced client is not enrolled locally".to_owned())
                .and_then(|client| {
                    if !desired_names.insert((planned.kind, client, value.name.clone())) {
                        return Err("duplicate Fleet HTTP route name".to_owned());
                    }
                    if let Some(other) =
                        desired_http.insert(value.hostname.to_ascii_lowercase(), endpoint)
                    {
                        Err(format!(
                            "HTTP hostname {} is also requested by Fleet resource {}",
                            value.hostname, other.resource_id
                        ))
                    } else {
                        Ok(())
                    }
                }),
            FleetResourceSpec::SniRoute(value) => clients
                .get(&value.agent_instance_id)
                .copied()
                .ok_or_else(|| "referenced client is not enrolled locally".to_owned())
                .and_then(|client| {
                    if !desired_names.insert((planned.kind, client, value.name.clone())) {
                        return Err("duplicate Fleet SNI route name".to_owned());
                    }
                    if let Some(other) =
                        desired_sni.insert(value.hostname.to_ascii_lowercase(), endpoint)
                    {
                        Err(format!(
                            "SNI hostname {} is also requested by Fleet resource {}",
                            value.hostname, other.resource_id
                        ))
                    } else {
                        Ok(())
                    }
                }),
            FleetResourceSpec::SecretTunnel(value) => {
                let provider = clients.get(&value.provider_agent_instance_id).copied();
                let allowed = value
                    .allowed_agent_instance_id
                    .map(|agent| clients.get(&agent).copied());
                if provider.is_none() || allowed.is_some_and(|client| client.is_none()) {
                    Err("referenced secret-tunnel client is not enrolled locally".to_owned())
                } else if !desired_names.insert((
                    planned.kind,
                    provider.expect("provider checked"),
                    value.name.clone(),
                )) {
                    Err("duplicate Fleet secret-tunnel name".to_owned())
                } else {
                    Ok(())
                }
            }
            FleetResourceSpec::Socks5Proxy(value) => clients
                .get(&value.agent_instance_id)
                .copied()
                .ok_or_else(|| "referenced client is not enrolled locally".to_owned())
                .and_then(|client| {
                    if !public_port_policy.allows_tcp(value.public_port) {
                        Err("SOCKS5 public port is outside the server policy".to_owned())
                    } else if !desired_names.insert((planned.kind, client, value.name.clone())) {
                        Err("duplicate Fleet SOCKS5 name".to_owned())
                    } else {
                        add_port(&mut desired_tcp, value.public_port)
                    }
                }),
            FleetResourceSpec::HttpProxy(value) => clients
                .get(&value.agent_instance_id)
                .copied()
                .ok_or_else(|| "referenced client is not enrolled locally".to_owned())
                .and_then(|client| {
                    if !public_port_policy.allows_tcp(value.public_port) {
                        Err("HTTP proxy public port is outside the server policy".to_owned())
                    } else if !desired_names.insert((planned.kind, client, value.name.clone())) {
                        Err("duplicate Fleet HTTP proxy name".to_owned())
                    } else {
                        add_port(&mut desired_tcp, value.public_port)
                    }
                }),
        };
        if let Err(message) = validation {
            conflicts.push(FleetConflict {
                code: "invalid_resource".to_owned(),
                resource_id: Some(resource_id),
                message,
            });
        }
    }

    for control in &bundle.traffic_controls {
        if !plan_by_resource.contains_key(&control.resource_id) {
            conflicts.push(FleetConflict {
                code: "unknown_traffic_control_resource".to_owned(),
                resource_id: Some(control.resource_id),
                message: "traffic control references a missing Fleet resource".to_owned(),
            });
        }
    }

    validate_local_tcp_conflicts(transaction, source_instance_id, &desired_tcp, conflicts)?;
    validate_local_udp_conflicts(transaction, source_instance_id, &desired_udp, conflicts)?;
    validate_local_hostname_conflicts(
        transaction,
        source_instance_id,
        "http_route_policies",
        FleetPolicyKind::HttpRoute,
        &desired_http,
        conflicts,
    )?;
    validate_local_hostname_conflicts(
        transaction,
        source_instance_id,
        "sni_route_policies",
        FleetPolicyKind::SniRoute,
        &desired_sni,
        conflicts,
    )?;
    Ok(())
}

fn port_group_protocol(protocol: FleetPortGroupProtocol) -> &'static str {
    match protocol {
        FleetPortGroupProtocol::Tcp => "tcp",
        FleetPortGroupProtocol::Udp => "udp",
    }
}

fn validate_local_tcp_conflicts(
    transaction: &Transaction<'_>,
    source_instance_id: Uuid,
    desired: &HashMap<u16, DesiredEndpoint>,
    conflicts: &mut Vec<FleetConflict>,
) -> anyhow::Result<()> {
    let occupants = load_public_ports(transaction, true)?;
    for (port, endpoint) in desired {
        let used = occupants.iter().any(|(kind, policy_id, occupied_port)| {
            occupied_port == port
                && !(*kind == endpoint.kind && *policy_id == endpoint.policy_id)
                && !is_owned_by_source(transaction, source_instance_id, *kind, *policy_id)
                    .unwrap_or(false)
        });
        if used {
            conflicts.push(FleetConflict {
                code: "tcp_port_in_use".to_owned(),
                resource_id: Some(endpoint.resource_id),
                message: format!("TCP public port {port} is already in use"),
            });
        }
    }
    Ok(())
}

fn validate_local_udp_conflicts(
    transaction: &Transaction<'_>,
    source_instance_id: Uuid,
    desired: &HashMap<u16, DesiredEndpoint>,
    conflicts: &mut Vec<FleetConflict>,
) -> anyhow::Result<()> {
    let occupants = load_public_ports(transaction, false)?;
    for (port, endpoint) in desired {
        let used = occupants.iter().any(|(kind, policy_id, occupied_port)| {
            occupied_port == port
                && !(*kind == endpoint.kind && *policy_id == endpoint.policy_id)
                && !is_owned_by_source(transaction, source_instance_id, *kind, *policy_id)
                    .unwrap_or(false)
        });
        if used {
            conflicts.push(FleetConflict {
                code: "udp_port_in_use".to_owned(),
                resource_id: Some(endpoint.resource_id),
                message: format!("UDP public port {port} is already in use"),
            });
        }
    }
    Ok(())
}

fn validate_local_hostname_conflicts(
    transaction: &Transaction<'_>,
    source_instance_id: Uuid,
    table: &str,
    kind: FleetPolicyKind,
    desired: &HashMap<String, DesiredEndpoint>,
    conflicts: &mut Vec<FleetConflict>,
) -> anyhow::Result<()> {
    for (hostname, endpoint) in desired {
        let occupant: Option<String> = transaction
            .query_row(
                &format!("SELECT id FROM {table} WHERE hostname = ?1"),
                [hostname],
                |row| row.get(0),
            )
            .optional()?;
        let used = occupant
            .map(|value| Uuid::parse_str(&value))
            .transpose()?
            .is_some_and(|policy_id| {
                policy_id != endpoint.policy_id
                    && !is_owned_by_source(transaction, source_instance_id, kind, policy_id)
                        .unwrap_or(false)
            });
        if used {
            conflicts.push(FleetConflict {
                code: "hostname_in_use".to_owned(),
                resource_id: Some(endpoint.resource_id),
                message: format!("hostname {hostname} is already in use"),
            });
        }
    }
    Ok(())
}

fn is_owned_by_source(
    transaction: &Transaction<'_>,
    source_instance_id: Uuid,
    kind: FleetPolicyKind,
    policy_id: Uuid,
) -> anyhow::Result<bool> {
    Ok(transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM fleet_resource_ownership WHERE source_instance_id = ?1 AND kind = ?2 AND policy_id = ?3)",
        params![
            source_instance_id.to_string(),
            kind.as_str(),
            policy_id.to_string(),
        ],
        |row| row.get(0),
    )?)
}

fn load_public_ports(
    transaction: &Transaction<'_>,
    tcp: bool,
) -> anyhow::Result<Vec<(FleetPolicyKind, Uuid, u16)>> {
    let queries = if tcp {
        vec![
            (
                FleetPolicyKind::Tcp,
                "SELECT id, public_port FROM tcp_tunnel_policies",
            ),
            (
                FleetPolicyKind::Socks5Proxy,
                "SELECT id, public_port FROM socks5_proxy_policies",
            ),
            (
                FleetPolicyKind::HttpProxy,
                "SELECT id, public_port FROM http_proxy_policies",
            ),
            (
                FleetPolicyKind::PortGroup,
                "SELECT policy_id, public_port FROM port_group_mappings WHERE protocol = 'tcp'",
            ),
        ]
    } else {
        vec![
            (
                FleetPolicyKind::Udp,
                "SELECT id, public_port FROM udp_tunnel_policies",
            ),
            (
                FleetPolicyKind::PortGroup,
                "SELECT policy_id, public_port FROM port_group_mappings WHERE protocol = 'udp'",
            ),
        ]
    };
    let mut ports = Vec::new();
    for (kind, sql) in queries {
        let mut statement = transaction.prepare(sql)?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, u16>(1)?))
        })?;
        for row in rows {
            let (policy_id, port) = row?;
            ports.push((kind, Uuid::parse_str(&policy_id)?, port));
        }
    }
    Ok(ports)
}

fn policy_exists(
    transaction: &Transaction<'_>,
    kind: FleetPolicyKind,
    policy_id: Uuid,
) -> anyhow::Result<bool> {
    let sql = match kind {
        FleetPolicyKind::Tcp => "SELECT EXISTS(SELECT 1 FROM tcp_tunnel_policies WHERE id = ?1)",
        FleetPolicyKind::Udp => "SELECT EXISTS(SELECT 1 FROM udp_tunnel_policies WHERE id = ?1)",
        FleetPolicyKind::PortGroup => {
            "SELECT EXISTS(SELECT 1 FROM port_group_policies WHERE id = ?1)"
        }
        FleetPolicyKind::HttpRoute => {
            "SELECT EXISTS(SELECT 1 FROM http_route_policies WHERE id = ?1)"
        }
        FleetPolicyKind::SniRoute => {
            "SELECT EXISTS(SELECT 1 FROM sni_route_policies WHERE id = ?1)"
        }
        FleetPolicyKind::SecretTunnel => {
            "SELECT EXISTS(SELECT 1 FROM secret_tunnel_policies WHERE id = ?1)"
        }
        FleetPolicyKind::Socks5Proxy => {
            "SELECT EXISTS(SELECT 1 FROM socks5_proxy_policies WHERE id = ?1)"
        }
        FleetPolicyKind::HttpProxy => {
            "SELECT EXISTS(SELECT 1 FROM http_proxy_policies WHERE id = ?1)"
        }
    };
    Ok(transaction.query_row(sql, [policy_id.to_string()], |row| row.get(0))?)
}

fn delete_policy_row(
    transaction: &Transaction<'_>,
    kind: FleetPolicyKind,
    policy_id: Uuid,
) -> anyhow::Result<()> {
    if kind == FleetPolicyKind::PortGroup {
        transaction.execute(
            "DELETE FROM port_group_mappings WHERE policy_id = ?1",
            [policy_id.to_string()],
        )?;
    }
    let sql = match kind {
        FleetPolicyKind::Tcp => "DELETE FROM tcp_tunnel_policies WHERE id = ?1",
        FleetPolicyKind::Udp => "DELETE FROM udp_tunnel_policies WHERE id = ?1",
        FleetPolicyKind::PortGroup => "DELETE FROM port_group_policies WHERE id = ?1",
        FleetPolicyKind::HttpRoute => "DELETE FROM http_route_policies WHERE id = ?1",
        FleetPolicyKind::SniRoute => "DELETE FROM sni_route_policies WHERE id = ?1",
        FleetPolicyKind::SecretTunnel => "DELETE FROM secret_tunnel_policies WHERE id = ?1",
        FleetPolicyKind::Socks5Proxy => "DELETE FROM socks5_proxy_policies WHERE id = ?1",
        FleetPolicyKind::HttpProxy => "DELETE FROM http_proxy_policies WHERE id = ?1",
    };
    transaction.execute(sql, [policy_id.to_string()])?;
    Ok(())
}

fn collect_runtime_invalidation(
    transaction: &Transaction<'_>,
    owned: &OwnedResource,
    invalidations: &mut Vec<FleetRuntimeInvalidation>,
) -> anyhow::Result<()> {
    match owned.kind {
        FleetPolicyKind::Tcp => {
            if let Some(port) = transaction
                .query_row(
                    "SELECT public_port FROM tcp_tunnel_policies WHERE id = ?1",
                    [owned.policy_id.to_string()],
                    |row| row.get(0),
                )
                .optional()?
            {
                invalidations.push(FleetRuntimeInvalidation::TcpPort(port));
            }
        }
        FleetPolicyKind::Udp => {
            if let Some(port) = transaction
                .query_row(
                    "SELECT public_port FROM udp_tunnel_policies WHERE id = ?1",
                    [owned.policy_id.to_string()],
                    |row| row.get(0),
                )
                .optional()?
            {
                invalidations.push(FleetRuntimeInvalidation::UdpPort(port));
            }
        }
        FleetPolicyKind::PortGroup => {
            let protocol: Option<String> = transaction
                .query_row(
                    "SELECT protocol FROM port_group_policies WHERE id = ?1",
                    [owned.policy_id.to_string()],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(protocol) = protocol {
                let mut statement = transaction
                    .prepare("SELECT public_port FROM port_group_mappings WHERE policy_id = ?1")?;
                let ports = statement
                    .query_map([owned.policy_id.to_string()], |row| row.get::<_, u16>(0))?;
                for port in ports {
                    invalidations.push(if protocol == "tcp" {
                        FleetRuntimeInvalidation::TcpPort(port?)
                    } else {
                        FleetRuntimeInvalidation::UdpPort(port?)
                    });
                }
            }
        }
        FleetPolicyKind::HttpRoute => {
            if let Some(hostname) = transaction
                .query_row(
                    "SELECT hostname FROM http_route_policies WHERE id = ?1",
                    [owned.policy_id.to_string()],
                    |row| row.get(0),
                )
                .optional()?
            {
                invalidations.push(FleetRuntimeInvalidation::HttpHostname(hostname));
            }
        }
        FleetPolicyKind::SniRoute => {
            if let Some(hostname) = transaction
                .query_row(
                    "SELECT hostname FROM sni_route_policies WHERE id = ?1",
                    [owned.policy_id.to_string()],
                    |row| row.get(0),
                )
                .optional()?
            {
                invalidations.push(FleetRuntimeInvalidation::SniHostname(hostname));
            }
        }
        FleetPolicyKind::SecretTunnel => {
            invalidations.push(FleetRuntimeInvalidation::SecretTunnel(owned.policy_id))
        }
        FleetPolicyKind::Socks5Proxy => {
            invalidations.push(FleetRuntimeInvalidation::Socks5Proxy(owned.policy_id))
        }
        FleetPolicyKind::HttpProxy => {
            invalidations.push(FleetRuntimeInvalidation::HttpProxy(owned.policy_id))
        }
    }
    Ok(())
}

fn delete_owned_policy(
    transaction: &Transaction<'_>,
    owned: &OwnedResource,
    invalidations: &mut Vec<FleetRuntimeInvalidation>,
) -> anyhow::Result<()> {
    collect_runtime_invalidation(transaction, owned, invalidations)?;
    delete_policy_row(transaction, owned.kind, owned.policy_id)?;
    transaction.execute(
        "DELETE FROM traffic_controls WHERE kind = ?1 AND policy_id = ?2",
        params![owned.kind.traffic_kind(), owned.policy_id.to_string()],
    )?;
    transaction.execute(
        "DELETE FROM traffic_daily_usage WHERE kind = ?1 AND policy_id = ?2",
        params![owned.kind.traffic_kind(), owned.policy_id.to_string()],
    )?;
    transaction.execute(
        "DELETE FROM fleet_credential_bindings WHERE source_instance_id = ?1 AND kind = ?2 AND policy_id = ?3",
        params![
            owned.source_instance_id.to_string(),
            owned.kind.as_str(),
            owned.policy_id.to_string(),
        ],
    )?;
    transaction.execute(
        "DELETE FROM fleet_resource_ownership WHERE source_instance_id = ?1 AND resource_id = ?2",
        params![
            owned.source_instance_id.to_string(),
            owned.resource_id.to_string(),
        ],
    )?;
    Ok(())
}

fn local_client_id(clients: &HashMap<Uuid, Uuid>, agent: Uuid) -> anyhow::Result<Uuid> {
    clients
        .get(&agent)
        .copied()
        .ok_or_else(|| anyhow::anyhow!("Fleet resource references an unavailable client"))
}

fn upsert_planned_resource(
    transaction: &Transaction<'_>,
    source_instance_id: Uuid,
    planned: &PlannedResource,
    clients: &HashMap<Uuid, Uuid>,
    _now: u64,
) -> anyhow::Result<()> {
    let id = planned.policy_id.to_string();
    match &planned.resource.spec {
        FleetResourceSpec::Tcp(value) => {
            transaction.execute(
                "INSERT INTO tcp_tunnel_policies (id, client_id, name, public_port, target_addr, max_connections, bandwidth_limit_bps, enabled) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    id,
                    local_client_id(clients, value.agent_instance_id)?.to_string(),
                    value.name,
                    value.public_port,
                    value.target_addr,
                    value.max_connections,
                    value.bandwidth_limit_bps,
                    planned.resource.enabled,
                ],
            )?;
        }
        FleetResourceSpec::Udp(value) => {
            transaction.execute(
                "INSERT INTO udp_tunnel_policies (id, client_id, name, public_port, target_addr, max_sessions, session_idle_timeout_seconds, bandwidth_limit_bps, enabled) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    id,
                    local_client_id(clients, value.agent_instance_id)?.to_string(),
                    value.name,
                    value.public_port,
                    value.target_addr,
                    value.max_sessions,
                    value.session_idle_timeout_seconds,
                    value.bandwidth_limit_bps,
                    planned.resource.enabled,
                ],
            )?;
        }
        FleetResourceSpec::PortGroup(value) => {
            let parsed = parse_port_mappings(
                &value.public_ports,
                &value.target_ports,
                1,
                u16::MAX,
                MAX_PORT_MAPPINGS,
            )?;
            let protocol = port_group_protocol(value.protocol);
            transaction.execute(
                "INSERT INTO port_group_policies (id, client_id, name, protocol, public_ports, target_host, target_ports, mapping_count, max_connections, max_sessions, session_idle_timeout_seconds, bandwidth_limit_bps, enabled) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    id,
                    local_client_id(clients, value.agent_instance_id)?.to_string(),
                    value.name,
                    protocol,
                    value.public_ports,
                    value.target_host,
                    value.target_ports,
                    parsed.pairs.len(),
                    value.max_connections,
                    value.max_sessions,
                    value.session_idle_timeout_seconds,
                    value.bandwidth_limit_bps,
                    planned.resource.enabled,
                ],
            )?;
            for mapping in parsed.pairs {
                transaction.execute(
                    "INSERT INTO port_group_mappings (policy_id, protocol, public_port, target_port, target_addr) VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        planned.policy_id.to_string(),
                        protocol,
                        mapping.public_port,
                        mapping.target_port,
                        target_addr(&value.target_host, mapping.target_port),
                    ],
                )?;
            }
        }
        FleetResourceSpec::HttpRoute(value) => {
            transaction.execute(
                "INSERT INTO http_route_policies (id, client_id, name, hostname, target_addr, max_connections, enabled) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    id,
                    local_client_id(clients, value.agent_instance_id)?.to_string(),
                    value.name,
                    value.hostname,
                    value.target_addr,
                    value.max_connections,
                    planned.resource.enabled,
                ],
            )?;
        }
        FleetResourceSpec::SniRoute(value) => {
            transaction.execute(
                "INSERT INTO sni_route_policies (id, client_id, name, hostname, target_addr, max_connections, bandwidth_limit_bps, enabled) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    id,
                    local_client_id(clients, value.agent_instance_id)?.to_string(),
                    value.name,
                    value.hostname,
                    value.target_addr,
                    value.max_connections,
                    value.bandwidth_limit_bps,
                    planned.resource.enabled,
                ],
            )?;
        }
        FleetResourceSpec::SecretTunnel(value) => {
            transaction.execute(
                "INSERT INTO secret_tunnel_policies (id, provider_client_id, allowed_client_id, name, target_addr, access_key_hash, max_connections, bandwidth_limit_bps, enabled) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    id,
                    local_client_id(clients, value.provider_agent_instance_id)?.to_string(),
                    value
                        .allowed_agent_instance_id
                        .map(|agent| local_client_id(clients, agent).map(|value| value.to_string()))
                        .transpose()?,
                    value.name,
                    value.target_addr,
                    planned
                        .credential_hash
                        .as_deref()
                        .ok_or_else(|| anyhow::anyhow!("Fleet secret credential is unavailable"))?,
                    value.max_connections,
                    value.bandwidth_limit_bps,
                    planned.resource.enabled,
                ],
            )?;
        }
        FleetResourceSpec::Socks5Proxy(value) => {
            transaction.execute(
                "INSERT INTO socks5_proxy_policies (id, client_id, name, public_port, username, password_hash, max_connections, bandwidth_limit_bps, enabled) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    id,
                    local_client_id(clients, value.agent_instance_id)?.to_string(),
                    value.name,
                    value.public_port,
                    value.username,
                    planned
                        .credential_hash
                        .as_deref()
                        .ok_or_else(|| anyhow::anyhow!("Fleet SOCKS5 credential is unavailable"))?,
                    value.max_connections,
                    value.bandwidth_limit_bps,
                    planned.resource.enabled,
                ],
            )?;
        }
        FleetResourceSpec::HttpProxy(value) => {
            transaction.execute(
                "INSERT INTO http_proxy_policies (id, client_id, name, public_port, username, password_hash, max_connections, bandwidth_limit_bps, enabled) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    id,
                    local_client_id(clients, value.agent_instance_id)?.to_string(),
                    value.name,
                    value.public_port,
                    value.username,
                    planned
                        .credential_hash
                        .as_deref()
                        .ok_or_else(|| anyhow::anyhow!("Fleet HTTP proxy credential is unavailable"))?,
                    value.max_connections,
                    value.bandwidth_limit_bps,
                    planned.resource.enabled,
                ],
            )?;
        }
    }
    transaction.execute(
        "INSERT INTO fleet_resource_ownership (source_instance_id, resource_id, kind, policy_id, resource_sha256, credential_ref)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(source_instance_id, resource_id) DO UPDATE SET kind = excluded.kind, policy_id = excluded.policy_id, resource_sha256 = excluded.resource_sha256, credential_ref = excluded.credential_ref",
        params![
            source_instance_id.to_string(),
            planned.resource.resource_id.to_string(),
            planned.kind.as_str(),
            planned.policy_id.to_string(),
            planned.resource_sha256,
            credential_ref(&planned.resource).map(|value| value.to_string()),
        ],
    )?;
    Ok(())
}

fn reconcile_traffic_controls(
    transaction: &Transaction<'_>,
    source_instance_id: Uuid,
    controls: &[FleetTrafficControl],
    plan: &[PlannedResource],
    now: u64,
) -> anyhow::Result<()> {
    let by_resource = plan
        .iter()
        .map(|resource| (resource.resource.resource_id, resource))
        .collect::<HashMap<_, _>>();
    for resource in plan {
        transaction.execute(
            "DELETE FROM traffic_controls WHERE kind = ?1 AND policy_id = ?2",
            params![resource.kind.traffic_kind(), resource.policy_id.to_string()],
        )?;
    }
    for control in controls {
        let planned = by_resource.get(&control.resource_id).ok_or_else(|| {
            anyhow::anyhow!("Fleet traffic control references a missing planned resource")
        })?;
        transaction.execute(
            "INSERT INTO traffic_controls (kind, policy_id, allowed_cidrs, denied_cidrs, max_connections_per_minute, daily_quota_bytes, active_weekdays_utc, start_minute_utc, end_minute_utc, enabled, updated_unix_seconds)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                planned.kind.traffic_kind(),
                planned.policy_id.to_string(),
                serde_json::to_string(&control.allowed_cidrs)?,
                serde_json::to_string(&control.denied_cidrs)?,
                control.max_connections_per_minute,
                control.daily_quota_bytes,
                serde_json::to_string(&control.active_weekdays_utc)?,
                control.start_minute_utc,
                control.end_minute_utc,
                control.enabled,
                now,
            ],
        )?;
    }
    let _ = source_instance_id;
    Ok(())
}

fn traffic_controls_match(
    transaction: &Transaction<'_>,
    controls: &[FleetTrafficControl],
    plan: &[PlannedResource],
) -> anyhow::Result<bool> {
    let desired = controls
        .iter()
        .map(|control| (control.resource_id, control))
        .collect::<HashMap<_, _>>();
    for resource in plan {
        let stored: Option<StoredTrafficControl> = transaction
            .query_row(
                "SELECT allowed_cidrs, denied_cidrs, max_connections_per_minute, daily_quota_bytes, active_weekdays_utc, start_minute_utc, end_minute_utc, enabled FROM traffic_controls WHERE kind = ?1 AND policy_id = ?2",
                params![resource.kind.traffic_kind(), resource.policy_id.to_string()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                    ))
                },
            )
            .optional()?;
        let Some(control) = desired.get(&resource.resource.resource_id).copied() else {
            if stored.is_some() {
                return Ok(false);
            }
            continue;
        };
        let Some((allowed, denied, rate, quota, weekdays, start, end, enabled)) = stored else {
            return Ok(false);
        };
        if serde_json::from_str::<Vec<String>>(&allowed)? != control.allowed_cidrs
            || serde_json::from_str::<Vec<String>>(&denied)? != control.denied_cidrs
            || rate != control.max_connections_per_minute
            || quota != control.daily_quota_bytes
            || serde_json::from_str::<Vec<u8>>(&weekdays)? != control.active_weekdays_utc
            || start != control.start_minute_utc
            || end != control.end_minute_utc
            || (enabled != 0) != control.enabled
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn reserve_generation(transaction: &Transaction<'_>) -> anyhow::Result<(Uuid, u64)> {
    let (source, generation): (String, u64) = transaction.query_row(
        "SELECT source_instance_id, generation FROM fleet_local_state WHERE singleton_id = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let generation = generation
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("Fleet generation is exhausted"))?;
    transaction.execute(
        "UPDATE fleet_local_state SET generation = ?1 WHERE singleton_id = 1",
        [generation],
    )?;
    Ok((Uuid::parse_str(&source)?, generation))
}

fn load_fleet_clients(
    transaction: &Transaction<'_>,
) -> anyhow::Result<Vec<(Uuid, linklake_core::fleet_protocol::FleetClientRef)>> {
    let mut statement = transaction.prepare(
        "SELECT client_id, agent_instance_id, name, agent_identity_public_key FROM clients WHERE enabled = 1 AND agent_identity_public_key IS NOT NULL ORDER BY agent_instance_id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        ))
    })?;
    rows.map(|row| {
        let (client, agent, name, public_key) = row?;
        Ok((
            Uuid::parse_str(&client)?,
            linklake_core::fleet_protocol::FleetClientRef {
                agent_instance_id: Uuid::parse_str(&agent)?,
                name,
                agent_identity_public_key: Some(public_key),
            },
        ))
    })
    .collect()
}

fn excluded_local_policies(
    transaction: &Transaction<'_>,
) -> anyhow::Result<HashSet<(FleetPolicyKind, Uuid)>> {
    let mut excluded = HashSet::new();
    let mut ownership =
        transaction.prepare("SELECT kind, policy_id FROM fleet_resource_ownership")?;
    let rows = ownership.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    for row in rows {
        let (kind, policy) = row?;
        excluded.insert((FleetPolicyKind::parse(&kind)?, Uuid::parse_str(&policy)?));
    }
    drop(ownership);
    let mut bindings =
        transaction.prepare("SELECT kind, policy_id FROM fleet_credential_bindings")?;
    let rows = bindings.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    for row in rows {
        let (kind, policy) = row?;
        excluded.insert((FleetPolicyKind::parse(&kind)?, Uuid::parse_str(&policy)?));
    }
    Ok(excluded)
}

fn export_resources(
    transaction: &Transaction<'_>,
    agents: &HashMap<Uuid, Uuid>,
    excluded: &HashSet<(FleetPolicyKind, Uuid)>,
) -> anyhow::Result<Vec<FleetResource>> {
    let mut resources = Vec::new();

    let mut statement = transaction.prepare(
        "SELECT id, client_id, name, public_port, target_addr, max_connections, bandwidth_limit_bps, enabled FROM tcp_tunnel_policies",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, u16>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, u16>(5)?,
            row.get::<_, Option<u64>>(6)?,
            row.get::<_, i64>(7)? != 0,
        ))
    })?;
    for row in rows {
        let (id, client, name, port, target, limit, bandwidth, enabled) = row?;
        let id = Uuid::parse_str(&id)?;
        if excluded.contains(&(FleetPolicyKind::Tcp, id)) {
            continue;
        }
        let Some(client) = agents.get(&Uuid::parse_str(&client)?).copied() else {
            continue;
        };
        resources.push(FleetResource {
            resource_id: id,
            enabled,
            spec: FleetResourceSpec::Tcp(FleetTcpResource {
                agent_instance_id: client,
                name,
                public_port: port,
                target_addr: target,
                max_connections: limit,
                bandwidth_limit_bps: bandwidth,
            }),
        });
    }
    drop(statement);

    let mut statement = transaction.prepare(
        "SELECT id, client_id, name, public_port, target_addr, max_sessions, session_idle_timeout_seconds, bandwidth_limit_bps, enabled FROM udp_tunnel_policies",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, u16>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, u16>(5)?,
            row.get::<_, u32>(6)?,
            row.get::<_, Option<u64>>(7)?,
            row.get::<_, i64>(8)? != 0,
        ))
    })?;
    for row in rows {
        let (id, client, name, port, target, sessions, idle, bandwidth, enabled) = row?;
        let id = Uuid::parse_str(&id)?;
        if excluded.contains(&(FleetPolicyKind::Udp, id)) {
            continue;
        }
        let Some(client) = agents.get(&Uuid::parse_str(&client)?).copied() else {
            continue;
        };
        resources.push(FleetResource {
            resource_id: id,
            enabled,
            spec: FleetResourceSpec::Udp(FleetUdpResource {
                agent_instance_id: client,
                name,
                public_port: port,
                target_addr: target,
                max_sessions: sessions,
                session_idle_timeout_seconds: idle,
                bandwidth_limit_bps: bandwidth,
            }),
        });
    }
    drop(statement);

    let mut statement = transaction.prepare(
        "SELECT id, client_id, name, protocol, public_ports, target_host, target_ports, max_connections, max_sessions, session_idle_timeout_seconds, bandwidth_limit_bps, enabled FROM port_group_policies",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, u16>(7)?,
            row.get::<_, u16>(8)?,
            row.get::<_, u32>(9)?,
            row.get::<_, Option<u64>>(10)?,
            row.get::<_, i64>(11)? != 0,
        ))
    })?;
    for row in rows {
        let (
            id,
            client,
            name,
            protocol,
            public_ports,
            target_host,
            target_ports,
            max_connections,
            max_sessions,
            idle,
            bandwidth,
            enabled,
        ) = row?;
        let id = Uuid::parse_str(&id)?;
        if excluded.contains(&(FleetPolicyKind::PortGroup, id)) {
            continue;
        }
        let Some(client) = agents.get(&Uuid::parse_str(&client)?).copied() else {
            continue;
        };
        resources.push(FleetResource {
            resource_id: id,
            enabled,
            spec: FleetResourceSpec::PortGroup(FleetPortGroupResource {
                agent_instance_id: client,
                name,
                protocol: match protocol.as_str() {
                    "tcp" => FleetPortGroupProtocol::Tcp,
                    "udp" => FleetPortGroupProtocol::Udp,
                    _ => anyhow::bail!("local port-group protocol is invalid"),
                },
                public_ports,
                target_host,
                target_ports,
                max_connections,
                max_sessions,
                session_idle_timeout_seconds: idle,
                bandwidth_limit_bps: bandwidth,
            }),
        });
    }
    drop(statement);

    let mut statement = transaction.prepare(
        "SELECT id, client_id, name, hostname, target_addr, max_connections, enabled FROM http_route_policies",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, u16>(5)?,
            row.get::<_, i64>(6)? != 0,
        ))
    })?;
    for row in rows {
        let (id, client, name, hostname, target, limit, enabled) = row?;
        let id = Uuid::parse_str(&id)?;
        if excluded.contains(&(FleetPolicyKind::HttpRoute, id)) {
            continue;
        }
        let Some(client) = agents.get(&Uuid::parse_str(&client)?).copied() else {
            continue;
        };
        resources.push(FleetResource {
            resource_id: id,
            enabled,
            spec: FleetResourceSpec::HttpRoute(FleetHttpRouteResource {
                agent_instance_id: client,
                name,
                hostname,
                target_addr: target,
                max_connections: limit,
            }),
        });
    }
    drop(statement);

    let mut statement = transaction.prepare(
        "SELECT id, client_id, name, hostname, target_addr, max_connections, bandwidth_limit_bps, enabled FROM sni_route_policies",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, u16>(5)?,
            row.get::<_, Option<u64>>(6)?,
            row.get::<_, i64>(7)? != 0,
        ))
    })?;
    for row in rows {
        let (id, client, name, hostname, target, limit, bandwidth, enabled) = row?;
        let id = Uuid::parse_str(&id)?;
        if excluded.contains(&(FleetPolicyKind::SniRoute, id)) {
            continue;
        }
        let Some(client) = agents.get(&Uuid::parse_str(&client)?).copied() else {
            continue;
        };
        resources.push(FleetResource {
            resource_id: id,
            enabled,
            spec: FleetResourceSpec::SniRoute(FleetSniRouteResource {
                agent_instance_id: client,
                name,
                hostname,
                target_addr: target,
                max_connections: limit,
                bandwidth_limit_bps: bandwidth,
            }),
        });
    }
    drop(statement);

    let mut statement = transaction.prepare(
        "SELECT id, provider_client_id, allowed_client_id, name, target_addr, max_connections, bandwidth_limit_bps, enabled FROM secret_tunnel_policies",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<String>>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, u16>(5)?,
            row.get::<_, Option<u64>>(6)?,
            row.get::<_, i64>(7)? != 0,
        ))
    })?;
    for row in rows {
        let (id, provider, allowed, name, target, limit, bandwidth, enabled) = row?;
        let id = Uuid::parse_str(&id)?;
        if excluded.contains(&(FleetPolicyKind::SecretTunnel, id)) {
            continue;
        }
        let Some(provider) = agents.get(&Uuid::parse_str(&provider)?).copied() else {
            continue;
        };
        let allowed = match allowed {
            Some(value) => {
                let client = Uuid::parse_str(&value)?;
                let Some(agent) = agents.get(&client).copied() else {
                    continue;
                };
                Some(agent)
            }
            None => None,
        };
        resources.push(FleetResource {
            resource_id: id,
            enabled,
            spec: FleetResourceSpec::SecretTunnel(FleetSecretTunnelResource {
                provider_agent_instance_id: provider,
                allowed_agent_instance_id: allowed,
                credential_ref: id,
                name,
                target_addr: target,
                max_connections: limit,
                bandwidth_limit_bps: bandwidth,
            }),
        });
    }
    drop(statement);

    for (kind, table) in [
        (FleetPolicyKind::Socks5Proxy, "socks5_proxy_policies"),
        (FleetPolicyKind::HttpProxy, "http_proxy_policies"),
    ] {
        let mut statement = transaction.prepare(&format!(
            "SELECT id, client_id, name, public_port, username, max_connections, bandwidth_limit_bps, enabled FROM {table}"
        ))?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, u16>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, u16>(5)?,
                row.get::<_, Option<u64>>(6)?,
                row.get::<_, i64>(7)? != 0,
            ))
        })?;
        for row in rows {
            let (id, client, name, port, username, limit, bandwidth, enabled) = row?;
            let id = Uuid::parse_str(&id)?;
            if excluded.contains(&(kind, id)) {
                continue;
            }
            let Some(client) = agents.get(&Uuid::parse_str(&client)?).copied() else {
                continue;
            };
            let spec = if kind == FleetPolicyKind::Socks5Proxy {
                FleetResourceSpec::Socks5Proxy(FleetSocks5ProxyResource {
                    agent_instance_id: client,
                    credential_ref: id,
                    name,
                    public_port: port,
                    username,
                    max_connections: limit,
                    bandwidth_limit_bps: bandwidth,
                })
            } else {
                FleetResourceSpec::HttpProxy(FleetHttpProxyResource {
                    agent_instance_id: client,
                    credential_ref: id,
                    name,
                    public_port: port,
                    username,
                    max_connections: limit,
                    bandwidth_limit_bps: bandwidth,
                })
            };
            resources.push(FleetResource {
                resource_id: id,
                enabled,
                spec,
            });
        }
    }
    Ok(resources)
}

type StoredTrafficControl = (
    String,
    String,
    Option<u32>,
    Option<u64>,
    String,
    Option<u16>,
    Option<u16>,
    i64,
);

fn export_traffic_controls(
    transaction: &Transaction<'_>,
    resources: &[FleetResource],
) -> anyhow::Result<Vec<FleetTrafficControl>> {
    let mut controls = Vec::new();
    for resource in resources {
        let kind = resource_kind(resource);
        let stored: Option<StoredTrafficControl> = transaction
            .query_row(
                "SELECT allowed_cidrs, denied_cidrs, max_connections_per_minute, daily_quota_bytes, active_weekdays_utc, start_minute_utc, end_minute_utc, enabled FROM traffic_controls WHERE kind = ?1 AND policy_id = ?2",
                params![kind.traffic_kind(), resource.resource_id.to_string()],
                |row| {
                    Ok((
                        row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?,
                        row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?,
                    ))
                },
            )
            .optional()?;
        let Some((allowed, denied, rate, quota, weekdays, start, end, enabled)) = stored else {
            continue;
        };
        controls.push(FleetTrafficControl {
            resource_id: resource.resource_id,
            enabled: enabled != 0,
            allowed_cidrs: serde_json::from_str(&allowed)?,
            denied_cidrs: serde_json::from_str(&denied)?,
            max_connections_per_minute: rate,
            daily_quota_bytes: quota,
            active_weekdays_utc: serde_json::from_str(&weekdays)?,
            start_minute_utc: start,
            end_minute_utc: end,
        });
    }
    Ok(controls)
}

fn target_addr(host: &str, port: u16) -> String {
    if host.parse::<Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn resource_kind(resource: &FleetResource) -> FleetPolicyKind {
    match resource.spec {
        FleetResourceSpec::Tcp(_) => FleetPolicyKind::Tcp,
        FleetResourceSpec::Udp(_) => FleetPolicyKind::Udp,
        FleetResourceSpec::PortGroup(_) => FleetPolicyKind::PortGroup,
        FleetResourceSpec::HttpRoute(_) => FleetPolicyKind::HttpRoute,
        FleetResourceSpec::SniRoute(_) => FleetPolicyKind::SniRoute,
        FleetResourceSpec::SecretTunnel(_) => FleetPolicyKind::SecretTunnel,
        FleetResourceSpec::Socks5Proxy(_) => FleetPolicyKind::Socks5Proxy,
        FleetResourceSpec::HttpProxy(_) => FleetPolicyKind::HttpProxy,
    }
}

fn referenced_agent_ids(resource: &FleetResource) -> Vec<Uuid> {
    match &resource.spec {
        FleetResourceSpec::Tcp(value) => vec![value.agent_instance_id],
        FleetResourceSpec::Udp(value) => vec![value.agent_instance_id],
        FleetResourceSpec::PortGroup(value) => vec![value.agent_instance_id],
        FleetResourceSpec::HttpRoute(value) => vec![value.agent_instance_id],
        FleetResourceSpec::SniRoute(value) => vec![value.agent_instance_id],
        FleetResourceSpec::SecretTunnel(value) => {
            let mut clients = vec![value.provider_agent_instance_id];
            clients.extend(value.allowed_agent_instance_id);
            clients
        }
        FleetResourceSpec::Socks5Proxy(value) => vec![value.agent_instance_id],
        FleetResourceSpec::HttpProxy(value) => vec![value.agent_instance_id],
    }
}

fn credential_ref(resource: &FleetResource) -> Option<Uuid> {
    match &resource.spec {
        FleetResourceSpec::SecretTunnel(value) => Some(value.credential_ref),
        FleetResourceSpec::Socks5Proxy(value) => Some(value.credential_ref),
        FleetResourceSpec::HttpProxy(value) => Some(value.credential_ref),
        _ => None,
    }
}

fn resource_sha256(resource: &FleetResource) -> anyhow::Result<String> {
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(resource)?)
    ))
}

fn deterministic_policy_id(
    source_instance_id: Uuid,
    resource_id: Uuid,
    kind: FleetPolicyKind,
) -> Uuid {
    let mut digest = Sha256::new();
    digest.update(b"linklake-fleet-policy-v1");
    digest.update(source_instance_id.as_bytes());
    digest.update(resource_id.as_bytes());
    digest.update(kind.as_str().as_bytes());
    let digest = digest.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        client_registry::ClientRegistry,
        http_route_catalog::HttpRouteCatalog,
        secret_tunnel_catalog::{CreateSecretTunnelPolicy, SecretTunnelCatalog},
        sni_route_catalog::SniRouteCatalog,
        traffic_control::TrafficControlCatalog,
        tunnel_catalog::{
            CreateHttpProxyPolicy, CreateSocks5ProxyPolicy, CreateTcpTunnelPolicy, TunnelCatalog,
        },
    };
    use linklake_core::fleet_protocol::FleetClientRef;

    struct TestState {
        database: Database,
        service: PolicyService,
        client_id: Uuid,
        agent_instance_id: Uuid,
        source_instance_id: Uuid,
        secret_ref: Uuid,
        socks_ref: Uuid,
        http_proxy_ref: Uuid,
    }

    fn setup() -> TestState {
        let database = Database::memory().unwrap();
        let port_policy = PublicPortPolicy::development_default();
        let mut clients = ClientRegistry::open_with_database(&database).unwrap();
        let agent_instance_id = Uuid::new_v4();
        let (client_id, _, _) = clients
            .enroll_with_identity(
                "fleet-agent".to_owned(),
                "windows".to_owned(),
                Some(agent_instance_id),
                Some("11".repeat(32)),
            )
            .unwrap();
        let mut tunnels =
            TunnelCatalog::open_with_database(&database, port_policy.clone()).unwrap();
        HttpRouteCatalog::open_with_database(&database).unwrap();
        SniRouteCatalog::open_with_database(&database).unwrap();
        let mut secrets = SecretTunnelCatalog::open_with_database(&database).unwrap();
        TrafficControlCatalog::open_with_database(&database).unwrap();
        let service = PolicyService::open_with_database(&database, port_policy).unwrap();
        let source_instance_id = Uuid::new_v4();
        let secret_ref = Uuid::new_v4();
        let socks_ref = Uuid::new_v4();
        let http_proxy_ref = Uuid::new_v4();

        let secret = secrets
            .create(CreateSecretTunnelPolicy {
                provider_client_id: client_id,
                allowed_client_id: None,
                name: "credential-secret".into(),
                target_addr: "127.0.0.1:24001".into(),
                max_connections: Some(32),
                bandwidth_limit_bps: None,
            })
            .unwrap();
        let socks = tunnels
            .create_socks5(CreateSocks5ProxyPolicy {
                client_id,
                name: "credential-socks".into(),
                public_port: 32_005,
                username: "fleet".into(),
                max_connections: Some(64),
                bandwidth_limit_bps: None,
            })
            .unwrap();
        let http_proxy = tunnels
            .create_http_proxy(CreateHttpProxyPolicy {
                client_id,
                name: "credential-http".into(),
                public_port: 32_006,
                username: "fleet".into(),
                max_connections: Some(64),
                bandwidth_limit_bps: None,
            })
            .unwrap();
        for request in [
            BindFleetCredential {
                source_instance_id,
                credential_ref: secret_ref,
                kind: FleetPolicyKind::SecretTunnel,
                policy_id: secret.policy.id,
            },
            BindFleetCredential {
                source_instance_id,
                credential_ref: socks_ref,
                kind: FleetPolicyKind::Socks5Proxy,
                policy_id: socks.policy.id,
            },
            BindFleetCredential {
                source_instance_id,
                credential_ref: http_proxy_ref,
                kind: FleetPolicyKind::HttpProxy,
                policy_id: http_proxy.policy.id,
            },
        ] {
            service.bind_credential(request, 1).unwrap();
        }
        TestState {
            database,
            service,
            client_id,
            agent_instance_id,
            source_instance_id,
            secret_ref,
            socks_ref,
            http_proxy_ref,
        }
    }

    fn bundle(state: &TestState, generation: u64, tcp_port: u16, socks_port: u16) -> FleetBundleV2 {
        let agent = state.agent_instance_id;
        let resources = vec![
            FleetResource {
                resource_id: Uuid::from_u128(1),
                enabled: true,
                spec: FleetResourceSpec::Tcp(FleetTcpResource {
                    agent_instance_id: agent,
                    name: "tcp".into(),
                    public_port: tcp_port,
                    target_addr: "127.0.0.1:23001".into(),
                    max_connections: 64,
                    bandwidth_limit_bps: None,
                }),
            },
            FleetResource {
                resource_id: Uuid::from_u128(2),
                enabled: true,
                spec: FleetResourceSpec::Udp(FleetUdpResource {
                    agent_instance_id: agent,
                    name: "udp".into(),
                    public_port: 32_002,
                    target_addr: "127.0.0.1:23002".into(),
                    max_sessions: 256,
                    session_idle_timeout_seconds: 120,
                    bandwidth_limit_bps: None,
                }),
            },
            FleetResource {
                resource_id: Uuid::from_u128(3),
                enabled: true,
                spec: FleetResourceSpec::PortGroup(FleetPortGroupResource {
                    agent_instance_id: agent,
                    name: "ports".into(),
                    protocol: FleetPortGroupProtocol::Tcp,
                    public_ports: "32003-32004".into(),
                    target_host: "127.0.0.1".into(),
                    target_ports: "23003-23004".into(),
                    max_connections: 64,
                    max_sessions: 256,
                    session_idle_timeout_seconds: 120,
                    bandwidth_limit_bps: None,
                }),
            },
            FleetResource {
                resource_id: Uuid::from_u128(4),
                enabled: true,
                spec: FleetResourceSpec::HttpRoute(FleetHttpRouteResource {
                    agent_instance_id: agent,
                    name: "web".into(),
                    hostname: "fleet-http.example.com".into(),
                    target_addr: "127.0.0.1:23005".into(),
                    max_connections: 64,
                }),
            },
            FleetResource {
                resource_id: Uuid::from_u128(5),
                enabled: true,
                spec: FleetResourceSpec::SniRoute(FleetSniRouteResource {
                    agent_instance_id: agent,
                    name: "tls".into(),
                    hostname: "fleet-sni.example.com".into(),
                    target_addr: "127.0.0.1:23006".into(),
                    max_connections: 64,
                    bandwidth_limit_bps: None,
                }),
            },
            FleetResource {
                resource_id: Uuid::from_u128(6),
                enabled: true,
                spec: FleetResourceSpec::SecretTunnel(FleetSecretTunnelResource {
                    provider_agent_instance_id: agent,
                    allowed_agent_instance_id: None,
                    credential_ref: state.secret_ref,
                    name: "secret".into(),
                    target_addr: "127.0.0.1:23007".into(),
                    max_connections: 32,
                    bandwidth_limit_bps: None,
                }),
            },
            FleetResource {
                resource_id: Uuid::from_u128(7),
                enabled: true,
                spec: FleetResourceSpec::Socks5Proxy(FleetSocks5ProxyResource {
                    agent_instance_id: agent,
                    credential_ref: state.socks_ref,
                    name: "socks".into(),
                    public_port: socks_port,
                    username: "fleet".into(),
                    max_connections: 64,
                    bandwidth_limit_bps: None,
                }),
            },
            FleetResource {
                resource_id: Uuid::from_u128(8),
                enabled: true,
                spec: FleetResourceSpec::HttpProxy(FleetHttpProxyResource {
                    agent_instance_id: agent,
                    credential_ref: state.http_proxy_ref,
                    name: "http-proxy".into(),
                    public_port: 32_006,
                    username: "fleet".into(),
                    max_connections: 64,
                    bandwidth_limit_bps: None,
                }),
            },
        ];
        FleetBundleV2::new(
            state.source_instance_id,
            generation,
            1_700_000_000 + generation,
            vec![FleetClientRef {
                agent_instance_id: agent,
                name: "fleet-agent".into(),
                agent_identity_public_key: Some("11".repeat(32)),
            }],
            resources,
            vec![FleetTrafficControl {
                resource_id: Uuid::from_u128(1),
                enabled: true,
                allowed_cidrs: vec!["10.0.0.0/8".into()],
                denied_cidrs: Vec::new(),
                max_connections_per_minute: Some(60),
                daily_quota_bytes: Some(1_048_576),
                active_weekdays_utc: Vec::new(),
                start_minute_utc: None,
                end_minute_utc: None,
            }],
        )
        .unwrap()
    }

    #[test]
    fn eight_resource_types_reconcile_atomically_and_reject_replays() {
        let state = setup();
        let first = state
            .service
            .reconcile(
                FleetReconcileRequest {
                    bundle: bundle(&state, 1, 32_001, 32_005),
                    dry_run: false,
                    expected_generation: Some(0),
                    expected_revision: None,
                },
                10,
            )
            .unwrap();
        assert!(first.applied);
        assert_eq!(first.created, 8);
        state
            .database
            .with_connection(|connection| {
                let owned: usize = connection.query_row(
                    "SELECT COUNT(*) FROM fleet_resource_ownership",
                    [],
                    |row| row.get(0),
                )?;
                assert_eq!(owned, 8);
                for table in [
                    "tcp_tunnel_policies",
                    "udp_tunnel_policies",
                    "port_group_policies",
                    "http_route_policies",
                    "sni_route_policies",
                    "secret_tunnel_policies",
                    "socks5_proxy_policies",
                    "http_proxy_policies",
                ] {
                    let count: usize = connection.query_row(
                        &format!("SELECT COUNT(*) FROM {table}"),
                        [],
                        |row| row.get(0),
                    )?;
                    assert_eq!(count, 1, "{table}");
                }
                Ok(())
            })
            .unwrap();

        let second_bundle = bundle(&state, 2, 32_005, 32_001);
        let second = state
            .service
            .reconcile(
                FleetReconcileRequest {
                    bundle: second_bundle.clone(),
                    dry_run: false,
                    expected_generation: Some(1),
                    expected_revision: Some(first.revision.clone()),
                },
                20,
            )
            .unwrap();
        assert!(second.applied, "{second:#?}");
        assert_eq!(second.updated, 2);
        let replay = state
            .service
            .reconcile(
                FleetReconcileRequest {
                    bundle: second_bundle,
                    dry_run: false,
                    expected_generation: None,
                    expected_revision: None,
                },
                21,
            )
            .unwrap();
        assert!(replay.idempotent);
        assert!(!replay.applied);
        assert!(state
            .service
            .reconcile(
                FleetReconcileRequest {
                    bundle: bundle(&state, 1, 32_001, 32_005),
                    dry_run: false,
                    expected_generation: None,
                    expected_revision: None,
                },
                22,
            )
            .is_err());
    }

    #[test]
    fn failed_sql_rolls_back_all_resource_tables_and_source_generation() {
        let state = setup();
        let first = state
            .service
            .reconcile(
                FleetReconcileRequest {
                    bundle: bundle(&state, 1, 32_001, 32_005),
                    dry_run: false,
                    expected_generation: None,
                    expected_revision: None,
                },
                10,
            )
            .unwrap();
        assert!(first.applied);
        state
            .database
            .with_connection(|connection| {
                connection.execute_batch(
                    "CREATE TRIGGER fail_fleet_udp BEFORE INSERT ON udp_tunnel_policies
                     BEGIN SELECT RAISE(ABORT, 'forced Fleet rollback'); END;",
                )?;
                Ok(())
            })
            .unwrap();
        let mut changed = bundle(&state, 2, 32_007, 32_005);
        if let FleetResourceSpec::Udp(udp) = &mut changed.resources[1].spec {
            udp.target_addr = "127.0.0.1:23999".into();
        }
        changed.refresh_integrity().unwrap();
        let rollback = state.service.reconcile(
            FleetReconcileRequest {
                bundle: changed,
                dry_run: false,
                expected_generation: Some(1),
                expected_revision: Some(first.revision),
            },
            20,
        );
        assert!(rollback.is_err(), "{rollback:#?}");
        state
            .database
            .with_connection(|connection| {
                let generation: u64 = connection.query_row(
                    "SELECT generation FROM fleet_source_states WHERE source_instance_id = ?1",
                    [state.source_instance_id.to_string()],
                    |row| row.get(0),
                )?;
                let port: u16 = connection.query_row(
                    "SELECT public_port FROM tcp_tunnel_policies",
                    [],
                    |row| row.get(0),
                )?;
                assert_eq!(generation, 1);
                assert_eq!(port, 32_001);
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn export_uses_stable_agent_id_and_omits_remote_owned_resources() {
        let state = setup();
        state
            .service
            .reconcile(
                FleetReconcileRequest {
                    bundle: bundle(&state, 1, 32_001, 32_005),
                    dry_run: false,
                    expected_generation: None,
                    expected_revision: None,
                },
                10,
            )
            .unwrap();
        let mut tunnels = TunnelCatalog::open_with_database(
            &state.database,
            PublicPortPolicy::development_default(),
        )
        .unwrap();
        let local = tunnels
            .create(CreateTcpTunnelPolicy {
                client_id: state.client_id,
                name: "local-only".into(),
                public_port: 32_020,
                target_addr: "127.0.0.1:24020".into(),
                max_connections: Some(64),
                bandwidth_limit_bps: None,
            })
            .unwrap();
        ClientRegistry::open_with_database(&state.database)
            .unwrap()
            .enroll_with_identity(
                "unused-agent".into(),
                "linux".into(),
                Some(Uuid::new_v4()),
                Some("22".repeat(32)),
            )
            .unwrap();
        let exported = state.service.export_bundle(30).unwrap();
        assert_eq!(exported.clients.len(), 1);
        assert_eq!(
            exported.clients[0].agent_instance_id,
            state.agent_instance_id
        );
        assert_eq!(exported.resources.len(), 1);
        assert_eq!(exported.resources[0].resource_id, local.id);
        assert!(matches!(
            exported.resources[0].spec,
            FleetResourceSpec::Tcp(_)
        ));
    }

    #[test]
    fn reconcile_repairs_database_drift_and_missing_non_secret_rows() {
        let state = setup();
        let desired = bundle(&state, 1, 32_001, 32_005);
        state
            .service
            .reconcile(
                FleetReconcileRequest {
                    bundle: desired.clone(),
                    dry_run: false,
                    expected_generation: None,
                    expected_revision: None,
                },
                10,
            )
            .unwrap();
        let policy_id = state
            .database
            .with_connection(|connection| {
                Ok(connection.query_row(
                    "SELECT policy_id FROM fleet_resource_ownership WHERE source_instance_id = ?1 AND resource_id = ?2",
                    params![state.source_instance_id.to_string(), Uuid::from_u128(1).to_string()],
                    |row| row.get::<_, String>(0),
                )?)
            })
            .unwrap();
        state
            .database
            .with_connection(|connection| {
                connection.execute(
                    "UPDATE tcp_tunnel_policies SET target_addr = '127.0.0.1:29999' WHERE id = ?1",
                    [&policy_id],
                )?;
                Ok(())
            })
            .unwrap();
        let repaired = state
            .service
            .reconcile(
                FleetReconcileRequest {
                    bundle: desired.clone(),
                    dry_run: false,
                    expected_generation: None,
                    expected_revision: None,
                },
                11,
            )
            .unwrap();
        assert!(repaired.applied);
        assert_eq!(repaired.updated, 1);
        state
            .database
            .with_connection(|connection| {
                connection.execute(
                    "DELETE FROM tcp_tunnel_policies WHERE id = ?1",
                    [&policy_id],
                )?;
                Ok(())
            })
            .unwrap();
        let recreated = state
            .service
            .reconcile(
                FleetReconcileRequest {
                    bundle: desired,
                    dry_run: false,
                    expected_generation: None,
                    expected_revision: None,
                },
                12,
            )
            .unwrap();
        assert!(recreated.applied);
        assert_eq!(recreated.updated, 1);
        state
            .database
            .with_connection(|connection| {
                let target: String = connection.query_row(
                    "SELECT target_addr FROM tcp_tunnel_policies WHERE id = ?1",
                    [&policy_id],
                    |row| row.get(0),
                )?;
                assert_eq!(target, "127.0.0.1:23001");
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn credential_unbind_detaches_ownership_and_revokes_future_reconcile() {
        let state = setup();
        state
            .service
            .reconcile(
                FleetReconcileRequest {
                    bundle: bundle(&state, 1, 32_001, 32_005),
                    dry_run: false,
                    expected_generation: None,
                    expected_revision: None,
                },
                10,
            )
            .unwrap();
        let binding = state
            .service
            .list_credential_bindings()
            .unwrap()
            .into_iter()
            .find(|binding| binding.credential_ref == state.socks_ref)
            .unwrap();
        assert!(state
            .service
            .delete_credential_binding(
                state.source_instance_id,
                FleetPolicyKind::Socks5Proxy,
                state.socks_ref,
            )
            .unwrap());
        assert!(!state
            .service
            .is_policy_managed(FleetPolicyKind::Socks5Proxy, binding.policy_id)
            .unwrap());
        state
            .database
            .with_connection(|connection| {
                let exists: bool = connection.query_row(
                    "SELECT EXISTS(SELECT 1 FROM socks5_proxy_policies WHERE id = ?1)",
                    [binding.policy_id.to_string()],
                    |row| row.get(0),
                )?;
                assert!(exists, "unbind must retain the local credential policy");
                Ok(())
            })
            .unwrap();
        let mut changed = bundle(&state, 2, 32_001, 32_009);
        changed.refresh_integrity().unwrap();
        let rejected = state
            .service
            .reconcile(
                FleetReconcileRequest {
                    bundle: changed,
                    dry_run: false,
                    expected_generation: None,
                    expected_revision: None,
                },
                20,
            )
            .unwrap();
        assert!(!rejected.applied);
        assert!(rejected
            .conflicts
            .iter()
            .any(|conflict| conflict.message.contains("credential")));
    }

    #[test]
    fn unused_bundle_clients_do_not_block_reconcile() {
        let state = setup();
        let mut desired = bundle(&state, 1, 32_001, 32_005);
        desired.clients.push(FleetClientRef {
            agent_instance_id: Uuid::new_v4(),
            name: "not-enrolled-and-unused".into(),
            agent_identity_public_key: Some("33".repeat(32)),
        });
        desired.refresh_integrity().unwrap();
        let result = state
            .service
            .reconcile(
                FleetReconcileRequest {
                    bundle: desired,
                    dry_run: false,
                    expected_generation: None,
                    expected_revision: None,
                },
                10,
            )
            .unwrap();
        assert!(result.applied);
        assert_eq!(result.created, 8);
    }

    #[test]
    fn duplicate_credential_refs_are_reported_before_sql_writes() {
        let state = setup();
        let mut desired = bundle(&state, 1, 32_001, 32_005);
        let mut duplicate = desired.resources[5].clone();
        duplicate.resource_id = Uuid::from_u128(9);
        if let FleetResourceSpec::SecretTunnel(secret) = &mut duplicate.spec {
            secret.name = "second-secret".into();
            secret.target_addr = "127.0.0.1:23009".into();
        }
        desired.resources.push(duplicate);
        desired.refresh_integrity().unwrap();
        let result = state
            .service
            .reconcile(
                FleetReconcileRequest {
                    bundle: desired,
                    dry_run: false,
                    expected_generation: None,
                    expected_revision: None,
                },
                10,
            )
            .unwrap();
        assert!(!result.applied);
        assert!(result
            .conflicts
            .iter()
            .any(|conflict| conflict.code == "duplicate_credential_ref"));
        let sources = state.service.list_sources().unwrap();
        assert!(sources.is_empty());
    }

    #[test]
    fn unreasonable_generation_is_rejected_and_admin_reset_recovers_state() {
        let state = setup();
        assert!(state
            .service
            .reconcile(
                FleetReconcileRequest {
                    bundle: bundle(&state, MAX_FLEET_GENERATION_ADVANCE + 1, 32_001, 32_005,),
                    dry_run: false,
                    expected_generation: None,
                    expected_revision: None,
                },
                10,
            )
            .is_err());
        state
            .service
            .reconcile(
                FleetReconcileRequest {
                    bundle: bundle(&state, 1, 32_001, 32_005),
                    dry_run: false,
                    expected_generation: None,
                    expected_revision: None,
                },
                11,
            )
            .unwrap();
        assert!(state
            .service
            .reset_source_state(state.source_instance_id)
            .unwrap());
        let recovered = state
            .service
            .reconcile(
                FleetReconcileRequest {
                    bundle: bundle(&state, 1, 32_001, 32_005),
                    dry_run: false,
                    expected_generation: None,
                    expected_revision: None,
                },
                12,
            )
            .unwrap();
        assert!(recovered.applied || recovered.idempotent);
    }
}
