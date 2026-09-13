//! Fleet 八类业务资源的共享快照和纯计划转换；凭据不进入导出内容。
use super::*;
use crate::{
    http_route_catalog::{self as http, postgres as http_pg},
    secret_tunnel_catalog::{self as secret, postgres as secret_pg},
    sni_route_catalog::{self as sni, postgres as sni_pg},
    traffic_control::{self as traffic, TrafficPolicyKind, UpsertTrafficControl},
    tunnel_catalog::{self as tunnel, postgres as tunnel_pg},
};

pub(super) enum SharedPolicy {
    Tunnel(tunnel_pg::TunnelSnapshot),
    Http(http::HttpRoutePolicy),
    Sni(sni::SniRoutePolicy),
    Secret(secret_pg::SecretTunnelSnapshot),
}
pub(super) type CatalogSnapshot = HashMap<(FleetPolicyKind, Uuid), SharedPolicy>;
pub(super) struct SharedPlan {
    pub(super) resource: FleetResource,
    pub(super) policy: SharedPolicy,
    pub(super) resource_sha256: String,
    pub(super) write_required: bool,
}
impl SharedPolicy {
    pub(super) fn id(&self) -> Uuid {
        match self {
            Self::Tunnel(s) => s.policy.id(),
            Self::Http(p) => p.id,
            Self::Sni(p) => p.id,
            Self::Secret(s) => s.policy.id,
        }
    }
    pub(super) fn kind(&self) -> FleetPolicyKind {
        match self {
            Self::Tunnel(s) => match s.policy {
                tunnel_pg::SharedTunnelPolicy::Tcp(_) => FleetPolicyKind::Tcp,
                tunnel_pg::SharedTunnelPolicy::Udp(_) => FleetPolicyKind::Udp,
                tunnel_pg::SharedTunnelPolicy::Socks5(_) => FleetPolicyKind::Socks5Proxy,
                tunnel_pg::SharedTunnelPolicy::HttpProxy(_) => FleetPolicyKind::HttpProxy,
                tunnel_pg::SharedTunnelPolicy::PortGroup(_) => FleetPolicyKind::PortGroup,
            },
            Self::Http(_) => FleetPolicyKind::HttpRoute,
            Self::Sni(_) => FleetPolicyKind::SniRoute,
            Self::Secret(_) => FleetPolicyKind::SecretTunnel,
        }
    }
    pub(super) fn key(&self) -> (FleetPolicyKind, Uuid) {
        (self.kind(), self.id())
    }
    pub(super) fn name_key(&self) -> (FleetPolicyKind, Uuid, String) {
        match self {
            Self::Tunnel(s) => (
                self.kind(),
                s.policy.client_id(),
                if self.kind() == FleetPolicyKind::PortGroup {
                    format!("{}:{}", s.policy.protocol(), s.policy.name())
                } else {
                    s.policy.name().to_owned()
                },
            ),
            Self::Http(p) => (self.kind(), p.client_id, p.name.clone()),
            Self::Sni(p) => (self.kind(), p.client_id, p.name.clone()),
            Self::Secret(s) => (
                self.kind(),
                s.policy.provider_client_id,
                s.policy.name.clone(),
            ),
        }
    }
    pub(super) fn unique_local_name(&self) -> bool {
        matches!(
            self.kind(),
            FleetPolicyKind::PortGroup
                | FleetPolicyKind::SecretTunnel
                | FleetPolicyKind::Socks5Proxy
                | FleetPolicyKind::HttpProxy
        )
    }
    pub(super) fn endpoints(&self) -> anyhow::Result<Vec<String>> {
        Ok(match self {
            Self::Tunnel(s) => s
                .policy
                .port_reservations()?
                .into_iter()
                .map(|(proto, port)| format!("{proto}:{port}"))
                .collect(),
            Self::Http(p) => vec![format!("http:{}", p.hostname)],
            Self::Sni(p) => vec![format!("sni:{}", p.hostname)],
            Self::Secret(_) => vec![],
        })
    }
    pub(super) fn credential(&self) -> Option<&str> {
        match self {
            Self::Tunnel(s) => s.password_hash.as_deref(),
            Self::Secret(s) => Some(&s.access_key_hash),
            _ => None,
        }
    }
    pub(super) fn same(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Tunnel(a), Self::Tunnel(b)) => {
                a.password_hash == b.password_hash
                    && match (&a.policy, &b.policy) {
                        (
                            tunnel_pg::SharedTunnelPolicy::Tcp(a),
                            tunnel_pg::SharedTunnelPolicy::Tcp(b),
                        ) => a == b,
                        (
                            tunnel_pg::SharedTunnelPolicy::Udp(a),
                            tunnel_pg::SharedTunnelPolicy::Udp(b),
                        ) => a == b,
                        (
                            tunnel_pg::SharedTunnelPolicy::Socks5(a),
                            tunnel_pg::SharedTunnelPolicy::Socks5(b),
                        ) => a == b,
                        (
                            tunnel_pg::SharedTunnelPolicy::HttpProxy(a),
                            tunnel_pg::SharedTunnelPolicy::HttpProxy(b),
                        ) => a == b,
                        (
                            tunnel_pg::SharedTunnelPolicy::PortGroup(a),
                            tunnel_pg::SharedTunnelPolicy::PortGroup(b),
                        ) => a == b,
                        _ => false,
                    }
            }
            (Self::Http(a), Self::Http(b)) => a == b,
            (Self::Sni(a), Self::Sni(b)) => a == b,
            (Self::Secret(a), Self::Secret(b)) => {
                a.policy == b.policy && a.access_key_hash == b.access_key_hash
            }
            _ => false,
        }
    }
    pub(super) fn invalidate(
        &self,
        output: &mut Vec<FleetRuntimeInvalidation>,
    ) -> anyhow::Result<()> {
        match self {
            Self::Tunnel(s) => match &s.policy {
                tunnel_pg::SharedTunnelPolicy::Tcp(p) => {
                    output.push(FleetRuntimeInvalidation::TcpPort(p.public_port))
                }
                tunnel_pg::SharedTunnelPolicy::Udp(p) => {
                    output.push(FleetRuntimeInvalidation::UdpPort(p.public_port))
                }
                tunnel_pg::SharedTunnelPolicy::Socks5(p) => {
                    output.push(FleetRuntimeInvalidation::Socks5Proxy(p.id))
                }
                tunnel_pg::SharedTunnelPolicy::HttpProxy(p) => {
                    output.push(FleetRuntimeInvalidation::HttpProxy(p.id))
                }
                tunnel_pg::SharedTunnelPolicy::PortGroup(_) => {
                    for (proto, port) in s.policy.port_reservations()? {
                        output.push(if proto == "tcp" {
                            FleetRuntimeInvalidation::TcpPort(port)
                        } else {
                            FleetRuntimeInvalidation::UdpPort(port)
                        });
                    }
                }
            },
            Self::Http(p) => {
                output.push(FleetRuntimeInvalidation::HttpHostname(p.hostname.clone()))
            }
            Self::Sni(p) => output.push(FleetRuntimeInvalidation::SniHostname(p.hostname.clone())),
            Self::Secret(s) => output.push(FleetRuntimeInvalidation::SecretTunnel(s.policy.id)),
        }
        Ok(())
    }
    pub(super) async fn put(
        &self,
        guard: &FleetPolicyTransaction<'_, '_>,
        ports: &PublicPortPolicy,
    ) -> anyhow::Result<()> {
        match self {
            Self::Tunnel(snapshot) => tunnel_pg::transaction_put(guard, ports, snapshot).await,
            Self::Http(policy) => http_pg::transaction_put(guard, policy).await,
            Self::Sni(policy) => sni_pg::transaction_put(guard, policy).await,
            Self::Secret(snapshot) => {
                secret_pg::transaction_put(guard, &snapshot.policy, &snapshot.access_key_hash).await
            }
        }
    }
}

pub(super) async fn load_catalog(
    guard: &FleetPolicyTransaction<'_, '_>,
    ports: &PublicPortPolicy,
) -> anyhow::Result<CatalogSnapshot> {
    let mut result = HashMap::new();
    for snapshot in tunnel_pg::transaction_list(guard.transaction(), ports).await? {
        let policy = SharedPolicy::Tunnel(snapshot);
        result.insert(policy.key(), policy);
    }
    for policy in http_pg::transaction_list(guard.transaction()).await? {
        result.insert(
            (FleetPolicyKind::HttpRoute, policy.id),
            SharedPolicy::Http(policy),
        );
    }
    for policy in sni_pg::transaction_list(guard.transaction()).await? {
        result.insert(
            (FleetPolicyKind::SniRoute, policy.id),
            SharedPolicy::Sni(policy),
        );
    }
    let hashes: HashMap<Uuid, String> = guard
        .transaction()
        .query(
            "SELECT id,access_key_hash FROM linklake_secret_tunnel_policies",
            &[],
        )
        .await?
        .iter()
        .map(|row| Ok((stored_id(row.try_get(0)?)?, row.try_get(1)?)))
        .collect::<anyhow::Result<_>>()?;
    for policy in secret_pg::transaction_list(guard).await? {
        let hash = hashes
            .get(&policy.id)
            .ok_or_else(|| anyhow::anyhow!("Secret credential snapshot missing"))?
            .clone();
        result.insert(
            (FleetPolicyKind::SecretTunnel, policy.id),
            SharedPolicy::Secret(secret_pg::SecretTunnelSnapshot {
                policy,
                access_key_hash: hash,
            }),
        );
    }
    Ok(result)
}

pub(super) async fn delete_resource(
    guard: &FleetPolicyTransaction<'_, '_>,
    kind: FleetPolicyKind,
    id: Uuid,
) -> anyhow::Result<()> {
    match kind {
        FleetPolicyKind::HttpRoute => {
            http_pg::transaction_delete(guard, id).await?;
        }
        FleetPolicyKind::SniRoute => {
            sni_pg::transaction_delete(guard, id).await?;
        }
        FleetPolicyKind::SecretTunnel => {
            secret_pg::transaction_delete(guard, id).await?;
        }
        _ => {
            tunnel_pg::transaction_delete(guard, id).await?;
        }
    }
    Ok(())
}

pub(super) fn build_policy(
    resource: &FleetResource,
    id: Uuid,
    clients: &HashMap<Uuid, Uuid>,
    hash: Option<&str>,
    ports: &PublicPortPolicy,
) -> anyhow::Result<SharedPolicy> {
    let wire = serde_json::to_value(&resource.spec)?;
    let mut request = wire
        .get("settings")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("Fleet settings are absent"))?;
    if let FleetResourceSpec::SecretTunnel(value) = &resource.spec {
        request["provider_client_id"] =
            serde_json::to_value(local_client_id(clients, value.provider_agent_instance_id)?)?;
        request["allowed_client_id"] = serde_json::to_value(
            value
                .allowed_agent_instance_id
                .map(|agent| local_client_id(clients, agent))
                .transpose()?,
        )?;
    } else {
        let agent = *referenced_agent_ids(resource)
            .first()
            .ok_or_else(|| anyhow::anyhow!("Fleet client missing"))?;
        request["client_id"] = serde_json::to_value(local_client_id(clients, agent)?)?;
    }
    let enabled = resource.enabled;
    Ok(match &resource.spec {
        FleetResourceSpec::Tcp(_) => SharedPolicy::Tunnel(tunnel_pg::TunnelSnapshot {
            policy: tunnel_pg::SharedTunnelPolicy::Tcp(tunnel::requested_tcp(
                ports,
                id,
                enabled,
                &serde_json::from_value(request)?,
            )?),
            password_hash: None,
        }),
        FleetResourceSpec::Udp(_) => SharedPolicy::Tunnel(tunnel_pg::TunnelSnapshot {
            policy: tunnel_pg::SharedTunnelPolicy::Udp(tunnel::requested_udp(
                ports,
                id,
                enabled,
                &serde_json::from_value(request)?,
            )?),
            password_hash: None,
        }),
        FleetResourceSpec::PortGroup(_) => SharedPolicy::Tunnel(tunnel_pg::TunnelSnapshot {
            policy: tunnel_pg::SharedTunnelPolicy::PortGroup(tunnel::requested_port_group(
                ports,
                id,
                enabled,
                &serde_json::from_value(request)?,
            )?),
            password_hash: None,
        }),
        FleetResourceSpec::HttpRoute(_) => SharedPolicy::Http(http::requested_policy(
            id,
            enabled,
            serde_json::from_value(request)?,
        )?),
        FleetResourceSpec::SniRoute(_) => SharedPolicy::Sni(sni::requested_policy(
            id,
            enabled,
            serde_json::from_value(request)?,
        )?),
        FleetResourceSpec::SecretTunnel(_) => {
            SharedPolicy::Secret(secret_pg::SecretTunnelSnapshot {
                policy: secret::requested_policy(id, enabled, serde_json::from_value(request)?)?,
                access_key_hash: hash
                    .ok_or_else(|| anyhow::anyhow!("Fleet Secret credential missing"))?
                    .to_owned(),
            })
        }
        FleetResourceSpec::Socks5Proxy(_) => SharedPolicy::Tunnel(tunnel_pg::TunnelSnapshot {
            policy: tunnel_pg::SharedTunnelPolicy::Socks5(tunnel::requested_socks5(
                ports,
                id,
                enabled,
                &serde_json::from_value(request)?,
            )?),
            password_hash: Some(
                hash.ok_or_else(|| anyhow::anyhow!("Fleet SOCKS5 credential missing"))?
                    .to_owned(),
            ),
        }),
        FleetResourceSpec::HttpProxy(_) => SharedPolicy::Tunnel(tunnel_pg::TunnelSnapshot {
            policy: tunnel_pg::SharedTunnelPolicy::HttpProxy(tunnel::requested_http_proxy(
                ports,
                id,
                enabled,
                &serde_json::from_value(request)?,
            )?),
            password_hash: Some(
                hash.ok_or_else(|| anyhow::anyhow!("Fleet HTTP proxy credential missing"))?
                    .to_owned(),
            ),
        }),
    })
}

pub(super) fn export_policy(
    policy: &SharedPolicy,
    agents: &HashMap<Uuid, Uuid>,
) -> anyhow::Result<Option<FleetResource>> {
    let (mut value, enabled) = match policy {
        SharedPolicy::Tunnel(s) => (
            serde_json::from_str::<serde_json::Value>(&s.policy.json()?)?,
            s.policy.enabled(),
        ),
        SharedPolicy::Http(p) => (serde_json::to_value(p)?, p.enabled),
        SharedPolicy::Sni(p) => (serde_json::to_value(p)?, p.enabled),
        SharedPolicy::Secret(s) => (serde_json::to_value(&s.policy)?, s.policy.enabled),
    };
    let object = value
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("Fleet policy is not an object"))?;
    object.remove("id");
    object.remove("enabled");
    object.remove("mapping_count");
    if policy.kind() == FleetPolicyKind::PortGroup {
        if let Some(host) = object.get("target_host").and_then(|value| value.as_str()) {
            let host = super::super::canonical_fleet_target_host(host);
            object.insert("target_host".into(), serde_json::Value::String(host));
        }
    }
    if let SharedPolicy::Secret(s) = policy {
        let Some(provider) = agents.get(&s.policy.provider_client_id) else {
            return Ok(None);
        };
        let allowed = match s.policy.allowed_client_id {
            Some(id) => {
                let Some(agent) = agents.get(&id) else {
                    return Ok(None);
                };
                Some(*agent)
            }
            None => None,
        };
        object.remove("provider_client_id");
        object.remove("allowed_client_id");
        object.insert(
            "provider_agent_instance_id".into(),
            serde_json::to_value(provider)?,
        );
        object.insert(
            "allowed_agent_instance_id".into(),
            serde_json::to_value(allowed)?,
        );
    } else {
        let local: Uuid = serde_json::from_value(
            object
                .remove("client_id")
                .ok_or_else(|| anyhow::anyhow!("Fleet policy client missing"))?,
        )?;
        let Some(agent) = agents.get(&local) else {
            return Ok(None);
        };
        object.insert("agent_instance_id".into(), serde_json::to_value(agent)?);
    }
    if policy.kind().requires_credential() {
        object.insert("credential_ref".into(), serde_json::to_value(policy.id())?);
    }
    let spec = serde_json::from_value(
        serde_json::json!({"kind":policy.kind().as_str(),"settings":value}),
    )?;
    Ok(Some(FleetResource {
        resource_id: policy.id(),
        enabled,
        spec,
    }))
}

pub(super) fn validate_final_plan(
    plan: &[SharedPlan],
    catalog: &CatalogSnapshot,
    owned: &HashMap<Uuid, OwnedResource>,
    conflicts: &mut Vec<FleetConflict>,
) -> anyhow::Result<()> {
    let mut endpoints = HashMap::new();
    let mut names = HashMap::new();
    let mut credentials = HashMap::new();
    let mut policies = HashMap::new();
    for planned in plan {
        let id = planned.resource.resource_id;
        let mut conflict = |code: &str, message: String| {
            conflicts.push(FleetConflict {
                code: code.into(),
                resource_id: Some(id),
                message,
            })
        };
        if let Some(other) = policies.insert(planned.policy.key(), id) {
            conflict(
                "resource_conflict",
                format!("local policy is also used by Fleet resource {other}"),
            );
        }
        if let Some(reference) = credential_ref(&planned.resource) {
            if let Some(other) = credentials.insert((planned.policy.kind(), reference), id) {
                conflict(
                    "duplicate_credential_ref",
                    format!("credential reference is also used by Fleet resource {other}"),
                );
            }
        }
        if let Some(other) = names.insert(planned.policy.name_key(), id) {
            conflict(
                "invalid_resource",
                format!("policy name is also requested by Fleet resource {other}"),
            );
        }
        for endpoint in planned.policy.endpoints()? {
            if let Some(other) = endpoints.insert(endpoint.clone(), id) {
                conflict(
                    "invalid_resource",
                    format!("{endpoint} is also requested by Fleet resource {other}"),
                );
            }
        }
    }
    let owned_keys: HashSet<_> = owned.values().map(|o| (o.kind, o.policy_id)).collect();
    let desired_keys: HashSet<_> = plan.iter().map(|p| p.policy.key()).collect();
    // 当前来源的旧资源整体让出位置，支持端口、名称、主机名交换及过期资源替换。
    for (key, local) in catalog {
        if owned_keys.contains(key) || desired_keys.contains(key) {
            continue;
        }
        for endpoint in local.endpoints()? {
            if let Some(id) = endpoints.get(&endpoint) {
                conflicts.push(FleetConflict {
                    code: "local_policy_conflict".into(),
                    resource_id: Some(*id),
                    message: format!("{endpoint} belongs to a policy outside this source"),
                });
            }
        }
        if local.unique_local_name() {
            if let Some(id) = names.get(&local.name_key()) {
                conflicts.push(FleetConflict {
                    code: "local_policy_conflict".into(),
                    resource_id: Some(*id),
                    message: "policy name belongs to a policy outside this source".into(),
                });
            }
        }
    }
    Ok(())
}

pub(super) fn desired_control(
    control: &FleetTrafficControl,
) -> anyhow::Result<UpsertTrafficControl> {
    traffic::normalized_settings(UpsertTrafficControl {
        allowed_cidrs: control.allowed_cidrs.clone(),
        denied_cidrs: control.denied_cidrs.clone(),
        max_connections_per_minute: control.max_connections_per_minute,
        daily_quota_bytes: control.daily_quota_bytes,
        active_weekdays_utc: control.active_weekdays_utc.clone(),
        start_minute_utc: control.start_minute_utc,
        end_minute_utc: control.end_minute_utc,
        enabled: control.enabled,
    })
}
pub(super) fn traffic_kind(kind: FleetPolicyKind) -> anyhow::Result<TrafficPolicyKind> {
    TrafficPolicyKind::parse(kind.traffic_kind())
}
pub(super) fn export_control(id: Uuid, settings: UpsertTrafficControl) -> FleetTrafficControl {
    FleetTrafficControl {
        resource_id: id,
        enabled: settings.enabled,
        allowed_cidrs: settings.allowed_cidrs,
        denied_cidrs: settings.denied_cidrs,
        max_connections_per_minute: settings.max_connections_per_minute,
        daily_quota_bytes: settings.daily_quota_bytes,
        active_weekdays_utc: settings.active_weekdays_utc,
        start_minute_utc: settings.start_minute_utc,
        end_minute_utc: settings.end_minute_utc,
    }
}
