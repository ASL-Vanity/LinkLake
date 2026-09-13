//! Fleet v1 的兼容入口；共享存储下预览与写入都使用同一份事务快照。
use crate::{
    fleet::{self, FleetImportResult, FleetPolicyBundle, FleetTcpPolicy, FleetUdpPolicy},
    policy_service::postgres::FleetPolicyTransaction,
    tunnel_catalog::{
        self,
        postgres::{self, SharedTunnelPolicy, TunnelSnapshot},
        CreateTcpTunnelPolicy, CreateUdpTunnelPolicy,
    },
    tunnel_store::TunnelStore,
};
use linklake_core::ClientSummary;
use std::collections::HashMap;
use uuid::Uuid;

pub(crate) async fn export(
    clients: &[ClientSummary],
    store: &TunnelStore,
) -> anyhow::Result<FleetPolicyBundle> {
    match store {
        TunnelStore::Sqlite(catalog) => fleet::export_policy_bundle(
            clients,
            &catalog.lock().expect("tunnel catalog lock poisoned"),
        ),
        TunnelStore::Postgres(catalog) => {
            let mut connection = catalog.storage.postgres_client().await?;
            let tx = connection
                .build_transaction()
                .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
                .read_only(true)
                .start()
                .await?;
            let policies = postgres::transaction_list(&tx, &catalog.public_port_policy).await?;
            let rows = tx
                .query("SELECT client_id,name FROM linklake_clients", &[])
                .await?;
            let names = rows
                .into_iter()
                .map(|row| {
                    Ok((
                        Uuid::parse_str(row.try_get("client_id")?)?,
                        row.try_get::<_, String>("name")?,
                    ))
                })
                .collect::<anyhow::Result<HashMap<_, _>>>()?;
            let mut bundle = FleetPolicyBundle::default();
            for item in policies {
                let Some(name) = names.get(&item.policy.client_id()) else {
                    continue;
                };
                match item.policy {
                    SharedTunnelPolicy::Tcp(p) => bundle.tcp.push(FleetTcpPolicy {
                        client_name: name.clone(),
                        name: p.name,
                        public_port: p.public_port,
                        target_addr: p.target_addr,
                        max_connections: p.max_connections,
                        bandwidth_limit_bps: p.bandwidth_limit_bps,
                        enabled: p.enabled,
                    }),
                    SharedTunnelPolicy::Udp(p) => bundle.udp.push(FleetUdpPolicy {
                        client_name: name.clone(),
                        name: p.name,
                        public_port: p.public_port,
                        target_addr: p.target_addr,
                        max_sessions: p.max_sessions,
                        session_idle_timeout_seconds: p.session_idle_timeout_seconds,
                        bandwidth_limit_bps: p.bandwidth_limit_bps,
                        enabled: p.enabled,
                    }),
                    _ => {}
                }
            }
            tx.commit().await?;
            Ok(bundle)
        }
    }
}

pub(crate) async fn import(
    bundle: &FleetPolicyBundle,
    clients: &[ClientSummary],
    store: &TunnelStore,
    dry_run: bool,
) -> anyhow::Result<FleetImportResult> {
    let catalog = match store {
        TunnelStore::Sqlite(catalog) => {
            return fleet::import_policy_bundle(
                bundle,
                clients,
                &mut catalog.lock().expect("tunnel catalog lock poisoned"),
                dry_run,
            )
        }
        TunnelStore::Postgres(catalog) => catalog,
    };
    let mut connection = catalog.storage.postgres_client().await?;
    let tx = connection.transaction().await?;
    let guard = FleetPolicyTransaction::lock(&tx, &catalog.runtime).await?;
    // 锁住身份行，防止名称匹配完成后客户端被禁用或重命名。
    let rows = tx
        .query(
            "SELECT client_id,name FROM linklake_clients WHERE enabled FOR SHARE",
            &[],
        )
        .await?;
    let mut names = HashMap::<String, Vec<Uuid>>::new();
    for row in rows {
        names
            .entry(row.try_get("name")?)
            .or_default()
            .push(Uuid::parse_str(row.try_get("client_id")?)?);
    }
    let mut existing = postgres::transaction_list(&tx, &catalog.public_port_policy).await?;
    let mut planned = Vec::new();
    let mut result = FleetImportResult::default();
    for input in &bundle.tcp {
        let Some(client) = resolve_client(&names, &input.client_name, &input.name, &mut result)
        else {
            continue;
        };
        let policy = tunnel_catalog::requested_tcp(
            &catalog.public_port_policy,
            Uuid::new_v4(),
            input.enabled,
            &CreateTcpTunnelPolicy {
                client_id: client,
                name: input.name.clone(),
                public_port: input.public_port,
                target_addr: input.target_addr.clone(),
                max_connections: Some(input.max_connections),
                bandwidth_limit_bps: input.bandwidth_limit_bps,
            },
        );
        match policy {
            Ok(policy) => plan(
                SharedTunnelPolicy::Tcp(policy),
                &mut existing,
                &mut planned,
                &mut result,
            )?,
            Err(_) => result
                .conflicts
                .push(format!("TCP {}: invalid policy", input.name)),
        }
    }
    for input in &bundle.udp {
        let Some(client) = resolve_client(&names, &input.client_name, &input.name, &mut result)
        else {
            continue;
        };
        let policy = tunnel_catalog::requested_udp(
            &catalog.public_port_policy,
            Uuid::new_v4(),
            input.enabled,
            &CreateUdpTunnelPolicy {
                client_id: client,
                name: input.name.clone(),
                public_port: input.public_port,
                target_addr: input.target_addr.clone(),
                max_sessions: Some(input.max_sessions),
                session_idle_timeout_seconds: Some(input.session_idle_timeout_seconds),
                bandwidth_limit_bps: input.bandwidth_limit_bps,
            },
        );
        match policy {
            Ok(policy) => plan(
                SharedTunnelPolicy::Udp(policy),
                &mut existing,
                &mut planned,
                &mut result,
            )?,
            Err(_) => result
                .conflicts
                .push(format!("UDP {}: invalid policy", input.name)),
        }
    }
    // v1 保留逐项冲突语义；全部有效新项一次提交，禁用策略从未短暂启用。
    if !dry_run {
        for item in planned {
            postgres::transaction_put(&guard, &catalog.public_port_policy, &item).await?;
        }
        guard.assert_current().await?;
        tx.commit().await?;
    }
    Ok(result)
}

fn resolve_client(
    names: &HashMap<String, Vec<Uuid>>,
    client: &str,
    policy: &str,
    result: &mut FleetImportResult,
) -> Option<Uuid> {
    match names.get(client).map(Vec::as_slice) {
        Some([id]) => Some(*id),
        _ => {
            result.conflicts.push(format!(
                "{policy}: client '{client}' is missing or ambiguous"
            ));
            None
        }
    }
}

fn plan(
    policy: SharedTunnelPolicy,
    existing: &mut Vec<TunnelSnapshot>,
    planned: &mut Vec<TunnelSnapshot>,
    result: &mut FleetImportResult,
) -> anyhow::Result<()> {
    if let Some(old) = existing
        .iter()
        .find(|old| old.policy.kind() == policy.kind() && old.policy.name() == policy.name())
    {
        let mut desired: serde_json::Value = serde_json::from_str(&policy.json()?)?;
        desired["id"] = serde_json::json!(old.policy.id());
        if desired == serde_json::from_str::<serde_json::Value>(&old.policy.json()?)? {
            result.unchanged += 1;
        } else {
            result.conflicts.push(format!(
                "{}: incompatible policy with the same name",
                policy.name()
            ));
        }
        return Ok(());
    }
    let ports = policy.port_reservations()?;
    for old in existing.iter() {
        if old
            .policy
            .port_reservations()?
            .iter()
            .any(|port| ports.contains(port))
        {
            result.conflicts.push(format!(
                "{}: public port is already assigned",
                policy.name()
            ));
            return Ok(());
        }
    }
    let snapshot = TunnelSnapshot {
        policy,
        password_hash: None,
    };
    existing.push(snapshot.clone());
    planned.push(snapshot);
    result.created += 1;
    Ok(())
}
