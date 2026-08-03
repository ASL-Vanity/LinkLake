//! 多云服务端目录与集中健康探测配置。

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::Path};
use uuid::Uuid;

use crate::database::Database;
use crate::tunnel_catalog::{CreateTcpTunnelPolicy, CreateUdpTunnelPolicy, TunnelCatalog};
use linklake_core::ClientSummary;

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct UpsertFleetPeer {
    pub(crate) name: String,
    pub(crate) url: String,
    pub(crate) region: String,
    #[serde(default = "default_weight")]
    pub(crate) weight: u16,
    #[serde(default = "default_priority")]
    pub(crate) priority: u16,
    pub(crate) token_env: String,
    #[serde(default = "default_true")]
    pub(crate) enabled: bool,
}

fn default_weight() -> u16 {
    100
}

fn default_priority() -> u16 {
    100
}

fn default_true() -> bool {
    true
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct FleetPeer {
    pub(crate) id: Uuid,
    pub(crate) name: String,
    pub(crate) url: String,
    pub(crate) region: String,
    pub(crate) weight: u16,
    pub(crate) priority: u16,
    pub(crate) token_env: String,
    pub(crate) token_configured: bool,
    pub(crate) enabled: bool,
    pub(crate) created_unix_seconds: u64,
    pub(crate) updated_unix_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct FleetTcpPolicy {
    pub(crate) client_name: String,
    pub(crate) name: String,
    pub(crate) public_port: u16,
    pub(crate) target_addr: String,
    pub(crate) max_connections: u16,
    pub(crate) bandwidth_limit_bps: Option<u64>,
    pub(crate) enabled: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct FleetUdpPolicy {
    pub(crate) client_name: String,
    pub(crate) name: String,
    pub(crate) public_port: u16,
    pub(crate) target_addr: String,
    pub(crate) max_sessions: u16,
    pub(crate) session_idle_timeout_seconds: u32,
    pub(crate) bandwidth_limit_bps: Option<u64>,
    pub(crate) enabled: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub(crate) struct FleetPolicyBundle {
    #[serde(default)]
    pub(crate) tcp: Vec<FleetTcpPolicy>,
    #[serde(default)]
    pub(crate) udp: Vec<FleetUdpPolicy>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub(crate) struct FleetImportResult {
    pub(crate) created: usize,
    pub(crate) unchanged: usize,
    pub(crate) conflicts: Vec<String>,
}

pub(crate) fn export_policy_bundle(
    clients: &[ClientSummary],
    tunnels: &TunnelCatalog,
) -> anyhow::Result<FleetPolicyBundle> {
    let client_names = clients
        .iter()
        .map(|client| (client.client_id, client.name.as_str()))
        .collect::<HashMap<_, _>>();
    let tcp = tunnels
        .list()?
        .into_iter()
        .filter_map(|policy| {
            client_names
                .get(&policy.client_id)
                .map(|client_name| FleetTcpPolicy {
                    client_name: (*client_name).to_owned(),
                    name: policy.name,
                    public_port: policy.public_port,
                    target_addr: policy.target_addr,
                    max_connections: policy.max_connections,
                    bandwidth_limit_bps: policy.bandwidth_limit_bps,
                    enabled: policy.enabled,
                })
        })
        .collect();
    let udp = tunnels
        .list_udp()
        .map_err(|error| anyhow::anyhow!(error.to_string()))?
        .into_iter()
        .filter_map(|policy| {
            client_names
                .get(&policy.client_id)
                .map(|client_name| FleetUdpPolicy {
                    client_name: (*client_name).to_owned(),
                    name: policy.name,
                    public_port: policy.public_port,
                    target_addr: policy.target_addr,
                    max_sessions: policy.max_sessions,
                    session_idle_timeout_seconds: policy.session_idle_timeout_seconds,
                    bandwidth_limit_bps: policy.bandwidth_limit_bps,
                    enabled: policy.enabled,
                })
        })
        .collect();
    Ok(FleetPolicyBundle { tcp, udp })
}

pub(crate) fn import_policy_bundle(
    bundle: &FleetPolicyBundle,
    clients: &[ClientSummary],
    tunnels: &mut TunnelCatalog,
    dry_run: bool,
) -> anyhow::Result<FleetImportResult> {
    let mut result = FleetImportResult::default();
    let mut clients_by_name = HashMap::<&str, Vec<Uuid>>::new();
    for client in clients.iter().filter(|client| client.enabled) {
        clients_by_name
            .entry(client.name.as_str())
            .or_default()
            .push(client.client_id);
    }
    let mut existing_tcp = tunnels.list()?;
    let mut existing_udp = tunnels
        .list_udp()
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;

    for policy in &bundle.tcp {
        let Some(ids) = clients_by_name.get(policy.client_name.as_str()) else {
            result.conflicts.push(format!(
                "TCP {}: client '{}' is missing",
                policy.name, policy.client_name
            ));
            continue;
        };
        if ids.len() != 1 {
            result.conflicts.push(format!(
                "TCP {}: client name '{}' is ambiguous",
                policy.name, policy.client_name
            ));
            continue;
        }
        let client_id = ids[0];
        if let Some(existing) = existing_tcp.iter().find(|item| item.name == policy.name) {
            if existing.client_id == client_id
                && existing.public_port == policy.public_port
                && existing.target_addr == policy.target_addr
                && existing.max_connections == policy.max_connections
                && existing.bandwidth_limit_bps == policy.bandwidth_limit_bps
                && existing.enabled == policy.enabled
            {
                result.unchanged += 1;
            } else {
                result.conflicts.push(format!(
                    "TCP {}: an incompatible policy with the same name exists",
                    policy.name
                ));
            }
            continue;
        }
        if !dry_run {
            match tunnels.create(CreateTcpTunnelPolicy {
                client_id,
                name: policy.name.clone(),
                public_port: policy.public_port,
                target_addr: policy.target_addr.clone(),
                max_connections: Some(policy.max_connections),
                bandwidth_limit_bps: policy.bandwidth_limit_bps,
            }) {
                Ok(created) => {
                    if !policy.enabled {
                        tunnels.set_enabled(created.id, false)?;
                    }
                    existing_tcp.push(created);
                }
                Err(error) => {
                    result
                        .conflicts
                        .push(format!("TCP {}: {error}", policy.name));
                    continue;
                }
            }
        }
        result.created += 1;
    }

    for policy in &bundle.udp {
        let Some(ids) = clients_by_name.get(policy.client_name.as_str()) else {
            result.conflicts.push(format!(
                "UDP {}: client '{}' is missing",
                policy.name, policy.client_name
            ));
            continue;
        };
        if ids.len() != 1 {
            result.conflicts.push(format!(
                "UDP {}: client name '{}' is ambiguous",
                policy.name, policy.client_name
            ));
            continue;
        }
        let client_id = ids[0];
        if let Some(existing) = existing_udp.iter().find(|item| item.name == policy.name) {
            if existing.client_id == client_id
                && existing.public_port == policy.public_port
                && existing.target_addr == policy.target_addr
                && existing.max_sessions == policy.max_sessions
                && existing.session_idle_timeout_seconds == policy.session_idle_timeout_seconds
                && existing.bandwidth_limit_bps == policy.bandwidth_limit_bps
                && existing.enabled == policy.enabled
            {
                result.unchanged += 1;
            } else {
                result.conflicts.push(format!(
                    "UDP {}: an incompatible policy with the same name exists",
                    policy.name
                ));
            }
            continue;
        }
        if !dry_run {
            match tunnels.create_udp(CreateUdpTunnelPolicy {
                client_id,
                name: policy.name.clone(),
                public_port: policy.public_port,
                target_addr: policy.target_addr.clone(),
                max_sessions: Some(policy.max_sessions),
                session_idle_timeout_seconds: Some(policy.session_idle_timeout_seconds),
                bandwidth_limit_bps: policy.bandwidth_limit_bps,
            }) {
                Ok(created) => {
                    if !policy.enabled {
                        tunnels
                            .set_udp_enabled(created.id, false)
                            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                    }
                    existing_udp.push(created);
                }
                Err(error) => {
                    result
                        .conflicts
                        .push(format!("UDP {}: {error}", policy.name));
                    continue;
                }
            }
        }
        result.created += 1;
    }
    Ok(result)
}

pub(crate) struct FleetCatalog {
    database: Connection,
}

impl FleetCatalog {
    #[allow(dead_code)]
    pub(crate) fn open(data_dir: Option<&Path>) -> anyhow::Result<Self> {
        let database = Database::open(data_dir)?;
        Self::open_with_database(&database)
    }

    pub(crate) fn open_with_database(database: &Database) -> anyhow::Result<Self> {
        let database = database.connect()?;
        database.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS fleet_peers (
                id TEXT PRIMARY KEY NOT NULL,
                name TEXT NOT NULL UNIQUE,
                url TEXT NOT NULL UNIQUE,
                region TEXT NOT NULL,
                weight INTEGER NOT NULL,
                priority INTEGER NOT NULL,
                token_env TEXT NOT NULL,
                enabled INTEGER NOT NULL,
                created_unix_seconds INTEGER NOT NULL,
                updated_unix_seconds INTEGER NOT NULL
            );
            ",
        )?;
        Ok(Self { database })
    }

    pub(crate) fn list(&self) -> anyhow::Result<Vec<FleetPeer>> {
        let mut statement = self.database.prepare(
            "SELECT id, name, url, region, weight, priority, token_env, enabled, created_unix_seconds, updated_unix_seconds FROM fleet_peers ORDER BY priority, name",
        )?;
        let rows = statement.query_map([], read_peer)?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    pub(crate) fn create(
        &mut self,
        request: UpsertFleetPeer,
        now: u64,
    ) -> anyhow::Result<FleetPeer> {
        let request = validate(request)?;
        let peer = FleetPeer {
            id: Uuid::new_v4(),
            name: request.name,
            url: request.url,
            region: request.region,
            weight: request.weight,
            priority: request.priority,
            token_configured: std::env::var_os(&request.token_env).is_some(),
            token_env: request.token_env,
            enabled: request.enabled,
            created_unix_seconds: now,
            updated_unix_seconds: now,
        };
        self.persist(&peer)?;
        Ok(peer)
    }

    pub(crate) fn update(
        &mut self,
        id: Uuid,
        request: UpsertFleetPeer,
        now: u64,
    ) -> anyhow::Result<Option<FleetPeer>> {
        let request = validate(request)?;
        let Some(existing) = self.get(id)? else {
            return Ok(None);
        };
        let peer = FleetPeer {
            id,
            name: request.name,
            url: request.url,
            region: request.region,
            weight: request.weight,
            priority: request.priority,
            token_configured: std::env::var_os(&request.token_env).is_some(),
            token_env: request.token_env,
            enabled: request.enabled,
            created_unix_seconds: existing.created_unix_seconds,
            updated_unix_seconds: now,
        };
        self.persist(&peer)?;
        Ok(Some(peer))
    }

    pub(crate) fn delete(&mut self, id: Uuid) -> anyhow::Result<bool> {
        Ok(self
            .database
            .execute("DELETE FROM fleet_peers WHERE id = ?1", [id.to_string()])?
            > 0)
    }

    fn get(&self, id: Uuid) -> anyhow::Result<Option<FleetPeer>> {
        Ok(self
            .database
            .query_row(
                "SELECT id, name, url, region, weight, priority, token_env, enabled, created_unix_seconds, updated_unix_seconds FROM fleet_peers WHERE id = ?1",
                [id.to_string()],
                read_peer,
            )
            .optional()?)
    }

    fn persist(&self, peer: &FleetPeer) -> anyhow::Result<()> {
        self.database.execute(
            "INSERT OR REPLACE INTO fleet_peers (id, name, url, region, weight, priority, token_env, enabled, created_unix_seconds, updated_unix_seconds) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![peer.id.to_string(), peer.name, peer.url, peer.region, peer.weight, peer.priority, peer.token_env, i64::from(peer.enabled), peer.created_unix_seconds as i64, peer.updated_unix_seconds as i64],
        )?;
        Ok(())
    }
}

fn validate(request: UpsertFleetPeer) -> anyhow::Result<UpsertFleetPeer> {
    let name = request.name.trim();
    let region = request.region.trim();
    let token_env = request.token_env.trim();
    let url = request.url.trim().trim_end_matches('/');
    anyhow::ensure!(
        !name.is_empty() && name.chars().count() <= 80,
        "fleet peer name is invalid"
    );
    anyhow::ensure!(
        !region.is_empty() && region.chars().count() <= 80,
        "fleet peer region is invalid"
    );
    anyhow::ensure!(
        request.weight > 0 && request.weight <= 10_000,
        "fleet peer weight is invalid"
    );
    anyhow::ensure!(request.priority <= 10_000, "fleet peer priority is invalid");
    anyhow::ensure!(
        token_env.starts_with("LINKLAKE_")
            && token_env
                .bytes()
                .all(|value| value.is_ascii_uppercase() || value.is_ascii_digit() || value == b'_'),
        "fleet peer token environment variable is invalid"
    );
    let parsed = url.parse::<axum::http::Uri>()?;
    anyhow::ensure!(
        matches!(parsed.scheme_str(), Some("http" | "https")) && parsed.authority().is_some(),
        "fleet peer URL is invalid"
    );
    Ok(UpsertFleetPeer {
        name: name.to_owned(),
        url: url.to_owned(),
        region: region.to_owned(),
        token_env: token_env.to_owned(),
        ..request
    })
}

fn read_peer(row: &rusqlite::Row<'_>) -> rusqlite::Result<FleetPeer> {
    let id = row.get::<_, String>(0)?;
    let token_env = row.get::<_, String>(6)?;
    Ok(FleetPeer {
        id: Uuid::parse_str(&id).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?,
        name: row.get(1)?,
        url: row.get(2)?,
        region: row.get(3)?,
        weight: row.get::<_, u16>(4)?,
        priority: row.get::<_, u16>(5)?,
        token_configured: std::env::var_os(&token_env).is_some(),
        token_env,
        enabled: row.get::<_, i64>(7)? != 0,
        created_unix_seconds: row.get::<_, i64>(8)?.max(0) as u64,
        updated_unix_seconds: row.get::<_, i64>(9)?.max(0) as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use linklake_core::{ManagedConfigMode, ManagedConfigStatus};

    fn client(name: &str) -> ClientSummary {
        ClientSummary {
            client_id: Uuid::new_v4(),
            agent_instance_id: Uuid::new_v4(),
            agent_identity_public_key: None,
            name: name.to_owned(),
            platform: "linux".to_owned(),
            group_name: None,
            tags: Vec::new(),
            notes: None,
            enabled: true,
            created_unix_seconds: 1,
            token_rotated_unix_seconds: None,
            last_seen_unix_seconds: 1,
            config_mode: ManagedConfigMode::ServerManaged,
            config_sync_status: ManagedConfigStatus::Synchronized,
            applied_config_revision: None,
            config_sync_error: None,
            config_checked_unix_seconds: None,
        }
    }

    #[test]
    fn peers_are_validated_and_persisted() {
        let root = std::env::temp_dir().join(format!("linklake-fleet-{}", Uuid::new_v4()));
        let id;
        {
            let mut catalog = FleetCatalog::open(Some(&root)).unwrap();
            let peer = catalog
                .create(
                    UpsertFleetPeer {
                        name: "Singapore".into(),
                        url: "https://sg.example.com/".into(),
                        region: "ap-southeast".into(),
                        weight: 100,
                        priority: 10,
                        token_env: "LINKLAKE_FLEET_SG_TOKEN".into(),
                        enabled: true,
                    },
                    1,
                )
                .unwrap();
            id = peer.id;
            assert_eq!(peer.url, "https://sg.example.com");
        }
        assert_eq!(
            FleetCatalog::open(Some(&root)).unwrap().list().unwrap()[0].id,
            id
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn policy_import_previews_creates_and_reports_conflicts_without_overwriting() {
        let clients = vec![client("edge")];
        let mut catalog = TunnelCatalog::open(None).unwrap();
        let bundle = FleetPolicyBundle {
            tcp: vec![FleetTcpPolicy {
                client_name: "edge".into(),
                name: "game".into(),
                public_port: 32010,
                target_addr: "127.0.0.1:2333@2,127.0.0.1:2444@1".into(),
                max_connections: 64,
                bandwidth_limit_bps: None,
                enabled: true,
            }],
            udp: vec![FleetUdpPolicy {
                client_name: "edge".into(),
                name: "voice".into(),
                public_port: 32011,
                target_addr: "127.0.0.1:2334".into(),
                max_sessions: 256,
                session_idle_timeout_seconds: 120,
                bandwidth_limit_bps: None,
                enabled: true,
            }],
        };
        let preview = import_policy_bundle(&bundle, &clients, &mut catalog, true).unwrap();
        assert_eq!(preview.created, 2);
        assert!(catalog.list().unwrap().is_empty());

        let applied = import_policy_bundle(&bundle, &clients, &mut catalog, false).unwrap();
        assert_eq!(applied.created, 2);
        assert!(applied.conflicts.is_empty());
        let repeated = import_policy_bundle(&bundle, &clients, &mut catalog, false).unwrap();
        assert_eq!(repeated.unchanged, 2);

        let mut conflicting = bundle.clone();
        conflicting.tcp[0].public_port = 32012;
        let result = import_policy_bundle(&conflicting, &clients, &mut catalog, false).unwrap();
        assert_eq!(result.conflicts.len(), 1);
        assert_eq!(catalog.list().unwrap()[0].public_port, 32010);
    }
}
