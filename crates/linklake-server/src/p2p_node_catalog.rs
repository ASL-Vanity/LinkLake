use linklake_core::p2p_protocol::{P2pCandidate, P2pIrohAddress, P2pTransport};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use std::{net::SocketAddr, path::Path};
use uuid::Uuid;

use crate::database::Database;

const MAX_CANDIDATES: usize = 8;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct P2pNodeRecord {
    pub(crate) client_id: Uuid,
    pub(crate) candidates: Vec<P2pCandidate>,
    pub(crate) updated_unix_seconds: u64,
}

pub(crate) struct P2pNodeCatalog {
    database: Connection,
}

impl P2pNodeCatalog {
    #[allow(dead_code)]
    pub(crate) fn open(data_dir: Option<&Path>) -> anyhow::Result<Self> {
        let database = Database::open(data_dir)?;
        Self::open_with_database(&database)
    }

    pub(crate) fn open_with_database(database: &Database) -> anyhow::Result<Self> {
        let database = database.connect()?;
        database.execute_batch(
            "CREATE TABLE IF NOT EXISTS p2p_nodes (
                client_id TEXT PRIMARY KEY NOT NULL,
                candidates_json TEXT NOT NULL,
                updated_unix_seconds INTEGER NOT NULL
            );",
        )?;
        Ok(Self { database })
    }

    pub(crate) fn upsert(
        &mut self,
        client_id: Uuid,
        mut candidates: Vec<P2pCandidate>,
        now: u64,
    ) -> anyhow::Result<P2pNodeRecord> {
        normalize_candidates(&mut candidates)?;
        candidates.sort_by_key(|candidate| candidate.priority);
        let json = serde_json::to_string(&candidates)?;
        self.database.execute(
            "INSERT INTO p2p_nodes (client_id, candidates_json, updated_unix_seconds) VALUES (?1, ?2, ?3)
             ON CONFLICT(client_id) DO UPDATE SET candidates_json = excluded.candidates_json, updated_unix_seconds = excluded.updated_unix_seconds",
            params![client_id.to_string(), json, now],
        )?;
        Ok(P2pNodeRecord {
            client_id,
            candidates,
            updated_unix_seconds: now,
        })
    }

    pub(crate) fn get(&self, client_id: Uuid) -> anyhow::Result<Option<P2pNodeRecord>> {
        self.database
            .query_row(
                "SELECT candidates_json, updated_unix_seconds FROM p2p_nodes WHERE client_id = ?1",
                [client_id.to_string()],
                |row| {
                    let json: String = row.get(0)?;
                    let candidates =
                        serde_json::from_str(&json).map_err(|_| rusqlite::Error::InvalidQuery)?;
                    Ok(P2pNodeRecord {
                        client_id,
                        candidates,
                        updated_unix_seconds: row.get(1)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub(crate) fn list(&self) -> anyhow::Result<Vec<P2pNodeRecord>> {
        let mut statement = self.database.prepare(
            "SELECT client_id, candidates_json, updated_unix_seconds FROM p2p_nodes ORDER BY updated_unix_seconds DESC",
        )?;
        let rows = statement.query_map([], |row| {
            let client_id: String = row.get(0)?;
            let json: String = row.get(1)?;
            Ok(P2pNodeRecord {
                client_id: Uuid::parse_str(&client_id)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?,
                candidates: serde_json::from_str(&json)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?,
                updated_unix_seconds: row.get(2)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }
}

fn normalize_candidates(candidates: &mut [P2pCandidate]) -> anyhow::Result<()> {
    anyhow::ensure!(
        !candidates.is_empty() && candidates.len() <= MAX_CANDIDATES,
        "invalid P2P candidate count"
    );
    let mut endpoints = std::collections::HashSet::new();
    for candidate in candidates {
        match candidate.transport {
            P2pTransport::Tcp => {
                let endpoint = candidate
                    .endpoint
                    .parse::<SocketAddr>()
                    .map_err(|_| anyhow::anyhow!("invalid P2P candidate"))?;
                anyhow::ensure!(
                    endpoints.insert(format!("tcp:{endpoint}")),
                    "invalid or duplicate P2P candidate"
                );
                candidate.endpoint = endpoint.to_string();
            }
            P2pTransport::IrohQuic => {
                let address: P2pIrohAddress = serde_json::from_str(&candidate.endpoint)
                    .map_err(|_| anyhow::anyhow!("invalid Iroh P2P candidate"))?;
                anyhow::ensure!(
                    !address.endpoint_id.is_empty()
                        && address.endpoint_id.len() <= 128
                        && !address.direct_addresses.is_empty()
                        && address.direct_addresses.len() <= MAX_CANDIDATES
                        && address
                            .direct_addresses
                            .iter()
                            .all(|value| value.parse::<SocketAddr>().is_ok())
                        && address.network.as_ref().is_none_or(|network| {
                            network
                                .global_v4
                                .as_ref()
                                .is_none_or(|value| value.parse::<std::net::SocketAddrV4>().is_ok())
                                && network.global_v6.as_ref().is_none_or(|value| {
                                    value.parse::<std::net::SocketAddrV6>().is_ok()
                                })
                        })
                        && address.relay_url.as_ref().is_none_or(|value| {
                            value.starts_with("https://") && value.len() <= 512
                        }),
                    "invalid Iroh P2P candidate"
                );
                let normalized = serde_json::to_string(&address)?;
                anyhow::ensure!(
                    endpoints.insert(format!("iroh:{normalized}")),
                    "invalid or duplicate P2P candidate"
                );
                candidate.endpoint = normalized;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_candidates_are_validated_sorted_and_persisted() {
        let id = Uuid::new_v4();
        let mut catalog = P2pNodeCatalog::open(None).expect("catalog should open");
        catalog
            .upsert(
                id,
                vec![
                    P2pCandidate {
                        transport: P2pTransport::Tcp,
                        endpoint: "127.0.0.1:40002".to_owned(),
                        priority: 20,
                    },
                    P2pCandidate {
                        transport: P2pTransport::Tcp,
                        endpoint: "127.0.0.1:40001".to_owned(),
                        priority: 10,
                    },
                ],
                100,
            )
            .expect("node should register");
        let node = catalog
            .get(id)
            .expect("node should query")
            .expect("node should exist");
        assert_eq!(node.candidates[0].priority, 10);
    }

    #[test]
    fn duplicate_and_invalid_candidates_are_rejected() {
        let id = Uuid::new_v4();
        let mut catalog = P2pNodeCatalog::open(None).expect("catalog should open");
        assert!(catalog
            .upsert(
                id,
                vec![
                    P2pCandidate {
                        transport: P2pTransport::Tcp,
                        endpoint: "[::1]:40001".to_owned(),
                        priority: 0,
                    },
                    P2pCandidate {
                        transport: P2pTransport::Tcp,
                        endpoint: "[0:0:0:0:0:0:0:1]:40001".to_owned(),
                        priority: 1,
                    },
                ],
                100,
            )
            .is_err());
        assert!(catalog
            .upsert(
                id,
                vec![P2pCandidate {
                    transport: P2pTransport::Tcp,
                    endpoint: "not-an-address".to_owned(),
                    priority: 0,
                }],
                100,
            )
            .is_err());
    }
}
