//! 多云服务端目录与集中健康探测配置。

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};
use uuid::Uuid;

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

pub(crate) struct FleetCatalog {
    database: Connection,
}

impl FleetCatalog {
    pub(crate) fn open(data_dir: Option<&Path>) -> anyhow::Result<Self> {
        let database = if let Some(data_dir) = data_dir {
            fs::create_dir_all(data_dir)?;
            Connection::open(data_dir.join("linklake.sqlite3"))?
        } else {
            Connection::open_in_memory()?
        };
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
}
