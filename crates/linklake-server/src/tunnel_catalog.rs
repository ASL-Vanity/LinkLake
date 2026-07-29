use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};
use uuid::Uuid;

pub(crate) const MIN_TCP_TUNNEL_PORT: u16 = 32_000;
pub(crate) const MAX_TCP_TUNNEL_PORT: u16 = 32_999;
const DEFAULT_MAX_CONNECTIONS: u16 = 64;
const MIN_BANDWIDTH_LIMIT_BPS: u64 = 1_024;
const MAX_BANDWIDTH_LIMIT_BPS: u64 = 1_000_000_000;

#[derive(Deserialize)]
pub(crate) struct CreateTcpTunnelPolicy {
    pub(crate) client_id: Uuid,
    pub(crate) name: String,
    pub(crate) public_port: u16,
    pub(crate) target_addr: String,
    pub(crate) max_connections: Option<u16>,
    pub(crate) bandwidth_limit_bps: Option<u64>,
}

#[derive(Serialize, Clone)]
pub(crate) struct TcpTunnelPolicy {
    pub(crate) id: Uuid,
    pub(crate) client_id: Uuid,
    pub(crate) name: String,
    pub(crate) public_port: u16,
    pub(crate) target_addr: String,
    pub(crate) max_connections: u16,
    pub(crate) bandwidth_limit_bps: Option<u64>,
    pub(crate) enabled: bool,
}

#[derive(Debug, PartialEq)]
pub(crate) struct TcpTunnelRuntimePolicy {
    pub(crate) max_connections: usize,
    pub(crate) bandwidth_limit_bps: Option<u64>,
}

pub(crate) struct TunnelCatalog {
    database: Connection,
}

impl TunnelCatalog {
    pub(crate) fn open(data_dir: Option<&Path>) -> anyhow::Result<Self> {
        let database = match data_dir {
            Some(data_dir) => {
                fs::create_dir_all(data_dir)?;
                Connection::open(data_dir.join("linklake.sqlite3"))?
            }
            None => Connection::open_in_memory()?,
        };
        database.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS tcp_tunnel_policies (
                id TEXT PRIMARY KEY NOT NULL,
                client_id TEXT NOT NULL,
                name TEXT NOT NULL,
                public_port INTEGER NOT NULL UNIQUE,
                target_addr TEXT NOT NULL,
                max_connections INTEGER NOT NULL DEFAULT 64,
                bandwidth_limit_bps INTEGER,
                enabled INTEGER NOT NULL DEFAULT 1
            );
            ",
        )?;
        let count: i64 = database.query_row("SELECT COUNT(*) FROM pragma_table_info('tcp_tunnel_policies') WHERE name = 'max_connections'", [], |row| row.get(0))?;
        if count == 0 {
            database.execute("ALTER TABLE tcp_tunnel_policies ADD COLUMN max_connections INTEGER NOT NULL DEFAULT 64", [])?;
        }
        let count: i64 = database.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('tcp_tunnel_policies') WHERE name = 'bandwidth_limit_bps'",
            [],
            |row| row.get(0),
        )?;
        if count == 0 {
            database.execute(
                "ALTER TABLE tcp_tunnel_policies ADD COLUMN bandwidth_limit_bps INTEGER",
                [],
            )?;
        }
        Ok(Self { database })
    }

    pub(crate) fn create(
        &mut self,
        request: CreateTcpTunnelPolicy,
    ) -> anyhow::Result<TcpTunnelPolicy> {
        validate_policy(&request)?;
        let policy = TcpTunnelPolicy {
            id: Uuid::new_v4(),
            client_id: request.client_id,
            name: request.name.trim().to_owned(),
            public_port: request.public_port,
            target_addr: request.target_addr.trim().to_owned(),
            max_connections: request.max_connections.unwrap_or(DEFAULT_MAX_CONNECTIONS),
            bandwidth_limit_bps: request.bandwidth_limit_bps,
            enabled: true,
        };
        self.database.execute(
            "INSERT INTO tcp_tunnel_policies (id, client_id, name, public_port, target_addr, max_connections, bandwidth_limit_bps, enabled) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1)",
            params![policy.id.to_string(), policy.client_id.to_string(), policy.name, policy.public_port, policy.target_addr, policy.max_connections, policy.bandwidth_limit_bps],
        )?;
        Ok(policy)
    }

    pub(crate) fn list(&self) -> anyhow::Result<Vec<TcpTunnelPolicy>> {
        let mut statement = self.database.prepare(
            "SELECT id, client_id, name, public_port, target_addr, max_connections, bandwidth_limit_bps, enabled FROM tcp_tunnel_policies ORDER BY public_port",
        )?;
        let rows = statement.query_map([], |row| {
            let id: String = row.get(0)?;
            let client_id: String = row.get(1)?;
            Ok(TcpTunnelPolicy {
                id: Uuid::parse_str(&id).map_err(|_| rusqlite::Error::InvalidQuery)?,
                client_id: Uuid::parse_str(&client_id)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?,
                name: row.get(2)?,
                public_port: row.get(3)?,
                target_addr: row.get(4)?,
                max_connections: row.get(5)?,
                bandwidth_limit_bps: row.get(6)?,
                enabled: row.get::<_, i64>(7)? != 0,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub(crate) fn set_enabled(&mut self, id: Uuid, enabled: bool) -> anyhow::Result<bool> {
        Ok(self.database.execute(
            "UPDATE tcp_tunnel_policies SET enabled = ?1 WHERE id = ?2",
            params![enabled, id.to_string()],
        )? != 0)
    }

    pub(crate) fn delete(&mut self, id: Uuid) -> anyhow::Result<bool> {
        Ok(self.database.execute(
            "DELETE FROM tcp_tunnel_policies WHERE id = ?1",
            [id.to_string()],
        )? != 0)
    }

    pub(crate) fn runtime_policy(
        &self,
        client_id: Uuid,
        name: &str,
        public_port: u16,
        target_addr: &str,
    ) -> anyhow::Result<Option<TcpTunnelRuntimePolicy>> {
        let value: Option<(i64, Option<i64>)> = self.database.query_row(
            "SELECT max_connections, bandwidth_limit_bps FROM tcp_tunnel_policies WHERE client_id = ?1 AND name = ?2 AND public_port = ?3 AND target_addr = ?4 AND enabled = 1",
            params![client_id.to_string(), name, public_port, target_addr],
            |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional()?;
        Ok(value.map(
            |(max_connections, bandwidth_limit_bps)| TcpTunnelRuntimePolicy {
                max_connections: max_connections as usize,
                bandwidth_limit_bps: bandwidth_limit_bps.map(|value| value as u64),
            },
        ))
    }
}

fn validate_policy(request: &CreateTcpTunnelPolicy) -> anyhow::Result<()> {
    anyhow::ensure!(
        !request.name.trim().is_empty() && request.name.len() <= 80,
        "tunnel name is invalid"
    );
    anyhow::ensure!(
        (MIN_TCP_TUNNEL_PORT..=MAX_TCP_TUNNEL_PORT).contains(&request.public_port),
        "public port is outside the permitted range"
    );
    anyhow::ensure!(
        valid_target_address(request.target_addr.trim()) && request.target_addr.len() <= 255,
        "target address is invalid"
    );
    anyhow::ensure!(
        request.max_connections.unwrap_or(DEFAULT_MAX_CONNECTIONS) >= 1
            && request.max_connections.unwrap_or(DEFAULT_MAX_CONNECTIONS) <= 1024,
        "connection limit is invalid"
    );
    anyhow::ensure!(
        request.bandwidth_limit_bps.is_none_or(|limit| {
            (MIN_BANDWIDTH_LIMIT_BPS..=MAX_BANDWIDTH_LIMIT_BPS).contains(&limit)
        }),
        "bandwidth limit is invalid"
    );
    Ok(())
}

fn valid_target_address(value: &str) -> bool {
    if value.parse::<std::net::SocketAddr>().is_ok() {
        return true;
    }
    let Some((host, port)) = value.rsplit_once(':') else {
        return false;
    };
    !host.is_empty()
        && !host.chars().any(char::is_whitespace)
        && port.parse::<u16>().is_ok_and(|port| port != 0)
}

#[cfg(test)]
mod tests {
    use super::{CreateTcpTunnelPolicy, TunnelCatalog};
    use uuid::Uuid;

    #[test]
    fn enabled_policy_authorizes_only_an_exact_tunnel_registration() {
        let client_id = Uuid::new_v4();
        let mut catalog = TunnelCatalog::open(None).expect("catalog should open");
        let policy = catalog
            .create(CreateTcpTunnelPolicy {
                client_id,
                name: "game".to_owned(),
                public_port: 32001,
                target_addr: "127.0.0.1:2333".to_owned(),
                max_connections: Some(12),
                bandwidth_limit_bps: Some(1_000_000),
            })
            .expect("policy should be created");
        assert_eq!(
            catalog
                .runtime_policy(client_id, "game", 32001, "127.0.0.1:2333")
                .expect("authorization should work"),
            Some(super::TcpTunnelRuntimePolicy {
                max_connections: 12,
                bandwidth_limit_bps: Some(1_000_000),
            })
        );
        assert_eq!(
            catalog
                .runtime_policy(client_id, "game", 32002, "127.0.0.1:2333")
                .expect("authorization should work"),
            None
        );
        catalog
            .set_enabled(policy.id, false)
            .expect("policy should update");
        assert_eq!(
            catalog
                .runtime_policy(client_id, "game", 32001, "127.0.0.1:2333")
                .expect("authorization should work"),
            None
        );
    }
}
