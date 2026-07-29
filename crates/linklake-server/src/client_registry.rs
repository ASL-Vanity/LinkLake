use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use linklake_core::ClientSummary;
use rusqlite::{params, Connection};
use std::{collections::HashMap, fs, path::Path};
use uuid::Uuid;

use crate::unix_seconds;

pub(crate) struct ClientRegistry {
    clients: HashMap<Uuid, RegisteredClient>,
    database: Option<Connection>,
}

#[derive(Clone)]
struct RegisteredClient {
    name: String,
    platform: String,
    access_token_hash: String,
    last_seen_unix_seconds: u64,
}

pub(crate) enum Authentication {
    Authenticated,
    UnknownClient,
    InvalidToken,
}

impl ClientRegistry {
    pub(crate) fn open(data_dir: Option<&Path>) -> anyhow::Result<Self> {
        let Some(data_dir) = data_dir else {
            return Ok(Self {
                clients: HashMap::new(),
                database: None,
            });
        };
        fs::create_dir_all(data_dir)?;
        let database_path = data_dir.join("linklake.sqlite3");
        let database = Connection::open(database_path)?;
        database.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS clients (
                client_id TEXT PRIMARY KEY NOT NULL,
                name TEXT NOT NULL,
                platform TEXT NOT NULL,
                access_token_hash TEXT NOT NULL,
                last_seen_unix_seconds INTEGER NOT NULL
            );
            ",
        )?;

        let mut statement = database.prepare(
            "SELECT client_id, name, platform, access_token_hash, last_seen_unix_seconds FROM clients",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                RegisteredClient {
                    name: row.get(1)?,
                    platform: row.get(2)?,
                    access_token_hash: row.get(3)?,
                    last_seen_unix_seconds: row.get(4)?,
                },
            ))
        })?;
        let mut clients = HashMap::new();
        for row in rows {
            let (client_id, client) = row?;
            let client_id = Uuid::parse_str(&client_id)
                .map_err(|_| anyhow::anyhow!("client database contains an invalid client ID"))?;
            clients.insert(client_id, client);
        }
        drop(statement);

        Ok(Self {
            clients,
            database: Some(database),
        })
    }

    pub(crate) fn count(&self) -> usize {
        self.clients.len()
    }

    pub(crate) fn contains(&self, client_id: Uuid) -> bool {
        self.clients.contains_key(&client_id)
    }

    pub(crate) fn summaries(&self) -> Vec<ClientSummary> {
        let mut summaries: Vec<_> = self
            .clients
            .iter()
            .map(|(client_id, client)| ClientSummary {
                client_id: *client_id,
                name: client.name.clone(),
                platform: client.platform.clone(),
                last_seen_unix_seconds: client.last_seen_unix_seconds,
            })
            .collect();
        summaries.sort_by(|left, right| left.name.cmp(&right.name));
        summaries
    }

    pub(crate) fn enroll(
        &mut self,
        name: String,
        platform: String,
    ) -> anyhow::Result<(Uuid, String)> {
        let client_id = Uuid::new_v4();
        let client_token = format!("llc_{}", Uuid::new_v4().simple());
        let client = RegisteredClient {
            name,
            platform,
            access_token_hash: hash_token(&client_token)?,
            last_seen_unix_seconds: unix_seconds(),
        };
        self.persist_client(client_id, &client)?;
        self.clients.insert(client_id, client);
        Ok((client_id, client_token))
    }

    pub(crate) fn authenticate_and_touch(
        &mut self,
        client_id: Uuid,
        token: &str,
    ) -> anyhow::Result<Authentication> {
        let Some(mut client) = self.clients.get(&client_id).cloned() else {
            return Ok(Authentication::UnknownClient);
        };
        if !verify_token(token, &client.access_token_hash)? {
            return Ok(Authentication::InvalidToken);
        }
        client.last_seen_unix_seconds = unix_seconds();
        self.persist_client(client_id, &client)?;
        self.clients.insert(client_id, client);
        Ok(Authentication::Authenticated)
    }

    fn persist_client(&self, client_id: Uuid, client: &RegisteredClient) -> anyhow::Result<()> {
        let Some(database) = &self.database else {
            return Ok(());
        };
        database.execute(
            "
            INSERT INTO clients (client_id, name, platform, access_token_hash, last_seen_unix_seconds)
            VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(client_id) DO UPDATE SET
                name = excluded.name,
                platform = excluded.platform,
                access_token_hash = excluded.access_token_hash,
                last_seen_unix_seconds = excluded.last_seen_unix_seconds
            ",
            params![
                client_id.to_string(),
                client.name,
                client.platform,
                client.access_token_hash,
                client.last_seen_unix_seconds,
            ],
        )?;
        Ok(())
    }
}

fn hash_token(token: &str) -> anyhow::Result<String> {
    let salt = SaltString::encode_b64(Uuid::new_v4().as_bytes())
        .map_err(|error| anyhow::anyhow!("could not create token salt: {error}"))?;
    Ok(Argon2::default()
        .hash_password(token.as_bytes(), &salt)
        .map_err(|error| anyhow::anyhow!("could not hash client token: {error}"))?
        .to_string())
}

fn verify_token(token: &str, token_hash: &str) -> anyhow::Result<bool> {
    let parsed_hash = PasswordHash::new(token_hash)
        .map_err(|error| anyhow::anyhow!("stored client token hash is invalid: {error}"))?;
    Ok(Argon2::default()
        .verify_password(token.as_bytes(), &parsed_hash)
        .is_ok())
}

#[cfg(test)]
mod tests {
    use super::{Authentication, ClientRegistry};

    #[test]
    fn client_token_is_verified_without_being_stored_in_plaintext() {
        let mut registry = ClientRegistry::open(None).expect("in-memory registry should open");
        let (client_id, token) = registry
            .enroll("test-client".to_owned(), "windows".to_owned())
            .expect("client should enroll");

        assert!(matches!(
            registry.authenticate_and_touch(client_id, &token),
            Ok(Authentication::Authenticated)
        ));
        assert!(matches!(
            registry.authenticate_and_touch(client_id, "wrong-token"),
            Ok(Authentication::InvalidToken)
        ));
    }

    #[test]
    fn persistent_registry_survives_reopen() {
        let data_dir =
            std::env::temp_dir().join(format!("linklake-registry-test-{}", uuid::Uuid::new_v4()));
        let (client_id, token) = {
            let mut registry =
                ClientRegistry::open(Some(&data_dir)).expect("persistent registry should open");
            registry
                .enroll("persisted-client".to_owned(), "windows".to_owned())
                .expect("client should enroll")
        };

        let mut reloaded =
            ClientRegistry::open(Some(&data_dir)).expect("persistent registry should reopen");
        assert!(matches!(
            reloaded.authenticate_and_touch(client_id, &token),
            Ok(Authentication::Authenticated)
        ));
        drop(reloaded);
        std::fs::remove_dir_all(data_dir).expect("temporary registry should be removed");
    }
}
