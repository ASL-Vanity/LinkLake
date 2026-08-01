//! 管理 API Token 的持久化、哈希验证和权限映射。

use getrandom::fill as random_fill;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fmt, fs, path::Path, str::FromStr};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ApiTokenScope {
    Read,
    Write,
    Administrator,
}

impl fmt::Display for ApiTokenScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Administrator => "administrator",
        })
    }
}

impl FromStr for ApiTokenScope {
    type Err = anyhow::Error;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "read" => Ok(Self::Read),
            "write" => Ok(Self::Write),
            "administrator" => Ok(Self::Administrator),
            _ => anyhow::bail!("invalid API token scope"),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct ApiTokenRecord {
    pub(crate) id: Uuid,
    pub(crate) name: String,
    pub(crate) scope: ApiTokenScope,
    pub(crate) created_unix_seconds: u64,
    pub(crate) expires_unix_seconds: Option<u64>,
    pub(crate) last_used_unix_seconds: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CreateApiToken {
    pub(crate) name: String,
    pub(crate) scope: ApiTokenScope,
    pub(crate) expires_unix_seconds: Option<u64>,
}

#[derive(Debug, Serialize)]
pub(crate) struct CreatedApiToken {
    #[serde(flatten)]
    pub(crate) record: ApiTokenRecord,
    pub(crate) token: String,
}

pub(crate) struct ApiTokenCatalog {
    database: Connection,
}

impl ApiTokenCatalog {
    pub(crate) fn open(data_dir: Option<&Path>) -> anyhow::Result<Self> {
        let database = if let Some(data_dir) = data_dir {
            fs::create_dir_all(data_dir)?;
            Connection::open(data_dir.join("linklake.sqlite3"))?
        } else {
            Connection::open_in_memory()?
        };
        database.execute_batch("CREATE TABLE IF NOT EXISTS management_api_tokens (id TEXT PRIMARY KEY NOT NULL, name TEXT NOT NULL UNIQUE, scope TEXT NOT NULL, token_hash BLOB NOT NULL UNIQUE, created_unix_seconds INTEGER NOT NULL, expires_unix_seconds INTEGER, last_used_unix_seconds INTEGER); CREATE INDEX IF NOT EXISTS management_api_tokens_expiry ON management_api_tokens(expires_unix_seconds);")?;
        Ok(Self { database })
    }

    pub(crate) fn list(&self) -> anyhow::Result<Vec<ApiTokenRecord>> {
        let mut statement = self.database.prepare("SELECT id, name, scope, created_unix_seconds, expires_unix_seconds, last_used_unix_seconds FROM management_api_tokens ORDER BY name")?;
        let records = statement
            .query_map([], read_record)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(records)
    }

    pub(crate) fn create(
        &mut self,
        request: CreateApiToken,
        now: u64,
    ) -> anyhow::Result<CreatedApiToken> {
        let name = request.name.trim();
        anyhow::ensure!(
            !name.is_empty() && name.chars().count() <= 80,
            "API token name is invalid"
        );
        anyhow::ensure!(
            request
                .expires_unix_seconds
                .is_none_or(|expires| expires > now),
            "API token expiry is invalid"
        );
        let mut random = [0_u8; 32];
        random_fill(&mut random)?;
        let token = format!("llapi_{}", hex(&random));
        let record = ApiTokenRecord {
            id: Uuid::new_v4(),
            name: name.to_owned(),
            scope: request.scope,
            created_unix_seconds: now,
            expires_unix_seconds: request.expires_unix_seconds,
            last_used_unix_seconds: None,
        };
        self.database.execute("INSERT INTO management_api_tokens (id, name, scope, token_hash, created_unix_seconds, expires_unix_seconds) VALUES (?1, ?2, ?3, ?4, ?5, ?6)", params![record.id.to_string(), record.name, record.scope.to_string(), token_hash(&token).to_vec(), now as i64, record.expires_unix_seconds.map(|value| value as i64)])?;
        Ok(CreatedApiToken { record, token })
    }

    pub(crate) fn revoke(&mut self, id: Uuid) -> anyhow::Result<bool> {
        Ok(self.database.execute(
            "DELETE FROM management_api_tokens WHERE id = ?1",
            [id.to_string()],
        )? > 0)
    }

    pub(crate) fn authenticate(
        &mut self,
        token: &str,
        now: u64,
    ) -> anyhow::Result<Option<ApiTokenRecord>> {
        if !token.starts_with("llapi_") {
            return Ok(None);
        }
        let hash = token_hash(token);
        let record = self.database.query_row("SELECT id, name, scope, created_unix_seconds, expires_unix_seconds, last_used_unix_seconds FROM management_api_tokens WHERE token_hash = ?1", [hash.to_vec()], read_record).optional()?;
        let Some(mut record) = record else {
            return Ok(None);
        };
        if record
            .expires_unix_seconds
            .is_some_and(|expires| expires <= now)
        {
            return Ok(None);
        }
        self.database.execute(
            "UPDATE management_api_tokens SET last_used_unix_seconds = ?2 WHERE id = ?1",
            params![record.id.to_string(), now as i64],
        )?;
        record.last_used_unix_seconds = Some(now);
        Ok(Some(record))
    }
}

fn token_hash(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|value| format!("{value:02x}")).collect()
}

fn read_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<ApiTokenRecord> {
    let id = row.get::<_, String>(0)?;
    let scope = row.get::<_, String>(2)?;
    Ok(ApiTokenRecord {
        id: Uuid::parse_str(&id).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?,
        name: row.get(1)?,
        scope: scope.parse().map_err(|error: anyhow::Error| {
            rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, error.into())
        })?,
        created_unix_seconds: row.get::<_, i64>(3)?.max(0) as u64,
        expires_unix_seconds: row
            .get::<_, Option<i64>>(4)?
            .map(|value| value.max(0) as u64),
        last_used_unix_seconds: row
            .get::<_, Option<i64>>(5)?
            .map(|value| value.max(0) as u64),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn token_is_returned_once_hashed_and_revocable() {
        let mut catalog = ApiTokenCatalog::open(None).unwrap();
        let created = catalog
            .create(
                CreateApiToken {
                    name: "automation".into(),
                    scope: ApiTokenScope::Write,
                    expires_unix_seconds: Some(200),
                },
                100,
            )
            .unwrap();
        assert!(catalog.authenticate(&created.token, 150).unwrap().is_some());
        assert!(catalog.authenticate(&created.token, 201).unwrap().is_none());
        assert!(catalog.revoke(created.record.id).unwrap());
    }
}
