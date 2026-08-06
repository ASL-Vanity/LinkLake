//! 多实例成员租约、Leader 选举与 fencing token。

use crate::storage::{CoordinationStorage, StorageBackend};
use rusqlite::{
    params, types::Type as SqliteType, OptionalExtension, Transaction as SqliteTransaction,
};
use serde::Serialize;
use std::{io, time::Duration};
use tokio_postgres::{Row as PostgresRow, Transaction as PostgresTransaction};

const SQLITE_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS ha_members (
    instance_id TEXT PRIMARY KEY NOT NULL,
    started_unix_seconds INTEGER NOT NULL,
    last_seen_unix_seconds INTEGER NOT NULL,
    lease_until_unix_seconds INTEGER NOT NULL,
    metadata_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ha_members_lease ON ha_members(lease_until_unix_seconds);
CREATE TABLE IF NOT EXISTS ha_fencing_sequence (
    singleton_id INTEGER PRIMARY KEY NOT NULL CHECK(singleton_id = 1),
    next_token INTEGER NOT NULL CHECK(next_token > 0)
);
INSERT OR IGNORE INTO ha_fencing_sequence(singleton_id, next_token) VALUES (1, 1);
CREATE TABLE IF NOT EXISTS ha_leader (
    singleton_id INTEGER PRIMARY KEY NOT NULL CHECK(singleton_id = 1),
    instance_id TEXT NOT NULL,
    fencing_token INTEGER NOT NULL CHECK(fencing_token > 0),
    acquired_unix_seconds INTEGER NOT NULL,
    renewed_unix_seconds INTEGER NOT NULL,
    lease_until_unix_seconds INTEGER NOT NULL
);
"#;

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct HaMember {
    pub(crate) instance_id: String,
    pub(crate) started_unix_seconds: u64,
    pub(crate) last_seen_unix_seconds: u64,
    pub(crate) lease_until_unix_seconds: u64,
    pub(crate) metadata_json: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct LeadershipLease {
    pub(crate) instance_id: String,
    pub(crate) fencing_token: u64,
    pub(crate) acquired_unix_seconds: u64,
    pub(crate) renewed_unix_seconds: u64,
    pub(crate) lease_until_unix_seconds: u64,
}

#[derive(Clone)]
pub(crate) struct HaCoordinator {
    storage: CoordinationStorage,
    instance_id: String,
    metadata_json: String,
    member_lease_seconds: u64,
    leader_lease_seconds: u64,
}

impl HaCoordinator {
    pub(crate) fn open(
        storage: CoordinationStorage,
        instance_id: impl Into<String>,
        metadata_json: impl Into<String>,
        member_lease: Duration,
        leader_lease: Duration,
    ) -> anyhow::Result<Self> {
        let instance_id = instance_id.into();
        anyhow::ensure!(!instance_id.trim().is_empty(), "HA instance ID is required");
        let metadata_json = metadata_json.into();
        serde_json::from_str::<serde_json::Value>(&metadata_json)
            .map_err(|error| anyhow::anyhow!("HA member metadata must be valid JSON: {error}"))?;
        let member_lease_seconds = lease_seconds(member_lease, "member")?;
        let leader_lease_seconds = lease_seconds(leader_lease, "leader")?;
        if let CoordinationStorage::Sqlite(database) = &storage {
            database.with_connection(|connection| {
                connection.execute_batch(SQLITE_SCHEMA)?;
                Ok(())
            })?;
        }
        Ok(Self {
            storage,
            instance_id,
            metadata_json,
            member_lease_seconds,
            leader_lease_seconds,
        })
    }

    pub(crate) fn backend(&self) -> StorageBackend {
        self.storage.backend()
    }

    pub(crate) fn instance_id(&self) -> &str {
        &self.instance_id
    }

    pub(crate) async fn register_or_renew_member(&self) -> anyhow::Result<HaMember> {
        match &self.storage {
            CoordinationStorage::Sqlite(database) => database.with_transaction(|transaction| {
                let now = sqlite_now(transaction)?;
                let lease_until = now.saturating_add(self.member_lease_seconds);
                transaction.execute(
                    "INSERT INTO ha_members(
                         instance_id, started_unix_seconds, last_seen_unix_seconds,
                         lease_until_unix_seconds, metadata_json
                     ) VALUES (?1, ?2, ?2, ?3, ?4)
                     ON CONFLICT(instance_id) DO UPDATE SET
                         last_seen_unix_seconds = excluded.last_seen_unix_seconds,
                         lease_until_unix_seconds = excluded.lease_until_unix_seconds,
                         metadata_json = excluded.metadata_json",
                    params![
                        self.instance_id,
                        as_i64(now)?,
                        as_i64(lease_until)?,
                        self.metadata_json,
                    ],
                )?;
                read_sqlite_member(transaction, &self.instance_id)?
                    .ok_or_else(|| anyhow::anyhow!("HA member disappeared after registration"))
            }),
            CoordinationStorage::Postgres(_) => {
                let mut client = self.storage.postgres_client().await?;
                let transaction = client.transaction().await?;
                let now = postgres_now(&transaction).await?;
                let lease_until = now.saturating_add(self.member_lease_seconds);
                let row = transaction
                    .query_one(
                        "INSERT INTO linklake_ha_members(
                             instance_id, started_at, last_seen_at, lease_until, metadata_json
                         ) VALUES ($1, to_timestamp($2), to_timestamp($2), to_timestamp($3), $4::jsonb)
                         ON CONFLICT(instance_id) DO UPDATE SET
                             last_seen_at = EXCLUDED.last_seen_at,
                             lease_until = EXCLUDED.lease_until,
                             metadata_json = EXCLUDED.metadata_json
                         RETURNING instance_id,
                             CAST(EXTRACT(EPOCH FROM started_at) AS BIGINT),
                             CAST(EXTRACT(EPOCH FROM last_seen_at) AS BIGINT),
                             CAST(EXTRACT(EPOCH FROM lease_until) AS BIGINT),
                             metadata_json::text",
                        &[
                            &self.instance_id,
                            &as_i64(now)?,
                            &as_i64(lease_until)?,
                            &self.metadata_json,
                        ],
                    )
                    .await?;
                let member = postgres_member(&row)?;
                transaction.commit().await?;
                Ok(member)
            }
        }
    }

    pub(crate) async fn active_members(&self) -> anyhow::Result<Vec<HaMember>> {
        match &self.storage {
            CoordinationStorage::Sqlite(database) => database.with_connection(|connection| {
                let now: i64 = connection.query_row(
                    "SELECT CAST(unixepoch('now') AS INTEGER)",
                    [],
                    |row| row.get(0),
                )?;
                let mut statement = connection.prepare(
                    "SELECT instance_id, started_unix_seconds, last_seen_unix_seconds,
                            lease_until_unix_seconds, metadata_json
                     FROM ha_members WHERE lease_until_unix_seconds > ?1
                     ORDER BY instance_id",
                )?;
                let rows = statement.query_map([now], sqlite_member_row)?;
                rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
            }),
            CoordinationStorage::Postgres(_) => {
                let client = self.storage.postgres_client().await?;
                client
                    .query(
                        "SELECT instance_id,
                            CAST(EXTRACT(EPOCH FROM started_at) AS BIGINT),
                            CAST(EXTRACT(EPOCH FROM last_seen_at) AS BIGINT),
                            CAST(EXTRACT(EPOCH FROM lease_until) AS BIGINT),
                            metadata_json::text
                         FROM linklake_ha_members
                         WHERE lease_until > clock_timestamp()
                         ORDER BY instance_id",
                        &[],
                    )
                    .await?
                    .iter()
                    .map(postgres_member)
                    .collect()
            }
        }
    }

    pub(crate) async fn prune_expired_members(&self) -> anyhow::Result<u64> {
        match &self.storage {
            CoordinationStorage::Sqlite(database) => database.with_connection(|connection| {
                Ok(connection.execute(
                    "DELETE FROM ha_members
                     WHERE lease_until_unix_seconds <= CAST(unixepoch('now') AS INTEGER)",
                    [],
                )? as u64)
            }),
            CoordinationStorage::Postgres(_) => {
                let client = self.storage.postgres_client().await?;
                Ok(client
                    .execute(
                        "DELETE FROM linklake_ha_members WHERE lease_until <= clock_timestamp()",
                        &[],
                    )
                    .await?)
            }
        }
    }

    pub(crate) async fn try_acquire_leadership(&self) -> anyhow::Result<Option<LeadershipLease>> {
        match &self.storage {
            CoordinationStorage::Sqlite(database) => database.with_transaction(|transaction| {
                let now = sqlite_now(transaction)?;
                let current = read_sqlite_leader(transaction)?;
                if let Some(current) = current {
                    if current.instance_id == self.instance_id
                        && current.lease_until_unix_seconds > now
                    {
                        return self.renew_sqlite_leader(transaction, current.fencing_token, now);
                    }
                    if current.lease_until_unix_seconds > now {
                        return Ok(None);
                    }
                }
                let token: i64 = transaction.query_row(
                    "UPDATE ha_fencing_sequence SET next_token = next_token + 1
                     WHERE singleton_id = 1 RETURNING next_token - 1",
                    [],
                    |row| row.get(0),
                )?;
                let token = positive(token, "fencing token")?;
                let lease_until = now.saturating_add(self.leader_lease_seconds);
                transaction.execute(
                    "INSERT INTO ha_leader(
                         singleton_id, instance_id, fencing_token, acquired_unix_seconds,
                         renewed_unix_seconds, lease_until_unix_seconds
                     ) VALUES (1, ?1, ?2, ?3, ?3, ?4)
                     ON CONFLICT(singleton_id) DO UPDATE SET
                         instance_id = excluded.instance_id,
                         fencing_token = excluded.fencing_token,
                         acquired_unix_seconds = excluded.acquired_unix_seconds,
                         renewed_unix_seconds = excluded.renewed_unix_seconds,
                         lease_until_unix_seconds = excluded.lease_until_unix_seconds",
                    params![
                        self.instance_id,
                        as_i64(token)?,
                        as_i64(now)?,
                        as_i64(lease_until)?,
                    ],
                )?;
                Ok(Some(LeadershipLease {
                    instance_id: self.instance_id.clone(),
                    fencing_token: token,
                    acquired_unix_seconds: now,
                    renewed_unix_seconds: now,
                    lease_until_unix_seconds: lease_until,
                }))
            }),
            CoordinationStorage::Postgres(_) => {
                let mut client = self.storage.postgres_client().await?;
                let transaction = client.transaction().await?;

                // 固定存在的序列表负责串行化“空 leader 行”场景，避免并发首次获取互相覆盖。
                transaction
                    .query_one(
                        "SELECT next_token FROM linklake_ha_fencing_sequence
                         WHERE singleton_id = 1 FOR UPDATE",
                        &[],
                    )
                    .await?;
                let current = read_postgres_leader_for_update(&transaction).await?;
                let now = postgres_now(&transaction).await?;
                let lease = if let Some(current) = current {
                    if current.instance_id == self.instance_id
                        && current.lease_until_unix_seconds > now
                    {
                        self.renew_postgres_leader(&transaction, current.fencing_token, now)
                            .await?
                    } else if current.lease_until_unix_seconds > now {
                        None
                    } else {
                        Some(self.acquire_postgres_leader(&transaction, now).await?)
                    }
                } else {
                    Some(self.acquire_postgres_leader(&transaction, now).await?)
                };
                transaction.commit().await?;
                Ok(lease)
            }
        }
    }

    pub(crate) async fn renew_leadership(
        &self,
        fencing_token: u64,
    ) -> anyhow::Result<Option<LeadershipLease>> {
        match &self.storage {
            CoordinationStorage::Sqlite(database) => database.with_transaction(|transaction| {
                let now = sqlite_now(transaction)?;
                self.renew_sqlite_leader(transaction, fencing_token, now)
            }),
            CoordinationStorage::Postgres(_) => {
                let mut client = self.storage.postgres_client().await?;
                let transaction = client.transaction().await?;
                let now = postgres_now(&transaction).await?;
                let lease = self
                    .renew_postgres_leader(&transaction, fencing_token, now)
                    .await?;
                transaction.commit().await?;
                Ok(lease)
            }
        }
    }

    pub(crate) async fn assert_current_fence(&self, fencing_token: u64) -> anyhow::Result<()> {
        let current = self.current_leader().await?;
        anyhow::ensure!(
            current.as_ref().is_some_and(|leader| {
                leader.instance_id == self.instance_id && leader.fencing_token == fencing_token
            }),
            "leadership fencing token is stale; refusing write"
        );
        Ok(())
    }

    pub(crate) async fn current_leader(&self) -> anyhow::Result<Option<LeadershipLease>> {
        match &self.storage {
            CoordinationStorage::Sqlite(database) => database.with_connection(|connection| {
                connection
                    .query_row(
                        "SELECT instance_id, fencing_token, acquired_unix_seconds,
                                renewed_unix_seconds, lease_until_unix_seconds
                         FROM ha_leader
                         WHERE singleton_id = 1
                           AND lease_until_unix_seconds > CAST(unixepoch('now') AS INTEGER)",
                        [],
                        sqlite_leader_row,
                    )
                    .optional()
                    .map_err(Into::into)
            }),
            CoordinationStorage::Postgres(_) => {
                let client = self.storage.postgres_client().await?;
                client
                    .query_opt(
                        "SELECT instance_id, fencing_token,
                            CAST(EXTRACT(EPOCH FROM acquired_at) AS BIGINT),
                            CAST(EXTRACT(EPOCH FROM renewed_at) AS BIGINT),
                            CAST(EXTRACT(EPOCH FROM lease_until) AS BIGINT)
                         FROM linklake_ha_leader
                         WHERE singleton_id = 1 AND lease_until > clock_timestamp()",
                        &[],
                    )
                    .await?
                    .map(|row| postgres_leader(&row))
                    .transpose()
            }
        }
    }

    fn renew_sqlite_leader(
        &self,
        transaction: &SqliteTransaction<'_>,
        fencing_token: u64,
        now: u64,
    ) -> anyhow::Result<Option<LeadershipLease>> {
        let lease_until = now.saturating_add(self.leader_lease_seconds);
        let changed = transaction.execute(
            "UPDATE ha_leader SET renewed_unix_seconds = ?3, lease_until_unix_seconds = ?4
             WHERE singleton_id = 1 AND instance_id = ?1 AND fencing_token = ?2
               AND lease_until_unix_seconds > ?3",
            params![
                self.instance_id,
                as_i64(fencing_token)?,
                as_i64(now)?,
                as_i64(lease_until)?,
            ],
        )?;
        if changed == 0 {
            return Ok(None);
        }
        anyhow::ensure!(changed == 1, "multiple leader rows were renewed");
        read_sqlite_leader(transaction)?
            .map(Some)
            .ok_or_else(|| anyhow::anyhow!("leader row disappeared"))
    }

    async fn renew_postgres_leader(
        &self,
        transaction: &PostgresTransaction<'_>,
        fencing_token: u64,
        now: u64,
    ) -> anyhow::Result<Option<LeadershipLease>> {
        let lease_until = now.saturating_add(self.leader_lease_seconds);
        transaction
            .query_opt(
                "UPDATE linklake_ha_leader
                 SET renewed_at = to_timestamp($3), lease_until = to_timestamp($4)
                 WHERE singleton_id = 1 AND instance_id = $1 AND fencing_token = $2
                   AND lease_until > to_timestamp($3)
                 RETURNING instance_id, fencing_token,
                     CAST(EXTRACT(EPOCH FROM acquired_at) AS BIGINT),
                     CAST(EXTRACT(EPOCH FROM renewed_at) AS BIGINT),
                     CAST(EXTRACT(EPOCH FROM lease_until) AS BIGINT)",
                &[
                    &self.instance_id,
                    &as_i64(fencing_token)?,
                    &as_i64(now)?,
                    &as_i64(lease_until)?,
                ],
            )
            .await?
            .map(|row| postgres_leader(&row))
            .transpose()
    }

    async fn acquire_postgres_leader(
        &self,
        transaction: &PostgresTransaction<'_>,
        now: u64,
    ) -> anyhow::Result<LeadershipLease> {
        let token_row = transaction
            .query_one(
                "UPDATE linklake_ha_fencing_sequence SET next_token = next_token + 1
                 WHERE singleton_id = 1 RETURNING next_token - 1",
                &[],
            )
            .await?;
        let token = positive(token_row.get::<_, i64>(0), "fencing token")?;
        let lease_until = now.saturating_add(self.leader_lease_seconds);
        transaction
            .execute(
                "INSERT INTO linklake_ha_leader(
                     singleton_id, instance_id, fencing_token, acquired_at, renewed_at, lease_until
                 ) VALUES (1, $1, $2, to_timestamp($3), to_timestamp($3), to_timestamp($4))
                 ON CONFLICT(singleton_id) DO UPDATE SET
                     instance_id = EXCLUDED.instance_id,
                     fencing_token = EXCLUDED.fencing_token,
                     acquired_at = EXCLUDED.acquired_at,
                     renewed_at = EXCLUDED.renewed_at,
                     lease_until = EXCLUDED.lease_until",
                &[
                    &self.instance_id,
                    &as_i64(token)?,
                    &as_i64(now)?,
                    &as_i64(lease_until)?,
                ],
            )
            .await?;
        Ok(LeadershipLease {
            instance_id: self.instance_id.clone(),
            fencing_token: token,
            acquired_unix_seconds: now,
            renewed_unix_seconds: now,
            lease_until_unix_seconds: lease_until,
        })
    }
}

fn read_sqlite_member(
    transaction: &SqliteTransaction<'_>,
    instance_id: &str,
) -> anyhow::Result<Option<HaMember>> {
    transaction
        .query_row(
            "SELECT instance_id, started_unix_seconds, last_seen_unix_seconds,
                    lease_until_unix_seconds, metadata_json
             FROM ha_members WHERE instance_id = ?1",
            [instance_id],
            sqlite_member_row,
        )
        .optional()
        .map_err(Into::into)
}

fn sqlite_member_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<HaMember> {
    Ok(HaMember {
        instance_id: row.get(0)?,
        started_unix_seconds: sqlite_nonnegative(row.get(1)?, 1, "member start time")?,
        last_seen_unix_seconds: sqlite_nonnegative(row.get(2)?, 2, "member last seen time")?,
        lease_until_unix_seconds: sqlite_nonnegative(row.get(3)?, 3, "member lease time")?,
        metadata_json: row.get(4)?,
    })
}

fn postgres_member(row: &PostgresRow) -> anyhow::Result<HaMember> {
    Ok(HaMember {
        instance_id: row.get(0),
        started_unix_seconds: positive_or_zero(row.get(1), "member start time")?,
        last_seen_unix_seconds: positive_or_zero(row.get(2), "member last seen time")?,
        lease_until_unix_seconds: positive_or_zero(row.get(3), "member lease time")?,
        metadata_json: row.get(4),
    })
}

fn read_sqlite_leader(
    transaction: &SqliteTransaction<'_>,
) -> anyhow::Result<Option<LeadershipLease>> {
    transaction
        .query_row(
            "SELECT instance_id, fencing_token, acquired_unix_seconds,
                    renewed_unix_seconds, lease_until_unix_seconds
             FROM ha_leader WHERE singleton_id = 1",
            [],
            sqlite_leader_row,
        )
        .optional()
        .map_err(Into::into)
}

fn sqlite_leader_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<LeadershipLease> {
    Ok(LeadershipLease {
        instance_id: row.get(0)?,
        fencing_token: sqlite_positive(row.get(1)?, 1, "fencing token")?,
        acquired_unix_seconds: sqlite_nonnegative(row.get(2)?, 2, "leader acquired time")?,
        renewed_unix_seconds: sqlite_nonnegative(row.get(3)?, 3, "leader renewed time")?,
        lease_until_unix_seconds: sqlite_nonnegative(row.get(4)?, 4, "leader lease time")?,
    })
}

async fn read_postgres_leader_for_update(
    transaction: &PostgresTransaction<'_>,
) -> anyhow::Result<Option<LeadershipLease>> {
    transaction
        .query_opt(
            "SELECT instance_id, fencing_token,
                CAST(EXTRACT(EPOCH FROM acquired_at) AS BIGINT),
                CAST(EXTRACT(EPOCH FROM renewed_at) AS BIGINT),
                CAST(EXTRACT(EPOCH FROM lease_until) AS BIGINT)
             FROM linklake_ha_leader WHERE singleton_id = 1 FOR UPDATE",
            &[],
        )
        .await?
        .map(|row| postgres_leader(&row))
        .transpose()
}

fn postgres_leader(row: &PostgresRow) -> anyhow::Result<LeadershipLease> {
    Ok(LeadershipLease {
        instance_id: row.get(0),
        fencing_token: positive(row.get(1), "fencing token")?,
        acquired_unix_seconds: positive_or_zero(row.get(2), "leader acquired time")?,
        renewed_unix_seconds: positive_or_zero(row.get(3), "leader renewed time")?,
        lease_until_unix_seconds: positive_or_zero(row.get(4), "leader lease time")?,
    })
}

fn sqlite_now(transaction: &SqliteTransaction<'_>) -> anyhow::Result<u64> {
    let now: i64 =
        transaction.query_row("SELECT CAST(unixepoch('now') AS INTEGER)", [], |row| {
            row.get(0)
        })?;
    positive_or_zero(now, "SQLite clock")
}

async fn postgres_now(transaction: &PostgresTransaction<'_>) -> anyhow::Result<u64> {
    let now: i64 = transaction
        .query_one(
            "SELECT CAST(EXTRACT(EPOCH FROM clock_timestamp()) AS BIGINT)",
            &[],
        )
        .await?
        .get(0);
    positive_or_zero(now, "PostgreSQL clock")
}

fn lease_seconds(duration: Duration, name: &str) -> anyhow::Result<u64> {
    let seconds = duration.as_secs();
    anyhow::ensure!(seconds >= 2, "{name} lease must be at least two seconds");
    Ok(seconds)
}

fn as_i64(value: u64) -> anyhow::Result<i64> {
    i64::try_from(value).map_err(|_| anyhow::anyhow!("value exceeds database integer range"))
}

fn positive(value: i64, label: &str) -> anyhow::Result<u64> {
    anyhow::ensure!(value > 0, "{label} must be positive");
    Ok(value as u64)
}

fn positive_or_zero(value: i64, label: &str) -> anyhow::Result<u64> {
    anyhow::ensure!(value >= 0, "{label} must not be negative");
    Ok(value as u64)
}

fn sqlite_nonnegative(value: i64, column: usize, label: &str) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|_| sqlite_integer_error(column, label, "must not be negative"))
}

fn sqlite_positive(value: i64, column: usize, label: &str) -> rusqlite::Result<u64> {
    if value <= 0 {
        return Err(sqlite_integer_error(column, label, "must be positive"));
    }
    Ok(value as u64)
}

fn sqlite_integer_error(column: usize, label: &str, requirement: &str) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        column,
        SqliteType::Integer,
        Box::new(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{label} {requirement}"),
        )),
    )
}
