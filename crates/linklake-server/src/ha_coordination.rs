//! 多实例成员租约、Leader 选举与 fencing token。

use crate::storage::{CoordinationStorage, StorageBackend};
use rusqlite::{
    params, types::Type as SqliteType, OptionalExtension, Transaction as SqliteTransaction,
};
use serde::Serialize;
use std::{io, time::Duration};
use tokio_postgres::{Row as PostgresRow, Transaction as PostgresTransaction};
use uuid::Uuid;

const MAX_INSTANCE_ID_BYTES: usize = 128;
const MAX_METADATA_JSON_BYTES: usize = 16 * 1024;
const MAX_MEMBER_LEASE_SECONDS: u64 = 5 * 60;
const MAX_LEADER_LEASE_SECONDS: u64 = 2 * 60;
const POSTGRES_INSTANCE_LOCK_SEED: i64 = 0x4c4c_4841_494e_5354;
const EXPIRED_LEASE_BATCH_SIZE: i64 = 128;
const EXPIRED_LEASE_POSTGRES_TIMEOUT: Duration = Duration::from_millis(500);

const SQLITE_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS ha_members (
    instance_id TEXT PRIMARY KEY NOT NULL,
    incarnation_id TEXT NOT NULL,
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
    incarnation_id TEXT NOT NULL,
    fencing_token INTEGER NOT NULL CHECK(fencing_token > 0),
    acquired_unix_seconds INTEGER NOT NULL,
    renewed_unix_seconds INTEGER NOT NULL,
    lease_until_unix_seconds INTEGER NOT NULL
);
"#;

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct HaMember {
    pub(crate) instance_id: String,
    pub(crate) incarnation_id: String,
    pub(crate) started_unix_seconds: u64,
    pub(crate) last_seen_unix_seconds: u64,
    pub(crate) lease_until_unix_seconds: u64,
    pub(crate) metadata_json: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct LeadershipLease {
    pub(crate) instance_id: String,
    pub(crate) incarnation_id: String,
    pub(crate) fencing_token: u64,
    pub(crate) acquired_unix_seconds: u64,
    pub(crate) renewed_unix_seconds: u64,
    pub(crate) lease_until_unix_seconds: u64,
}

#[derive(Clone)]
pub(crate) struct HaCoordinator {
    storage: CoordinationStorage,
    instance_id: String,
    incarnation_id: String,
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
        let instance_id = instance_id.into().trim().to_owned();
        validate_instance_id(&instance_id)?;
        let metadata_json = normalize_metadata_json(metadata_json.into())?;
        let incarnation_id = Uuid::new_v4().to_string();
        let member_lease_seconds = lease_seconds(member_lease, "member", MAX_MEMBER_LEASE_SECONDS)?;
        let leader_lease_seconds = lease_seconds(leader_lease, "leader", MAX_LEADER_LEASE_SECONDS)?;
        anyhow::ensure!(
            leader_lease_seconds <= member_lease_seconds,
            "leader lease must not exceed member lease"
        );
        if let CoordinationStorage::Sqlite(database) = &storage {
            database.with_connection(|connection| {
                connection.execute_batch(SQLITE_SCHEMA)?;
                Ok(())
            })?;
        }
        Ok(Self {
            storage,
            instance_id,
            incarnation_id,
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

    pub(crate) fn incarnation_id(&self) -> &str {
        &self.incarnation_id
    }

    pub(crate) fn storage(&self) -> &CoordinationStorage {
        &self.storage
    }

    /// 回收持久 SQLite 上一次异常退出留下的本机租约。
    ///
    /// `Database::persistent` 在整个 `DatabaseInner` 生命周期持有数据目录
    /// 的独占文件锁，因此能证明同一目录的旧 Server 已退出。该恢复只允许
    /// 首个进程内 runtime 执行，并且仅作用于 SQLite；PostgreSQL 仍由活动
    /// member lease 和 incarnation 检查阻止冲突接管。fencing sequence 保留，
    /// 让恢复后的新 Leader 继续使用严格递增的 token。
    pub(crate) fn recover_stale_sqlite_leases(&self) -> anyhow::Result<bool> {
        let CoordinationStorage::Sqlite(database) = &self.storage else {
            return Ok(false);
        };
        if !database.claim_sqlite_ha_recovery() {
            return Ok(false);
        }
        database.with_transaction(|transaction| {
            transaction.execute("UPDATE ha_members SET lease_until_unix_seconds = 0", [])?;
            transaction.execute("UPDATE ha_leader SET lease_until_unix_seconds = 0", [])?;
            transaction.execute(
                "UPDATE public_port_ownership SET lease_until_unix_seconds = 0",
                [],
            )?;
            transaction.execute("UPDATE job_leases SET lease_until_unix_seconds = 0", [])?;
            Ok(())
        })?;
        Ok(true)
    }

    pub(crate) async fn register_or_renew_member(&self) -> anyhow::Result<HaMember> {
        match &self.storage {
            CoordinationStorage::Sqlite(database) => database.with_transaction(|transaction| {
                let now = sqlite_now(transaction)?;
                let lease_until = now.saturating_add(self.member_lease_seconds);
                match read_sqlite_member(transaction, &self.instance_id)? {
                    Some(current) if current.incarnation_id == self.incarnation_id => {
                        let changed = transaction.execute(
                            "UPDATE ha_members
                             SET last_seen_unix_seconds = ?3,
                                 lease_until_unix_seconds = ?4, metadata_json = ?5
                             WHERE instance_id = ?1 AND incarnation_id = ?2",
                            params![
                                self.instance_id,
                                self.incarnation_id,
                                as_i64(now)?,
                                as_i64(lease_until)?,
                                self.metadata_json,
                            ],
                        )?;
                        anyhow::ensure!(changed == 1, "HA member renewal changed no row");
                    }
                    Some(current) if current.lease_until_unix_seconds > now => {
                        anyhow::bail!("another incarnation is active for this HA instance ID");
                    }
                    Some(_) => {
                        let changed = transaction.execute(
                            "UPDATE ha_members
                             SET incarnation_id = ?2, started_unix_seconds = ?3,
                                 last_seen_unix_seconds = ?3, lease_until_unix_seconds = ?4,
                                 metadata_json = ?5
                             WHERE instance_id = ?1",
                            params![
                                self.instance_id,
                                self.incarnation_id,
                                as_i64(now)?,
                                as_i64(lease_until)?,
                                self.metadata_json,
                            ],
                        )?;
                        anyhow::ensure!(changed == 1, "HA member takeover changed no row");
                    }
                    None => {
                        let changed = transaction.execute(
                            "INSERT INTO ha_members(
                                 instance_id, incarnation_id, started_unix_seconds,
                                 last_seen_unix_seconds, lease_until_unix_seconds, metadata_json
                             ) VALUES (?1, ?2, ?3, ?3, ?4, ?5)",
                            params![
                                self.instance_id,
                                self.incarnation_id,
                                as_i64(now)?,
                                as_i64(lease_until)?,
                                self.metadata_json,
                            ],
                        )?;
                        anyhow::ensure!(changed == 1, "HA member registration changed no row");
                    }
                }
                read_sqlite_member(transaction, &self.instance_id)?
                    .ok_or_else(|| anyhow::anyhow!("HA member disappeared after registration"))
            }),
            CoordinationStorage::Postgres(_) => {
                let mut client = self.storage.postgres_client().await?;
                let transaction = client.transaction().await?;
                lock_postgres_instance(&transaction, &self.instance_id).await?;
                let current =
                    read_postgres_member_for_update(&transaction, &self.instance_id).await?;
                let now = postgres_now(&transaction).await?;
                let lease_until = now.saturating_add(self.member_lease_seconds);
                let row = match current {
                    Some(current) if current.incarnation_id == self.incarnation_id => {
                        transaction
                            .query_one(
                                "UPDATE linklake_ha_members
                                 SET last_seen_at = to_timestamp($3::bigint),
                                     lease_until = to_timestamp($4::bigint),
                                     metadata_json = $5::text::jsonb
                                 WHERE instance_id = $1 AND incarnation_id = $2
                                 RETURNING instance_id, incarnation_id,
                                     CAST(EXTRACT(EPOCH FROM started_at) AS BIGINT),
                                     CAST(EXTRACT(EPOCH FROM last_seen_at) AS BIGINT),
                                     CAST(EXTRACT(EPOCH FROM lease_until) AS BIGINT),
                                     metadata_json::text",
                                &[
                                    &self.instance_id,
                                    &self.incarnation_id,
                                    &as_i64(now)?,
                                    &as_i64(lease_until)?,
                                    &self.metadata_json,
                                ],
                            )
                            .await?
                    }
                    Some(current) if current.lease_until_unix_seconds > now => {
                        anyhow::bail!("another incarnation is active for this HA instance ID");
                    }
                    Some(_) => {
                        transaction
                            .query_one(
                                "UPDATE linklake_ha_members
                                 SET incarnation_id = $2,
                                     started_at = to_timestamp($3::bigint),
                                     last_seen_at = to_timestamp($3::bigint),
                                     lease_until = to_timestamp($4::bigint),
                                     metadata_json = $5::text::jsonb
                                 WHERE instance_id = $1
                                 RETURNING instance_id, incarnation_id,
                                     CAST(EXTRACT(EPOCH FROM started_at) AS BIGINT),
                                     CAST(EXTRACT(EPOCH FROM last_seen_at) AS BIGINT),
                                     CAST(EXTRACT(EPOCH FROM lease_until) AS BIGINT),
                                     metadata_json::text",
                                &[
                                    &self.instance_id,
                                    &self.incarnation_id,
                                    &as_i64(now)?,
                                    &as_i64(lease_until)?,
                                    &self.metadata_json,
                                ],
                            )
                            .await?
                    }
                    None => {
                        transaction
                            .query_one(
                                "INSERT INTO linklake_ha_members(
                                     instance_id, incarnation_id, started_at, last_seen_at,
                                     lease_until, metadata_json
                                 ) VALUES ($1, $2, to_timestamp($3::bigint),
                                     to_timestamp($3::bigint), to_timestamp($4::bigint),
                                     $5::text::jsonb)
                                 RETURNING instance_id, incarnation_id,
                                     CAST(EXTRACT(EPOCH FROM started_at) AS BIGINT),
                                     CAST(EXTRACT(EPOCH FROM last_seen_at) AS BIGINT),
                                     CAST(EXTRACT(EPOCH FROM lease_until) AS BIGINT),
                                     metadata_json::text",
                                &[
                                    &self.instance_id,
                                    &self.incarnation_id,
                                    &as_i64(now)?,
                                    &as_i64(lease_until)?,
                                    &self.metadata_json,
                                ],
                            )
                            .await?
                    }
                };
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
                    "SELECT instance_id, incarnation_id, started_unix_seconds, last_seen_unix_seconds,
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
                            incarnation_id,
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
        prune_expired_lease_batch(
            &self.storage,
            "DELETE FROM ha_members
             WHERE rowid IN (
                 SELECT rowid FROM ha_members
                 WHERE lease_until_unix_seconds <= CAST(unixepoch('now') AS INTEGER)
                 ORDER BY lease_until_unix_seconds, instance_id LIMIT ?1
             ) AND lease_until_unix_seconds <= CAST(unixepoch('now') AS INTEGER)",
            "WITH expired AS (
                 SELECT instance_id FROM linklake_ha_members
                 WHERE lease_until <= clock_timestamp()
                 ORDER BY lease_until, instance_id LIMIT $1
                 FOR UPDATE SKIP LOCKED
             ) DELETE FROM linklake_ha_members AS member USING expired
               WHERE member.instance_id = expired.instance_id
                 AND member.lease_until <= clock_timestamp()",
        )
        .await
    }

    pub(crate) async fn try_acquire_leadership(&self) -> anyhow::Result<Option<LeadershipLease>> {
        match &self.storage {
            CoordinationStorage::Sqlite(database) => database.with_transaction(|transaction| {
                let now = sqlite_now(transaction)?;
                anyhow::ensure!(
                    sqlite_member_is_active(
                        transaction,
                        &self.instance_id,
                        &self.incarnation_id,
                        now,
                    )?,
                    "active HA member lease is required before acquiring leadership"
                );
                let current = read_sqlite_leader(transaction)?;
                if let Some(current) = current {
                    let current_member_active = sqlite_member_is_active(
                        transaction,
                        &current.instance_id,
                        &current.incarnation_id,
                        now,
                    )?;
                    if current_member_active
                        && current.instance_id == self.instance_id
                        && current.incarnation_id == self.incarnation_id
                        && current.lease_until_unix_seconds > now
                    {
                        return self.renew_sqlite_leader(transaction, current.fencing_token, now);
                    }
                    if current_member_active && current.lease_until_unix_seconds > now {
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
                let changed = transaction.execute(
                    "INSERT INTO ha_leader(
                         singleton_id, instance_id, incarnation_id, fencing_token,
                         acquired_unix_seconds, renewed_unix_seconds, lease_until_unix_seconds
                     ) VALUES (1, ?1, ?2, ?3, ?4, ?4, ?5)
                     ON CONFLICT(singleton_id) DO UPDATE SET
                         instance_id = excluded.instance_id,
                         incarnation_id = excluded.incarnation_id,
                         fencing_token = excluded.fencing_token,
                         acquired_unix_seconds = excluded.acquired_unix_seconds,
                         renewed_unix_seconds = excluded.renewed_unix_seconds,
                         lease_until_unix_seconds = excluded.lease_until_unix_seconds",
                    params![
                        self.instance_id,
                        self.incarnation_id,
                        as_i64(token)?,
                        as_i64(now)?,
                        as_i64(lease_until)?,
                    ],
                )?;
                anyhow::ensure!(changed == 1, "leader acquisition changed no row");
                Ok(Some(LeadershipLease {
                    instance_id: self.instance_id.clone(),
                    incarnation_id: self.incarnation_id.clone(),
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
                anyhow::ensure!(
                    postgres_member_is_active(
                        &transaction,
                        &self.instance_id,
                        &self.incarnation_id,
                    )
                    .await?,
                    "active HA member lease is required before acquiring leadership"
                );
                let lease = if let Some(current) = current {
                    let current_member_active = postgres_member_is_active(
                        &transaction,
                        &current.instance_id,
                        &current.incarnation_id,
                    )
                    .await?;
                    if current_member_active
                        && current.instance_id == self.instance_id
                        && current.incarnation_id == self.incarnation_id
                        && current.lease_until_unix_seconds > now
                    {
                        self.renew_postgres_leader(&transaction, current.fencing_token, now)
                            .await?
                    } else if current_member_active && current.lease_until_unix_seconds > now {
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
                if !sqlite_member_is_active(
                    transaction,
                    &self.instance_id,
                    &self.incarnation_id,
                    now,
                )? {
                    return Ok(None);
                }
                self.renew_sqlite_leader(transaction, fencing_token, now)
            }),
            CoordinationStorage::Postgres(_) => {
                let mut client = self.storage.postgres_client().await?;
                let transaction = client.transaction().await?;
                let current = read_postgres_leader_for_update(&transaction).await?;
                let now = postgres_now(&transaction).await?;
                let renewable = current.as_ref().is_some_and(|leader| {
                    leader.instance_id == self.instance_id
                        && leader.incarnation_id == self.incarnation_id
                        && leader.fencing_token == fencing_token
                        && leader.lease_until_unix_seconds > now
                });
                let member_active = if renewable {
                    postgres_member_is_active(&transaction, &self.instance_id, &self.incarnation_id)
                        .await?
                } else {
                    false
                };
                let lease = if renewable && member_active {
                    self.renew_postgres_leader(&transaction, fencing_token, now)
                        .await?
                } else {
                    None
                };
                transaction.commit().await?;
                Ok(lease)
            }
        }
    }

    /// 必须从 `Database::with_transaction` 创建的 IMMEDIATE 事务内调用，并在同一事务写入。
    pub(crate) fn assert_sqlite_transaction_fence(
        &self,
        transaction: &SqliteTransaction<'_>,
        fencing_token: u64,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(fencing_token > 0, "fencing token must be positive");
        let current: bool = transaction.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM ha_leader AS leader
                 JOIN ha_members AS member
                   ON member.instance_id = leader.instance_id
                  AND member.incarnation_id = leader.incarnation_id
                 WHERE leader.singleton_id = 1 AND leader.instance_id = ?1
                   AND leader.incarnation_id = ?2 AND leader.fencing_token = ?3
                   AND leader.lease_until_unix_seconds > CAST(unixepoch('now') AS INTEGER)
                   AND member.lease_until_unix_seconds > CAST(unixepoch('now') AS INTEGER)
             )",
            params![
                self.instance_id,
                self.incarnation_id,
                as_i64(fencing_token)?,
            ],
            |row| row.get(0),
        )?;
        anyhow::ensure!(current, "leadership fencing token is stale; refusing write");
        Ok(())
    }

    /// 共享锁定 leader/member 行并验证当前进程身份；调用方必须在同一事务完成写入。
    pub(crate) async fn assert_postgres_transaction_fence(
        &self,
        transaction: &PostgresTransaction<'_>,
        fencing_token: u64,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(fencing_token > 0, "fencing token must be positive");
        let expected_token = as_i64(fencing_token)?;
        let row = transaction
            .query_opt(
                "SELECT instance_id, incarnation_id, fencing_token,
                    lease_until > clock_timestamp()
                 FROM linklake_ha_leader WHERE singleton_id = 1 FOR SHARE",
                &[],
            )
            .await?;
        let current = row.is_some_and(|row| {
            row.get::<_, String>(0) == self.instance_id
                && row.get::<_, String>(1) == self.incarnation_id
                && row.get::<_, i64>(2) == expected_token
                && row.get::<_, bool>(3)
        });
        let member_active = if current {
            transaction
                .query_opt(
                    "SELECT lease_until > clock_timestamp()
                     FROM linklake_ha_members
                     WHERE instance_id = $1 AND incarnation_id = $2 FOR SHARE",
                    &[&self.instance_id, &self.incarnation_id],
                )
                .await?
                .is_some_and(|row| row.get(0))
        } else {
            false
        };
        anyhow::ensure!(
            current && member_active,
            "leadership fencing token is stale; refusing write"
        );
        Ok(())
    }

    pub(crate) async fn current_leader(&self) -> anyhow::Result<Option<LeadershipLease>> {
        match &self.storage {
            CoordinationStorage::Sqlite(database) => database.with_connection(|connection| {
                connection
                    .query_row(
                        "SELECT instance_id, incarnation_id, fencing_token, acquired_unix_seconds,
                                renewed_unix_seconds, lease_until_unix_seconds
                         FROM ha_leader AS leader
                         WHERE leader.singleton_id = 1
                           AND leader.lease_until_unix_seconds > CAST(unixepoch('now') AS INTEGER)
                           AND EXISTS(
                               SELECT 1 FROM ha_members AS member
                               WHERE member.instance_id = leader.instance_id
                                 AND member.incarnation_id = leader.incarnation_id
                                 AND member.lease_until_unix_seconds > CAST(unixepoch('now') AS INTEGER)
                           )",
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
                        "SELECT instance_id, incarnation_id, fencing_token,
                            CAST(EXTRACT(EPOCH FROM acquired_at) AS BIGINT),
                            CAST(EXTRACT(EPOCH FROM renewed_at) AS BIGINT),
                            CAST(EXTRACT(EPOCH FROM lease_until) AS BIGINT)
                         FROM linklake_ha_leader
                         WHERE singleton_id = 1 AND lease_until > clock_timestamp()
                           AND EXISTS(
                               SELECT 1 FROM linklake_ha_members AS member
                               WHERE member.instance_id = linklake_ha_leader.instance_id
                                 AND member.incarnation_id = linklake_ha_leader.incarnation_id
                                 AND member.lease_until > clock_timestamp()
                           )",
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
            "UPDATE ha_leader SET renewed_unix_seconds = ?4, lease_until_unix_seconds = ?5
             WHERE singleton_id = 1 AND instance_id = ?1 AND incarnation_id = ?2
               AND fencing_token = ?3 AND lease_until_unix_seconds > ?4",
            params![
                self.instance_id,
                self.incarnation_id,
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
                 SET renewed_at = to_timestamp($4::bigint),
                     lease_until = to_timestamp($5::bigint)
                 WHERE singleton_id = 1 AND instance_id = $1 AND incarnation_id = $2
                   AND fencing_token = $3 AND lease_until > to_timestamp($4::bigint)
                 RETURNING instance_id, incarnation_id, fencing_token,
                     CAST(EXTRACT(EPOCH FROM acquired_at) AS BIGINT),
                     CAST(EXTRACT(EPOCH FROM renewed_at) AS BIGINT),
                     CAST(EXTRACT(EPOCH FROM lease_until) AS BIGINT)",
                &[
                    &self.instance_id,
                    &self.incarnation_id,
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
        let changed = transaction
            .execute(
                "INSERT INTO linklake_ha_leader(
                     singleton_id, instance_id, incarnation_id, fencing_token,
                     acquired_at, renewed_at, lease_until
                 ) VALUES (1, $1, $2, $3, to_timestamp($4::bigint),
                     to_timestamp($4::bigint), to_timestamp($5::bigint))
                 ON CONFLICT(singleton_id) DO UPDATE SET
                     instance_id = EXCLUDED.instance_id,
                     incarnation_id = EXCLUDED.incarnation_id,
                     fencing_token = EXCLUDED.fencing_token,
                     acquired_at = EXCLUDED.acquired_at,
                     renewed_at = EXCLUDED.renewed_at,
                     lease_until = EXCLUDED.lease_until",
                &[
                    &self.instance_id,
                    &self.incarnation_id,
                    &as_i64(token)?,
                    &as_i64(now)?,
                    &as_i64(lease_until)?,
                ],
            )
            .await?;
        anyhow::ensure!(changed == 1, "leader acquisition changed no row");
        Ok(LeadershipLease {
            instance_id: self.instance_id.clone(),
            incarnation_id: self.incarnation_id.clone(),
            fencing_token: token,
            acquired_unix_seconds: now,
            renewed_unix_seconds: now,
            lease_until_unix_seconds: lease_until,
        })
    }
}

/// 维护不能占住心跳执行线程；每批只处理少量行，遇到正在续租的写入就让行。
pub(crate) async fn prune_expired_lease_batch(
    storage: &CoordinationStorage,
    sqlite_query: &'static str,
    postgres_query: &'static str,
) -> anyhow::Result<u64> {
    match storage {
        CoordinationStorage::Sqlite(database) => {
            let database = database.clone();
            // 必须收尾此 blocking 任务，不能在外层超时后将其遗留在后台写数据库。
            tokio::task::spawn_blocking(move || -> anyhow::Result<u64> {
                let mut connection = database.connect()?;
                connection.busy_timeout(Duration::ZERO)?;
                let transaction = connection
                    .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                let deleted = transaction.execute(sqlite_query, [EXPIRED_LEASE_BATCH_SIZE])?;
                transaction.commit()?;
                Ok(deleted as u64)
            })
            .await
            .map_err(|_| anyhow::anyhow!("SQLite expired lease maintenance task failed"))?
        }
        CoordinationStorage::Postgres(_) => {
            tokio::time::timeout(EXPIRED_LEASE_POSTGRES_TIMEOUT, async {
                let mut client = storage.postgres_client().await?;
                let transaction = client.transaction().await?;
                transaction
                    .batch_execute(
                        "SET LOCAL statement_timeout = '250ms';
                         SET LOCAL lock_timeout = '25ms'",
                    )
                    .await?;
                let deleted = transaction
                    .execute(postgres_query, &[&EXPIRED_LEASE_BATCH_SIZE])
                    .await?;
                transaction.commit().await?;
                Ok(deleted)
            })
            .await
            .map_err(|_| anyhow::anyhow!("PostgreSQL expired lease maintenance timed out"))?
        }
    }
}

fn read_sqlite_member(
    transaction: &SqliteTransaction<'_>,
    instance_id: &str,
) -> anyhow::Result<Option<HaMember>> {
    transaction
        .query_row(
            "SELECT instance_id, incarnation_id, started_unix_seconds, last_seen_unix_seconds,
                    lease_until_unix_seconds, metadata_json
             FROM ha_members WHERE instance_id = ?1",
            [instance_id],
            sqlite_member_row,
        )
        .optional()
        .map_err(Into::into)
}

fn sqlite_member_is_active(
    transaction: &SqliteTransaction<'_>,
    instance_id: &str,
    incarnation_id: &str,
    now: u64,
) -> anyhow::Result<bool> {
    Ok(transaction.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM ha_members
             WHERE instance_id = ?1 AND incarnation_id = ?2
               AND lease_until_unix_seconds > ?3
         )",
        params![instance_id, incarnation_id, as_i64(now)?],
        |row| row.get(0),
    )?)
}

fn sqlite_member_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<HaMember> {
    let metadata_json: String = row.get(5)?;
    validate_metadata_json(&metadata_json).map_err(|error| sqlite_text_error(5, error))?;
    Ok(HaMember {
        instance_id: row.get(0)?,
        incarnation_id: row.get(1)?,
        started_unix_seconds: sqlite_nonnegative(row.get(2)?, 2, "member start time")?,
        last_seen_unix_seconds: sqlite_nonnegative(row.get(3)?, 3, "member last seen time")?,
        lease_until_unix_seconds: sqlite_nonnegative(row.get(4)?, 4, "member lease time")?,
        metadata_json,
    })
}

fn postgres_member(row: &PostgresRow) -> anyhow::Result<HaMember> {
    let metadata_json: String = row.get(5);
    validate_metadata_json(&metadata_json)?;
    Ok(HaMember {
        instance_id: row.get(0),
        incarnation_id: row.get(1),
        started_unix_seconds: positive_or_zero(row.get(2), "member start time")?,
        last_seen_unix_seconds: positive_or_zero(row.get(3), "member last seen time")?,
        lease_until_unix_seconds: positive_or_zero(row.get(4), "member lease time")?,
        metadata_json,
    })
}

async fn read_postgres_member_for_update(
    transaction: &PostgresTransaction<'_>,
    instance_id: &str,
) -> anyhow::Result<Option<HaMember>> {
    transaction
        .query_opt(
            "SELECT instance_id, incarnation_id,
                CAST(EXTRACT(EPOCH FROM started_at) AS BIGINT),
                CAST(EXTRACT(EPOCH FROM last_seen_at) AS BIGINT),
                CAST(EXTRACT(EPOCH FROM lease_until) AS BIGINT),
                metadata_json::text
             FROM linklake_ha_members WHERE instance_id = $1 FOR UPDATE",
            &[&instance_id],
        )
        .await?
        .map(|row| postgres_member(&row))
        .transpose()
}

async fn postgres_member_is_active(
    transaction: &PostgresTransaction<'_>,
    instance_id: &str,
    incarnation_id: &str,
) -> anyhow::Result<bool> {
    Ok(transaction
        .query_opt(
            "SELECT lease_until > clock_timestamp()
             FROM linklake_ha_members
             WHERE instance_id = $1 AND incarnation_id = $2 FOR UPDATE",
            &[&instance_id, &incarnation_id],
        )
        .await?
        .is_some_and(|row| row.get(0)))
}

fn read_sqlite_leader(
    transaction: &SqliteTransaction<'_>,
) -> anyhow::Result<Option<LeadershipLease>> {
    transaction
        .query_row(
            "SELECT instance_id, incarnation_id, fencing_token, acquired_unix_seconds,
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
        incarnation_id: row.get(1)?,
        fencing_token: sqlite_positive(row.get(2)?, 2, "fencing token")?,
        acquired_unix_seconds: sqlite_nonnegative(row.get(3)?, 3, "leader acquired time")?,
        renewed_unix_seconds: sqlite_nonnegative(row.get(4)?, 4, "leader renewed time")?,
        lease_until_unix_seconds: sqlite_nonnegative(row.get(5)?, 5, "leader lease time")?,
    })
}

async fn read_postgres_leader_for_update(
    transaction: &PostgresTransaction<'_>,
) -> anyhow::Result<Option<LeadershipLease>> {
    transaction
        .query_opt(
            "SELECT instance_id, incarnation_id, fencing_token,
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
        incarnation_id: row.get(1),
        fencing_token: positive(row.get(2), "fencing token")?,
        acquired_unix_seconds: positive_or_zero(row.get(3), "leader acquired time")?,
        renewed_unix_seconds: positive_or_zero(row.get(4), "leader renewed time")?,
        lease_until_unix_seconds: positive_or_zero(row.get(5), "leader lease time")?,
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

async fn lock_postgres_instance(
    transaction: &PostgresTransaction<'_>,
    instance_id: &str,
) -> anyhow::Result<()> {
    transaction
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, $2))",
            &[&instance_id, &POSTGRES_INSTANCE_LOCK_SEED],
        )
        .await?;
    Ok(())
}

fn validate_instance_id(instance_id: &str) -> anyhow::Result<()> {
    anyhow::ensure!(!instance_id.is_empty(), "HA instance ID is required");
    anyhow::ensure!(
        instance_id.len() <= MAX_INSTANCE_ID_BYTES,
        "HA instance ID exceeds {MAX_INSTANCE_ID_BYTES} bytes"
    );
    anyhow::ensure!(
        !instance_id.chars().any(char::is_control),
        "HA instance ID must not contain control characters"
    );
    Ok(())
}

fn normalize_metadata_json(metadata_json: String) -> anyhow::Result<String> {
    validate_metadata_json(&metadata_json)?;
    let value = serde_json::from_str::<serde_json::Value>(&metadata_json)?;
    let normalized = serde_json::to_string(&value)?;
    anyhow::ensure!(
        normalized.len() <= MAX_METADATA_JSON_BYTES,
        "HA member metadata exceeds {MAX_METADATA_JSON_BYTES} bytes"
    );
    Ok(normalized)
}

fn validate_metadata_json(metadata_json: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        metadata_json.len() <= MAX_METADATA_JSON_BYTES,
        "HA member metadata exceeds {MAX_METADATA_JSON_BYTES} bytes"
    );
    let value = serde_json::from_str::<serde_json::Value>(metadata_json)
        .map_err(|error| anyhow::anyhow!("HA member metadata must be valid JSON: {error}"))?;
    anyhow::ensure!(
        value.is_object(),
        "HA member metadata must be a JSON object"
    );
    Ok(())
}

fn lease_seconds(duration: Duration, name: &str, maximum: u64) -> anyhow::Result<u64> {
    let seconds = duration.as_secs();
    anyhow::ensure!(seconds >= 2, "{name} lease must be at least two seconds");
    anyhow::ensure!(
        seconds <= maximum,
        "{name} lease must not exceed {maximum} seconds"
    );
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

fn sqlite_text_error(column: usize, error: anyhow::Error) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        column,
        SqliteType::Text,
        Box::new(io::Error::new(
            io::ErrorKind::InvalidData,
            error.to_string(),
        )),
    )
}

#[cfg(test)]
mod maintenance_tests {
    use super::*;
    use crate::database::Database;

    fn coordinator(database: &Database, instance_id: &str) -> HaCoordinator {
        HaCoordinator::open(
            CoordinationStorage::Sqlite(database.clone()),
            instance_id,
            "{}",
            Duration::from_secs(300),
            Duration::from_secs(120),
        )
        .expect("coordinator should open")
    }

    #[tokio::test]
    async fn member_maintenance_is_bounded_and_preserves_renewed_members() {
        let database = Database::memory().expect("database should open");
        let active = coordinator(&database, "active");
        let renewed = coordinator(&database, "renewed");
        active
            .register_or_renew_member()
            .await
            .expect("active member should register");
        let original = renewed
            .register_or_renew_member()
            .await
            .expect("renewed member should register");
        database
            .with_transaction(|transaction| {
                transaction.execute(
                    "UPDATE ha_members SET lease_until_unix_seconds = 0
                     WHERE instance_id = 'renewed'",
                    [],
                )?;
                for index in 0..EXPIRED_LEASE_BATCH_SIZE + 3 {
                    transaction.execute(
                        "INSERT INTO ha_members(instance_id, incarnation_id,
                             started_unix_seconds, last_seen_unix_seconds,
                             lease_until_unix_seconds, metadata_json)
                         VALUES (?1, ?2, 0, 0, 0, '{}')",
                        params![format!("expired-{index}"), Uuid::new_v4().to_string()],
                    )?;
                }
                Ok(())
            })
            .expect("expired members should seed");
        let current = renewed
            .register_or_renew_member()
            .await
            .expect("member should renew before maintenance");
        assert_eq!(current.incarnation_id, original.incarnation_id);
        assert_eq!(
            active
                .prune_expired_members()
                .await
                .expect("first maintenance batch should succeed"),
            EXPIRED_LEASE_BATCH_SIZE as u64
        );
        assert_eq!(
            active
                .prune_expired_members()
                .await
                .expect("second maintenance batch should succeed"),
            3
        );
        assert_eq!(
            active
                .prune_expired_members()
                .await
                .expect("empty maintenance batch should succeed"),
            0
        );
        let members = active
            .active_members()
            .await
            .expect("active members should list");
        assert_eq!(members.len(), 2);
        assert!(members.iter().any(|member| member == &current));
        let stored: i64 =
            database
                .with_connection(|connection| {
                    Ok(connection
                        .query_row("SELECT COUNT(*) FROM ha_members", [], |row| row.get(0))?)
                })
                .expect("remaining members should count");
        assert_eq!(stored, 2);
    }
}
