//! 需要全局单执行者的后台任务租约与完成账本。

use crate::{ha_coordination::HaCoordinator, storage::CoordinationStorage};
use rusqlite::{params, OptionalExtension, Transaction as SqliteTransaction};
use serde::Serialize;
use std::time::Duration;
use tokio_postgres::Transaction as PostgresTransaction;
use uuid::Uuid;

const SQLITE_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS job_leases (
    job_key TEXT PRIMARY KEY NOT NULL,
    job_kind TEXT NOT NULL,
    lease_id TEXT NOT NULL,
    owner_instance_id TEXT NOT NULL,
    owner_incarnation_id TEXT NOT NULL,
    fencing_token INTEGER NOT NULL CHECK(fencing_token > 0),
    acquired_unix_seconds INTEGER NOT NULL,
    renewed_unix_seconds INTEGER NOT NULL,
    lease_until_unix_seconds INTEGER NOT NULL,
    last_completed_unix_seconds INTEGER,
    last_error_code TEXT
);
CREATE INDEX IF NOT EXISTS job_leases_owner
    ON job_leases(owner_instance_id, lease_until_unix_seconds);
"#;

const POSTGRES_JOB_LOCK_SEED: i64 = 0x4c4c_4a4f_425f_4c4b;
const MAX_JOB_KEY_BYTES: usize = 256;
const MAX_JOB_KIND_BYTES: usize = 64;
const MAX_ERROR_CODE_BYTES: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct JobLease {
    pub(crate) job_key: String,
    pub(crate) job_kind: String,
    pub(crate) lease_id: Uuid,
    pub(crate) owner_instance_id: String,
    pub(crate) owner_incarnation_id: String,
    pub(crate) fencing_token: u64,
    pub(crate) acquired_unix_seconds: u64,
    pub(crate) renewed_unix_seconds: u64,
    pub(crate) lease_until_unix_seconds: u64,
    pub(crate) last_completed_unix_seconds: Option<u64>,
    pub(crate) last_error_code: Option<String>,
}

#[derive(Clone)]
pub(crate) struct JobLeases {
    coordinator: HaCoordinator,
    lease_seconds: u64,
}

impl JobLeases {
    pub(crate) fn open(coordinator: HaCoordinator, lease: Duration) -> anyhow::Result<Self> {
        let lease_seconds = lease_seconds(lease)?;
        if let CoordinationStorage::Sqlite(database) = coordinator.storage() {
            database.with_transaction(ensure_sqlite_schema)?;
        }
        Ok(Self {
            coordinator,
            lease_seconds,
        })
    }

    pub(crate) async fn acquire(
        &self,
        job_key: &str,
        job_kind: &str,
        fencing_token: u64,
    ) -> anyhow::Result<Option<JobLease>> {
        let job_key = normalize_identifier(job_key, "job key", MAX_JOB_KEY_BYTES)?;
        let job_kind = normalize_identifier(job_kind, "job kind", MAX_JOB_KIND_BYTES)?;
        anyhow::ensure!(fencing_token > 0, "fencing token must be positive");
        match self.coordinator.storage() {
            CoordinationStorage::Sqlite(database) => database.with_transaction(|transaction| {
                self.coordinator
                    .assert_sqlite_transaction_fence(transaction, fencing_token)?;
                let now = sqlite_now(transaction)?;
                let current = read_sqlite_job(transaction, &job_key)?;
                let mode = claim_mode(
                    current.as_ref(),
                    &job_kind,
                    self.coordinator.instance_id(),
                    self.coordinator.incarnation_id(),
                    fencing_token,
                    now,
                )?;
                match mode {
                    ClaimMode::Conflict => Ok(None),
                    ClaimMode::Fresh => {
                        let lease_id = Uuid::new_v4();
                        let lease_until = now.saturating_add(self.lease_seconds);
                        let changed = transaction.execute(
                            "INSERT INTO job_leases(
                                 job_key, job_kind, lease_id, owner_instance_id,
                                 owner_incarnation_id, fencing_token, acquired_unix_seconds,
                                 renewed_unix_seconds, lease_until_unix_seconds,
                                 last_completed_unix_seconds, last_error_code
                             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, ?8, NULL, NULL)
                             ON CONFLICT(job_key) DO UPDATE SET
                                 lease_id = excluded.lease_id,
                                 owner_instance_id = excluded.owner_instance_id,
                                 owner_incarnation_id = excluded.owner_incarnation_id,
                                 fencing_token = excluded.fencing_token,
                                 acquired_unix_seconds = excluded.acquired_unix_seconds,
                                 renewed_unix_seconds = excluded.renewed_unix_seconds,
                                 lease_until_unix_seconds = excluded.lease_until_unix_seconds,
                                 last_error_code = NULL",
                            params![
                                job_key,
                                job_kind,
                                lease_id.to_string(),
                                self.coordinator.instance_id(),
                                self.coordinator.incarnation_id(),
                                as_i64(fencing_token)?,
                                as_i64(now)?,
                                as_i64(lease_until)?,
                            ],
                        )?;
                        anyhow::ensure!(changed == 1, "job lease acquisition changed no row");
                        read_sqlite_job(transaction, &job_key)?
                            .map(Some)
                            .ok_or_else(|| {
                                anyhow::anyhow!("job lease disappeared after acquisition")
                            })
                    }
                }
            }),
            CoordinationStorage::Postgres(_) => {
                let mut client = self.coordinator.storage().postgres_client().await?;
                let transaction = client.transaction().await?;
                self.coordinator
                    .assert_postgres_transaction_fence(&transaction, fencing_token)
                    .await?;
                lock_postgres_job(&transaction, &job_key).await?;
                let now = postgres_now(&transaction).await?;
                let current = read_postgres_job_for_update(&transaction, &job_key).await?;
                let mode = claim_mode(
                    current.as_ref(),
                    &job_kind,
                    self.coordinator.instance_id(),
                    self.coordinator.incarnation_id(),
                    fencing_token,
                    now,
                )?;
                let lease = match mode {
                    ClaimMode::Conflict => None,
                    ClaimMode::Fresh => {
                        let lease_id = Uuid::new_v4();
                        Some(
                            replace_postgres_job(
                                &transaction,
                                &job_key,
                                &job_kind,
                                lease_id,
                                self.coordinator.instance_id(),
                                self.coordinator.incarnation_id(),
                                fencing_token,
                                now,
                                now.saturating_add(self.lease_seconds),
                            )
                            .await?,
                        )
                    }
                };
                transaction.commit().await?;
                Ok(lease)
            }
        }
    }

    pub(crate) async fn renew(
        &self,
        job_key: &str,
        job_kind: &str,
        lease_id: Uuid,
        fencing_token: u64,
    ) -> anyhow::Result<Option<JobLease>> {
        let job_key = normalize_identifier(job_key, "job key", MAX_JOB_KEY_BYTES)?;
        let job_kind = normalize_identifier(job_kind, "job kind", MAX_JOB_KIND_BYTES)?;
        anyhow::ensure!(fencing_token > 0, "fencing token must be positive");
        match self.coordinator.storage() {
            CoordinationStorage::Sqlite(database) => database.with_transaction(|transaction| {
                self.coordinator
                    .assert_sqlite_transaction_fence(transaction, fencing_token)?;
                let now = sqlite_now(transaction)?;
                let lease_until = now.saturating_add(self.lease_seconds);
                let changed = transaction.execute(
                    "UPDATE job_leases
                     SET renewed_unix_seconds = ?7, lease_until_unix_seconds = ?8
                     WHERE job_key = ?1 AND job_kind = ?2 AND lease_id = ?3
                       AND owner_instance_id = ?4 AND owner_incarnation_id = ?5
                       AND fencing_token = ?6 AND lease_until_unix_seconds > ?7",
                    params![
                        job_key,
                        job_kind,
                        lease_id.to_string(),
                        self.coordinator.instance_id(),
                        self.coordinator.incarnation_id(),
                        as_i64(fencing_token)?,
                        as_i64(now)?,
                        as_i64(lease_until)?,
                    ],
                )?;
                anyhow::ensure!(changed <= 1, "multiple job leases were renewed");
                if changed == 0 {
                    return Ok(None);
                }
                read_sqlite_job(transaction, &job_key)?
                    .map(Some)
                    .ok_or_else(|| anyhow::anyhow!("job lease disappeared after renewal"))
            }),
            CoordinationStorage::Postgres(_) => {
                let mut client = self.coordinator.storage().postgres_client().await?;
                let transaction = client.transaction().await?;
                self.coordinator
                    .assert_postgres_transaction_fence(&transaction, fencing_token)
                    .await?;
                lock_postgres_job(&transaction, &job_key).await?;
                let now = postgres_now(&transaction).await?;
                let lease = renew_postgres_job(
                    &transaction,
                    &job_key,
                    &job_kind,
                    lease_id,
                    self.coordinator.instance_id(),
                    self.coordinator.incarnation_id(),
                    fencing_token,
                    now,
                    now.saturating_add(self.lease_seconds),
                )
                .await?;
                transaction.commit().await?;
                Ok(lease)
            }
        }
    }

    pub(crate) async fn complete(
        &self,
        job_key: &str,
        job_kind: &str,
        lease_id: Uuid,
        fencing_token: u64,
    ) -> anyhow::Result<bool> {
        self.finish(job_key, job_kind, lease_id, fencing_token, None)
            .await
    }

    pub(crate) async fn fail(
        &self,
        job_key: &str,
        job_kind: &str,
        lease_id: Uuid,
        fencing_token: u64,
        error_code: &str,
    ) -> anyhow::Result<bool> {
        let error_code = normalize_identifier(error_code, "job error code", MAX_ERROR_CODE_BYTES)?;
        self.finish(job_key, job_kind, lease_id, fencing_token, Some(error_code))
            .await
    }

    pub(crate) async fn active(&self) -> anyhow::Result<Vec<JobLease>> {
        match self.coordinator.storage() {
            CoordinationStorage::Sqlite(database) => database.with_connection(|connection| {
                let mut statement = connection.prepare(
                    "SELECT job.job_key, job.job_kind, job.lease_id, job.owner_instance_id,
                            job.owner_incarnation_id, job.fencing_token,
                            job.acquired_unix_seconds, job.renewed_unix_seconds,
                            job.lease_until_unix_seconds, job.last_completed_unix_seconds,
                            job.last_error_code
                     FROM job_leases AS job
                     JOIN ha_leader AS leader
                       ON leader.instance_id = job.owner_instance_id
                      AND leader.incarnation_id = job.owner_incarnation_id
                      AND leader.fencing_token = job.fencing_token
                     JOIN ha_members AS member
                       ON member.instance_id = job.owner_instance_id
                      AND member.incarnation_id = job.owner_incarnation_id
                     WHERE job.lease_until_unix_seconds > CAST(unixepoch('now') AS INTEGER)
                       AND leader.lease_until_unix_seconds > CAST(unixepoch('now') AS INTEGER)
                       AND member.lease_until_unix_seconds > CAST(unixepoch('now') AS INTEGER)
                     ORDER BY job.job_key",
                )?;
                let rows = statement.query_map([], sqlite_job_row)?;
                rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
            }),
            CoordinationStorage::Postgres(_) => {
                let client = self.coordinator.storage().postgres_client().await?;
                client
                    .query(
                        "SELECT job.job_key, job.job_kind, job.lease_id, job.owner_instance_id,
                            job.owner_incarnation_id, job.fencing_token,
                            CAST(EXTRACT(EPOCH FROM job.acquired_at) AS BIGINT),
                            CAST(EXTRACT(EPOCH FROM job.renewed_at) AS BIGINT),
                            CAST(EXTRACT(EPOCH FROM job.lease_until) AS BIGINT),
                            CAST(EXTRACT(EPOCH FROM job.last_completed_at) AS BIGINT),
                            job.last_error_code
                         FROM linklake_job_leases AS job
                         JOIN linklake_ha_leader AS leader
                           ON leader.instance_id = job.owner_instance_id
                          AND leader.incarnation_id = job.owner_incarnation_id
                          AND leader.fencing_token = job.fencing_token
                         JOIN linklake_ha_members AS member
                           ON member.instance_id = job.owner_instance_id
                          AND member.incarnation_id = job.owner_incarnation_id
                         WHERE job.lease_until > clock_timestamp()
                           AND leader.lease_until > clock_timestamp()
                           AND member.lease_until > clock_timestamp()
                         ORDER BY job.job_key",
                        &[],
                    )
                    .await?
                    .iter()
                    .map(postgres_job)
                    .collect()
            }
        }
    }

    async fn finish(
        &self,
        job_key: &str,
        job_kind: &str,
        lease_id: Uuid,
        fencing_token: u64,
        error_code: Option<String>,
    ) -> anyhow::Result<bool> {
        let job_key = normalize_identifier(job_key, "job key", MAX_JOB_KEY_BYTES)?;
        let job_kind = normalize_identifier(job_kind, "job kind", MAX_JOB_KIND_BYTES)?;
        anyhow::ensure!(fencing_token > 0, "fencing token must be positive");
        match self.coordinator.storage() {
            CoordinationStorage::Sqlite(database) => database.with_transaction(|transaction| {
                self.coordinator
                    .assert_sqlite_transaction_fence(transaction, fencing_token)?;
                let now = sqlite_now(transaction)?;
                let changed = transaction.execute(
                    "UPDATE job_leases
                     SET renewed_unix_seconds = ?7, lease_until_unix_seconds = ?7,
                         last_completed_unix_seconds = CASE WHEN ?8 IS NULL THEN ?7 ELSE last_completed_unix_seconds END,
                         last_error_code = ?8
                     WHERE job_key = ?1 AND job_kind = ?2 AND lease_id = ?3
                       AND owner_instance_id = ?4 AND owner_incarnation_id = ?5
                       AND fencing_token = ?6 AND lease_until_unix_seconds > ?7",
                    params![
                        job_key,
                        job_kind,
                        lease_id.to_string(),
                        self.coordinator.instance_id(),
                        self.coordinator.incarnation_id(),
                        as_i64(fencing_token)?,
                        as_i64(now)?,
                        error_code,
                    ],
                )?;
                anyhow::ensure!(changed <= 1, "multiple job leases were finished");
                Ok(changed == 1)
            }),
            CoordinationStorage::Postgres(_) => {
                let mut client = self.coordinator.storage().postgres_client().await?;
                let transaction = client.transaction().await?;
                self.coordinator
                    .assert_postgres_transaction_fence(&transaction, fencing_token)
                    .await?;
                lock_postgres_job(&transaction, &job_key).await?;
                let now = postgres_now(&transaction).await?;
                let changed = transaction
                    .execute(
                        "UPDATE linklake_job_leases
                         SET renewed_at = to_timestamp($7), lease_until = to_timestamp($7),
                             last_completed_at = CASE WHEN $8::text IS NULL
                                 THEN to_timestamp($7) ELSE last_completed_at END,
                             last_error_code = $8
                         WHERE job_key = $1 AND job_kind = $2 AND lease_id = $3
                           AND owner_instance_id = $4 AND owner_incarnation_id = $5
                           AND fencing_token = $6 AND lease_until > to_timestamp($7)",
                        &[
                            &job_key,
                            &job_kind,
                            &lease_id.to_string(),
                            &self.coordinator.instance_id(),
                            &self.coordinator.incarnation_id(),
                            &as_i64(fencing_token)?,
                            &as_i64(now)?,
                            &error_code,
                        ],
                    )
                    .await?;
                anyhow::ensure!(changed <= 1, "multiple job leases were finished");
                transaction.commit().await?;
                Ok(changed == 1)
            }
        }
    }
}

fn ensure_sqlite_schema(transaction: &SqliteTransaction<'_>) -> anyhow::Result<()> {
    transaction.execute_batch(SQLITE_SCHEMA)?;
    if sqlite_column_is_required(transaction, "job_leases", "lease_id")? {
        return Ok(());
    }

    // 升级时重新生成租约身份，确保重启前遗留 worker 无法完成或续租新账本中的任务。
    anyhow::ensure!(
        !sqlite_table_exists(transaction, "job_leases_lease_upgrade")?,
        "unfinished job lease schema upgrade was detected"
    );
    transaction.execute_batch(
        "ALTER TABLE job_leases RENAME TO job_leases_lease_upgrade;
         DROP INDEX IF EXISTS job_leases_owner;",
    )?;
    transaction.execute_batch(SQLITE_SCHEMA)?;
    transaction.execute(
        "INSERT INTO job_leases(
             job_key, job_kind, lease_id, owner_instance_id, owner_incarnation_id,
             fencing_token, acquired_unix_seconds, renewed_unix_seconds,
             lease_until_unix_seconds, last_completed_unix_seconds, last_error_code
         )
         SELECT job_key, job_kind, lower(hex(randomblob(16))), owner_instance_id,
                owner_incarnation_id, fencing_token, acquired_unix_seconds,
                renewed_unix_seconds, lease_until_unix_seconds,
                last_completed_unix_seconds, last_error_code
         FROM job_leases_lease_upgrade",
        [],
    )?;
    transaction.execute_batch("DROP TABLE job_leases_lease_upgrade;")?;
    Ok(())
}

fn sqlite_column_is_required(
    transaction: &SqliteTransaction<'_>,
    table: &str,
    column: &str,
) -> anyhow::Result<bool> {
    let mut statement = transaction.prepare(&format!("PRAGMA table_info({table})"))?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        if row.get::<_, String>(1)? == column {
            return Ok(row.get::<_, i64>(3)? == 1);
        }
    }
    Ok(false)
}

fn sqlite_table_exists(transaction: &SqliteTransaction<'_>, table: &str) -> anyhow::Result<bool> {
    Ok(transaction.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1
         )",
        [table],
        |row| row.get(0),
    )?)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClaimMode {
    Conflict,
    Fresh,
}

fn claim_mode(
    current: Option<&JobLease>,
    job_kind: &str,
    owner_instance_id: &str,
    owner_incarnation_id: &str,
    fencing_token: u64,
    now: u64,
) -> anyhow::Result<ClaimMode> {
    let Some(current) = current else {
        return Ok(ClaimMode::Fresh);
    };
    anyhow::ensure!(
        current.job_kind == job_kind,
        "job key is permanently bound to a different job kind"
    );
    if current.fencing_token > fencing_token {
        anyhow::bail!("job lease contains a newer fencing token");
    }
    if current.fencing_token < fencing_token {
        return Ok(ClaimMode::Fresh);
    }
    anyhow::ensure!(
        current.owner_instance_id == owner_instance_id
            && current.owner_incarnation_id == owner_incarnation_id,
        "job lease reuses one fencing token across different process sessions"
    );
    if current.lease_until_unix_seconds <= now {
        return Ok(ClaimMode::Fresh);
    }
    Ok(ClaimMode::Conflict)
}

fn read_sqlite_job(
    transaction: &SqliteTransaction<'_>,
    job_key: &str,
) -> anyhow::Result<Option<JobLease>> {
    transaction
        .query_row(
            "SELECT job_key, job_kind, lease_id, owner_instance_id, owner_incarnation_id,
                    fencing_token, acquired_unix_seconds, renewed_unix_seconds,
                    lease_until_unix_seconds, last_completed_unix_seconds, last_error_code
             FROM job_leases WHERE job_key = ?1",
            [job_key],
            sqlite_job_row,
        )
        .optional()
        .map_err(Into::into)
}

fn sqlite_job_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<JobLease> {
    let lease_id = Uuid::parse_str(&row.get::<_, String>(2)?).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, Box::new(error))
    })?;
    Ok(JobLease {
        job_key: row.get(0)?,
        job_kind: row.get(1)?,
        lease_id,
        owner_instance_id: row.get(3)?,
        owner_incarnation_id: row.get(4)?,
        fencing_token: sqlite_positive(row.get(5)?, 5, "job fencing token")?,
        acquired_unix_seconds: sqlite_nonnegative(row.get(6)?, 6, "job acquired time")?,
        renewed_unix_seconds: sqlite_nonnegative(row.get(7)?, 7, "job renewed time")?,
        lease_until_unix_seconds: sqlite_nonnegative(row.get(8)?, 8, "job lease time")?,
        last_completed_unix_seconds: row
            .get::<_, Option<i64>>(9)?
            .map(|value| sqlite_nonnegative(value, 9, "job completion time"))
            .transpose()?,
        last_error_code: row.get(10)?,
    })
}

async fn read_postgres_job_for_update(
    transaction: &PostgresTransaction<'_>,
    job_key: &str,
) -> anyhow::Result<Option<JobLease>> {
    transaction
        .query_opt(
            "SELECT job_key, job_kind, lease_id, owner_instance_id, owner_incarnation_id,
                fencing_token,
                CAST(EXTRACT(EPOCH FROM acquired_at) AS BIGINT),
                CAST(EXTRACT(EPOCH FROM renewed_at) AS BIGINT),
                CAST(EXTRACT(EPOCH FROM lease_until) AS BIGINT),
                CAST(EXTRACT(EPOCH FROM last_completed_at) AS BIGINT),
                last_error_code
             FROM linklake_job_leases WHERE job_key = $1 FOR UPDATE",
            &[&job_key],
        )
        .await?
        .map(|row| postgres_job(&row))
        .transpose()
}

async fn renew_postgres_job(
    transaction: &PostgresTransaction<'_>,
    job_key: &str,
    job_kind: &str,
    lease_id: Uuid,
    owner_instance_id: &str,
    owner_incarnation_id: &str,
    fencing_token: u64,
    now: u64,
    lease_until: u64,
) -> anyhow::Result<Option<JobLease>> {
    transaction
        .query_opt(
            "UPDATE linklake_job_leases
             SET renewed_at = to_timestamp($7), lease_until = to_timestamp($8)
             WHERE job_key = $1 AND job_kind = $2 AND lease_id = $3
               AND owner_instance_id = $4 AND owner_incarnation_id = $5
               AND fencing_token = $6 AND lease_until > to_timestamp($7)
             RETURNING job_key, job_kind, lease_id, owner_instance_id,
                 owner_incarnation_id, fencing_token,
                 CAST(EXTRACT(EPOCH FROM acquired_at) AS BIGINT),
                 CAST(EXTRACT(EPOCH FROM renewed_at) AS BIGINT),
                 CAST(EXTRACT(EPOCH FROM lease_until) AS BIGINT),
                 CAST(EXTRACT(EPOCH FROM last_completed_at) AS BIGINT),
                 last_error_code",
            &[
                &job_key,
                &job_kind,
                &lease_id.to_string(),
                &owner_instance_id,
                &owner_incarnation_id,
                &as_i64(fencing_token)?,
                &as_i64(now)?,
                &as_i64(lease_until)?,
            ],
        )
        .await?
        .map(|row| postgres_job(&row))
        .transpose()
}

async fn replace_postgres_job(
    transaction: &PostgresTransaction<'_>,
    job_key: &str,
    job_kind: &str,
    lease_id: Uuid,
    owner_instance_id: &str,
    owner_incarnation_id: &str,
    fencing_token: u64,
    now: u64,
    lease_until: u64,
) -> anyhow::Result<JobLease> {
    let row = transaction
        .query_one(
            "INSERT INTO linklake_job_leases(
                 job_key, job_kind, lease_id, owner_instance_id, owner_incarnation_id,
                 fencing_token, acquired_at, renewed_at, lease_until,
                 last_completed_at, last_error_code
             ) VALUES ($1, $2, $3, $4, $5, $6, to_timestamp($7), to_timestamp($7),
                 to_timestamp($8), NULL, NULL)
             ON CONFLICT(job_key) DO UPDATE SET
                 lease_id = EXCLUDED.lease_id,
                 owner_instance_id = EXCLUDED.owner_instance_id,
                 owner_incarnation_id = EXCLUDED.owner_incarnation_id,
                 fencing_token = EXCLUDED.fencing_token,
                 acquired_at = EXCLUDED.acquired_at,
                 renewed_at = EXCLUDED.renewed_at,
                 lease_until = EXCLUDED.lease_until,
                 last_error_code = NULL
             RETURNING job_key, job_kind, lease_id, owner_instance_id,
                 owner_incarnation_id, fencing_token,
                 CAST(EXTRACT(EPOCH FROM acquired_at) AS BIGINT),
                 CAST(EXTRACT(EPOCH FROM renewed_at) AS BIGINT),
                 CAST(EXTRACT(EPOCH FROM lease_until) AS BIGINT),
                 CAST(EXTRACT(EPOCH FROM last_completed_at) AS BIGINT),
                 last_error_code",
            &[
                &job_key,
                &job_kind,
                &lease_id.to_string(),
                &owner_instance_id,
                &owner_incarnation_id,
                &as_i64(fencing_token)?,
                &as_i64(now)?,
                &as_i64(lease_until)?,
            ],
        )
        .await?;
    postgres_job(&row)
}

fn postgres_job(row: &tokio_postgres::Row) -> anyhow::Result<JobLease> {
    Ok(JobLease {
        job_key: row.get(0),
        job_kind: row.get(1),
        lease_id: Uuid::parse_str(&row.get::<_, String>(2))?,
        owner_instance_id: row.get(3),
        owner_incarnation_id: row.get(4),
        fencing_token: positive(row.get(5), "job fencing token")?,
        acquired_unix_seconds: nonnegative(row.get(6), "job acquired time")?,
        renewed_unix_seconds: nonnegative(row.get(7), "job renewed time")?,
        lease_until_unix_seconds: nonnegative(row.get(8), "job lease time")?,
        last_completed_unix_seconds: row
            .get::<_, Option<i64>>(9)
            .map(|value| nonnegative(value, "job completion time"))
            .transpose()?,
        last_error_code: row.get(10),
    })
}

async fn lock_postgres_job(
    transaction: &PostgresTransaction<'_>,
    job_key: &str,
) -> anyhow::Result<()> {
    transaction
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, $2))",
            &[&job_key, &POSTGRES_JOB_LOCK_SEED],
        )
        .await?;
    Ok(())
}

fn sqlite_now(transaction: &SqliteTransaction<'_>) -> anyhow::Result<u64> {
    let value: i64 =
        transaction.query_row("SELECT CAST(unixepoch('now') AS INTEGER)", [], |row| {
            row.get(0)
        })?;
    nonnegative(value, "SQLite clock")
}

async fn postgres_now(transaction: &PostgresTransaction<'_>) -> anyhow::Result<u64> {
    let value: i64 = transaction
        .query_one(
            "SELECT CAST(EXTRACT(EPOCH FROM clock_timestamp()) AS BIGINT)",
            &[],
        )
        .await?
        .get(0);
    nonnegative(value, "PostgreSQL clock")
}

fn normalize_identifier(value: &str, label: &str, maximum: usize) -> anyhow::Result<String> {
    let value = value.trim();
    anyhow::ensure!(!value.is_empty(), "{label} is required");
    anyhow::ensure!(value.len() <= maximum, "{label} exceeds {maximum} bytes");
    anyhow::ensure!(
        !value.chars().any(char::is_control),
        "{label} must not contain control characters"
    );
    Ok(value.to_owned())
}

fn lease_seconds(duration: Duration) -> anyhow::Result<u64> {
    let seconds = duration.as_secs();
    anyhow::ensure!(seconds >= 2, "job lease must be at least two seconds");
    anyhow::ensure!(seconds <= 5 * 60, "job lease must not exceed 300 seconds");
    Ok(seconds)
}

fn as_i64(value: u64) -> anyhow::Result<i64> {
    i64::try_from(value).map_err(|_| anyhow::anyhow!("value exceeds database integer range"))
}

fn positive(value: i64, label: &str) -> anyhow::Result<u64> {
    anyhow::ensure!(value > 0, "{label} must be positive");
    Ok(value as u64)
}

fn nonnegative(value: i64, label: &str) -> anyhow::Result<u64> {
    anyhow::ensure!(value >= 0, "{label} must not be negative");
    Ok(value as u64)
}

fn sqlite_positive(value: i64, column: usize, label: &str) -> rusqlite::Result<u64> {
    if value <= 0 {
        return Err(sqlite_integer_error(column, label, "must be positive"));
    }
    Ok(value as u64)
}

fn sqlite_nonnegative(value: i64, column: usize, label: &str) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|_| sqlite_integer_error(column, label, "must not be negative"))
}

fn sqlite_integer_error(column: usize, label: &str, requirement: &str) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        column,
        rusqlite::types::Type::Integer,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{label} {requirement}"),
        )),
    )
}
