//! 共享协调平面的目标健康状态与迟滞更新。

use crate::{ha_coordination::HaCoordinator, storage::CoordinationStorage};
use rusqlite::{params, OptionalExtension, Transaction as SqliteTransaction};
use serde::Serialize;
use std::time::Duration;
use tokio_postgres::Transaction as PostgresTransaction;

const SQLITE_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS target_health (
    target_key TEXT PRIMARY KEY NOT NULL,
    member_alive INTEGER NOT NULL CHECK(member_alive IN (0, 1)),
    control_channel_healthy INTEGER NOT NULL CHECK(control_channel_healthy IN (0, 1)),
    application_healthy INTEGER NOT NULL CHECK(application_healthy IN (0, 1)),
    effective_healthy INTEGER NOT NULL CHECK(effective_healthy IN (0, 1)),
    consecutive_successes INTEGER NOT NULL CHECK(consecutive_successes >= 0),
    consecutive_failures INTEGER NOT NULL CHECK(consecutive_failures >= 0),
    weight INTEGER NOT NULL CHECK(weight > 0),
    revision INTEGER NOT NULL CHECK(revision >= 0),
    last_probe_unix_seconds INTEGER,
    last_transition_unix_seconds INTEGER NOT NULL,
    last_error_summary TEXT
);
CREATE INDEX IF NOT EXISTS target_health_effective
    ON target_health(effective_healthy, weight, target_key);
"#;

const MAX_TARGET_KEY_BYTES: usize = 256;
const MAX_ERROR_SUMMARY_BYTES: usize = 320;
const MAX_WEIGHT: u32 = 1_000_000;
const MAX_REVISION: u64 = i64::MAX as u64;
const POSTGRES_TARGET_LOCK_SEED: i64 = 0x4c4c_5441_5247_4554;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct TargetHealth {
    pub(crate) target_key: String,
    pub(crate) member_alive: bool,
    pub(crate) control_channel_healthy: bool,
    pub(crate) application_healthy: bool,
    pub(crate) effective_healthy: bool,
    pub(crate) consecutive_successes: u32,
    pub(crate) consecutive_failures: u32,
    pub(crate) weight: u32,
    pub(crate) revision: u64,
    pub(crate) last_probe_unix_seconds: Option<u64>,
    pub(crate) last_transition_unix_seconds: u64,
    pub(crate) last_error_summary: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TargetHealthObservation {
    pub(crate) target_key: String,
    pub(crate) member_alive: bool,
    pub(crate) control_channel_healthy: bool,
    pub(crate) application_healthy: bool,
    pub(crate) weight: u32,
    pub(crate) revision: u64,
    pub(crate) error_summary: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct TargetHealthUpdate {
    pub(crate) accepted: bool,
    pub(crate) duplicate: bool,
    pub(crate) previous_effective_healthy: bool,
    pub(crate) health: TargetHealth,
}

#[derive(Clone)]
pub(crate) struct TargetHealthCatalog {
    coordinator: HaCoordinator,
    success_threshold: u32,
    failure_threshold: u32,
    stale_after_seconds: u64,
}

impl TargetHealthCatalog {
    pub(crate) fn open(
        coordinator: HaCoordinator,
        success_threshold: u32,
        failure_threshold: u32,
        stale_after: Duration,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            (1..=1_000).contains(&success_threshold),
            "target health success threshold must be between 1 and 1000"
        );
        anyhow::ensure!(
            (1..=1_000).contains(&failure_threshold),
            "target health failure threshold must be between 1 and 1000"
        );
        let stale_after_seconds = stale_after.as_secs();
        anyhow::ensure!(
            (1..=86_400).contains(&stale_after_seconds),
            "target health stale timeout must be between 1 and 86400 seconds"
        );
        if let CoordinationStorage::Sqlite(database) = coordinator.storage() {
            database.with_transaction(|transaction| {
                transaction.execute_batch(SQLITE_SCHEMA)?;
                Ok(())
            })?;
        }
        Ok(Self {
            coordinator,
            success_threshold,
            failure_threshold,
            stale_after_seconds,
        })
    }

    pub(crate) async fn observe(
        &self,
        observation: TargetHealthObservation,
        fencing_token: u64,
    ) -> anyhow::Result<TargetHealthUpdate> {
        let observation = normalize_observation(observation)?;
        anyhow::ensure!(fencing_token > 0, "fencing token must be positive");
        match self.coordinator.storage() {
            CoordinationStorage::Sqlite(database) => database.with_transaction(|transaction| {
                self.coordinator
                    .assert_sqlite_transaction_fence(transaction, fencing_token)?;
                let now = sqlite_now(transaction)?;
                let mut current = read_sqlite(transaction, &observation.target_key)?;
                if let Some(current) = current.as_mut() {
                    apply_staleness(current, now, self.stale_after_seconds);
                }
                let update = calculate_update(
                    current.as_ref(),
                    &observation,
                    now,
                    self.success_threshold,
                    self.failure_threshold,
                )?;
                if update.accepted {
                    write_sqlite(transaction, &update.health)?;
                }
                Ok(update)
            }),
            CoordinationStorage::Postgres(_) => {
                let mut client = self.coordinator.storage().postgres_client().await?;
                let transaction = client.transaction().await?;
                self.coordinator
                    .assert_postgres_transaction_fence(&transaction, fencing_token)
                    .await?;
                lock_postgres_target(&transaction, &observation.target_key).await?;
                let now = postgres_now(&transaction).await?;
                let mut current =
                    read_postgres_for_update(&transaction, &observation.target_key).await?;
                if let Some(current) = current.as_mut() {
                    apply_staleness(current, now, self.stale_after_seconds);
                }
                let update = calculate_update(
                    current.as_ref(),
                    &observation,
                    now,
                    self.success_threshold,
                    self.failure_threshold,
                )?;
                if update.accepted {
                    write_postgres(&transaction, &update.health).await?;
                }
                transaction.commit().await?;
                Ok(update)
            }
        }
    }

    pub(crate) async fn get(&self, target_key: &str) -> anyhow::Result<Option<TargetHealth>> {
        let target_key = normalize_target_key(target_key)?;
        let mut health = match self.coordinator.storage() {
            CoordinationStorage::Sqlite(database) => database.with_connection(|connection| {
                let mut statement = connection.prepare(
                    "SELECT target_key, member_alive, control_channel_healthy,
                            application_healthy, effective_healthy, consecutive_successes,
                            consecutive_failures, weight, revision, last_probe_unix_seconds,
                            last_transition_unix_seconds, last_error_summary
                     FROM target_health WHERE target_key = ?1",
                )?;
                statement
                    .query_row([target_key], sqlite_row)
                    .optional()
                    .map_err(Into::into)
            }),
            CoordinationStorage::Postgres(_) => {
                let client = self.coordinator.storage().postgres_client().await?;
                client
                    .query_opt(
                        "SELECT target_key, member_alive, control_channel_healthy,
                                application_healthy, effective_healthy,
                                consecutive_successes, consecutive_failures, weight, revision,
                                CAST(EXTRACT(EPOCH FROM last_probe_at) AS BIGINT),
                                CAST(EXTRACT(EPOCH FROM last_transition_at) AS BIGINT),
                                last_error_summary
                         FROM linklake_target_health WHERE target_key = $1",
                        &[&target_key],
                    )
                    .await?
                    .map(|row| postgres_row(&row))
                    .transpose()
            }
        }?;
        if let Some(health) = health.as_mut() {
            let now = self.coordinator.storage().database_unix_seconds().await?;
            apply_staleness(health, now, self.stale_after_seconds);
        }
        Ok(health)
    }

    pub(crate) async fn list(&self) -> anyhow::Result<Vec<TargetHealth>> {
        let mut health = match self.coordinator.storage() {
            CoordinationStorage::Sqlite(database) => database.with_connection(|connection| {
                let mut statement = connection.prepare(
                    "SELECT target_key, member_alive, control_channel_healthy,
                            application_healthy, effective_healthy, consecutive_successes,
                            consecutive_failures, weight, revision, last_probe_unix_seconds,
                            last_transition_unix_seconds, last_error_summary
                     FROM target_health ORDER BY target_key",
                )?;
                let rows = statement.query_map([], sqlite_row)?;
                rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
            }),
            CoordinationStorage::Postgres(_) => {
                let client = self.coordinator.storage().postgres_client().await?;
                client
                    .query(
                        "SELECT target_key, member_alive, control_channel_healthy,
                                application_healthy, effective_healthy,
                                consecutive_successes, consecutive_failures, weight, revision,
                                CAST(EXTRACT(EPOCH FROM last_probe_at) AS BIGINT),
                                CAST(EXTRACT(EPOCH FROM last_transition_at) AS BIGINT),
                                last_error_summary
                         FROM linklake_target_health ORDER BY target_key",
                        &[],
                    )
                    .await?
                    .iter()
                    .map(postgres_row)
                    .collect()
            }
        }?;
        let now = self.coordinator.storage().database_unix_seconds().await?;
        for health in &mut health {
            apply_staleness(health, now, self.stale_after_seconds);
        }
        Ok(health)
    }
}

fn apply_staleness(health: &mut TargetHealth, now: u64, stale_after_seconds: u64) {
    let stale = health
        .last_probe_unix_seconds
        .is_none_or(|last_probe| now.saturating_sub(last_probe) >= stale_after_seconds);
    if stale {
        health.effective_healthy = false;
    }
}

fn normalize_observation(
    mut observation: TargetHealthObservation,
) -> anyhow::Result<TargetHealthObservation> {
    observation.target_key = normalize_target_key(&observation.target_key)?;
    anyhow::ensure!(
        (1..=MAX_WEIGHT).contains(&observation.weight),
        "target health weight must be between 1 and {MAX_WEIGHT}"
    );
    anyhow::ensure!(
        observation.revision <= MAX_REVISION,
        "target health revision exceeds database range"
    );
    observation.error_summary = observation
        .error_summary
        .map(|summary| normalize_error_summary(&summary))
        .transpose()?;
    Ok(observation)
}

fn normalize_target_key(value: &str) -> anyhow::Result<String> {
    let value = value.trim();
    anyhow::ensure!(!value.is_empty(), "target key is required");
    anyhow::ensure!(
        value.len() <= MAX_TARGET_KEY_BYTES,
        "target key is too long"
    );
    anyhow::ensure!(
        !value.chars().any(char::is_control),
        "target key must not contain control characters"
    );
    Ok(value.to_owned())
}

fn normalize_error_summary(value: &str) -> anyhow::Result<String> {
    let mut summary = value
        .trim()
        .chars()
        .map(|character| {
            if matches!(character, '\r' | '\n' | '\t') {
                ' '
            } else {
                character
            }
        })
        .collect::<String>();
    if summary.chars().count() > MAX_ERROR_SUMMARY_BYTES {
        summary = summary.chars().take(MAX_ERROR_SUMMARY_BYTES).collect();
    }
    anyhow::ensure!(!summary.is_empty(), "target health error summary is empty");
    Ok(summary)
}

fn calculate_update(
    current: Option<&TargetHealth>,
    observation: &TargetHealthObservation,
    now: u64,
    success_threshold: u32,
    failure_threshold: u32,
) -> anyhow::Result<TargetHealthUpdate> {
    let Some(current) = current else {
        let effective = success_threshold <= 1 && instantaneous_healthy(observation);
        return Ok(TargetHealthUpdate {
            accepted: true,
            duplicate: false,
            previous_effective_healthy: false,
            health: new_health(observation, effective, now),
        });
    };
    if observation.revision < current.revision {
        return Ok(TargetHealthUpdate {
            accepted: false,
            duplicate: false,
            previous_effective_healthy: current.effective_healthy,
            health: current.clone(),
        });
    }
    let same_observation = observation.revision == current.revision
        && current.member_alive == observation.member_alive
        && current.control_channel_healthy == observation.control_channel_healthy
        && current.application_healthy == observation.application_healthy
        && current.weight == observation.weight
        && current.last_error_summary == observation.error_summary;
    if observation.revision == current.revision {
        anyhow::ensure!(
            same_observation,
            "target health revision conflicts with an existing observation"
        );
        return Ok(TargetHealthUpdate {
            accepted: false,
            duplicate: true,
            previous_effective_healthy: current.effective_healthy,
            health: current.clone(),
        });
    }
    let instantaneous = instantaneous_healthy(observation);
    let (successes, failures, effective) = if instantaneous {
        let successes = current
            .consecutive_successes
            .saturating_add(1)
            .min(success_threshold);
        let effective = current.effective_healthy || successes >= success_threshold;
        (successes, 0, effective)
    } else {
        let failures = current
            .consecutive_failures
            .saturating_add(1)
            .min(failure_threshold);
        let effective = current.effective_healthy && failures < failure_threshold;
        (0, failures, effective)
    };
    let transition_at = if effective != current.effective_healthy {
        now
    } else {
        current.last_transition_unix_seconds
    };
    Ok(TargetHealthUpdate {
        accepted: true,
        duplicate: false,
        previous_effective_healthy: current.effective_healthy,
        health: TargetHealth {
            target_key: observation.target_key.clone(),
            member_alive: observation.member_alive,
            control_channel_healthy: observation.control_channel_healthy,
            application_healthy: observation.application_healthy,
            effective_healthy: effective,
            consecutive_successes: successes,
            consecutive_failures: failures,
            weight: observation.weight,
            revision: observation.revision,
            last_probe_unix_seconds: Some(now),
            last_transition_unix_seconds: transition_at,
            last_error_summary: observation.error_summary.clone(),
        },
    })
}

fn new_health(
    observation: &TargetHealthObservation,
    effective_healthy: bool,
    now: u64,
) -> TargetHealth {
    TargetHealth {
        target_key: observation.target_key.clone(),
        member_alive: observation.member_alive,
        control_channel_healthy: observation.control_channel_healthy,
        application_healthy: observation.application_healthy,
        effective_healthy,
        consecutive_successes: if instantaneous_healthy(observation) {
            1
        } else {
            0
        },
        consecutive_failures: if instantaneous_healthy(observation) {
            0
        } else {
            1
        },
        weight: observation.weight,
        revision: observation.revision,
        last_probe_unix_seconds: Some(now),
        last_transition_unix_seconds: now,
        last_error_summary: observation.error_summary.clone(),
    }
}

fn instantaneous_healthy(observation: &TargetHealthObservation) -> bool {
    observation.member_alive
        && observation.control_channel_healthy
        && observation.application_healthy
}

fn write_sqlite(transaction: &SqliteTransaction<'_>, health: &TargetHealth) -> anyhow::Result<()> {
    transaction.execute(
        "INSERT INTO target_health(
             target_key, member_alive, control_channel_healthy, application_healthy,
             effective_healthy, consecutive_successes, consecutive_failures, weight,
             revision, last_probe_unix_seconds, last_transition_unix_seconds,
             last_error_summary
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
         ON CONFLICT(target_key) DO UPDATE SET
             member_alive = excluded.member_alive,
             control_channel_healthy = excluded.control_channel_healthy,
             application_healthy = excluded.application_healthy,
             effective_healthy = excluded.effective_healthy,
             consecutive_successes = excluded.consecutive_successes,
             consecutive_failures = excluded.consecutive_failures,
             weight = excluded.weight,
             revision = excluded.revision,
             last_probe_unix_seconds = excluded.last_probe_unix_seconds,
             last_transition_unix_seconds = excluded.last_transition_unix_seconds,
             last_error_summary = excluded.last_error_summary",
        params![
            health.target_key,
            bool_i64(health.member_alive),
            bool_i64(health.control_channel_healthy),
            bool_i64(health.application_healthy),
            bool_i64(health.effective_healthy),
            i64::from(health.consecutive_successes),
            i64::from(health.consecutive_failures),
            i64::from(health.weight),
            as_i64(health.revision)?,
            health.last_probe_unix_seconds.map(as_i64).transpose()?,
            as_i64(health.last_transition_unix_seconds)?,
            health.last_error_summary,
        ],
    )?;
    Ok(())
}

async fn write_postgres(
    transaction: &PostgresTransaction<'_>,
    health: &TargetHealth,
) -> anyhow::Result<()> {
    let last_probe = health.last_probe_unix_seconds.map(as_i64).transpose()?;
    transaction
        .execute(
            "INSERT INTO linklake_target_health(
                 target_key, member_alive, control_channel_healthy, application_healthy,
                 effective_healthy, consecutive_successes, consecutive_failures, weight,
                 revision, last_probe_at, last_transition_at, last_error_summary
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9,
                 to_timestamp($10::bigint), to_timestamp($11::bigint), $12)
             ON CONFLICT(target_key) DO UPDATE SET
                 member_alive = EXCLUDED.member_alive,
                 control_channel_healthy = EXCLUDED.control_channel_healthy,
                 application_healthy = EXCLUDED.application_healthy,
                 effective_healthy = EXCLUDED.effective_healthy,
                 consecutive_successes = EXCLUDED.consecutive_successes,
                 consecutive_failures = EXCLUDED.consecutive_failures,
                 weight = EXCLUDED.weight,
                 revision = EXCLUDED.revision,
                 last_probe_at = EXCLUDED.last_probe_at,
                 last_transition_at = EXCLUDED.last_transition_at,
                 last_error_summary = EXCLUDED.last_error_summary",
            &[
                &health.target_key,
                &health.member_alive,
                &health.control_channel_healthy,
                &health.application_healthy,
                &health.effective_healthy,
                &as_i32(health.consecutive_successes)?,
                &as_i32(health.consecutive_failures)?,
                &as_i32(health.weight)?,
                &as_i64(health.revision)?,
                &last_probe,
                &as_i64(health.last_transition_unix_seconds)?,
                &health.last_error_summary,
            ],
        )
        .await?;
    Ok(())
}

async fn lock_postgres_target(
    transaction: &PostgresTransaction<'_>,
    target_key: &str,
) -> anyhow::Result<()> {
    transaction
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, $2))",
            &[&target_key, &POSTGRES_TARGET_LOCK_SEED],
        )
        .await?;
    Ok(())
}

fn read_sqlite(
    transaction: &SqliteTransaction<'_>,
    target_key: &str,
) -> anyhow::Result<Option<TargetHealth>> {
    transaction
        .query_row(
            "SELECT target_key, member_alive, control_channel_healthy,
                    application_healthy, effective_healthy, consecutive_successes,
                    consecutive_failures, weight, revision, last_probe_unix_seconds,
                    last_transition_unix_seconds, last_error_summary
             FROM target_health WHERE target_key = ?1",
            [target_key],
            sqlite_row,
        )
        .optional()
        .map_err(Into::into)
}

async fn read_postgres_for_update(
    transaction: &PostgresTransaction<'_>,
    target_key: &str,
) -> anyhow::Result<Option<TargetHealth>> {
    transaction
        .query_opt(
            "SELECT target_key, member_alive, control_channel_healthy,
                    application_healthy, effective_healthy, consecutive_successes,
                    consecutive_failures, weight, revision,
                    CAST(EXTRACT(EPOCH FROM last_probe_at) AS BIGINT),
                    CAST(EXTRACT(EPOCH FROM last_transition_at) AS BIGINT),
                    last_error_summary
             FROM linklake_target_health WHERE target_key = $1 FOR UPDATE",
            &[&target_key],
        )
        .await?
        .map(|row| postgres_row(&row))
        .transpose()
}

fn sqlite_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<TargetHealth> {
    Ok(TargetHealth {
        target_key: row.get(0)?,
        member_alive: sqlite_bool(row.get(1)?, 1)?,
        control_channel_healthy: sqlite_bool(row.get(2)?, 2)?,
        application_healthy: sqlite_bool(row.get(3)?, 3)?,
        effective_healthy: sqlite_bool(row.get(4)?, 4)?,
        consecutive_successes: sqlite_u32(row.get(5)?, 5, "target successes")?,
        consecutive_failures: sqlite_u32(row.get(6)?, 6, "target failures")?,
        weight: sqlite_positive_u32(row.get(7)?, 7, "target weight")?,
        revision: sqlite_u64(row.get(8)?, 8, "target revision")?,
        last_probe_unix_seconds: row
            .get::<_, Option<i64>>(9)?
            .map(|value| sqlite_u64(value, 9, "target probe time"))
            .transpose()?,
        last_transition_unix_seconds: sqlite_u64(row.get(10)?, 10, "target transition time")?,
        last_error_summary: row.get(11)?,
    })
}

fn postgres_row(row: &tokio_postgres::Row) -> anyhow::Result<TargetHealth> {
    Ok(TargetHealth {
        target_key: row.get(0),
        member_alive: row.get(1),
        control_channel_healthy: row.get(2),
        application_healthy: row.get(3),
        effective_healthy: row.get(4),
        consecutive_successes: u32::try_from(row.get::<_, i32>(5))
            .map_err(|_| anyhow::anyhow!("target success count is invalid"))?,
        consecutive_failures: u32::try_from(row.get::<_, i32>(6))
            .map_err(|_| anyhow::anyhow!("target failure count is invalid"))?,
        weight: positive_u32(row.get::<_, i32>(7), "target weight")?,
        revision: nonnegative_u64(row.get(8), "target revision")?,
        last_probe_unix_seconds: row
            .get::<_, Option<i64>>(9)
            .map(|value| nonnegative_u64(value, "target probe time"))
            .transpose()?,
        last_transition_unix_seconds: nonnegative_u64(row.get(10), "target transition time")?,
        last_error_summary: row.get(11),
    })
}

fn sqlite_now(transaction: &SqliteTransaction<'_>) -> anyhow::Result<u64> {
    let value: i64 =
        transaction.query_row("SELECT CAST(unixepoch('now') AS INTEGER)", [], |row| {
            row.get(0)
        })?;
    nonnegative_u64(value, "SQLite clock")
}

async fn postgres_now(transaction: &PostgresTransaction<'_>) -> anyhow::Result<u64> {
    let value: i64 = transaction
        .query_one(
            "SELECT CAST(EXTRACT(EPOCH FROM clock_timestamp()) AS BIGINT)",
            &[],
        )
        .await?
        .get(0);
    nonnegative_u64(value, "PostgreSQL clock")
}

fn bool_i64(value: bool) -> i64 {
    if value {
        1
    } else {
        0
    }
}

fn as_i32(value: u32) -> anyhow::Result<i32> {
    i32::try_from(value).map_err(|_| anyhow::anyhow!("value exceeds database integer range"))
}

fn as_i64(value: u64) -> anyhow::Result<i64> {
    i64::try_from(value).map_err(|_| anyhow::anyhow!("value exceeds database integer range"))
}

fn nonnegative_u64(value: i64, label: &str) -> anyhow::Result<u64> {
    u64::try_from(value).map_err(|_| anyhow::anyhow!("{label} must not be negative"))
}

fn positive_u32(value: i32, label: &str) -> anyhow::Result<u32> {
    anyhow::ensure!(value > 0, "{label} must be positive");
    Ok(value as u32)
}

fn sqlite_bool(value: i64, column: usize) -> rusqlite::Result<bool> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(sqlite_integer_error(column, "boolean value is invalid")),
    }
}

fn sqlite_u32(value: i64, column: usize, label: &str) -> rusqlite::Result<u32> {
    u32::try_from(value).map_err(|_| sqlite_integer_error(column, &format!("{label} is invalid")))
}

fn sqlite_positive_u32(value: i64, column: usize, label: &str) -> rusqlite::Result<u32> {
    let value = sqlite_u32(value, column, label)?;
    if value == 0 {
        return Err(sqlite_integer_error(
            column,
            &format!("{label} must be positive"),
        ));
    }
    Ok(value)
}

fn sqlite_u64(value: i64, column: usize, label: &str) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|_| sqlite_integer_error(column, &format!("{label} is invalid")))
}

fn sqlite_integer_error(column: usize, message: &str) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        column,
        rusqlite::types::Type::Integer,
        Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            message.to_owned(),
        )),
    )
}
