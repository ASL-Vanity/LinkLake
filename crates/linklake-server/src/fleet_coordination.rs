//! Fleet generation、同步进度与冲突账本的共享协调存储。

use crate::{ha_coordination::HaCoordinator, storage::CoordinationStorage};
use rusqlite::{params, OptionalExtension, Transaction as SqliteTransaction};
use serde::Serialize;
use std::str::FromStr;
use tokio_postgres::Transaction as PostgresTransaction;
use uuid::Uuid;

const SQLITE_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS fleet_generations (
    source_instance_id TEXT PRIMARY KEY NOT NULL,
    generation INTEGER NOT NULL CHECK(generation >= 0),
    revision TEXT NOT NULL,
    owner_instance_id TEXT NOT NULL,
    owner_incarnation_id TEXT NOT NULL,
    fencing_token INTEGER NOT NULL CHECK(fencing_token > 0),
    resource_count INTEGER NOT NULL CHECK(resource_count >= 0),
    sync_state TEXT NOT NULL CHECK(sync_state IN (
        'pending', 'applying', 'ready', 'conflicted', 'failed'
    )),
    sync_progress INTEGER NOT NULL CHECK(sync_progress BETWEEN 0 AND 100),
    updated_unix_seconds INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS fleet_conflicts (
    conflict_id TEXT PRIMARY KEY NOT NULL,
    source_instance_id TEXT NOT NULL,
    generation INTEGER NOT NULL CHECK(generation >= 0),
    resource_kind TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    owner_instance_id TEXT,
    conflict_code TEXT NOT NULL,
    detail_summary TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('open', 'resolved')),
    detected_unix_seconds INTEGER NOT NULL,
    resolved_unix_seconds INTEGER,
    resolution TEXT
);
CREATE INDEX IF NOT EXISTS fleet_conflicts_source_state
    ON fleet_conflicts(source_instance_id, state, detected_unix_seconds DESC);
"#;

const POSTGRES_SOURCE_LOCK_SEED: i64 = 0x4c4c_464c_545f_5352;
const POSTGRES_CONFLICT_LOCK_SEED: i64 = 0x4c4c_464c_545f_4346;
const MAX_INSTANCE_ID_BYTES: usize = 128;
const MAX_REVISION_BYTES: usize = 256;
const MAX_RESOURCE_KIND_BYTES: usize = 64;
const MAX_RESOURCE_ID_BYTES: usize = 256;
const MAX_CONFLICT_CODE_BYTES: usize = 96;
const MAX_DETAIL_SUMMARY_CHARS: usize = 512;
const MAX_RESOLUTION_CHARS: usize = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FleetSyncState {
    Pending,
    Applying,
    Ready,
    Conflicted,
    Failed,
}

impl FleetSyncState {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Applying => "applying",
            Self::Ready => "ready",
            Self::Conflicted => "conflicted",
            Self::Failed => "failed",
        }
    }
}

impl FromStr for FleetSyncState {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "pending" => Ok(Self::Pending),
            "applying" => Ok(Self::Applying),
            "ready" => Ok(Self::Ready),
            "conflicted" => Ok(Self::Conflicted),
            "failed" => Ok(Self::Failed),
            _ => anyhow::bail!("unknown Fleet sync state"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FleetConflictState {
    Open,
    Resolved,
}

impl FleetConflictState {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Resolved => "resolved",
        }
    }
}

impl FromStr for FleetConflictState {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "open" => Ok(Self::Open),
            "resolved" => Ok(Self::Resolved),
            _ => anyhow::bail!("unknown Fleet conflict state"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct FleetGeneration {
    pub(crate) source_instance_id: String,
    pub(crate) generation: u64,
    pub(crate) revision: String,
    pub(crate) owner_instance_id: String,
    pub(crate) owner_incarnation_id: String,
    pub(crate) fencing_token: u64,
    pub(crate) resource_count: u64,
    pub(crate) sync_state: FleetSyncState,
    pub(crate) sync_progress: u8,
    pub(crate) updated_unix_seconds: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FleetGenerationInput {
    pub(crate) source_instance_id: String,
    pub(crate) generation: u64,
    pub(crate) revision: String,
    pub(crate) resource_count: u64,
    pub(crate) sync_state: FleetSyncState,
    pub(crate) sync_progress: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct FleetGenerationUpdate {
    pub(crate) accepted: bool,
    pub(crate) duplicate: bool,
    pub(crate) generation: FleetGeneration,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct FleetConflict {
    pub(crate) conflict_id: Uuid,
    pub(crate) source_instance_id: String,
    pub(crate) generation: u64,
    pub(crate) resource_kind: String,
    pub(crate) resource_id: String,
    pub(crate) owner_instance_id: Option<String>,
    pub(crate) conflict_code: String,
    pub(crate) detail_summary: String,
    pub(crate) state: FleetConflictState,
    pub(crate) detected_unix_seconds: u64,
    pub(crate) resolved_unix_seconds: Option<u64>,
    pub(crate) resolution: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FleetConflictInput {
    pub(crate) conflict_id: Uuid,
    pub(crate) source_instance_id: String,
    pub(crate) generation: u64,
    pub(crate) resource_kind: String,
    pub(crate) resource_id: String,
    pub(crate) owner_instance_id: Option<String>,
    pub(crate) conflict_code: String,
    pub(crate) detail_summary: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct FleetConflictWrite {
    pub(crate) duplicate: bool,
    pub(crate) conflict: FleetConflict,
}

#[derive(Clone)]
pub(crate) struct FleetCoordination {
    coordinator: HaCoordinator,
}

impl FleetCoordination {
    pub(crate) fn open(coordinator: HaCoordinator) -> anyhow::Result<Self> {
        if let CoordinationStorage::Sqlite(database) = coordinator.storage() {
            database.with_transaction(|transaction| {
                transaction.execute_batch(SQLITE_SCHEMA)?;
                Ok(())
            })?;
        }
        Ok(Self { coordinator })
    }

    pub(crate) async fn record_generation(
        &self,
        input: FleetGenerationInput,
        fencing_token: u64,
    ) -> anyhow::Result<FleetGenerationUpdate> {
        let input = normalize_generation_input(input)?;
        anyhow::ensure!(fencing_token > 0, "fencing token must be positive");
        match self.coordinator.storage() {
            CoordinationStorage::Sqlite(database) => database.with_transaction(|transaction| {
                self.coordinator
                    .assert_sqlite_transaction_fence(transaction, fencing_token)?;
                let now = sqlite_now(transaction)?;
                let current = read_sqlite_generation(transaction, &input.source_instance_id)?;
                let update = calculate_generation_update(
                    current.as_ref(),
                    &input,
                    self.coordinator.instance_id(),
                    self.coordinator.incarnation_id(),
                    fencing_token,
                    now,
                )?;
                if update.accepted {
                    ensure_no_open_conflicts_for_ready_sqlite(transaction, &update.generation)?;
                    write_sqlite_generation(transaction, &update.generation)?;
                }
                Ok(update)
            }),
            CoordinationStorage::Postgres(_) => {
                let mut client = self.coordinator.storage().postgres_client().await?;
                let transaction = client.transaction().await?;
                self.coordinator
                    .assert_postgres_transaction_fence(&transaction, fencing_token)
                    .await?;
                lock_postgres_source(&transaction, &input.source_instance_id).await?;
                let now = postgres_now(&transaction).await?;
                let current =
                    read_postgres_generation_for_update(&transaction, &input.source_instance_id)
                        .await?;
                let update = calculate_generation_update(
                    current.as_ref(),
                    &input,
                    self.coordinator.instance_id(),
                    self.coordinator.incarnation_id(),
                    fencing_token,
                    now,
                )?;
                if update.accepted {
                    ensure_no_open_conflicts_for_ready_postgres(&transaction, &update.generation)
                        .await?;
                    write_postgres_generation(&transaction, &update.generation).await?;
                }
                transaction.commit().await?;
                Ok(update)
            }
        }
    }

    pub(crate) async fn record_conflict(
        &self,
        input: FleetConflictInput,
        fencing_token: u64,
    ) -> anyhow::Result<FleetConflictWrite> {
        let input = normalize_conflict_input(input)?;
        anyhow::ensure!(fencing_token > 0, "fencing token must be positive");
        match self.coordinator.storage() {
            CoordinationStorage::Sqlite(database) => database.with_transaction(|transaction| {
                self.coordinator
                    .assert_sqlite_transaction_fence(transaction, fencing_token)?;
                ensure_sqlite_generation_matches(
                    transaction,
                    &input.source_instance_id,
                    input.generation,
                )?;
                let current = read_sqlite_conflict(transaction, input.conflict_id)?;
                if let Some(current) = current {
                    ensure_conflict_identity(&current, &input)?;
                    return Ok(FleetConflictWrite {
                        duplicate: true,
                        conflict: current,
                    });
                }
                let conflict = new_conflict(input, sqlite_now(transaction)?);
                write_sqlite_conflict(transaction, &conflict)?;
                mark_sqlite_generation_conflicted(
                    transaction,
                    &conflict.source_instance_id,
                    conflict.generation,
                    self.coordinator.instance_id(),
                    self.coordinator.incarnation_id(),
                    fencing_token,
                )?;
                Ok(FleetConflictWrite {
                    duplicate: false,
                    conflict,
                })
            }),
            CoordinationStorage::Postgres(_) => {
                let mut client = self.coordinator.storage().postgres_client().await?;
                let transaction = client.transaction().await?;
                self.coordinator
                    .assert_postgres_transaction_fence(&transaction, fencing_token)
                    .await?;
                lock_postgres_source(&transaction, &input.source_instance_id).await?;
                lock_postgres_conflict(&transaction, input.conflict_id).await?;
                ensure_postgres_generation_matches(
                    &transaction,
                    &input.source_instance_id,
                    input.generation,
                )
                .await?;
                let current =
                    read_postgres_conflict_for_update(&transaction, input.conflict_id).await?;
                if let Some(current) = current {
                    ensure_conflict_identity(&current, &input)?;
                    transaction.commit().await?;
                    return Ok(FleetConflictWrite {
                        duplicate: true,
                        conflict: current,
                    });
                }
                let conflict = new_conflict(input, postgres_now(&transaction).await?);
                write_postgres_conflict(&transaction, &conflict).await?;
                mark_postgres_generation_conflicted(
                    &transaction,
                    &conflict.source_instance_id,
                    conflict.generation,
                    self.coordinator.instance_id(),
                    self.coordinator.incarnation_id(),
                    fencing_token,
                )
                .await?;
                transaction.commit().await?;
                Ok(FleetConflictWrite {
                    duplicate: false,
                    conflict,
                })
            }
        }
    }

    pub(crate) async fn resolve_conflict(
        &self,
        conflict_id: Uuid,
        resolution: &str,
        fencing_token: u64,
    ) -> anyhow::Result<Option<FleetConflictWrite>> {
        let resolution =
            normalize_summary(resolution, "conflict resolution", MAX_RESOLUTION_CHARS)?;
        anyhow::ensure!(fencing_token > 0, "fencing token must be positive");
        match self.coordinator.storage() {
            CoordinationStorage::Sqlite(database) => database.with_transaction(|transaction| {
                self.coordinator
                    .assert_sqlite_transaction_fence(transaction, fencing_token)?;
                let Some(mut conflict) = read_sqlite_conflict(transaction, conflict_id)? else {
                    return Ok(None);
                };
                if conflict.state == FleetConflictState::Resolved {
                    anyhow::ensure!(
                        conflict.resolution.as_deref() == Some(resolution.as_str()),
                        "Fleet conflict was resolved with a different resolution"
                    );
                    return Ok(Some(FleetConflictWrite {
                        duplicate: true,
                        conflict,
                    }));
                }
                let now = sqlite_now(transaction)?;
                conflict.state = FleetConflictState::Resolved;
                conflict.resolved_unix_seconds = Some(now);
                conflict.resolution = Some(resolution);
                update_sqlite_conflict_resolution(transaction, &conflict)?;
                Ok(Some(FleetConflictWrite {
                    duplicate: false,
                    conflict,
                }))
            }),
            CoordinationStorage::Postgres(_) => {
                let mut client = self.coordinator.storage().postgres_client().await?;
                let transaction = client.transaction().await?;
                self.coordinator
                    .assert_postgres_transaction_fence(&transaction, fencing_token)
                    .await?;
                let Some(source_instance_id) =
                    read_postgres_conflict_source(&transaction, conflict_id).await?
                else {
                    transaction.commit().await?;
                    return Ok(None);
                };
                lock_postgres_source(&transaction, &source_instance_id).await?;
                lock_postgres_conflict(&transaction, conflict_id).await?;
                let Some(mut conflict) =
                    read_postgres_conflict_for_update(&transaction, conflict_id).await?
                else {
                    transaction.commit().await?;
                    return Ok(None);
                };
                if conflict.state == FleetConflictState::Resolved {
                    anyhow::ensure!(
                        conflict.resolution.as_deref() == Some(resolution.as_str()),
                        "Fleet conflict was resolved with a different resolution"
                    );
                    transaction.commit().await?;
                    return Ok(Some(FleetConflictWrite {
                        duplicate: true,
                        conflict,
                    }));
                }
                let now = postgres_now(&transaction).await?;
                conflict.state = FleetConflictState::Resolved;
                conflict.resolved_unix_seconds = Some(now);
                conflict.resolution = Some(resolution);
                update_postgres_conflict_resolution(&transaction, &conflict).await?;
                transaction.commit().await?;
                Ok(Some(FleetConflictWrite {
                    duplicate: false,
                    conflict,
                }))
            }
        }
    }

    pub(crate) async fn generations(&self) -> anyhow::Result<Vec<FleetGeneration>> {
        match self.coordinator.storage() {
            CoordinationStorage::Sqlite(database) => database.with_connection(|connection| {
                let mut statement = connection.prepare(
                    "SELECT source_instance_id, generation, revision, owner_instance_id,
                            owner_incarnation_id, fencing_token, resource_count, sync_state,
                            sync_progress, updated_unix_seconds
                     FROM fleet_generations ORDER BY source_instance_id",
                )?;
                let rows = statement.query_map([], sqlite_generation_row)?;
                rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
            }),
            CoordinationStorage::Postgres(_) => {
                let client = self.coordinator.storage().postgres_client().await?;
                client
                    .query(
                        "SELECT source_instance_id, generation, revision, owner_instance_id,
                                owner_incarnation_id, fencing_token, resource_count, sync_state,
                                sync_progress,
                                CAST(EXTRACT(EPOCH FROM updated_at) AS BIGINT)
                         FROM linklake_fleet_generations ORDER BY source_instance_id",
                        &[],
                    )
                    .await?
                    .iter()
                    .map(postgres_generation_row)
                    .collect()
            }
        }
    }

    pub(crate) async fn conflicts(
        &self,
        source_instance_id: Option<&str>,
        state: Option<FleetConflictState>,
    ) -> anyhow::Result<Vec<FleetConflict>> {
        let source_instance_id = source_instance_id
            .map(|value| normalize_identifier(value, "source instance ID", MAX_INSTANCE_ID_BYTES))
            .transpose()?;
        match self.coordinator.storage() {
            CoordinationStorage::Sqlite(database) => database.with_connection(|connection| {
                let mut statement = connection.prepare(
                    "SELECT conflict_id, source_instance_id, generation, resource_kind,
                            resource_id, owner_instance_id, conflict_code, detail_summary,
                            state, detected_unix_seconds, resolved_unix_seconds, resolution
                     FROM fleet_conflicts
                     WHERE (?1 IS NULL OR source_instance_id = ?1)
                       AND (?2 IS NULL OR state = ?2)
                     ORDER BY detected_unix_seconds DESC, conflict_id",
                )?;
                let state = state.map(FleetConflictState::as_str);
                let rows =
                    statement.query_map(params![source_instance_id, state], sqlite_conflict_row)?;
                rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
            }),
            CoordinationStorage::Postgres(_) => {
                let client = self.coordinator.storage().postgres_client().await?;
                let state = state.map(FleetConflictState::as_str);
                client
                    .query(
                        "SELECT conflict_id, source_instance_id, generation, resource_kind,
                                resource_id, owner_instance_id, conflict_code, detail_summary,
                                state, CAST(EXTRACT(EPOCH FROM detected_at) AS BIGINT),
                                CAST(EXTRACT(EPOCH FROM resolved_at) AS BIGINT), resolution
                         FROM linklake_fleet_conflicts
                         WHERE ($1::text IS NULL OR source_instance_id = $1)
                           AND ($2::text IS NULL OR state = $2)
                         ORDER BY detected_at DESC, conflict_id",
                        &[&source_instance_id, &state],
                    )
                    .await?
                    .iter()
                    .map(postgres_conflict_row)
                    .collect()
            }
        }
    }
}

fn normalize_generation_input(
    mut input: FleetGenerationInput,
) -> anyhow::Result<FleetGenerationInput> {
    input.source_instance_id = normalize_identifier(
        &input.source_instance_id,
        "source instance ID",
        MAX_INSTANCE_ID_BYTES,
    )?;
    input.revision = normalize_identifier(&input.revision, "Fleet revision", MAX_REVISION_BYTES)?;
    anyhow::ensure!(
        input.generation <= i64::MAX as u64,
        "Fleet generation is too large"
    );
    anyhow::ensure!(
        input.resource_count <= i64::MAX as u64,
        "Fleet resource count is too large"
    );
    validate_sync_state(input.sync_state, input.sync_progress)?;
    Ok(input)
}

fn normalize_conflict_input(mut input: FleetConflictInput) -> anyhow::Result<FleetConflictInput> {
    anyhow::ensure!(
        !input.conflict_id.is_nil(),
        "Fleet conflict ID must not be nil"
    );
    input.source_instance_id = normalize_identifier(
        &input.source_instance_id,
        "source instance ID",
        MAX_INSTANCE_ID_BYTES,
    )?;
    input.resource_kind = normalize_identifier(
        &input.resource_kind,
        "Fleet resource kind",
        MAX_RESOURCE_KIND_BYTES,
    )?;
    input.resource_id = normalize_identifier(
        &input.resource_id,
        "Fleet resource ID",
        MAX_RESOURCE_ID_BYTES,
    )?;
    input.owner_instance_id = input
        .owner_instance_id
        .map(|value| normalize_identifier(&value, "resource owner", MAX_INSTANCE_ID_BYTES))
        .transpose()?;
    input.conflict_code = normalize_identifier(
        &input.conflict_code,
        "Fleet conflict code",
        MAX_CONFLICT_CODE_BYTES,
    )?;
    input.detail_summary = normalize_summary(
        &input.detail_summary,
        "Fleet conflict detail",
        MAX_DETAIL_SUMMARY_CHARS,
    )?;
    anyhow::ensure!(
        input.generation <= i64::MAX as u64,
        "Fleet generation is too large"
    );
    Ok(input)
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

fn normalize_summary(value: &str, label: &str, maximum: usize) -> anyhow::Result<String> {
    let mut output = String::new();
    let mut previous_space = false;
    for character in value.trim().chars() {
        let character = if character.is_control() {
            ' '
        } else {
            character
        };
        if character.is_whitespace() {
            if !previous_space {
                output.push(' ');
                previous_space = true;
            }
        } else {
            output.push(character);
            previous_space = false;
        }
        if output.chars().count() >= maximum {
            break;
        }
    }
    let output = output.trim().to_owned();
    anyhow::ensure!(!output.is_empty(), "{label} is required");
    Ok(output)
}

fn validate_sync_state(state: FleetSyncState, progress: u8) -> anyhow::Result<()> {
    anyhow::ensure!(progress <= 100, "Fleet sync progress must not exceed 100");
    match state {
        FleetSyncState::Pending => {
            anyhow::ensure!(
                progress == 0,
                "pending Fleet generations must have zero progress"
            )
        }
        FleetSyncState::Applying => anyhow::ensure!(
            progress < 100,
            "applying Fleet generations must have progress below 100"
        ),
        FleetSyncState::Ready => anyhow::ensure!(
            progress == 100,
            "ready Fleet generations must have 100 progress"
        ),
        FleetSyncState::Conflicted | FleetSyncState::Failed => {}
    }
    Ok(())
}

fn calculate_generation_update(
    current: Option<&FleetGeneration>,
    input: &FleetGenerationInput,
    owner_instance_id: &str,
    owner_incarnation_id: &str,
    fencing_token: u64,
    now: u64,
) -> anyhow::Result<FleetGenerationUpdate> {
    if let Some(current) = current {
        if input.generation < current.generation {
            return Ok(FleetGenerationUpdate {
                accepted: false,
                duplicate: false,
                generation: current.clone(),
            });
        }
        if input.generation == current.generation {
            anyhow::ensure!(
                input.revision == current.revision,
                "Fleet generation was already bound to another revision"
            );
            anyhow::ensure!(
                input.resource_count == current.resource_count,
                "Fleet generation was already bound to another resource count"
            );
            anyhow::ensure!(
                input.sync_progress >= current.sync_progress,
                "Fleet sync progress must not move backwards"
            );
            anyhow::ensure!(
                valid_state_transition(current.sync_state, input.sync_state),
                "Fleet sync state transition is invalid"
            );
            if current.fencing_token > fencing_token {
                anyhow::bail!("Fleet generation contains a newer fencing token");
            }
            if current.fencing_token == fencing_token {
                anyhow::ensure!(
                    current.owner_instance_id == owner_instance_id
                        && current.owner_incarnation_id == owner_incarnation_id,
                    "Fleet generation reuses one fencing token across process sessions"
                );
            }
            let duplicate = current.sync_state == input.sync_state
                && current.sync_progress == input.sync_progress
                && current.owner_instance_id == owner_instance_id
                && current.owner_incarnation_id == owner_incarnation_id
                && current.fencing_token == fencing_token;
            if duplicate {
                return Ok(FleetGenerationUpdate {
                    accepted: false,
                    duplicate: true,
                    generation: current.clone(),
                });
            }
        }
    }
    Ok(FleetGenerationUpdate {
        accepted: true,
        duplicate: false,
        generation: FleetGeneration {
            source_instance_id: input.source_instance_id.clone(),
            generation: input.generation,
            revision: input.revision.clone(),
            owner_instance_id: owner_instance_id.to_owned(),
            owner_incarnation_id: owner_incarnation_id.to_owned(),
            fencing_token,
            resource_count: input.resource_count,
            sync_state: input.sync_state,
            sync_progress: input.sync_progress,
            updated_unix_seconds: now,
        },
    })
}

fn valid_state_transition(current: FleetSyncState, next: FleetSyncState) -> bool {
    current == next
        || matches!(
            (current, next),
            (FleetSyncState::Pending, FleetSyncState::Applying)
                | (FleetSyncState::Pending, FleetSyncState::Conflicted)
                | (FleetSyncState::Pending, FleetSyncState::Failed)
                | (FleetSyncState::Applying, FleetSyncState::Ready)
                | (FleetSyncState::Applying, FleetSyncState::Conflicted)
                | (FleetSyncState::Applying, FleetSyncState::Failed)
                | (FleetSyncState::Conflicted, FleetSyncState::Applying)
                | (FleetSyncState::Conflicted, FleetSyncState::Ready)
                | (FleetSyncState::Conflicted, FleetSyncState::Failed)
        )
}

fn new_conflict(input: FleetConflictInput, now: u64) -> FleetConflict {
    FleetConflict {
        conflict_id: input.conflict_id,
        source_instance_id: input.source_instance_id,
        generation: input.generation,
        resource_kind: input.resource_kind,
        resource_id: input.resource_id,
        owner_instance_id: input.owner_instance_id,
        conflict_code: input.conflict_code,
        detail_summary: input.detail_summary,
        state: FleetConflictState::Open,
        detected_unix_seconds: now,
        resolved_unix_seconds: None,
        resolution: None,
    }
}

fn ensure_conflict_identity(
    current: &FleetConflict,
    input: &FleetConflictInput,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        current.source_instance_id == input.source_instance_id
            && current.generation == input.generation
            && current.resource_kind == input.resource_kind
            && current.resource_id == input.resource_id
            && current.owner_instance_id == input.owner_instance_id
            && current.conflict_code == input.conflict_code
            && current.detail_summary == input.detail_summary,
        "Fleet conflict ID is already bound to another conflict"
    );
    Ok(())
}

fn read_sqlite_generation(
    transaction: &SqliteTransaction<'_>,
    source_instance_id: &str,
) -> anyhow::Result<Option<FleetGeneration>> {
    transaction
        .query_row(
            "SELECT source_instance_id, generation, revision, owner_instance_id,
                    owner_incarnation_id, fencing_token, resource_count, sync_state,
                    sync_progress, updated_unix_seconds
             FROM fleet_generations WHERE source_instance_id = ?1",
            [source_instance_id],
            sqlite_generation_row,
        )
        .optional()
        .map_err(Into::into)
}

fn write_sqlite_generation(
    transaction: &SqliteTransaction<'_>,
    generation: &FleetGeneration,
) -> anyhow::Result<()> {
    transaction.execute(
        "INSERT INTO fleet_generations(
             source_instance_id, generation, revision, owner_instance_id,
             owner_incarnation_id, fencing_token, resource_count, sync_state,
             sync_progress, updated_unix_seconds
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
         ON CONFLICT(source_instance_id) DO UPDATE SET
             generation = excluded.generation,
             revision = excluded.revision,
             owner_instance_id = excluded.owner_instance_id,
             owner_incarnation_id = excluded.owner_incarnation_id,
             fencing_token = excluded.fencing_token,
             resource_count = excluded.resource_count,
             sync_state = excluded.sync_state,
             sync_progress = excluded.sync_progress,
             updated_unix_seconds = excluded.updated_unix_seconds",
        params![
            generation.source_instance_id,
            as_i64(generation.generation)?,
            generation.revision,
            generation.owner_instance_id,
            generation.owner_incarnation_id,
            as_i64(generation.fencing_token)?,
            as_i64(generation.resource_count)?,
            generation.sync_state.as_str(),
            i64::from(generation.sync_progress),
            as_i64(generation.updated_unix_seconds)?,
        ],
    )?;
    Ok(())
}

fn ensure_no_open_conflicts_for_ready_sqlite(
    transaction: &SqliteTransaction<'_>,
    generation: &FleetGeneration,
) -> anyhow::Result<()> {
    if generation.sync_state != FleetSyncState::Ready {
        return Ok(());
    }
    let open: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM fleet_conflicts
         WHERE source_instance_id = ?1 AND generation = ?2 AND state = 'open'",
        params![
            generation.source_instance_id,
            as_i64(generation.generation)?
        ],
        |row| row.get(0),
    )?;
    anyhow::ensure!(
        open == 0,
        "Fleet generation cannot become ready with open conflicts"
    );
    Ok(())
}

fn ensure_sqlite_generation_matches(
    transaction: &SqliteTransaction<'_>,
    source_instance_id: &str,
    generation: u64,
) -> anyhow::Result<()> {
    let current = read_sqlite_generation(transaction, source_instance_id)?
        .ok_or_else(|| anyhow::anyhow!("Fleet generation does not exist"))?;
    anyhow::ensure!(
        current.generation == generation,
        "Fleet conflict targets a stale generation"
    );
    Ok(())
}

fn write_sqlite_conflict(
    transaction: &SqliteTransaction<'_>,
    conflict: &FleetConflict,
) -> anyhow::Result<()> {
    transaction.execute(
        "INSERT INTO fleet_conflicts(
             conflict_id, source_instance_id, generation, resource_kind, resource_id,
             owner_instance_id, conflict_code, detail_summary, state,
             detected_unix_seconds, resolved_unix_seconds, resolution
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        params![
            conflict.conflict_id.to_string(),
            conflict.source_instance_id,
            as_i64(conflict.generation)?,
            conflict.resource_kind,
            conflict.resource_id,
            conflict.owner_instance_id,
            conflict.conflict_code,
            conflict.detail_summary,
            conflict.state.as_str(),
            as_i64(conflict.detected_unix_seconds)?,
            conflict.resolved_unix_seconds.map(as_i64).transpose()?,
            conflict.resolution,
        ],
    )?;
    Ok(())
}

fn mark_sqlite_generation_conflicted(
    transaction: &SqliteTransaction<'_>,
    source_instance_id: &str,
    generation: u64,
    owner_instance_id: &str,
    owner_incarnation_id: &str,
    fencing_token: u64,
) -> anyhow::Result<()> {
    let changed = transaction.execute(
        "UPDATE fleet_generations
         SET sync_state = 'conflicted', owner_instance_id = ?3,
             owner_incarnation_id = ?4, fencing_token = ?5,
             updated_unix_seconds = CAST(unixepoch('now') AS INTEGER)
         WHERE source_instance_id = ?1 AND generation = ?2",
        params![
            source_instance_id,
            as_i64(generation)?,
            owner_instance_id,
            owner_incarnation_id,
            as_i64(fencing_token)?
        ],
    )?;
    anyhow::ensure!(
        changed == 1,
        "Fleet generation disappeared while recording conflict"
    );
    Ok(())
}

fn read_sqlite_conflict(
    transaction: &SqliteTransaction<'_>,
    conflict_id: Uuid,
) -> anyhow::Result<Option<FleetConflict>> {
    transaction
        .query_row(
            "SELECT conflict_id, source_instance_id, generation, resource_kind,
                    resource_id, owner_instance_id, conflict_code, detail_summary,
                    state, detected_unix_seconds, resolved_unix_seconds, resolution
             FROM fleet_conflicts WHERE conflict_id = ?1",
            [conflict_id.to_string()],
            sqlite_conflict_row,
        )
        .optional()
        .map_err(Into::into)
}

fn update_sqlite_conflict_resolution(
    transaction: &SqliteTransaction<'_>,
    conflict: &FleetConflict,
) -> anyhow::Result<()> {
    let changed = transaction.execute(
        "UPDATE fleet_conflicts
         SET state = ?2, resolved_unix_seconds = ?3, resolution = ?4
         WHERE conflict_id = ?1 AND state = 'open'",
        params![
            conflict.conflict_id.to_string(),
            conflict.state.as_str(),
            conflict.resolved_unix_seconds.map(as_i64).transpose()?,
            conflict.resolution,
        ],
    )?;
    anyhow::ensure!(changed == 1, "Fleet conflict changed during resolution");
    Ok(())
}

fn sqlite_generation_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<FleetGeneration> {
    Ok(FleetGeneration {
        source_instance_id: row.get(0)?,
        generation: sqlite_u64(row.get(1)?, 1, "Fleet generation")?,
        revision: row.get(2)?,
        owner_instance_id: row.get(3)?,
        owner_incarnation_id: row.get(4)?,
        fencing_token: sqlite_positive_u64(row.get(5)?, 5, "Fleet fencing token")?,
        resource_count: sqlite_u64(row.get(6)?, 6, "Fleet resource count")?,
        sync_state: row.get::<_, String>(7)?.parse().map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                7,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?,
        sync_progress: sqlite_progress(row.get(8)?, 8)?,
        updated_unix_seconds: sqlite_u64(row.get(9)?, 9, "Fleet update time")?,
    })
}

fn sqlite_conflict_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<FleetConflict> {
    let conflict_id = Uuid::parse_str(&row.get::<_, String>(0)?).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(error))
    })?;
    Ok(FleetConflict {
        conflict_id,
        source_instance_id: row.get(1)?,
        generation: sqlite_u64(row.get(2)?, 2, "Fleet conflict generation")?,
        resource_kind: row.get(3)?,
        resource_id: row.get(4)?,
        owner_instance_id: row.get(5)?,
        conflict_code: row.get(6)?,
        detail_summary: row.get(7)?,
        state: row.get::<_, String>(8)?.parse().map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                8,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?,
        detected_unix_seconds: sqlite_u64(row.get(9)?, 9, "Fleet conflict time")?,
        resolved_unix_seconds: row
            .get::<_, Option<i64>>(10)?
            .map(|value| sqlite_u64(value, 10, "Fleet resolution time"))
            .transpose()?,
        resolution: row.get(11)?,
    })
}

async fn read_postgres_generation_for_update(
    transaction: &PostgresTransaction<'_>,
    source_instance_id: &str,
) -> anyhow::Result<Option<FleetGeneration>> {
    transaction
        .query_opt(
            "SELECT source_instance_id, generation, revision, owner_instance_id,
                    owner_incarnation_id, fencing_token, resource_count, sync_state,
                    sync_progress, CAST(EXTRACT(EPOCH FROM updated_at) AS BIGINT)
             FROM linklake_fleet_generations
             WHERE source_instance_id = $1 FOR UPDATE",
            &[&source_instance_id],
        )
        .await?
        .map(|row| postgres_generation_row(&row))
        .transpose()
}

async fn write_postgres_generation(
    transaction: &PostgresTransaction<'_>,
    generation: &FleetGeneration,
) -> anyhow::Result<()> {
    transaction
        .execute(
            "INSERT INTO linklake_fleet_generations(
                 source_instance_id, generation, revision, owner_instance_id,
                 owner_incarnation_id, fencing_token, resource_count, sync_state,
                 sync_progress, updated_at
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9,
                 to_timestamp($10::bigint))
             ON CONFLICT(source_instance_id) DO UPDATE SET
                 generation = EXCLUDED.generation,
                 revision = EXCLUDED.revision,
                 owner_instance_id = EXCLUDED.owner_instance_id,
                 owner_incarnation_id = EXCLUDED.owner_incarnation_id,
                 fencing_token = EXCLUDED.fencing_token,
                 resource_count = EXCLUDED.resource_count,
                 sync_state = EXCLUDED.sync_state,
                 sync_progress = EXCLUDED.sync_progress,
                 updated_at = EXCLUDED.updated_at",
            &[
                &generation.source_instance_id,
                &as_i64(generation.generation)?,
                &generation.revision,
                &generation.owner_instance_id,
                &generation.owner_incarnation_id,
                &as_i64(generation.fencing_token)?,
                &as_i64(generation.resource_count)?,
                &generation.sync_state.as_str(),
                &i32::from(generation.sync_progress),
                &as_i64(generation.updated_unix_seconds)?,
            ],
        )
        .await?;
    Ok(())
}

async fn ensure_no_open_conflicts_for_ready_postgres(
    transaction: &PostgresTransaction<'_>,
    generation: &FleetGeneration,
) -> anyhow::Result<()> {
    if generation.sync_state != FleetSyncState::Ready {
        return Ok(());
    }
    let open: i64 = transaction
        .query_one(
            "SELECT COUNT(*) FROM linklake_fleet_conflicts
             WHERE source_instance_id = $1 AND generation = $2 AND state = 'open'",
            &[
                &generation.source_instance_id,
                &as_i64(generation.generation)?,
            ],
        )
        .await?
        .get(0);
    anyhow::ensure!(
        open == 0,
        "Fleet generation cannot become ready with open conflicts"
    );
    Ok(())
}

async fn ensure_postgres_generation_matches(
    transaction: &PostgresTransaction<'_>,
    source_instance_id: &str,
    generation: u64,
) -> anyhow::Result<()> {
    let current = read_postgres_generation_for_update(transaction, source_instance_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("Fleet generation does not exist"))?;
    anyhow::ensure!(
        current.generation == generation,
        "Fleet conflict targets a stale generation"
    );
    Ok(())
}

async fn write_postgres_conflict(
    transaction: &PostgresTransaction<'_>,
    conflict: &FleetConflict,
) -> anyhow::Result<()> {
    let resolved = conflict.resolved_unix_seconds.map(as_i64).transpose()?;
    transaction
        .execute(
            "INSERT INTO linklake_fleet_conflicts(
                 conflict_id, source_instance_id, generation, resource_kind, resource_id,
                 owner_instance_id, conflict_code, detail_summary, state,
                 detected_at, resolved_at, resolution
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9,
                 to_timestamp($10::bigint), to_timestamp($11::bigint), $12)",
            &[
                &conflict.conflict_id.to_string(),
                &conflict.source_instance_id,
                &as_i64(conflict.generation)?,
                &conflict.resource_kind,
                &conflict.resource_id,
                &conflict.owner_instance_id,
                &conflict.conflict_code,
                &conflict.detail_summary,
                &conflict.state.as_str(),
                &as_i64(conflict.detected_unix_seconds)?,
                &resolved,
                &conflict.resolution,
            ],
        )
        .await?;
    Ok(())
}

async fn mark_postgres_generation_conflicted(
    transaction: &PostgresTransaction<'_>,
    source_instance_id: &str,
    generation: u64,
    owner_instance_id: &str,
    owner_incarnation_id: &str,
    fencing_token: u64,
) -> anyhow::Result<()> {
    let changed = transaction
        .execute(
            "UPDATE linklake_fleet_generations
             SET sync_state = 'conflicted', owner_instance_id = $3,
                 owner_incarnation_id = $4, fencing_token = $5,
                 updated_at = clock_timestamp()
             WHERE source_instance_id = $1 AND generation = $2",
            &[
                &source_instance_id,
                &as_i64(generation)?,
                &owner_instance_id,
                &owner_incarnation_id,
                &as_i64(fencing_token)?,
            ],
        )
        .await?;
    anyhow::ensure!(
        changed == 1,
        "Fleet generation disappeared while recording conflict"
    );
    Ok(())
}

async fn read_postgres_conflict_source(
    transaction: &PostgresTransaction<'_>,
    conflict_id: Uuid,
) -> anyhow::Result<Option<String>> {
    Ok(transaction
        .query_opt(
            "SELECT source_instance_id FROM linklake_fleet_conflicts
             WHERE conflict_id = $1",
            &[&conflict_id.to_string()],
        )
        .await?
        .map(|row| row.get(0)))
}

async fn read_postgres_conflict_for_update(
    transaction: &PostgresTransaction<'_>,
    conflict_id: Uuid,
) -> anyhow::Result<Option<FleetConflict>> {
    transaction
        .query_opt(
            "SELECT conflict_id, source_instance_id, generation, resource_kind,
                    resource_id, owner_instance_id, conflict_code, detail_summary,
                    state, CAST(EXTRACT(EPOCH FROM detected_at) AS BIGINT),
                    CAST(EXTRACT(EPOCH FROM resolved_at) AS BIGINT), resolution
             FROM linklake_fleet_conflicts WHERE conflict_id = $1 FOR UPDATE",
            &[&conflict_id.to_string()],
        )
        .await?
        .map(|row| postgres_conflict_row(&row))
        .transpose()
}

async fn update_postgres_conflict_resolution(
    transaction: &PostgresTransaction<'_>,
    conflict: &FleetConflict,
) -> anyhow::Result<()> {
    let resolved = conflict.resolved_unix_seconds.map(as_i64).transpose()?;
    let changed = transaction
        .execute(
            "UPDATE linklake_fleet_conflicts
             SET state = $2, resolved_at = to_timestamp($3::bigint), resolution = $4
             WHERE conflict_id = $1 AND state = 'open'",
            &[
                &conflict.conflict_id.to_string(),
                &conflict.state.as_str(),
                &resolved,
                &conflict.resolution,
            ],
        )
        .await?;
    anyhow::ensure!(changed == 1, "Fleet conflict changed during resolution");
    Ok(())
}

fn postgres_generation_row(row: &tokio_postgres::Row) -> anyhow::Result<FleetGeneration> {
    Ok(FleetGeneration {
        source_instance_id: row.get(0),
        generation: nonnegative_u64(row.get(1), "Fleet generation")?,
        revision: row.get(2),
        owner_instance_id: row.get(3),
        owner_incarnation_id: row.get(4),
        fencing_token: positive_u64(row.get(5), "Fleet fencing token")?,
        resource_count: nonnegative_u64(row.get(6), "Fleet resource count")?,
        sync_state: row.get::<_, String>(7).parse()?,
        sync_progress: progress_u8(row.get(8))?,
        updated_unix_seconds: nonnegative_u64(row.get(9), "Fleet update time")?,
    })
}

fn postgres_conflict_row(row: &tokio_postgres::Row) -> anyhow::Result<FleetConflict> {
    Ok(FleetConflict {
        conflict_id: Uuid::parse_str(&row.get::<_, String>(0))?,
        source_instance_id: row.get(1),
        generation: nonnegative_u64(row.get(2), "Fleet conflict generation")?,
        resource_kind: row.get(3),
        resource_id: row.get(4),
        owner_instance_id: row.get(5),
        conflict_code: row.get(6),
        detail_summary: row.get(7),
        state: row.get::<_, String>(8).parse()?,
        detected_unix_seconds: nonnegative_u64(row.get(9), "Fleet conflict time")?,
        resolved_unix_seconds: row
            .get::<_, Option<i64>>(10)
            .map(|value| nonnegative_u64(value, "Fleet resolution time"))
            .transpose()?,
        resolution: row.get(11),
    })
}

async fn lock_postgres_source(
    transaction: &PostgresTransaction<'_>,
    source_instance_id: &str,
) -> anyhow::Result<()> {
    transaction
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, $2))",
            &[&source_instance_id, &POSTGRES_SOURCE_LOCK_SEED],
        )
        .await?;
    Ok(())
}

async fn lock_postgres_conflict(
    transaction: &PostgresTransaction<'_>,
    conflict_id: Uuid,
) -> anyhow::Result<()> {
    transaction
        .query_one(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, $2))",
            &[&conflict_id.to_string(), &POSTGRES_CONFLICT_LOCK_SEED],
        )
        .await?;
    Ok(())
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

fn as_i64(value: u64) -> anyhow::Result<i64> {
    i64::try_from(value).map_err(|_| anyhow::anyhow!("value exceeds database integer range"))
}

fn nonnegative_u64(value: i64, label: &str) -> anyhow::Result<u64> {
    u64::try_from(value).map_err(|_| anyhow::anyhow!("{label} must not be negative"))
}

fn positive_u64(value: i64, label: &str) -> anyhow::Result<u64> {
    anyhow::ensure!(value > 0, "{label} must be positive");
    Ok(value as u64)
}

fn progress_u8(value: i32) -> anyhow::Result<u8> {
    anyhow::ensure!((0..=100).contains(&value), "Fleet sync progress is invalid");
    Ok(value as u8)
}

fn sqlite_u64(value: i64, column: usize, label: &str) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|_| sqlite_integer_error(column, &format!("{label} is invalid")))
}

fn sqlite_positive_u64(value: i64, column: usize, label: &str) -> rusqlite::Result<u64> {
    if value <= 0 {
        return Err(sqlite_integer_error(
            column,
            &format!("{label} must be positive"),
        ));
    }
    Ok(value as u64)
}

fn sqlite_progress(value: i64, column: usize) -> rusqlite::Result<u8> {
    if !(0..=100).contains(&value) {
        return Err(sqlite_integer_error(
            column,
            "Fleet sync progress is invalid",
        ));
    }
    Ok(value as u8)
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
