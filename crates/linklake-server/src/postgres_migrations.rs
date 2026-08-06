//! PostgreSQL 协调平面的独立迁移账本。

use sha2::{Digest, Sha256};
use std::collections::HashSet;
use tokio_postgres::{Client, Transaction};

pub(crate) const CURRENT_POSTGRES_SCHEMA_VERSION: i64 = 2;
const ADVISORY_LOCK_ID: i64 = 0x4c4c_4841_4d49_4752;

const MIGRATION_V1_NAME: &str = "ha_coordination_foundation";
const MIGRATION_V1_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS linklake_ha_members (
    instance_id TEXT PRIMARY KEY,
    started_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    lease_until TIMESTAMPTZ NOT NULL,
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS linklake_ha_members_lease
    ON linklake_ha_members(lease_until);

CREATE TABLE IF NOT EXISTS linklake_ha_fencing_sequence (
    singleton_id SMALLINT PRIMARY KEY CHECK(singleton_id = 1),
    next_token BIGINT NOT NULL CHECK(next_token > 0)
);
INSERT INTO linklake_ha_fencing_sequence(singleton_id, next_token)
VALUES (1, 1) ON CONFLICT(singleton_id) DO NOTHING;

CREATE TABLE IF NOT EXISTS linklake_ha_leader (
    singleton_id SMALLINT PRIMARY KEY CHECK(singleton_id = 1),
    instance_id TEXT NOT NULL,
    fencing_token BIGINT NOT NULL CHECK(fencing_token > 0),
    acquired_at TIMESTAMPTZ NOT NULL,
    renewed_at TIMESTAMPTZ NOT NULL,
    lease_until TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS linklake_public_port_ownership (
    protocol TEXT NOT NULL CHECK(protocol IN ('tcp', 'udp')),
    public_port INTEGER NOT NULL CHECK(public_port BETWEEN 1 AND 65535),
    owner_instance_id TEXT NOT NULL,
    fencing_token BIGINT NOT NULL CHECK(fencing_token > 0),
    policy_id TEXT NOT NULL,
    acquired_at TIMESTAMPTZ NOT NULL,
    renewed_at TIMESTAMPTZ NOT NULL,
    lease_until TIMESTAMPTZ NOT NULL,
    PRIMARY KEY(protocol, public_port)
);
CREATE INDEX IF NOT EXISTS linklake_public_port_owner
    ON linklake_public_port_ownership(owner_instance_id, lease_until);

CREATE TABLE IF NOT EXISTS linklake_job_leases (
    job_key TEXT PRIMARY KEY,
    job_kind TEXT NOT NULL,
    owner_instance_id TEXT NOT NULL,
    fencing_token BIGINT NOT NULL CHECK(fencing_token > 0),
    acquired_at TIMESTAMPTZ NOT NULL,
    renewed_at TIMESTAMPTZ NOT NULL,
    lease_until TIMESTAMPTZ NOT NULL,
    last_completed_at TIMESTAMPTZ,
    last_error_code TEXT
);
CREATE INDEX IF NOT EXISTS linklake_job_leases_owner
    ON linklake_job_leases(owner_instance_id, lease_until);

CREATE TABLE IF NOT EXISTS linklake_target_health (
    target_key TEXT PRIMARY KEY,
    member_alive BOOLEAN NOT NULL,
    control_channel_healthy BOOLEAN NOT NULL,
    application_healthy BOOLEAN NOT NULL,
    effective_healthy BOOLEAN NOT NULL,
    consecutive_successes INTEGER NOT NULL,
    consecutive_failures INTEGER NOT NULL,
    weight INTEGER NOT NULL CHECK(weight > 0),
    revision BIGINT NOT NULL,
    last_probe_at TIMESTAMPTZ,
    last_transition_at TIMESTAMPTZ NOT NULL,
    last_error_summary TEXT
);

CREATE TABLE IF NOT EXISTS linklake_fleet_generations (
    source_instance_id TEXT PRIMARY KEY,
    generation BIGINT NOT NULL CHECK(generation >= 0),
    revision TEXT NOT NULL,
    owner_instance_id TEXT NOT NULL,
    fencing_token BIGINT NOT NULL CHECK(fencing_token > 0),
    resource_count BIGINT NOT NULL CHECK(resource_count >= 0),
    sync_state TEXT NOT NULL,
    sync_progress INTEGER NOT NULL CHECK(sync_progress BETWEEN 0 AND 100),
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS linklake_fleet_conflicts (
    conflict_id TEXT PRIMARY KEY,
    source_instance_id TEXT NOT NULL,
    generation BIGINT NOT NULL,
    resource_kind TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    owner_instance_id TEXT,
    conflict_code TEXT NOT NULL,
    detail_summary TEXT NOT NULL,
    state TEXT NOT NULL,
    detected_at TIMESTAMPTZ NOT NULL,
    resolved_at TIMESTAMPTZ,
    resolution TEXT
);
CREATE INDEX IF NOT EXISTS linklake_fleet_conflicts_source_state
    ON linklake_fleet_conflicts(source_instance_id, state, detected_at DESC);
"#;

const MIGRATION_V2_NAME: &str = "ha_incarnation_fencing";
const MIGRATION_V2_SQL: &str = r#"
ALTER TABLE linklake_ha_members
    ADD COLUMN incarnation_id TEXT NOT NULL DEFAULT 'legacy';
ALTER TABLE linklake_ha_members
    ALTER COLUMN incarnation_id DROP DEFAULT;

ALTER TABLE linklake_ha_leader
    ADD COLUMN incarnation_id TEXT NOT NULL DEFAULT 'legacy';
ALTER TABLE linklake_ha_leader
    ALTER COLUMN incarnation_id DROP DEFAULT;

ALTER TABLE linklake_public_port_ownership
    ADD COLUMN owner_incarnation_id TEXT NOT NULL DEFAULT 'legacy';
ALTER TABLE linklake_public_port_ownership
    ALTER COLUMN owner_incarnation_id DROP DEFAULT;

ALTER TABLE linklake_job_leases
    ADD COLUMN owner_incarnation_id TEXT NOT NULL DEFAULT 'legacy';
ALTER TABLE linklake_job_leases
    ALTER COLUMN owner_incarnation_id DROP DEFAULT;

ALTER TABLE linklake_fleet_generations
    ADD COLUMN owner_incarnation_id TEXT NOT NULL DEFAULT 'legacy';
ALTER TABLE linklake_fleet_generations
    ALTER COLUMN owner_incarnation_id DROP DEFAULT;
"#;

struct Migration {
    version: i64,
    name: &'static str,
    sql: &'static str,
}

const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: MIGRATION_V1_NAME,
        sql: MIGRATION_V1_SQL,
    },
    Migration {
        version: 2,
        name: MIGRATION_V2_NAME,
        sql: MIGRATION_V2_SQL,
    },
];

pub(crate) async fn apply(client: &mut Client) -> anyhow::Result<()> {
    let transaction = client.transaction().await?;
    transaction
        .query_one("SELECT pg_advisory_xact_lock($1)", &[&ADVISORY_LOCK_ID])
        .await?;
    transaction
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS linklake_postgres_schema_migrations (
                 version BIGINT PRIMARY KEY,
                 name TEXT NOT NULL,
                 checksum_sha256 TEXT NOT NULL,
                 applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
             );",
        )
        .await?;

    let rows = transaction
        .query(
            "SELECT version, name, checksum_sha256
             FROM linklake_postgres_schema_migrations ORDER BY version",
            &[],
        )
        .await?;
    for row in rows {
        let version: i64 = row.get(0);
        let name: String = row.get(1);
        let checksum: String = row.get(2);
        let migration = MIGRATIONS
            .iter()
            .find(|migration| migration.version == version)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "PostgreSQL schema version {version} is newer than this LinkLake build"
                )
            })?;
        anyhow::ensure!(
            name == migration.name && checksum == migration_checksum(migration),
            "PostgreSQL migration ledger checksum mismatch at version {version}"
        );
    }

    for migration in MIGRATIONS {
        let checksum = migration_checksum(migration);
        let existing = transaction
            .query_opt(
                "SELECT name, checksum_sha256
                 FROM linklake_postgres_schema_migrations WHERE version = $1",
                &[&migration.version],
            )
            .await?;
        if let Some(row) = existing {
            let name: String = row.get(0);
            let stored: String = row.get(1);
            anyhow::ensure!(
                name == migration.name && stored == checksum,
                "PostgreSQL migration ledger changed at version {}",
                migration.version
            );
            continue;
        }
        transaction.batch_execute(migration.sql).await?;
        transaction
            .execute(
                "INSERT INTO linklake_postgres_schema_migrations(version, name, checksum_sha256)
                 VALUES ($1, $2, $3)",
                &[&migration.version, &migration.name, &checksum],
            )
            .await?;
    }

    let applied: i64 = transaction
        .query_one(
            "SELECT COALESCE(MAX(version), 0)
             FROM linklake_postgres_schema_migrations",
            &[],
        )
        .await?
        .get(0);
    anyhow::ensure!(
        applied == CURRENT_POSTGRES_SCHEMA_VERSION,
        "PostgreSQL migration ledger is incomplete: expected {CURRENT_POSTGRES_SCHEMA_VERSION}, got {applied}"
    );
    verify_schema_structure(&transaction).await?;
    transaction.commit().await?;
    Ok(())
}

async fn verify_schema_structure(transaction: &Transaction<'_>) -> anyhow::Result<()> {
    const TABLES: &[(&str, &[&str])] = &[
        (
            "linklake_ha_members",
            &[
                "instance_id",
                "incarnation_id",
                "last_seen_at",
                "lease_until",
                "metadata_json",
            ],
        ),
        (
            "linklake_ha_fencing_sequence",
            &["singleton_id", "next_token"],
        ),
        (
            "linklake_ha_leader",
            &[
                "instance_id",
                "incarnation_id",
                "fencing_token",
                "lease_until",
            ],
        ),
        (
            "linklake_public_port_ownership",
            &[
                "protocol",
                "public_port",
                "owner_instance_id",
                "owner_incarnation_id",
                "fencing_token",
                "lease_until",
            ],
        ),
        (
            "linklake_job_leases",
            &[
                "job_key",
                "job_kind",
                "owner_instance_id",
                "owner_incarnation_id",
                "fencing_token",
                "lease_until",
            ],
        ),
        (
            "linklake_target_health",
            &[
                "target_key",
                "member_alive",
                "control_channel_healthy",
                "application_healthy",
                "effective_healthy",
                "revision",
            ],
        ),
        (
            "linklake_fleet_generations",
            &[
                "source_instance_id",
                "generation",
                "owner_instance_id",
                "owner_incarnation_id",
                "fencing_token",
                "sync_progress",
            ],
        ),
        (
            "linklake_fleet_conflicts",
            &[
                "conflict_id",
                "source_instance_id",
                "resource_kind",
                "resource_id",
                "state",
            ],
        ),
    ];
    for (table, required_columns) in TABLES {
        let exists: bool = transaction
            .query_one("SELECT to_regclass($1) IS NOT NULL", &[table])
            .await?
            .get(0);
        anyhow::ensure!(
            exists,
            "PostgreSQL migration ledger exists but table {table} is missing"
        );
        let rows = transaction
            .query(
                "SELECT column_name FROM information_schema.columns
                 WHERE table_schema = current_schema() AND table_name = $1",
                &[table],
            )
            .await?;
        let columns = rows
            .iter()
            .map(|row| row.get::<_, String>(0))
            .collect::<HashSet<_>>();
        for column in *required_columns {
            anyhow::ensure!(
                columns.contains(*column),
                "PostgreSQL migration ledger exists but {table}.{column} is missing"
            );
        }
    }
    Ok(())
}

fn migration_checksum(migration: &Migration) -> String {
    let mut digest = Sha256::new();
    digest.update(b"linklake-postgres-migration-v1\0");
    digest.update(migration.version.to_be_bytes());
    digest.update(migration.name.as_bytes());
    digest.update(b"\0");
    digest.update(migration.sql.as_bytes());
    format!("{:x}", digest.finalize())
}
