//! PostgreSQL 协调平面的独立迁移账本。

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tokio_postgres::{Client, Transaction};

pub(crate) const CURRENT_POSTGRES_SCHEMA_VERSION: i64 = 3;
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

const MIGRATION_V3_NAME: &str = "resource_lease_identity";
const MIGRATION_V3_SQL: &str = r#"
ALTER TABLE linklake_public_port_ownership
    ADD COLUMN lease_id TEXT;
UPDATE linklake_public_port_ownership
SET lease_id = md5(
    protocol || ':' || public_port::text || ':' || ctid::text || ':' ||
    random()::text || ':' || clock_timestamp()::text
)::uuid::text;
ALTER TABLE linklake_public_port_ownership
    ALTER COLUMN lease_id SET NOT NULL;

ALTER TABLE linklake_job_leases
    ADD COLUMN lease_id TEXT;
UPDATE linklake_job_leases
SET lease_id = md5(
    job_key || ':' || ctid::text || ':' || random()::text || ':' ||
    clock_timestamp()::text
)::uuid::text;
ALTER TABLE linklake_job_leases
    ALTER COLUMN lease_id SET NOT NULL;
"#;

struct Migration {
    version: i64,
    name: &'static str,
    sql: &'static str,
}

struct ColumnExpectation {
    name: &'static str,
    postgres_type: &'static str,
    nullable: bool,
}

struct TableExpectation {
    name: &'static str,
    primary_key: &'static [&'static str],
    columns: &'static [ColumnExpectation],
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
    Migration {
        version: 3,
        name: MIGRATION_V3_NAME,
        sql: MIGRATION_V3_SQL,
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
    const TABLES: &[TableExpectation] = &[
        TableExpectation {
            name: "linklake_ha_members",
            primary_key: &["instance_id"],
            columns: &[
                required("instance_id", "text"),
                required("incarnation_id", "text"),
                required("started_at", "timestamptz"),
                required("last_seen_at", "timestamptz"),
                required("lease_until", "timestamptz"),
                required("metadata_json", "jsonb"),
            ],
        },
        TableExpectation {
            name: "linklake_ha_fencing_sequence",
            primary_key: &["singleton_id"],
            columns: &[
                required("singleton_id", "int2"),
                required("next_token", "int8"),
            ],
        },
        TableExpectation {
            name: "linklake_ha_leader",
            primary_key: &["singleton_id"],
            columns: &[
                required("singleton_id", "int2"),
                required("instance_id", "text"),
                required("incarnation_id", "text"),
                required("fencing_token", "int8"),
                required("acquired_at", "timestamptz"),
                required("renewed_at", "timestamptz"),
                required("lease_until", "timestamptz"),
            ],
        },
        TableExpectation {
            name: "linklake_public_port_ownership",
            primary_key: &["protocol", "public_port"],
            columns: &[
                required("protocol", "text"),
                required("public_port", "int4"),
                required("lease_id", "text"),
                required("owner_instance_id", "text"),
                required("owner_incarnation_id", "text"),
                required("fencing_token", "int8"),
                required("policy_id", "text"),
                required("acquired_at", "timestamptz"),
                required("renewed_at", "timestamptz"),
                required("lease_until", "timestamptz"),
            ],
        },
        TableExpectation {
            name: "linklake_job_leases",
            primary_key: &["job_key"],
            columns: &[
                required("job_key", "text"),
                required("job_kind", "text"),
                required("lease_id", "text"),
                required("owner_instance_id", "text"),
                required("owner_incarnation_id", "text"),
                required("fencing_token", "int8"),
                required("acquired_at", "timestamptz"),
                required("renewed_at", "timestamptz"),
                required("lease_until", "timestamptz"),
                optional("last_completed_at", "timestamptz"),
                optional("last_error_code", "text"),
            ],
        },
        TableExpectation {
            name: "linklake_target_health",
            primary_key: &["target_key"],
            columns: &[
                required("target_key", "text"),
                required("member_alive", "bool"),
                required("control_channel_healthy", "bool"),
                required("application_healthy", "bool"),
                required("effective_healthy", "bool"),
                required("consecutive_successes", "int4"),
                required("consecutive_failures", "int4"),
                required("weight", "int4"),
                required("revision", "int8"),
                optional("last_probe_at", "timestamptz"),
                required("last_transition_at", "timestamptz"),
                optional("last_error_summary", "text"),
            ],
        },
        TableExpectation {
            name: "linklake_fleet_generations",
            primary_key: &["source_instance_id"],
            columns: &[
                required("source_instance_id", "text"),
                required("generation", "int8"),
                required("revision", "text"),
                required("owner_instance_id", "text"),
                required("owner_incarnation_id", "text"),
                required("fencing_token", "int8"),
                required("resource_count", "int8"),
                required("sync_state", "text"),
                required("sync_progress", "int4"),
                required("updated_at", "timestamptz"),
            ],
        },
        TableExpectation {
            name: "linklake_fleet_conflicts",
            primary_key: &["conflict_id"],
            columns: &[
                required("conflict_id", "text"),
                required("source_instance_id", "text"),
                required("generation", "int8"),
                required("resource_kind", "text"),
                required("resource_id", "text"),
                optional("owner_instance_id", "text"),
                required("conflict_code", "text"),
                required("detail_summary", "text"),
                required("state", "text"),
                required("detected_at", "timestamptz"),
                optional("resolved_at", "timestamptz"),
                optional("resolution", "text"),
            ],
        },
    ];
    for table in TABLES {
        let exists: bool = transaction
            .query_one("SELECT to_regclass($1) IS NOT NULL", &[&table.name])
            .await?
            .get(0);
        anyhow::ensure!(
            exists,
            "PostgreSQL migration ledger exists but table {} is missing",
            table.name
        );
        let rows = transaction
            .query(
                "SELECT column_name, udt_name, is_nullable = 'YES'
                 FROM information_schema.columns
                 WHERE table_schema = current_schema() AND table_name = $1",
                &[&table.name],
            )
            .await?;
        let columns = rows
            .iter()
            .map(|row| {
                (
                    row.get::<_, String>(0),
                    (row.get::<_, String>(1), row.get::<_, bool>(2)),
                )
            })
            .collect::<HashMap<_, _>>();
        for expected in table.columns {
            let Some((postgres_type, nullable)) = columns.get(expected.name) else {
                anyhow::bail!(
                    "PostgreSQL migration ledger exists but {}.{} is missing",
                    table.name,
                    expected.name
                );
            };
            anyhow::ensure!(
                postgres_type == expected.postgres_type && *nullable == expected.nullable,
                "PostgreSQL schema mismatch for {}.{}: expected type {} nullable={}, got type {} nullable={}",
                table.name,
                expected.name,
                expected.postgres_type,
                expected.nullable,
                postgres_type,
                nullable
            );
        }
        let primary_key = transaction
            .query(
                "SELECT attribute.attname
                 FROM pg_index AS idx
                 JOIN pg_class AS relation ON relation.oid = idx.indrelid
                 JOIN pg_namespace AS namespace ON namespace.oid = relation.relnamespace
                 JOIN LATERAL unnest(idx.indkey) WITH ORDINALITY AS key(attnum, position)
                   ON TRUE
                 JOIN pg_attribute AS attribute
                   ON attribute.attrelid = relation.oid AND attribute.attnum = key.attnum
                 WHERE namespace.nspname = current_schema()
                   AND relation.relname = $1 AND idx.indisprimary
                 ORDER BY key.position",
                &[&table.name],
            )
            .await?
            .iter()
            .map(|row| row.get::<_, String>(0))
            .collect::<Vec<_>>();
        anyhow::ensure!(
            primary_key.len() == table.primary_key.len()
                && primary_key
                    .iter()
                    .zip(table.primary_key.iter())
                    .all(|(actual, expected)| actual == expected),
            "PostgreSQL primary key mismatch for {}",
            table.name
        );
    }
    Ok(())
}

const fn required(name: &'static str, postgres_type: &'static str) -> ColumnExpectation {
    ColumnExpectation {
        name,
        postgres_type,
        nullable: false,
    }
}

const fn optional(name: &'static str, postgres_type: &'static str) -> ColumnExpectation {
    ColumnExpectation {
        name,
        postgres_type,
        nullable: true,
    }
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
