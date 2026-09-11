//! PostgreSQL 协调平面的独立迁移账本。

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tokio_postgres::{Client, Transaction};

pub(crate) const CURRENT_POSTGRES_SCHEMA_VERSION: i64 = 15;
const ADVISORY_LOCK_ID: i64 = 0x4c4c_4841_4d49_4752;

const MIGRATION_V15_NAME: &str = "durable_dns01_publication_intents";
const MIGRATION_V15_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS linklake_dns01_intents (
    id TEXT PRIMARY KEY,
    provider TEXT NOT NULL,
    next_cleanup BIGINT NOT NULL,
    state JSONB NOT NULL CHECK(octet_length(state::text)<=16384)
);
CREATE INDEX IF NOT EXISTS linklake_dns01_intents_due ON linklake_dns01_intents(provider,next_cleanup);
"#;

const MIGRATION_V14_NAME: &str = "shared_http01_challenges";
const MIGRATION_V14_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS linklake_http01_challenges (
    hostname TEXT NOT NULL CHECK(octet_length(hostname) BETWEEN 1 AND 253),
    token TEXT NOT NULL CHECK(octet_length(token) BETWEEN 1 AND 256),
    publication_id TEXT NOT NULL,
    job_key TEXT NOT NULL,
    lease_id TEXT NOT NULL,
    key_authorization TEXT NOT NULL CHECK(octet_length(key_authorization) BETWEEN 45 AND 300),
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY(hostname,token)
);
CREATE INDEX IF NOT EXISTS linklake_http01_challenges_expiry ON linklake_http01_challenges(expires_at);
"#;

const MIGRATION_V13_NAME: &str = "certificate_cluster_key_binding";
const MIGRATION_V13_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS linklake_certificate_key_binding (
    singleton_id INTEGER PRIMARY KEY CHECK(singleton_id=1),
    fingerprint TEXT NOT NULL
);
"#;

const MIGRATION_V12_NAME: &str = "shared_certificate_catalog";
const MIGRATION_V12_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS linklake_acme_config (
    singleton_id INTEGER PRIMARY KEY CHECK(singleton_id=1),
    config JSONB NOT NULL
);
INSERT INTO linklake_acme_config(singleton_id,config) VALUES(1,
    '{"enabled":false,"environment":"production","directory_url":"https://acme-v02.api.letsencrypt.org/directory","contact_email":"","terms_accepted":false,"challenge_type":"http-01","renew_before_days":30,"updated_at":0}'::jsonb)
    ON CONFLICT(singleton_id) DO NOTHING;
CREATE TABLE IF NOT EXISTS linklake_route_tls (
    route_id TEXT PRIMARY KEY,
    revision TEXT NOT NULL,
    policy JSONB NOT NULL
);
CREATE TABLE IF NOT EXISTS linklake_certificate_states (
    route_id TEXT PRIMARY KEY,
    state JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS linklake_certificate_states_renewal
    ON linklake_certificate_states((state->>'status'),((state->>'next_renewal')::bigint));
CREATE TABLE IF NOT EXISTS linklake_certificate_materials (
    identifier TEXT PRIMARY KEY,
    route_id TEXT NOT NULL UNIQUE,
    generation TEXT NOT NULL,
    certificate_pem BYTEA NOT NULL CHECK(octet_length(certificate_pem) <= 2097152),
    encrypted_private_key BYTEA NOT NULL CHECK(octet_length(encrypted_private_key) <= 2097200),
    updated_unix_seconds BIGINT NOT NULL
);
CREATE TABLE IF NOT EXISTS linklake_acme_accounts (
    directory_url TEXT PRIMARY KEY,
    encrypted_credentials BYTEA NOT NULL CHECK(octet_length(encrypted_credentials) <= 2097200),
    updated_unix_seconds BIGINT NOT NULL
);
"#;

const MIGRATION_V11_NAME: &str = "shared_alerts_and_notification_outbox";
const MIGRATION_V11_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS linklake_alert_rules (
    id TEXT PRIMARY KEY,
    rule JSONB NOT NULL
);
CREATE TABLE IF NOT EXISTS linklake_alert_events (
    id BIGSERIAL PRIMARY KEY,
    rule_id TEXT NOT NULL,
    subject TEXT NOT NULL,
    active BOOLEAN NOT NULL,
    updated_unix_seconds BIGINT NOT NULL,
    event JSONB NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS linklake_alert_events_active_subject
    ON linklake_alert_events(rule_id,subject) WHERE active;
CREATE INDEX IF NOT EXISTS linklake_alert_events_updated
    ON linklake_alert_events(updated_unix_seconds DESC,id DESC);
CREATE TABLE IF NOT EXISTS linklake_alert_deliveries (
    id BIGSERIAL PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    event_id BIGINT NOT NULL,
    rule_name TEXT NOT NULL,
    subject TEXT NOT NULL,
    resolved BOOLEAN NOT NULL,
    channel TEXT NOT NULL CHECK(channel IN ('webhook','email')),
    payload JSONB NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('pending','delivering','delivered','dead_letter')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts >= 0),
    next_attempt_unix_seconds BIGINT NOT NULL,
    lease_expires_unix_seconds BIGINT,
    lease_token TEXT,
    last_error TEXT,
    created_unix_seconds BIGINT NOT NULL,
    updated_unix_seconds BIGINT NOT NULL,
    delivered_unix_seconds BIGINT,
    CHECK ((state='delivering' AND lease_token IS NOT NULL AND lease_expires_unix_seconds IS NOT NULL)
        OR (state<>'delivering' AND lease_token IS NULL AND lease_expires_unix_seconds IS NULL))
);
CREATE INDEX IF NOT EXISTS linklake_alert_deliveries_due
    ON linklake_alert_deliveries(state,next_attempt_unix_seconds,id);
CREATE INDEX IF NOT EXISTS linklake_alert_deliveries_updated
    ON linklake_alert_deliveries(updated_unix_seconds DESC,id DESC);
CREATE TABLE IF NOT EXISTS linklake_alert_delivery_counters (
    singleton_id INTEGER PRIMARY KEY CHECK(singleton_id=1),
    defaults_initialized BOOLEAN NOT NULL DEFAULT FALSE,
    delivered_total BIGINT NOT NULL DEFAULT 0,
    failed_attempts_total BIGINT NOT NULL DEFAULT 0,
    dead_letter_total BIGINT NOT NULL DEFAULT 0
);
INSERT INTO linklake_alert_delivery_counters(singleton_id) VALUES(1) ON CONFLICT DO NOTHING;
"#;

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

const MIGRATION_V4_NAME: &str = "remote_update_coordination";
const MIGRATION_V4_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS linklake_update_tasks (
    task_id TEXT PRIMARY KEY,
    target_client_id TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_fingerprint TEXT NOT NULL CHECK(length(request_fingerprint) = 64),
    state TEXT NOT NULL CHECK(state IN (
        'queued', 'claimed', 'running', 'cancel_requested',
        'succeeded', 'failed', 'cancelled'
    )),
    created_unix_seconds BIGINT NOT NULL CHECK(created_unix_seconds > 0),
    lease_deadline_unix_seconds BIGINT,
    lease_token_sha256 TEXT,
    snapshot_json TEXT NOT NULL,
    UNIQUE(requested_by, idempotency_key),
    CHECK(
        (lease_deadline_unix_seconds IS NULL AND lease_token_sha256 IS NULL)
        OR
        (lease_deadline_unix_seconds IS NOT NULL AND lease_deadline_unix_seconds > 0
         AND lease_token_sha256 IS NOT NULL AND length(lease_token_sha256) = 64)
    )
);
CREATE UNIQUE INDEX IF NOT EXISTS linklake_update_tasks_one_active_target
    ON linklake_update_tasks(target_client_id)
    WHERE state IN ('queued', 'claimed', 'running', 'cancel_requested');
CREATE INDEX IF NOT EXISTS linklake_update_tasks_target_created
    ON linklake_update_tasks(target_client_id, created_unix_seconds DESC);
CREATE INDEX IF NOT EXISTS linklake_update_tasks_claim_queue
    ON linklake_update_tasks(target_client_id, state, created_unix_seconds ASC);
CREATE INDEX IF NOT EXISTS linklake_update_tasks_active_lease
    ON linklake_update_tasks(lease_deadline_unix_seconds)
    WHERE state IN ('claimed', 'running', 'cancel_requested');

CREATE TABLE IF NOT EXISTS linklake_update_task_events (
    event_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES linklake_update_tasks(task_id) ON DELETE RESTRICT,
    sequence BIGINT NOT NULL CHECK(sequence > 0),
    kind TEXT NOT NULL,
    created_unix_seconds BIGINT NOT NULL CHECK(created_unix_seconds > 0),
    event_json TEXT NOT NULL,
    UNIQUE(task_id, sequence)
);
CREATE INDEX IF NOT EXISTS linklake_update_task_events_sequence
    ON linklake_update_task_events(task_id, sequence ASC);

CREATE OR REPLACE FUNCTION linklake_reject_update_task_event_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'linklake_update_task_events is append-only';
END;
$$;
DROP TRIGGER IF EXISTS linklake_update_task_events_no_mutation
    ON linklake_update_task_events;
CREATE TRIGGER linklake_update_task_events_no_mutation
BEFORE UPDATE OR DELETE ON linklake_update_task_events
FOR EACH ROW EXECUTE FUNCTION linklake_reject_update_task_event_mutation();
"#;

const MIGRATION_V5_NAME: &str = "remote_update_terminal_replay";
const MIGRATION_V5_SQL: &str = r#"
ALTER TABLE linklake_update_tasks
    ADD COLUMN terminal_worker_instance_id TEXT,
    ADD COLUMN terminal_lease_token_sha256 TEXT,
    ADD COLUMN terminal_report_sha256 TEXT;

ALTER TABLE linklake_update_tasks
    ADD CONSTRAINT linklake_update_tasks_terminal_replay_complete CHECK (
        (terminal_worker_instance_id IS NULL
         AND terminal_lease_token_sha256 IS NULL
         AND terminal_report_sha256 IS NULL)
        OR
        (state IN ('succeeded', 'failed', 'cancelled')
         AND terminal_worker_instance_id IS NOT NULL
         AND terminal_lease_token_sha256 IS NOT NULL
         AND length(terminal_lease_token_sha256) = 64
         AND terminal_report_sha256 IS NOT NULL
         AND length(terminal_report_sha256) = 64)
    );
"#;

// 认证、管理 API Token 与客户端身份的事实源。在 PostgreSQL 模式下这些表替代
// 同名 SQLite 表；密码和客户端令牌仍只保存 Argon2 摘要，会话与 API Token
// 只保存 SHA-256 摘要，明文永远不会进入数据库。
const MIGRATION_V6_NAME: &str = "application_identity_foundation";
const MIGRATION_V6_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS linklake_administrators (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    created_unix_seconds BIGINT NOT NULL,
    must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('administrator', 'operator', 'auditor')),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    last_login_unix_seconds BIGINT,
    totp_secret TEXT,
    totp_enabled BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS linklake_admin_sessions (
    session_id TEXT PRIMARY KEY,
    session_secret_hash TEXT NOT NULL,
    username TEXT NOT NULL REFERENCES linklake_administrators(username) ON DELETE CASCADE,
    created_unix_seconds BIGINT NOT NULL,
    expires_unix_seconds BIGINT NOT NULL,
    remote_addr TEXT,
    user_agent TEXT
);
CREATE INDEX IF NOT EXISTS linklake_admin_sessions_expiry
    ON linklake_admin_sessions(expires_unix_seconds);
CREATE INDEX IF NOT EXISTS linklake_admin_sessions_username
    ON linklake_admin_sessions(username, created_unix_seconds DESC);

CREATE TABLE IF NOT EXISTS linklake_management_api_tokens (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    scope TEXT NOT NULL CHECK (scope IN ('read', 'write', 'administrator')),
    token_hash BYTEA NOT NULL UNIQUE,
    created_unix_seconds BIGINT NOT NULL,
    expires_unix_seconds BIGINT,
    last_used_unix_seconds BIGINT,
    fleet_source_instance_id TEXT
);
CREATE INDEX IF NOT EXISTS linklake_management_api_tokens_expiry
    ON linklake_management_api_tokens(expires_unix_seconds);

CREATE TABLE IF NOT EXISTS linklake_clients (
    client_id TEXT PRIMARY KEY,
    agent_instance_id TEXT NOT NULL UNIQUE,
    agent_identity_public_key TEXT UNIQUE,
    name TEXT NOT NULL,
    platform TEXT NOT NULL,
    group_name TEXT,
    tags_json JSONB NOT NULL DEFAULT '[]'::jsonb,
    notes TEXT,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_unix_seconds BIGINT NOT NULL,
    token_rotated_unix_seconds BIGINT,
    access_token_hash TEXT NOT NULL,
    last_seen_unix_seconds BIGINT NOT NULL,
    config_mode TEXT NOT NULL DEFAULT 'local',
    config_sync_status TEXT NOT NULL DEFAULT 'unknown',
    applied_config_revision TEXT,
    config_sync_error TEXT,
    config_checked_unix_seconds BIGINT
);
CREATE UNIQUE INDEX IF NOT EXISTS linklake_clients_agent_identity_public_key
    ON linklake_clients(agent_identity_public_key)
    WHERE agent_identity_public_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS linklake_clients_last_seen
    ON linklake_clients(last_seen_unix_seconds DESC);
"#;

const MIGRATION_V7_NAME: &str = "shared_fleet_peer_catalog";
const MIGRATION_V7_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS linklake_fleet_peers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    url TEXT NOT NULL UNIQUE,
    region TEXT NOT NULL,
    weight INTEGER NOT NULL CHECK (weight BETWEEN 1 AND 10000),
    priority INTEGER NOT NULL CHECK (priority BETWEEN 0 AND 10000),
    token_env TEXT NOT NULL,
    enabled BOOLEAN NOT NULL,
    created_unix_seconds BIGINT NOT NULL CHECK (created_unix_seconds >= 0),
    updated_unix_seconds BIGINT NOT NULL CHECK (updated_unix_seconds >= 0)
);
"#;

const MIGRATION_V8_NAME: &str = "shared_fleet_health_dns";
const MIGRATION_V8_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS linklake_fleet_health (
    peer_id TEXT PRIMARY KEY REFERENCES linklake_fleet_peers(id) ON DELETE CASCADE,
    snapshot JSONB NOT NULL CHECK (jsonb_typeof(snapshot) = 'object')
);
CREATE TABLE IF NOT EXISTS linklake_fleet_probe_events (
    sequence BIGSERIAL NOT NULL,
    event_id TEXT PRIMARY KEY,
    peer_id TEXT NOT NULL REFERENCES linklake_fleet_peers(id) ON DELETE CASCADE,
    observed_unix_seconds BIGINT NOT NULL,
    success BOOLEAN NOT NULL,
    accepted BOOLEAN NOT NULL,
    transition_reason TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS linklake_fleet_probe_events_peer ON linklake_fleet_probe_events(peer_id, observed_unix_seconds DESC, sequence DESC);
CREATE TABLE IF NOT EXISTS linklake_fleet_health_counters (
    name TEXT PRIMARY KEY,
    value BIGINT NOT NULL CHECK (value >= 0)
);
CREATE TABLE IF NOT EXISTS linklake_fleet_dns_failovers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    zone_id TEXT NOT NULL,
    record_id TEXT NOT NULL,
    snapshot JSONB NOT NULL CHECK (jsonb_typeof(snapshot) = 'object'),
    UNIQUE(zone_id, record_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS linklake_fleet_dns_hostname ON linklake_fleet_dns_failovers ((snapshot->>'hostname'));
CREATE TABLE IF NOT EXISTS linklake_fleet_dns_events (
    operation_id TEXT PRIMARY KEY,
    failover_id TEXT NOT NULL REFERENCES linklake_fleet_dns_failovers(id) ON DELETE CASCADE,
    completed_unix_seconds BIGINT NOT NULL,
    snapshot JSONB NOT NULL CHECK (jsonb_typeof(snapshot) = 'object')
);
CREATE INDEX IF NOT EXISTS linklake_fleet_dns_events_failover ON linklake_fleet_dns_events(failover_id, completed_unix_seconds DESC, operation_id DESC);
"#;

const MIGRATION_V9_NAME: &str = "shared_audit_log";
const MIGRATION_V9_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS linklake_audit_events (
    id BIGSERIAL PRIMARY KEY,
    occurred_unix_seconds BIGINT NOT NULL,
    action TEXT NOT NULL,
    subject TEXT NOT NULL,
    detail TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS linklake_audit_events_occurred ON linklake_audit_events(occurred_unix_seconds DESC);
CREATE TABLE IF NOT EXISTS linklake_audit_retention (
    singleton_id INTEGER PRIMARY KEY CHECK(singleton_id=1),
    retained_events BIGINT NOT NULL CHECK(retained_events>=0)
);
INSERT INTO linklake_audit_retention(singleton_id,retained_events)
    SELECT 1,COUNT(*) FROM linklake_audit_events ON CONFLICT(singleton_id) DO NOTHING;
"#;

const MIGRATION_V10_NAME: &str = "shared_metrics_history";
const MIGRATION_V10_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS linklake_metrics_history_recent (
    timestamp_unix_seconds BIGINT PRIMARY KEY,
    sample JSONB NOT NULL CHECK(jsonb_typeof(sample)='object')
);
CREATE TABLE IF NOT EXISTS linklake_metrics_history_archive (
    minute_bucket BIGINT PRIMARY KEY,
    timestamp_unix_seconds BIGINT NOT NULL,
    sample JSONB NOT NULL CHECK(jsonb_typeof(sample)='object')
);
CREATE INDEX IF NOT EXISTS linklake_metrics_history_archive_timestamp ON linklake_metrics_history_archive(timestamp_unix_seconds);
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
    Migration {
        version: 4,
        name: MIGRATION_V4_NAME,
        sql: MIGRATION_V4_SQL,
    },
    Migration {
        version: 5,
        name: MIGRATION_V5_NAME,
        sql: MIGRATION_V5_SQL,
    },
    Migration {
        version: 6,
        name: MIGRATION_V6_NAME,
        sql: MIGRATION_V6_SQL,
    },
    Migration {
        version: 7,
        name: MIGRATION_V7_NAME,
        sql: MIGRATION_V7_SQL,
    },
    Migration {
        version: 8,
        name: MIGRATION_V8_NAME,
        sql: MIGRATION_V8_SQL,
    },
    Migration {
        version: 9,
        name: MIGRATION_V9_NAME,
        sql: MIGRATION_V9_SQL,
    },
    Migration {
        version: 10,
        name: MIGRATION_V10_NAME,
        sql: MIGRATION_V10_SQL,
    },
    Migration {
        version: 11,
        name: MIGRATION_V11_NAME,
        sql: MIGRATION_V11_SQL,
    },
    Migration {
        version: 12,
        name: MIGRATION_V12_NAME,
        sql: MIGRATION_V12_SQL,
    },
    Migration {
        version: 13,
        name: MIGRATION_V13_NAME,
        sql: MIGRATION_V13_SQL,
    },
    Migration {
        version: 14,
        name: MIGRATION_V14_NAME,
        sql: MIGRATION_V14_SQL,
    },
    Migration {
        version: 15,
        name: MIGRATION_V15_NAME,
        sql: MIGRATION_V15_SQL,
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
            name: "linklake_dns01_intents",
            primary_key: &["id"],
            columns: &[
                required("id", "text"),
                required("provider", "text"),
                required("next_cleanup", "int8"),
                required("state", "jsonb"),
            ],
        },
        TableExpectation {
            name: "linklake_http01_challenges",
            primary_key: &["hostname", "token"],
            columns: &[
                required("hostname", "text"),
                required("token", "text"),
                required("publication_id", "text"),
                required("job_key", "text"),
                required("lease_id", "text"),
                required("key_authorization", "text"),
                required("expires_at", "timestamptz"),
            ],
        },
        TableExpectation {
            name: "linklake_certificate_key_binding",
            primary_key: &["singleton_id"],
            columns: &[
                required("singleton_id", "int4"),
                required("fingerprint", "text"),
            ],
        },
        TableExpectation {
            name: "linklake_acme_config",
            primary_key: &["singleton_id"],
            columns: &[
                required("singleton_id", "int4"),
                required("config", "jsonb"),
            ],
        },
        TableExpectation {
            name: "linklake_route_tls",
            primary_key: &["route_id"],
            columns: &[
                required("route_id", "text"),
                required("revision", "text"),
                required("policy", "jsonb"),
            ],
        },
        TableExpectation {
            name: "linklake_certificate_states",
            primary_key: &["route_id"],
            columns: &[required("route_id", "text"), required("state", "jsonb")],
        },
        TableExpectation {
            name: "linklake_certificate_materials",
            primary_key: &["identifier"],
            columns: &[
                required("identifier", "text"),
                required("route_id", "text"),
                required("generation", "text"),
                required("certificate_pem", "bytea"),
                required("encrypted_private_key", "bytea"),
                required("updated_unix_seconds", "int8"),
            ],
        },
        TableExpectation {
            name: "linklake_acme_accounts",
            primary_key: &["directory_url"],
            columns: &[
                required("directory_url", "text"),
                required("encrypted_credentials", "bytea"),
                required("updated_unix_seconds", "int8"),
            ],
        },
        TableExpectation {
            name: "linklake_alert_rules",
            primary_key: &["id"],
            columns: &[required("id", "text"), required("rule", "jsonb")],
        },
        TableExpectation {
            name: "linklake_alert_events",
            primary_key: &["id"],
            columns: &[
                required("id", "int8"),
                required("rule_id", "text"),
                required("subject", "text"),
                required("active", "bool"),
                required("updated_unix_seconds", "int8"),
                required("event", "jsonb"),
            ],
        },
        TableExpectation {
            name: "linklake_alert_deliveries",
            primary_key: &["id"],
            columns: &[
                required("id", "int8"),
                required("idempotency_key", "text"),
                required("event_id", "int8"),
                required("rule_name", "text"),
                required("subject", "text"),
                required("resolved", "bool"),
                required("channel", "text"),
                required("payload", "jsonb"),
                required("state", "text"),
                required("attempts", "int4"),
                required("next_attempt_unix_seconds", "int8"),
                optional("lease_expires_unix_seconds", "int8"),
                optional("lease_token", "text"),
                optional("last_error", "text"),
                required("created_unix_seconds", "int8"),
                required("updated_unix_seconds", "int8"),
                optional("delivered_unix_seconds", "int8"),
            ],
        },
        TableExpectation {
            name: "linklake_alert_delivery_counters",
            primary_key: &["singleton_id"],
            columns: &[
                required("singleton_id", "int4"),
                required("defaults_initialized", "bool"),
                required("delivered_total", "int8"),
                required("failed_attempts_total", "int8"),
                required("dead_letter_total", "int8"),
            ],
        },
        TableExpectation {
            name: "linklake_metrics_history_recent",
            primary_key: &["timestamp_unix_seconds"],
            columns: &[
                required("timestamp_unix_seconds", "int8"),
                required("sample", "jsonb"),
            ],
        },
        TableExpectation {
            name: "linklake_metrics_history_archive",
            primary_key: &["minute_bucket"],
            columns: &[
                required("minute_bucket", "int8"),
                required("timestamp_unix_seconds", "int8"),
                required("sample", "jsonb"),
            ],
        },
        TableExpectation {
            name: "linklake_audit_events",
            primary_key: &["id"],
            columns: &[
                required("id", "int8"),
                required("occurred_unix_seconds", "int8"),
                required("action", "text"),
                required("subject", "text"),
                required("detail", "text"),
            ],
        },
        TableExpectation {
            name: "linklake_audit_retention",
            primary_key: &["singleton_id"],
            columns: &[
                required("singleton_id", "int4"),
                required("retained_events", "int8"),
            ],
        },
        TableExpectation {
            name: "linklake_fleet_health",
            primary_key: &["peer_id"],
            columns: &[required("peer_id", "text"), required("snapshot", "jsonb")],
        },
        TableExpectation {
            name: "linklake_fleet_probe_events",
            primary_key: &["event_id"],
            columns: &[
                required("sequence", "int8"),
                required("event_id", "text"),
                required("peer_id", "text"),
                required("observed_unix_seconds", "int8"),
                required("success", "bool"),
                required("accepted", "bool"),
                required("transition_reason", "text"),
            ],
        },
        TableExpectation {
            name: "linklake_fleet_health_counters",
            primary_key: &["name"],
            columns: &[required("name", "text"), required("value", "int8")],
        },
        TableExpectation {
            name: "linklake_fleet_dns_failovers",
            primary_key: &["id"],
            columns: &[
                required("id", "text"),
                required("name", "text"),
                required("zone_id", "text"),
                required("record_id", "text"),
                required("snapshot", "jsonb"),
            ],
        },
        TableExpectation {
            name: "linklake_fleet_dns_events",
            primary_key: &["operation_id"],
            columns: &[
                required("operation_id", "text"),
                required("failover_id", "text"),
                required("completed_unix_seconds", "int8"),
                required("snapshot", "jsonb"),
            ],
        },
        TableExpectation {
            name: "linklake_fleet_peers",
            primary_key: &["id"],
            columns: &[
                required("id", "text"),
                required("name", "text"),
                required("url", "text"),
                required("region", "text"),
                required("weight", "int4"),
                required("priority", "int4"),
                required("token_env", "text"),
                required("enabled", "bool"),
                required("created_unix_seconds", "int8"),
                required("updated_unix_seconds", "int8"),
            ],
        },
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
        TableExpectation {
            name: "linklake_update_tasks",
            primary_key: &["task_id"],
            columns: &[
                required("task_id", "text"),
                required("target_client_id", "text"),
                required("requested_by", "text"),
                required("idempotency_key", "text"),
                required("request_fingerprint", "text"),
                required("state", "text"),
                required("created_unix_seconds", "int8"),
                optional("lease_deadline_unix_seconds", "int8"),
                optional("lease_token_sha256", "text"),
                optional("terminal_worker_instance_id", "text"),
                optional("terminal_lease_token_sha256", "text"),
                optional("terminal_report_sha256", "text"),
                required("snapshot_json", "text"),
            ],
        },
        TableExpectation {
            name: "linklake_update_task_events",
            primary_key: &["event_id"],
            columns: &[
                required("event_id", "text"),
                required("task_id", "text"),
                required("sequence", "int8"),
                required("kind", "text"),
                required("created_unix_seconds", "int8"),
                required("event_json", "text"),
            ],
        },
        TableExpectation {
            name: "linklake_administrators",
            primary_key: &["username"],
            columns: &[
                required("username", "text"),
                required("password_hash", "text"),
                required("created_unix_seconds", "int8"),
                required("must_change_password", "bool"),
                required("display_name", "text"),
                required("role", "text"),
                required("enabled", "bool"),
                optional("last_login_unix_seconds", "int8"),
                optional("totp_secret", "text"),
                required("totp_enabled", "bool"),
            ],
        },
        TableExpectation {
            name: "linklake_admin_sessions",
            primary_key: &["session_id"],
            columns: &[
                required("session_id", "text"),
                required("session_secret_hash", "text"),
                required("username", "text"),
                required("created_unix_seconds", "int8"),
                required("expires_unix_seconds", "int8"),
                optional("remote_addr", "text"),
                optional("user_agent", "text"),
            ],
        },
        TableExpectation {
            name: "linklake_management_api_tokens",
            primary_key: &["id"],
            columns: &[
                required("id", "text"),
                required("name", "text"),
                required("scope", "text"),
                required("token_hash", "bytea"),
                required("created_unix_seconds", "int8"),
                optional("expires_unix_seconds", "int8"),
                optional("last_used_unix_seconds", "int8"),
                optional("fleet_source_instance_id", "text"),
            ],
        },
        TableExpectation {
            name: "linklake_clients",
            primary_key: &["client_id"],
            columns: &[
                required("client_id", "text"),
                required("agent_instance_id", "text"),
                optional("agent_identity_public_key", "text"),
                required("name", "text"),
                required("platform", "text"),
                optional("group_name", "text"),
                required("tags_json", "jsonb"),
                optional("notes", "text"),
                required("enabled", "bool"),
                required("created_unix_seconds", "int8"),
                optional("token_rotated_unix_seconds", "int8"),
                required("access_token_hash", "text"),
                required("last_seen_unix_seconds", "int8"),
                required("config_mode", "text"),
                required("config_sync_status", "text"),
                optional("applied_config_revision", "text"),
                optional("config_sync_error", "text"),
                optional("config_checked_unix_seconds", "int8"),
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
