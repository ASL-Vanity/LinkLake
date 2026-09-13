//! 显式、停机的 SQLite -> PostgreSQL 导入；不是运行时同步或每副本初始化。
//! 源快照适配器必须完整分类非空表，遗漏业务表时拒绝生成可提交计划。

use std::{collections::BTreeMap, fmt};

use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio_postgres::Transaction;

use crate::{certificate_catalog::postgres::CERTIFICATE_STATE_LOCK, storage::CoordinationStorage};

#[path = "storage_migration_source.rs"]
pub(crate) mod source;

const RECEIPTS: &str = "linklake_storage_migration_receipts";

/// 不提供 Debug：计划包含身份凭据摘要、TOTP 和加密材料，不能通过日志输出。
pub(crate) struct MigrationRow {
    table: String,
    values: Value,
}

pub(crate) struct MigrationPlan {
    source_fingerprint: String,
    key_fingerprint: String,
    rows: Vec<MigrationRow>,
    // 持有源进程锁和 SQLite 快照，直到调用方完成提交或放弃计划。
    _source: source::SourceGuard,
}

impl MigrationPlan {
    /// 预览不包含源行正文，可在 CLI 显示；持有计划期间源进程锁仍有效。
    pub(crate) fn preview(&self) -> MigrationSummary {
        summary(self, false)
    }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct MigrationSummary {
    pub(crate) source_fingerprint: String,
    pub(crate) key_fingerprint: String,
    pub(crate) already_imported: bool,
    pub(crate) imported_rows: BTreeMap<String, u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MigrationError {
    InvalidSource,
    SourceInUse,
    UnsupportedSourceData,
    PendingExternalOperations,
    InvalidKey,
    SnapshotTooLarge,
    DatabaseUnavailable,
    TargetInUse,
    TargetNotEmpty,
    TargetChanged,
    TransactionFailed,
}

impl MigrationError {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::InvalidSource => "storage_migration_invalid_source",
            Self::SourceInUse => "storage_migration_source_in_use",
            Self::UnsupportedSourceData => "storage_migration_unsupported_source_data",
            Self::PendingExternalOperations => "storage_migration_pending_external_operations",
            Self::InvalidKey => "storage_migration_invalid_key",
            Self::SnapshotTooLarge => "storage_migration_snapshot_too_large",
            Self::DatabaseUnavailable => "storage_migration_database_unavailable",
            Self::TargetInUse => "storage_migration_target_in_use",
            Self::TargetNotEmpty => "storage_migration_target_not_empty",
            Self::TargetChanged => "storage_migration_target_changed",
            Self::TransactionFailed => "storage_migration_transaction_failed",
        }
    }
}
impl fmt::Display for MigrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for MigrationError {}
type Result<T> = std::result::Result<T, MigrationError>;
fn database<T>(result: std::result::Result<T, tokio_postgres::Error>) -> Result<T> {
    // 不保留可能包含凭据/材料的 SQL 错误 detail。
    result.map_err(|_| MigrationError::TransactionFailed)
}

fn identifier(value: &str) -> Result<String> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
    {
        return Err(MigrationError::UnsupportedSourceData);
    }
    Ok(format!("\"{value}\""))
}

/// 仅导入到已经完成 schema migration、尚未运行服务的新 PostgreSQL 数据库。
/// 同源重复调用必须同时匹配回执和实时表摘要；禁止合并或覆盖业务变更。
pub(crate) async fn import_sqlite_plan(
    storage: &CoordinationStorage,
    plan: &MigrationPlan,
) -> Result<MigrationSummary> {
    let mut client = storage
        .postgres_client()
        .await
        .map_err(|_| MigrationError::DatabaseUnavailable)?;
    let transaction = database(client.transaction().await)?;
    database(
        transaction
            .batch_execute("SET LOCAL lock_timeout = '10s'")
            .await,
    )?;
    // 与 schema migration 同锁，锁顺序是 schema -> 业务目录 -> 应用表。
    database(
        transaction
            .query_one(
                "SELECT pg_advisory_xact_lock($1)",
                &[&0x4c4c_4841_4d49_4752i64],
            )
            .await,
    )?;
    database(
        transaction
            .query_one(
                "SELECT pg_advisory_xact_lock($1)",
                &[&CERTIFICATE_STATE_LOCK],
            )
            .await,
    )?;
    let tables = database(transaction.query(
        "SELECT tablename FROM pg_tables WHERE schemaname=current_schema() AND tablename LIKE 'linklake\\_%' ESCAPE '\\' ORDER BY tablename",
        &[],
    ).await)?.into_iter().map(|row| row.get::<_, String>(0))
        .filter(|name| name != "linklake_postgres_schema_migrations").collect::<Vec<_>>();
    if !tables.iter().any(|name| name == RECEIPTS) {
        return Err(MigrationError::DatabaseUnavailable);
    }
    // 表名仅来自已验证标识符；不接受用户提供 SQL。全部应用表同时锁定，避免空表检查竞争。
    let quoted = tables
        .iter()
        .map(|name| identifier(name))
        .collect::<Result<Vec<_>>>()?
        .join(",");
    database(
        transaction
            .batch_execute(&format!("LOCK TABLE {quoted} IN SHARE ROW EXCLUSIVE MODE"))
            .await,
    )?;
    let active: bool = database(transaction.query_one(
        "SELECT EXISTS(SELECT 1 FROM linklake_ha_members WHERE lease_until>clock_timestamp()) OR EXISTS(SELECT 1 FROM linklake_ha_leader WHERE lease_until>clock_timestamp())",
        &[],
    ).await)?.get(0);
    if active {
        return Err(MigrationError::TargetInUse);
    }

    if let Some(receipt) = database(transaction.query_opt(
        "SELECT source_fingerprint,key_fingerprint,manifest FROM linklake_storage_migration_receipts WHERE singleton_id=1",
        &[],
    ).await)? {
        let source: String = receipt.get(0);
        let key: String = receipt.get(1);
        let manifest: Value = receipt.get(2);
        if source != plan.source_fingerprint || key != plan.key_fingerprint {
            return Err(MigrationError::TargetNotEmpty);
        }
        if target_manifest(&transaction, &tables).await? != manifest { return Err(MigrationError::TargetChanged); }
        database(transaction.commit().await)?;
        return Ok(summary(plan, true));
    }

    validate_pristine_target(&transaction, &tables).await?;
    // 只替换已核对的 schema 初始种子；所有业务表已证明为空。
    database(
        transaction
            .batch_execute("DELETE FROM linklake_acme_config; DELETE FROM linklake_audit_retention; DELETE FROM linklake_alert_delivery_counters")
            .await,
    )?;
    for row in &plan.rows {
        if !tables.contains(&row.table) {
            return Err(MigrationError::DatabaseUnavailable);
        }
        let object = row
            .values
            .as_object()
            .ok_or(MigrationError::InvalidSource)?;
        let columns = object
            .keys()
            .map(|name| identifier(name))
            .collect::<Result<Vec<_>>>()?;
        if columns.is_empty() {
            return Err(MigrationError::InvalidSource);
        }
        let table = identifier(&row.table)?;
        let names = columns.join(",");
        let sql = format!("INSERT INTO {table} ({names}) SELECT {names} FROM jsonb_populate_record(NULL::{table},$1)");
        database(transaction.execute(&sql, &[&row.values]).await)?;
    }
    // BIGSERIAL 源 ID 原样导入；ALTER SEQUENCE RESTART 随事务回滚，避免 setval 独立提交。
    restart_sequences(&transaction, &tables).await?;
    let manifest = target_manifest(&transaction, &tables).await?;
    database(transaction.execute(
        "INSERT INTO linklake_storage_migration_receipts(singleton_id,source_fingerprint,key_fingerprint,manifest,committed_unix_seconds)
         VALUES(1,$1,$2,$3,EXTRACT(EPOCH FROM clock_timestamp())::bigint)",
        &[&plan.source_fingerprint,&plan.key_fingerprint,&manifest],
    ).await)?;
    database(transaction.commit().await)?;
    Ok(summary(plan, false))
}

fn summary(plan: &MigrationPlan, already_imported: bool) -> MigrationSummary {
    let mut imported_rows = BTreeMap::new();
    for row in &plan.rows {
        *imported_rows.entry(row.table.clone()).or_insert(0) += 1;
    }
    MigrationSummary {
        source_fingerprint: plan.source_fingerprint.clone(),
        key_fingerprint: plan.key_fingerprint.clone(),
        already_imported,
        imported_rows,
    }
}

/// 验证能否切回保留的原 SQLite：仅当原源快照和目标全部数据都未变化。
/// 不删除目标、不修改源、不改部署配置；调用方在确认成功后完成部署后端切换。
pub(crate) async fn verify_sqlite_rollback(
    storage: &CoordinationStorage,
    plan: &MigrationPlan,
) -> Result<MigrationSummary> {
    let mut client = storage
        .postgres_client()
        .await
        .map_err(|_| MigrationError::DatabaseUnavailable)?;
    let transaction = database(client.transaction().await)?;
    database(
        transaction
            .batch_execute("SET LOCAL lock_timeout='10s'")
            .await,
    )?;
    database(
        transaction
            .query_one(
                "SELECT pg_advisory_xact_lock($1)",
                &[&0x4c4c_4841_4d49_4752i64],
            )
            .await,
    )?;
    database(
        transaction
            .query_one(
                "SELECT pg_advisory_xact_lock($1)",
                &[&CERTIFICATE_STATE_LOCK],
            )
            .await,
    )?;
    let tables=database(transaction.query("SELECT tablename FROM pg_tables WHERE schemaname=current_schema() AND tablename LIKE 'linklake\\_%' ESCAPE '\\' ORDER BY tablename",&[]).await)?
        .into_iter().map(|row|row.get::<_,String>(0)).filter(|name|name!="linklake_postgres_schema_migrations").collect::<Vec<_>>();
    if !tables.iter().any(|name| name == RECEIPTS) {
        return Err(MigrationError::DatabaseUnavailable);
    }
    let quoted = tables
        .iter()
        .map(|name| identifier(name))
        .collect::<Result<Vec<_>>>()?
        .join(",");
    database(
        transaction
            .batch_execute(&format!("LOCK TABLE {quoted} IN SHARE MODE"))
            .await,
    )?;
    let active:bool=database(transaction.query_one("SELECT EXISTS(SELECT 1 FROM linklake_ha_members WHERE lease_until>clock_timestamp()) OR EXISTS(SELECT 1 FROM linklake_ha_leader WHERE lease_until>clock_timestamp())",&[]).await)?.get(0);
    if active {
        return Err(MigrationError::TargetInUse);
    }
    let receipt=database(transaction.query_opt("SELECT source_fingerprint,key_fingerprint,manifest FROM linklake_storage_migration_receipts WHERE singleton_id=1",&[]).await)?.ok_or(MigrationError::TargetChanged)?;
    let fingerprint: String = receipt.get(0);
    let key: String = receipt.get(1);
    let manifest: Value = receipt.get(2);
    if fingerprint != plan.source_fingerprint
        || key != plan.key_fingerprint
        || target_manifest(&transaction, &tables).await? != manifest
    {
        return Err(MigrationError::TargetChanged);
    }
    database(transaction.commit().await)?;
    Ok(summary(plan, true))
}

async fn validate_pristine_target(transaction: &Transaction<'_>, tables: &[String]) -> Result<()> {
    for name in tables {
        let quoted = identifier(name)?;
        let count: i64 = database(
            transaction
                .query_one(&format!("SELECT COUNT(*) FROM {quoted}"), &[])
                .await,
        )?
        .get(0);
        if count == 0 {
            continue;
        }
        let valid = match name.as_str() {
            "linklake_ha_fencing_sequence" => database(transaction.query_one("SELECT COUNT(*)=1 AND bool_and(singleton_id=1 AND next_token=1) FROM linklake_ha_fencing_sequence", &[]).await)?.get(0),
            "linklake_audit_retention" => database(transaction.query_one("SELECT COUNT(*)=1 AND bool_and(singleton_id=1 AND retained_events=0) FROM linklake_audit_retention", &[]).await)?.get(0),
            "linklake_alert_delivery_counters" => database(transaction.query_one("SELECT COUNT(*)=1 AND bool_and(singleton_id=1 AND NOT defaults_initialized AND delivered_total=0 AND failed_attempts_total=0 AND dead_letter_total=0) FROM linklake_alert_delivery_counters", &[]).await)?.get(0),
            "linklake_acme_config" => database(transaction.query_one(
                "SELECT COUNT(*)=1 AND bool_and(singleton_id=1 AND config = '{\"enabled\":false,\"environment\":\"production\",\"directory_url\":\"https://acme-v02.api.letsencrypt.org/directory\",\"contact_email\":\"\",\"terms_accepted\":false,\"challenge_type\":\"http-01\",\"renew_before_days\":30,\"updated_at\":0}'::jsonb) FROM linklake_acme_config", &[],
            ).await)?.get(0),
            _ => false,
        };
        if !valid {
            return Err(MigrationError::TargetNotEmpty);
        }
    }
    Ok(())
}

async fn target_manifest(transaction: &Transaction<'_>, tables: &[String]) -> Result<Value> {
    let mut result = serde_json::Map::new();
    for table in tables.iter().filter(|name| name.as_str() != RECEIPTS) {
        let quoted = identifier(table)?;
        let mut digest = Sha256::new();
        let mut count = 0u64;
        // 服务端只排序一次，游标分批读取，避免每批重新扫描大规模审计/材料表。
        database(transaction.batch_execute(&format!("DECLARE linklake_migration_manifest NO SCROLL CURSOR FOR SELECT to_jsonb(t)::text FROM {quoted} t ORDER BY to_jsonb(t)::text COLLATE \"C\"")).await)?;
        loop {
            let rows = database(
                transaction
                    .query("FETCH FORWARD 8 FROM linklake_migration_manifest", &[])
                    .await,
            )?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                let value: String = row.get(0);
                digest.update((value.len() as u64).to_be_bytes());
                digest.update(value.as_bytes());
                count += 1;
            }
        }
        database(
            transaction
                .batch_execute("CLOSE linklake_migration_manifest")
                .await,
        )?;
        result.insert(
            table.clone(),
            json!({"rows":count,"sha256":format!("{:x}",digest.finalize())}),
        );
    }
    Ok(Value::Object(result))
}

async fn restart_sequences(transaction: &Transaction<'_>, tables: &[String]) -> Result<()> {
    for table in tables {
        let columns = database(transaction.query(
            "SELECT column_name FROM information_schema.columns WHERE table_schema=current_schema() AND table_name=$1 AND column_default LIKE 'nextval(%'",
            &[table],
        ).await)?;
        for row in columns {
            let column: String = row.get(0);
            let sequence: Option<String> = database(
                transaction
                    .query_one("SELECT pg_get_serial_sequence($1,$2)", &[table, &column])
                    .await,
            )?
            .get(0);
            let Some(sequence) = sequence else {
                return Err(MigrationError::TransactionFailed);
            };
            let sequence = sequence
                .split('.')
                .map(identifier)
                .collect::<Result<Vec<_>>>()?
                .join(".");
            let maximum: Option<i64> = database(
                transaction
                    .query_one(
                        &format!(
                            "SELECT MAX({}) FROM {}",
                            identifier(&column)?,
                            identifier(table)?
                        ),
                        &[],
                    )
                    .await,
            )?
            .get(0);
            let next = maximum
                .unwrap_or(0)
                .checked_add(1)
                .ok_or(MigrationError::InvalidSource)?;
            database(
                transaction
                    .batch_execute(&format!("ALTER SEQUENCE {sequence} RESTART WITH {next}"))
                    .await,
            )?;
        }
    }
    Ok(())
}
