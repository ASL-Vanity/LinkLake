//! PostgreSQL 历史指标；由采样任务的 Leader 写入，任一实例从共享时间序列读取。

use crate::{
    ha_runtime::HaRuntime, storage::CoordinationStorage, MetricsHistory, MetricsHistorySample,
    METRICS_HISTORY_ARCHIVE_CAPACITY, METRICS_HISTORY_ARCHIVE_SAMPLE_INTERVAL_SECONDS,
    METRICS_HISTORY_CAPACITY, METRICS_HISTORY_RECENT_RETENTION_SECONDS,
    METRICS_HISTORY_RETENTION_SECONDS,
};
use std::sync::Arc;

pub(crate) struct PostgresMetricsHistory {
    pub(crate) storage: CoordinationStorage,
    pub(crate) runtime: Arc<HaRuntime>,
}

impl PostgresMetricsHistory {
    pub(crate) async fn load(&self) -> anyhow::Result<MetricsHistory> {
        self.load_range(METRICS_HISTORY_RETENTION_SECONDS, None)
            .await
    }

    pub(crate) async fn load_range(
        &self,
        range_seconds: u64,
        policy_key: Option<&str>,
    ) -> anyhow::Result<MetricsHistory> {
        let mut client = self.storage.postgres_client().await?;
        let transaction = client
            .build_transaction()
            .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
            .read_only(true)
            .start()
            .await?;
        let mut history =
            MetricsHistory::new(METRICS_HISTORY_CAPACITY, METRICS_HISTORY_ARCHIVE_CAPACITY);
        let now: i64 = transaction
            .query_one(
                "SELECT FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::bigint",
                &[],
            )
            .await?
            .get(0);
        for (table, retention, capacity, samples) in [
            (
                "linklake_metrics_history_recent",
                METRICS_HISTORY_RECENT_RETENTION_SECONDS,
                history.capacity,
                &mut history.samples,
            ),
            (
                "linklake_metrics_history_archive",
                METRICS_HISTORY_RETENTION_SECONDS,
                history.archive_capacity,
                &mut history.archive_samples,
            ),
        ] {
            if table == "linklake_metrics_history_archive"
                && range_seconds <= METRICS_HISTORY_RECENT_RETENTION_SECONDS
            {
                continue;
            }
            let cutoff = now.saturating_sub(
                range_seconds
                    .min(retention)
                    .saturating_add(METRICS_HISTORY_ARCHIVE_SAMPLE_INTERVAL_SECONDS)
                    as i64,
            );
            // 总览不搬运所有策略历史；单策略页面只提取请求的那条序列。
            let rows = transaction.query(&format!(
                "SELECT ((sample - 'policies') || jsonb_build_object('policies', CASE WHEN $3::text IS NOT NULL AND (sample->'policies') ? $3 THEN jsonb_build_object($3, sample->'policies'->$3) ELSE '{{}}'::jsonb END))::text FROM (SELECT timestamp_unix_seconds,sample FROM {table} WHERE timestamp_unix_seconds >= $1 ORDER BY timestamp_unix_seconds DESC LIMIT $2) retained ORDER BY timestamp_unix_seconds"
            ), &[&cutoff, &(capacity as i64), &policy_key]).await?;
            for row in rows {
                samples.push_back(serde_json::from_str(row.get(0))?);
            }
        }
        transaction.commit().await?;
        Ok(history)
    }

    pub(crate) async fn record(
        &self,
        mut sample: MetricsHistorySample,
    ) -> anyhow::Result<MetricsHistorySample> {
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        transaction
            .query_one("SELECT pg_advisory_xact_lock($1)", &[&0x4c4c_4d48_4953_i64])
            .await?;
        let token = self.runtime.fencing_token()?;
        self.runtime
            .coordinator()
            .assert_postgres_transaction_fence(&transaction, token)
            .await?;
        // 共享序列以数据库时钟为准，避免不同实例的本地时钟偏差覆盖新样本。
        let now: i64 = transaction
            .query_one(
                "SELECT FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::bigint",
                &[],
            )
            .await?
            .get(0);
        sample.timestamp_unix_seconds = u64::try_from(now)?;
        let previous: Option<i64> = transaction
            .query_one(
                "SELECT MAX(timestamp_unix_seconds) FROM linklake_metrics_history_recent",
                &[],
            )
            .await?
            .get(0);
        if previous.is_some_and(|previous| previous > now) {
            transaction.batch_execute("DELETE FROM linklake_metrics_history_recent; DELETE FROM linklake_metrics_history_archive;").await?;
        }
        let json = serde_json::to_string(&sample)?;
        transaction.execute("INSERT INTO linklake_metrics_history_recent(timestamp_unix_seconds,sample) VALUES($1,$2::text::jsonb) ON CONFLICT(timestamp_unix_seconds) DO UPDATE SET sample=excluded.sample", &[&now,&json]).await?;
        let bucket = now / METRICS_HISTORY_ARCHIVE_SAMPLE_INTERVAL_SECONDS as i64;
        transaction.execute("INSERT INTO linklake_metrics_history_archive(minute_bucket,timestamp_unix_seconds,sample) VALUES($1,$2,$3::text::jsonb) ON CONFLICT(minute_bucket) DO UPDATE SET timestamp_unix_seconds=excluded.timestamp_unix_seconds,sample=excluded.sample", &[&bucket,&now,&json]).await?;
        for (table, retention) in [
            (
                "linklake_metrics_history_recent",
                METRICS_HISTORY_RECENT_RETENTION_SECONDS,
            ),
            (
                "linklake_metrics_history_archive",
                METRICS_HISTORY_RETENTION_SECONDS,
            ),
        ] {
            transaction
                .execute(
                    &format!("DELETE FROM {table} WHERE timestamp_unix_seconds < $1"),
                    &[&now.saturating_sub(retention as i64)],
                )
                .await?;
        }
        transaction.commit().await?;
        Ok(sample)
    }
}
