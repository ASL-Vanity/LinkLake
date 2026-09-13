//! 显式忽略的真实PostgreSQL回归；必须由隔离容器harness启动，不会默认连接用户数据库。

use crate::{
    database::Database,
    ha_runtime::{HaRuntime, HaRuntimeConfig},
    policy_service::postgres::FleetPolicyTransaction,
    storage::{CoordinationStorage, StorageConfig},
    traffic_control::{
        postgres::{self, PostgresTrafficControlCatalog},
        usage_meter::TrafficUsageMeter,
        usage_spool::TrafficUsageSpool,
        TrafficDecision, TrafficPolicyKind, TrafficUsageEvent, UpsertTrafficControl,
    },
    traffic_control_store::TrafficControlStore,
};
use std::{env, path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    sync::{watch, Barrier},
    task::JoinSet,
    time::timeout,
};
use uuid::Uuid;

struct Cluster {
    storage_a: CoordinationStorage,
    storage_b: CoordinationStorage,
    runtime_a: Arc<HaRuntime>,
    runtime_b: Arc<HaRuntime>,
}

impl Cluster {
    async fn open() -> anyhow::Result<Self> {
        anyhow::ensure!(
            env::var("LINKLAKE_PG_TEST_ALLOW_DISPOSABLE").as_deref() == Ok("1"),
            "Use tests/postgres-ha-traffic.ps1 -RunVerification with its disposable database"
        );
        let url = env::var("LINKLAKE_POSTGRES_URL")?;
        let parsed: tokio_postgres::Config = url.parse()?;
        anyhow::ensure!(
            parsed
                .get_dbname()
                .is_some_and(|name| name.starts_with("linklake_ha_test_")),
            "PG regression requires a disposable test database name"
        );
        anyhow::ensure!(
            !parsed.get_hosts().is_empty()
                && parsed.get_hosts().iter().all(|host| match host {
                    tokio_postgres::config::Host::Tcp(name) =>
                        name == "127.0.0.1" || name == "localhost" || name == "::1",
                    #[cfg(unix)]
                    tokio_postgres::config::Host::Unix(_) => false,
                }),
            "PG regression is restricted to loopback PostgreSQL"
        );
        anyhow::ensure!(
            env::var_os("LINKLAKE_HA_INSTANCE_ID").is_none(),
            "Harness must clear instance override so replicas are distinct"
        );
        let config = StorageConfig::from_environment()?;
        CoordinationStorage::initialize_empty_postgres(&config).await?;
        let local = Database::memory()?;
        let storage_a = CoordinationStorage::open(&config, &local).await?;
        let storage_b = CoordinationStorage::open(&config, &local).await?;
        let runtime_a = Arc::new(HaRuntime::open(
            storage_a.clone(),
            HaRuntimeConfig::from_environment("traffic-test-a")?,
        )?);
        let runtime_b = Arc::new(HaRuntime::open(
            storage_b.clone(),
            HaRuntimeConfig::from_environment("traffic-test-b")?,
        )?);
        runtime_a.bootstrap().await?;
        runtime_b.bootstrap().await?;
        anyhow::ensure!(
            runtime_a.is_leader() && !runtime_b.is_leader(),
            "Expected one real leader and one follower"
        );
        // 独立pool、独立PG后端连接；不能以同一连接上的串行模拟替代并发验证。
        let a = storage_a.postgres_client().await?;
        let b = storage_b.postgres_client().await?;
        let a_pid: i32 = a.query_one("SELECT pg_backend_pid()", &[]).await?.get(0);
        let b_pid: i32 = b.query_one("SELECT pg_backend_pid()", &[]).await?.get(0);
        anyhow::ensure!(
            a_pid != b_pid,
            "Two replicas must use different PostgreSQL sessions"
        );
        drop((a, b));
        Ok(Self {
            storage_a,
            storage_b,
            runtime_a,
            runtime_b,
        })
    }

    fn a(&self) -> Arc<PostgresTrafficControlCatalog> {
        Arc::new(PostgresTrafficControlCatalog {
            storage: self.storage_a.clone(),
            runtime: self.runtime_a.clone(),
        })
    }
    fn b(&self) -> Arc<PostgresTrafficControlCatalog> {
        Arc::new(PostgresTrafficControlCatalog {
            storage: self.storage_b.clone(),
            runtime: self.runtime_b.clone(),
        })
    }
    async fn renew(&self) -> anyhow::Result<()> {
        self.runtime_a.refresh().await?;
        self.runtime_b.refresh().await?;
        Ok(())
    }
}

fn settings(rate: Option<u32>, quota: Option<u64>) -> UpsertTrafficControl {
    UpsertTrafficControl {
        allowed_cidrs: vec!["10.0.0.0/8".into()],
        denied_cidrs: vec!["10.1.0.0/16".into()],
        max_connections_per_minute: rate,
        daily_quota_bytes: quota,
        active_weekdays_utc: vec![],
        start_minute_utc: None,
        end_minute_utc: None,
        enabled: true,
    }
}

fn event(id: Uuid, bytes: u64) -> TrafficUsageEvent {
    TrafficUsageEvent {
        event_id: Uuid::new_v4(),
        kind: TrafficPolicyKind::Http,
        policy_id: id,
        bytes,
    }
}

async fn stored_usage(storage: &CoordinationStorage, id: Uuid) -> anyhow::Result<u64> {
    let value: String = storage.postgres_client().await?.query_one(
        "SELECT COALESCE(SUM(bytes),0)::text FROM linklake_traffic_daily_usage WHERE kind='http' AND policy_id=$1", &[&id.to_string()],
    ).await?.get(0);
    Ok(value.parse()?)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "Requires isolated real PostgreSQL; use tests/postgres-ha-traffic.ps1 -RunVerification"]
async fn real_postgres_traffic_cluster_contract() -> anyhow::Result<()> {
    let cluster = Cluster::open().await?;
    let a = cluster.a();
    let b = cluster.b();
    let kind = TrafficPolicyKind::Http;
    let source = "10.2.3.4".parse()?;
    let id = Uuid::new_v4();
    a.upsert(kind, id, settings(Some(12), Some(1_000_000)))
        .await?;
    assert_eq!(
        b.get(kind, id)
            .await?
            .unwrap()
            .settings
            .max_connections_per_minute,
        Some(12)
    );
    assert!(
        b.authorize(kind, id, source).await.is_err(),
        "Follower cannot start public traffic"
    );

    // 真实48个并发任务与多个数据库连接争抢同一12连接窗口。
    let barrier = Arc::new(Barrier::new(49));
    let mut tasks = JoinSet::new();
    for index in 0..48 {
        let catalog = if index % 2 == 0 {
            a.clone()
        } else {
            Arc::new(PostgresTrafficControlCatalog {
                storage: cluster.storage_b.clone(),
                runtime: cluster.runtime_a.clone(),
            })
        };
        let barrier = barrier.clone();
        tasks.spawn(async move {
            barrier.wait().await;
            catalog.authorize(kind, id, source).await
        });
    }
    barrier.wait().await;
    let mut allowed = 0;
    let mut limited = 0;
    while let Some(result) = tasks.join_next().await {
        match result?? {
            TrafficDecision::Allowed => allowed += 1,
            TrafficDecision::RateLimited => limited += 1,
            other => panic!("unexpected admission {other:?}"),
        }
    }
    assert_eq!(
        (allowed, limited),
        (12, 36),
        "Shared window must not admit limit per process/connection"
    );
    let reserved: i64 = cluster.storage_a.postgres_client().await?.query_one("SELECT SUM(connections)::bigint FROM linklake_traffic_connection_windows WHERE kind='http' AND policy_id=$1", &[&id.to_string()]).await?.get(0);
    assert_eq!(reserved, 12);

    // 日期/时钟由PG提供：构造过期窗口旁证，生产authorize执行真正删除/预留。
    {
        let mut client = cluster.storage_a.postgres_client().await?;
        let tx = client.transaction().await?;
        tx.execute(
            "DELETE FROM linklake_traffic_connection_windows WHERE kind='http' AND policy_id=$1",
            &[&id.to_string()],
        )
        .await?;
        tx.execute("INSERT INTO linklake_traffic_connection_windows VALUES('http',$1,floor(extract(epoch FROM clock_timestamp()))::bigint+600,12)", &[&id.to_string()]).await?;
        tx.commit().await?;
    }
    assert_eq!(
        a.authorize(kind, id, source).await?,
        TrafficDecision::RateLimited,
        "Clock rollback must not discard future buckets"
    );
    cluster.storage_a.postgres_client().await?.execute("UPDATE linklake_traffic_connection_windows SET unix_second=floor(extract(epoch FROM clock_timestamp()))::bigint-60 WHERE kind='http' AND policy_id=$1", &[&id.to_string()]).await?;
    assert_eq!(
        a.authorize(kind, id, source).await?,
        TrafficDecision::Allowed,
        "60-second expired bucket must be pruned"
    );
    cluster.renew().await?;

    // 规则变更与窗口清理在同一事务；rollback之后目录/限速都应保持旧值。
    let before = a.get(kind, id).await?.unwrap().settings;
    {
        let mut client = cluster.storage_a.postgres_client().await?;
        let tx = client.transaction().await?;
        let guard = FleetPolicyTransaction::lock(&tx, &cluster.runtime_a).await?;
        postgres::transaction_put(&guard, kind, id, settings(Some(1), Some(2048))).await?;
        tx.rollback().await?;
    }
    assert_eq!(a.get(kind, id).await?.unwrap().settings, before);
    let remaining: i64 = cluster.storage_a.postgres_client().await?.query_one("SELECT SUM(connections)::bigint FROM linklake_traffic_connection_windows WHERE kind='http' AND policy_id=$1", &[&id.to_string()]).await?.get(0);
    assert_eq!(
        remaining, 1,
        "Rolled-back put must not clear committed rate reservations"
    );

    // 共享pending先进入配额，drain后不增加第二遍；48次并发同UUID只计一次。
    a.upsert(kind, id, settings(None, Some(1024))).await?;
    let first = event(id, 1024);
    let mut duplicate_tasks = JoinSet::new();
    for _ in 0..48 {
        let a = a.clone();
        let value = first.clone();
        duplicate_tasks.spawn(async move { a.enqueue_usage_event(&value).await });
    }
    while let Some(result) = duplicate_tasks.join_next().await {
        result??;
    }
    assert_eq!(stored_usage(&cluster.storage_a, id).await?, 0);
    assert_eq!(b.get(kind, id).await?.unwrap().used_today_bytes, 1024);
    assert_eq!(
        a.authorize(kind, id, source).await?,
        TrafficDecision::QuotaExceeded
    );
    a.drain_pending_usage().await?;
    assert_eq!(stored_usage(&cluster.storage_a, id).await?, 1024);
    assert_eq!(a.get(kind, id).await?.unwrap().used_today_bytes, 1024);
    a.record_usage_event(&first).await?;
    assert_eq!(
        stored_usage(&cluster.storage_a, id).await?,
        1024,
        "Lost client acknowledgement/replay must not duplicate usage"
    );
    let conflict = TrafficUsageEvent {
        bytes: 2048,
        ..first.clone()
    };
    assert!(a.enqueue_usage_event(&conflict).await.is_err());
    assert_eq!(stored_usage(&cluster.storage_a, id).await?, 1024);

    // 多连接独立事件不能丢更新，值不受i64限制。
    let counter_id = Uuid::new_v4();
    a.upsert(kind, counter_id, settings(None, Some(u64::MAX)))
        .await?;
    let mut increments = JoinSet::new();
    for _ in 0..32 {
        let a = a.clone();
        let value = event(counter_id, 257);
        increments.spawn(async move { a.record_usage_event(&value).await });
    }
    while let Some(result) = increments.join_next().await {
        result??;
    }
    assert_eq!(
        stored_usage(&cluster.storage_a, counter_id).await?,
        32 * 257
    );
    a.record_usage_event(&event(counter_id, u64::MAX)).await?;
    assert_eq!(
        stored_usage(&cluster.storage_a, counter_id).await?,
        u64::MAX
    );
    assert_eq!(
        b.get(kind, counter_id).await?.unwrap().used_today_bytes,
        u64::MAX
    );
    cluster.renew().await?;

    // 实际文件spool重开；先远端成功后本机未ack，重放必须幂等。
    let artifacts = PathBuf::from(env::var("LINKLAKE_PG_TEST_ARTIFACT_DIR")?);
    let spool_dir = artifacts.join("persistent-spool");
    let database = Database::persistent(&spool_dir)?;
    let spool = Arc::new(TrafficUsageSpool::open(&database)?);
    assert!(spool.is_persistent());
    let spool_id = Uuid::new_v4();
    a.upsert(kind, spool_id, settings(None, None)).await?;
    let value = event(spool_id, 4096);
    spool.enqueue(&value)?;
    a.enqueue_usage_event(&value).await?;
    drop(spool);
    drop(database);
    let database = Database::persistent(&spool_dir)?;
    let spool = Arc::new(TrafficUsageSpool::open(&database)?);
    assert_eq!(spool.pending_count()?, 1);
    let store = Arc::new(TrafficControlStore::open(
        &database,
        cluster.storage_a.clone(),
        cluster.runtime_a.clone(),
    )?);
    spool.pump(&store).await?;
    assert_eq!(spool.pending_count()?, 0);
    assert_eq!(stored_usage(&cluster.storage_a, spool_id).await?, 4096);
    let meter = TrafficUsageMeter::new(spool.clone(), kind, spool_id);
    meter.add(31)?;
    let (stop_tx, stop_rx) = watch::channel(false);
    let worker = {
        let spool = spool.clone();
        let store = store.clone();
        tokio::spawn(async move { spool.run(&store, stop_rx, Duration::from_secs(5)).await })
    };
    spool.close_admission();
    assert_eq!(spool.active_meter_count()?, 1);
    drop(meter);
    assert_eq!(spool.active_meter_count()?, 0);
    stop_tx.send(true)?;
    timeout(Duration::from_secs(8), worker).await???;
    assert_eq!(spool.pending_count()?, 0);
    a.drain_pending_usage().await?;
    assert_eq!(stored_usage(&cluster.storage_a, spool_id).await?, 4096 + 31);

    // 数据库真实租约失效/新Leader接管；旧进程内token故意保留以验证事务fence。
    cluster.storage_a.postgres_client().await?.execute("UPDATE linklake_ha_leader SET lease_until=clock_timestamp()-interval '1 second' WHERE singleton_id=1", &[]).await?;
    cluster.runtime_b.refresh().await?;
    assert!(cluster.runtime_b.is_leader());
    assert!(
        a.upsert(kind, id, settings(None, None)).await.is_err(),
        "Stale process must not mutate catalog"
    );
    assert!(
        a.authorize(kind, id, source).await.is_err(),
        "Stale process must not authorize traffic"
    );
    let last = event(id, 73);
    assert!(
        a.record_usage_event(&last).await.is_err(),
        "Stale Leader must not directly apply quota"
    );
    a.enqueue_usage_event(&last).await?; // A仍有有效member，可卸载最后计量。
    assert_eq!(b.get(kind, id).await?.unwrap().used_today_bytes, 1024 + 73);
    b.drain_pending_usage().await?;
    assert_eq!(stored_usage(&cluster.storage_b, id).await?, 1024 + 73);
    a.enqueue_usage_event(&last).await?;
    b.drain_pending_usage().await?;
    assert_eq!(stored_usage(&cluster.storage_b, id).await?, 1024 + 73);

    // 失效member不能继续上传，拒绝不能留下任何事件行。
    cluster.storage_b.postgres_client().await?.execute("UPDATE linklake_ha_members SET lease_until=clock_timestamp()-interval '1 second' WHERE instance_id=$1", &[&cluster.runtime_a.coordinator().instance_id()]).await?;
    let denied = event(id, 99);
    assert!(a.enqueue_usage_event(&denied).await.is_err());
    let exists: bool = cluster
        .storage_b
        .postgres_client()
        .await?
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM linklake_traffic_usage_events WHERE event_id=$1)",
            &[&denied.event_id.to_string()],
        )
        .await?
        .get(0);
    assert!(!exists);

    // 存储损坏必须返回错误，不能经默认allowlist/enable字段放行。
    cluster.storage_b.postgres_client().await?.execute("UPDATE linklake_traffic_controls SET settings=settings-'allowed_cidrs' WHERE kind='http' AND policy_id=$1", &[&id.to_string()]).await?;
    assert!(b.get(kind, id).await.is_err());
    assert!(b.authorize(kind, id, source).await.is_err());
    b.upsert(kind, id, settings(None, None)).await?;
    assert_eq!(
        b.authorize(kind, id, "10.1.1.1".parse()?).await?,
        TrafficDecision::SourceDenied
    );
    assert!(b.delete(kind, id).await?);
    assert!(b.get(kind, id).await?.is_none());
    assert_eq!(
        stored_usage(&cluster.storage_b, id).await?,
        1024 + 73,
        "Deleting rules must preserve usage history"
    );
    eprintln!("real_pg_traffic_contract_complete: independent connections, atomic admission, UUID replay, spool restart/drain, Leader failover, member rejection, rollback and corruption checks");
    Ok(())
}
