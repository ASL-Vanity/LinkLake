//! 显式运行的真实 PostgreSQL 迁移、材料轮换与 Fleet 验收；仅允许独立 loopback 测试库。

use crate::{
    certificate_catalog::{
        postgres::{private_key_context, CERTIFICATE_STATE_LOCK},
        CertificateCatalog, RouteTlsMode, UpdateRouteTlsPolicy,
    },
    certificate_key_maintenance::{
        rotate_postgres_certificate_key, CertificateKeyMaintenanceError,
    },
    certificate_manager::CERTIFICATE_COMMIT_MARKER,
    certificate_material::CertificateMaterialCipher,
    client_registry::ClientRegistry,
    database::Database,
    ha_runtime::{HaRuntime, HaRuntimeConfig},
    http_route_catalog::{CreateHttpRoutePolicy, GrpcBackendTransport, HttpRouteCatalog},
    policy_service::{
        postgres::PostgresPolicyService, BindFleetCredential, FleetPolicyKind,
        FleetReconcileRequest, PolicyService,
    },
    public_port_policy::PublicPortPolicy,
    secret_tunnel_catalog::{CreateSecretTunnelPolicy, SecretTunnelCatalog},
    storage::{CoordinationStorage, StorageConfig},
    storage_migration::{
        import_sqlite_plan,
        source::{prepare_sqlite_migration, MigrationSourceOptions},
        verify_sqlite_rollback, MigrationError,
    },
    traffic_control::{TrafficControlCatalog, TrafficPolicyKind, TrafficUsageEvent},
    tunnel_catalog::{CreateHttpProxyPolicy, CreateSocks5ProxyPolicy, TunnelCatalog},
};
use linklake_core::fleet_protocol::*;
use serde_json::Value;
use std::{
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::time::timeout;
use uuid::Uuid;
use zeroize::Zeroizing;

struct SourceFixture {
    directory: PathBuf,
    client_id: Uuid,
    agent_instance_id: Uuid,
    source_instance_id: Uuid,
    secret_ref: Uuid,
    socks_ref: Uuid,
    http_proxy_ref: Uuid,
    route_id: Uuid,
    certificate: Vec<u8>,
    private_key: Zeroizing<Vec<u8>>,
    event: TrafficUsageEvent,
    credential_hashes: Vec<(String, String)>,
}

fn write_test_key(root: &Path, name: &str) -> anyhow::Result<PathBuf> {
    let path = root.join(name);
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut key = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *key).map_err(|_| anyhow::anyhow!("test key randomness failed"))?;
    options.open(&path)?.write_all(&*key)?;
    Ok(path)
}

fn source_options() -> MigrationSourceOptions {
    MigrationSourceOptions {
        max_snapshot_bytes: 16 * 1024 * 1024,
        account_directories: vec![],
        public_port_policy: PublicPortPolicy::development_default(),
    }
}

fn source_fixture(root: &Path) -> anyhow::Result<SourceFixture> {
    let directory = root.join("sqlite-source");
    let database = Database::persistent(&directory)?;
    crate::database_migrations::prepare(&database)?.finish()?;
    crate::migrate_application_schema(&database)?;
    let mut clients = ClientRegistry::open_with_database(&database)?;
    let agent_instance_id = Uuid::new_v4();
    let (client_id, _, _) = clients.enroll_with_identity(
        "fleet-agent".into(),
        "windows".into(),
        Some(agent_instance_id),
        Some("11".repeat(32)),
    )?;
    let ports = PublicPortPolicy::development_default();
    let mut tunnels = TunnelCatalog::open_with_database(&database, ports.clone())?;
    let mut secrets = SecretTunnelCatalog::open_with_database(&database)?;
    let mut http = HttpRouteCatalog::open_with_database(&database)?;
    let service = PolicyService::open_with_database(&database, ports)?;
    let source_instance_id = Uuid::new_v4();
    let secret_ref = Uuid::new_v4();
    let socks_ref = Uuid::new_v4();
    let http_proxy_ref = Uuid::new_v4();
    let secret = secrets.create(CreateSecretTunnelPolicy {
        provider_client_id: client_id,
        allowed_client_id: None,
        name: "credential-secret".into(),
        target_addr: "127.0.0.1:24001".into(),
        max_connections: Some(32),
        bandwidth_limit_bps: None,
    })?;
    let socks = tunnels.create_socks5(CreateSocks5ProxyPolicy {
        client_id,
        name: "credential-socks".into(),
        public_port: 32_005,
        username: "fleet".into(),
        max_connections: Some(64),
        bandwidth_limit_bps: None,
        allow_private_networks: false,
    })?;
    let proxy = tunnels.create_http_proxy(CreateHttpProxyPolicy {
        client_id,
        name: "credential-http".into(),
        public_port: 32_006,
        username: "fleet".into(),
        max_connections: Some(64),
        bandwidth_limit_bps: None,
        allow_private_networks: false,
    })?;
    for (kind, credential_ref, policy_id) in [
        (FleetPolicyKind::SecretTunnel, secret_ref, secret.policy.id),
        (FleetPolicyKind::Socks5Proxy, socks_ref, socks.policy.id),
        (FleetPolicyKind::HttpProxy, http_proxy_ref, proxy.policy.id),
    ] {
        service.bind_credential(
            BindFleetCredential {
                source_instance_id,
                credential_ref,
                kind,
                policy_id,
            },
            1,
        )?;
    }
    let route = http.create(CreateHttpRoutePolicy {
        client_id,
        name: "migration-certificate".into(),
        hostname: "migration.example.test".into(),
        target_addr: "127.0.0.1:24080".into(),
        max_connections: Some(16),
        grpc_backend_transport: GrpcBackendTransport::Tls,
        grpc_backend_server_name: Some("backend.example.test".into()),
        grpc_backend_trust_profile: Some("private-ca".into()),
    })?;
    let mut certificates = CertificateCatalog::open_with_database(&database)?;
    certificates.set_route_tls(
        route.id,
        UpdateRouteTlsPolicy {
            mode: RouteTlsMode::Acme,
            redirect_http_to_https: true,
            certificate_identifier: None,
        },
        1_700_000_000,
    )?;
    certificates.record_certificate_success(
        route.id,
        "test-ca",
        1_699_000_000,
        4_000_000_000,
        1_700_000_000,
    )?;
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec![route.hostname.clone()])?;
    let certificate = cert.pem().into_bytes();
    let private_key = Zeroizing::new(signing_key.serialize_pem().into_bytes());
    let generation = directory.join("certificates/migration.example.test/generations/0001-test");
    fs::create_dir_all(&generation)?;
    fs::write(generation.join("fullchain.pem"), &certificate)?;
    fs::write(generation.join("private-key.pem"), &*private_key)?;
    fs::write(generation.join("committed"), CERTIFICATE_COMMIT_MARKER)?;
    let mut traffic = TrafficControlCatalog::open_with_database(&database)?;
    let event = TrafficUsageEvent {
        event_id: Uuid::new_v4(),
        kind: TrafficPolicyKind::Http,
        policy_id: route.id,
        bytes: u64::MAX,
    };
    traffic.record_usage_event(&event, 1_700_000_000)?;
    let credential_hashes = database.with_connection(|connection| {
        let mut values = vec![];
        for (table, field) in [
            ("clients", "access_token_hash"),
            ("secret_tunnel_policies", "access_key_hash"),
            ("socks5_proxy_policies", "password_hash"),
            ("http_proxy_policies", "password_hash"),
        ] {
            values.push((
                table.to_owned(),
                connection.query_row(&format!("SELECT {field} FROM {table}"), [], |row| {
                    row.get(0)
                })?,
            ));
        }
        Ok(values)
    })?;
    Ok(SourceFixture {
        directory,
        client_id,
        agent_instance_id,
        source_instance_id,
        secret_ref,
        socks_ref,
        http_proxy_ref,
        route_id: route.id,
        certificate,
        private_key,
        event,
        credential_hashes,
    })
}

async fn open_isolated_storage() -> anyhow::Result<CoordinationStorage> {
    anyhow::ensure!(
        env::var("LINKLAKE_PG_TEST_ALLOW_DISPOSABLE").as_deref() == Ok("1"),
        "Use tests/storage-maintenance-postgres.ps1 -RunVerification"
    );
    let config: tokio_postgres::Config = env::var("LINKLAKE_POSTGRES_URL")?.parse()?;
    anyhow::ensure!(
        config
            .get_dbname()
            .is_some_and(|name| name.starts_with("linklake_ha_test_")),
        "Disposable test database required"
    );
    anyhow::ensure!(!config.get_hosts().is_empty() && config.get_hosts().iter().all(|host| matches!(host,
        tokio_postgres::config::Host::Tcp(name) if name == "127.0.0.1" || name == "::1" || name == "localhost")), "Only loopback test databases are allowed");
    anyhow::ensure!(
        env::var_os("LINKLAKE_HA_INSTANCE_ID").is_none(),
        "Clear the instance override before testing"
    );
    let config = StorageConfig::from_environment()?;
    CoordinationStorage::initialize_empty_postgres(&config).await?;
    CoordinationStorage::open_existing_postgres(&config).await
}

async fn count(storage: &CoordinationStorage, table: &str) -> anyhow::Result<i64> {
    // 表名只能来自本文件中的常量，不接收命令行输入。
    Ok(storage
        .postgres_client()
        .await?
        .query_one(&format!("SELECT COUNT(*) FROM {table}"), &[])
        .await?
        .get(0))
}

async fn migration_contract(
    storage: &CoordinationStorage,
    fixture: &SourceFixture,
    key: &Path,
) -> anyhow::Result<()> {
    let options = source_options();
    {
        let _live_source = Database::persistent(&fixture.directory)?;
        assert!(matches!(
            prepare_sqlite_migration(&fixture.directory, key, &options),
            Err(MigrationError::SourceInUse)
        ));
    }
    let mut small = source_options();
    small.max_snapshot_bytes = 32;
    assert!(matches!(
        prepare_sqlite_migration(&fixture.directory, key, &small),
        Err(MigrationError::SnapshotTooLarge)
    ));
    {
        let source = rusqlite::Connection::open(fixture.directory.join("linklake.sqlite3"))?;
        source.execute_batch("CREATE TABLE maintenance_unknown_fixture(value TEXT); INSERT INTO maintenance_unknown_fixture VALUES('must not skip');")?;
        assert!(matches!(
            prepare_sqlite_migration(&fixture.directory, key, &options),
            Err(MigrationError::UnsupportedSourceData)
        ));
        source.execute_batch("DROP TABLE maintenance_unknown_fixture; UPDATE certificate_states SET status='issuing';")?;
        assert!(matches!(
            prepare_sqlite_migration(&fixture.directory, key, &options),
            Err(MigrationError::PendingExternalOperations)
        ));
        source.execute_batch("UPDATE certificate_states SET status='active';")?;
    }
    let plan = prepare_sqlite_migration(&fixture.directory, key, &options)?;
    assert!(
        plan.preview()
            .imported_rows
            .get("linklake_certificate_materials")
            == Some(&1)
    );
    assert!(
        Database::persistent(&fixture.directory).is_err(),
        "A prepared migration must retain the source process lock"
    );
    // 证书配置是靠后的写入：故障必须连同前面已插入的身份/策略整体回滚。
    storage.postgres_client().await?.batch_execute(
        "CREATE FUNCTION maintenance_fail_import() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'maintenance fixture rejection'; END $$;
         CREATE TRIGGER maintenance_fail_import BEFORE INSERT ON linklake_acme_config FOR EACH ROW EXECUTE FUNCTION maintenance_fail_import();"
    ).await?;
    assert!(matches!(
        import_sqlite_plan(storage, &plan).await,
        Err(MigrationError::TransactionFailed)
    ));
    for table in [
        "linklake_clients",
        "linklake_tunnel_policies",
        "linklake_certificate_key_binding",
        "linklake_storage_migration_receipts",
    ] {
        assert_eq!(
            count(storage, table).await?,
            0,
            "Partial import leaked in {table}"
        );
    }
    assert_eq!(count(storage, "linklake_acme_config").await?, 1);
    storage.postgres_client().await?.batch_execute("DROP TRIGGER maintenance_fail_import ON linklake_acme_config; DROP FUNCTION maintenance_fail_import();").await?;
    {
        let mut client = storage.postgres_client().await?;
        let blocker = client.transaction().await?;
        blocker
            .query_one(
                "SELECT pg_advisory_xact_lock($1)",
                &[&0x4c4c_4841_4d49_4752i64],
            )
            .await?;
        assert!(timeout(
            Duration::from_millis(200),
            import_sqlite_plan(storage, &plan)
        )
        .await
        .is_err());
        blocker.rollback().await?;
    }
    assert_eq!(
        count(storage, "linklake_storage_migration_receipts").await?,
        0
    );
    let imported = import_sqlite_plan(storage, &plan).await?;
    assert!(!imported.already_imported);
    assert!(import_sqlite_plan(storage, &plan).await?.already_imported);
    assert!(
        verify_sqlite_rollback(storage, &plan)
            .await?
            .already_imported
    );
    let fingerprint = imported.source_fingerprint;
    drop(plan);
    let plan = prepare_sqlite_migration(&fixture.directory, key, &options)?;
    assert_eq!(
        plan.preview().source_fingerprint,
        fingerprint,
        "Random encryption must not change the source fingerprint"
    );
    assert!(import_sqlite_plan(storage, &plan).await?.already_imported);
    assert_eq!(
        count(storage, "linklake_storage_migration_receipts").await?,
        1
    );
    for (source_table, expected) in &fixture.credential_hashes {
        let sql = match source_table.as_str() {
            "clients" => "SELECT access_token_hash FROM linklake_clients",
            "secret_tunnel_policies" => {
                "SELECT access_key_hash FROM linklake_secret_tunnel_policies"
            }
            "socks5_proxy_policies" => {
                "SELECT password_hash FROM linklake_tunnel_policies WHERE kind='socks5_proxy'"
            }
            "http_proxy_policies" => {
                "SELECT password_hash FROM linklake_tunnel_policies WHERE kind='http_proxy'"
            }
            _ => unreachable!(),
        };
        let actual: String = storage
            .postgres_client()
            .await?
            .query_one(sql, &[])
            .await?
            .get(0);
        assert!(
            actual == *expected,
            "Credential hash changed during migration"
        );
    }
    let row = storage
        .postgres_client()
        .await?
        .query_one(
            "SELECT bytes::text,applied FROM linklake_traffic_usage_events WHERE event_id=$1",
            &[&fixture.event.event_id.to_string()],
        )
        .await?;
    assert_eq!(row.get::<_, String>(0), u64::MAX.to_string());
    assert!(row.get::<_, bool>(1));
    let usage: String = storage
        .postgres_client()
        .await?
        .query_one(
            "SELECT bytes::text FROM linklake_traffic_daily_usage WHERE policy_id=$1",
            &[&fixture.route_id.to_string()],
        )
        .await?
        .get(0);
    assert_eq!(usage, u64::MAX.to_string());
    let material = storage.postgres_client().await?.query_one("SELECT certificate_pem,encrypted_private_key FROM linklake_certificate_materials WHERE route_id=$1", &[&fixture.route_id.to_string()]).await?;
    let cert: Vec<u8> = material.get(0);
    let encrypted: Vec<u8> = material.get(1);
    assert!(cert == fixture.certificate);
    let cipher = CertificateMaterialCipher::from_key_file(key)?;
    let context = private_key_context(fixture.route_id, "migration.example.test", &cert);
    assert!(*cipher.open(&context, &encrypted)? == *fixture.private_key);
    // 已有新业务变更时拒绝重导及自动切回旧快照。
    storage
        .postgres_client()
        .await?
        .execute(
            "UPDATE linklake_clients SET notes='target changed' WHERE client_id=$1",
            &[&fixture.client_id.to_string()],
        )
        .await?;
    assert!(matches!(
        import_sqlite_plan(storage, &plan).await,
        Err(MigrationError::TargetChanged)
    ));
    assert!(matches!(
        verify_sqlite_rollback(storage, &plan).await,
        Err(MigrationError::TargetChanged)
    ));
    drop(plan);
    let source = rusqlite::Connection::open(fixture.directory.join("linklake.sqlite3"))?;
    source.execute("UPDATE clients SET notes='source changed'", [])?;
    drop(source);
    let changed = prepare_sqlite_migration(&fixture.directory, key, &options)?;
    assert!(matches!(
        import_sqlite_plan(storage, &changed).await,
        Err(MigrationError::TargetNotEmpty)
    ));
    eprintln!("real_pg_maintenance_stage: migration_complete");
    Ok(())
}

async fn material_snapshot(storage: &CoordinationStorage) -> anyhow::Result<Value> {
    Ok(storage.postgres_client().await?.query_one(
        "SELECT jsonb_build_object('binding',(SELECT jsonb_agg(to_jsonb(x)) FROM linklake_certificate_key_binding x),
          'certificates',(SELECT jsonb_agg(to_jsonb(x) ORDER BY identifier) FROM linklake_certificate_materials x),
          'accounts',(SELECT jsonb_agg(to_jsonb(x) ORDER BY directory_url) FROM linklake_acme_accounts x))", &[]).await?.get(0))
}

async fn rotation_contract(
    storage: &CoordinationStorage,
    root: &Path,
    previous: &Path,
) -> anyhow::Result<()> {
    let next = write_test_key(root, "next-test-key.bin")?;
    let wrong = write_test_key(root, "wrong-test-key.bin")?;
    let old_cipher = CertificateMaterialCipher::from_key_file(previous)?;
    let next_cipher = CertificateMaterialCipher::from_key_file(&next)?;
    // 17 条保证第三批也被处理；迁移的真实 PEM 会一起经过轮换。
    for index in 0..17 {
        let identifier = format!("rotation-{index:02}.example.test");
        let route = Uuid::new_v4();
        let cert = format!("public certificate fixture {index}").into_bytes();
        let encrypted = old_cipher.seal(
            &private_key_context(route, &identifier, &cert),
            format!("private fixture {index}").as_bytes(),
        )?;
        storage
            .postgres_client()
            .await?
            .execute(
                "INSERT INTO linklake_certificate_materials VALUES($1,$2,$3,$4,$5,1700000000)",
                &[
                    &identifier,
                    &route.to_string(),
                    &Uuid::new_v4().to_string(),
                    &cert,
                    &encrypted,
                ],
            )
            .await?;
        let directory = format!("https://ca-{index:02}.example.test/directory");
        let encrypted = old_cipher.seal(
            &format!("acme-account:{directory}"),
            format!("account fixture {index}").as_bytes(),
        )?;
        storage
            .postgres_client()
            .await?
            .execute(
                "INSERT INTO linklake_acme_accounts VALUES($1,$2,1700000000)",
                &[&directory, &encrypted],
            )
            .await?;
    }
    let original = material_snapshot(storage).await?;
    assert_eq!(
        rotate_postgres_certificate_key(storage, previous, previous)
            .await
            .unwrap_err(),
        CertificateKeyMaintenanceError::UnchangedKey
    );
    assert_eq!(
        rotate_postgres_certificate_key(storage, &wrong, &next)
            .await
            .unwrap_err(),
        CertificateKeyMaintenanceError::WrongPreviousKey
    );
    // 后续批次失败：已经轮换过的早期证书及绑定仍须保持完全原值。
    for (table, selector, field) in [
        (
            "linklake_certificate_materials",
            "identifier='rotation-16.example.test'",
            "encrypted_private_key",
        ),
        (
            "linklake_acme_accounts",
            "directory_url='https://ca-16.example.test/directory'",
            "encrypted_credentials",
        ),
    ] {
        let sql = format!("SELECT {field} FROM {table} WHERE {selector}");
        let saved: Vec<u8> = storage
            .postgres_client()
            .await?
            .query_one(&sql, &[])
            .await?
            .get(0);
        let mut damaged = saved.clone();
        damaged[16] ^= 1;
        storage
            .postgres_client()
            .await?
            .execute(
                &format!("UPDATE {table} SET {field}=$1 WHERE {selector}"),
                &[&damaged],
            )
            .await?;
        let before_failure = material_snapshot(storage).await?;
        assert_eq!(
            rotate_postgres_certificate_key(storage, previous, &next)
                .await
                .unwrap_err(),
            CertificateKeyMaintenanceError::InvalidStoredMaterial
        );
        assert!(
            material_snapshot(storage).await? == before_failure,
            "A later corrupt row must roll back earlier batches"
        );
        storage
            .postgres_client()
            .await?
            .execute(
                &format!("UPDATE {table} SET {field}=$1 WHERE {selector}"),
                &[&saved],
            )
            .await?;
    }
    assert!(material_snapshot(storage).await? == original);
    storage.postgres_client().await?.execute("INSERT INTO linklake_ha_members(instance_id,incarnation_id,started_at,last_seen_at,lease_until) VALUES('maintenance-live-fixture',$1,clock_timestamp(),clock_timestamp(),clock_timestamp()+interval '60 seconds')", &[&Uuid::new_v4().to_string()]).await?;
    assert_eq!(
        rotate_postgres_certificate_key(storage, previous, &next)
            .await
            .unwrap_err(),
        CertificateKeyMaintenanceError::ActiveInstances
    );
    storage
        .postgres_client()
        .await?
        .execute(
            "DELETE FROM linklake_ha_members WHERE instance_id='maintenance-live-fixture'",
            &[],
        )
        .await?;
    {
        let mut client = storage.postgres_client().await?;
        let blocker = client.transaction().await?;
        blocker
            .query_one(
                "SELECT pg_advisory_xact_lock($1)",
                &[&CERTIFICATE_STATE_LOCK],
            )
            .await?;
        assert!(timeout(
            Duration::from_millis(200),
            rotate_postgres_certificate_key(storage, previous, &next)
        )
        .await
        .is_err());
        blocker.rollback().await?;
    }
    assert!(material_snapshot(storage).await? == original);
    let rotated = rotate_postgres_certificate_key(storage, previous, &next).await?;
    assert_eq!(rotated.certificates_reencrypted, 18);
    assert_eq!(rotated.accounts_reencrypted, 17);
    assert_eq!(rotated.current_fingerprint, next_cipher.fingerprint());
    let after = material_snapshot(storage).await?;
    for (before, after) in original["certificates"]
        .as_array()
        .unwrap()
        .iter()
        .zip(after["certificates"].as_array().unwrap())
    {
        for field in [
            "identifier",
            "route_id",
            "generation",
            "certificate_pem",
            "updated_unix_seconds",
        ] {
            assert!(
                before[field] == after[field],
                "Rotation changed immutable certificate metadata"
            );
        }
    }
    for row in storage.postgres_client().await?.query("SELECT identifier,route_id,certificate_pem,encrypted_private_key FROM linklake_certificate_materials", &[]).await? {
        let identifier: String = row.get(0);
        let route: String = row.get(1);
        let cert: Vec<u8> = row.get(2);
        let encrypted: Vec<u8> = row.get(3);
        let context = private_key_context(Uuid::parse_str(&route)?, &identifier, &cert);
        assert!(next_cipher.open(&context, &encrypted).is_ok());
        assert!(old_cipher.open(&context, &encrypted).is_err());
    }
    for row in storage
        .postgres_client()
        .await?
        .query(
            "SELECT directory_url,encrypted_credentials FROM linklake_acme_accounts",
            &[],
        )
        .await?
    {
        let directory: String = row.get(0);
        let encrypted: Vec<u8> = row.get(1);
        let context = format!("acme-account:{directory}");
        assert!(next_cipher.open(&context, &encrypted).is_ok());
        assert!(old_cipher.open(&context, &encrypted).is_err());
    }
    let reverse = rotate_postgres_certificate_key(storage, &next, previous).await?;
    assert_eq!(reverse.current_fingerprint, old_cipher.fingerprint());
    assert_eq!(reverse.certificates_reencrypted, 18);
    assert_eq!(reverse.accounts_reencrypted, 17);
    eprintln!("real_pg_maintenance_stage: rotation_complete");
    Ok(())
}

fn request(
    bundle: FleetBundleV2,
    expected_generation: Option<u64>,
    expected_revision: Option<String>,
) -> FleetReconcileRequest {
    FleetReconcileRequest {
        bundle,
        dry_run: false,
        expected_generation,
        expected_revision,
    }
}

async fn fleet_snapshot(storage: &CoordinationStorage) -> anyhow::Result<Value> {
    Ok(storage.postgres_client().await?.query_one(
        "SELECT jsonb_build_object('tunnels',(SELECT jsonb_agg(to_jsonb(x) ORDER BY id) FROM linklake_tunnel_policies x),
          'ports',(SELECT jsonb_agg(to_jsonb(x) ORDER BY protocol,public_port) FROM linklake_tunnel_ports x),
          'http',(SELECT jsonb_agg(to_jsonb(x) ORDER BY id) FROM linklake_http_route_policies x),
          'sni',(SELECT jsonb_agg(to_jsonb(x) ORDER BY id) FROM linklake_sni_route_policies x),
          'secret',(SELECT jsonb_agg(to_jsonb(x) ORDER BY id) FROM linklake_secret_tunnel_policies x),
          'owners',(SELECT jsonb_agg(to_jsonb(x) ORDER BY resource_id) FROM linklake_fleet_resource_ownership x),
          'sources',(SELECT jsonb_agg(to_jsonb(x) ORDER BY source_instance_id) FROM linklake_fleet_source_states x),
          'traffic',(SELECT jsonb_agg(to_jsonb(x) ORDER BY kind,policy_id) FROM linklake_traffic_controls x))", &[]).await?.get(0))
}

async fn fleet_contract(
    storage: &CoordinationStorage,
    fixture: &SourceFixture,
) -> anyhow::Result<()> {
    let storage_b =
        CoordinationStorage::open_existing_postgres(&StorageConfig::from_environment()?).await?;
    let runtime_a = Arc::new(HaRuntime::open(
        storage.clone(),
        HaRuntimeConfig::from_environment("maintenance-fleet-a")?,
    )?);
    let runtime_b = Arc::new(HaRuntime::open(
        storage_b.clone(),
        HaRuntimeConfig::from_environment("maintenance-fleet-b")?,
    )?);
    runtime_a.bootstrap().await?;
    runtime_b.bootstrap().await?;
    assert!(runtime_a.is_leader() && !runtime_b.is_leader());
    let a = PostgresPolicyService {
        storage: storage.clone(),
        runtime: runtime_a.clone(),
        public_port_policy: PublicPortPolicy::development_default(),
    };
    let b = PostgresPolicyService {
        storage: storage_b.clone(),
        runtime: runtime_b.clone(),
        public_port_policy: PublicPortPolicy::development_default(),
    };
    {
        let ca = storage.postgres_client().await?;
        let cb = storage_b.postgres_client().await?;
        let pid_a: i32 = ca.query_one("SELECT pg_backend_pid()", &[]).await?.get(0);
        let pid_b: i32 = cb.query_one("SELECT pg_backend_pid()", &[]).await?.get(0);
        assert_ne!(pid_a, pid_b);
    }
    assert!(b
        .reconcile(request(bundle(fixture, 1, 32_001, 32_005), None, None))
        .await
        .is_err());
    let first = a
        .reconcile(request(bundle(fixture, 1, 32_001, 32_005), Some(0), None))
        .await?;
    assert!(
        first.applied && first.conflicts.is_empty(),
        "First eight-kind reconcile failed: {first:?}"
    );
    assert_eq!(first.created, 8);
    assert_eq!(
        count(storage, "linklake_fleet_resource_ownership").await?,
        8
    );
    assert_eq!(count(storage, "linklake_tunnel_policies").await?, 5);
    assert_eq!(count(storage, "linklake_http_route_policies").await?, 2);
    assert_eq!(count(storage, "linklake_sni_route_policies").await?, 1);
    assert_eq!(count(storage, "linklake_secret_tunnel_policies").await?, 1);
    assert_eq!(b.list_sources().await?[0].generation, 1);
    let second_bundle = bundle(fixture, 2, 32_005, 32_001);
    let second = a
        .reconcile(request(
            second_bundle.clone(),
            Some(1),
            Some(first.revision.clone()),
        ))
        .await?;
    assert!(
        second.applied && second.conflicts.is_empty(),
        "Port swap failed: {second:?}"
    );
    assert_eq!(second.updated, 2);
    let before_replay = fleet_snapshot(storage).await?;
    let replay = a
        .reconcile(request(second_bundle.clone(), None, None))
        .await?;
    assert!(replay.idempotent && !replay.applied);
    assert!(
        fleet_snapshot(storage).await? == before_replay,
        "Replay changed shared state"
    );
    assert!(a
        .reconcile(request(bundle(fixture, 1, 32_001, 32_005), None, None))
        .await
        .is_err());
    assert!(a
        .reconcile(request(bundle(fixture, 2, 32_007, 32_001), None, None))
        .await
        .is_err());
    assert!(a
        .reconcile(request(bundle(fixture, 3, 32_007, 32_001), Some(1), None))
        .await
        .is_err());
    let exported = a.export_bundle().await?;
    assert_eq!(
        exported.resources.len(),
        1,
        "Export must exclude the eight remote-owned resources"
    );
    assert_eq!(exported.resources[0].resource_id, fixture.route_id);
    // 在后续表失败，保证端口、全部目录、流量与归属/代际一次性回滚。
    storage.postgres_client().await?.batch_execute(
        "CREATE FUNCTION maintenance_fail_fleet() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.kind='udp' THEN RAISE EXCEPTION 'maintenance fixture rejection'; END IF; RETURN NEW; END $$;
         CREATE TRIGGER maintenance_fail_fleet BEFORE INSERT ON linklake_tunnel_policies FOR EACH ROW EXECUTE FUNCTION maintenance_fail_fleet();"
    ).await?;
    let mut changed = bundle(fixture, 3, 32_007, 32_001);
    if let FleetResourceSpec::Udp(policy) = &mut changed.resources[1].spec {
        policy.target_addr = "127.0.0.1:23999".into();
    }
    changed.refresh_integrity()?;
    let before_failure = fleet_snapshot(storage).await?;
    assert!(a
        .reconcile(request(changed, Some(2), Some(second.revision.clone())))
        .await
        .is_err());
    assert!(
        fleet_snapshot(storage).await? == before_failure,
        "Failed reconcile leaked partial state"
    );
    storage.postgres_client().await?.batch_execute("DROP TRIGGER maintenance_fail_fleet ON linklake_tunnel_policies; DROP FUNCTION maintenance_fail_fleet();").await?;
    // 数据库租约过期后接管；旧进程仍保留旧本地 token，真实写入须受数据库 fence 拒绝。
    storage
        .postgres_client()
        .await?
        .execute(
            "UPDATE linklake_ha_leader SET lease_until=clock_timestamp()-interval '1 second'",
            &[],
        )
        .await?;
    runtime_b.refresh().await?;
    assert!(runtime_b.is_leader());
    assert!(a
        .reconcile(request(
            bundle(fixture, 3, 32_007, 32_001),
            Some(2),
            Some(second.revision.clone())
        ))
        .await
        .is_err());
    let third = b
        .reconcile(request(
            bundle(fixture, 3, 32_007, 32_001),
            Some(2),
            Some(second.revision),
        ))
        .await?;
    assert!(third.applied);
    assert_eq!(a.list_sources().await?[0].generation, 3);
    eprintln!("real_pg_maintenance_stage: fleet_complete");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "Requires tests/storage-maintenance-postgres.ps1 -RunVerification and isolated PostgreSQL"]
async fn real_postgres_maintenance_cluster_contract() -> anyhow::Result<()> {
    let storage = open_isolated_storage().await?;
    let root = PathBuf::from(env::var("LINKLAKE_PG_TEST_ARTIFACT_DIR")?);
    fs::create_dir_all(&root)?;
    let previous = write_test_key(&root, "previous-test-key.bin")?;
    let fixture = source_fixture(&root)?;
    migration_contract(&storage, &fixture, &previous).await?;
    rotation_contract(&storage, &root, &previous).await?;
    fleet_contract(&storage, &fixture).await?;
    eprintln!("real_pg_maintenance_contract_complete: migration_rotation_fleet");
    Ok(())
}

fn bundle(state: &SourceFixture, generation: u64, tcp_port: u16, socks_port: u16) -> FleetBundleV2 {
    let agent = state.agent_instance_id;
    let resources = vec![
        FleetResource {
            resource_id: Uuid::from_u128(1),
            enabled: true,
            spec: FleetResourceSpec::Tcp(FleetTcpResource {
                agent_instance_id: agent,
                name: "tcp".into(),
                public_port: tcp_port,
                target_addr: "127.0.0.1:23001".into(),
                max_connections: 64,
                bandwidth_limit_bps: None,
            }),
        },
        FleetResource {
            resource_id: Uuid::from_u128(2),
            enabled: true,
            spec: FleetResourceSpec::Udp(FleetUdpResource {
                agent_instance_id: agent,
                name: "udp".into(),
                public_port: 32_002,
                target_addr: "127.0.0.1:23002".into(),
                max_sessions: 256,
                session_idle_timeout_seconds: 120,
                bandwidth_limit_bps: None,
            }),
        },
        FleetResource {
            resource_id: Uuid::from_u128(3),
            enabled: true,
            spec: FleetResourceSpec::PortGroup(FleetPortGroupResource {
                agent_instance_id: agent,
                name: "ports".into(),
                protocol: FleetPortGroupProtocol::Tcp,
                public_ports: "32003-32004".into(),
                target_host: "127.0.0.1".into(),
                target_ports: "23003-23004".into(),
                max_connections: 64,
                max_sessions: 256,
                session_idle_timeout_seconds: 120,
                bandwidth_limit_bps: None,
            }),
        },
        FleetResource {
            resource_id: Uuid::from_u128(4),
            enabled: true,
            spec: FleetResourceSpec::HttpRoute(FleetHttpRouteResource {
                agent_instance_id: agent,
                name: "web".into(),
                hostname: "fleet-http.example.com".into(),
                target_addr: "127.0.0.1:23005".into(),
                max_connections: 64,
                grpc_backend_transport: FleetGrpcBackendTransport::H2c,
                grpc_backend_server_name: None,
                grpc_backend_trust_profile: None,
            }),
        },
        FleetResource {
            resource_id: Uuid::from_u128(5),
            enabled: true,
            spec: FleetResourceSpec::SniRoute(FleetSniRouteResource {
                agent_instance_id: agent,
                name: "tls".into(),
                hostname: "fleet-sni.example.com".into(),
                target_addr: "127.0.0.1:23006".into(),
                max_connections: 64,
                bandwidth_limit_bps: None,
            }),
        },
        FleetResource {
            resource_id: Uuid::from_u128(6),
            enabled: true,
            spec: FleetResourceSpec::SecretTunnel(FleetSecretTunnelResource {
                provider_agent_instance_id: agent,
                allowed_agent_instance_id: None,
                credential_ref: state.secret_ref,
                name: "secret".into(),
                target_addr: "127.0.0.1:23007".into(),
                max_connections: 32,
                bandwidth_limit_bps: None,
            }),
        },
        FleetResource {
            resource_id: Uuid::from_u128(7),
            enabled: true,
            spec: FleetResourceSpec::Socks5Proxy(FleetSocks5ProxyResource {
                agent_instance_id: agent,
                credential_ref: state.socks_ref,
                name: "socks".into(),
                public_port: socks_port,
                username: "fleet".into(),
                max_connections: 64,
                bandwidth_limit_bps: None,
                allow_private_networks: false,
            }),
        },
        FleetResource {
            resource_id: Uuid::from_u128(8),
            enabled: true,
            spec: FleetResourceSpec::HttpProxy(FleetHttpProxyResource {
                agent_instance_id: agent,
                credential_ref: state.http_proxy_ref,
                name: "http-proxy".into(),
                public_port: 32_006,
                username: "fleet".into(),
                max_connections: 64,
                bandwidth_limit_bps: None,
                allow_private_networks: false,
            }),
        },
    ];
    FleetBundleV2::new(
        state.source_instance_id,
        generation,
        1_700_000_000 + generation,
        vec![FleetClientRef {
            agent_instance_id: agent,
            name: "fleet-agent".into(),
            agent_identity_public_key: Some("11".repeat(32)),
        }],
        resources,
        vec![FleetTrafficControl {
            resource_id: Uuid::from_u128(1),
            enabled: true,
            allowed_cidrs: vec!["10.0.0.0/8".into()],
            denied_cidrs: Vec::new(),
            max_connections_per_minute: Some(60),
            daily_quota_bytes: Some(1_048_576),
            active_weekdays_utc: Vec::new(),
            start_minute_utc: None,
            end_minute_utc: None,
        }],
    )
    .unwrap()
}
