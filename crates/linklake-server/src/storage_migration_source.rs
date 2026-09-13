//! SQLite 源快照与显式表映射。只读源文件；任何非空未知表都阻止导入。

use super::*;
use fs2::FileExt;
use rusqlite::{types::ValueRef, Connection, OpenFlags};
use serde::de::DeserializeOwned;
use std::{
    collections::{BTreeSet, HashMap},
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

use crate::certificate_material::CertificateMaterialCipher;

#[path = "storage_migration_materials.rs"]
mod materials;

pub(crate) struct SourceGuard {
    connection: Connection,
    _process_lock: File,
    directory: PathBuf,
}

pub(crate) struct MigrationSourceOptions {
    /// 源 JSON 快照的显式上限，默认调用方建议 512 MiB；超限不截断导入。
    pub(crate) max_snapshot_bytes: usize,
    /// 除当前 ACME directory 外的历史账户目录 URL，用于识别磁盘账户文件。
    pub(crate) account_directories: Vec<String>,
    /// 必须使用源部署的真实公网端口配置，不能用宽松默认值替代。
    pub(crate) public_port_policy: crate::public_port_policy::PublicPortPolicy,
}

struct Builder {
    source: SourceGuard,
    tables: BTreeMap<String, Vec<Value>>,
    mapped: BTreeSet<String>,
    rows: Vec<MigrationRow>,
    digest: Sha256,
    staged_bytes: usize,
    max_bytes: usize,
    oversized: bool,
}

/// 调用方应在启动任何 SQLite Catalog/HA runtime 前调用，避免隐式建表或迁移。
pub(crate) fn prepare_sqlite_migration(
    directory: &Path,
    key_file: &Path,
    options: &MigrationSourceOptions,
) -> Result<MigrationPlan> {
    let directory = directory
        .canonicalize()
        .map_err(|_| MigrationError::InvalidSource)?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .open(directory.join("linklake.sqlite3.lock"))
        .map_err(|_| MigrationError::InvalidSource)?;
    lock.try_lock_exclusive()
        .map_err(|_| MigrationError::SourceInUse)?;
    let connection = Connection::open_with_flags(
        directory.join("linklake.sqlite3"),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(|_| MigrationError::InvalidSource)?;
    connection
        .execute_batch("PRAGMA query_only=ON; BEGIN DEFERRED;")
        .map_err(|_| MigrationError::InvalidSource)?;
    let check: String = connection
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .map_err(|_| MigrationError::InvalidSource)?;
    if check != "ok" {
        return Err(MigrationError::InvalidSource);
    }
    let cipher = CertificateMaterialCipher::from_key_file(key_file)
        .map_err(|_| MigrationError::InvalidKey)?;
    let key_fingerprint = cipher.fingerprint();
    let source = SourceGuard {
        connection,
        _process_lock: lock,
        directory,
    };
    let tables = read_tables(&source.connection, options.max_snapshot_bytes)?;
    let mut digest = Sha256::new();
    digest.update(b"linklake-sqlite-postgres-migration-v1\0");
    digest.update(key_fingerprint.as_bytes());
    digest.update(
        serde_json::to_vec(&options.public_port_policy.view())
            .map_err(|_| MigrationError::InvalidSource)?,
    );
    for (name, rows) in &tables {
        digest.update((name.len() as u64).to_be_bytes());
        digest.update(name.as_bytes());
        for row in rows {
            let bytes = serde_json::to_vec(row).map_err(|_| MigrationError::InvalidSource)?;
            digest.update((bytes.len() as u64).to_be_bytes());
            digest.update(bytes);
        }
    }
    let mut builder = Builder {
        source,
        tables,
        mapped: BTreeSet::new(),
        rows: Vec::new(),
        digest,
        staged_bytes: 0,
        max_bytes: options.max_snapshot_bytes,
        oversized: false,
    };
    builder.reject_pending_operations()?;
    builder.identities_and_ledgers()?;
    builder.policies(&options.public_port_policy)?;
    builder.traffic()?;
    builder.fleet_health()?;
    builder.observability()?;
    builder.certificates(&cipher, options)?;
    if builder.oversized {
        return Err(MigrationError::SnapshotTooLarge);
    }
    builder.validate_references()?;
    // 租约和发现缓存是运行时状态，不能把旧 owner/fencing 恢复为新库权限。
    for table in [
        "schema_migrations",
        "ha_members",
        "ha_leader",
        "ha_fencing_sequence",
        "public_port_ownership",
        "job_leases",
        "target_health",
        "p2p_nodes",
    ] {
        builder.mapped.insert(table.to_owned());
    }
    if builder
        .tables
        .iter()
        .any(|(name, rows)| !rows.is_empty() && !builder.mapped.contains(name))
    {
        return Err(MigrationError::UnsupportedSourceData);
    }
    Ok(MigrationPlan {
        source_fingerprint: format!("{:x}", builder.digest.finalize()),
        key_fingerprint,
        rows: builder.rows,
        _source: builder.source,
    })
}

fn read_tables(connection: &Connection, limit: usize) -> Result<BTreeMap<String, Vec<Value>>> {
    let mut statement = connection.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        .map_err(|_| MigrationError::InvalidSource)?;
    let names = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|_| MigrationError::InvalidSource)?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| MigrationError::InvalidSource)?;
    let mut tables = BTreeMap::new();
    let mut bytes = 0usize;
    for table in names {
        let mut statement = connection
            .prepare(&format!("SELECT * FROM {}", identifier(&table)?))
            .map_err(|_| MigrationError::InvalidSource)?;
        let columns = statement
            .column_names()
            .iter()
            .map(|name| (*name).to_owned())
            .collect::<Vec<_>>();
        let mut query = statement
            .query([])
            .map_err(|_| MigrationError::InvalidSource)?;
        let mut rows = Vec::new();
        while let Some(row) = query.next().map_err(|_| MigrationError::InvalidSource)? {
            let mut values = serde_json::Map::new();
            for (index, column) in columns.iter().enumerate() {
                let value = row
                    .get_ref(index)
                    .map_err(|_| MigrationError::InvalidSource)?;
                let value = if table.starts_with("traffic_")
                    && matches!(column.as_str(), "bytes" | "daily_quota_bytes")
                    && !matches!(value, ValueRef::Null)
                {
                    let decoded = if let ValueRef::Text(value) = value {
                        let raw = std::str::from_utf8(value)
                            .map_err(|_| MigrationError::InvalidSource)?;
                        let parsed = raw
                            .parse::<u64>()
                            .map_err(|_| MigrationError::InvalidSource)?;
                        if parsed.to_string() != raw {
                            return Err(MigrationError::InvalidSource);
                        }
                        parsed
                    } else {
                        crate::traffic_control::decode_sqlite_u64(value)
                            .map_err(|_| MigrationError::InvalidSource)?
                    };
                    json!(decoded)
                } else {
                    match value {
                        ValueRef::Null => Value::Null,
                        ValueRef::Integer(value) => json!(value),
                        ValueRef::Real(value) => serde_json::Number::from_f64(value)
                            .map(Value::Number)
                            .ok_or(MigrationError::InvalidSource)?,
                        ValueRef::Text(value) => Value::String(
                            std::str::from_utf8(value)
                                .map_err(|_| MigrationError::InvalidSource)?
                                .to_owned(),
                        ),
                        ValueRef::Blob(value) => Value::String(bytea(value)),
                    }
                };
                values.insert(column.clone(), value);
            }
            let value = Value::Object(values);
            bytes = bytes
                .checked_add(
                    serde_json::to_vec(&value)
                        .map_err(|_| MigrationError::InvalidSource)?
                        .len(),
                )
                .ok_or(MigrationError::SnapshotTooLarge)?;
            if bytes > limit {
                return Err(MigrationError::SnapshotTooLarge);
            }
            rows.push(value);
        }
        rows.sort_by_cached_key(Value::to_string);
        tables.insert(table, rows);
    }
    Ok(tables)
}

fn bytea(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut result = String::from("\\x");
    for byte in bytes {
        write!(&mut result, "{byte:02x}").expect("string formatting");
    }
    result
}
fn text<'a>(row: &'a Value, field: &str) -> Result<&'a str> {
    row.get(field)
        .and_then(Value::as_str)
        .ok_or(MigrationError::InvalidSource)
}
fn copy(row: &Value, fields: &[&str]) -> Result<Value> {
    let mut result = serde_json::Map::new();
    for field in fields {
        result.insert(
            (*field).to_owned(),
            row.get(*field)
                .cloned()
                .ok_or(MigrationError::InvalidSource)?,
        );
    }
    Ok(Value::Object(result))
}
fn booleans(row: &mut Value, fields: &[&str]) -> Result<()> {
    for field in fields {
        if let Some(value) = row.get_mut(*field) {
            *value = match value.as_i64() {
                Some(0) => Value::Bool(false),
                Some(1) => Value::Bool(true),
                _ if value.is_boolean() => value.clone(),
                _ => return Err(MigrationError::InvalidSource),
            };
        }
    }
    Ok(())
}
fn parse_json_fields(row: &mut Value, fields: &[&str]) -> Result<()> {
    for field in fields {
        if let Some(value) = row.get_mut(*field) {
            if let Some(raw) = value.as_str() {
                *value = serde_json::from_str(raw).map_err(|_| MigrationError::InvalidSource)?;
            }
        }
    }
    Ok(())
}
fn validate_model<T: DeserializeOwned>(value: &Value) -> Result<()> {
    serde_json::from_value::<T>(value.clone())
        .map(|_| ())
        .map_err(|_| MigrationError::InvalidSource)
}
fn revision(scope: &str, value: &Value) -> String {
    let digest = Sha256::digest(format!("linklake-sqlite-revision:{scope}:{value}"));
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    // 自定义确定性 UUID 使用 version 8，不能伪称 SHA-1 UUIDv5。
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes).to_string()
}

impl Builder {
    fn take(&mut self, name: &str) -> Vec<Value> {
        self.mapped.insert(name.to_owned());
        self.tables.get(name).cloned().unwrap_or_default()
    }
    fn add(&mut self, table: &str, values: Value) {
        let size = values.to_string().len();
        self.staged_bytes = self.staged_bytes.saturating_add(size);
        if self.staged_bytes > self.max_bytes {
            self.oversized = true;
            return;
        }
        self.rows.push(MigrationRow {
            table: table.to_owned(),
            values,
        });
    }

    fn reject_pending_operations(&mut self) -> Result<()> {
        for table in ["dns01_intents"] {
            if !self.take(table).is_empty() {
                return Err(MigrationError::PendingExternalOperations);
            }
        }
        for row in self.tables.get("update_tasks").into_iter().flatten() {
            if !matches!(
                row["state"].as_str(),
                Some("succeeded" | "failed" | "cancelled")
            ) {
                return Err(MigrationError::PendingExternalOperations);
            }
        }
        for row in self.tables.get("fleet_dns_failovers").into_iter().flatten() {
            if row
                .get("pending_operation_id")
                .is_some_and(|value| !value.is_null())
            {
                return Err(MigrationError::PendingExternalOperations);
            }
        }
        for row in self
            .tables
            .get("alert_notification_deliveries")
            .into_iter()
            .flatten()
        {
            if row["state"] == "delivering" {
                return Err(MigrationError::PendingExternalOperations);
            }
        }
        for row in self.tables.get("certificate_states").into_iter().flatten() {
            if matches!(row["status"].as_str(), Some("issuing" | "renewing")) {
                return Err(MigrationError::PendingExternalOperations);
            }
        }
        for row in self.tables.get("fleet_generations").into_iter().flatten() {
            if matches!(row["sync_state"].as_str(), Some("pending" | "applying")) {
                return Err(MigrationError::PendingExternalOperations);
            }
        }
        let legacy = self.source.directory.join("acme/dns01-records");
        if legacy.exists()
            && std::fs::read_dir(legacy)
                .map_err(|_| MigrationError::InvalidSource)?
                .next()
                .is_some()
        {
            return Err(MigrationError::PendingExternalOperations);
        }
        Ok(())
    }

    fn identities_and_ledgers(&mut self) -> Result<()> {
        for table in [
            "administrators",
            "admin_sessions",
            "management_api_tokens",
            "clients",
            "fleet_peers",
            "fleet_local_state",
            "fleet_source_states",
            "fleet_resource_ownership",
            "fleet_credential_bindings",
            "fleet_generations",
            "fleet_conflicts",
            "update_task_events",
        ] {
            for mut row in self.take(table) {
                booleans(
                    &mut row,
                    &[
                        "must_change_password",
                        "enabled",
                        "totp_enabled",
                        "cancel_requested",
                    ],
                )?;
                parse_json_fields(&mut row, &["tags_json"])?;
                self.add(&format!("linklake_{table}"), row);
            }
        }
        let mut tasks = Vec::new();
        for mut row in self.take("update_tasks") {
            booleans(&mut row, &["cancel_requested"])?;
            let mut snapshot = copy(
                &row,
                &[
                    "task_id",
                    "target_client_id",
                    "action",
                    "state",
                    "stage",
                    "recovery_state",
                    "requested_by",
                    "idempotency_key",
                    "attempt",
                    "cancel_requested",
                    "lease_owner",
                    "lease_deadline_unix_seconds",
                    "error_code",
                    "created_unix_seconds",
                    "updated_unix_seconds",
                    "completed_unix_seconds",
                ],
            )?;
            snapshot["schema_version"] =
                json!(linklake_core::remote_update::REMOTE_UPDATE_CONTRACT_VERSION);
            for (source, target) in [
                ("restart_binding_json", "restart"),
                ("result_json", "result"),
            ] {
                snapshot[target] = match row.get(source).and_then(Value::as_str) {
                    Some(value) => {
                        serde_json::from_str(value).map_err(|_| MigrationError::InvalidSource)?
                    }
                    None => Value::Null,
                };
            }
            let parsed: linklake_core::remote_update::RemoteUpdateTask =
                serde_json::from_value(snapshot.clone())
                    .map_err(|_| MigrationError::InvalidSource)?;
            parsed
                .validate()
                .map_err(|_| MigrationError::InvalidSource)?;
            let mut target = copy(
                &row,
                &[
                    "task_id",
                    "target_client_id",
                    "requested_by",
                    "idempotency_key",
                    "request_fingerprint",
                    "state",
                    "created_unix_seconds",
                    "lease_deadline_unix_seconds",
                    "lease_token_sha256",
                    "terminal_worker_instance_id",
                    "terminal_lease_token_sha256",
                    "terminal_report_sha256",
                ],
            )?;
            target["snapshot_json"] =
                json!(serde_json::to_string(&parsed).map_err(|_| MigrationError::InvalidSource)?);
            self.staged_bytes = self.staged_bytes.saturating_add(target.to_string().len());
            if self.staged_bytes > self.max_bytes {
                return Err(MigrationError::SnapshotTooLarge);
            }
            tasks.push(MigrationRow {
                table: "linklake_update_tasks".to_owned(),
                values: target,
            });
        }
        // 事件表外键不可延迟：任务行必须在事件之前插入。
        let index = self
            .rows
            .iter()
            .position(|row| row.table == "linklake_update_task_events")
            .unwrap_or(self.rows.len());
        self.rows.splice(index..index, tasks);
        Ok(())
    }

    fn policies(
        &mut self,
        public_ports: &crate::public_port_policy::PublicPortPolicy,
    ) -> Result<()> {
        for (source, target) in [
            ("http_route_policies", "linklake_http_route_policies"),
            ("sni_route_policies", "linklake_sni_route_policies"),
            ("secret_tunnel_policies", "linklake_secret_tunnel_policies"),
        ] {
            for mut policy in self.take(source) {
                booleans(&mut policy, &["enabled"])?;
                let mut row = match source {
                    "secret_tunnel_policies" => copy(
                        &policy,
                        &["id", "provider_client_id", "name", "access_key_hash"],
                    )?,
                    _ => copy(&policy, &["id", "hostname"])?,
                };
                policy
                    .as_object_mut()
                    .ok_or(MigrationError::InvalidSource)?
                    .remove("access_key_hash");
                match source {
                    "http_route_policies" => {
                        row["revision"] = json!(revision(source, &policy));
                        crate::http_route_catalog::postgres::decode_snapshot(
                            text(&policy, "id")?,
                            text(&policy, "hostname")?,
                            text(&row, "revision")?,
                            &policy.to_string(),
                        )
                        .map_err(|_| MigrationError::InvalidSource)?;
                    }
                    "sni_route_policies" => {
                        row["revision"] = json!(revision(source, &policy));
                        crate::sni_route_catalog::postgres::decode_policy(
                            text(&policy, "id")?,
                            text(&policy, "hostname")?,
                            &policy.to_string(),
                        )
                        .map_err(|_| MigrationError::InvalidSource)?;
                    }
                    _ => {
                        let typed: crate::secret_tunnel_catalog::SecretTunnelPolicy =
                            serde_json::from_value(policy.clone())
                                .map_err(|_| MigrationError::InvalidSource)?;
                        crate::secret_tunnel_catalog::postgres::validate_stored_policy(&typed)
                            .map_err(|_| MigrationError::InvalidSource)?;
                    }
                }
                row["policy"] = policy;
                self.add(target, row);
            }
        }
        let mappings = self.take("port_group_mappings");
        for (source, kind, protocol) in [
            ("tcp_tunnel_policies", "tcp", "tcp"),
            ("udp_tunnel_policies", "udp", "udp"),
            ("socks5_proxy_policies", "socks5_proxy", "both"),
            ("http_proxy_policies", "http_proxy", "tcp"),
            ("port_group_policies", "port_group", ""),
        ] {
            for mut policy in self.take(source) {
                booleans(&mut policy, &["enabled", "allow_private_networks"])?;
                let password = policy
                    .as_object_mut()
                    .ok_or(MigrationError::InvalidSource)?
                    .remove("password_hash")
                    .unwrap_or(Value::Null);
                let protocol = if kind == "port_group" {
                    text(&policy, "protocol")?.to_owned()
                } else {
                    protocol.to_owned()
                };
                use crate::tunnel_catalog::postgres::SharedTunnelPolicy;
                let shared = match kind {
                    "tcp" => SharedTunnelPolicy::Tcp(
                        serde_json::from_value(policy.clone())
                            .map_err(|_| MigrationError::InvalidSource)?,
                    ),
                    "udp" => SharedTunnelPolicy::Udp(
                        serde_json::from_value(policy.clone())
                            .map_err(|_| MigrationError::InvalidSource)?,
                    ),
                    "socks5_proxy" => SharedTunnelPolicy::Socks5(
                        serde_json::from_value(policy.clone())
                            .map_err(|_| MigrationError::InvalidSource)?,
                    ),
                    "http_proxy" => SharedTunnelPolicy::HttpProxy(
                        serde_json::from_value(policy.clone())
                            .map_err(|_| MigrationError::InvalidSource)?,
                    ),
                    _ => SharedTunnelPolicy::PortGroup(
                        serde_json::from_value(policy.clone())
                            .map_err(|_| MigrationError::InvalidSource)?,
                    ),
                };
                shared
                    .canonical(public_ports)
                    .map_err(|_| MigrationError::InvalidSource)?;
                let mut row = copy(&policy, &["id", "client_id", "name"])?;
                row["kind"] = json!(kind);
                row["protocol"] = json!(protocol);
                row["password_hash"] = password;
                row["policy"] = policy.clone();
                self.add("linklake_tunnel_policies", row);
                let ports = if kind == "port_group" {
                    let selected = mappings
                        .iter()
                        .filter(|mapping| mapping["policy_id"] == policy["id"])
                        .collect::<Vec<_>>();
                    let parsed = linklake_core::port_mapping::parse_port_mappings(
                        text(&policy, "public_ports")?,
                        text(&policy, "target_ports")?,
                        1,
                        u16::MAX,
                        linklake_core::port_mapping::MAX_PORT_MAPPINGS,
                    )
                    .map_err(|_| MigrationError::InvalidSource)?;
                    if selected.len()
                        != policy["mapping_count"]
                            .as_u64()
                            .ok_or(MigrationError::InvalidSource)?
                            as usize
                        || selected.len() != parsed.pairs.len()
                    {
                        return Err(MigrationError::InvalidSource);
                    }
                    for pair in &parsed.pairs {
                        let host = text(&policy, "target_host")?;
                        let target = if host.parse::<std::net::Ipv6Addr>().is_ok() {
                            format!("[{host}]:{}", pair.target_port)
                        } else {
                            format!("{host}:{}", pair.target_port)
                        };
                        if !selected.iter().any(|mapping| {
                            mapping["protocol"] == policy["protocol"]
                                && mapping["public_port"] == json!(pair.public_port)
                                && mapping["target_port"] == json!(pair.target_port)
                                && mapping["target_addr"] == json!(target)
                        }) {
                            return Err(MigrationError::InvalidSource);
                        }
                    }
                    selected
                        .into_iter()
                        .map(|mapping| mapping["public_port"].clone())
                        .collect::<Vec<_>>()
                } else {
                    vec![policy["public_port"].clone()]
                };
                for port in ports {
                    for transport in if protocol == "both" {
                        vec!["tcp", "udp"]
                    } else {
                        vec![protocol.as_str()]
                    } {
                        self.add("linklake_tunnel_ports",json!({"protocol":transport,"public_port":port,"policy_id":policy["id"]}));
                    }
                }
            }
        }
        Ok(())
    }

    fn traffic(&mut self) -> Result<()> {
        for mut source in self.take("traffic_controls") {
            booleans(&mut source, &["enabled"])?;
            parse_json_fields(
                &mut source,
                &["allowed_cidrs", "denied_cidrs", "active_weekdays_utc"],
            )?;
            let mut settings = source.clone();
            let object = settings
                .as_object_mut()
                .ok_or(MigrationError::InvalidSource)?;
            for field in ["kind", "policy_id", "updated_unix_seconds"] {
                object.remove(field);
            }
            let typed: crate::traffic_control::UpsertTrafficControl =
                serde_json::from_value(settings.clone())
                    .map_err(|_| MigrationError::InvalidSource)?;
            let normalized = crate::traffic_control::normalized_settings(typed)
                .map_err(|_| MigrationError::InvalidSource)?;
            if serde_json::to_value(normalized).map_err(|_| MigrationError::InvalidSource)?
                != settings
            {
                return Err(MigrationError::InvalidSource);
            }
            let mut row = copy(&source, &["kind", "policy_id", "updated_unix_seconds"])?;
            row["settings"] = settings;
            self.add("linklake_traffic_controls", row);
        }
        for row in self.take("traffic_daily_usage") {
            self.add("linklake_traffic_daily_usage", row);
        }
        let mut events = HashMap::new();
        for mut row in self.take("traffic_usage_events") {
            let id = text(&row, "event_id")?.to_owned();
            row["received_unix_seconds"] = json!(row["utc_day"]
                .as_u64()
                .ok_or(MigrationError::InvalidSource)?
                .checked_mul(86400)
                .ok_or(MigrationError::InvalidSource)?);
            row["applied"] = json!(true);
            events.insert(id, row);
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| MigrationError::InvalidSource)?
            .as_secs();
        for source in self.take("traffic_usage_spool") {
            let id = text(&source, "event_id")?.to_owned();
            if let Some(applied) = events.get(&id) {
                if ["kind", "policy_id", "bytes"]
                    .iter()
                    .any(|field| applied[*field] != source[*field])
                {
                    return Err(MigrationError::InvalidSource);
                }
                continue;
            }
            let mut row = copy(&source, &["event_id", "kind", "policy_id", "bytes"])?;
            row["utc_day"] = json!(now / 86400);
            row["received_unix_seconds"] = json!(now);
            row["applied"] = json!(false);
            events.insert(id, row);
        }
        for row in events.into_values() {
            self.add("linklake_traffic_usage_events", row);
        }
        Ok(())
    }

    fn fleet_health(&mut self) -> Result<()> {
        let configs = self.take("fleet_peer_health_config");
        let states = self.take("fleet_peer_health_state");
        if configs.len() != states.len() {
            return Err(MigrationError::InvalidSource);
        }
        for row in configs {
            let id = Uuid::parse_str(text(&row, "peer_id")?)
                .map_err(|_| MigrationError::InvalidSource)?;
            let snapshot = crate::fleet_health::read_snapshot(&self.source.connection, id)
                .map_err(|_| MigrationError::InvalidSource)?
                .ok_or(MigrationError::InvalidSource)?;
            self.add(
                "linklake_fleet_health",
                json!({"peer_id":id,"snapshot":snapshot}),
            );
        }
        for mut row in self.take("fleet_probe_events") {
            booleans(&mut row, &["success", "accepted"])?;
            self.add(
                "linklake_fleet_probe_events",
                copy(
                    &row,
                    &[
                        "event_id",
                        "peer_id",
                        "observed_unix_seconds",
                        "success",
                        "accepted",
                        "transition_reason",
                    ],
                )?,
            );
        }
        for row in self.take("fleet_health_counters") {
            self.add("linklake_fleet_health_counters", row);
        }
        let targets = self.take("fleet_dns_targets");
        for row in self.take("fleet_dns_failovers") {
            let id =
                Uuid::parse_str(text(&row, "id")?).map_err(|_| MigrationError::InvalidSource)?;
            let mut snapshot = crate::fleet_health::read_dns_failover(&self.source.connection, id)
                .map_err(|_| MigrationError::InvalidSource)?
                .ok_or(MigrationError::InvalidSource)?;
            for target in targets
                .iter()
                .filter(|target| target["failover_id"] == row["id"])
            {
                snapshot
                    .targets
                    .push(crate::fleet_health::FleetDnsPeerTarget {
                        peer_id: Uuid::parse_str(text(target, "peer_id")?)
                            .map_err(|_| MigrationError::InvalidSource)?,
                        value: text(target, "target_value")?.to_owned(),
                    });
            }
            snapshot.targets.sort_by_key(|target| target.peer_id);
            // 凭据由新部署提供；不把当前进程环境探测当作持久就绪状态。
            snapshot.token_configured = false;
            self.add("linklake_fleet_dns_failovers",json!({"id":id,"name":snapshot.name,"zone_id":snapshot.zone_id,"record_id":snapshot.record_id,"snapshot":snapshot}));
        }
        for mut row in self.take("fleet_dns_switch_events") {
            booleans(&mut row, &["applied"])?;
            let target = row
                .as_object_mut()
                .ok_or(MigrationError::InvalidSource)?
                .remove("target_value")
                .ok_or(MigrationError::InvalidSource)?;
            row["target"] = target;
            validate_model::<crate::fleet_health::FleetDnsSwitchEvent>(&row)?;
            self.add("linklake_fleet_dns_events",json!({"operation_id":row["operation_id"],"failover_id":row["failover_id"],"completed_unix_seconds":row["completed_unix_seconds"],"snapshot":row}));
        }
        Ok(())
    }

    fn observability(&mut self) -> Result<()> {
        let audit = self.take("audit_events");
        let retained = audit.len();
        for row in audit {
            self.add("linklake_audit_events", row);
        }
        self.add(
            "linklake_audit_retention",
            json!({"singleton_id":1,"retained_events":retained}),
        );
        for source in ["metrics_history_recent", "metrics_history_archive"] {
            for mut row in self.take(source) {
                let sample: Value = serde_json::from_str(text(&row, "sample_json")?)
                    .map_err(|_| MigrationError::InvalidSource)?;
                row.as_object_mut()
                    .ok_or(MigrationError::InvalidSource)?
                    .remove("sample_json");
                row["sample"] = sample;
                self.add(&format!("linklake_{source}"), row);
            }
        }
        for mut row in self.take("alert_rules") {
            booleans(&mut row, &["enabled", "notify_webhook", "notify_email"])?;
            validate_model::<crate::alerting::AlertRule>(&row)?;
            self.add("linklake_alert_rules", json!({"id":row["id"],"rule":row}));
        }
        for mut row in self.take("alert_events") {
            booleans(&mut row, &["active"])?;
            validate_model::<crate::alerting::AlertEvent>(&row)?;
            self.add("linklake_alert_events",json!({"id":row["id"],"rule_id":row["rule_id"],"subject":row["subject"],"active":row["active"],"updated_unix_seconds":row["updated_unix_seconds"],"event":row}));
        }
        for mut row in self.take("alert_notification_deliveries") {
            booleans(&mut row, &["resolved"])?;
            let payload: Value = serde_json::from_str(text(&row, "payload_json")?)
                .map_err(|_| MigrationError::InvalidSource)?;
            row.as_object_mut()
                .ok_or(MigrationError::InvalidSource)?
                .remove("payload_json");
            row["payload"] = payload;
            if !row["lease_expires_unix_seconds"].is_null() || !row["lease_token"].is_null() {
                return Err(MigrationError::PendingExternalOperations);
            }
            self.add("linklake_alert_deliveries", row);
        }
        let counters = self.take("alert_notification_delivery_counters");
        if counters.is_empty() {
            self.add("linklake_alert_delivery_counters",json!({"singleton_id":1,"defaults_initialized":true,"delivered_total":0,"failed_attempts_total":0,"dead_letter_total":0}));
        } else {
            for mut row in counters {
                let id = row
                    .as_object_mut()
                    .ok_or(MigrationError::InvalidSource)?
                    .remove("singleton")
                    .ok_or(MigrationError::InvalidSource)?;
                row["singleton_id"] = id;
                row["defaults_initialized"] = json!(true);
                self.add("linklake_alert_delivery_counters", row);
            }
        }
        Ok(())
    }

    fn certificates(
        &mut self,
        cipher: &CertificateMaterialCipher,
        options: &MigrationSourceOptions,
    ) -> Result<()> {
        let configs = self.take("acme_config");
        if configs.len() != 1 {
            return Err(MigrationError::InvalidSource);
        }
        let mut config = configs[0].clone();
        config
            .as_object_mut()
            .ok_or(MigrationError::InvalidSource)?
            .remove("singleton_id");
        booleans(&mut config, &["enabled", "terms_accepted"])?;
        validate_model::<crate::certificate_catalog::AcmeConfig>(&config)?;
        self.add(
            "linklake_acme_config",
            json!({"singleton_id":1,"config":config}),
        );
        let routes = self.take("http_route_tls_policies");
        for mut policy in routes.clone() {
            booleans(&mut policy, &["redirect_http_to_https"])?;
            validate_model::<crate::certificate_catalog::RouteTlsPolicy>(&policy)?;
            self.add("linklake_route_tls",json!({"route_id":policy["route_id"],"revision":revision("tls",&policy),"policy":policy}));
        }
        let states = self.take("certificate_states");
        for state in states.clone() {
            validate_model::<crate::certificate_catalog::CertificateState>(&state)?;
            self.add(
                "linklake_certificate_states",
                json!({"route_id":state["route_id"],"state":state}),
            );
        }
        self.add(
            "linklake_certificate_key_binding",
            json!({"singleton_id":1,"fingerprint":cipher.fingerprint()}),
        );
        materials::import(self, cipher, &config, &routes, &states, options)
    }

    fn validate_references(&self) -> Result<()> {
        let clients = self
            .tables
            .get("clients")
            .into_iter()
            .flatten()
            .map(|row| text(row, "client_id"))
            .collect::<Result<BTreeSet<_>>>()?;
        let mut policies = BTreeSet::new();
        for (table, kind) in [
            ("tcp_tunnel_policies", "tcp"),
            ("udp_tunnel_policies", "udp"),
            ("port_group_policies", "port_group"),
            ("http_route_policies", "http_route"),
            ("sni_route_policies", "sni_route"),
            ("secret_tunnel_policies", "secret_tunnel"),
            ("socks5_proxy_policies", "socks5_proxy"),
            ("http_proxy_policies", "http_proxy"),
        ] {
            for row in self.tables.get(table).into_iter().flatten() {
                let id = text(row, "id")?;
                let parsed = Uuid::parse_str(id).map_err(|_| MigrationError::InvalidSource)?;
                if parsed.is_nil() || parsed.to_string() != id {
                    return Err(MigrationError::InvalidSource);
                }
                policies.insert((kind, id));
                let client = if kind == "secret_tunnel" {
                    "provider_client_id"
                } else {
                    "client_id"
                };
                if !clients.contains(text(row, client)?) {
                    return Err(MigrationError::InvalidSource);
                }
                if let Some(allowed) = row.get("allowed_client_id").and_then(Value::as_str) {
                    if !clients.contains(allowed) {
                        return Err(MigrationError::InvalidSource);
                    }
                }
            }
        }
        let ownership = self
            .tables
            .get("fleet_resource_ownership")
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let bindings = self
            .tables
            .get("fleet_credential_bindings")
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        for owner in ownership {
            if !self
                .tables
                .get("fleet_source_states")
                .into_iter()
                .flatten()
                .any(|source| source["source_instance_id"] == owner["source_instance_id"])
            {
                return Err(MigrationError::InvalidSource);
            }
            if !policies.contains(&(text(owner, "kind")?, text(owner, "policy_id")?)) {
                return Err(MigrationError::InvalidSource);
            }
            if let Some(reference) = owner.get("credential_ref").and_then(Value::as_str) {
                if !bindings.iter().any(|binding| {
                    binding["source_instance_id"] == owner["source_instance_id"]
                        && binding["credential_ref"] == reference
                        && binding["kind"] == owner["kind"]
                        && binding["policy_id"] == owner["policy_id"]
                }) {
                    return Err(MigrationError::InvalidSource);
                }
            }
        }
        for binding in bindings {
            if !policies.contains(&(text(binding, "kind")?, text(binding, "policy_id")?)) {
                return Err(MigrationError::InvalidSource);
            }
        }
        for source in self.tables.get("fleet_source_states").into_iter().flatten() {
            let owned = ownership
                .iter()
                .filter(|owner| owner["source_instance_id"] == source["source_instance_id"])
                .count();
            if source["resource_count"].as_u64() != Some(owned as u64) {
                return Err(MigrationError::InvalidSource);
            }
        }
        for row in self.tables.get("port_group_mappings").into_iter().flatten() {
            if !policies.contains(&("port_group", text(row, "policy_id")?)) {
                return Err(MigrationError::InvalidSource);
            }
        }
        for target in self.tables.get("fleet_dns_targets").into_iter().flatten() {
            if !self
                .tables
                .get("fleet_dns_failovers")
                .into_iter()
                .flatten()
                .any(|row| row["id"] == target["failover_id"])
                || !self
                    .tables
                    .get("fleet_peers")
                    .into_iter()
                    .flatten()
                    .any(|row| row["id"] == target["peer_id"])
            {
                return Err(MigrationError::InvalidSource);
            }
        }
        for row in self.tables.get("traffic_controls").into_iter().flatten() {
            let kind = match text(row, "kind")? {
                "http" => "http_route",
                "sni" => "sni_route",
                "secret" => "secret_tunnel",
                "socks5" => "socks5_proxy",
                kind => kind,
            };
            if !policies.contains(&(kind, text(row, "policy_id")?)) {
                return Err(MigrationError::InvalidSource);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_preserves_full_u64_usage_and_binary_token_hash() {
        let connection = Connection::open_in_memory().unwrap();
        connection.execute_batch("CREATE TABLE traffic_daily_usage(bytes INTEGER); CREATE TABLE traffic_usage_events(bytes TEXT); CREATE TABLE management_api_tokens(token_hash BLOB);").unwrap();
        connection
            .execute(
                "INSERT INTO traffic_usage_events VALUES(?1)",
                [u64::MAX.to_string()],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO traffic_daily_usage VALUES(?1)",
                [u64::MAX.to_be_bytes().as_slice()],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO management_api_tokens VALUES(?1)",
                [&[0u8, 15, 255][..]],
            )
            .unwrap();
        let tables = read_tables(&connection, 4096).unwrap();
        assert_eq!(
            tables["traffic_daily_usage"][0]["bytes"].as_u64(),
            Some(u64::MAX)
        );
        assert_eq!(
            tables["traffic_usage_events"][0]["bytes"].as_u64(),
            Some(u64::MAX)
        );
        assert_eq!(
            tables["management_api_tokens"][0]["token_hash"],
            "\\x000fff"
        );
    }

    #[test]
    fn snapshot_limit_rejects_instead_of_returning_partial_rows() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE clients(name TEXT); INSERT INTO clients VALUES('a'),('b');",
            )
            .unwrap();
        assert_eq!(
            read_tables(&connection, 13).unwrap_err(),
            MigrationError::SnapshotTooLarge
        );
    }

    #[test]
    fn invalid_sqlite_boolean_cannot_become_an_enabled_policy() {
        let mut row = json!({"enabled":2});
        assert_eq!(
            booleans(&mut row, &["enabled"]),
            Err(MigrationError::InvalidSource)
        );
        let mut disabled = json!({"enabled":0});
        booleans(&mut disabled, &["enabled"]).unwrap();
        assert_eq!(disabled["enabled"], false);
    }
}
