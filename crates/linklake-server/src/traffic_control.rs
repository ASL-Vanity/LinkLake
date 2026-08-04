//! 转发策略的来源过滤、连接速率、日流量配额与时间计划。

use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    net::IpAddr,
    path::Path,
};
use uuid::Uuid;

use crate::database::Database;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TrafficPolicyKind {
    Tcp,
    Udp,
    Http,
    Sni,
    Secret,
    Socks5,
    HttpProxy,
    PortGroup,
}

impl TrafficPolicyKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Http => "http",
            Self::Sni => "sni",
            Self::Secret => "secret",
            Self::Socks5 => "socks5",
            Self::HttpProxy => "http_proxy",
            Self::PortGroup => "port_group",
        }
    }

    pub(crate) fn parse(value: &str) -> anyhow::Result<Self> {
        match value {
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            "http" => Ok(Self::Http),
            "sni" => Ok(Self::Sni),
            "secret" => Ok(Self::Secret),
            "socks5" => Ok(Self::Socks5),
            "http_proxy" | "http-proxy" => Ok(Self::HttpProxy),
            "port_group" | "ports" => Ok(Self::PortGroup),
            _ => anyhow::bail!("invalid traffic policy kind"),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct UpsertTrafficControl {
    #[serde(default)]
    pub(crate) allowed_cidrs: Vec<String>,
    #[serde(default)]
    pub(crate) denied_cidrs: Vec<String>,
    pub(crate) max_connections_per_minute: Option<u32>,
    pub(crate) daily_quota_bytes: Option<u64>,
    #[serde(default)]
    pub(crate) active_weekdays_utc: Vec<u8>,
    pub(crate) start_minute_utc: Option<u16>,
    pub(crate) end_minute_utc: Option<u16>,
    #[serde(default = "default_true")]
    pub(crate) enabled: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct TrafficControlRecord {
    pub(crate) kind: TrafficPolicyKind,
    pub(crate) policy_id: Uuid,
    #[serde(flatten)]
    pub(crate) settings: UpsertTrafficControl,
    pub(crate) used_today_bytes: u64,
    pub(crate) updated_unix_seconds: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TrafficDecision {
    Allowed,
    SourceDenied,
    OutsideSchedule,
    RateLimited,
    QuotaExceeded,
}

pub(crate) struct TrafficControlCatalog {
    database: Connection,
    connection_windows: HashMap<(TrafficPolicyKind, Uuid), VecDeque<u64>>,
}

impl TrafficControlCatalog {
    #[allow(dead_code)]
    pub(crate) fn open(data_dir: Option<&Path>) -> anyhow::Result<Self> {
        let database = Database::open(data_dir)?;
        Self::open_with_database(&database)
    }

    pub(crate) fn open_with_database(database: &Database) -> anyhow::Result<Self> {
        let database = database.connect()?;
        database.execute_batch(
            "CREATE TABLE IF NOT EXISTS traffic_controls (
                kind TEXT NOT NULL,
                policy_id TEXT NOT NULL,
                allowed_cidrs TEXT NOT NULL,
                denied_cidrs TEXT NOT NULL,
                max_connections_per_minute INTEGER,
                daily_quota_bytes INTEGER,
                active_weekdays_utc TEXT NOT NULL,
                start_minute_utc INTEGER,
                end_minute_utc INTEGER,
                enabled INTEGER NOT NULL,
                updated_unix_seconds INTEGER NOT NULL,
                PRIMARY KEY(kind, policy_id)
            );
            CREATE TABLE IF NOT EXISTS traffic_daily_usage (
                kind TEXT NOT NULL,
                policy_id TEXT NOT NULL,
                utc_day INTEGER NOT NULL,
                bytes INTEGER NOT NULL,
                PRIMARY KEY(kind, policy_id, utc_day)
            );",
        )?;
        Ok(Self {
            database,
            connection_windows: HashMap::new(),
        })
    }

    pub(crate) fn get(
        &self,
        kind: TrafficPolicyKind,
        policy_id: Uuid,
        now: u64,
    ) -> anyhow::Result<Option<TrafficControlRecord>> {
        self.database
            .query_row(
                "SELECT allowed_cidrs, denied_cidrs, max_connections_per_minute, daily_quota_bytes, active_weekdays_utc, start_minute_utc, end_minute_utc, enabled, updated_unix_seconds FROM traffic_controls WHERE kind = ?1 AND policy_id = ?2",
                params![kind.as_str(), policy_id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, Option<u32>>(2)?,
                        row.get::<_, Option<u64>>(3)?, row.get::<_, String>(4)?, row.get::<_, Option<u16>>(5)?,
                        row.get::<_, Option<u16>>(6)?, row.get::<_, i64>(7)? != 0, row.get::<_, u64>(8)?,
                    ))
                },
            )
            .optional()?
            .map(|(allowed, denied, rate, quota, weekdays, start, end, enabled, updated)| {
                Ok(TrafficControlRecord {
                    kind,
                    policy_id,
                    settings: UpsertTrafficControl {
                        allowed_cidrs: serde_json::from_str(&allowed)?,
                        denied_cidrs: serde_json::from_str(&denied)?,
                        max_connections_per_minute: rate,
                        daily_quota_bytes: quota,
                        active_weekdays_utc: serde_json::from_str(&weekdays)?,
                        start_minute_utc: start,
                        end_minute_utc: end,
                        enabled,
                    },
                    used_today_bytes: self.usage(kind, policy_id, utc_day(now))?,
                    updated_unix_seconds: updated,
                })
            })
            .transpose()
    }

    pub(crate) fn upsert(
        &mut self,
        kind: TrafficPolicyKind,
        policy_id: Uuid,
        request: UpsertTrafficControl,
        now: u64,
    ) -> anyhow::Result<TrafficControlRecord> {
        validate(&request)?;
        let allowed = normalize_cidrs(&request.allowed_cidrs)?;
        let denied = normalize_cidrs(&request.denied_cidrs)?;
        let mut weekdays = request.active_weekdays_utc.clone();
        weekdays.sort_unstable();
        weekdays.dedup();
        let settings = UpsertTrafficControl {
            allowed_cidrs: allowed,
            denied_cidrs: denied,
            active_weekdays_utc: weekdays,
            ..request
        };
        self.database.execute(
            "INSERT INTO traffic_controls (kind, policy_id, allowed_cidrs, denied_cidrs, max_connections_per_minute, daily_quota_bytes, active_weekdays_utc, start_minute_utc, end_minute_utc, enabled, updated_unix_seconds)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(kind, policy_id) DO UPDATE SET allowed_cidrs=excluded.allowed_cidrs, denied_cidrs=excluded.denied_cidrs, max_connections_per_minute=excluded.max_connections_per_minute, daily_quota_bytes=excluded.daily_quota_bytes, active_weekdays_utc=excluded.active_weekdays_utc, start_minute_utc=excluded.start_minute_utc, end_minute_utc=excluded.end_minute_utc, enabled=excluded.enabled, updated_unix_seconds=excluded.updated_unix_seconds",
            params![kind.as_str(), policy_id.to_string(), serde_json::to_string(&settings.allowed_cidrs)?, serde_json::to_string(&settings.denied_cidrs)?, settings.max_connections_per_minute, settings.daily_quota_bytes, serde_json::to_string(&settings.active_weekdays_utc)?, settings.start_minute_utc, settings.end_minute_utc, settings.enabled, now],
        )?;
        self.connection_windows.remove(&(kind, policy_id));
        self.get(kind, policy_id, now)?
            .ok_or_else(|| anyhow::anyhow!("traffic control could not be read after update"))
    }

    pub(crate) fn delete(
        &mut self,
        kind: TrafficPolicyKind,
        policy_id: Uuid,
    ) -> anyhow::Result<bool> {
        self.connection_windows.remove(&(kind, policy_id));
        Ok(self.database.execute(
            "DELETE FROM traffic_controls WHERE kind = ?1 AND policy_id = ?2",
            params![kind.as_str(), policy_id.to_string()],
        )? > 0)
    }

    /// Fleet 原子提交后丢弃进程内速率窗口；持久化日配额仍保留在 SQLite 中。
    pub(crate) fn reset_runtime_state(&mut self) {
        self.connection_windows.clear();
    }

    pub(crate) fn authorize(
        &mut self,
        kind: TrafficPolicyKind,
        policy_id: Uuid,
        source: IpAddr,
        now: u64,
    ) -> anyhow::Result<TrafficDecision> {
        let Some(record) = self.get(kind, policy_id, now)? else {
            return Ok(TrafficDecision::Allowed);
        };
        let settings = record.settings;
        if !settings.enabled {
            return Ok(TrafficDecision::Allowed);
        }
        if settings
            .denied_cidrs
            .iter()
            .any(|cidr| cidr_matches(cidr, source))
            || (!settings.allowed_cidrs.is_empty()
                && !settings
                    .allowed_cidrs
                    .iter()
                    .any(|cidr| cidr_matches(cidr, source)))
        {
            return Ok(TrafficDecision::SourceDenied);
        }
        if !schedule_allows(&settings, now) {
            return Ok(TrafficDecision::OutsideSchedule);
        }
        if settings
            .daily_quota_bytes
            .is_some_and(|quota| record.used_today_bytes >= quota)
        {
            return Ok(TrafficDecision::QuotaExceeded);
        }
        if let Some(limit) = settings.max_connections_per_minute {
            let window = self
                .connection_windows
                .entry((kind, policy_id))
                .or_default();
            while window
                .front()
                .is_some_and(|timestamp| timestamp.saturating_add(60) <= now)
            {
                window.pop_front();
            }
            if window.len() >= limit as usize {
                return Ok(TrafficDecision::RateLimited);
            }
            window.push_back(now);
        }
        Ok(TrafficDecision::Allowed)
    }

    pub(crate) fn record_bytes(
        &mut self,
        kind: TrafficPolicyKind,
        policy_id: Uuid,
        bytes: u64,
        now: u64,
    ) -> anyhow::Result<()> {
        if bytes == 0 {
            return Ok(());
        }
        self.database.execute(
            "INSERT INTO traffic_daily_usage (kind, policy_id, utc_day, bytes) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(kind, policy_id, utc_day) DO UPDATE SET bytes = bytes + excluded.bytes",
            params![kind.as_str(), policy_id.to_string(), utc_day(now), bytes],
        )?;
        Ok(())
    }

    fn usage(&self, kind: TrafficPolicyKind, policy_id: Uuid, day: u64) -> anyhow::Result<u64> {
        Ok(self.database.query_row(
            "SELECT COALESCE((SELECT bytes FROM traffic_daily_usage WHERE kind = ?1 AND policy_id = ?2 AND utc_day = ?3), 0)",
            params![kind.as_str(), policy_id.to_string(), day],
            |row| row.get(0),
        )?)
    }
}

fn validate(request: &UpsertTrafficControl) -> anyhow::Result<()> {
    anyhow::ensure!(
        request.allowed_cidrs.len() <= 64 && request.denied_cidrs.len() <= 64,
        "too many CIDR entries"
    );
    normalize_cidrs(&request.allowed_cidrs)?;
    normalize_cidrs(&request.denied_cidrs)?;
    anyhow::ensure!(
        request
            .max_connections_per_minute
            .is_none_or(|value| (1..=1_000_000).contains(&value)),
        "connection rate is invalid"
    );
    anyhow::ensure!(
        request.daily_quota_bytes.is_none_or(|value| value >= 1024),
        "daily quota is invalid"
    );
    anyhow::ensure!(
        request.active_weekdays_utc.iter().all(|value| *value <= 6),
        "weekday is invalid"
    );
    anyhow::ensure!(
        request.start_minute_utc.is_some() == request.end_minute_utc.is_some(),
        "schedule window is incomplete"
    );
    anyhow::ensure!(
        request.start_minute_utc.is_none_or(|value| value < 1440)
            && request.end_minute_utc.is_none_or(|value| value < 1440),
        "schedule minute is invalid"
    );
    Ok(())
}

fn normalize_cidrs(values: &[String]) -> anyhow::Result<Vec<String>> {
    values
        .iter()
        .map(|value| parse_cidr(value).map(|cidr| cidr.normalized()))
        .collect()
}

#[derive(Clone, Copy)]
struct Cidr {
    address: IpAddr,
    prefix: u8,
}

impl Cidr {
    fn normalized(self) -> String {
        format!("{}/{}", self.address, self.prefix)
    }
}

fn parse_cidr(value: &str) -> anyhow::Result<Cidr> {
    let (address, prefix) = match value.trim().split_once('/') {
        Some((address, prefix)) => (address.parse::<IpAddr>()?, prefix.parse::<u8>()?),
        None => {
            let address = value.trim().parse::<IpAddr>()?;
            let prefix = if address.is_ipv4() { 32 } else { 128 };
            return Ok(Cidr { address, prefix });
        }
    };
    anyhow::ensure!(
        prefix <= if address.is_ipv4() { 32 } else { 128 },
        "CIDR prefix is invalid"
    );
    Ok(Cidr { address, prefix })
}

fn cidr_matches(value: &str, source: IpAddr) -> bool {
    let Ok(cidr) = parse_cidr(value) else {
        return false;
    };
    match (cidr.address, source) {
        (IpAddr::V4(network), IpAddr::V4(source)) => {
            let mask = if cidr.prefix == 0 {
                0
            } else {
                u32::MAX << (32 - cidr.prefix)
            };
            u32::from(network) & mask == u32::from(source) & mask
        }
        (IpAddr::V6(network), IpAddr::V6(source)) => {
            let mask = if cidr.prefix == 0 {
                0
            } else {
                u128::MAX << (128 - cidr.prefix)
            };
            u128::from(network) & mask == u128::from(source) & mask
        }
        _ => false,
    }
}

fn schedule_allows(settings: &UpsertTrafficControl, now: u64) -> bool {
    let day = now / 86_400;
    let weekday = ((day + 3) % 7) as u8; // 1970-01-01 是周四，周一为 0。
    if !settings.active_weekdays_utc.is_empty() && !settings.active_weekdays_utc.contains(&weekday)
    {
        return false;
    }
    let (Some(start), Some(end)) = (settings.start_minute_utc, settings.end_minute_utc) else {
        return true;
    };
    let minute = ((now % 86_400) / 60) as u16;
    if start == end {
        true
    } else if start < end {
        (start..end).contains(&minute)
    } else {
        minute >= start || minute < end
    }
}

fn utc_day(now: u64) -> u64 {
    now / 86_400
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> UpsertTrafficControl {
        UpsertTrafficControl {
            allowed_cidrs: vec!["10.0.0.0/8".into()],
            denied_cidrs: vec!["10.1.0.0/16".into()],
            max_connections_per_minute: Some(2),
            daily_quota_bytes: Some(1024),
            active_weekdays_utc: vec![],
            start_minute_utc: None,
            end_minute_utc: None,
            enabled: true,
        }
    }

    #[test]
    fn source_rate_and_persistent_quota_are_enforced() {
        let mut catalog = TrafficControlCatalog::open(None).unwrap();
        let id = Uuid::new_v4();
        catalog
            .upsert(TrafficPolicyKind::Tcp, id, settings(), 100)
            .unwrap();
        assert_eq!(
            catalog
                .authorize(TrafficPolicyKind::Tcp, id, "10.1.2.3".parse().unwrap(), 100)
                .unwrap(),
            TrafficDecision::SourceDenied
        );
        assert_eq!(
            catalog
                .authorize(TrafficPolicyKind::Tcp, id, "10.2.2.3".parse().unwrap(), 100)
                .unwrap(),
            TrafficDecision::Allowed
        );
        assert_eq!(
            catalog
                .authorize(TrafficPolicyKind::Tcp, id, "10.2.2.4".parse().unwrap(), 101)
                .unwrap(),
            TrafficDecision::Allowed
        );
        assert_eq!(
            catalog
                .authorize(TrafficPolicyKind::Tcp, id, "10.2.2.5".parse().unwrap(), 102)
                .unwrap(),
            TrafficDecision::RateLimited
        );
        catalog
            .record_bytes(TrafficPolicyKind::Tcp, id, 1024, 103)
            .unwrap();
        assert_eq!(
            catalog
                .authorize(TrafficPolicyKind::Tcp, id, "10.2.2.6".parse().unwrap(), 161)
                .unwrap(),
            TrafficDecision::QuotaExceeded
        );
    }
}
