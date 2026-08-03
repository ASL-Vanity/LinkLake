//! HTTP 后端传输与连接池的共享状态契约。
//!
//! 本模块只维护可确定性测试的元数据，不持有套接字或 Hyper sender。
//! HTTP/2 与正向代理后续会按这里返回的连接标识管理实际传输对象；
//! 因此引入本模块不会改变当前 HTTP/1 路由行为。

use linklake_core::BoxedIo;
use std::{
    collections::{HashMap, HashSet},
    error::Error,
    fmt,
    future::Future,
    net::{IpAddr, SocketAddr},
    num::NonZeroUsize,
    pin::Pin,
    str::FromStr,
    time::{Duration, Instant},
};
use uuid::Uuid;

/// 建立一条真实后端传输时使用的异步返回类型。
pub type BackendConnectFuture<'a, E> =
    Pin<Box<dyn Future<Output = Result<BoxedIo, E>> + Send + 'a>>;

/// 将连接池与 LinkLake 控制通道解耦的后端连接契约。
pub trait BackendConnector: Send + Sync {
    type Error: Error + Send + Sync + 'static;

    fn connect<'a>(&'a self, origin: &'a OriginKey) -> BackendConnectFuture<'a, Self::Error>;
}

/// 已协商并用于连接复用的 HTTP 协议。
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BackendProtocol {
    Http1,
    Http2,
}

/// 后端传输是否额外使用 TLS。
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum BackendSecurity {
    Plaintext,
    Tls { server_name: Box<str> },
}

impl BackendSecurity {
    pub fn tls(server_name: &str) -> Result<Self, OriginKeyError> {
        Ok(Self::Tls {
            server_name: normalize_server_name(server_name)?.into_boxed_str(),
        })
    }
}

/// 一个可复用后端连接的完整隔离键。
///
/// 策略、目标地址、HTTP 版本或 TLS 身份任一不同，都不能共享连接。
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct OriginKey {
    policy_id: Uuid,
    authority: Box<str>,
    protocol: BackendProtocol,
    security: BackendSecurity,
}

impl OriginKey {
    pub fn new(
        policy_id: Uuid,
        authority: &str,
        protocol: BackendProtocol,
        security: BackendSecurity,
    ) -> Result<Self, OriginKeyError> {
        Ok(Self {
            policy_id,
            authority: normalize_authority(authority)?.into_boxed_str(),
            protocol,
            security,
        })
    }

    pub fn policy_id(&self) -> Uuid {
        self.policy_id
    }

    pub fn authority(&self) -> &str {
        &self.authority
    }

    pub fn protocol(&self) -> BackendProtocol {
        self.protocol
    }

    pub fn security(&self) -> &BackendSecurity {
        &self.security
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OriginKeyError {
    InvalidAuthority,
    InvalidServerName,
}

impl fmt::Display for OriginKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidAuthority => "HTTP backend authority is invalid",
            Self::InvalidServerName => "HTTP backend TLS server name is invalid",
        })
    }
}

impl Error for OriginKeyError {}

/// 一条连接能够被借出的方式。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendConnectionMode {
    /// HTTP/1 连接同一时间只能处理一个请求。
    Exclusive,
    /// HTTP/2 连接可同时承载多个流。
    Multiplexed {
        max_concurrent_streams: NonZeroUsize,
    },
}

impl BackendConnectionMode {
    fn capacity(self) -> usize {
        match self {
            Self::Exclusive => 1,
            Self::Multiplexed {
                max_concurrent_streams,
            } => max_concurrent_streams.get(),
        }
    }
}

/// 连接池容量与空闲回收限制。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackendPoolLimits {
    pub max_connections: NonZeroUsize,
    pub max_connections_per_origin: NonZeroUsize,
    pub idle_timeout: Duration,
}

impl BackendPoolLimits {
    pub fn new(
        max_connections: NonZeroUsize,
        max_connections_per_origin: NonZeroUsize,
        idle_timeout: Duration,
    ) -> Result<Self, BackendPoolLimitsError> {
        if max_connections_per_origin > max_connections {
            return Err(BackendPoolLimitsError::OriginLimitExceedsGlobalLimit);
        }
        if idle_timeout.is_zero() {
            return Err(BackendPoolLimitsError::ZeroIdleTimeout);
        }
        Ok(Self {
            max_connections,
            max_connections_per_origin,
            idle_timeout,
        })
    }
}

impl Default for BackendPoolLimits {
    fn default() -> Self {
        Self {
            max_connections: NonZeroUsize::new(512).expect("static pool limit is non-zero"),
            max_connections_per_origin: NonZeroUsize::new(8)
                .expect("static origin pool limit is non-zero"),
            idle_timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendPoolLimitsError {
    OriginLimitExceedsGlobalLimit,
    ZeroIdleTimeout,
}

impl fmt::Display for BackendPoolLimitsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::OriginLimitExceedsGlobalLimit => {
                "per-origin HTTP backend limit exceeds the global limit"
            }
            Self::ZeroIdleTimeout => "HTTP backend idle timeout must be greater than zero",
        })
    }
}

impl Error for BackendPoolLimitsError {}

/// 池内连接的稳定标识；实际传输对象应使用同一标识存放在运行时表中。
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BackendConnectionId(u64);

impl BackendConnectionId {
    pub fn get(self) -> u64 {
        self.0
    }
}

/// 容量回收、超时和协议事件导致连接离池的原因。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendRemovalReason {
    GlobalCapacity,
    OriginCapacity,
    IdleTimeout,
    PolicyInvalidated,
    Disconnected,
    GoAway,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendRemoval {
    pub connection_id: BackendConnectionId,
    pub origin: OriginKey,
    pub reason: BackendRemovalReason,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendRegistration {
    pub connection_id: BackendConnectionId,
    pub removals: Vec<BackendRemoval>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackendLease {
    pub connection_id: BackendConnectionId,
    pub origin: OriginKey,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendRegisterError {
    CapacityBusy,
}

impl fmt::Display for BackendRegisterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("all HTTP backend connections are busy")
    }
}

impl Error for BackendRegisterError {}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BackendPoolSnapshot {
    pub connections: usize,
    pub origins: usize,
    pub active_streams: usize,
    pub draining_connections: usize,
}

#[derive(Debug)]
struct BackendEntry {
    origin: OriginKey,
    mode: BackendConnectionMode,
    active_streams: usize,
    last_activity: Instant,
    draining: bool,
}

impl BackendEntry {
    fn available(&self) -> bool {
        !self.draining && self.active_streams < self.mode.capacity()
    }

    fn idle(&self) -> bool {
        self.active_streams == 0
    }
}

/// 后端连接池的纯状态机。
///
/// 所有方法都是同步且不执行网络 I/O，便于对容量、失效和协议事件做确定性测试。
#[derive(Debug)]
pub struct BackendPoolState {
    limits: BackendPoolLimits,
    next_connection_id: u64,
    entries: HashMap<BackendConnectionId, BackendEntry>,
}

impl BackendPoolState {
    pub fn new(limits: BackendPoolLimits) -> Self {
        Self {
            limits,
            next_connection_id: 1,
            entries: HashMap::new(),
        }
    }

    pub fn register(
        &mut self,
        origin: OriginKey,
        mode: BackendConnectionMode,
        now: Instant,
    ) -> Result<BackendRegistration, BackendRegisterError> {
        let mut removals = Vec::new();
        while self.connection_count_for_origin(&origin)
            >= self.limits.max_connections_per_origin.get()
        {
            let Some(connection_id) = self.oldest_idle(Some(&origin)) else {
                return Err(BackendRegisterError::CapacityBusy);
            };
            if let Some(removal) = self.remove(connection_id, BackendRemovalReason::OriginCapacity)
            {
                removals.push(removal);
            }
        }
        while self.entries.len() >= self.limits.max_connections.get() {
            let Some(connection_id) = self.oldest_idle(None) else {
                return Err(BackendRegisterError::CapacityBusy);
            };
            if let Some(removal) = self.remove(connection_id, BackendRemovalReason::GlobalCapacity)
            {
                removals.push(removal);
            }
        }

        let connection_id = self.next_available_connection_id();
        self.entries.insert(
            connection_id,
            BackendEntry {
                origin,
                mode,
                active_streams: 0,
                last_activity: now,
                draining: false,
            },
        );
        Ok(BackendRegistration {
            connection_id,
            removals,
        })
    }

    pub fn acquire(&mut self, origin: &OriginKey, now: Instant) -> Option<BackendLease> {
        let connection_id = self
            .entries
            .iter()
            .filter(|(_, entry)| &entry.origin == origin && entry.available())
            .min_by_key(|(connection_id, entry)| {
                (
                    entry.active_streams,
                    std::cmp::Reverse(entry.last_activity),
                    **connection_id,
                )
            })
            .map(|(connection_id, _)| *connection_id)?;
        let entry = self
            .entries
            .get_mut(&connection_id)
            .expect("selected backend connection must still exist");
        entry.active_streams += 1;
        entry.last_activity = now;
        Some(BackendLease {
            connection_id,
            origin: entry.origin.clone(),
        })
    }

    /// 释放一次请求或 HTTP/2 流；若连接已进入 draining，则最后一个流退出时移除。
    pub fn release(
        &mut self,
        connection_id: BackendConnectionId,
        now: Instant,
    ) -> Option<BackendRemoval> {
        let entry = self.entries.get_mut(&connection_id)?;
        if entry.active_streams == 0 {
            return None;
        }
        entry.active_streams -= 1;
        entry.last_activity = now;
        if entry.draining && entry.active_streams == 0 {
            return self.remove(connection_id, BackendRemovalReason::GoAway);
        }
        None
    }

    /// 收到 HTTP/2 GOAWAY 后停止分配新流；没有活动流时立即移除。
    pub fn mark_goaway(&mut self, connection_id: BackendConnectionId) -> Option<BackendRemoval> {
        let entry = self.entries.get_mut(&connection_id)?;
        if entry.active_streams == 0 {
            return self.remove(connection_id, BackendRemovalReason::GoAway);
        }
        entry.draining = true;
        None
    }

    pub fn disconnected(&mut self, connection_id: BackendConnectionId) -> Option<BackendRemoval> {
        self.remove(connection_id, BackendRemovalReason::Disconnected)
    }

    pub fn invalidate_policy(&mut self, policy_id: Uuid) -> Vec<BackendRemoval> {
        let connection_ids = self
            .entries
            .iter()
            .filter_map(|(connection_id, entry)| {
                (entry.origin.policy_id() == policy_id).then_some(*connection_id)
            })
            .collect::<Vec<_>>();
        connection_ids
            .into_iter()
            .filter_map(|connection_id| {
                self.remove(connection_id, BackendRemovalReason::PolicyInvalidated)
            })
            .collect()
    }

    pub fn prune_idle(&mut self, now: Instant) -> Vec<BackendRemoval> {
        let idle_timeout = self.limits.idle_timeout;
        let connection_ids = self
            .entries
            .iter()
            .filter_map(|(connection_id, entry)| {
                (entry.idle()
                    && now
                        .checked_duration_since(entry.last_activity)
                        .is_some_and(|idle| idle >= idle_timeout))
                .then_some(*connection_id)
            })
            .collect::<Vec<_>>();
        connection_ids
            .into_iter()
            .filter_map(|connection_id| {
                self.remove(connection_id, BackendRemovalReason::IdleTimeout)
            })
            .collect()
    }

    pub fn snapshot(&self) -> BackendPoolSnapshot {
        BackendPoolSnapshot {
            connections: self.entries.len(),
            origins: self
                .entries
                .values()
                .map(|entry| &entry.origin)
                .collect::<HashSet<_>>()
                .len(),
            active_streams: self
                .entries
                .values()
                .map(|entry| entry.active_streams)
                .sum(),
            draining_connections: self.entries.values().filter(|entry| entry.draining).count(),
        }
    }

    pub fn contains(&self, connection_id: BackendConnectionId) -> bool {
        self.entries.contains_key(&connection_id)
    }

    fn connection_count_for_origin(&self, origin: &OriginKey) -> usize {
        self.entries
            .values()
            .filter(|entry| &entry.origin == origin)
            .count()
    }

    fn next_available_connection_id(&mut self) -> BackendConnectionId {
        loop {
            let connection_id = BackendConnectionId(self.next_connection_id.max(1));
            self.next_connection_id = connection_id.0.wrapping_add(1).max(1);
            if !self.entries.contains_key(&connection_id) {
                return connection_id;
            }
        }
    }

    fn oldest_idle(&self, origin: Option<&OriginKey>) -> Option<BackendConnectionId> {
        self.entries
            .iter()
            .filter(|(_, entry)| {
                entry.idle() && origin.is_none_or(|origin| &entry.origin == origin)
            })
            .min_by_key(|(connection_id, entry)| (entry.last_activity, **connection_id))
            .map(|(connection_id, _)| *connection_id)
    }

    fn remove(
        &mut self,
        connection_id: BackendConnectionId,
        reason: BackendRemovalReason,
    ) -> Option<BackendRemoval> {
        self.entries
            .remove(&connection_id)
            .map(|entry| BackendRemoval {
                connection_id,
                origin: entry.origin,
                reason,
            })
    }
}

fn normalize_authority(value: &str) -> Result<String, OriginKeyError> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 255
        || value.contains("//")
        || value.chars().any(|character| {
            character.is_whitespace()
                || character.is_control()
                || matches!(character, '/' | '\\' | '?' | '#' | '@')
        })
    {
        return Err(OriginKeyError::InvalidAuthority);
    }
    if let Ok(socket) = SocketAddr::from_str(value) {
        return Ok(socket.to_string());
    }
    let (host, port) = value
        .rsplit_once(':')
        .ok_or(OriginKeyError::InvalidAuthority)?;
    if host.contains(':') {
        return Err(OriginKeyError::InvalidAuthority);
    }
    let port = port
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or(OriginKeyError::InvalidAuthority)?;
    let host = normalize_dns_name(host).ok_or(OriginKeyError::InvalidAuthority)?;
    Ok(format!("{host}:{port}"))
}

fn normalize_server_name(value: &str) -> Result<String, OriginKeyError> {
    let value = value.trim();
    if let Ok(address) = value.parse::<IpAddr>() {
        return Ok(address.to_string());
    }
    normalize_dns_name(value).ok_or(OriginKeyError::InvalidServerName)
}

fn normalize_dns_name(value: &str) -> Option<String> {
    let value = value.trim_end_matches('.').to_ascii_lowercase();
    if value.is_empty()
        || value.len() > 253
        || !value.is_ascii()
        || !value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return None;
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn non_zero(value: usize) -> NonZeroUsize {
        NonZeroUsize::new(value).expect("test limit must be non-zero")
    }

    fn limits(global: usize, per_origin: usize, idle_seconds: u64) -> BackendPoolLimits {
        BackendPoolLimits::new(
            non_zero(global),
            non_zero(per_origin),
            Duration::from_secs(idle_seconds),
        )
        .expect("test pool limits should be valid")
    }

    fn origin(policy: u128, target: &str, protocol: BackendProtocol) -> OriginKey {
        OriginKey::new(
            Uuid::from_u128(policy),
            target,
            protocol,
            BackendSecurity::Plaintext,
        )
        .expect("test origin should be valid")
    }

    #[test]
    fn origin_key_normalizes_authority_and_separates_security_contexts() {
        let policy_id = Uuid::from_u128(7);
        let plaintext = OriginKey::new(
            policy_id,
            " Example.COM.:8080 ",
            BackendProtocol::Http1,
            BackendSecurity::Plaintext,
        )
        .expect("plain origin should normalize");
        let same = OriginKey::new(
            policy_id,
            "example.com:8080",
            BackendProtocol::Http1,
            BackendSecurity::Plaintext,
        )
        .expect("equivalent origin should normalize");
        assert_eq!(plaintext, same);
        assert_eq!(plaintext.authority(), "example.com:8080");
        assert_ne!(
            plaintext,
            OriginKey::new(
                Uuid::from_u128(8),
                "example.com:8080",
                BackendProtocol::Http1,
                BackendSecurity::Plaintext,
            )
            .expect("another policy origin should build")
        );

        let tls = OriginKey::new(
            policy_id,
            "example.com:8080",
            BackendProtocol::Http2,
            BackendSecurity::tls("EXAMPLE.COM.").expect("TLS name should normalize"),
        )
        .expect("TLS origin should build");
        assert_ne!(plaintext, tls);
        assert_eq!(
            tls.security(),
            &BackendSecurity::Tls {
                server_name: "example.com".into()
            }
        );
        assert!(OriginKey::new(
            policy_id,
            "missing-port",
            BackendProtocol::Http1,
            BackendSecurity::Plaintext
        )
        .is_err());
        assert!(BackendSecurity::tls("bad_name.example.com").is_err());
    }

    #[test]
    fn exclusive_and_multiplexed_connections_enforce_stream_capacity() {
        let now = Instant::now();
        let mut pool = BackendPoolState::new(limits(4, 4, 30));
        let http1 = origin(1, "127.0.0.1:8080", BackendProtocol::Http1);
        let http2 = origin(2, "[::1]:9090", BackendProtocol::Http2);
        let http1_id = pool
            .register(http1.clone(), BackendConnectionMode::Exclusive, now)
            .expect("HTTP/1 connection should register")
            .connection_id;
        let http2_id = pool
            .register(
                http2.clone(),
                BackendConnectionMode::Multiplexed {
                    max_concurrent_streams: non_zero(2),
                },
                now,
            )
            .expect("HTTP/2 connection should register")
            .connection_id;

        assert_eq!(pool.acquire(&http1, now).unwrap().connection_id, http1_id);
        assert!(pool.acquire(&http1, now).is_none());
        assert_eq!(pool.acquire(&http2, now).unwrap().connection_id, http2_id);
        assert_eq!(pool.acquire(&http2, now).unwrap().connection_id, http2_id);
        assert!(pool.acquire(&http2, now).is_none());
        assert_eq!(pool.snapshot().active_streams, 3);

        assert!(pool.release(http1_id, now).is_none());
        assert_eq!(pool.acquire(&http1, now).unwrap().connection_id, http1_id);
    }

    #[test]
    fn capacity_evicts_oldest_idle_connection_and_never_active_connections() {
        let now = Instant::now();
        let mut pool = BackendPoolState::new(limits(2, 1, 30));
        let first = origin(1, "one.example:80", BackendProtocol::Http1);
        let second = origin(2, "two.example:80", BackendProtocol::Http1);
        let first_id = pool
            .register(first.clone(), BackendConnectionMode::Exclusive, now)
            .unwrap()
            .connection_id;
        let second_id = pool
            .register(
                second.clone(),
                BackendConnectionMode::Exclusive,
                now + Duration::from_secs(1),
            )
            .unwrap()
            .connection_id;
        let replacement = pool
            .register(
                second.clone(),
                BackendConnectionMode::Exclusive,
                now + Duration::from_secs(2),
            )
            .expect("idle origin entry should be replaced");
        assert_eq!(replacement.removals.len(), 1);
        assert_eq!(
            replacement.removals[0],
            BackendRemoval {
                connection_id: second_id,
                origin: second.clone(),
                reason: BackendRemovalReason::OriginCapacity,
            }
        );
        assert!(pool.contains(first_id));

        let first_lease = pool.acquire(&first, now).unwrap();
        let second_lease = pool.acquire(&second, now).unwrap();
        let third = origin(3, "three.example:80", BackendProtocol::Http1);
        assert_eq!(
            pool.register(third, BackendConnectionMode::Exclusive, now),
            Err(BackendRegisterError::CapacityBusy)
        );
        assert!(pool.contains(first_lease.connection_id));
        assert!(pool.contains(second_lease.connection_id));
    }

    #[test]
    fn global_capacity_evicts_the_least_recently_used_idle_connection() {
        let now = Instant::now();
        let mut pool = BackendPoolState::new(limits(2, 2, 30));
        let first = origin(1, "one.example:80", BackendProtocol::Http1);
        let second = origin(2, "two.example:80", BackendProtocol::Http1);
        let third = origin(3, "three.example:80", BackendProtocol::Http1);
        let first_id = pool
            .register(first.clone(), BackendConnectionMode::Exclusive, now)
            .unwrap()
            .connection_id;
        let second_id = pool
            .register(
                second,
                BackendConnectionMode::Exclusive,
                now + Duration::from_secs(1),
            )
            .unwrap()
            .connection_id;

        let registration = pool
            .register(
                third,
                BackendConnectionMode::Exclusive,
                now + Duration::from_secs(2),
            )
            .expect("global capacity should recycle one idle connection");
        assert_eq!(registration.removals.len(), 1);
        assert_eq!(registration.removals[0].connection_id, first_id);
        assert_eq!(
            registration.removals[0].reason,
            BackendRemovalReason::GlobalCapacity
        );
        assert!(!pool.contains(first_id));
        assert!(pool.contains(second_id));
        assert!(pool.contains(registration.connection_id));
    }

    #[test]
    fn idle_pruning_ignores_active_connections() {
        let now = Instant::now();
        let mut pool = BackendPoolState::new(limits(4, 4, 10));
        let idle = origin(1, "idle.example:80", BackendProtocol::Http1);
        let active = origin(2, "active.example:80", BackendProtocol::Http1);
        let idle_id = pool
            .register(idle.clone(), BackendConnectionMode::Exclusive, now)
            .unwrap()
            .connection_id;
        let active_id = pool
            .register(active.clone(), BackendConnectionMode::Exclusive, now)
            .unwrap()
            .connection_id;
        pool.acquire(&active, now).expect("connection should lease");

        let removals = pool.prune_idle(now + Duration::from_secs(10));
        assert_eq!(removals.len(), 1);
        assert_eq!(removals[0].connection_id, idle_id);
        assert_eq!(removals[0].reason, BackendRemovalReason::IdleTimeout);
        assert!(pool.contains(active_id));
    }

    #[test]
    fn policy_invalidation_removes_idle_and_active_connections() {
        let now = Instant::now();
        let policy_id = Uuid::from_u128(42);
        let first = OriginKey::new(
            policy_id,
            "first.example:80",
            BackendProtocol::Http1,
            BackendSecurity::Plaintext,
        )
        .unwrap();
        let second = OriginKey::new(
            policy_id,
            "second.example:80",
            BackendProtocol::Http2,
            BackendSecurity::Plaintext,
        )
        .unwrap();
        let other = origin(99, "other.example:80", BackendProtocol::Http1);
        let mut pool = BackendPoolState::new(limits(6, 3, 30));
        let first_id = pool
            .register(first.clone(), BackendConnectionMode::Exclusive, now)
            .unwrap()
            .connection_id;
        let second_id = pool
            .register(
                second.clone(),
                BackendConnectionMode::Multiplexed {
                    max_concurrent_streams: non_zero(8),
                },
                now,
            )
            .unwrap()
            .connection_id;
        let other_id = pool
            .register(other, BackendConnectionMode::Exclusive, now)
            .unwrap()
            .connection_id;
        pool.acquire(&second, now)
            .expect("HTTP/2 stream should lease");

        let removals = pool.invalidate_policy(policy_id);
        assert_eq!(removals.len(), 2);
        assert!(removals
            .iter()
            .all(|removal| removal.reason == BackendRemovalReason::PolicyInvalidated));
        assert!(!pool.contains(first_id));
        assert!(!pool.contains(second_id));
        assert!(pool.contains(other_id));
        assert_eq!(pool.snapshot().connections, 1);
    }

    #[test]
    fn disconnect_and_goaway_remove_connections_at_the_correct_time() {
        let now = Instant::now();
        let origin = origin(1, "grpc.example:443", BackendProtocol::Http2);
        let mut pool = BackendPoolState::new(limits(4, 4, 30));
        let connection_id = pool
            .register(
                origin.clone(),
                BackendConnectionMode::Multiplexed {
                    max_concurrent_streams: non_zero(8),
                },
                now,
            )
            .unwrap()
            .connection_id;
        pool.acquire(&origin, now).expect("stream should lease");
        assert!(pool.mark_goaway(connection_id).is_none());
        assert!(pool.acquire(&origin, now).is_none());
        assert_eq!(pool.snapshot().draining_connections, 1);
        let removal = pool
            .release(connection_id, now + Duration::from_secs(1))
            .expect("last GOAWAY stream should remove connection");
        assert_eq!(removal.reason, BackendRemovalReason::GoAway);

        let replacement = pool
            .register(origin, BackendConnectionMode::Exclusive, now)
            .unwrap()
            .connection_id;
        let removal = pool
            .disconnected(replacement)
            .expect("disconnect should remove connection");
        assert_eq!(removal.reason, BackendRemovalReason::Disconnected);
        assert_eq!(pool.snapshot(), BackendPoolSnapshot::default());
    }

    #[test]
    fn pool_limit_validation_is_strict() {
        assert_eq!(
            BackendPoolLimits::new(non_zero(2), non_zero(3), Duration::from_secs(1)),
            Err(BackendPoolLimitsError::OriginLimitExceedsGlobalLimit)
        );
        assert_eq!(
            BackendPoolLimits::new(non_zero(2), non_zero(2), Duration::ZERO),
            Err(BackendPoolLimitsError::ZeroIdleTimeout)
        );
    }
}
