//! 对 LLUD 分片进行有界、可过期的 UDP datagram 重组。

use crate::udp_protocol::{UdpDirection, UdpFragment, UdpProtocolError};
use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};
use thiserror::Error;
use uuid::Uuid;

pub const UDP_REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(2);
pub const DEFAULT_UDP_REASSEMBLY_MEMORY_BYTES: usize = 8 * 1024 * 1024;
pub const DEFAULT_MAX_INCOMPLETE_PER_SESSION: usize = 4;
pub const DEFAULT_MAX_INCOMPLETE_DATAGRAMS: usize = 4_096;
pub const DEFAULT_MAX_COMPLETED_DATAGRAMS: usize = 4_096;
const REASSEMBLY_CLEANUP_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Debug, Clone)]
pub struct UdpReassemblyConfig {
    pub timeout: Duration,
    pub completed_retention: Duration,
    pub max_buffered_bytes: usize,
    pub max_incomplete_per_session: usize,
    pub max_incomplete_datagrams: usize,
    pub max_completed_datagrams: usize,
}

impl Default for UdpReassemblyConfig {
    fn default() -> Self {
        Self {
            timeout: UDP_REASSEMBLY_TIMEOUT,
            completed_retention: UDP_REASSEMBLY_TIMEOUT,
            max_buffered_bytes: DEFAULT_UDP_REASSEMBLY_MEMORY_BYTES,
            max_incomplete_per_session: DEFAULT_MAX_INCOMPLETE_PER_SESSION,
            max_incomplete_datagrams: DEFAULT_MAX_INCOMPLETE_DATAGRAMS,
            max_completed_datagrams: DEFAULT_MAX_COMPLETED_DATAGRAMS,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct DatagramKey {
    direction: UdpDirection,
    session_id: Uuid,
    datagram_id: u64,
}

impl From<&UdpFragment> for DatagramKey {
    fn from(fragment: &UdpFragment) -> Self {
        Self {
            direction: fragment.direction,
            session_id: fragment.session_id,
            datagram_id: fragment.datagram_id,
        }
    }
}

struct PartialDatagram {
    started_at: Instant,
    original_length: usize,
    fragment_count: u16,
    fragments: Vec<Option<Vec<u8>>>,
    received_fragments: usize,
    received_bytes: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub enum UdpReassemblyOutcome {
    Pending,
    Duplicate,
    Complete(Vec<u8>),
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct UdpReassemblyExpiration {
    pub incomplete_datagrams: usize,
    pub buffered_bytes: usize,
    pub completed_datagrams: usize,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum UdpReassemblyError {
    #[error("invalid UDP fragment: {0}")]
    InvalidFragment(#[from] UdpProtocolError),
    #[error("UDP reassembly configuration contains a zero limit")]
    InvalidConfiguration,
    #[error("UDP reassembly memory limit has been reached")]
    MemoryLimit,
    #[error("UDP reassembly incomplete datagram limit has been reached")]
    IncompleteDatagramLimit,
    #[error("UDP session has too many incomplete datagrams")]
    SessionIncompleteLimit,
    #[error("UDP fragments for the same datagram contain inconsistent metadata")]
    MetadataMismatch,
    #[error("UDP fragment conflicts with an already received fragment")]
    ConflictingFragment,
    #[error("UDP fragment bytes exceed the declared original datagram length")]
    DeclaredLengthExceeded,
    #[error("completed UDP fragment bytes do not match the declared datagram length")]
    CompletedLengthMismatch,
}

pub struct UdpReassembler {
    config: UdpReassemblyConfig,
    partials: HashMap<DatagramKey, PartialDatagram>,
    incomplete_by_session: HashMap<Uuid, usize>,
    completed: HashMap<DatagramKey, Instant>,
    completed_order: VecDeque<(DatagramKey, Instant)>,
    buffered_bytes: usize,
    next_cleanup_at: Option<Instant>,
}

impl UdpReassembler {
    pub fn new(config: UdpReassemblyConfig) -> Result<Self, UdpReassemblyError> {
        if config.max_buffered_bytes == 0
            || config.max_incomplete_per_session == 0
            || config.max_incomplete_datagrams == 0
            || config.max_completed_datagrams == 0
        {
            return Err(UdpReassemblyError::InvalidConfiguration);
        }
        Ok(Self {
            config,
            partials: HashMap::new(),
            incomplete_by_session: HashMap::new(),
            completed: HashMap::new(),
            completed_order: VecDeque::new(),
            buffered_bytes: 0,
            next_cleanup_at: None,
        })
    }

    pub fn push(
        &mut self,
        fragment: UdpFragment,
        now: Instant,
    ) -> Result<UdpReassemblyOutcome, UdpReassemblyError> {
        fragment.validate()?;
        self.expire(now);
        let key = DatagramKey::from(&fragment);
        if self.completed.contains_key(&key) {
            return Ok(UdpReassemblyOutcome::Duplicate);
        }

        if fragment.original_length == 0 {
            self.remember_completed(key, now);
            return Ok(UdpReassemblyOutcome::Complete(Vec::new()));
        }

        if !self.partials.contains_key(&key) {
            self.insert_partial(key, &fragment, now)?;
        }

        let index = usize::from(fragment.fragment_index);
        let mut failure = None;
        let mut duplicate = false;
        let mut complete = false;
        {
            let partial = self
                .partials
                .get_mut(&key)
                .expect("a partial datagram was inserted before use");
            if partial.original_length != fragment.original_length as usize
                || partial.fragment_count != fragment.fragment_count
            {
                failure = Some(UdpReassemblyError::MetadataMismatch);
            } else if let Some(existing) = &partial.fragments[index] {
                if existing == &fragment.payload {
                    duplicate = true;
                } else {
                    failure = Some(UdpReassemblyError::ConflictingFragment);
                }
            } else if partial.received_bytes + fragment.payload.len() > partial.original_length {
                failure = Some(UdpReassemblyError::DeclaredLengthExceeded);
            } else {
                partial.received_bytes += fragment.payload.len();
                partial.received_fragments += 1;
                partial.fragments[index] = Some(fragment.payload);
                complete = partial.received_fragments == usize::from(partial.fragment_count);
            }
        }

        if let Some(error) = failure {
            self.remove_partial(&key);
            return Err(error);
        }
        if duplicate {
            return Ok(UdpReassemblyOutcome::Duplicate);
        }
        if !complete {
            return Ok(UdpReassemblyOutcome::Pending);
        }

        let partial = self
            .remove_partial(&key)
            .expect("completed partial datagram should still exist");
        if partial.received_bytes != partial.original_length {
            return Err(UdpReassemblyError::CompletedLengthMismatch);
        }
        let mut payload = Vec::with_capacity(partial.original_length);
        for fragment in partial.fragments {
            payload.extend(fragment.expect("all fragment slots are present after completion"));
        }
        if payload.len() != partial.original_length {
            return Err(UdpReassemblyError::CompletedLengthMismatch);
        }
        self.remember_completed(key, now);
        Ok(UdpReassemblyOutcome::Complete(payload))
    }

    pub fn expire(&mut self, now: Instant) -> UdpReassemblyExpiration {
        if self.next_cleanup_at.is_some_and(|deadline| now < deadline) {
            return UdpReassemblyExpiration::default();
        }
        self.next_cleanup_at = Some(now + REASSEMBLY_CLEANUP_INTERVAL);

        let expired_partial_keys = self
            .partials
            .iter()
            .filter_map(|(key, partial)| {
                elapsed_at_least(now, partial.started_at, self.config.timeout).then_some(*key)
            })
            .collect::<Vec<_>>();
        let mut expiration = UdpReassemblyExpiration::default();
        for key in expired_partial_keys {
            if let Some(partial) = self.remove_partial(&key) {
                expiration.incomplete_datagrams += 1;
                expiration.buffered_bytes += partial.original_length;
            }
        }

        while let Some((key, completed_at)) = self.completed_order.front().copied() {
            let is_current = self.completed.get(&key).copied() == Some(completed_at);
            if is_current && !elapsed_at_least(now, completed_at, self.config.completed_retention) {
                break;
            }
            self.completed_order.pop_front();
            if is_current && self.completed.remove(&key).is_some() {
                expiration.completed_datagrams += 1;
            }
        }
        expiration
    }

    /// 立即丢弃指定会话的未完成报文和去重记录，用于会话关闭时释放内存。
    pub fn discard_session(&mut self, session_id: Uuid) -> UdpReassemblyExpiration {
        let partial_keys = self
            .partials
            .keys()
            .filter(|key| key.session_id == session_id)
            .copied()
            .collect::<Vec<_>>();
        let mut expiration = UdpReassemblyExpiration::default();
        for key in partial_keys {
            if let Some(partial) = self.remove_partial(&key) {
                expiration.incomplete_datagrams += 1;
                expiration.buffered_bytes += partial.original_length;
            }
        }

        let completed_keys = self
            .completed
            .keys()
            .filter(|key| key.session_id == session_id)
            .copied()
            .collect::<Vec<_>>();
        for key in completed_keys {
            if self.completed.remove(&key).is_some() {
                expiration.completed_datagrams += 1;
            }
        }
        expiration
    }

    pub fn buffered_bytes(&self) -> usize {
        self.buffered_bytes
    }

    pub fn incomplete_datagrams(&self) -> usize {
        self.partials.len()
    }

    fn insert_partial(
        &mut self,
        key: DatagramKey,
        fragment: &UdpFragment,
        now: Instant,
    ) -> Result<(), UdpReassemblyError> {
        if self.partials.len() >= self.config.max_incomplete_datagrams {
            return Err(UdpReassemblyError::IncompleteDatagramLimit);
        }
        let per_session = self
            .incomplete_by_session
            .get(&fragment.session_id)
            .copied()
            .unwrap_or(0);
        if per_session >= self.config.max_incomplete_per_session {
            return Err(UdpReassemblyError::SessionIncompleteLimit);
        }
        let reserved_bytes = fragment.original_length as usize;
        if self.buffered_bytes.saturating_add(reserved_bytes) > self.config.max_buffered_bytes {
            return Err(UdpReassemblyError::MemoryLimit);
        }
        self.partials.insert(
            key,
            PartialDatagram {
                started_at: now,
                original_length: reserved_bytes,
                fragment_count: fragment.fragment_count,
                fragments: (0..fragment.fragment_count).map(|_| None).collect(),
                received_fragments: 0,
                received_bytes: 0,
            },
        );
        self.buffered_bytes += reserved_bytes;
        *self
            .incomplete_by_session
            .entry(fragment.session_id)
            .or_insert(0) += 1;
        Ok(())
    }

    fn remove_partial(&mut self, key: &DatagramKey) -> Option<PartialDatagram> {
        let partial = self.partials.remove(key)?;
        self.buffered_bytes = self.buffered_bytes.saturating_sub(partial.original_length);
        if let Some(count) = self.incomplete_by_session.get_mut(&key.session_id) {
            *count -= 1;
            if *count == 0 {
                self.incomplete_by_session.remove(&key.session_id);
            }
        }
        Some(partial)
    }

    fn remember_completed(&mut self, key: DatagramKey, now: Instant) {
        if self.completed.len() >= self.config.max_completed_datagrams {
            self.evict_oldest_completed();
        }
        self.completed.insert(key, now);
        self.completed_order.push_back((key, now));
        if self.completed_order.len() > self.config.max_completed_datagrams.saturating_mul(2) {
            self.compact_completed_order();
        }
    }

    fn evict_oldest_completed(&mut self) {
        while let Some((key, completed_at)) = self.completed_order.pop_front() {
            if self.completed.get(&key).copied() == Some(completed_at) {
                self.completed.remove(&key);
                return;
            }
        }
    }

    fn compact_completed_order(&mut self) {
        self.completed_order
            .retain(|(key, completed_at)| self.completed.get(key).copied() == Some(*completed_at));
    }
}

fn elapsed_at_least(now: Instant, earlier: Instant, duration: Duration) -> bool {
    now.checked_duration_since(earlier).unwrap_or_default() >= duration
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::udp_protocol::{fragment_datagram, UdpFragment};

    fn session(value: u128) -> Uuid {
        Uuid::from_u128(value)
    }

    fn fragments(session_id: Uuid, datagram_id: u64, payload: &[u8]) -> Vec<UdpFragment> {
        fragment_datagram(
            UdpDirection::PublicToTarget,
            session_id,
            datagram_id,
            payload,
            43,
        )
        .expect("test datagram should fragment")
        .iter()
        .map(|frame| UdpFragment::decode(frame).expect("test fragment should decode"))
        .collect()
    }

    fn config() -> UdpReassemblyConfig {
        UdpReassemblyConfig {
            timeout: UDP_REASSEMBLY_TIMEOUT,
            completed_retention: UDP_REASSEMBLY_TIMEOUT,
            max_buffered_bytes: 128,
            max_incomplete_per_session: 2,
            max_incomplete_datagrams: 4,
            max_completed_datagrams: 4,
        }
    }

    #[test]
    fn reassembles_out_of_order_and_ignores_duplicates() {
        let now = Instant::now();
        let mut reassembler = UdpReassembler::new(config()).expect("configuration should work");
        let parts = fragments(session(1), 7, b"abcdefghi");
        assert_eq!(
            reassembler.push(parts[2].clone(), now),
            Ok(UdpReassemblyOutcome::Pending)
        );
        assert_eq!(
            reassembler.push(parts[2].clone(), now),
            Ok(UdpReassemblyOutcome::Duplicate)
        );
        assert_eq!(
            reassembler.push(parts[0].clone(), now),
            Ok(UdpReassemblyOutcome::Pending)
        );
        assert_eq!(
            reassembler.push(parts[1].clone(), now),
            Ok(UdpReassemblyOutcome::Complete(b"abcdefghi".to_vec()))
        );
        assert_eq!(reassembler.buffered_bytes(), 0);
        assert_eq!(
            reassembler.push(parts[0].clone(), now),
            Ok(UdpReassemblyOutcome::Duplicate)
        );
    }

    #[test]
    fn zero_length_datagram_completes_and_is_deduplicated() {
        let now = Instant::now();
        let mut reassembler = UdpReassembler::new(config()).expect("configuration should work");
        let fragment = fragments(session(1), 1, &[]).remove(0);
        assert_eq!(
            reassembler.push(fragment.clone(), now),
            Ok(UdpReassemblyOutcome::Complete(Vec::new()))
        );
        assert_eq!(
            reassembler.push(fragment, now),
            Ok(UdpReassemblyOutcome::Duplicate)
        );
    }

    #[test]
    fn conflicting_or_mismatched_fragments_discard_partial_datagram() {
        let now = Instant::now();
        let mut reassembler = UdpReassembler::new(config()).expect("configuration should work");
        let parts = fragments(session(1), 1, b"abcdef");
        assert_eq!(
            reassembler.push(parts[0].clone(), now),
            Ok(UdpReassemblyOutcome::Pending)
        );
        let mut conflict = parts[0].clone();
        conflict.payload[0] ^= 0xff;
        assert_eq!(
            reassembler.push(conflict, now),
            Err(UdpReassemblyError::ConflictingFragment)
        );
        assert_eq!(reassembler.incomplete_datagrams(), 0);

        assert_eq!(
            reassembler.push(parts[0].clone(), now),
            Ok(UdpReassemblyOutcome::Pending)
        );
        let mut mismatch = parts[1].clone();
        mismatch.original_length += 1;
        assert_eq!(
            reassembler.push(mismatch, now),
            Err(UdpReassemblyError::MetadataMismatch)
        );
        assert_eq!(reassembler.incomplete_datagrams(), 0);
    }

    #[test]
    fn enforces_memory_session_and_global_incomplete_limits() {
        let now = Instant::now();
        let mut memory_config = config();
        memory_config.max_buffered_bytes = 5;
        let mut reassembler =
            UdpReassembler::new(memory_config).expect("configuration should work");
        assert_eq!(
            reassembler.push(fragments(session(1), 1, b"abcdef").remove(0), now),
            Err(UdpReassemblyError::MemoryLimit)
        );

        let mut session_config = config();
        session_config.max_incomplete_per_session = 1;
        let mut reassembler =
            UdpReassembler::new(session_config).expect("configuration should work");
        assert_eq!(
            reassembler.push(fragments(session(1), 1, b"abcdef").remove(0), now),
            Ok(UdpReassemblyOutcome::Pending)
        );
        assert_eq!(
            reassembler.push(fragments(session(1), 2, b"ghijkl").remove(0), now),
            Err(UdpReassemblyError::SessionIncompleteLimit)
        );

        let mut global_config = config();
        global_config.max_incomplete_datagrams = 1;
        let mut reassembler =
            UdpReassembler::new(global_config).expect("configuration should work");
        assert_eq!(
            reassembler.push(fragments(session(1), 1, b"abcdef").remove(0), now),
            Ok(UdpReassemblyOutcome::Pending)
        );
        assert_eq!(
            reassembler.push(fragments(session(2), 1, b"ghijkl").remove(0), now),
            Err(UdpReassemblyError::IncompleteDatagramLimit)
        );
    }

    #[test]
    fn expiration_releases_memory_and_completed_deduplication() {
        let now = Instant::now();
        let mut reassembler = UdpReassembler::new(config()).expect("configuration should work");
        let partial = fragments(session(1), 1, b"abcdef").remove(0);
        assert_eq!(
            reassembler.push(partial, now),
            Ok(UdpReassemblyOutcome::Pending)
        );
        let complete = fragments(session(2), 2, b"ok").remove(0);
        assert_eq!(
            reassembler.push(complete.clone(), now),
            Ok(UdpReassemblyOutcome::Complete(b"ok".to_vec()))
        );

        let expiration = reassembler.expire(now + UDP_REASSEMBLY_TIMEOUT);
        assert_eq!(expiration.incomplete_datagrams, 1);
        assert_eq!(expiration.buffered_bytes, 6);
        assert_eq!(expiration.completed_datagrams, 1);
        assert_eq!(reassembler.buffered_bytes(), 0);
        assert_eq!(
            reassembler.push(complete, now + UDP_REASSEMBLY_TIMEOUT),
            Ok(UdpReassemblyOutcome::Complete(b"ok".to_vec()))
        );
    }

    #[test]
    fn discarding_session_releases_only_its_reassembly_state() {
        let now = Instant::now();
        let mut reassembler = UdpReassembler::new(config()).expect("configuration should work");
        let first_partial = fragments(session(1), 1, b"abcdef").remove(0);
        let second_partial = fragments(session(2), 2, b"ghijkl").remove(0);
        let completed = fragments(session(1), 3, b"ok").remove(0);
        assert_eq!(
            reassembler.push(first_partial, now),
            Ok(UdpReassemblyOutcome::Pending)
        );
        assert_eq!(
            reassembler.push(second_partial, now),
            Ok(UdpReassemblyOutcome::Pending)
        );
        assert_eq!(
            reassembler.push(completed, now),
            Ok(UdpReassemblyOutcome::Complete(b"ok".to_vec()))
        );

        let discarded = reassembler.discard_session(session(1));

        assert_eq!(discarded.incomplete_datagrams, 1);
        assert_eq!(discarded.buffered_bytes, 6);
        assert_eq!(discarded.completed_datagrams, 1);
        assert_eq!(reassembler.incomplete_datagrams(), 1);
        assert_eq!(reassembler.buffered_bytes(), 6);
    }

    #[test]
    fn rejects_zero_configuration_limits() {
        let mut invalid = config();
        invalid.max_incomplete_per_session = 0;
        assert!(matches!(
            UdpReassembler::new(invalid),
            Err(UdpReassemblyError::InvalidConfiguration)
        ));
    }

    #[test]
    fn rejects_invalid_hand_built_fragment_without_panicking() {
        let now = Instant::now();
        let mut reassembler = UdpReassembler::new(config()).expect("configuration should work");
        let invalid = UdpFragment {
            direction: UdpDirection::PublicToTarget,
            session_id: session(1),
            datagram_id: 1,
            fragment_index: 7,
            fragment_count: 2,
            original_length: 6,
            payload: vec![1, 2, 3],
        };
        assert!(matches!(
            reassembler.push(invalid, now),
            Err(UdpReassemblyError::InvalidFragment(_))
        ));
        assert_eq!(reassembler.incomplete_datagrams(), 0);
    }
}
