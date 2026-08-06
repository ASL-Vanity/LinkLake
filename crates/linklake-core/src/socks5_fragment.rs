//! RFC 1928 SOCKS5 UDP FRAG 的有界重组器。
//!
//! 为避免任意高序号分片制造稀疏状态，只有序号 1 可以创建重组；创建后允许
//! `max_reorder_gap` 范围内乱序。相同分片可幂等重复，内容或终片标志冲突会
//! 丢弃整个数据报。所有完成、冲突、会话关闭与超时路径都会归还预算。

use crate::socks5_udp::{Socks5UdpDatagram, Socks5UdpFragment, Socks5UdpTarget};
use std::{
    collections::{BTreeMap, HashMap},
    hash::Hash,
    time::{Duration, Instant},
};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Socks5FragmentConfig {
    pub timeout: Duration,
    pub max_fragments_per_datagram: usize,
    pub max_bytes_per_datagram: usize,
    pub max_reorder_gap: u8,
    pub max_inflight_per_session: usize,
    pub max_fragments_per_session: usize,
    pub max_bytes_per_session: usize,
    pub max_inflight_global: usize,
    pub max_fragments_global: usize,
    pub max_bytes_global: usize,
}

impl Default for Socks5FragmentConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            max_fragments_per_datagram: 64,
            max_bytes_per_datagram: u16::MAX as usize,
            max_reorder_gap: 16,
            max_inflight_per_session: 8,
            max_fragments_per_session: 128,
            max_bytes_per_session: 256 * 1024,
            max_inflight_global: 1024,
            max_fragments_global: 8192,
            max_bytes_global: 16 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Error, Clone, Copy, Eq, PartialEq)]
pub enum Socks5FragmentConfigError {
    #[error("SOCKS5 fragment timeout must be positive")]
    ZeroTimeout,
    #[error("SOCKS5 fragment limits must be positive and internally consistent")]
    InvalidLimit,
}

#[derive(Debug, Error, Clone, Copy, Eq, PartialEq)]
pub enum Socks5FragmentError {
    #[error("the first SOCKS5 fragment must have sequence 1")]
    MissingInitialFragment,
    #[error("SOCKS5 fragment sequence exceeds the configured limit")]
    SequenceLimit,
    #[error("SOCKS5 fragment reorder gap exceeds the configured limit")]
    ReorderGap,
    #[error("SOCKS5 fragment conflicts with a duplicate")]
    ConflictingDuplicate,
    #[error("SOCKS5 datagram contains conflicting final fragments")]
    ConflictingFinalFragment,
    #[error("SOCKS5 datagram repeats its final fragment")]
    DuplicateFinalFragment,
    #[error("SOCKS5 fragment appears after the final sequence")]
    FragmentAfterFinal,
    #[error("SOCKS5 fragmented datagram exceeds its byte budget")]
    DatagramByteBudget,
    #[error("SOCKS5 session fragment budget is exhausted")]
    SessionFragmentBudget,
    #[error("SOCKS5 session byte budget is exhausted")]
    SessionByteBudget,
    #[error("SOCKS5 session reassembly budget is exhausted")]
    SessionInflightBudget,
    #[error("global SOCKS5 fragment budget is exhausted")]
    GlobalFragmentBudget,
    #[error("global SOCKS5 fragment byte budget is exhausted")]
    GlobalByteBudget,
    #[error("global SOCKS5 reassembly budget is exhausted")]
    GlobalInflightBudget,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Socks5FragmentOutcome {
    Complete {
        datagram: Socks5UdpDatagram,
        fragmented: bool,
    },
    Pending,
    Duplicate,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Socks5FragmentExpiration {
    pub datagrams: usize,
    pub fragments: usize,
    pub bytes: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Socks5FragmentSnapshot {
    pub inflight_datagrams: usize,
    pub buffered_fragments: usize,
    pub buffered_bytes: usize,
    pub sessions: usize,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct FragmentKey<K> {
    session: K,
    target: Socks5UdpTarget,
    port: u16,
}

struct Assembly {
    target: Socks5UdpTarget,
    port: u16,
    fragments: BTreeMap<u8, Vec<u8>>,
    final_sequence: Option<u8>,
    highest_contiguous: u8,
    bytes: usize,
    last_activity: Instant,
}

#[derive(Clone, Copy, Debug, Default)]
struct Usage {
    datagrams: usize,
    fragments: usize,
    bytes: usize,
}

pub struct Socks5FragmentReassembler<K> {
    config: Socks5FragmentConfig,
    assemblies: HashMap<FragmentKey<K>, Assembly>,
    sessions: HashMap<K, Usage>,
    global_fragments: usize,
    global_bytes: usize,
}

impl<K> Socks5FragmentReassembler<K>
where
    K: Clone + Eq + Hash,
{
    pub fn new(config: Socks5FragmentConfig) -> Result<Self, Socks5FragmentConfigError> {
        validate_config(config)?;
        Ok(Self {
            config,
            assemblies: HashMap::new(),
            sessions: HashMap::new(),
            global_fragments: 0,
            global_bytes: 0,
        })
    }

    pub fn push(
        &mut self,
        session: K,
        fragment: Socks5UdpFragment,
        now: Instant,
    ) -> Result<Socks5FragmentOutcome, Socks5FragmentError> {
        if fragment.sequence == 0 {
            return Ok(Socks5FragmentOutcome::Complete {
                datagram: Socks5UdpDatagram {
                    target: fragment.target,
                    port: fragment.port,
                    payload: fragment.payload,
                },
                fragmented: false,
            });
        }
        if fragment.sequence as usize > self.config.max_fragments_per_datagram {
            return Err(Socks5FragmentError::SequenceLimit);
        }
        let key = FragmentKey {
            session: session.clone(),
            target: fragment.target.clone(),
            port: fragment.port,
        };
        let created = !self.assemblies.contains_key(&key);
        if created {
            if fragment.sequence != 1 {
                return Err(Socks5FragmentError::MissingInitialFragment);
            }
            self.reserve_new_assembly(&session)?;
            self.assemblies.insert(
                key.clone(),
                Assembly {
                    target: fragment.target.clone(),
                    port: fragment.port,
                    fragments: BTreeMap::new(),
                    final_sequence: None,
                    highest_contiguous: 0,
                    bytes: 0,
                    last_activity: now,
                },
            );
        }

        let conflict = {
            let assembly = self
                .assemblies
                .get(&key)
                .expect("SOCKS5 assembly was created above");
            if let Some(existing) = assembly.fragments.get(&fragment.sequence) {
                let existing_final = assembly.final_sequence == Some(fragment.sequence);
                if existing_final && fragment.final_fragment {
                    Some(Socks5FragmentError::DuplicateFinalFragment)
                } else if existing == &fragment.payload && existing_final == fragment.final_fragment
                {
                    return Ok(Socks5FragmentOutcome::Duplicate);
                } else {
                    Some(Socks5FragmentError::ConflictingDuplicate)
                }
            } else if assembly
                .final_sequence
                .is_some_and(|final_sequence| fragment.sequence > final_sequence)
            {
                Some(Socks5FragmentError::FragmentAfterFinal)
            } else if fragment.final_fragment
                && assembly
                    .final_sequence
                    .is_some_and(|final_sequence| final_sequence != fragment.sequence)
            {
                Some(Socks5FragmentError::ConflictingFinalFragment)
            } else if fragment.sequence
                > assembly
                    .highest_contiguous
                    .saturating_add(self.config.max_reorder_gap)
                    .saturating_add(1)
            {
                return Err(Socks5FragmentError::ReorderGap);
            } else {
                None
            }
        };
        if let Some(error) = conflict {
            self.remove_assembly(&key);
            return Err(error);
        }

        if let Err(error) = self.reserve_fragment(&session, &key, fragment.payload.len()) {
            if created {
                self.remove_assembly(&key);
            }
            return Err(error);
        }
        let assembly = self
            .assemblies
            .get_mut(&key)
            .expect("SOCKS5 assembly must exist after budget reservation");
        if fragment.final_fragment {
            assembly.final_sequence = Some(fragment.sequence);
        }
        assembly.bytes = assembly.bytes.saturating_add(fragment.payload.len());
        assembly
            .fragments
            .insert(fragment.sequence, fragment.payload);
        assembly.last_activity = now;
        while assembly
            .fragments
            .contains_key(&assembly.highest_contiguous.saturating_add(1))
        {
            assembly.highest_contiguous = assembly.highest_contiguous.saturating_add(1);
        }
        let complete = assembly
            .final_sequence
            .is_some_and(|final_sequence| assembly.highest_contiguous == final_sequence);
        if !complete {
            return Ok(Socks5FragmentOutcome::Pending);
        }

        let assembly = self
            .remove_assembly(&key)
            .expect("complete SOCKS5 assembly must still exist");
        let final_sequence = assembly
            .final_sequence
            .expect("complete SOCKS5 assembly has a final fragment");
        let mut payload = Vec::with_capacity(assembly.bytes);
        for sequence in 1..=final_sequence {
            payload.extend_from_slice(
                assembly
                    .fragments
                    .get(&sequence)
                    .expect("contiguous complete assembly has every fragment"),
            );
        }
        Ok(Socks5FragmentOutcome::Complete {
            datagram: Socks5UdpDatagram {
                target: assembly.target,
                port: assembly.port,
                payload,
            },
            fragmented: true,
        })
    }

    pub fn expire(&mut self, now: Instant) -> Socks5FragmentExpiration {
        let keys = self
            .assemblies
            .iter()
            .filter_map(|(key, assembly)| {
                now.checked_duration_since(assembly.last_activity)
                    .is_some_and(|elapsed| elapsed >= self.config.timeout)
                    .then_some(key.clone())
            })
            .collect::<Vec<_>>();
        let mut expired = Socks5FragmentExpiration::default();
        for key in keys {
            if let Some(assembly) = self.remove_assembly(&key) {
                expired.datagrams = expired.datagrams.saturating_add(1);
                expired.fragments = expired.fragments.saturating_add(assembly.fragments.len());
                expired.bytes = expired.bytes.saturating_add(assembly.bytes);
            }
        }
        expired
    }

    pub fn discard_session(&mut self, session: &K) -> Socks5FragmentExpiration {
        let keys = self
            .assemblies
            .keys()
            .filter(|key| &key.session == session)
            .cloned()
            .collect::<Vec<_>>();
        let mut discarded = Socks5FragmentExpiration::default();
        for key in keys {
            if let Some(assembly) = self.remove_assembly(&key) {
                discarded.datagrams = discarded.datagrams.saturating_add(1);
                discarded.fragments = discarded.fragments.saturating_add(assembly.fragments.len());
                discarded.bytes = discarded.bytes.saturating_add(assembly.bytes);
            }
        }
        discarded
    }

    pub fn snapshot(&self) -> Socks5FragmentSnapshot {
        Socks5FragmentSnapshot {
            inflight_datagrams: self.assemblies.len(),
            buffered_fragments: self.global_fragments,
            buffered_bytes: self.global_bytes,
            sessions: self.sessions.len(),
        }
    }

    fn reserve_new_assembly(&mut self, session: &K) -> Result<(), Socks5FragmentError> {
        if self.assemblies.len() >= self.config.max_inflight_global {
            return Err(Socks5FragmentError::GlobalInflightBudget);
        }
        let usage = self.sessions.get(session).copied().unwrap_or_default();
        if usage.datagrams >= self.config.max_inflight_per_session {
            return Err(Socks5FragmentError::SessionInflightBudget);
        }
        self.sessions.entry(session.clone()).or_default().datagrams += 1;
        Ok(())
    }

    fn reserve_fragment(
        &mut self,
        session: &K,
        key: &FragmentKey<K>,
        bytes: usize,
    ) -> Result<(), Socks5FragmentError> {
        let assembly = self
            .assemblies
            .get(key)
            .expect("SOCKS5 assembly exists before reserving a fragment");
        if assembly.fragments.len() >= self.config.max_fragments_per_datagram {
            return Err(Socks5FragmentError::SequenceLimit);
        }
        if assembly.bytes.saturating_add(bytes) > self.config.max_bytes_per_datagram {
            self.remove_assembly(key);
            return Err(Socks5FragmentError::DatagramByteBudget);
        }
        let usage = self.sessions.get(session).copied().unwrap_or_default();
        if usage.fragments >= self.config.max_fragments_per_session {
            return Err(Socks5FragmentError::SessionFragmentBudget);
        }
        if usage.bytes.saturating_add(bytes) > self.config.max_bytes_per_session {
            return Err(Socks5FragmentError::SessionByteBudget);
        }
        if self.global_fragments >= self.config.max_fragments_global {
            return Err(Socks5FragmentError::GlobalFragmentBudget);
        }
        if self.global_bytes.saturating_add(bytes) > self.config.max_bytes_global {
            return Err(Socks5FragmentError::GlobalByteBudget);
        }
        let usage = self
            .sessions
            .get_mut(session)
            .expect("session usage exists");
        usage.fragments = usage.fragments.saturating_add(1);
        usage.bytes = usage.bytes.saturating_add(bytes);
        self.global_fragments = self.global_fragments.saturating_add(1);
        self.global_bytes = self.global_bytes.saturating_add(bytes);
        Ok(())
    }

    fn remove_assembly(&mut self, key: &FragmentKey<K>) -> Option<Assembly> {
        let assembly = self.assemblies.remove(key)?;
        self.global_fragments = self
            .global_fragments
            .saturating_sub(assembly.fragments.len());
        self.global_bytes = self.global_bytes.saturating_sub(assembly.bytes);
        if let Some(usage) = self.sessions.get_mut(&key.session) {
            usage.datagrams = usage.datagrams.saturating_sub(1);
            usage.fragments = usage.fragments.saturating_sub(assembly.fragments.len());
            usage.bytes = usage.bytes.saturating_sub(assembly.bytes);
            if usage.datagrams == 0 && usage.fragments == 0 && usage.bytes == 0 {
                self.sessions.remove(&key.session);
            }
        }
        Some(assembly)
    }
}

fn validate_config(config: Socks5FragmentConfig) -> Result<(), Socks5FragmentConfigError> {
    if config.timeout.is_zero() {
        return Err(Socks5FragmentConfigError::ZeroTimeout);
    }
    if config.max_fragments_per_datagram == 0
        || config.max_fragments_per_datagram > 127
        || config.max_bytes_per_datagram == 0
        || config.max_reorder_gap == 0
        || config.max_inflight_per_session == 0
        || config.max_fragments_per_session < config.max_fragments_per_datagram
        || config.max_bytes_per_session < config.max_bytes_per_datagram
        || config.max_inflight_global < config.max_inflight_per_session
        || config.max_fragments_global < config.max_fragments_per_session
        || config.max_bytes_global < config.max_bytes_per_session
    {
        return Err(Socks5FragmentConfigError::InvalidLimit);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn fragment(sequence: u8, final_fragment: bool, payload: &[u8]) -> Socks5UdpFragment {
        Socks5UdpFragment {
            sequence,
            final_fragment,
            target: Socks5UdpTarget::Ip(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            port: 53,
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn bounded_reordering_duplicates_completion_and_timeout_release_budgets() {
        let now = Instant::now();
        let mut reassembler = Socks5FragmentReassembler::new(Socks5FragmentConfig::default())
            .expect("default config is valid");
        assert_eq!(
            reassembler.push(1_u64, fragment(1, false, b"a"), now),
            Ok(Socks5FragmentOutcome::Pending)
        );
        assert_eq!(
            reassembler.push(1_u64, fragment(3, true, b"c"), now),
            Ok(Socks5FragmentOutcome::Pending)
        );
        assert_eq!(
            reassembler.push(1_u64, fragment(1, false, b"a"), now),
            Ok(Socks5FragmentOutcome::Duplicate)
        );
        let complete = reassembler
            .push(1_u64, fragment(2, false, b"b"), now)
            .unwrap();
        assert!(matches!(
            complete,
            Socks5FragmentOutcome::Complete {
                datagram: Socks5UdpDatagram { ref payload, .. },
                fragmented: true,
            } if payload == b"abc"
        ));
        assert_eq!(reassembler.snapshot(), Socks5FragmentSnapshot::default());

        reassembler
            .push(3_u64, fragment(1, false, b"a"), now)
            .unwrap();
        reassembler
            .push(3_u64, fragment(3, true, b"c"), now)
            .unwrap();
        assert_eq!(
            reassembler.push(3_u64, fragment(3, true, b"c"), now),
            Err(Socks5FragmentError::DuplicateFinalFragment)
        );
        assert_eq!(reassembler.snapshot(), Socks5FragmentSnapshot::default());

        reassembler
            .push(2_u64, fragment(1, false, b"pending"), now)
            .unwrap();
        let expired = reassembler.expire(now + Duration::from_secs(5));
        assert_eq!(expired.datagrams, 1);
        assert_eq!(reassembler.snapshot(), Socks5FragmentSnapshot::default());
    }

    #[test]
    fn rejects_sparse_starts_conflicting_final_and_conflicting_duplicate() {
        let now = Instant::now();
        let mut reassembler =
            Socks5FragmentReassembler::new(Socks5FragmentConfig::default()).unwrap();
        assert_eq!(
            reassembler.push(1_u64, fragment(2, false, b"late"), now),
            Err(Socks5FragmentError::MissingInitialFragment)
        );
        reassembler
            .push(1_u64, fragment(1, false, b"one"), now)
            .unwrap();
        assert_eq!(
            reassembler.push(1_u64, fragment(1, false, b"changed"), now),
            Err(Socks5FragmentError::ConflictingDuplicate)
        );
        assert_eq!(reassembler.snapshot(), Socks5FragmentSnapshot::default());

        reassembler
            .push(1_u64, fragment(1, false, b"one"), now)
            .unwrap();
        reassembler
            .push(1_u64, fragment(3, true, b"three"), now)
            .unwrap();
        assert_eq!(
            reassembler.push(1_u64, fragment(2, true, b"two"), now),
            Err(Socks5FragmentError::ConflictingFinalFragment)
        );
        assert_eq!(reassembler.snapshot(), Socks5FragmentSnapshot::default());
    }
}
