//! LinkLake UDP 数据面的二进制报文格式。

use thiserror::Error;
use uuid::Uuid;

pub const UDP_DATAGRAM_MAGIC: [u8; 4] = *b"LLUD";
pub const UDP_DATAGRAM_VERSION: u8 = 1;
pub const UDP_DATAGRAM_HEADER_BYTES: usize = 40;
pub const MAX_UDP_DATAGRAM_BYTES: usize = 65_507;
pub const MAX_UDP_FRAGMENTS: u16 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum UdpDirection {
    PublicToTarget = 1,
    TargetToPublic = 2,
}

impl TryFrom<u8> for UdpDirection {
    type Error = UdpProtocolError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::PublicToTarget),
            2 => Ok(Self::TargetToPublic),
            _ => Err(UdpProtocolError::InvalidDirection(value)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpFragment {
    pub direction: UdpDirection,
    pub session_id: Uuid,
    pub datagram_id: u64,
    pub fragment_index: u16,
    pub fragment_count: u16,
    pub original_length: u32,
    pub payload: Vec<u8>,
}

impl UdpFragment {
    pub fn validate(&self) -> Result<(), UdpProtocolError> {
        validate_fragment(self)
    }

    pub fn encode(&self) -> Result<Vec<u8>, UdpProtocolError> {
        self.validate()?;
        let mut encoded = Vec::with_capacity(UDP_DATAGRAM_HEADER_BYTES + self.payload.len());
        encoded.extend_from_slice(&UDP_DATAGRAM_MAGIC);
        encoded.push(UDP_DATAGRAM_VERSION);
        encoded.push(self.direction as u8);
        encoded.extend_from_slice(&0_u16.to_be_bytes());
        encoded.extend_from_slice(self.session_id.as_bytes());
        encoded.extend_from_slice(&self.datagram_id.to_be_bytes());
        encoded.extend_from_slice(&self.fragment_index.to_be_bytes());
        encoded.extend_from_slice(&self.fragment_count.to_be_bytes());
        encoded.extend_from_slice(&self.original_length.to_be_bytes());
        encoded.extend_from_slice(&self.payload);
        Ok(encoded)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, UdpProtocolError> {
        if encoded.len() < UDP_DATAGRAM_HEADER_BYTES {
            return Err(UdpProtocolError::FrameTooShort(encoded.len()));
        }
        if encoded[..4] != UDP_DATAGRAM_MAGIC {
            return Err(UdpProtocolError::InvalidMagic);
        }
        if encoded[4] != UDP_DATAGRAM_VERSION {
            return Err(UdpProtocolError::UnsupportedVersion(encoded[4]));
        }
        let direction = UdpDirection::try_from(encoded[5])?;
        let flags = u16::from_be_bytes([encoded[6], encoded[7]]);
        if flags != 0 {
            return Err(UdpProtocolError::UnsupportedFlags(flags));
        }

        let session_id = Uuid::from_bytes(
            encoded[8..24]
                .try_into()
                .expect("the fixed UDP header contains a complete UUID"),
        );
        let fragment = Self {
            direction,
            session_id,
            datagram_id: u64::from_be_bytes(
                encoded[24..32]
                    .try_into()
                    .expect("the fixed UDP header contains a complete datagram ID"),
            ),
            fragment_index: u16::from_be_bytes([encoded[32], encoded[33]]),
            fragment_count: u16::from_be_bytes([encoded[34], encoded[35]]),
            original_length: u32::from_be_bytes(
                encoded[36..40]
                    .try_into()
                    .expect("the fixed UDP header contains a complete original length"),
            ),
            payload: encoded[UDP_DATAGRAM_HEADER_BYTES..].to_vec(),
        };
        fragment.validate()?;
        Ok(fragment)
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum UdpProtocolError {
    #[error("UDP data frame is shorter than the 40-byte header: {0}")]
    FrameTooShort(usize),
    #[error("UDP data frame magic is invalid")]
    InvalidMagic,
    #[error("UDP data frame version is unsupported: {0}")]
    UnsupportedVersion(u8),
    #[error("UDP data frame direction is invalid: {0}")]
    InvalidDirection(u8),
    #[error("UDP data frame contains unsupported flags: {0:#06x}")]
    UnsupportedFlags(u16),
    #[error("UDP session ID must not be nil")]
    NilSessionId,
    #[error("UDP fragment count is invalid: {0}")]
    InvalidFragmentCount(u16),
    #[error("UDP fragment index {index} is outside fragment count {count}")]
    InvalidFragmentIndex { index: u16, count: u16 },
    #[error("UDP datagram is larger than {MAX_UDP_DATAGRAM_BYTES} bytes: {0}")]
    DatagramTooLarge(usize),
    #[error("UDP fragment payload is inconsistent with its original datagram length")]
    InvalidFragmentLength,
    #[error("UDP data frame limit must be larger than the 40-byte header")]
    FrameLimitTooSmall,
    #[error("UDP datagram requires more than {MAX_UDP_FRAGMENTS} fragments")]
    TooManyFragments,
}

/// 将一个原始 UDP datagram 分成可直接交给 QUIC DATAGRAM 的 LLUD 帧。
pub fn fragment_datagram(
    direction: UdpDirection,
    session_id: Uuid,
    datagram_id: u64,
    payload: &[u8],
    max_frame_bytes: usize,
) -> Result<Vec<Vec<u8>>, UdpProtocolError> {
    if session_id.is_nil() {
        return Err(UdpProtocolError::NilSessionId);
    }
    if payload.len() > MAX_UDP_DATAGRAM_BYTES {
        return Err(UdpProtocolError::DatagramTooLarge(payload.len()));
    }
    if max_frame_bytes <= UDP_DATAGRAM_HEADER_BYTES {
        return Err(UdpProtocolError::FrameLimitTooSmall);
    }

    let max_fragment_payload = max_frame_bytes - UDP_DATAGRAM_HEADER_BYTES;
    let fragment_count = if payload.is_empty() {
        1
    } else {
        payload.len().div_ceil(max_fragment_payload)
    };
    if fragment_count > usize::from(MAX_UDP_FRAGMENTS) {
        return Err(UdpProtocolError::TooManyFragments);
    }
    let fragment_count = fragment_count as u16;
    let mut frames = Vec::with_capacity(usize::from(fragment_count));
    if payload.is_empty() {
        frames.push(
            UdpFragment {
                direction,
                session_id,
                datagram_id,
                fragment_index: 0,
                fragment_count: 1,
                original_length: 0,
                payload: Vec::new(),
            }
            .encode()?,
        );
        return Ok(frames);
    }

    for (index, chunk) in payload.chunks(max_fragment_payload).enumerate() {
        frames.push(
            UdpFragment {
                direction,
                session_id,
                datagram_id,
                fragment_index: index as u16,
                fragment_count,
                original_length: payload.len() as u32,
                payload: chunk.to_vec(),
            }
            .encode()?,
        );
    }
    Ok(frames)
}

fn validate_fragment(fragment: &UdpFragment) -> Result<(), UdpProtocolError> {
    if fragment.session_id.is_nil() {
        return Err(UdpProtocolError::NilSessionId);
    }
    if fragment.fragment_count == 0 || fragment.fragment_count > MAX_UDP_FRAGMENTS {
        return Err(UdpProtocolError::InvalidFragmentCount(
            fragment.fragment_count,
        ));
    }
    if fragment.fragment_index >= fragment.fragment_count {
        return Err(UdpProtocolError::InvalidFragmentIndex {
            index: fragment.fragment_index,
            count: fragment.fragment_count,
        });
    }
    let original_length = fragment.original_length as usize;
    if original_length > MAX_UDP_DATAGRAM_BYTES {
        return Err(UdpProtocolError::DatagramTooLarge(original_length));
    }
    if original_length == 0 {
        if fragment.fragment_count != 1
            || fragment.fragment_index != 0
            || !fragment.payload.is_empty()
        {
            return Err(UdpProtocolError::InvalidFragmentLength);
        }
        return Ok(());
    }
    if fragment.payload.is_empty() || fragment.payload.len() > original_length {
        return Err(UdpProtocolError::InvalidFragmentLength);
    }
    if fragment.fragment_count == 1 && fragment.payload.len() != original_length {
        return Err(UdpProtocolError::InvalidFragmentLength);
    }
    if fragment.fragment_count > 1 && fragment.payload.len() == original_length {
        return Err(UdpProtocolError::InvalidFragmentLength);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session_id() -> Uuid {
        Uuid::from_u128(1)
    }

    #[test]
    fn fragment_round_trip_preserves_all_header_fields() {
        let fragment = UdpFragment {
            direction: UdpDirection::TargetToPublic,
            session_id: session_id(),
            datagram_id: u64::MAX - 7,
            fragment_index: 1,
            fragment_count: 2,
            original_length: 5,
            payload: vec![4, 5],
        };
        let encoded = fragment.encode().expect("fragment should encode");
        assert_eq!(encoded.len(), UDP_DATAGRAM_HEADER_BYTES + 2);
        assert_eq!(UdpFragment::decode(&encoded), Ok(fragment));
    }

    #[test]
    fn zero_length_datagram_is_valid() {
        let frames = fragment_datagram(UdpDirection::PublicToTarget, session_id(), 9, &[], 1_200)
            .expect("zero-length datagram should encode");
        assert_eq!(frames.len(), 1);
        let fragment = UdpFragment::decode(&frames[0]).expect("frame should decode");
        assert_eq!(fragment.original_length, 0);
        assert!(fragment.payload.is_empty());
    }

    #[test]
    fn maximum_datagram_fragments_within_sixty_four_frames() {
        let payload = vec![0x5a; MAX_UDP_DATAGRAM_BYTES];
        let frames = fragment_datagram(
            UdpDirection::PublicToTarget,
            session_id(),
            10,
            &payload,
            1_200,
        )
        .expect("maximum datagram should fit into QUIC-sized frames");
        assert!(frames.len() <= usize::from(MAX_UDP_FRAGMENTS));
        let rebuilt = frames
            .iter()
            .flat_map(|frame| {
                UdpFragment::decode(frame)
                    .expect("frame should decode")
                    .payload
            })
            .collect::<Vec<_>>();
        assert_eq!(rebuilt, payload);
    }

    #[test]
    fn fragmentation_enforces_datagram_and_frame_limits() {
        let oversized = vec![0; MAX_UDP_DATAGRAM_BYTES + 1];
        assert_eq!(
            fragment_datagram(
                UdpDirection::PublicToTarget,
                session_id(),
                1,
                &oversized,
                1_200
            ),
            Err(UdpProtocolError::DatagramTooLarge(
                MAX_UDP_DATAGRAM_BYTES + 1
            ))
        );
        assert_eq!(
            fragment_datagram(
                UdpDirection::PublicToTarget,
                session_id(),
                1,
                &[1],
                UDP_DATAGRAM_HEADER_BYTES
            ),
            Err(UdpProtocolError::FrameLimitTooSmall)
        );
        assert_eq!(
            fragment_datagram(
                UdpDirection::PublicToTarget,
                session_id(),
                1,
                &[0; 65],
                UDP_DATAGRAM_HEADER_BYTES + 1
            ),
            Err(UdpProtocolError::TooManyFragments)
        );
    }

    #[test]
    fn decoder_rejects_malformed_fixed_header_fields() {
        let valid = fragment_datagram(
            UdpDirection::PublicToTarget,
            session_id(),
            1,
            &[1, 2, 3],
            1_200,
        )
        .expect("frame should encode")
        .remove(0);

        assert_eq!(
            UdpFragment::decode(&valid[..UDP_DATAGRAM_HEADER_BYTES - 1]),
            Err(UdpProtocolError::FrameTooShort(
                UDP_DATAGRAM_HEADER_BYTES - 1
            ))
        );
        let mut malformed = valid.clone();
        malformed[0] = b'X';
        assert_eq!(
            UdpFragment::decode(&malformed),
            Err(UdpProtocolError::InvalidMagic)
        );
        let mut malformed = valid.clone();
        malformed[4] = 2;
        assert_eq!(
            UdpFragment::decode(&malformed),
            Err(UdpProtocolError::UnsupportedVersion(2))
        );
        let mut malformed = valid.clone();
        malformed[5] = 0xff;
        assert_eq!(
            UdpFragment::decode(&malformed),
            Err(UdpProtocolError::InvalidDirection(0xff))
        );
        let mut malformed = valid;
        malformed[7] = 1;
        assert_eq!(
            UdpFragment::decode(&malformed),
            Err(UdpProtocolError::UnsupportedFlags(1))
        );
    }

    #[test]
    fn decoder_rejects_invalid_fragment_metadata() {
        let base = UdpFragment {
            direction: UdpDirection::PublicToTarget,
            session_id: session_id(),
            datagram_id: 1,
            fragment_index: 0,
            fragment_count: 1,
            original_length: 1,
            payload: vec![1],
        }
        .encode()
        .expect("base frame should encode");

        let mut malformed = base.clone();
        malformed[8..24].fill(0);
        assert_eq!(
            UdpFragment::decode(&malformed),
            Err(UdpProtocolError::NilSessionId)
        );
        let mut malformed = base.clone();
        malformed[34..36].copy_from_slice(&0_u16.to_be_bytes());
        assert_eq!(
            UdpFragment::decode(&malformed),
            Err(UdpProtocolError::InvalidFragmentCount(0))
        );
        let mut malformed = base.clone();
        malformed[32..34].copy_from_slice(&1_u16.to_be_bytes());
        assert_eq!(
            UdpFragment::decode(&malformed),
            Err(UdpProtocolError::InvalidFragmentIndex { index: 1, count: 1 })
        );
        let mut malformed = base.clone();
        malformed[36..40].copy_from_slice(&((MAX_UDP_DATAGRAM_BYTES + 1) as u32).to_be_bytes());
        assert_eq!(
            UdpFragment::decode(&malformed),
            Err(UdpProtocolError::DatagramTooLarge(
                MAX_UDP_DATAGRAM_BYTES + 1
            ))
        );
        let mut malformed = base;
        malformed[36..40].copy_from_slice(&2_u32.to_be_bytes());
        assert_eq!(
            UdpFragment::decode(&malformed),
            Err(UdpProtocolError::InvalidFragmentLength)
        );
    }
}
