//! 共享证书材料的认证加密封装。集群密钥来自独立文件，不写入共享数据库。

use chacha20poly1305::{
    aead::{AeadInOut, KeyInit},
    Tag, XChaCha20Poly1305, XNonce,
};
use std::{fs::File, io::Read, path::Path};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"LLCERT01";
const NONCE_BYTES: usize = 24;
const TAG_BYTES: usize = 16;
pub(crate) const MAX_MATERIAL_BYTES: usize = 2 * 1024 * 1024;

pub(crate) struct CertificateMaterialCipher {
    key: Zeroizing<[u8; 32]>,
}

impl CertificateMaterialCipher {
    /// 文件必须恰好包含 32 字节随机密钥；所有 HA 成员使用同一密钥。
    pub(crate) fn from_key_file(path: &Path) -> anyhow::Result<Self> {
        let file = File::open(path)?;
        let metadata = file.metadata()?;
        anyhow::ensure!(
            metadata.is_file() && metadata.len() == 32,
            "certificate material key file must contain exactly 32 bytes"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            anyhow::ensure!(
                metadata.permissions().mode() & 0o077 == 0,
                "certificate material key must not allow group or other access"
            );
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(33));
        file.take(33).read_to_end(&mut bytes)?;
        anyhow::ensure!(
            bytes.len() == 32,
            "certificate material key file changed while reading"
        );
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&bytes);
        Ok(Self { key })
    }

    pub(crate) fn seal(&self, context: &str, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        anyhow::ensure!(
            plaintext.len() <= MAX_MATERIAL_BYTES,
            "certificate material exceeds size limit"
        );
        let aad = associated_data(context)?;
        let mut nonce_bytes = [0u8; NONCE_BYTES];
        getrandom::fill(&mut nonce_bytes)
            .map_err(|_| anyhow::anyhow!("secure randomness unavailable"))?;
        let nonce = XNonce::try_from(nonce_bytes.as_slice()).expect("fixed nonce length");
        let cipher = XChaCha20Poly1305::new_from_slice(self.key.as_ref())
            .map_err(|_| anyhow::anyhow!("invalid material key"))?;
        let mut buffer = Zeroizing::new(plaintext.to_vec());
        let tag = cipher
            .encrypt_inout_detached(&nonce, &aad, buffer.as_mut_slice().into())
            .map_err(|_| anyhow::anyhow!("certificate material encryption failed"))?;
        let mut envelope = Vec::with_capacity(MAGIC.len() + NONCE_BYTES + buffer.len() + TAG_BYTES);
        envelope.extend_from_slice(MAGIC);
        envelope.extend_from_slice(&nonce_bytes);
        envelope.extend_from_slice(&buffer);
        envelope.extend_from_slice(tag.as_ref());
        Ok(envelope)
    }

    pub(crate) fn open(
        &self,
        context: &str,
        envelope: &[u8],
    ) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        let overhead = MAGIC.len() + NONCE_BYTES + TAG_BYTES;
        anyhow::ensure!(
            envelope.len() >= overhead && envelope.len() <= MAX_MATERIAL_BYTES + overhead,
            "invalid certificate material length"
        );
        anyhow::ensure!(
            envelope.starts_with(MAGIC),
            "unsupported certificate material format"
        );
        let aad = associated_data(context)?;
        let nonce = XNonce::try_from(&envelope[MAGIC.len()..MAGIC.len() + NONCE_BYTES])
            .expect("fixed nonce length");
        let tag = Tag::try_from(&envelope[envelope.len() - TAG_BYTES..]).expect("fixed tag length");
        let mut plaintext = Zeroizing::new(
            envelope[MAGIC.len() + NONCE_BYTES..envelope.len() - TAG_BYTES].to_vec(),
        );
        let cipher = XChaCha20Poly1305::new_from_slice(self.key.as_ref())
            .map_err(|_| anyhow::anyhow!("invalid material key"))?;
        cipher
            .decrypt_inout_detached(&nonce, &aad, plaintext.as_mut_slice().into(), &tag)
            .map_err(|_| anyhow::anyhow!("certificate material authentication failed"))?;
        Ok(plaintext)
    }
}

fn associated_data(context: &str) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(
        !context.is_empty() && context.len() <= 4096,
        "invalid certificate material context"
    );
    let mut aad = Vec::with_capacity(MAGIC.len() + context.len());
    aad.extend_from_slice(MAGIC);
    aad.extend_from_slice(context.as_bytes());
    Ok(aad)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn material_authentication_binds_key_context_and_every_envelope_byte() {
        let cipher = CertificateMaterialCipher {
            key: Zeroizing::new([7; 32]),
        };
        let envelope = cipher
            .seal("certificate:example.com", b"private material")
            .unwrap();
        assert_eq!(
            &**cipher.open("certificate:example.com", &envelope).unwrap(),
            b"private material"
        );
        assert!(cipher.open("certificate:other.example", &envelope).is_err());
        let other = CertificateMaterialCipher {
            key: Zeroizing::new([8; 32]),
        };
        assert!(other.open("certificate:example.com", &envelope).is_err());
        for index in 0..envelope.len() {
            let mut changed = envelope.clone();
            changed[index] ^= 1;
            assert!(cipher.open("certificate:example.com", &changed).is_err());
        }
        assert_ne!(
            envelope,
            cipher
                .seal("certificate:example.com", b"private material")
                .unwrap()
        );
    }

    #[test]
    fn material_rejects_truncation_and_oversized_input() {
        let cipher = CertificateMaterialCipher {
            key: Zeroizing::new([9; 32]),
        };
        let envelope = cipher
            .seal("acme:directory", b"account credentials")
            .unwrap();
        for length in 0..envelope.len() {
            assert!(cipher.open("acme:directory", &envelope[..length]).is_err());
        }
        assert!(cipher
            .seal("certificate:test", &vec![0; MAX_MATERIAL_BYTES + 1])
            .is_err());
    }
}
