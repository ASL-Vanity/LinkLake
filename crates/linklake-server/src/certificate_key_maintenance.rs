//! 停服维护：一个 PostgreSQL 事务内轮换全部证书私钥和 ACME 账户密文。
//! 调用方必须先停止所有副本；租约检查不能代替确认进程已经退出。

use std::{fmt, path::Path};

use serde::Serialize;
use tokio_postgres::Transaction;
use uuid::Uuid;

use crate::{
    certificate_catalog::{
        normalize_certificate_identifier,
        postgres::{private_key_context, CERTIFICATE_STATE_LOCK},
    },
    certificate_material::CertificateMaterialCipher,
    storage::CoordinationStorage,
};

/// 可输出到 CLI/审计；不包含域名、账户、证书正文、路径或密钥字节。
#[derive(Debug, Serialize)]
pub(crate) struct CertificateKeyRotationSummary {
    pub(crate) previous_fingerprint: String,
    pub(crate) current_fingerprint: String,
    pub(crate) certificates_reencrypted: u64,
    pub(crate) accounts_reencrypted: u64,
}

/// 故意不附底层错误链：数据库约束详情或解码错误可能包含材料正文。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CertificateKeyMaintenanceError {
    InvalidKeyFile,
    UnchangedKey,
    DatabaseUnavailable,
    TransactionFailed,
    ActiveInstances,
    MissingBinding,
    WrongPreviousKey,
    InvalidStoredMaterial,
    EncryptionFailed,
}

impl CertificateKeyMaintenanceError {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::InvalidKeyFile => "certificate_rotation_invalid_key_file",
            Self::UnchangedKey => "certificate_rotation_unchanged_key",
            Self::DatabaseUnavailable => "certificate_rotation_database_unavailable",
            Self::TransactionFailed => "certificate_rotation_transaction_failed",
            Self::ActiveInstances => "certificate_rotation_active_instances",
            Self::MissingBinding => "certificate_rotation_missing_binding",
            Self::WrongPreviousKey => "certificate_rotation_wrong_previous_key",
            Self::InvalidStoredMaterial => "certificate_rotation_invalid_material",
            Self::EncryptionFailed => "certificate_rotation_encryption_failed",
        }
    }
}

impl fmt::Display for CertificateKeyMaintenanceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for CertificateKeyMaintenanceError {}

type Result<T> = std::result::Result<T, CertificateKeyMaintenanceError>;

fn database<T>(result: std::result::Result<T, tokio_postgres::Error>) -> Result<T> {
    result.map_err(|_| CertificateKeyMaintenanceError::TransactionFailed)
}

/// 仅接受已有、权限严格的 32 字节文件。该入口不创建密钥、不修改文件或运行迁移。
/// 返回成功意味着 COMMIT 得到确认；COMMIT 连接中断时必须先核对 binding 再决定恢复。
pub(crate) async fn rotate_postgres_certificate_key(
    storage: &CoordinationStorage,
    previous_key_file: &Path,
    next_key_file: &Path,
) -> Result<CertificateKeyRotationSummary> {
    let previous = CertificateMaterialCipher::from_key_file(previous_key_file)
        .map_err(|_| CertificateKeyMaintenanceError::InvalidKeyFile)?;
    let next = CertificateMaterialCipher::from_key_file(next_key_file)
        .map_err(|_| CertificateKeyMaintenanceError::InvalidKeyFile)?;
    let previous_fingerprint = previous.fingerprint();
    let current_fingerprint = next.fingerprint();
    if previous_fingerprint == current_fingerprint {
        return Err(CertificateKeyMaintenanceError::UnchangedKey);
    }
    let mut client = storage
        .postgres_client()
        .await
        .map_err(|_| CertificateKeyMaintenanceError::DatabaseUnavailable)?;
    let transaction = database(client.transaction().await)?;
    // 防止锁等待无限挂起；证书目录先取同一个 advisory lock，与生产写入顺序一致。
    database(
        transaction
            .batch_execute("SET LOCAL lock_timeout = '10s'")
            .await,
    )?;
    database(
        transaction
            .query_one(
                "SELECT pg_advisory_xact_lock($1)",
                &[&CERTIFICATE_STATE_LOCK],
            )
            .await,
    )?;
    // 禁止维护期间新成员登记/续租。活实例检查在锁后进行，避免检查与登记竞争。
    database(
        transaction
            .batch_execute(
                "LOCK TABLE linklake_ha_members, linklake_ha_leader IN SHARE MODE;
         LOCK TABLE linklake_certificate_key_binding, linklake_certificate_materials,
                    linklake_acme_accounts IN SHARE ROW EXCLUSIVE MODE",
            )
            .await,
    )?;
    let active: bool = database(transaction.query_one(
        "SELECT EXISTS(SELECT 1 FROM linklake_ha_members WHERE lease_until > clock_timestamp())
             OR EXISTS(SELECT 1 FROM linklake_ha_leader WHERE lease_until > clock_timestamp())",
        &[],
    ).await)?.get(0);
    if active {
        return Err(CertificateKeyMaintenanceError::ActiveInstances);
    }
    let binding = database(transaction.query_opt(
        "SELECT fingerprint FROM linklake_certificate_key_binding WHERE singleton_id=1 FOR UPDATE",
        &[],
    ).await)?.ok_or(CertificateKeyMaintenanceError::MissingBinding)?;
    let bound: String = binding.get(0);
    if bound != previous_fingerprint {
        return Err(CertificateKeyMaintenanceError::WrongPreviousKey);
    }

    let certificates_reencrypted = rotate_certificates(&transaction, &previous, &next).await?;
    let accounts_reencrypted = rotate_accounts(&transaction, &previous, &next).await?;
    let changed = database(transaction.execute(
        "UPDATE linklake_certificate_key_binding SET fingerprint=$1 WHERE singleton_id=1 AND fingerprint=$2",
        &[&current_fingerprint, &previous_fingerprint],
    ).await)?;
    if changed != 1 {
        return Err(CertificateKeyMaintenanceError::WrongPreviousKey);
    }
    database(transaction.commit().await)?;
    Ok(CertificateKeyRotationSummary {
        previous_fingerprint,
        current_fingerprint,
        certificates_reencrypted,
        accounts_reencrypted,
    })
}

/// 保留原 generation、时间、证书正文和策略，不触发证书重新签发。
async fn rotate_certificates(
    transaction: &Transaction<'_>,
    previous: &CertificateMaterialCipher,
    next: &CertificateMaterialCipher,
) -> Result<u64> {
    let mut after: Option<String> = None;
    let mut count = 0;
    loop {
        // 每批最多 8 条（单条证书和材料各受数据库 2MiB 限制）。
        let rows = database(
            transaction
                .query(
                    "SELECT identifier,route_id,certificate_pem,encrypted_private_key
             FROM linklake_certificate_materials
             WHERE ($1::text IS NULL OR identifier > $1) ORDER BY identifier LIMIT 8 FOR UPDATE",
                    &[&after],
                )
                .await,
        )?;
        if rows.is_empty() {
            return Ok(count);
        }
        for row in rows {
            let identifier: String = row.get(0);
            let route: String = row.get(1);
            let certificate: Vec<u8> = row.get(2);
            let encrypted: Vec<u8> = row.get(3);
            let route_id = Uuid::parse_str(&route)
                .map_err(|_| CertificateKeyMaintenanceError::InvalidStoredMaterial)?;
            let normalized = normalize_certificate_identifier(&identifier)
                .map_err(|_| CertificateKeyMaintenanceError::InvalidStoredMaterial)?;
            if normalized != identifier {
                return Err(CertificateKeyMaintenanceError::InvalidStoredMaterial);
            }
            let context = private_key_context(route_id, &identifier, &certificate);
            let replacement = reencrypt(previous, next, &context, &encrypted)?;
            let changed = database(
                transaction
                    .execute(
                        "UPDATE linklake_certificate_materials SET encrypted_private_key=$1
                 WHERE identifier=$2 AND route_id=$3",
                        &[&replacement, &identifier, &route],
                    )
                    .await,
            )?;
            if changed != 1 {
                return Err(CertificateKeyMaintenanceError::TransactionFailed);
            }
            after = Some(identifier);
            count += 1;
        }
    }
}

async fn rotate_accounts(
    transaction: &Transaction<'_>,
    previous: &CertificateMaterialCipher,
    next: &CertificateMaterialCipher,
) -> Result<u64> {
    let mut after: Option<String> = None;
    let mut count = 0;
    loop {
        let rows = database(transaction.query(
            "SELECT directory_url,encrypted_credentials FROM linklake_acme_accounts
             WHERE ($1::text IS NULL OR directory_url > $1) ORDER BY directory_url LIMIT 8 FOR UPDATE",
            &[&after],
        ).await)?;
        if rows.is_empty() {
            return Ok(count);
        }
        for row in rows {
            let directory: String = row.get(0);
            let encrypted: Vec<u8> = row.get(1);
            let replacement = reencrypt(
                previous,
                next,
                &format!("acme-account:{directory}"),
                &encrypted,
            )?;
            let changed = database(transaction.execute(
                "UPDATE linklake_acme_accounts SET encrypted_credentials=$1 WHERE directory_url=$2",
                &[&replacement, &directory],
            ).await)?;
            if changed != 1 {
                return Err(CertificateKeyMaintenanceError::TransactionFailed);
            }
            after = Some(directory);
            count += 1;
        }
    }
}

fn reencrypt(
    previous: &CertificateMaterialCipher,
    next: &CertificateMaterialCipher,
    context: &str,
    encrypted: &[u8],
) -> Result<Vec<u8>> {
    // open 返回 Zeroizing，明文既不写日志也不离开本函数。
    let plaintext = previous
        .open(context, encrypted)
        .map_err(|_| CertificateKeyMaintenanceError::InvalidStoredMaterial)?;
    next.seal(context, &plaintext)
        .map_err(|_| CertificateKeyMaintenanceError::EncryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn test_cipher(byte: u8) -> CertificateMaterialCipher {
        // 仅供测试的固定材料；独立临时文件以 create_new 和严格权限创建。
        let path = std::env::temp_dir().join(format!("linklake-rotation-test-{}", Uuid::new_v4()));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&path).unwrap();
        file.write_all(&[byte; 32]).unwrap();
        drop(file);
        let cipher = CertificateMaterialCipher::from_key_file(&path);
        std::fs::remove_file(path).unwrap();
        cipher.unwrap()
    }

    #[test]
    fn reencrypt_preserves_plaintext_and_context_but_replaces_key() {
        let previous = test_cipher(7);
        let next = test_cipher(9);
        for context in [
            "certificate-key:route:example.test:hash",
            "acme-account:https://ca.example/directory",
        ] {
            let original = previous.seal(context, b"private test material").unwrap();
            let replacement = reencrypt(&previous, &next, context, &original).unwrap();
            assert_eq!(
                &**next.open(context, &replacement).unwrap(),
                b"private test material"
            );
            assert!(previous.open(context, &replacement).is_err());
            assert!(next.open("another-resource", &replacement).is_err());
            let rollback = reencrypt(&next, &previous, context, &replacement).unwrap();
            assert_eq!(
                &**previous.open(context, &rollback).unwrap(),
                b"private test material"
            );
        }
    }

    #[test]
    fn corrupt_material_returns_safe_error_without_underlying_details() {
        let previous = test_cipher(11);
        let next = test_cipher(13);
        let mut original = previous
            .seal("acme-account:directory", b"private test credentials")
            .unwrap();
        original[8] ^= 1;
        let error = reencrypt(&previous, &next, "acme-account:directory", &original).unwrap_err();
        assert_eq!(error, CertificateKeyMaintenanceError::InvalidStoredMaterial);
        assert_eq!(error.to_string(), "certificate_rotation_invalid_material");
        assert!(std::error::Error::source(&error).is_none());
    }
}
