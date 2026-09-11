//! PostgreSQL 证书配置和状态目录；写入在同一共享锁及 Leader fencing 下执行。

use super::*;
use crate::{
    certificate_material::{CertificateMaterialCipher, MAX_MATERIAL_BYTES},
    job_leases::JobLease,
};
use crate::{ha_runtime::HaRuntime, storage::CoordinationStorage};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio_postgres::Transaction as PgTransaction;
use zeroize::Zeroizing;

pub(crate) const CERTIFICATE_STATE_LOCK: i64 = 0x4c4c_4345_5254_5354;

async fn http_route_is_current(
    transaction: &PgTransaction<'_>,
    expected: &crate::http_route_catalog::HttpRoutePolicy,
    revision: Uuid,
    tls: &RouteTlsPolicy,
    identifier: &str,
) -> anyhow::Result<bool> {
    let current =
        crate::http_route_catalog::postgres::transaction_snapshot(transaction, expected.id).await?;
    Ok(http_route_snapshot_matches(
        current.as_ref(),
        expected,
        revision,
        tls,
        identifier,
    ))
}

fn http_route_snapshot_matches(
    current: Option<&crate::http_route_catalog::postgres::HttpRouteSnapshot>,
    expected: &crate::http_route_catalog::HttpRoutePolicy,
    revision: Uuid,
    tls: &RouteTlsPolicy,
    identifier: &str,
) -> bool {
    current.is_some_and(|current| {
        current.revision == revision
            && current.policy == *expected
            && current.policy.enabled
            && tls.route_id == expected.id
            && tls.mode == RouteTlsMode::Acme
            && tls
                .certificate_identifier
                .as_deref()
                .unwrap_or(&current.policy.hostname)
                == identifier
            && certificate_identifier_covers_hostname(identifier, &current.policy.hostname)
    })
}

pub(crate) struct PostgresCertificateCatalog {
    pub(crate) storage: CoordinationStorage,
    pub(crate) runtime: Arc<HaRuntime>,
}

pub(crate) struct SharedCertificateMaterial {
    pub(crate) generation: String,
    pub(crate) certificate_pem: Vec<u8>,
    pub(crate) private_key_pem: Zeroizing<Vec<u8>>,
}

pub(crate) struct RouteTlsSnapshot {
    pub(crate) policy: RouteTlsPolicy,
    pub(crate) revision: Uuid,
}

pub(crate) fn certificate_job_key(identifier: &str) -> anyhow::Result<String> {
    let identifier = normalize_certificate_identifier(identifier)?;
    Ok(format!(
        "certificate:{:x}",
        Sha256::digest(identifier.as_bytes())
    ))
}

pub(crate) fn acme_account_job_key(directory_url: &str) -> anyhow::Result<String> {
    validate_https_url(directory_url)?;
    Ok(format!(
        "acme_account:{:x}",
        Sha256::digest(directory_url.as_bytes())
    ))
}

impl PostgresCertificateCatalog {
    pub(crate) async fn route_views(
        &self,
        route_ids: &[Uuid],
    ) -> anyhow::Result<
        std::collections::HashMap<Uuid, (Option<RouteTlsPolicy>, Option<CertificateState>)>,
    > {
        let ids: Vec<_> = route_ids.iter().map(Uuid::to_string).collect();
        let client = self.storage.postgres_client().await?;
        client.query("SELECT wanted.route_id,tls.policy::text,cert.state::text FROM unnest($1::text[]) AS wanted(route_id)
            LEFT JOIN linklake_route_tls AS tls ON tls.route_id=wanted.route_id
            LEFT JOIN linklake_certificate_states AS cert ON cert.route_id=wanted.route_id", &[&ids]).await?.iter().map(|row| {
                Ok((Uuid::parse_str(row.get(0))?,(row.get::<_,Option<&str>>(1).map(serde_json::from_str).transpose()?,row.get::<_,Option<&str>>(2).map(serde_json::from_str).transpose()?)))
            }).collect()
    }

    pub(crate) async fn record_failure_if_tls_current(
        &self,
        lease: &JobLease,
        expected_tls: &RouteTlsPolicy,
        revision: Uuid,
        expected_route: &crate::http_route_catalog::HttpRoutePolicy,
        route_revision: Uuid,
        expected_config: &AcmeConfig,
        identifier: &str,
        error_code: &str,
        error_message: &str,
    ) -> anyhow::Result<bool> {
        anyhow::ensure!(
            lease.job_kind == "certificate" && lease.job_key == certificate_job_key(identifier)?,
            "certificate job identity does not match failure"
        );
        let error_code = error_code.trim();
        let error_message = error_message.trim();
        anyhow::ensure!(
            !error_code.is_empty()
                && error_code.len() <= 80
                && error_code
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')),
            "invalid certificate failure code"
        );
        anyhow::ensure!(
            !error_message.is_empty() && error_message.len() <= 2000,
            "invalid certificate failure message"
        );
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        self.fence(&transaction).await?;
        self.runtime
            .jobs()
            .assert_postgres_transaction_lease(&transaction, lease)
            .await?;
        let current = transaction
            .query_opt(
                "SELECT policy::text,revision FROM linklake_route_tls WHERE route_id=$1 FOR UPDATE",
                &[&expected_tls.route_id.to_string()],
            )
            .await?
            .map(|row| -> anyhow::Result<_> {
                Ok((
                    serde_json::from_str::<RouteTlsPolicy>(row.get(0))?,
                    Uuid::parse_str(row.get(1))?,
                ))
            })
            .transpose()?;
        let config = read_acme_config(&transaction).await?;
        if !http_route_is_current(
            &transaction,
            expected_route,
            route_revision,
            expected_tls,
            identifier,
        )
        .await?
        {
            transaction.commit().await?;
            return Ok(false);
        }
        if !current.as_ref().is_some_and(|(policy, current_revision)| {
            policy == expected_tls && *current_revision == revision
        }) || expected_tls.mode != RouteTlsMode::Acme
            || !config.enabled
            || &config != expected_config
        {
            transaction.commit().await?;
            return Ok(false);
        }
        let mut state = read_state(&transaction, expected_tls.route_id)
            .await?
            .unwrap_or_else(|| empty_state(expected_tls.route_id, CertificateStatus::Error));
        state.status = CertificateStatus::Error;
        state.last_attempt = Some(database_now(&transaction).await?);
        state.failure_count = state
            .failure_count
            .checked_add(1)
            .ok_or(CertificateCatalogError::InvalidStoredData("failure_count"))?;
        state.last_error_code = Some(error_code.to_owned());
        state.last_error_message = Some(error_message.to_owned());
        save_state(&transaction, &state).await?;
        transaction.commit().await?;
        Ok(true)
    }

    pub(crate) async fn material_key_fingerprint(&self) -> anyhow::Result<Option<String>> {
        let client = self.storage.postgres_client().await?;
        Ok(client
            .query_opt(
                "SELECT fingerprint FROM linklake_certificate_key_binding WHERE singleton_id=1",
                &[],
            )
            .await?
            .map(|row| row.get(0)))
    }

    pub(crate) async fn bind_material_key(
        &self,
        cipher: &CertificateMaterialCipher,
    ) -> anyhow::Result<()> {
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        self.fence(&transaction).await?;
        bind_key(&transaction, cipher).await?;
        transaction.commit().await?;
        Ok(())
    }

    /// 证书、私钥密文和成功状态必须共同提交，不能留下只有 active 状态的空证书。
    pub(crate) async fn commit_certificate_if_tls_current(
        &self,
        cipher: &CertificateMaterialCipher,
        lease: &JobLease,
        expected_tls: &RouteTlsPolicy,
        expected_tls_revision: Uuid,
        expected_route: &crate::http_route_catalog::HttpRoutePolicy,
        route_revision: Uuid,
        expected_config: &AcmeConfig,
        identifier: &str,
        certificate_pem: &[u8],
        private_key_pem: &[u8],
    ) -> anyhow::Result<bool> {
        let identifier = normalize_certificate_identifier(identifier)?;
        anyhow::ensure!(
            expected_tls
                .certificate_identifier
                .as_ref()
                .is_none_or(|expected| expected == &identifier),
            "certificate identifier differs from TLS policy"
        );
        anyhow::ensure!(
            lease.job_kind == "certificate" && lease.job_key == certificate_job_key(&identifier)?,
            "certificate job identity does not match material"
        );
        anyhow::ensure!(
            certificate_pem.len() <= MAX_MATERIAL_BYTES
                && private_key_pem.len() <= MAX_MATERIAL_BYTES,
            "certificate material exceeds size limit"
        );
        let metadata = crate::certificate_manager::validate_certificate(
            &identifier,
            certificate_pem,
            private_key_pem,
        )?
        .1;
        let context = private_key_context(expected_tls.route_id, &identifier, certificate_pem);
        let encrypted_key = cipher.seal(&context, private_key_pem)?;
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        self.fence(&transaction).await?;
        bind_key(&transaction, cipher).await?;
        self.runtime
            .jobs()
            .assert_postgres_transaction_lease(&transaction, lease)
            .await?;
        let current = transaction
            .query_opt(
                "SELECT policy::text,revision FROM linklake_route_tls WHERE route_id=$1 FOR UPDATE",
                &[&expected_tls.route_id.to_string()],
            )
            .await?
            .map(|row| -> anyhow::Result<_> {
                Ok((
                    serde_json::from_str::<RouteTlsPolicy>(row.get(0))?,
                    Uuid::parse_str(row.get(1))?,
                ))
            })
            .transpose()?;
        if !current.as_ref().is_some_and(|(policy, revision)| {
            policy == expected_tls && *revision == expected_tls_revision
        }) || expected_tls.mode != RouteTlsMode::Acme
        {
            transaction.commit().await?;
            return Ok(false);
        }
        let config = read_acme_config(&transaction).await?;
        if !config.enabled || &config != expected_config {
            transaction.commit().await?;
            return Ok(false);
        }
        if !http_route_is_current(
            &transaction,
            expected_route,
            route_revision,
            expected_tls,
            &identifier,
        )
        .await?
        {
            transaction.commit().await?;
            return Ok(false);
        }
        let now = database_now(&transaction).await?;
        let not_before = i64::try_from(metadata.not_before_unix_seconds)?;
        let not_after = i64::try_from(metadata.not_after_unix_seconds)?;
        anyhow::ensure!(
            not_before < not_after && now < not_after,
            "issued certificate has expired before commit"
        );
        let changed = transaction.execute(
            "INSERT INTO linklake_certificate_materials(identifier,route_id,generation,certificate_pem,encrypted_private_key,updated_unix_seconds)
             VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(identifier) DO UPDATE SET generation=EXCLUDED.generation,
             certificate_pem=EXCLUDED.certificate_pem,encrypted_private_key=EXCLUDED.encrypted_private_key,updated_unix_seconds=EXCLUDED.updated_unix_seconds
             WHERE linklake_certificate_materials.route_id=EXCLUDED.route_id",
            &[&identifier,&expected_tls.route_id.to_string(),&Uuid::new_v4().to_string(),&certificate_pem,&encrypted_key,&now],
        ).await?;
        anyhow::ensure!(
            changed == 1,
            "certificate material belongs to another route"
        );
        let state = CertificateState {
            route_id: expected_tls.route_id,
            status: CertificateStatus::Active,
            issuer: Some(metadata.issuer),
            not_before: Some(not_before),
            not_after: Some(not_after),
            next_renewal: Some(
                not_after
                    .saturating_sub(i64::from(config.renew_before_days) * SECONDS_PER_DAY)
                    .max(not_before),
            ),
            last_attempt: Some(now),
            last_success: Some(now),
            failure_count: 0,
            last_error_code: None,
            last_error_message: None,
        };
        save_state(&transaction, &state).await?;
        transaction.commit().await?;
        Ok(true)
    }

    pub(crate) async fn read_certificate_material(
        &self,
        cipher: &CertificateMaterialCipher,
        route_id: Uuid,
        identifier: &str,
    ) -> anyhow::Result<Option<SharedCertificateMaterial>> {
        let identifier = normalize_certificate_identifier(identifier)?;
        let client = self.storage.postgres_client().await?;
        let Some(row) = client.query_opt("SELECT generation,certificate_pem,encrypted_private_key FROM linklake_certificate_materials WHERE identifier=$1 AND route_id=$2",
            &[&identifier,&route_id.to_string()]).await? else { return Ok(None); };
        let certificate_pem: Vec<u8> = row.get(1);
        let encrypted_key: Vec<u8> = row.get(2);
        let private_key_pem = cipher.open(
            &private_key_context(route_id, &identifier, &certificate_pem),
            &encrypted_key,
        )?;
        crate::certificate_manager::validate_certificate(
            &identifier,
            &certificate_pem,
            &private_key_pem,
        )?;
        Ok(Some(SharedCertificateMaterial {
            generation: row.get(0),
            certificate_pem,
            private_key_pem,
        }))
    }

    pub(crate) async fn delete_certificate_material(
        &self,
        route_id: Uuid,
        identifier: &str,
    ) -> anyhow::Result<bool> {
        let identifier = normalize_certificate_identifier(identifier)?;
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        self.fence(&transaction).await?;
        let changed = transaction
            .execute(
                "DELETE FROM linklake_certificate_materials WHERE route_id=$1 AND identifier=$2",
                &[&route_id.to_string(), &identifier],
            )
            .await?
            > 0;
        transaction.commit().await?;
        Ok(changed)
    }

    pub(crate) async fn read_account_credentials(
        &self,
        cipher: &CertificateMaterialCipher,
        directory_url: &str,
    ) -> anyhow::Result<Option<Zeroizing<Vec<u8>>>> {
        validate_https_url(directory_url)?;
        let client = self.storage.postgres_client().await?;
        let row = client
            .query_opt(
                "SELECT encrypted_credentials FROM linklake_acme_accounts WHERE directory_url=$1",
                &[&directory_url],
            )
            .await?;
        row.map(|row| {
            cipher.open(
                &format!("acme-account:{directory_url}"),
                row.get::<_, &[u8]>(0),
            )
        })
        .transpose()
    }

    pub(crate) async fn store_account_if_absent(
        &self,
        cipher: &CertificateMaterialCipher,
        lease: &JobLease,
        directory_url: &str,
        credentials: &[u8],
    ) -> anyhow::Result<bool> {
        anyhow::ensure!(
            lease.job_kind == "acme_account"
                && lease.job_key == acme_account_job_key(directory_url)?,
            "ACME account job identity does not match directory"
        );
        anyhow::ensure!(
            credentials.len() <= MAX_MATERIAL_BYTES,
            "ACME account credentials exceed size limit"
        );
        let _: instant_acme::AccountCredentials = serde_json::from_slice(credentials)?;
        let encrypted = cipher.seal(&format!("acme-account:{directory_url}"), credentials)?;
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        self.fence(&transaction).await?;
        bind_key(&transaction, cipher).await?;
        self.runtime
            .jobs()
            .assert_postgres_transaction_lease(&transaction, lease)
            .await?;
        let now = database_now(&transaction).await?;
        let changed = transaction.execute("INSERT INTO linklake_acme_accounts(directory_url,encrypted_credentials,updated_unix_seconds)
            VALUES($1,$2,$3) ON CONFLICT(directory_url) DO NOTHING", &[&directory_url,&encrypted,&now]).await? > 0;
        transaction.commit().await?;
        Ok(changed)
    }

    pub(crate) async fn fence(&self, transaction: &PgTransaction<'_>) -> anyhow::Result<()> {
        transaction
            .query_one(
                "SELECT pg_advisory_xact_lock($1)",
                &[&CERTIFICATE_STATE_LOCK],
            )
            .await?;
        let token = self.runtime.fencing_token()?;
        self.runtime
            .coordinator()
            .assert_postgres_transaction_fence(transaction, token)
            .await?;
        Ok(())
    }

    pub(crate) async fn get_acme_config(&self) -> anyhow::Result<AcmeConfig> {
        let client = self.storage.postgres_client().await?;
        let row = client
            .query_one(
                "SELECT config::text FROM linklake_acme_config WHERE singleton_id=1",
                &[],
            )
            .await?;
        Ok(serde_json::from_str(row.get(0))?)
    }

    pub(crate) async fn update_acme_config(
        &self,
        request: UpdateAcmeConfig,
        _now: i64,
    ) -> anyhow::Result<AcmeConfig> {
        validate_acme_config(&request)?;
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        self.fence(&transaction).await?;
        let existing = read_acme_config(&transaction).await?;
        let config = AcmeConfig {
            enabled: request.enabled,
            environment: request.environment,
            directory_url: request.directory_url.trim().to_owned(),
            contact_email: request.contact_email.trim().to_ascii_lowercase(),
            terms_accepted: request.terms_accepted,
            challenge_type: request.challenge_type.unwrap_or(existing.challenge_type),
            renew_before_days: request.renew_before_days,
            updated_at: database_now(&transaction).await?,
        };
        transaction
            .execute(
                "UPDATE linklake_acme_config SET config=$1::text::jsonb WHERE singleton_id=1",
                &[&serde_json::to_string(&config)?],
            )
            .await?;
        transaction.commit().await?;
        Ok(config)
    }

    pub(crate) async fn get_route_tls(
        &self,
        route_id: Uuid,
    ) -> anyhow::Result<Option<RouteTlsPolicy>> {
        let client = self.storage.postgres_client().await?;
        client
            .query_opt(
                "SELECT policy::text FROM linklake_route_tls WHERE route_id=$1",
                &[&route_id.to_string()],
            )
            .await?
            .map(|row| serde_json::from_str(row.get(0)).map_err(Into::into))
            .transpose()
    }

    pub(crate) async fn get_route_tls_snapshot(
        &self,
        route_id: Uuid,
    ) -> anyhow::Result<Option<RouteTlsSnapshot>> {
        let client = self.storage.postgres_client().await?;
        client
            .query_opt(
                "SELECT policy::text,revision FROM linklake_route_tls WHERE route_id=$1",
                &[&route_id.to_string()],
            )
            .await?
            .map(|row| -> anyhow::Result<_> {
                Ok(RouteTlsSnapshot {
                    policy: serde_json::from_str(row.get(0))?,
                    revision: Uuid::parse_str(row.get(1))?,
                })
            })
            .transpose()
    }

    pub(crate) async fn set_route_tls(
        &self,
        route_id: Uuid,
        request: UpdateRouteTlsPolicy,
        _now: i64,
    ) -> anyhow::Result<RouteTlsPolicy> {
        if request.mode == RouteTlsMode::Disabled && request.redirect_http_to_https {
            return Err(CertificateCatalogError::InvalidRedirectPolicy.into());
        }
        let certificate_identifier = request
            .certificate_identifier
            .as_deref()
            .map(normalize_certificate_identifier)
            .transpose()
            .map_err(|_| CertificateCatalogError::InvalidCertificateIdentifier)?;
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        self.fence(&transaction).await?;
        let policy = RouteTlsPolicy {
            route_id,
            mode: request.mode,
            redirect_http_to_https: request.redirect_http_to_https,
            certificate_identifier,
            updated_at: database_now(&transaction).await?,
        };
        transaction
            .execute(
                "INSERT INTO linklake_route_tls(route_id,revision,policy) VALUES($1,$2,$3::text::jsonb)
            ON CONFLICT(route_id) DO UPDATE SET revision=EXCLUDED.revision,policy=EXCLUDED.policy",
                &[&route_id.to_string(), &Uuid::new_v4().to_string(), &serde_json::to_string(&policy)?],
            )
            .await?;
        transaction.commit().await?;
        Ok(policy)
    }

    pub(crate) async fn delete_route_tls(&self, route_id: Uuid) -> anyhow::Result<bool> {
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        self.fence(&transaction).await?;
        let changed = transaction
            .execute(
                "DELETE FROM linklake_route_tls WHERE route_id=$1",
                &[&route_id.to_string()],
            )
            .await?
            > 0;
        transaction
            .execute(
                "DELETE FROM linklake_certificate_materials WHERE route_id=$1",
                &[&route_id.to_string()],
            )
            .await?;
        transaction
            .execute(
                "DELETE FROM linklake_certificate_states WHERE route_id=$1",
                &[&route_id.to_string()],
            )
            .await?;
        transaction.commit().await?;
        Ok(changed)
    }

    pub(crate) async fn get_certificate_state(
        &self,
        route_id: Uuid,
    ) -> anyhow::Result<Option<CertificateState>> {
        let client = self.storage.postgres_client().await?;
        client
            .query_opt(
                "SELECT state::text FROM linklake_certificate_states WHERE route_id=$1",
                &[&route_id.to_string()],
            )
            .await?
            .map(|row| serde_json::from_str(row.get(0)).map_err(Into::into))
            .transpose()
    }

    pub(crate) async fn list_certificate_states(&self) -> anyhow::Result<Vec<CertificateState>> {
        let client = self.storage.postgres_client().await?;
        client
            .query(
                "SELECT state::text FROM linklake_certificate_states ORDER BY route_id",
                &[],
            )
            .await?
            .iter()
            .map(|row| serde_json::from_str(row.get(0)).map_err(Into::into))
            .collect()
    }

    pub(crate) async fn update_certificate_status(
        &self,
        route_id: Uuid,
        expected_status: Option<CertificateStatus>,
        new_status: CertificateStatus,
        attempted_at: Option<i64>,
    ) -> anyhow::Result<bool> {
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        self.fence(&transaction).await?;
        let existing = read_state(&transaction, route_id).await?;
        if existing.as_ref().map(|state| state.status) != expected_status {
            transaction.commit().await?;
            return Ok(false);
        }
        let mut state = existing.unwrap_or_else(|| empty_state(route_id, new_status));
        state.status = new_status;
        // 时间来源统一为共享数据库；调用参数只表示是否记录此次尝试。
        if attempted_at.is_some() {
            state.last_attempt = Some(database_now(&transaction).await?);
        }
        save_state(&transaction, &state).await?;
        transaction.commit().await?;
        Ok(true)
    }

    pub(crate) async fn record_certificate_success(
        &self,
        route_id: Uuid,
        issuer: &str,
        not_before: i64,
        not_after: i64,
        _completed_at: i64,
    ) -> anyhow::Result<CertificateState> {
        let issuer = issuer.trim();
        if issuer.is_empty() || issuer.len() > 255 {
            return Err(CertificateCatalogError::InvalidIssuer.into());
        }
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        self.fence(&transaction).await?;
        let now = database_now(&transaction).await?;
        if not_before >= not_after || now >= not_after {
            return Err(CertificateCatalogError::InvalidCertificateValidity.into());
        }
        let config = read_acme_config(&transaction).await?;
        let next_renewal = not_after
            .saturating_sub(i64::from(config.renew_before_days) * SECONDS_PER_DAY)
            .max(not_before);
        let state = CertificateState {
            route_id,
            status: CertificateStatus::Active,
            issuer: Some(issuer.to_owned()),
            not_before: Some(not_before),
            not_after: Some(not_after),
            next_renewal: Some(next_renewal),
            last_attempt: Some(now),
            last_success: Some(now),
            failure_count: 0,
            last_error_code: None,
            last_error_message: None,
        };
        save_state(&transaction, &state).await?;
        transaction.commit().await?;
        Ok(state)
    }

    pub(crate) async fn record_certificate_failure(
        &self,
        route_id: Uuid,
        error_code: &str,
        error_message: &str,
        _attempted_at: i64,
    ) -> anyhow::Result<CertificateState> {
        let error_code = error_code.trim();
        let error_message = error_message.trim();
        if error_code.is_empty()
            || error_code.len() > 80
            || !error_code
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        {
            return Err(CertificateCatalogError::InvalidErrorCode.into());
        }
        if error_message.is_empty() || error_message.len() > 2000 {
            return Err(CertificateCatalogError::InvalidErrorMessage.into());
        }
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        self.fence(&transaction).await?;
        let mut state = read_state(&transaction, route_id)
            .await?
            .unwrap_or_else(|| empty_state(route_id, CertificateStatus::Error));
        state.status = CertificateStatus::Error;
        state.last_attempt = Some(database_now(&transaction).await?);
        state.failure_count = state
            .failure_count
            .checked_add(1)
            .ok_or(CertificateCatalogError::InvalidStoredData("failure_count"))?;
        state.last_error_code = Some(error_code.to_owned());
        state.last_error_message = Some(error_message.to_owned());
        save_state(&transaction, &state).await?;
        transaction.commit().await?;
        Ok(state)
    }

    pub(crate) async fn delete_certificate_state(&self, route_id: Uuid) -> anyhow::Result<bool> {
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        self.fence(&transaction).await?;
        let changed = transaction
            .execute(
                "DELETE FROM linklake_certificate_states WHERE route_id=$1",
                &[&route_id.to_string()],
            )
            .await?
            > 0;
        transaction
            .execute(
                "DELETE FROM linklake_certificate_materials WHERE route_id=$1",
                &[&route_id.to_string()],
            )
            .await?;
        transaction.commit().await?;
        Ok(changed)
    }
}

async fn database_now(transaction: &PgTransaction<'_>) -> anyhow::Result<i64> {
    Ok(transaction
        .query_one(
            "SELECT floor(extract(epoch FROM clock_timestamp()))::bigint",
            &[],
        )
        .await?
        .get(0))
}

async fn read_acme_config(transaction: &PgTransaction<'_>) -> anyhow::Result<AcmeConfig> {
    let row = transaction
        .query_one(
            "SELECT config::text FROM linklake_acme_config WHERE singleton_id=1",
            &[],
        )
        .await?;
    Ok(serde_json::from_str(row.get(0))?)
}

async fn read_state(
    transaction: &PgTransaction<'_>,
    route_id: Uuid,
) -> anyhow::Result<Option<CertificateState>> {
    transaction
        .query_opt(
            "SELECT state::text FROM linklake_certificate_states WHERE route_id=$1 FOR UPDATE",
            &[&route_id.to_string()],
        )
        .await?
        .map(|row| serde_json::from_str(row.get(0)).map_err(Into::into))
        .transpose()
}

async fn save_state(
    transaction: &PgTransaction<'_>,
    state: &CertificateState,
) -> anyhow::Result<()> {
    transaction
        .execute(
            "INSERT INTO linklake_certificate_states(route_id,state) VALUES($1,$2::text::jsonb)
        ON CONFLICT(route_id) DO UPDATE SET state=EXCLUDED.state",
            &[&state.route_id.to_string(), &serde_json::to_string(state)?],
        )
        .await?;
    Ok(())
}

fn empty_state(route_id: Uuid, status: CertificateStatus) -> CertificateState {
    CertificateState {
        route_id,
        status,
        issuer: None,
        not_before: None,
        not_after: None,
        next_renewal: None,
        last_attempt: None,
        last_success: None,
        failure_count: 0,
        last_error_code: None,
        last_error_message: None,
    }
}

fn private_key_context(route_id: Uuid, identifier: &str, certificate_pem: &[u8]) -> String {
    // 绑定资源归属、域名和证书内容，拒绝跨行替换密文或混装证书与私钥。
    format!(
        "certificate-key:{route_id}:{identifier}:{:x}",
        Sha256::digest(certificate_pem)
    )
}

#[cfg(test)]
mod route_commit_tests {
    use super::*;
    use crate::http_route_catalog::{
        postgres::HttpRouteSnapshot, GrpcBackendTransport, HttpRoutePolicy,
    };

    #[test]
    fn certificate_commit_rejects_reverted_routes_and_ownership_changes() {
        let expected = HttpRoutePolicy {
            id: Uuid::new_v4(),
            client_id: Uuid::new_v4(),
            name: "site".to_owned(),
            hostname: "site.example.com".to_owned(),
            target_addr: "127.0.0.1:8080".to_owned(),
            max_connections: 64,
            grpc_backend_transport: GrpcBackendTransport::H2c,
            grpc_backend_server_name: None,
            grpc_backend_trust_profile: None,
            enabled: true,
        };
        let tls = RouteTlsPolicy {
            route_id: expected.id,
            mode: RouteTlsMode::Acme,
            redirect_http_to_https: false,
            certificate_identifier: None,
            updated_at: 1,
        };
        let revision = Uuid::new_v4();
        let mut current = HttpRouteSnapshot {
            policy: expected.clone(),
            revision,
        };
        let matches = |snapshot: Option<&HttpRouteSnapshot>| {
            http_route_snapshot_matches(snapshot, &expected, revision, &tls, &expected.hostname)
        };
        assert!(matches(Some(&current)));
        assert!(!matches(None));
        // 配置即使完全改回原值，新的版本也不能接收旧任务结果。
        current.revision = Uuid::new_v4();
        assert!(!matches(Some(&current)));
        current.revision = revision;
        current.policy.client_id = Uuid::new_v4();
        assert!(!matches(Some(&current)));
        current.policy = expected.clone();
        current.policy.enabled = false;
        assert!(!matches(Some(&current)));
        current.policy = expected.clone();
        current.policy.target_addr = "127.0.0.1:9090".to_owned();
        assert!(!matches(Some(&current)));
        current.policy = expected.clone();
        assert!(!http_route_snapshot_matches(
            Some(&current),
            &expected,
            revision,
            &tls,
            "other.example.com"
        ));
        let wildcard = RouteTlsPolicy {
            certificate_identifier: Some("*.example.com".to_owned()),
            ..tls
        };
        assert!(http_route_snapshot_matches(
            Some(&current),
            &expected,
            revision,
            &wildcard,
            "*.example.com"
        ));
    }
}

async fn bind_key(
    transaction: &PgTransaction<'_>,
    cipher: &CertificateMaterialCipher,
) -> anyhow::Result<()> {
    let fingerprint = cipher.fingerprint();
    transaction.execute("INSERT INTO linklake_certificate_key_binding(singleton_id,fingerprint) VALUES(1,$1) ON CONFLICT(singleton_id) DO NOTHING", &[&fingerprint]).await?;
    let stored: String = transaction
        .query_one(
            "SELECT fingerprint FROM linklake_certificate_key_binding WHERE singleton_id=1",
            &[],
        )
        .await?
        .get(0);
    anyhow::ensure!(
        stored == fingerprint,
        "certificate material key differs from the configured cluster key"
    );
    Ok(())
}
