//! HTTP-01 共享挑战：响应只在发布任务及其 Leader 租约均有效时可见。

use crate::{
    certificate_catalog::postgres::{certificate_job_key, PostgresCertificateCatalog},
    certificate_manager::validate_challenge_token,
    http_route_catalog::normalize_hostname,
    job_leases::JobLease,
};
use uuid::Uuid;

const MAX_SHARED_CHALLENGES: i64 = 4096;
const CHALLENGE_TTL_SECONDS: i64 = 600;

// 不含授权正文；清理必须匹配本次发布，旧 guard 不能删除替代挑战。
pub(crate) struct SharedHttp01Publication {
    hostname: String,
    token: String,
    publication_id: String,
    job_key: String,
    lease_id: String,
}

impl PostgresCertificateCatalog {
    pub(crate) async fn publish_http01(
        &self,
        lease: &JobLease,
        hostname: &str,
        token: &str,
        key_authorization: &str,
    ) -> anyhow::Result<SharedHttp01Publication> {
        let hostname = normalize_hostname(hostname)?;
        validate_key_authorization(token, key_authorization)?;
        anyhow::ensure!(
            lease.job_kind == "certificate" && lease.job_key == certificate_job_key(&hostname)?,
            "HTTP-01 publication does not match the certificate job"
        );
        let publication = SharedHttp01Publication {
            hostname,
            token: token.to_owned(),
            publication_id: Uuid::new_v4().to_string(),
            job_key: lease.job_key.clone(),
            lease_id: lease.lease_id.to_string(),
        };
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        self.fence(&transaction).await?;
        self.runtime
            .jobs()
            .assert_postgres_transaction_lease(&transaction, lease)
            .await?;
        // 取消无需异步 Drop；租约失效即不可读，下一次发布回收遗留记录。
        transaction
            .execute(
                "DELETE FROM linklake_http01_challenges AS challenge
             WHERE expires_at <= clock_timestamp() OR NOT EXISTS (
                 SELECT 1 FROM linklake_job_leases AS job
                 JOIN linklake_ha_leader AS leader
                   ON leader.instance_id=job.owner_instance_id
                  AND leader.incarnation_id=job.owner_incarnation_id
                  AND leader.fencing_token=job.fencing_token
                 JOIN linklake_ha_members AS member
                   ON member.instance_id=job.owner_instance_id
                  AND member.incarnation_id=job.owner_incarnation_id
                 WHERE job.job_key=challenge.job_key AND job.lease_id=challenge.lease_id
                   AND job.job_kind='certificate' AND job.lease_until>clock_timestamp()
                   AND leader.lease_until>clock_timestamp() AND member.lease_until>clock_timestamp()
             )",
                &[],
            )
            .await?;
        let count: i64 = transaction.query_one(
            "SELECT count(*) FROM linklake_http01_challenges WHERE NOT (hostname=$1 AND token=$2)",
            &[&publication.hostname, &publication.token],
        ).await?.get(0);
        anyhow::ensure!(
            count < MAX_SHARED_CHALLENGES,
            "shared HTTP-01 challenge capacity reached"
        );
        transaction.execute(
            "INSERT INTO linklake_http01_challenges(hostname,token,publication_id,job_key,lease_id,key_authorization,expires_at)
             VALUES($1,$2,$3,$4,$5,$6,clock_timestamp()+($7::bigint * INTERVAL '1 second'))
             ON CONFLICT(hostname,token) DO UPDATE SET publication_id=excluded.publication_id,
                 job_key=excluded.job_key,lease_id=excluded.lease_id,
                 key_authorization=excluded.key_authorization,expires_at=excluded.expires_at",
            &[&publication.hostname, &publication.token, &publication.publication_id,
              &publication.job_key, &publication.lease_id, &key_authorization, &CHALLENGE_TTL_SECONDS],
        ).await?;
        transaction.commit().await?;
        Ok(publication)
    }

    pub(crate) async fn lookup_http01(
        &self,
        hostname: &str,
        token: &str,
    ) -> anyhow::Result<Option<String>> {
        let Ok(hostname) = normalize_hostname(hostname) else {
            return Ok(None);
        };
        if validate_challenge_token(token).is_err() {
            return Ok(None);
        }
        // Follower 只读共享库；数据库不可用时不回退本机内存或过期缓存。
        let client = self.storage.postgres_client().await?;
        let value: Option<String> = client
            .query_opt(
                "SELECT challenge.key_authorization FROM linklake_http01_challenges AS challenge
             JOIN linklake_job_leases AS job
               ON job.job_key=challenge.job_key AND job.lease_id=challenge.lease_id
             JOIN linklake_ha_leader AS leader
               ON leader.instance_id=job.owner_instance_id
              AND leader.incarnation_id=job.owner_incarnation_id
              AND leader.fencing_token=job.fencing_token
             JOIN linklake_ha_members AS member
               ON member.instance_id=job.owner_instance_id
              AND member.incarnation_id=job.owner_incarnation_id
             WHERE challenge.hostname=$1 AND challenge.token=$2
               AND challenge.expires_at>clock_timestamp() AND job.job_kind='certificate'
               AND job.lease_until>clock_timestamp() AND leader.lease_until>clock_timestamp()
               AND member.lease_until>clock_timestamp()",
                &[&hostname, &token],
            )
            .await?
            .map(|row| row.get(0));
        if let Some(value) = &value {
            validate_key_authorization(token, value)?;
        }
        Ok(value)
    }

    pub(crate) async fn cleanup_http01(
        &self,
        publication: SharedHttp01Publication,
    ) -> anyhow::Result<()> {
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        self.fence(&transaction).await?;
        transaction
            .execute(
                "DELETE FROM linklake_http01_challenges WHERE hostname=$1 AND token=$2
             AND publication_id=$3 AND job_key=$4 AND lease_id=$5",
                &[
                    &publication.hostname,
                    &publication.token,
                    &publication.publication_id,
                    &publication.job_key,
                    &publication.lease_id,
                ],
            )
            .await?;
        transaction.commit().await?;
        Ok(())
    }
}

fn validate_key_authorization(token: &str, value: &str) -> anyhow::Result<()> {
    validate_challenge_token(token)?;
    let (published_token, thumbprint) = value.split_once('.').unwrap_or_default();
    anyhow::ensure!(
        published_token == token
            && thumbprint.len() == 43
            && thumbprint
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        "HTTP-01 key authorization is invalid"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_key_authorization;

    #[test]
    fn authorization_rejects_token_mismatch_and_response_injection() {
        let thumbprint = "A".repeat(43);
        assert!(validate_key_authorization("token_1", &format!("token_1.{thumbprint}")).is_ok());
        for value in [
            format!("other.{thumbprint}"),
            format!("token_1.{thumbprint}\r\nX-Injected: yes"),
            "token_1.short".to_owned(),
            format!("token_1.{}", "A".repeat(44)),
            format!("token_1.{}.extra", thumbprint),
        ] {
            assert!(validate_key_authorization("token_1", &value).is_err());
        }
        assert!(validate_key_authorization("../token", &format!("../token.{thumbprint}")).is_err());
    }
}
