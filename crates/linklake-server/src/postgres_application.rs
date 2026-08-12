//! PostgreSQL-backed application identity repositories.
//!
//! The existing SQLite catalogs remain the default single-instance backend.  In
//! PostgreSQL mode these repositories are the only source of truth for
//! administrators, sessions, management API tokens, and registered clients.

use getrandom::fill as random_fill;
use linklake_core::{ClientSummary, ManagedConfigMode, ManagedConfigStatus};
use uuid::Uuid;

use crate::{
    admin_auth::{
        self, AdminAuth, BootstrapCredentials, CreateUser, LoginAttempt, NewSession,
        SessionIdentity, SessionRecord, UpdateUser, UserRecord, UserRole,
    },
    api_tokens::{ApiTokenCatalog, ApiTokenRecord, ApiTokenScope, CreateApiToken, CreatedApiToken},
    client_registry::{self, Authentication, ClientRegistry, UpdateClient},
    database::Database,
    storage::{CoordinationStorage, StorageBackend},
    unix_seconds,
};

fn ensure_postgres(storage: &CoordinationStorage) -> anyhow::Result<()> {
    anyhow::ensure!(
        storage.backend() == StorageBackend::Postgres,
        "application PostgreSQL repository requires PostgreSQL coordination storage"
    );
    Ok(())
}

fn parse_uuid(value: &str, field: &str) -> anyhow::Result<Uuid> {
    Uuid::parse_str(value).map_err(|error| anyhow::anyhow!("invalid {field}: {error}"))
}

fn row_bool(row: &tokio_postgres::Row, index: usize) -> bool {
    row.get::<_, bool>(index)
}

fn nonnegative(value: i64) -> u64 {
    value.max(0) as u64
}

fn optional_nonnegative(value: Option<i64>) -> Option<u64> {
    value.map(nonnegative)
}

fn is_unique_violation(error: &tokio_postgres::Error) -> bool {
    error
        .as_db_error()
        .is_some_and(|database_error| database_error.code().code() == "23505")
}

pub(crate) struct PostgresAdminAuth {
    storage: CoordinationStorage,
    dummy_password_hash: String,
}

impl PostgresAdminAuth {
    pub(crate) async fn open(
        storage: CoordinationStorage,
        bootstrap: Option<BootstrapCredentials>,
    ) -> anyhow::Result<Self> {
        ensure_postgres(&storage)?;
        let dummy_password_hash =
            admin_auth::hash_password("linklake-dummy-password-verification")?;
        let mut client = storage.postgres_client().await?;
        let count: i64 = client
            .query_one("SELECT COUNT(*) FROM linklake_administrators", &[])
            .await?
            .get(0);
        if count == 0 {
            let bootstrap = bootstrap.ok_or_else(|| {
                anyhow::anyhow!(
                    "no administrator exists; set LINKLAKE_ADMIN_USERNAME and LINKLAKE_ADMIN_PASSWORD for the first start"
                )
            })?;
            let password_hash = admin_auth::hash_password(&bootstrap.password)?;
            let now = unix_seconds() as i64;
            client
                .execute(
                    "INSERT INTO linklake_administrators
                     (username, password_hash, created_unix_seconds, must_change_password,
                      display_name, role, enabled)
                     VALUES ($1, $2, $3, $4, $5, 'administrator', TRUE)",
                    &[
                        &bootstrap.username,
                        &password_hash,
                        &now,
                        &bootstrap.force_password_change,
                        &bootstrap.username,
                    ],
                )
                .await
                .map_err(|error| {
                    if is_unique_violation(&error) {
                        anyhow::anyhow!("administrator username already exists")
                    } else {
                        error.into()
                    }
                })?;
            tracing::info!("Created initial LinkLake administrator account in PostgreSQL.");
        }
        drop(client);
        Ok(Self {
            storage,
            dummy_password_hash,
        })
    }

    pub(crate) async fn login_with_context(
        &mut self,
        username: &str,
        password: &str,
        totp_code: Option<&str>,
        remote_addr: Option<&str>,
        user_agent: Option<&str>,
    ) -> anyhow::Result<LoginAttempt> {
        let mut client = self.storage.postgres_client().await?;
        let row = client
            .query_opt(
                "SELECT password_hash, must_change_password, enabled, role, display_name,
                        totp_secret, totp_enabled
                 FROM linklake_administrators WHERE username = $1",
                &[&username],
            )
            .await?;
        let Some(row) = row else {
            let _ = admin_auth::verify_password(password, &self.dummy_password_hash)?;
            return Ok(LoginAttempt::InvalidCredentials);
        };
        let password_hash: String = row.get(0);
        if !row_bool(&row, 2) || !admin_auth::verify_password(password, &password_hash)? {
            return Ok(LoginAttempt::InvalidCredentials);
        }
        let must_change_password: bool = row.get(1);
        let role = UserRole::parse(row.get::<_, &str>(3))?;
        let display_name: String = row.get(4);
        let totp_secret: Option<String> = row.get(5);
        let totp_enabled = row_bool(&row, 6);
        if totp_enabled {
            let Some(code) = totp_code.filter(|value| !value.trim().is_empty()) else {
                return Ok(LoginAttempt::TotpRequired);
            };
            let Some(secret) = totp_secret.as_deref() else {
                return Ok(LoginAttempt::InvalidCredentials);
            };
            if !admin_auth::verify_totp(secret, code, unix_seconds()) {
                return Ok(LoginAttempt::InvalidCredentials);
            }
        }
        let session_id = Uuid::new_v4();
        let session_secret = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let session_id_text = session_id.to_string();
        let session_secret_hash = admin_auth::hash_session_secret(&session_secret);
        let username = username.to_owned();
        let remote_addr = remote_addr.map(|value| value.chars().take(128).collect::<String>());
        let user_agent = user_agent.map(|value| value.chars().take(512).collect::<String>());
        let now = unix_seconds();
        let expires = now + admin_auth::SESSION_LIFETIME_SECONDS;
        client
            .execute(
                "DELETE FROM linklake_admin_sessions WHERE expires_unix_seconds <= $1",
                &[&(now as i64)],
            )
            .await?;
        client
            .execute(
                "INSERT INTO linklake_admin_sessions
                 (session_id, session_secret_hash, username, created_unix_seconds,
                  expires_unix_seconds, remote_addr, user_agent)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
                &[
                    &session_id_text,
                    &session_secret_hash,
                    &username,
                    &(now as i64),
                    &(expires as i64),
                    &remote_addr,
                    &user_agent,
                ],
            )
            .await?;
        client
            .execute(
                "UPDATE linklake_administrators SET last_login_unix_seconds = $1 WHERE username = $2",
                &[&(now as i64), &username],
            )
            .await?;
        Ok(LoginAttempt::Success(NewSession {
            session_id,
            cookie_value: format!("{session_id_text}.{session_secret}"),
            display_name,
            expires_unix_seconds: expires,
            password_change_required: must_change_password,
            role,
            totp_enabled,
        }))
    }

    pub(crate) async fn authenticate_session(
        &self,
        cookie_value: &str,
    ) -> anyhow::Result<Option<SessionIdentity>> {
        let Some((session_id, session_secret)) = cookie_value.split_once('.') else {
            return Ok(None);
        };
        let Ok(session_id) = Uuid::parse_str(session_id) else {
            return Ok(None);
        };
        let session_id_text = session_id.to_string();
        let mut client = self.storage.postgres_client().await?;
        let row = client
            .query_opt(
                "SELECT s.session_secret_hash, s.expires_unix_seconds, a.username,
                        a.display_name, a.role, a.must_change_password, a.totp_enabled
                 FROM linklake_admin_sessions s
                 JOIN linklake_administrators a ON a.username = s.username
                 WHERE s.session_id = $1 AND a.enabled = TRUE",
                &[&session_id_text],
            )
            .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let expires: i64 = row.get(1);
        if expires <= unix_seconds() as i64 {
            client
                .execute(
                    "DELETE FROM linklake_admin_sessions WHERE session_id = $1",
                    &[&session_id_text],
                )
                .await?;
            return Ok(None);
        }
        let session_secret_hash: String = row.get(0);
        if !session_secret_hash.starts_with("sha256:")
            || !admin_auth::verify_session_secret(session_secret, &session_secret_hash)
        {
            if !session_secret_hash.starts_with("sha256:") {
                client
                    .execute(
                        "DELETE FROM linklake_admin_sessions WHERE session_id = $1",
                        &[&session_id_text],
                    )
                    .await?;
            }
            return Ok(None);
        }
        Ok(Some(SessionIdentity {
            session_id,
            username: row.get(2),
            display_name: row.get(3),
            role: UserRole::parse(row.get::<_, &str>(4))?,
            expires_unix_seconds: nonnegative(expires),
            password_change_required: row_bool(&row, 5),
            totp_enabled: row_bool(&row, 6),
        }))
    }

    pub(crate) async fn logout(&mut self, cookie_value: &str) -> anyhow::Result<()> {
        let Some((session_id, _)) = cookie_value.split_once('.') else {
            return Ok(());
        };
        let Ok(session_id) = Uuid::parse_str(session_id) else {
            return Ok(());
        };
        let session_id_text = session_id.to_string();
        self.storage
            .postgres_client()
            .await?
            .execute(
                "DELETE FROM linklake_admin_sessions WHERE session_id = $1",
                &[&session_id_text],
            )
            .await?;
        Ok(())
    }

    pub(crate) async fn change_password(
        &mut self,
        cookie_value: &str,
        new_password: &str,
    ) -> anyhow::Result<bool> {
        admin_auth::validate_password(new_password)?;
        let Some((session_id, _)) = cookie_value.split_once('.') else {
            return Ok(false);
        };
        let Ok(session_id) = Uuid::parse_str(session_id) else {
            return Ok(false);
        };
        let session_id_text = session_id.to_string();
        let Some(identity) = self.authenticate_session(cookie_value).await? else {
            return Ok(false);
        };
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        let password_hash = admin_auth::hash_password(new_password)?;
        let updated = transaction
            .execute(
                "UPDATE linklake_administrators SET password_hash = $1, must_change_password = FALSE WHERE username = $2",
                &[&password_hash, &identity.username],
            )
            .await?;
        if updated == 0 {
            return Ok(false);
        }
        transaction
            .execute(
                "DELETE FROM linklake_admin_sessions WHERE username = $1 AND session_id <> $2",
                &[&identity.username, &session_id_text],
            )
            .await?;
        transaction.commit().await?;
        Ok(true)
    }

    pub(crate) async fn list_users(&self) -> anyhow::Result<Vec<UserRecord>> {
        let mut client = self.storage.postgres_client().await?;
        let now = unix_seconds() as i64;
        client
            .execute(
                "DELETE FROM linklake_admin_sessions WHERE expires_unix_seconds <= $1",
                &[&now],
            )
            .await?;
        let rows = client
            .query(
                "SELECT a.username, a.display_name, a.role, a.enabled,
                        a.must_change_password, a.created_unix_seconds,
                        a.last_login_unix_seconds,
                        COUNT(s.session_id) FILTER (WHERE s.expires_unix_seconds > $1),
                        a.totp_enabled
                 FROM linklake_administrators a
                 LEFT JOIN linklake_admin_sessions s ON s.username = a.username
                 GROUP BY a.username ORDER BY a.username",
                &[&now],
            )
            .await?;
        rows.into_iter().map(user_record_from_row).collect()
    }

    pub(crate) async fn create_user(&mut self, request: CreateUser) -> anyhow::Result<UserRecord> {
        admin_auth::validate_credentials(&request.username, &request.password)?;
        admin_auth::validate_display_name(&request.display_name)?;
        let password_hash = admin_auth::hash_password(&request.password)?;
        let display_name = request.display_name.trim().to_owned();
        let role = request.role.as_str().to_owned();
        let now = unix_seconds() as i64;
        let mut client = self.storage.postgres_client().await?;
        let result = client
            .execute(
                "INSERT INTO linklake_administrators
                 (username, password_hash, created_unix_seconds, must_change_password,
                  display_name, role, enabled)
                 VALUES ($1, $2, $3, $4, $5, $6, TRUE)",
                &[
                    &request.username,
                    &password_hash,
                    &now,
                    &request.force_password_change,
                    &display_name,
                    &role,
                ],
            )
            .await;
        match result {
            Ok(_) => self
                .user(&request.username)
                .await?
                .ok_or_else(|| anyhow::anyhow!("created user could not be read")),
            Err(error) if is_unique_violation(&error) => anyhow::bail!("username already exists"),
            Err(error) => Err(error.into()),
        }
    }

    pub(crate) async fn update_user(
        &mut self,
        actor: &str,
        username: &str,
        request: UpdateUser,
    ) -> anyhow::Result<Option<UserRecord>> {
        admin_auth::validate_display_name(&request.display_name)?;
        let Some(current) = self.user(username).await? else {
            return Ok(None);
        };
        if username == actor && (!request.enabled || request.role != UserRole::Administrator) {
            anyhow::bail!("current user cannot be disabled or demoted")
        }
        if current.enabled
            && current.role == UserRole::Administrator
            && (!request.enabled || request.role != UserRole::Administrator)
            && self.enabled_administrator_count().await? <= 1
        {
            anyhow::bail!("last administrator cannot be disabled or demoted")
        }
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        let display_name = request.display_name.trim().to_owned();
        let role = request.role.as_str().to_owned();
        transaction
            .execute(
                "UPDATE linklake_administrators SET display_name = $1, role = $2, enabled = $3 WHERE username = $4",
                &[&display_name, &role, &request.enabled, &username],
            )
            .await?;
        if !request.enabled || request.role != current.role {
            transaction
                .execute(
                    "DELETE FROM linklake_admin_sessions WHERE username = $1",
                    &[&username],
                )
                .await?;
        }
        transaction.commit().await?;
        self.user(username).await
    }

    pub(crate) async fn delete_user(
        &mut self,
        actor: &str,
        username: &str,
    ) -> anyhow::Result<bool> {
        let Some(current) = self.user(username).await? else {
            return Ok(false);
        };
        if username == actor {
            anyhow::bail!("current user cannot be deleted")
        }
        if current.enabled
            && current.role == UserRole::Administrator
            && self.enabled_administrator_count().await? <= 1
        {
            anyhow::bail!("last administrator cannot be deleted")
        }
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        transaction
            .execute(
                "DELETE FROM linklake_admin_sessions WHERE username = $1",
                &[&username],
            )
            .await?;
        let deleted = transaction
            .execute(
                "DELETE FROM linklake_administrators WHERE username = $1",
                &[&username],
            )
            .await?;
        transaction.commit().await?;
        Ok(deleted > 0)
    }

    pub(crate) async fn reset_user_password(
        &mut self,
        username: &str,
        new_password: &str,
        force_password_change: bool,
    ) -> anyhow::Result<bool> {
        admin_auth::validate_password(new_password)?;
        let password_hash = admin_auth::hash_password(new_password)?;
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        let updated = transaction
            .execute(
                "UPDATE linklake_administrators SET password_hash = $1, must_change_password = $2 WHERE username = $3",
                &[&password_hash, &force_password_change, &username],
            )
            .await?;
        if updated == 0 {
            return Ok(false);
        }
        transaction
            .execute(
                "DELETE FROM linklake_admin_sessions WHERE username = $1",
                &[&username],
            )
            .await?;
        transaction.commit().await?;
        Ok(true)
    }

    pub(crate) async fn revoke_user_sessions(&mut self, username: &str) -> anyhow::Result<bool> {
        if self.user(username).await?.is_none() {
            return Ok(false);
        }
        self.storage
            .postgres_client()
            .await?
            .execute(
                "DELETE FROM linklake_admin_sessions WHERE username = $1",
                &[&username],
            )
            .await?;
        // 与 SQLite catalog 保持一致：用户存在即视为撤销操作成功，
        // 即使该用户当前没有活动会话。
        Ok(true)
    }

    pub(crate) async fn begin_totp(&mut self, username: &str) -> anyhow::Result<Option<String>> {
        if self.user(username).await?.is_none() {
            return Ok(None);
        }
        let mut secret = [0_u8; 20];
        random_fill(&mut secret)?;
        let encoded = admin_auth::base32_encode(&secret);
        self.storage
            .postgres_client()
            .await?
            .execute(
                "UPDATE linklake_administrators SET totp_secret = $1, totp_enabled = FALSE WHERE username = $2",
                &[&encoded, &username],
            )
            .await?;
        Ok(Some(encoded))
    }

    pub(crate) async fn enable_totp(
        &mut self,
        username: &str,
        current_session_id: Uuid,
        code: &str,
    ) -> anyhow::Result<bool> {
        let mut client = self.storage.postgres_client().await?;
        let secret = client
            .query_opt(
                "SELECT totp_secret FROM linklake_administrators WHERE username = $1",
                &[&username],
            )
            .await?
            .and_then(|row| row.get::<_, Option<String>>(0));
        let Some(secret) = secret else {
            return Ok(false);
        };
        if !admin_auth::verify_totp(&secret, code, unix_seconds()) {
            return Ok(false);
        }
        let current_session_id_text = current_session_id.to_string();
        let transaction = client.transaction().await?;
        transaction
            .execute(
                "UPDATE linklake_administrators SET totp_enabled = TRUE WHERE username = $1",
                &[&username],
            )
            .await?;
        transaction
            .execute(
                "DELETE FROM linklake_admin_sessions WHERE username = $1 AND session_id <> $2",
                &[&username, &current_session_id_text],
            )
            .await?;
        transaction.commit().await?;
        Ok(true)
    }

    pub(crate) async fn disable_totp(
        &mut self,
        username: &str,
        code: &str,
    ) -> anyhow::Result<bool> {
        let mut client = self.storage.postgres_client().await?;
        let secret = client
            .query_opt(
                "SELECT totp_secret FROM linklake_administrators WHERE username = $1 AND totp_enabled = TRUE",
                &[&username],
            )
            .await?
            .and_then(|row| row.get::<_, Option<String>>(0));
        let Some(secret) = secret else {
            return Ok(false);
        };
        if !admin_auth::verify_totp(&secret, code, unix_seconds()) {
            return Ok(false);
        }
        client
            .execute(
                "UPDATE linklake_administrators SET totp_secret = NULL, totp_enabled = FALSE WHERE username = $1",
                &[&username],
            )
            .await?;
        Ok(true)
    }

    pub(crate) async fn list_sessions(&self) -> anyhow::Result<Vec<SessionRecord>> {
        let mut client = self.storage.postgres_client().await?;
        let now = unix_seconds() as i64;
        client
            .execute(
                "DELETE FROM linklake_admin_sessions WHERE expires_unix_seconds <= $1",
                &[&now],
            )
            .await?;
        let rows = client
            .query(
                "SELECT session_id, username, created_unix_seconds, expires_unix_seconds,
                        remote_addr, user_agent
                 FROM linklake_admin_sessions ORDER BY created_unix_seconds DESC",
                &[],
            )
            .await?;
        rows.into_iter().map(session_record_from_row).collect()
    }

    pub(crate) async fn revoke_session(
        &mut self,
        actor_session_id: Uuid,
        session_id: Uuid,
    ) -> anyhow::Result<bool> {
        anyhow::ensure!(
            actor_session_id != session_id,
            "current session cannot be revoked from session management"
        );
        let session_id_text = session_id.to_string();
        let deleted = self
            .storage
            .postgres_client()
            .await?
            .execute(
                "DELETE FROM linklake_admin_sessions WHERE session_id = $1",
                &[&session_id_text],
            )
            .await?;
        Ok(deleted > 0)
    }

    async fn user(&self, username: &str) -> anyhow::Result<Option<UserRecord>> {
        let mut client = self.storage.postgres_client().await?;
        let row = client
            .query_opt(
                "SELECT a.username, a.display_name, a.role, a.enabled,
                        a.must_change_password, a.created_unix_seconds,
                        a.last_login_unix_seconds,
                        (SELECT COUNT(*) FROM linklake_admin_sessions s
                         WHERE s.username = a.username AND s.expires_unix_seconds > $1),
                        a.totp_enabled
                 FROM linklake_administrators a WHERE a.username = $2",
                &[&(unix_seconds() as i64), &username],
            )
            .await?;
        row.map(|row| user_record_from_row(&row)).transpose()
    }

    async fn enabled_administrator_count(&self) -> anyhow::Result<u64> {
        let mut client = self.storage.postgres_client().await?;
        let count: i64 = client
            .query_one(
                "SELECT COUNT(*) FROM linklake_administrators WHERE role = 'administrator' AND enabled = TRUE",
                &[],
            )
            .await?
            .get(0);
        Ok(nonnegative(count))
    }
}

fn user_record_from_row(row: &tokio_postgres::Row) -> anyhow::Result<UserRecord> {
    Ok(UserRecord {
        username: row.get(0),
        display_name: row.get(1),
        role: UserRole::parse(row.get::<_, &str>(2))?,
        enabled: row_bool(row, 3),
        must_change_password: row_bool(row, 4),
        created_unix_seconds: nonnegative(row.get(5)),
        last_login_unix_seconds: optional_nonnegative(row.get(6)),
        active_sessions: nonnegative(row.get(7)),
        totp_enabled: row_bool(row, 8),
    })
}

fn session_record_from_row(row: tokio_postgres::Row) -> anyhow::Result<SessionRecord> {
    Ok(SessionRecord {
        session_id: parse_uuid(row.get(0), "session ID")?,
        username: row.get(1),
        created_unix_seconds: nonnegative(row.get(2)),
        expires_unix_seconds: nonnegative(row.get(3)),
        remote_addr: row.get(4),
        user_agent: row.get(5),
    })
}

pub(crate) struct PostgresApiTokenCatalog {
    storage: CoordinationStorage,
}

impl PostgresApiTokenCatalog {
    pub(crate) async fn open(storage: CoordinationStorage) -> anyhow::Result<Self> {
        ensure_postgres(&storage)?;
        // 迁移已在 Storage::open 中完成；这里再次确认表存在，避免在错误的
        // 数据库或未完成迁移的连接上静默工作。
        let mut client = storage.postgres_client().await?;
        let exists: bool = client
            .query_one(
                "SELECT to_regclass('linklake_management_api_tokens') IS NOT NULL",
                &[],
            )
            .await?
            .get(0);
        anyhow::ensure!(exists, "PostgreSQL API token schema is missing");
        drop(client);
        Ok(Self { storage })
    }

    pub(crate) async fn list(&self) -> anyhow::Result<Vec<ApiTokenRecord>> {
        let rows = self
            .storage
            .postgres_client()
            .await?
            .query(
                "SELECT id, name, scope, created_unix_seconds, expires_unix_seconds,
                        last_used_unix_seconds, fleet_source_instance_id
                 FROM linklake_management_api_tokens ORDER BY name",
                &[],
            )
            .await?;
        rows.into_iter().map(api_token_record_from_row).collect()
    }

    pub(crate) async fn create(
        &mut self,
        request: CreateApiToken,
        now: u64,
    ) -> anyhow::Result<CreatedApiToken> {
        let name = request.name.trim();
        anyhow::ensure!(
            !name.is_empty() && name.chars().count() <= 80,
            "API token name is invalid"
        );
        anyhow::ensure!(
            request
                .expires_unix_seconds
                .is_none_or(|expires| expires > now),
            "API token expiry is invalid"
        );
        anyhow::ensure!(
            request
                .fleet_source_instance_id
                .is_none_or(|source| !source.is_nil()),
            "Fleet source instance ID is invalid"
        );
        anyhow::ensure!(
            request.fleet_source_instance_id.is_none() || request.scope != ApiTokenScope::Read,
            "read-only API tokens cannot be bound as Fleet writers"
        );
        let mut random = [0_u8; 32];
        random_fill(&mut random)?;
        let token = format!("llapi_{}", crate::api_tokens::hex(&random));
        let record = ApiTokenRecord {
            id: Uuid::new_v4(),
            name: name.to_owned(),
            scope: request.scope,
            created_unix_seconds: now,
            expires_unix_seconds: request.expires_unix_seconds,
            last_used_unix_seconds: None,
            fleet_source_instance_id: request.fleet_source_instance_id,
        };
        let id_text = record.id.to_string();
        let scope_text = record.scope.to_string();
        let token_hash = crate::api_tokens::token_hash(&token).to_vec();
        let expires_unix_seconds = record.expires_unix_seconds.map(|value| value as i64);
        let fleet_source_instance_id = record
            .fleet_source_instance_id
            .map(|value| value.to_string());
        let mut client = self.storage.postgres_client().await?;
        let result = client
            .execute(
                "INSERT INTO linklake_management_api_tokens
                 (id, name, scope, token_hash, created_unix_seconds,
                  expires_unix_seconds, fleet_source_instance_id)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
                &[
                    &id_text,
                    &record.name,
                    &scope_text,
                    &token_hash,
                    &(now as i64),
                    &expires_unix_seconds,
                    &fleet_source_instance_id,
                ],
            )
            .await;
        match result {
            Ok(_) => Ok(CreatedApiToken { record, token }),
            Err(error) if is_unique_violation(&error) => {
                anyhow::bail!("API token name already exists")
            }
            Err(error) => Err(error.into()),
        }
    }

    pub(crate) async fn revoke(&mut self, id: Uuid) -> anyhow::Result<bool> {
        let id_text = id.to_string();
        Ok(self
            .storage
            .postgres_client()
            .await?
            .execute(
                "DELETE FROM linklake_management_api_tokens WHERE id = $1",
                &[&id_text],
            )
            .await?
            > 0)
    }

    pub(crate) async fn authenticate(
        &mut self,
        token: &str,
        now: u64,
    ) -> anyhow::Result<Option<ApiTokenRecord>> {
        if !token.starts_with("llapi_") {
            return Ok(None);
        }
        let hash = crate::api_tokens::token_hash(token).to_vec();
        let mut client = self.storage.postgres_client().await?;
        let row = client
            .query_opt(
                "SELECT id, name, scope, created_unix_seconds, expires_unix_seconds,
                        last_used_unix_seconds, fleet_source_instance_id
                 FROM linklake_management_api_tokens WHERE token_hash = $1",
                &[&hash],
            )
            .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let mut record = api_token_record_from_row(&row)?;
        if record
            .expires_unix_seconds
            .is_some_and(|expires| expires <= now)
        {
            return Ok(None);
        }
        let record_id = record.id.to_string();
        let now_i64 = now as i64;
        client
            .execute(
                "UPDATE linklake_management_api_tokens SET last_used_unix_seconds = $2 WHERE id = $1",
                &[&record_id, &now_i64],
            )
            .await?;
        record.last_used_unix_seconds = Some(now);
        Ok(Some(record))
    }
}

fn api_token_record_from_row(row: &tokio_postgres::Row) -> anyhow::Result<ApiTokenRecord> {
    Ok(ApiTokenRecord {
        id: parse_uuid(row.get(0), "API token ID")?,
        name: row.get(1),
        scope: row.get::<_, &str>(2).parse()?,
        created_unix_seconds: nonnegative(row.get(3)),
        expires_unix_seconds: optional_nonnegative(row.get(4)),
        last_used_unix_seconds: optional_nonnegative(row.get(5)),
        fleet_source_instance_id: row
            .get::<_, Option<String>>(6)
            .map(|value| parse_uuid(&value, "Fleet source instance ID"))
            .transpose()?,
    })
}

#[derive(Clone)]
struct PostgresRegisteredClient {
    agent_instance_id: Uuid,
    agent_identity_public_key: Option<String>,
    name: String,
    platform: String,
    group_name: Option<String>,
    tags: Vec<String>,
    notes: Option<String>,
    enabled: bool,
    created_unix_seconds: u64,
    token_rotated_unix_seconds: Option<u64>,
    access_token_hash: String,
    last_seen_unix_seconds: u64,
    config_mode: ManagedConfigMode,
    config_sync_status: ManagedConfigStatus,
    applied_config_revision: Option<String>,
    config_sync_error: Option<String>,
    config_checked_unix_seconds: Option<u64>,
}

pub(crate) struct PostgresClientRegistry {
    storage: CoordinationStorage,
}

impl PostgresClientRegistry {
    pub(crate) async fn open(storage: CoordinationStorage) -> anyhow::Result<Self> {
        ensure_postgres(&storage)?;
        let mut client = storage.postgres_client().await?;
        let exists: bool = client
            .query_one("SELECT to_regclass('linklake_clients') IS NOT NULL", &[])
            .await?
            .get(0);
        anyhow::ensure!(exists, "PostgreSQL client registry schema is missing");
        drop(client);
        Ok(Self { storage })
    }

    pub(crate) async fn count(&self) -> anyhow::Result<usize> {
        let count: i64 = self
            .storage
            .postgres_client()
            .await?
            .query_one("SELECT COUNT(*) FROM linklake_clients", &[])
            .await?
            .get(0);
        usize::try_from(count.max(0)).map_err(|_| anyhow::anyhow!("client count overflow"))
    }

    pub(crate) async fn contains(&self, client_id: Uuid) -> anyhow::Result<bool> {
        let client_id_text = client_id.to_string();
        Ok(self
            .storage
            .postgres_client()
            .await?
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM linklake_clients WHERE client_id = $1 AND enabled = TRUE)",
                &[&client_id_text],
            )
            .await?
            .get(0))
    }

    pub(crate) async fn summaries(&self) -> anyhow::Result<Vec<ClientSummary>> {
        let rows = self
            .storage
            .postgres_client()
            .await?
            .query(
                "SELECT client_id, agent_instance_id, agent_identity_public_key, name, platform,
                        group_name, tags_json::text, notes, enabled, created_unix_seconds,
                        token_rotated_unix_seconds, last_seen_unix_seconds, config_mode,
                        config_sync_status, applied_config_revision, config_sync_error,
                        config_checked_unix_seconds
                 FROM linklake_clients ORDER BY name",
                &[],
            )
            .await?;
        rows.into_iter()
            .map(|row| client_summary_from_row(&row))
            .collect()
    }

    pub(crate) async fn summary_by_id(
        &self,
        client_id: Uuid,
    ) -> anyhow::Result<Option<ClientSummary>> {
        self.load(client_id)
            .await
            .map(|value| value.map(|client| client_summary(client_id, &client)))
    }

    pub(crate) async fn enroll_with_identity(
        &mut self,
        name: String,
        platform: String,
        agent_instance_id: Option<Uuid>,
        agent_identity_public_key: Option<String>,
    ) -> anyhow::Result<(Uuid, Uuid, String)> {
        let agent_instance_id = agent_instance_id.unwrap_or_else(Uuid::new_v4);
        anyhow::ensure!(
            !agent_instance_id.is_nil(),
            "agent instance ID must not be nil"
        );
        let client_token = format!("llc_{}", Uuid::new_v4().simple());
        let token_hash = client_registry::hash_token(&client_token)?;
        let now = unix_seconds();
        let agent_instance_id_text = agent_instance_id.to_string();
        let mut client = self.storage.postgres_client().await?;
        let transaction = client.transaction().await?;
        let existing = transaction
            .query_opt(
                "SELECT client_id, agent_identity_public_key FROM linklake_clients
                 WHERE agent_instance_id = $1 FOR UPDATE",
                &[&agent_instance_id_text],
            )
            .await?;
        let result = if let Some(row) = existing {
            let client_id = parse_uuid(row.get(0), "client ID")?;
            let stored_key: Option<String> = row.get(1);
            let Some(public_key) = agent_identity_public_key else {
                anyhow::bail!("agent instance ID is already enrolled");
            };
            anyhow::ensure!(
                stored_key
                    .as_deref()
                    .is_none_or(|stored| stored == public_key),
                "agent identity public key does not match the enrolled instance"
            );
            let public_key = Some(public_key);
            let client_id_text = client_id.to_string();
            let now_i64 = now as i64;
            transaction
                .execute(
                    "UPDATE linklake_clients
                     SET agent_identity_public_key = $1, name = $2, platform = $3,
                         enabled = TRUE, access_token_hash = $4,
                         token_rotated_unix_seconds = $5, last_seen_unix_seconds = $5
                     WHERE client_id = $6",
                    &[
                        &public_key,
                        &name,
                        &platform,
                        &token_hash,
                        &now_i64,
                        &client_id_text,
                    ],
                )
                .await?;
            client_id
        } else {
            let client_id = Uuid::new_v4();
            let client_id_text = client_id.to_string();
            let now_i64 = now as i64;
            let tags = "[]";
            let config_mode = client_registry::config_mode_name(ManagedConfigMode::Local);
            let config_status = client_registry::config_status_name(ManagedConfigStatus::Unknown);
            transaction
                .execute(
                    "INSERT INTO linklake_clients
                     (client_id, agent_instance_id, agent_identity_public_key, name, platform,
                      tags_json, enabled, created_unix_seconds, access_token_hash,
                      last_seen_unix_seconds, config_mode, config_sync_status)
                     VALUES ($1, $2, $3, $4, $5, $6::jsonb, TRUE, $7, $8, $7, $9, $10)",
                    &[
                        &client_id_text,
                        &agent_instance_id_text,
                        &agent_identity_public_key,
                        &name,
                        &platform,
                        &tags,
                        &now_i64,
                        &token_hash,
                        &config_mode,
                        &config_status,
                    ],
                )
                .await
                .map_err(|error| {
                    if is_unique_violation(&error) {
                        anyhow::anyhow!("client identity already exists")
                    } else {
                        error.into()
                    }
                })?;
            client_id
        };
        transaction.commit().await?;
        Ok((result, agent_instance_id, client_token))
    }

    pub(crate) async fn authenticate_and_touch(
        &mut self,
        client_id: Uuid,
        token: &str,
    ) -> anyhow::Result<Authentication> {
        let Some(client) = self.load(client_id).await? else {
            return Ok(Authentication::UnknownClient);
        };
        if !client.enabled {
            return Ok(Authentication::DisabledClient);
        }
        if !client_registry::verify_token(token, &client.access_token_hash)? {
            return Ok(Authentication::InvalidToken);
        }
        let now = unix_seconds() as i64;
        let client_id_text = client_id.to_string();
        self.storage
            .postgres_client()
            .await?
            .execute(
                "UPDATE linklake_clients SET last_seen_unix_seconds = $1 WHERE client_id = $2",
                &[&now, &client_id_text],
            )
            .await?;
        Ok(Authentication::Authenticated)
    }

    pub(crate) async fn update(
        &mut self,
        client_id: Uuid,
        request: UpdateClient,
    ) -> anyhow::Result<Option<ClientSummary>> {
        client_registry::validate_name(&request.name)?;
        let group_name =
            client_registry::normalize_optional_text(request.group_name, 64, "client group")?;
        let notes = client_registry::normalize_optional_text(request.notes, 512, "client notes")?;
        let tags = client_registry::normalize_tags(request.tags)?;
        let Some(_) = self.load(client_id).await? else {
            return Ok(None);
        };
        let tags_json = serde_json::to_string(&tags)?;
        let name = request.name.trim().to_owned();
        let client_id_text = client_id.to_string();
        self.storage
            .postgres_client()
            .await?
            .execute(
                "UPDATE linklake_clients
                 SET name = $1, group_name = $2, tags_json = $3::jsonb,
                     notes = $4, enabled = $5
                 WHERE client_id = $6",
                &[
                    &name,
                    &group_name,
                    &tags_json,
                    &notes,
                    &request.enabled,
                    &client_id_text,
                ],
            )
            .await?;
        self.summary_by_id(client_id).await
    }

    pub(crate) async fn rotate_token(&mut self, client_id: Uuid) -> anyhow::Result<Option<String>> {
        let Some(_) = self.load(client_id).await? else {
            return Ok(None);
        };
        let client_token = format!("llc_{}", Uuid::new_v4().simple());
        let token_hash = client_registry::hash_token(&client_token)?;
        let now_i64 = unix_seconds() as i64;
        let client_id_text = client_id.to_string();
        let updated = self
            .storage
            .postgres_client()
            .await?
            .execute(
                "UPDATE linklake_clients SET access_token_hash = $1,
                        token_rotated_unix_seconds = $2 WHERE client_id = $3",
                &[&token_hash, &now_i64, &client_id_text],
            )
            .await?;
        Ok((updated > 0).then_some(client_token))
    }

    pub(crate) async fn delete(&mut self, client_id: Uuid) -> anyhow::Result<bool> {
        let client_id_text = client_id.to_string();
        Ok(self
            .storage
            .postgres_client()
            .await?
            .execute(
                "DELETE FROM linklake_clients WHERE client_id = $1",
                &[&client_id_text],
            )
            .await?
            > 0)
    }

    pub(crate) async fn update_config_sync(
        &mut self,
        client_id: Uuid,
        mode: ManagedConfigMode,
        status: ManagedConfigStatus,
        applied_revision: Option<String>,
        error: Option<String>,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(self.load(client_id).await?.is_some(), "unknown client");
        let applied_revision = applied_revision.filter(|value| value.len() <= 128);
        let error = error
            .map(|value| value.trim().chars().take(512).collect::<String>())
            .filter(|value| !value.is_empty());
        let mode_text = client_registry::config_mode_name(mode);
        let status_text = client_registry::config_status_name(status);
        let now_i64 = unix_seconds() as i64;
        let client_id_text = client_id.to_string();
        self.storage
            .postgres_client()
            .await?
            .execute(
                "UPDATE linklake_clients
                 SET config_mode = $1, config_sync_status = $2,
                     applied_config_revision = $3, config_sync_error = $4,
                     config_checked_unix_seconds = $5
                 WHERE client_id = $6",
                &[
                    &mode_text,
                    &status_text,
                    &applied_revision,
                    &error,
                    &now_i64,
                    &client_id_text,
                ],
            )
            .await?;
        Ok(())
    }

    async fn load(&self, client_id: Uuid) -> anyhow::Result<Option<PostgresRegisteredClient>> {
        let client_id_text = client_id.to_string();
        let row = self
            .storage
            .postgres_client()
            .await?
            .query_opt(
                "SELECT agent_instance_id, agent_identity_public_key, name, platform,
                        group_name, tags_json::text, notes, enabled, created_unix_seconds,
                        token_rotated_unix_seconds, access_token_hash, last_seen_unix_seconds,
                        config_mode, config_sync_status, applied_config_revision,
                        config_sync_error, config_checked_unix_seconds
                 FROM linklake_clients WHERE client_id = $1",
                &[&client_id_text],
            )
            .await?;
        row.map(|row| registered_client_from_row(&row)).transpose()
    }
}

fn registered_client_from_row(
    row: &tokio_postgres::Row,
) -> anyhow::Result<PostgresRegisteredClient> {
    let tags_json: String = row.get(5);
    Ok(PostgresRegisteredClient {
        agent_instance_id: parse_uuid(row.get(0), "agent instance ID")?,
        agent_identity_public_key: row.get(1),
        name: row.get(2),
        platform: row.get(3),
        group_name: row.get(4),
        tags: serde_json::from_str(&tags_json).unwrap_or_default(),
        notes: row.get(6),
        enabled: row_bool(row, 7),
        created_unix_seconds: nonnegative(row.get(8)),
        token_rotated_unix_seconds: optional_nonnegative(row.get(9)),
        access_token_hash: row.get(10),
        last_seen_unix_seconds: nonnegative(row.get(11)),
        config_mode: client_registry::parse_config_mode(row.get(12)),
        config_sync_status: client_registry::parse_config_status(row.get(13)),
        applied_config_revision: row.get(14),
        config_sync_error: row.get(15),
        config_checked_unix_seconds: optional_nonnegative(row.get(16)),
    })
}

fn client_summary_from_row(row: &tokio_postgres::Row) -> anyhow::Result<ClientSummary> {
    let client_id = parse_uuid(row.get(0), "client ID")?;
    let tags_json: String = row.get(6);
    Ok(ClientSummary {
        client_id,
        agent_instance_id: parse_uuid(row.get(1), "agent instance ID")?,
        agent_identity_public_key: row.get(2),
        name: row.get(3),
        platform: row.get(4),
        group_name: row.get(5),
        tags: serde_json::from_str(&tags_json).unwrap_or_default(),
        notes: row.get(7),
        enabled: row_bool(row, 8),
        created_unix_seconds: nonnegative(row.get(9)),
        token_rotated_unix_seconds: optional_nonnegative(row.get(10)),
        last_seen_unix_seconds: nonnegative(row.get(11)),
        config_mode: client_registry::parse_config_mode(row.get(12)),
        config_sync_status: client_registry::parse_config_status(row.get(13)),
        applied_config_revision: row.get(14),
        config_sync_error: row.get(15),
        config_checked_unix_seconds: optional_nonnegative(row.get(16)),
    })
}

fn client_summary(client_id: Uuid, client: &PostgresRegisteredClient) -> ClientSummary {
    ClientSummary {
        client_id,
        agent_instance_id: client.agent_instance_id,
        agent_identity_public_key: client.agent_identity_public_key.clone(),
        name: client.name.clone(),
        platform: client.platform.clone(),
        group_name: client.group_name.clone(),
        tags: client.tags.clone(),
        notes: client.notes.clone(),
        enabled: client.enabled,
        created_unix_seconds: client.created_unix_seconds,
        token_rotated_unix_seconds: client.token_rotated_unix_seconds,
        last_seen_unix_seconds: client.last_seen_unix_seconds,
        config_mode: client.config_mode,
        config_sync_status: client.config_sync_status,
        applied_config_revision: client.applied_config_revision.clone(),
        config_sync_error: client.config_sync_error.clone(),
        config_checked_unix_seconds: client.config_checked_unix_seconds,
    }
}

/// Runtime facade selected once during startup.  The SQLite branch delegates
/// to the existing synchronous catalogs; the PostgreSQL branch never opens or
/// consults the application-domain SQLite tables.
pub(crate) enum AdminAuthStore {
    Sqlite(AdminAuth),
    Postgres(PostgresAdminAuth),
}

impl AdminAuthStore {
    pub(crate) async fn open(
        storage: &CoordinationStorage,
        database: &Database,
        bootstrap: Option<BootstrapCredentials>,
    ) -> anyhow::Result<Self> {
        match storage.backend() {
            StorageBackend::Sqlite => Ok(Self::Sqlite(AdminAuth::open_with_database(
                database, bootstrap,
            )?)),
            StorageBackend::Postgres => Ok(Self::Postgres(
                PostgresAdminAuth::open(storage.clone(), bootstrap).await?,
            )),
        }
    }

    pub(crate) async fn login_with_context(
        &mut self,
        username: &str,
        password: &str,
        totp_code: Option<&str>,
        remote_addr: Option<&str>,
        user_agent: Option<&str>,
    ) -> anyhow::Result<LoginAttempt> {
        match self {
            Self::Sqlite(auth) => {
                auth.login_with_context(username, password, totp_code, remote_addr, user_agent)
            }
            Self::Postgres(auth) => {
                auth.login_with_context(username, password, totp_code, remote_addr, user_agent)
                    .await
            }
        }
    }

    pub(crate) async fn authenticate_session(
        &self,
        cookie_value: &str,
    ) -> anyhow::Result<Option<SessionIdentity>> {
        match self {
            Self::Sqlite(auth) => auth.authenticate_session(cookie_value),
            Self::Postgres(auth) => auth.authenticate_session(cookie_value).await,
        }
    }

    pub(crate) async fn logout(&mut self, cookie_value: &str) -> anyhow::Result<()> {
        match self {
            Self::Sqlite(auth) => auth.logout(cookie_value),
            Self::Postgres(auth) => auth.logout(cookie_value).await,
        }
    }

    pub(crate) async fn change_password(
        &mut self,
        cookie_value: &str,
        new_password: &str,
    ) -> anyhow::Result<bool> {
        match self {
            Self::Sqlite(auth) => auth.change_password(cookie_value, new_password),
            Self::Postgres(auth) => auth.change_password(cookie_value, new_password).await,
        }
    }

    pub(crate) async fn list_users(&self) -> anyhow::Result<Vec<UserRecord>> {
        match self {
            Self::Sqlite(auth) => auth.list_users(),
            Self::Postgres(auth) => auth.list_users().await,
        }
    }

    pub(crate) async fn create_user(&mut self, request: CreateUser) -> anyhow::Result<UserRecord> {
        match self {
            Self::Sqlite(auth) => auth.create_user(request),
            Self::Postgres(auth) => auth.create_user(request).await,
        }
    }

    pub(crate) async fn update_user(
        &mut self,
        actor: &str,
        username: &str,
        request: UpdateUser,
    ) -> anyhow::Result<Option<UserRecord>> {
        match self {
            Self::Sqlite(auth) => auth.update_user(actor, username, request),
            Self::Postgres(auth) => auth.update_user(actor, username, request).await,
        }
    }

    pub(crate) async fn delete_user(
        &mut self,
        actor: &str,
        username: &str,
    ) -> anyhow::Result<bool> {
        match self {
            Self::Sqlite(auth) => auth.delete_user(actor, username),
            Self::Postgres(auth) => auth.delete_user(actor, username).await,
        }
    }

    pub(crate) async fn reset_user_password(
        &mut self,
        username: &str,
        new_password: &str,
        force_password_change: bool,
    ) -> anyhow::Result<bool> {
        match self {
            Self::Sqlite(auth) => {
                auth.reset_user_password(username, new_password, force_password_change)
            }
            Self::Postgres(auth) => {
                auth.reset_user_password(username, new_password, force_password_change)
                    .await
            }
        }
    }

    pub(crate) async fn revoke_user_sessions(&mut self, username: &str) -> anyhow::Result<bool> {
        match self {
            Self::Sqlite(auth) => auth.revoke_user_sessions(username),
            Self::Postgres(auth) => auth.revoke_user_sessions(username).await,
        }
    }

    pub(crate) async fn begin_totp(&mut self, username: &str) -> anyhow::Result<Option<String>> {
        match self {
            Self::Sqlite(auth) => auth.begin_totp(username),
            Self::Postgres(auth) => auth.begin_totp(username).await,
        }
    }

    pub(crate) async fn enable_totp(
        &mut self,
        username: &str,
        current_session_id: Uuid,
        code: &str,
    ) -> anyhow::Result<bool> {
        match self {
            Self::Sqlite(auth) => auth.enable_totp(username, current_session_id, code),
            Self::Postgres(auth) => auth.enable_totp(username, current_session_id, code).await,
        }
    }

    pub(crate) async fn disable_totp(
        &mut self,
        username: &str,
        code: &str,
    ) -> anyhow::Result<bool> {
        match self {
            Self::Sqlite(auth) => auth.disable_totp(username, code),
            Self::Postgres(auth) => auth.disable_totp(username, code).await,
        }
    }

    pub(crate) async fn list_sessions(&self) -> anyhow::Result<Vec<SessionRecord>> {
        match self {
            Self::Sqlite(auth) => auth.list_sessions(),
            Self::Postgres(auth) => auth.list_sessions().await,
        }
    }

    pub(crate) async fn revoke_session(
        &mut self,
        actor_session_id: Uuid,
        session_id: Uuid,
    ) -> anyhow::Result<bool> {
        match self {
            Self::Sqlite(auth) => auth.revoke_session(actor_session_id, session_id),
            Self::Postgres(auth) => auth.revoke_session(actor_session_id, session_id).await,
        }
    }
}

pub(crate) enum ApiTokenStore {
    Sqlite(ApiTokenCatalog),
    Postgres(PostgresApiTokenCatalog),
}

impl ApiTokenStore {
    pub(crate) async fn open(
        storage: &CoordinationStorage,
        database: &Database,
    ) -> anyhow::Result<Self> {
        match storage.backend() {
            StorageBackend::Sqlite => {
                Ok(Self::Sqlite(ApiTokenCatalog::open_with_database(database)?))
            }
            StorageBackend::Postgres => Ok(Self::Postgres(
                PostgresApiTokenCatalog::open(storage.clone()).await?,
            )),
        }
    }

    pub(crate) async fn list(&self) -> anyhow::Result<Vec<ApiTokenRecord>> {
        match self {
            Self::Sqlite(catalog) => catalog.list(),
            Self::Postgres(catalog) => catalog.list().await,
        }
    }

    pub(crate) async fn create(
        &mut self,
        request: CreateApiToken,
        now: u64,
    ) -> anyhow::Result<CreatedApiToken> {
        match self {
            Self::Sqlite(catalog) => catalog.create(request, now),
            Self::Postgres(catalog) => catalog.create(request, now).await,
        }
    }

    pub(crate) async fn revoke(&mut self, id: Uuid) -> anyhow::Result<bool> {
        match self {
            Self::Sqlite(catalog) => catalog.revoke(id),
            Self::Postgres(catalog) => catalog.revoke(id).await,
        }
    }

    pub(crate) async fn authenticate(
        &mut self,
        token: &str,
        now: u64,
    ) -> anyhow::Result<Option<ApiTokenRecord>> {
        match self {
            Self::Sqlite(catalog) => catalog.authenticate(token, now),
            Self::Postgres(catalog) => catalog.authenticate(token, now).await,
        }
    }
}

pub(crate) enum ClientRegistryStore {
    Sqlite(ClientRegistry),
    Postgres(PostgresClientRegistry),
}

impl ClientRegistryStore {
    pub(crate) async fn open(
        storage: &CoordinationStorage,
        database: &Database,
    ) -> anyhow::Result<Self> {
        match storage.backend() {
            StorageBackend::Sqlite => {
                Ok(Self::Sqlite(ClientRegistry::open_with_database(database)?))
            }
            StorageBackend::Postgres => Ok(Self::Postgres(
                PostgresClientRegistry::open(storage.clone()).await?,
            )),
        }
    }

    pub(crate) async fn count(&self) -> anyhow::Result<usize> {
        match self {
            Self::Sqlite(registry) => Ok(registry.count()),
            Self::Postgres(registry) => registry.count().await,
        }
    }

    pub(crate) async fn contains(&self, client_id: Uuid) -> anyhow::Result<bool> {
        match self {
            Self::Sqlite(registry) => Ok(registry.contains(client_id)),
            Self::Postgres(registry) => registry.contains(client_id).await,
        }
    }

    pub(crate) async fn summaries(&self) -> anyhow::Result<Vec<ClientSummary>> {
        match self {
            Self::Sqlite(registry) => Ok(registry.summaries()),
            Self::Postgres(registry) => registry.summaries().await,
        }
    }

    pub(crate) async fn summary_by_id(
        &self,
        client_id: Uuid,
    ) -> anyhow::Result<Option<ClientSummary>> {
        match self {
            Self::Sqlite(registry) => Ok(registry.summary_by_id(client_id)),
            Self::Postgres(registry) => registry.summary_by_id(client_id).await,
        }
    }

    pub(crate) async fn enroll_with_identity(
        &mut self,
        name: String,
        platform: String,
        agent_instance_id: Option<Uuid>,
        agent_identity_public_key: Option<String>,
    ) -> anyhow::Result<(Uuid, Uuid, String)> {
        match self {
            Self::Sqlite(registry) => registry.enroll_with_identity(
                name,
                platform,
                agent_instance_id,
                agent_identity_public_key,
            ),
            Self::Postgres(registry) => {
                registry
                    .enroll_with_identity(
                        name,
                        platform,
                        agent_instance_id,
                        agent_identity_public_key,
                    )
                    .await
            }
        }
    }

    pub(crate) async fn authenticate_and_touch(
        &mut self,
        client_id: Uuid,
        token: &str,
    ) -> anyhow::Result<Authentication> {
        match self {
            Self::Sqlite(registry) => registry.authenticate_and_touch(client_id, token),
            Self::Postgres(registry) => registry.authenticate_and_touch(client_id, token).await,
        }
    }

    pub(crate) async fn update(
        &mut self,
        client_id: Uuid,
        request: UpdateClient,
    ) -> anyhow::Result<Option<ClientSummary>> {
        match self {
            Self::Sqlite(registry) => registry.update(client_id, request),
            Self::Postgres(registry) => registry.update(client_id, request).await,
        }
    }

    pub(crate) async fn rotate_token(&mut self, client_id: Uuid) -> anyhow::Result<Option<String>> {
        match self {
            Self::Sqlite(registry) => registry.rotate_token(client_id),
            Self::Postgres(registry) => registry.rotate_token(client_id).await,
        }
    }

    pub(crate) async fn delete(&mut self, client_id: Uuid) -> anyhow::Result<bool> {
        match self {
            Self::Sqlite(registry) => registry.delete(client_id),
            Self::Postgres(registry) => registry.delete(client_id).await,
        }
    }

    pub(crate) async fn update_config_sync(
        &mut self,
        client_id: Uuid,
        mode: ManagedConfigMode,
        status: ManagedConfigStatus,
        applied_revision: Option<String>,
        error: Option<String>,
    ) -> anyhow::Result<()> {
        match self {
            Self::Sqlite(registry) => {
                registry.update_config_sync(client_id, mode, status, applied_revision, error)
            }
            Self::Postgres(registry) => {
                registry
                    .update_config_sync(client_id, mode, status, applied_revision, error)
                    .await
            }
        }
    }
}
