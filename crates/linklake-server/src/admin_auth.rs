use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use getrandom::fill as random_fill;
use hmac::{Hmac, Mac};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::path::Path;
use uuid::Uuid;

use crate::database::Database;

const SESSION_LIFETIME_SECONDS: u64 = 8 * 60 * 60;

pub(crate) struct BootstrapCredentials {
    pub(crate) username: String,
    pub(crate) password: String,
    force_password_change: bool,
}

pub(crate) struct AdminAuth {
    database: Connection,
    dummy_password_hash: String,
}

pub(crate) struct NewSession {
    pub(crate) session_id: Uuid,
    pub(crate) cookie_value: String,
    pub(crate) display_name: String,
    pub(crate) expires_unix_seconds: u64,
    pub(crate) password_change_required: bool,
    pub(crate) role: UserRole,
    pub(crate) totp_enabled: bool,
}

pub(crate) enum LoginAttempt {
    Success(NewSession),
    InvalidCredentials,
    TotpRequired,
}

type AdministratorLoginRow = (String, i64, i64, String, String, Option<String>, i64);

#[derive(Debug, Clone)]
pub(crate) struct SessionIdentity {
    pub(crate) session_id: Uuid,
    pub(crate) username: String,
    pub(crate) display_name: String,
    pub(crate) role: UserRole,
    pub(crate) expires_unix_seconds: u64,
    pub(crate) password_change_required: bool,
    pub(crate) totp_enabled: bool,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum UserRole {
    Administrator,
    Operator,
    Auditor,
}

impl UserRole {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Administrator => "administrator",
            Self::Operator => "operator",
            Self::Auditor => "auditor",
        }
    }

    fn parse(value: &str) -> anyhow::Result<Self> {
        match value {
            "administrator" => Ok(Self::Administrator),
            "operator" => Ok(Self::Operator),
            "auditor" => Ok(Self::Auditor),
            _ => anyhow::bail!("invalid user role"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct UserRecord {
    pub(crate) username: String,
    pub(crate) display_name: String,
    pub(crate) role: UserRole,
    pub(crate) enabled: bool,
    pub(crate) must_change_password: bool,
    pub(crate) created_unix_seconds: u64,
    pub(crate) last_login_unix_seconds: Option<u64>,
    pub(crate) active_sessions: u64,
    pub(crate) totp_enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct SessionRecord {
    pub(crate) session_id: Uuid,
    pub(crate) username: String,
    pub(crate) created_unix_seconds: u64,
    pub(crate) expires_unix_seconds: u64,
    pub(crate) remote_addr: Option<String>,
    pub(crate) user_agent: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CreateUser {
    pub(crate) username: String,
    pub(crate) display_name: String,
    pub(crate) role: UserRole,
    pub(crate) password: String,
    #[serde(default = "default_true")]
    pub(crate) force_password_change: bool,
}

#[derive(Debug, Deserialize)]
pub(crate) struct UpdateUser {
    pub(crate) display_name: String,
    pub(crate) role: UserRole,
    pub(crate) enabled: bool,
}

fn default_true() -> bool {
    true
}

impl BootstrapCredentials {
    pub(crate) fn from_environment(allow_insecure_default: bool) -> anyhow::Result<Option<Self>> {
        let username = std::env::var("LINKLAKE_ADMIN_USERNAME")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let password = std::env::var("LINKLAKE_ADMIN_PASSWORD")
            .ok()
            .filter(|value| !value.is_empty());
        match (username, password) {
            (Some(username), Some(password)) => {
                validate_credentials(&username, &password)?;
                Ok(Some(Self {
                    username,
                    password,
                    force_password_change: false,
                }))
            }
            (None, None) if allow_insecure_default => {
                tracing::warn!("Creating insecure development-only administrator admin / 123456; the first login must change this password.");
                Ok(Some(Self {
                    username: "admin".to_owned(),
                    password: "123456".to_owned(),
                    force_password_change: true,
                }))
            }
            (None, None) => Ok(None),
            _ => anyhow::bail!(
                "LINKLAKE_ADMIN_USERNAME and LINKLAKE_ADMIN_PASSWORD must be configured together"
            ),
        }
    }

    pub(crate) fn schema_migration_placeholder(username: String) -> Self {
        Self {
            username,
            password: format!("LinkLake-schema-migration-{}", Uuid::new_v4()),
            force_password_change: true,
        }
    }
}

impl AdminAuth {
    #[allow(dead_code)]
    pub(crate) fn open(
        data_dir: Option<&Path>,
        bootstrap: Option<BootstrapCredentials>,
    ) -> anyhow::Result<Self> {
        let database = Database::open(data_dir)?;
        Self::open_with_database(&database, bootstrap)
    }

    pub(crate) fn open_with_database(
        database: &Database,
        bootstrap: Option<BootstrapCredentials>,
    ) -> anyhow::Result<Self> {
        let database = database.connect()?;
        database.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS administrators (
                username TEXT PRIMARY KEY NOT NULL,
                password_hash TEXT NOT NULL,
                created_unix_seconds INTEGER NOT NULL,
                must_change_password INTEGER NOT NULL DEFAULT 0,
                display_name TEXT NOT NULL DEFAULT '',
                role TEXT NOT NULL DEFAULT 'administrator',
                enabled INTEGER NOT NULL DEFAULT 1,
                last_login_unix_seconds INTEGER,
                totp_secret TEXT,
                totp_enabled INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS admin_sessions (
                session_id TEXT PRIMARY KEY NOT NULL,
                session_secret_hash TEXT NOT NULL,
                username TEXT NOT NULL,
                created_unix_seconds INTEGER NOT NULL DEFAULT 0,
                expires_unix_seconds INTEGER NOT NULL,
                remote_addr TEXT,
                user_agent TEXT
            );
            CREATE INDEX IF NOT EXISTS admin_sessions_expiry ON admin_sessions(expires_unix_seconds);
            ",
        )?;
        ensure_auth_columns(&database)?;
        let administrator_count: u64 =
            database.query_row("SELECT COUNT(*) FROM administrators", [], |row| row.get(0))?;
        if administrator_count == 0 {
            let bootstrap = bootstrap.ok_or_else(|| {
                anyhow::anyhow!(
                    "no administrator exists; set LINKLAKE_ADMIN_USERNAME and LINKLAKE_ADMIN_PASSWORD for the first start"
                )
            })?;
            database.execute(
                "INSERT INTO administrators (username, password_hash, created_unix_seconds, must_change_password, display_name, role, enabled) VALUES (?1, ?2, ?3, ?4, ?5, 'administrator', 1)",
                params![
                    bootstrap.username,
                    hash_password(&bootstrap.password)?,
                    unix_seconds() as i64,
                    bootstrap.force_password_change,
                    bootstrap.username,
                ],
            )?;
            tracing::info!("Created initial LinkLake administrator account.");
        }
        Ok(Self {
            database,
            // 未知用户名也执行一次与真实密码相同的 Argon2 校验，降低明显的账户枚举时序差。
            dummy_password_hash: hash_password("linklake-dummy-password-verification")?,
        })
    }

    #[cfg(test)]
    pub(crate) fn login(
        &mut self,
        username: &str,
        password: &str,
    ) -> anyhow::Result<Option<NewSession>> {
        match self.login_with_totp(username, password, None)? {
            LoginAttempt::Success(session) => Ok(Some(session)),
            LoginAttempt::InvalidCredentials | LoginAttempt::TotpRequired => Ok(None),
        }
    }

    #[cfg(test)]
    pub(crate) fn login_with_totp(
        &mut self,
        username: &str,
        password: &str,
        totp_code: Option<&str>,
    ) -> anyhow::Result<LoginAttempt> {
        self.login_with_context(username, password, totp_code, None, None)
    }

    pub(crate) fn login_with_context(
        &mut self,
        username: &str,
        password: &str,
        totp_code: Option<&str>,
        remote_addr: Option<&str>,
        user_agent: Option<&str>,
    ) -> anyhow::Result<LoginAttempt> {
        let administrator: Option<AdministratorLoginRow> = self
            .database
            .query_row(
                "SELECT password_hash, must_change_password, enabled, role, display_name, totp_secret, totp_enabled FROM administrators WHERE username = ?1",
                [username],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .optional()?;
        let (must_change_password, role, display_name, totp_secret, totp_enabled) =
            match administrator {
                Some((
                    password_hash,
                    must_change_password,
                    enabled,
                    role,
                    display_name,
                    totp_secret,
                    totp_enabled,
                )) => {
                    if enabled == 0 || !verify_password(password, &password_hash)? {
                        return Ok(LoginAttempt::InvalidCredentials);
                    }
                    (
                        must_change_password,
                        UserRole::parse(&role)?,
                        display_name,
                        totp_secret,
                        totp_enabled != 0,
                    )
                }
                None => {
                    let _ = verify_password(password, &self.dummy_password_hash)?;
                    return Ok(LoginAttempt::InvalidCredentials);
                }
            };
        if totp_enabled {
            let Some(code) = totp_code.filter(|value| !value.trim().is_empty()) else {
                return Ok(LoginAttempt::TotpRequired);
            };
            let Some(secret) = totp_secret.as_deref() else {
                return Ok(LoginAttempt::InvalidCredentials);
            };
            if !verify_totp(secret, code, unix_seconds()) {
                return Ok(LoginAttempt::InvalidCredentials);
            }
        }
        let session_id = Uuid::new_v4();
        let session_secret = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let expires_unix_seconds = unix_seconds() + SESSION_LIFETIME_SECONDS;
        self.database.execute(
            "DELETE FROM admin_sessions WHERE expires_unix_seconds <= ?1",
            [unix_seconds() as i64],
        )?;
        self.database.execute(
            "INSERT INTO admin_sessions (session_id, session_secret_hash, username, created_unix_seconds, expires_unix_seconds, remote_addr, user_agent) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                session_id.to_string(),
                hash_session_secret(&session_secret),
                username,
                unix_seconds() as i64,
                expires_unix_seconds as i64,
                remote_addr.map(|value| value.chars().take(128).collect::<String>()),
                user_agent.map(|value| value.chars().take(512).collect::<String>()),
            ],
        )?;
        self.database.execute(
            "UPDATE administrators SET last_login_unix_seconds = ?1 WHERE username = ?2",
            params![unix_seconds() as i64, username],
        )?;
        Ok(LoginAttempt::Success(NewSession {
            session_id,
            cookie_value: format!("{session_id}.{session_secret}"),
            display_name,
            expires_unix_seconds,
            password_change_required: must_change_password != 0,
            role,
            totp_enabled,
        }))
    }

    pub(crate) fn authenticate_session(
        &self,
        cookie_value: &str,
    ) -> anyhow::Result<Option<SessionIdentity>> {
        let Some((session_id, session_secret)) = cookie_value.split_once('.') else {
            return Ok(None);
        };
        let Ok(session_id) = Uuid::parse_str(session_id) else {
            return Ok(None);
        };
        let session: Option<(String, i64, String, String, String, i64, i64)> = self
            .database
            .query_row(
                "SELECT s.session_secret_hash, s.expires_unix_seconds, a.username, a.display_name, a.role, a.must_change_password, a.totp_enabled FROM admin_sessions s JOIN administrators a ON a.username = s.username WHERE s.session_id = ?1 AND a.enabled = 1",
                [session_id.to_string()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            session_secret_hash,
            expires_unix_seconds,
            username,
            display_name,
            role,
            must_change_password,
            totp_enabled,
        )) = session
        else {
            return Ok(None);
        };
        if expires_unix_seconds <= unix_seconds() as i64 {
            return Ok(None);
        }
        if !session_secret_hash.starts_with("sha256:") {
            // 旧版本使用 Argon2 保存会话 secret。升级后明确使其失效，避免高频 API
            // 鉴权继续承担密码哈希的 CPU 成本。
            self.database.execute(
                "DELETE FROM admin_sessions WHERE session_id = ?1",
                [session_id.to_string()],
            )?;
            return Ok(None);
        }
        if !verify_session_secret(session_secret, &session_secret_hash) {
            return Ok(None);
        }
        Ok(Some(SessionIdentity {
            session_id,
            username,
            display_name,
            role: UserRole::parse(&role)?,
            expires_unix_seconds: expires_unix_seconds as u64,
            password_change_required: must_change_password != 0,
            totp_enabled: totp_enabled != 0,
        }))
    }

    pub(crate) fn logout(&mut self, cookie_value: &str) -> anyhow::Result<()> {
        let Some((session_id, _)) = cookie_value.split_once('.') else {
            return Ok(());
        };
        if let Ok(session_id) = Uuid::parse_str(session_id) {
            self.database.execute(
                "DELETE FROM admin_sessions WHERE session_id = ?1",
                [session_id.to_string()],
            )?;
        }
        Ok(())
    }

    pub(crate) fn change_password(
        &mut self,
        cookie_value: &str,
        new_password: &str,
    ) -> anyhow::Result<bool> {
        validate_password(new_password)?;
        let Some((session_id, _)) = cookie_value.split_once('.') else {
            return Ok(false);
        };
        let Ok(session_id) = Uuid::parse_str(session_id) else {
            return Ok(false);
        };
        let Some(identity) = self.authenticate_session(cookie_value)? else {
            return Ok(false);
        };
        let transaction = self.database.transaction()?;
        transaction.execute(
            "UPDATE administrators SET password_hash = ?1, must_change_password = 0 WHERE username = ?2",
            params![hash_password(new_password)?, identity.username],
        )?;
        transaction.execute(
            "DELETE FROM admin_sessions WHERE username = ?1 AND session_id <> ?2",
            params![identity.username, session_id.to_string()],
        )?;
        transaction.commit()?;
        Ok(true)
    }

    pub(crate) fn list_users(&self) -> anyhow::Result<Vec<UserRecord>> {
        self.database.execute(
            "DELETE FROM admin_sessions WHERE expires_unix_seconds <= ?1",
            [unix_seconds() as i64],
        )?;
        let mut statement = self.database.prepare(
            "SELECT a.username, a.display_name, a.role, a.enabled, a.must_change_password, a.created_unix_seconds, a.last_login_unix_seconds, COUNT(s.session_id), a.totp_enabled FROM administrators a LEFT JOIN admin_sessions s ON s.username = a.username GROUP BY a.username ORDER BY a.username",
        )?;
        let rows = statement.query_map([], |row| {
            let role: String = row.get(2)?;
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                role,
                row.get::<_, i64>(3)? != 0,
                row.get::<_, i64>(4)? != 0,
                row.get::<_, i64>(5)? as u64,
                row.get::<_, Option<i64>>(6)?.map(|value| value as u64),
                row.get::<_, i64>(7)? as u64,
                row.get::<_, i64>(8)? != 0,
            ))
        })?;
        rows.map(|row| {
            let (
                username,
                display_name,
                role,
                enabled,
                must_change_password,
                created_unix_seconds,
                last_login_unix_seconds,
                active_sessions,
                totp_enabled,
            ) = row?;
            Ok(UserRecord {
                username,
                display_name,
                role: UserRole::parse(&role)?,
                enabled,
                must_change_password,
                created_unix_seconds,
                last_login_unix_seconds,
                active_sessions,
                totp_enabled,
            })
        })
        .collect()
    }

    pub(crate) fn create_user(&mut self, request: CreateUser) -> anyhow::Result<UserRecord> {
        validate_credentials(&request.username, &request.password)?;
        validate_display_name(&request.display_name)?;
        let result = self.database.execute(
            "INSERT INTO administrators (username, password_hash, created_unix_seconds, must_change_password, display_name, role, enabled) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1)",
            params![
                request.username,
                hash_password(&request.password)?,
                unix_seconds() as i64,
                request.force_password_change,
                request.display_name.trim(),
                request.role.as_str(),
            ],
        );
        match result {
            Ok(_) => self
                .user(&request.username)?
                .ok_or_else(|| anyhow::anyhow!("created user could not be read")),
            Err(error) if is_constraint_violation(&error) => {
                anyhow::bail!("username already exists")
            }
            Err(error) => Err(error.into()),
        }
    }

    pub(crate) fn update_user(
        &mut self,
        actor: &str,
        username: &str,
        request: UpdateUser,
    ) -> anyhow::Result<Option<UserRecord>> {
        validate_display_name(&request.display_name)?;
        let Some(current) = self.user(username)? else {
            return Ok(None);
        };
        if username == actor && (!request.enabled || request.role != UserRole::Administrator) {
            anyhow::bail!("current user cannot be disabled or demoted")
        }
        if current.enabled
            && current.role == UserRole::Administrator
            && (!request.enabled || request.role != UserRole::Administrator)
            && self.enabled_administrator_count()? <= 1
        {
            anyhow::bail!("last administrator cannot be disabled or demoted")
        }
        let transaction = self.database.transaction()?;
        transaction.execute(
            "UPDATE administrators SET display_name = ?1, role = ?2, enabled = ?3 WHERE username = ?4",
            params![
                request.display_name.trim(),
                request.role.as_str(),
                request.enabled,
                username,
            ],
        )?;
        if !request.enabled || request.role != current.role {
            transaction.execute("DELETE FROM admin_sessions WHERE username = ?1", [username])?;
        }
        transaction.commit()?;
        self.user(username)
    }

    pub(crate) fn delete_user(&mut self, actor: &str, username: &str) -> anyhow::Result<bool> {
        let Some(current) = self.user(username)? else {
            return Ok(false);
        };
        if username == actor {
            anyhow::bail!("current user cannot be deleted")
        }
        if current.enabled
            && current.role == UserRole::Administrator
            && self.enabled_administrator_count()? <= 1
        {
            anyhow::bail!("last administrator cannot be deleted")
        }
        let transaction = self.database.transaction()?;
        transaction.execute("DELETE FROM admin_sessions WHERE username = ?1", [username])?;
        transaction.execute("DELETE FROM administrators WHERE username = ?1", [username])?;
        transaction.commit()?;
        Ok(true)
    }

    pub(crate) fn reset_user_password(
        &mut self,
        username: &str,
        new_password: &str,
        force_password_change: bool,
    ) -> anyhow::Result<bool> {
        validate_password(new_password)?;
        let transaction = self.database.transaction()?;
        let updated = transaction.execute(
            "UPDATE administrators SET password_hash = ?1, must_change_password = ?2 WHERE username = ?3",
            params![hash_password(new_password)?, force_password_change, username],
        )?;
        if updated == 0 {
            return Ok(false);
        }
        transaction.execute("DELETE FROM admin_sessions WHERE username = ?1", [username])?;
        transaction.commit()?;
        Ok(true)
    }

    pub(crate) fn revoke_user_sessions(&mut self, username: &str) -> anyhow::Result<bool> {
        if self.user(username)?.is_none() {
            return Ok(false);
        }
        self.database
            .execute("DELETE FROM admin_sessions WHERE username = ?1", [username])?;
        Ok(true)
    }

    /// 生成新的 TOTP 密钥，但在校验首个验证码前不启用双因素认证。
    pub(crate) fn begin_totp(&mut self, username: &str) -> anyhow::Result<Option<String>> {
        if self.user(username)?.is_none() {
            return Ok(None);
        }
        let mut secret = [0_u8; 20];
        random_fill(&mut secret)?;
        let encoded = base32_encode(&secret);
        self.database.execute(
            "UPDATE administrators SET totp_secret = ?1, totp_enabled = 0 WHERE username = ?2",
            params![encoded, username],
        )?;
        Ok(Some(encoded))
    }

    /// 验证设置阶段的首个验证码并启用 TOTP，同时撤销除当前会话外的其他会话。
    pub(crate) fn enable_totp(
        &mut self,
        username: &str,
        current_session_id: Uuid,
        code: &str,
    ) -> anyhow::Result<bool> {
        let secret: Option<Option<String>> = self
            .database
            .query_row(
                "SELECT totp_secret FROM administrators WHERE username = ?1",
                [username],
                |row| row.get(0),
            )
            .optional()?;
        let Some(Some(secret)) = secret else {
            return Ok(false);
        };
        if !verify_totp(&secret, code, unix_seconds()) {
            return Ok(false);
        }
        let transaction = self.database.transaction()?;
        transaction.execute(
            "UPDATE administrators SET totp_enabled = 1 WHERE username = ?1",
            [username],
        )?;
        transaction.execute(
            "DELETE FROM admin_sessions WHERE username = ?1 AND session_id <> ?2",
            params![username, current_session_id.to_string()],
        )?;
        transaction.commit()?;
        Ok(true)
    }

    /// 使用当前有效的 TOTP 验证码关闭双因素认证，并清除密钥。
    pub(crate) fn disable_totp(&mut self, username: &str, code: &str) -> anyhow::Result<bool> {
        let secret: Option<Option<String>> = self
            .database
            .query_row(
                "SELECT CASE WHEN totp_enabled = 1 THEN totp_secret ELSE NULL END FROM administrators WHERE username = ?1",
                [username],
                |row| row.get(0),
            )
            .optional()?;
        let Some(Some(secret)) = secret else {
            return Ok(false);
        };
        if !verify_totp(&secret, code, unix_seconds()) {
            return Ok(false);
        }
        self.database.execute(
            "UPDATE administrators SET totp_secret = NULL, totp_enabled = 0 WHERE username = ?1",
            [username],
        )?;
        Ok(true)
    }

    pub(crate) fn list_sessions(&self) -> anyhow::Result<Vec<SessionRecord>> {
        self.database.execute(
            "DELETE FROM admin_sessions WHERE expires_unix_seconds <= ?1",
            [unix_seconds() as i64],
        )?;
        let mut statement = self.database.prepare(
            "SELECT session_id, username, created_unix_seconds, expires_unix_seconds, remote_addr, user_agent FROM admin_sessions ORDER BY created_unix_seconds DESC",
        )?;
        let rows = statement.query_map([], |row| {
            let session_id: String = row.get(0)?;
            Ok(SessionRecord {
                session_id: Uuid::parse_str(&session_id)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?,
                username: row.get(1)?,
                created_unix_seconds: row.get::<_, i64>(2)? as u64,
                expires_unix_seconds: row.get::<_, i64>(3)? as u64,
                remote_addr: row.get(4)?,
                user_agent: row.get(5)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub(crate) fn revoke_session(
        &mut self,
        actor_session_id: Uuid,
        session_id: Uuid,
    ) -> anyhow::Result<bool> {
        anyhow::ensure!(
            actor_session_id != session_id,
            "current session cannot be revoked from session management"
        );
        Ok(self.database.execute(
            "DELETE FROM admin_sessions WHERE session_id = ?1",
            [session_id.to_string()],
        )? > 0)
    }

    fn user(&self, username: &str) -> anyhow::Result<Option<UserRecord>> {
        self.database
            .query_row(
                "SELECT a.username, a.display_name, a.role, a.enabled, a.must_change_password, a.created_unix_seconds, a.last_login_unix_seconds, (SELECT COUNT(*) FROM admin_sessions s WHERE s.username = a.username AND s.expires_unix_seconds > ?1), a.totp_enabled FROM administrators a WHERE a.username = ?2",
                params![unix_seconds() as i64, username],
                |row| {
                    let role: String = row.get(2)?;
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        role,
                        row.get::<_, i64>(3)? != 0,
                        row.get::<_, i64>(4)? != 0,
                        row.get::<_, i64>(5)? as u64,
                        row.get::<_, Option<i64>>(6)?.map(|value| value as u64),
                        row.get::<_, i64>(7)? as u64,
                        row.get::<_, i64>(8)? != 0,
                    ))
                },
            )
            .optional()?
            .map(|(username, display_name, role, enabled, must_change_password, created_unix_seconds, last_login_unix_seconds, active_sessions, totp_enabled)| {
                Ok(UserRecord {
                    username,
                    display_name,
                    role: UserRole::parse(&role)?,
                    enabled,
                    must_change_password,
                    created_unix_seconds,
                    last_login_unix_seconds,
                    active_sessions,
                    totp_enabled,
                })
            })
            .transpose()
    }

    fn enabled_administrator_count(&self) -> anyhow::Result<u64> {
        Ok(self.database.query_row(
            "SELECT COUNT(*) FROM administrators WHERE role = 'administrator' AND enabled = 1",
            [],
            |row| row.get(0),
        )?)
    }
}

fn ensure_auth_columns(database: &Connection) -> anyhow::Result<()> {
    let mut statement = database.prepare("PRAGMA table_info(administrators)")?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    let mut names = Vec::new();
    for column in columns {
        names.push(column?);
    }
    for (name, definition) in [
        ("must_change_password", "INTEGER NOT NULL DEFAULT 0"),
        ("display_name", "TEXT NOT NULL DEFAULT ''"),
        ("role", "TEXT NOT NULL DEFAULT 'administrator'"),
        ("enabled", "INTEGER NOT NULL DEFAULT 1"),
        ("last_login_unix_seconds", "INTEGER"),
        ("totp_secret", "TEXT"),
        ("totp_enabled", "INTEGER NOT NULL DEFAULT 0"),
    ] {
        if !names.iter().any(|column| column == name) {
            database.execute(
                &format!("ALTER TABLE administrators ADD COLUMN {name} {definition}"),
                [],
            )?;
        }
    }
    database.execute(
        "UPDATE administrators SET display_name = username WHERE display_name = ''",
        [],
    )?;
    let mut statement = database.prepare("PRAGMA table_info(admin_sessions)")?;
    let session_columns = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<Vec<_>, _>>()?;
    if !session_columns
        .iter()
        .any(|column| column == "created_unix_seconds")
    {
        database.execute(
            "ALTER TABLE admin_sessions ADD COLUMN created_unix_seconds INTEGER NOT NULL DEFAULT 0",
            [],
        )?;
    }
    for (name, definition) in [("remote_addr", "TEXT"), ("user_agent", "TEXT")] {
        if !session_columns.iter().any(|column| column == name) {
            database.execute(
                &format!("ALTER TABLE admin_sessions ADD COLUMN {name} {definition}"),
                [],
            )?;
        }
    }
    Ok(())
}

fn validate_credentials(username: &str, password: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        username.len() >= 3
            && username.len() <= 64
            && username
                .bytes()
                .all(|character| character.is_ascii_alphanumeric()
                    || character == b'_'
                    || character == b'-'),
        "administrator username must be 3-64 ASCII letters, digits, underscores, or hyphens"
    );
    validate_password(password)?;
    Ok(())
}

fn validate_password(password: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        password.len() >= 12,
        "administrator password must contain at least 12 characters"
    );
    Ok(())
}

fn validate_display_name(display_name: &str) -> anyhow::Result<()> {
    let display_name = display_name.trim();
    anyhow::ensure!(
        !display_name.is_empty()
            && display_name.chars().count() <= 80
            && !display_name.chars().any(char::is_control),
        "display name must contain 1-80 visible characters"
    );
    Ok(())
}

fn is_constraint_violation(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(database_error, _)
            if database_error.code == rusqlite::ErrorCode::ConstraintViolation
    )
}

fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::encode_b64(Uuid::new_v4().as_bytes())
        .map_err(|error| anyhow::anyhow!("could not create credential salt: {error}"))?;
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|error| anyhow::anyhow!("could not hash credential: {error}"))?
        .to_string())
}

fn verify_password(password: &str, password_hash: &str) -> anyhow::Result<bool> {
    let parsed_hash = PasswordHash::new(password_hash)
        .map_err(|error| anyhow::anyhow!("stored credential hash is invalid: {error}"))?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

fn hash_session_secret(secret: &str) -> String {
    format!("sha256:{:x}", Sha256::digest(secret.as_bytes()))
}

fn verify_session_secret(secret: &str, expected_hash: &str) -> bool {
    constant_time_eq(
        hash_session_secret(secret).as_bytes(),
        expected_hash.as_bytes(),
    )
}

fn base32_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut output = String::with_capacity((input.len() * 8).div_ceil(5));
    let mut buffer = 0_u32;
    let mut bits = 0_u8;
    for byte in input {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            output.push(ALPHABET[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        output.push(ALPHABET[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    output
}

fn base32_decode(input: &str) -> Option<Vec<u8>> {
    let mut output = Vec::with_capacity(input.len() * 5 / 8);
    let mut buffer = 0_u32;
    let mut bits = 0_u8;
    for character in input.bytes().filter(|value| !value.is_ascii_whitespace()) {
        let value = match character.to_ascii_uppercase() {
            b'A'..=b'Z' => character.to_ascii_uppercase() - b'A',
            b'2'..=b'7' => character - b'2' + 26,
            _ => return None,
        };
        buffer = (buffer << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            output.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    (!output.is_empty()).then_some(output)
}

fn totp_code(secret: &[u8], unix_seconds: u64) -> Option<String> {
    let counter = unix_seconds / 30;
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).ok()?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[19] & 0x0f);
    let binary = (u32::from(digest[offset] & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    Some(format!("{:06}", binary % 1_000_000))
}

fn verify_totp(encoded_secret: &str, code: &str, unix_seconds: u64) -> bool {
    let code = code.trim();
    if code.len() != 6 || !code.bytes().all(|value| value.is_ascii_digit()) {
        return false;
    }
    let Some(secret) = base32_decode(encoded_secret) else {
        return false;
    };
    [-30_i64, 0, 30].into_iter().any(|offset| {
        let candidate_time = unix_seconds.saturating_add_signed(offset);
        totp_code(&secret, candidate_time)
            .is_some_and(|candidate| constant_time_eq(candidate.as_bytes(), code.as_bytes()))
    })
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        difference |= (left.get(index).copied().unwrap_or(0)
            ^ right.get(index).copied().unwrap_or(0)) as usize;
    }
    difference == 0
}

fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::{
        base32_decode, base32_encode, constant_time_eq, hash_password, totp_code,
        verify_session_secret, verify_totp, AdminAuth, BootstrapCredentials, CreateUser,
        LoginAttempt, UpdateUser, UserRole,
    };
    use rusqlite::params;
    use uuid::Uuid;

    #[test]
    fn authenticated_session_is_created_from_a_hashed_password() {
        let mut auth = AdminAuth::open(
            None,
            Some(BootstrapCredentials {
                username: "admin".to_owned(),
                password: "correct-horse-battery-staple".to_owned(),
                force_password_change: false,
            }),
        )
        .expect("administrator database should initialize");
        assert!(auth
            .login("admin", "incorrect-password")
            .expect("login should execute")
            .is_none());
        assert!(auth
            .login("missing-admin", "incorrect-password")
            .expect("unknown login should execute dummy verification")
            .is_none());
        let session = auth
            .login("admin", "correct-horse-battery-staple")
            .expect("login should execute")
            .expect("correct password should create a session");
        let (session_id, session_secret) = session
            .cookie_value
            .split_once('.')
            .expect("session cookie should contain an id and secret");
        let stored_hash: String = auth
            .database
            .query_row(
                "SELECT session_secret_hash FROM admin_sessions WHERE session_id = ?1",
                [session_id],
                |row| row.get(0),
            )
            .expect("session hash should be stored");
        assert!(stored_hash.starts_with("sha256:"));
        assert!(!stored_hash.starts_with("$argon2"));
        assert!(verify_session_secret(session_secret, &stored_hash));
        assert!(!verify_session_secret("wrong-session-secret", &stored_hash));
        let identity = auth
            .authenticate_session(&session.cookie_value)
            .expect("session should verify")
            .expect("session should exist");
        assert_eq!(identity.username, "admin");
        assert_eq!(identity.expires_unix_seconds, session.expires_unix_seconds);
        assert!(!identity.password_change_required);
        auth.logout(&session.cookie_value)
            .expect("logout should execute");
        assert!(auth
            .authenticate_session(&session.cookie_value)
            .expect("revoked session should verify as false")
            .is_none());
    }

    #[test]
    fn forced_initial_password_requires_a_change_before_management_access() {
        let mut auth = AdminAuth::open(
            None,
            Some(BootstrapCredentials {
                username: "admin".to_owned(),
                password: "123456".to_owned(),
                force_password_change: true,
            }),
        )
        .expect("development administrator database should initialize");
        let session = auth
            .login("admin", "123456")
            .expect("login should execute")
            .expect("initial password should create a session");
        let other_session = auth
            .login("admin", "123456")
            .expect("second login should execute")
            .expect("second login should create a session");
        assert!(session.password_change_required);
        assert!(
            auth.authenticate_session(&session.cookie_value)
                .expect("session should verify")
                .expect("session should exist")
                .password_change_required
        );

        assert!(auth
            .change_password(&session.cookie_value, "a-long-replacement-password")
            .expect("password change should execute"));
        assert!(
            !auth
                .authenticate_session(&session.cookie_value)
                .expect("session should verify")
                .expect("session should exist")
                .password_change_required
        );
        assert!(auth
            .authenticate_session(&other_session.cookie_value)
            .expect("other session should verify")
            .is_none());
        assert!(auth
            .login("admin", "123456")
            .expect("old password login should execute")
            .is_none());
        assert!(auth
            .login("admin", "a-long-replacement-password")
            .expect("new password login should execute")
            .is_some());
    }

    #[test]
    fn user_roles_sessions_and_last_administrator_are_protected() {
        let mut auth = AdminAuth::open(
            None,
            Some(BootstrapCredentials {
                username: "admin".to_owned(),
                password: "correct-horse-battery-staple".to_owned(),
                force_password_change: false,
            }),
        )
        .expect("administrator database should initialize");
        let user = auth
            .create_user(CreateUser {
                username: "operator".to_owned(),
                display_name: "Operations".to_owned(),
                role: UserRole::Operator,
                password: "operator-initial-password".to_owned(),
                force_password_change: true,
            })
            .expect("operator should be created");
        assert_eq!(user.role, UserRole::Operator);
        assert!(user.must_change_password);

        let operator_session = auth
            .login("operator", "operator-initial-password")
            .expect("operator login should execute")
            .expect("operator should log in");
        assert_eq!(operator_session.role, UserRole::Operator);
        assert_eq!(auth.list_sessions().expect("sessions should list").len(), 1);

        let updated = auth
            .update_user(
                "admin",
                "operator",
                UpdateUser {
                    display_name: "Security Audit".to_owned(),
                    role: UserRole::Auditor,
                    enabled: true,
                },
            )
            .expect("user update should execute")
            .expect("user should exist");
        assert_eq!(updated.role, UserRole::Auditor);
        assert!(auth
            .authenticate_session(&operator_session.cookie_value)
            .expect("old session should be checked")
            .is_none());

        assert!(auth
            .update_user(
                "admin",
                "admin",
                UpdateUser {
                    display_name: "Administrator".to_owned(),
                    role: UserRole::Auditor,
                    enabled: true,
                },
            )
            .expect_err("current administrator cannot demote itself")
            .to_string()
            .contains("current user"));
        assert!(auth
            .delete_user("admin", "admin")
            .expect_err("current administrator cannot delete itself")
            .to_string()
            .contains("current user"));

        assert!(auth
            .reset_user_password("operator", "operator-replacement-password", false)
            .expect("password reset should execute"));
        assert!(auth
            .login("operator", "operator-initial-password")
            .expect("old password login should execute")
            .is_none());
        assert!(auth
            .login("operator", "operator-replacement-password")
            .expect("new password login should execute")
            .is_some());
        assert!(auth
            .delete_user("admin", "operator")
            .expect("operator deletion should execute"));
    }

    #[test]
    fn legacy_argon2_session_hashes_are_explicitly_revoked() {
        let auth = AdminAuth::open(
            None,
            Some(BootstrapCredentials {
                username: "admin".to_owned(),
                password: "correct-horse-battery-staple".to_owned(),
                force_password_change: false,
            }),
        )
        .expect("administrator database should initialize");
        let session_id = Uuid::new_v4();
        let session_secret = "legacy-session-secret";
        auth.database
            .execute(
                "INSERT INTO admin_sessions (session_id, session_secret_hash, username, expires_unix_seconds) VALUES (?1, ?2, 'admin', ?3)",
                params![
                    session_id.to_string(),
                    hash_password(session_secret).expect("legacy hash should generate"),
                    super::unix_seconds() as i64 + 60,
                ],
            )
            .expect("legacy session should insert");
        assert!(auth
            .authenticate_session(&format!("{session_id}.{session_secret}"))
            .expect("legacy session verification should execute")
            .is_none());
        let remaining: u64 = auth
            .database
            .query_row(
                "SELECT COUNT(*) FROM admin_sessions WHERE session_id = ?1",
                [session_id.to_string()],
                |row| row.get(0),
            )
            .expect("legacy session count should query");
        assert_eq!(remaining, 0);
    }

    #[test]
    fn constant_time_comparison_rejects_different_values_and_lengths() {
        assert!(constant_time_eq(b"same", b"same"));
        assert!(!constant_time_eq(b"same", b"diff"));
        assert!(!constant_time_eq(b"same", b"same-longer"));
    }

    #[test]
    fn base32_and_totp_match_rfc_vectors() {
        let secret = b"12345678901234567890";
        let encoded = base32_encode(secret);
        assert_eq!(base32_decode(&encoded).as_deref(), Some(secret.as_slice()));
        assert_eq!(totp_code(secret, 59).as_deref(), Some("287082"));
        assert!(verify_totp(&encoded, "287082", 59));
        assert!(!verify_totp(&encoded, "287083", 59));
    }

    #[test]
    fn totp_setup_is_required_after_enable_and_can_be_disabled() {
        let mut auth = AdminAuth::open(
            None,
            Some(BootstrapCredentials {
                username: "admin".to_owned(),
                password: "correct-horse-battery-staple".to_owned(),
                force_password_change: false,
            }),
        )
        .expect("administrator database should initialize");
        let session = auth
            .login("admin", "correct-horse-battery-staple")
            .expect("login should execute")
            .expect("login should succeed");
        let secret = auth
            .begin_totp("admin")
            .expect("setup should execute")
            .expect("user should exist");
        let code = totp_code(
            &base32_decode(&secret).expect("secret should decode"),
            super::unix_seconds(),
        )
        .expect("code should generate");
        assert!(auth
            .enable_totp("admin", session.session_id, &code)
            .expect("enable should execute"));
        assert!(matches!(
            auth.login_with_totp("admin", "correct-horse-battery-staple", None)
                .expect("login should execute"),
            LoginAttempt::TotpRequired
        ));
        assert!(matches!(
            auth.login_with_totp("admin", "correct-horse-battery-staple", Some(&code))
                .expect("login should execute"),
            LoginAttempt::Success(_)
        ));
        assert!(auth
            .disable_totp("admin", &code)
            .expect("disable should execute"));
        assert!(auth
            .login("admin", "correct-horse-battery-staple")
            .expect("login should execute")
            .is_some());
    }
}
