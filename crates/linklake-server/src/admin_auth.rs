use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rusqlite::{params, Connection, OptionalExtension};
use std::{fs, path::Path};
use uuid::Uuid;

const SESSION_LIFETIME_SECONDS: u64 = 8 * 60 * 60;

pub(crate) struct BootstrapCredentials {
    pub(crate) username: String,
    pub(crate) password: String,
    force_password_change: bool,
}

pub(crate) struct AdminAuth {
    database: Connection,
}

pub(crate) struct NewSession {
    pub(crate) cookie_value: String,
    pub(crate) expires_unix_seconds: u64,
    pub(crate) password_change_required: bool,
}

pub(crate) struct SessionIdentity {
    pub(crate) username: String,
    pub(crate) password_change_required: bool,
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
}

impl AdminAuth {
    pub(crate) fn open(
        data_dir: Option<&Path>,
        bootstrap: Option<BootstrapCredentials>,
    ) -> anyhow::Result<Self> {
        let database = match data_dir {
            Some(data_dir) => {
                fs::create_dir_all(data_dir)?;
                Connection::open(data_dir.join("linklake.sqlite3"))?
            }
            None => Connection::open_in_memory()?,
        };
        database.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS administrators (
                username TEXT PRIMARY KEY NOT NULL,
                password_hash TEXT NOT NULL,
                created_unix_seconds INTEGER NOT NULL,
                must_change_password INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS admin_sessions (
                session_id TEXT PRIMARY KEY NOT NULL,
                session_secret_hash TEXT NOT NULL,
                username TEXT NOT NULL,
                expires_unix_seconds INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS admin_sessions_expiry ON admin_sessions(expires_unix_seconds);
            ",
        )?;
        ensure_password_change_column(&database)?;
        let administrator_count: u64 =
            database.query_row("SELECT COUNT(*) FROM administrators", [], |row| row.get(0))?;
        if administrator_count == 0 {
            let bootstrap = bootstrap.ok_or_else(|| {
                anyhow::anyhow!(
                    "no administrator exists; set LINKLAKE_ADMIN_USERNAME and LINKLAKE_ADMIN_PASSWORD for the first start"
                )
            })?;
            database.execute(
                "INSERT INTO administrators (username, password_hash, created_unix_seconds, must_change_password) VALUES (?1, ?2, ?3, ?4)",
                params![
                    bootstrap.username,
                    hash_secret(&bootstrap.password)?,
                    unix_seconds() as i64,
                    bootstrap.force_password_change,
                ],
            )?;
            tracing::info!("Created initial LinkLake administrator account.");
        }
        Ok(Self { database })
    }

    pub(crate) fn login(
        &mut self,
        username: &str,
        password: &str,
    ) -> anyhow::Result<Option<NewSession>> {
        let administrator: Option<(String, i64)> = self
            .database
            .query_row(
                "SELECT password_hash, must_change_password FROM administrators WHERE username = ?1",
                [username],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((password_hash, must_change_password)) = administrator else {
            return Ok(None);
        };
        if !verify_secret(password, &password_hash)? {
            return Ok(None);
        }
        let session_id = Uuid::new_v4();
        let session_secret = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let expires_unix_seconds = unix_seconds() + SESSION_LIFETIME_SECONDS;
        self.database.execute(
            "DELETE FROM admin_sessions WHERE expires_unix_seconds <= ?1",
            [unix_seconds() as i64],
        )?;
        self.database.execute(
            "INSERT INTO admin_sessions (session_id, session_secret_hash, username, expires_unix_seconds) VALUES (?1, ?2, ?3, ?4)",
            params![
                session_id.to_string(),
                hash_secret(&session_secret)?,
                username,
                expires_unix_seconds as i64,
            ],
        )?;
        Ok(Some(NewSession {
            cookie_value: format!("{session_id}.{session_secret}"),
            expires_unix_seconds,
            password_change_required: must_change_password != 0,
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
        let session: Option<(String, i64, String, i64)> = self
            .database
            .query_row(
                "SELECT s.session_secret_hash, s.expires_unix_seconds, a.username, a.must_change_password FROM admin_sessions s JOIN administrators a ON a.username = s.username WHERE s.session_id = ?1",
                [session_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let Some((session_secret_hash, expires_unix_seconds, username, must_change_password)) =
            session
        else {
            return Ok(None);
        };
        if expires_unix_seconds <= unix_seconds() as i64 {
            return Ok(None);
        }
        if !verify_secret(session_secret, &session_secret_hash)? {
            return Ok(None);
        }
        Ok(Some(SessionIdentity {
            username,
            password_change_required: must_change_password != 0,
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
        let Some(identity) = self.authenticate_session(cookie_value)? else {
            return Ok(false);
        };
        self.database.execute(
            "UPDATE administrators SET password_hash = ?1, must_change_password = 0 WHERE username = ?2",
            params![hash_secret(new_password)?, identity.username],
        )?;
        Ok(true)
    }
}

fn ensure_password_change_column(database: &Connection) -> anyhow::Result<()> {
    let mut statement = database.prepare("PRAGMA table_info(administrators)")?;
    let columns = statement.query_map([], |row| row.get::<_, String>(1))?;
    let mut has_column = false;
    for column in columns {
        if column? == "must_change_password" {
            has_column = true;
            break;
        }
    }
    if !has_column {
        database.execute(
            "ALTER TABLE administrators ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0",
            [],
        )?;
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

fn hash_secret(secret: &str) -> anyhow::Result<String> {
    let salt = SaltString::encode_b64(Uuid::new_v4().as_bytes())
        .map_err(|error| anyhow::anyhow!("could not create credential salt: {error}"))?;
    Ok(Argon2::default()
        .hash_password(secret.as_bytes(), &salt)
        .map_err(|error| anyhow::anyhow!("could not hash credential: {error}"))?
        .to_string())
}

fn verify_secret(secret: &str, secret_hash: &str) -> anyhow::Result<bool> {
    let parsed_hash = PasswordHash::new(secret_hash)
        .map_err(|error| anyhow::anyhow!("stored credential hash is invalid: {error}"))?;
    Ok(Argon2::default()
        .verify_password(secret.as_bytes(), &parsed_hash)
        .is_ok())
}

fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::{AdminAuth, BootstrapCredentials};

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
        let session = auth
            .login("admin", "correct-horse-battery-staple")
            .expect("login should execute")
            .expect("correct password should create a session");
        assert!(auth
            .authenticate_session(&session.cookie_value)
            .expect("session should verify")
            .is_some());
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
    }
}
