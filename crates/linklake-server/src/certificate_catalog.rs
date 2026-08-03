use hyper::Uri;
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::{Deserialize, Serialize};
use std::{error::Error, fmt, path::Path};
use uuid::Uuid;

use crate::database::Database;

pub(crate) const LETS_ENCRYPT_PRODUCTION_DIRECTORY: &str =
    "https://acme-v02.api.letsencrypt.org/directory";
pub(crate) const LETS_ENCRYPT_STAGING_DIRECTORY: &str =
    "https://acme-staging-v02.api.letsencrypt.org/directory";

const MIN_RENEW_BEFORE_DAYS: u8 = 7;
const MAX_RENEW_BEFORE_DAYS: u8 = 60;
const SECONDS_PER_DAY: i64 = 86_400;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AcmeEnvironment {
    Production,
    Staging,
    Custom,
}

impl AcmeEnvironment {
    fn as_str(self) -> &'static str {
        match self {
            Self::Production => "production",
            Self::Staging => "staging",
            Self::Custom => "custom",
        }
    }

    fn parse(value: &str) -> Result<Self, CertificateCatalogError> {
        match value {
            "production" => Ok(Self::Production),
            "staging" => Ok(Self::Staging),
            "custom" => Ok(Self::Custom),
            _ => Err(CertificateCatalogError::InvalidStoredData(
                "acme_environment",
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct AcmeConfig {
    pub(crate) enabled: bool,
    pub(crate) environment: AcmeEnvironment,
    pub(crate) directory_url: String,
    pub(crate) contact_email: String,
    pub(crate) terms_accepted: bool,
    pub(crate) renew_before_days: u8,
    pub(crate) updated_at: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct UpdateAcmeConfig {
    pub(crate) enabled: bool,
    pub(crate) environment: AcmeEnvironment,
    pub(crate) directory_url: String,
    pub(crate) contact_email: String,
    pub(crate) terms_accepted: bool,
    pub(crate) renew_before_days: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RouteTlsMode {
    Disabled,
    Acme,
}

impl RouteTlsMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Acme => "acme",
        }
    }

    fn parse(value: &str) -> Result<Self, CertificateCatalogError> {
        match value {
            "disabled" => Ok(Self::Disabled),
            "acme" => Ok(Self::Acme),
            _ => Err(CertificateCatalogError::InvalidStoredData("tls_mode")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct RouteTlsPolicy {
    pub(crate) route_id: Uuid,
    pub(crate) mode: RouteTlsMode,
    pub(crate) redirect_http_to_https: bool,
    pub(crate) updated_at: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct UpdateRouteTlsPolicy {
    pub(crate) mode: RouteTlsMode,
    pub(crate) redirect_http_to_https: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CertificateStatus {
    Disabled,
    Pending,
    Issuing,
    Active,
    Renewing,
    Error,
    Expired,
}

impl CertificateStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Pending => "pending",
            Self::Issuing => "issuing",
            Self::Active => "active",
            Self::Renewing => "renewing",
            Self::Error => "error",
            Self::Expired => "expired",
        }
    }

    fn parse(value: &str) -> Result<Self, CertificateCatalogError> {
        match value {
            "disabled" => Ok(Self::Disabled),
            "pending" => Ok(Self::Pending),
            "issuing" => Ok(Self::Issuing),
            "active" => Ok(Self::Active),
            "renewing" => Ok(Self::Renewing),
            "error" => Ok(Self::Error),
            "expired" => Ok(Self::Expired),
            _ => Err(CertificateCatalogError::InvalidStoredData(
                "certificate_status",
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct CertificateState {
    pub(crate) route_id: Uuid,
    pub(crate) status: CertificateStatus,
    pub(crate) issuer: Option<String>,
    pub(crate) not_before: Option<i64>,
    pub(crate) not_after: Option<i64>,
    pub(crate) next_renewal: Option<i64>,
    pub(crate) last_attempt: Option<i64>,
    pub(crate) last_success: Option<i64>,
    pub(crate) failure_count: u32,
    pub(crate) last_error_code: Option<String>,
    pub(crate) last_error_message: Option<String>,
}

impl CertificateState {
    pub(crate) fn renewal_due(&self, now: i64) -> bool {
        matches!(
            self.status,
            CertificateStatus::Active | CertificateStatus::Error
        ) && self
            .next_renewal
            .is_some_and(|next_renewal| now >= next_renewal)
    }

    pub(crate) fn expired_at(&self, now: i64) -> bool {
        self.not_after.is_some_and(|not_after| now >= not_after)
    }
}

#[derive(Debug)]
pub(crate) enum CertificateCatalogError {
    InvalidDirectoryUrl,
    DirectoryUrlDoesNotMatchEnvironment,
    InvalidContactEmail,
    TermsNotAccepted,
    InvalidRenewalWindow,
    InvalidRedirectPolicy,
    InvalidCertificateValidity,
    InvalidIssuer,
    InvalidErrorCode,
    InvalidErrorMessage,
    InvalidStoredData(&'static str),
    Io(std::io::Error),
    Database(rusqlite::Error),
}

impl CertificateCatalogError {
    /// 返回可供 API 和审计日志稳定使用的错误码。
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::InvalidDirectoryUrl => "invalid_directory_url",
            Self::DirectoryUrlDoesNotMatchEnvironment => "directory_url_does_not_match_environment",
            Self::InvalidContactEmail => "invalid_contact_email",
            Self::TermsNotAccepted => "terms_not_accepted",
            Self::InvalidRenewalWindow => "invalid_renewal_window",
            Self::InvalidRedirectPolicy => "invalid_redirect_policy",
            Self::InvalidCertificateValidity => "invalid_certificate_validity",
            Self::InvalidIssuer => "invalid_issuer",
            Self::InvalidErrorCode => "invalid_error_code",
            Self::InvalidErrorMessage => "invalid_error_message",
            Self::InvalidStoredData(_) => "invalid_stored_data",
            Self::Io(_) => "certificate_io_error",
            Self::Database(_) => "certificate_database_error",
        }
    }
}

impl fmt::Display for CertificateCatalogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Self::InvalidStoredData(field) = self {
            return write!(
                formatter,
                "certificate database contains invalid data in {field}"
            );
        }
        let message = match self {
            Self::InvalidDirectoryUrl => "ACME directory URL is invalid",
            Self::DirectoryUrlDoesNotMatchEnvironment => {
                "ACME directory URL does not match the selected environment"
            }
            Self::InvalidContactEmail => "ACME contact email is invalid",
            Self::TermsNotAccepted => "ACME terms must be accepted before enabling ACME",
            Self::InvalidRenewalWindow => "certificate renewal window is invalid",
            Self::InvalidRedirectPolicy => "HTTP to HTTPS redirect requires ACME TLS mode",
            Self::InvalidCertificateValidity => "certificate validity period is invalid",
            Self::InvalidIssuer => "certificate issuer is invalid",
            Self::InvalidErrorCode => "certificate error code is invalid",
            Self::InvalidErrorMessage => "certificate error message is invalid",
            Self::InvalidStoredData(_) => unreachable!("handled before message selection"),
            Self::Io(_) => "certificate storage operation failed",
            Self::Database(_) => "certificate database operation failed",
        };
        formatter.write_str(message)
    }
}

impl Error for CertificateCatalogError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Database(error) => Some(error),
            _ => None,
        }
    }
}

impl From<rusqlite::Error> for CertificateCatalogError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Database(error)
    }
}

impl From<std::io::Error> for CertificateCatalogError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

pub(crate) struct CertificateCatalog {
    database: Connection,
}

impl CertificateCatalog {
    #[allow(dead_code)]
    pub(crate) fn open(data_dir: Option<&Path>) -> Result<Self, CertificateCatalogError> {
        let database = Database::open(data_dir)
            .map_err(|error| CertificateCatalogError::Io(std::io::Error::other(error)))?;
        Self::open_with_database(&database)
    }

    pub(crate) fn open_with_database(database: &Database) -> Result<Self, CertificateCatalogError> {
        let database = database.connect()?;
        database.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS acme_config (
                singleton_id INTEGER PRIMARY KEY NOT NULL CHECK (singleton_id = 1),
                enabled INTEGER NOT NULL,
                environment TEXT NOT NULL,
                directory_url TEXT NOT NULL,
                contact_email TEXT NOT NULL,
                terms_accepted INTEGER NOT NULL,
                renew_before_days INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            INSERT OR IGNORE INTO acme_config (
                singleton_id, enabled, environment, directory_url, contact_email,
                terms_accepted, renew_before_days, updated_at
            ) VALUES (
                1, 0, 'production',
                'https://acme-v02.api.letsencrypt.org/directory', '', 0, 30, 0
            );

            CREATE TABLE IF NOT EXISTS http_route_tls_policies (
                route_id TEXT PRIMARY KEY NOT NULL,
                mode TEXT NOT NULL,
                redirect_http_to_https INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS certificate_states (
                route_id TEXT PRIMARY KEY NOT NULL,
                status TEXT NOT NULL,
                issuer TEXT,
                not_before INTEGER,
                not_after INTEGER,
                next_renewal INTEGER,
                last_attempt INTEGER,
                last_success INTEGER,
                failure_count INTEGER NOT NULL DEFAULT 0,
                last_error_code TEXT,
                last_error_message TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_certificate_states_renewal
                ON certificate_states(status, next_renewal);
            ",
        )?;
        Ok(Self { database })
    }

    pub(crate) fn get_acme_config(&self) -> Result<AcmeConfig, CertificateCatalogError> {
        let stored = self.database.query_row(
            "SELECT enabled, environment, directory_url, contact_email, terms_accepted, renew_before_days, updated_at FROM acme_config WHERE singleton_id = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            },
        )?;
        let renew_before_days = u8::try_from(stored.5)
            .map_err(|_| CertificateCatalogError::InvalidStoredData("renew_before_days"))?;
        if !(MIN_RENEW_BEFORE_DAYS..=MAX_RENEW_BEFORE_DAYS).contains(&renew_before_days) {
            return Err(CertificateCatalogError::InvalidStoredData(
                "renew_before_days",
            ));
        }
        Ok(AcmeConfig {
            enabled: stored.0 != 0,
            environment: AcmeEnvironment::parse(&stored.1)?,
            directory_url: stored.2,
            contact_email: stored.3,
            terms_accepted: stored.4 != 0,
            renew_before_days,
            updated_at: stored.6,
        })
    }

    pub(crate) fn update_acme_config(
        &mut self,
        request: UpdateAcmeConfig,
        now: i64,
    ) -> Result<AcmeConfig, CertificateCatalogError> {
        validate_acme_config(&request)?;
        let directory_url = request.directory_url.trim().to_owned();
        let contact_email = request.contact_email.trim().to_ascii_lowercase();
        self.database.execute(
            "UPDATE acme_config SET enabled = ?1, environment = ?2, directory_url = ?3, contact_email = ?4, terms_accepted = ?5, renew_before_days = ?6, updated_at = ?7 WHERE singleton_id = 1",
            params![
                request.enabled,
                request.environment.as_str(),
                directory_url,
                contact_email,
                request.terms_accepted,
                request.renew_before_days,
                now,
            ],
        )?;
        self.get_acme_config()
    }

    pub(crate) fn get_route_tls(
        &self,
        route_id: Uuid,
    ) -> Result<Option<RouteTlsPolicy>, CertificateCatalogError> {
        let stored = self
            .database
            .query_row(
                "SELECT mode, redirect_http_to_https, updated_at FROM http_route_tls_policies WHERE route_id = ?1",
                [route_id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()?;
        stored
            .map(|(mode, redirect_http_to_https, updated_at)| {
                Ok(RouteTlsPolicy {
                    route_id,
                    mode: RouteTlsMode::parse(&mode)?,
                    redirect_http_to_https: redirect_http_to_https != 0,
                    updated_at,
                })
            })
            .transpose()
    }

    pub(crate) fn set_route_tls(
        &mut self,
        route_id: Uuid,
        request: UpdateRouteTlsPolicy,
        now: i64,
    ) -> Result<RouteTlsPolicy, CertificateCatalogError> {
        if request.mode == RouteTlsMode::Disabled && request.redirect_http_to_https {
            return Err(CertificateCatalogError::InvalidRedirectPolicy);
        }
        self.database.execute(
            "INSERT INTO http_route_tls_policies (route_id, mode, redirect_http_to_https, updated_at) VALUES (?1, ?2, ?3, ?4) ON CONFLICT(route_id) DO UPDATE SET mode = excluded.mode, redirect_http_to_https = excluded.redirect_http_to_https, updated_at = excluded.updated_at",
            params![
                route_id.to_string(),
                request.mode.as_str(),
                request.redirect_http_to_https,
                now,
            ],
        )?;
        Ok(RouteTlsPolicy {
            route_id,
            mode: request.mode,
            redirect_http_to_https: request.redirect_http_to_https,
            updated_at: now,
        })
    }

    pub(crate) fn delete_route_tls(
        &mut self,
        route_id: Uuid,
    ) -> Result<bool, CertificateCatalogError> {
        Ok(self.database.execute(
            "DELETE FROM http_route_tls_policies WHERE route_id = ?1",
            [route_id.to_string()],
        )? != 0)
    }

    pub(crate) fn get_certificate_state(
        &self,
        route_id: Uuid,
    ) -> Result<Option<CertificateState>, CertificateCatalogError> {
        let mut statement = self.database.prepare(
            "SELECT route_id, status, issuer, not_before, not_after, next_renewal, last_attempt, last_success, failure_count, last_error_code, last_error_message FROM certificate_states WHERE route_id = ?1",
        )?;
        let stored = statement
            .query_row([route_id.to_string()], read_certificate_state_row)
            .optional()?;
        stored.map(parse_certificate_state).transpose()
    }

    pub(crate) fn list_certificate_states(
        &self,
    ) -> Result<Vec<CertificateState>, CertificateCatalogError> {
        let mut statement = self.database.prepare(
            "SELECT route_id, status, issuer, not_before, not_after, next_renewal, last_attempt, last_success, failure_count, last_error_code, last_error_message FROM certificate_states ORDER BY route_id",
        )?;
        let rows = statement.query_map([], read_certificate_state_row)?;
        let mut states = Vec::new();
        for row in rows {
            states.push(parse_certificate_state(row?)?);
        }
        Ok(states)
    }

    /// 以比较并交换方式推进状态。`expected_status = None` 只在记录尚不存在时插入。
    pub(crate) fn update_certificate_status(
        &mut self,
        route_id: Uuid,
        expected_status: Option<CertificateStatus>,
        new_status: CertificateStatus,
        attempted_at: Option<i64>,
    ) -> Result<bool, CertificateCatalogError> {
        let changed = match expected_status {
            Some(expected_status) => self.database.execute(
                "UPDATE certificate_states SET status = ?1, last_attempt = COALESCE(?2, last_attempt) WHERE route_id = ?3 AND status = ?4",
                params![
                    new_status.as_str(),
                    attempted_at,
                    route_id.to_string(),
                    expected_status.as_str(),
                ],
            )?,
            None => self.database.execute(
                "INSERT OR IGNORE INTO certificate_states (route_id, status, last_attempt, failure_count) VALUES (?1, ?2, ?3, 0)",
                params![route_id.to_string(), new_status.as_str(), attempted_at],
            )?,
        };
        Ok(changed != 0)
    }

    /// 原子写入签发或续期成功结果，并清空此前错误和失败计数。
    pub(crate) fn record_certificate_success(
        &mut self,
        route_id: Uuid,
        issuer: &str,
        not_before: i64,
        not_after: i64,
        completed_at: i64,
    ) -> Result<CertificateState, CertificateCatalogError> {
        let issuer = issuer.trim();
        if issuer.is_empty() || issuer.len() > 255 {
            return Err(CertificateCatalogError::InvalidIssuer);
        }
        if not_before >= not_after || completed_at >= not_after {
            return Err(CertificateCatalogError::InvalidCertificateValidity);
        }
        let renew_before_days = i64::from(self.get_acme_config()?.renew_before_days);
        let next_renewal = not_after
            .saturating_sub(renew_before_days * SECONDS_PER_DAY)
            .max(not_before);
        self.database.execute(
            "INSERT INTO certificate_states (route_id, status, issuer, not_before, not_after, next_renewal, last_attempt, last_success, failure_count, last_error_code, last_error_message) VALUES (?1, 'active', ?2, ?3, ?4, ?5, ?6, ?6, 0, NULL, NULL) ON CONFLICT(route_id) DO UPDATE SET status = 'active', issuer = excluded.issuer, not_before = excluded.not_before, not_after = excluded.not_after, next_renewal = excluded.next_renewal, last_attempt = excluded.last_attempt, last_success = excluded.last_success, failure_count = 0, last_error_code = NULL, last_error_message = NULL",
            params![
                route_id.to_string(),
                issuer,
                not_before,
                not_after,
                next_renewal,
                completed_at,
            ],
        )?;
        self.get_certificate_state(route_id)?
            .ok_or(CertificateCatalogError::InvalidStoredData(
                "certificate_state",
            ))
    }

    /// 原子累计失败次数并保留现有证书元数据，便于续期失败后继续提供旧证书。
    pub(crate) fn record_certificate_failure(
        &mut self,
        route_id: Uuid,
        error_code: &str,
        error_message: &str,
        attempted_at: i64,
    ) -> Result<CertificateState, CertificateCatalogError> {
        let error_code = error_code.trim();
        let error_message = error_message.trim();
        if error_code.is_empty()
            || error_code.len() > 80
            || !error_code
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        {
            return Err(CertificateCatalogError::InvalidErrorCode);
        }
        if error_message.is_empty() || error_message.len() > 2_000 {
            return Err(CertificateCatalogError::InvalidErrorMessage);
        }
        self.database.execute(
            "INSERT INTO certificate_states (route_id, status, last_attempt, failure_count, last_error_code, last_error_message) VALUES (?1, 'error', ?2, 1, ?3, ?4) ON CONFLICT(route_id) DO UPDATE SET status = 'error', last_attempt = excluded.last_attempt, failure_count = certificate_states.failure_count + 1, last_error_code = excluded.last_error_code, last_error_message = excluded.last_error_message",
            params![route_id.to_string(), attempted_at, error_code, error_message],
        )?;
        self.get_certificate_state(route_id)?
            .ok_or(CertificateCatalogError::InvalidStoredData(
                "certificate_state",
            ))
    }

    pub(crate) fn delete_certificate_state(
        &mut self,
        route_id: Uuid,
    ) -> Result<bool, CertificateCatalogError> {
        Ok(self.database.execute(
            "DELETE FROM certificate_states WHERE route_id = ?1",
            [route_id.to_string()],
        )? != 0)
    }
}

type StoredCertificateState = (
    String,
    String,
    Option<String>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    i64,
    Option<String>,
    Option<String>,
);

fn read_certificate_state_row(row: &Row<'_>) -> rusqlite::Result<StoredCertificateState> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
    ))
}

fn parse_certificate_state(
    stored: StoredCertificateState,
) -> Result<CertificateState, CertificateCatalogError> {
    let route_id = Uuid::parse_str(&stored.0)
        .map_err(|_| CertificateCatalogError::InvalidStoredData("route_id"))?;
    let failure_count = u32::try_from(stored.8)
        .map_err(|_| CertificateCatalogError::InvalidStoredData("failure_count"))?;
    Ok(CertificateState {
        route_id,
        status: CertificateStatus::parse(&stored.1)?,
        issuer: stored.2,
        not_before: stored.3,
        not_after: stored.4,
        next_renewal: stored.5,
        last_attempt: stored.6,
        last_success: stored.7,
        failure_count,
        last_error_code: stored.9,
        last_error_message: stored.10,
    })
}

fn validate_acme_config(request: &UpdateAcmeConfig) -> Result<(), CertificateCatalogError> {
    let directory_url = request.directory_url.trim();
    validate_https_url(directory_url)?;
    match request.environment {
        AcmeEnvironment::Production if directory_url != LETS_ENCRYPT_PRODUCTION_DIRECTORY => {
            return Err(CertificateCatalogError::DirectoryUrlDoesNotMatchEnvironment);
        }
        AcmeEnvironment::Staging if directory_url != LETS_ENCRYPT_STAGING_DIRECTORY => {
            return Err(CertificateCatalogError::DirectoryUrlDoesNotMatchEnvironment);
        }
        _ => {}
    }

    let contact_email = request.contact_email.trim();
    if (!contact_email.is_empty() && !valid_email(contact_email))
        || (request.enabled && contact_email.is_empty())
    {
        return Err(CertificateCatalogError::InvalidContactEmail);
    }
    if request.enabled && !request.terms_accepted {
        return Err(CertificateCatalogError::TermsNotAccepted);
    }
    if !(MIN_RENEW_BEFORE_DAYS..=MAX_RENEW_BEFORE_DAYS).contains(&request.renew_before_days) {
        return Err(CertificateCatalogError::InvalidRenewalWindow);
    }
    Ok(())
}

fn validate_https_url(value: &str) -> Result<(), CertificateCatalogError> {
    let uri = value
        .parse::<Uri>()
        .map_err(|_| CertificateCatalogError::InvalidDirectoryUrl)?;
    if uri.scheme_str() != Some("https")
        || uri.authority().is_none()
        || uri.host().is_none_or(|host| host.is_empty())
        || uri.path().is_empty()
        || uri.path() == "/"
        || uri.query().is_some()
    {
        return Err(CertificateCatalogError::InvalidDirectoryUrl);
    }
    Ok(())
}

fn valid_email(value: &str) -> bool {
    if value.len() > 254
        || !value.is_ascii()
        || value.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return false;
    }
    let Some((local, domain)) = value.rsplit_once('@') else {
        return false;
    };
    !local.is_empty()
        && local.len() <= 64
        && !local.starts_with('.')
        && !local.ends_with('.')
        && !local.contains("..")
        && local.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'%' | b'+' | b'-')
        })
        && domain.contains('.')
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::{
        AcmeEnvironment, CertificateCatalog, CertificateCatalogError, CertificateStatus,
        RouteTlsMode, UpdateAcmeConfig, UpdateRouteTlsPolicy, LETS_ENCRYPT_PRODUCTION_DIRECTORY,
        LETS_ENCRYPT_STAGING_DIRECTORY,
    };
    use std::fs;
    use uuid::Uuid;

    fn enabled_config(environment: AcmeEnvironment, directory_url: &str) -> UpdateAcmeConfig {
        UpdateAcmeConfig {
            enabled: true,
            environment,
            directory_url: directory_url.to_owned(),
            contact_email: "Admin@Example.com".to_owned(),
            terms_accepted: true,
            renew_before_days: 30,
        }
    }

    #[test]
    fn config_and_route_policy_persist_in_existing_database() {
        let root = std::env::temp_dir().join(format!("linklake-cert-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).expect("test directory should be created");
        let route_id = Uuid::new_v4();
        {
            let mut catalog = CertificateCatalog::open(Some(&root)).expect("catalog should open");
            let config = catalog
                .update_acme_config(
                    enabled_config(AcmeEnvironment::Staging, LETS_ENCRYPT_STAGING_DIRECTORY),
                    100,
                )
                .expect("config should update");
            assert_eq!(config.contact_email, "admin@example.com");
            catalog
                .set_route_tls(
                    route_id,
                    UpdateRouteTlsPolicy {
                        mode: RouteTlsMode::Acme,
                        redirect_http_to_https: true,
                    },
                    101,
                )
                .expect("route policy should update");
        }
        let catalog = CertificateCatalog::open(Some(&root)).expect("catalog should reopen");
        assert_eq!(
            catalog
                .get_acme_config()
                .expect("config should persist")
                .environment,
            AcmeEnvironment::Staging
        );
        assert_eq!(
            catalog
                .get_route_tls(route_id)
                .expect("route policy should load")
                .expect("route policy should exist")
                .mode,
            RouteTlsMode::Acme
        );
        drop(catalog);
        fs::remove_dir_all(root).expect("test directory should be removed");
    }

    #[test]
    fn acme_validation_has_stable_errors() {
        let mut catalog = CertificateCatalog::open(None).expect("catalog should open");
        let mut request =
            enabled_config(AcmeEnvironment::Production, LETS_ENCRYPT_STAGING_DIRECTORY);
        let error = catalog
            .update_acme_config(request.clone(), 1)
            .expect_err("mismatched preset should fail");
        assert_eq!(error.code(), "directory_url_does_not_match_environment");

        request.environment = AcmeEnvironment::Custom;
        request.directory_url = "http://acme.example.com/directory".to_owned();
        assert!(matches!(
            catalog.update_acme_config(request.clone(), 1),
            Err(CertificateCatalogError::InvalidDirectoryUrl)
        ));
        request.directory_url = "https://acme.example.com/directory".to_owned();
        request.contact_email = "not-an-email".to_owned();
        assert!(matches!(
            catalog.update_acme_config(request.clone(), 1),
            Err(CertificateCatalogError::InvalidContactEmail)
        ));
        request.contact_email = "admin@example.com".to_owned();
        request.terms_accepted = false;
        assert!(matches!(
            catalog.update_acme_config(request.clone(), 1),
            Err(CertificateCatalogError::TermsNotAccepted)
        ));
        request.terms_accepted = true;
        request.renew_before_days = 6;
        assert!(matches!(
            catalog.update_acme_config(request, 1),
            Err(CertificateCatalogError::InvalidRenewalWindow)
        ));

        for boundary in [7, 60] {
            let mut request = enabled_config(
                AcmeEnvironment::Production,
                LETS_ENCRYPT_PRODUCTION_DIRECTORY,
            );
            request.renew_before_days = boundary;
            assert_eq!(
                catalog
                    .update_acme_config(request, 2)
                    .expect("renewal boundary should be accepted")
                    .renew_before_days,
                boundary
            );
        }

        assert!(matches!(
            catalog.set_route_tls(
                Uuid::new_v4(),
                UpdateRouteTlsPolicy {
                    mode: RouteTlsMode::Disabled,
                    redirect_http_to_https: true,
                },
                1,
            ),
            Err(CertificateCatalogError::InvalidRedirectPolicy)
        ));

        let route_id = Uuid::new_v4();
        catalog
            .set_route_tls(
                route_id,
                UpdateRouteTlsPolicy {
                    mode: RouteTlsMode::Acme,
                    redirect_http_to_https: false,
                },
                1,
            )
            .expect("route TLS policy should insert");
        assert!(catalog
            .delete_route_tls(route_id)
            .expect("route TLS policy should delete"));
    }

    #[test]
    fn status_updates_use_compare_and_swap_and_failures_accumulate() {
        let route_id = Uuid::new_v4();
        let mut catalog = CertificateCatalog::open(None).expect("catalog should open");
        assert!(catalog
            .update_certificate_status(route_id, None, CertificateStatus::Pending, None)
            .expect("initial state should insert"));
        assert!(!catalog
            .update_certificate_status(route_id, None, CertificateStatus::Issuing, Some(10))
            .expect("second initial insert should not replace state"));
        assert!(!catalog
            .update_certificate_status(
                route_id,
                Some(CertificateStatus::Active),
                CertificateStatus::Renewing,
                Some(10),
            )
            .expect("wrong expected state should not update"));
        assert!(catalog
            .update_certificate_status(
                route_id,
                Some(CertificateStatus::Pending),
                CertificateStatus::Issuing,
                Some(10),
            )
            .expect("matching expected state should update"));

        let first = catalog
            .record_certificate_failure(route_id, "acme_timeout", "ACME request timed out", 11)
            .expect("failure should record");
        let second = catalog
            .record_certificate_failure(route_id, "acme_timeout", "ACME request timed out", 12)
            .expect("failure should accumulate");
        assert_eq!(first.failure_count, 1);
        assert_eq!(second.failure_count, 2);
        assert_eq!(second.status, CertificateStatus::Error);
        assert_eq!(catalog.list_certificate_states().unwrap().len(), 1);
        assert!(catalog.delete_certificate_state(route_id).unwrap());
        assert!(catalog.get_certificate_state(route_id).unwrap().is_none());
    }

    #[test]
    fn success_calculates_inclusive_renewal_boundary() {
        let route_id = Uuid::new_v4();
        let mut catalog = CertificateCatalog::open(None).expect("catalog should open");
        catalog
            .update_acme_config(
                enabled_config(
                    AcmeEnvironment::Production,
                    LETS_ENCRYPT_PRODUCTION_DIRECTORY,
                ),
                1,
            )
            .expect("config should update");
        let not_before = 1_000_000;
        let not_after = not_before + 90 * 86_400;
        let completed_at = not_before + 10;
        let state = catalog
            .record_certificate_success(
                route_id,
                "Let's Encrypt",
                not_before,
                not_after,
                completed_at,
            )
            .expect("success should record");
        let renewal = not_after - 30 * 86_400;
        assert_eq!(state.next_renewal, Some(renewal));
        assert!(!state.renewal_due(renewal - 1));
        assert!(state.renewal_due(renewal));
        assert!(!state.expired_at(not_after - 1));
        assert!(state.expired_at(not_after));
        assert_eq!(state.failure_count, 0);
        assert!(state.last_error_code.is_none());
    }
}
