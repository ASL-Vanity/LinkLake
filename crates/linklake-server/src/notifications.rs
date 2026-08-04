//! 告警 Webhook 与 SMTP 通知发送器。

use crate::alerting::{
    AlertNotification, AlertSeverity, NotificationChannel, NotificationDelivery,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use linklake_core::BoxedIo;
use serde::Serialize;
use std::{env, fmt, net::IpAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};
use tokio_rustls::{
    rustls::{pki_types::ServerName, ClientConfig, RootCertStore},
    TlsConnector,
};

const NOTIFICATION_TIMEOUT: Duration = Duration::from_secs(15);
const WEBHOOK_URL_MAX_BYTES: usize = 2_048;
const SMTP_HOST_MAX_BYTES: usize = 253;
const SMTP_MAILBOX_MAX_BYTES: usize = 254;
const SMTP_RECIPIENTS_MAX: usize = 64;
const SMTP_SUBJECT_MAX_CHARS: usize = 180;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SmtpStage {
    Greeting,
    Ehlo,
    StartTls,
    Auth,
    MailFrom,
    Recipient,
    Data,
    Message,
    Quit,
}

impl SmtpStage {
    fn as_str(self) -> &'static str {
        match self {
            Self::Greeting => "greeting",
            Self::Ehlo => "ehlo",
            Self::StartTls => "starttls",
            Self::Auth => "auth",
            Self::MailFrom => "mail_from",
            Self::Recipient => "recipient",
            Self::Data => "data",
            Self::Message => "message",
            Self::Quit => "quit",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum NotificationFailureCode {
    WebhookInvalidConfiguration,
    WebhookTimeout,
    WebhookTransport,
    WebhookHttpStatus(u16),
    SmtpInvalidConfiguration,
    SmtpTimeout,
    SmtpConnect,
    SmtpTls,
    SmtpIo(SmtpStage),
    SmtpProtocol(SmtpStage),
    SmtpStatus(SmtpStage, u16),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NotificationDeliveryError {
    code: NotificationFailureCode,
}

impl NotificationDeliveryError {
    fn new(code: NotificationFailureCode) -> Self {
        Self { code }
    }

    pub(crate) fn safe_code(&self) -> String {
        match self.code {
            NotificationFailureCode::WebhookInvalidConfiguration => {
                "webhook_invalid_configuration".to_owned()
            }
            NotificationFailureCode::WebhookTimeout => "webhook_timeout".to_owned(),
            NotificationFailureCode::WebhookTransport => "webhook_transport".to_owned(),
            NotificationFailureCode::WebhookHttpStatus(status) => {
                format!("webhook_http_status_{status}")
            }
            NotificationFailureCode::SmtpInvalidConfiguration => {
                "smtp_invalid_configuration".to_owned()
            }
            NotificationFailureCode::SmtpTimeout => "smtp_timeout".to_owned(),
            NotificationFailureCode::SmtpConnect => "smtp_connect".to_owned(),
            NotificationFailureCode::SmtpTls => "smtp_tls".to_owned(),
            NotificationFailureCode::SmtpIo(stage) => {
                format!("smtp_io_{}", stage.as_str())
            }
            NotificationFailureCode::SmtpProtocol(stage) => {
                format!("smtp_protocol_{}", stage.as_str())
            }
            NotificationFailureCode::SmtpStatus(stage, status) => {
                format!("smtp_status_{}_{status}", stage.as_str())
            }
        }
    }
}

impl fmt::Display for NotificationDeliveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.safe_code())
    }
}

impl std::error::Error for NotificationDeliveryError {}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct NotificationChannelView {
    pub(crate) webhook_configured: bool,
    pub(crate) smtp_configured: bool,
    pub(crate) smtp_host: Option<String>,
    pub(crate) smtp_port: Option<u16>,
    pub(crate) smtp_tls: Option<String>,
    pub(crate) smtp_from: Option<String>,
    pub(crate) smtp_recipients: Vec<String>,
}

#[derive(Clone)]
struct NotificationConfig {
    webhook_url: Option<String>,
    allow_loopback_http: bool,
    smtp: Option<SmtpConfig>,
}

#[derive(Clone)]
struct SmtpConfig {
    host: String,
    port: u16,
    tls: SmtpTls,
    username: Option<String>,
    password: Option<String>,
    from: String,
    recipients: Vec<String>,
    allow_insecure: bool,
}

#[derive(Clone, Copy)]
enum SmtpTls {
    None,
    StartTls,
    Implicit,
}

impl SmtpTls {
    fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::StartTls => "starttls",
            Self::Implicit => "implicit",
        }
    }
}

impl SmtpConfig {
    fn validate(&self) -> Result<(), NotificationDeliveryError> {
        if !valid_smtp_host(&self.host)
            || self.port == 0
            || !valid_mailbox(&self.from)
            || self.recipients.is_empty()
            || self.recipients.len() > SMTP_RECIPIENTS_MAX
            || self
                .recipients
                .iter()
                .any(|recipient| !valid_mailbox(recipient))
            || self.username.as_deref().is_some_and(has_header_injection)
            || self.password.is_some() != self.username.is_some()
            || (matches!(self.tls, SmtpTls::None)
                && (!self.allow_insecure || !smtp_host_is_loopback(&self.host)))
        {
            return Err(NotificationDeliveryError::new(
                NotificationFailureCode::SmtpInvalidConfiguration,
            ));
        }
        Ok(())
    }
}

fn has_header_injection(value: &str) -> bool {
    value.chars().any(char::is_control)
}

fn valid_smtp_host(host: &str) -> bool {
    (!host.is_empty()
        && host.len() <= SMTP_HOST_MAX_BYTES
        && !has_header_injection(host)
        && !host.chars().any(char::is_whitespace)
        && host.parse::<IpAddr>().is_ok())
        || (!host.is_empty()
            && host.len() <= SMTP_HOST_MAX_BYTES
            && host.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .chars()
                        .all(|value| value.is_ascii_alphanumeric() || value == '-')
            }))
}

fn smtp_host_is_loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn valid_mailbox(mailbox: &str) -> bool {
    if mailbox.is_empty()
        || mailbox.len() > SMTP_MAILBOX_MAX_BYTES
        || mailbox.trim() != mailbox
        || has_header_injection(mailbox)
        || mailbox.chars().any(char::is_whitespace)
        || mailbox.contains(['<', '>', ',', ';'])
    {
        return false;
    }
    let mut parts = mailbox.split('@');
    let Some(local) = parts.next() else {
        return false;
    };
    let Some(domain) = parts.next() else {
        return false;
    };
    !local.is_empty()
        && local.len() <= 64
        && !local.starts_with('.')
        && !local.ends_with('.')
        && !local.contains("..")
        && local.chars().all(|value| {
            value.is_ascii_alphanumeric()
                || matches!(
                    value,
                    '!' | '#'
                        | '$'
                        | '%'
                        | '&'
                        | '\''
                        | '*'
                        | '+'
                        | '-'
                        | '/'
                        | '='
                        | '?'
                        | '^'
                        | '_'
                        | '`'
                        | '{'
                        | '|'
                        | '}'
                        | '~'
                        | '.'
                )
        })
        && valid_smtp_host(domain)
}

fn validate_webhook_url(
    url: &str,
    allow_loopback_http: bool,
) -> Result<reqwest::Url, NotificationDeliveryError> {
    let parsed = reqwest::Url::parse(url).map_err(|_| {
        NotificationDeliveryError::new(NotificationFailureCode::WebhookInvalidConfiguration)
    })?;
    let loopback_http = parsed.scheme() == "http"
        && allow_loopback_http
        && parsed.host_str().is_some_and(|host| {
            host.eq_ignore_ascii_case("localhost")
                || host
                    .parse::<IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
        });
    if url.len() > WEBHOOK_URL_MAX_BYTES
        || (!parsed.username().is_empty() || parsed.password().is_some())
        || parsed.host_str().is_none()
        || !(parsed.scheme() == "https" || loopback_http)
    {
        return Err(NotificationDeliveryError::new(
            NotificationFailureCode::WebhookInvalidConfiguration,
        ));
    }
    Ok(parsed)
}

fn safe_header_value(value: &str, max_chars: usize) -> String {
    value
        .chars()
        .map(|value| if value.is_control() { ' ' } else { value })
        .take(max_chars)
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn valid_idempotency_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .chars()
            .all(|value| value.is_ascii_alphanumeric() || matches!(value, '-' | '_'))
}

impl NotificationConfig {
    fn from_env() -> Self {
        let webhook_url = nonempty_env("LINKLAKE_ALERT_WEBHOOK_URL");
        let allow_loopback_http = true_env("LINKLAKE_ALERT_ALLOW_LOOPBACK_HTTP");
        let smtp = nonempty_env("LINKLAKE_SMTP_HOST").and_then(|host| {
            let from = nonempty_env("LINKLAKE_SMTP_FROM")?;
            let recipients = nonempty_env("LINKLAKE_SMTP_TO")?
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>();
            if recipients.is_empty() {
                return None;
            }
            let tls = match env::var("LINKLAKE_SMTP_TLS")
                .unwrap_or_else(|_| "starttls".to_owned())
                .trim()
                .to_ascii_lowercase()
                .as_str()
            {
                "none" => SmtpTls::None,
                "implicit" | "smtps" => SmtpTls::Implicit,
                _ => SmtpTls::StartTls,
            };
            let default_port = match tls {
                SmtpTls::Implicit => 465,
                _ => 587,
            };
            let port = env::var("LINKLAKE_SMTP_PORT")
                .ok()
                .and_then(|value| value.parse::<u16>().ok())
                .unwrap_or(default_port);
            Some(SmtpConfig {
                host,
                port,
                tls,
                username: nonempty_env("LINKLAKE_SMTP_USERNAME"),
                password: secret_env_or_file(
                    "LINKLAKE_SMTP_PASSWORD",
                    "LINKLAKE_SMTP_PASSWORD_FILE",
                ),
                from,
                recipients,
                allow_insecure: true_env("LINKLAKE_SMTP_ALLOW_INSECURE"),
            })
        });
        Self {
            webhook_url,
            allow_loopback_http,
            smtp,
        }
    }

    fn view(&self) -> NotificationChannelView {
        let webhook_configured = self
            .webhook_url
            .as_deref()
            .is_some_and(|url| validate_webhook_url(url, self.allow_loopback_http).is_ok());
        let smtp = self.smtp.as_ref().filter(|smtp| smtp.validate().is_ok());
        NotificationChannelView {
            webhook_configured,
            smtp_configured: smtp.is_some(),
            smtp_host: smtp.map(|smtp| smtp.host.clone()),
            smtp_port: smtp.map(|smtp| smtp.port),
            smtp_tls: smtp.map(|smtp| smtp.tls.as_str().to_owned()),
            smtp_from: smtp.map(|smtp| smtp.from.clone()),
            smtp_recipients: smtp.map(|smtp| smtp.recipients.clone()).unwrap_or_default(),
        }
    }
}

fn nonempty_env(name: &str) -> Option<String> {
    env::var(name).ok().and_then(|value| {
        let value = value.trim();
        (!value.is_empty()).then(|| value.to_owned())
    })
}

fn secret_env_or_file(value_name: &str, file_name: &str) -> Option<String> {
    if let Some(value) = nonempty_env(value_name) {
        return Some(value);
    }
    let path = nonempty_env(file_name)?;
    let metadata = std::fs::metadata(&path).ok()?;
    if !metadata.is_file() || metadata.len() > 16 * 1024 {
        return None;
    }
    let value = std::fs::read_to_string(path).ok()?;
    let value = value.trim_end_matches(['\r', '\n']).to_owned();
    (!value.is_empty()).then_some(value)
}

fn true_env(name: &str) -> bool {
    env::var(name).ok().is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes"
        )
    })
}

pub(crate) fn channel_view() -> NotificationChannelView {
    NotificationConfig::from_env().view()
}

pub(crate) async fn deliver(
    delivery: &NotificationDelivery,
) -> Result<(), NotificationDeliveryError> {
    let config = NotificationConfig::from_env();
    deliver_with_config(delivery, &config).await
}

async fn deliver_with_config(
    delivery: &NotificationDelivery,
    config: &NotificationConfig,
) -> Result<(), NotificationDeliveryError> {
    match delivery.channel {
        NotificationChannel::Webhook => {
            let configured_url = config.webhook_url.as_deref().ok_or_else(|| {
                NotificationDeliveryError::new(NotificationFailureCode::WebhookInvalidConfiguration)
            })?;
            let url = validate_webhook_url(configured_url, config.allow_loopback_http)?;
            send_webhook(&url, &delivery.notification, &delivery.idempotency_key).await
        }
        NotificationChannel::Email => {
            let smtp = config.smtp.as_ref().ok_or_else(|| {
                NotificationDeliveryError::new(NotificationFailureCode::SmtpInvalidConfiguration)
            })?;
            send_email(smtp, &delivery.notification, &delivery.idempotency_key).await
        }
    }
}

async fn send_webhook(
    url: &reqwest::Url,
    notification: &AlertNotification,
    idempotency_key: &str,
) -> Result<(), NotificationDeliveryError> {
    #[derive(Serialize)]
    struct Payload<'a> {
        product: &'static str,
        event: &'a crate::alerting::AlertEvent,
        status: &'static str,
    }
    if !valid_idempotency_key(idempotency_key) {
        return Err(NotificationDeliveryError::new(
            NotificationFailureCode::WebhookInvalidConfiguration,
        ));
    }
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| NotificationDeliveryError::new(NotificationFailureCode::WebhookTransport))?;
    let response = timeout(
        NOTIFICATION_TIMEOUT,
        client
            .post(url.clone())
            .header("User-Agent", "LinkLake-Alert/1")
            .header(
                "Idempotency-Key",
                format!("linklake-alert-{idempotency_key}"),
            )
            .json(&Payload {
                product: linklake_core::PRODUCT_NAME,
                event: &notification.event,
                status: if notification.resolved {
                    "resolved"
                } else {
                    "firing"
                },
            })
            .send(),
    )
    .await
    .map_err(|_| NotificationDeliveryError::new(NotificationFailureCode::WebhookTimeout))?
    .map_err(|_| NotificationDeliveryError::new(NotificationFailureCode::WebhookTransport))?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(NotificationDeliveryError::new(
            NotificationFailureCode::WebhookHttpStatus(response.status().as_u16()),
        ))
    }
}

async fn send_email(
    config: &SmtpConfig,
    notification: &AlertNotification,
    idempotency_key: &str,
) -> Result<(), NotificationDeliveryError> {
    config.validate()?;
    if !valid_idempotency_key(idempotency_key) {
        return Err(NotificationDeliveryError::new(
            NotificationFailureCode::SmtpInvalidConfiguration,
        ));
    }
    timeout(
        NOTIFICATION_TIMEOUT,
        send_email_inner(config, notification, idempotency_key),
    )
    .await
    .map_err(|_| NotificationDeliveryError::new(NotificationFailureCode::SmtpTimeout))?
}

async fn send_email_inner(
    config: &SmtpConfig,
    notification: &AlertNotification,
    idempotency_key: &str,
) -> Result<(), NotificationDeliveryError> {
    let tcp = TcpStream::connect((config.host.as_str(), config.port))
        .await
        .map_err(|_| NotificationDeliveryError::new(NotificationFailureCode::SmtpConnect))?;
    let mut stream: BoxedIo = match config.tls {
        SmtpTls::Implicit => tls_stream(tcp, &config.host).await?,
        _ => Box::new(tcp),
    };
    expect_smtp(&mut stream, &[220], SmtpStage::Greeting).await?;
    smtp_command(&mut stream, "EHLO linklake", &[250], SmtpStage::Ehlo).await?;
    if matches!(config.tls, SmtpTls::StartTls) {
        smtp_command(&mut stream, "STARTTLS", &[220], SmtpStage::StartTls).await?;
        stream = tls_stream(stream, &config.host).await?;
        smtp_command(&mut stream, "EHLO linklake", &[250], SmtpStage::Ehlo).await?;
    }
    if let Some(username) = config.username.as_deref() {
        let password = config.password.as_deref().ok_or_else(|| {
            NotificationDeliveryError::new(NotificationFailureCode::SmtpInvalidConfiguration)
        })?;
        smtp_command(&mut stream, "AUTH LOGIN", &[334], SmtpStage::Auth).await?;
        smtp_command(
            &mut stream,
            &BASE64.encode(username),
            &[334],
            SmtpStage::Auth,
        )
        .await?;
        smtp_command(
            &mut stream,
            &BASE64.encode(password),
            &[235],
            SmtpStage::Auth,
        )
        .await?;
    }
    smtp_command(
        &mut stream,
        &format!("MAIL FROM:<{}>", config.from),
        &[250],
        SmtpStage::MailFrom,
    )
    .await?;
    for recipient in &config.recipients {
        smtp_command(
            &mut stream,
            &format!("RCPT TO:<{recipient}>",),
            &[250, 251],
            SmtpStage::Recipient,
        )
        .await?;
    }
    smtp_command(&mut stream, "DATA", &[354], SmtpStage::Data).await?;
    let status = if notification.resolved {
        "RESOLVED"
    } else {
        "FIRING"
    };
    let severity = match notification.event.severity {
        AlertSeverity::Info => "info",
        AlertSeverity::Warning => "warning",
        AlertSeverity::Critical => "critical",
    };
    let rule_name = safe_header_value(&notification.event.rule_name, SMTP_SUBJECT_MAX_CHARS);
    let rule_name = if rule_name.is_empty() {
        "Alert"
    } else {
        &rule_name
    };
    let subject = safe_header_value(
        &format!("[LinkLake][{status}][{severity}] {rule_name}"),
        SMTP_SUBJECT_MAX_CHARS,
    );
    let body = format!(
        "LinkLake alert {status}\n\nRule: {}\nSeverity: {severity}\nSubject: {}\nValue: {}\nThreshold: {}\nMessage: {}\nUpdated: {}\n",
        notification.event.rule_name,
        notification.event.subject,
        notification.event.value,
        notification.event.threshold,
        notification.event.message,
        notification.event.updated_unix_seconds,
    );
    let recipients = config.recipients.join(", ");
    let message = format!(
        "From: {}\r\nTo: {}\r\nSubject: {}\r\nMessage-ID: <linklake-alert-{idempotency_key}@linklake.invalid>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n{}",
        config.from,
        recipients,
        subject,
        dot_stuff(&body)
    );
    stream.write_all(message.as_bytes()).await.map_err(|_| {
        NotificationDeliveryError::new(NotificationFailureCode::SmtpIo(SmtpStage::Message))
    })?;
    stream.write_all(b"\r\n.\r\n").await.map_err(|_| {
        NotificationDeliveryError::new(NotificationFailureCode::SmtpIo(SmtpStage::Message))
    })?;
    stream.flush().await.map_err(|_| {
        NotificationDeliveryError::new(NotificationFailureCode::SmtpIo(SmtpStage::Message))
    })?;
    expect_smtp(&mut stream, &[250], SmtpStage::Message).await?;
    let _ = smtp_command(&mut stream, "QUIT", &[221], SmtpStage::Quit).await;
    Ok(())
}

fn dot_stuff(value: &str) -> String {
    value
        .replace("\r\n", "\n")
        .replace('\r', "\n")
        .split('\n')
        .map(|line| {
            if line.starts_with('.') {
                format!(".{line}")
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\r\n")
}

async fn tls_stream<S>(stream: S, host: &str) -> Result<BoxedIo, NotificationDeliveryError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let native = rustls_native_certs::load_native_certs();
    let mut roots = RootCertStore::empty();
    for certificate in native.certs {
        roots
            .add(certificate)
            .map_err(|_| NotificationDeliveryError::new(NotificationFailureCode::SmtpTls))?;
    }
    if roots.is_empty() {
        return Err(NotificationDeliveryError::new(
            NotificationFailureCode::SmtpTls,
        ));
    }
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_name = ServerName::try_from(host.to_owned())
        .map_err(|_| NotificationDeliveryError::new(NotificationFailureCode::SmtpTls))?;
    let stream = TlsConnector::from(Arc::new(config))
        .connect(server_name, stream)
        .await
        .map_err(|_| NotificationDeliveryError::new(NotificationFailureCode::SmtpTls))?;
    Ok(Box::new(stream))
}

async fn smtp_command(
    stream: &mut BoxedIo,
    command: &str,
    expected: &[u16],
    stage: SmtpStage,
) -> Result<(), NotificationDeliveryError> {
    stream
        .write_all(command.as_bytes())
        .await
        .map_err(|_| NotificationDeliveryError::new(NotificationFailureCode::SmtpIo(stage)))?;
    stream
        .write_all(b"\r\n")
        .await
        .map_err(|_| NotificationDeliveryError::new(NotificationFailureCode::SmtpIo(stage)))?;
    stream
        .flush()
        .await
        .map_err(|_| NotificationDeliveryError::new(NotificationFailureCode::SmtpIo(stage)))?;
    expect_smtp(stream, expected, stage).await.map(|_| ())
}

async fn expect_smtp(
    stream: &mut BoxedIo,
    expected: &[u16],
    stage: SmtpStage,
) -> Result<u16, NotificationDeliveryError> {
    let mut expected_code = None;
    loop {
        let line = read_smtp_line(stream, stage).await?;
        let code = line
            .as_bytes()
            .get(..3)
            .and_then(|value| std::str::from_utf8(value).ok())
            .and_then(|value| value.parse::<u16>().ok())
            .ok_or_else(|| {
                NotificationDeliveryError::new(NotificationFailureCode::SmtpProtocol(stage))
            })?;
        expected_code.get_or_insert(code);
        if line.as_bytes().get(3) == Some(&b' ') {
            if expected.contains(&code) {
                return Ok(code);
            }
            return Err(NotificationDeliveryError::new(
                NotificationFailureCode::SmtpStatus(stage, code),
            ));
        }
        if line.as_bytes().get(3) != Some(&b'-') || expected_code != Some(code) {
            return Err(NotificationDeliveryError::new(
                NotificationFailureCode::SmtpProtocol(stage),
            ));
        }
    }
}

async fn read_smtp_line(
    stream: &mut BoxedIo,
    stage: SmtpStage,
) -> Result<String, NotificationDeliveryError> {
    let mut bytes = Vec::with_capacity(128);
    loop {
        let byte = stream
            .read_u8()
            .await
            .map_err(|_| NotificationDeliveryError::new(NotificationFailureCode::SmtpIo(stage)))?;
        bytes.push(byte);
        if bytes.len() > 16 * 1024 {
            return Err(NotificationDeliveryError::new(
                NotificationFailureCode::SmtpProtocol(stage),
            ));
        }
        if bytes.ends_with(b"\r\n") {
            bytes.truncate(bytes.len() - 2);
            return String::from_utf8(bytes).map_err(|_| {
                NotificationDeliveryError::new(NotificationFailureCode::SmtpProtocol(stage))
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerting::AlertEvent;
    use std::sync::Mutex;
    use tokio::net::TcpListener;
    use uuid::Uuid;

    fn test_notification(rule_name: &str) -> AlertNotification {
        AlertNotification {
            event: AlertEvent {
                id: 7,
                rule_id: Uuid::new_v4(),
                rule_name: rule_name.to_owned(),
                severity: AlertSeverity::Critical,
                subject: "service".to_owned(),
                active: true,
                value: 2.0,
                threshold: 1.0,
                message: "test message".to_owned(),
                started_unix_seconds: 1,
                updated_unix_seconds: 2,
                resolved_unix_seconds: None,
                last_notified_unix_seconds: None,
            },
            resolved: false,
            webhook: true,
            email: true,
        }
    }

    fn test_delivery(channel: NotificationChannel, rule_name: &str) -> NotificationDelivery {
        NotificationDelivery {
            id: 1,
            idempotency_key: "delivery_test_1".to_owned(),
            lease_token: "lease".to_owned(),
            channel,
            notification: test_notification(rule_name),
            attempts: 1,
        }
    }

    #[test]
    fn smtp_dot_stuffing_preserves_lines() {
        assert_eq!(dot_stuff("one\n.two\n..three"), "one\r\n..two\r\n...three");
    }

    #[test]
    fn webhook_and_smtp_configuration_reject_injection() {
        for url in [
            "http://example.com/hook",
            "https://user:supersecret@example.com/hook",
            "file:///tmp/hook",
        ] {
            let error = validate_webhook_url(url, false).expect_err("URL must be rejected");
            assert_eq!(error.safe_code(), "webhook_invalid_configuration");
            assert!(!error.to_string().contains("supersecret"));
        }
        assert!(validate_webhook_url("http://127.0.0.1/hook", false).is_err());
        assert!(validate_webhook_url("http://127.0.0.1/hook", true).is_ok());
        assert!(validate_webhook_url("http://example.com/hook", true).is_err());

        for value in [
            "smtp.example.com\r\nQUIT",
            "smtp.example.com HELO",
            "sender@example.com\r\nBcc: supersecret@example.com",
            "recipient@example.com\nDATA",
        ] {
            assert!(!valid_smtp_host(value) || !valid_mailbox(value));
        }
        assert_eq!(
            safe_header_value("line one\r\nBcc: supersecret", SMTP_SUBJECT_MAX_CHARS),
            "line one Bcc: supersecret"
        );
        assert!(
            safe_header_value(&"x".repeat(500), SMTP_SUBJECT_MAX_CHARS)
                .chars()
                .count()
                <= SMTP_SUBJECT_MAX_CHARS
        );
    }

    #[tokio::test]
    async fn webhook_socket_e2e_uses_safe_error_codes_without_leaking_url() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let address = listener.local_addr().expect("listener address");
        let request = Arc::new(Mutex::new(String::new()));
        let captured = Arc::clone(&request);
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("webhook should connect");
            let mut bytes = Vec::with_capacity(4 * 1024);
            let mut chunk = [0_u8; 1024];
            loop {
                let size = socket.read(&mut chunk).await.expect("request should read");
                if size == 0 {
                    break;
                }
                bytes.extend_from_slice(&chunk[..size]);
                let Some(header_end) = bytes.windows(4).position(|value| value == b"\r\n\r\n")
                else {
                    continue;
                };
                let headers = String::from_utf8_lossy(&bytes[..header_end]);
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .unwrap_or_default();
                if bytes.len() >= header_end + 4 + content_length {
                    break;
                }
            }
            *captured.lock().expect("capture lock") = String::from_utf8_lossy(&bytes).into_owned();
            socket
                .write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n")
                .await
                .expect("response should write");
        });
        let config = NotificationConfig {
            webhook_url: Some(format!(
                "http://{address}/notify?token=supersecret&user=operator"
            )),
            allow_loopback_http: true,
            smtp: None,
        };
        let error = deliver_with_config(
            &test_delivery(NotificationChannel::Webhook, "socket webhook"),
            &config,
        )
        .await
        .expect_err("503 must fail");
        server.await.expect("server task should finish");
        assert_eq!(error.safe_code(), "webhook_http_status_503");
        assert!(!error.to_string().contains("supersecret"));
        let request = request.lock().expect("capture lock");
        assert!(request.starts_with("POST /notify?token=supersecret&user=operator HTTP/1.1"));
        assert!(request
            .to_ascii_lowercase()
            .contains("idempotency-key: linklake-alert-delivery_test_1"));
    }

    #[tokio::test]
    async fn smtp_socket_e2e_sends_a_bounded_single_line_subject() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let address = listener.local_addr().expect("listener address");
        let transcript = Arc::new(Mutex::new(Vec::<String>::new()));
        let captured = Arc::clone(&transcript);
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("SMTP should connect");
            socket
                .write_all(b"220 local test\r\n")
                .await
                .expect("greeting");
            let mut pending = Vec::<u8>::new();
            let mut data_mode = false;
            loop {
                let mut byte = [0_u8; 1];
                if socket.read_exact(&mut byte).await.is_err() {
                    break;
                }
                pending.push(byte[0]);
                if data_mode && pending.ends_with(b"\r\n.\r\n") {
                    captured
                        .lock()
                        .expect("capture lock")
                        .push(String::from_utf8_lossy(&pending).into_owned());
                    pending.clear();
                    data_mode = false;
                    socket.write_all(b"250 queued\r\n").await.expect("queued");
                    continue;
                }
                if !data_mode && pending.ends_with(b"\r\n") {
                    let line = String::from_utf8_lossy(&pending).trim().to_owned();
                    captured.lock().expect("capture lock").push(line.clone());
                    pending.clear();
                    let response = if line == "EHLO linklake" {
                        b"250 local\r\n".as_slice()
                    } else if line.starts_with("MAIL FROM:") || line.starts_with("RCPT TO:") {
                        b"250 ok\r\n".as_slice()
                    } else if line == "DATA" {
                        data_mode = true;
                        b"354 send data\r\n".as_slice()
                    } else if line == "QUIT" {
                        b"221 bye\r\n".as_slice()
                    } else {
                        b"500 unexpected supersecret response\r\n".as_slice()
                    };
                    socket.write_all(response).await.expect("SMTP response");
                    if line == "QUIT" {
                        break;
                    }
                }
            }
        });
        let config = NotificationConfig {
            webhook_url: None,
            allow_loopback_http: false,
            smtp: Some(SmtpConfig {
                host: "127.0.0.1".to_owned(),
                port: address.port(),
                tls: SmtpTls::None,
                username: None,
                password: None,
                from: "alerts@example.com".to_owned(),
                recipients: vec!["ops@example.com".to_owned()],
                allow_insecure: true,
            }),
        };
        deliver_with_config(
            &test_delivery(
                NotificationChannel::Email,
                &format!("line one\r\nBcc: supersecret {}", "x".repeat(500)),
            ),
            &config,
        )
        .await
        .expect("SMTP delivery should succeed");
        server.await.expect("server task should finish");
        let transcript = transcript.lock().expect("capture lock");
        let message = transcript
            .iter()
            .find(|line| line.contains("Subject:"))
            .expect("message should be captured");
        let subject = message
            .lines()
            .find_map(|line| line.strip_prefix("Subject: "))
            .expect("subject should exist");
        assert!(!subject.contains(['\r', '\n']));
        assert!(subject.chars().count() <= SMTP_SUBJECT_MAX_CHARS);
        let headers = message
            .split_once("\r\n\r\n")
            .map(|(headers, _)| headers)
            .expect("message headers should end");
        assert!(!headers.contains("\r\nBcc:"));
    }

    #[tokio::test]
    async fn smtp_raw_response_and_credentials_never_enter_errors() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let address = listener.local_addr().expect("listener address");
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("SMTP should connect");
            socket
                .write_all(b"550 rejected supersecret raw response\r\n")
                .await
                .expect("response should write");
        });
        let config = SmtpConfig {
            host: "127.0.0.1".to_owned(),
            port: address.port(),
            tls: SmtpTls::None,
            username: Some("operator".to_owned()),
            password: Some("supersecret".to_owned()),
            from: "alerts@example.com".to_owned(),
            recipients: vec!["ops@example.com".to_owned()],
            allow_insecure: true,
        };
        let error = send_email(
            &config,
            &test_notification("safe failure"),
            "delivery_test_2",
        )
        .await
        .expect_err("SMTP greeting should fail");
        server.await.expect("server task should finish");
        assert_eq!(error.safe_code(), "smtp_status_greeting_550");
        assert!(!error.to_string().contains("supersecret"));
        assert!(!error.to_string().contains("operator"));
    }
}
