//! 告警 Webhook 与 SMTP 通知发送器。

use crate::alerting::{AlertNotification, AlertSeverity};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use linklake_core::BoxedIo;
use serde::Serialize;
use std::{env, sync::Arc, time::Duration};
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

impl NotificationConfig {
    fn from_env() -> Self {
        let webhook_url = nonempty_env("LINKLAKE_ALERT_WEBHOOK_URL");
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
                password: nonempty_env("LINKLAKE_SMTP_PASSWORD"),
                from,
                recipients,
            })
        });
        Self { webhook_url, smtp }
    }

    fn view(&self) -> NotificationChannelView {
        NotificationChannelView {
            webhook_configured: self.webhook_url.is_some(),
            smtp_configured: self.smtp.is_some(),
            smtp_host: self.smtp.as_ref().map(|smtp| smtp.host.clone()),
            smtp_port: self.smtp.as_ref().map(|smtp| smtp.port),
            smtp_tls: self.smtp.as_ref().map(|smtp| smtp.tls.as_str().to_owned()),
            smtp_from: self.smtp.as_ref().map(|smtp| smtp.from.clone()),
            smtp_recipients: self
                .smtp
                .as_ref()
                .map(|smtp| smtp.recipients.clone())
                .unwrap_or_default(),
        }
    }
}

fn nonempty_env(name: &str) -> Option<String> {
    env::var(name).ok().and_then(|value| {
        let value = value.trim();
        (!value.is_empty()).then(|| value.to_owned())
    })
}

pub(crate) fn channel_view() -> NotificationChannelView {
    NotificationConfig::from_env().view()
}

pub(crate) async fn dispatch(notification: AlertNotification) {
    let config = NotificationConfig::from_env();
    if notification.webhook {
        if let Some(url) = config.webhook_url {
            let notification = notification.clone();
            tokio::spawn(async move {
                if let Err(error) = send_webhook(&url, &notification).await {
                    tracing::error!("Could not deliver alert webhook: {error}");
                }
            });
        }
    }
    if notification.email {
        if let Some(smtp) = config.smtp {
            tokio::spawn(async move {
                if let Err(error) = send_email(&smtp, &notification).await {
                    tracing::error!("Could not deliver alert email: {error}");
                }
            });
        }
    }
}

async fn send_webhook(url: &str, notification: &AlertNotification) -> anyhow::Result<()> {
    #[derive(Serialize)]
    struct Payload<'a> {
        product: &'static str,
        event: &'a crate::alerting::AlertEvent,
        status: &'static str,
    }
    let response = timeout(
        NOTIFICATION_TIMEOUT,
        reqwest::Client::new()
            .post(url)
            .header("User-Agent", "LinkLake-Alert/1")
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
    .map_err(|_| anyhow::anyhow!("webhook request timed out"))??;
    anyhow::ensure!(
        response.status().is_success(),
        "webhook returned HTTP {}",
        response.status()
    );
    Ok(())
}

async fn send_email(config: &SmtpConfig, notification: &AlertNotification) -> anyhow::Result<()> {
    timeout(NOTIFICATION_TIMEOUT, send_email_inner(config, notification))
        .await
        .map_err(|_| anyhow::anyhow!("SMTP delivery timed out"))?
}

async fn send_email_inner(
    config: &SmtpConfig,
    notification: &AlertNotification,
) -> anyhow::Result<()> {
    let tcp = TcpStream::connect((config.host.as_str(), config.port)).await?;
    let mut stream: BoxedIo = match config.tls {
        SmtpTls::Implicit => tls_stream(tcp, &config.host).await?,
        _ => Box::new(tcp),
    };
    expect_smtp(&mut stream, &[220]).await?;
    smtp_command(&mut stream, "EHLO linklake", &[250]).await?;
    if matches!(config.tls, SmtpTls::StartTls) {
        smtp_command(&mut stream, "STARTTLS", &[220]).await?;
        stream = tls_stream(stream, &config.host).await?;
        smtp_command(&mut stream, "EHLO linklake", &[250]).await?;
    }
    if let Some(username) = config.username.as_deref() {
        let password = config
            .password
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("SMTP password is not configured"))?;
        smtp_command(&mut stream, "AUTH LOGIN", &[334]).await?;
        smtp_command(&mut stream, &BASE64.encode(username), &[334]).await?;
        smtp_command(&mut stream, &BASE64.encode(password), &[235]).await?;
    }
    smtp_command(&mut stream, &format!("MAIL FROM:<{}>", config.from), &[250]).await?;
    for recipient in &config.recipients {
        smtp_command(&mut stream, &format!("RCPT TO:<{recipient}>",), &[250, 251]).await?;
    }
    smtp_command(&mut stream, "DATA", &[354]).await?;
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
    let subject = format!(
        "[LinkLake][{status}][{severity}] {}",
        notification.event.rule_name
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
        "From: {}\r\nTo: {}\r\nSubject: {}\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n{}",
        config.from,
        recipients,
        subject,
        dot_stuff(&body)
    );
    stream.write_all(message.as_bytes()).await?;
    stream.write_all(b"\r\n.\r\n").await?;
    stream.flush().await?;
    expect_smtp(&mut stream, &[250]).await?;
    let _ = smtp_command(&mut stream, "QUIT", &[221]).await;
    Ok(())
}

fn dot_stuff(value: &str) -> String {
    value
        .replace("\r\n", "\n")
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

async fn tls_stream<S>(stream: S, host: &str) -> anyhow::Result<BoxedIo>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let native = rustls_native_certs::load_native_certs();
    let mut roots = RootCertStore::empty();
    for certificate in native.certs {
        roots.add(certificate)?;
    }
    anyhow::ensure!(
        !roots.is_empty(),
        "no native TLS root certificates are available"
    );
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server_name = ServerName::try_from(host.to_owned())?;
    let stream = TlsConnector::from(Arc::new(config))
        .connect(server_name, stream)
        .await?;
    Ok(Box::new(stream))
}

async fn smtp_command(stream: &mut BoxedIo, command: &str, expected: &[u16]) -> anyhow::Result<()> {
    stream.write_all(command.as_bytes()).await?;
    stream.write_all(b"\r\n").await?;
    stream.flush().await?;
    expect_smtp(stream, expected).await.map(|_| ())
}

async fn expect_smtp(stream: &mut BoxedIo, expected: &[u16]) -> anyhow::Result<String> {
    let mut response = String::new();
    let mut expected_code = None;
    loop {
        let line = read_smtp_line(stream).await?;
        anyhow::ensure!(line.len() >= 4, "SMTP returned a malformed response");
        let code = line[..3].parse::<u16>()?;
        expected_code.get_or_insert(code);
        response.push_str(&line);
        response.push('\n');
        if line.as_bytes().get(3) == Some(&b' ') {
            anyhow::ensure!(
                expected.contains(&code),
                "SMTP returned unexpected response {code}: {}",
                response.trim()
            );
            return Ok(response);
        }
        anyhow::ensure!(
            line.as_bytes().get(3) == Some(&b'-') && expected_code == Some(code),
            "SMTP returned an invalid multiline response"
        );
    }
}

async fn read_smtp_line(stream: &mut BoxedIo) -> anyhow::Result<String> {
    let mut bytes = Vec::with_capacity(128);
    loop {
        let byte = stream.read_u8().await?;
        bytes.push(byte);
        anyhow::ensure!(bytes.len() <= 16 * 1024, "SMTP response line is too long");
        if bytes.ends_with(b"\r\n") {
            bytes.truncate(bytes.len() - 2);
            return Ok(String::from_utf8(bytes)?);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smtp_dot_stuffing_preserves_lines() {
        assert_eq!(dot_stuff("one\n.two\n..three"), "one\r\n..two\r\n...three");
    }
}
