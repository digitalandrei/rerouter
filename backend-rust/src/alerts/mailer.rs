//! SMTP mailer (lettre, rustls — no openssl). The entire SMTP contract lives in
//! the environment — SMTP_HOST / SMTP_PORT / SMTP_USERNAME / SMTP_PASSWORD /
//! SMTP_FROM (see deploy/env/rerouter.example.env) — never in config files.

use anyhow::{Context, Result};
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

pub struct Mailer {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
}

impl Mailer {
    /// Build the pooled SMTP transport (STARTTLS via rustls).
    pub fn from_env() -> Result<Self> {
        let host = std::env::var("SMTP_HOST").context("SMTP_HOST not set")?;
        let port: u16 = std::env::var("SMTP_PORT")
            .unwrap_or_else(|_| "587".to_string())
            .parse()
            .context("SMTP_PORT is not a valid port")?;
        let username = std::env::var("SMTP_USERNAME").context("SMTP_USERNAME not set")?;
        let password = std::env::var("SMTP_PASSWORD").context("SMTP_PASSWORD not set")?;
        let from: Mailbox = std::env::var("SMTP_FROM")
            .context("SMTP_FROM not set")?
            .parse()
            .context("SMTP_FROM is not a valid mailbox")?;

        let transport = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&host)
            .context("building SMTP transport")?
            .port(port)
            .credentials(Credentials::new(username, password))
            .build();

        Ok(Self { transport, from })
    }

    /// Send one alert email. The caller records the outcome in
    /// alert_deliveries; an SMTP accept is recorded as `sent` (delivery
    /// failures surface later as bounces).
    pub async fn send(&self, to: &str, subject: &str, body: String) -> Result<()> {
        let message = Message::builder()
            .from(self.from.clone())
            .to(to.parse().context("recipient address")?)
            .subject(subject)
            .body(body)
            .context("building message")?;
        self.transport.send(message).await.context("smtp send")?;
        Ok(())
    }
}

// TODO(milestone 2): plain-text templates per event type — event + severity,
// asset/prefix, rule + metric value, reroute state, timestamp, and a deep link
// to the SPA page. Never include secrets or raw credentials.
