//! Microsoft Teams (incoming webhook) delivery — the second alert channel.
//!
//! Endpoint URLs are stored encrypted (AES-256-GCM, `crypto`) in
//! `webhook_endpoints`; they are decrypted into memory only here and NEVER logged.
//! A delivery POSTs a Teams MessageCard built from the same alert body the email
//! channel renders — no secrets are ever placed in the payload.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde_json::json;
use sqlx::MySqlPool;

/// A resolved Teams endpoint with its decrypted webhook URL.
pub struct WebhookEndpoint {
    pub id: u64,
    pub name: String,
    pub url: String,
}

/// Theme color (hex, no `#`) for a Teams MessageCard, by severity.
fn theme_color(severity: &str) -> &'static str {
    match severity {
        "critical" => "d13438", // red
        "warning" => "ffaa44",  // amber
        _ => "0078d4",          // blue
    }
}

/// Load every enabled Teams endpoint subscribed to this event_type (a NULL
/// subscription event_type = all events). URLs are decrypted; an endpoint whose
/// ciphertext fails to decrypt is skipped (logged by the caller via count).
pub async fn load_subscribed(pool: &MySqlPool, event_type: &str) -> Result<Vec<WebhookEndpoint>> {
    let rows = sqlx::query_as::<_, (u64, String, Vec<u8>)>(
        "SELECT DISTINCT e.id, e.name, e.url_encrypted \
         FROM webhook_endpoints e \
         JOIN webhook_subscriptions s ON s.endpoint_id = e.id \
         WHERE e.enabled = 1 AND s.enabled = 1 \
           AND (s.event_type IS NULL OR s.event_type = ?)",
    )
    .bind(event_type)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .filter_map(|(id, name, blob)| {
            crate::crypto::open_str(&blob)
                .ok()
                .map(|url| WebhookEndpoint { id, name, url })
        })
        .collect())
}

/// Load one endpoint (decrypted) by id — used by the test-send endpoint.
pub async fn load_one(pool: &MySqlPool, id: u64) -> Result<Option<WebhookEndpoint>> {
    let row = sqlx::query_as::<_, (u64, String, Vec<u8>)>(
        "SELECT id, name, url_encrypted FROM webhook_endpoints WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(match row {
        Some((id, name, blob)) => Some(WebhookEndpoint {
            id,
            name,
            url: crate::crypto::open_str(&blob).context("decrypting webhook URL")?,
        }),
        None => None,
    })
}

/// POST a Teams MessageCard to an incoming-webhook URL. Returns an error on a
/// transport failure or a non-2xx response (recorded as a failed delivery).
pub async fn post_teams(url: &str, title: &str, severity: &str, text: &str) -> Result<()> {
    // MessageCard renders markdown; collapse single newlines into hard breaks so
    // the multi-line alert body stays readable in Teams.
    let body_md = text.replace('\n', "\n\n");
    let card = json!({
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "summary": title,
        "themeColor": theme_color(severity),
        "title": title,
        "text": body_md,
    });
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .context("building HTTP client")?;
    let resp = client
        .post(url)
        .json(&card)
        .send()
        .await
        .context("posting to Teams webhook")?;
    if !resp.status().is_success() {
        bail!("Teams webhook returned HTTP {}", resp.status().as_u16());
    }
    Ok(())
}
