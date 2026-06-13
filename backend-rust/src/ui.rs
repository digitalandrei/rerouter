//! OPTIONAL single-binary UI (cargo feature "embed-ui", default OFF).
//!
//! Embeds ../frontend/dist into the binary (rust-embed) and serves the React
//! SPA at `/` as the router fallback: real files get their proper mime type,
//! unknown extensionless paths fall back to index.html (client-side routes),
//! and /api/* ALWAYS wins — an unmatched /api path is a JSON 404, never HTML.
//!
//! Build:
//!   (cd frontend && npm ci && npm run build) && cargo build --release --features embed-ui
//!
//! The default build never references frontend/dist, so `cargo check` stays
//! green without a frontend build.

use axum::http::{header, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::Json;
use rust_embed::RustEmbed;
use serde_json::json;

/// frontend/dist, embedded at compile time (path relative to backend-rust/).
#[derive(RustEmbed)]
#[folder = "../frontend/dist"]
struct Dist;

/// Axum fallback handler: everything the explicit /api routes did not match.
pub async fn serve_spa(uri: Uri) -> Response {
    let path = uri.path();

    // /api/* always wins: explicit API routes are matched before this fallback,
    // so anything still here is a genuine API 404 — never serve it HTML.
    if path == "/api" || path.starts_with("/api/") {
        return (StatusCode::NOT_FOUND, Json(json!({ "error": "not_found" }))).into_response();
    }

    let trimmed = path.trim_start_matches('/');
    let candidate = if trimmed.is_empty() { "index.html" } else { trimmed };
    if let Some(file) = Dist::get(candidate) {
        return asset_response(candidate, file);
    }
    // Client-side route (e.g. /devices, /mitigations, /settings) -> index.html fallback.
    match Dist::get("index.html") {
        Some(file) => asset_response("index.html", file),
        None => (StatusCode::NOT_FOUND, "embedded UI is missing index.html").into_response(),
    }
}

fn asset_response(path: &str, file: rust_embed::EmbeddedFile) -> Response {
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    // Vite emits content-hashed filenames under assets/ — safe to cache hard.
    let cache = if path.starts_with("assets/") {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    };
    (
        [(header::CONTENT_TYPE, mime.as_ref()), (header::CACHE_CONTROL, cache)],
        file.data.into_owned(),
    )
        .into_response()
}
