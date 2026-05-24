//! Dashboard static assets embedded via rust-embed, served by axum (S010).
//!
//! The dashboard is a single-page app that fetches from the existing API
//! endpoints (bridge, DNS, proxy, rules) and auto-refreshes every 5 seconds.
//!
//! Mount with: `router.merge(outcall_ui::router())`

#![forbid(unsafe_code)]

use axum::{
    Router,
    body::Body,
    extract::Path,
    http::{Response, StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use rust_embed::RustEmbed;

/// Embedded assets from the `assets/` directory at compile time.
#[derive(RustEmbed)]
#[folder = "assets/"]
struct Assets;

/// Returns an Axum router that serves the dashboard under `/ui/`.
///
/// Routes:
///   GET /ui        → index.html
///   GET /ui/       → index.html
///   GET /ui/*path  → assets/*path (CSS, JS, images, etc.)
pub fn router() -> Router {
    Router::new()
        .route("/ui", get(serve_index))
        .route("/ui/", get(serve_index))
        .route("/ui/{*path}", get(serve_asset))
}

async fn serve_index() -> impl IntoResponse {
    serve_embedded_file("index.html")
}

async fn serve_asset(Path(path): Path<String>) -> impl IntoResponse {
    serve_embedded_file(&path)
}

fn serve_embedded_file(path: &str) -> Response<Body> {
    match Assets::get(path) {
        Some(content) => {
            let mime = mime_guess::from_path(path)
                .first_or_octet_stream()
                .to_string();
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, mime)
                .header(header::CACHE_CONTROL, "no-cache")
                .body(Body::from(content.data))
                .unwrap()
        }
        None => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("Not found"))
            .unwrap(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_html_is_embedded() {
        assert!(Assets::get("index.html").is_some());
    }

    #[test]
    fn nonexistent_asset_returns_none() {
        assert!(Assets::get("does_not_exist.js").is_none());
    }
}
