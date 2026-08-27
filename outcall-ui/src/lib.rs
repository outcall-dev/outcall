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
    http::{HeaderValue, Response, StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use rust_embed::RustEmbed;

const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'none'";

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
    let mut response = match Assets::get(path) {
        Some(content) => {
            let mime = mime_guess::from_path(path)
                .first_or_octet_stream()
                .to_string();
            let mut response = Response::new(Body::from(content.data));
            if let Ok(content_type) = HeaderValue::from_str(&mime) {
                response
                    .headers_mut()
                    .insert(header::CONTENT_TYPE, content_type);
            }
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            response
        }
        None => {
            let mut response = Response::new(Body::from("Not found"));
            *response.status_mut() = StatusCode::NOT_FOUND;
            response
        }
    };
    apply_security_headers(response.headers_mut());
    response
}

fn apply_security_headers(headers: &mut axum::http::HeaderMap) {
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert(
        "cross-origin-resource-policy",
        HeaderValue::from_static("same-origin"),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_html_is_embedded() {
        let asset = Assets::get("index.html").expect("embedded dashboard");
        let html = std::str::from_utf8(&asset.data).expect("UTF-8 dashboard");
        assert!(html.contains("/ui/styles.css"));
        assert!(html.contains("/ui/app.js"));
        assert!(!html.contains("<style"));
        assert!(!html.contains("<script>"));
    }

    #[test]
    fn dashboard_assets_are_embedded() {
        let script = Assets::get("app.js").expect("embedded dashboard script");
        let script = std::str::from_utf8(&script.data).expect("UTF-8 dashboard script");
        for endpoint in [
            "/api/v1/bridge",
            "/api/v1/dns",
            "/api/v1/proxy",
            "/api/v1/networks",
            "/api/v1/containers",
            "/api/v1/rules/active",
            "/api/v1/rules",
            "/api/v1/requests/rules",
            "/api/v1/dns/cache?entries=true",
        ] {
            assert!(script.contains(endpoint), "missing endpoint {endpoint}");
        }
        assert!(script.contains("window.location.hash.slice(1)"));
        assert!(script.contains("headers[\"X-Outcall-Token\"] = token"));
        assert!(script.contains("history.replaceState"));
        assert!(!script.contains("innerHTML"));
        assert!(Assets::get("styles.css").is_some());
    }

    #[test]
    fn asset_responses_have_browser_security_headers() {
        let response = serve_embedded_file("index.html");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(
            response.headers()["content-security-policy"],
            CONTENT_SECURITY_POLICY
        );
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        assert_eq!(response.headers()["referrer-policy"], "no-referrer");
        assert_eq!(response.headers()["x-frame-options"], "DENY");
        assert_eq!(
            response.headers()["cross-origin-resource-policy"],
            "same-origin"
        );
    }

    #[test]
    fn missing_asset_is_hardened_too() {
        let response = serve_embedded_file("does_not_exist.js");
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    }

    #[test]
    fn nonexistent_asset_returns_none() {
        assert!(Assets::get("does_not_exist.js").is_none());
    }
}
