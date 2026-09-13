use regex_lite::Regex;
use std::sync::LazyLock;
use std::time::Duration;

const ANTIGRAVITY_CSRF_TOKEN_ENV: &str = "ANTIGRAVITY_CSRF_TOKEN";
const DISCOVERY_TIMEOUT: Duration = Duration::from_millis(750);
const DISCOVERY_BODY_MAX_BYTES: usize = 256 * 1024;

pub(super) fn token_override() -> Option<String> {
    std::env::var(ANTIGRAVITY_CSRF_TOKEN_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub(super) fn parse_token_from_index(text: &str) -> Option<String> {
    static CSRF_TOKEN_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#""csrfToken"\s*:\s*"([^"]+)""#)
            .expect("valid Antigravity hub csrfToken pattern")
    });
    CSRF_TOKEN_RE
        .captures(text)
        .and_then(|captures| captures.get(1))
        .map(|value| value.as_str().trim().to_string())
        .filter(|value| !value.is_empty())
}

pub(super) fn missing_token_response(status: reqwest::StatusCode, text: &str) -> bool {
    (status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN)
        && text.to_ascii_lowercase().contains("missing csrf token")
}

async fn bounded_response_text(mut response: reqwest::Response) -> Option<String> {
    if response
        .content_length()
        .is_some_and(|length| length > DISCOVERY_BODY_MAX_BYTES as u64)
    {
        return None;
    }

    let mut body = Vec::new();
    loop {
        let chunk = response.chunk().await.ok()?;
        let Some(chunk) = chunk else {
            break;
        };
        if body.len().saturating_add(chunk.len()) > DISCOVERY_BODY_MAX_BYTES {
            return None;
        }
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body).ok()
}

pub(super) async fn discover_token(
    client: &reqwest::Client,
    ports: impl IntoIterator<Item = u16>,
) -> Option<String> {
    // Current agy hub builds publish csrfToken in window.__APP_CONFIG__ on
    // one of their own loopback listeners. Callers supply only ports owned by
    // the detected process; never log the token or page body.
    for port in ports.into_iter().take(8) {
        for scheme in ["https", "http"] {
            let url = format!("{scheme}://127.0.0.1:{port}/");
            let response = client.get(&url).timeout(DISCOVERY_TIMEOUT).send().await;
            let Ok(response) = response else {
                continue;
            };
            if !response.status().is_success() {
                continue;
            }
            let Some(text) = bounded_response_text(response).await else {
                continue;
            };
            if let Some(token) = parse_token_from_index(&text) {
                return Some(token);
            }
        }
    }
    None
}
