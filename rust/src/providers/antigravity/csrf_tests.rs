use super::*;

fn cli_process_info() -> ProcessInfo {
    ProcessInfo {
        csrf_token: String::new(),
        extension_server_csrf_token: None,
        extension_port: None,
        pid: Some(7777),
        source: ProcessSource::Cli,
    }
}

fn ide_process_info() -> ProcessInfo {
    ProcessInfo {
        csrf_token: "primary-token".to_string(),
        extension_server_csrf_token: Some("extension-token".to_string()),
        extension_port: Some(54123),
        pid: Some(4242),
        source: ProcessSource::Ide,
    }
}

fn build_request(process_info: &ProcessInfo, cli_override: Option<&str>) -> reqwest::Request {
    let client = reqwest::Client::new();
    let request = client.post("https://127.0.0.1:1/test");
    AntigravityProvider::with_csrf_header(request, process_info, cli_override)
        .build()
        .expect("request should build")
}

#[test]
fn tokenless_cli_remains_compatible_without_override() {
    let request = build_request(&cli_process_info(), None);
    assert!(request.headers().get("X-Codeium-Csrf-Token").is_none());
}

#[test]
fn cli_override_adds_csrf_header() {
    let request = build_request(&cli_process_info(), Some("cli-token"));
    assert_eq!(
        request
            .headers()
            .get("X-Codeium-Csrf-Token")
            .and_then(|value| value.to_str().ok()),
        Some("cli-token")
    );
}

#[test]
fn blank_cli_override_keeps_request_tokenless() {
    let request = build_request(&cli_process_info(), Some("   "));
    assert!(request.headers().get("X-Codeium-Csrf-Token").is_none());
}

#[test]
fn ide_still_prefers_extension_csrf_token() {
    let request = build_request(&ide_process_info(), Some("ignored-cli-token"));
    assert_eq!(
        request
            .headers()
            .get("X-Codeium-Csrf-Token")
            .and_then(|value| value.to_str().ok()),
        Some("extension-token")
    );
}

#[test]
fn missing_csrf_response_is_not_treated_as_logged_out() {
    let error = AntigravityProvider::cli_csrf_error(
        reqwest::StatusCode::UNAUTHORIZED,
        r#"{"code":"unauthenticated","message":"missing CSRF token"}"#,
    )
    .expect("missing CSRF should be classified separately");

    assert!(AntigravityProvider::should_surface_probe_failure(&error));
    assert!(!matches!(error, ProviderError::AuthRequired));
    assert!(error.to_string().contains(ANTIGRAVITY_CSRF_TOKEN_ENV));
}

#[test]
fn ordinary_cli_unauthorized_is_not_a_csrf_error() {
    assert!(
        AntigravityProvider::cli_csrf_error(
            reqwest::StatusCode::UNAUTHORIZED,
            r#"{"code":"unauthenticated","message":"not logged in"}"#,
        )
        .is_none()
    );
}
