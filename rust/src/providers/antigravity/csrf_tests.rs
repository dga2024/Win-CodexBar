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

#[test]
fn tokenless_cli_has_no_request_csrf_token() {
    assert_eq!(cli_process_info().request_csrf_token(), None);
}

#[test]
fn cli_uses_token_after_discovery() {
    let mut process = cli_process_info();
    process.csrf_token = "cli-token".to_string();
    assert_eq!(process.request_csrf_token(), Some("cli-token"));
}

#[test]
fn ide_still_prefers_extension_csrf_token() {
    assert_eq!(
        ide_process_info().request_csrf_token(),
        Some("extension-token")
    );
}

#[test]
fn parses_csrf_token_from_hub_index_page() {
    let html = r#"<html><script>window.__APP_CONFIG__ = {"csrfToken":"hub-token-123","other":true};</script></html>"#;
    assert_eq!(
        cli_csrf::parse_token_from_index(html).as_deref(),
        Some("hub-token-123")
    );
}

#[test]
fn ignores_index_page_without_csrf_token() {
    let html = r#"<html><script>window.__APP_CONFIG__ = {"other":true};</script></html>"#;
    assert_eq!(cli_csrf::parse_token_from_index(html), None);
}

#[test]
fn missing_csrf_is_detected_only_for_auth_statuses() {
    let body = r#"{"code":"unauthenticated","message":"missing CSRF token"}"#;
    assert!(cli_csrf::missing_token_response(
        reqwest::StatusCode::UNAUTHORIZED,
        body
    ));
    assert!(cli_csrf::missing_token_response(
        reqwest::StatusCode::FORBIDDEN,
        body
    ));
    assert!(!cli_csrf::missing_token_response(
        reqwest::StatusCode::INTERNAL_SERVER_ERROR,
        body
    ));
}

#[test]
fn ordinary_logged_out_response_is_not_missing_csrf() {
    assert!(!cli_csrf::missing_token_response(
        reqwest::StatusCode::UNAUTHORIZED,
        r#"{"code":"unauthenticated","message":"not logged in"}"#,
    ));
}

#[test]
fn csrf_negotiation_failure_surfaces_instead_of_offline_history() {
    let error = ProviderError::Other(format!(
        "{CLI_CSRF_REQUIRED_PREFIX}: no token could be discovered"
    ));
    let offline = Some(ProviderFetchResult::new(
        UsageSnapshot::new(RateWindow::informational("Offline · 42 conversations")),
        "offline",
    ));

    let result = AntigravityProvider::resolve_probe_failure(error, offline);
    assert!(matches!(
        result,
        Err(ProviderError::Other(message)) if message.starts_with(CLI_CSRF_REQUIRED_PREFIX)
    ));
}
