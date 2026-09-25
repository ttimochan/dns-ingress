use dns_ingress::app::App;
use dns_ingress::config::AppConfig;
use std::sync::Arc;

#[test]
fn test_app_new() {
    let config = AppConfig::default();
    let app = App::new(config);
    assert!(Arc::strong_count(&app.rewriter) >= 1);
}

#[tokio::test]
async fn test_app_start_with_all_disabled() {
    let mut config = AppConfig::default();
    config.servers.dot.enabled = false;
    config.servers.doh.enabled = false;
    config.servers.doq.enabled = false;
    config.servers.doh3.enabled = false;
    config.servers.healthcheck.enabled = false;

    let mut app = App::new(config);
    let result = app.start().await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_app_start_with_some_enabled() {
    let mut config = AppConfig::default();
    config.servers.dot.enabled = true;
    config.servers.doh.enabled = false;
    config.servers.doq.enabled = false;
    config.servers.doh3.enabled = false;
    config.servers.healthcheck.enabled = false;

    let mut app = App::new(config);
    let result = app.start().await;
    assert!(result.is_err());
}
