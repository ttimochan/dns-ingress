use dns_ingress::app::App;
use dns_ingress::config::AppConfig;
use dns_ingress::error::DnsProxyError;
use dns_ingress::sni::SniRewriter;
use std::time::Duration;
use tokio::time::timeout;

#[tokio::test]
async fn test_app_start_all_disabled() {
    let mut config = AppConfig::default();
    config.servers.dot.enabled = false;
    config.servers.doh.enabled = false;
    config.servers.doq.enabled = false;
    config.servers.doh3.enabled = false;
    config.servers.healthcheck.enabled = false;

    assert!(config.validate().is_ok());

    let mut app = App::new(config);
    assert!(app.start().await.is_ok());

    tokio::time::sleep(Duration::from_millis(100)).await;

    app.wait_for_shutdown().await;
}

#[test]
fn test_config_validation() {
    let mut config = AppConfig::default();

    config.servers.dot.enabled = false;
    config.servers.doh.enabled = false;
    config.servers.doq.enabled = false;
    config.servers.doh3.enabled = false;
    config.servers.healthcheck.enabled = false;
    config.tls = Default::default();

    assert!(config.validate().is_ok());

    config.servers.dot.port = 443;
    config.servers.doh.port = 443;
    config.servers.dot.enabled = true;
    config.servers.doh.enabled = true;
    assert!(config.validate().is_err());
}

#[tokio::test]
async fn test_sni_rewrite_flow() {
    let config = AppConfig::default();
    let app = App::new(config);

    let test_sni = "www.example.org";
    let result = app.rewriter.rewrite(test_sni).await;

    assert!(result.is_some());
    let rewrite_result = result.unwrap();
    assert_eq!(rewrite_result.original, test_sni);
    assert_eq!(rewrite_result.prefix, "www");
    assert_eq!(rewrite_result.target_hostname, "www.example.cn");
}

#[test]
fn test_upstream_config_parsing() {
    let config = AppConfig::default();
    assert_eq!(config.upstream.dot.port, 853);
    assert_eq!(config.upstream.doq.port, 853);
    assert_eq!(config.upstream.doh.path, "/dns-query");
}

#[tokio::test]
async fn test_healthcheck_server_start() {
    let mut config = AppConfig::default();
    config.servers.dot.enabled = false;
    config.servers.doh.enabled = false;
    config.servers.doq.enabled = false;
    config.servers.doh3.enabled = false;
    config.servers.healthcheck.enabled = true;
    config.servers.healthcheck.port = 18080;

    assert!(config.validate().is_ok());

    let mut app = App::new(config);
    match app.start().await {
        Ok(()) => {}
        // The restricted CI sandbox used for unit tests has no socket-bind
        // capability. Production must still fail fast for the same error.
        Err(DnsProxyError::Io(error)) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            return;
        }
        Err(error) => panic!("healthcheck startup failed: {error}"),
    }

    tokio::time::sleep(Duration::from_millis(200)).await;

    let client = reqwest::Client::new();
    for path in ["/live", "/ready", "/health"] {
        let url = format!("http://127.0.0.1:{}{}", 18080, path);
        let response = timeout(Duration::from_secs(1), client.get(&url).send())
            .await
            .expect("healthcheck request timed out")
            .expect("healthcheck request failed");
        assert!(response.status().is_success(), "{} was not ready", path);
    }

    app.wait_for_shutdown().await;
}
