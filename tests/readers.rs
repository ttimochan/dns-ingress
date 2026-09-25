use dns_ingress::config::{AppConfig, RewriteConfig};
use dns_ingress::metrics::Metrics;
use dns_ingress::readers::{DoH3Server, DoHServer, DoQServer, DoTServer, HealthcheckServer};
use dns_ingress::rewrite::create_rewriter;
use std::sync::Arc;

fn create_test_rewriter() -> dns_ingress::rewrite::SniRewriterType {
    create_rewriter(RewriteConfig {
        base_domains: vec!["example.com".to_string()],
        target_suffix: ".example.cn".to_string(),
    })
}

#[test]
fn test_healthcheck_server_new() {
    let config = Arc::new(AppConfig::default());
    let _server = HealthcheckServer::with_metrics_and_readiness(
        config,
        Arc::new(Metrics::new()),
        Arc::new(std::sync::atomic::AtomicBool::new(true)),
    );
}

#[test]
fn test_dot_server_new() {
    let config = Arc::new(AppConfig::default());
    let rewriter = create_test_rewriter();
    let metrics = Arc::new(Metrics::new());
    let _server = DoTServer::new(config, rewriter, metrics);
}

#[test]
fn test_doh_server_new() {
    let config = Arc::new(AppConfig::default());
    let rewriter = create_test_rewriter();
    let metrics = Arc::new(Metrics::new());
    let _server = DoHServer::new(config, rewriter, metrics);
}

#[test]
fn test_doq_server_new() {
    let config = Arc::new(AppConfig::default());
    let rewriter = create_test_rewriter();
    let metrics = Arc::new(Metrics::new());
    let _server = DoQServer::new(config, rewriter, metrics);
}

#[test]
fn test_doh3_server_new() {
    let config = Arc::new(AppConfig::default());
    let rewriter = create_test_rewriter();
    let metrics = Arc::new(Metrics::new());
    let _server = DoH3Server::new(config, rewriter, metrics);
}

#[tokio::test]
async fn test_healthcheck_server_start_disabled() {
    let mut config = AppConfig::default();
    config.servers.healthcheck.enabled = false;
    let config = Arc::new(config);
    let server = HealthcheckServer::with_metrics_and_readiness(
        config,
        Arc::new(Metrics::new()),
        Arc::new(std::sync::atomic::AtomicBool::new(true)),
    );

    let result = server.start().await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_dot_server_start_disabled() {
    let mut config = AppConfig::default();
    config.servers.dot.enabled = false;
    let config = Arc::new(config);
    let rewriter = create_test_rewriter();
    let metrics = Arc::new(Metrics::new());
    let server = DoTServer::new(config, rewriter, metrics);

    let result = server.start().await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_doh_server_start_disabled() {
    let mut config = AppConfig::default();
    config.servers.doh.enabled = false;
    let config = Arc::new(config);
    let rewriter = create_test_rewriter();
    let metrics = Arc::new(Metrics::new());
    let server = DoHServer::new(config, rewriter, metrics);

    let result = server.start().await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_doq_server_start_disabled() {
    let mut config = AppConfig::default();
    config.servers.doq.enabled = false;
    let config = Arc::new(config);
    let rewriter = create_test_rewriter();
    let metrics = Arc::new(Metrics::new());
    let server = DoQServer::new(config, rewriter, metrics);

    let result = server.start().await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_doh3_server_start_disabled() {
    let mut config = AppConfig::default();
    config.servers.doh3.enabled = false;
    let config = Arc::new(config);
    let rewriter = create_test_rewriter();
    let metrics = Arc::new(Metrics::new());
    let server = DoH3Server::new(config, rewriter, metrics);

    let result = server.start().await;
    assert!(result.is_ok());
}
