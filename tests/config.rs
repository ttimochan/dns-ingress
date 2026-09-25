use dns_ingress::config::{AppConfig, RewriteConfig};
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn test_default_config() {
    let config = AppConfig::default();
    assert_eq!(config.rewrite.base_domains.len(), 2);
    assert!(
        config
            .rewrite
            .base_domains
            .contains(&"example.com".to_string())
    );
    assert!(
        config
            .rewrite
            .base_domains
            .contains(&"example.org".to_string())
    );
    assert_eq!(config.rewrite.target_suffix, ".example.cn");
}

#[test]
fn test_config_from_toml() {
    let toml_content = r#"
[rewrite]
base_domains = ["test.com", "test.org"]
target_suffix = ".test.cn"

[servers.dot]
enabled = true
bind_address = "127.0.0.1"
port = 853

[servers.doh]
enabled = false
bind_address = "0.0.0.0"
port = 443

[servers.doq]
enabled = true
bind_address = "0.0.0.0"
port = 853

[servers.doh3]
enabled = false
bind_address = "0.0.0.0"
port = 443

[upstream]
[upstream.dot]
port = 1853
[upstream.doh]
port = 1443
path = "/dns-query"
[upstream.doq]
port = 2853
[upstream.doh3]
port = 2443
path = "/dns-query"
"#;

    let mut file = NamedTempFile::new().unwrap();
    file.write_all(toml_content.as_bytes()).unwrap();
    file.flush().unwrap();

    let config = AppConfig::from_file(file.path()).unwrap();
    assert_eq!(config.rewrite.base_domains.len(), 2);
    assert_eq!(config.rewrite.target_suffix, ".test.cn");
    assert_eq!(config.servers.dot.bind_address, "127.0.0.1");
    assert!(!config.servers.doh.enabled);
}

#[test]
fn test_upstream_config() {
    let config = AppConfig::default();
    assert_eq!(config.upstream.dot.port, 853);
    assert_eq!(config.upstream.doq.port, 853);
}

#[test]
fn test_tcp_and_udp_may_share_dns_port() {
    let mut config = AppConfig::default();
    config.servers.doh.enabled = false;
    config.servers.doh3.enabled = false;
    config.servers.healthcheck.enabled = false;
    let cert = NamedTempFile::new().unwrap();
    let key = NamedTempFile::new().unwrap();
    config.tls.default = Some(dns_ingress::config::CertificateConfig {
        cert_file: cert.path().display().to_string(),
        key_file: key.path().display().to_string(),
    });
    assert!(config.validate().is_ok());
}

#[test]
fn test_legacy_fixed_upstream_is_rejected() {
    let toml_content = r#"
[rewrite]
base_domains = ["example.org"]
target_suffix = ".example.cn"
[servers.dot]
enabled = false
bind_address = "127.0.0.1"
port = 853
[servers.doh]
enabled = false
bind_address = "127.0.0.1"
port = 443
[servers.doq]
enabled = false
bind_address = "127.0.0.1"
port = 853
[servers.doh3]
enabled = false
bind_address = "127.0.0.1"
port = 443
[upstream]
default = "8.8.8.8:853"
"#;
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(toml_content.as_bytes()).unwrap();
    assert!(AppConfig::from_file(file.path()).is_err());
}

#[test]
fn test_missing_config_is_rejected() {
    assert!(AppConfig::from_file("/nonexistent/file.toml").is_err());
}

#[test]
fn test_legacy_passthrough_route_is_rejected() {
    let legacy = r#"
base_domains = ["example.org"]
target_suffix = ".example.cn"
rewrite_failure_strategy = "passthrough"
"#;
    assert!(toml::from_str::<RewriteConfig>(legacy).is_err());
}

#[test]
fn test_legacy_mtls_fields_are_rejected() {
    let content = r#"
[rewrite]
base_domains = ["example.org"]
target_suffix = ".example.cn"
[servers.dot]
enabled = false
bind_address = "127.0.0.1"
port = 853
[servers.doh]
enabled = false
bind_address = "127.0.0.1"
port = 443
[servers.doq]
enabled = false
bind_address = "127.0.0.1"
port = 853
[servers.doh3]
enabled = false
bind_address = "127.0.0.1"
port = 443
[upstream.dot]
port = 853
[upstream.doh]
port = 443
[upstream.doq]
port = 853
[upstream.doh3]
port = 443
[tls]
require_client_cert = true
"#;
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(content.as_bytes()).unwrap();
    let error = AppConfig::from_file(file.path()).unwrap_err();
    assert!(error.to_string().contains("mTLS"));
}

#[test]
fn test_resource_limits_must_be_positive() {
    let mut config = AppConfig::default();
    config.servers.dot.enabled = false;
    config.servers.doh.enabled = false;
    config.servers.doq.enabled = false;
    config.servers.doh3.enabled = false;
    config.limits.max_inflight_requests_per_connection = 0;
    assert!(config.validate().is_err());
}

#[test]
fn test_rewrite_domains_require_valid_dns_labels() {
    for invalid in ["a..example", "-edge.example", "edge-.example", ".example"] {
        let mut config = AppConfig::default();
        config.servers.dot.enabled = false;
        config.servers.doh.enabled = false;
        config.servers.doq.enabled = false;
        config.servers.doh3.enabled = false;
        config.rewrite.base_domains = vec![invalid.to_string()];
        assert!(config.validate().is_err(), "{invalid} must be rejected");
    }
}
