use dns_ingress::config::{AppConfig, CertificateConfig, TlsConfig};
use dns_ingress::tls_utils::{CertificateResolver, DynamicCertResolver};
use std::sync::Arc;

#[test]
fn test_certificate_resolver_new() {
    let config = AppConfig::default();
    assert!(CertificateResolver::new(&config).is_ok());
}

#[test]
fn test_invalid_certificate_fails_at_startup() {
    let mut config = AppConfig::default();
    let mut tls_config = TlsConfig::default();

    let cert_config = CertificateConfig {
        cert_file: "/nonexistent/cert.pem".to_string(),
        key_file: "/nonexistent/key.pem".to_string(),
    };

    tls_config
        .certs
        .insert("example.com".to_string(), cert_config);
    config.tls = tls_config;

    assert!(CertificateResolver::new(&config).is_err());
}

#[test]
fn test_get_cert_for_domain_no_config() {
    let config = AppConfig::default();
    let resolver = CertificateResolver::new(&config).unwrap();

    let result = resolver.get_cert_for_domain("unknown.com");
    assert!(result.is_err());
    if let Err(e) = result {
        let err_msg = format!("{}", e);
        assert!(err_msg.contains("No certificate configured"));
    }
}

#[test]
fn test_dynamic_cert_resolver_new() {
    let config = AppConfig::default();
    let resolver = Arc::new(CertificateResolver::new(&config).unwrap());
    let dynamic_resolver = DynamicCertResolver::new(resolver);

    assert!(Arc::strong_count(&dynamic_resolver.resolver) >= 1);
}
