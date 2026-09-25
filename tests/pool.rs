use dns_ingress::upstream::pool::ConnectionPool;
use std::sync::Arc;
use std::sync::Once;

static INIT: Once = Once::new();

fn init_crypto_provider() {
    INIT.call_once(|| {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .expect("Failed to install default crypto provider");
    });
}

#[test]
fn test_get_client_reuse() {
    init_crypto_provider();
    let pool = ConnectionPool::new();
    let sni = "example.com";

    let client1 = pool.get_client(sni).unwrap();
    let client2 = pool.get_client(sni).unwrap();

    // Should return the same client instance
    assert_eq!(Arc::as_ptr(&client1), Arc::as_ptr(&client2));
}

#[test]
fn test_multiple_snis() {
    init_crypto_provider();
    let pool = ConnectionPool::new();

    let client1 = pool.get_client("example.com").unwrap();
    let client2 = pool.get_client("example.org").unwrap();

    // Should be different clients
    assert_ne!(Arc::as_ptr(&client1), Arc::as_ptr(&client2));
}

#[test]
fn test_connection_pool_default() {
    init_crypto_provider();
    let _pool = ConnectionPool::default();
}

#[test]
fn test_connection_pool_with_config() {
    init_crypto_provider();
    use std::time::Duration;

    let pool = ConnectionPool::with_config(Duration::from_secs(30), Duration::from_secs(5), 5);

    // Test that it works
    let _client = pool.get_client("example.com").unwrap();
}
