use dns_ingress::upstream::pool::{ConnectionPool, HttpClient};
use dns_ingress::upstream::{create_connection_pool_with_limit, forward_http_request};
use std::sync::Once;
use std::time::Duration;

static INIT: Once = Once::new();

fn init_crypto_provider() {
    INIT.call_once(|| {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .expect("Failed to install default crypto provider");
    });
}

#[test]
fn test_create_connection_pool() {
    init_crypto_provider();
    let _pool = create_connection_pool_with_limit(16);
}

#[test]
fn test_upstream_module_imports() {
    init_crypto_provider();
    // Test that upstream module exports are accessible
    // Verify the module structure exists
    let pool = create_connection_pool_with_limit(16);
    let _client = pool.get_client("example.com");
    assert!(std::any::type_name::<HttpClient>().contains("Client"));
    assert!(std::any::type_name::<ConnectionPool>().contains("ConnectionPool"));
}

#[tokio::test]
async fn test_forward_http_request_invalid_uri() {
    init_crypto_provider();
    use bytes::Bytes;
    use hyper::HeaderMap;
    use hyper::Method;

    let pool = create_connection_pool_with_limit(16);
    let headers = HeaderMap::new();

    // Test with invalid URI - should handle gracefully
    let result = forward_http_request(
        &pool,
        "not-a-valid-uri",
        "example.com",
        Method::GET,
        &headers,
        Bytes::new(),
        Duration::from_secs(1),
    )
    .await;

    // Should return an error or error response (BAD_GATEWAY)
    match result {
        Ok((resp, _)) => {
            // If it succeeds, it should be an error response
            assert!(resp.status().is_client_error() || resp.status().is_server_error());
        }
        Err(_) => {
            // Error is also acceptable for invalid URI
        }
    }
}
