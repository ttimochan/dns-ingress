use crate::proxy::http::{
    collect_body_with_progress, is_dns_message_content_type, validate_dns_message,
};
use crate::upstream::pool::ConnectionPool;
use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::Full;
use hyper::{Method, Request, Response, StatusCode};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, warn};

#[allow(dead_code)] // retained as the public default-trust constructor
pub fn create_connection_pool_with_limit(max_clients: usize) -> Arc<ConnectionPool> {
    Arc::new(ConnectionPool::with_max_clients(max_clients))
}

pub fn create_connection_pool_with_limit_and_root_store(
    max_clients: usize,
    root_store: Arc<rustls::RootCertStore>,
) -> Arc<ConnectionPool> {
    Arc::new(ConnectionPool::with_max_clients_and_root_store(
        max_clients,
        root_store,
    ))
}

/// Forward HTTP request to upstream server with timeout control
/// Returns the response and the body size in bytes for metrics
///
/// This function uses a connection pool to reuse connections for the same SNI,
/// enabling keepalive and avoiding repeated TLS handshakes.
pub async fn forward_http_request(
    pool: &ConnectionPool,
    upstream_uri: &str,
    target_hostname: &str,
    method: Method,
    headers: &hyper::HeaderMap,
    body: Bytes,
    timeout: Duration,
) -> Result<(Response<Full<Bytes>>, u64)> {
    // Get or create a client for this SNI (target_hostname)
    // This ensures connection reuse for the same target
    let client = pool.get_client(target_hostname)?;
    let mut req = Request::builder()
        .method(method.clone())
        .uri(upstream_uri)
        .body(Full::new(body.clone()))
        .with_context(|| {
            format!(
                "Failed to build HTTP request: {} {} (target: {})",
                method, upstream_uri, target_hostname
            )
        })?;

    // A rewritten target is a distinct HTTP authority.  Never forward
    // credentials, cookies, forwarding headers, or connection-specific state
    // across that boundary; DoH only needs content negotiation metadata.
    let allowed_headers = ["accept", "content-type"];
    for (key, value) in headers {
        if allowed_headers.contains(&key.as_str()) {
            req.headers_mut().insert(key, value.clone());
        }
    }

    req.headers_mut().insert(
        "host",
        target_hostname
            .parse()
            .with_context(|| format!("Invalid target hostname: {}", target_hostname))?,
    );

    debug!(
        "Sending {} request to upstream: {} (Host: {}, SNI: {})",
        method, upstream_uri, target_hostname, target_hostname
    );

    // Add timeout control to prevent hanging requests
    // The client from the pool will reuse existing connections when possible
    let request_future = client.request(req);
    let timeout_future = tokio::time::timeout(timeout, request_future);

    match timeout_future.await {
        Ok(Ok(resp)) => {
            let status = resp.status();
            let (parts, body) = resp.into_parts();

            debug!(
                "Received response from upstream: {} {}",
                status, upstream_uri
            );

            let body_bytes = collect_body_with_progress(
                body,
                timeout,
                &format!("Upstream response body for {upstream_uri}"),
            )
            .await?;

            let body_size = body_bytes.len() as u64;
            debug!("Response body size: {} bytes", body_size);

            if status.is_success() {
                let content_type = parts
                    .headers
                    .get(hyper::header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok());
                if !is_dns_message_content_type(content_type) {
                    anyhow::bail!(
                        "HTTP upstream response for {} is successful but not application/dns-message",
                        upstream_uri
                    );
                }
                validate_dns_message(&body_bytes, "HTTP upstream DNS response").with_context(
                    || format!("HTTP upstream response for {} is malformed", upstream_uri),
                )?;
            } else {
                warn!(
                    "Upstream returned non-success status: {} {} (body: {} bytes)",
                    status, upstream_uri, body_size
                );
            }

            Ok((
                Response::from_parts(parts, Full::new(body_bytes)),
                body_size,
            ))
        }
        Ok(Err(e)) => {
            error!(
                "HTTP upstream request failed: {} {} -> {} (target: {})",
                method, upstream_uri, e, target_hostname
            );

            // Return a proper error response instead of panicking
            let error_msg = format!("Upstream error: {}", e);
            let error_body = Full::new(error_msg.clone().into());
            let error_size = error_msg.len() as u64;
            Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(error_body)
                .map(|resp| (resp, error_size))
                .with_context(|| {
                    format!(
                        "Failed to create error response for upstream failure: {}",
                        upstream_uri
                    )
                })
        }
        Err(_) => {
            error!(
                "HTTP upstream request timeout: {} {} (target: {}, timeout: {:?})",
                method, upstream_uri, target_hostname, timeout
            );

            // Return timeout error response
            let error_msg = format!("Upstream timeout after {:?}", timeout);
            let error_body = Full::new(error_msg.clone().into());
            let error_size = error_msg.len() as u64;
            Response::builder()
                .status(StatusCode::GATEWAY_TIMEOUT)
                .body(error_body)
                .map(|resp| (resp, error_size))
                .with_context(|| {
                    format!(
                        "Failed to create timeout response for upstream: {}",
                        upstream_uri
                    )
                })
        }
    }
}
