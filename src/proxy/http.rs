use crate::config::HttpUpstreamConfig;
use crate::metrics::{Metrics, Timer};
use crate::rewrite::SniRewriterType;
use crate::sni::SniRewriter;
use crate::upstream::http::forward_http_request;
use crate::upstream::pool::ConnectionPool;
use anyhow::{Context, Result};
use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Limited};
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode};
use std::sync::Arc;
use tracing::{debug, info};

const DNS_MESSAGE_MEDIA_TYPE: &str = "application/dns-message";
pub(crate) const MAX_DNS_MESSAGE_SIZE: usize = u16::MAX as usize;

/// Validate the wire representation shared by DoH over TCP and HTTP/3.
/// DNS messages always contain the twelve-octet DNS header; accepting a
/// syntactically-valid base64 value alone would forward malformed requests.
pub(crate) fn validate_dns_message(message: &[u8], context: &str) -> Result<()> {
    if !(12..=MAX_DNS_MESSAGE_SIZE).contains(&message.len()) {
        anyhow::bail!("{context} must contain one DNS message between 12 and 65535 bytes");
    }
    Ok(())
}

pub(crate) fn is_dns_message_content_type(value: Option<&str>) -> bool {
    value
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case(DNS_MESSAGE_MEDIA_TYPE))
}

pub(crate) fn validate_doh_get_query(uri: &hyper::Uri, protocol: &str) -> Result<()> {
    let dns_parameter = uri.query().and_then(|query| {
        query.split('&').find_map(|parameter| {
            let (name, value) = parameter.split_once('=')?;
            (name == "dns").then_some(value)
        })
    });
    let dns_parameter = dns_parameter.ok_or_else(|| {
        anyhow::anyhow!("{protocol} GET requests require a non-empty dns query parameter")
    })?;
    if dns_parameter.is_empty() {
        anyhow::bail!("{protocol} dns query parameter must be unpadded base64url");
    }
    let message = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(dns_parameter)
        .map_err(|_| {
            anyhow::anyhow!("{protocol} dns query parameter must be unpadded base64url")
        })?;
    validate_dns_message(&message, &format!("{protocol} GET dns query parameter"))
}

/// Handle HTTP request with SNI rewriting and upstream forwarding
#[allow(clippy::too_many_arguments)] // request context is supplied by the TLS connection
pub async fn handle_http_request(
    req: Request<Incoming>,
    rewriter: SniRewriterType,
    pool: &ConnectionPool,
    metrics: Arc<Metrics>,
    endpoint: &HttpUpstreamConfig,
    request_path: &str,
    tls_sni: &str,
    transaction_timeout: std::time::Duration,
) -> Response<http_body_util::Full<hyper::body::Bytes>> {
    match handle_http_request_inner(
        req,
        rewriter,
        pool,
        metrics,
        endpoint,
        request_path,
        tls_sni,
        transaction_timeout,
    )
    .await
    {
        Ok(response) => response,
        Err(error) => doh_error_response(&error.to_string()),
    }
}

#[allow(clippy::too_many_arguments)] // internal counterpart keeps public behavior simple
async fn handle_http_request_inner(
    req: Request<Incoming>,
    rewriter: SniRewriterType,
    pool: &ConnectionPool,
    metrics: Arc<Metrics>,
    endpoint: &HttpUpstreamConfig,
    request_path: &str,
    tls_sni: &str,
    transaction_timeout: std::time::Duration,
) -> Result<Response<http_body_util::Full<hyper::body::Bytes>>> {
    let timer = Timer::start();
    let method = req.method().clone();
    let uri = req.uri().clone();

    if uri.path() != request_path {
        anyhow::bail!("DoH request path must be {}", request_path);
    }

    let host = req
        .headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .map(str::to_owned)
        .or_else(|| {
            req.uri()
                .authority()
                .map(|authority| authority.as_str().to_owned())
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Missing or invalid Host header in {} request to {}",
                method,
                uri
            )
        })
        .context("Failed to extract Host header from request")?;
    let host = crate::utils::normalize_hostname(&host)
        .ok_or_else(|| anyhow::anyhow!("Invalid DoH Host header"))?;
    if host != tls_sni {
        anyhow::bail!("DoH Host ({}) does not match TLS SNI ({})", host, tls_sni);
    }
    if method != Method::GET && method != Method::POST {
        anyhow::bail!("DoH only supports GET and POST");
    }

    if method == Method::GET {
        validate_doh_get_query(&uri, "DoH")?;
    } else {
        let content_type = req
            .headers()
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok());
        if !is_dns_message_content_type(content_type) {
            anyhow::bail!("DoH POST Content-Type must be application/dns-message");
        }
    }

    debug!("Processing {} request for host: {}", method, host);

    let rewrite_result = rewriter
        .rewrite(&host)
        .await
        .ok_or_else(|| {
            anyhow::anyhow!(
                "SNI rewrite failed for hostname: {} (no matching base domain found)",
                host
            )
        })
        .context("SNI rewrite operation failed")?;

    // Record SNI rewrite
    metrics.record_sni_rewrite();

    info!(
        "HTTP request: {} {} -> SNI rewrite: {} -> {} -> Target: {}",
        method,
        uri.path(),
        rewrite_result.original,
        rewrite_result.prefix,
        rewrite_result.target_hostname
    );

    // Build upstream URI without unnecessary allocation
    let query = req
        .uri()
        .query()
        .map(|query| format!("?{}", query))
        .unwrap_or_default();

    let upstream_uri = format!(
        "https://{}:{}{}{}",
        rewrite_result.target_hostname, endpoint.port, endpoint.path, query
    );

    debug!("Forwarding request to upstream: {}", upstream_uri);

    // Extract headers before consuming request
    let headers = req.headers().clone();

    // Extract body if POST (zerocopy: reuse bytes when possible)
    let body = if method == Method::POST {
        Limited::new(req.into_body(), MAX_DNS_MESSAGE_SIZE)
            .collect()
            .await
            .map_err(|error| {
                anyhow::anyhow!(
                    "DoH request body exceeds the DNS message limit or could not be read: {error}"
                )
            })?
            .to_bytes()
    } else {
        Bytes::new()
    };

    if method == Method::POST {
        validate_dns_message(&body, "DoH POST body")?;
    }

    debug!("Request body size: {} bytes", body.len());

    let bytes_received = body.len() as u64;

    // Forward request using connection pool for connection reuse
    let result = forward_http_request(
        pool,
        &upstream_uri,
        &rewrite_result.target_hostname,
        method,
        &headers,
        body,
        transaction_timeout,
    )
    .await;

    let duration = timer.elapsed();

    // Record metrics and extract response
    match result {
        Ok((response, bytes_sent)) => {
            let success = response.status().is_success();
            metrics.record_request(success, bytes_received, bytes_sent, duration);
            if !success {
                metrics.record_upstream_error();
            }
            Ok(response)
        }
        Err(e) => {
            debug!("HTTP request failed: {}", e);
            metrics.record_request(false, bytes_received, 0, duration);
            metrics.record_upstream_error();
            Err(e).with_context(|| {
                format!(
                    "Failed to forward HTTP request to upstream: {}",
                    upstream_uri
                )
            })
        }
    }
}

fn doh_error_response(message: &str) -> Response<http_body_util::Full<hyper::body::Bytes>> {
    let status = if message.contains("request path") {
        StatusCode::NOT_FOUND
    } else if message.contains("only supports GET and POST") {
        StatusCode::METHOD_NOT_ALLOWED
    } else if message.contains("Content-Type") {
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    } else if message.contains("exceeds the DNS message limit") || message.contains("65535 bytes") {
        StatusCode::PAYLOAD_TOO_LARGE
    } else if message.contains("Failed to forward HTTP request to upstream")
        || message.contains("upstream response")
    {
        StatusCode::BAD_GATEWAY
    } else {
        StatusCode::BAD_REQUEST
    };
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(http_body_util::Full::new(hyper::body::Bytes::from(
            message.to_string(),
        )))
        .expect("static DoH error response is valid")
}

#[cfg(test)]
mod tests {
    use super::{validate_dns_message, validate_doh_get_query};

    #[test]
    fn get_dns_parameter_requires_decodable_dns_wire_message() {
        let valid = hyper::Uri::from_static("/dns-query?dns=AAAAAAAAAAAAAAAA");
        assert!(validate_doh_get_query(&valid, "DoH").is_ok());

        let malformed = hyper::Uri::from_static("/dns-query?dns=not%2Bbase64");
        assert!(validate_doh_get_query(&malformed, "DoH").is_err());
        assert!(validate_dns_message(&[0; 11], "test").is_err());
    }
}
