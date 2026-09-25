use crate::config::HttpUpstreamConfig;
use crate::metrics::{Metrics, Timer};
use crate::rewrite::SniRewriterType;
use crate::sni::SniRewriter;
use crate::upstream::http::forward_http_request;
use crate::upstream::pool::ConnectionPool;
use anyhow::{Context, Result};
use base64::Engine;
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::{Method, Request, Response, StatusCode};
use std::sync::Arc;
use tracing::{debug, info};

const DNS_MESSAGE_MEDIA_TYPE: &str = "application/dns-message";
pub(crate) const MAX_DNS_MESSAGE_SIZE: usize = u16::MAX as usize;

#[derive(Debug, thiserror::Error)]
pub(crate) enum BodyCollectionError {
    #[error("{operation} stalled without progress")]
    Stalled { operation: String },
    #[error("{operation} exceeds the DNS message limit")]
    TooLarge { operation: String },
    #[error("{operation} could not be read: {reason}")]
    Read { operation: String, reason: String },
}

#[derive(Debug)]
enum DohHttpError {
    BadRequest,
    NotFound,
    MethodNotAllowed,
    UnsupportedMediaType,
    PayloadTooLarge,
    RequestTimeout,
    GatewayTimeout,
    BadGateway,
}

impl From<anyhow::Error> for DohHttpError {
    fn from(error: anyhow::Error) -> Self {
        let _ = error;
        Self::BadRequest
    }
}

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

/// Collect a bounded HTTP body while resetting the deadline after each frame.
/// `transaction_timeout_seconds` is a no-progress limit, not a total transfer
/// duration: a slow peer that keeps delivering DNS payload bytes may finish.
pub(crate) async fn collect_body_with_progress(
    mut body: Incoming,
    timeout: std::time::Duration,
    operation: &str,
) -> std::result::Result<Bytes, BodyCollectionError> {
    let mut collected = Vec::new();
    loop {
        let frame = tokio::time::timeout(timeout, body.frame())
            .await
            .map_err(|_| BodyCollectionError::Stalled {
                operation: operation.to_string(),
            })?;
        let Some(frame) = frame else { break };
        let frame = frame.map_err(|error| BodyCollectionError::Read {
            operation: operation.to_string(),
            reason: error.to_string(),
        })?;
        if let Ok(data) = frame.into_data() {
            let remaining = MAX_DNS_MESSAGE_SIZE.saturating_sub(collected.len());
            if data.len() > remaining {
                return Err(BodyCollectionError::TooLarge {
                    operation: operation.to_string(),
                });
            }
            collected.extend_from_slice(&data);
        }
    }
    Ok(Bytes::from(collected))
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
        Err(error) => {
            debug!(?error, "DoH request rejected");
            doh_error_response(error)
        }
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
) -> std::result::Result<Response<http_body_util::Full<hyper::body::Bytes>>, DohHttpError> {
    let timer = Timer::start();
    let method = req.method().clone();
    let uri = req.uri().clone();

    if uri.path() != request_path {
        return Err(DohHttpError::NotFound);
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
        return Err(DohHttpError::BadRequest);
    }
    if method != Method::GET && method != Method::POST {
        return Err(DohHttpError::MethodNotAllowed);
    }

    if method == Method::GET {
        validate_doh_get_query(&uri, "DoH")?;
    } else {
        let content_type = req
            .headers()
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok());
        if !is_dns_message_content_type(content_type) {
            return Err(DohHttpError::UnsupportedMediaType);
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
        collect_body_with_progress(req.into_body(), transaction_timeout, "DoH request body")
            .await
            .map_err(|error| match error {
                BodyCollectionError::Stalled { .. } => DohHttpError::RequestTimeout,
                BodyCollectionError::TooLarge { .. } => DohHttpError::PayloadTooLarge,
                BodyCollectionError::Read { .. } => DohHttpError::BadRequest,
            })?
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
            if matches!(
                e.downcast_ref::<BodyCollectionError>(),
                Some(BodyCollectionError::Stalled { .. })
            ) {
                Err(DohHttpError::GatewayTimeout)
            } else {
                Err(DohHttpError::BadGateway)
            }
        }
    }
}

fn doh_error_response(error: DohHttpError) -> Response<http_body_util::Full<hyper::body::Bytes>> {
    let (status, message, allow) = match error {
        DohHttpError::BadRequest => (StatusCode::BAD_REQUEST, "invalid DoH request", None),
        DohHttpError::NotFound => (StatusCode::NOT_FOUND, "DoH endpoint not found", None),
        DohHttpError::MethodNotAllowed => (
            StatusCode::METHOD_NOT_ALLOWED,
            "method not allowed",
            Some("GET, POST"),
        ),
        DohHttpError::UnsupportedMediaType => (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Content-Type must be application/dns-message",
            None,
        ),
        DohHttpError::PayloadTooLarge => (
            StatusCode::PAYLOAD_TOO_LARGE,
            "DNS message exceeds 65535 bytes",
            None,
        ),
        DohHttpError::RequestTimeout => {
            (StatusCode::REQUEST_TIMEOUT, "request body timed out", None)
        }
        DohHttpError::GatewayTimeout => (StatusCode::GATEWAY_TIMEOUT, "upstream timed out", None),
        DohHttpError::BadGateway => (StatusCode::BAD_GATEWAY, "upstream request failed", None),
    };
    let mut builder = Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8");
    if let Some(allow) = allow {
        builder = builder.header(hyper::header::ALLOW, allow);
    }
    builder
        .body(http_body_util::Full::new(hyper::body::Bytes::from(message)))
        .expect("static DoH error response is valid")
}

#[cfg(test)]
mod tests {
    use super::{DohHttpError, doh_error_response, validate_dns_message, validate_doh_get_query};
    use hyper::StatusCode;

    #[test]
    fn get_dns_parameter_requires_decodable_dns_wire_message() {
        let valid = hyper::Uri::from_static("/dns-query?dns=AAAAAAAAAAAAAAAA");
        assert!(validate_doh_get_query(&valid, "DoH").is_ok());

        let malformed = hyper::Uri::from_static("/dns-query?dns=not%2Bbase64");
        assert!(validate_doh_get_query(&malformed, "DoH").is_err());
        assert!(validate_dns_message(&[0; 11], "test").is_err());
    }

    #[test]
    fn typed_errors_have_stable_http_semantics() {
        let not_found = doh_error_response(DohHttpError::NotFound);
        assert_eq!(not_found.status(), StatusCode::NOT_FOUND);

        let method = doh_error_response(DohHttpError::MethodNotAllowed);
        assert_eq!(method.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(method.headers()[hyper::header::ALLOW], "GET, POST");

        assert_eq!(
            doh_error_response(DohHttpError::RequestTimeout).status(),
            StatusCode::REQUEST_TIMEOUT
        );
        assert_eq!(
            doh_error_response(DohHttpError::GatewayTimeout).status(),
            StatusCode::GATEWAY_TIMEOUT
        );
    }
}
