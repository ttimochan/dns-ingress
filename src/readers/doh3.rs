use crate::config::AppConfig;
use crate::error::{DnsProxyError, DnsProxyResult};
use crate::metrics::{Metrics, Timer};
use crate::proxy::http::{
    is_dns_message_content_type, validate_dns_message, validate_doh_get_query,
};
use crate::quic::{QuicApplication, create_quic_server_endpoint};
use crate::rewrite::SniRewriterType;
use crate::sni::SniRewriter;
use crate::tasks::TaskGroup;
use crate::upstream::Http3ConnectionPool;
use crate::upstream::forward_http3_request;
use bytes::{Buf, Bytes};
use h3::server::Connection as H3ServerConnection;
use http_body_util::BodyExt;
use hyper::Method;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{Semaphore, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info};

const MAX_DNS_MESSAGE_SIZE: usize = u16::MAX as usize;

pub struct DoH3Server {
    config: Arc<AppConfig>,
    rewriter: SniRewriterType,
    metrics: Arc<Metrics>,
    pool: Arc<Http3ConnectionPool>,
    tasks: TaskGroup,
}

impl DoH3Server {
    #[allow(dead_code)] // retained for standalone reader construction
    pub fn new(config: Arc<AppConfig>, rewriter: SniRewriterType, metrics: Arc<Metrics>) -> Self {
        let root_store =
            crate::tls_utils::load_upstream_root_store(config.tls.upstream_ca_file.as_deref())
                .expect("standalone DoH3 server requires a valid upstream trust store");
        Self::with_root_store(config, rewriter, metrics, root_store)
    }

    pub(crate) fn with_root_store(
        config: Arc<AppConfig>,
        rewriter: SniRewriterType,
        metrics: Arc<Metrics>,
        root_store: Arc<rustls::RootCertStore>,
    ) -> Self {
        Self {
            pool: Arc::new(Http3ConnectionPool::with_root_store(
                config.limits.max_upstream_pool_entries,
                root_store,
            )),
            config,
            rewriter,
            metrics,
            tasks: TaskGroup::default(),
        }
    }

    pub(crate) fn task_group(&self) -> TaskGroup {
        self.tasks.clone()
    }

    #[allow(dead_code)]
    pub async fn start(&self) -> DnsProxyResult<()> {
        self.run(CancellationToken::new(), None).await
    }

    pub async fn run(
        &self,
        shutdown: CancellationToken,
        ready: Option<oneshot::Sender<DnsProxyResult<()>>>,
    ) -> DnsProxyResult<()> {
        let server_config = &self.config.servers.doh3;
        if !server_config.enabled {
            info!("DoH3 server is disabled");
            return Ok(());
        }

        let bind_addr = format!("{}:{}", server_config.bind_address, server_config.port);
        let addr: SocketAddr = bind_addr
            .parse()
            .map_err(|e| DnsProxyError::InvalidInput(format!("Invalid bind address: {}", e)))?;

        let endpoint = match create_quic_server_endpoint(
            self.config.as_ref(),
            addr,
            QuicApplication::H3,
        )
        .await
        {
            Ok(endpoint) => endpoint,
            Err(error) => {
                if let Some(sender) = ready {
                    let _ = sender.send(Err(DnsProxyError::Protocol(error.to_string())));
                }
                return Err(error.into());
            }
        };
        info!("DoH3 server listening on UDP {}", addr);

        let rewriter = Arc::clone(&self.rewriter);
        let metrics = Arc::clone(&self.metrics);
        let upstream_endpoint = self.config.upstream.doh3.clone();
        let request_path = self.config.servers.doh3.path.clone();
        let pool = Arc::clone(&self.pool);
        let max_streams = self.config.limits.max_inflight_requests_per_connection;
        let transaction_timeout =
            std::time::Duration::from_secs(self.config.limits.transaction_timeout_seconds);
        let connection_limit = Arc::new(Semaphore::new(
            self.config.limits.max_connections_per_listener,
        ));
        if let Some(sender) = ready {
            let _ = sender.send(Ok(()));
        }

        loop {
            let conn = tokio::select! {
                _ = shutdown.cancelled() => break,
                conn = endpoint.accept() => conn,
            };
            let Some(conn) = conn else { break };
            let permit = tokio::select! {
                _ = shutdown.cancelled() => break,
                permit = Arc::clone(&connection_limit).acquire_owned() => match permit {
                    Ok(permit) => permit,
                    Err(_) => break,
                },
            };
            let rewriter = Arc::clone(&rewriter);
            let metrics = Arc::clone(&metrics);
            let endpoint = upstream_endpoint.clone();
            let request_path = request_path.clone();
            let pool = Arc::clone(&pool);
            let shutdown = shutdown.clone();
            let tasks = self.tasks.clone();
            let connection_tasks = tasks.clone();
            tasks.spawn(async move {
                let _connection_permit = permit;
                let connected = tokio::select! {
                    _ = shutdown.cancelled() => return,
                    connected = tokio::time::timeout(transaction_timeout, conn) => match connected {
                        Ok(connection) => connection,
                        Err(_) => {
                            error!("DoH3 connection handshake timed out");
                            return;
                        }
                    },
                };
                match connected {
                    Ok(connection) => {
                        let remote_addr = connection.remote_address();
                        info!("New DoH3 connection from {}", remote_addr);
                        let metrics_clone = Arc::clone(&metrics);
                        if let Err(e) = Self::handle_connection(
                            connection,
                            rewriter,
                            metrics,
                            endpoint,
                            request_path,
                            max_streams,
                            transaction_timeout,
                            shutdown,
                            pool,
                            connection_tasks,
                        )
                        .await
                        {
                            error!("DoH3 connection handling error from {}: {}", remote_addr, e);
                            metrics_clone.record_upstream_error();
                        } else {
                            debug!(
                                "DoH3 connection from {} completed successfully",
                                remote_addr
                            );
                        }
                    }
                    Err(e) => {
                        error!("DoH3 connection establishment error: {}", e);
                    }
                }
            }).await;
        }

        self.tasks
            .close_and_wait_until(tokio::time::Instant::now() + std::time::Duration::from_secs(10))
            .await;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)] // per-connection runtime dependencies are explicit
    async fn handle_connection(
        connection: quinn::Connection,
        rewriter: SniRewriterType,
        metrics: Arc<Metrics>,
        endpoint: crate::config::HttpUpstreamConfig,
        request_path: String,
        max_streams: usize,
        transaction_timeout: std::time::Duration,
        shutdown: CancellationToken,
        pool: Arc<Http3ConnectionPool>,
        tasks: TaskGroup,
    ) -> DnsProxyResult<()> {
        let tls_sni = connection
            .handshake_data()
            .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
            .and_then(|data| data.server_name.clone())
            .ok_or_else(|| {
                DnsProxyError::InvalidInput("DoH3 requires TLS SNI hostname".to_string())
            })?;
        // Create H3 connection from quinn connection
        let mut conn = tokio::time::timeout(
            transaction_timeout,
            H3ServerConnection::new(h3_quinn::Connection::new(connection)),
        )
        .await
        .map_err(|_| DnsProxyError::Timeout {
            upstream: "DoH3 client control stream".to_string(),
        })?
        .map_err(|e| DnsProxyError::Protocol(format!("Failed to create H3 connection: {}", e)))?;

        let stream_limit = Arc::new(Semaphore::new(max_streams));
        loop {
            let accepted = tokio::select! {
                _ = shutdown.cancelled() => break,
                accepted = conn.accept() => accepted,
            };
            match accepted {
                Ok(Some(resolver)) => {
                    let permit = tokio::select! {
                        _ = shutdown.cancelled() => break,
                        permit = Arc::clone(&stream_limit).acquire_owned() => match permit {
                            Ok(permit) => permit,
                            Err(_) => break,
                        },
                    };
                    let rewriter = Arc::clone(&rewriter);
                    let metrics = Arc::clone(&metrics);
                    let endpoint = endpoint.clone();
                    let request_path = request_path.clone();
                    let tls_sni = tls_sni.clone();
                    let shutdown = shutdown.clone();
                    let pool = Arc::clone(&pool);
                    let request_tasks = tasks.clone();
                    request_tasks
                        .spawn(async move {
                            let _request_permit = permit;
                            // Resolve the request
                            let resolved = tokio::select! {
                                _ = shutdown.cancelled() => return,
                                resolved = resolver.resolve_request() => resolved,
                            };
                            match resolved {
                                Ok((req, stream)) => {
                                    if let Err(e) = Self::handle_request(
                                        req,
                                        stream,
                                        rewriter,
                                        metrics,
                                        endpoint,
                                        &request_path,
                                        &tls_sni,
                                        transaction_timeout,
                                        shutdown,
                                        pool,
                                    )
                                    .await
                                    {
                                        error!("DoH3 request handling error: {}", e);
                                    } else {
                                        debug!("DoH3 request handled successfully");
                                    }
                                }
                                Err(e) => {
                                    error!("DoH3 request resolution error: {}", e);
                                }
                            }
                        })
                        .await;
                }
                Ok(None) => {
                    // Connection closed
                    debug!("DoH3 connection closed by client");
                    break;
                }
                Err(e) => {
                    error!("DoH3 connection accept error: {}", e);
                    break;
                }
            }
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)] // request owns stream plus connection runtime dependencies
    async fn handle_request(
        req: hyper::Request<()>,
        mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
        rewriter: SniRewriterType,
        metrics: Arc<Metrics>,
        endpoint: crate::config::HttpUpstreamConfig,
        request_path: &str,
        tls_sni: &str,
        transaction_timeout: std::time::Duration,
        shutdown: CancellationToken,
        pool: Arc<Http3ConnectionPool>,
    ) -> DnsProxyResult<()> {
        let result = Self::process_request(
            req,
            &mut stream,
            rewriter,
            metrics,
            endpoint,
            request_path,
            tls_sni,
            transaction_timeout,
            shutdown,
            pool,
        )
        .await;
        if let Err(error) = &result {
            let _ = Self::send_error_response(&mut stream, error).await;
        }
        result
    }

    #[allow(clippy::too_many_arguments)] // split to guarantee an HTTP error response on failure
    async fn process_request(
        req: hyper::Request<()>,
        stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
        rewriter: SniRewriterType,
        metrics: Arc<Metrics>,
        endpoint: crate::config::HttpUpstreamConfig,
        request_path: &str,
        tls_sni: &str,
        transaction_timeout: std::time::Duration,
        shutdown: CancellationToken,
        pool: Arc<Http3ConnectionPool>,
    ) -> DnsProxyResult<()> {
        let timer = Timer::start();
        let method = req.method().clone();
        let uri = req.uri().clone();
        info!("New DoH3 request: {} {}", method, uri);

        if uri.path() != request_path {
            return Err(DnsProxyError::InvalidInput(format!(
                "DoH3 request path must be {}",
                request_path
            )));
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
                DnsProxyError::InvalidInput(format!(
                    "Missing or invalid Host header in {} request to {}",
                    method, uri
                ))
            })?;
        let host = crate::utils::normalize_hostname(&host)
            .ok_or_else(|| DnsProxyError::InvalidInput("Invalid DoH3 Host header".to_string()))?;
        if host != tls_sni.to_ascii_lowercase() {
            return Err(DnsProxyError::InvalidInput(
                "DoH3 Host does not match TLS SNI".to_string(),
            ));
        }
        if method != Method::GET && method != Method::POST {
            return Err(DnsProxyError::InvalidInput(
                "DoH3 only supports GET and POST".to_string(),
            ));
        }

        if method == Method::GET {
            validate_doh_get_query(&uri, "DoH3")
                .map_err(|error| DnsProxyError::InvalidInput(error.to_string()))?;
        } else {
            let content_type = req
                .headers()
                .get(hyper::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok());
            if !is_dns_message_content_type(content_type) {
                return Err(DnsProxyError::InvalidInput(
                    "DoH3 POST Content-Type must be application/dns-message".to_string(),
                ));
            }
        }

        debug!("Processing DoH3 request for host: {}", host);

        let rewrite_result = rewriter.rewrite(&host).await.ok_or_else(|| {
            DnsProxyError::SniRewrite(crate::error::SniRewriteError::NoMatchingBaseDomain {
                hostname: host.clone(),
            })
        })?;

        // Record SNI rewrite
        metrics.record_sni_rewrite();

        info!(
            "DoH3 request: {} {} -> SNI rewrite: {} -> {} -> Target: {}",
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

        debug!("Forwarding DoH3 request to upstream: {}", upstream_uri);

        // Read request body if POST (zerocopy where possible)
        let body = if *req.method() == Method::POST {
            let mut body_data = Vec::new();
            loop {
                let received = tokio::select! {
                    _ = shutdown.cancelled() => return Ok(()),
                    received = tokio::time::timeout(transaction_timeout, stream.recv_data()) => match received {
                        Ok(received) => received,
                        Err(_) => return Err(DnsProxyError::Timeout {
                            upstream: "DoH3 request body".to_string(),
                        }),
                    },
                };
                match received {
                    Ok(Some(mut chunk)) => {
                        if body_data.len().saturating_add(chunk.remaining()) > MAX_DNS_MESSAGE_SIZE
                        {
                            return Err(DnsProxyError::InvalidInput(
                                "DoH3 POST body exceeds the DNS message limit".to_string(),
                            ));
                        }
                        while chunk.has_remaining() {
                            body_data.extend_from_slice(chunk.chunk());
                            chunk.advance(chunk.chunk().len());
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        return Err(DnsProxyError::Protocol(format!(
                            "Failed to read DoH3 request body: {}",
                            e
                        )));
                    }
                }
            }
            debug!("Read DoH3 request body: {} bytes", body_data.len());
            Bytes::from(body_data)
        } else {
            Bytes::new()
        };

        let bytes_received = body.len() as u64;

        if method == Method::POST {
            validate_dns_message(&body, "DoH3 POST body")
                .map_err(|error| DnsProxyError::InvalidInput(error.to_string()))?;
        }

        let request = forward_http3_request(
            &upstream_uri,
            &rewrite_result.target_hostname,
            endpoint.port,
            req.method().clone(),
            req.headers(),
            body,
            transaction_timeout,
            &pool,
        );
        let result = tokio::select! {
            _ = shutdown.cancelled() => return Ok(()),
            result = request => result,
        };

        let duration = timer.elapsed();

        let response = match result {
            Ok((resp, bytes_sent)) => {
                let success = resp.status().is_success();
                metrics.record_request(success, bytes_received, bytes_sent, duration);
                if !success {
                    metrics.record_upstream_error();
                }
                resp
            }
            Err(e) => {
                debug!("DoH3 upstream request failed: {}", e);
                metrics.record_request(false, bytes_received, 0, duration);
                metrics.record_upstream_error();
                return Err(DnsProxyError::Upstream(
                    crate::error::UpstreamError::RequestFailed {
                        upstream: upstream_uri,
                        reason: e.to_string(),
                    },
                ));
            }
        };

        debug!("Received response from upstream, sending to DoH3 client");

        // Send response back to client
        let (parts, response_body) = response.into_parts();
        let response_body = response_body
            .collect()
            .await
            .map_err(|e| {
                DnsProxyError::Protocol(format!("Failed to read upstream DoH3 body: {}", e))
            })?
            .to_bytes();
        tokio::time::timeout(
            transaction_timeout,
            stream.send_response(hyper::Response::from_parts(parts, ())),
        )
        .await
        .map_err(|_| DnsProxyError::Timeout {
            upstream: "DoH3 client response headers".to_string(),
        })?
        .map_err(|e| DnsProxyError::Protocol(format!("Failed to send DoH3 response: {}", e)))?;
        tokio::time::timeout(transaction_timeout, stream.send_data(response_body))
            .await
            .map_err(|_| DnsProxyError::Timeout {
                upstream: "DoH3 client response body".to_string(),
            })?
            .map_err(|e| {
                DnsProxyError::Protocol(format!("Failed to send DoH3 response body: {}", e))
            })?;

        tokio::time::timeout(transaction_timeout, stream.finish())
            .await
            .map_err(|_| DnsProxyError::Timeout {
                upstream: "DoH3 client response finish".to_string(),
            })?
            .map_err(|e| {
                DnsProxyError::Protocol(format!("Failed to finish DoH3 response: {}", e))
            })?;

        Ok(())
    }

    async fn send_error_response(
        stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
        error: &DnsProxyError,
    ) -> DnsProxyResult<()> {
        let message = error.to_string();
        let status = if message.contains("request path") {
            hyper::StatusCode::NOT_FOUND
        } else if message.contains("only supports GET and POST") {
            hyper::StatusCode::METHOD_NOT_ALLOWED
        } else if message.contains("Content-Type") {
            hyper::StatusCode::UNSUPPORTED_MEDIA_TYPE
        } else if message.contains("exceeds") || message.contains("65535 bytes") {
            hyper::StatusCode::PAYLOAD_TOO_LARGE
        } else if matches!(error, DnsProxyError::Timeout { .. }) {
            hyper::StatusCode::GATEWAY_TIMEOUT
        } else if matches!(error, DnsProxyError::Overloaded { .. }) {
            hyper::StatusCode::SERVICE_UNAVAILABLE
        } else if matches!(error, DnsProxyError::Upstream(_)) {
            hyper::StatusCode::BAD_GATEWAY
        } else {
            hyper::StatusCode::BAD_REQUEST
        };
        let mut response = hyper::Response::builder()
            .status(status)
            .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(())
            .map_err(|error| DnsProxyError::Protocol(error.to_string()))?;
        if status == hyper::StatusCode::METHOD_NOT_ALLOWED {
            response.headers_mut().insert(
                hyper::header::ALLOW,
                hyper::header::HeaderValue::from_static("GET, POST"),
            );
        }
        stream
            .send_response(response)
            .await
            .map_err(|error| DnsProxyError::Protocol(error.to_string()))?;
        stream
            .send_data(Bytes::from(message))
            .await
            .map_err(|error| DnsProxyError::Protocol(error.to_string()))?;
        stream
            .finish()
            .await
            .map_err(|error| DnsProxyError::Protocol(error.to_string()))
    }
}
