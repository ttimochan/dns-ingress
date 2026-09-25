use crate::config::AppConfig;
use crate::error::DnsProxyResult;
use crate::metrics::Metrics;
use crate::proxy::handle_http_request;
use crate::rewrite::SniRewriterType;
use crate::upstream::create_connection_pool_with_limit;
use crate::upstream::pool::ConnectionPool;
use crate::utils::backoff::BackoffCounter;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoBuilder;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, oneshot};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

pub struct DoHServer {
    config: Arc<AppConfig>,
    rewriter: SniRewriterType,
    pool: Arc<ConnectionPool>,
    backoff: Arc<BackoffCounter>,
    metrics: Arc<Metrics>,
}

impl DoHServer {
    pub fn new(config: Arc<AppConfig>, rewriter: SniRewriterType, metrics: Arc<Metrics>) -> Self {
        let max_upstream_pool_entries = config.limits.max_upstream_pool_entries;
        Self {
            config,
            rewriter,
            pool: create_connection_pool_with_limit(max_upstream_pool_entries),
            backoff: Arc::new(BackoffCounter::new()),
            metrics,
        }
    }

    /// Standalone entry point retained for reader-level tests. Applications
    /// should use `run` so startup and shutdown are supervised by `App`.
    #[allow(dead_code)]
    pub async fn start(&self) -> DnsProxyResult<()> {
        self.run(CancellationToken::new(), None).await
    }

    pub async fn run(
        &self,
        shutdown: CancellationToken,
        ready: Option<oneshot::Sender<DnsProxyResult<()>>>,
    ) -> DnsProxyResult<()> {
        let server_config = &self.config.servers.doh;
        if !server_config.enabled {
            info!("DoH server is disabled");
            return Ok(());
        }

        let bind_addr = format!("{}:{}", server_config.bind_address, server_config.port);
        let listener = match TcpListener::bind(&bind_addr).await {
            Ok(listener) => listener,
            Err(error) => {
                let kind = error.kind();
                let message = error.to_string();
                if let Some(sender) = ready {
                    let _ = sender.send(Err(crate::error::DnsProxyError::Io(std::io::Error::new(
                        kind,
                        message.clone(),
                    ))));
                }
                return Err(crate::error::DnsProxyError::Io(std::io::Error::new(
                    kind, message,
                )));
            }
        };
        let mut tls_config = crate::tls_utils::create_server_config(self.config.as_ref())
            .await
            .map_err(|e| crate::error::DnsProxyError::Tls(e.to_string()))?;
        tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(tls_config));

        info!("DoH server listening on TCP {}", bind_addr);

        let rewriter = Arc::clone(&self.rewriter);
        let pool = Arc::clone(&self.pool);
        let metrics = Arc::clone(&self.metrics);
        let endpoint = self.config.upstream.doh.clone();
        let request_path = self.config.servers.doh.path.clone();
        let connection_limit = Arc::new(Semaphore::new(
            self.config.limits.max_connections_per_listener,
        ));
        let max_inflight = self.config.limits.max_inflight_requests_per_connection;
        let transaction_timeout =
            std::time::Duration::from_secs(self.config.limits.transaction_timeout_seconds);
        if let Some(sender) = ready {
            let _ = sender.send(Ok(()));
        }

        loop {
            let accepted = tokio::select! {
                _ = shutdown.cancelled() => break,
                accepted = listener.accept() => accepted,
            };
            match accepted {
                Ok((stream, addr)) => {
                    let permit = match Arc::clone(&connection_limit).acquire_owned().await {
                        Ok(permit) => permit,
                        Err(_) => break,
                    };
                    let rewriter = Arc::clone(&rewriter);
                    let pool = Arc::clone(&pool);
                    let metrics = Arc::clone(&metrics);
                    let acceptor = acceptor.clone();
                    let endpoint = endpoint.clone();
                    let request_path = request_path.clone();
                    let shutdown = shutdown.clone();
                    tokio::spawn(async move {
                        let _connection_permit = permit;
                        let tls_stream = match acceptor.accept(stream).await {
                            Ok(stream) => stream,
                            Err(e) => {
                                error!("DoH TLS handshake error from {}: {}", addr, e);
                                return;
                            }
                        };
                        let tls_sni = match tls_stream.get_ref().1.server_name() {
                            Some(sni) => sni.to_ascii_lowercase(),
                            None => {
                                error!("DoH connection from {} has no TLS SNI", addr);
                                return;
                            }
                        };
                        let io = TokioIo::new(tls_stream);
                        let request_limit = Arc::new(Semaphore::new(max_inflight));
                        let service = service_fn(move |req| {
                            let rewriter = Arc::clone(&rewriter);
                            let pool = Arc::clone(&pool);
                            let metrics = Arc::clone(&metrics);
                            let endpoint = endpoint.clone();
                            let request_path = request_path.clone();
                            let tls_sni = tls_sni.clone();
                            let client_addr = addr;
                            let request_limit = Arc::clone(&request_limit);
                            let transaction_timeout = transaction_timeout;
                            async move {
                                let _request_permit = request_limit.acquire_owned().await.expect(
                                    "request semaphore remains open while DoH connection runs",
                                );
                                let response = handle_http_request(
                                    req,
                                    rewriter,
                                    &pool,
                                    metrics,
                                    &endpoint,
                                    &request_path,
                                    &tls_sni,
                                    transaction_timeout,
                                )
                                .await;
                                tracing::debug!("DoH request handled for {}", client_addr);
                                Ok::<_, std::convert::Infallible>(response)
                            }
                        });

                        let builder = AutoBuilder::new(TokioExecutor::new());
                        let connection = builder.serve_connection(io, service);
                        let result = tokio::select! {
                            _ = shutdown.cancelled() => Ok(()),
                            result = connection => result,
                        };
                        if let Err(e) = result {
                            error!("DoH connection error from {}: {}", addr, e);
                        } else {
                            tracing::debug!("DoH connection from {} completed", addr);
                        }
                    });
                }
                Err(e) => {
                    error!("DoH accept error on {}: {}", bind_addr, e);
                    // Use exponential backoff to prevent tight error loop
                    let delay = self.backoff.next_delay(100, 5000);
                    tokio::time::sleep(delay).await;
                }
            }
        }
        Ok(())
    }
}
