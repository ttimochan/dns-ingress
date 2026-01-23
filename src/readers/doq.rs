use crate::config::AppConfig;
use crate::error::DnsProxyResult;
use crate::metrics::{Metrics, Timer};
use crate::quic::create_quic_server_endpoint;
use crate::rewrite::SniRewriterType;
use crate::upstream::forward_quic_stream;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{error, info};

pub struct DoQServer {
    config: Arc<AppConfig>,
    rewriter: SniRewriterType,
    metrics: Arc<Metrics>,
}

impl DoQServer {
    pub fn new(config: Arc<AppConfig>, rewriter: SniRewriterType, metrics: Arc<Metrics>) -> Self {
        Self {
            config,
            rewriter,
            metrics,
        }
    }

    pub async fn start(&self) -> DnsProxyResult<()> {
        let server_config = &self.config.servers.doq;
        if !server_config.enabled {
            info!("DoQ server is disabled");
            return Ok(());
        }

        let bind_addr = format!("{}:{}", server_config.bind_address, server_config.port);
        let addr: SocketAddr = bind_addr.parse().map_err(|e| {
            crate::error::DnsProxyError::InvalidInput(format!("Invalid bind address: {}", e))
        })?;

        let endpoint = create_quic_server_endpoint(self.config.as_ref(), addr).await?;
        info!("DoQ server listening on UDP {}", addr);

        let upstream = self
            .config
            .doq_upstream()
            .map_err(|e| crate::error::DnsProxyError::Config(e.to_string()))?;
        let upstream_hostname = self.config.dot_upstream_hostname(); // Reuse the same method
        let rewriter = Arc::clone(&self.rewriter);

        let metrics = Arc::clone(&self.metrics);
        while let Some(conn) = endpoint.accept().await {
            let rewriter = Arc::clone(&rewriter);
            let upstream_addr = upstream;
            let upstream_host = upstream_hostname.clone();
            let m = Arc::clone(&metrics);
            tokio::spawn(async move {
                match conn.await {
                    Ok(connection) => {
                        info!("New DoQ connection from {}", connection.remote_address());
                        let remote_addr = connection.remote_address();
                        if let Err(e) = Self::handle_connection(
                            connection,
                            upstream_addr,
                            rewriter,
                            &upstream_host,
                            m,
                        )
                        .await
                        {
                            error!("DoQ connection handling error from {}: {}", remote_addr, e);
                        } else {
                            tracing::debug!(
                                "DoQ connection from {} completed successfully",
                                remote_addr
                            );
                        }
                    }
                    Err(e) => {
                        error!("DoQ connection establishment error: {}", e);
                    }
                }
            });
        }

        Ok(())
    }

    async fn handle_connection(
        connection: quinn::Connection,
        upstream: SocketAddr,
        _rewriter: SniRewriterType,
        upstream_hostname: &str,
        metrics: Arc<Metrics>,
    ) -> DnsProxyResult<()> {
        loop {
            let timer = Timer::start();
            match connection.accept_bi().await {
                Ok((send, recv)) => {
                    // Forward stream using zerocopy where possible
                    let result = forward_quic_stream(send, recv, upstream, upstream_hostname).await;
                    let duration = timer.elapsed();

                    // Estimate bytes (QUIC streams don't easily expose byte counts)
                    // We'll use a reasonable estimate based on typical DNS message sizes
                    let estimated_bytes = 512u64; // Typical DNS query/response size

                    match result {
                        Ok(_) => {
                            tracing::debug!(
                                "DoQ stream forwarded successfully to {} (SNI: {})",
                                upstream,
                                upstream_hostname
                            );
                            metrics.record_request(
                                true,
                                estimated_bytes,
                                estimated_bytes,
                                duration,
                            );
                        }
                        Err(e) => {
                            error!(
                                "DoQ stream forwarding error to upstream {} (SNI: {}): {}",
                                upstream, upstream_hostname, e
                            );
                            metrics.record_request(false, estimated_bytes, 0, duration);
                        }
                    }
                }
                Err(quinn::ConnectionError::ApplicationClosed { .. }) => {
                    info!("DoQ connection closed");
                    break;
                }
                Err(e) => {
                    error!("DoQ stream error: {}", e);
                    break;
                }
            }
        }

        Ok(())
    }
}
