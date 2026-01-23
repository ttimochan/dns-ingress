use crate::config::AppConfig;
use crate::error::{DnsProxyError, DnsProxyResult};
use crate::metrics::{Metrics, Timer};
use crate::rewrite::SniRewriterType;
use crate::tls_utils;
use crate::utils::backoff::BackoffCounter;
use rustls::pki_types::ServerName;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{error, info};

pub struct DoTServer {
    config: Arc<AppConfig>,
    rewriter: SniRewriterType,
    backoff: Arc<BackoffCounter>,
    metrics: Arc<Metrics>,
}

impl DoTServer {
    pub fn new(config: Arc<AppConfig>, rewriter: SniRewriterType, metrics: Arc<Metrics>) -> Self {
        Self {
            config,
            rewriter,
            backoff: Arc::new(BackoffCounter::new()),
            metrics,
        }
    }

    pub async fn start(&self) -> DnsProxyResult<()> {
        let server_config = &self.config.servers.dot;
        if !server_config.enabled {
            info!("DoT server is disabled");
            return Ok(());
        }

        let server_tls_config = tls_utils::create_server_config(self.config.as_ref())
            .await
            .map_err(|e| DnsProxyError::Tls(e.to_string()))?;
        let acceptor = TlsAcceptor::from(Arc::new(server_tls_config));

        let bind_addr = format!("{}:{}", server_config.bind_address, server_config.port);
        let listener = TcpListener::bind(&bind_addr).await?;

        info!("DoT server listening on TCP {}", bind_addr);

        let upstream = self
            .config
            .dot_upstream()
            .map_err(|e| DnsProxyError::Config(e.to_string()))?;
        let upstream_hostname = self.config.dot_upstream_hostname();
        let rewriter = Arc::clone(&self.rewriter);

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    info!("New DoT connection from {}", addr);
                    let acceptor = acceptor.clone();
                    let rewriter = Arc::clone(&rewriter);
                    let upstream_addr = upstream;
                    let upstream_host = upstream_hostname.clone();
                    let metrics = Arc::clone(&self.metrics);
                    tokio::spawn(async move {
                        match acceptor.accept(stream).await {
                            Ok(tls_stream) => {
                                if let Err(e) = Self::handle_connection(
                                    tls_stream,
                                    rewriter,
                                    upstream_addr,
                                    &upstream_host,
                                    metrics,
                                )
                                .await
                                {
                                    error!("DoT connection handling error from {}: {}", addr, e);
                                } else {
                                    tracing::debug!(
                                        "DoT connection from {} completed successfully",
                                        addr
                                    );
                                }
                            }
                            Err(e) => {
                                error!("DoT TLS handshake error from {}: {}", addr, e);
                            }
                        }
                    });
                }
                Err(e) => {
                    error!("DoT accept error on {}: {}", bind_addr, e);
                    let delay = self.backoff.next_delay(100, 5000);
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }

    async fn handle_connection(
        stream: tokio_rustls::server::TlsStream<TcpStream>,
        _rewriter: SniRewriterType,
        upstream: std::net::SocketAddr,
        upstream_hostname: &str,
        metrics: Arc<Metrics>,
    ) -> DnsProxyResult<()> {
        use tracing::debug;

        let timer = Timer::start();
        let (mut reader, mut writer) = tokio::io::split(stream);

        // Read DNS message from client (zerocopy: use Bytes directly)
        let mut buffer = Vec::with_capacity(4096);
        reader.read_to_end(&mut buffer).await?;

        if buffer.is_empty() {
            debug!("Received empty DNS message, closing connection");
            return Ok(());
        }

        let bytes_received = buffer.len() as u64;

        debug!(
            "Received DNS message: {} bytes, forwarding to upstream {} (SNI: {})",
            bytes_received, upstream, upstream_hostname
        );

        // Connect to upstream
        let upstream_stream = TcpStream::connect(upstream).await.map_err(|e| {
            DnsProxyError::Upstream(crate::error::UpstreamError::ConnectionFailed {
                upstream: upstream.to_string(),
                reason: format!("Failed to connect: {}", e),
            })
        })?;

        let client_config =
            create_client_config().map_err(|e| DnsProxyError::Tls(e.to_string()))?;
        let connector = TlsConnector::from(Arc::new(client_config));
        let sni_name = ServerName::try_from(upstream_hostname.to_string()).map_err(|e| {
            DnsProxyError::InvalidInput(format!(
                "Failed to create ServerName for upstream connection: {}",
                e
            ))
        })?;

        let upstream_tls = connector
            .connect(sni_name, upstream_stream)
            .await
            .map_err(|e| {
                DnsProxyError::Upstream(crate::error::UpstreamError::ConnectionFailed {
                    upstream: upstream.to_string(),
                    reason: format!("Failed to establish TLS connection: {}", e),
                })
            })?;
        let (mut up_reader, mut up_writer) = tokio::io::split(upstream_tls);

        // Forward message (zerocopy: use slice reference)
        up_writer.write_all(&buffer).await?;
        up_writer.flush().await?;

        // Read response (zerocopy: reuse buffer)
        buffer.clear();
        buffer.reserve(4096);
        up_reader.read_to_end(&mut buffer).await?;

        debug!(
            "Received DNS response: {} bytes, sending to client",
            buffer.len()
        );

        // Send response back (zerocopy: use slice reference)
        let bytes_sent = buffer.len() as u64;
        writer.write_all(&buffer).await?;
        writer.flush().await?;

        // Record metrics
        let duration = timer.elapsed();
        metrics.record_request(true, bytes_received, bytes_sent, duration);

        Ok(())
    }
}

/// Create TLS client configuration for upstream connections
/// Uses system root certificates for proper TLS verification
fn create_client_config() -> DnsProxyResult<rustls::ClientConfig> {
    let mut root_store = rustls::RootCertStore::empty();

    // Load system root certificates
    let cert_result = rustls_native_certs::load_native_certs();
    for cert in cert_result.certs {
        root_store.add(cert).map_err(|e| {
            DnsProxyError::Certificate(crate::error::CertificateError::LoadFailed {
                path: "system".to_string(),
                reason: format!("Failed to add root certificate: {}", e),
            })
        })?;
    }

    Ok(rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth())
}
