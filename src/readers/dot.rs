use crate::config::AppConfig;
use crate::error::{DnsProxyError, DnsProxyResult};
use crate::metrics::{Metrics, Timer};
use crate::rewrite::SniRewriterType;
use crate::sni::SniRewriter;
use crate::tls_utils;
use crate::utils::backoff::BackoffCounter;
use rustls::pki_types::ServerName;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, oneshot};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::sync::CancellationToken;
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

    #[allow(dead_code)]
    pub async fn start(&self) -> DnsProxyResult<()> {
        self.run(CancellationToken::new(), None).await
    }

    pub async fn run(
        &self,
        shutdown: CancellationToken,
        ready: Option<oneshot::Sender<DnsProxyResult<()>>>,
    ) -> DnsProxyResult<()> {
        let server_config = &self.config.servers.dot;
        if !server_config.enabled {
            info!("DoT server is disabled");
            return Ok(());
        }

        let mut server_tls_config =
            match tls_utils::create_server_config(self.config.as_ref()).await {
                Ok(config) => config,
                Err(error) => {
                    let error = DnsProxyError::Tls(error.to_string());
                    if let Some(sender) = ready {
                        let _ = sender.send(Err(DnsProxyError::Tls(error.to_string())));
                    }
                    return Err(error);
                }
            };
        // RFC 8310 identifies DoT through ALPN "dot".  Rustls still accepts
        // legacy clients that do not offer ALPN, while clients that do offer it
        // negotiate the protocol explicitly.
        server_tls_config.alpn_protocols = vec![b"dot".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(server_tls_config));

        let bind_addr = format!("{}:{}", server_config.bind_address, server_config.port);
        let listener = match TcpListener::bind(&bind_addr).await {
            Ok(listener) => listener,
            Err(error) => {
                let kind = error.kind();
                let message = error.to_string();
                if let Some(sender) = ready {
                    let _ = sender.send(Err(DnsProxyError::Io(std::io::Error::new(
                        kind,
                        message.clone(),
                    ))));
                }
                return Err(DnsProxyError::Io(std::io::Error::new(kind, message)));
            }
        };

        info!("DoT server listening on TCP {}", bind_addr);

        let rewriter = Arc::clone(&self.rewriter);
        let upstream_port = self.config.upstream.dot.port;
        let connection_limit = Arc::new(Semaphore::new(
            self.config.limits.max_connections_per_listener,
        ));
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
                    info!("New DoT connection from {}", addr);
                    let permit = match Arc::clone(&connection_limit).acquire_owned().await {
                        Ok(permit) => permit,
                        Err(_) => break,
                    };
                    let acceptor = acceptor.clone();
                    let rewriter = Arc::clone(&rewriter);
                    let metrics = Arc::clone(&self.metrics);
                    let shutdown = shutdown.clone();
                    tokio::spawn(async move {
                        let _connection_permit = permit;
                        let accepted = tokio::select! {
                            _ = shutdown.cancelled() => return,
                            accepted = acceptor.accept(stream) => accepted,
                        };
                        match accepted {
                            Ok(tls_stream) => {
                                let source_hostname = tls_stream
                                    .get_ref()
                                    .1
                                    .server_name()
                                    .map(str::to_owned)
                                    .ok_or_else(|| {
                                        DnsProxyError::InvalidInput(
                                            "DoT requires a TLS SNI hostname".to_string(),
                                        )
                                    });
                                match source_hostname {
                                    Ok(source_hostname) => {
                                        let handling = Self::handle_connection(
                                            tls_stream,
                                            rewriter,
                                            source_hostname,
                                            upstream_port,
                                            metrics,
                                        );
                                        let result = tokio::select! {
                                            _ = shutdown.cancelled() => Ok(()),
                                            result = handling => result,
                                        };
                                        if let Err(e) = result {
                                            error!(
                                                "DoT connection handling error from {}: {}",
                                                addr, e
                                            );
                                        } else {
                                            tracing::debug!(
                                                "DoT connection from {} completed successfully",
                                                addr
                                            );
                                        }
                                    }
                                    Err(e) => {
                                        error!("DoT connection from {} rejected: {}", addr, e)
                                    }
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
        Ok(())
    }

    async fn handle_connection(
        stream: tokio_rustls::server::TlsStream<TcpStream>,
        rewriter: SniRewriterType,
        source_hostname: String,
        upstream_port: u16,
        metrics: Arc<Metrics>,
    ) -> DnsProxyResult<()> {
        use tracing::debug;

        let timer = Timer::start();
        let target = rewriter
            .rewrite(&source_hostname)
            .await
            .ok_or_else(|| {
                DnsProxyError::SniRewrite(crate::error::SniRewriteError::NoMatchingBaseDomain {
                    hostname: source_hostname.clone(),
                })
            })?
            .target_hostname;
        debug!(
            "Forwarding DoT connection to upstream {}:{}",
            target, upstream_port
        );

        let upstream_stream = TcpStream::connect((target.as_str(), upstream_port))
            .await
            .map_err(|e| {
                DnsProxyError::Upstream(crate::error::UpstreamError::ConnectionFailed {
                    upstream: format!("{}:{}", target, upstream_port),
                    reason: format!("Failed to connect: {}", e),
                })
            })?;

        let client_config =
            create_client_config().map_err(|e| DnsProxyError::Tls(e.to_string()))?;
        let connector = TlsConnector::from(Arc::new(client_config));
        let sni_name = ServerName::try_from(target.clone()).map_err(|e| {
            DnsProxyError::InvalidInput(format!(
                "Failed to create ServerName for upstream connection: {}",
                e
            ))
        })?;

        let mut upstream_tls = connector
            .connect(sni_name, upstream_stream)
            .await
            .map_err(|e| {
                DnsProxyError::Upstream(crate::error::UpstreamError::ConnectionFailed {
                    upstream: format!("{}:{}", target, upstream_port),
                    reason: format!("Failed to establish TLS connection: {}", e),
                })
            })?;
        // DoT carries a continuous sequence of 2-octet-length-prefixed DNS
        // messages.  A transparent bidirectional relay preserves pipelining
        // and multi-message AXFR/IXFR transactions; the old one-request /
        // one-response loop incorrectly truncated transfers.
        let mut client_tls = stream;
        match tokio::io::copy_bidirectional(&mut client_tls, &mut upstream_tls).await {
            Ok((client_to_upstream, upstream_to_client)) => {
                metrics.record_request(
                    true,
                    client_to_upstream,
                    upstream_to_client,
                    timer.elapsed(),
                );
                Ok(())
            }
            Err(error) => {
                metrics.record_request(false, 0, 0, timer.elapsed());
                Err(error.into())
            }
        }
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

    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"dot".to_vec()];
    Ok(config)
}
