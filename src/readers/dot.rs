use crate::config::AppConfig;
use crate::error::{DnsProxyError, DnsProxyResult};
use crate::metrics::{Metrics, Timer};
use crate::rewrite::SniRewriterType;
use crate::sni::SniRewriter;
use crate::tasks::TaskGroup;
use crate::tls_utils;
use crate::utils::backoff::BackoffCounter;
use rustls::pki_types::ServerName;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
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
    tasks: TaskGroup,
    root_store: Arc<rustls::RootCertStore>,
}

impl DoTServer {
    #[allow(dead_code)] // retained for standalone reader construction
    pub fn new(config: Arc<AppConfig>, rewriter: SniRewriterType, metrics: Arc<Metrics>) -> Self {
        let root_store =
            crate::tls_utils::load_upstream_root_store(config.tls.upstream_ca_file.as_deref())
                .expect("standalone DoT server requires a valid upstream trust store");
        Self::with_root_store(config, rewriter, metrics, root_store)
    }

    pub(crate) fn with_root_store(
        config: Arc<AppConfig>,
        rewriter: SniRewriterType,
        metrics: Arc<Metrics>,
        root_store: Arc<rustls::RootCertStore>,
    ) -> Self {
        Self {
            config,
            rewriter,
            backoff: Arc::new(BackoffCounter::new()),
            metrics,
            tasks: TaskGroup::default(),
            root_store,
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
        let root_store = Arc::clone(&self.root_store);
        let idle_timeout =
            std::time::Duration::from_secs(self.config.limits.transaction_timeout_seconds);
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
                    let permit = tokio::select! {
                        _ = shutdown.cancelled() => break,
                        permit = Arc::clone(&connection_limit).acquire_owned() => match permit {
                            Ok(permit) => permit,
                            Err(_) => break,
                        },
                    };
                    let acceptor = acceptor.clone();
                    let rewriter = Arc::clone(&rewriter);
                    let metrics = Arc::clone(&self.metrics);
                    let root_store = Arc::clone(&root_store);
                    let shutdown = shutdown.clone();
                    let tasks = self.tasks.clone();
                    tasks.spawn(async move {
                        let _connection_permit = permit;
                        let accepted = tokio::select! {
                            _ = shutdown.cancelled() => return,
                            accepted = tokio::time::timeout(idle_timeout, acceptor.accept(stream)) => match accepted {
                                Ok(result) => result,
                                Err(_) => {
                                    error!("DoT TLS handshake from {} timed out", addr);
                                    return;
                                }
                            },
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
                                            root_store,
                                            idle_timeout,
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
                    }).await;
                }
                Err(e) => {
                    error!("DoT accept error on {}: {}", bind_addr, e);
                    let delay = self.backoff.next_delay(100, 5000);
                    tokio::time::sleep(delay).await;
                }
            }
        }
        self.tasks
            .close_and_wait_until(tokio::time::Instant::now() + std::time::Duration::from_secs(10))
            .await;
        Ok(())
    }

    async fn handle_connection(
        stream: tokio_rustls::server::TlsStream<TcpStream>,
        rewriter: SniRewriterType,
        source_hostname: String,
        upstream_port: u16,
        root_store: Arc<rustls::RootCertStore>,
        idle_timeout: std::time::Duration,
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

        let upstream_stream = tokio::time::timeout(
            idle_timeout,
            TcpStream::connect((target.as_str(), upstream_port)),
        )
        .await
        .map_err(|_| DnsProxyError::Timeout {
            upstream: format!("{}:{}", target, upstream_port),
        })?
        .map_err(|e| {
            DnsProxyError::Upstream(crate::error::UpstreamError::ConnectionFailed {
                upstream: format!("{}:{}", target, upstream_port),
                reason: format!("Failed to connect: {}", e),
            })
        })?;

        let client_config = create_client_config(root_store)?;
        let connector = TlsConnector::from(Arc::new(client_config));
        let sni_name = ServerName::try_from(target.clone()).map_err(|e| {
            DnsProxyError::InvalidInput(format!(
                "Failed to create ServerName for upstream connection: {}",
                e
            ))
        })?;

        let upstream_tls =
            tokio::time::timeout(idle_timeout, connector.connect(sni_name, upstream_stream))
                .await
                .map_err(|_| DnsProxyError::Timeout {
                    upstream: format!("{}:{}", target, upstream_port),
                })?
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
        let (client_reader, client_writer) = tokio::io::split(stream);
        let (upstream_reader, upstream_writer) = tokio::io::split(upstream_tls);
        let upstream = format!("{}:{}", target, upstream_port);
        match tokio::try_join!(
            relay_direction(
                client_reader,
                upstream_writer,
                idle_timeout,
                upstream.clone()
            ),
            relay_direction(upstream_reader, client_writer, idle_timeout, upstream),
        ) {
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
                Err(error)
            }
        }
    }
}

/// Relay one half of a DoT TCP stream with a timeout that resets after every
/// successful read or write. This preserves long-running AXFR/IXFR transfers
/// while still releasing peers that stop making progress.
async fn relay_direction<R, W>(
    mut reader: R,
    mut writer: W,
    idle_timeout: std::time::Duration,
    upstream: String,
) -> DnsProxyResult<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut total = 0_u64;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = tokio::time::timeout(idle_timeout, reader.read(&mut buffer))
            .await
            .map_err(|_| DnsProxyError::Timeout {
                upstream: upstream.clone(),
            })??;
        if read == 0 {
            tokio::time::timeout(idle_timeout, writer.shutdown())
                .await
                .map_err(|_| DnsProxyError::Timeout { upstream })??;
            return Ok(total);
        }
        tokio::time::timeout(idle_timeout, writer.write_all(&buffer[..read]))
            .await
            .map_err(|_| DnsProxyError::Timeout {
                upstream: upstream.clone(),
            })??;
        total += read as u64;
    }
}

/// Create TLS client configuration for upstream connections
/// Uses public roots plus an optional private upstream CA bundle.
fn create_client_config(
    root_store: Arc<rustls::RootCertStore>,
) -> DnsProxyResult<rustls::ClientConfig> {
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates((*root_store).clone())
        .with_no_client_auth();
    config.alpn_protocols = vec![b"dot".to_vec()];
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::relay_direction;
    use crate::error::DnsProxyError;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn relay_preserves_data_and_half_closes_the_peer() {
        let (reader, mut source) = tokio::io::duplex(64);
        let (writer, mut destination) = tokio::io::duplex(64);
        source.write_all(b"dns-transfer").await.unwrap();
        source.shutdown().await.unwrap();

        let copied = relay_direction(
            reader,
            writer,
            std::time::Duration::from_secs(1),
            "upstream.test:853".to_string(),
        )
        .await
        .unwrap();
        let mut bytes = Vec::new();
        destination.read_to_end(&mut bytes).await.unwrap();

        assert_eq!(copied, 12);
        assert_eq!(bytes, b"dns-transfer");
    }

    #[tokio::test]
    async fn relay_times_out_when_a_direction_stops_making_progress() {
        let (reader, _source) = tokio::io::duplex(64);
        let (writer, _destination) = tokio::io::duplex(64);

        let result = relay_direction(
            reader,
            writer,
            std::time::Duration::from_millis(10),
            "upstream.test:853".to_string(),
        )
        .await;

        assert!(matches!(result, Err(DnsProxyError::Timeout { .. })));
    }
}
