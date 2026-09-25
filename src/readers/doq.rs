use crate::config::AppConfig;
use crate::error::DnsProxyResult;
use crate::metrics::{Metrics, Timer};
use crate::quic::{QuicApplication, create_quic_server_endpoint};
use crate::rewrite::SniRewriterType;
use crate::tasks::TaskGroup;
use crate::upstream::QuicConnectionPool;
use crate::upstream::forward_quic_stream;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

pub struct DoQServer {
    config: Arc<AppConfig>,
    rewriter: SniRewriterType,
    metrics: Arc<Metrics>,
    pool: Arc<QuicConnectionPool>,
    tasks: TaskGroup,
}

impl DoQServer {
    #[allow(dead_code)] // retained for standalone reader construction
    pub fn new(config: Arc<AppConfig>, rewriter: SniRewriterType, metrics: Arc<Metrics>) -> Self {
        let root_store =
            crate::tls_utils::load_upstream_root_store(config.tls.upstream_ca_file.as_deref())
                .expect("standalone DoQ server requires a valid upstream trust store");
        Self::with_root_store(config, rewriter, metrics, root_store)
    }

    pub(crate) fn with_root_store(
        config: Arc<AppConfig>,
        rewriter: SniRewriterType,
        metrics: Arc<Metrics>,
        root_store: Arc<rustls::RootCertStore>,
    ) -> Self {
        Self {
            pool: Arc::new(QuicConnectionPool::with_root_store(
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
        let server_config = &self.config.servers.doq;
        if !server_config.enabled {
            info!("DoQ server is disabled");
            return Ok(());
        }

        let bind_addr = format!("{}:{}", server_config.bind_address, server_config.port);
        let addr: SocketAddr = bind_addr.parse().map_err(|e| {
            crate::error::DnsProxyError::InvalidInput(format!("Invalid bind address: {}", e))
        })?;

        let endpoint =
            match create_quic_server_endpoint(self.config.as_ref(), addr, QuicApplication::Doq)
                .await
            {
                Ok(endpoint) => endpoint,
                Err(error) => {
                    if let Some(sender) = ready {
                        let _ = sender.send(Err(crate::error::DnsProxyError::Protocol(
                            error.to_string(),
                        )));
                    }
                    return Err(error.into());
                }
            };
        info!("DoQ server listening on UDP {}", addr);

        let rewriter = Arc::clone(&self.rewriter);
        let upstream_port = self.config.upstream.doq.port;
        let max_streams = self.config.limits.max_inflight_requests_per_connection;
        let transaction_timeout =
            std::time::Duration::from_secs(self.config.limits.transaction_timeout_seconds);
        let connection_limit = Arc::new(Semaphore::new(
            self.config.limits.max_connections_per_listener,
        ));

        let metrics = Arc::clone(&self.metrics);
        let pool = Arc::clone(&self.pool);
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
                permit = Arc::clone(&connection_limit).acquire_owned() => permit.map_err(|_| {
                    crate::error::DnsProxyError::Protocol("DoQ listener stopped".into())
                })?,
            };
            let rewriter = Arc::clone(&rewriter);
            let m = Arc::clone(&metrics);
            let pool = Arc::clone(&pool);
            let connection_shutdown = shutdown.clone();
            let tasks = self.tasks.clone();
            let connection_tasks = tasks.clone();
            tasks.spawn(async move {
                let _permit = permit;
                let connected = tokio::select! {
                    _ = connection_shutdown.cancelled() => return,
                    connected = tokio::time::timeout(transaction_timeout, conn) => match connected {
                        Ok(connection) => connection,
                        Err(_) => {
                            error!("DoQ connection handshake timed out");
                            return;
                        }
                    },
                };
                match connected {
                    Ok(connection) => {
                        info!("New DoQ connection from {}", connection.remote_address());
                        let remote_addr = connection.remote_address();
                        if let Err(e) = Self::handle_connection(
                            connection,
                            rewriter,
                            upstream_port,
                            max_streams,
                            transaction_timeout,
                            connection_shutdown.clone(),
                            pool,
                            m,
                            connection_tasks,
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
        upstream_port: u16,
        max_streams: usize,
        transaction_timeout: std::time::Duration,
        shutdown: CancellationToken,
        pool: Arc<QuicConnectionPool>,
        metrics: Arc<Metrics>,
        tasks: TaskGroup,
    ) -> DnsProxyResult<()> {
        let handshake = connection.handshake_data().ok_or_else(|| {
            crate::error::DnsProxyError::InvalidInput("DoQ requires TLS SNI hostname".to_string())
        })?;
        let source_hostname = handshake
            .downcast::<quinn::crypto::rustls::HandshakeData>()
            .ok()
            .and_then(|data| data.server_name.clone())
            .ok_or({
                crate::error::DnsProxyError::InvalidInput(
                    "DoQ requires TLS SNI hostname".to_string(),
                )
            })?;
        let target = crate::sni::SniRewriter::rewrite(&*rewriter, &source_hostname)
            .await
            .ok_or({
                crate::error::DnsProxyError::SniRewrite(
                    crate::error::SniRewriteError::NoMatchingBaseDomain {
                        hostname: source_hostname,
                    },
                )
            })?
            .target_hostname;

        let unidirectional = connection.clone();
        let uni_shutdown = shutdown.clone();
        let uni_tasks = tasks.clone();
        uni_tasks
            .spawn(async move {
                let accepted = tokio::select! {
                    _ = uni_shutdown.cancelled() => return,
                    accepted = unidirectional.accept_uni() => accepted,
                };
                if accepted.is_ok() {
                    unidirectional
                        .close(quinn::VarInt::from_u32(0x2), b"DoQ unidirectional stream");
                }
            })
            .await;

        let stream_limit = Arc::new(Semaphore::new(max_streams));
        loop {
            let accepted = tokio::select! {
                _ = shutdown.cancelled() => break,
                accepted = connection.accept_bi() => accepted,
            };
            match accepted {
                Ok((send, recv)) => {
                    let permit = tokio::select! {
                        _ = shutdown.cancelled() => break,
                        permit = Arc::clone(&stream_limit).acquire_owned() => permit.map_err(|_| {
                            crate::error::DnsProxyError::Protocol("DoQ connection stopped".into())
                        })?,
                    };
                    let target = target.clone();
                    let metrics = Arc::clone(&metrics);
                    let close_connection = connection.clone();
                    let shutdown = shutdown.clone();
                    let pool = Arc::clone(&pool);
                    let stream_tasks = tasks.clone();
                    stream_tasks
                        .spawn(async move {
                            let _permit = permit;
                            let timer = Timer::start();
                            let forwarding = forward_quic_stream(
                                send,
                                recv,
                                &target,
                                upstream_port,
                                &pool,
                                transaction_timeout,
                            );
                            let result = tokio::select! {
                                _ = shutdown.cancelled() => return,
                                result = forwarding => result,
                            };
                            match result {
                                Ok((bytes_received, bytes_sent)) => metrics.record_request(
                                    true,
                                    bytes_received,
                                    bytes_sent,
                                    timer.elapsed(),
                                ),
                                Err(error) => {
                                    error!(
                                        "DoQ stream forwarding error to upstream {}:{}: {}",
                                        target, upstream_port, error
                                    );
                                    metrics.record_request(false, 0, 0, timer.elapsed());
                                    metrics.record_upstream_error();
                                    if matches!(error, crate::error::DnsProxyError::Protocol(_)) {
                                        close_connection.close(
                                            quinn::VarInt::from_u32(0x2),
                                            b"DoQ protocol error",
                                        );
                                    }
                                }
                            }
                        })
                        .await;
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
