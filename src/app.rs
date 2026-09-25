use crate::config::AppConfig;
use crate::error::{DnsProxyError, DnsProxyResult};
use crate::metrics::Metrics;
use crate::rewrite::{SniRewriterType, create_rewriter};
use crate::tls_utils::CertificateResolver;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

const SHUTDOWN_GRACE: std::time::Duration = std::time::Duration::from_secs(10);

pub struct App {
    config: Arc<AppConfig>,
    pub rewriter: SniRewriterType,
    metrics: Arc<Metrics>,
    ready: Arc<AtomicBool>,
    shutdown: CancellationToken,
    failed: Arc<AtomicBool>,
    handles: Vec<JoinHandle<()>>,
}

impl App {
    pub fn new(config: AppConfig) -> Self {
        let config = Arc::new(config);
        let rewriter = create_rewriter(config.rewrite.clone());
        Self {
            config,
            rewriter,
            metrics: Arc::new(Metrics::new()),
            ready: Arc::new(AtomicBool::new(false)),
            shutdown: CancellationToken::new(),
            failed: Arc::new(AtomicBool::new(false)),
            handles: Vec::new(),
        }
    }

    /// Start every enabled listener and wait until each one owns its production
    /// socket. A successful return is therefore a real readiness boundary.
    pub async fn start(&mut self) -> DnsProxyResult<()> {
        info!("Starting DNS Proxy Server...");
        self.config.validate()?;
        self.ready.store(false, Ordering::Release);
        self.failed.store(false, Ordering::Release);

        if [
            self.config.servers.dot.enabled,
            self.config.servers.doh.enabled,
            self.config.servers.doq.enabled,
            self.config.servers.doh3.enabled,
        ]
        .into_iter()
        .any(|enabled| enabled)
        {
            if self.config.tls.default.is_none() && self.config.tls.certs.is_empty() {
                return Err(DnsProxyError::Tls(
                    "at least one TLS certificate is required for an enabled DNS listener"
                        .to_string(),
                ));
            }
            CertificateResolver::new(self.config.as_ref())?;
        }

        let mut readiness = Vec::new();
        if self.config.servers.healthcheck.enabled {
            let config = Arc::clone(&self.config);
            let metrics = Arc::clone(&self.metrics);
            let ready = Arc::clone(&self.ready);
            readiness.push(
                self.spawn_server("healthcheck", move |shutdown, sender| async move {
                    crate::readers::HealthcheckServer::with_metrics_and_readiness(
                        config, metrics, ready,
                    )
                    .run(shutdown, Some(sender))
                    .await
                }),
            );
        }
        if self.config.servers.dot.enabled {
            let config = Arc::clone(&self.config);
            let rewriter = Arc::clone(&self.rewriter);
            let metrics = Arc::clone(&self.metrics);
            readiness.push(
                self.spawn_server("DoT", move |shutdown, sender| async move {
                    crate::readers::DoTServer::new(config, rewriter, metrics)
                        .run(shutdown, Some(sender))
                        .await
                }),
            );
        }
        if self.config.servers.doh.enabled {
            let config = Arc::clone(&self.config);
            let rewriter = Arc::clone(&self.rewriter);
            let metrics = Arc::clone(&self.metrics);
            readiness.push(
                self.spawn_server("DoH", move |shutdown, sender| async move {
                    crate::readers::DoHServer::new(config, rewriter, metrics)
                        .run(shutdown, Some(sender))
                        .await
                }),
            );
        }
        if self.config.servers.doq.enabled {
            let config = Arc::clone(&self.config);
            let rewriter = Arc::clone(&self.rewriter);
            let metrics = Arc::clone(&self.metrics);
            readiness.push(
                self.spawn_server("DoQ", move |shutdown, sender| async move {
                    crate::readers::DoQServer::new(config, rewriter, metrics)
                        .run(shutdown, Some(sender))
                        .await
                }),
            );
        }
        if self.config.servers.doh3.enabled {
            let config = Arc::clone(&self.config);
            let rewriter = Arc::clone(&self.rewriter);
            let metrics = Arc::clone(&self.metrics);
            readiness.push(
                self.spawn_server("DoH3", move |shutdown, sender| async move {
                    crate::readers::DoH3Server::new(config, rewriter, metrics)
                        .run(shutdown, Some(sender))
                        .await
                }),
            );
        }

        for (name, receiver) in readiness {
            match receiver.await {
                Ok(Ok(())) => info!("{} listener is bound", name),
                Ok(Err(error)) => {
                    self.shutdown().await;
                    return Err(error);
                }
                Err(_) => {
                    self.shutdown().await;
                    return Err(DnsProxyError::Protocol(format!(
                        "{} server exited before reporting listener readiness",
                        name
                    )));
                }
            }
        }
        if self.failed.load(Ordering::Acquire) {
            self.shutdown().await;
            return Err(DnsProxyError::Protocol(
                "a listener exited during startup".to_string(),
            ));
        }
        self.ready.store(true, Ordering::Release);
        info!(
            "All enabled servers are ready ({} tasks)",
            self.handles.len()
        );
        Ok(())
    }

    fn spawn_server<F, Fut>(
        &mut self,
        name: &'static str,
        runner: F,
    ) -> (&'static str, oneshot::Receiver<DnsProxyResult<()>>)
    where
        F: FnOnce(CancellationToken, oneshot::Sender<DnsProxyResult<()>>) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = DnsProxyResult<()>> + Send + 'static,
    {
        let (sender, receiver) = oneshot::channel();
        let shutdown = self.shutdown.clone();
        let ready = Arc::clone(&self.ready);
        let failed = Arc::clone(&self.failed);
        self.handles.push(tokio::spawn(async move {
            if let Err(error) = runner(shutdown.clone(), sender).await
                && !shutdown.is_cancelled()
            {
                error!("{} server stopped unexpectedly: {}", name, error);
                failed.store(true, Ordering::Release);
                ready.store(false, Ordering::Release);
            }
        }));
        (name, receiver)
    }

    /// Cancel listeners and active work, then wait a single global grace
    /// period. Timed-out handles are explicitly aborted and joined.
    pub async fn shutdown(&mut self) {
        self.ready.store(false, Ordering::Release);
        self.shutdown.cancel();
        let deadline = tokio::time::Instant::now() + SHUTDOWN_GRACE;
        let total = self.handles.len();
        for mut handle in self.handles.drain(..) {
            match tokio::time::timeout_at(deadline, &mut handle).await {
                Ok(_) => {}
                Err(_) => {
                    warn!("Shutdown grace period elapsed; aborting remaining server task");
                    handle.abort();
                    let _ = handle.await;
                }
            }
        }
        info!("All server tasks stopped ({})", total);
    }

    pub async fn wait_for_shutdown(&mut self) {
        self.shutdown().await;
    }
}
