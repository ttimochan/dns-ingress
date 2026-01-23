use crate::config::AppConfig;
use crate::error::DnsProxyResult;
use crate::metrics::Metrics;
use crate::rewrite::{SniRewriterType, create_rewriter};
use crate::server::{ServerResources, ServerStarter};
use crate::tls_utils::CertificateResolver;
use std::sync::Arc;
use tokio::task::JoinHandle;
use tracing::{info, warn};

pub struct App {
    config: Arc<AppConfig>,
    pub rewriter: SniRewriterType,
    metrics: Arc<Metrics>,
    handles: Vec<JoinHandle<()>>,
}

impl App {
    pub fn new(config: AppConfig) -> Self {
        let config = Arc::new(config);
        let rewriter = create_rewriter(config.rewrite.clone());
        let metrics = Arc::new(Metrics::new());
        Self {
            config,
            rewriter,
            metrics,
            handles: Vec::new(),
        }
    }

    pub fn start(&mut self) -> DnsProxyResult<()> {
        info!("Starting DNS Proxy Server...");

        self.preload_certificates();
        self.start_healthcheck_server();
        self.start_dot_server();
        self.start_doh_server();
        self.start_doq_server();
        self.start_doh3_server();

        info!("All enabled servers started ({} tasks)", self.handles.len());
        Ok(())
    }

    fn preload_certificates(&self) {
        if self.config.tls.default.is_none() && self.config.tls.certs.is_empty() {
            warn!("No TLS certificates configured, TLS handshake will fail for incoming connections");
            return;
        }

        info!("Preloading TLS certificates...");

        let config = Arc::clone(&self.config);

        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Failed to create runtime for certificate preloading");

            rt.block_on(async {
                let resolver = CertificateResolver::with_arc(config);

                if let Some(ref default_cert) = resolver.tls_config().tls.default {
                    match CertificateResolver::load_certificate(default_cert).await {
                        Ok(_) => info!("Preloaded default TLS certificate"),
                        Err(e) => warn!("Failed to preload default certificate: {}", e),
                    }
                }

                for (domain, cert_config) in &resolver.tls_config().tls.certs {
                    match CertificateResolver::load_certificate(cert_config).await {
                        Ok(_) => info!("Preloaded TLS certificate for domain: {}", domain),
                        Err(e) => warn!("Failed to preload certificate for {}: {}", domain, e),
                    }
                }
            });
        });
    }

    pub async fn wait_for_shutdown(&mut self) {
        info!("Waiting for all servers to shutdown...");

        let mut remaining = self.handles.len();
        while remaining > 0 {
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                self.handles.remove(0)
            ).await;

            match result {
                Ok(_) => {
                    remaining -= 1;
                    if remaining > 0 {
                        info!("{} server(s) remaining...", remaining);
                    }
                }
                Err(_) => {
                    warn!("Timeout waiting for server shutdown, forcing close...");
                    break;
                }
            }
        }

        for handle in self.handles.drain(..) {
            handle.abort();
        }

        info!("All servers shutdown complete");
    }

    fn start_healthcheck_server(&mut self) {
        use crate::readers::HealthcheckServer;
        if !self.config.servers.healthcheck.enabled {
            return;
        }

        let config = Arc::clone(&self.config);
        let bind_addr = format!(
            "{}:{}",
            self.config.servers.healthcheck.bind_address, self.config.servers.healthcheck.port
        );
        let path = self.config.servers.healthcheck.path.clone();
        let handle = tokio::spawn(async move {
            let server = HealthcheckServer::new(config);
            if let Err(e) = server.start().await {
                tracing::error!("Healthcheck server error: {}", e);
            }
        });
        self.handles.push(handle);
        info!(
            "Healthcheck server started on {} at path {}",
            bind_addr, path
        );
    }

    fn start_dot_server(&mut self) {
        use crate::readers::DoTServer;
        let resources = ServerResources::new(
            Arc::clone(&self.config),
            Arc::clone(&self.rewriter),
            Arc::clone(&self.metrics),
        );
        if let Some(handle) = ServerStarter::start_server(
            "DoT",
            &self.config.servers.dot,
            resources,
            |resources| async move {
                let server =
                    DoTServer::new(resources.config, resources.rewriter, resources.metrics);
                server.start().await
            },
        ) {
            self.handles.push(handle);
        }
    }

    fn start_doh_server(&mut self) {
        use crate::readers::DoHServer;
        let resources = ServerResources::new(
            Arc::clone(&self.config),
            Arc::clone(&self.rewriter),
            Arc::clone(&self.metrics),
        );
        if let Some(handle) = ServerStarter::start_server(
            "DoH",
            &self.config.servers.doh,
            resources,
            |resources| async move {
                let server =
                    DoHServer::new(resources.config, resources.rewriter, resources.metrics);
                server.start().await
            },
        ) {
            self.handles.push(handle);
        }
    }

    fn start_doq_server(&mut self) {
        use crate::readers::DoQServer;
        let resources = ServerResources::new(
            Arc::clone(&self.config),
            Arc::clone(&self.rewriter),
            Arc::clone(&self.metrics),
        );
        if let Some(handle) = ServerStarter::start_server(
            "DoQ",
            &self.config.servers.doq,
            resources,
            |resources| async move {
                let server =
                    DoQServer::new(resources.config, resources.rewriter, resources.metrics);
                server.start().await
            },
        ) {
            self.handles.push(handle);
        }
    }

    fn start_doh3_server(&mut self) {
        use crate::readers::DoH3Server;
        let resources = ServerResources::new(
            Arc::clone(&self.config),
            Arc::clone(&self.rewriter),
            Arc::clone(&self.metrics),
        );
        if let Some(handle) = ServerStarter::start_server(
            "DoH3",
            &self.config.servers.doh3,
            resources,
            |resources| async move {
                let server =
                    DoH3Server::new(resources.config, resources.rewriter, resources.metrics);
                server.start().await
            },
        ) {
            self.handles.push(handle);
        }
    }
}
