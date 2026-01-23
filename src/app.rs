use crate::config::AppConfig;
use crate::error::DnsProxyResult;
use crate::metrics::Metrics;
use crate::rewrite::{SniRewriterType, create_rewriter};
use crate::server::{ServerResources, ServerStarter};
use std::sync::Arc;
use tokio::task::JoinHandle;
use tracing::info;

/// DNS Proxy application that manages all protocol servers
pub struct App {
    config: Arc<AppConfig>,
    pub rewriter: SniRewriterType,
    metrics: Arc<Metrics>,
    handles: Vec<JoinHandle<()>>,
}

impl App {
    /// Create a new App instance with the given configuration
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

    /// Start all enabled servers and return handles for graceful shutdown
    pub fn start(&mut self) -> DnsProxyResult<()> {
        info!("Starting DNS Proxy Server...");

        self.start_healthcheck_server();
        self.start_dot_server();
        self.start_doh_server();
        self.start_doq_server();
        self.start_doh3_server();

        info!("All enabled servers started ({} tasks)", self.handles.len());
        Ok(())
    }

    /// Wait for all server tasks to complete (for graceful shutdown)
    pub async fn wait_for_shutdown(&mut self) {
        info!("Waiting for all servers to shutdown...");
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
