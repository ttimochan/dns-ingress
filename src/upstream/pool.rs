use anyhow::Result;
use dashmap::DashMap;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use std::sync::Arc;
use std::time::Duration;
use tracing::debug;

const DEFAULT_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(60);
const DEFAULT_CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_MAX_IDLE_CONNECTIONS: usize = 10;
const DEFAULT_MAX_CLIENTS: usize = 256;

pub type HttpClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;

pub struct ConnectionPool {
    clients: Arc<DashMap<String, Arc<HttpClient>>>,
    keepalive_timeout: Duration,
    connection_timeout: Duration,
    max_idle_connections: usize,
    max_clients: usize,
    root_store: Arc<rustls::RootCertStore>,
}

impl ConnectionPool {
    pub fn new() -> Self {
        Self::with_config(
            DEFAULT_KEEPALIVE_TIMEOUT,
            DEFAULT_CONNECTION_TIMEOUT,
            DEFAULT_MAX_IDLE_CONNECTIONS,
        )
    }

    #[allow(dead_code)] // retained as the public default-trust constructor
    pub fn with_max_clients(max_clients: usize) -> Self {
        Self::with_max_clients_and_root_store(
            max_clients,
            crate::tls_utils::load_upstream_root_store(None)
                .expect("platform trust store must be available"),
        )
    }

    pub fn with_max_clients_and_root_store(
        max_clients: usize,
        root_store: Arc<rustls::RootCertStore>,
    ) -> Self {
        let mut pool = Self::new();
        pool.max_clients = max_clients;
        pool.root_store = root_store;
        pool
    }

    pub fn with_config(
        keepalive_timeout: Duration,
        connection_timeout: Duration,
        max_idle_connections: usize,
    ) -> Self {
        Self {
            clients: Arc::new(DashMap::new()),
            keepalive_timeout,
            connection_timeout,
            max_idle_connections,
            max_clients: DEFAULT_MAX_CLIENTS,
            root_store: crate::tls_utils::load_upstream_root_store(None)
                .expect("platform trust store must be available"),
        }
    }

    pub fn get_client(&self, sni: &str) -> Result<Arc<HttpClient>> {
        if let Some(client) = self.clients.get(sni) {
            debug!("Reusing existing HTTP client for SNI: {}", sni);
            return Ok(Arc::clone(client.value()));
        }

        debug!("Creating new HTTP client for SNI: {}", sni);
        if self.clients.len() >= self.max_clients {
            // Bound attacker-controlled rewritten hostnames. HTTP clients are
            // cheap to recreate; evicting an arbitrary idle entry is safer
            // than retaining an unbounded authority map.
            if let Some(key) = self.clients.iter().next().map(|entry| entry.key().clone()) {
                self.clients.remove(&key);
            }
        }
        let client = self.create_client()?;
        let client_arc = Arc::new(client);

        self.clients
            .entry(sni.to_string())
            .or_insert_with(|| Arc::clone(&client_arc));

        Ok(self
            .clients
            .get(sni)
            .map(|entry| Arc::clone(entry.value()))
            .unwrap_or(client_arc))
    }

    fn create_client(&self) -> Result<HttpClient> {
        let mut http_connector = HttpConnector::new();
        http_connector.set_keepalive(Some(self.keepalive_timeout));
        http_connector.set_connect_timeout(Some(self.connection_timeout));

        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates((*self.root_store).clone())
            .with_no_client_auth();
        let https_connector = HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            .https_or_http()
            .enable_http2()
            .wrap_connector(http_connector);

        Ok(Client::builder(TokioExecutor::new())
            .pool_max_idle_per_host(self.max_idle_connections)
            .pool_idle_timeout(self.keepalive_timeout)
            .set_host(false)
            .build(https_connector))
    }
}

impl Default for ConnectionPool {
    fn default() -> Self {
        Self::new()
    }
}
