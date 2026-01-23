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

pub type HttpClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;

pub struct ConnectionPool {
    clients: Arc<DashMap<String, Arc<HttpClient>>>,
    keepalive_timeout: Duration,
    connection_timeout: Duration,
    max_idle_connections: usize,
}

impl ConnectionPool {
    pub fn new() -> Self {
        Self::with_config(
            DEFAULT_KEEPALIVE_TIMEOUT,
            DEFAULT_CONNECTION_TIMEOUT,
            DEFAULT_MAX_IDLE_CONNECTIONS,
        )
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
        }
    }

    pub fn get_client(&self, sni: &str) -> Arc<HttpClient> {
        if let Some(client) = self.clients.get(sni) {
            debug!("Reusing existing HTTP client for SNI: {}", sni);
            return Arc::clone(client.value());
        }

        debug!("Creating new HTTP client for SNI: {}", sni);
        let client = self.create_client();
        let client_arc = Arc::new(client);

        self.clients
            .entry(sni.to_string())
            .or_insert_with(|| Arc::clone(&client_arc));

        self.clients
            .get(sni)
            .map(|entry| Arc::clone(entry.value()))
            .unwrap_or(client_arc)
    }

    fn create_client(&self) -> HttpClient {
        let mut http_connector = HttpConnector::new();
        http_connector.set_keepalive(Some(self.keepalive_timeout));
        http_connector.set_connect_timeout(Some(self.connection_timeout));

        let https_connector = HttpsConnectorBuilder::new()
            .with_native_roots()
            .expect("Failed to load native root certificates")
            .https_or_http()
            .enable_http2()
            .wrap_connector(http_connector);

        Client::builder(TokioExecutor::new())
            .pool_max_idle_per_host(self.max_idle_connections)
            .pool_idle_timeout(self.keepalive_timeout)
            .set_host(false)
            .build(https_connector)
    }
}

impl Default for ConnectionPool {
    fn default() -> Self {
        Self::new()
    }
}
