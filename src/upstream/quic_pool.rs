use crate::error::{DnsProxyError, DnsProxyResult};
use crate::quic::QuicApplication;
use crate::quic::client::{UpstreamQuicConnection, connect_quic_upstream};
use bytes::Bytes;
use futures::future;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Bounded QUIC connection cache. The endpoint is retained with its connection
/// so a cached entry represents a real reusable UDP/TLS/QUIC session.
pub struct QuicConnectionPool {
    entries: Mutex<HashMap<(QuicApplication, String, u16), Arc<UpstreamQuicConnection>>>,
    max_entries: usize,
}

type H3Sender = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

/// A long-lived H3 client session. H3 request senders are cloneable and share
/// one control stream, while the driver remains active for the session life.
pub struct Http3Session {
    sender: H3Sender,
    _connection: Arc<UpstreamQuicConnection>,
    driver: tokio::task::JoinHandle<()>,
}

impl Http3Session {
    pub(crate) fn sender(&self) -> H3Sender {
        self.sender.clone()
    }
}

impl Drop for Http3Session {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

pub struct Http3ConnectionPool {
    entries: Mutex<HashMap<(String, u16), Arc<Http3Session>>>,
    max_entries: usize,
}

impl Http3ConnectionPool {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            max_entries,
        }
    }

    pub async fn get(&self, hostname: &str, port: u16) -> DnsProxyResult<Arc<Http3Session>> {
        let key = (hostname.to_string(), port);
        if let Some(session) = self.entries.lock().await.get(&key).cloned() {
            return Ok(session);
        }

        let address = tokio::net::lookup_host((hostname, port))
            .await
            .map_err(|error| upstream_error(hostname, port, error.to_string()))?
            .next()
            .ok_or_else(|| upstream_error(hostname, port, "DNS lookup returned no addresses"))?;
        let connection = Arc::new(
            connect_quic_upstream(address, hostname, QuicApplication::H3)
                .await
                .map_err(|error| upstream_error(hostname, port, error.to_string()))?,
        );
        let (mut driver, sender) =
            h3::client::new(h3_quinn::Connection::new(connection.connection.clone()))
                .await
                .map_err(|error| {
                    DnsProxyError::Protocol(format!("HTTP/3 client setup failed: {error}"))
                })?;
        let driver = tokio::spawn(async move {
            let _ = future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        let session = Arc::new(Http3Session {
            sender,
            _connection: connection,
            driver,
        });

        let mut entries = self.entries.lock().await;
        if let Some(existing) = entries.get(&key) {
            return Ok(Arc::clone(existing));
        }
        if entries.len() >= self.max_entries {
            return Err(DnsProxyError::Upstream(
                crate::error::UpstreamError::RequestFailed {
                    upstream: format!("{}:{}", hostname, port),
                    reason: "HTTP/3 upstream pool is at capacity".to_string(),
                },
            ));
        }
        entries.insert(key, Arc::clone(&session));
        Ok(session)
    }
}

impl QuicConnectionPool {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            max_entries,
        }
    }

    pub async fn get(
        &self,
        application: QuicApplication,
        hostname: &str,
        port: u16,
    ) -> DnsProxyResult<Arc<UpstreamQuicConnection>> {
        let key = (application, hostname.to_string(), port);
        if let Some(connection) = self.entries.lock().await.get(&key).cloned() {
            return Ok(connection);
        }

        let address = tokio::net::lookup_host((hostname, port))
            .await
            .map_err(|error| upstream_error(hostname, port, error.to_string()))?
            .next()
            .ok_or_else(|| upstream_error(hostname, port, "DNS lookup returned no addresses"))?;
        let connection = Arc::new(
            connect_quic_upstream(address, hostname, application)
                .await
                .map_err(|error| upstream_error(hostname, port, error.to_string()))?,
        );

        let mut entries = self.entries.lock().await;
        if let Some(existing) = entries.get(&key) {
            return Ok(Arc::clone(existing));
        }
        if entries.len() >= self.max_entries {
            return Err(DnsProxyError::Upstream(
                crate::error::UpstreamError::RequestFailed {
                    upstream: format!("{}:{}", hostname, port),
                    reason: "QUIC upstream pool is at capacity".to_string(),
                },
            ));
        }
        entries.insert(key, Arc::clone(&connection));
        Ok(connection)
    }
}

fn upstream_error(hostname: &str, port: u16, reason: impl Into<String>) -> DnsProxyError {
    DnsProxyError::Upstream(crate::error::UpstreamError::ConnectionFailed {
        upstream: format!("{}:{}", hostname, port),
        reason: reason.into(),
    })
}
