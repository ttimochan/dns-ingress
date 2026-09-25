use crate::error::{DnsProxyError, DnsProxyResult, UpstreamError};
use crate::quic::QuicApplication;
use crate::quic::client::{UpstreamQuicConnection, connect_quic_upstream};
use bytes::Bytes;
use futures::future;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

type QuicKey = (QuicApplication, String, u16);
type H3Key = (String, u16);
type H3Sender = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

struct PoolSlot {
    _permit: OwnedSemaphorePermit,
}

#[derive(Clone)]
pub struct QuicConnectionLease {
    connection: Arc<UpstreamQuicConnection>,
    // Keep capacity reserved until the final in-flight borrower exits, even
    // if invalidate() has already removed the cache entry.
    _slot: Arc<PoolSlot>,
}

impl QuicConnectionLease {
    pub(crate) fn connection(&self) -> &Arc<UpstreamQuicConnection> {
        &self.connection
    }

    fn is_idle(&self) -> bool {
        Arc::strong_count(&self._slot) == 1
    }
}

/// Bounded QUIC connection cache. A permit is acquired before name resolution
/// or a handshake begins, preventing high-cardinality hostnames from creating
/// unbounded in-progress QUIC connections.
pub struct QuicConnectionPool {
    entries: Mutex<HashMap<QuicKey, CachedLease<QuicConnectionLease>>>,
    slots: Arc<Semaphore>,
    root_store: Arc<rustls::RootCertStore>,
}

/// A long-lived H3 client session. H3 request senders are cloneable and share
/// one control stream, while the driver remains active for the session life.
pub struct Http3Session {
    sender: H3Sender,
    _connection: Arc<UpstreamQuicConnection>,
    driver: tokio::task::JoinHandle<()>,
    alive: Arc<AtomicBool>,
}

impl Http3Session {
    pub(crate) fn sender(&self) -> H3Sender {
        self.sender.clone()
    }

    fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }
}

impl Drop for Http3Session {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

#[derive(Clone)]
pub struct Http3SessionLease {
    session: Arc<Http3Session>,
    _slot: Arc<PoolSlot>,
}

impl Http3SessionLease {
    pub(crate) fn sender(&self) -> H3Sender {
        self.session.sender()
    }

    fn is_alive(&self) -> bool {
        self.session.is_alive()
    }

    fn is_idle(&self) -> bool {
        Arc::strong_count(&self._slot) == 1
    }
}

struct CachedLease<T> {
    lease: T,
    last_used: Instant,
}

pub struct Http3ConnectionPool {
    entries: Mutex<HashMap<H3Key, CachedLease<Http3SessionLease>>>,
    slots: Arc<Semaphore>,
    root_store: Arc<rustls::RootCertStore>,
}

impl Http3ConnectionPool {
    #[allow(dead_code)] // retained as the public default-trust constructor
    pub fn new(max_entries: usize) -> Self {
        Self::with_root_store(
            max_entries,
            crate::tls_utils::load_upstream_root_store(None)
                .expect("platform trust store must be available"),
        )
    }

    pub fn with_root_store(max_entries: usize, root_store: Arc<rustls::RootCertStore>) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            slots: Arc::new(Semaphore::new(max_entries)),
            root_store,
        }
    }

    pub async fn get(&self, hostname: &str, port: u16) -> DnsProxyResult<Http3SessionLease> {
        let key = (hostname.to_string(), port);
        {
            let mut entries = self.entries.lock().await;
            if let Some(entry) = entries.get_mut(&key)
                && entry.lease.is_alive()
            {
                entry.last_used = Instant::now();
                return Ok(entry.lease.clone());
            }
            entries.remove(&key);
        }

        let slot = self.acquire_slot(hostname, port).await?;
        {
            let mut entries = self.entries.lock().await;
            if let Some(entry) = entries.get_mut(&key)
                && entry.lease.is_alive()
            {
                entry.last_used = Instant::now();
                return Ok(entry.lease.clone());
            }
        }

        let address = tokio::net::lookup_host((hostname, port))
            .await
            .map_err(|error| upstream_error(hostname, port, error.to_string()))?
            .next()
            .ok_or_else(|| upstream_error(hostname, port, "DNS lookup returned no addresses"))?;
        let connection = Arc::new(
            connect_quic_upstream(
                address,
                hostname,
                QuicApplication::H3,
                Arc::clone(&self.root_store),
            )
            .await
            .map_err(|error| upstream_error(hostname, port, error.to_string()))?,
        );
        let (mut driver, sender) =
            h3::client::new(h3_quinn::Connection::new(connection.connection.clone()))
                .await
                .map_err(|error| {
                    DnsProxyError::Protocol(format!("HTTP/3 client setup failed: {error}"))
                })?;
        let alive = Arc::new(AtomicBool::new(true));
        let driver_alive = Arc::clone(&alive);
        let driver = tokio::spawn(async move {
            let _ = future::poll_fn(|cx| driver.poll_close(cx)).await;
            driver_alive.store(false, Ordering::Release);
        });
        let session = Arc::new(Http3Session {
            sender,
            _connection: connection,
            driver,
            alive,
        });

        let mut entries = self.entries.lock().await;
        if let Some(entry) = entries.get_mut(&key)
            && entry.lease.is_alive()
        {
            entry.last_used = Instant::now();
            return Ok(entry.lease.clone());
        }
        let lease = Http3SessionLease {
            session,
            _slot: slot,
        };
        entries.insert(
            key,
            CachedLease {
                lease: lease.clone(),
                last_used: Instant::now(),
            },
        );
        Ok(lease)
    }

    async fn acquire_slot(&self, hostname: &str, port: u16) -> DnsProxyResult<Arc<PoolSlot>> {
        if let Ok(permit) = Arc::clone(&self.slots).try_acquire_owned() {
            return Ok(Arc::new(PoolSlot { _permit: permit }));
        }
        let evicted = {
            let mut entries = self.entries.lock().await;
            entries.retain(|_, entry| entry.lease.is_alive());
            entries
                .iter()
                .filter(|(_, entry)| entry.lease.is_idle())
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(key, _)| key.clone())
                .and_then(|key| entries.remove(&key))
        };
        drop(evicted);
        Arc::clone(&self.slots)
            .try_acquire_owned()
            .map(|permit| Arc::new(PoolSlot { _permit: permit }))
            .map_err(|_| overloaded(hostname, port, "HTTP/3"))
    }

    pub async fn invalidate(&self, hostname: &str, port: u16) {
        self.entries
            .lock()
            .await
            .remove(&(hostname.to_string(), port));
    }
}

impl QuicConnectionPool {
    #[allow(dead_code)] // retained as the public default-trust constructor
    pub fn new(max_entries: usize) -> Self {
        Self::with_root_store(
            max_entries,
            crate::tls_utils::load_upstream_root_store(None)
                .expect("platform trust store must be available"),
        )
    }

    pub fn with_root_store(max_entries: usize, root_store: Arc<rustls::RootCertStore>) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            slots: Arc::new(Semaphore::new(max_entries)),
            root_store,
        }
    }

    pub async fn get(
        &self,
        application: QuicApplication,
        hostname: &str,
        port: u16,
    ) -> DnsProxyResult<QuicConnectionLease> {
        let key = (application, hostname.to_string(), port);
        {
            let mut entries = self.entries.lock().await;
            if let Some(entry) = entries.get_mut(&key)
                && entry.lease.connection.connection.close_reason().is_none()
            {
                entry.last_used = Instant::now();
                return Ok(entry.lease.clone());
            }
            entries.remove(&key);
        }

        let slot = self.acquire_slot(hostname, port).await?;
        {
            let mut entries = self.entries.lock().await;
            if let Some(entry) = entries.get_mut(&key)
                && entry.lease.connection.connection.close_reason().is_none()
            {
                entry.last_used = Instant::now();
                return Ok(entry.lease.clone());
            }
        }

        let address = tokio::net::lookup_host((hostname, port))
            .await
            .map_err(|error| upstream_error(hostname, port, error.to_string()))?
            .next()
            .ok_or_else(|| upstream_error(hostname, port, "DNS lookup returned no addresses"))?;
        let connection = Arc::new(
            connect_quic_upstream(address, hostname, application, Arc::clone(&self.root_store))
                .await
                .map_err(|error| upstream_error(hostname, port, error.to_string()))?,
        );

        let mut entries = self.entries.lock().await;
        if let Some(entry) = entries.get_mut(&key)
            && entry.lease.connection.connection.close_reason().is_none()
        {
            entry.last_used = Instant::now();
            return Ok(entry.lease.clone());
        }
        let lease = QuicConnectionLease {
            connection,
            _slot: slot,
        };
        entries.insert(
            key,
            CachedLease {
                lease: lease.clone(),
                last_used: Instant::now(),
            },
        );
        Ok(lease)
    }

    async fn acquire_slot(&self, hostname: &str, port: u16) -> DnsProxyResult<Arc<PoolSlot>> {
        if let Ok(permit) = Arc::clone(&self.slots).try_acquire_owned() {
            return Ok(Arc::new(PoolSlot { _permit: permit }));
        }
        let evicted = {
            let mut entries = self.entries.lock().await;
            entries.retain(|_, entry| entry.lease.connection.connection.close_reason().is_none());
            entries
                .iter()
                .filter(|(_, entry)| entry.lease.is_idle())
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(key, _)| key.clone())
                .and_then(|key| entries.remove(&key))
        };
        drop(evicted);
        Arc::clone(&self.slots)
            .try_acquire_owned()
            .map(|permit| Arc::new(PoolSlot { _permit: permit }))
            .map_err(|_| overloaded(hostname, port, "QUIC"))
    }

    pub async fn invalidate(&self, application: QuicApplication, hostname: &str, port: u16) {
        self.entries
            .lock()
            .await
            .remove(&(application, hostname.to_string(), port));
    }
}

fn overloaded(hostname: &str, port: u16, protocol: &str) -> DnsProxyError {
    DnsProxyError::Overloaded {
        upstream: format!("{}:{}", hostname, port),
        protocol: protocol.to_string(),
    }
}

fn upstream_error(hostname: &str, port: u16, reason: impl Into<String>) -> DnsProxyError {
    DnsProxyError::Upstream(UpstreamError::ConnectionFailed {
        upstream: format!("{}:{}", hostname, port),
        reason: reason.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::{Http3ConnectionPool, QuicConnectionPool};
    use crate::error::DnsProxyError;
    use crate::quic::QuicApplication;

    #[tokio::test]
    async fn quic_pool_rejects_before_resolution_when_all_slots_are_reserved() {
        let pool = QuicConnectionPool::new(1);
        let _slot = pool
            .slots
            .clone()
            .try_acquire_owned()
            .expect("test reserves the only slot");
        let result = pool
            .get(QuicApplication::Doq, "does-not-resolve.invalid", 853)
            .await;
        assert!(matches!(result, Err(DnsProxyError::Overloaded { .. })));
    }

    #[tokio::test]
    async fn h3_pool_rejects_before_resolution_when_all_slots_are_reserved() {
        let pool = Http3ConnectionPool::new(1);
        let _slot = pool
            .slots
            .clone()
            .try_acquire_owned()
            .expect("test reserves the only slot");
        let result = pool.get("does-not-resolve.invalid", 443).await;
        assert!(matches!(result, Err(DnsProxyError::Overloaded { .. })));
    }
}
