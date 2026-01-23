use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct Metrics {
    total_requests: Arc<AtomicU64>,
    successful_requests: Arc<AtomicU64>,
    failed_requests: Arc<AtomicU64>,
    bytes_received: Arc<AtomicU64>,
    bytes_sent: Arc<AtomicU64>,
    sni_rewrites: Arc<AtomicU64>,
    upstream_errors: Arc<AtomicU64>,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            total_requests: Arc::new(AtomicU64::new(0)),
            successful_requests: Arc::new(AtomicU64::new(0)),
            failed_requests: Arc::new(AtomicU64::new(0)),
            bytes_received: Arc::new(AtomicU64::new(0)),
            bytes_sent: Arc::new(AtomicU64::new(0)),
            sni_rewrites: Arc::new(AtomicU64::new(0)),
            upstream_errors: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn record_request(
        &self,
        success: bool,
        bytes_received_val: u64,
        bytes_sent_val: u64,
        duration: Duration,
    ) {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        if success {
            self.successful_requests.fetch_add(1, Ordering::Relaxed);
        } else {
            self.failed_requests.fetch_add(1, Ordering::Relaxed);
        }
        self.bytes_received
            .fetch_add(bytes_received_val, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes_sent_val, Ordering::Relaxed);

        tracing::debug!(
            "request processed: success={}, bytes_recv={}, bytes_sent={}, duration_ms={:.2}",
            success,
            bytes_received_val,
            bytes_sent_val,
            duration.as_secs_f64() * 1000.0
        );
    }

    pub fn record_sni_rewrite(&self) {
        self.sni_rewrites.fetch_add(1, Ordering::Relaxed);
        tracing::debug!("SNI rewrite performed");
    }

    pub fn record_upstream_error(&self) {
        self.upstream_errors.fetch_add(1, Ordering::Relaxed);
        tracing::debug!("upstream error recorded");
    }
}

pub struct Timer {
    start: Instant,
}

impl Timer {
    pub fn start() -> Self {
        Self {
            start: Instant::now(),
        }
    }

    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }
}
