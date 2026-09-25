use serde::Serialize;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

#[derive(Debug, Serialize)]
pub struct MetricsSnapshot {
    pub total_requests: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub sni_rewrites: u64,
    pub upstream_errors: u64,
    pub processing_duration_micros: u64,
}

#[derive(Clone)]
pub struct Metrics {
    total_requests: Arc<AtomicU64>,
    successful_requests: Arc<AtomicU64>,
    failed_requests: Arc<AtomicU64>,
    bytes_received: Arc<AtomicU64>,
    bytes_sent: Arc<AtomicU64>,
    sni_rewrites: Arc<AtomicU64>,
    upstream_errors: Arc<AtomicU64>,
    processing_duration_micros: Arc<AtomicU64>,
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
            processing_duration_micros: Arc::new(AtomicU64::new(0)),
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
        self.processing_duration_micros.fetch_add(
            duration.as_micros().min(u64::MAX as u128) as u64,
            Ordering::Relaxed,
        );

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

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            total_requests: self.total_requests.load(Ordering::Relaxed),
            successful_requests: self.successful_requests.load(Ordering::Relaxed),
            failed_requests: self.failed_requests.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            sni_rewrites: self.sni_rewrites.load(Ordering::Relaxed),
            upstream_errors: self.upstream_errors.load(Ordering::Relaxed),
            processing_duration_micros: self.processing_duration_micros.load(Ordering::Relaxed),
        }
    }

    pub fn prometheus(&self) -> String {
        let s = self.snapshot();
        format!(
            "# TYPE dns_ingress_requests_total counter\ndns_ingress_requests_total {}\n# TYPE dns_ingress_requests_success_total counter\ndns_ingress_requests_success_total {}\n# TYPE dns_ingress_requests_failed_total counter\ndns_ingress_requests_failed_total {}\n# TYPE dns_ingress_bytes_received_total counter\ndns_ingress_bytes_received_total {}\n# TYPE dns_ingress_bytes_sent_total counter\ndns_ingress_bytes_sent_total {}\n# TYPE dns_ingress_sni_rewrites_total counter\ndns_ingress_sni_rewrites_total {}\n# TYPE dns_ingress_upstream_errors_total counter\ndns_ingress_upstream_errors_total {}\n# TYPE dns_ingress_request_duration_seconds summary\ndns_ingress_request_duration_seconds_sum {:.6}\ndns_ingress_request_duration_seconds_count {}\n",
            s.total_requests,
            s.successful_requests,
            s.failed_requests,
            s.bytes_received,
            s.bytes_sent,
            s.sni_rewrites,
            s.upstream_errors,
            s.processing_duration_micros as f64 / 1_000_000.0,
            s.total_requests,
        )
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
