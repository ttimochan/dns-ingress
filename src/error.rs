/// Error types for DNS Proxy
use thiserror::Error;

/// Main error type for DNS Proxy operations
#[derive(Error, Debug)]
pub enum DnsProxyError {
    /// SNI rewrite errors
    #[error("SNI rewrite failed: {0}")]
    SniRewrite(#[from] SniRewriteError),

    /// TLS/SSL errors
    #[error("TLS error: {0}")]
    Tls(String),

    /// Certificate errors
    #[error("Certificate error: {0}")]
    Certificate(#[from] CertificateError),

    /// Upstream connection errors
    #[error("Upstream connection error: {0}")]
    Upstream(#[from] UpstreamError),

    /// Upstream did not make progress before the configured deadline.
    #[error("Upstream timeout: {upstream}")]
    Timeout { upstream: String },

    /// Bounded shared resources cannot accept another upstream authority.
    #[error("{protocol} upstream pool is overloaded for {upstream}")]
    Overloaded { upstream: String, protocol: String },

    /// Network I/O errors
    #[error("Network I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Protocol-specific errors
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// Invalid input errors
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

/// SNI rewrite specific errors
#[derive(Error, Debug)]
pub enum SniRewriteError {
    /// No matching base domain found
    #[error("No matching base domain found for hostname: {hostname}")]
    NoMatchingBaseDomain { hostname: String },
}

/// Certificate-related errors
#[derive(Error, Debug)]
pub enum CertificateError {
    /// Failed to load certificate
    #[error("Failed to load certificate from {path}: {reason}")]
    LoadFailed { path: String, reason: String },

    /// Certificate not configured for domain
    #[error("No certificate configured for domain: {domain}")]
    NotConfigured { domain: String },

    /// Invalid certificate format
    #[error("Invalid certificate format: {reason}")]
    InvalidFormat { reason: String },

    /// Private key error
    #[error("Private key error: {reason}")]
    PrivateKey { reason: String },
}

/// Upstream connection errors
#[derive(Error, Debug)]
pub enum UpstreamError {
    /// Connection failed
    #[error("Failed to connect to upstream {upstream}: {reason}")]
    ConnectionFailed { upstream: String, reason: String },

    /// Request failed
    #[error("Upstream request failed to {upstream}: {reason}")]
    RequestFailed { upstream: String, reason: String },
}

/// Result type alias for convenience
pub type DnsProxyResult<T> = Result<T, DnsProxyError>;

impl std::convert::From<anyhow::Error> for DnsProxyError {
    fn from(e: anyhow::Error) -> Self {
        DnsProxyError::Protocol(e.to_string())
    }
}
