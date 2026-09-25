//! Utility functions for DNS Proxy
//!
//! Contains exponential backoff utilities and other helper functions.

pub mod backoff;

/// Extract a canonical DNS hostname from an HTTP Host/authority value.
pub fn normalize_hostname(authority: &str) -> Option<String> {
    let authority = authority.parse::<hyper::http::uri::Authority>().ok()?;
    let host = authority.host().trim_end_matches('.').to_ascii_lowercase();
    (!host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-'))
    .then_some(host)
}
