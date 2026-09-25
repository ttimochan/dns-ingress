use crate::config::AppConfig;
use crate::tls_utils;
use anyhow::{Context, Result};
use quinn::crypto::rustls::QuicServerConfig;
use quinn::{Endpoint, ServerConfig};
use std::net::SocketAddr;
use std::sync::Arc;

/// ALPN values registered by the applicable DNS transports.
///
/// A QUIC listener must serve one application protocol only: accepting a DoQ
/// connection as HTTP/3 (or the inverse) makes the first stream undecodable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QuicApplication {
    Doq,
    H3,
}

impl QuicApplication {
    pub const fn alpn(self) -> &'static [u8] {
        match self {
            Self::Doq => b"doq",
            Self::H3 => b"h3",
        }
    }
}

/// Create a QUIC server endpoint from application config
pub async fn create_quic_server_endpoint(
    config: &AppConfig,
    bind_addr: SocketAddr,
    application: QuicApplication,
) -> Result<Endpoint> {
    // Create TLS server configuration
    let mut rustls_config = tls_utils::create_server_config(config)
        .await
        .context("Failed to create TLS server config")?;
    rustls_config.alpn_protocols = vec![application.alpn().to_vec()];

    // rustls::ServerConfig is already compatible with quinn::rustls::ServerConfig
    let rustls_config_arc = Arc::new(rustls_config);
    let quic_server_config = QuicServerConfig::try_from(rustls_config_arc)
        .context("Failed to create QuicServerConfig")?;
    let quinn_server_config = ServerConfig::with_crypto(Arc::new(quic_server_config));

    Endpoint::server(quinn_server_config, bind_addr).context("Failed to create QUIC endpoint")
}
