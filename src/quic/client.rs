use super::config::QuicApplication;
use anyhow::{Context, Result};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::rustls::ClientConfig;
use quinn::{ClientConfig as QuinnClientConfig, Connection, Endpoint};
use std::net::SocketAddr;
use std::sync::Arc;

/// A connection must retain its endpoint for its entire lifetime. Keeping both
/// in a pool avoids creating a UDP socket and TLS/QUIC handshake per DNS query.
pub struct UpstreamQuicConnection {
    pub _endpoint: Endpoint,
    pub connection: Connection,
}

/// Create a QUIC client connection to upstream server.
pub async fn connect_quic_upstream(
    addr: SocketAddr,
    server_name: &str,
    application: QuicApplication,
    root_store: Arc<rustls::RootCertStore>,
) -> Result<UpstreamQuicConnection> {
    let mut client_crypto = ClientConfig::builder()
        .with_root_certificates((*root_store).clone())
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![application.alpn().to_vec()];

    let quic_client_config =
        QuicClientConfig::try_from(client_crypto).context("Failed to create QuicClientConfig")?;
    let client_config = QuinnClientConfig::new(Arc::new(quic_client_config));

    let bind_addr = if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let mut endpoint = Endpoint::client(bind_addr.parse()?)?;
    endpoint.set_default_client_config(client_config);

    let connection = endpoint
        .connect(addr, server_name)?
        .await
        .context("Failed to connect to upstream QUIC server")?;
    Ok(UpstreamQuicConnection {
        _endpoint: endpoint,
        connection,
    })
}
