mod app;
mod config;
mod error;
mod logging;
mod metrics;
mod proxy;
mod quic;
mod readers;
mod rewrite;
mod rewriters;
mod sni;
mod tls_utils;
mod upstream;
mod utils;

use anyhow::{Context, Result};
use tokio::signal;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|e| anyhow::anyhow!("Failed to install default crypto provider: {:?}", e))?;

    let config = config::AppConfig::from_file("config.toml")
        .context("Failed to load required config.toml")?;

    config
        .validate()
        .context("Configuration validation failed")?;

    let _guard =
        logging::init_logging(&config.logging).context("Failed to initialize logging system")?;

    info!("DNS Proxy Server starting...");

    let mut app = app::App::new(config);
    app.start()
        .await
        .context("Failed to start DNS Proxy Server")?;

    info!("DNS Proxy Server started successfully. Press Ctrl+C to shutdown.");

    signal::ctrl_c()
        .await
        .context("Failed to listen for shutdown signal")?;

    info!("Shutdown signal received, shutting down gracefully...");
    app.wait_for_shutdown().await;

    info!("DNS Proxy Server shut down complete.");

    Ok(())
}
