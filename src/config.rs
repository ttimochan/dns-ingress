use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::SocketAddr;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    pub rewrite: RewriteConfig,
    pub servers: ServersConfig,
    pub upstream: UpstreamConfig,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RewriteConfig {
    /// Base domains to match (e.g., ["example.com", "example.org"])
    /// The rewriter will extract prefix from hostnames matching these base domains
    pub base_domains: Vec<String>,
    /// Target suffix for upstream (e.g., ".example.cn")
    /// The extracted prefix will be combined with this suffix to form the target hostname
    pub target_suffix: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServersConfig {
    pub dot: ServerPortConfig,
    pub doh: ServerPortConfig,
    pub doq: ServerPortConfig,
    pub doh3: ServerPortConfig,
    #[serde(default = "HealthcheckConfig::default")]
    pub healthcheck: HealthcheckConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerPortConfig {
    pub enabled: bool,
    pub bind_address: String,
    pub port: u16,
    /// HTTP request path for DoH/DoH3 listeners. Ignored by DoT and DoQ.
    #[serde(default = "default_doh_path")]
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthcheckConfig {
    pub enabled: bool,
    pub bind_address: String,
    pub port: u16,
    pub path: String,
}

impl Default for HealthcheckConfig {
    fn default() -> Self {
        HealthcheckConfig {
            enabled: true,
            bind_address: "0.0.0.0".to_string(),
            port: 8080,
            path: "/health".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamConfig {
    pub dot: DnsUpstreamConfig,
    pub doh: HttpUpstreamConfig,
    pub doq: DnsUpstreamConfig,
    pub doh3: HttpUpstreamConfig,
}

/// The destination hostname is always produced by the rewriter.  These
/// settings deliberately contain only protocol endpoint details, so a stale
/// fixed upstream IP cannot silently bypass domain routing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsUpstreamConfig {
    #[serde(default = "default_dns_port")]
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpUpstreamConfig {
    #[serde(default = "default_https_port")]
    pub port: u16,
    #[serde(default = "default_doh_path")]
    pub path: String,
}

fn default_dns_port() -> u16 {
    853
}
fn default_https_port() -> u16 {
    443
}
fn default_doh_path() -> String {
    "/dns-query".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// Default certificate configuration (used when no domain-specific cert is found)
    #[serde(default)]
    pub default: Option<CertificateConfig>,
    /// Domain-specific certificate configurations
    /// Key is the domain name (e.g., "example.com"), value is the certificate config
    #[serde(default)]
    pub certs: std::collections::HashMap<String, CertificateConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    /// Log level: trace, debug, info, warn, error (default: info)
    #[serde(default = "default_log_level")]
    pub level: String,
    /// Log file path (optional, if not set, logs only to stdout/stderr)
    #[serde(default)]
    pub file: Option<String>,
    /// Enable JSON format for logs (default: false)
    #[serde(default)]
    pub json: bool,
    /// Enable log rotation (default: true if file is set)
    #[serde(default = "default_true")]
    pub rotation: bool,
    /// Maximum log file size in bytes before rotation (default: 10MB)
    #[serde(default = "default_max_file_size")]
    pub max_file_size: u64,
    /// Number of log files to keep (default: 5)
    #[serde(default = "default_max_files")]
    pub max_files: usize,
}

/// Bounded resource usage for publicly exposed listeners. Zone transfers are
/// streamed and therefore do not need a total-byte limit.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    #[serde(default = "default_max_connections_per_listener")]
    pub max_connections_per_listener: usize,
    #[serde(default = "default_max_inflight_requests_per_connection")]
    pub max_inflight_requests_per_connection: usize,
    #[serde(default = "default_max_upstream_pool_entries")]
    pub max_upstream_pool_entries: usize,
    #[serde(default = "default_transaction_timeout_seconds")]
    pub transaction_timeout_seconds: u64,
}

fn default_max_connections_per_listener() -> usize {
    1024
}
fn default_max_inflight_requests_per_connection() -> usize {
    64
}
fn default_max_upstream_pool_entries() -> usize {
    256
}
fn default_transaction_timeout_seconds() -> u64 {
    30
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_connections_per_listener: default_max_connections_per_listener(),
            max_inflight_requests_per_connection: default_max_inflight_requests_per_connection(),
            max_upstream_pool_entries: default_max_upstream_pool_entries(),
            transaction_timeout_seconds: default_transaction_timeout_seconds(),
        }
    }
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_true() -> bool {
    true
}

fn default_max_file_size() -> u64 {
    10 * 1024 * 1024 // 10MB
}

fn default_max_files() -> usize {
    5
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            file: None,
            json: false,
            rotation: default_true(),
            max_file_size: default_max_file_size(),
            max_files: default_max_files(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateConfig {
    /// Certificate file path (PEM format)
    pub cert_file: String,
    /// Private key file path (PEM format)
    pub key_file: String,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            rewrite: RewriteConfig {
                base_domains: vec!["example.com".to_string(), "example.org".to_string()],
                target_suffix: ".example.cn".to_string(),
            },
            servers: ServersConfig {
                dot: ServerPortConfig {
                    enabled: true,
                    bind_address: "0.0.0.0".to_string(),
                    port: 853,
                    path: default_doh_path(),
                },
                doh: ServerPortConfig {
                    enabled: true,
                    bind_address: "0.0.0.0".to_string(),
                    port: 443,
                    path: default_doh_path(),
                },
                doq: ServerPortConfig {
                    enabled: true,
                    bind_address: "0.0.0.0".to_string(),
                    port: 853,
                    path: default_doh_path(),
                },
                doh3: ServerPortConfig {
                    enabled: false,
                    bind_address: "0.0.0.0".to_string(),
                    port: 443,
                    path: default_doh_path(),
                },
                healthcheck: HealthcheckConfig::default(),
            },
            upstream: UpstreamConfig {
                dot: DnsUpstreamConfig {
                    port: default_dns_port(),
                },
                doh: HttpUpstreamConfig {
                    port: default_https_port(),
                    path: default_doh_path(),
                },
                doq: DnsUpstreamConfig {
                    port: default_dns_port(),
                },
                doh3: HttpUpstreamConfig {
                    port: default_https_port(),
                    path: default_doh_path(),
                },
            },
            tls: TlsConfig::default(),
            logging: LoggingConfig::default(),
            limits: LimitsConfig::default(),
        }
    }
}

impl AppConfig {
    /// Load configuration from a TOML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path.as_ref())
            .with_context(|| format!("Failed to read config file: {:?}", path.as_ref()))?;
        reject_removed_v1_fields(&content)?;
        let config: AppConfig =
            toml::from_str(&content).with_context(|| "Failed to parse config file")?;
        Ok(config)
    }

    /// Validate configuration before starting servers
    pub fn validate(&self) -> Result<()> {
        use std::collections::HashSet;

        // Check for port conflicts
        let mut ports = HashSet::new();

        // Check standard server ports
        let standard_servers: &[(&str, &str, &ServerPortConfig)] = &[
            ("dot", "tcp", &self.servers.dot),
            ("doh", "tcp", &self.servers.doh),
            ("doq", "udp", &self.servers.doq),
            ("doh3", "udp", &self.servers.doh3),
        ];

        for (name, transport, config) in standard_servers {
            if config.enabled {
                let addr = format!("{}:{}", config.bind_address, config.port);
                if let Ok(socket_addr) = addr.parse::<SocketAddr>() {
                    if !ports.insert((*transport, socket_addr.ip(), socket_addr.port())) {
                        anyhow::bail!(
                            "Port conflict: {} is already used by another server",
                            socket_addr.port()
                        );
                    }
                } else {
                    anyhow::bail!("Invalid bind address for {}: {}", name, addr);
                }
            }
        }

        // Check healthcheck server port
        if self.servers.healthcheck.enabled {
            let addr = format!(
                "{}:{}",
                self.servers.healthcheck.bind_address, self.servers.healthcheck.port
            );
            if let Ok(socket_addr) = addr.parse::<SocketAddr>() {
                if !ports.insert(("tcp", socket_addr.ip(), socket_addr.port())) {
                    anyhow::bail!(
                        "Port conflict: {} is already used by another server",
                        socket_addr.port()
                    );
                }
            } else {
                anyhow::bail!("Invalid bind address for healthcheck: {}", addr);
            }
        }

        // Validate TLS certificate files exist
        if let Some(default_cert) = &self.tls.default {
            std::fs::metadata(&default_cert.cert_file).with_context(|| {
                format!(
                    "Default certificate file not found: {}",
                    default_cert.cert_file
                )
            })?;
            std::fs::metadata(&default_cert.key_file).with_context(|| {
                format!("Default key file not found: {}", default_cert.key_file)
            })?;
        }

        for (domain, cert_config) in &self.tls.certs {
            std::fs::metadata(&cert_config.cert_file).with_context(|| {
                format!(
                    "Certificate file not found for {}: {}",
                    domain, cert_config.cert_file
                )
            })?;
            std::fs::metadata(&cert_config.key_file).with_context(|| {
                format!(
                    "Key file not found for {}: {}",
                    domain, cert_config.key_file
                )
            })?;
        }

        // Validate rewrite configuration
        if self.rewrite.base_domains.is_empty() {
            anyhow::bail!("At least one base domain must be configured for SNI rewriting");
        }

        if !self.rewrite.target_suffix.starts_with('.') {
            anyhow::bail!("Target suffix must start with '.' (e.g., '.example.cn')");
        }

        if self
            .rewrite
            .base_domains
            .iter()
            .any(|domain| !is_ascii_dns_name(domain))
            || !is_ascii_dns_suffix(&self.rewrite.target_suffix)
        {
            anyhow::bail!("Rewrite domains must be lowercase ASCII DNS names");
        }

        if self.limits.max_connections_per_listener == 0
            || self.limits.max_inflight_requests_per_connection == 0
            || self.limits.max_upstream_pool_entries == 0
            || self.limits.transaction_timeout_seconds == 0
        {
            anyhow::bail!("All resource limits must be greater than zero");
        }

        if [
            self.servers.dot.enabled,
            self.servers.doh.enabled,
            self.servers.doq.enabled,
            self.servers.doh3.enabled,
        ]
        .into_iter()
        .any(|enabled| enabled)
            && self.tls.default.is_none()
            && self.tls.certs.is_empty()
        {
            anyhow::bail!(
                "At least one TLS certificate is required when a DNS ingress listener is enabled"
            );
        }

        for (protocol, endpoint) in [("doh", &self.upstream.doh), ("doh3", &self.upstream.doh3)] {
            if !endpoint.path.starts_with('/') {
                anyhow::bail!("{} upstream path must start with '/'", protocol);
            }
        }

        for (protocol, server) in [("doh", &self.servers.doh), ("doh3", &self.servers.doh3)] {
            if !server.path.starts_with('/') {
                anyhow::bail!("{} listener path must start with '/'", protocol);
            }
        }

        Ok(())
    }
}

fn is_ascii_dns_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            let bytes = label.as_bytes();
            !bytes.is_empty()
                && bytes.len() <= 63
                && bytes.first().is_some_and(u8::is_ascii_alphanumeric)
                && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
                && bytes
                    .iter()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        })
}

fn is_ascii_dns_suffix(suffix: &str) -> bool {
    suffix.starts_with('.') && is_ascii_dns_name(&suffix[1..])
}

fn reject_removed_v1_fields(content: &str) -> Result<()> {
    let value: toml::Value =
        toml::from_str(content).with_context(|| "Failed to parse config file")?;
    let has_key = |section: &str, key: &str| {
        value
            .get(section)
            .and_then(toml::Value::as_table)
            .is_some_and(|table| table.contains_key(key))
    };
    if has_key("rewrite", "rewrite_failure_strategy") {
        anyhow::bail!(
            "rewrite.rewrite_failure_strategy was removed in v2; unmatched domains are always rejected"
        );
    }
    if has_key("upstream", "default") {
        anyhow::bail!(
            "upstream.default was removed in v2; upstream hostnames are always derived from rewrite"
        );
    }
    for key in [
        "ca_file",
        "require_client_cert",
        "client_cert_file",
        "client_key_file",
    ] {
        if has_key("tls", key) {
            anyhow::bail!(
                "tls.{} was removed in v2; inbound mTLS is not supported",
                key
            );
        }
    }
    Ok(())
}
