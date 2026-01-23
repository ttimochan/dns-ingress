use crate::config::{AppConfig, CertificateConfig};
use crate::error::{CertificateError, DnsProxyError, DnsProxyResult};
use dashmap::DashMap;
use rustls::server::{ClientHello, ResolvesServerCert, ServerConfig as RustlsServerConfig};
use rustls::sign::CertifiedKey;
use std::io::BufReader;
use std::sync::Arc;
use tokio::fs;

pub struct CertificateResolver {
    config: AppConfig,
    pub cert_cache: Arc<DashMap<String, Arc<CertifiedKey>>>,
}

impl CertificateResolver {
    pub fn new(config: AppConfig) -> Self {
        Self {
            config,
            cert_cache: Arc::new(DashMap::new()),
        }
    }

    pub fn with_arc(config: Arc<AppConfig>) -> Self {
        Self {
            config: (*config).clone(),
            cert_cache: Arc::new(DashMap::new()),
        }
    }

    pub fn tls_config(&self) -> &AppConfig {
        &self.config
    }

    pub async fn load_certificate(
        cert_config: &CertificateConfig,
    ) -> DnsProxyResult<Arc<CertifiedKey>> {
        let cert_bytes = fs::read(&cert_config.cert_file).await.map_err(|e| {
            DnsProxyError::Certificate(CertificateError::LoadFailed {
                path: cert_config.cert_file.clone(),
                reason: format!("Failed to read: {}", e),
            })
        })?;

        let key_bytes = fs::read(&cert_config.key_file).await.map_err(|e| {
            DnsProxyError::Certificate(CertificateError::LoadFailed {
                path: cert_config.key_file.clone(),
                reason: format!("Failed to read: {}", e),
            })
        })?;

        let mut cert_reader = BufReader::new(cert_bytes.as_slice());
        let certs_iter = rustls_pemfile::certs(&mut cert_reader);

        let certs: Vec<rustls::pki_types::CertificateDer> =
            certs_iter.collect::<Result<Vec<_>, _>>().map_err(|e| {
                DnsProxyError::Certificate(CertificateError::InvalidFormat {
                    reason: format!("Failed to parse certificate: {}", e),
                })
            })?;

        if certs.is_empty() {
            return Err(DnsProxyError::Certificate(
                CertificateError::InvalidFormat {
                    reason: "No certificates found in certificate file".to_string(),
                },
            ));
        }

        let mut key_reader = BufReader::new(key_bytes.as_slice());
        let mut keys_iter = rustls_pemfile::pkcs8_private_keys(&mut key_reader);

        let key_bytes = keys_iter
            .next()
            .ok_or_else(|| {
                DnsProxyError::Certificate(CertificateError::PrivateKey {
                    reason: "No private key found in key file".to_string(),
                })
            })?
            .map_err(|e| {
                DnsProxyError::Certificate(CertificateError::PrivateKey {
                    reason: format!("Failed to parse private key: {}", e),
                })
            })?;

        let key = rustls::pki_types::PrivateKeyDer::from(key_bytes);
        let signing_key =
            rustls::crypto::aws_lc_rs::sign::any_supported_type(&key).map_err(|e| {
                DnsProxyError::Certificate(CertificateError::PrivateKey {
                    reason: format!("Failed to create signing key: {}", e),
                })
            })?;

        let certified_key = CertifiedKey::new(certs, signing_key);

        Ok(Arc::new(certified_key))
    }

    pub async fn get_cert_for_domain(&self, domain: &str) -> DnsProxyResult<Arc<CertifiedKey>> {
        // Check cache first (fast path, lock-free with DashMap)
        if let Some(cert) = self.cert_cache.get(domain) {
            return Ok(Arc::clone(cert.value()));
        }

        // Load certificate from configuration
        let cert_config = self
            .config
            .tls
            .get_cert_config_or_err(domain)
            .map_err(|_e| {
                DnsProxyError::Certificate(CertificateError::NotConfigured {
                    domain: domain.to_string(),
                })
            })?;

        let cert = Self::load_certificate(cert_config).await.map_err(|e| {
            DnsProxyError::Certificate(CertificateError::LoadFailed {
                path: cert_config.cert_file.clone(),
                reason: format!("Failed to load for domain {}: {}", domain, e),
            })
        })?;

        // Update cache (lock-free)
        self.cert_cache
            .insert(domain.to_string(), Arc::clone(&cert));

        Ok(cert)
    }
}

pub struct DynamicCertResolver {
    pub resolver: Arc<CertificateResolver>,
}

impl DynamicCertResolver {
    pub fn new(resolver: Arc<CertificateResolver>) -> Self {
        Self { resolver }
    }
}

impl std::fmt::Debug for DynamicCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DynamicCertResolver")
    }
}

impl ResolvesServerCert for DynamicCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = match client_hello.server_name() {
            Some(sni) => sni,
            None => {
                tracing::warn!("TLS handshake without SNI, cannot select certificate");
                return None;
            }
        };

        let resolver = self.resolver.clone();
        let sni_str = sni.to_string();

        tracing::debug!("Resolving certificate for SNI: {}", sni_str);

        let rt = tokio::runtime::Handle::try_current();
        if let Ok(handle) = rt {
            match handle.block_on(resolver.get_cert_for_domain(&sni_str)) {
                Ok(cert) => {
                    tracing::debug!("Successfully loaded certificate for SNI: {}", sni_str);
                    Some(cert)
                }
                Err(e) => {
                    tracing::error!("Failed to load certificate for SNI {}: {}", sni_str, e);
                    None
                }
            }
        } else {
            tracing::error!(
                "No tokio runtime available for certificate loading (SNI: {})",
                sni_str
            );
            None
        }
    }
}

pub async fn create_server_config(config: &AppConfig) -> DnsProxyResult<RustlsServerConfig> {
    let resolver = Arc::new(CertificateResolver::new(config.clone()));
    let cert_resolver = Arc::new(DynamicCertResolver::new(resolver));

    Ok(RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(cert_resolver))
}
