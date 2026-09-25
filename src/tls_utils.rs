use crate::config::{AppConfig, CertificateConfig};
use crate::error::{CertificateError, DnsProxyError, DnsProxyResult};
use rustls::server::{ClientHello, ResolvesServerCert, ServerConfig as RustlsServerConfig};
use rustls::sign::CertifiedKey;
use std::io::BufReader;
use std::sync::Arc;

pub struct CertificateResolver {
    certs: std::collections::HashMap<String, Arc<CertifiedKey>>,
    default: Option<Arc<CertifiedKey>>,
}

impl CertificateResolver {
    /// Load every configured certificate before accepting traffic. Rustls calls
    /// `resolve` synchronously during a handshake, so disk I/O here would
    /// otherwise block the runtime (and used to attempt a nested runtime).
    pub fn new(config: &AppConfig) -> DnsProxyResult<Self> {
        let default = config
            .tls
            .default
            .as_ref()
            .map(Self::load_certificate)
            .transpose()?;
        let mut certs = std::collections::HashMap::new();
        for (domain, cert_config) in &config.tls.certs {
            certs.insert(
                domain.to_ascii_lowercase(),
                Self::load_certificate(cert_config)?,
            );
        }
        Ok(Self { certs, default })
    }

    pub fn load_certificate(cert_config: &CertificateConfig) -> DnsProxyResult<Arc<CertifiedKey>> {
        let cert_bytes = std::fs::read(&cert_config.cert_file).map_err(|e| {
            DnsProxyError::Certificate(CertificateError::LoadFailed {
                path: cert_config.cert_file.clone(),
                reason: format!("Failed to read: {}", e),
            })
        })?;

        let key_bytes = std::fs::read(&cert_config.key_file).map_err(|e| {
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

    pub fn get_cert_for_domain(&self, domain: &str) -> DnsProxyResult<Arc<CertifiedKey>> {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        if let Some(cert) = self.certs.get(&domain) {
            return Ok(Arc::clone(cert));
        }
        // A configured base-domain certificate applies to its subdomains. Pick
        // the longest suffix so overlapping bases remain deterministic.
        if let Some((_, cert)) = self
            .certs
            .iter()
            .filter(|(base, _)| {
                domain.ends_with(base.as_str())
                    && domain.len() > base.len()
                    && domain.as_bytes()[domain.len() - base.len() - 1] == b'.'
            })
            .max_by_key(|(base, _)| base.len())
        {
            return Ok(Arc::clone(cert));
        }
        self.default.clone().ok_or(DnsProxyError::Certificate(
            CertificateError::NotConfigured { domain },
        ))
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

        let sni_str = sni.to_string();

        tracing::debug!("Resolving certificate for SNI: {}", sni_str);

        match self.resolver.get_cert_for_domain(&sni_str) {
            Ok(cert) => Some(cert),
            Err(e) => {
                tracing::error!("No certificate for SNI {}: {}", sni_str, e);
                None
            }
        }
    }
}

pub async fn create_server_config(config: &AppConfig) -> DnsProxyResult<RustlsServerConfig> {
    let resolver = Arc::new(CertificateResolver::new(config)?);
    let cert_resolver = Arc::new(DynamicCertResolver::new(resolver));

    Ok(RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(cert_resolver))
}
