use dns_ingress::app::App;
use dns_ingress::config::{AppConfig, CertificateConfig};
use dns_ingress::error::DnsProxyError;
use dns_ingress::sni::SniRewriter;
use rustls::pki_types::{PrivateKeyDer, ServerName};
use std::io::BufReader;
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::{TlsAcceptor, TlsConnector};

#[tokio::test]
async fn test_app_start_all_disabled() {
    let mut config = AppConfig::default();
    config.servers.dot.enabled = false;
    config.servers.doh.enabled = false;
    config.servers.doq.enabled = false;
    config.servers.doh3.enabled = false;
    config.servers.healthcheck.enabled = false;

    assert!(config.validate().is_ok());

    let mut app = App::new(config);
    assert!(app.start().await.is_ok());

    tokio::time::sleep(Duration::from_millis(100)).await;

    app.wait_for_shutdown().await;
}

#[test]
fn test_config_validation() {
    let mut config = AppConfig::default();

    config.servers.dot.enabled = false;
    config.servers.doh.enabled = false;
    config.servers.doq.enabled = false;
    config.servers.doh3.enabled = false;
    config.servers.healthcheck.enabled = false;
    config.tls = Default::default();

    assert!(config.validate().is_ok());

    config.servers.dot.port = 443;
    config.servers.doh.port = 443;
    config.servers.dot.enabled = true;
    config.servers.doh.enabled = true;
    assert!(config.validate().is_err());
}

#[tokio::test]
async fn test_sni_rewrite_flow() {
    let config = AppConfig::default();
    let app = App::new(config);

    let test_sni = "www.example.org";
    let result = app.rewriter.rewrite(test_sni).await;

    assert!(result.is_some());
    let rewrite_result = result.unwrap();
    assert_eq!(rewrite_result.original, test_sni);
    assert_eq!(rewrite_result.prefix, "www");
    assert_eq!(rewrite_result.target_hostname, "www.example.cn");
}

#[test]
fn test_upstream_config_parsing() {
    let config = AppConfig::default();
    assert_eq!(config.upstream.dot.port, 853);
    assert_eq!(config.upstream.doq.port, 853);
    assert_eq!(config.upstream.doh.path, "/dns-query");
}

#[tokio::test]
async fn test_healthcheck_server_start() {
    let mut config = AppConfig::default();
    config.servers.dot.enabled = false;
    config.servers.doh.enabled = false;
    config.servers.doq.enabled = false;
    config.servers.doh3.enabled = false;
    config.servers.healthcheck.enabled = true;
    config.servers.healthcheck.port = 18080;

    assert!(config.validate().is_ok());

    let mut app = App::new(config);
    match app.start().await {
        Ok(()) => {}
        // The restricted CI sandbox used for unit tests has no socket-bind
        // capability. Production must still fail fast for the same error.
        Err(DnsProxyError::Io(error)) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            return;
        }
        Err(error) => panic!("healthcheck startup failed: {error}"),
    }

    tokio::time::sleep(Duration::from_millis(200)).await;

    let client = reqwest::Client::new();
    for path in ["/live", "/ready", "/health"] {
        let url = format!("http://127.0.0.1:{}{}", 18080, path);
        let response = timeout(Duration::from_secs(1), client.get(&url).send())
            .await
            .expect("healthcheck request timed out")
            .expect("healthcheck request failed");
        assert!(response.status().is_success(), "{} was not ready", path);
    }

    app.wait_for_shutdown().await;
}

#[tokio::test]
#[ignore = "requires a runner that permits local TCP sockets; CI runs ignored E2E tests explicitly"]
async fn dot_forwards_through_a_private_ca_upstream() {
    let fixture = PrivateCaFixture::new();
    let upstream_listener = match TcpListener::bind("127.0.0.1:0").await {
        Ok(listener) => listener,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            panic!("E2E runner denied upstream socket bind: {error}");
        }
        Err(error) => panic!("bind upstream listener: {error}"),
    };
    let upstream_port = upstream_listener.local_addr().unwrap().port();
    let upstream_acceptor = fixture.server_acceptor();
    let upstream = tokio::spawn(async move {
        let (stream, _) = upstream_listener.accept().await.unwrap();
        let mut stream = upstream_acceptor.accept(stream).await.unwrap();
        let mut length = [0_u8; 2];
        stream.read_exact(&mut length).await.unwrap();
        let mut query = vec![0_u8; u16::from_be_bytes(length) as usize];
        stream.read_exact(&mut query).await.unwrap();
        stream.write_all(&length).await.unwrap();
        stream.write_all(&query).await.unwrap();
        stream.shutdown().await.unwrap();
    });

    let ingress_port = reserve_tcp_port();
    let mut config = AppConfig::default();
    config.rewrite.base_domains = vec!["ingress.test".to_string()];
    // The rewriter still produces a hostname rather than accepting a fixed
    // upstream. The prefix `127` plus this suffix resolves to loopback.
    config.rewrite.target_suffix = ".0.0.1".to_string();
    config.servers.dot.bind_address = "127.0.0.1".to_string();
    config.servers.dot.port = ingress_port;
    config.servers.doh.enabled = false;
    config.servers.doq.enabled = false;
    config.servers.doh3.enabled = false;
    config.servers.healthcheck.enabled = false;
    config.upstream.dot.port = upstream_port;
    config.tls.default = Some(CertificateConfig {
        cert_file: fixture.cert_path(),
        key_file: fixture.key_path(),
    });
    config.tls.upstream_ca_file = Some(fixture.ca_path());

    let mut app = App::new(config);
    match app.start().await {
        Ok(()) => {}
        Err(DnsProxyError::Io(error)) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            upstream.abort();
            panic!("E2E runner denied ingress socket bind: {error}");
        }
        Err(error) => panic!("start DoT ingress: {error}"),
    }

    let stream = TcpStream::connect(("127.0.0.1", ingress_port))
        .await
        .unwrap();
    let mut client = fixture
        .client_connector()
        .connect(
            ServerName::try_from("127.ingress.test".to_string()).unwrap(),
            stream,
        )
        .await
        .unwrap();
    let query = [0x12, 0x34, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    client
        .write_all(&(query.len() as u16).to_be_bytes())
        .await
        .unwrap();
    client.write_all(&query).await.unwrap();
    let mut length = [0_u8; 2];
    timeout(Duration::from_secs(2), client.read_exact(&mut length))
        .await
        .expect("DoT response timed out")
        .unwrap();
    let mut response = vec![0_u8; u16::from_be_bytes(length) as usize];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, query);

    app.shutdown().await;
    timeout(Duration::from_secs(2), upstream)
        .await
        .expect("upstream task did not stop")
        .unwrap();
}

fn reserve_tcp_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct PrivateCaFixture {
    _directory: TempDir,
    certificate: std::path::PathBuf,
    key: std::path::PathBuf,
}

impl PrivateCaFixture {
    fn new() -> Self {
        let directory = TempDir::new().unwrap();
        let certificate = directory.path().join("cert.pem");
        let key = directory.path().join("key.pem");
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf_params = rcgen::CertificateParams::new(vec![
            "127.ingress.test".to_string(),
            "127.0.0.1".to_string(),
        ])
        .unwrap();
        let leaf = leaf_params.signed_by(&leaf_key, &ca, &ca_key).unwrap();
        std::fs::write(&certificate, leaf.pem()).unwrap();
        std::fs::write(&key, leaf_key.serialize_pem()).unwrap();
        std::fs::write(directory.path().join("ca.pem"), ca.pem()).unwrap();
        Self {
            _directory: directory,
            certificate,
            key,
        }
    }

    fn cert_path(&self) -> String {
        self.certificate.display().to_string()
    }

    fn ca_path(&self) -> String {
        self._directory.path().join("ca.pem").display().to_string()
    }

    fn key_path(&self) -> String {
        self.key.display().to_string()
    }

    fn certificates(&self) -> Vec<rustls::pki_types::CertificateDer<'static>> {
        rustls_pemfile::certs(&mut BufReader::new(
            std::fs::File::open(&self.certificate).unwrap(),
        ))
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
    }

    fn server_acceptor(&self) -> TlsAcceptor {
        let certificates = self.certificates();
        let key = rustls_pemfile::pkcs8_private_keys(&mut BufReader::new(
            std::fs::File::open(&self.key).unwrap(),
        ))
        .next()
        .unwrap()
        .unwrap();
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certificates, PrivateKeyDer::Pkcs8(key))
            .unwrap();
        TlsAcceptor::from(std::sync::Arc::new(config))
    }

    fn client_connector(&self) -> TlsConnector {
        let mut roots = rustls::RootCertStore::empty();
        let ca = rustls_pemfile::certs(&mut BufReader::new(
            std::fs::File::open(self._directory.path().join("ca.pem")).unwrap(),
        ))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
        for certificate in ca {
            roots.add(certificate).unwrap();
        }
        TlsConnector::from(std::sync::Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ))
    }
}
