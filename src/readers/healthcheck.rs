use crate::config::AppConfig;
use crate::error::DnsProxyResult;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info};

pub struct HealthcheckServer {
    config: Arc<AppConfig>,
}

impl HealthcheckServer {
    pub fn new(config: Arc<AppConfig>) -> Self {
        Self { config }
    }

    pub async fn start(&self) -> DnsProxyResult<()> {
        let server_config = &self.config.servers.healthcheck;
        if !server_config.enabled {
            info!("Healthcheck server is disabled");
            return Ok(());
        }

        let bind_addr = format!("{}:{}", server_config.bind_address, server_config.port);
        let listener = TcpListener::bind(&bind_addr).await?;

        info!(
            "Healthcheck server listening on {}:{} at path {}",
            server_config.bind_address, server_config.port, server_config.path
        );

        let healthcheck_path = server_config.path.clone();

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    let path = healthcheck_path.clone();
                    let client_addr = addr;
                    tokio::spawn(async move {
                        let io = TokioIo::new(stream);
                        let service = service_fn(move |req| {
                            let path = path.clone();
                            let addr = client_addr;
                            async move {
                                handle_healthcheck(req, &path).await.map_err(|e| {
                                    error!("Healthcheck handler error from {}: {}", addr, e);
                                    std::io::Error::other(e.to_string())
                                })
                            }
                        });

                        if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
                            error!("Healthcheck connection error from {}: {}", client_addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("Healthcheck accept error: {}", e);
                }
            }
        }
    }
}

async fn handle_healthcheck(
    req: Request<hyper::body::Incoming>,
    healthcheck_path: &str,
) -> Result<Response<Full<Bytes>>, std::io::Error> {
    if req.method() != Method::GET {
        return Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Full::new(Bytes::from("Method not allowed")))
            .map_err(std::io::Error::other);
    }

    let path = req.uri().path();

    if path != healthcheck_path {
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from("Not found")))
            .map_err(std::io::Error::other);
    }

    let response = serde_json::json!({
        "status": "healthy",
        "service": "dns-proxy"
    });

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(response.to_string())))
        .map_err(std::io::Error::other)
}
