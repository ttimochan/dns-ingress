use crate::config::AppConfig;
use crate::error::DnsProxyResult;
use crate::metrics::Metrics;
use crate::tasks::TaskGroup;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, oneshot};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

pub struct HealthcheckServer {
    config: Arc<AppConfig>,
    metrics: Arc<Metrics>,
    ready: Arc<AtomicBool>,
    tasks: TaskGroup,
}

impl HealthcheckServer {
    pub fn with_metrics_and_readiness(
        config: Arc<AppConfig>,
        metrics: Arc<Metrics>,
        ready: Arc<AtomicBool>,
    ) -> Self {
        Self {
            config,
            metrics,
            ready,
            tasks: TaskGroup::default(),
        }
    }

    pub(crate) fn task_group(&self) -> TaskGroup {
        self.tasks.clone()
    }

    #[allow(dead_code)]
    pub async fn start(&self) -> DnsProxyResult<()> {
        self.run(CancellationToken::new(), None).await
    }

    pub async fn run(
        &self,
        shutdown: CancellationToken,
        ready_sender: Option<oneshot::Sender<DnsProxyResult<()>>>,
    ) -> DnsProxyResult<()> {
        let server_config = &self.config.servers.healthcheck;
        if !server_config.enabled {
            info!("Healthcheck server is disabled");
            return Ok(());
        }

        let bind_addr = format!("{}:{}", server_config.bind_address, server_config.port);
        let listener = match TcpListener::bind(&bind_addr).await {
            Ok(listener) => listener,
            Err(error) => {
                let kind = error.kind();
                let message = error.to_string();
                if let Some(sender) = ready_sender {
                    let _ = sender.send(Err(crate::error::DnsProxyError::Io(std::io::Error::new(
                        kind,
                        message.clone(),
                    ))));
                }
                return Err(crate::error::DnsProxyError::Io(std::io::Error::new(
                    kind, message,
                )));
            }
        };

        info!(
            "Healthcheck server listening on {}:{} at path {}",
            server_config.bind_address, server_config.port, server_config.path
        );

        let healthcheck_path = server_config.path.clone();
        let metrics = Arc::clone(&self.metrics);
        let ready = Arc::clone(&self.ready);
        let connection_limit = Arc::new(Semaphore::new(
            self.config.limits.max_connections_per_listener,
        ));
        if let Some(sender) = ready_sender {
            let _ = sender.send(Ok(()));
        }

        loop {
            let accepted = tokio::select! {
                _ = shutdown.cancelled() => break,
                accepted = listener.accept() => accepted,
            };
            match accepted {
                Ok((stream, addr)) => {
                    let permit = tokio::select! {
                        _ = shutdown.cancelled() => break,
                        permit = Arc::clone(&connection_limit).acquire_owned() => match permit {
                            Ok(permit) => permit,
                            Err(_) => break,
                        },
                    };
                    let path = healthcheck_path.clone();
                    let metrics = Arc::clone(&metrics);
                    let ready = Arc::clone(&ready);
                    let client_addr = addr;
                    let shutdown = shutdown.clone();
                    let tasks = self.tasks.clone();
                    tasks
                        .spawn(async move {
                            let _connection_permit = permit;
                            let io = TokioIo::new(stream);
                            let service = service_fn(move |req| {
                                let path = path.clone();
                                let addr = client_addr;
                                let metrics = Arc::clone(&metrics);
                                let ready = Arc::clone(&ready);
                                async move {
                                    handle_healthcheck(
                                        req,
                                        &path,
                                        &metrics,
                                        ready.load(Ordering::Relaxed),
                                    )
                                    .await
                                    .map_err(|e| {
                                        error!("Healthcheck handler error from {}: {}", addr, e);
                                        std::io::Error::other(e.to_string())
                                    })
                                }
                            });

                            let connection = http1::Builder::new().serve_connection(io, service);
                            let result = tokio::select! {
                                _ = shutdown.cancelled() => Ok(()),
                                result = connection => result,
                            };
                            if let Err(e) = result {
                                error!("Healthcheck connection error from {}: {}", client_addr, e);
                            }
                        })
                        .await;
                }
                Err(e) => {
                    error!("Healthcheck accept error: {}", e);
                }
            }
        }
        self.tasks
            .close_and_wait_until(tokio::time::Instant::now() + std::time::Duration::from_secs(10))
            .await;
        Ok(())
    }
}

async fn handle_healthcheck(
    req: Request<hyper::body::Incoming>,
    healthcheck_path: &str,
    metrics: &Metrics,
    ready: bool,
) -> Result<Response<Full<Bytes>>, std::io::Error> {
    if req.method() != Method::GET {
        return Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(Full::new(Bytes::from("Method not allowed")))
            .map_err(std::io::Error::other);
    }

    let path = req.uri().path();

    if path == "/live" {
        return Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(r#"{"status":"live"}"#)))
            .map_err(std::io::Error::other);
    }
    if path == "/ready" {
        let status = if ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        };
        let body = if ready {
            r#"{"status":"ready"}"#
        } else {
            r#"{"status":"not_ready"}"#
        };
        return Response::builder()
            .status(status)
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(body)))
            .map_err(std::io::Error::other);
    }

    if path == "/metrics" || path == "/stats" {
        return Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/plain; version=0.0.4")
            .body(Full::new(Bytes::from(metrics.prometheus())))
            .map_err(std::io::Error::other);
    }
    if path == "/metrics/json" {
        return Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(
                serde_json::to_string(&metrics.snapshot()).map_err(std::io::Error::other)?,
            )))
            .map_err(std::io::Error::other);
    }
    if path != healthcheck_path {
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from("Not found")))
            .map_err(std::io::Error::other);
    }

    let response = serde_json::json!({
        "status": if ready { "ready" } else { "not_ready" },
        "service": "dns-proxy"
    });

    Response::builder()
        .status(if ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        })
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(response.to_string())))
        .map_err(std::io::Error::other)
}
