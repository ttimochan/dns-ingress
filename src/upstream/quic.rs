use crate::error::{DnsProxyError, DnsProxyResult};
use crate::proxy::http::{is_dns_message_content_type, validate_dns_message};
use crate::quic::QuicApplication;
use crate::upstream::quic_pool::Http3ConnectionPool;
use crate::upstream::quic_pool::QuicConnectionPool;
use bytes::{Buf, Bytes};
use hyper::{Method, Request, Response};
use quinn::{RecvStream, SendStream};
use std::time::Duration;

const MAX_DNS_MESSAGE_SIZE: usize = u16::MAX as usize;

/// Forward exactly one DoQ transaction between two QUIC streams.
///
/// RFC 9250 maps one query to one client-initiated bidirectional stream.  The
/// query is one framed DNS message followed by FIN; the response may contain
/// multiple frames (for example AXFR/IXFR) and is relayed without buffering a
/// complete zone transfer in memory.
pub async fn forward_quic_stream(
    mut client_send: SendStream,
    mut client_recv: RecvStream,
    server_name: &str,
    upstream_port: u16,
    pool: &QuicConnectionPool,
    idle_timeout: Duration,
) -> DnsProxyResult<(u64, u64)> {
    let query = read_doq_query(&mut client_recv, idle_timeout).await?;
    let bytes_received = (query.len() + 2) as u64;

    let upstream_conn = tokio::time::timeout(
        idle_timeout,
        pool.get(QuicApplication::Doq, server_name, upstream_port),
    )
    .await
    .map_err(|_| doq_idle_timeout("opening upstream connection"))??;

    let (mut upstream_send, mut upstream_recv) = match tokio::time::timeout(
        idle_timeout,
        upstream_conn.connection().connection.open_bi(),
    )
    .await
    {
        Ok(Ok(streams)) => streams,
        Ok(Err(error)) => {
            pool.invalidate(QuicApplication::Doq, server_name, upstream_port)
                .await;
            return Err(DnsProxyError::Upstream(
                crate::error::UpstreamError::RequestFailed {
                    upstream: format!("{}:{}", server_name, upstream_port),
                    reason: format!("Failed to open DoQ stream: {error}"),
                },
            ));
        }
        Err(_) => {
            pool.invalidate(QuicApplication::Doq, server_name, upstream_port)
                .await;
            return Err(doq_idle_timeout("opening upstream stream"));
        }
    };
    write_doq_frame(&mut upstream_send, &query, idle_timeout).await?;
    upstream_send.finish().map_err(|error| {
        DnsProxyError::Upstream(crate::error::UpstreamError::RequestFailed {
            upstream: format!("{}:{}", server_name, upstream_port),
            reason: format!("Failed to finish DoQ query: {error}"),
        })
    })?;

    let mut bytes_sent = 0_u64;
    while let Some(response) = read_doq_frame(&mut upstream_recv, idle_timeout).await? {
        if response.len() < 12 || response[..2] != [0, 0] {
            return Err(DnsProxyError::Protocol(
                "DoQ upstream response has an invalid DNS message ID".to_string(),
            ));
        }
        bytes_sent += (response.len() + 2) as u64;
        write_doq_frame(&mut client_send, &response, idle_timeout).await?;
    }
    client_send
        .finish()
        .map_err(|e| DnsProxyError::Protocol(format!("Failed to finish client stream: {}", e)))?;

    Ok((bytes_received, bytes_sent))
}

async fn read_doq_query(recv: &mut RecvStream, idle_timeout: Duration) -> DnsProxyResult<Bytes> {
    let query = read_doq_frame(recv, idle_timeout).await?.ok_or_else(|| {
        DnsProxyError::Protocol("DoQ stream ended before query frame".to_string())
    })?;
    if query.len() < 12 {
        return Err(DnsProxyError::Protocol(
            "DoQ query is shorter than the DNS header".to_string(),
        ));
    }
    if query[..2] != [0, 0] {
        return Err(DnsProxyError::Protocol(
            "DoQ query DNS message ID must be zero".to_string(),
        ));
    }
    if read_doq_frame(recv, idle_timeout).await?.is_some() {
        return Err(DnsProxyError::Protocol(
            "DoQ stream contains more than one query".to_string(),
        ));
    }
    Ok(query)
}

async fn read_doq_frame(
    recv: &mut RecvStream,
    idle_timeout: Duration,
) -> DnsProxyResult<Option<Bytes>> {
    let mut length = [0_u8; 2];
    match tokio::time::timeout(idle_timeout, recv.read_exact(&mut length))
        .await
        .map_err(|_| doq_idle_timeout("reading DoQ frame length"))?
    {
        Ok(()) => {}
        Err(quinn::ReadExactError::FinishedEarly(0)) => return Ok(None),
        Err(error) => {
            return Err(DnsProxyError::Protocol(format!(
                "DoQ stream ended with an incomplete frame: {error}"
            )));
        }
    }
    let length = u16::from_be_bytes(length) as usize;
    if length == 0 {
        return Err(DnsProxyError::Protocol(
            "DoQ DNS frame must not be empty".to_string(),
        ));
    }
    let mut message = vec![0_u8; length];
    tokio::time::timeout(idle_timeout, recv.read_exact(&mut message))
        .await
        .map_err(|_| doq_idle_timeout("reading DoQ message"))?
        .map_err(|error| {
            DnsProxyError::Protocol(format!(
                "DoQ stream ended with an incomplete DNS message: {error}"
            ))
        })?;
    Ok(Some(Bytes::from(message)))
}

async fn write_doq_frame(
    send: &mut SendStream,
    message: &[u8],
    idle_timeout: Duration,
) -> DnsProxyResult<()> {
    let length = u16::try_from(message.len())
        .map_err(|_| DnsProxyError::Protocol("DoQ message exceeds 65535 bytes".to_string()))?;
    tokio::time::timeout(idle_timeout, send.write_all(&length.to_be_bytes()))
        .await
        .map_err(|_| doq_idle_timeout("writing DoQ frame length"))?
        .map_err(|error| {
            DnsProxyError::Protocol(format!("Failed to write DoQ frame length: {error}"))
        })?;
    tokio::time::timeout(idle_timeout, send.write_all(message))
        .await
        .map_err(|_| doq_idle_timeout("writing DoQ message"))?
        .map_err(|error| {
            DnsProxyError::Protocol(format!("Failed to write DoQ frame body: {error}"))
        })
}

fn doq_idle_timeout(operation: &str) -> DnsProxyError {
    DnsProxyError::Timeout {
        upstream: format!("DoQ transaction ({operation})"),
    }
}

/// Forward a DoH request over HTTP/3. DoH3 callers must never downgrade this
/// hop to TCP HTTPS, because HTTP/3 is selected and framed through QUIC ALPN.
#[allow(clippy::too_many_arguments)] // HTTP/3 forwarding needs request and pool context
pub async fn forward_http3_request(
    upstream_uri: &str,
    target_hostname: &str,
    port: u16,
    method: Method,
    headers: &hyper::HeaderMap,
    body: Bytes,
    timeout: Duration,
    pool: &Http3ConnectionPool,
) -> DnsProxyResult<(Response<http_body_util::Full<Bytes>>, u64)> {
    let session = tokio::time::timeout(timeout, pool.get(target_hostname, port))
        .await
        .map_err(|_| DnsProxyError::Timeout {
            upstream: format!("{}:{}", target_hostname, port),
        })??;
    let mut sender = session.sender();

    let request = async move {
        let mut request = Request::builder()
            .method(method)
            .uri(upstream_uri)
            .body(())
            .map_err(|error| DnsProxyError::Protocol(format!("Invalid HTTP/3 request: {error}")))?;
        for (name, value) in headers {
            if ["accept", "content-type"].contains(&name.as_str()) {
                request.headers_mut().insert(name, value.clone());
            }
        }
        request.headers_mut().insert(
            hyper::header::HOST,
            target_hostname.parse().map_err(|error| {
                DnsProxyError::Protocol(format!("Invalid upstream Host header: {error}"))
            })?,
        );
        let mut stream = tokio::time::timeout(timeout, sender.send_request(request))
            .await
            .map_err(|_| DnsProxyError::Timeout {
                upstream: upstream_uri.to_string(),
            })?
            .map_err(|error| {
                DnsProxyError::Upstream(crate::error::UpstreamError::RequestFailed {
                    upstream: upstream_uri.to_string(),
                    reason: error.to_string(),
                })
            })?;
        if !body.is_empty() {
            tokio::time::timeout(timeout, stream.send_data(body))
                .await
                .map_err(|_| DnsProxyError::Timeout {
                    upstream: upstream_uri.to_string(),
                })?
                .map_err(|error| DnsProxyError::Protocol(error.to_string()))?;
        }
        tokio::time::timeout(timeout, stream.finish())
            .await
            .map_err(|_| DnsProxyError::Timeout {
                upstream: upstream_uri.to_string(),
            })?
            .map_err(|error| DnsProxyError::Protocol(error.to_string()))?;
        let response = tokio::time::timeout(timeout, stream.recv_response())
            .await
            .map_err(|_| DnsProxyError::Timeout {
                upstream: upstream_uri.to_string(),
            })?
            .map_err(|error| DnsProxyError::Protocol(error.to_string()))?;
        let mut response_body = Vec::new();
        while let Some(chunk) = tokio::time::timeout(timeout, stream.recv_data())
            .await
            .map_err(|_| DnsProxyError::Timeout {
                upstream: upstream_uri.to_string(),
            })?
            .map_err(|error| DnsProxyError::Protocol(error.to_string()))?
        {
            if response_body.len().saturating_add(chunk.remaining()) > MAX_DNS_MESSAGE_SIZE {
                return Err(DnsProxyError::Upstream(
                    crate::error::UpstreamError::RequestFailed {
                        upstream: upstream_uri.to_string(),
                        reason: "HTTP/3 upstream response exceeds DNS message limit".to_string(),
                    },
                ));
            }
            response_body.extend_from_slice(chunk.chunk());
        }
        if response.status().is_success() {
            let content_type = response
                .headers()
                .get(hyper::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok());
            if !is_dns_message_content_type(content_type) {
                return Err(DnsProxyError::Upstream(
                    crate::error::UpstreamError::RequestFailed {
                        upstream: upstream_uri.to_string(),
                        reason: "HTTP/3 upstream returned a successful non-DNS response"
                            .to_string(),
                    },
                ));
            }
            validate_dns_message(&response_body, "HTTP/3 upstream DNS response").map_err(
                |error| {
                    DnsProxyError::Upstream(crate::error::UpstreamError::RequestFailed {
                        upstream: upstream_uri.to_string(),
                        reason: error.to_string(),
                    })
                },
            )?;
        }
        let response_body = Bytes::from(response_body);
        let length = response_body.len() as u64;
        Ok::<_, DnsProxyError>((
            response.map(|()| http_body_util::Full::new(response_body)),
            length,
        ))
    };
    let result = request.await;
    if result.is_err() {
        pool.invalidate(target_hostname, port).await;
    }
    result
}
