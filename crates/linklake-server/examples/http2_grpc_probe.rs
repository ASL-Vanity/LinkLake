use anyhow::{anyhow, Context};
use bytes::Bytes;
use http_body_util::{channel::Channel, combinators::UnsyncBoxBody, BodyExt, Full};
use hyper::{
    body::Incoming,
    client::conn::http2 as client_http2,
    header::{self, HeaderMap, HeaderValue},
    server::conn::http2 as server_http2,
    service::service_fn,
    Request, Response, StatusCode, Uri, Version,
};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use serde_json::json;
use std::{
    convert::Infallible,
    error::Error,
    fs::OpenOptions,
    io::Write,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::mpsc,
    time::{sleep, timeout},
};

type BoxError = Box<dyn Error + Send + Sync>;
type ProbeBody = UnsyncBoxBody<Bytes, BoxError>;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    match arguments.first().map(String::as_str) {
        Some("backend") if arguments.len() == 3 => {
            run_backend(arguments[1].parse()?, PathBuf::from(&arguments[2])).await
        }
        Some("probe-stream") if arguments.len() == 3 => {
            probe_stream(arguments[1].parse()?, &arguments[2]).await
        }
        Some("probe-single") if arguments.len() == 5 => {
            probe_single(
                arguments[1].parse()?,
                &arguments[2],
                &arguments[3],
                &arguments[4],
            )
            .await
        }
        Some("probe-cancel") if arguments.len() == 3 => {
            probe_cancel(arguments[1].parse()?, &arguments[2]).await
        }
        _ => Err(anyhow!(
            "usage: http2_grpc_probe backend <listen> <observations> | probe-stream <endpoint> <host> | probe-single <endpoint> <host> <path> <payload> | probe-cancel <endpoint> <host>"
        )),
    }
}

async fn run_backend(listen: SocketAddr, observations: PathBuf) -> anyhow::Result<()> {
    let listener = TcpListener::bind(listen).await?;
    let next_connection_id = Arc::new(AtomicU64::new(1));
    loop {
        let (stream, _) = listener.accept().await?;
        let connection_id = next_connection_id.fetch_add(1, Ordering::Relaxed);
        let observations = observations.clone();
        tokio::spawn(async move {
            if let Err(error) =
                serve_backend_connection(stream, connection_id, observations.clone()).await
            {
                append_observation(
                    &observations,
                    json!({
                        "event": "connection_error",
                        "connection_id": connection_id,
                        "message": error.to_string(),
                    }),
                );
            }
        });
    }
}

async fn serve_backend_connection(
    stream: TcpStream,
    connection_id: u64,
    observations: PathBuf,
) -> anyhow::Result<()> {
    append_observation(
        &observations,
        json!({"event": "connection_open", "connection_id": connection_id}),
    );
    let (goaway_tx, mut goaway_rx) = mpsc::unbounded_channel();
    let service_observations = observations.clone();
    let service = service_fn(move |request: Request<Incoming>| {
        let goaway_tx = goaway_tx.clone();
        let observations = service_observations.clone();
        async move {
            let path = request.uri().path().to_owned();
            let cancel_mode = path == "/grpc.echo/Cancel";
            let goaway_mode = path == "/grpc.echo/GoAway";
            append_observation(
                &observations,
                json!({
                    "event": "request",
                    "connection_id": connection_id,
                    "path": path,
                }),
            );
            let mut request_body = request.into_body();
            let (mut response_tx, response_body) = Channel::<Bytes, Infallible>::new(16);
            tokio::spawn(async move {
                while let Some(frame) = request_body.frame().await {
                    let Ok(frame) = frame else {
                        return;
                    };
                    let Some(data) = frame.data_ref().filter(|data| !data.is_empty()) else {
                        continue;
                    };
                    if response_tx.send_data(data.clone()).await.is_err() {
                        return;
                    }
                    if cancel_mode {
                        loop {
                            sleep(Duration::from_millis(50)).await;
                            if response_tx
                                .send_data(Bytes::from_static(b"tick"))
                                .await
                                .is_err()
                            {
                                append_observation(
                                    &observations,
                                    json!({
                                        "event": "cancelled",
                                        "connection_id": connection_id,
                                    }),
                                );
                                return;
                            }
                        }
                    }
                }
                let mut trailers = HeaderMap::new();
                trailers.insert("grpc-status", HeaderValue::from_static("0"));
                trailers.insert("grpc-message", HeaderValue::from_static("ok"));
                if response_tx.send_trailers(trailers).await.is_ok() && goaway_mode {
                    append_observation(
                        &observations,
                        json!({
                            "event": "goaway",
                            "connection_id": connection_id,
                        }),
                    );
                    let _ = goaway_tx.send(());
                }
            });
            Ok::<_, Infallible>(
                Response::builder()
                    .status(StatusCode::OK)
                    .version(Version::HTTP_2)
                    .header(header::CONTENT_TYPE, "application/grpc")
                    .header("x-linklake-backend-connection", connection_id.to_string())
                    .body(response_body)
                    .expect("static HTTP/2 backend response should build"),
            )
        }
    });
    let mut builder = server_http2::Builder::new(TokioExecutor::new());
    builder
        .timer(TokioTimer::new())
        .adaptive_window(true)
        .max_concurrent_streams(Some(256))
        .keep_alive_interval(Some(Duration::from_secs(20)))
        .keep_alive_timeout(Duration::from_secs(10));
    let connection = builder.serve_connection(TokioIo::new(stream), service);
    tokio::pin!(connection);
    tokio::select! {
        result = &mut connection => result?,
        _ = goaway_rx.recv() => {
            connection.as_mut().graceful_shutdown();
            connection.await?;
        }
    }
    append_observation(
        &observations,
        json!({"event": "connection_closed", "connection_id": connection_id}),
    );
    Ok(())
}

async fn probe_stream(endpoint: SocketAddr, host: &str) -> anyhow::Result<()> {
    let sender = connect_probe(endpoint).await?;
    let (mut first_tx, first_body) = Channel::<Bytes, Infallible>::new(4);
    let first_body = first_body
        .map_err(|never| -> BoxError { match never {} })
        .boxed_unsync();
    let mut first_sender = sender.clone();
    let mut first_response = first_sender
        .send_request(grpc_request(host, "/grpc.echo/Stream", first_body)?)
        .await?;
    let first_connection = backend_connection(&first_response)?;

    first_tx.send_data(Bytes::from_static(b"one")).await?;
    let first_chunk = next_data(first_response.body_mut()).await?;

    let mut second_sender = sender.clone();
    let second_response = second_sender
        .send_request(grpc_request(
            host,
            "/grpc.echo/Stream",
            full_body(Bytes::from_static(b"two")),
        )?)
        .await?;
    let second_connection = backend_connection(&second_response)?;
    let (second_bytes, second_status) = collect_response(second_response).await?;

    first_tx.send_data(Bytes::from_static(b"three")).await?;
    drop(first_tx);
    let (remaining_bytes, first_status) = collect_response(first_response).await?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "first_chunk": String::from_utf8_lossy(&first_chunk),
            "remaining": String::from_utf8_lossy(&remaining_bytes),
            "second": String::from_utf8_lossy(&second_bytes),
            "first_status": first_status,
            "second_status": second_status,
            "first_connection": first_connection,
            "second_connection": second_connection,
        }))?
    );
    Ok(())
}

async fn probe_single(
    endpoint: SocketAddr,
    host: &str,
    path: &str,
    payload: &str,
) -> anyhow::Result<()> {
    let sender = connect_probe(endpoint).await?;
    let mut sender = sender.clone();
    let response = sender
        .send_request(grpc_request(
            host,
            path,
            full_body(Bytes::copy_from_slice(payload.as_bytes())),
        )?)
        .await?;
    let connection = backend_connection(&response)?;
    let (bytes, grpc_status) = collect_response(response).await?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "body": String::from_utf8_lossy(&bytes),
            "grpc_status": grpc_status,
            "backend_connection": connection,
        }))?
    );
    Ok(())
}

async fn probe_cancel(endpoint: SocketAddr, host: &str) -> anyhow::Result<()> {
    let sender = connect_probe(endpoint).await?;
    let mut cancel_sender = sender.clone();
    let mut cancel_response = cancel_sender
        .send_request(grpc_request(
            host,
            "/grpc.echo/Cancel",
            full_body(Bytes::from_static(b"cancel-me")),
        )?)
        .await?;
    let cancelled_connection = backend_connection(&cancel_response)?;
    let first_chunk = next_data(cancel_response.body_mut()).await?;
    drop(cancel_response);
    sleep(Duration::from_millis(300)).await;

    let mut recovery_sender = sender.clone();
    let recovery_response = recovery_sender
        .send_request(grpc_request(
            host,
            "/grpc.echo/Stream",
            full_body(Bytes::from_static(b"after-cancel")),
        )?)
        .await?;
    let recovery_connection = backend_connection(&recovery_response)?;
    let (recovery_body, grpc_status) = collect_response(recovery_response).await?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "first_chunk": String::from_utf8_lossy(&first_chunk),
            "recovery_body": String::from_utf8_lossy(&recovery_body),
            "grpc_status": grpc_status,
            "cancelled_connection": cancelled_connection,
            "recovery_connection": recovery_connection,
        }))?
    );
    Ok(())
}

async fn connect_probe(
    endpoint: SocketAddr,
) -> anyhow::Result<client_http2::SendRequest<ProbeBody>> {
    let stream = TcpStream::connect(endpoint).await?;
    let mut builder = client_http2::Builder::new(TokioExecutor::new());
    builder
        .timer(TokioTimer::new())
        .adaptive_window(true)
        .keep_alive_interval(Some(Duration::from_secs(20)))
        .keep_alive_timeout(Duration::from_secs(10));
    let (sender, connection) = timeout(
        Duration::from_secs(10),
        builder.handshake(TokioIo::new(stream)),
    )
    .await
    .context("public HTTP/2 handshake timed out")??;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(sender)
}

fn grpc_request(host: &str, path: &str, body: ProbeBody) -> anyhow::Result<Request<ProbeBody>> {
    let uri = Uri::builder()
        .scheme("http")
        .authority(host)
        .path_and_query(path)
        .build()?;
    Ok(Request::builder()
        .method("POST")
        .uri(uri)
        .version(Version::HTTP_2)
        .header(header::HOST, host)
        .header(header::CONTENT_TYPE, "application/grpc")
        .header(header::TE, "trailers")
        .body(body)?)
}

fn full_body(bytes: Bytes) -> ProbeBody {
    Full::new(bytes)
        .map_err(|never| -> BoxError { match never {} })
        .boxed_unsync()
}

fn backend_connection(response: &Response<Incoming>) -> anyhow::Result<u64> {
    response
        .headers()
        .get("x-linklake-backend-connection")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| anyhow!("response is missing the backend connection identifier"))
}

async fn next_data(body: &mut Incoming) -> anyhow::Result<Bytes> {
    loop {
        let frame = timeout(Duration::from_secs(10), body.frame())
            .await
            .context("response data timed out")?
            .ok_or_else(|| anyhow!("response ended before data"))??;
        if let Some(data) = frame.data_ref().filter(|data| !data.is_empty()) {
            return Ok(data.clone());
        }
    }
}

async fn collect_response(response: Response<Incoming>) -> anyhow::Result<(Bytes, String)> {
    let collected = timeout(Duration::from_secs(10), response.into_body().collect())
        .await
        .context("response body timed out")??;
    let grpc_status = collected
        .trailers()
        .and_then(|trailers| trailers.get("grpc-status"))
        .and_then(|value| value.to_str().ok())
        .unwrap_or("missing")
        .to_owned();
    Ok((collected.to_bytes(), grpc_status))
}

fn append_observation(path: &Path, value: serde_json::Value) {
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "{value}");
    }
}
