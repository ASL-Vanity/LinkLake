use crate::{
    client_registry::Authentication,
    http_route_catalog::normalize_hostname,
    record_audit,
    tcp_tunnel::{copy_bidirectional_with_limit, BandwidthLimiter},
    AppState,
};
use linklake_core::{read_control_frame, write_control_frame, BoxedIo, ControlFrame};
use std::{
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{split, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot, watch, OwnedSemaphorePermit, Semaphore},
    time::{timeout, timeout_at, Instant},
};
use uuid::Uuid;

const CLIENT_HELLO_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECTION_PAIR_TIMEOUT: Duration = Duration::from_secs(10);
const CONTROL_IDLE_TIMEOUT: Duration = Duration::from_secs(35);
const CONNECTION_MAX_LIFETIME: Duration = Duration::from_secs(2 * 60 * 60);
const MAX_TLS_RECORD_BYTES: usize = 18_432;
const MAX_CLIENT_HELLO_BYTES: usize = 64 * 1024;

pub(crate) struct SniRouteRegistration {
    registration_id: Uuid,
    stop_tx: watch::Sender<()>,
    context: Arc<SniRouteContext>,
}

#[derive(Default)]
pub(crate) struct SniRouteStatistics {
    pub(crate) active_connections: AtomicUsize,
    pub(crate) connections_total: AtomicU64,
    pub(crate) rejected_connections: AtomicU64,
    pub(crate) client_hello_errors: AtomicU64,
    pub(crate) unknown_sni: AtomicU64,
    pub(crate) bytes_from_public: AtomicU64,
    pub(crate) bytes_to_public: AtomicU64,
    pub(crate) pairing_timeouts: AtomicU64,
    pub(crate) transfer_errors: AtomicU64,
    pub(crate) lifetime_timeouts: AtomicU64,
}

struct SniRouteContext {
    client_id: Uuid,
    command_tx: mpsc::Sender<ControlFrame>,
    stop: watch::Receiver<()>,
    permits: Arc<Semaphore>,
    statistics: Arc<SniRouteStatistics>,
    bandwidth_limiter: Option<Arc<BandwidthLimiter>>,
}

struct ConnectionActivity {
    statistics: Arc<SniRouteStatistics>,
    _route_permit: OwnedSemaphorePermit,
    _global_permit: OwnedSemaphorePermit,
}

struct PendingConnectionGuard {
    state: Arc<AppState>,
    connection_id: Uuid,
}

impl Drop for ConnectionActivity {
    fn drop(&mut self) {
        self.statistics
            .active_connections
            .fetch_sub(1, Ordering::Relaxed);
    }
}

impl Drop for PendingConnectionGuard {
    fn drop(&mut self) {
        if let Ok(mut pending) = self.state.pending_connections.try_lock() {
            pending.remove(&self.connection_id);
            return;
        }
        let state = self.state.clone();
        let connection_id = self.connection_id;
        tokio::spawn(async move {
            state
                .pending_connections
                .lock()
                .await
                .remove(&connection_id);
        });
    }
}

pub(crate) async fn run_listener(
    state: Arc<AppState>,
    listener: TcpListener,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        let accepted = tokio::select! {
            _ = shutdown.changed() => break,
            accepted = listener.accept() => accepted,
        };
        match accepted {
            Ok((stream, peer)) => {
                let state = state.clone();
                tokio::spawn(async move {
                    if let Err(error) = serve_connection(state, stream).await {
                        tracing::debug!("TLS SNI connection from {peer} ended: {error}");
                    }
                });
            }
            Err(error) => tracing::error!("TLS SNI listener accept error: {error}"),
        }
    }
}

async fn serve_connection(state: Arc<AppState>, mut public: TcpStream) -> anyhow::Result<()> {
    let (hostname, client_hello) =
        match timeout(CLIENT_HELLO_TIMEOUT, read_client_hello_sni(&mut public)).await {
            Ok(Ok(value)) => value,
            _ => {
                state
                    .metrics
                    .sni_client_hello_errors_total
                    .fetch_add(1, Ordering::Relaxed);
                anyhow::bail!("invalid or timed out TLS ClientHello")
            }
        };
    let context = state
        .sni_routes
        .lock()
        .expect("SNI route registry lock poisoned")
        .get(&hostname)
        .map(|registration| registration.context.clone());
    let Some(context) = context else {
        state
            .metrics
            .sni_unknown_hostname_total
            .fetch_add(1, Ordering::Relaxed);
        if let Some(statistics) = state
            .sni_route_statistics
            .lock()
            .expect("SNI route statistics lock poisoned")
            .get(&hostname)
        {
            statistics.unknown_sni.fetch_add(1, Ordering::Relaxed);
        }
        anyhow::bail!("unknown or offline TLS SNI hostname")
    };
    let Ok(route_permit) = context.permits.clone().try_acquire_owned() else {
        context
            .statistics
            .rejected_connections
            .fetch_add(1, Ordering::Relaxed);
        anyhow::bail!("TLS SNI route connection limit reached")
    };
    let Ok(global_permit) = state.global_connection_permits.clone().try_acquire_owned() else {
        context
            .statistics
            .rejected_connections
            .fetch_add(1, Ordering::Relaxed);
        anyhow::bail!("global connection limit reached")
    };
    context
        .statistics
        .active_connections
        .fetch_add(1, Ordering::Relaxed);
    context
        .statistics
        .connections_total
        .fetch_add(1, Ordering::Relaxed);
    let _activity = ConnectionActivity {
        statistics: context.statistics.clone(),
        _route_permit: route_permit,
        _global_permit: global_permit,
    };
    let mut agent = match request_client_stream(&state, &context).await {
        Ok(stream) => stream,
        Err(pairing_timeout) => {
            if pairing_timeout {
                context
                    .statistics
                    .pairing_timeouts
                    .fetch_add(1, Ordering::Relaxed);
            }
            anyhow::bail!("TLS SNI backend is unavailable")
        }
    };
    agent.write_all(&client_hello).await?;
    context
        .statistics
        .bytes_from_public
        .fetch_add(client_hello.len() as u64, Ordering::Relaxed);
    let mut stop = context.stop.clone();
    let transfer = tokio::select! {
        _ = stop.changed() => return Ok(()),
        result = timeout(
            CONNECTION_MAX_LIFETIME,
            copy_bidirectional_with_limit(&mut public, &mut agent, context.bandwidth_limiter.clone()),
        ) => result,
    };
    match transfer {
        Ok(Ok((from_public, to_public))) => {
            context
                .statistics
                .bytes_from_public
                .fetch_add(from_public, Ordering::Relaxed);
            context
                .statistics
                .bytes_to_public
                .fetch_add(to_public, Ordering::Relaxed);
            Ok(())
        }
        Ok(Err(error)) => {
            context
                .statistics
                .transfer_errors
                .fetch_add(1, Ordering::Relaxed);
            Err(error.into())
        }
        Err(_) => {
            context
                .statistics
                .lifetime_timeouts
                .fetch_add(1, Ordering::Relaxed);
            anyhow::bail!("TLS SNI connection reached maximum lifetime")
        }
    }
}

async fn request_client_stream(
    state: &Arc<AppState>,
    context: &SniRouteContext,
) -> Result<BoxedIo, bool> {
    let Ok(_pending_permit) = state.pending_connection_permits.clone().try_acquire_owned() else {
        return Err(false);
    };
    let connection_id = Uuid::new_v4();
    let (data_tx, data_rx) = oneshot::channel();
    state
        .pending_connections
        .lock()
        .await
        .insert(connection_id, (context.client_id, data_tx));
    let _pending_guard = PendingConnectionGuard {
        state: state.clone(),
        connection_id,
    };
    let mut stop = context.stop.clone();
    let deadline = Instant::now() + CONNECTION_PAIR_TIMEOUT;
    match tokio::select! {
        _ = stop.changed() => return Err(false),
        result = timeout_at(deadline, context.command_tx.send(ControlFrame::OpenTcpConnection { connection_id })) => result,
    } {
        Ok(Ok(())) => {}
        Ok(Err(_)) => return Err(false),
        Err(_) => return Err(true),
    }
    match tokio::select! {
        _ = stop.changed() => return Err(false),
        result = timeout_at(deadline, data_rx) => result,
    } {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(_)) => Err(false),
        Err(_) => Err(true),
    }
}

pub(crate) async fn register_route(
    state: Arc<AppState>,
    mut stream: BoxedIo,
    client_id: Uuid,
    client_token: String,
    name: String,
    hostname: String,
    target_addr: String,
) {
    if !authenticated_client(&state, client_id, &client_token) {
        send_error(&mut stream, "invalid client credentials").await;
        return;
    }
    let Ok(hostname) = normalize_hostname(&hostname) else {
        send_error(&mut stream, "invalid TLS SNI hostname").await;
        return;
    };
    let runtime = state
        .sni_route_catalog
        .lock()
        .expect("SNI route catalog lock poisoned")
        .runtime_policy(client_id, &name, &hostname, &target_addr)
        .unwrap_or(None);
    let Some(runtime) = runtime else {
        send_error(
            &mut stream,
            "no enabled management policy matches this TLS SNI route",
        )
        .await;
        return;
    };
    let registration_id = Uuid::new_v4();
    let (command_tx, command_rx) = mpsc::channel(64);
    let (stop_tx, stop_rx) = watch::channel(());
    let statistics = {
        let mut all = state
            .sni_route_statistics
            .lock()
            .expect("SNI route statistics lock poisoned");
        all.entry(hostname.clone())
            .or_insert_with(|| Arc::new(SniRouteStatistics::default()))
            .clone()
    };
    let context = Arc::new(SniRouteContext {
        client_id,
        command_tx,
        stop: stop_rx.clone(),
        permits: Arc::new(Semaphore::new(runtime.max_connections)),
        statistics,
        bandwidth_limiter: runtime
            .bandwidth_limit_bps
            .map(BandwidthLimiter::new)
            .map(Arc::new),
    });
    if let Some(previous) = state
        .sni_routes
        .lock()
        .expect("SNI route registry lock poisoned")
        .insert(
            hostname.clone(),
            SniRouteRegistration {
                registration_id,
                stop_tx,
                context,
            },
        )
    {
        let _ = previous.stop_tx.send(());
    }
    record_audit(
        &state,
        "sni_route.registered",
        &client_id.to_string(),
        &format!("name={name}; hostname={hostname}; target={target_addr}"),
    );
    let (reader, mut writer) = split(stream);
    if write_control_frame(
        &mut writer,
        &ControlFrame::TlsRouteRegistered {
            hostname: hostname.clone(),
        },
    )
    .await
    .is_err()
    {
        remove_route(&state, &hostname, registration_id);
        return;
    }
    run_registered_control(
        state,
        hostname,
        registration_id,
        reader,
        writer,
        command_rx,
        stop_rx,
    )
    .await;
}

async fn run_registered_control(
    state: Arc<AppState>,
    hostname: String,
    registration_id: Uuid,
    mut reader: ReadHalf<BoxedIo>,
    mut writer: WriteHalf<BoxedIo>,
    mut commands: mpsc::Receiver<ControlFrame>,
    mut stop: watch::Receiver<()>,
) {
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            command = commands.recv() => {
                let Some(command) = command else { break };
                if write_control_frame(&mut writer, &command).await.is_err() { break; }
            }
            frame = timeout(CONTROL_IDLE_TIMEOUT, read_control_frame(&mut reader)) => {
                match frame {
                    Ok(Ok(ControlFrame::ControlHeartbeat { nonce })) => {
                        if write_control_frame(&mut writer, &ControlFrame::ControlHeartbeatAck { nonce }).await.is_err() { break; }
                    }
                    Ok(Ok(_)) => break,
                    Ok(Err(_)) | Err(_) => break,
                }
            }
        }
    }
    remove_route(&state, &hostname, registration_id);
}

pub(crate) fn stop_hostname(state: &AppState, hostname: &str) {
    if let Some(route) = state
        .sni_routes
        .lock()
        .expect("SNI route registry lock poisoned")
        .remove(hostname)
    {
        let _ = route.stop_tx.send(());
    }
}

pub(crate) fn stop_all(state: &AppState) {
    let routes = state
        .sni_routes
        .lock()
        .expect("SNI route registry lock poisoned")
        .drain()
        .map(|(_, route)| route)
        .collect::<Vec<_>>();
    for route in routes {
        let _ = route.stop_tx.send(());
    }
}

fn remove_route(state: &AppState, hostname: &str, registration_id: Uuid) {
    let mut routes = state
        .sni_routes
        .lock()
        .expect("SNI route registry lock poisoned");
    if routes
        .get(hostname)
        .is_some_and(|route| route.registration_id == registration_id)
    {
        if let Some(route) = routes.remove(hostname) {
            let _ = route.stop_tx.send(());
        }
    }
}

fn authenticated_client(state: &AppState, client_id: Uuid, token: &str) -> bool {
    let mut clients = state.clients.lock().expect("client registry lock poisoned");
    matches!(
        clients.authenticate_and_touch(client_id, token),
        Ok(Authentication::Authenticated)
    )
}

async fn send_error(stream: &mut BoxedIo, message: &str) {
    let _ = write_control_frame(
        stream,
        &ControlFrame::Error {
            message: message.to_owned(),
        },
    )
    .await;
}

async fn read_client_hello_sni(stream: &mut TcpStream) -> anyhow::Result<(String, Vec<u8>)> {
    let mut wire = Vec::new();
    let mut handshake = Vec::new();
    loop {
        let mut header = [0_u8; 5];
        stream.read_exact(&mut header).await?;
        let record_length = usize::from(u16::from_be_bytes([header[3], header[4]]));
        anyhow::ensure!(
            header[0] == 22
                && header[1] == 3
                && record_length != 0
                && record_length <= MAX_TLS_RECORD_BYTES,
            "invalid TLS handshake record"
        );
        anyhow::ensure!(
            wire.len() + 5 + record_length <= MAX_CLIENT_HELLO_BYTES + 5 * 8,
            "TLS ClientHello is too large"
        );
        let mut payload = vec![0_u8; record_length];
        stream.read_exact(&mut payload).await?;
        wire.extend_from_slice(&header);
        wire.extend_from_slice(&payload);
        handshake.extend_from_slice(&payload);
        if handshake.len() < 4 {
            continue;
        }
        anyhow::ensure!(handshake[0] == 1, "first TLS handshake is not ClientHello");
        let length = (usize::from(handshake[1]) << 16)
            | (usize::from(handshake[2]) << 8)
            | usize::from(handshake[3]);
        anyhow::ensure!(
            length <= MAX_CLIENT_HELLO_BYTES,
            "TLS ClientHello is too large"
        );
        if handshake.len() < 4 + length {
            continue;
        }
        let hostname = parse_client_hello_sni(&handshake[4..4 + length])?;
        return Ok((hostname, wire));
    }
}

fn parse_client_hello_sni(hello: &[u8]) -> anyhow::Result<String> {
    let mut cursor = 0_usize;
    take(hello, &mut cursor, 2 + 32)?;
    let session_length = usize::from(*take(hello, &mut cursor, 1)?.first().unwrap());
    take(hello, &mut cursor, session_length)?;
    let cipher_length = read_u16(hello, &mut cursor)?;
    anyhow::ensure!(
        cipher_length >= 2 && cipher_length % 2 == 0,
        "invalid cipher list"
    );
    take(hello, &mut cursor, cipher_length)?;
    let compression_length = usize::from(*take(hello, &mut cursor, 1)?.first().unwrap());
    anyhow::ensure!(compression_length != 0, "invalid compression list");
    take(hello, &mut cursor, compression_length)?;
    let extensions_length = read_u16(hello, &mut cursor)?;
    let extensions = take(hello, &mut cursor, extensions_length)?;
    anyhow::ensure!(cursor == hello.len(), "trailing ClientHello bytes");
    let mut extension_cursor = 0_usize;
    while extension_cursor < extensions.len() {
        let kind = read_u16(extensions, &mut extension_cursor)?;
        let length = read_u16(extensions, &mut extension_cursor)?;
        let value = take(extensions, &mut extension_cursor, length)?;
        if kind != 0 {
            continue;
        }
        let mut sni_cursor = 0_usize;
        let list_length = read_u16(value, &mut sni_cursor)?;
        anyhow::ensure!(list_length == value.len() - 2, "invalid SNI list length");
        while sni_cursor < value.len() {
            let name_type = *take(value, &mut sni_cursor, 1)?.first().unwrap();
            let name_length = read_u16(value, &mut sni_cursor)?;
            let name = take(value, &mut sni_cursor, name_length)?;
            if name_type == 0 {
                let name = std::str::from_utf8(name)?;
                return normalize_hostname(name);
            }
        }
    }
    anyhow::bail!("TLS ClientHello has no SNI hostname")
}

fn read_u16(input: &[u8], cursor: &mut usize) -> anyhow::Result<usize> {
    let value = take(input, cursor, 2)?;
    Ok(usize::from(u16::from_be_bytes([value[0], value[1]])))
}

fn take<'a>(input: &'a [u8], cursor: &mut usize, length: usize) -> anyhow::Result<&'a [u8]> {
    let end = cursor
        .checked_add(length)
        .ok_or_else(|| anyhow::anyhow!("TLS ClientHello length overflow"))?;
    anyhow::ensure!(end <= input.len(), "truncated TLS ClientHello");
    let value = &input[*cursor..end];
    *cursor = end;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::{parse_client_hello_sni, read_client_hello_sni};
    use std::sync::Arc;
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::{
        rustls::{pki_types::ServerName, ClientConfig, RootCertStore},
        TlsConnector,
    };

    #[test]
    fn extracts_and_normalizes_sni_from_client_hello_body() {
        let hostname = b"TLS.Example.COM";
        let mut extensions = Vec::new();
        let list_length = 1 + 2 + hostname.len();
        extensions.extend_from_slice(&0_u16.to_be_bytes());
        extensions.extend_from_slice(&((2 + list_length) as u16).to_be_bytes());
        extensions.extend_from_slice(&(list_length as u16).to_be_bytes());
        extensions.push(0);
        extensions.extend_from_slice(&(hostname.len() as u16).to_be_bytes());
        extensions.extend_from_slice(hostname);
        let mut hello = Vec::new();
        hello.extend_from_slice(&[3, 3]);
        hello.extend_from_slice(&[0; 32]);
        hello.push(0);
        hello.extend_from_slice(&2_u16.to_be_bytes());
        hello.extend_from_slice(&[0x13, 0x01]);
        hello.push(1);
        hello.push(0);
        hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        hello.extend_from_slice(&extensions);
        assert_eq!(
            parse_client_hello_sni(&hello).expect("SNI should parse"),
            "tls.example.com"
        );
    }

    #[tokio::test]
    async fn reads_a_real_rustls_client_hello_without_terminating_tls() {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let address = listener.local_addr().expect("address should exist");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("client should connect");
            read_client_hello_sni(&mut stream)
                .await
                .expect("ClientHello should parse")
        });
        let client = TcpStream::connect(address)
            .await
            .expect("TCP should connect");
        let config = ClientConfig::builder()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(config));
        let name = ServerName::try_from("passthrough.example.com")
            .expect("server name should parse")
            .to_owned();
        let connect = tokio::spawn(async move { connector.connect(name, client).await });
        let (hostname, wire) = server.await.expect("server task should complete");
        assert_eq!(hostname, "passthrough.example.com");
        assert_eq!(wire[0], 22);
        connect.abort();
    }
}
