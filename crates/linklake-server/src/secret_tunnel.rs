use crate::{
    client_registry::Authentication,
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
    io::{split, ReadHalf, WriteHalf},
    sync::{mpsc, oneshot, watch, Semaphore},
    time::{timeout, Instant},
};
use uuid::Uuid;

const CONTROL_IDLE_TIMEOUT: Duration = Duration::from_secs(35);
const CONNECTION_PAIR_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECTION_MAX_LIFETIME: Duration = Duration::from_secs(2 * 60 * 60);

pub(crate) struct SecretTunnelRegistration {
    registration_id: Uuid,
    stop_tx: watch::Sender<()>,
    context: Arc<SecretTunnelContext>,
}

struct SecretTunnelContext {
    provider_client_id: Uuid,
    command_tx: mpsc::Sender<ControlFrame>,
    stop: watch::Receiver<()>,
    permits: Arc<Semaphore>,
    statistics: Arc<SecretTunnelStatistics>,
    bandwidth_limiter: Option<Arc<BandwidthLimiter>>,
}

#[derive(Default)]
pub(crate) struct SecretTunnelStatistics {
    pub(crate) active_connections: AtomicUsize,
    pub(crate) connections_total: AtomicU64,
    pub(crate) rejected_connections: AtomicU64,
    pub(crate) bytes_from_visitor: AtomicU64,
    pub(crate) bytes_to_visitor: AtomicU64,
    pub(crate) pairing_timeouts: AtomicU64,
    pub(crate) transfer_errors: AtomicU64,
    pub(crate) lifetime_timeouts: AtomicU64,
}

pub(crate) async fn register_provider(
    state: Arc<AppState>,
    mut stream: BoxedIo,
    provider_client_id: Uuid,
    client_token: String,
    name: String,
    target_addr: String,
) {
    if !authenticated_client(&state, provider_client_id, &client_token) {
        reject(&state, &mut stream, "invalid client credentials").await;
        return;
    }
    let runtime_policy = state
        .secret_tunnel_catalog
        .lock()
        .expect("secret tunnel catalog lock poisoned")
        .provider_runtime_policy(provider_client_id, &name, &target_addr)
        .unwrap_or(None);
    let Some(runtime_policy) = runtime_policy else {
        reject(
            &state,
            &mut stream,
            "no enabled management policy matches this secret tunnel",
        )
        .await;
        return;
    };

    let (command_tx, command_rx) = mpsc::channel(64);
    let (stop_tx, stop_rx) = watch::channel(());
    let registration_id = Uuid::new_v4();
    let statistics = state
        .secret_tunnel_statistics
        .lock()
        .expect("secret tunnel statistics lock poisoned")
        .entry(runtime_policy.policy_id)
        .or_insert_with(|| Arc::new(SecretTunnelStatistics::default()))
        .clone();
    let context = Arc::new(SecretTunnelContext {
        provider_client_id: runtime_policy.provider_client_id,
        command_tx,
        stop: stop_rx.clone(),
        permits: Arc::new(Semaphore::new(runtime_policy.max_connections)),
        statistics,
        bandwidth_limiter: runtime_policy
            .bandwidth_limit_bps
            .map(BandwidthLimiter::new)
            .map(Arc::new),
    });
    if let Some(previous) = state
        .secret_tunnels
        .lock()
        .expect("secret tunnel registry lock poisoned")
        .insert(
            runtime_policy.policy_id,
            SecretTunnelRegistration {
                registration_id,
                stop_tx,
                context,
            },
        )
    {
        let _ = previous.stop_tx.send(());
    }
    state
        .metrics
        .tunnel_registrations_total
        .fetch_add(1, Ordering::Relaxed);
    record_audit(
        &state,
        "secret_tunnel.registered",
        &runtime_policy.policy_id.to_string(),
        &format!("provider={provider_client_id}; name={name}; target={target_addr}"),
    );

    let (reader, mut writer) = split(stream);
    if write_control_frame(
        &mut writer,
        &ControlFrame::SecretTunnelRegistered {
            tunnel_id: runtime_policy.policy_id,
        },
    )
    .await
    .is_err()
    {
        remove_registration(&state, runtime_policy.policy_id, registration_id);
        return;
    }
    run_provider_control(
        state,
        runtime_policy.policy_id,
        registration_id,
        reader,
        writer,
        command_rx,
        stop_rx,
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn run_provider_control(
    state: Arc<AppState>,
    policy_id: Uuid,
    registration_id: Uuid,
    mut reader: ReadHalf<BoxedIo>,
    mut writer: WriteHalf<BoxedIo>,
    mut commands: mpsc::Receiver<ControlFrame>,
    mut stop: watch::Receiver<()>,
) {
    let (frames_tx, mut frames_rx) = mpsc::channel(16);
    let reader_task = tokio::spawn(async move {
        while let Ok(frame) = read_control_frame(&mut reader).await {
            if frames_tx.send(frame).await.is_err() {
                break;
            }
        }
    });
    let idle_timeout = tokio::time::sleep(CONTROL_IDLE_TIMEOUT);
    tokio::pin!(idle_timeout);
    loop {
        tokio::select! {
            _ = stop.changed() => break,
            _ = &mut idle_timeout => {
                tracing::warn!("Secret tunnel control heartbeat timed out for {policy_id}");
                break;
            }
            command = commands.recv() => match command {
                Some(command) if write_control_frame(&mut writer, &command).await.is_err() => break,
                Some(_) => {}
                None => break,
            },
            frame = frames_rx.recv() => match frame {
                Some(ControlFrame::ControlHeartbeat { nonce }) => {
                    idle_timeout.as_mut().reset(Instant::now() + CONTROL_IDLE_TIMEOUT);
                    if write_control_frame(&mut writer, &ControlFrame::ControlHeartbeatAck { nonce }).await.is_err() {
                        break;
                    }
                }
                Some(_) => {
                    state.metrics.control_protocol_errors_total.fetch_add(1, Ordering::Relaxed);
                    break;
                }
                None => break,
            }
        }
    }
    reader_task.abort();
    remove_registration(&state, policy_id, registration_id);
}

pub(crate) async fn connect_visitor(
    state: Arc<AppState>,
    mut visitor_stream: BoxedIo,
    visitor_client_id: Uuid,
    client_token: String,
    access_key: String,
) {
    if !authenticated_client(&state, visitor_client_id, &client_token) {
        reject(&state, &mut visitor_stream, "invalid client credentials").await;
        return;
    }
    let runtime_policy = state
        .secret_tunnel_catalog
        .lock()
        .expect("secret tunnel catalog lock poisoned")
        .access_runtime_policy(visitor_client_id, &access_key)
        .unwrap_or(None);
    let Some(runtime_policy) = runtime_policy else {
        reject(
            &state,
            &mut visitor_stream,
            "invalid or unauthorized secret tunnel key",
        )
        .await;
        return;
    };
    let context = state
        .secret_tunnels
        .lock()
        .expect("secret tunnel registry lock poisoned")
        .get(&runtime_policy.policy_id)
        .map(|registration| registration.context.clone());
    let Some(context) = context else {
        reject(
            &state,
            &mut visitor_stream,
            "secret tunnel provider is offline",
        )
        .await;
        return;
    };
    let Ok(_policy_permit) = context.permits.clone().try_acquire_owned() else {
        context
            .statistics
            .rejected_connections
            .fetch_add(1, Ordering::Relaxed);
        reject(
            &state,
            &mut visitor_stream,
            "secret tunnel connection limit reached",
        )
        .await;
        return;
    };
    let Ok(_global_permit) = state.global_connection_permits.clone().try_acquire_owned() else {
        context
            .statistics
            .rejected_connections
            .fetch_add(1, Ordering::Relaxed);
        reject(
            &state,
            &mut visitor_stream,
            "server connection limit reached",
        )
        .await;
        return;
    };
    let Ok(pending_permit) = state.pending_connection_permits.clone().try_acquire_owned() else {
        context
            .statistics
            .rejected_connections
            .fetch_add(1, Ordering::Relaxed);
        reject(
            &state,
            &mut visitor_stream,
            "server pending connection limit reached",
        )
        .await;
        return;
    };

    context
        .statistics
        .active_connections
        .fetch_add(1, Ordering::Relaxed);
    context
        .statistics
        .connections_total
        .fetch_add(1, Ordering::Relaxed);
    let connection_id = Uuid::new_v4();
    let (data_tx, data_rx) = oneshot::channel();
    state
        .pending_connections
        .lock()
        .await
        .insert(connection_id, (context.provider_client_id, data_tx));
    if context
        .command_tx
        .send(ControlFrame::OpenSecretConnection { connection_id })
        .await
        .is_err()
    {
        state
            .pending_connections
            .lock()
            .await
            .remove(&connection_id);
        context
            .statistics
            .active_connections
            .fetch_sub(1, Ordering::Relaxed);
        reject(
            &state,
            &mut visitor_stream,
            "secret tunnel provider disconnected",
        )
        .await;
        return;
    }
    let mut stop = context.stop.clone();
    let pair_result = tokio::select! {
        _ = stop.changed() => {
            state.pending_connections.lock().await.remove(&connection_id);
            context.statistics.active_connections.fetch_sub(1, Ordering::Relaxed);
            return;
        }
        result = timeout(CONNECTION_PAIR_TIMEOUT, data_rx) => result,
    };
    match pair_result {
        Ok(Ok(mut provider_stream)) => {
            drop(pending_permit);
            if write_control_frame(
                &mut visitor_stream,
                &ControlFrame::SecretTunnelConnected {
                    tunnel_id: runtime_policy.policy_id,
                },
            )
            .await
            .is_err()
            {
                context
                    .statistics
                    .active_connections
                    .fetch_sub(1, Ordering::Relaxed);
                return;
            }
            let transfer = tokio::select! {
                _ = stop.changed() => None,
                result = timeout(
                    CONNECTION_MAX_LIFETIME,
                    copy_bidirectional_with_limit(
                        &mut visitor_stream,
                        &mut provider_stream,
                        context.bandwidth_limiter.clone(),
                    ),
                ) => Some(result),
            };
            match transfer {
                Some(Ok(Ok((from_visitor, to_visitor)))) => {
                    context
                        .statistics
                        .bytes_from_visitor
                        .fetch_add(from_visitor, Ordering::Relaxed);
                    context
                        .statistics
                        .bytes_to_visitor
                        .fetch_add(to_visitor, Ordering::Relaxed);
                }
                Some(Ok(Err(error))) => {
                    context
                        .statistics
                        .transfer_errors
                        .fetch_add(1, Ordering::Relaxed);
                    tracing::warn!("Secret tunnel transfer failed: {error}");
                }
                Some(Err(_)) => {
                    context
                        .statistics
                        .lifetime_timeouts
                        .fetch_add(1, Ordering::Relaxed);
                }
                None => {}
            }
        }
        Ok(Err(_)) => {
            drop(pending_permit);
        }
        Err(_) => {
            drop(pending_permit);
            context
                .statistics
                .pairing_timeouts
                .fetch_add(1, Ordering::Relaxed);
            state
                .pending_connections
                .lock()
                .await
                .remove(&connection_id);
            let _ = write_control_frame(
                &mut visitor_stream,
                &ControlFrame::Error {
                    message: "secret tunnel pairing timed out".to_owned(),
                },
            )
            .await;
        }
    }
    context
        .statistics
        .active_connections
        .fetch_sub(1, Ordering::Relaxed);
}

pub(crate) fn stop_policy(state: &AppState, policy_id: Uuid) {
    if let Some(registration) = state
        .secret_tunnels
        .lock()
        .expect("secret tunnel registry lock poisoned")
        .remove(&policy_id)
    {
        let _ = registration.stop_tx.send(());
    }
}

pub(crate) fn stop_all(state: &AppState) {
    let registrations = state
        .secret_tunnels
        .lock()
        .expect("secret tunnel registry lock poisoned")
        .drain()
        .map(|(_, registration)| registration)
        .collect::<Vec<_>>();
    for registration in registrations {
        let _ = registration.stop_tx.send(());
    }
}

fn remove_registration(state: &AppState, policy_id: Uuid, registration_id: Uuid) {
    let should_remove = state
        .secret_tunnels
        .lock()
        .expect("secret tunnel registry lock poisoned")
        .get(&policy_id)
        .is_some_and(|registration| registration.registration_id == registration_id);
    if should_remove {
        state
            .secret_tunnels
            .lock()
            .expect("secret tunnel registry lock poisoned")
            .remove(&policy_id);
    }
}

fn authenticated_client(state: &AppState, client_id: Uuid, token: &str) -> bool {
    let mut clients = state.clients.lock().expect("client registry lock poisoned");
    matches!(
        clients.authenticate_and_touch(client_id, token),
        Ok(Authentication::Authenticated)
    )
}

async fn reject(state: &AppState, stream: &mut BoxedIo, message: &str) {
    state
        .metrics
        .registration_rejections_total
        .fetch_add(1, Ordering::Relaxed);
    let _ = write_control_frame(
        stream,
        &ControlFrame::Error {
            message: message.to_owned(),
        },
    )
    .await;
}
