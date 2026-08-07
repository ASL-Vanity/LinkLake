//! 将公网端口所有权租约绑定到具体协议运行时，并在续租失败时立即停止监听。

use crate::{
    ha_coordination::LeadershipLease,
    ha_runtime::HaRuntime,
    public_port_ownership::{PublicPortLease, PublicPortOwnership, PublicPortProtocol},
};
use std::{sync::Arc, time::Duration};
use tokio::{
    sync::watch,
    task::JoinHandle,
    time::{interval_at, timeout, Instant, MissedTickBehavior},
};
use uuid::Uuid;

pub(crate) struct HaPublicPortLease {
    ownership: PublicPortOwnership,
    lease: Option<PublicPortLease>,
    heartbeat: Duration,
    leadership: watch::Receiver<Option<LeadershipLease>>,
    expected_fencing_token: u64,
}

impl HaPublicPortLease {
    pub(crate) async fn acquire(
        runtime: &Arc<HaRuntime>,
        protocol: PublicPortProtocol,
        public_port: u16,
        policy_id: Uuid,
    ) -> anyhow::Result<Option<Self>> {
        let fencing_token = runtime.fencing_token()?;
        let ownership = runtime.public_ports().clone();
        let lease = ownership
            .acquire(protocol, public_port, policy_id, fencing_token)
            .await?;
        Ok(lease.map(|lease| Self {
            ownership,
            expected_fencing_token: fencing_token,
            lease: Some(lease),
            heartbeat: runtime.heartbeat(),
            leadership: runtime.subscribe_leadership(),
        }))
    }

    pub(crate) fn spawn_supervisor(
        mut self,
        mut stop: watch::Receiver<()>,
        stop_tx: watch::Sender<()>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            if !self.leadership_matches() {
                let _ = stop_tx.send(());
                self.release_inner().await;
                return;
            }
            let mut heartbeat = interval_at(Instant::now() + self.heartbeat, self.heartbeat);
            heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = stop.changed() => break,
                    changed = self.leadership.changed() => {
                        if changed.is_err() || !self.leadership_matches() {
                            tracing::warn!("HA leadership changed; stopping public port listener");
                            let _ = stop_tx.send(());
                            break;
                        }
                    }
                    _ = heartbeat.tick() => {
                        match timeout(self.heartbeat, self.renew()).await {
                            Ok(Ok(true)) => {}
                            Ok(Ok(false)) => {
                                tracing::warn!("Public port ownership lease was lost; stopping listener");
                                let _ = stop_tx.send(());
                                break;
                            }
                            Ok(Err(error)) => {
                                tracing::warn!("Public port ownership renewal failed: {error}");
                                let _ = stop_tx.send(());
                                break;
                            }
                            Err(_) => {
                                tracing::warn!("Public port ownership renewal timed out; stopping listener");
                                let _ = stop_tx.send(());
                                break;
                            }
                        }
                    }
                }
            }
            self.release_inner().await;
        })
    }

    pub(crate) async fn release(mut self) {
        self.release_inner().await;
    }

    async fn renew(&self) -> anyhow::Result<bool> {
        if !self.leadership_matches() {
            return Ok(false);
        }
        let Some(lease) = self.lease.as_ref() else {
            return Ok(false);
        };
        Ok(self
            .ownership
            .renew(
                lease.protocol,
                lease.public_port,
                lease.policy_id,
                lease.lease_id,
                lease.fencing_token,
            )
            .await?
            .is_some())
    }

    fn leadership_matches(&self) -> bool {
        self.leadership
            .borrow()
            .as_ref()
            .is_some_and(|lease| lease.fencing_token == self.expected_fencing_token)
    }

    async fn release_inner(&mut self) {
        let Some(lease) = self.lease.take() else {
            return;
        };
        if let Err(error) = self
            .ownership
            .release(
                lease.protocol,
                lease.public_port,
                lease.policy_id,
                lease.lease_id,
                lease.fencing_token,
            )
            .await
        {
            tracing::debug!(
                protocol = %lease.protocol,
                public_port = lease.public_port,
                "Public port ownership release failed: {error}"
            );
        }
    }
}

impl Drop for HaPublicPortLease {
    fn drop(&mut self) {
        let Some(lease) = self.lease.take() else {
            return;
        };
        let ownership = self.ownership.clone();
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        runtime.spawn(async move {
            let _ = ownership
                .release(
                    lease.protocol,
                    lease.public_port,
                    lease.policy_id,
                    lease.lease_id,
                    lease.fencing_token,
                )
                .await;
        });
    }
}
