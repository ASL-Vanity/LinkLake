//! 隧道目录异步双后端入口；PG 故障不回退本机 SQLite。
use crate::{
    database::Database,
    ha_runtime::HaRuntime,
    public_port_policy::PublicPortPolicy,
    storage::CoordinationStorage,
    tunnel_catalog::{postgres::PostgresTunnelCatalog, *},
};
use std::sync::{Arc, Mutex};
use uuid::Uuid;
pub(crate) enum TunnelStore {
    Sqlite(Mutex<TunnelCatalog>),
    Postgres(PostgresTunnelCatalog),
}
impl TunnelStore {
    pub(crate) async fn validate_existing(&self) -> anyhow::Result<()> {
        match self {
            Self::Sqlite(_) => Ok(()),
            Self::Postgres(catalog) => catalog.validate_existing().await,
        }
    }

    pub(crate) fn open(
        database: &Database,
        storage: CoordinationStorage,
        runtime: Arc<HaRuntime>,
        public_port_policy: PublicPortPolicy,
    ) -> anyhow::Result<Self> {
        Ok(match storage {
            CoordinationStorage::Sqlite(_) => Self::Sqlite(Mutex::new(
                TunnelCatalog::open_with_database(database, public_port_policy)?,
            )),
            storage @ CoordinationStorage::Postgres(_) => Self::Postgres(PostgresTunnelCatalog {
                storage,
                runtime,
                public_port_policy,
            }),
        })
    }
    pub(crate) async fn create(
        &self,
        request: CreateTcpTunnelPolicy,
    ) -> anyhow::Result<TcpTunnelPolicy> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("tunnel catalog lock poisoned")
                .create(request),
            Self::Postgres(catalog) => catalog.create(request).await,
        }
    }
    pub(crate) async fn list(&self) -> anyhow::Result<Vec<TcpTunnelPolicy>> {
        match self {
            Self::Sqlite(catalog) => catalog.lock().expect("tunnel catalog lock poisoned").list(),
            Self::Postgres(catalog) => catalog.list().await,
        }
    }
    pub(crate) async fn policy_by_id(&self, id: Uuid) -> anyhow::Result<Option<TcpTunnelPolicy>> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("tunnel catalog lock poisoned")
                .policy_by_id(id),
            Self::Postgres(catalog) => catalog.policy_by_id(id).await,
        }
    }
    pub(crate) async fn update(
        &self,
        id: Uuid,
        request: UpdateTcpTunnelPolicy,
    ) -> anyhow::Result<Option<TcpTunnelPolicy>> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("tunnel catalog lock poisoned")
                .update(id, request),
            Self::Postgres(catalog) => catalog.update(id, request).await,
        }
    }
    pub(crate) async fn set_enabled(&self, id: Uuid, enabled: bool) -> anyhow::Result<bool> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("tunnel catalog lock poisoned")
                .set_enabled(id, enabled),
            Self::Postgres(catalog) => catalog.set_enabled(id, enabled).await,
        }
    }
    pub(crate) async fn delete(&self, id: Uuid) -> anyhow::Result<bool> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("tunnel catalog lock poisoned")
                .delete(id),
            Self::Postgres(catalog) => catalog.delete(id).await,
        }
    }
    pub(crate) async fn runtime_policy(
        &self,
        client_id: Uuid,
        name: &str,
        public_port: u16,
        target_addr: &str,
    ) -> anyhow::Result<Option<TcpTunnelRuntimePolicy>> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("tunnel catalog lock poisoned")
                .runtime_policy(client_id, name, public_port, target_addr),
            Self::Postgres(catalog) => {
                catalog
                    .runtime_policy(client_id, name, public_port, target_addr)
                    .await
            }
        }
    }
    pub(crate) async fn create_socks5(
        &self,
        request: CreateSocks5ProxyPolicy,
    ) -> Result<CreatedSocks5ProxyPolicy, Socks5PolicyError> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("tunnel catalog lock poisoned")
                .create_socks5(request),
            Self::Postgres(catalog) => catalog.create_socks5(request).await,
        }
    }
    pub(crate) async fn list_socks5(&self) -> Result<Vec<Socks5ProxyPolicy>, Socks5PolicyError> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("tunnel catalog lock poisoned")
                .list_socks5(),
            Self::Postgres(catalog) => catalog.list_socks5().await,
        }
    }
    pub(crate) async fn set_socks5_enabled(
        &self,
        id: Uuid,
        enabled: bool,
    ) -> Result<bool, Socks5PolicyError> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("tunnel catalog lock poisoned")
                .set_socks5_enabled(id, enabled),
            Self::Postgres(catalog) => catalog.set_socks5_enabled(id, enabled).await,
        }
    }
    pub(crate) async fn delete_socks5(
        &self,
        id: Uuid,
    ) -> Result<Option<Socks5ProxyPolicy>, Socks5PolicyError> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("tunnel catalog lock poisoned")
                .delete_socks5(id),
            Self::Postgres(catalog) => catalog.delete_socks5(id).await,
        }
    }
    pub(crate) async fn socks5_policy_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<Socks5ProxyPolicy>, Socks5PolicyError> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("tunnel catalog lock poisoned")
                .socks5_policy_by_id(id),
            Self::Postgres(catalog) => catalog.socks5_policy_by_id(id).await,
        }
    }
    pub(crate) async fn update_socks5(
        &self,
        id: Uuid,
        request: UpdateSocks5ProxyPolicy,
    ) -> Result<Option<Socks5ProxyPolicy>, Socks5PolicyError> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("tunnel catalog lock poisoned")
                .update_socks5(id, request),
            Self::Postgres(catalog) => catalog.update_socks5(id, request).await,
        }
    }
    pub(crate) async fn socks5_runtime_policy(
        &self,
        client_id: Uuid,
        name: &str,
        public_port: u16,
    ) -> Result<Option<Socks5ProxyRuntimePolicy>, Socks5PolicyError> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("tunnel catalog lock poisoned")
                .socks5_runtime_policy(client_id, name, public_port),
            Self::Postgres(catalog) => {
                catalog
                    .socks5_runtime_policy(client_id, name, public_port)
                    .await
            }
        }
    }
    pub(crate) async fn create_http_proxy(
        &self,
        request: CreateHttpProxyPolicy,
    ) -> Result<CreatedHttpProxyPolicy, HttpProxyPolicyError> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("tunnel catalog lock poisoned")
                .create_http_proxy(request),
            Self::Postgres(catalog) => catalog.create_http_proxy(request).await,
        }
    }
    pub(crate) async fn list_http_proxies(
        &self,
    ) -> Result<Vec<HttpProxyPolicy>, HttpProxyPolicyError> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("tunnel catalog lock poisoned")
                .list_http_proxies(),
            Self::Postgres(catalog) => catalog.list_http_proxies().await,
        }
    }
    pub(crate) async fn set_http_proxy_enabled(
        &self,
        id: Uuid,
        enabled: bool,
    ) -> Result<bool, HttpProxyPolicyError> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("tunnel catalog lock poisoned")
                .set_http_proxy_enabled(id, enabled),
            Self::Postgres(catalog) => catalog.set_http_proxy_enabled(id, enabled).await,
        }
    }
    pub(crate) async fn delete_http_proxy(
        &self,
        id: Uuid,
    ) -> Result<Option<HttpProxyPolicy>, HttpProxyPolicyError> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("tunnel catalog lock poisoned")
                .delete_http_proxy(id),
            Self::Postgres(catalog) => catalog.delete_http_proxy(id).await,
        }
    }
    pub(crate) async fn http_proxy_policy_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<HttpProxyPolicy>, HttpProxyPolicyError> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("tunnel catalog lock poisoned")
                .http_proxy_policy_by_id(id),
            Self::Postgres(catalog) => catalog.http_proxy_policy_by_id(id).await,
        }
    }
    pub(crate) async fn update_http_proxy(
        &self,
        id: Uuid,
        request: UpdateHttpProxyPolicy,
    ) -> Result<Option<HttpProxyPolicy>, HttpProxyPolicyError> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("tunnel catalog lock poisoned")
                .update_http_proxy(id, request),
            Self::Postgres(catalog) => catalog.update_http_proxy(id, request).await,
        }
    }
    pub(crate) async fn http_proxy_runtime_policy(
        &self,
        client_id: Uuid,
        name: &str,
        public_port: u16,
    ) -> Result<Option<HttpProxyRuntimePolicy>, HttpProxyPolicyError> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("tunnel catalog lock poisoned")
                .http_proxy_runtime_policy(client_id, name, public_port),
            Self::Postgres(catalog) => {
                catalog
                    .http_proxy_runtime_policy(client_id, name, public_port)
                    .await
            }
        }
    }
    pub(crate) async fn create_udp(
        &self,
        request: CreateUdpTunnelPolicy,
    ) -> Result<UdpTunnelPolicy, UdpPolicyError> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("tunnel catalog lock poisoned")
                .create_udp(request),
            Self::Postgres(catalog) => catalog.create_udp(request).await,
        }
    }
    pub(crate) async fn list_udp(&self) -> Result<Vec<UdpTunnelPolicy>, UdpPolicyError> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("tunnel catalog lock poisoned")
                .list_udp(),
            Self::Postgres(catalog) => catalog.list_udp().await,
        }
    }
    pub(crate) async fn udp_policy_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<UdpTunnelPolicy>, UdpPolicyError> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("tunnel catalog lock poisoned")
                .udp_policy_by_id(id),
            Self::Postgres(catalog) => catalog.udp_policy_by_id(id).await,
        }
    }
    pub(crate) async fn update_udp(
        &self,
        id: Uuid,
        request: UpdateUdpTunnelPolicy,
    ) -> Result<Option<UdpTunnelPolicy>, UdpPolicyError> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("tunnel catalog lock poisoned")
                .update_udp(id, request),
            Self::Postgres(catalog) => catalog.update_udp(id, request).await,
        }
    }
    pub(crate) async fn set_udp_enabled(
        &self,
        id: Uuid,
        enabled: bool,
    ) -> Result<bool, UdpPolicyError> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("tunnel catalog lock poisoned")
                .set_udp_enabled(id, enabled),
            Self::Postgres(catalog) => catalog.set_udp_enabled(id, enabled).await,
        }
    }
    pub(crate) async fn delete_udp(&self, id: Uuid) -> Result<bool, UdpPolicyError> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("tunnel catalog lock poisoned")
                .delete_udp(id),
            Self::Postgres(catalog) => catalog.delete_udp(id).await,
        }
    }
    pub(crate) async fn udp_runtime_policy(
        &self,
        client_id: Uuid,
        name: &str,
        public_port: u16,
        target_addr: &str,
    ) -> Result<Option<UdpTunnelRuntimePolicy>, UdpPolicyError> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("tunnel catalog lock poisoned")
                .udp_runtime_policy(client_id, name, public_port, target_addr),
            Self::Postgres(catalog) => {
                catalog
                    .udp_runtime_policy(client_id, name, public_port, target_addr)
                    .await
            }
        }
    }
    pub(crate) async fn create_port_group(
        &self,
        request: CreatePortGroupPolicy,
    ) -> Result<PortGroupPolicy, PortGroupPolicyError> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("tunnel catalog lock poisoned")
                .create_port_group(request),
            Self::Postgres(catalog) => catalog.create_port_group(request).await,
        }
    }
    pub(crate) async fn list_port_groups(
        &self,
    ) -> Result<Vec<PortGroupPolicy>, PortGroupPolicyError> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("tunnel catalog lock poisoned")
                .list_port_groups(),
            Self::Postgres(catalog) => catalog.list_port_groups().await,
        }
    }
    pub(crate) async fn port_group_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<PortGroupPolicy>, PortGroupPolicyError> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("tunnel catalog lock poisoned")
                .port_group_by_id(id),
            Self::Postgres(catalog) => catalog.port_group_by_id(id).await,
        }
    }
    pub(crate) async fn update_port_group(
        &self,
        id: Uuid,
        request: UpdatePortGroupPolicy,
    ) -> Result<Option<PortGroupPolicy>, PortGroupPolicyError> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("tunnel catalog lock poisoned")
                .update_port_group(id, request),
            Self::Postgres(catalog) => catalog.update_port_group(id, request).await,
        }
    }
    pub(crate) async fn port_group_mappings(
        &self,
        id: Uuid,
    ) -> Result<Vec<PortGroupMapping>, PortGroupPolicyError> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("tunnel catalog lock poisoned")
                .port_group_mappings(id),
            Self::Postgres(catalog) => catalog.port_group_mappings(id).await,
        }
    }
    pub(crate) async fn set_port_group_enabled(
        &self,
        id: Uuid,
        enabled: bool,
    ) -> Result<bool, PortGroupPolicyError> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("tunnel catalog lock poisoned")
                .set_port_group_enabled(id, enabled),
            Self::Postgres(catalog) => catalog.set_port_group_enabled(id, enabled).await,
        }
    }
    pub(crate) async fn delete_port_group(
        &self,
        id: Uuid,
    ) -> Result<Option<PortGroupPolicy>, PortGroupPolicyError> {
        match self {
            Self::Sqlite(catalog) => catalog
                .lock()
                .expect("tunnel catalog lock poisoned")
                .delete_port_group(id),
            Self::Postgres(catalog) => catalog.delete_port_group(id).await,
        }
    }
}
