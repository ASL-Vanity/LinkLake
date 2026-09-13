//! 共享隧道业务目录。端口预留与策略在同一 Leader/Fleet 事务中提交。
use super::*;
use crate::{
    ha_runtime::HaRuntime, policy_service::postgres::FleetPolicyTransaction,
    storage::CoordinationStorage,
};
use std::sync::Arc;
use tokio_postgres::{GenericClient, Row, Transaction};

pub(crate) struct PostgresTunnelCatalog {
    pub(crate) storage: CoordinationStorage,
    pub(crate) runtime: Arc<HaRuntime>,
    pub(crate) public_port_policy: PublicPortPolicy,
}

#[derive(Clone)]
pub(crate) enum SharedTunnelPolicy {
    Tcp(TcpTunnelPolicy),
    Udp(UdpTunnelPolicy),
    Socks5(Socks5ProxyPolicy),
    HttpProxy(HttpProxyPolicy),
    PortGroup(PortGroupPolicy),
}

// 不提供 Debug，防止凭据摘要进入普通策略日志或 API。
#[derive(Clone)]
pub(crate) struct TunnelSnapshot {
    pub(crate) policy: SharedTunnelPolicy,
    pub(crate) password_hash: Option<String>,
}

#[derive(Debug)]
pub(crate) enum TunnelMutationError {
    DuplicateName,
    DuplicatePublicPort,
    FleetManaged,
}
impl std::fmt::Display for TunnelMutationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::DuplicateName => "duplicate tunnel name",
            Self::DuplicatePublicPort => "public port is already assigned",
            Self::FleetManaged => "fleet_managed_policy",
        })
    }
}
impl std::error::Error for TunnelMutationError {}

impl SharedTunnelPolicy {
    pub(crate) fn id(&self) -> Uuid {
        match self {
            Self::Tcp(p) => p.id,
            Self::Udp(p) => p.id,
            Self::Socks5(p) => p.id,
            Self::HttpProxy(p) => p.id,
            Self::PortGroup(p) => p.id,
        }
    }
    pub(crate) fn client_id(&self) -> Uuid {
        match self {
            Self::Tcp(p) => p.client_id,
            Self::Udp(p) => p.client_id,
            Self::Socks5(p) => p.client_id,
            Self::HttpProxy(p) => p.client_id,
            Self::PortGroup(p) => p.client_id,
        }
    }
    pub(crate) fn name(&self) -> &str {
        match self {
            Self::Tcp(p) => &p.name,
            Self::Udp(p) => &p.name,
            Self::Socks5(p) => &p.name,
            Self::HttpProxy(p) => &p.name,
            Self::PortGroup(p) => &p.name,
        }
    }
    pub(crate) fn enabled(&self) -> bool {
        match self {
            Self::Tcp(p) => p.enabled,
            Self::Udp(p) => p.enabled,
            Self::Socks5(p) => p.enabled,
            Self::HttpProxy(p) => p.enabled,
            Self::PortGroup(p) => p.enabled,
        }
    }
    pub(crate) fn kind(&self) -> &'static str {
        match self {
            Self::Tcp(_) => "tcp",
            Self::Udp(_) => "udp",
            Self::Socks5(_) => "socks5_proxy",
            Self::HttpProxy(_) => "http_proxy",
            Self::PortGroup(_) => "port_group",
        }
    }
    pub(crate) fn protocol(&self) -> &'static str {
        match self {
            Self::Tcp(_) | Self::HttpProxy(_) => "tcp",
            Self::Udp(_) => "udp",
            Self::Socks5(_) => "both",
            Self::PortGroup(p) => p.protocol.as_str(),
        }
    }
    fn set_enabled(&mut self, enabled: bool) {
        match self {
            Self::Tcp(p) => p.enabled = enabled,
            Self::Udp(p) => p.enabled = enabled,
            Self::Socks5(p) => p.enabled = enabled,
            Self::HttpProxy(p) => p.enabled = enabled,
            Self::PortGroup(p) => p.enabled = enabled,
        }
    }
    pub(crate) fn json(&self) -> anyhow::Result<String> {
        Ok(match self {
            Self::Tcp(p) => serde_json::to_string(p)?,
            Self::Udp(p) => serde_json::to_string(p)?,
            Self::Socks5(p) => serde_json::to_string(p)?,
            Self::HttpProxy(p) => serde_json::to_string(p)?,
            Self::PortGroup(p) => serde_json::to_string(p)?,
        })
    }
    pub(crate) fn canonical(&self, ports: &PublicPortPolicy) -> anyhow::Result<()> {
        match self {
            Self::Tcp(p) => {
                let request: CreateTcpTunnelPolicy =
                    serde_json::from_str(&serde_json::to_string(p)?)?;
                let canonical = requested_tcp(ports, p.id, p.enabled, &request)?;
                anyhow::ensure!(&canonical == p, "noncanonical shared tunnel policy");
            }
            Self::Udp(p) => {
                let request: CreateUdpTunnelPolicy =
                    serde_json::from_str(&serde_json::to_string(p)?)?;
                let canonical = requested_udp(ports, p.id, p.enabled, &request)?;
                anyhow::ensure!(&canonical == p, "noncanonical shared tunnel policy");
            }
            Self::Socks5(p) => {
                let request: CreateSocks5ProxyPolicy =
                    serde_json::from_str(&serde_json::to_string(p)?)?;
                let canonical = requested_socks5(ports, p.id, p.enabled, &request)?;
                anyhow::ensure!(&canonical == p, "noncanonical shared tunnel policy");
            }
            Self::HttpProxy(p) => {
                let request: CreateHttpProxyPolicy =
                    serde_json::from_str(&serde_json::to_string(p)?)?;
                let canonical = requested_http_proxy(ports, p.id, p.enabled, &request)?;
                anyhow::ensure!(&canonical == p, "noncanonical shared tunnel policy");
            }
            Self::PortGroup(p) => {
                let request: CreatePortGroupPolicy =
                    serde_json::from_str(&serde_json::to_string(p)?)?;
                let canonical = requested_port_group(ports, p.id, p.enabled, &request)?;
                anyhow::ensure!(&canonical == p, "noncanonical shared tunnel policy");
            }
        }
        Ok(())
    }
    pub(crate) fn port_reservations(&self) -> anyhow::Result<Vec<(&'static str, u16)>> {
        Ok(match self {
            Self::Tcp(p) => vec![("tcp", p.public_port)],
            Self::Udp(p) => vec![("udp", p.public_port)],
            Self::Socks5(p) => vec![("tcp", p.public_port), ("udp", p.public_port)],
            Self::HttpProxy(p) => vec![("tcp", p.public_port)],
            Self::PortGroup(p) => parse_port_mappings(
                &p.public_ports,
                &p.target_ports,
                1,
                u16::MAX,
                MAX_PORT_MAPPINGS,
            )?
            .pairs
            .into_iter()
            .map(|pair| (p.protocol.as_str(), pair.public_port))
            .collect(),
        })
    }
    fn unique_name(&self) -> bool {
        matches!(
            self,
            Self::Socks5(_) | Self::HttpProxy(_) | Self::PortGroup(_)
        )
    }
}
impl TunnelSnapshot {
    fn validate(&self, ports: &PublicPortPolicy) -> anyhow::Result<()> {
        self.policy.canonical(ports)?;
        if matches!(
            self.policy,
            SharedTunnelPolicy::Socks5(_) | SharedTunnelPolicy::HttpProxy(_)
        ) {
            anyhow::ensure!(
                self.password_hash.as_ref().is_some_and(|h| h.len() == 64
                    && h.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))),
                "invalid shared proxy credential"
            );
        } else {
            anyhow::ensure!(
                self.password_hash.is_none(),
                "unexpected credential on tunnel"
            );
        }
        Ok(())
    }
}

fn decode(row: &Row, ports: &PublicPortPolicy) -> anyhow::Result<TunnelSnapshot> {
    let kind: &str = row.try_get("kind")?;
    let json: &str = row.try_get("policy")?;
    anyhow::ensure!(
        json.len() <= 16384,
        "shared tunnel policy exceeds size bound"
    );
    let policy = match kind {
        "tcp" => SharedTunnelPolicy::Tcp(serde_json::from_str::<TcpTunnelPolicy>(json)?),
        "udp" => SharedTunnelPolicy::Udp(serde_json::from_str::<UdpTunnelPolicy>(json)?),
        "socks5_proxy" => {
            SharedTunnelPolicy::Socks5(serde_json::from_str::<Socks5ProxyPolicy>(json)?)
        }
        "http_proxy" => {
            SharedTunnelPolicy::HttpProxy(serde_json::from_str::<HttpProxyPolicy>(json)?)
        }
        "port_group" => {
            SharedTunnelPolicy::PortGroup(serde_json::from_str::<PortGroupPolicy>(json)?)
        }
        _ => anyhow::bail!("unknown shared tunnel kind"),
    };
    anyhow::ensure!(
        policy.id().to_string() == row.try_get::<_, &str>("id")?
            && policy.client_id().to_string() == row.try_get::<_, &str>("client_id")?
            && policy.name() == row.try_get::<_, &str>("name")?
            && policy.protocol() == row.try_get::<_, &str>("protocol")?,
        "shared tunnel row identity mismatch"
    );
    let snapshot = TunnelSnapshot {
        policy,
        password_hash: row.try_get("password_hash")?,
    };
    snapshot.validate(ports)?;
    Ok(snapshot)
}
const SELECT: &str = "SELECT id,kind,client_id,name,protocol,policy::text,password_hash";

// 单条 SELECT 同时读取目录及预留，避免读取跨事务代际。
async fn read_rows<C: GenericClient + Sync>(
    client: &C,
    ports: &PublicPortPolicy,
    id: Option<Uuid>,
) -> anyhow::Result<Vec<TunnelSnapshot>> {
    let sql=format!("{SELECT}, COALESCE((SELECT jsonb_agg(jsonb_build_array(r.protocol,r.public_port) ORDER BY r.protocol,r.public_port) FROM linklake_tunnel_ports r WHERE r.policy_id=linklake_tunnel_policies.id),'[]'::jsonb)::text AS reservations FROM linklake_tunnel_policies WHERE ($1::text IS NULL OR id=$1) ORDER BY kind,id");
    let rows = client.query(&sql, &[&id.map(|id| id.to_string())]).await?;
    decode_rows(&rows, ports)
}

fn decode_rows(rows: &[Row], ports: &PublicPortPolicy) -> anyhow::Result<Vec<TunnelSnapshot>> {
    rows.iter()
        .map(|row| {
            let snapshot = decode(row, ports)?;
            let reservations: &str = row.try_get("reservations")?;
            anyhow::ensure!(
                reservations.len() <= 16384,
                "shared port reservations exceed size bound"
            );
            let actual: Vec<(String, u16)> = serde_json::from_str(reservations)?;
            let mut expected: Vec<(String, u16)> = snapshot
                .policy
                .port_reservations()?
                .into_iter()
                .map(|(p, n)| (p.to_owned(), n))
                .collect();
            expected.sort();
            anyhow::ensure!(
                actual == expected,
                "shared tunnel port reservation mismatch"
            );
            Ok(snapshot)
        })
        .collect()
}
pub(crate) async fn transaction_list(
    tx: &Transaction<'_>,
    ports: &PublicPortPolicy,
) -> anyhow::Result<Vec<TunnelSnapshot>> {
    read_rows(tx, ports, None).await
}
pub(crate) async fn transaction_snapshot(
    tx: &Transaction<'_>,
    ports: &PublicPortPolicy,
    id: Uuid,
) -> anyhow::Result<Option<TunnelSnapshot>> {
    Ok(read_rows(tx, ports, Some(id)).await?.pop())
}

pub(crate) async fn transaction_put(
    guard: &FleetPolicyTransaction<'_, '_>,
    ports: &PublicPortPolicy,
    snapshot: &TunnelSnapshot,
) -> anyhow::Result<()> {
    snapshot.validate(ports)?;
    guard.assert_current().await?;
    let tx = guard.transaction();
    let policy = &snapshot.policy;
    let id = policy.id().to_string();
    if let Some(row) = tx
        .query_opt(
            "SELECT kind FROM linklake_tunnel_policies WHERE id=$1",
            &[&id],
        )
        .await?
    {
        anyhow::ensure!(
            row.try_get::<_, &str>(0)? == policy.kind(),
            "cannot change tunnel resource kind"
        );
    }
    if policy.unique_name() && tx.query_opt("SELECT id FROM linklake_tunnel_policies WHERE kind=$1 AND client_id=$2 AND name=$3 AND protocol=$4 AND id<>$5",
        &[&policy.kind(),&policy.client_id().to_string(),&policy.name(),&policy.protocol(),&id]).await?.is_some() {
        return Err(TunnelMutationError::DuplicateName.into());
    }
    let reservations = policy.port_reservations()?;
    for (protocol, port) in &reservations {
        if tx.query_opt("SELECT policy_id FROM linklake_tunnel_ports WHERE protocol=$1 AND public_port=$2 AND policy_id<>$3",&[protocol,&i32::from(*port),&id]).await?.is_some() {
            return Err(TunnelMutationError::DuplicatePublicPort.into());
        }
    }
    tx.execute("INSERT INTO linklake_tunnel_policies(id,kind,client_id,name,protocol,policy,password_hash) VALUES($1,$2,$3,$4,$5,$6::text::jsonb,$7) ON CONFLICT(id) DO UPDATE SET client_id=excluded.client_id,name=excluded.name,protocol=excluded.protocol,policy=excluded.policy,password_hash=excluded.password_hash",
        &[&id,&policy.kind(),&policy.client_id().to_string(),&policy.name(),&policy.protocol(),&policy.json()?,&snapshot.password_hash]).await?;
    tx.execute(
        "DELETE FROM linklake_tunnel_ports WHERE policy_id=$1",
        &[&id],
    )
    .await?;
    for (protocol, port) in reservations {
        tx.execute(
            "INSERT INTO linklake_tunnel_ports(protocol,public_port,policy_id) VALUES($1,$2,$3)",
            &[&protocol, &i32::from(port), &id],
        )
        .await?;
    }
    guard.assert_current().await?;
    Ok(())
}
pub(crate) async fn transaction_delete(
    guard: &FleetPolicyTransaction<'_, '_>,
    id: Uuid,
) -> anyhow::Result<bool> {
    guard.assert_current().await?;
    Ok(guard
        .transaction()
        .execute(
            "DELETE FROM linklake_tunnel_policies WHERE id=$1",
            &[&id.to_string()],
        )
        .await?
        != 0)
}
async fn ensure_unmanaged(tx: &Transaction<'_>, id: Uuid) -> anyhow::Result<()> {
    if tx
        .query_opt(
            "SELECT policy_id FROM linklake_fleet_resource_ownership WHERE policy_id=$1",
            &[&id.to_string()],
        )
        .await?
        .is_some()
    {
        return Err(TunnelMutationError::FleetManaged.into());
    }
    Ok(())
}
impl PostgresTunnelCatalog {
    pub(crate) async fn validate_existing(&self) -> anyhow::Result<()> {
        self.all().await.map(|_| ())
    }

    async fn all(&self) -> anyhow::Result<Vec<TunnelSnapshot>> {
        let client = self.storage.postgres_client().await?;
        read_rows(&*client, &self.public_port_policy, None).await
    }
    async fn for_port(
        &self,
        protocol: &str,
        public_port: u16,
    ) -> anyhow::Result<Vec<TunnelSnapshot>> {
        let client = self.storage.postgres_client().await?;
        let sql=format!("{SELECT}, COALESCE((SELECT jsonb_agg(jsonb_build_array(r.protocol,r.public_port) ORDER BY r.protocol,r.public_port) FROM linklake_tunnel_ports r WHERE r.policy_id=linklake_tunnel_policies.id),'[]'::jsonb)::text AS reservations FROM linklake_tunnel_policies WHERE id=(SELECT policy_id FROM linklake_tunnel_ports WHERE protocol=$1 AND public_port=$2)");
        let rows = client
            .query(&sql, &[&protocol, &i32::from(public_port)])
            .await?;
        decode_rows(&rows, &self.public_port_policy)
    }
    async fn snapshot(&self, id: Uuid) -> anyhow::Result<Option<TunnelSnapshot>> {
        let client = self.storage.postgres_client().await?;
        Ok(read_rows(&*client, &self.public_port_policy, Some(id))
            .await?
            .pop())
    }
    async fn save(
        &self,
        mut next: TunnelSnapshot,
        create: bool,
    ) -> anyhow::Result<Option<TunnelSnapshot>> {
        let mut client = self.storage.postgres_client().await?;
        let tx = client.transaction().await?;
        let guard = FleetPolicyTransaction::lock(&tx, &self.runtime).await?;
        ensure_unmanaged(&tx, next.policy.id()).await?;
        let previous =
            transaction_snapshot(&tx, &self.public_port_policy, next.policy.id()).await?;
        if create {
            anyhow::ensure!(previous.is_none(), "tunnel id already exists");
        } else {
            let Some(previous) = previous else {
                return Ok(None);
            };
            if previous.policy.kind() != next.policy.kind() {
                return Ok(None);
            }
            next.policy.set_enabled(previous.policy.enabled());
            next.password_hash = previous.password_hash;
        }
        transaction_put(&guard, &self.public_port_policy, &next).await?;
        guard.assert_current().await?;
        tx.commit().await?;
        Ok(Some(next))
    }
    async fn enable(&self, id: Uuid, kind: &str, enabled: bool) -> anyhow::Result<bool> {
        let mut client = self.storage.postgres_client().await?;
        let tx = client.transaction().await?;
        let guard = FleetPolicyTransaction::lock(&tx, &self.runtime).await?;
        ensure_unmanaged(&tx, id).await?;
        let Some(mut current) = transaction_snapshot(&tx, &self.public_port_policy, id).await?
        else {
            return Ok(false);
        };
        if current.policy.kind() != kind {
            return Ok(false);
        }
        current.policy.set_enabled(enabled);
        transaction_put(&guard, &self.public_port_policy, &current).await?;
        guard.assert_current().await?;
        tx.commit().await?;
        Ok(true)
    }
    async fn remove(&self, id: Uuid, kind: &str) -> anyhow::Result<Option<TunnelSnapshot>> {
        let mut client = self.storage.postgres_client().await?;
        let tx = client.transaction().await?;
        let guard = FleetPolicyTransaction::lock(&tx, &self.runtime).await?;
        ensure_unmanaged(&tx, id).await?;
        let Some(current) = transaction_snapshot(&tx, &self.public_port_policy, id).await? else {
            return Ok(None);
        };
        if current.policy.kind() != kind {
            return Ok(None);
        }
        transaction_delete(&guard, id).await?;
        guard.assert_current().await?;
        tx.commit().await?;
        Ok(Some(current))
    }
}
impl PostgresTunnelCatalog {
    pub(crate) async fn create(
        &self,
        request: CreateTcpTunnelPolicy,
    ) -> anyhow::Result<TcpTunnelPolicy> {
        let policy = requested_tcp(&self.public_port_policy, Uuid::new_v4(), true, &request)?;

        self.save(
            TunnelSnapshot {
                policy: SharedTunnelPolicy::Tcp(policy.clone()),
                password_hash: None,
            },
            true,
        )
        .await?;
        Ok(policy)
    }
    pub(crate) async fn list(&self) -> anyhow::Result<Vec<TcpTunnelPolicy>> {
        let mut policies: Vec<_> = self
            .all()
            .await?
            .into_iter()
            .filter_map(|s| match s.policy {
                SharedTunnelPolicy::Tcp(p) => Some(p),
                _ => None,
            })
            .collect();
        policies.sort_by_key(|p| p.public_port);
        Ok(policies)
    }
    pub(crate) async fn policy_by_id(&self, id: Uuid) -> anyhow::Result<Option<TcpTunnelPolicy>> {
        Ok(self.snapshot(id).await?.and_then(|s| match s.policy {
            SharedTunnelPolicy::Tcp(p) => Some(p),
            _ => None,
        }))
    }
    pub(crate) async fn update(
        &self,
        id: Uuid,
        request: UpdateTcpTunnelPolicy,
    ) -> anyhow::Result<Option<TcpTunnelPolicy>> {
        let policy = requested_tcp(&self.public_port_policy, id, true, &request)?;
        Ok(self
            .save(
                TunnelSnapshot {
                    policy: SharedTunnelPolicy::Tcp(policy),
                    password_hash: None,
                },
                false,
            )
            .await?
            .and_then(|s| match s.policy {
                SharedTunnelPolicy::Tcp(p) => Some(p),
                _ => None,
            }))
    }
    pub(crate) async fn set_enabled(&self, id: Uuid, enabled: bool) -> anyhow::Result<bool> {
        self.enable(id, "tcp", enabled).await
    }
    pub(crate) async fn delete(&self, id: Uuid) -> anyhow::Result<bool> {
        Ok(self.remove(id, "tcp").await?.is_some())
    }
}
impl UdpPolicyError {
    fn from_storage(error: anyhow::Error) -> Self {
        match error.downcast::<Self>() {
            Ok(error) => error,
            Err(error) => match error.downcast::<TunnelMutationError>() {
                Ok(TunnelMutationError::DuplicatePublicPort) => Self::DuplicatePublicPort,
                Ok(TunnelMutationError::FleetManaged) => Self::FleetManaged,
                Ok(TunnelMutationError::DuplicateName) => {
                    Self::Storage(anyhow::anyhow!("duplicate tunnel name"))
                }
                Err(error) => Self::Storage(error),
            },
        }
    }
}
impl PostgresTunnelCatalog {
    pub(crate) async fn create_udp(
        &self,
        request: CreateUdpTunnelPolicy,
    ) -> Result<UdpTunnelPolicy, UdpPolicyError> {
        let policy = requested_udp(&self.public_port_policy, Uuid::new_v4(), true, &request)?;

        self.save(
            TunnelSnapshot {
                policy: SharedTunnelPolicy::Udp(policy.clone()),
                password_hash: None,
            },
            true,
        )
        .await
        .map_err(UdpPolicyError::from_storage)?;
        Ok(policy)
    }
    pub(crate) async fn list_udp(&self) -> Result<Vec<UdpTunnelPolicy>, UdpPolicyError> {
        let mut policies: Vec<_> = self
            .all()
            .await
            .map_err(UdpPolicyError::from_storage)?
            .into_iter()
            .filter_map(|s| match s.policy {
                SharedTunnelPolicy::Udp(p) => Some(p),
                _ => None,
            })
            .collect();
        policies.sort_by_key(|p| p.public_port);
        Ok(policies)
    }
    pub(crate) async fn udp_policy_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<UdpTunnelPolicy>, UdpPolicyError> {
        Ok(self
            .snapshot(id)
            .await
            .map_err(UdpPolicyError::from_storage)?
            .and_then(|s| match s.policy {
                SharedTunnelPolicy::Udp(p) => Some(p),
                _ => None,
            }))
    }
    pub(crate) async fn update_udp(
        &self,
        id: Uuid,
        request: UpdateUdpTunnelPolicy,
    ) -> Result<Option<UdpTunnelPolicy>, UdpPolicyError> {
        let policy = requested_udp(&self.public_port_policy, id, true, &request)?;
        Ok(self
            .save(
                TunnelSnapshot {
                    policy: SharedTunnelPolicy::Udp(policy),
                    password_hash: None,
                },
                false,
            )
            .await
            .map_err(UdpPolicyError::from_storage)?
            .and_then(|s| match s.policy {
                SharedTunnelPolicy::Udp(p) => Some(p),
                _ => None,
            }))
    }
    pub(crate) async fn set_udp_enabled(
        &self,
        id: Uuid,
        enabled: bool,
    ) -> Result<bool, UdpPolicyError> {
        self.enable(id, "udp", enabled)
            .await
            .map_err(UdpPolicyError::from_storage)
    }
    pub(crate) async fn delete_udp(&self, id: Uuid) -> Result<bool, UdpPolicyError> {
        Ok(self
            .remove(id, "udp")
            .await
            .map_err(UdpPolicyError::from_storage)?
            .is_some())
    }
}
impl Socks5PolicyError {
    fn from_storage(error: anyhow::Error) -> Self {
        match error.downcast::<Self>() {
            Ok(error) => error,
            Err(error) => match error.downcast::<TunnelMutationError>() {
                Ok(TunnelMutationError::DuplicatePublicPort) => Self::DuplicatePublicPort,
                Ok(TunnelMutationError::FleetManaged) => Self::FleetManaged,
                Ok(TunnelMutationError::DuplicateName) => Self::DuplicateName,
                Err(error) => Self::Storage(error),
            },
        }
    }
}
impl PostgresTunnelCatalog {
    pub(crate) async fn create_socks5(
        &self,
        request: CreateSocks5ProxyPolicy,
    ) -> Result<CreatedSocks5ProxyPolicy, Socks5PolicyError> {
        let policy = requested_socks5(&self.public_port_policy, Uuid::new_v4(), true, &request)?;
        let password = format!("llp_{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        self.save(
            TunnelSnapshot {
                policy: SharedTunnelPolicy::Socks5(policy.clone()),
                password_hash: Some(hash_socks5_password(&password)),
            },
            true,
        )
        .await
        .map_err(Socks5PolicyError::from_storage)?;
        Ok(CreatedSocks5ProxyPolicy { policy, password })
    }
    pub(crate) async fn list_socks5(&self) -> Result<Vec<Socks5ProxyPolicy>, Socks5PolicyError> {
        let mut policies: Vec<_> = self
            .all()
            .await
            .map_err(Socks5PolicyError::from_storage)?
            .into_iter()
            .filter_map(|s| match s.policy {
                SharedTunnelPolicy::Socks5(p) => Some(p),
                _ => None,
            })
            .collect();
        policies.sort_by_key(|p| p.public_port);
        Ok(policies)
    }
    pub(crate) async fn socks5_policy_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<Socks5ProxyPolicy>, Socks5PolicyError> {
        Ok(self
            .snapshot(id)
            .await
            .map_err(Socks5PolicyError::from_storage)?
            .and_then(|s| match s.policy {
                SharedTunnelPolicy::Socks5(p) => Some(p),
                _ => None,
            }))
    }
    pub(crate) async fn update_socks5(
        &self,
        id: Uuid,
        request: UpdateSocks5ProxyPolicy,
    ) -> Result<Option<Socks5ProxyPolicy>, Socks5PolicyError> {
        let policy = requested_socks5(&self.public_port_policy, id, true, &request)?;
        Ok(self
            .save(
                TunnelSnapshot {
                    policy: SharedTunnelPolicy::Socks5(policy),
                    password_hash: None,
                },
                false,
            )
            .await
            .map_err(Socks5PolicyError::from_storage)?
            .and_then(|s| match s.policy {
                SharedTunnelPolicy::Socks5(p) => Some(p),
                _ => None,
            }))
    }
    pub(crate) async fn set_socks5_enabled(
        &self,
        id: Uuid,
        enabled: bool,
    ) -> Result<bool, Socks5PolicyError> {
        self.enable(id, "socks5_proxy", enabled)
            .await
            .map_err(Socks5PolicyError::from_storage)
    }
    pub(crate) async fn delete_socks5(
        &self,
        id: Uuid,
    ) -> Result<Option<Socks5ProxyPolicy>, Socks5PolicyError> {
        Ok(self
            .remove(id, "socks5_proxy")
            .await
            .map_err(Socks5PolicyError::from_storage)?
            .and_then(|s| match s.policy {
                SharedTunnelPolicy::Socks5(p) => Some(p),
                _ => None,
            }))
    }
}
impl HttpProxyPolicyError {
    fn from_storage(error: anyhow::Error) -> Self {
        match error.downcast::<Self>() {
            Ok(error) => error,
            Err(error) => match error.downcast::<TunnelMutationError>() {
                Ok(TunnelMutationError::DuplicatePublicPort) => Self::DuplicatePublicPort,
                Ok(TunnelMutationError::FleetManaged) => Self::FleetManaged,
                Ok(TunnelMutationError::DuplicateName) => Self::DuplicateName,
                Err(error) => Self::Storage(error),
            },
        }
    }
}
impl PostgresTunnelCatalog {
    pub(crate) async fn create_http_proxy(
        &self,
        request: CreateHttpProxyPolicy,
    ) -> Result<CreatedHttpProxyPolicy, HttpProxyPolicyError> {
        let policy =
            requested_http_proxy(&self.public_port_policy, Uuid::new_v4(), true, &request)?;
        let password = format!("llh_{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        self.save(
            TunnelSnapshot {
                policy: SharedTunnelPolicy::HttpProxy(policy.clone()),
                password_hash: Some(hash_http_proxy_password(&password)),
            },
            true,
        )
        .await
        .map_err(HttpProxyPolicyError::from_storage)?;
        Ok(CreatedHttpProxyPolicy { policy, password })
    }
    pub(crate) async fn list_http_proxies(
        &self,
    ) -> Result<Vec<HttpProxyPolicy>, HttpProxyPolicyError> {
        let mut policies: Vec<_> = self
            .all()
            .await
            .map_err(HttpProxyPolicyError::from_storage)?
            .into_iter()
            .filter_map(|s| match s.policy {
                SharedTunnelPolicy::HttpProxy(p) => Some(p),
                _ => None,
            })
            .collect();
        policies.sort_by_key(|p| p.public_port);
        Ok(policies)
    }
    pub(crate) async fn http_proxy_policy_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<HttpProxyPolicy>, HttpProxyPolicyError> {
        Ok(self
            .snapshot(id)
            .await
            .map_err(HttpProxyPolicyError::from_storage)?
            .and_then(|s| match s.policy {
                SharedTunnelPolicy::HttpProxy(p) => Some(p),
                _ => None,
            }))
    }
    pub(crate) async fn update_http_proxy(
        &self,
        id: Uuid,
        request: UpdateHttpProxyPolicy,
    ) -> Result<Option<HttpProxyPolicy>, HttpProxyPolicyError> {
        let policy = requested_http_proxy(&self.public_port_policy, id, true, &request)?;
        Ok(self
            .save(
                TunnelSnapshot {
                    policy: SharedTunnelPolicy::HttpProxy(policy),
                    password_hash: None,
                },
                false,
            )
            .await
            .map_err(HttpProxyPolicyError::from_storage)?
            .and_then(|s| match s.policy {
                SharedTunnelPolicy::HttpProxy(p) => Some(p),
                _ => None,
            }))
    }
    pub(crate) async fn set_http_proxy_enabled(
        &self,
        id: Uuid,
        enabled: bool,
    ) -> Result<bool, HttpProxyPolicyError> {
        self.enable(id, "http_proxy", enabled)
            .await
            .map_err(HttpProxyPolicyError::from_storage)
    }
    pub(crate) async fn delete_http_proxy(
        &self,
        id: Uuid,
    ) -> Result<Option<HttpProxyPolicy>, HttpProxyPolicyError> {
        Ok(self
            .remove(id, "http_proxy")
            .await
            .map_err(HttpProxyPolicyError::from_storage)?
            .and_then(|s| match s.policy {
                SharedTunnelPolicy::HttpProxy(p) => Some(p),
                _ => None,
            }))
    }
}
impl PortGroupPolicyError {
    fn from_storage(error: anyhow::Error) -> Self {
        match error.downcast::<Self>() {
            Ok(error) => error,
            Err(error) => match error.downcast::<TunnelMutationError>() {
                Ok(TunnelMutationError::DuplicatePublicPort) => Self::DuplicatePublicPort,
                Ok(TunnelMutationError::FleetManaged) => Self::FleetManaged,
                Ok(TunnelMutationError::DuplicateName) => Self::DuplicateName,
                Err(error) => Self::Storage(error),
            },
        }
    }
}
impl PostgresTunnelCatalog {
    pub(crate) async fn create_port_group(
        &self,
        request: CreatePortGroupPolicy,
    ) -> Result<PortGroupPolicy, PortGroupPolicyError> {
        let policy =
            requested_port_group(&self.public_port_policy, Uuid::new_v4(), true, &request)?;

        self.save(
            TunnelSnapshot {
                policy: SharedTunnelPolicy::PortGroup(policy.clone()),
                password_hash: None,
            },
            true,
        )
        .await
        .map_err(PortGroupPolicyError::from_storage)?;
        Ok(policy)
    }
    pub(crate) async fn list_port_groups(
        &self,
    ) -> Result<Vec<PortGroupPolicy>, PortGroupPolicyError> {
        let mut policies: Vec<_> = self
            .all()
            .await
            .map_err(PortGroupPolicyError::from_storage)?
            .into_iter()
            .filter_map(|s| match s.policy {
                SharedTunnelPolicy::PortGroup(p) => Some(p),
                _ => None,
            })
            .collect();
        policies.sort_by(|a, b| {
            (a.protocol.as_str(), &a.public_ports).cmp(&(b.protocol.as_str(), &b.public_ports))
        });
        Ok(policies)
    }
    pub(crate) async fn port_group_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<PortGroupPolicy>, PortGroupPolicyError> {
        Ok(self
            .snapshot(id)
            .await
            .map_err(PortGroupPolicyError::from_storage)?
            .and_then(|s| match s.policy {
                SharedTunnelPolicy::PortGroup(p) => Some(p),
                _ => None,
            }))
    }
    pub(crate) async fn update_port_group(
        &self,
        id: Uuid,
        request: UpdatePortGroupPolicy,
    ) -> Result<Option<PortGroupPolicy>, PortGroupPolicyError> {
        let policy = requested_port_group(&self.public_port_policy, id, true, &request)?;
        Ok(self
            .save(
                TunnelSnapshot {
                    policy: SharedTunnelPolicy::PortGroup(policy),
                    password_hash: None,
                },
                false,
            )
            .await
            .map_err(PortGroupPolicyError::from_storage)?
            .and_then(|s| match s.policy {
                SharedTunnelPolicy::PortGroup(p) => Some(p),
                _ => None,
            }))
    }
    pub(crate) async fn set_port_group_enabled(
        &self,
        id: Uuid,
        enabled: bool,
    ) -> Result<bool, PortGroupPolicyError> {
        self.enable(id, "port_group", enabled)
            .await
            .map_err(PortGroupPolicyError::from_storage)
    }
    pub(crate) async fn delete_port_group(
        &self,
        id: Uuid,
    ) -> Result<Option<PortGroupPolicy>, PortGroupPolicyError> {
        Ok(self
            .remove(id, "port_group")
            .await
            .map_err(PortGroupPolicyError::from_storage)?
            .and_then(|s| match s.policy {
                SharedTunnelPolicy::PortGroup(p) => Some(p),
                _ => None,
            }))
    }
}
impl PostgresTunnelCatalog {
    pub(crate) async fn port_group_mappings(
        &self,
        id: Uuid,
    ) -> Result<Vec<PortGroupMapping>, PortGroupPolicyError> {
        let Some(p) = self.port_group_by_id(id).await? else {
            return Ok(Vec::new());
        };
        mappings(&p).map_err(PortGroupPolicyError::from_storage)
    }
    pub(crate) async fn runtime_policy(
        &self,
        client_id: Uuid,
        name: &str,
        public_port: u16,
        target: &str,
    ) -> anyhow::Result<Option<TcpTunnelRuntimePolicy>> {
        for snapshot in self.for_port("tcp", public_port).await? {
            if !snapshot.policy.enabled()
                || snapshot.policy.client_id() != client_id
                || snapshot.policy.name() != name
            {
                continue;
            }
            match snapshot.policy {
                SharedTunnelPolicy::Tcp(p)
                    if p.public_port == public_port && p.target_addr == target =>
                {
                    return Ok(Some(TcpTunnelRuntimePolicy {
                        policy_id: p.id,
                        policy_kind: TrafficPolicyKind::Tcp,
                        max_connections: usize::from(p.max_connections),
                        bandwidth_limit_bps: p.bandwidth_limit_bps,
                    }))
                }
                SharedTunnelPolicy::PortGroup(p)
                    if p.protocol == PortGroupProtocol::Tcp
                        && mappings(&p)?
                            .iter()
                            .any(|m| m.public_port == public_port && m.target_addr == target) =>
                {
                    return Ok(Some(TcpTunnelRuntimePolicy {
                        policy_id: p.id,
                        policy_kind: TrafficPolicyKind::PortGroup,
                        max_connections: usize::from(p.max_connections),
                        bandwidth_limit_bps: p.bandwidth_limit_bps,
                    }))
                }
                _ => {}
            }
        }
        Ok(None)
    }
    pub(crate) async fn udp_runtime_policy(
        &self,
        client_id: Uuid,
        name: &str,
        public_port: u16,
        target: &str,
    ) -> Result<Option<UdpTunnelRuntimePolicy>, UdpPolicyError> {
        for snapshot in self
            .for_port("udp", public_port)
            .await
            .map_err(UdpPolicyError::from_storage)?
        {
            if !snapshot.policy.enabled()
                || snapshot.policy.client_id() != client_id
                || snapshot.policy.name() != name
            {
                continue;
            }
            match snapshot.policy {
                SharedTunnelPolicy::Udp(p)
                    if p.public_port == public_port && p.target_addr == target =>
                {
                    return Ok(Some(UdpTunnelRuntimePolicy {
                        policy_id: p.id,
                        policy_kind: TrafficPolicyKind::Udp,
                        max_sessions: usize::from(p.max_sessions),
                        session_idle_timeout_seconds: u64::from(p.session_idle_timeout_seconds),
                        bandwidth_limit_bps: p.bandwidth_limit_bps,
                    }))
                }
                SharedTunnelPolicy::PortGroup(p)
                    if p.protocol == PortGroupProtocol::Udp
                        && mappings(&p)
                            .map_err(UdpPolicyError::from_storage)?
                            .iter()
                            .any(|m| m.public_port == public_port && m.target_addr == target) =>
                {
                    return Ok(Some(UdpTunnelRuntimePolicy {
                        policy_id: p.id,
                        policy_kind: TrafficPolicyKind::PortGroup,
                        max_sessions: usize::from(p.max_sessions),
                        session_idle_timeout_seconds: u64::from(p.session_idle_timeout_seconds),
                        bandwidth_limit_bps: p.bandwidth_limit_bps,
                    }))
                }
                _ => {}
            }
        }
        Ok(None)
    }
    pub(crate) async fn socks5_runtime_policy(
        &self,
        client_id: Uuid,
        name: &str,
        public_port: u16,
    ) -> Result<Option<Socks5ProxyRuntimePolicy>, Socks5PolicyError> {
        for snapshot in self
            .for_port("tcp", public_port)
            .await
            .map_err(Socks5PolicyError::from_storage)?
        {
            if let SharedTunnelPolicy::Socks5(p) = snapshot.policy {
                if p.enabled
                    && p.client_id == client_id
                    && p.name == name
                    && p.public_port == public_port
                {
                    return Ok(Some(Socks5ProxyRuntimePolicy {
                        policy_id: p.id,
                        username: p.username,
                        password_hash: snapshot.password_hash.ok_or_else(|| {
                            Socks5PolicyError::Storage(anyhow::anyhow!("missing proxy credential"))
                        })?,
                        max_connections: usize::from(p.max_connections),
                        bandwidth_limit_bps: p.bandwidth_limit_bps,
                        allow_private_networks: p.allow_private_networks,
                    }));
                }
            }
        }
        Ok(None)
    }
    pub(crate) async fn http_proxy_runtime_policy(
        &self,
        client_id: Uuid,
        name: &str,
        public_port: u16,
    ) -> Result<Option<HttpProxyRuntimePolicy>, HttpProxyPolicyError> {
        for snapshot in self
            .for_port("tcp", public_port)
            .await
            .map_err(HttpProxyPolicyError::from_storage)?
        {
            if let SharedTunnelPolicy::HttpProxy(p) = snapshot.policy {
                if p.enabled
                    && p.client_id == client_id
                    && p.name == name
                    && p.public_port == public_port
                {
                    return Ok(Some(HttpProxyRuntimePolicy {
                        policy_id: p.id,
                        username: p.username,
                        password_hash: snapshot.password_hash.ok_or_else(|| {
                            HttpProxyPolicyError::Storage(anyhow::anyhow!(
                                "missing proxy credential"
                            ))
                        })?,
                        max_connections: usize::from(p.max_connections),
                        bandwidth_limit_bps: p.bandwidth_limit_bps,
                        allow_private_networks: p.allow_private_networks,
                    }));
                }
            }
        }
        Ok(None)
    }
}

fn mappings(p: &PortGroupPolicy) -> anyhow::Result<Vec<PortGroupMapping>> {
    Ok(parse_port_mappings(
        &p.public_ports,
        &p.target_ports,
        1,
        u16::MAX,
        MAX_PORT_MAPPINGS,
    )?
    .pairs
    .into_iter()
    .map(|pair| PortGroupMapping {
        public_port: pair.public_port,
        target_port: pair.target_port,
        target_addr: target_addr(&p.target_host, pair.target_port),
    })
    .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn socks5() -> Socks5ProxyPolicy {
        requested_socks5(
            &PublicPortPolicy::development_default(),
            Uuid::new_v4(),
            true,
            &CreateSocks5ProxyPolicy {
                client_id: Uuid::new_v4(),
                name: "proxy".into(),
                public_port: 32001,
                username: "lake".into(),
                max_connections: Some(32),
                bandwidth_limit_bps: Some(4096),
                allow_private_networks: false,
            },
        )
        .unwrap()
    }

    #[test]
    fn socks5_reserves_both_transports_even_when_disabled() {
        let mut policy = socks5();
        policy.enabled = false;
        assert_eq!(
            SharedTunnelPolicy::Socks5(policy)
                .port_reservations()
                .unwrap(),
            vec![("tcp", 32001), ("udp", 32001)]
        );
    }

    #[test]
    fn socks5_cannot_reserve_a_blocked_udp_port() {
        let policy = socks5();
        let request: CreateSocks5ProxyPolicy =
            serde_json::from_str(&serde_json::to_string(&policy).unwrap()).unwrap();
        assert!(matches!(
            requested_socks5(
                &PublicPortPolicy::for_test("32000-32999", "32000-32999", "", "32001"),
                policy.id,
                true,
                &request
            ),
            Err(Socks5PolicyError::InvalidPublicPort)
        ));
    }

    #[test]
    fn proxy_hash_is_required_and_never_serialized_with_public_policy() {
        let policy = SharedTunnelPolicy::Socks5(socks5());
        let mut snapshot = TunnelSnapshot {
            policy,
            password_hash: None,
        };
        assert!(snapshot
            .validate(&PublicPortPolicy::development_default())
            .is_err());
        snapshot.password_hash = Some("a".repeat(64));
        assert!(snapshot
            .validate(&PublicPortPolicy::development_default())
            .is_ok());
        let public = snapshot.policy.json().unwrap();
        assert!(!public.contains("password"));
        assert!(!public.contains(&"a".repeat(64)));
        snapshot.password_hash = Some("A".repeat(64));
        assert!(snapshot
            .validate(&PublicPortPolicy::development_default())
            .is_err());
    }

    #[test]
    fn proxy_json_cannot_override_the_separate_credential_column() {
        let mut document = serde_json::to_value(socks5()).unwrap();
        document["password_hash"] = serde_json::Value::String("a".repeat(64));
        assert!(serde_json::from_value::<Socks5ProxyPolicy>(document).is_err());
    }

    #[test]
    fn corrupted_shared_limits_are_rejected_before_runtime_authorization() {
        let mut policy = socks5();
        policy.max_connections = 0;
        let snapshot = TunnelSnapshot {
            policy: SharedTunnelPolicy::Socks5(policy),
            password_hash: Some("a".repeat(64)),
        };
        assert!(snapshot
            .validate(&PublicPortPolicy::development_default())
            .is_err());
    }

    #[test]
    fn corrupt_group_count_and_target_mapping_are_not_authorized() {
        let mut policy = requested_port_group(
            &PublicPortPolicy::development_default(),
            Uuid::new_v4(),
            true,
            &CreatePortGroupPolicy {
                client_id: Uuid::new_v4(),
                name: "ports".into(),
                protocol: PortGroupProtocol::Udp,
                public_ports: "32001,32003".into(),
                target_host: "::1".into(),
                target_ports: "81,83".into(),
                max_connections: None,
                max_sessions: None,
                session_idle_timeout_seconds: None,
                bandwidth_limit_bps: None,
            },
        )
        .unwrap();
        let expected = vec![
            PortGroupMapping {
                public_port: 32001,
                target_port: 81,
                target_addr: "[::1]:81".into(),
            },
            PortGroupMapping {
                public_port: 32003,
                target_port: 83,
                target_addr: "[::1]:83".into(),
            },
        ];
        assert_eq!(mappings(&policy).unwrap(), expected);
        policy.mapping_count = 1;
        assert!(SharedTunnelPolicy::PortGroup(policy)
            .canonical(&PublicPortPolicy::development_default())
            .is_err());
    }

    #[test]
    fn fleet_conflicts_keep_the_api_code_across_protocols() {
        assert_eq!(
            Socks5PolicyError::from_storage(TunnelMutationError::FleetManaged.into()).code(),
            "fleet_managed_policy"
        );
        assert_eq!(
            HttpProxyPolicyError::from_storage(TunnelMutationError::FleetManaged.into()).code(),
            "fleet_managed_policy"
        );
        assert_eq!(
            UdpPolicyError::from_storage(TunnelMutationError::FleetManaged.into()).code(),
            "fleet_managed_policy"
        );
        assert_eq!(
            PortGroupPolicyError::from_storage(TunnelMutationError::FleetManaged.into()).code(),
            "fleet_managed_policy"
        );
    }

    #[test]
    fn egress_policy_change_invalidates_proxy_runtime_snapshot() {
        let policy = Socks5ProxyRuntimePolicy {
            policy_id: Uuid::new_v4(),
            username: "lake".into(),
            password_hash: "a".repeat(64),
            max_connections: 32,
            bandwidth_limit_bps: Some(4096),
            allow_private_networks: true,
        };
        let mut current = policy.clone();
        current.allow_private_networks = false;
        assert_ne!(policy, current);
        current = policy.clone();
        current.password_hash = "b".repeat(64);
        assert_ne!(policy, current);
    }
}
