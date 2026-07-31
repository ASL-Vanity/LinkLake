//! 基于 Iroh QUIC 的 UDP 地址发现、打洞和直连数据通道。

use iroh::{
    endpoint::ConnectionType, Endpoint, NodeAddr, NodeId, RelayMode, RelayUrl, SecretKey, Watcher,
};
use linklake_core::p2p_protocol::{
    P2pCandidate, P2pIrohAddress, P2pMappingBehavior, P2pNetworkProfile, P2pTransport,
};
use sha2::{Digest, Sha256};
use std::{net::SocketAddr, str::FromStr, time::Duration};
use tokio::{
    io::{split, AsyncWriteExt},
    net::TcpStream,
    time::{sleep, timeout, Instant},
};

pub(crate) const ALPN: &[u8] = b"linklake/p2p/1";
const DIRECT_PATH_TIMEOUT: Duration = Duration::from_secs(8);

pub(crate) async fn build_endpoint(
    bind: SocketAddr,
    relay_url: Option<&str>,
    client_token: &str,
    accept_incoming: bool,
) -> anyhow::Result<Endpoint> {
    let relay_mode = match relay_url {
        Some(value) => RelayMode::Custom(RelayUrl::from_str(value)?.into()),
        None => RelayMode::Disabled,
    };
    let mut material = Sha256::new();
    material.update(b"LinkLake-Iroh-Endpoint-v1\0");
    material.update(client_token.as_bytes());
    let secret: [u8; 32] = material.finalize().into();
    let mut builder = Endpoint::builder()
        .relay_mode(relay_mode)
        .secret_key(SecretKey::from_bytes(&secret));
    if accept_incoming {
        builder = builder.alpns(vec![ALPN.to_vec()]);
    }
    builder = match bind {
        SocketAddr::V4(address) => builder.bind_addr_v4(address),
        SocketAddr::V6(address) => builder.bind_addr_v6(address),
    };
    let endpoint = builder.bind().await?;
    if relay_url.is_some() {
        timeout(Duration::from_secs(10), endpoint.home_relay().initialized())
            .await
            .map_err(|_| anyhow::anyhow!("Iroh rendezvous relay did not become ready"))?;
    }
    Ok(endpoint)
}

pub(crate) async fn candidate(endpoint: &Endpoint, priority: u16) -> anyhow::Result<P2pCandidate> {
    let addresses = endpoint.direct_addresses().initialized().await;
    let direct_addresses = addresses
        .iter()
        .map(|address| address.addr.to_string())
        .collect::<Vec<_>>();
    let report = endpoint.net_report().get();
    let network = report.map(|report| P2pNetworkProfile {
        udp_v4: report.udp_v4,
        udp_v6: report.udp_v6,
        mapping_behavior: if !report.has_udp() {
            P2pMappingBehavior::Blocked
        } else {
            match report.mapping_varies_by_dest() {
                Some(true) => P2pMappingBehavior::DestinationDependent,
                Some(false) => P2pMappingBehavior::EndpointIndependent,
                None => P2pMappingBehavior::Unknown,
            }
        },
        global_v4: report.global_v4.map(|address| address.to_string()),
        global_v6: report.global_v6.map(|address| address.to_string()),
        port_mapping: addresses
            .iter()
            .any(|address| address.typ.to_string() == "portmap"),
    });
    let value = P2pIrohAddress {
        endpoint_id: endpoint.node_id().to_string(),
        direct_addresses,
        relay_url: endpoint.home_relay().get().first().map(ToString::to_string),
        network,
    };
    anyhow::ensure!(
        !value.direct_addresses.is_empty(),
        "Iroh endpoint has no direct UDP addresses"
    );
    Ok(P2pCandidate {
        transport: P2pTransport::IrohQuic,
        endpoint: serde_json::to_string(&value)?,
        priority,
    })
}

pub(crate) async fn connect(
    candidate: &P2pCandidate,
    client_token: &str,
) -> anyhow::Result<(Endpoint, iroh::endpoint::Connection)> {
    anyhow::ensure!(
        candidate.transport == P2pTransport::IrohQuic,
        "not an Iroh candidate"
    );
    let address: P2pIrohAddress = serde_json::from_str(&candidate.endpoint)?;
    let endpoint_id = NodeId::from_str(&address.endpoint_id)?;
    let direct_addresses = address
        .direct_addresses
        .iter()
        .map(|value| value.parse::<SocketAddr>())
        .collect::<Result<Vec<_>, _>>()?;
    let relay = address
        .relay_url
        .as_deref()
        .map(RelayUrl::from_str)
        .transpose()?;
    let remote = NodeAddr::from_parts(endpoint_id, relay, direct_addresses);
    let bind = match address
        .direct_addresses
        .first()
        .and_then(|value| value.parse::<SocketAddr>().ok())
    {
        Some(SocketAddr::V6(_)) => "[::]:0".parse()?,
        _ => "0.0.0.0:0".parse()?,
    };
    let endpoint = build_endpoint(bind, address.relay_url.as_deref(), client_token, false).await?;
    // Iroh 0.92 在地址监测器完成初始化前立即 connect，Windows 上可能尚未开始接收 UDP。
    endpoint.direct_addresses().initialized().await;
    let connection = timeout(DIRECT_PATH_TIMEOUT, endpoint.connect(remote, ALPN))
        .await
        .map_err(|_| anyhow::anyhow!("Iroh connection timed out"))??;
    wait_for_direct(&endpoint, endpoint_id).await?;
    Ok((endpoint, connection))
}

pub(crate) async fn wait_for_direct(endpoint: &Endpoint, remote: NodeId) -> anyhow::Result<()> {
    let deadline = Instant::now() + DIRECT_PATH_TIMEOUT;
    loop {
        if endpoint.conn_type(remote).is_some_and(|mut connection| {
            matches!(
                connection.get(),
                ConnectionType::Direct(_) | ConnectionType::Mixed(_, _)
            )
        }) {
            return Ok(());
        }
        anyhow::ensure!(Instant::now() < deadline, "Iroh path remained relay-only");
        sleep(Duration::from_millis(100)).await;
    }
}

pub(crate) async fn relay_tcp_quic(
    tcp: &mut TcpStream,
    mut quic_send: iroh::endpoint::SendStream,
    mut quic_recv: iroh::endpoint::RecvStream,
) -> anyhow::Result<()> {
    let (mut tcp_read, mut tcp_write) = split(tcp);
    let upload = async {
        tokio::io::copy(&mut tcp_read, &mut quic_send).await?;
        quic_send.finish()?;
        quic_send.stopped().await?;
        Ok::<(), anyhow::Error>(())
    };
    let download = async {
        tokio::io::copy(&mut quic_recv, &mut tcp_write).await?;
        tcp_write.shutdown().await?;
        Ok::<(), anyhow::Error>(())
    };
    tokio::try_join!(upload, download)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn local_iroh_endpoints_establish_a_direct_udp_path() {
        let provider = build_endpoint("127.0.0.1:0".parse().unwrap(), None, "provider", true)
            .await
            .expect("provider should bind");
        let candidate = candidate(&provider, 0)
            .await
            .expect("candidate should serialize");
        let server = tokio::spawn({
            let provider = provider.clone();
            async move {
                let incoming = provider.accept().await.expect("incoming should exist");
                let connection = incoming
                    .accept()
                    .expect("incoming should be accepted")
                    .await
                    .expect("incoming should connect");
                wait_for_direct(
                    &provider,
                    connection
                        .remote_node_id()
                        .expect("remote node id should exist"),
                )
                .await
                .expect("provider path should become direct");
                let (mut send, mut recv) =
                    connection.accept_bi().await.expect("stream should arrive");
                let value = recv.read_to_end(32).await.expect("payload should read");
                send.write_all(&value).await.expect("payload should echo");
                send.finish().expect("stream should close");
                send.stopped().await.expect("stream should be acknowledged");
            }
        });
        let (visitor, connection) = connect(&candidate, "visitor")
            .await
            .expect("visitor should connect");
        let (mut send, mut recv) = connection.open_bi().await.expect("stream should open");
        send.write_all(b"udp-hole-punch")
            .await
            .expect("payload should write");
        send.finish().expect("stream should close");
        assert_eq!(
            recv.read_to_end(32).await.expect("echo should read"),
            b"udp-hole-punch"
        );
        server.await.expect("server task should finish");
        visitor.close().await;
        provider.close().await;
    }
}
