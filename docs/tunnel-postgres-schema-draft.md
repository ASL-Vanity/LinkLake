# Tunnel PostgreSQL 历史 schema 设计草案

本文保留 v1.1 集成期间的隧道共享存储设计，供开发参考，不是当前进度或验证结果记录。
实际使用以[使用说明](user-guide.zh-CN.md)、[存储迁移](storage-migration.md)和
[PostgreSQL 升级与恢复](postgres-upgrades.md)为准。schema、接口和迁移序号以当前代码为准，
不得将下列草案 SQL 作为独立迁移脚本执行。

## Migration SQL

```sql
CREATE TABLE linklake_tunnel_policies (
    id TEXT PRIMARY KEY CHECK(length(id)=36),
    kind TEXT NOT NULL CHECK(kind IN ('tcp','udp','socks5_proxy','http_proxy','port_group')),
    client_id TEXT NOT NULL CHECK(length(client_id)=36),
    name TEXT NOT NULL CHECK(octet_length(name) BETWEEN 1 AND 80),
    protocol TEXT NOT NULL CHECK(protocol IN ('tcp','udp','both')),
    policy JSONB NOT NULL CHECK(jsonb_typeof(policy)='object' AND octet_length(policy::text)<=16384),
    password_hash TEXT,
    CHECK(policy->>'id'=id AND policy->>'client_id'=client_id AND policy->>'name'=name),
    CHECK(policy ?& ARRAY['id','client_id','name','enabled'] AND jsonb_typeof(policy->'enabled')='boolean'),
    CHECK(NOT (policy ?| ARRAY['password','password_hash'])),
    CHECK(
        (kind IN ('tcp','http_proxy') AND protocol='tcp') OR
        (kind='udp' AND protocol='udp') OR
        (kind='socks5_proxy' AND protocol='both') OR
        (kind='port_group' AND protocol IN ('tcp','udp') AND policy->>'protocol'=protocol)
    ),
    CHECK(
        (kind IN ('socks5_proxy','http_proxy') AND password_hash IS NOT NULL AND password_hash ~ '^[0-9a-f]{64}$') OR
        (kind NOT IN ('socks5_proxy','http_proxy') AND password_hash IS NULL)
    )
);
CREATE UNIQUE INDEX linklake_tunnel_policies_unique_name
    ON linklake_tunnel_policies(kind,client_id,protocol,name)
    WHERE kind IN ('socks5_proxy','http_proxy','port_group');
CREATE TABLE linklake_tunnel_ports (
    protocol TEXT NOT NULL CHECK(protocol IN ('tcp','udp')),
    public_port INTEGER NOT NULL CHECK(public_port BETWEEN 1 AND 65535),
    policy_id TEXT NOT NULL REFERENCES linklake_tunnel_policies(id) ON DELETE CASCADE,
    PRIMARY KEY(protocol,public_port)
);
CREATE INDEX linklake_tunnel_ports_policy_id ON linklake_tunnel_ports(policy_id);
```

## 结构期望

- linklake_tunnel_policies: id text not null PK; kind/client_id/name/protocol text not null; policy jsonb not null; password_hash text nullable.
- linklake_tunnel_ports: protocol text not null + public_port integer not null composite PK; policy_id text not null; FK 删除目录时级联释放预留。
- 两个命名索引及全部 CHECK 同时纳入 schema verifier；旧迁移保持逐字不变。
- JSONB 仅存公开策略；代理摘要仅在专属 password_hash 列。端口预留在启用和禁用状态均保留。TCP/HTTP proxy 占 TCP；UDP 占 UDP；SOCKS5 同占 TCP/UDP；PortGroup 占其协议全部映射。

## 接线接口

tunnel_catalog::postgres:
- SharedTunnelPolicy::{Tcp(TcpTunnelPolicy), Udp(UdpTunnelPolicy), Socks5(Socks5ProxyPolicy), HttpProxy(HttpProxyPolicy), PortGroup(PortGroupPolicy)}
- policy.id()/client_id()/name()/kind()/protocol()/enabled()/json()/port_reservations()
- TunnelSnapshot { policy: SharedTunnelPolicy, password_hash: Option<String> };不实现 Debug 或 Serialize。
- transaction_list(&Transaction, &PublicPortPolicy) -> Result<Vec<TunnelSnapshot>>
- transaction_snapshot(&Transaction, &PublicPortPolicy, id:Uuid) -> Result<Option<TunnelSnapshot>>
- transaction_put(&FleetPolicyTransaction, &PublicPortPolicy, &TunnelSnapshot) -> Result<()>
- transaction_delete(&FleetPolicyTransaction,id:Uuid) -> Result<bool>

Fleet 必须先读取原 snapshot（保留代理摘要），计算全部最终策略，校验全部，再删除需交换的旧资源并 put 全部目标；与 ownership/流量/代际同事务。公开目录写入拒绝托管策略，Fleet 使用 guard 接口。调用方提交前再次 guard.assert_current。

接线设计：主程序增加 mod tunnel_store；AppState.tunnel_catalog 改 TunnelStore；初始化使用 TunnelStore::open(&database,storage.clone(),ha_runtime.clone(),public_port_policy.clone())，所有原锁内目录调用改为 await。Store 提供原全部公开业务方法，返回类型不变。PG 读取失败不回退本机。

新增错误分支：
- Socks5PolicyError/HttpProxyPolicyError/UdpPolicyError/PortGroupPolicyError::Storage(anyhow::Error) -> HTTP 500。
- 同四类 ::FleetManaged -> 409 fleet_managed_policy。
- TCP anyhow 可 downcast TunnelMutationError::FleetManaged -> 409；DuplicatePublicPort -> 409，其他存储错误 -> 500。

## 行为设计与验证范围

- 五类创建/更新共用 requested_* 构造和校验；所有 PG JSON 读取校验 canonical、行身份及同语句读取的全部端口预留。
- 改 SOCKS5 请求校验为同时允许 TCP/UDP，与其 UDP relay、冲突预留及旧启动检查一致。
- PG 写入同事务共享 Fleet/证书 advisory lock、精确 Leader fence；enable/update 保留凭据，create 仅返回一次明文。
- 设计列出的验证范围包括 CRUD/typed errors/唯一性、双实例旧Leader拒写、禁用保留预留、跨协议冲突和允许TCP/UDP同端口、PortGroup交换、Fleet原子reconcile、损坏行拒绝授权及代理摘要不外泄。本段不记录执行结果。
