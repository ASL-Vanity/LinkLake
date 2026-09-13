# LinkLake Helm Chart

## 默认 SQLite 部署

默认配置使用单实例 SQLite、`Deployment/Recreate` 和独立的数据、日志 PVC。Chart 强制
`replicaCount=1`，避免两个服务端同时打开同一 SQLite 数据库。认证信息和 TLS 私钥必须由部署方
预先创建，Chart 不接受也不会渲染明文凭据。

```bash
kubectl create secret generic linklake-auth \
  --from-literal=enrollment-token='replace-me' \
  --from-literal=admin-username='admin' \
  --from-literal=admin-password='replace-me'

kubectl create secret tls linklake-management-tls --cert=management.crt --key=management.key
kubectl create secret tls linklake-control-tls --cert=control.crt --key=control.key

helm upgrade --install linklake deploy/helm/linklake \
  --set auth.existingSecret=linklake-auth \
  --set tls.managementSecret=linklake-management-tls \
  --set tls.controlSecret=linklake-control-tls
```

默认创建的 PVC 带有 `helm.sh/resource-policy: keep`，卸载 Chart 时保留数据。若确实需要随
Chart 删除，可设置 `persistence.data.retainOnDelete=false` 和
`persistence.logs.retainOnDelete=false`。

## PostgreSQL 共享存储与多副本

v1.1 的 PostgreSQL 模式共享管理员、客户端、八类策略、证书及 ACME 账户、Fleet、流量账务、
审计、指标、告警与更新任务。各 Pod 的本地目录保存实例身份、未上传流量和暂存状态，
需要独立持久卷。部署方还须配置能路由到 Leader 的管理、控制及公网入口。

Chart 只有在以下条件全部满足时才允许多副本：

- `storage.backend=postgres`；
- PostgreSQL URL 来自既有 Secret；
- `ha.enabled=true` 且 `replicaCount>=2`；
- 每个 Pod 使用独立 PVC，禁止多个进程共享同一个 SQLite RWX 卷。

```bash
kubectl create secret generic linklake-postgres \
  --from-literal=postgres-url='postgresql://linklake:replace-me@postgres.example/linklake?sslmode=require'

helm upgrade --install linklake deploy/helm/linklake \
  --set auth.existingSecret=linklake-auth \
  --set tls.managementSecret=linklake-management-tls \
  --set tls.controlSecret=linklake-control-tls \
  --set storage.backend=postgres \
  --set storage.postgres.existingSecret=linklake-postgres \
  --set certificateMaterial.existingSecret=linklake-certificate-material \
  --set ha.enabled=true \
  --set replicaCount=3
```

`linklake-certificate-material` 必须预先包含下文所述的 32 字节原始材料密钥。
`storage.postgres.replicatedStateAcknowledged` 保留为兼容项，已不再要求设置；无须复制
各 Pod 的 SQLite 来同步业务。数据库备份、迁移和升级分别参见
[迁移说明](../../../docs/storage-migration.md)、[密钥维护](../../../docs/certificate-key-maintenance.md)
和 [PostgreSQL 升级](../../../docs/postgres-upgrades.md)。

HA 模式渲染为 `StatefulSet`，Pod 名通过 Downward API 写入 `LINKLAKE_HA_INSTANCE_ID`，从而
保证实例 ID 唯一。滚动策略使用 `RollingUpdate`；PVC 默认在缩容和删除 StatefulSet 时均保留，
可通过 `ha.pvcRetention.whenScaled` 与 `ha.pvcRetention.whenDeleted` 改为 `Delete`。

Follower 会拒绝客户端控制连接以及所有修改状态的管理请求。普通 Kubernetes Service 本身不会
识别 LinkLake leader，因此生产入口必须具备 leader-aware 健康检查、路由或客户端重试；不能仅
因为 StatefulSet 副本数大于一就宣称已经获得完整 HA。

## 探针、端口与网络策略

`/startupz`、`/readyz`、`/livez` 分别用于启动、就绪和存活探针。管理员调用
`POST /api/v1/lifecycle/drain` 后，Pod 会退出就绪状态；维护流程应轮询
`GET /api/v1/lifecycle`，确认 `drained=true` 后再删除 Pod。

Kubernetes Service 不支持端口范围。每个公网 TCP/UDP 端口必须分别加入
`services.data.publicTcpPorts` 或 `services.data.publicUdpPorts`，并同时在云负载均衡器、安全组
和 NetworkPolicy 中放行。

管理 Service 默认是 `ClusterIP`。启用 `networkPolicy.enabled=true` 后，只有
`networkPolicy.managementFrom` 显式允许的来源才能访问管理端口；空列表保持拒绝管理入口的
安全默认值。

---

## English

### Shared certificate material key

Set `certificateMaterial.existingSecret` to a pre-created Secret and
`certificateMaterial.key` to its data key (default `certificate-key`). The decoded
value must be exactly 32 raw bytes, not a hex or base64 text file. Use the same
key on every PostgreSQL replica and keep an encrypted backup separate from the
database backup. The chart never generates or embeds key contents.

The non-root init container uses the server image, copies the Secret into a
memory-backed volume and sets mode `0600`. The server receives that volume
read-only through `LINKLAKE_CERTIFICATE_KEY_FILE`. Keep `podSecurityContext.fsGroup`
configured (default `10001`), and keep the init and server user IDs identical.
Custom server images must provide `/bin/sh`, `cat`, `wc`, `chmod`, `mv` and `rm`.
Existing-Secret changes are not a supported key-rotation procedure: the key is
copied at Pod initialization, and existing PostgreSQL material is bound to the
original key. Do not replace the key without an explicit material re-encryption
and rollback procedure. Those operations are not provided by this chart.

### 共享证书材料密钥

设置 `certificateMaterial.existingSecret` 为预先创建的 Secret，
`certificateMaterial.key` 指定其中的数据项（默认 `certificate-key`）。
解码后必须是 32 字节原始二进制，不能使用十六进制或 base64 文本文件。
所有 PostgreSQL 副本使用同一密钥，并在数据库备份之外单独加密备份。
Chart 不生成或渲染密钥正文。

非 root init 使用服务端镜像，将 Secret 复制到内存卷并设为 `0600`；
服务进程只读挂载，通过 `LINKLAKE_CERTIFICATE_KEY_FILE` 使用该文件。
保留 `podSecurityContext.fsGroup`（默认 `10001`），并保持 init 和服务端 UID 一致。
自定义镜像需提供 `/bin/sh`、`cat`、`wc`、`chmod`、`mv` 和 `rm`。
Secret 内容变更只会在 Pod 初始化时复制，不能当作密钥轮换：PG 已有材料绑定原密钥。
使用 [v1.1 轮换命令](../../../docs/certificate-key-maintenance.md)完成整体重加密后再替换
Secret 并重建 Pod；Chart 不会代替维护命令执行重加密。

The default installation is a single SQLite writer rendered as a
`Deployment` with the `Recreate` strategy. Credentials and TLS keys must come from pre-created
Kubernetes Secrets. Generated PVCs are retained when the Helm release is removed unless
`retainOnDelete` is disabled.

In v1.1, PostgreSQL stores shared identities, all eight policy kinds, certificates and ACME accounts,
Fleet, traffic accounting, audit, metrics, alerts and update tasks. Per-Pod persistent directories hold
instance identity, pending traffic and staging data. Application-state replication between local SQLite
files is no longer required; `replicatedStateAcknowledged` is retained only for compatibility. Configure
leader-aware ingress for management, control and public traffic, and use PostgreSQL backup and recovery
tools for the cluster. A local SQLite backup is not a cluster backup.

When explicitly enabled, HA renders a StatefulSet with unique per-Pod PVCs, pod-name instance IDs,
RollingUpdate, and configurable PVC retention. Never mount one shared writable SQLite volume into
multiple LinkLake server processes.
