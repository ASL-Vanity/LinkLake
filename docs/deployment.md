# LinkLake 部署指南 / Deployment Guide

本目录提供 Docker Compose、Prometheus、Grafana、systemd、launchd 和 Windows 服务模板。生产环境必须为管理端和控制端配置受信 TLS，令牌通过环境变量或容器 secret 注入，不写入仓库。

## Docker Compose

1. 复制 `deploy/linklake.env.example` 为 `deploy/linklake.env` 并替换所有令牌、密码、域名和证书。
2. 为 Prometheus 创建只读 `llapi_` Token，并以 Docker secret 挂载到 `/run/secrets/linklake_metrics_token`。
3. 在 `deploy/` 运行 `docker compose up -d --build`。

示例端口发布范围为 `32000-32999`，其中会自动避开 LinkLake 自身使用的 `32100-32105`。Docker 桥接网络不能在容器启动后动态发布范围外的新端口；如需开放其他业务端口，应按实际策略扩展 `ports`，或仅在 Linux 上经过安全评估后改用 host 网络。

Compose 健康检查通过 `linklake-client check --ca-cert` 严格校验管理证书。默认内部地址是 `https://linklake:32100`，因此容器内管理证书必须包含 `linklake` DNS SAN；若使用其他内部名称，请同步修改 `LINKLAKE_HEALTH_URL` 和证书 SAN。

## Nginx / Caddy / Cloudflare

- 管理界面可由 Nginx 或 Caddy 反向代理到管理监听端，但仍建议 LinkLake 自身启用 TLS。
- HTTP-01 的 80/tcp 必须保留原始 Host，并把 `/.well-known/acme-challenge/` 交给 LinkLake。
- 业务 HTTPS 若由 LinkLake 管理证书，443/tcp 必须四层透传到 `LINKLAKE_HTTPS_BIND`；不要在前置代理终止 TLS。
- Cloudflare 代理只适合受支持的 HTTP/HTTPS 业务。任意 TCP/UDP、游戏端口、SOCKS5、HTTP CONNECT 和 SNI 透传应使用 DNS-only 记录或 Cloudflare Spectrum 等相应产品。
- DNS 自动化建议创建最小权限 API Token，仅授予目标 Zone 的 `DNS Edit`。不要使用全账户 Global API Key。
- `scripts/cloudflare-dns-upsert.ps1` 使用 Zone ID 和最小权限 API Token 幂等创建或覆盖 A、AAAA、CNAME 记录；Token 只通过参数传入，不写入文件。

## ACME DNS-01 与 Cloudflare

HTTP-01 仍是默认挑战类型，不配置 Cloudflare 凭据时行为与旧版本一致。需要通配符证书或无法开放公网 80/tcp 时，可为服务端配置 Cloudflare DNS-01：

```bash
install -m 0600 /dev/stdin /run/secrets/linklake_cloudflare_token <<'EOF'
replace-with-a-zone-scoped-token
EOF
export LINKLAKE_CLOUDFLARE_API_TOKEN_FILE=/run/secrets/linklake_cloudflare_token
```

也可使用 `LINKLAKE_CLOUDFLARE_API_TOKEN` 环境变量，但不得同时配置两个来源。生产 Token 应限制到所需 Zone，并只授予 Zone 读取与 DNS 编辑权限；不要使用 Global API Key，也不要把 Token 放入 systemd 命令行、ACME API JSON、SQLite 或仓库。Unix secret file 必须禁止 group/other 访问，否则服务端启动失败。

管理 API 的 `PUT /api/v1/acme/config` 只接受 `challenge_type: "http-01" | "dns-01"`，只读响应最多返回 `cloudflare_token_configured`。它故意不提供 Token 写入、清除或回显字段。通配符由逐路由 TLS 策略声明，例如：

```json
{
  "mode": "acme",
  "redirect_http_to_https": true,
  "certificate_identifier": "*.example.com"
}
```

`certificate_identifier` 必须是路由域名本身，或只覆盖一层子域名的通配符；通配符只允许在 DNS-01 模式使用。省略该字段会为新路由使用路由域名，并在更新既有通配符路由时保留当前值；若要恢复精确证书，应显式传入该路由域名。

LinkLake 会查找最长匹配的 Cloudflare Zone，创建 `_acme-challenge` TXT，确认 DoH 可见后通知 ACME 服务，并在成功、失败或超时后删除记录。清理信息保存在 `LINKLAKE_DATA_DIR/acme/dns01-records`，只包含 Zone/Record ID；删除暂时失败时会在下一次 DNS-01 操作前重试。可选的超时参数为：

- `LINKLAKE_ACME_DNS_PROPAGATION_TIMEOUT_SECONDS`：默认 `60`，范围 `1-300`。
- `LINKLAKE_ACME_DNS_PROPAGATION_INTERVAL_MILLISECONDS`：默认 `1000`，范围 `50-10000`。

`LINKLAKE_CLOUDFLARE_API_BASE_URL` 与 `LINKLAKE_ACME_DNS_LOOKUP_URL` 仅用于受控测试或私有兼容端点；生产应保留 HTTPS 默认值。

## Prometheus

抓取端点为 `/api/v1/metrics/prometheus`，必须携带管理 Bearer Token。建议创建 `read` scope API Token。端点使用 Prometheus text exposition 0.0.4 格式，指标统一以 `linklake_` 开头。Compose 示例在隔离的容器网络内加密抓取，但为兼容外部域名证书暂时关闭了服务端证书校验；生产部署内部 CA 时，应把 `insecure_skip_verify` 替换为 `ca_file` 和正确的 `server_name`。

## Native packages

`scripts/package-native-linux.sh` 在 Debian/Ubuntu 生成 `.deb`，在安装 `rpmbuild` 的环境生成 `.rpm`。包内包含服务端、客户端、systemd 单元和环境变量示例。

## 安全更新与回滚

生产更新前先确认 `linklake-server --version-json` 或 `linklake-client --version-json` 中的产品、版本、目标平台和提交号。服务更新需要拥有停止/启动对应 systemd 或 Windows service 的权限。

```bash
sudo linklake-server update download
sudo linklake-server update apply --yes --data-dir /var/lib/linklake
sudo linklake-server update status
sudo linklake-server update rollback --yes --data-dir /var/lib/linklake
sudo linklake-server update recover --yes --data-dir /var/lib/linklake
```

更新器只替换 `/usr/local/bin/linklake-server` 或 `/usr/local/bin/linklake-client`（Windows 为安装目录中的对应 `.exe`），不会改动 `/etc/linklake`、`/var/lib/linklake`、ProgramData 中的数据/证书/配置或日志。服务原先运行时，替换后必须恢复并稳定运行；候选服务接管前失败时会自动恢复旧二进制。服务端替换前会在数据目录外创建经过身份绑定的 SQLite 快照，并在隔离副本中预演候选迁移；候选服务接管前失败时，先恢复数据库快照再恢复旧二进制。服务端会把 `--data-dir` 与已注册服务的 `LINKLAKE_DATA_DIR` 规范化比较，并使用仅存在实际数据目录中的认证密钥保护计划、日志和快照元数据。若断电或故障发生在候选服务可能已接收写入之后，`update recover` 会关闭失败并保留标记，要求人工决定恢复路径，避免自动恢复旧快照而丢失新写入。人工回滚使用最后一份摘要与目标路径均匹配的备份；如果回滚跨越 schema 或迁移台账边界，必须额外提供 `--restore-database-snapshot --confirm-data-loss --yes`，否则会关闭失败。

正式 Release 必须包含 Ed25519 清单和签名。没有生产 CI signing secret 时禁止发布；开发验证可以使用 RFC 测试夹具和 `--development-signature`，但不得把这种状态部署为生产更新。

## 加密托管状态备份与恢复

`backup-full` 可在服务运行时生成 SQLite 一致性快照，并把数据库、ACME 账户状态和托管证书写入分块认证加密归档；日志不会进入归档。SQLite 是单点快照，ACME 和证书随后逐项采集，因此在线备份不是三个组件完全同一时刻的全局快照；需要严格一致性时应先停止服务。存在已提交证书 generation 时只备份有效提交且证书/私钥匹配的 generation，并排除顶层兼容 PEM；旧安装没有 generation 时必须通过证书/私钥匹配。归档路径必须位于数据目录外部，密码只通过非交互标准输入或受 ACL 保护的文件提供：

```bash
sudo linklake-server backup-full \
  --data-dir /var/lib/linklake \
  --output /srv/linklake-backups/linklake-full.llb \
  --password-file /run/secrets/linklake_backup_password
```

恢复必须先停止服务。数据目录必须提前由安装器或管理员安全创建，不能是符号链接或重解析点；Linux 应归服务账户所有并设为 `0700`，Windows 仅授权 SYSTEM、Administrators、LocalService 和目录所有者。`restore-full` 不会替管理员临时创建或推断这个权限边界。Unix 恢复会在替换前分别记录原数据库文件、`acme/` 和 `certificates/` 的 uid/gid，并递归应用到对应恢复树；目标原本不存在时才回退 data-dir owner。命令会取得与服务端相同的数据库进程锁，验证加密终止记录、TAR 白名单、文件数量/大小、SHA-256 清单、SQLite 完整性、架构版本和迁移账本，并在暂存区迁移受支持的旧数据库后才替换数据；更高产品版本或数据库架构版本会失败关闭。旧状态保存在数据目录内的 `.pre-restore-*`，任一替换失败会回滚。持久 restore journal 同时覆盖进程崩溃和断电窗口：服务下次持锁启动时会根据已同步的提交标记幂等回滚旧状态或完成新状态。明文暂存只位于数据目录安全边界内，异常残留由活动锁协调后清理。

归档只覆盖 LinkLake 数据目录中的托管状态，不包含服务环境变量、Enrollment Token、数据目录外 TLS 私钥、服务定义、防火墙、反向代理、DNS、容器编排或生产签名密钥。必须为这些外部配置和 Secret 建立独立备份，不能把 `.llb` 当作整机镜像。

```bash
sudo systemctl stop linklake-server
sudo linklake-server restore-full \
  --data-dir /var/lib/linklake \
  --input /srv/linklake-backups/linklake-full.llb \
  --password-file /run/secrets/linklake_backup_password
sudo systemctl start linklake-server
```

应定期在隔离主机上演练恢复，并验证管理登录、客户端重连、ACME 续期和业务协议，而不能只检查备份命令退出码。

---

The same rules apply in English: enable trusted TLS for management and control listeners, inject secrets at runtime, preserve Host for ACME HTTP-01, use layer-4 pass-through when LinkLake terminates business TLS, and use DNS-only records for arbitrary TCP/UDP unless an appropriate Cloudflare proxy product is configured. HTTP-01 remains the default. For DNS-01, provide a zone-scoped Cloudflare token through `LINKLAKE_CLOUDFLARE_API_TOKEN_FILE` (preferred, mode `0600`) or `LINKLAKE_CLOUDFLARE_API_TOKEN`, never both. The management API accepts only the challenge selection and returns only `cloudflare_token_configured`; wildcard `certificate_identifier` values are accepted only with DNS-01.

For upgrades, verify `--version-json`, then use `update download/apply/status/rollback` with service-control privileges. The updater replaces only the selected executable and leaves `/etc/linklake`, `/var/lib/linklake`, ProgramData configuration/databases/certificates, and logs unchanged. A previously running service must become stably active or the old executable is restored automatically. Formal releases require the Ed25519 manifest and signature; the development signature path must never be treated as production.

For encrypted managed-state recovery, `backup-full` captures a point-in-time SQLite snapshot followed by atomically committed ACME and certificate state while excluding logs. A committed certificate generation supersedes top-level compatibility PEM files; legacy pairs are accepted only after certificate/private-key matching. The data directory must already be securely created, service-owned, and must not be a symlink or reparse point. It is not a globally simultaneous host snapshot. Supply a password of at least 16 bytes only with non-interactive `--password-stdin` or `--password-file`, keep the archive outside the data directory, stop the service before `restore-full`, separately protect external service/network configuration and secrets, and periodically prove restoration on an isolated host.
