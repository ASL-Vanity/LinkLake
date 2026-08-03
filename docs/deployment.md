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
sudo linklake-server update apply --yes
sudo linklake-server update status
sudo linklake-server update rollback --yes
```

更新器只替换 `/usr/local/bin/linklake-server` 或 `/usr/local/bin/linklake-client`（Windows 为安装目录中的对应 `.exe`），不会改动 `/etc/linklake`、`/var/lib/linklake`、ProgramData 中的数据/证书/配置或日志。服务原先运行时，替换后必须恢复并稳定运行；否则自动恢复旧二进制。人工回滚使用最后一份摘要与目标路径均匹配的备份。

正式 Release 必须包含 Ed25519 清单和签名。没有生产 CI signing secret 时禁止发布；开发验证可以使用 RFC 测试夹具和 `--development-signature`，但不得把这种状态部署为生产更新。

---

The same rules apply in English: enable trusted TLS for management and control listeners, inject secrets at runtime, preserve Host for ACME HTTP-01, use layer-4 pass-through when LinkLake terminates business TLS, and use DNS-only records for arbitrary TCP/UDP unless an appropriate Cloudflare proxy product is configured. HTTP-01 remains the default. For DNS-01, provide a zone-scoped Cloudflare token through `LINKLAKE_CLOUDFLARE_API_TOKEN_FILE` (preferred, mode `0600`) or `LINKLAKE_CLOUDFLARE_API_TOKEN`, never both. The management API accepts only the challenge selection and returns only `cloudflare_token_configured`; wildcard `certificate_identifier` values are accepted only with DNS-01.

For upgrades, verify `--version-json`, then use `update download/apply/status/rollback` with service-control privileges. The updater replaces only the selected executable and leaves `/etc/linklake`, `/var/lib/linklake`, ProgramData configuration/databases/certificates, and logs unchanged. A previously running service must become stably active or the old executable is restored automatically. Formal releases require the Ed25519 manifest and signature; the development signature path must never be treated as production.
