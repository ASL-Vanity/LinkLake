# LinkLake SLO 与告警可观测性

LinkLake 服务端将协议请求与错误累计计数写入 30 天指标历史，并在 `GET /api/v1/slo`、`GET /api/v1/metrics` 和 `GET /api/v1/metrics/prometheus` 暴露统一的 SLO 结果。管理 API 需要只读或更高权限的 Bearer Token。

## SLO 口径

- 默认可用性目标为 `99.9%`，可用 `LINKLAKE_SLO_AVAILABILITY_TARGET=0.999` 调整；值必须严格位于 `0` 和 `1` 之间。
- 可用性为 `1 - errors / requests`；无请求窗口按 `100%` 可用处理，不产生 burn 告警。
- 30 天错误预算总比例为 `1 - target`。API 同时返回已消耗倍数和剩余比例，剩余比例下限为 `0`。
- burn rate 为窗口错误率除以允许错误率。快速告警要求 `5m` 与 `1h` 同时至少 `14.4x`；慢速告警要求 `6h` 与 `24h` 同时至少 `6x`，避免单窗口尖峰误报。
- HTTP 延迟测量从服务端接收已准入请求到取得后端响应头；Prometheus 输出标准直方图 `linklake_http_request_duration_seconds`，并同时输出 p50/p95/p99 近似值。

## 通知可靠性与安全边界

告警通知先进入 SQLite outbox，再经租约领取、指数退避、最多十次尝试和 dead-letter 状态机投递。重启、租约超时或旧 worker 回写不会造成状态倒退；dead-letter 可从管理 API/Manager 手动重试。

- 数据库、API 与日志仅记录稳定安全码，例如 `webhook_http_status_503`、`smtp_status_auth_535`；不会记录 Webhook query/userinfo、SMTP 用户名/密码或 SMTP 原始响应。
- Webhook 生产配置只允许 HTTPS，并拒绝 URL userinfo。`LINKLAKE_ALERT_ALLOW_LOOPBACK_HTTP=true` 仅允许 `localhost` 或 loopback IP 的测试端点。
- SMTP host、from、to 拒绝控制字符、空白命令拼接和邮件头注入；Subject 被折叠为单行且最多 180 个字符。
- SMTP 默认必须使用 `implicit` 或 `starttls`。`LINKLAKE_SMTP_ALLOW_INSECURE=true` 仅供 loopback socket E2E/隔离测试使用。

## Prometheus、Alertmanager 与 Grafana

Docker Compose 会加载：

- `deploy/prometheus/linklake-recording-rules.yml`
- `deploy/prometheus/linklake-alert-rules.yml`
- `deploy/alertmanager/alertmanager.yml`
- `deploy/grafana/dashboards/linklake-overview.json`

Alertmanager 默认 receiver 不向外发送，避免把目标 URL 或凭据写入仓库。生产部署应通过 secret 管理系统注入 receiver 配置。Helm 用户可开启：

```yaml
monitoring:
  serviceMonitor:
    enabled: true
    insecureSkipVerify: false
  prometheusRule:
    enabled: true
```

`ServiceMonitor` 从现有认证 Secret 的 `auth.managementTokenKey` 读取 Bearer Token。生产 TLS 必须使用受信 CA；不要把 `insecureSkipVerify` 当作生产默认值。

## 运维检查

1. 确认 `/api/v1/slo` 的 `slo_observed_seconds` 随运行增长，30 天归档保留正常。
2. 在 Grafana 检查错误预算、四个 burn rate、HTTP p50/p95/p99 和通知 dead-letter。
3. 触发测试告警时只使用 loopback Webhook/SMTP socket；检查数据库 `last_error` 与 API 响应不包含测试字符串 `supersecret`。
4. 生产启用外部通知前，先用只读日志与 dead-letter 列表验证失败码，再通过 secret 管理系统配置目标和凭据。
