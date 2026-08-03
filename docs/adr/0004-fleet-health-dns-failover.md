# ADR 0004: Fleet 健康状态与 DNS 故障切换

状态：已接受

## 决策

Fleet 节点健康不再由总览请求临时探测，而由服务端后台探测器持续写入 SQLite。每个节点使用以下状态：

- `unknown`：尚未收到足够的有效探测结果，首次成功确认期间仍保持此状态；
- `recovering`：节点曾进入 `unhealthy`，正在用连续成功重新证明健康；
- `healthy`：连续成功次数达到阈值；
- `degraded`：已经失败，但连续失败次数尚未达到故障阈值；
- `unhealthy`：连续失败次数达到阈值。

连续成功阈值、连续失败阈值和节点恢复冷却时间通过
`/api/v1/fleet/peers/:peer_id/health-config` 配置。状态、计数、最近成功/失败、错误摘要、状态变更原因、冷却截止时间和遥测均持久化，因此进程重启不会把节点重置为 `unknown` 或绕过迟滞。

DNS 故障切换配置通过 `/api/v1/fleet/dns-failovers` 管理。当前实现使用 Cloudflare 的固定 HTTPS API 地址，支持 A、AAAA 和 CNAME 记录。每项配置显式绑定节点与 DNS 目标值，只选择满足以下全部条件的节点：

1. 节点条目已启用；
2. 健康状态为 `healthy`；
3. 节点健康冷却已经结束；
4. DNS 配置自身的切换冷却已经结束；
5. 目标值符合记录类型。

已经承载 DNS 的节点处于 `degraded` 时会继续保持当前记录，直到连续失败达到 `unhealthy`，避免一次瞬时失败触发切换。节点从 `unhealthy` 恢复后必须重新达到成功阈值并等待健康冷却结束，才允许回切。其他节点的探测事件不会改变当前节点的状态、计数或 DNS 选择。

DNS 更新使用持久化操作 ID 和短租约。重复执行同一操作是幂等的；服务在供应商请求完成前退出时，租约到期后会重试相同操作。只有供应商明确成功后才推进 `current_peer_id` 和 `current_target`。失败会保留原当前节点、记录摘要并进入重试冷却。管理员可以持久化冻结或恢复单项 DNS 自动切换。

## 安全边界

- 数据库、API 响应和审计日志只保存 Token 环境变量名及 `token_configured`，不保存或回显原始 Token。
- DNS 配置 JSON 使用 `deny_unknown_fields`，携带 `token`、`api_key` 等未声明原始密钥字段的请求会被拒绝。
- Cloudflare Token 仅在执行请求时从指定环境变量读取，不进入 URL、错误摘要或审计详情。
- Zone ID 和 Record ID 必须是 32 位十六进制 Cloudflare 标识，供应商 API 主机固定，避免把配置接口变成任意 SSRF 出口。
- 外部错误摘要会去除控制字符并限制长度。

## 可观测性与验证

Fleet 总览返回每个节点的健康配置、状态、连续计数、时间戳、变更原因、冷却状态及 DNS 可用性，并返回 DNS 配置和 Fleet 汇总指标。`/api/v1/metrics` 与 Prometheus 导出包含节点状态、探测、状态迁移、DNS 切换、失败、冻结和待处理操作计数。`/api/v1/fleet/dns-failovers/:id/events` 提供最近的持久化 DNS 切换与失败账本，即使进程在供应商成功后、通用审计日志写入前退出，操作结果仍可追踪。探测与切换累计计数独立持久化；每个节点只保留最近 16384 条探测明细，避免长期运行导致数据库无限增长。所有配置、健康迁移、冻结/恢复和切换结果均进入审计日志。

单元测试覆盖抖动迟滞、恢复冷却、无关节点隔离、状态重开、重复/过期探测、并发重复事件、DNS 操作租约、重复完成、冻结/恢复和失败回滚。`tests/fleet-health-e2e.ps1` 覆盖真实管理 API、后台自探测、重启持久化、Prometheus、审计账本和原始密钥字段拒绝。

---

# ADR 0004: Fleet health and DNS failover

Status: Accepted

Fleet health is a persisted five-state machine driven by background probes, with configurable consecutive success/failure thresholds and recovery cooldowns. DNS changes are planned only from stable healthy peers and use persisted operation IDs, leases, switch cooldowns, audit records, manual freeze/resume, and commit-after-provider-success semantics. Provider credentials are environment-only; raw credential fields are rejected and never stored or returned. The API, Web UI, Manager, JSON metrics, Prometheus export, unit tests, and the Fleet health E2E expose and verify this contract.
