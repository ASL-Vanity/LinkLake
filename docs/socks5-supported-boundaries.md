# SOCKS5 支持边界

LinkLake 正式支持 SOCKS5 `CONNECT` 与 `BIND`；服务端启用 UDP relay 时，同时支持 `UDP ASSOCIATE` 和有界 UDP `FRAG` 重组。

`GET /api/v1/socks5-proxies` 会为每条策略返回只读 `capabilities`。启用 UDP relay 时：

```json
{
  "connect": true,
  "udp_associate": true,
  "bind": true,
  "udp_fragmentation": true
}
```

未启用 UDP relay 时，`connect` 与 `bind` 仍为 `true`，`udp_associate` 与 `udp_fragmentation` 为 `false`。聚合 `/api/v1/metrics` 响应通过 `socks5_capabilities` 返回同一契约。

## BIND

- BIND 只在完成 RFC 1929 认证后接受，并在服务端创建临时 TCP 监听器；它不会让远端请求任意命令或脚本。
- 临时端口只从 `LINKLAKE_TCP_PUBLIC_PORTS`（或公共端口范围）允许且未保留的 TCP 端口中租用，并必须通过真实操作系统 bind。管理、控制、HTTP/HTTPS、TLS-SNI 等现有监听端口不会被租用。
- 请求地址与端口不是新的转发目标，而是入站对端约束。IP 必须精确匹配；域名在服务端以 5 秒超时解析，最多保留 16 个地址；非零端口必须匹配入站连接的源端口。
- 服务端先返回临时监听地址；只有匹配对端到达后才发送第二个成功响应并开始双向传输。等待上限为 120 秒，最多容忍 32 个不匹配或不获准的对端。
- 动态租约每 30 秒续租，并在控制连接关闭、策略停止、等待超时、租约失败、传输结束或其他错误路径释放。单次传输仍受策略流量控制、全局连接预算、带宽限制和两小时最长生命周期约束。
- 当前默认动态端口租约由单个服务端进程持有；这不等同于多个服务端共享同一端口所有权，也不构成完整 HA 端口协调承诺。

## UDP FRAG

- UDP FRAG 只在已认证、已绑定来源的 `UDP ASSOCIATE` 内重组。分片必须来自该关联认可的 UDP endpoint，完成后的目标响应仍受“只接受已访问目标”约束。
- 默认严格按 RFC 1928 序号连续接收：新数据报必须从序号 1 开始，低 7 位是序号，高位标记最后一片。默认不接受乱序间隙。
- 单数据报最多 64 片且编码后不超过 `65507` 字节；5 秒没有完成即清理。
- 每个关联最多同时重组 8 个数据报、缓冲 128 片和 256 KiB；整个服务端进程最多同时重组 1024 个数据报、缓冲 8192 片和 16 MiB。达到任一预算都会丢弃并计数。
- 相同内容的非终止重复片只计数且不重复占用预算；冲突重复、重复终止片、多个终止序号、终止片后的额外分片、缺失首片或超出预算会丢弃对应重组状态。
- SOCKS5 层完成重组后才发送到目标。LinkLake 内部 QUIC DATAGRAM 可能独立分片/重组，但它与 SOCKS5 `FRAG` 序号不是同一协议层。UDP 仍是最佳努力传输。

## 可观测性与兼容字段

策略视图和聚合指标分别提供以下数据；聚合名称带 `socks5_` 前缀：

- BIND：`bind_requests_total`、`bind_active_leases`、`bind_first_replies_total`、`bind_second_replies_total`、`bind_accept_timeouts_total`、`bind_peer_rejections_total`、`bind_failures_total`、`bind_cancellations_total`。
- FRAG：`udp_fragments_from_public_total`、`udp_fragmented_datagrams_completed_total`、`udp_fragment_duplicates_total`、`udp_fragment_rejections_total`、`udp_fragment_budget_rejections_total`、`udp_fragment_timeouts_total`、`udp_fragment_source_rejections_total`，以及当前重组数据报、分片和字节数。

旧字段 `bind_rejected_total` 与 `udp_fragmentation_unsupported_total` 仅为序列化兼容保留，不能再用于判断当前 capability。Web UI 与 Flutter Manager 展示 capability 和运行指标，不提供绕过上述限制的开关。
