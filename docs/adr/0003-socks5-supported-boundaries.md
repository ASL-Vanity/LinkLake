# ADR 0003：明确 SOCKS5 的支持边界

- 状态：接受
- 日期：2026-08-03

## 背景

LinkLake 已实现 SOCKS5 `CONNECT` 与 `UDP ASSOCIATE`。RFC 1928 还定义了 `BIND`，并允许 SOCKS5 UDP 应用层使用 `FRAG` 字段。现有代码会拒绝 BIND 并丢弃非零 FRAG，但管理 API 只提供通用“命令不支持”和“UDP 丢弃”统计，容易让使用者把稳定产品边界误解为待修复故障。

## 决定

- 正式支持 `CONNECT`。
- UDP relay 启用时支持 `UDP ASSOCIATE`；未启用时明确报告不可用。
- 不实现 `BIND`，继续确定性返回 reply `0x07`（Command not supported）。
- 不实现 SOCKS5 UDP `FRAG`，继续丢弃所有非零 FRAG 数据报。
- 在策略列表和聚合指标中返回只读 capability：`connect`、`udp_associate`、`bind`、`udp_fragmentation`。
- BIND 和 FRAG 分别增加独立累计指标，同时保留原有通用计数以兼容现有监控。
- Web UI 与 Flutter Manager 只展示 capability，不提供无法生效的 BIND 或 FRAG 配置项。

## 原因

SOCKS5 BIND 需要服务端建立临时公网监听端口并发送两次响应，会扩大动态端口、防火墙和滥用控制面，主要服务于主动 FTP 等低需求旧式协议。UDP FRAG 需要在 SOCKS5 会话层增加有序重组、超时、内存预算和攻击防护；LinkLake 内部 QUIC 数据平面的分片重组不能替代这一应用层语义。

当前产品定位优先保证常用代理能力、网络可达性和行为可预测性。明确拒绝并提供可观测性，比提供不完整实现更安全。

## 兼容性

- CONNECT 与 UDP ASSOCIATE 数据路径不变。
- BIND 仍返回原有 `0x07`，非零 FRAG 仍被丢弃。
- 原有 `unsupported_commands` 与 `udp_dropped_datagrams` 继续累计。
- 新字段只读且向后兼容；旧 Web UI、Manager 和 API 客户端可以忽略。
