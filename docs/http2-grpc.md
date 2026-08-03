# HTTP/2 与 gRPC 支持边界

LinkLake 的 HTTP 域名路由同时接受 HTTP/1.1 与 HTTP/2。

## 公网入口

- `LINKLAKE_HTTP_BIND` 自动识别 HTTP/1.1 与 HTTP/2 prior knowledge。
- `LINKLAKE_HTTPS_BIND` 通过 TLS ALPN 优先协商 `h2`，并保留 `http/1.1` 回退。
- 当前不实现从 HTTP/1.1 `Upgrade: h2c` 升级到 HTTP/2；明文 HTTP/2 客户端应直接发送连接前言。

## 后端协议

- 普通 HTTP/2 请求转换为 HTTP/1.1 后端请求，因此现有本地网站无需改为 HTTP/2。
- 原生 gRPC 通过 `Content-Type: application/grpc` 或 `application/grpc+...` 识别，并使用持久化、多路复用的 h2c 后端连接。
- gRPC 本地目标必须直接支持明文 HTTP/2 prior knowledge。当前没有本地目标 TLS、ALPN 或 h2c Upgrade 配置项。
- gRPC-Web 不会被当作原生 gRPC；它继续按普通 HTTP 请求处理。

## 生命周期与限制

- 每条 HTTP 策略的 `max_connections` 对 HTTP/2 表示最大并发流数。
- 同一策略的 h2c 连接可以承载多个流，不会跨策略、目标安全上下文或协议共享。
- 收到 GOAWAY 或发现 sender 已关闭后，旧连接停止接收新流；活动流完成后移除，后续请求创建新连接。
- 策略停用、删除、客户端重新注册或服务端关闭会立即使该策略的后端池失效，并取消活动流。
- 建连、HTTP/2 握手和响应头均有超时；响应体不使用固定总时长限制，因此支持长流。

## gRPC 语义

- 请求和响应 DATA 帧按背压流式转发，不聚合完整消息。
- `TE: trailers`、响应 trailers、`grpc-status` 与 `grpc-message` 保持不变。
- 公网客户端取消流时，LinkLake 丢弃对应响应体并释放后端流租约，不关闭同一连接上的其他流。
- WebSocket/WSS 继续使用 HTTP/1.1 Upgrade，不会进入 gRPC 后端池。

## 可观测性

`/api/v1/metrics`、Prometheus 端点和每条 HTTP 策略视图提供：

- HTTP/2 活跃流和请求数；
- gRPC 活跃流、请求、trailers、失败与取消；
- 后端活动连接/流、累计建连、复用、恢复、GOAWAY、失败和池容量拒绝。

管理 API 的只读 `capabilities` 对象明确报告 HTTP/1.1、HTTP/2、gRPC、TLS ALPN、h2c prior knowledge 以及 `grpc_backend_transport = "h2c"`。这些字段不是策略开关。
