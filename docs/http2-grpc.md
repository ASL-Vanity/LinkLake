# HTTP/2 与 gRPC 支持边界

LinkLake 的 HTTP 域名路由接受 HTTP/1.1、HTTP/2 prior knowledge，以及受限的 HTTP/1.1 `Upgrade: h2c`。原生 gRPC 可以使用明文 h2c 或经过验证的 TLS/ALPN `h2` 本地目标。

## 公网入口

- `LINKLAKE_HTTP_BIND` 自动识别 HTTP/1.1 与 HTTP/2 prior knowledge。
- `LINKLAKE_HTTPS_BIND` 通过 TLS ALPN 优先协商 `h2`，并保留 `http/1.1` 回退。
- HTTP/1.1 `Upgrade: h2c` 必须同时且唯一地声明 `Upgrade: h2c`、`Connection: Upgrade, HTTP2-Settings` 与一个合法的 base64url `HTTP2-Settings`。重复 setting、畸形值、超过 1024 字节的解码设置或带请求体的 Upgrade 会被拒绝。
- h2c Upgrade 全局最多并发 128 条，升级握手超时 10 秒，升级后字节流最长存活 2 小时。只有本地目标返回有效 `101 Switching Protocols` 后才进入双向传输。

## 普通 HTTP 后端

- 普通 HTTP/2 请求转换为 HTTP/1.1 后端请求，因此现有本地网站无需改为 HTTP/2。
- HTTP/1.1 后端使用受限连接池；连接不会跨策略、目标或安全上下文共享。歧义逐跳头、请求走私边界和池容量继续失败关闭。
- WebSocket/WSS 使用 HTTP/1.1 Upgrade；它与 h2c Upgrade 都不会进入原生 gRPC 后端池。

## gRPC 后端传输

原生 gRPC 通过 `Content-Type: application/grpc` 或 `application/grpc+...` 识别。每条 HTTP 路由可配置：

```json
{
  "grpc_backend_transport": "tls",
  "grpc_backend_server_name": "grpc.internal.example",
  "grpc_backend_trust_profile": "private_ca"
}
```

- `grpc_backend_transport = "h2c"` 是默认值。本地目标必须直接接受 HTTP/2 prior knowledge；不能同时携带 TLS server name 或 trust profile。
- `grpc_backend_transport = "tls"` 必须提供 DNS 形式的 `grpc_backend_server_name`；IP literal、空标签和不合法 DNS 名称会被拒绝。TLS 握手使用该名称做 SNI 与证书身份校验，并强制协商 ALPN `h2`。
- TLS 模式未指定 `grpc_backend_trust_profile` 时，使用 LinkLake 服务端所在系统的本机信任根。指定 profile 时，服务端从 `LINKLAKE_GRPC_TRUST_PROFILE_DIR/<profile>.pem` 读取独立 CA 集。
- profile 名只允许 1–64 个 ASCII 字母、数字、连字符和下划线。目录与文件均需可 canonicalize，文件必须仍位于配置目录内、为普通文件且不超过 1 MiB；最多加载 64 张证书和 1 MiB DER。缺目录、越界路径、空文件、无效证书或超限都会失败关闭。
- TLS 握手超时为 10 秒。h2c 与 TLS、不同 server name、系统信任与不同 profile 的连接池永不共享。
- gRPC-Web 不会被当作原生 gRPC，继续按普通 HTTP 请求处理。

## 生命周期与限制

- 每条 HTTP 策略的 `max_connections` 对 HTTP/2 表示最大并发流数。
- 同一策略和安全上下文的 HTTP/2 后端连接可以承载多个流。
- 收到 GOAWAY 或发现 sender 已关闭后，旧连接停止接收新流；活动流完成后移除，后续请求创建新连接。
- 策略停用、删除、客户端重新注册或服务端关闭会使该策略的后端池失效，并取消活动流。
- 建连、HTTP/2 握手和响应头均有超时；响应体不使用固定总时长限制，因此支持长流。

## gRPC 语义

- 请求和响应 DATA 帧按背压流式转发，不聚合完整消息。
- `TE: trailers`、响应 trailers、`grpc-status` 与 `grpc-message` 保持不变。
- 公网客户端取消流时，LinkLake 丢弃对应响应体并释放后端流租约，不关闭同一连接上的其他流。
- 自动重试只服从内置的请求重放安全策略，不允许管理端把任意非幂等请求标记为可重放。

## 可观测性与 API

`/api/v1/metrics`、Prometheus 端点和每条 HTTP 策略视图提供：

- HTTP/2 活跃流和请求数；
- gRPC 活跃流、请求、trailers、失败与取消；
- 后端活动连接/流、累计建连、复用、恢复、GOAWAY、失败和池容量拒绝；
- h2c Upgrade 尝试、活动、完成、拒绝、超时与失败；
- gRPC TLS 握手、握手失败、ALPN 失败、系统信任连接和 profile 信任连接。

路由记录中的 `grpc_backend_transport`、`grpc_backend_server_name` 与 `grpc_backend_trust_profile` 是每条策略的权威配置。聚合只读 `capabilities.grpc_backend_transport = "h2c"` 是保留的默认传输提示，不代表 TLS 后端不可用，也不能替代路由字段。
