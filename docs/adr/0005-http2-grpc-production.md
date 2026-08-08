# ADR 0005：HTTP/2 与 gRPC 生产数据面

- 状态：接受（修订）
- 原决定日期：2026-08-03
- 修订日期：2026-08-08

## 背景

ADR 0002 已建立 HTTP 后端连接池的纯状态契约，但线上 HTTP 路由仍固定使用 HTTP/1.1，并为每个请求创建一条独立 LinkLake 数据连接。该模型不能承载原生 gRPC 的 HTTP/2、trailers、双向流或连接级 GOAWAY。

## 决定

- 公网 HTTP 使用 Hyper 自动识别 HTTP/1.1 和 HTTP/2 prior knowledge。
- 公网 HTTP 受限支持 HTTP/1.1 `Upgrade: h2c`：设置头、请求体、并发、握手与会话生命周期必须通过固定门禁。
- 原生 HTTPS 的证书配置通过 ALPN 同时公布 `h2` 与 `http/1.1`，并按协商结果选择严格的服务端协议。
- 普通 HTTP/2 请求转换为 HTTP/1.1 后端请求，保持既有本地网站兼容性。
- `application/grpc` 与 `application/grpc+...` 请求使用到客户端本地目标的持久化 HTTP/2 连接池；每条路由可选择 h2c 或经证书校验、SNI 和 ALPN `h2` 的 TLS。
- 每条策略独立维护真实 Hyper sender 与 ADR 0002 状态机；连接复用不跨策略。
- 后端流租约与公网响应体同寿命。响应完成、取消、错误、策略失效或 GOAWAY 排空时确定性释放。
- GOAWAY 连接停止分配新流，允许活动流完成，并在后续请求时创建替代连接。
- 路由 schema 增加 `grpc_backend_transport`、`grpc_backend_server_name` 与 `grpc_backend_trust_profile`；仍复用现有 `OpenTcpConnection` 数据流。

## 当前边界

- h2c gRPC 后端只支持 HTTP/2 prior knowledge，不通过 HTTP/1.1 Upgrade 建立。
- TLS gRPC 后端必须使用 DNS server name，验证系统或命名 profile 信任根，并成功协商 ALPN `h2`。
- 公网 h2c Upgrade 与 gRPC 后端传输是两个独立边界；前者只在本地目标返回有效 `101` 后进入字节流模式。
- gRPC-Web 留在普通 HTTP 转发路径。
- 重放只服从内置方法安全策略；管理端不能把任意非幂等请求标记为可重放。GOAWAY 或断线后的常规恢复适用于后续新请求。

## 验证

- 单元测试使用真实 Hyper HTTP/2 双工连接验证并发流、双向流、trailers、复用和 GOAWAY 恢复。
- `tests/http2-grpc-e2e.ps1` 启动真实 LinkLake 服务端、客户端和 h2c 目标，验证公开 h2c 入口、流取消、后端连接复用、GOAWAY、重连及管理指标。
- 既有 HTTP/1、WebSocket/WSS 与 HTTPS/ACME E2E 继续作为兼容性门禁。
