# ADR 0005：HTTP/2 与 gRPC 生产数据面

- 状态：接受
- 日期：2026-08-03

## 背景

ADR 0002 已建立 HTTP 后端连接池的纯状态契约，但线上 HTTP 路由仍固定使用 HTTP/1.1，并为每个请求创建一条独立 LinkLake 数据连接。该模型不能承载原生 gRPC 的 HTTP/2、trailers、双向流或连接级 GOAWAY。

## 决定

- 公网 HTTP 使用 Hyper 自动识别 HTTP/1.1 和 HTTP/2 prior knowledge。
- 原生 HTTPS 的证书配置通过 ALPN 同时公布 `h2` 与 `http/1.1`，并按协商结果选择严格的服务端协议。
- 普通 HTTP/2 请求转换为 HTTP/1.1 后端请求，保持既有本地网站兼容性。
- `application/grpc` 与 `application/grpc+...` 请求使用到客户端本地目标的持久化 h2c 连接池。
- 每条策略独立维护真实 Hyper sender 与 ADR 0002 状态机；连接复用不跨策略。
- 后端流租约与公网响应体同寿命。响应完成、取消、错误、策略失效或 GOAWAY 排空时确定性释放。
- GOAWAY 连接停止分配新流，允许活动流完成，并在后续请求时创建替代连接。
- 不修改数据库、HTTP 路由策略 schema 或 LinkLake 客户端控制协议；复用现有 `OpenTcpConnection` 数据流。

## 当前边界

- gRPC 后端只支持明文 HTTP/2 prior knowledge（h2c）。
- 不支持本地目标 TLS/ALPN 或 HTTP/1.1 h2c Upgrade。
- gRPC-Web 留在普通 HTTP 转发路径。
- 不自动重放已经开始发送的请求；GOAWAY 或断线后的恢复适用于后续新请求。

## 验证

- 单元测试使用真实 Hyper HTTP/2 双工连接验证并发流、双向流、trailers、复用和 GOAWAY 恢复。
- `tests/http2-grpc-e2e.ps1` 启动真实 LinkLake 服务端、客户端和 h2c 目标，验证公开 h2c 入口、流取消、后端连接复用、GOAWAY、重连及管理指标。
- 既有 HTTP/1、WebSocket/WSS 与 HTTPS/ACME E2E 继续作为兼容性门禁。
