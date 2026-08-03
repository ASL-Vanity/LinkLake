# ADR 0002：建立共享 HTTP 后端传输与连接池状态契约

- 状态：接受
- 日期：2026-08-03

## 背景

当前 HTTP 域名路由为每个请求建立一条独立数据连接，并固定使用 HTTP/1.1；HTTP 正向代理也在每条公网 TCP 连接上只处理一个请求。后续 HTTP/2、gRPC 和正向代理 keep-alive 都需要复用后端连接，但三项能力不能分别维护互不兼容的连接生命周期。

## 决定

在不改变现有转发行为的前提下，先加入 `http_backend_pool` 模块，统一定义：

- `OriginKey`：使用策略、目标 authority、已协商 HTTP 协议和 TLS 身份隔离连接。
- `BackendConnector`：将后端流的建立过程与控制通道实现解耦。
- `BackendConnectionMode`：区分 HTTP/1 独占连接和 HTTP/2 多路复用连接。
- `BackendPoolState`：以纯同步元数据状态机维护容量、租用、空闲回收、策略失效、断线和 GOAWAY。

本阶段不让现有 `http_tunnel` 或 `http_proxy_tunnel` 使用连接池，不改变数据库、API、Web UI、Manager 或线上网络行为。

## 约束

- 不同策略之间永不共享连接，即使目标地址相同。
- 明文与 TLS、HTTP/1 与 HTTP/2、不同 TLS server name 之间永不共享连接。
- 容量不足时只能回收空闲连接，不能为新连接强制中断正在处理的请求或流。
- 策略停用或删除时应移除该策略的全部空闲及活动连接。
- 收到 HTTP/2 GOAWAY 后不得再分配新流；已有流完成后移除连接。
- 连接池状态机不持有套接字，使容量和生命周期测试不依赖网络、时钟睡眠或真实 Hyper 连接。

## 依赖选择

继续使用现有 Hyper 1.x 与 Hyper-util 0.1，只开启后续必需的 `http2` 和 `server-auto` feature。此变更不替换 HTTP 库，也不引入新的第三方包。

## 后续接入顺序

1. HTTP/HTTPS 路由使用自动 HTTP/1/HTTP/2 前端和共享后端池。
2. gRPC 在 HTTP/2 路径上验证 streaming、trailers、取消和 GOAWAY。
3. HTTP 正向代理接入 HTTP/1 keep-alive 与按 origin 的后端复用。
4. 完成上述行为测试后，移除旧的单请求连接生命周期代码。
