# LinkLake

[English](README.en.md) | 中文

LinkLake 是一个使用 Rust 从零实现的跨平台安全隧道平台，采用独立的核心、服务端、客户端和管理平面架构。

LinkLake 的代码实现、自动化测试与项目文档由 OpenAI GPT-5.6 完成；项目所有者负责需求定义、基础设施授权与最终验收。

当前版本已完成 TCP 与 UDP 生产化、多端口/端口范围、Secret 私密隧道、TLS SNI 原样透传、多节点 P2P 直连与显式服务端中继回退、SOCKS5 TCP/UDP 代理、HTTP 正向代理/CONNECT、HTTP 域名路由以及第一阶段原生 HTTPS 与 ACME 证书自动化。

## 高级网络与安全

- TCP、UDP、HTTP、TLS SNI 和 Secret 目标支持加权目标池，例如 `127.0.0.1:2333@2,127.0.0.1:2444@1`；权重只参与新连接或新会话的加权轮询，最多 16 个目标，不会复制展开目标列表。
- 每条策略可配置允许/拒绝 CIDR、每分钟新连接上限、UTC 星期/时间窗口和持久化 UTC 日流量配额。Web UI 与 Flutter Manager 均可编辑，TCP、UDP、端口组、HTTP、SNI、Secret 中继、SOCKS5 TCP/UDP 与 HTTP Proxy 均计入控制。
- Secret 访问端推荐使用 `path_policy = "prefer_direct"`；也可设置 `direct_only` 或 `relay_only`。旧配置 `prefer_direct = true/false` 继续兼容。
- 管理平面支持 RFC 6238 TOTP、活动会话撤销，以及只显示一次、数据库仅保存 SHA-256 摘要的 `llapi_` API Token；权限范围为 `read`、`write`、`administrator`。Fleet 写入 Token 还可绑定唯一 `fleet_source_instance_id`，接收端拒绝未绑定或来源不匹配的 reconcile。
- 多云管理可监控服务端健康、优先级、权重和故障切换顺序，并可预览或执行 TCP/UDP 策略同步。同步按启用客户端的唯一名称映射，只创建缺失策略；同名但参数不同的策略会报告冲突且不会覆盖。

## 部署与可观测性

- [Docker Compose](deploy/docker-compose.yml) 提供 LinkLake、Prometheus 和 Grafana；`/api/v1/metrics/prometheus` 使用 Bearer 鉴权并输出 `linklake_` 指标。
- [部署指南](docs/deployment.md) 包含 Nginx、Caddy、Cloudflare DNS-only/代理边界、最小权限 DNS Token、DEB/RPM 和容器证书要求。
- [SOCKS5 支持边界说明](docs/adr/0003-socks5-supported-boundaries.md) 明确记录 CONNECT、可选 UDP ASSOCIATE、BIND 拒绝和 UDP FRAG 丢弃语义。
- Linux 发布资产包含 `.deb`、`.rpm` 及 SHA-256；Cloudflare DNS 幂等更新脚本位于 `scripts/cloudflare-dns-upsert.ps1`。

## TCP 生产能力

- TLS 控制通道、Argon2 客户端令牌、精确策略授权
- 应用层心跳、半开连接检测与客户端 TLS 会话复用
- 指数退避与随机抖动重连
- 单策略和全局连接限制、全局待配对限制
- 单策略双向聚合带宽限制
- 策略停用/删除立即关闭监听和现有连接
- 流量、失败、拒绝、超时、重连和认证指标
- SQLite 持久化、审计、在线备份和完整性校验恢复
- 中英文 Web UI、账号密码登录、安全 Cookie 和 5 秒自动刷新
- Windows 原生服务与 Linux systemd
- 服务端和客户端按小时轮转日志，默认保留 168 个文件

## UDP 生产能力

当前 UDP 实现包括：

- 独立的 UDP 策略持久化、创建、启停、删除、精确客户端授权和在线状态
- 公网 UDP 端口到客户端本地 UDP 服务的会话映射，通过 QUIC 中继数据通道传送数据报
- 每策略最大会话数、会话空闲超时、全局会话限制和聚合带宽限制
- 数据报分片/重组保护，以及过大、畸形、限速和会话上限丢包统计
- QUIC Retry 地址验证、一次性短期 ticket、挂接超时，以及全局/单源待挂接和活跃连接限制
- 单源 IP 活跃会话上限，单源/单策略/全局新会话速率限制，以及客户端共享队列内存预算
- 双向数据包、流量、重组超时、会话超时和传输错误指标
- 中英文 Web UI 与 `[[udp_tunnels]]` 多策略客户端配置

TCP 与 UDP 使用独立的操作系统端口命名空间，因此可以同时创建 TCP `32001` 和 UDP `32001`；同一个 UDP 公网端口只能属于一条 UDP 策略。默认公网端口范围为 `32000-32999`，服务端可分别为 TCP、UDP 配置 `1-65535` 内的单端口或多个区间。

UDP relay 默认不启用。只有设置 `LINKLAKE_UDP_RELAY_BIND` 时才会启动，并且必须同时提供外部可达的 `LINKLAKE_UDP_RELAY_ENDPOINT` 和与控制通道证书匹配的 `LINKLAKE_UDP_RELAY_SERVER_NAME`。UDP 已完成自动化本地验收以及独立公网服务器、Linux 服务端和 Windows 客户端之间的端到端验收。

公网业务 UDP 端口默认使用 `LINKLAKE_UDP_PUBLIC_BIND_MODE=auto`：服务端为同一端口分别创建 IPv4 与 `IPV6_V6ONLY` socket；主机明确不支持或未启用 IPv6 时仅降级为 IPv4，端口冲突、权限不足等真实部署错误不会被自动忽略。设为 `ipv4_only` 可显式只监听 IPv4；设为 `dual_stack_required` 时，服务端启动阶段会探测双栈能力，且后续任一公网 UDP 监听器无法同时绑定 IPv4/IPv6 都会失败关闭。QUIC relay 的地址族仍由 `LINKLAKE_UDP_RELAY_BIND` 独立决定。客户端到本地 target 的连接按目标地址族建立，可使用 IPv4 或 IPv6。部署时只开放实际需要的 relay 和业务 UDP 端口，并保留云防火墙或上游 DDoS 防护。

UDP 和 QUIC DATAGRAM 均为最佳努力传输，LinkLake 不会把 UDP 转换为可靠字节流。自动化本地测试覆盖到 `65507` 字节的数据报，但公网中的 MTU、IP 分片、运营商网络、代理和防火墙可能丢弃较大的原始 UDP 数据报；应用可以控制包长时，建议将 `1200` 字节或更小作为保守的互联网默认值，并在业务层按需实现重试、序号或容错。

## 多端口与端口范围

- TCP、UDP 均可创建端口组，公网端口和目标端口支持单端口、逗号列表、升序闭区间及其混合形式，例如 `32001,32010-32012`
- 两侧按展开顺序一一映射，例如公网 `32001,32010-32012` 对应目标 `2333,2400-2402`；展开数量必须相同
- 表达式会在保存前规范化；拒绝降序范围、重复端口、越界端口和歧义语法，每组最多展开 256 个映射
- 公网端口必须符合服务端配置的允许范围且不能属于保留端口，目标端口允许 `1-65535`；目标主机单独填写域名、IPv4 或 IPv6，不包含端口
- TCP 端口组与普通 TCP、SOCKS5、HTTP 正向代理和其他 TCP 端口组共享端口命名空间；UDP 端口组与普通 UDP、SOCKS5 UDP 和其他 UDP 端口组共享 UDP 命名空间
- TCP 与 UDP 可使用相同数值的公网端口。创建端口组使用数据库事务，任一映射冲突时整组均不会写入
- 服务端托管模式会把端口组展开为现有 TCP/UDP 客户端任务；整组启停、删除、在线映射数量、连接/会话和流量统计均可在 Web UI 查看

本地 `local` 或 `report_only` 模式也可声明：

```toml
[[port_groups]]
name = "game-range"
protocol = "tcp"
public_ports = "32001,32010-32012"
target_host = "127.0.0.1"
target_ports = "2333,2400-2402"
```

### 公网端口策略

默认策略保持兼容，仅允许 `32000-32999`。服务端支持以下环境变量：

```text
# TCP、UDP 共用的默认允许范围；可使用单端口、逗号列表和升序区间。
LINKLAKE_PUBLIC_PORT_RANGES=80,443,10000-19999,30000-65535
# 可选：分别覆盖 TCP 或 UDP 允许范围。
LINKLAKE_TCP_PUBLIC_PORTS=80,443,10000-65535
LINKLAKE_UDP_PUBLIC_PORTS=10000-65535
# 22 默认属于 TCP 保留端口；可在此增加 SSH、数据库或其他宿主机服务端口。
LINKLAKE_RESERVED_TCP_PORTS=22,25,3306
LINKLAKE_RESERVED_UDP_PORTS=53
```

管理 API、控制通道、HTTP/HTTPS、TLS SNI 和 UDP relay 当前实际监听的端口会自动加入相应协议的保留集合。Web UI 从 `GET /api/v1/public-port-policy` 读取策略并在表单中显示。若现有数据库策略被新范围排除，服务端会拒绝启动并明确报告冲突策略，避免静默离线。Linux 监听 `1-1023` 需要 root 或 `CAP_NET_BIND_SERVICE`，官方 systemd 服务已仅授予该能力；手动运行时需要自行处理。云安全组、系统防火墙和其他进程占用仍会影响实际可达性。

## Secret 私密隧道

- 访问端只监听本机地址，通过 LinkLake TLS 控制通道连接目标客户端，不在服务端开放公网业务端口
- Web UI 指定目标客户端、本地目标地址，并可选限制唯一允许访问的客户端
- 创建策略时生成 `lls_...` 高熵访问密钥；密钥只在创建响应中显示一次，SQLite 仅保存 SHA-256 哈希
- 目标端 `[[secret_tunnels]]` 可由服务端托管配置下发；访问端 `[[secret_visitors]]` 和访问密钥始终保存在访问端本地配置中
- 支持策略启停/删除、目标端自动重连、每策略与全局连接限制、待配对限制、聚合带宽限制
- Web UI 展示在线状态、活跃/累计/拒绝连接、双向流量、配对超时、传输错误和生命周期超时

典型用途包括不直接暴露公网端口的 RDP、SSH、数据库、内部管理面板和临时 TCP 服务。远程部署必须配置控制通道 TLS；访问密钥不是客户端身份的替代品，访问端仍需使用已注册的客户端 ID 与令牌认证。

## 多节点与 P2P 直连

- 目标客户端通过 `[client]` 中的 `p2p_bind` 同时监听 TCP 与 Iroh QUIC/UDP，并用 `p2p_endpoint` 登记 TCP 可达地址；两项必须成对配置。`p2p_tcp_enabled` 与 `p2p_iroh_enabled` 可分别关闭传输，但至少保留一种
- Iroh QUIC 候选自动发布本地、STUN/QAD 公网映射和路由器端口映射地址；配置 `p2p_relay_url` 后使用自托管 Iroh 会合服务完成地址发现、NAT 映射检测和 UDP 打洞
- 服务端持久化节点目录，候选每 30 秒刷新，120 秒内视为新鲜；Web UI 和 `GET /api/v1/p2p/nodes` 同时展示候选、UDP 可用性、映射行为、端口映射、会合服务与更新时间
- 访问端 `[[secret_visitors]]` 默认使用 `path_policy = "prefer_direct"`，会先申请绑定目标端、访问端、目标地址和协议版本的 HMAC-SHA256 短期票据；也可设置 `direct_only` 或 `relay_only`
- 票据有效期 30 秒且只能消费一次；目标端通过已认证控制平面在线验证票据，拒绝过期、重放、签名错误和目标节点身份不匹配的请求
- 候选缺失、直连超时、拒绝、认证失败或协议错误都会明确记录原因，并回退到现有 Secret 服务端中继；直连成功、中继回退和会话签发均有独立指标与审计
- 访问端并发竞速所有 Iroh QUIC/UDP 与 TCP 候选，仅把单次票据交给首个成功建立传输层连接的候选；其余尝试立即取消
- Iroh 连接只在路径成为 `Direct` 或 `Mixed` 后承载业务数据；若只能使用 Iroh relay-only，连接会被关闭并回退到 LinkLake Secret 服务端中继，避免旁路中继策略、指标与限额

TCP 直连在短期票据认证之后使用 `Noise_NNpsk0_25519_ChaChaPoly_SHA256`，每个会话由服务端生成独立 32 字节 PSK，并以 ChaCha20-Poly1305 加密全部业务字节；双方每 `2^20` 条消息同步 rekey。Iroh 路径使用 QUIC/TLS 1.3 端到端加密。PSK 只通过双方已有的认证控制通道下发，不写入公开候选或直连票据。

```toml
[client]
p2p_bind = "0.0.0.0:40000"
p2p_endpoint = "203.0.113.10:40000"
p2p_relay_url = "https://relay.example.com"
p2p_tcp_enabled = true
p2p_iroh_enabled = true

[[secret_visitors]]
name = "private-rdp-access"
local_bind = "127.0.0.1:13389"
access_key = "lls_replace-with-the-one-time-access-key"
path_policy = "prefer_direct"
```

自托管会合服务使用固定的 `iroh-relay 1.0.3`。生产配置、systemd 单元、Nginx WebSocket 反向代理片段和安装脚本位于 `packaging/iroh-relay/`；需为会合域名提供受信 TLS 证书，并开放公网 `443/tcp` 与 `7842/udp`。默认配置让 Relay 监听回环高位端口，避免与 Web UI 的 Nginx 监听冲突。该服务协助发现和打洞，不替代 LinkLake 的受控业务中继。

## SOCKS5 TCP/UDP 代理

- 服务端在同一数值端口监听 SOCKS5 TCP 与 UDP，目标域名解析和出口连接由指定 LinkLake 客户端执行
- 支持 SOCKS5 `CONNECT` 和 `UDP ASSOCIATE`；`BIND` 明确返回“不支持命令”
- 强制 RFC 1929 用户名/密码认证，不允许匿名或免认证模式
- Web UI 创建策略时生成高熵 `llp_...` 密码，密码只显示一次，SQLite 仅保存 SHA-256 哈希
- 用户名限制为 1 到 64 个 ASCII 字母、数字、点、下划线或连字符
- TCP 和 UDP 均支持 IPv4、IPv6 和域名目标，域名由出口客户端解析；UDP 每个关联最多记录 256 个已访问目标，只接受这些目标的响应
- UDP 关联绑定到已认证的 TCP 控制连接、客户端源 IP 和首个 UDP endpoint；控制连接关闭时立即撤销关联
- `UDP ASSOCIATE` 的公网 UDP 监听遵循 `LINKLAKE_UDP_PUBLIC_BIND_MODE`；服务端按实际接收地址族回包，`BND.ADDR` 始终描述服务端侧地址族，不回显客户端请求地址
- SOCKS5 UDP `FRAG` 不受支持，非零 `FRAG` 数据报会被丢弃并计入指标
- TCP/UDP 共享策略聚合带宽上限，并支持策略/全局/待配对连接限制、握手和配对超时、启停/删除和客户端自动重连
- Web UI 和指标提供连接、CONNECT 请求、认证失败、握手错误、不支持命令、目标连接失败、TCP/UDP 流量、UDP 关联/数据报/限速丢包和传输错误统计

SOCKS5 TCP 与普通 TCP 隧道共享 TCP 公网端口命名空间；启用 UDP relay 后，SOCKS5 还会占用相同数值的 UDP 端口，因此也不能与普通 UDP 策略使用同一端口。若服务端未配置 UDP relay，SOCKS5 `CONNECT` 仍可用，但 `UDP ASSOCIATE` 会返回“不支持命令”。SOCKS5 UDP 复用上文的 QUIC DATAGRAM relay，属于最佳努力传输并具有相同的公网 MTU 风险。公网 SOCKS5 属于通用网络出口，必须保管好一次性密码、只开放实际需要的来源，并保留云防火墙、主机防火墙和上游滥用防护。

## HTTP 正向代理 / CONNECT

- 服务端监听独立 HTTP 代理公网端口，指定 LinkLake 客户端负责解析目标域名并建立出口 TCP 连接
- 强制 HTTP Basic `Proxy-Authorization`，不允许匿名代理；Web UI 创建策略时生成一次性高熵 `llh_...` 密码，SQLite 仅保存 SHA-256 哈希
- 普通 HTTP 请求必须使用 `http://` absolute-form；服务端校验 URI 与 `Host` 一致，改写为 origin-form，并在转发前移除代理凭据和逐跳请求头
- HTTPS、WebSocket 和任意 TCP 协议通过 `CONNECT host:port` 建立双向隧道；CONNECT 任一方向关闭时立即释放整条连接
- 拒绝重复 `Host`、重复 `Content-Length`、`Content-Length + Transfer-Encoding`、非 chunked Transfer-Encoding 和其他有请求走私歧义的报文
- 请求体支持无正文、`Content-Length` 和严格 chunked 定界；响应支持 HEAD、1xx、204/304、`Content-Length`、chunked 与 EOF 定界，不依赖连接关闭猜测消息边界
- 支持 IPv4、IPv6 和严格 ASCII 域名、策略/全局/待配对连接限制、聚合双向带宽限制、启停/删除、出口自动重连、审计与完整指标

HTTP 正向代理、SOCKS5 和普通 TCP 隧道共享 TCP 公网端口命名空间，三者不能使用相同端口。当前每个普通 HTTP 公网连接只处理一个代理请求并强制源站响应后关闭；需要长连接、协议升级或 HTTPS 时应使用 CONNECT。公网正向代理属于通用网络出口，必须保护凭据、限制来源并保留云防火墙、主机防火墙和上游滥用控制。

## HTTP/HTTPS 域名路由

- 根据 HTTP Host 和 TLS SNI 将不同域名转发到指定客户端及其本地 HTTP 服务
- HTTP/HTTPS 路由策略使用 SQLite 持久化，支持创建、启停、删除和在线状态展示
- 每条路由可配置最大并发连接数，并统计请求数、失败数、流量和配对超时
- 服务端原生终止 TLS，按精确 SNI 选择证书，并拒绝无 SNI、未知 SNI 以及 SNI 与 Host 不一致的请求
- ACME 支持 Let's Encrypt 生产环境、测试环境和自定义目录，可选择保持兼容的 HTTP-01，或使用 Cloudflare DNS-01 自动签发和续期证书
- DNS-01 支持 `certificate_identifier=*.example.com` 通配符证书；通配符必须覆盖路由域名且不会在 HTTP-01 模式下被接受
- Cloudflare Token 仅从 `LINKLAKE_CLOUDFLARE_API_TOKEN` 或 `LINKLAKE_CLOUDFLARE_API_TOKEN_FILE` 读取；管理 API、SQLite、审计事件和状态响应都不接收或回显原始 Token
- Web UI 提供中英文 ACME 设置、路由 TLS 开关、立即签发/续期、证书状态和错误展示
- 可在证书生效后使用 `308` 将 HTTP 跳转到 HTTPS；HTTP-01 挑战路径始终保持明文可达
- 公网明文入口自动识别 HTTP/1.1 和 HTTP/2 prior knowledge；原生 HTTPS 通过 ALPN 优先协商 `h2`，并保留 `http/1.1` 回退
- 普通 HTTP/2 请求会转换为 HTTP/1.1 后端请求以兼容现有网站；`Content-Type: application/grpc` 的原生 gRPC 请求使用持久化 h2c 后端连接池
- gRPC 支持长流、双向流、trailers、取消、连接复用、GOAWAY 排空与后续连接恢复；策略并发限制按 HTTP/2 流生效
- 当前 gRPC 本地目标必须提供明文 HTTP/2 prior knowledge（h2c），暂不支持 h2c Upgrade 或本地目标 TLS；详细边界见 [HTTP/2 与 gRPC 指南](docs/http2-grpc.md)
- WebSocket/WSS 继续使用 HTTP/1.1 Upgrade；Cloudflare DNS-01 与通配符证书已支持，HTTP-01 与 DNS-01 均沿用现有路由和证书生命周期

使用前需要把路由域名的 DNS 记录指向 LinkLake 服务端。HTTP-01 要求公网 80 端口能够按原始 Host 到达 `LINKLAKE_HTTP_BIND`；业务 HTTPS 的公网 443 端口必须把 TLS 原样送到 `LINKLAKE_HTTPS_BIND`，由 LinkLake 完成 SNI 选证书和 TLS 终止。

DNS-01 不要求公网 80 端口可达。Cloudflare Token 应至少限制到目标 Zone 的读取与 DNS 编辑权限，推荐通过权限为 `0600` 的 secret file 注入。服务端只读返回 `cloudflare_token_configured`；切勿把 Token 放入 ACME API 请求、命令行参数、仓库或数据库。

如果前置 Nginx 已在 443 终止业务 TLS，LinkLake 托管的证书不会被使用。应让 LinkLake 直接监听 443，或使用 Nginx `stream` 按 SNI 做 TCP 透传；管理界面可以继续使用独立的管理 TLS 入口。80 端口可以普通反向代理到 LinkLake，但不得重写 Host 或拦截 `/.well-known/acme-challenge/`。

## TLS SNI 原样透传

TLS SNI 原样透传适合由客户端本地服务持有证书并终止 TLS 的 HTTPS、SMTPS、IMAPS、POP3S 和其他 TLS 服务。服务端只在限时、限长读取 TLS ClientHello 后提取并规范化 SNI；不解密、不修改 TLS 内容、不持有业务证书，并把已经读取的原始 ClientHello 与后续字节完整转发到目标客户端。

- 服务端通过 `LINKLAKE_TLS_PASSTHROUGH_BIND` 启用独立监听，例如 `0.0.0.0:443`
- 路由按精确 SNI 匹配，缺失 SNI、未知 SNI、畸形或超时 ClientHello 会被拒绝并计入指标
- 支持服务端托管和本地 `[[tls_routes]]`、启停/删除、连接/全局/待配对限制、聚合带宽限制、最长连接寿命、审计和完整指标
- `LINKLAKE_TLS_PASSTHROUGH_BIND` 不能与原生 HTTPS 的 `LINKLAKE_HTTPS_BIND` 绑定同一个 IP:端口；同一个公网 443 必须在“LinkLake 终止 TLS”和“SNI 原样透传”之间选择，或由前置四层代理按 SNI 分流到不同后端
- 透传路由不会使用 LinkLake ACME 证书；证书、TLS 版本、ALPN 和应用协议全部由本地目标服务负责

```toml
[[tls_routes]]
name = "mail-tls"
hostname = "mail.example.com"
target = "127.0.0.1:465"
```

## 本地启动

```powershell
$env:LINKLAKE_ENROLLMENT_TOKEN = "自行设置一个长随机令牌"
$env:LINKLAKE_ADMIN_USERNAME = "admin"
$env:LINKLAKE_ADMIN_PASSWORD = "自行设置至少12位的强密码"
$env:LINKLAKE_DATA_DIR = "C:\LinkLake\data"
$env:LINKLAKE_HTTP_BIND = "127.0.0.1:32102"
$env:LINKLAKE_HTTPS_BIND = "127.0.0.1:32103"
$env:LINKLAKE_TLS_PASSTHROUGH_BIND = "127.0.0.1:32105"
cargo run -p linklake-server
```

访问 `http://127.0.0.1:32100`。管理员密码只用于首次初始化，数据库仅保存 Argon2 哈希。

仅限回环开发环境，可用以下选项创建 `admin / 123456`；首次登录必须立即改密：

```powershell
$env:LINKLAKE_ALLOW_INSECURE_DEFAULT_ADMIN = "1"
```

公网监听必须同时配置管理端和控制端 TLS 证书，服务端会拒绝明文公网绑定。

## 客户端注册与运行

```powershell
cargo run -p linklake-client -- enroll `
  --server http://127.0.0.1:32100 `
  --token $env:LINKLAKE_ENROLLMENT_TOKEN `
  --name dev-machine
```

注册结果中的客户端令牌只显示一次。TCP 隧道可以先在 Web UI 创建完全匹配的策略，再运行代理：

```powershell
cargo run -p linklake-client -- agent `
  --control 127.0.0.1:32101 `
  --client-id <client-id> `
  --token <client-token> `
  --public-port 32001 `
  --target 127.0.0.1:8080 `
  --name development-tcp
```

生产客户端推荐使用 [examples/linklake-client.toml](examples/linklake-client.toml) 中的服务端托管模式。单云使用 `[client]`；多云使用 [examples/linklake-client-multi-server.toml](examples/linklake-client-multi-server.toml) 中的多个 `[[servers]]`。每个身份独立保存控制地址、CA、客户端 ID/令牌以及可选 P2P 设置，服务端分别下发带 SHA-256 修订号的 TCP、UDP、端口组、HTTP、TLS SNI、Secret 目标端、SOCKS5 和 HTTP 正向代理配置：

```powershell
cargo run -p linklake-client -- run --config .\linklake-client.toml
```

支持三种 `config_mode`：

- `server_managed`：Web UI 是权威来源。客户端验证配置后写入 `managed.toml`，旧版本保存在 `managed.toml.backup`，并按差异动态启动、停止或重建隧道。
- `report_only`：继续运行本地 `[[tcp_tunnels]]`、`[[udp_tunnels]]`、`[[port_groups]]`、`[[http_routes]]`、`[[tls_routes]]`、`[[secret_tunnels]]`、`[[socks5_proxies]]` 和 `[[http_proxies]]`，只向 Web UI 报告是否与服务端策略一致。
- `local`：运行本地条目，不允许服务端覆盖，但仍报告配置冲突状态。

服务端不会下发或修改客户端令牌、CA、控制地址、P2P 监听/候选地址、日志路径、服务设置或 `[[secret_visitors]]` 访问密钥。写入过程先验证临时文件，再保留最后一次有效备份；下发失败、配置损坏或服务端离线时继续运行最后一次有效配置。Web UI 的客户端选择框会显示配置模式、同步状态和应用错误。

Linux systemd 服务默认把托管配置保存到 `/var/lib/linklake-client/managed.toml`；Windows 默认保存在引导配置文件旁边。也可以通过 `managed_config_path` 或 `LINKLAKE_STATE_DIR` 指定位置。

多云模式会为未显式设置 `managed_config_path` 的入口分别使用 `managed.<server-name>.toml`。任一云入口断线只影响该入口，其他入口继续运行；同一组本地 `local/report_only` 策略会复制到全部云入口。`server_managed` 模式下，可在各服务端 Web UI 建立指向同一目标地址的策略，从而把一个本地游戏或其他服务同时发布到云 A 和云 B。多云模式的 Secret 访问端必须在 `[[secret_visitors]]` 中使用 `server = "cloud-a"` 指定所属入口。

远程控制连接还必须指定 `control_ca_cert` 和 `control_server_name`。公网端口范围由各服务端独立决定，因此云 A 与云 B 可以使用不同公网端口；TCP 与 UDP 仍可使用相同的数值端口。

客户端可以按语义版本检查 GitHub Release。候选版本默认继续跟踪候选版本，稳定版本默认只跟踪稳定版本，也可以显式选择通道：

```powershell
linklake-client check-update --channel auto
linklake-client check-update --channel stable
linklake-client check-update --channel prerelease
```

输出为 JSON，包含当前版本、所选通道、最新版本、是否存在更新和 Release 地址；网络请求最长等待 15 秒。

### 构建身份、安全自动更新与回滚

服务端和客户端使用同一套无副作用构建信息格式；`--version` 不读取配置、不初始化日志、不启动监听，也不要求管理员环境：

```powershell
linklake-server --version
linklake-client --version
linklake-server --version-json
```

输出包含产品名、语义版本、目标平台，以及发布构建通过 `LINKLAKE_GIT_COMMIT` 注入的可选提交号。

客户端可以把“检查更新”继续到可信下载、原子安装和回滚：

```powershell
linklake-client update download
linklake-client update apply --yes
linklake-client update status
linklake-client update rollback --yes
```

服务端使用相同契约：

```powershell
linklake-server check-update
linklake-server update download
linklake-server update apply --yes
linklake-server update status
linklake-server update rollback --yes
```

- `download` 仅下载和验证，不修改正在使用的程序。
- `apply` 自动下载最新兼容版本，创建备份，并启动独立帮助进程替换客户端；替换系统安装目录通常需要管理员/root 权限。
- `status` 返回最后一次操作的 `scheduled/installing/succeeded/rolled_back/failed` 状态。
- `rollback` 使用最近一份与当前安装不同且摘要有效的本地备份。生产签名策略禁止网络降级；`--allow-downgrade` 仅与显式 `--development-signature` 测试路径同时有效。
- 自动安装目标必须支持统一的 `--version`，因此不会自动安装 0.8.0-rc.1 之前不符合新契约的旧包；旧二进制仍可作为已验证本地备份恢复。
- 默认状态目录位于当前用户的本地状态目录，也可以通过 `--state-dir` 显式指定。

安全验证链包括：HTTPS 与仓库路径约束、GitHub 资产 SHA-256、独立 `.sha256`、Ed25519 签名发布清单、下载大小、ZIP/TAR 路径与条目限制、`release.json` 产品/版本/平台、暂存二进制摘要、带摘要的帮助进程计划、安装前目标摘要、安装后 `--version` 以及 systemd/Windows service/launchd 恢复。客户端或服务端更新器只替换对应可执行文件，不覆盖配置、SQLite 数据库、托管状态、证书或日志。任一安装、版本或服务恢复检查失败时会自动恢复备份。

独立信任根位于 `security/release-keys.json`。正式 Release 必须由 CI secret 提供与仓库生产公钥匹配的 Ed25519 私钥，否则流水线关闭失败；仓库只含公钥、格式和明确标记的 RFC 8032 测试夹具。开发测试必须显式使用 `--development-signature`，生产默认绝不接受测试密钥。密钥轮换通过并行登记新旧公钥及版本有效区间完成。完整威胁模型、清单格式和轮换步骤见 `docs/update-security.zh-CN.md`。

Manager UI 不直接替换自身文件。`linklake-client manager-update download/apply/status/rollback` 提供稳定 JSON 契约，`apply`/`rollback` 必须传入 `--manager-pid <pid>`。命令返回 schema v2 且 `requires_manager_exit=true` 后 Manager 才退出；独立帮助进程等待该 PID，复核完整暂存/安装目录树摘要，在同卷切换目录并自动回滚失败。机器可读契约位于 `docs/manager-update-json-schema.json`，Flutter 封装位于 `apps/linklake_manager/lib/update_protocol.dart`。

## 管理与指标

- 兼容健康检查：`GET /api/v1/health`
- 公共探针：`GET /livez|readyz|startupz`，等价 API 路径为 `GET /api/v1/health/live|ready|startup`
- 生命周期状态：`GET /api/v1/lifecycle`；返回阶段、是否接受新工作、活跃 TCP、待配对连接、活跃 UDP、待处理 P2P 会话、排空截止时间和是否已排空
- 管理员排空与恢复：`POST /api/v1/lifecycle/drain`（可选 JSON `{"timeout_seconds":30}`）和 `POST /api/v1/lifecycle/resume`
- 登录后指标：`GET /api/v1/metrics`
- 历史指标：`GET /api/v1/metrics/history?range=1h|12h|1d|7d|30d`；12 小时内保留 5 秒样本，长期历史按分钟归档并最多保留 30 天
- 用户管理：`GET/POST /api/v1/users`、`PUT/DELETE /api/v1/users/:username`
- 密码重置与会话撤销：`POST /api/v1/users/:username/reset-password|revoke-sessions`
- 活跃会话：`GET /api/v1/sessions`、`DELETE /api/v1/sessions/:session_id`
- 公网端口策略：`GET /api/v1/public-port-policy`
- TCP 策略：`GET/POST /api/v1/tcp-tunnels`
- UDP 策略：`GET/POST /api/v1/udp-tunnels`
- UDP 策略启停：`POST /api/v1/udp-tunnels/:id/enabled`
- UDP 策略删除：`DELETE /api/v1/udp-tunnels/:id`
- 端口组：`GET/POST /api/v1/port-groups`
- 端口组启停：`POST /api/v1/port-groups/:id/enabled`
- 端口组删除：`DELETE /api/v1/port-groups/:id`
- HTTP/HTTPS 路由：`GET/POST /api/v1/http-routes`
- TLS SNI 透传路由：`GET/POST /api/v1/sni-routes`
- TLS SNI 路由启停：`POST /api/v1/sni-routes/:id/enabled`
- TLS SNI 路由删除：`DELETE /api/v1/sni-routes/:id`
- Secret 私密隧道：`GET/POST /api/v1/secret-tunnels`
- Secret 策略启停：`POST /api/v1/secret-tunnels/:id/enabled`
- Secret 策略删除：`DELETE /api/v1/secret-tunnels/:id`
- SOCKS5 代理：`GET/POST /api/v1/socks5-proxies`
- SOCKS5 策略启停：`POST /api/v1/socks5-proxies/:id/enabled`
- SOCKS5 策略删除：`DELETE /api/v1/socks5-proxies/:id`
- HTTP 正向代理：`GET/POST /api/v1/http-proxies`
- HTTP 正向代理启停：`POST /api/v1/http-proxies/:id/enabled`
- HTTP 正向代理删除：`DELETE /api/v1/http-proxies/:id`
- 路由启停：`POST /api/v1/http-routes/:id/enabled`
- 路由 TLS 设置：`PUT /api/v1/http-routes/:id/tls`
- 立即签发/续期：`POST /api/v1/http-routes/:id/certificate/issue|renew`
- ACME 设置：`GET/PUT /api/v1/acme/config`
- 路由删除：`DELETE /api/v1/http-routes/:id`
- P2P 节点目录：`GET /api/v1/p2p/nodes`
- Web UI 可配置 TCP/TLS SNI/Secret/SOCKS5/HTTP 正向代理聚合带宽、UDP 聚合带宽/最大会话数/空闲超时、TCP/HTTP/TLS SNI/Secret/SOCKS5/HTTP 正向代理最大连接数、Secret 访问客户端限制、代理用户名、ACME 环境和逐路由 HTTPS
- 指标与策略视图包括 P2P 节点新鲜度、直连与中继回退、TLS SNI ClientHello/未知域名/连接/流量、Secret 连接和流量、SOCKS5 请求/认证/连接/流量、HTTP 正向代理请求/CONNECT/认证/畸形报文/流量、UDP 会话/数据包/流量/丢包/超时、HTTP/HTTPS 路由流量和失败、TLS 握手失败、证书总数、30 天内到期、已过期、ACME 订单、续期和 HTTP-01 挑战
- `LINKLAKE_MANAGEMENT_TOKEN` 可作为自动化 API Bearer Token，不用于 Web 登录
- Web UI 支持管理员、运维人员和审计人员三种用户组：管理员拥有全部权限，运维人员可管理客户端与转发策略，审计人员只读；当前用户和最后一个启用的管理员受到保护
- Web UI 提供极光湖面、极简海洋、翡翠纸面、霓虹深空和高对比度五套完整视觉风格；每套风格独立定义背景、材质、圆角、边框、阴影和图表表现，并支持跟随系统切换明暗模式

日志目录通过 `LINKLAKE_LOG_DIR` 设置。服务端未设置时默认使用 `LINKLAKE_DATA_DIR/logs`；客户端未设置时输出到控制台，服务安装器会为其设置轮转日志目录。

## 数据库备份与恢复

备份可以在服务运行时执行：

```powershell
linklake-server backup --data-dir C:\LinkLake\data --output D:\Backups\linklake.sqlite3
```

恢复前应停止服务：

```powershell
linklake-server restore --data-dir C:\LinkLake\data --input D:\Backups\linklake.sqlite3
```

恢复会先取得 `linklake.sqlite3.lock` 独占锁并执行 SQLite 完整性检查；服务仍在运行时会直接失败。原数据库保存为 `linklake.sqlite3.pre-restore-<时间戳>`。

加密托管状态备份与恢复使用 `backup-full` / `restore-full`，包含 SQLite 在线快照、`acme/` 和 `certificates/`，不包含日志：

```powershell
linklake-server backup-full --data-dir C:\LinkLake\data --output D:\Backups\linklake-full.llb --password-file D:\Secrets\linklake-backup.pass

# 恢复前停止 LinkLakeServer 服务
linklake-server restore-full --data-dir C:\LinkLake\data --input D:\Backups\linklake-full.llb --password-file D:\Secrets\linklake-backup.pass
```

密码至少 16 字节，只能通过 `--password-stdin` 或 `--password-file` 输入，不能出现在命令行参数、日志或错误信息中；`--password-stdin` 会拒绝可交互终端，必须使用管道或重定向。备份使用固定受限的 Argon2id 和 64 KiB 分块 XChaCha20-Poly1305，认证格式头、分块序号、长度和显式终止记录；错误密码、篡改、截断、未知版本及尾随数据都会失败关闭。恢复会在完整解密、TAR 路径/链接/数量/大小校验、SHA-256 清单、SQLite `integrity_check`、架构版本和迁移账本全部通过后，在暂存区迁移受支持的旧数据库，随后才替换当前状态。来自更高 LinkLake 版本或更高数据库架构版本的备份会失败关闭。原数据库、ACME 状态和证书会保存到同一 `.pre-restore-<时间戳>-<随机值>` 目录，替换失败自动回滚。

`--data-dir` 必须由安装器或管理员提前安全创建，不能是符号链接、重解析点或由备份命令临时创建的任意目录。Linux 建议归服务账户所有并设为 `0700`；Windows 应只授权 SYSTEM、Administrators、LocalService 和该目录所有者。Unix 恢复会分别保留原数据库文件、`acme/` 和 `certificates/` 的 uid/gid，并把对应 owner 递归应用到恢复树；仅当某个目标原本不存在时才回退到 data-dir owner。备份与恢复会拒绝不存在或不安全的数据目录，而不会替管理员猜测权限边界。

所有可能包含明文的暂存文件只创建在数据目录安全边界内，并通过活动文件锁避免清理仍在运行的备份；异常退出留下的暂存目录会在下次服务启动或备份前清理。恢复替换由持久 journal 保护：提交标记落盘前发生进程崩溃或断电，下一次服务启动会幂等恢复旧状态；提交标记已落盘则验证并保留新状态，避免数据库、ACME 和证书处于混合版本。

在线备份的 SQLite 是单点一致快照；ACME 文件和证书在其后逐项采集。ACME 凭据使用原子文件提交；存在已提交 generation 时，备份只保留带有效提交标记且证书/私钥匹配的 generation，并排除可能处于半更新状态的顶层兼容 PEM。没有 generation 的旧安装必须先通过证书/私钥匹配验证。这仍不代表数据库、ACME 和证书处于同一时刻的全局快照；需要严格跨组件一致性时，应先停止服务再执行备份。

归档不包含日志、服务环境变量与 Enrollment Token、数据目录外的管理/控制 TLS 私钥、systemd/Windows service/launchd 定义、防火墙、反向代理、DNS、容器编排配置或生产签名密钥。因此它不能单独重建整台主机；这些外部配置和 Secret 必须通过独立的基础设施备份恢复流程保护。

备份输入和输出必须位于 `LINKLAKE_DATA_DIR` 外部。密码文件和 `.llb` 归档都应使用仅备份管理员可读的 ACL，并与恢复密钥分开保存。

## 生产安装

Windows 发布包：

- `windows/install-server.ps1`：以 `LocalService` 安装或事务升级 `LinkLakeServer`；TLS 证书和私钥会复制到只读托管目录，启动或验证失败会恢复旧二进制、服务配置和运行状态
- `windows/install-client.ps1`：以 `LocalService` 安装或事务升级 `LinkLakeClient`；默认保留现有配置，只有显式使用 `-ReplaceConfig` 才会替换
- `windows/uninstall.ps1`：事务移除所选服务和程序二进制，默认保留配置、状态、日志和服务端数据；永久清理还必须同时使用 `-PurgeData -ConfirmPurge LINKLAKE-PURGE`

Windows 安装器只接受本地绝对目标路径，拒绝重解析点、目录权限重叠、畸形服务环境和不匹配的包内 SHA-256 清单。同一时间只允许一个安装、升级或卸载事务。通过网络取得发布包时，应先按签名发布清单获得可信 SHA-256，再运行：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify-windows-package.ps1 -ExpectedSha256 <签名清单中的64位SHA-256>
```

Linux 发布包：

```sh
sudo ./systemd/install-linux.sh server
sudo ./systemd/install-linux.sh client
```

安装器只启用服务，不会在占位凭据未修改时主动启动。编辑 `/etc/linklake/server.env` 或 `/etc/linklake/client.toml` 后再执行 `systemctl start`。

启用 UDP relay 的服务端配置示例：

```text
LINKLAKE_UDP_RELAY_BIND=0.0.0.0:32104
LINKLAKE_UDP_RELAY_ENDPOINT=udp.example.com:32104
LINKLAKE_UDP_RELAY_SERVER_NAME=udp.example.com
LINKLAKE_UDP_PUBLIC_BIND_MODE=auto
```

relay QUIC TLS 复用 `LINKLAKE_CONTROL_CERT_PATH` 和 `LINKLAKE_CONTROL_KEY_PATH`。必须在云安全组和系统防火墙中开放 relay 的 UDP 端口，以及实际创建的 UDP 公网策略端口；不要在没有需要时开放整个允许范围。

`LINKLAKE_UDP_PUBLIC_BIND_MODE` 可选 `auto`（默认）、`ipv4_only`、`dual_stack_required`。业务 UDP 与 relay 的监听地址族相互独立；仅把 relay 绑定到 IPv6 不会改变业务端口策略，反之亦然。运行指标提供 IPv4/IPv6 绑定成功、自动降级和绑定失败计数。

## 构建与验证

仓库通过 `rust-toolchain.toml` 固定 Rust `1.91.0`，并通过 `Cargo.lock` 固定依赖。建议使用 rustup 安装工具链；CI 会在 Windows、Linux 和 macOS 上使用相同版本。

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\tcp-e2e.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\udp-e2e.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\http-e2e.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\sni-e2e.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\secret-e2e.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\windows-installer-contract.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\package-windows.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify-windows-package.ps1
$env:FLUTTER_BIN = 'F:\Tools\flutter\bin\flutter.bat'
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\package-manager-windows.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify-manager-windows.ps1
```

Linux：

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
pwsh -NoProfile -File ./tests/https-e2e.ps1
bash scripts/package-linux.sh
bash scripts/verify-linux-package.sh
sh scripts/package-manager-linux.sh
sh scripts/verify-manager-linux.sh
```

TCP 端到端测试覆盖真实二进制回显、限速、连接限制、重连、策略生命周期、配对超时和指标。UDP 端到端测试覆盖同一业务端口的 IPv4/IPv6 双栈回显、`0` 到 `65507` 字节真实数据报回显、多会话、限速丢包、空闲回收、分片重组、策略生命周期、重连、TCP/UDP 同数值端口、TCP/UDP 连续端口组的全部映射及指标；生产验收还覆盖独立公网服务器、Linux 服务端和 Windows 客户端。TLS SNI E2E 使用真实自签名目标和 .NET `SslStream`，覆盖原始 ClientHello 透传、真实 TLS 握手/回显、未知 SNI 拒绝、启停恢复、删除和指标。Secret E2E 覆盖托管目标端、一次性密钥隔离、访问客户端白名单、错误密钥、连接限制、启停恢复、删除失效、统计、两个独立客户端之间的真实 P2P 直连、不可达候选下的显式中继回退，以及服务端无公网业务监听。SOCKS5 E2E 覆盖托管出口、一次性密码隔离、强制认证、错误密码、域名/IPv4 CONNECT、IPv4/IPv6 公网传输下的真实 UDP ASSOCIATE 回显、UDP 分片拒绝、TCP 控制连接生命周期、BIND 拒绝、连接限制、策略恢复和指标。HTTP E2E 同时覆盖 Host 路由以及正向代理的一次性密码、强制/错误认证、absolute-form 改写、凭据隔离、GET/POST 请求体、请求走私拒绝、真实 CONNECT 隧道、连接限制、客户端重连、策略生命周期和指标。HTTPS/ACME 测试在 Linux CI 中使用本地 Pebble 与 Cloudflare/DoH Mock，覆盖 HTTP-01、DNS-01、通配符 SNI、TXT 生命周期、证书签发与续期、HTTPS 转发、跳转、持久化、失败恢复和证书指标，不访问公网证书机构或真实 Cloudflare API。

macOS 使用 `scripts/package-macos.sh`、`scripts/verify-macos-package.sh`、`scripts/package-manager-macos.sh` 和 `scripts/verify-manager-macos.sh` 构建并校验核心服务与 Flutter 管理客户端。

打包脚本支持 `SOURCE_DATE_EPOCH`。设置相同时间戳并使用相同源码、工具链、目标平台和锁定依赖时，归档内的文件顺序、时间和发布清单保持稳定。Windows 生成 ZIP 和 SHA-256，Linux/macOS 生成 tar.gz 和 SHA-256；三个平台均同时生成 LinkLake 核心包和 LinkLake Manager 包。

`.github/workflows/ci.yml` 会在推送和拉取请求中执行格式、Clippy、单元测试、脚本语法检查、使用锁定 Playwright/Chromium 的真实 WebUI 浏览器冒烟测试、Windows TCP/UDP/HTTP/TLS SNI/Secret-P2P/SOCKS5 E2E、Linux Pebble HTTP-01/Cloudflare DNS-01 E2E，以及 Flutter Manager 的 Windows/Linux/macOS 分析、测试和 Release 构建。WebUI 测试运行时生成一次性 localhost 证书，失败时保留截图和服务日志，不依赖开发者机器上的 Node 路径、浏览器模块或固定测试私钥。`.github/workflows/soak.yml` 每周或手动运行长稳、弱网、崩溃、重启、并发与吞吐矩阵。正式标签还必须通过 Windows Authenticode、macOS Developer ID/Apple 公证、Linux OpenPGP、GHCR OCI SBOM/provenance 与 Cosign 摘要签名，再生成文件级 SPDX/GitHub 证明和 LinkLake Ed25519 更新清单。全部 GitHub Actions 都固定到完整提交 SHA，发布任务只恢复缓存且不写入缓存，checkout 不保留 Git 凭据。完整说明与必需 Secret 清单见 [`docs/release-supply-chain.zh-CN.md`](docs/release-supply-chain.zh-CN.md)。

## 后续路线

1. Secret 私密隧道：已完成
2. SOCKS5 TCP：已完成
3. SOCKS5 UDP Associate：已完成
4. HTTP Forward Proxy / CONNECT：已完成
5. 多端口与端口范围：已完成
6. TLS SNI 透传：已完成
7. 多节点和显式中继回退的 P2P：已完成
8. Flutter 管理客户端：已完成首个跨平台版本

## 许可证

LinkLake 采用 Apache License 2.0。版权归 ASL-Vanity 与 LinkLake contributors 所有；完整条款与归属说明见 [`LICENSE`](LICENSE) 和 [`NOTICE`](NOTICE)。

- 第三方组件及许可证：[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) 与 [`THIRD_PARTY_LICENSES.html`](THIRD_PARTY_LICENSES.html)
- LinkLake 名称、双岸 Logo 和品牌资产：[`TRADEMARKS.md`](TRADEMARKS.md)
- 贡献、原创性与 DCO 签署要求：[`CONTRIBUTING.md`](CONTRIBUTING.md)

Apache License 2.0 不授予 LinkLake 品牌和商标使用权。修改版、分支和托管服务可以准确说明其基于 LinkLake，但不得暗示由 LinkLake 官方维护或背书。
