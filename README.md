# LinkLake

[English](README.en.md) | 中文 | [使用说明](docs/user-guide.zh-CN.md) | [路线图](ROADMAP.md) | [发行版本](https://github.com/ASL-Vanity/LinkLake/releases)

LinkLake 是使用 Rust 实现的跨平台安全隧道与服务发布平台。把 Client 放在能访问目标服务的机器上，由 Server 提供公网入口，即可发布内网的 TCP、UDP 和 Web 服务，或通过 Secret 私密隧道访问它们。

Server 自带 Web UI；可选的 Flutter 桌面程序 LinkLake Manager 用于管理服务器与本机客户端。Server 和 Client 都可以独立运行或安装为系统服务。

**当前仓库版本为 `1.1.0`。** 本页说明当前仓库能力，可下载版本及资产以 [GitHub Releases](https://github.com/ASL-Vanity/LinkLake/releases) 为准。

## 核心能力

| 场景 | 能力 |
| --- | --- |
| 服务发布 | TCP、UDP、端口组与范围、Secret 私密隧道、TLS SNI 原样透传；加权目标池结合客户端健康探测选择新连接目标 |
| Web 与 API | HTTP/HTTPS 域名路由、WebSocket、HTTP/2、原生 gRPC；gRPC 后端支持 h2c 或校验证书的 TLS |
| 代理出口 | 需认证的 SOCKS5 CONNECT/BIND、可选 UDP ASSOCIATE 与有界 FRAG 重组；HTTP 正向代理/CONNECT，显式配置私网出口权限 |
| 证书自动化 | ACME HTTP-01、Cloudflare DNS-01、泛域名证书与续期；Web/Manager 可配置挑战方式并查看就绪状态 |
| 访问控制 | 管理员/操作员/审计员、TOTP、会话撤销与限权 API Token；CIDR、连接速率、带宽、时间窗口和 UTC 日流量配额 |
| 多入口与高可用 | 客户端连接多个独立 Server；Secret 加密 P2P 与受控中继回退；Fleet v2 代际、归属与冲突检查，健康监测和 Cloudflare DNS 故障切换 |
| 共享状态 | PostgreSQL 共享身份、策略、证书、Fleet、流量及运维状态；租约与 fencing 限制过期 Leader 的写入 |
| 管理与运维 | 中英文 Web/桌面界面与主题、审计、指标和 SLO、Prometheus/Grafana，以及服务端协调的远程客户端更新任务 |

UDP 中继需单独启用，数据报为最佳努力传输；P2P 是否直连取决于 NAT 与网络条件。节点接管或入口切换后，已有连接可能需要重建。

## 快速开始

完整的安装包使用、TLS、系统服务和集群配置见[使用说明](docs/user-guide.zh-CN.md)。以下是在 Rust 仓库根目录使用 **PowerShell 7** 的本机源码示例；工具链由 `rust-toolchain.toml` 固定为 Rust `1.91.0`。先准备一个可用的目标服务，例如 `127.0.0.1:8080`。

启动 Server：

```powershell
$env:LINKLAKE_BIND = "127.0.0.1:32100"
$env:LINKLAKE_CONTROL_BIND = "127.0.0.1:32101"
$env:LINKLAKE_DATA_DIR = Join-Path $PWD "data"
$env:LINKLAKE_ADMIN_USERNAME = "admin"
$env:LINKLAKE_ADMIN_PASSWORD = Read-Host "初始管理员密码（至少12位）" -MaskInput
$env:LINKLAKE_ENROLLMENT_TOKEN = Read-Host "设置独立的长随机注册令牌" -MaskInput
cargo run --locked -p linklake-server
```

打开 `http://127.0.0.1:32100` 并登录，按页面提示完成初始密码修改。环境变量中的管理员密码只用于首次初始化，不能重置已有账号。

另开终端，使用同一枚注册令牌注册 Client：

```powershell
$enrollmentToken = Read-Host "Server 的注册令牌" -MaskInput
cargo run --locked -p linklake-client -- enroll `
  --server http://127.0.0.1:32100 `
  --token $enrollmentToken `
  --name local-demo `
  --identity-file ./client-state/agent-identity.json
```

保存返回的 `client_id`、一次性 `client_token` 和机器身份文件。创建 `linklake-client.toml`：

```toml
config_version = 2

[client]
control = "127.0.0.1:32101"
client_id = "替换为注册返回的UUID"
client_token = "替换为注册返回的客户端令牌"
config_mode = "server_managed"
managed_config_path = "managed.toml"
```

```powershell
cargo run --locked -p linklake-client -- run --config ./linklake-client.toml
```

在 Web UI 确认 `local-demo` 在线，然后创建并启用 TCP 策略：选择该客户端，公网端口 `32080`，目标 `127.0.0.1:8080`。客户端会接收托管配置；访问 Server 的 `32080` 端口即可连接目标服务。目标地址由 Client 访问，因此这里的 `127.0.0.1` 指 Client 所在机器。

示例仅将管理和控制监听限制在本机，业务端口由策略另行创建。跨机器部署前，按[部署指南](docs/deployment.md)配置可信的管理/控制 TLS、监听地址和防火墙。默认可分配业务端口范围为 `32000–32999`。更多配置见[单服务端示例](examples/linklake-client.toml)和[多服务端示例](examples/linklake-client-multi-server.toml)。

## 平台与安装

发布工作流覆盖以下目标；具体版本的包名、校验文件与签名以对应 Release 为准。

| 平台 | 发布资产与运行方式 |
| --- | --- |
| Windows x86_64 | Server/Client ZIP、Windows 服务脚本；独立 Manager ZIP |
| Linux x86_64 | Server/Client tar.gz、DEB/RPM 与 systemd；独立 Manager tar.gz |
| 容器与 Kubernetes | Server OCI 镜像 `linux/amd64`；[Docker Compose](deploy/docker-compose.yml) 与 [Helm chart](deploy/helm/linklake) |
| macOS | 保留源码构建与 CI 兼容性；没有官方发行资产或自动更新通道 |

## SQLite 与 PostgreSQL

| 模式 | 状态与部署 | 维护方式 |
| --- | --- | --- |
| SQLite 单机 | 一个 Server 进程独占自己的数据目录，适合独立入口 | 备份完整数据目录与配置；使用 SQLite 专用检查、备份、恢复及更新流程 |
| PostgreSQL HA | 多副本共享业务数据库；每个副本仍需独立持久目录，保存实例身份、待确认流量账务和暂存状态 | PostgreSQL 备份/PITR，另备份实例状态、材料密钥及外部凭据；按集群兼容性安排升级 |

PostgreSQL 的租约与 fencing 协调 Leader 接管；数据库可用性、公网入口路由及负载均衡仍由部署方负责。共享数据库失败时不会回退本地 SQLite，也不会把现有 TCP/QUIC 会话迁移到另一副本。多个独立 Server 配合客户端 `[[servers]]`/Fleet，与多个副本共享同一 PostgreSQL 数据库，是两种不同的部署方式。

SQLite → PostgreSQL 使用[显式停机迁移](docs/storage-migration.md)，要求停止源进程和所有目标副本。目标开始产生新写入后，不能把切回旧 SQLite 视为无损回滚。PostgreSQL 升级不适用单机 SQLite 快照更新协议；回退镜像也不会回退数据库，参见[集群升级与恢复](docs/postgres-upgrades.md)。

PostgreSQL 证书材料使用所有副本一致的独立 **32 字节原始密钥文件**。这把密钥需单独备份；替换部署 Secret 不会重加密已有材料。[密钥轮换](docs/certificate-key-maintenance.md)要求停止所有副本后执行维护命令。

## 安全更新

安装前验证 SHA-256、GitHub 构建证明和生产 Ed25519 更新清单；Linux 软件包另有 OpenPGP 签名，OCI 镜像按摘要验证签名与构建来源。Windows 官方包按当前个人开源发布策略有意不使用 Authenticode 签名。

Client、单机 Server 与 Manager 提供各自的安全更新流程；Server 还可协调远程客户端更新。开发构建和开发签名不能作为生产更新信任。恢复方式取决于数据库状态及候选程序是否已经启动或接受写入，不能仅凭旧二进制可用就承诺回滚。

操作步骤与边界见[更新安全](docs/update-security.zh-CN.md)、[发布供应链](docs/release-supply-chain.zh-CN.md)及[PostgreSQL 集群升级](docs/postgres-upgrades.md)。

## 文档索引

| 主题 | 文档 |
| --- | --- |
| 从安装到日常使用 | [使用说明](docs/user-guide.zh-CN.md)、[部署指南](docs/deployment.md)、[配置示例](examples/linklake-client.toml) |
| HTTP/2 与 gRPC | [路由与后端 TLS](docs/http2-grpc.md) |
| SOCKS5 | [支持范围与安全边界](docs/socks5-supported-boundaries.md) |
| 多入口与 Fleet | [Fleet Bundle v2](docs/adr/0003-fleet-bundle-v2.md)、[健康与 DNS 切换设计](docs/adr/0004-fleet-health-dns-failover.md) |
| 可观测性 | [指标、告警与 SLO](docs/slo-observability.md) |
| 数据与密钥维护 | [存储迁移](docs/storage-migration.md)、[集群升级与恢复](docs/postgres-upgrades.md)、[证书材料密钥](docs/certificate-key-maintenance.md) |
| 更新与供应链 | [更新安全](docs/update-security.zh-CN.md)、[发布验证](docs/release-supply-chain.zh-CN.md) |
| 参与项目 | [路线图](ROADMAP.md)、[贡献指南](CONTRIBUTING.md)、[安全问题报告](SECURITY.md) |

## 许可证与品牌

Copyright 2026 ASL-Vanity and LinkLake contributors。源代码采用 [Apache License 2.0](LICENSE)；LinkLake 名称、双岸 Logo 与视觉标识遵循[品牌政策](TRADEMARKS.md)。

代码、测试、文档和发布工程在项目所有者的需求、审阅、基础设施授权及验收下，使用 OpenAI GPT-5.6 协助开发。完整署名见 [NOTICE](NOTICE)，第三方依赖见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) 与 [THIRD_PARTY_LICENSES.html](THIRD_PARTY_LICENSES.html)。
