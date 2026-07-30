# LinkLake v2

[English](README.en.md) | 中文

LinkLake 是一个使用 Rust 从零实现的跨平台安全隧道平台，采用独立的核心、服务端、客户端和管理平面架构。

LinkLake 的代码实现、自动化测试与项目文档由 OpenAI GPT-5.6 完成；项目所有者负责需求定义、基础设施授权与最终验收。

当前版本已完成 TCP 生产化、HTTP 域名路由以及第一阶段原生 HTTPS 与 ACME 证书自动化；UDP 和 P2P 尚未实现。

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

## HTTP/HTTPS 域名路由

- 根据 HTTP Host 和 TLS SNI 将不同域名转发到指定客户端及其本地 HTTP 服务
- HTTP/HTTPS 路由策略使用 SQLite 持久化，支持创建、启停、删除和在线状态展示
- 每条路由可配置最大并发连接数，并统计请求数、失败数、流量和配对超时
- 服务端原生终止 TLS，按精确 SNI 选择证书，并拒绝无 SNI、未知 SNI 以及 SNI 与 Host 不一致的请求
- ACME 支持 Let's Encrypt 生产环境、测试环境和自定义目录，通过 HTTP-01 自动签发和续期证书
- Web UI 提供中英文 ACME 设置、路由 TLS 开关、立即签发/续期、证书状态和错误展示
- 可在证书生效后使用 `308` 将 HTTP 跳转到 HTTPS；HTTP-01 挑战路径始终保持明文可达
- 第一阶段提供 HTTP/1.1 和 WebSocket/WSS，不支持需要 DNS-01 的通配符证书

使用前需要把路由域名的 DNS 记录指向 LinkLake 服务端。HTTP-01 要求公网 80 端口能够按原始 Host 到达 `LINKLAKE_HTTP_BIND`；业务 HTTPS 的公网 443 端口必须把 TLS 原样送到 `LINKLAKE_HTTPS_BIND`，由 LinkLake 完成 SNI 选证书和 TLS 终止。

如果前置 Nginx 已在 443 终止业务 TLS，LinkLake 托管的证书不会被使用。应让 LinkLake 直接监听 443，或使用 Nginx `stream` 按 SNI 做 TCP 透传；管理界面可以继续使用独立的管理 TLS 入口。80 端口可以普通反向代理到 LinkLake，但不得重写 Host 或拦截 `/.well-known/acme-challenge/`。

## 本地启动

```powershell
$env:LINKLAKE_ENROLLMENT_TOKEN = "自行设置一个长随机令牌"
$env:LINKLAKE_ADMIN_USERNAME = "admin"
$env:LINKLAKE_ADMIN_PASSWORD = "自行设置至少12位的强密码"
$env:LINKLAKE_DATA_DIR = "C:\LinkLake\data"
$env:LINKLAKE_HTTP_BIND = "127.0.0.1:32102"
$env:LINKLAKE_HTTPS_BIND = "127.0.0.1:32103"
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

TCP 隧道和 HTTP 域名路由的多策略配置见 [examples/linklake-client.toml](examples/linklake-client.toml)。HTTP 路由使用 `[[http_routes]]`，其中 `hostname` 必须与 Web UI 中创建的域名完全匹配：

```powershell
cargo run -p linklake-client -- run --config .\linklake-client.toml
```

远程控制连接还必须指定 `control_ca_cert` 和 `control_server_name`。当前公网 TCP 端口范围为 `32000-32999`。

## 管理与指标

- 健康检查：`GET /api/v1/health`
- 登录后指标：`GET /api/v1/metrics`
- TCP 策略：`GET/POST /api/v1/tcp-tunnels`
- HTTP/HTTPS 路由：`GET/POST /api/v1/http-routes`
- 路由启停：`POST /api/v1/http-routes/:id/enabled`
- 路由 TLS 设置：`PUT /api/v1/http-routes/:id/tls`
- 立即签发/续期：`POST /api/v1/http-routes/:id/certificate/issue|renew`
- ACME 设置：`GET/PUT /api/v1/acme/config`
- 路由删除：`DELETE /api/v1/http-routes/:id`
- Web UI 可配置 TCP 聚合带宽、TCP/HTTP 最大连接数、ACME 环境和逐路由 HTTPS
- 指标包括 HTTP/HTTPS 流量和失败、TLS 握手失败、证书总数、30 天内到期、已过期、ACME 订单、续期和 HTTP-01 挑战
- `LINKLAKE_MANAGEMENT_TOKEN` 可作为自动化 API Bearer Token，不用于 Web 登录

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

恢复会先执行 SQLite 完整性检查，并将原数据库保存为 `linklake.sqlite3.pre-restore-<时间戳>`。

ACME 账户凭据和证书私钥保存在 `LINKLAKE_DATA_DIR/acme` 与 `LINKLAKE_DATA_DIR/certificates`，不包含在仅针对 SQLite 的 `backup` 输出中。需要完整灾难恢复时应单独加密备份这两个目录，并把所有数据库和证书备份视为敏感凭据。

## 生产安装

Windows 发布包：

- `windows/install-server.ps1`：安装并启动 `LinkLakeServer`
- `windows/install-client.ps1`：安装并启动 `LinkLakeClient`
- `windows/uninstall.ps1`：移除服务但保留程序和数据

Linux 发布包：

```sh
sudo ./systemd/install-linux.sh server
sudo ./systemd/install-linux.sh client
```

安装器只启用服务，不会在占位凭据未修改时主动启动。编辑 `/etc/linklake/server.env` 或 `/etc/linklake/client.toml` 后再执行 `systemctl start`。

## 构建与验证

仓库通过 `rust-toolchain.toml` 固定 Rust `1.88.0`，并通过 `Cargo.lock` 固定依赖。建议使用 rustup 安装工具链；CI 会在 Windows 和 Linux 上使用相同版本。

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\tcp-e2e.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\http-e2e.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\package-windows.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify-windows-package.ps1
```

Linux：

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
pwsh -NoProfile -File ./tests/https-e2e.ps1
bash scripts/package-linux.sh
bash scripts/verify-linux-package.sh
```

TCP 端到端测试覆盖真实二进制回显、限速、连接限制、重连、策略生命周期、配对超时和指标。HTTP 端到端测试覆盖 Host 路由、请求与响应传输、连接限制、客户端重连、策略生命周期和指标。HTTPS/ACME 测试在 Linux CI 中使用本地 Pebble 服务，覆盖 HTTP-01、SNI、证书签发与续期、HTTPS 转发、跳转、持久化、失败恢复和证书指标，不访问公网证书机构。

打包脚本支持 `SOURCE_DATE_EPOCH`。设置相同时间戳并使用相同源码、工具链、目标平台和锁定依赖时，归档内的文件顺序、时间和发布清单保持稳定。Windows 生成 ZIP 和 SHA-256，Linux 生成 tar.gz 和 SHA-256。

`.github/workflows/ci.yml` 会在推送和拉取请求中执行格式、Clippy、单元测试、脚本语法检查、Windows TCP/HTTP E2E 以及 Linux Pebble HTTPS/ACME E2E。`.github/workflows/release.yml` 会在手动触发时构建双平台产物；推送 `v*` 标签时还会创建或更新对应 GitHub Release。

## 后续路线

1. HTTP 域名路由：第一阶段已完成
2. HTTPS 终止与证书自动化：第一阶段已完成
3. UDP 隧道
4. Flutter 管理客户端
5. 多节点和显式中继回退的 P2P

许可证将在全部功能开发完成后由项目所有者确定。
