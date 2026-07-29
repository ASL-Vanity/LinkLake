# LinkLake v2

[English](README.en.md) | 中文

LinkLake 是一个使用 Rust 从零实现的跨平台安全隧道平台，采用独立的核心、服务端、客户端和管理平面架构。

LinkLake 的代码实现、自动化测试与项目文档由 OpenAI GPT-5.6 完成；项目所有者负责需求定义、基础设施授权与最终验收。

当前版本已完成 TCP 生产化；UDP、HTTP/HTTPS 域名路由和 P2P 尚未实现。

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

## 本地启动

```powershell
$env:LINKLAKE_ENROLLMENT_TOKEN = "自行设置一个长随机令牌"
$env:LINKLAKE_ADMIN_USERNAME = "admin"
$env:LINKLAKE_ADMIN_PASSWORD = "自行设置至少12位的强密码"
$env:LINKLAKE_DATA_DIR = "C:\LinkLake\data"
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

注册结果中的客户端令牌只显示一次。先在 Web UI 创建完全匹配的 TCP 策略，再运行代理：

```powershell
cargo run -p linklake-client -- agent `
  --control 127.0.0.1:32101 `
  --client-id <client-id> `
  --token <client-token> `
  --public-port 32001 `
  --target 127.0.0.1:8080 `
  --name development-tcp
```

多隧道配置见 [examples/linklake-client.toml](examples/linklake-client.toml)：

```powershell
cargo run -p linklake-client -- run --config .\linklake-client.toml
```

远程控制连接还必须指定 `control_ca_cert` 和 `control_server_name`。当前公网 TCP 端口范围为 `32000-32999`。

## 管理与指标

- 健康检查：`GET /api/v1/health`
- 登录后指标：`GET /api/v1/metrics`
- Web UI 可配置最大连接数和聚合带宽上限
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
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\package-windows.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify-windows-package.ps1
```

Linux：

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
bash scripts/package-linux.sh
bash scripts/verify-linux-package.sh
```

端到端测试覆盖真实二进制回显、限速、连接限制、重连、策略生命周期、配对超时和指标。

打包脚本支持 `SOURCE_DATE_EPOCH`。设置相同时间戳并使用相同源码、工具链、目标平台和锁定依赖时，归档内的文件顺序、时间和发布清单保持稳定。Windows 生成 ZIP 和 SHA-256，Linux 生成 tar.gz 和 SHA-256。

`.github/workflows/ci.yml` 会在推送和拉取请求中执行格式、Clippy、单元测试、脚本语法检查和 Windows TCP E2E。`.github/workflows/release.yml` 会在手动触发时构建双平台产物；推送 `v*` 标签时还会创建或更新对应 GitHub Release。

## 后续路线

1. HTTP/HTTPS 域名路由与证书自动化
2. UDP 隧道
3. Flutter 管理客户端
4. 多节点和显式中继回退的 P2P

许可证将在全部功能开发完成后由项目所有者确定。
