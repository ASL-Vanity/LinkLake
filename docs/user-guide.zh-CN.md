# LinkLake 使用说明

[English](user-guide.en.md)

本文对应 LinkLake `v1.1.2` 的命令与配置。安装包以 GitHub Releases 提供的完整发行资产为准，请选择与目标平台匹配的包，并核对版本、校验和与签名。涉及路径、域名、端口和凭据的示例均需替换为自己的值。

## 1. 先认识三个程序

| 程序 | 放在哪里 | 负责什么 |
| --- | --- | --- |
| Server：`linklake-server` | 提供公网入口的服务器或集群 | 管理账号、客户端与转发策略，提供 Web UI、管理 API 和转发入口 |
| Client：`linklake-client` | 能访问实际目标服务的机器 | 向 Server 注册、维持控制连接，把流量送到本机或所在网络中的目标 |
| Manager：LinkLake Manager | 管理员的桌面电脑 | 图形化管理一个或多个 Server，以及本机 Client 的配置、服务和更新 |

Web UI 随 Server 提供，无需另装前端。Manager 是可选的桌面管理程序；关闭 Manager 不应代替停止已安装为系统服务的 Client。

请区分两个地址：管理地址是 `https://管理域名:32100`，供浏览器、Manager 和注册命令使用；控制地址是 `控制域名:32101`，写入客户端 TOML，供持续转发使用。控制地址不带 `http://` 或 `https://`。

## 2. 选择部署方式

| 场景 | 建议方式 | 需要保留的状态 |
| --- | --- | --- |
| 一台 Server，先把内网服务接出来 | SQLite 单机 | 完整 Server 数据目录、部署配置和外部凭据 |
| 多个 Server 副本使用同一套账号和策略 | PostgreSQL HA | 共享 PostgreSQL、每个副本独立持久目录、共同的证书材料密钥、入口配置 |
| 同一目标同时接入多个独立云服务器 | 客户端 `[[servers]]` 配置，可配合 Fleet | 各独立 Server 的凭据、客户端稳定身份及每个入口的托管配置 |

SQLite 只允许一个 Server 进程打开同一个数据目录。不要把同一 SQLite 目录挂给多个副本。

PostgreSQL 模式共享管理员与会话、客户端、八类策略、Fleet、证书与 ACME 账户、流量控制和账务、告警、审计、指标及更新任务等业务状态。每个副本的本地目录仍保存独立实例身份、待确认流量账务和暂存状态，必须使用各自的持久卷。无需再为每个副本复制一份业务 SQLite；旧的 `LINKLAKE_HA_REPLICATED_STATE` 和 Helm `replicatedStateAcknowledged` 仅为兼容保留。

HA 的 Leader 接管不等于公网入口已经切换。负载均衡器、DNS、客户端使用的固定控制地址及业务端口，仍需由部署方配置。已有 TCP 会话在副本故障后可能断开，应用和客户端需要重新连接。

## 3. 第一次跑通：Windows 本机示例

以下使用 PowerShell 7，在解压后的 Server/Client 安装包根目录运行。先准备一个已经正常监听的目标服务，例如 `127.0.0.1:8080`。

### 3.1 启动 Server

```powershell
$env:LINKLAKE_BIND = '127.0.0.1:32100'
$env:LINKLAKE_CONTROL_BIND = '127.0.0.1:32101'
$env:LINKLAKE_DATA_DIR = 'C:\LinkLake\server-data'
$env:LINKLAKE_ADMIN_USERNAME = 'admin'
$env:LINKLAKE_ADMIN_PASSWORD = Read-Host '初始管理员密码（至少12位）' -MaskInput
$env:LINKLAKE_ENROLLMENT_TOKEN = Read-Host '设置一枚独立的长随机注册令牌' -MaskInput
.\bin\linklake-server.exe
```

打开 `http://127.0.0.1:32100`，用刚设置的账号登录，按提示修改初始密码。启动环境变量只用于首次创建管理员；修改环境变量不会重置数据库里已有管理员的密码。

此示例的管理和控制监听仅接受本机连接。业务转发端口由策略另行创建；只创建允许被访问的目标服务。

### 3.2 注册 Client

另开一个 PowerShell 终端，在安装包根目录执行。注册令牌使用上一步设置的同一枚值。

```powershell
$enrollmentToken = Read-Host 'Server 的注册令牌' -MaskInput
.\bin\linklake-client.exe enroll `
  --server http://127.0.0.1:32100 `
  --token $enrollmentToken `
  --name windows-lab `
  --identity-file C:\LinkLake\client\agent-identity.json
```

保存返回的 `client_id` 和一次性显示的 `client_token`，并保护 `agent-identity.json`。后续接入其他独立 Server 时，应复用这份机器身份文件；不要复制另一台机器的身份文件来代替注册。

### 3.3 写配置并持续运行

创建 `C:\LinkLake\client\client.toml`：

```toml
config_version = 2

[client]
control = "127.0.0.1:32101"
client_id = "替换为注册返回的UUID"
client_token = "替换为注册返回的客户端令牌"
config_mode = "server_managed"
managed_config_path = 'C:\LinkLake\client\managed.toml'
```

```powershell
.\bin\linklake-client.exe run --config C:\LinkLake\client\client.toml
```

在 Web 的“客户端”页面确认 `windows-lab` 在线，然后进入 TCP 页面新建策略：选择该客户端，填写名称、公网端口 `32080`、目标地址 `127.0.0.1:8080`，保存并启用。目标地址由 Client 所在机器访问；这里的 `127.0.0.1` 指 Client 自己。

客户端采用 `server_managed` 后会接收并应用管理端策略，无需把每条 TCP/UDP 隧道抄进本地文件。访问 Server 的 `32080` 端口即可进入目标服务；跨机器访问前还需完成下一节的 TLS、监听和防火墙配置。

## 4. 换成长期运行的部署

接续本机示例时，先停止前台 Server/Client，再启动对应系统服务。需要沿用账号、客户端和策略时，让长期部署使用原数据目录，或按第10节备份并恢复到最终目录；新建一个空数据目录不会保留原来的注册关系。

### 4.1 域名、TLS 与端口

远程管理和远程控制监听都要求配置证书与私钥。管理端 TLS、控制端 TLS 和业务 HTTPS 是三个独立用途：为管理网页配置证书，不会自动为业务域名签发证书。

| 用途 | 配置项 | 常见端口与要求 |
| --- | --- | --- |
| 管理网页、API、客户端注册 | `LINKLAKE_BIND` | TCP 32100；非回环地址必须提供管理 TLS |
| 客户端控制连接 | `LINKLAKE_CONTROL_BIND` | TCP 32101；非回环地址必须提供控制 TLS |
| HTTP 域名路由、HTTP-01 挑战 | `LINKLAKE_HTTP_BIND` | 示例内部 TCP 32102；HTTP-01 公网入口必须为80 |
| LinkLake 终止业务 TLS | `LINKLAKE_HTTPS_BIND` | 示例内部 TCP 32103；通常映射公网443 |
| UDP/QUIC relay | `LINKLAKE_UDP_RELAY_BIND` | 示例 UDP 32104；还需配置外部 endpoint 与 server name |
| TLS SNI 原样透传 | `LINKLAKE_TLS_PASSTHROUGH_BIND` | 示例 TCP 32105；必须与业务 HTTPS 使用不同监听地址 |
| TCP/UDP/代理策略的公网端口 | 策略中的公网端口 | 同时受端口允许范围、服务端监听冲突、防火墙和云安全组约束 |

环境变量示例：

```dotenv
LINKLAKE_BIND=0.0.0.0:32100
LINKLAKE_CONTROL_BIND=0.0.0.0:32101
LINKLAKE_DATA_DIR=/var/lib/linklake
LINKLAKE_LOG_DIR=/var/log/linklake
LINKLAKE_MANAGEMENT_CERT_PATH=/etc/linklake/management-cert.pem
LINKLAKE_MANAGEMENT_KEY_PATH=/etc/linklake/management-key.pem
LINKLAKE_CONTROL_CERT_PATH=/etc/linklake/control-cert.pem
LINKLAKE_CONTROL_KEY_PATH=/etc/linklake/control-key.pem
LINKLAKE_PUBLIC_PORT_RANGES=32000-32999
```

另行注入注册令牌和初始管理员配置，并让运行账户能够读取证书文件。裸二进制默认管理/控制地址为回环地址，HTTP、HTTPS、SNI、UDP relay 默认不会自动开启；部署模板可能已经显式开启这些监听。

远程 Client 对应配置：

```toml
config_version = 2

[client]
control = "tunnel.example.com:32101"
control_ca_cert = 'C:\LinkLake\client\control-ca.pem'
control_server_name = "tunnel.example.com"
client_id = "替换为注册返回的UUID"
client_token = "替换为客户端令牌"
config_mode = "server_managed"
managed_config_path = 'C:\LinkLake\client\managed.toml'
```

`control_ca_cert` 是客户端用于信任控制端证书的 PEM 文件，`control_server_name` 必须匹配证书中的域名。它们不配置管理 API 的证书信任。远程 `enroll --server https://...` 示例需要客户端能够验证管理端 HTTPS；`enroll` 当前没有 `--ca-cert` 参数，`check` 命令的该参数也不会改变注册命令的信任设置。

默认公网策略范围是 `32000-32999`。可用 `LINKLAKE_TCP_PUBLIC_PORTS` / `LINKLAKE_UDP_PUBLIC_PORTS` 分别设置范围，用 `LINKLAKE_RESERVED_TCP_PORTS` / `LINKLAKE_RESERVED_UDP_PORTS` 增加保留端口。已经关闭的策略仍可能保留端口，释放前应删除对应策略或调整端口。只在系统防火墙和云安全组中开放实际使用的端口。

### 4.2 Linux systemd

在已解压并核对过的 Linux 安装包根目录执行：

```sh
sudo ./systemd/install-linux.sh server
sudoedit /etc/linklake/server.env
sudo systemctl start linklake-server
sudo systemctl status linklake-server
```

安装脚本创建服务账户、目录和 systemd 单元，并设置开机启动；不会代填凭据或直接启动服务。编辑 `server.env` 时按前文配置监听、TLS、数据目录、注册令牌和管理员初始密码。

在目标机器安装 Client：

```sh
sudo ./systemd/install-linux.sh client
sudoedit /etc/linklake/client.toml
sudo systemctl start linklake-client
sudo systemctl status linklake-client
```

先完成注册，再把返回的凭据写入配置。Linux TOML 路径使用 `/etc/linklake/...`；不要直接保留 Windows 示例路径。系统服务使用的账户、身份文件和状态目录应保持稳定，避免从交互用户切换到服务账户时丢失机器身份或托管状态。

### 4.3 Windows 系统服务

在管理员 PowerShell 中，从核对过的 Windows 安装包根目录执行单机 SQLite 安装：

```powershell
$enrollment = Read-Host '注册令牌' -AsSecureString
$adminPassword = Read-Host '初始管理员密码' -AsSecureString
.\windows\install-server.ps1 `
  -EnrollmentToken $enrollment `
  -AdminUsername admin `
  -AdminPassword $adminPassword

.\windows\install-client.ps1 -ConfigPath C:\LinkLake\client\client.toml
Get-Service LinkLakeServer, LinkLakeClient
```

默认 Server 仍只开放回环管理和控制。需要远程访问时，在安装参数中同时指定 `-Bind`、`-ControlBind`、`-ManagementCertificate`、`-ManagementKey`、`-ControlCertificate`、`-ControlKey`；按需增加 `-HttpBind`、`-HttpsBind` 等。可先使用 `-NoStart` 完成安装，再核对配置后启动服务。

默认程序目录为 `C:\Program Files\LinkLake`，Server 数据目录为 `C:\ProgramData\LinkLake\data`，Client 配置为 `C:\ProgramData\LinkLake\client.toml`。重新安装 Client 默认保留现有配置，只有显式 `-ReplaceConfig` 才替换。这里的 Server 安装器仅支持单机 SQLite，不能用来升级 PostgreSQL 集群。

### 4.4 Docker Compose

[Compose 模板](../deploy/docker-compose.yml) 包含 Server 和可选监控栈。从仓库根目录开始：

```sh
cp deploy/linklake.env.example deploy/linklake.env
# 编辑 deploy/linklake.env，并把管理、控制证书放到 deploy/certs/。
# 在同一终端设置 GRAFANA_ADMIN_PASSWORD；模板展开时要求此变量存在。
docker compose -f deploy/docker-compose.yml up -d --build linklake
```

务必把模板中的域名、注册令牌、密码和 UDP relay 地址替换为自己的配置。`LINKLAKE_HEALTH_URL` 的主机名也必须能通过挂载的管理证书校验。只保留所需监听及端口映射；容器内新增策略不会自动修改宿主机的 `ports` 映射。

Server 数据和日志使用命名卷，证书目录只读挂载。不要通过删除数据卷来“重新启动”。需要监控栈时，再准备 `deploy/secrets/linklake_metrics_token` 中的只读 API Token，核对 Prometheus TLS 配置和 Grafana 密码，然后启动其余服务。更多说明见[部署指南](deployment.md)。

## 5. 使用 Web 与 Manager 管理

Manager 解压时保留完整目录；Windows 启动 `linklake_manager.exe`，其他桌面平台启动对应应用包。在“服务端列表”添加自己的管理 URL，再输入用户名、密码和需要时的 TOTP。不要把示例服务端地址当作自己部署的实例，也不要把控制端口填入此处。

Web 和 Manager 均提供客户端、协议策略、ACME、HA、Fleet、指标和告警等页面。管理员可管理账号、会话和 API Token；运维账号按权限管理策略；审计账号用于只读查看。首次登录应完成密码修改，并按需要配置 TOTP、检查已有会话。

客户端三种配置模式：

| 模式 | 日常操作 |
| --- | --- |
| `server_managed` | 在 Web/Manager 改策略，Client 接收并应用；不要手工修改自动生成的 `managed.toml` |
| `report_only` | 本地 TOML 为运行来源，向管理端报告差异，便于逐步迁移 |
| `local` | 按本地 TOML 运行，不接受管理端覆盖 |

修改后查看客户端的在线状态、配置修订与同步结果；“已保存策略”不等于 Client 已在线并成功连接目标。配置示例见[单入口](../examples/linklake-client.toml)和[多入口](../examples/linklake-client-multi-server.toml)。

## 6. 创建哪种转发

在 Web 导航中的协议页面或 Manager 同名页面新建策略，选择负责访问目标的 Client，填写目标地址与限制，保存并启用。

| 类型 | 适合用途 | 创建时的关键配置 |
| --- | --- | --- |
| TCP | SSH、RDP、数据库、TCP 游戏服务等 | 公网端口、目标 `host:port`、最大连接数 |
| UDP | UDP 游戏、语音、其他 UDP 应用 | 公网 UDP 端口、目标、会话数和空闲超时；Server 必须启用 UDP relay |
| 端口组 | 一批对应端口或端口范围 | TCP/UDP、两侧等数量端口表达式、目标主机；按展开顺序一一映射，每组最多256个 |
| HTTP/HTTPS | 网站、WebSocket、HTTP/2、gRPC | 路由域名、目标地址；HTTPS 再设置该路由的 TLS 模式 |
| TLS SNI | TLS 在内网目标服务终止的场景 | SNI 域名、目标地址、独立 SNI 监听；证书由目标服务负责 |
| Secret | 不开放公网业务端口的私密访问 | 目标端 Client、目标地址、允许的访问端 Client、一次性访问密钥 |
| SOCKS5 | 通过指定 Client 所在网络出站 | 公网代理端口、用户名、一次性密码、连接及出口限制 |
| HTTP Proxy | HTTP 正向代理和 CONNECT 出站 | 公网代理端口、用户名、一次性密码、出口限制 |

SOCKS5 同时涉及 TCP 和 UDP 端口预留，不能按仅占用 TCP 规划端口。代理的“允许私有网络”开关决定是否允许连接内网目标；保持关闭直到确实需要该用途，不要把公网代理配置成无认证出口。具体命令和兼容边界见 [SOCKS5 指南](socks5-supported-boundaries.md)。

HTTP/HTTPS 路由需要域名解析到 Server，前置代理应保留原始 Host。gRPC 后端默认 `h2c`；目标需要 TLS 时，配置 `grpc_backend_transport="tls"`、匹配证书的 `grpc_backend_server_name`，以及需要时的 `grpc_backend_trust_profile`。详见 [HTTP/2 与 gRPC](http2-grpc.md)。

### Secret 访问端示例

先在管理端创建 Secret 目标策略，保存一次性 `access_key`；访问端 Client 也需注册。将以下条目附加到访问端自己的 TOML，访问端条目不会由 `server_managed` 自动下发：

```toml
[[secret_visitors]]
name = "private-service-access"
local_bind = "127.0.0.1:13389"
access_key = "替换为一次性显示的lls_访问密钥"
path_policy = "relay_only"
```

连接访问端本机 `127.0.0.1:13389` 即可访问目标；是否能登录 RDP、SSH 等应用，仍由目标应用自己的认证决定。`relay_only` 固定走中继；配置 P2P 后可选择 `prefer_direct`，直连不可用时回到中继；`direct_only` 则在直连不可用时失败。多入口配置中的 visitor 还需填写 `server = "对应入口名称"`。

### 流量与访问限制

在策略的流量控制中设置所需的配额、连接速率、来源 CIDR 或时间窗口；调度时间按 UTC 解释。配额用于后续转发授权，不应理解为所有存量长连接都会在某个精确字节处立即中断。

PG 集群会共享流量控制和使用量，Client/Server 停机时应正常排空。若界面或日志提示账务暂存故障，新转发可能被拒绝；应恢复本机持久盘或数据库连接，不能删除待确认流量文件来“清零”。宿主机永久丢失且本机数据未上传时，不能保证这部分账务零丢失。

## 7. 业务 HTTPS 与 ACME

1. 为业务启用 `LINKLAKE_HTTP_BIND`、`LINKLAKE_HTTPS_BIND`，并保留持久数据目录。
2. 打开 ACME 设置，先选择测试环境，填写联系邮箱、确认条款、选择挑战方式和续期窗口。
3. 打开 HTTP 路由的 TLS 设置，启用 ACME，按需设置 HTTP 跳转 HTTPS 和证书标识。
4. 发起签发，查看证书状态和失败原因；确认域名、挑战和访问路径正确后，再切换所需环境并签发正式证书。

HTTP-01 要求公网80能按原始 Host 到达 HTTP 监听。业务公网443应把 TLS 连接原样送到 LinkLake 的 HTTPS 监听，由 LinkLake 选择证书。启用 SNI 透传时，由目标服务持有证书；两种方式不能绑定同一个 IP:端口。

需要通配符或无法提供公网80时，可选 Cloudflare DNS-01。将受限 Token 配置到 Server 的 `LINKLAKE_CLOUDFLARE_API_TOKEN_FILE`，或使用 `LINKLAKE_CLOUDFLARE_API_TOKEN`，两个来源不能同时设置。文件仅允许服务账户读取；Token 应限于所需 Zone 的读取/DNS 编辑权限。ACME 页面只显示凭据是否就绪，不接受或回显 Token 正文。

`certificate_identifier` 可填路由域名或覆盖其一层子域名的通配符，例如 `*.example.com`；通配符必须使用 DNS-01。若要把已有通配符策略改为精确证书，显式填写该路由域名。

PG 的证书私钥和 ACME 账户需要所有副本共享同一份 `LINKLAKE_CERTIFICATE_KEY_FILE`：内容必须是32字节原始二进制，不能是十六进制或 base64 文本；Unix 权限为 `0600` 等仅拥有者可读写的模式。数据库备份之外还需单独保存该密钥。直接替换文件或 Kubernetes Secret 不会重新加密已有材料，轮换方法见第10节。

## 8. PostgreSQL HA 与 Kubernetes

### 8.1 部署前准备

准备 LinkLake 使用的独立 PostgreSQL 数据库、受信 TLS 连接、受保护的连接串、每个 Server 副本独立的持久目录，以及一致的监听、端口策略和外部凭据配置。PG 模式默认要求数据库 TLS 校验，不要把仅用于回环测试的 `LINKLAKE_POSTGRES_ALLOW_INSECURE_LOOPBACK` 当成生产连接方案。

每个副本至少配置：

```dotenv
LINKLAKE_STORAGE_BACKEND=postgres
LINKLAKE_POSTGRES_URL=postgresql://linklake:替换密码@postgres.example.com/linklake
LINKLAKE_DATA_DIR=/var/lib/linklake
LINKLAKE_HA_INSTANCE_ID=linklake-a
LINKLAKE_CERTIFICATE_KEY_FILE=/etc/linklake/cluster-certificate.key
```

下一个副本使用不同的 `LINKLAKE_HA_INSTANCE_ID` 和独立持久目录，连接同一数据库、使用同一证书材料密钥。不要把同一个数据卷直接复制成两个同时运行的实例身份。数据库连接失败不会自动退回本机 SQLite。

新数据库可先由维护进程运行 `linklake-server initialize-postgres` 初始化空的 LinkLake schema；它不会启动 Server。已有 SQLite 部署不要只改后端变量，按第10节执行迁移。

### 8.2 Helm 关键配置

Chart 不内置数据库或明文凭据。预先在部署命名空间中准备以下 Secret：

| Secret 示例名称 | 必需的数据项 |
| --- | --- |
| `linklake-auth` | `enrollment-token`、`admin-username`、`admin-password`；需要时另加 `management-token` |
| `linklake-management-tls` | 标准 TLS Secret 的 `tls.crt`、`tls.key` |
| `linklake-control-tls` | 标准 TLS Secret 的 `tls.crt`、`tls.key` |
| `linklake-postgres` | `postgres-url` |
| `linklake-certificate-material` | `certificate-key`，解码后为32字节原始密钥 |

例如保存以下非秘密配置为 `values.local.yaml`，再替换镜像和外部地址：

```yaml
replicaCount: 3
image:
  repository: 替换为已取得镜像的仓库
  tag: 替换为已确认的镜像标签
auth:
  existingSecret: linklake-auth
tls:
  managementSecret: linklake-management-tls
  controlSecret: linklake-control-tls
storage:
  backend: postgres
  postgres:
    existingSecret: linklake-postgres
ha:
  enabled: true
certificateMaterial:
  existingSecret: linklake-certificate-material
server:
  udpRelay:
    advertisedEndpoint: relay.example.com:32104
    serverName: relay.example.com
services:
  data:
    publicTcpPorts: [32080]
    publicUdpPorts: []
```

```sh
helm upgrade --install linklake deploy/helm/linklake \
  --namespace linklake --create-namespace \
  --values values.local.yaml
```

HA 使用 StatefulSet 和每 Pod 独立 PVC；默认 SQLite 则使用单副本 Deployment。Chart 中启用的协议监听应与自己的证书、域名和 Service 暴露方式匹配；不需要的 HTTP、HTTPS、SNI 或 UDP relay 可在 values 中关闭。Kubernetes Service 不支持端口范围，业务公网端口需逐个加入 `publicTcpPorts` / `publicUdpPorts`。

### 8.3 配好入口再观察接管

`/livez` 用于存活检查，`/readyz` 用于生命周期就绪检查，`/leaderz` 同时要求实例就绪且为 Leader。前置负载均衡器应依据 `/leaderz` 选择接受控制连接与修改请求的副本；不能仅凭 `/readyz` 或普通 Service 随机分流认定入口会自动跟随 Leader。

Follower 的读取能力不代表它接受策略修改或新的转发控制连接。收到“当前不是 Leader”的响应时，先核对入口和 HA 页面，不要反复在错误副本重试写入。共享策略不会自动配置云负载均衡器，也不会自动发现、替换客户端 TOML 中的控制地址。

扩缩容时保留未确认账务的实例持久卷；待正常排空和数据确认后，再按自己的保留策略处理。默认保留 PVC 不等于已完成异地备份。部署细项见 [Chart 配置](../deploy/helm/linklake/values.yaml)与 [PostgreSQL 升级和恢复](postgres-upgrades.md)。

## 9. 多入口与 Fleet

多入口客户端配置使用多个 `[[servers]]`，每项有独立的管理关系、控制地址、CA、Client ID 和 Token。同一客户端接入独立 Server 时分别注册，但复用稳定机器身份；这与一个 PG 集群内部共享注册数据的多个副本不同。

Fleet 用于在独立 Server 之间管理节点、健康、策略同步和可选 DNS 故障切换。日常流程：

1. 在各目标 Server 完成客户端注册，确认稳定身份和公钥匹配。
2. 为接收端创建具备所需权限并绑定来源 `source_instance_id` 的 API Token，在来源 Server 的多云/Fleet 页面添加目标节点。
3. 先预览同步结果，处理缺失客户端、端口冲突和凭据绑定，再执行同步。
4. 到 Fleet 共享账本查看 generation、进度和冲突结果；同步完成后核对目标策略及客户端在线状态。

Fleet v2 覆盖八类策略和对应流量控制，使用来源与资源 ID 跟踪归属。Secret、SOCKS5、HTTP Proxy 仅传递凭据引用；目标侧需预先准备本地凭据并绑定，Bundle 不携带密码、访问密钥、客户端 Token 或证书私钥。普通交互登录及通用管理 Token 不能代替 v2 reconcile 所需的来源绑定 Token。

已由 Fleet 管理的策略不能随意在目标侧普通 CRUD 中修改。需从来源变更并同步，或先按管理流程解除归属。旧版本节点的兼容同步范围与 v2 不同，应先查看预览和协议能力，再执行变更。

自动化可使用 `POST /api/v1/fleet/v2/bundle` 导出、`POST /api/v1/fleet/v2/reconcile` 预览/应用，并通过 `/api/v1/fleet/v2/sources`、`/generations`、`/conflicts` 及 `/credentials` 管理来源状态、账本和凭据引用。协议说明见 [Fleet Bundle v2](adr/0003-fleet-bundle-v2.md)。

DNS 故障切换需要显式配置 Cloudflare Zone、记录、节点与目标值、健康阈值及冷却策略。它不会自动创建一套通用负载均衡网络；DNS TTL、缓存及已有连接都会影响用户实际恢复时间。可先冻结自动变更、查看计划和事件，再恢复执行。见 [Fleet 健康与 DNS 设计](adr/0004-fleet-health-dns-failover.md)。

## 10. 备份、迁移、密钥轮换和升级

维护命令不会自动读取 systemd 的 `server.env` 或 Kubernetes Secret。运行前把对应部署的环境和凭据安全注入维护进程，并确认使用的是正确数据目录与数据库。下列停机命令应在自己的维护窗口执行。

### SQLite 备份与恢复

仅备份数据库可使用 `backup`；需要包含托管证书和 ACME 状态时使用加密 `backup-full`：

```sh
linklake-server backup-full \
  --data-dir /var/lib/linklake \
  --output /srv/linklake-backups/linklake-full.llb \
  --password-file /secure/linklake-backup.pass
```

输出和密码文件应在数据目录外。在线备份中的 SQLite、证书和账户不保证是完全相同时间点；需要严格一致性时先停止 Server。部署环境变量、外部 TLS 文件、材料密钥、服务定义和 DNS/负载均衡配置应独立备份。

恢复前停止 Server，确认目标目录已按服务账户和要求的访问权限准备好：

```sh
linklake-server restore-full \
  --data-dir /var/lib/linklake \
  --input /srv/linklake-backups/linklake-full.llb \
  --password-file /secure/linklake-backup.pass
```

恢复后核对登录、客户端重连、目标服务和证书，再恢复业务入口。完整范围与权限要求见[部署指南](deployment.md)。

### SQLite 迁移到 PostgreSQL

先完整备份，排空并停止 SQLite Server 和全部目标 PG 副本，暂停自动重启/扩容。准备空的目标数据库、共同材料密钥，并保留原端口策略、监听和历史自定义 ACME 账户目录配置。

在配置了目标 PG 环境的维护进程中执行：

```sh
linklake-server initialize-postgres
linklake-server migrate-sqlite-to-postgres \
  --data-dir /var/lib/linklake \
  --certificate-key-file /secure/cluster-certificate.key \
  --all-instances-stopped --preview
linklake-server migrate-sqlite-to-postgres \
  --data-dir /var/lib/linklake \
  --certificate-key-file /secure/cluster-certificate.key \
  --all-instances-stopped
```

预览通过后再执行不带 `--preview` 的提交。自定义历史 ACME 目录可重复传 `--account-directory URL`；快照上限默认512MiB，可用 `--max-snapshot-mib` 调整。未知非空表、未结束的外部操作等会阻止迁移，应先在原服务中处理完成。

迁移后保留源目录；核对账号、客户端、策略、证书和账务，再启动 PG 副本并切换入口。不能同时运行两套独立可写控制平面。若提交响应丢失，保留停机状态，按迁移回执确认结果，不要清空目标库重来。

只有源和目标均保持迁移时状态，才可能通过以下回滚资格检查：

```sh
linklake-server verify-sqlite-rollback \
  --data-dir /var/lib/linklake \
  --certificate-key-file /secure/cluster-certificate.key \
  --all-instances-stopped
```

该命令不切换配置、不删除 PG，也不把运行后的新数据反向合并回 SQLite。目标接收新数据后，不应直接切回旧快照。详见[存储迁移](storage-migration.md)。

### PG 证书材料密钥轮换

备份 PG、旧密钥和部署配置，准备独立的新32字节密钥。排空并停止全部副本和自动重启，等待仍有效的租约正常到期，再执行：

```sh
linklake-server rotate-certificate-key \
  --previous-key-file /secure/old-key \
  --next-key-file /secure/new-key \
  --all-instances-stopped
```

确认事务成功后，所有副本统一改用新密钥；Helm 部署还需更新受控 Secret 并重新创建 Pod，才能重新复制材料文件。响应中断时先只读核对数据库密钥指纹，再决定使用旧配置或新配置，不能盲目重试。详见[证书材料密钥维护](certificate-key-maintenance.md)。

### 更新与集群恢复

先查看实际安装身份和候选版本：

```sh
linklake-server --version-json
linklake-client --version-json
linklake-client check-update --channel stable
```

已安装为系统服务的单机 Client 可用 `update download`、`update apply --yes` 和 `update status`；Web/Manager 的更新页面也提供相应操作。单机 SQLite Server 示例：

```sh
linklake-server update download
linklake-server update apply --yes --data-dir /var/lib/linklake
linklake-server update status
```

以上操作需要服务控制权限及符合要求的签名包。Manager 自更新应从其界面发起，由帮助进程处理退出和替换，不要在运行中只覆盖一个可执行文件。中断恢复、回滚和跨 schema 数据恢复的确认要求见[安全更新说明](update-security.zh-CN.md)。

PG 的备份、恢复和升级必须使用 PostgreSQL 备份/PITR 工具与集群部署流程。一个副本的 `linklake.sqlite3` 不是集群备份，单机 `backup` / `restore` / Server updater 也不是 PG 升级工具。保留各实例的流量暂存卷、共同材料密钥、外部凭据和部署配置；不要删除 `postgres-storage.marker` 绕过保护。

候选 Server 启动后可能已修改数据库，镜像降级或 `helm rollback` 本身不能撤销这些变化。应先确认 schema 兼容性，必要时在维护窗口停止所有写入并恢复匹配的数据、密钥和程序版本。详见 [PostgreSQL 集群升级与恢复](postgres-upgrades.md)及[发布签名与供应链](release-supply-chain.zh-CN.md)。

## 11. 日常查看与常见问题

优先查看客户端在线和同步状态、目标服务、协议页连接/流量、HA Leader、告警及审计记录。只读监控抓取地址为 `/api/v1/metrics/prometheus`，使用 `read` scope 的 API Bearer Token；注册令牌不能代替管理 API Token。

```sh
linklake-client check --server https://management.example.com:32100
linklake-client diagnose --config /etc/linklake/client.toml
linklake-client logs --lines 100
linklake-client service status
```

管理 API 使用私有 CA 时，健康检查可额外传 `check --ca-cert /path/to/management-ca.pem`。服务端日志由 `LINKLAKE_LOG_DIR` 指定，未设置时使用数据目录下的 `logs`；systemd 部署还可查看 `journalctl -u linklake-server` 或 `journalctl -u linklake-client`。

| 现象 | 先检查什么 |
| --- | --- |
| 浏览器或 Manager 无法连接 | 是否填了管理地址；DNS、TLS 域名、端口映射和防火墙是否匹配 |
| 注册返回未授权 | 是否用了 Enrollment Token；是否误把 Client Token 或管理 Token 当注册令牌 |
| Client 离线或配置未应用 | Client 是否持续运行、控制地址与 CA/server name 是否正确、模式是否为 `server_managed` |
| 策略已保存但无法访问 | 目标从 Client 上是否可达；策略是否启用；业务端口是否允许并已暴露；是否命中配额/来源/时间限制 |
| 端口被拒绝或被占用 | 是否超出范围、撞到系统/内置监听、被其他策略或禁用策略预留；SOCKS5 是否同时占用了 UDP |
| UDP 不通而 TCP 正常 | 是否启用了 UDP relay，endpoint/server name 是否外部可达且匹配控制证书，relay 与业务 UDP 端口是否分别放行 |
| HTTPS 签发失败 | ACME 环境、域名、80/443 到达方式、DNS-01 Token/传播和证书材料密钥是否就绪 |
| HA 写操作或控制连接被拒绝 | 请求是否到达当前 Leader，入口是否使用 `/leaderz`，实例是否处于排空状态 |
| PG 启动失败或材料无法解密 | 后端变量与连接串是否一致、数据库 TLS 是否受信、实例目录是否持久、所有副本是否使用匹配的32字节密钥 |
| 同步显示 Fleet 归属或凭据冲突 | 来源绑定 Token、稳定客户端身份、目标侧凭据绑定、端口与 generation 是否匹配；先重新预览 |

计划停机时先通过管理 API `POST /api/v1/lifecycle/drain` 进入排空，查询 `GET /api/v1/lifecycle`，待 `drained=true` 后停止服务，并留足停机超时供账务写入完成。重新启动后再检查就绪、Leader 和实际业务入口。可观测性说明见 [SLO 与指标](slo-observability.md)。
