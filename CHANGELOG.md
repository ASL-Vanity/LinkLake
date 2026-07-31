# LinkLake 更新日志

本项目采用语义化版本号。候选版本用于完整验收，不代表已对外发布。

## 0.4.0-rc.1 - 2026-07-31

### 新增

- TCP、UDP、连续或离散端口组、HTTP/HTTPS、TLS SNI 原样透传、Secret、SOCKS5 TCP/UDP 与 HTTP 正向代理/CONNECT。
- Secret P2P 支持 Noise `NNpsk0` + ChaCha20-Poly1305 TCP 加密、Iroh QUIC/UDP 打洞和受控服务端中继回退。
- STUN/QAD 公网地址、NAT 映射行为、路由器端口映射和自托管 Iroh 会合服务信息上报。
- 多候选并发竞速，单次票据只发送到胜出连接；Iroh relay-only 路径不承载业务数据。
- 双语 Web UI、账号密码登录、首次登录强制改密、服务端托管配置与审计/指标。
- Windows、Linux、macOS 服务定义和可校验发布包；Linux Pebble HTTPS/ACME 自动化。
- Flutter Manager 的 Windows、Linux、macOS CI、Release 构建和独立可校验发布包。
- 项目许可证确定为 Apache License 2.0，并将 `LICENSE` 与 `NOTICE` 纳入全部发布包。

### 可靠性与安全

- 一次性访问密钥和代理密码仅返回一次，数据库保存哈希。
- P2P 票据短期、单次消费、防重放；每个会话使用独立 PSK，双方定期 rekey。
- SQLite 在线备份、完整性校验恢复、启动迁移前自动备份和向前版本拒绝。
- 并发、分片弱网、吞吐、限速、进程崩溃、客户端重连、服务端重启和 soak 测试矩阵。
- 每周及手动触发的 Windows 长稳矩阵工作流，失败时保留可下载报告。
- 普通 HTTP 正向代理在完整响应返回后再关闭 TLS 数据通道，避免 Windows 客户端提前 EOF。
- TCP 类数据通道把缺失 TLS `close_notify` 的底层 EOF 作为半关闭处理，保留已传输字节且不再制造失败指标。
- 公网验收逐项原子保存结果，并为允许丢包的 UDP 可达性检查提供有限重试。

### 验收

- Windows 客户端、新加坡服务端与上海公网验收机完成 16/16 数据通道实测。
- Rust 工作区测试、Clippy、Windows/Linux 发布包校验及 Flutter 管理端分析、测试和 Windows Release 构建通过。

### 升级说明

- 服务端首次打开旧数据库时，会在数据目录创建 `linklake.sqlite3.pre-migration-v<版本>-<时间>` 后再提交架构版本。
- 客户端可运行 `linklake-client migrate-config --input old.toml --output new.toml` 生成并验证当前格式；不会覆盖原文件。
