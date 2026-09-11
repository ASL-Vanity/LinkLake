# LinkLake Manager

LinkLake Manager 是 LinkLake 的 Flutter 跨平台管理客户端，目前提供：

- 多服务端配置、账号密码和 TOTP 登录，以及初始密码强制修改；
- 中英文与跟随系统的浅色/深色界面；
- 导航中的 ACME 设置页：配置环境、HTTP-01/DNS-01、联系邮箱、条款和续期窗口，查看账户与凭据就绪状态；管理员和运维可保存，审计人员只读；
- 状态、持久化指标、客户端、P2P 节点、审计记录和全部转发策略管理；
- 告警规则、活动告警、Webhook/SMTP 通知状态和 API Token 管理；
- 多云服务端健康、优先级、权重、策略同步预览与执行；
- 本地客户端配置诊断、日志查看、系统服务安装与启停；
- 当前版本、GitHub 候选版本和更新可用性诊断。
- 客户端更新包的下载校验、原子安装、状态查看和备份回滚。
- Windows、Linux 与 macOS 的托盘驻留、关闭到托盘和登录后自启动；macOS 使用固定版本的 LaunchAtLogin 集成。

LinkLake Manager is the Flutter cross-platform administration client for LinkLake. It supports multi-server profiles, password/TOTP sign-in, persistent metrics, complete policy administration, alerts and notification status, API tokens, fleet synchronization, local client diagnostics, service control, logs, verified client download/install/rollback workflows, tray residence, close-to-tray, and launch-at-login on Windows, Linux, and macOS.

The ACME navigation page configures the environment, HTTP-01/DNS-01 validation,
contact email, terms and renewal window, and displays account and credential
readiness. Administrators and operators can save; auditors have read-only access.
No certificate material keys or Cloudflare tokens are entered or returned by this
page. Older servers without credential-status fields are shown as unknown. For
SQLite, material-key readiness may mean that a shared key is not required.

ACME 页不接收或展示证书材料密钥及 Cloudflare Token 正文；旧服务器未提供凭据状态时显示未知。
SQLite 的材料密钥就绪状态可以表示当前后端无需共享密钥。HTTP 路由中原有证书操作入口保持可用。

## 验证 / Verification

```powershell
flutter pub get
flutter analyze
flutter test
flutter build windows --release
```

Linux 和 macOS 请分别使用 `flutter build linux --release` 与 `flutter build macos --release`。仓库根目录下的发布脚本会生成带 SHA-256 校验文件的管理客户端压缩包。

Use `flutter build linux --release` or `flutter build macos --release` on the corresponding host. Release scripts in the repository root produce manager archives with SHA-256 checksum files.
