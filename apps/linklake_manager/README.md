# LinkLake Manager

LinkLake Manager 是 LinkLake 的 Flutter 跨平台管理客户端，目前提供：

- 多服务端配置、账号密码和 TOTP 登录，以及初始密码强制修改；
- 中英文与跟随系统的浅色/深色界面；
- 状态、持久化指标、客户端、P2P 节点、审计记录和全部转发策略管理；
- 告警规则、活动告警、Webhook/SMTP 通知状态和 API Token 管理；
- 多云服务端健康、优先级、权重、策略同步预览与执行；
- 本地客户端配置诊断、日志查看、系统服务安装与启停；
- 当前版本、GitHub 候选版本和更新可用性诊断。
- 客户端更新包的下载校验、原子安装、状态查看和备份回滚。
- Windows、Linux 与 macOS 的托盘驻留、关闭到托盘和登录后自启动；macOS 使用固定版本的 LaunchAtLogin 集成。

LinkLake Manager is the Flutter cross-platform administration client for LinkLake. It supports multi-server profiles, password/TOTP sign-in, persistent metrics, complete policy administration, alerts and notification status, API tokens, fleet synchronization, local client diagnostics, service control, logs, verified client download/install/rollback workflows, tray residence, close-to-tray, and launch-at-login on Windows, Linux, and macOS.

## 验证 / Verification

```powershell
flutter pub get
flutter analyze
flutter test
flutter build windows --release
```

Linux 和 macOS 请分别使用 `flutter build linux --release` 与 `flutter build macos --release`。仓库根目录下的发布脚本会生成带 SHA-256 校验文件的管理客户端压缩包。

Use `flutter build linux --release` or `flutter build macos --release` on the corresponding host. Release scripts in the repository root produce manager archives with SHA-256 checksum files.
