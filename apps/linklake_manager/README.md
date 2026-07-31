# LinkLake Manager

LinkLake Manager 是 LinkLake 的 Flutter 跨平台管理客户端，目前提供：

- 服务端地址、管理员账号和密码登录；
- 初始密码强制修改；
- 中英文界面；
- 状态、指标、客户端、P2P 节点、审计记录和全部转发策略查看；
- TCP/UDP 策略创建与刷新。

LinkLake Manager is the Flutter cross-platform administration client for LinkLake. It supports administrator sign-in, forced initial-password changes, Chinese/English UI, runtime dashboards, policy inspection, audit records, and TCP/UDP policy creation.

## 验证 / Verification

```powershell
flutter pub get
flutter analyze
flutter test
flutter build windows --release
```

Linux 和 macOS 请分别使用 `flutter build linux --release` 与 `flutter build macos --release`。仓库根目录下的发布脚本会生成带 SHA-256 校验文件的管理客户端压缩包。

Use `flutter build linux --release` or `flutter build macos --release` on the corresponding host. Release scripts in the repository root produce manager archives with SHA-256 checksum files.
