# LinkLake v0.8 更新安全模型

日期：2026-08-02

## 威胁模型与兼容性审计

审计对象包括原 `crates/linklake-client/src/updater.rs`、服务端启动顺序、Windows/systemd/launchd 服务定义、三平台包结构、Manager 包结构和 Release workflow。

原实现已经具备 HTTPS 主机/仓库路径约束、GitHub 资产摘要、独立 `.sha256`、归档路径与大小限制、二进制暂存、同目录替换、服务恢复和自动回滚，但存在以下产品化缺口：

1. 更新器只属于客户端，服务端没有同等 download/apply/status/rollback 能力。
2. 服务端在处理版本参数前运行数据库工具检测和日志初始化，无法证明 `--version` 完全无副作用。
3. `.sha256` 与被保护资产位于同一仓库/Release 权限域，发布账号被接管时攻击者可以同时替换两者。
4. Manager 只有包和版本检查，没有可供 UI 稳定调用的暂存、安装、状态和回滚协议。
5. 原帮助计划没有产品字段，不能安全复用于多个服务；版本解析假定版本号是输出最后一个字段。
6. 生产与测试签名路径未隔离，密钥轮换和最低更新器版本没有协议字段。

本模型保护以下攻击：下载内容损坏、资产/校验文件不一致、Release 资产被仓库权限攻击者替换、路径穿越/符号链接/归档炸弹、下载后或调度后的暂存文件篡改、错误目标替换、并发修改、服务无法恢复，以及新程序版本身份不符。

不直接解决：已签名恶意构建、生产私钥泄露、运行中主机的管理员/root 被完全攻陷、操作系统信任根被攻陷、Manager 安装目录被其他高权限进程持续锁定。对应缓解措施是 CI 最小权限、离线生成生产密钥、分支和 Release 保护、密钥撤销/轮换、帮助进程超时与自动回滚。

## 签名清单

正式 Release 发布两个固定资产：

- `linklake-release-manifest-v1.json`
- `linklake-release-manifest-v1.sig`

清单精确包含：`schema_version`、`release_version`、`key_id`、`minimum_updater_version`、`created_unix_seconds`，以及每个 `component/target/name/sha256/size` 资产。资产必须按 component、target、name 严格排序。服务端和客户端可以引用同一基础包；Manager 引用独立 `linklake-manager-*` 包。签名绑定唯一规范字节：按结构字段声明顺序生成的紧凑 UTF-8 JSON，末尾仅有一个 LF。验证器拒绝其他空白、字段顺序、重复资产身份和尾随字节，即使分离签名本身有效也不接受。

验证顺序为：GitHub HTTPS/仓库归属 → GitHub 资产摘要 → Ed25519 清单 → 清单版本/密钥有效区间/最低更新器版本 → 清单资产身份/大小/摘要 → `.sha256` → 归档与内部 `release.json` → 暂存摘要 → 安装计划摘要 → 安装后版本和服务状态。

生产策略拒绝网络降级。降级只通过本机已验证备份完成；`--allow-downgrade` 仅在同时显式启用 `--development-signature` 时用于测试。

## 密钥管理与轮换

- 生产私钥不得生成或保存在仓库、构建产物、日志或开发状态目录中，只由 `LINKLAKE_RELEASE_SIGNING_KEY_B64` CI secret 注入。
- `security/release-keys.json` 只登记公钥、用途和语义版本有效区间。
- 仓库中的 RFC 8032 私钥夹具明确标记为 development，只用于测试；生产验证默认拒绝它。
- 新密钥轮换时，先提交新公钥并设置未来 `not_before_version`，发布至少一个同时信任新旧公钥的更新器，再切换 CI secret；最后为旧公钥设置 `not_after_version`。
- 紧急撤销时，删除/截止被泄露公钥并通过仍可信的另一把生产密钥发布更新。若没有第二把可信密钥，需要人工安全分发新的信任根。

当前仓库尚未登记生产公钥。因此标签 Release 会在签名步骤关闭失败，直到维护者离线生成生产密钥、仅提交公钥并配置两个 CI secret。这是预期的安全阻断，不应通过启用测试密钥绕过。

## 替换与回滚不变量

- 客户端/服务端只替换 `linklake-client[.exe]` 或 `linklake-server[.exe]`；配置、SQLite、证书、日志和状态目录不进入替换集合。
- 目标、传入文件和旧文件均位于目标父目录内完成重命名，避免跨卷“伪原子”移动。
- 仅在服务确实引用目标二进制时停止/恢复 `LinkLakeClient`、`LinkLakeServer`、对应 systemd 单元或 launchd label。
- 服务原先停止时更新后保持停止；原先运行时必须连续多次确认恢复运行。
- Manager 把完整暂存目录树和已安装目录树摘要写入帮助计划，在目标安装目录同级复制并复核暂存树，然后只在目标卷内切换目录。Flutter 必须传入自身 PID，收到 `requires_manager_exit=true` 后退出；帮助进程在触碰安装目录前等待该精确进程退出，并受固定超时约束。
- 任一摘要、版本、重命名或服务恢复失败都会尝试恢复旧版本，并把最终状态写入 JSON。

## 稳定接口

客户端和服务端均支持：`check-update`、`update download/apply/status/rollback`、隐藏帮助命令，以及 `--version`/`--version-json`。

Manager 使用：

```text
linklake-client manager-update download --current-version <semver>
linklake-client manager-update apply --install-dir <dir> --manager-pid <pid> --yes
linklake-client manager-update status
linklake-client manager-update rollback --install-dir <dir> --manager-pid <pid> --yes
```

所有成功输出均为 JSON。`apply`/`rollback` 返回 `schema_version=2`、帮助进程 PID、Manager PID、状态路径、退出截止时间和 `requires_manager_exit=true`。UI 只有在成功解析该响应后才退出，然后轮询 `status`，直到 `succeeded`、`rolled_back` 或 `failed`。机器可读契约位于 `docs/manager-update-json-schema.json`，Flutter 适配器位于 `apps/linklake_manager/lib/update_protocol.dart`。

以下冲突全部关闭失败：暂存或安装目录树摘要变化、Release 版本或平台变化、未知安装目录、把 updater PID 冒充 Manager PID、Manager 退出超时、目录仍被锁定、同卷重命名失败、切换后验证失败。更新流程不会修改 Manager 包内外的 env、SQLite、ACME、证书或日志。
