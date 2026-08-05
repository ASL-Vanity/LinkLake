# LinkLake v1.0 更新安全模型

日期：2026-08-05

## 威胁模型与兼容性审计

审计覆盖旧版仅客户端更新器、服务端启动顺序、Windows/systemd/launchd 服务定义、全部软件包布局、Manager 包以及 Release 工作流。

旧更新器已经具备 HTTPS 主机和仓库路径限制、GitHub 与独立 `.sha256` 摘要校验、归档大小限制、安全暂存、同目录替换、服务恢复和失败回滚能力。产品化前仍存在这些缺口：服务端没有更新器；服务端在输出版本信息前会执行启动相关操作；校验和与资产使用同一个发布者信任域；Manager 没有稳定的安装协议；帮助进程计划只适用于客户端；生产与测试签名、密钥轮换元数据没有隔离。

v1.0 设计防护下载损坏、资产与校验和不一致、仓库发布者权限被接管后替换 GitHub Release 资产、路径穿越、符号链接与归档炸弹、暂存文件被篡改、错误目标替换、并发修改、服务恢复失败、已安装版本不匹配、服务端 schema/迁移台账不兼容、数据库迁移或回滚被中断，以及可写更新目录中伪造的服务端恢复状态。

它不能独自防护由获授权生产密钥签名的恶意构建、生产密钥泄露、运行主机被管理员/root 完全控制、操作系统信任根被攻破，或高权限进程无限期锁定 Manager 安装目录。相应缓解措施包括最小权限 CI、离线生成生产密钥、受保护的分支/Release、密钥轮换与撤销、帮助进程超时和自动回滚。

## 签名清单

每个标签 Release（稳定版或语义版本预发布版）都会发布 `linklake-release-manifest-v1.json` 和 `linklake-release-manifest-v1.sig`。清单绑定 `release_version`、`key_id`、`minimum_updater_version`、创建时间，以及每个资产的 `component`、`target`、`name`、`sha256` 和 `size`。资产必须按 component、target、name 严格排序。分离签名覆盖唯一的规范字节编码：按结构体字段声明顺序生成紧凑 UTF-8 JSON，并且结尾只能有一个 LF。即使分离签名本身有效，验证器也会拒绝替代空白、字段顺序、重复身份和尾随字节。

验证顺序为：GitHub HTTPS/仓库归属；GitHub 资产摘要；Ed25519 清单；Release、密钥有效区间和最低更新器版本；签名资产身份/大小/摘要；`.sha256`；归档与内部 `release.json`；暂存摘要；带摘要的帮助进程计划；安装后版本；服务恢复。

生产策略拒绝通过网络降级。降级只能通过本机已验证的备份完成；`--allow-downgrade` 只会与显式的 `--development-signature` 测试策略同时生效。

## 官方平台范围

正式更新清单有意只包含 `windows-x86_64` 与 `linux-x86_64` 可安装资产。macOS 保留源码构建和 CI 兼容性，但没有官方 GitHub Release 包、签名清单条目、自动更新路径、Developer ID 或公证门禁。本模型提及 launchd 只是在描述源码兼容性，不代表受支持的官方发行通道。

## 密钥管理与轮换

- 生产私钥只能通过 CI Secret `LINKLAKE_RELEASE_SIGNING_KEY_B64` 提供；不得生成或保存在仓库、构建产物、日志或更新器状态中。
- `security/release-keys.json` 只登记公钥、用途和语义版本有效区间。
- 已提交的 RFC 8032 私钥夹具明确标记为开发用途，生产策略会拒绝它。
- 轮换时先加入带未来 `not_before_version` 的新公钥，发布一个同时信任新旧公钥的更新器，再切换 CI Secret，最后为旧公钥设置 `not_after_version`。
- 紧急撤销需要另一把仍可信的生产密钥；如果没有，必须通过独立的已认证通道分发新的信任根。

当前已登记适用于 `1.0.0` 发布线的生产公钥 `linklake-production-2026-08-a`。标签 Release 仍会在签名步骤关闭失败，除非 `LINKLAKE_RELEASE_SIGNING_KEY_ID` 选择该已登记生产密钥，且 `LINKLAKE_RELEASE_SIGNING_KEY_B64` 提供与其匹配的私钥种子。禁止使用开发夹具绕过这一安全阻断。

## 替换与回滚不变量

- 客户端操作只替换选定可执行文件。服务端操作必须显式提供数据目录；已注册服务会先将该参数与服务配置中的 `LINKLAKE_DATA_DIR` 规范化比较，任何快照或替换前必须完全一致。旧二进制在活动数据目录外创建 SQLite 快照；候选程序在隔离副本上真实预演迁移；候选服务接管前的失败会先恢复已认证的快照，再恢复旧二进制。配置、证书、日志和托管状态不在替换集合中。
- 传入和被替换的可执行文件都只在目标父目录内重命名。
- 只有服务确实引用目标可执行文件时才控制服务。原先停止的服务保持停止；原先运行的服务必须稳定恢复运行。
- Manager 将完整的暂存与已安装目录树摘要绑定进帮助进程计划，在安装目录同级复制暂存载荷并验证复制后的目录树，然后在目标卷内切换目录。Flutter 必须传入自身 PID，并在收到 `requires_manager_exit=true` 后退出；帮助进程在触碰安装目录前等待该精确进程退出，并受固定超时限制。
- 每个计划都有 UUID 操作目录、持久化活动标记和日志、更新锁以及 SHA-256 绑定。服务端计划、活动标记、日志、备份元数据和快照元数据还会使用仅保存在实际服务数据目录中的随机密钥做 HMAC-SHA-256 认证。Windows 状态目录会应用受保护 DACL，并拒绝 UNC、verbatim 和设备路径。服务端快照还绑定操作 ID、计划摘要、源 schema/迁移台账、回滚二进制和候选迁移契约。
- 任一摘要、版本、重命名、迁移预演或候选服务接管前的失败都会尝试自动恢复并记录最终 JSON 状态。服务端自动回滚会先恢复数据库、验证源 schema/迁移台账，然后才恢复旧二进制。如果候选服务可能已经接收写入，LinkLake 会有意保留已认证标记并要求人工恢复，而不会恢复旧快照导致这些写入丢失。`linklake-server update recover --yes --data-dir <路径>` 会认证标记并遵循同一规则。
- 手动跨越 schema 或迁移台账边界回滚默认关闭失败；只有同时提供 `--restore-database-snapshot`、`--confirm-data-loss` 和 `--yes` 才允许执行。

## 稳定接口

客户端提供 `check-update`、`update download/apply/status/rollback`、隐藏帮助命令以及 `--version`/`--version-json`。服务端提供相同命令和额外的 `update recover`；服务端 `apply`、`rollback`、`recover` 都要求显式数据目录，避免二进制与 SQLite 状态脱节。

Manager 使用：

```text
linklake-client manager-update download --current-version <semver>
linklake-client manager-update apply --install-dir <dir> --manager-pid <pid> --yes
linklake-client manager-update status
linklake-client manager-update rollback --install-dir <dir> --manager-pid <pid> --yes
```

成功命令返回 JSON。`apply` 和 `rollback` 返回 `schema_version=2`、帮助进程 PID、Manager PID、状态路径、退出截止时间和 `requires_manager_exit=true`。UI 只有在成功解析响应后才退出，随后轮询 `status`，直到得到 `succeeded`、`rolled_back` 或 `failed`。机器可读契约位于 `docs/manager-update-json-schema.json`；Flutter 的底层适配器位于 `apps/linklake_manager/lib/update_protocol.dart`。

冲突或不安全条件全部关闭失败：暂存或已安装目录树摘要变化、Release 版本或平台变化、未知安装目录、把更新器 PID 伪装成 Manager PID、Manager 退出超时、目录仍被锁定、同卷重命名失败或切换后验证失败。任何操作都不会修改 Manager 载荷内外的环境文件、SQLite 数据库、ACME 状态、证书或日志。
