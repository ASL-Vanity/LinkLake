# 显式 SQLite → PostgreSQL 迁移与回滚

本页适用于 v1.1 的显式维护命令。迁移、幂等重试、原身份与凭据保留、真实证书材料、
完整 u64 流量与回滚资格检查已在隔离 PostgreSQL 中验证。选择发行包时应核对版本，
旧版二进制不包含这些命令。

## 维护前提

- 升级源数据库到本版本支持的 SQLite schema，并完成一次正常的原服务恢复与排空。
  迁移器只读 SQLite，不会替源执行 schema migration 或隐式修复。保留迁移前完整备份。
- 停止唯一 SQLite 服务进程以及所有目标 PostgreSQL 服务副本，暂停自动重启/扩容。
  源 `linklake.sqlite3.lock` 必须存在并能独占取得；不要删除锁文件绕过检查。
- 为全新目标库执行本版本 PostgreSQL schema migration（含导入回执表），不要先启动应用，
  避免自动创建管理员、节点、默认策略或导出来源 ID。目标只允许原始 schema 种子。
- 备份源完整数据目录、SQLite WAL/SHM 所在一致性备份、原启动参数/环境配置、外部凭据引用
  和密钥。Cloudflare/Fleet/SMTP 等环境凭据不会从旧进程内存自动迁移，部署时须另行配置。
- 准备已有的 32 字节目标集群材料密钥文件。Unix 必须禁止 group/other 访问。所有目标副本
  使用相同密钥，并在数据库备份之外单独加密备份；不把密钥正文放在 CLI 参数或日志里。
- 按源部署实际值提供公网端口策略；不能为了通过迁移而把端口范围放宽。
  SQLite 旧内存连接速率窗口不能导出，切流前保持至少 60 秒停流窗口。

## 代码入口与导入过程

维护终端需先安全加载 `LINKLAKE_STORAGE_BACKEND=postgres`、`LINKLAKE_POSTGRES_URL`
和原部署公网端口相关环境变量。以下路径需替换成实际受保护的源目录和材料密钥：

```sh
# 只初始化全新目标，已有业务数据的目标会被拒绝。
linklake-server initialize-postgres

# 先查看摘要，再执行同一份源的导入。
linklake-server migrate-sqlite-to-postgres --data-dir /var/lib/linklake-source --certificate-key-file /secure/certificate.key --all-instances-stopped --preview
linklake-server migrate-sqlite-to-postgres --data-dir /var/lib/linklake-source --certificate-key-file /secure/certificate.key --all-instances-stopped

# 需要切回保留的源时，先检查目标和源都仍与回执一致。
linklake-server verify-sqlite-rollback --data-dir /var/lib/linklake-source --certificate-key-file /secure/certificate.key --all-instances-stopped
```

大快照可显式设置 `--max-snapshot-mib`（默认 512，允许 1–4096）；历史自定义 ACME
directory 可重复传入 `--account-directory URL`。`--preview` 不导入数据。

`storage_migration::source::prepare_sqlite_migration(data_dir, key_file, &options)` 返回持有
源进程锁及只读 SQLite 事务的 `MigrationPlan`。`MigrationSourceOptions` 包含：

- `max_snapshot_bytes: usize`：源快照和暂存目标行各自的上限，调用方建议默认 512 MiB。
  超限明确失败，不截断数据；大库需规划内存后显式调整。
- `account_directories: Vec<String>`：历史自定义 ACME directory URL。当前配置和两个
  Let's Encrypt 标准环境会自动识别；发现其他账户文件时必须提供其目录，不能静默漏迁。
- `public_port_policy: PublicPortPolicy`：源部署实际公网端口范围与保留端口配置。

`plan.preview()` 只返回源指纹、目标密钥指纹与每表导入行数，没有凭据或材料正文。
计划不能写到普通 JSON 日志或临时明文文件。持有计划期间源进程不能启动；维护 CLI 应直接
await 导入，不将借用 SQLite 连接的计划作为需要 `Sync` 的通用后台任务。

`import_sqlite_plan(&storage, &plan)` 在一个 PostgreSQL 事务中：

1. 先设 10 秒锁等待上限，再取得 schema 迁移锁、证书/业务目录共用锁及全部应用表锁。
2. 拒绝有效 HA member/Leader 租约；检查目标所有应用表，仅允许原始 schema 种子。
3. 按外键顺序导入全部计划行，恢复序列下一值，最后同事务写导入回执并提交。
4. 对相同源的重复调用，还要核对回执及实时目标表摘要。原始源指纹不依赖随机密文、
   新 revision 或当前导入时间；目标发生任何变化都拒绝自动覆盖。

源 SQLite/账户/证书文件不修改。旧密码、令牌、Secret 和代理凭据摘要保持原值，
不会生成替代身份或让客户端重新注册。所有错误只输出固定错误码，隐藏底层 SQL/材料详情。

## 覆盖与明确重建的状态

| 类别 | 导入内容 |
| --- | --- |
| 身份 | 管理员、TOTP、会话、管理 API Token、客户端 ID/身份公钥/认证摘要及配置同步状态 |
| 业务策略 | HTTP/SNI/Secret/TCP/UDP/SOCKS5/HTTP Proxy/端口组，原 ID、gRPC TLS 字段、访问/密码摘要及出口限制 |
| 端口 | 从规范化策略及已核对的端口组映射重建静态端口预留；不复制旧实例的活动端口租约 |
| 流量 | 控制规则、完整 u64 日账、已应用事件 UUID、未确认本机 spool；重复 UUID 核对载荷并避免重复计量 |
| Fleet | peers、健康配置/状态、探测事件的共享字段、DNS/目标/切换事件、来源 ID、归属/凭据绑定、原 hash/代际/冲突 |
| 证书 | ACME 配置、TLS 策略、状态、当前有效结构的提交代证书及私钥、可识别目录的历史 ACME 账户 |
| 观测与任务 | 审计、近期/归档指标、告警规则/事件/待通知与计数、已终结更新任务及事件/终结重放摘要 |

PostgreSQL 中不存在 SQLite 对应版本字段的额外探测历史细节（延迟/前后状态等），以及旧证书
历史代与兼容文件，仍由原目录备份保留；迁移不会删除它们。PG 当前运行材料每标识一份。
HTTP/SNI/TLS 的旧 SQLite 没有共享 revision，导入使用源内容决定的 UUIDv8，不改变策略 ID。
证书材料 generation 同样由源证书内容决定，旧磁盘代目录名保留在原备份。

源中有未清理 DNS-01 意图/旧日志、待 DNS 执行计划、签发或续期中状态、正在发送通知、
未终结更新任务、正在应用的 Fleet generation 时拒绝迁移。应先在原服务完成恢复/取消，
再次排空停机；不能将这些需要外部结果确认的任务当作普通历史复制。

HA 成员/Leader/job/端口租约、fencing 序列和目标健康/P2P 发现缓存由新服务重建，
不授予旧实例在目标库中的权限。未知非空 SQLite 表阻止导入，不能悄悄略过新业务表。

已应用流量事件按原 UTC 日导入 `applied=true`，不再次累加日账。未确认 spool 若已存在
同 UUID 已应用事件，只验证载荷；其余按首次导入时间的 UTC 日作为 pending。
原 spool 保留，目标启动后的同 UUID 重放仍依赖共享事件去重，不会重复计费。

## 切流与回滚

确认提交成功后保留源目录，配置所有 PostgreSQL 副本的 URL、同一材料密钥和完整外部启动
配置。先验证管理员登录、原客户端认证、策略一致性、证书加载、流量账务和 Fleet 归属，再切流。
不能同时启动源 SQLite 和目标服务，让同一批客户端接受两套独立控制平面写入。

COMMIT 连接中断可能意味着目标已经提交。保留停机状态，用同一源与密钥重新准备计划、
重新调用导入：回执与实时摘要匹配时返回 `already_imported=true`；不匹配就停止，禁止清空
目标或手工改回执强行重试。回执表不包含自身于 manifest，避免自引用摘要。

`verify_sqlite_rollback(&storage, &plan)` 是不写数据的回滚资格校验：原源指纹、目标密钥指纹
与实时完整目标摘要都须匹配导入回执，且目标没有活动租约。验证成功后，部署层可以保持
目标停机、把后端配置切回保留的 SQLite 原目录并启动原单实例。模块不会删除 PostgreSQL，
也不会替调用方更改服务配置。启动原服务前须释放 `MigrationPlan`，让源进程锁与只读事务退出。

若目标已经接收新数据（包括启动后生成的审计、租约或指标），校验将拒绝自动切回旧快照。
此时需要明确的数据恢复/对账决定，或恢复匹配时间点的完整备份；不能把丢弃新数据描述成
无损回滚。此工具不提供任意运行中 PG 数据反向合并到旧 SQLite 的操作。

## 迁移验收

隔离 PostgreSQL 回归覆盖原身份/凭据、真实 PEM、完整 u64、同源幂等和回滚资格；
可复用 `tests/storage-maintenance-postgres.ps1` 对独立测试库执行验证。
生产迁移应先保存可恢复的源备份，检查预览数量，再核对登录、客户端认证、策略、证书和流量。
未演练的数据库中断或外部服务故障不构成无损恢复保证，按上述回执和指纹流程处理。

## English

The v1.1 maintenance CLI supports explicit SQLite-to-PostgreSQL migration and rollback
eligibility checks. Isolated PostgreSQL regression covers preserved identities and
credentials, real PEM material, full-range u64 traffic, idempotent import and rollback
eligibility. Use binaries matching this documentation; older releases lack these commands.

Stop the SQLite server and all target replicas, disable automatic restarts, retain a
complete source backup and deployment configuration, and prepare a schema-only target.
The tool takes the existing SQLite process lock and a read-only snapshot; it never
migrates or modifies the source schema. Provide the original public-port policy,
historical custom ACME directory URLs, and a protected 32-byte target material key.

The plan preserves identity and credential hashes, business policies, port mappings,
traffic accounting/UUID deduplication, Fleet ownership/generations, certificate/account
materials, supported observation history and terminal update tasks. Runtime leases and
discovery caches are rebuilt. Pending external operations and unknown nonempty source
tables reject migration. Historical certificate generations and SQLite-only probe
details remain in the retained source backup. External environment credentials must
be configured separately on the new deployment.

Import and its receipt commit in one PostgreSQL transaction after locking schema and
application writes and verifying a pristine target. Retries require both the same
source fingerprint and an unchanged live target manifest. Random encryption, generated
revisions and import timestamps do not alter the source fingerprint. A lost COMMIT
response is an unknown outcome, not proof of rollback; retry against the receipt while
all services remain stopped.

The rollback verifier permits switching deployment configuration back to the original
SQLite directory only when source and target remain unchanged. It deletes nothing and
does not change service configuration. Once PostgreSQL has accepted new data, automatic
reversion to the old snapshot is refused; a deliberate backup/reconciliation decision
is required. Running two independent writable control planes is unsupported.
