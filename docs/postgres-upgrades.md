# PostgreSQL 集群升级与恢复 / PostgreSQL cluster upgrades and recovery

## 中文

PostgreSQL 模式把共享身份、策略、证书材料及业务状态放在 PostgreSQL；每个实例的持久数据目录仍保存独立实例身份、待确认流量账务和更新暂存。备份 `linklake.sqlite3` 不能备份整个集群。

服务在 PostgreSQL 数据目录写入 `postgres-storage.marker`。单机 SQLite 的检查、备份、恢复及更新 helper 会同时检查配置与此标记；Windows 单机安装器也拒绝使用 SQLite 快照升级 PostgreSQL 服务。不要删除标记来绕过检查。标记不包含连接串或密钥。远程客户端更新继续使用共享任务目录，不受这一单机服务端维护限制影响。

容器和 Helm 仍可部署 PostgreSQL 模式。升级前记录当前镜像摘要、chart/values、共享数据库 schema 和迁移账本，以及所有副本的配置和持久卷。证书的 32 字节材料密钥必须单独加密保管，数据库备份不包含这把解密密钥；Cloudflare 等外部凭据也需要自己的恢复方案。

集群升级步骤：

1. 在隔离环境恢复一次 PostgreSQL 备份，用候选版本验证迁移、策略、证书及客户端连接。使用 PostgreSQL 提供的备份/PITR 工具，并确认备份的实际可恢复性；仅生成文件不等于恢复验证。
2. 确认候选版本和旧版本对目标 schema 的读写兼容范围。只有确认兼容的迁移才能在旧、新副本并存时滚动执行；未经确认的 schema 变更应安排维护窗口、停止所有副本和共享数据库写入，再备份 PostgreSQL 与各实例持久目录。
3. 部署候选镜像。Helm HA 使用 StatefulSet；可按 `ha.updateStrategy.partition` 保留未升级副本并逐步放行，但该机制本身不能证明数据库向后兼容。
4. 核对 schema/迁移账本、Leader/Follower 状态、管理与控制连接、业务转发、证书解密及流量账务。继续观察接管和连接重建，再完成其余副本升级。

若候选进程从未启动，且已确认数据库未改变，可以恢复旧运行文件。候选进程启动后可能已提交迁移或业务写入：不要直接 `helm rollback`、回退镜像或恢复一个节点的 SQLite 来代表集群回滚。优先部署兼容当前 schema 的修复版本；必须恢复数据库时，先停止所有写入者，明确确认会丢失的备份后数据，在隔离库验证恢复后，将匹配的数据库、材料密钥、实例持久状态及兼容二进制作为一个恢复计划执行。恢复旧数据库还需要检查 DNS 等外部状态是否需要重新协调。

Linux 原生包在候选服务开始启动后会保留候选运行文件与 `/var/lib/linklake/package-backup/pending` 的旧文件；失败时不再自动降级二进制。此目录只是运行文件/服务状态备份，并不是数据库备份。恢复前先检查实际数据库状态；不要删除 `candidate-started` 标记来强行触发旧二进制回滚。

## English

PostgreSQL mode stores shared identities, policies, certificate material and business state in PostgreSQL. Each instance still needs its own persistent data directory for instance identity, unacknowledged traffic accounting and update staging. A backup of `linklake.sqlite3` is not a cluster backup.

The server writes `postgres-storage.marker` in a PostgreSQL instance's data directory. Standalone SQLite inspection, backup, restore and update helpers check both configuration and this marker. The Windows standalone installer also refuses to upgrade PostgreSQL through its SQLite snapshot protocol. Do not remove the marker to bypass the check. It contains no credentials. Shared remote client update tasks remain available; this restriction concerns standalone server maintenance.

Container and Helm deployments remain supported. Before upgrading, record image digests, chart/values, database schema and migration ledger, instance configuration and persistent volumes. Keep the 32-byte certificate material key in a separate encrypted backup: the database backup does not contain its decryption key. External credentials need their own recovery plan.

1. Restore a PostgreSQL backup in an isolated environment and exercise candidate migrations, policies, certificate loading and client connections. Use PostgreSQL backup/PITR tooling and verify restoration, rather than merely checking that a backup file exists.
2. Establish the old and new versions' read/write compatibility with the target schema. Roll only compatible migrations while versions coexist. For an unproven schema transition, schedule maintenance, stop every replica and database writer, then back up PostgreSQL and each instance's persistent directory.
3. Deploy the candidate image. Helm HA uses a StatefulSet; `ha.updateStrategy.partition` can stage replica upgrades, but it does not establish schema compatibility.
4. Verify the schema/ledger, leadership, management/control connections, forwarding, certificate decryption and traffic accounting. Observe failover and connection recovery before completing the rollout.

Old runtime files can be restored before candidate startup only after confirming the database is unchanged. Once a candidate starts, it may already have committed migrations or application writes. An image rollback, `helm rollback`, or one instance's SQLite restore cannot roll back the cluster database. Prefer a repair compatible with the current schema. If database recovery is necessary, stop every writer, explicitly account for post-backup data loss, validate the backup in isolation, and restore matching database state, certificate key, persistent instance state and compatible binaries as one recovery plan. Reconcile external state such as DNS afterward.

Linux native packages preserve candidate runtime files and the previous files under `/var/lib/linklake/package-backup/pending` after candidate activation starts; activation failure no longer triggers an automatic binary downgrade. That directory backs up runtime files and service state, not the database. Inspect the database before recovery, and do not remove `candidate-started` to force an old binary rollback.
