# ADR 0004：共享 SQLite 数据库与显式迁移账本

- 状态：接受
- 日期：2026-08-03

## 背景

服务端各 Catalog 过去直接打开同一个 `linklake.sqlite3`，分别设置 PRAGMA 并在构造函数中执行建表或 `ALTER TABLE`。这种方式虽然能够保存数据，但存在四个问题：

- 不同连接的外键、忙等待和同步策略可能不一致；
- 无法在八类策略之间建立统一的事务入口；
- 两个 LinkLake 服务端进程可能误用同一数据目录；
- `PRAGMA user_version` 只记录数字，无法证明该版本实际执行了哪一份迁移。

## 决定

新增共享 `Database` 句柄，并由服务端启动流程只创建一次。所有 Catalog 都从该句柄创建连接，统一启用：

- 文件数据库使用 WAL；
- `foreign_keys=ON`；
- `synchronous=NORMAL`；
- 5 秒 busy timeout；
- `trusted_schema=OFF`；
- 内存模式使用带 keeper 的共享 URI 数据库。

文件数据库同时持有操作系统级独占锁。锁文件可以保留在磁盘，但进程退出或崩溃后锁会由操作系统释放；因此不依赖删除一个可能残留的 PID 文件来判断服务是否存活。

`Database::with_transaction` 为 Fleet reconcile、备份元数据和后续跨 Catalog 操作提供单连接 `BEGIN IMMEDIATE` 事务。Catalog 仍可保留自己的长连接，但不得再自行选择数据库路径或连接参数。

Schema v10 建立 `schema_migrations` 账本，记录版本、名称、迁移 SQL 的 SHA-256 和应用时间。已达到 v10 的数据库如果缺少账本或校验和不匹配，服务端必须失败关闭。v0-v9 被视为既有兼容基线；升级到 v10 前仍执行完整在线备份，从 v10 开始的新迁移必须作为独立、版本化 SQL 加入账本，不能继续只修改 Catalog 构造函数。

## 后果

- 同一数据目录只能被一个服务端进程作为主数据库使用；SQLite 文件不能放在 NFS/SMB 上供多个实例共同写入。
- 联邦式多云节点继续各自拥有本地 SQLite；真正共享控制面的 HA 需要 PostgreSQL、实例租约和端口所有权，不在本 ADR 中伪装实现。
- 后续抽取 `PolicyService` 时，八类资源的 preview、创建、更新、启停和删除可以在一个事务内完成，运行时变更必须在数据库提交成功后再应用。
