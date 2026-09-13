# PostgreSQL 迁移、密钥轮换和 Fleet 实库验收

状态（2026-09-12）：已编译并在独立本地 PostgreSQL 16.15 上通过，结果位于 `logs/dev/pg-maintenance-16437db1b79d4a94b9554d33209a2286/result.json`。这只证明下列断言，不等同于完整发布验收通过。

## 运行

需要已有 Rust 工具链与 Docker Linux 引擎，或已核对来源的本地 PostgreSQL 二进制目录。脚本不安装依赖、不注册服务或修复 Docker 配置。

```powershell
pwsh -NoProfile -File tests/storage-maintenance-postgres.ps1 -RunVerification

# 复用已编译测试程序和本地portable PostgreSQL，不启动Cargo或Docker。
pwsh -NoProfile -File tests/storage-maintenance-postgres.ps1 -RunVerification -PostgresBinDir '<absolute-pg-bin-directory>' -TestBinaryPath '<absolute-compiled-server-test.exe>'
```

`main.rs` 必须注册 `#[cfg(test)] mod real_postgres_maintenance_tests;`。测试保留 `#[ignore]`，普通 `cargo test` 不连接数据库。入口只启动一个随机名、随机数据库的临时 PostgreSQL 容器；端口仅发布到 `127.0.0.1`，没有宿主目录挂载或命名卷。连接只传给子进程，不能将实际业务库 URL 传入此脚本。

`-PostgresImage` 可指定镜像标签或摘要，`-TimeoutSeconds` 可设为 60–3600 秒。`-PostgresBinDir` 使用本次目录下的新 pgdata、随机 loopback 端口和测试数据库，结束时由 pg_ctl 关闭，不注册服务。`-TestBinaryPath` 直接执行已编译的测试程序；省略时才运行 Cargo，并保留调用方的 `CARGO_TARGET_DIR`。`-DisposablePostgresUrl` 仅接受使用 linklake 测试用户、127.0.0.1 和 `linklake_ha_test_` 随机库名的新空库；不负责关闭外部实例，不能指向业务数据。

完整输出、仅供测试的新密钥、源 SQLite/PEM 固件及成功回执保留在 `logs/dev/pg-maintenance-<uuid>/`。结束时只关闭脚本创建的数据库实例。脚本同时检查命名测试执行结果及末尾证据标记，拒绝零测试假成功。

## 断言

- 源进程锁冲突、计划持锁、快照超限、未知非空表和未完成签发拒迁。
- 真实只读 SQLite 源经生产迁移入口导入 v22 PostgreSQL；靠后 SQL 故障回滚所有先前写入与回执，锁等待取消不留下导入。
- 重建计划后的同源重试保持源指纹、原凭据摘要、完整 u64 日账/事件和真实 PEM。目标改变拒绝重导及自动回滚，源改变拒绝覆盖已有目标。
- 18 份证书（含迁移 PEM）和 17 个账户跨批轮换；后批证书/账户坏密文回滚全部早期更新，错误旧密钥、同密钥、活动成员、取消路径拒绝写入。
- 正向/反向轮换、旧密钥失效、新密钥可读；证书正文、身份、generation 和时间字段不变。
- 独立连接池和两套 HA runtime 执行八类 Fleet reconcile；TCP/SOCKS 端口原子交换、同代幂等、旧代/错误前提拒绝、远端归属不再导出、后续表故障整体回滚。
- Follower 不能修改目录；数据库 Leader 失效后接管，仍持旧本地 token 的实例被真实数据库 fence 拒写，新 Leader 可以继续下一代。

SQL 仅用于固件、只读旁证和明确故障注入；迁移、轮换、reconcile 和接管均调用生产实现。

## 边界

本套使用两个 HA runtime，但只有一个 Rust 测试进程。尚不能代替真实服务进程终止、网络分区、COMMIT 回包丢失、部署切换、在线 HTTPS/续期、外部 ACME 和生产材料恢复验收。轮换测试账户是独立测试正文，不执行外部账户注册。流量并发/持久 spool 由 `tests/postgres-ha-traffic.ps1` 单独覆盖。

## English

This opt-in suite runs production migration, certificate-key rotation and Fleet reconciliation against a disposable loopback PostgreSQL container. Default tests never connect to a database. It checks source locking, rollback and replay, unchanged credentials and full u64 accounting, real PEM migration, multi-batch rotation with late-row failures, all eight Fleet resource kinds, atomic port swaps and leader fencing. Logs and synthetic fixtures remain under the ignored development log directory; only the container created by the harness is removed.

Two runtime instances share one test process. Process termination, network partitions, lost COMMIT responses, deployment cutover, live HTTPS/renewal and external ACME behavior require separate acceptance tests. Do not interpret this suite as complete release or production recovery certification.
