# 真实 PostgreSQL Traffic 验收入口

状态（2026-09-12）：已编译并在独立本地 PostgreSQL 16.15 上通过，结果位于 `logs/dev/pg-ha-traffic-ea232ceccf8444db9f27265bcdcca7a0/result.json`。覆盖范围和限制见下文。

## 集成

在 `crates/linklake-server/src/main.rs` 中注册：

```rust
#[cfg(test)]
mod real_postgres_traffic_tests;
```

不要删除测试的 `#[ignore]`。默认 cargo test 不应自行连接任何数据库。

## 执行

依赖 Rust 工具链、Docker 和可获取的 PostgreSQL 镜像；脚本不安装依赖或改全局环境。

```powershell
pwsh -NoProfile -File tests/postgres-ha-traffic.ps1 -RunVerification

# 使用本地portable PostgreSQL与已编译测试程序，无需Docker或再次启动Cargo。
pwsh -NoProfile -File tests/postgres-ha-traffic.ps1 -RunVerification -PostgresBinDir '<absolute-pg-bin-directory>' -TestBinaryPath '<absolute-compiled-server-test.exe>'
```

可用 `-PostgresImage` 指定已审核镜像标签或摘要，用 `-TimeoutSeconds` 指定60–3600秒总测试超时。脚本仅创建自己的随机名容器，端口仅绑定127.0.0.1，数据库名以 `linklake_ha_test_` 开头。连接信息仅传给测试子进程，不打印URI。不接受外部生产连接作为替代。

`-PostgresBinDir` 改用日志目录下的独立 pgdata，通过 pg_ctl 启停且不注册服务。`-TestBinaryPath` 直接执行命名 ignored 测试；省略时调用 Cargo，但不覆盖 `CARGO_TARGET_DIR`。也可用 `-DisposablePostgresUrl` 连接明确隔离的新空库，参数仅接受 `linklake@127.0.0.1` 与 `linklake_ha_test_` 前缀库名，不关闭该外部实例。

脚本会编译并运行唯一被过滤的 ignored 测试。若没有真正执行指定测试、缺少最终证据标记或任何断言失败，即使 cargo 返回0也判定失败。结束只清理该脚本创建的容器，保留 `logs/dev/pg-ha-traffic-<uuid>/` 的 Rust输出、PostgreSQL日志、spool文件和成功时的result.json。

## 覆盖及限制

真实数据库及生产Rust store/coordinator接口覆盖：

- 两套HaRuntime与独立PostgreSQL连接池，检查pg_backend_pid不同。
- 48并发连接争抢12/min共享配额；窗口到期与数据库时钟回拨保守处理。
- Fleet事务内put回滚后配置与速率窗口均保持原值。
- 48次同UUID并发上传、未知客户端确认后重放、载荷冲突拒绝。
- pending已计入配额；应用pending前后不双计；多连接增量不丢更新；完整u64及饱和。
- 实际文件SQLite spool关闭重开；共享提交后本机未ack重放；meter最终Drop及worker关闭排空。
- PostgreSQL中的Leader租约失效、新Leader接管；旧Leader拒绝直接写入但有效member可卸载计量；member失效后上传不留下事件行。
- 损坏共享JSON返回错误；来源CIDR拒绝；删除控制规则保留日账历史。

SQL只用于结果旁证及可控故障注入，授权/计量/上传/接管调用真实实现。

此测试有两个HaRuntime但只有一个Rust测试进程，不能代替真实两个服务进程的发布、网络中断和宿主机故障E2E。它也不证明Fleet八类资源交换、证书密钥轮换或数据迁移完成；分别运行主线Fleet验收和 `tests/storage-maintenance-postgres.ps1`（待对应代理交付）。不得把本套通过扩大为完整HA或发布验收通过。
