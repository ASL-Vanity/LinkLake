# PostgreSQL 双服务进程 HTTP 接管验收

状态（2026-09-12）：已在独立 PostgreSQL 16.15、本次构建的 v1.1.0 server/client 上通过。结果位于 `logs/dev/pg-two-process-3d189e28623a490ab5b39feac28200b6/result.json`，旧 Leader fencing token 1，新 Leader token 2；本次数据库及应用进程均已关闭。

脚本只使用已编译的 server/client，不启动 Cargo；必须显式传 `-RunVerification`。

```powershell
pwsh -NoProfile -File tests/postgres-two-process-e2e.ps1 -RunVerification -PostgresBinDir '<absolute-pg-bin-directory>'
```

默认二进制位于 `target/verification-v1/debug/`，可通过 `-ServerPath` 和 `-ClientPath` 指定。省略 `-PostgresBinDir` 时使用隔离 Docker 容器，也可用 `-PostgresImage` 指定镜像。所有数据库、管理、控制、HTTP 和目标监听器仅使用 loopback。服务端有独立数据目录和 OS 进程；数据库和新测试凭据仅存在本次日志目录中。

测试通过同一管理员会话核对两进程的共享客户端、HTTP 策略和 Leader/Follower 状态，验证 Follower 拒写及真实 HTTP 转发。随后终止 Leader 进程，等待真实数据库时钟使租约过期，由 Follower 接管并提高 fencing token。用原客户端 ID/token 连接新 Leader，确认 HTTP 恢复。最后用原数据目录重启旧实例，验证它作为 Follower 读取新策略、继续拒写且不打断新 Leader 转发。

结果和完整进程日志保存在 `logs/dev/pg-two-process-<uuid>/`，成功才写 `result.json`。结束仅关闭本次启动的应用、目标和数据库进程。

边界：客户端控制端点由测试显式切换，不证明自动发现或负载均衡器配置；覆盖 HTTP 转发，不代表全部协议、网络分区、COMMIT 回包丢失、密钥维护或外部 ACME 已验收。

## English

This opt-in harness starts two independent server processes, a disposable PostgreSQL instance, a real HTTP target and a client. It checks shared authentication and policy reads, follower write rejection, real forwarding, leader process termination, lease-expiry takeover, a higher fencing token, reuse of the original client credentials, and the old server restarting as a follower. All listeners bind to loopback. The harness explicitly switches the client's control endpoint; automatic discovery, load-balancer configuration and other protocols require separate acceptance tests.
