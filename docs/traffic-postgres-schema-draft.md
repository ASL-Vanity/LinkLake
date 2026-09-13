# Traffic PostgreSQL 与持久账务历史设计草案（2026-09-11）

本文保留 v1.1 集成期间的共享流量控制、持久账务和运行时接线设计，供开发参考，
不作为当前集成进度或验证结果记录。实际操作以[使用说明](user-guide.zh-CN.md)、
[存储迁移](storage-migration.md)和[PostgreSQL 升级与恢复](postgres-upgrades.md)为准。
schema、接口和迁移序号以当前代码为准，不应单独执行下列草案 SQL。

## 迁移 SQL 设计记录

草案中的迁移名称为 `shared_traffic_control_and_usage_events`：

```sql
CREATE TABLE IF NOT EXISTS linklake_traffic_controls (
    kind TEXT NOT NULL CHECK(kind IN ('tcp','udp','http','sni','secret','socks5','http_proxy','port_group')),
    policy_id TEXT NOT NULL,
    settings JSONB NOT NULL CHECK(octet_length(settings::text)<=16384),
    updated_unix_seconds BIGINT NOT NULL CHECK(updated_unix_seconds>=0),
    PRIMARY KEY(kind,policy_id)
);
CREATE TABLE IF NOT EXISTS linklake_traffic_daily_usage (
    kind TEXT NOT NULL CHECK(kind IN ('tcp','udp','http','sni','secret','socks5','http_proxy','port_group')),
    policy_id TEXT NOT NULL,
    utc_day BIGINT NOT NULL CHECK(utc_day>=0),
    bytes NUMERIC(20,0) NOT NULL CHECK(bytes BETWEEN 0 AND 18446744073709551615),
    PRIMARY KEY(kind,policy_id,utc_day)
);
CREATE TABLE IF NOT EXISTS linklake_traffic_connection_windows (
    kind TEXT NOT NULL CHECK(kind IN ('tcp','udp','http','sni','secret','socks5','http_proxy','port_group')),
    policy_id TEXT NOT NULL,
    unix_second BIGINT NOT NULL CHECK(unix_second>=0),
    connections INTEGER NOT NULL CHECK(connections BETWEEN 1 AND 1000000),
    PRIMARY KEY(kind,policy_id,unix_second)
);
CREATE TABLE IF NOT EXISTS linklake_traffic_usage_events (
    event_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK(kind IN ('tcp','udp','http','sni','secret','socks5','http_proxy','port_group')),
    policy_id TEXT NOT NULL,
    bytes NUMERIC(20,0) NOT NULL CHECK(bytes BETWEEN 0 AND 18446744073709551615),
    utc_day BIGINT NOT NULL CHECK(utc_day>=0),
    received_unix_seconds BIGINT NOT NULL CHECK(received_unix_seconds>=0),
    applied BOOLEAN NOT NULL
);
CREATE INDEX IF NOT EXISTS linklake_traffic_usage_events_pending ON linklake_traffic_usage_events(received_unix_seconds,event_id) WHERE NOT applied;
CREATE INDEX IF NOT EXISTS linklake_traffic_usage_events_pending_policy ON linklake_traffic_usage_events(kind,policy_id,utc_day) WHERE NOT applied;
```

结构期望：

```rust
TableExpectation { name: "linklake_traffic_controls", primary_key: &["kind","policy_id"], columns: &[
    required("kind","text"), required("policy_id","text"), required("settings","jsonb"), required("updated_unix_seconds","int8"),
]},
TableExpectation { name: "linklake_traffic_daily_usage", primary_key: &["kind","policy_id","utc_day"], columns: &[
    required("kind","text"), required("policy_id","text"), required("utc_day","int8"), required("bytes","numeric"),
]},
TableExpectation { name: "linklake_traffic_connection_windows", primary_key: &["kind","policy_id","unix_second"], columns: &[
    required("kind","text"), required("policy_id","text"), required("unix_second","int8"), required("connections","int4"),
]},
TableExpectation { name: "linklake_traffic_usage_events", primary_key: &["event_id"], columns: &[
    required("event_id","text"), required("kind","text"), required("policy_id","text"), required("bytes","numeric"),
    required("utc_day","int8"), required("received_unix_seconds","int8"), required("applied","bool"),
]},
```

## 核心接口与语义

- 接线设计：main注册 `mod traffic_control_store;`，AppState用 `TrafficControlStore::open(&database,storage.clone(),runtime.clone())`。
- 原get/upsert/delete/authorize/record_bytes/reset_runtime_state均异步；保留原now参数用于SQLite，PG忽略本机时钟，用DB clock_timestamp。
- PG公开upsert/delete持FleetPolicyTransaction，同事务拒绝已托管资源；`ManagedTrafficPolicy` 可anyhow downcast映射409。存储失败需500/503，不能统一映射invalid_traffic_control/400，更不能放行。
- 来源CIDR拒绝优先；计划支持跨午夜；配额达到阈值拒绝新连接，保持原语义：尚未记账的活动传输不预留配额，不保证正在传输的连接在阈值精确中止。
- 每策略锁稳定派生于kind+UUID。配置锁顺序Fleet全局→Leader/member共享行→策略；热路径只Leader/member→策略，不争用全局目录锁。
- 60秒滑动窗口为每秒计数桶，删除 `unix_second <= now-60` 再同事务SUM/预留；双实例/重启共享；时钟回拨保留未来桶保守拒绝。正常最多60个活跃秒桶/策略，每桶最多1000000。
- 配置更改只清理该策略连接窗口；delete保留日配额/事件账务。PG reset_runtime_state没有本机状态可清，不删除无关策略窗口。
- `transaction_list(guard)`、`transaction_snapshot(guard,kind,id)`、`transaction_put(guard,kind,id,UpsertTrafficControl)`、`transaction_delete(guard,kind,id)`都借用同一个FleetPolicyTransaction。调用方提交前再assert_current；不另开数据库事务。
- shared JSON读取要求完整字段集、类型、规范化CIDR/weekday等，缺失enabled/allowlist不会通过serde默认值悄悄放行。

## 幂等事件及旧Leader接管

- `TrafficUsageEvent { event_id,kind,policy_id,bytes }`，event_id必须非nil。`record_usage_event(&event,now)`同事务去重+日账累计；同UUID不同载荷拒绝。
- `record_bytes`为兼容调用每次产生新UUID；发生未知提交结果后不能再次调用record_bytes盲重试。可重试工作必须保留同一event_id。
- `enqueue_usage_event(&event,now)`：PG只验证当前member/incarnation有效（非Leader也可卸载最后账务），同事务存为pending；SQLite直接幂等入账。重试不改变第一次接收事件的DB UTC日。
- `drain_pending_usage()`：当前Leader每次最多64条，同事务event行锁→策略锁→累加日账→applied，提交前fence。Follower返回0；旧Leader上传的shared pending可被新Leader接管。
- get/authorize计算 `min(u64::MAX,已应用日账 + shared pending)`，避免pending尚未drain时低估配额。更新applied与累加同事务，读快照不会双计。
- 日账NUMERIC支持完整u64，累加饱和。事件账本不自动清理，防迟到重试复计；将来保留期必须配合所有spool的确认水位，不能简单按时间删除去重行。

## HTTP Drop与受监督worker接线

- `traffic_control::usage_spool::TrafficUsageSpool::open(&database)` 使用原本机Database，专属连接PRAGMA synchronous=FULL；生产须确认 `is_persistent()`，内存DB不能声称持久恢复。
- AppState持有spool。所有流量结算优先 `spool.record(kind,id,bytes)`；尤其 `http_tunnel.rs` 的 `ConnectionActivity::drop` 只能同步落spool，禁止tokio::spawn。返回错误设置粘性fault；故障处理要求停止新转发并暴露错误，不能只记录warning后继续。
- 所有新连接在授权前 `spool.ensure_admission_ready()`；如pending非零，先await pump后重试，再调用store.authorize。这样未上传增量不能继续按旧共享配额放行。磁盘故障不能靠后续成功清除。
- 独立supervised任务调用 `spool.run(&store,stop,drain_timeout)`，每250ms pump，每轮网络上限10s，停止时显式drain。pump只在目标提交确认后删除本机事件；未知提交/崩溃后同UUID重试。
- 关闭顺序：停止新连接→关闭/等待连接与Body释放(产生最终事件)→通知spool worker stop并等待drain→最后停止HA成员心跳。不得在Body仍活动时宣布排空完成。
- drain成功意味着本机outbox已上传/SQLite已入账；PG shared pending仍可能等待Leader合并，但已进入配额且有共享持久记录。超时保留原记录并返回错误。
- 同步Drop磁盘失败无法异步补救，必须报告且阻断新流量；仍活动连接若进程直接崩溃，未产生的最终计数仍需运行时周期checkpoint。宿主机永久丢失且尚未上传的本机spool不能靠PG恢复。不能宣传零丢账或严格在途字节预算。
- 接线文件：tcp_tunnel.rs、udp_tunnel.rs、http_tunnel.rs、http_proxy_tunnel.rs、sni_tunnel.rs、secret_tunnel.rs、socks5_tunnel.rs；普通async结束/周期记账也应统一进入spool，避免旧Leader最后结果被fence后直接丢弃。

## SQLite迁移注意

- 新SQLite `traffic_usage_events(event_id,kind,policy_id,bytes TEXT,utc_day)`为已应用去重账本；迁移为PG applied=true，不能再次加日账。
- 新SQLite `traffic_usage_spool(sequence,event_id,kind,policy_id,bytes TEXT)`为未确认outbox；迁移为PG pending或保留原spool后重放，必须使用同UUID去重。
- `traffic_daily_usage.bytes`及`traffic_controls.daily_quota_bytes`在<=i64::MAX时继续INTEGER，超出时用8字节大端BLOB避免SQLite INTEGER affinity转REAL。导出使用公开 `traffic_control::decode_sqlite_u64(ValueRef)`；所有历史正常INTEGER兼容。迁移工具必须支持该编码，不能row.get::<u64>直接读BLOB。
- 活动进程中的旧SQLite内存连接窗口不能凭空导出；迁移应明确停流与60秒冷却窗口或按已暂停状态处理，不能宣称保留未持久的旧窗口。

## 当时列出的验证范围

草案列出的覆盖点包括：不完整/损坏JSON、CIDR/时间计划/配额优先级、完整u64与饱和、UUID重试/冲突/跨日、spool重开/远端确认后本机ack前中断/失败保留/排空超时。
需要实际PG双实例覆盖的场景包括：原子限速、窗口边界/回拨、并发计量不丢增量、pending转applied不双计、旧Leader上传/新Leader接管、失效member拒绝、共享连接故障拒绝授权、配置/Fleet交换并发、事务取消和未知提交、关闭顺序、周期checkpoint与迁移。本节仅保存验证范围，不记录执行结果；rustfmt/静态检查不等于功能验证。

## 运行时接线设计补充

- 新 `traffic_usage_meter.rs`：活动meter持久checkpoint；成功公网读写逐次累计，64KiB阈值、spool worker每250ms、最后Drop三条路径均入同一spool。checkpoint提交不明重试保留同事件UUID。
- `tcp_tunnel/udp_tunnel/socks5_tunnel/http_proxy_tunnel/secret_tunnel/sni_tunnel/http_tunnel.rs` 已切 `authorize_traffic(...).await`；统一10秒存储等待上限，等待前后核对public-work/精确Leader token，故障不放行。
- TCP/Secret/SOCKS5 CONNECT/BIND使用MeteredIo封装公网侧；UDP/SOCKS5 UDP逐包add并由worker周期checkpoint；SNI包含已读ClientHello；HTTP请求/响应Body、h2c和其他Upgrade均纳入meter。旧最终record_bytes已移除，避免双计；错误/取消时的部分已传字节也会在Drop checkpoint。
- HTTP proxy实际公网wire读写被计入，包含请求/响应头；业务统计仍用原协议计数。不会存储HTTP正文、凭据或头字段内容。
- AppState精确新增 `traffic_usage_spool: Arc<traffic_control::usage_spool::TrafficUsageSpool>`。主程序调用run仍使用相同接口。`pump`先checkpoint活动meters，包括空闲长连接。
- 停机先调用 `close_admission()`，它和meter注册共用互斥边界；随后停止所有公开转发，等待 `active_meter_count()` 归零，最后stop worker/drain并停止HA heartbeat。计数使用显式AtomicUsize，最后Drop完成checkpoint后才decrement，不依赖Weak strong_count，防止先观察0后才落最终事件的竞态。关闭后新建空meter不登记且禁止IO。
- HTTP2获取backend/请求响应、HTTP1请求响应/后台driver、SNI ClientHello写、Secret Connected写均加入route stop取消；原HTTP Body/Upgrade、SNI/Secret配对/传输取消机制保留。SOCKS5 UDP后台读取任务增加同步abort-on-drop，错误退出不遗留读取任务。
- 主程序启动/关闭生命周期接线及相关测试以当前代码为准。当时列出的回归点包括活动meter空闲checkpoint/最终Drop不双计、部分传输Drop、关闭后禁止IO、关闭与晚注册计数；本段不记录执行结果。
