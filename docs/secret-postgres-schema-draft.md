# Secret PostgreSQL 集成草案（2026-09-11）

已实现但未编译和功能验证。此文件是集成说明，不是已执行迁移。

## 新迁移 SQL

由集成者分配新版本，既有迁移 SQL 不变。迁移名称建议 `shared_secret_tunnel_catalog`。

```sql
CREATE TABLE IF NOT EXISTS linklake_secret_tunnel_policies (
    id TEXT PRIMARY KEY,
    provider_client_id TEXT NOT NULL,
    name TEXT NOT NULL CHECK(octet_length(name) BETWEEN 1 AND 80),
    access_key_hash TEXT NOT NULL UNIQUE CHECK(access_key_hash ~ '^[0-9a-f]{64}$'),
    policy JSONB NOT NULL CHECK(octet_length(policy::text)<=16384),
    UNIQUE(provider_client_id,name),
    CHECK (policy->>'id' IS NOT NULL AND policy->>'id'=id),
    CHECK (policy->>'provider_client_id' IS NOT NULL AND policy->>'provider_client_id'=provider_client_id),
    CHECK (policy->>'name' IS NOT NULL AND policy->>'name'=name),
    CHECK (NOT (policy ? 'access_key') AND NOT (policy ? 'access_key_hash'))
);
```

结构验证期望：

```rust
TableExpectation {
    name: "linklake_secret_tunnel_policies",
    primary_key: &["id"],
    columns: &[
        required("id", "text"),
        required("provider_client_id", "text"),
        required("name", "text"),
        required("access_key_hash", "text"),
        required("policy", "jsonb"),
    ],
},
```

## 接线点

- main.rs 注册 `mod secret_tunnel_store;`；AppState 改为 `SecretTunnelStore`，初始化调用 `SecretTunnelStore::open(&database, coordination_storage.clone(), ha_runtime.clone())`。
- 原目录所有 8 类调用 create/update/list/policy_by_id/set_enabled/delete/provider_runtime_policy/access_runtime_policy 改 `.await`；API 错误映射 `ManagedPolicy => 409`，`Storage(_) | Database(_) => 500`。
- PG runtime 只查询共享表，不回退 SQLite；获取策略后的本机注册依然需主程序 Leader/public-work 二次核验。
- API CRUD 保持原返回类型；create 仍仅返回一次明文 key；update/enabled/Fleet put 保留 access_key_hash。`SecretTunnelPolicy` 增加 Deserialize/deny_unknown_fields，用共用旧校验函数拒绝共享损坏数据。
- 凭据哈希是独立列；snapshot 故意不实现 Debug 或 Serialize，公开 list 不返回 hash。SQL 错误对外只有稳定 error code。
- `secret_tunnel_catalog::postgres` 暴露 `transaction_list/snapshot/insert/update/put/delete`，所有接口必须传 `&FleetPolicyTransaction`，内部 assert_current，调用者最后提交前仍需 assert_current。guard 必须有 `transaction()` 访问器。
- `transaction_list` 返回公开 policy；`transaction_snapshot` 返回 `{ policy, access_key_hash }`。Fleet 原子交换前保存 snapshot，删除后 `transaction_put(guard, &policy, &saved_hash)`；已有记录仅当 hash 相同才允许 put，避免配置应用暗中换 key。
- `ensure_name_available` 只读 helper 接受原始 Transaction；公开写入在共享锁内调用，Fleet 可在删除交换资源后调用，唯一约束为最后保障。
- 原始内部 insert/update/delete 无归属拒绝（Fleet 自身要改托管资源），仅公开 CRUD 在共享事务内拒绝被 Fleet 托管的策略。

## 待统一验证

已定义、未执行：共享行损坏/非规范字段/额外私密字段拒绝；精确 provider/name/target；visitor 限制、禁用、无限制 visitor；稳定错误码。
仍需集成后的真实双实例 PG：创建唯一性、旧 Leader 拒写、托管 409、跨实例凭据授权、更新保留密钥、存储故障拒绝授权、Fleet 原子交换、SQLite→PG 迁移保留哈希。SQLite 写入仍遵循既有本机工作流，未冒充 PG HA 已接通。
