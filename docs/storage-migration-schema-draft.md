# 显式存储迁移回执表历史设计草案

本文保留 v1.1 集成期间的回执表设计，供理解迁移机制参考，不是当前进度或验证结果记录。
实际操作以[使用说明](user-guide.zh-CN.md)和[存储迁移指南](storage-migration.md)为准；
schema 与迁移序号以代码中的版本化迁移为准，不应单独执行下列草案 SQL。

回执用于标记一次完整的原子导入，支持提交响应丢失后的结果判定。
回执不包含凭据、域名或数据正文。

```sql
CREATE TABLE IF NOT EXISTS linklake_storage_migration_receipts (
    singleton_id INTEGER PRIMARY KEY CHECK(singleton_id=1),
    source_fingerprint TEXT NOT NULL CHECK(source_fingerprint ~ '^[0-9a-f]{64}$'),
    key_fingerprint TEXT NOT NULL CHECK(key_fingerprint ~ '^[0-9a-f]{64}$'),
    manifest JSONB NOT NULL CHECK(jsonb_typeof(manifest)='object'),
    committed_unix_seconds BIGINT NOT NULL CHECK(committed_unix_seconds>=0)
);
```

结构期望：singleton_id integer / source_fingerprint text / key_fingerprint text /
manifest jsonb / committed_unix_seconds bigint，全部 NOT NULL，PK singleton_id。

manifest 仅记录每个受保护目标表的行数及内容摘要。命中相同源指纹后还必须比较实时目标
manifest，不能仅凭旧回执宣称目标仍等于导入快照。源或目标变化均应拒绝自动合并或覆盖。
