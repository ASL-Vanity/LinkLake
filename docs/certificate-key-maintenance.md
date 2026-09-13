# 证书材料密钥维护 / Certificate material key maintenance

本页适用于 v1.1 的证书材料密钥轮换命令。多批次证书和账户的正反轮换、活动实例拒绝、
坏密文触发整体回滚已在隔离 PostgreSQL 中验证。数据库连接中断后的处理仍应遵循下文
指纹核对流程，不能把一次命令报错理解为事务一定没有提交。

## 范围与备份

`LINKLAKE_CERTIFICATE_KEY_FILE` 指向独立的 32 字节原始二进制文件。Unix 必须禁止
group/other 访问，例如 `0600`；不要使用十六进制或 base64 文本作为文件内容。
PostgreSQL 中的证书私钥和 ACME 账户凭据依赖此密钥。数据库备份不能替代密钥备份。

将旧密钥和新密钥分别保存在受控、加密的备份中，备份数据库并记录对应密钥指纹。
限制备份读取权限。不要将密钥提交 Git、放进工单或粘贴到日志。备份数据库包含其他
认证和配置数据，按完整服务数据保护，不只按公开证书保护。

## 轮换顺序

1. 安排维护窗口，停止所有 LinkLake 服务端副本及自动重启、自动扩容控制。
   先完成流量排空，再确认进程已退出；过期租约不能证明旧进程已经停止。
2. 保留完整数据库备份、原密钥和原部署配置。独立准备符合文件权限要求的新密钥。
   不覆盖原密钥文件，也不先替换运行部署使用的 Kubernetes Secret。
3. 在已配置 PostgreSQL 环境变量的维护进程中运行下面命令：
   此入口只支持 PostgreSQL，不执行 schema migration，不启动 HA runtime。
   若有仍有效的成员或 Leader 租约，会拒绝操作；等待正常到期，不手动删除租约绕过。
4. 入口在一个事务中获取证书目录共用锁、阻止成员登记，并锁定全部材料表。
   精确验证旧密钥指纹，逐批解密证书私钥和账户凭据，使用原有认证上下文重新加密，
   最后更新密钥绑定并提交。任一密文损坏、旧密钥错误、加密或 SQL 失败均不会提交部分轮换。
   证书正文、generation、业务配置和原更新时间保持不变。
5. 收到成功摘要后，所有副本统一配置新密钥；Kubernetes 需要更新受控 Secret 并重新创建
   Pod，使 init 容器重新复制文件。确认全部副本指向新密钥后，再恢复服务和流量。
6. 验证各副本启动、证书加载、现有 HTTPS、账户读取以及后续续期。保留旧密钥和备份
   至维护验收与备份保留期结束，不因轮换命令成功立即销毁恢复材料。

模块只返回两枚密钥指纹和重加密计数，不返回域名、账户、路径或材料正文。它也不修改
文件系统上的部署配置、Kubernetes Secret 或本地证书缓存。磁盘/PVC 备份和缓存仍需保护。

```sh
linklake-server rotate-certificate-key --previous-key-file /secure/old-key --next-key-file /secure/new-key --all-instances-stopped
```

The command requires the existing current PostgreSQL schema and never starts an HA member or applies migrations.

## 失败与回滚

- `certificate_rotation_active_instances`：仍有有效租约。核实服务已停止，等待正常到期。
- `certificate_rotation_wrong_previous_key`：旧密钥不匹配当前数据库绑定。核对备份和目标库，
  不重新初始化绑定，也不使用 SQL 直接改指纹。
- `certificate_rotation_invalid_material`：至少一项密文或身份上下文无效。整体回滚，保留旧密钥，
  从受控备份调查恢复。不能跳过坏行后将其他记录当作完整轮换发布。
- `certificate_rotation_transaction_failed`：可能是锁超时、SQL 或连接错误。尤其 COMMIT
  响应丢失时，结果可能已经提交，不能假定失败就等于旧密钥仍有效。

连接中断后，在副本仍停止的前提下重新连接，通过只读查询核对绑定：

```sql
SELECT fingerprint FROM linklake_certificate_key_binding WHERE singleton_id = 1;
```

绑定是旧指纹时继续使用旧配置；绑定是新指纹时按已提交处理，配置新密钥。
任何其他结果都应停止恢复流程并核对备份/目标库，禁止盲目重试或手改绑定。

完整回退可选择在所有副本停止时，以新密钥作为 previous、旧密钥作为 next，再执行同一
事务入口；也可恢复轮换前的完整数据库备份和相匹配的旧密钥。后者会丢弃备份之后的数据，
应与业务恢复目标一起决定。不能只换回旧密钥文件而保留新密文数据库。

## 维护验收

隔离 PostgreSQL 回归已覆盖超过单批的证书与账户正反轮换、材料内容保留、活动实例拒绝，
以及后续批次坏密文触发整体回滚。维护完成后仍应核对当前部署的密钥指纹、证书加载和账户
读取；实际 HTTPS 和续期还取决于当前证书、DNS 与 ACME 服务。连接中断按前述流程确认提交结果。

## English

The v1.1 CLI rotates shared certificate material keys. Isolated PostgreSQL regression
covers multi-batch forward/reverse rotation, active-instance rejection and atomic rollback
when a later batch contains invalid ciphertext. A lost COMMIT response still requires
the fingerprint checks below; it does not prove that the transaction rolled back.

Keep the original 32-byte binary key, the replacement key, and a matching full
database backup in access-controlled encrypted storage. Unix key files must deny
group/other access. A database backup alone cannot recover encrypted private keys
or ACME account credentials.

Stop every server replica, disable automatic restarts/scaling, and confirm the
processes have exited before invoking the rotation entry point. Expired leases
are not proof that processes have stopped. The entry point rejects live member or
Leader leases, serializes with certificate writes, blocks new member registration,
validates the exact old fingerprint, and re-encrypts all private keys and account
credentials in one transaction. It preserves authenticated contexts, certificate
contents, generations, timestamps and policy configuration. It does not initialize
an absent binding, generate keys, change deployment files or delete local caches.

After a confirmed commit, configure the new key on every replica before restarting.
For Helm, replace the controlled Secret and recreate Pods so the init container
copies the new key. Verify certificate loading, existing HTTPS, account reads and
renewal before completing maintenance. Protect local caches and PVC backups too.

An error during COMMIT may leave the outcome unknown. While replicas remain stopped,
read `linklake_certificate_key_binding.fingerprint` and compare it with the old and
new fingerprints. Do not retry blindly or change the binding manually. Rollback
requires either a reverse transaction using new-to-old keys or restoration of the
complete matching database/key backup. Replacing only the key file is not rollback.

Release validation must cover multi-batch certificate/account rotation, wrong keys,
corrupt later rows with full rollback, concurrent writes and membership, cancellation,
commit-response loss, reverse rotation, and real two-instance TLS/renewal recovery.
