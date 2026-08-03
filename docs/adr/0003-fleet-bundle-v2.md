# ADR 0003：Fleet Bundle v2 采用版本化、无秘密的期望状态协议

- 状态：接受
- 日期：2026-08-03

## 背景

现有 Fleet 同步只传输 TCP 和 UDP 策略，并以客户端名称和策略名称判断是否已存在。它无法稳定表达端口组、HTTP、SNI、Secret、SOCKS5 和 HTTP Proxy，也无法安全支持后续的更新、删除、原子应用与多云自动故障切换。

同步协议还必须避免把每台服务端独立签发的客户端 token、代理密码、Secret access key、证书私钥或其他秘密混入普通策略 Bundle。

## 决定

LinkLake 使用 `FleetBundleV2` 表达一个来源实例在某一 generation 下的完整期望状态。

顶层固定包含：

- `schema_version = 2`
- `source_instance_id`
- 单调递增的 `generation`
- `generated_unix_seconds`
- 稳定客户端引用 `clients`
- 八类资源 `resources`
- 与资源 ID 绑定的 `traffic_controls`
- `content_sha256`
- `revision`

八类资源为：

1. TCP
2. UDP
3. 端口组
4. HTTP Route
5. SNI Route
6. Secret Tunnel
7. SOCKS5 Proxy
8. HTTP Proxy

每项资源使用来源实例内稳定且非空的 `resource_id`。策略引用客户端时使用跨服务端稳定的 `agent_instance_id`，不使用某一台服务端签发的 `client_id` 或可变名称。

Secret、SOCKS5 和 HTTP Proxy 只携带不含秘密的 `credential_ref`。凭据材料若需要跨节点复制，必须由未来独立、受限且加密的凭据通道处理。

## 规范化与完整性

`content_sha256` 计算时不包含 `content_sha256` 和 `revision` 本身，并执行以下规范化：

- 客户端按 `agent_instance_id` 排序。
- 资源按 `resource_id` 排序。
- 流量控制按 `resource_id` 排序。
- CIDR 转换为规范网络地址并排序。
- UTC 星期集合排序。
- JSON 使用固定结构字段顺序和紧凑 UTF-8 表示。

`content_sha256` 是 64 位小写十六进制字符串。`revision` 固定为 `sha256:<content_sha256>`。因此集合输入顺序不会改变 revision，而任何受保护字段变化都会改变 revision。

## 解码与校验

`FleetBundleV2` 在 serde 反序列化阶段完成验证，拒绝：

- 不等于 2 的 schema version。
- 空或 nil 的来源、客户端、资源和凭据引用 ID。
- generation 或生成时间为 0。
- 重复客户端、资源或流量控制 ID。
- 引用不存在客户端或资源的记录。
- 空名称、非法主机名、目标地址、端口、用户名、端口表达式、CIDR、调度窗口和限额。
- 非规范端口表达式、目标池和主机字段。
- 无效、被篡改或不一致的摘要与 revision。
- 任何模型未声明的字段。

最后一项使 `client_token`、`password`、`access_key`、`private_key` 等字段在顶层、客户端或资源内部都会被 serde 拒绝。

## 安全边界

Fleet Bundle 是策略期望状态，不是秘密封装格式。

以下内容不得进入 Bundle：

- 客户端 enrollment token 和 client token。
- Secret access key 及其可直接使用的等价物。
- SOCKS5、HTTP Proxy 的明文密码。
- TLS/ACME 账户私钥、证书私钥。
- 管理员密码、会话 Cookie、TOTP secret 和管理 API token。

`credential_ref` 不能用于直接认证，也不能反推出对应凭据。

## 后果

- 后续 Fleet reconcile 可以用 `(source_instance_id, resource_id)` 建立稳定 ownership。
- generation 可用于拒绝旧状态和重放。
- revision 可用于幂等同步、审计和能力比较。
- 八类策略和流量控制共享一份协议合同。
- 凭据复制必须另行设计，不能通过临时向 Bundle 增加密码字段实现。
- 当前版本只定义协议和校验，不实现数据库迁移、策略应用、服务端 API 或 UI。
