# LinkLake Helm Chart

该 Chart 面向当前单进程 SQLite 架构，强制 `replicaCount=1`，并使用 `Deployment/Recreate` 防止滚动更新期间出现两个服务端同时打开数据库。它不会创建或保存明文密码、令牌和私钥；部署前必须准备认证 Secret 与两个 TLS Secret。

```bash
kubectl create secret generic linklake-auth \
  --from-literal=enrollment-token='replace-me' \
  --from-literal=admin-username='admin' \
  --from-literal=admin-password='replace-me'

kubectl create secret tls linklake-management-tls --cert=management.crt --key=management.key
kubectl create secret tls linklake-control-tls --cert=control.crt --key=control.key

helm upgrade --install linklake deploy/helm/linklake \
  --set auth.existingSecret=linklake-auth \
  --set tls.managementSecret=linklake-management-tls \
  --set tls.controlSecret=linklake-control-tls
```

`/startupz`、`/readyz`、`/livez` 分别用于启动、就绪和存活探针。管理员调用 `POST /api/v1/lifecycle/drain` 后，Pod 会立刻从 Service 就绪端点中摘除，但已有连接继续运行；维护流程应轮询 `GET /api/v1/lifecycle`，确认 `drained=true` 后再删除 Pod。

Kubernetes Service 不支持端口范围。业务策略使用的每个公网 TCP/UDP 端口必须分别加入 `services.data.publicTcpPorts` 或 `services.data.publicUdpPorts`，同时在云负载均衡器、安全组和 NetworkPolicy 中放行。管理 Service 默认是 `ClusterIP`，不建议直接暴露到公网。

启用 `networkPolicy.enabled=true` 后，数据面端口仍接受集群内来源；管理端口只有在 `networkPolicy.managementFrom` 明确配置允许来源时才会开放。空列表采用拒绝管理入口的安全默认值，例如只允许带有 `app: linklake-operator` 标签的 Pod：

```yaml
networkPolicy:
  enabled: true
  managementFrom:
    - podSelector:
        matchLabels:
          app: linklake-operator
```

PVC 应由底层存储提供快照或备份。该 Chart 的 PDB 默认 `minAvailable=1`，会阻止自愿驱逐唯一 Pod；计划维护前应先执行 drain，再临时调整/删除 PDB。当前 SQLite 单写者架构不支持通过增加副本获得高可用。
