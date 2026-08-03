# LinkLake Security Policy / 安全策略

## Supported versions / 支持范围

LinkLake is still in prerelease development. Security fixes are provided only for the latest published release and the current default branch. Older releases, forks, unofficial packages, and locally modified builds are not covered.

LinkLake 仍处于预发布阶段。安全修复仅面向最新公开版本和当前默认分支；旧版本、派生仓库、非官方安装包和本地修改构建不在支持范围内。

| Version / 版本 | Security updates / 安全更新 |
| --- | --- |
| Latest published release / 最新公开版本 | Yes / 是 |
| Default branch / 默认分支 | Best effort / 尽力支持 |
| Older releases / 更早版本 | No / 否 |

## Reporting a vulnerability / 报告漏洞

Please report suspected vulnerabilities privately through [GitHub Security Advisories](https://github.com/ASL-Vanity/LinkLake/security/advisories/new). Do not open a public issue, discussion, or pull request before maintainers have coordinated disclosure and a fix.

请通过 [GitHub Security Advisories](https://github.com/ASL-Vanity/LinkLake/security/advisories/new) 私下报告疑似漏洞。在维护者完成修复与披露协调前，请勿创建公开 Issue、Discussion 或 Pull Request。

Include the affected version or commit, deployment model, reproducible steps, security impact, and the smallest proof needed to validate the issue. Never submit production tokens, passwords, private keys, personal data, complete database dumps, or unrelated customer traffic. Replace sensitive values with redacted test fixtures.

报告应包含受影响版本或提交、部署方式、复现步骤、安全影响和验证所需的最小证明。不得提交生产令牌、密码、私钥、个人数据、完整数据库备份或无关用户流量；请使用脱敏测试数据替代。

## Response targets / 响应目标

These are operational targets, not contractual guarantees:

- Initial acknowledgement within 3 business days.
- Initial triage and severity assessment within 7 business days.
- A status update or remediation plan within 14 business days after triage.
- Coordinated disclosure timing depends on severity, affected users, and release readiness.

以上是运维目标而非合同保证：3 个工作日内确认收到，7 个工作日内完成初步分级，并在分级后 14 个工作日内提供状态或修复计划。公开披露时间取决于严重程度、影响范围和版本准备情况。

The project does not currently promise a bug bounty or monetary reward. / 项目目前不承诺漏洞赏金或其他经济奖励。

## Safe-harbor boundaries / 善意研究边界

Good-faith research must use systems you own or are explicitly authorized to test, minimize data access, stop after obtaining sufficient proof, and avoid service disruption. Social engineering, credential stuffing, denial of service, persistence, destructive changes, broad internet scanning, and retaining or sharing third-party data are out of scope.

善意研究必须仅针对自有或明确授权的系统，尽量减少数据访问，在取得足够证明后立即停止，并避免影响服务。社会工程、撞库、拒绝服务、持久化、破坏性修改、大范围公网扫描，以及保存或传播第三方数据均不在授权范围内。

If testing could affect other users or production availability, contact the maintainers first and wait for written authorization. Compliance with applicable law remains the researcher's responsibility.

若测试可能影响其他用户或生产可用性，请先联系维护者并等待书面授权。研究者仍需自行遵守适用法律。
