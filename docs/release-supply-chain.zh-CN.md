# 发布供应链安全

LinkLake 正式发布只提供 Windows 与 Linux 官方二进制。按 `v1.0.0` 的个人开源发布策略，Windows 软件包有意未签名，Windows 可能显示“未知发布者”或 SmartScreen 警告。这不取消完整性和来源证据：只能从官方 GitHub Release 获取软件包，并验证 SHA-256 旁车文件、GitHub 文件证明和更新器的 Ed25519 发布清单；Linux 还必须验证 OpenPGP 分离签名。GHCR 镜像的 OCI SBOM/provenance 与 Cosign keyless 签名仍是强制门禁。macOS 保留源码与 CI 兼容性，但不提供官方二进制、更新清单资产、自动更新通道、Developer ID 或公证门禁。

每个语义版本预发布标签（包括 `v1.0.0-rc.1`、`v1.0.0-beta.1` 和 `v1.0.0-preview.1`）都会作为 GitHub 预发布版发布，并继续强制使用生产 Ed25519 更新信任根、Linux OpenPGP 签名、GitHub Attestation 与 GHCR Cosign 证据。稳定标签不含语义版本预发布标识（例如 `v1.0.0`）；每个有效标签都会在 Linux 或更新器签名材料缺失、格式错误或无效时关闭失败。官方 Windows 任务始终显式选择 `-WindowsSigningMode none`，不会获得 Windows PFX 凭据。保留的 `-Mode pfx` 后端只供未来经过单独审批的运维流程显式选择；`-Mode cloud` 刻意尚未实现并会关闭失败。工作流会在上传资产前校正已有 Release 的预发布状态；Apple 凭据不属于发布策略。

## 发布顺序

1. 同一标签提交上的完整 CI 与安全扫描先运行；Windows、Linux 官方打包任务并行执行。可复用 CI 仍会构建和测试 macOS 源码兼容性，但不会生成发布资产。
2. Windows 软件包以显式未签名模式构建；该模式发现任何被注入的 PFX 凭据都会拒绝继续。每个标签发布（包括全部语义版本预发布）都会让 Linux 的 tar.gz、DEB 和 RPM 使用运行时注入的 OpenPGP 私钥生成 `.asc`，随后仅凭公开密钥与固定指纹再次验证。
3. 两个官方打包任务都成功后，容器任务才把固定标签和提交标签推送到 GHCR。Buildx 同时附加 OCI SBOM/provenance；GitHub 创建镜像 provenance；Cosign 使用 GitHub OIDC 对不可变摘要做 keyless 签名并立即按工作流身份验证。
4. 发布汇总任务合并资产后，先重新验证 Linux OpenPGP、全部 `.sha256`、Windows/Linux 平台集合，并拒绝 macOS 归档、错误版本、重复名称、符号链接与篡改，再允许生成发布证据。
5. 固定版本的 Syft 逐个扫描每个 ZIP、tar.gz、DEB 和 RPM，生成一对一的 SPDX 2.x 详细 SBOM；`scripts/prepare-release-attestations.mjs` 再生成排序稳定的发布主体清单与集合 SBOM。
6. `linklake-release-sign` 从 CI Secret 读取生产 Ed25519 种子，生成并立即验证 `linklake-release-manifest-v1.json` 与分离签名。平台签名、SBOM、容器证据不会被误解析为更新器安装资产。
7. GitHub 文件 provenance、SBOM 证明、Ed25519 校验和此前所有平台/镜像门禁全部成功后，才创建或更新 GitHub Release；发布说明会明确披露 Windows 未签名策略。

## 正式发布 Secret

每个有效语义版本标签都需要下表中的 Linux OpenPGP 与更新器 Secrets。Windows PFX Secret 不属于正式发布 Secret 清单：`v1.0.0` 的官方 Windows 任务明确以未签名模式构建。未来如经单独审批而启用 `-Mode pfx` 工作流，才需要 `LINKLAKE_WINDOWS_SIGNING_PFX_B64`、`LINKLAKE_WINDOWS_SIGNING_PFX_PASSWORD` 和 `LINKLAKE_WINDOWS_SIGNING_CERT_SHA256`；当前发布工作流既不会注入也不会要求它们。

| 平台 | Secret | 用途 |
| --- | --- | --- |
| Linux | `LINKLAKE_LINUX_GPG_PRIVATE_KEY_B64` | Base64 编码的 OpenPGP 私钥导出 |
| Linux | `LINKLAKE_LINUX_GPG_PASSPHRASE` | OpenPGP 私钥口令，通过标准输入交给 GPG |
| Linux | `LINKLAKE_LINUX_GPG_FINGERPRINT` | 固定 40 位主密钥指纹 |
| 更新器 | `LINKLAKE_RELEASE_SIGNING_KEY_B64` | 生产 Ed25519 种子 |
| 更新器 | `LINKLAKE_RELEASE_SIGNING_KEY_ID` | 已登记生产公钥的 key ID |

仓库自身不生成或提交任何生产私钥。发布前必须离线生成生产更新签名密钥、提交对应公钥，并配置 Linux 与更新器所需 Secrets。

可选工具 `scripts/generate-linux-release-key.sh` 只能在运维人员控制的离线容器或工作站中使用。它拒绝覆盖已有文件，通过标准输入向 GnuPG 提供口令，使用全新的纯公钥密钥环验证测试签名，并且只写入显式指定的备份目录。`scripts/verify-linux-release-key-backup.sh` 会独立核对加密私钥、口令、公钥和固定指纹。私钥输出必须保存在仓库外，并在配置对应 GitHub Secrets 前完成备份。

## 工作流边界

- 所有 `uses:` 都固定到完整的 40 位提交 SHA；版本号只作为旁注，不能作为可变执行引用。
- checkout 统一设置 `persist-credentials: false`。
- 正式发布只使用 `actions/cache/restore`，不会从具有写权限的任务保存缓存。
- 发布汇总任务只下载名称匹配 `linklake-*` 的产物；CI 证据和 Buildx 调试记录不能进入 `dist` 或 GitHub Release。
- 官方 Windows 任务传入 `-WindowsSigningMode none`，不注入 Windows PFX 凭据；若未签名模式发现这类凭据会拒绝静默签名。可选 PFX 后端必须经显式审批的工作流调用；云签名处于保留状态并关闭失败。
- macOS 源码/CI 产物会在生成 SBOM、Attestation 和更新清单前被明确排除在官方发布集合之外。
- Shell 命令只能读取显式环境变量，禁止把 GitHub expression 直接拼进命令正文。
- 文件证明任务只在 `v*` 标签发布时获得 `id-token: write`、`attestations: write` 和 `artifact-metadata: write`；容器任务另外只获得推送 GHCR 所需的 `packages: write`。
- CI 与安全工作流通过 `workflow_call` 被标签发布复用；普通分支推送仍独立运行 CI，标签不会再触发第二套重复 CI。
- `.github/zizmor.yml` 不保留工作流安全豁免；`scripts/check-workflow-hardening.mjs`、actionlint 和 zizmor 共同守门。

## 下载方验证

先验证发布页提供的 SHA-256，再验证 GitHub 证明：

```sh
sha256sum --check linklake-<version>-linux-x86_64.tar.gz.sha256
gh attestation verify linklake-<version>-linux-x86_64.tar.gz --repo OWNER/REPOSITORY
```

Linux 还应固定核对公钥指纹后验证分离签名：

```sh
gpg --import linklake-linux-release-public-key.asc
gpg --fingerprint <固定的40位指纹>
gpg --verify linklake-<version>-linux-x86_64.tar.gz.asc linklake-<version>-linux-x86_64.tar.gz
```

Windows 用户应预期未签名软件包提示，只从官方 Release 下载，使用 `Get-FileHash -Algorithm SHA256` 与发布的 `.sha256` 旁车文件比对，并使用 `gh attestation verify` 验证 GitHub 文件证明。内置更新器在自动安装前会独立验证生产 Ed25519 清单。这些校验提供完整性和发布来源证据，但不能提供 Authenticode 所提供的操作系统发布者身份。GHCR 镜像必须按发布证据中的 `image@sha256:...` 使用，并验证工作流身份对应的 Cosign 证书。macOS 用户需要从源码构建并遵循 CI/源码验证说明；没有可供核验的官方 macOS 包或原生签名链。

LinkLake 内置更新器还会验证 Ed25519 清单、资产名称、平台、大小、摘要、归档路径、内部 `release.json`、安装后版本及服务恢复结果。正式清单只包含 Windows 与 Linux 可安装资产，因此 macOS 没有兼容的官方资产或自动更新路径。Linux OpenPGP、GitHub 证明和 LinkLake 更新信任根相互补充，不能互相替代；它们也不能替代缺少的 Windows 原生发布者身份。

## 本地门禁

```sh
node scripts/check-workflow-hardening.mjs
node --test tests/release-attestations.test.mjs tests/macos-signing-contract.test.mjs
sh tests/linux-signing-contract.sh
node scripts/check-security-exceptions.mjs
```

真实 SBOM 和 GitHub OIDC 证明只能在正式 GitHub Actions 标签任务中生成；本地测试负责验证资产集合、摘要、SPDX 合同和工作流权限/顺序。
