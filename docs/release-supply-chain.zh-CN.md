# 发布供应链安全

LinkLake 正式发布使用相互独立的证据链：SHA-256 旁车文件、Windows Authenticode、macOS Developer ID 与 Apple 公证、Linux OpenPGP 分离签名、GHCR 镜像的 OCI SBOM/provenance 与 Cosign keyless 签名、GitHub 文件证明，以及更新器自己的 Ed25519 发布清单。任一必需证据失败都会关闭发布。

## 发布顺序

1. 同一标签提交上的完整 CI、安全扫描以及 Windows、Linux、macOS 打包任务并行执行；任一门禁失败都会阻止后续发布。
2. Windows 包内所有 EXE/DLL 使用固定指纹的 Authenticode 证书和 RFC 3161 时间戳；PFX 密码只进入 PowerShell `SecureString`，不会传给 SignTool 参数。macOS 核心二进制和 Manager `.app` 使用 Developer ID、hardened runtime、App Store Connect API 公证，Manager 还必须成功装订票据。Linux 的 tar.gz、DEB 和 RPM 使用运行时注入的 OpenPGP 私钥生成 `.asc`，随后仅凭公开密钥与固定指纹再次验证。
3. 三个平台签名全部成功后，容器任务才把固定标签和提交标签推送到 GHCR。Buildx 同时附加 OCI SBOM/provenance；GitHub 创建镜像 provenance；Cosign 使用 GitHub OIDC 对不可变摘要做 keyless 签名并立即按工作流身份验证。
4. 发布汇总任务合并资产后，先重新验证 Linux OpenPGP、全部 `.sha256`、平台集合、版本、重复名称、符号链接与篡改，再允许生成发布证据。
5. 固定版本的 Syft 逐个扫描每个 ZIP、tar.gz、DEB 和 RPM，生成一对一的 SPDX 2.x 详细 SBOM；`scripts/prepare-release-attestations.mjs` 再生成排序稳定的发布主体清单与集合 SBOM。
6. `linklake-release-sign` 从 CI Secret 读取生产 Ed25519 种子，生成并立即验证 `linklake-release-manifest-v1.json` 与分离签名。平台签名、SBOM、容器证据不会被误解析为更新器安装资产。
7. GitHub 文件 provenance、SBOM 证明、Ed25519 校验和此前所有平台/镜像门禁全部成功后，才创建或更新 GitHub Release。

## 正式发布 Secret

正式 `v*` 标签需要以下 GitHub Actions Secrets；缺失、格式错误、证书或密钥与固定指纹不一致都会关闭失败：

| 平台 | Secret | 用途 |
| --- | --- | --- |
| Windows | `LINKLAKE_WINDOWS_SIGNING_PFX_B64` | Base64 编码的 Authenticode PFX |
| Windows | `LINKLAKE_WINDOWS_SIGNING_PFX_PASSWORD` | PFX 密码 |
| Windows | `LINKLAKE_WINDOWS_SIGNING_CERT_SHA256` | 证书 DER 的固定 SHA-256 指纹 |
| macOS | `LINKLAKE_MACOS_SIGNING_CERT_P12_B64` | Base64 编码的 Developer ID Application P12 |
| macOS | `LINKLAKE_MACOS_SIGNING_CERT_PASSWORD` | P12 密码 |
| macOS | `LINKLAKE_MACOS_SIGNING_IDENTITY` | `Developer ID Application: ...` 身份名称 |
| macOS | `LINKLAKE_MACOS_SIGNING_CERT_SHA256` | Developer ID 证书固定 SHA-256 指纹 |
| macOS | `LINKLAKE_APPLE_API_KEY_P8_B64` | App Store Connect API 私钥 |
| macOS | `LINKLAKE_APPLE_API_KEY_ID` | 10 位 API Key ID |
| macOS | `LINKLAKE_APPLE_API_ISSUER_ID` | API Issuer UUID |
| Linux | `LINKLAKE_LINUX_GPG_PRIVATE_KEY_B64` | Base64 编码的 OpenPGP 私钥导出 |
| Linux | `LINKLAKE_LINUX_GPG_PASSPHRASE` | OpenPGP 私钥口令，通过标准输入交给 GPG |
| Linux | `LINKLAKE_LINUX_GPG_FINGERPRINT` | 固定 40 位主密钥指纹 |
| 更新器 | `LINKLAKE_RELEASE_SIGNING_KEY_B64` | 生产 Ed25519 种子 |
| 更新器 | `LINKLAKE_RELEASE_SIGNING_KEY_ID` | 已登记生产公钥的 key ID |

仓库不生成或提交任何生产私钥。当前仍只有 development Ed25519 公钥；在离线生成生产密钥、提交对应公钥并配置上述 Secrets 前，正式标签按设计不能发布。

## 工作流边界

- 所有 `uses:` 都固定到完整的 40 位提交 SHA；版本号只作为旁注，不能作为可变执行引用。
- checkout 统一设置 `persist-credentials: false`。
- 正式发布只使用 `actions/cache/restore`，不会从具有写权限的任务保存缓存。
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

GHCR 镜像必须按发布证据中的 `image@sha256:...` 使用，并验证工作流身份对应的 Cosign 证书。Windows 可用 `Get-AuthenticodeSignature`，macOS 可用 `codesign --verify`、`spctl --assess` 和 `xcrun stapler validate` 检查原生信任链。

LinkLake 内置更新器还会验证 Ed25519 清单、资产名称、平台、大小、摘要、归档路径、内部 `release.json`、安装后版本及服务恢复结果。平台签名、GitHub 证明和 LinkLake 更新信任根相互补充，不能互相替代。

## 本地门禁

```sh
node scripts/check-workflow-hardening.mjs
node --test tests/release-attestations.test.mjs tests/macos-signing-contract.test.mjs
sh tests/linux-signing-contract.sh
node scripts/check-security-exceptions.mjs
```

真实 SBOM 和 GitHub OIDC 证明只能在正式 GitHub Actions 标签任务中生成；本地测试负责验证资产集合、摘要、SPDX 合同和工作流权限/顺序。
