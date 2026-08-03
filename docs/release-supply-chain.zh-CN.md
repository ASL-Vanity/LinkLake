# 发布供应链安全

LinkLake 正式发布使用三层独立证据：平台打包脚本生成的 SHA-256 旁车文件、GitHub/Sigstore 资产证明，以及 LinkLake 更新器自己的 Ed25519 发布清单。任一层失败都会在上传 GitHub Release 前关闭失败。

## 发布顺序

1. Windows、Linux、macOS 分别构建并验证核心包和 Manager 包；Linux 额外生成 DEB 与 RPM。
2. 发布任务合并资产并重新计算所有 `.sha256`，拒绝缺失平台、错误版本、重复文件名、符号链接或被篡改的包。
3. 固定版本的 Syft 逐个扫描每个 ZIP、tar.gz、DEB 和 RPM，生成一对一的 SPDX 2.x 详细 SBOM；脚本校验格式、大小和非空软件包集合，并为每份 SBOM 生成 SHA-256。
4. `scripts/prepare-release-attestations.mjs` 将详细 SBOM 通过 SPDX `externalDocumentRefs` 连接成发布集合文档，并生成排序稳定的 `linklake-<version>-release-subjects.sha256`。build provenance 与 SBOM 证明必须引用这同一份主体清单。
5. `linklake-release-sign` 从 CI secret 读取生产 Ed25519 种子，生成并立即验证 `linklake-release-manifest-v1.json` 与分离签名。私钥不会进入命令行、仓库、制品或日志。
6. 两项 GitHub 证明和 Ed25519 校验全部成功后，才创建或更新 GitHub Release。

## 工作流边界

- 所有 `uses:` 都固定到完整的 40 位提交 SHA；版本号只作为旁注，不能作为可变执行引用。
- checkout 统一设置 `persist-credentials: false`。
- 正式发布只使用 `actions/cache/restore`，不会从具有写权限的任务保存缓存。
- Shell 命令只能读取显式环境变量，禁止把 GitHub expression 直接拼进命令正文。
- GitHub 证明任务只在 `v*` 标签发布时获得 `id-token: write`、`attestations: write` 和 `artifact-metadata: write`。
- `.github/zizmor.yml` 不保留工作流安全豁免；`scripts/check-workflow-hardening.mjs`、actionlint 和 zizmor 共同守门。

## 下载方验证

先验证发布页提供的 SHA-256，再验证 GitHub 证明：

```sh
sha256sum --check linklake-<version>-linux-x86_64.tar.gz.sha256
gh attestation verify linklake-<version>-linux-x86_64.tar.gz --repo OWNER/REPOSITORY
```

LinkLake 内置更新器还会验证 Ed25519 清单、资产名称、平台、大小、摘要、归档路径、内部 `release.json`、安装后版本及服务恢复结果。GitHub 证明不能代替 LinkLake 自己的更新信任根，二者必须同时成立。

## 本地门禁

```sh
node scripts/check-workflow-hardening.mjs
node --test tests/release-attestations.test.mjs
node scripts/check-security-exceptions.mjs
```

真实 SBOM 和 GitHub OIDC 证明只能在正式 GitHub Actions 标签任务中生成；本地测试负责验证资产集合、摘要、SPDX 合同和工作流权限/顺序。
