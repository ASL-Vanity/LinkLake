# 为 LinkLake 贡献 / Contributing to LinkLake

感谢你改进 LinkLake。提交代码前请先创建或关联 Issue，说明问题、设计边界和验证方式；安全漏洞请不要公开披露，应通过 GitHub Security Advisory 私下报告。

Thank you for improving LinkLake. Before submitting a substantial change, open or reference an issue describing the problem, design boundary, and verification plan. Report vulnerabilities privately through GitHub Security Advisories rather than a public issue.

## 基本要求 / Requirements

1. 贡献必须是你有权提交的原创作品，或明确标注来源与兼容许可证。
2. 不得复制、翻译或改写许可证不兼容的第三方代码。
3. Rust 代码执行 `cargo fmt --all -- --check`、Clippy 和工作区测试。
4. Flutter 修改执行 `flutter analyze`、`flutter test` 和目标平台 Release 构建。
5. 修改依赖时同步更新第三方许可证文件。
6. 代码注释优先使用简洁中文；公开 API、协议字段和必要术语可保留英文。

## Developer Certificate of Origin

每个提交必须使用 `git commit -s` 添加 `Signed-off-by` 行。这表示贡献者同意 Developer Certificate of Origin 1.1，并确认自己有权按项目许可证提交该贡献。

Every commit must include a `Signed-off-by` line created with `git commit -s`. This certifies that the contributor has the right to submit the contribution under the project license in accordance with Developer Certificate of Origin 1.1.

示例 / Example:

```text
Signed-off-by: Your Name <you@example.com>
```

## 许可证 / License

除非另有明确书面说明，提交到本仓库的贡献将按 Apache License 2.0 授权，并包含在项目现有的版权归属中。提交代码不授予 LinkLake 品牌和商标使用权，相关规则见 `TRADEMARKS.md`。

Unless explicitly agreed otherwise in writing, contributions are licensed under the Apache License 2.0 and included in the existing project attribution. Contributions do not grant rights to LinkLake branding; see `TRADEMARKS.md`.
