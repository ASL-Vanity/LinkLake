# LinkLake 第三方软件声明 / Third-Party Notices

LinkLake 本身采用 Apache License 2.0。LinkLake 使用的第三方组件仍分别受其原始许可证约束；本文件不修改、替代或扩展这些许可证。

LinkLake itself is licensed under the Apache License 2.0. Third-party components remain governed by their original licenses. This notice does not replace or modify those terms.

## Rust 依赖 / Rust dependencies

锁定 Rust 工作区的组件、版本、许可证文本与版权声明完整收录在 [`THIRD_PARTY_LICENSES.html`](THIRD_PARTY_LICENSES.html)。该文件通过以下命令生成：

```text
node scripts/generate-third-party-licenses.mjs
```

发布前必须重新生成该文件并确认工作树没有差异。Rust 依赖中包含通过 Iroh 引入的 MPL-2.0 组件；MPL 覆盖的组件仍按 MPL-2.0 提供，其源代码位置和许可证文本均列在生成文件中。

## Flutter Manager 依赖 / Flutter Manager dependencies

Flutter Release 构建会在应用资源中生成完整第三方许可证清单。下表列出 `apps/linklake_manager/pubspec.lock` 当前锁定的托管依赖；Flutter SDK、`flutter_test` 与 `sky_engine` 的声明由 Flutter 生成的应用许可证清单覆盖。

| Package | Version | License |
|---|---:|---|
| async | 2.13.1 | BSD-3-Clause |
| boolean_selector | 2.1.2 | BSD-3-Clause |
| characters | 1.4.1 | BSD-3-Clause |
| clock | 1.1.2 | Apache-2.0 |
| collection | 1.19.1 | BSD-3-Clause |
| cupertino_icons | 1.0.9 | MIT |
| fake_async | 1.3.3 | Apache-2.0 |
| flutter_lints | 6.0.0 | BSD-3-Clause |
| leak_tracker | 11.0.2 | BSD-3-Clause |
| leak_tracker_flutter_testing | 3.0.10 | BSD-3-Clause |
| leak_tracker_testing | 3.0.2 | BSD-3-Clause |
| lints | 6.1.0 | BSD-3-Clause |
| matcher | 0.12.19 | BSD-3-Clause |
| material_color_utilities | 0.13.0 | Apache-2.0 |
| meta | 1.18.0 | BSD-3-Clause |
| path | 1.9.1 | BSD-3-Clause |
| source_span | 1.10.2 | BSD-3-Clause |
| stack_trace | 1.12.1 | BSD-3-Clause |
| stream_channel | 2.1.4 | BSD-3-Clause |
| string_scanner | 1.4.1 | BSD-3-Clause |
| term_glyph | 1.2.2 | BSD-3-Clause |
| test_api | 0.7.11 | BSD-3-Clause |
| vector_math | 2.2.0 | BSD-3-Clause |
| vm_service | 15.2.0 | BSD-3-Clause |

## Web UI 与品牌资产 / Web UI and brand assets

当前 Web UI 未引入外部 JavaScript、CSS、字体或图标库。`assets/brand/linklake` 中的 LinkLake 品牌资产属于项目自有内容；其品牌使用限制见 [`TRADEMARKS.md`](TRADEMARKS.md)。

## 维护要求 / Maintenance

- 修改 `Cargo.lock` 后重新生成 `THIRD_PARTY_LICENSES.html`。
- 修改 `pubspec.lock` 后核对本表及 Flutter 生成的许可证清单。
- 发布包必须同时包含 `LICENSE`、`NOTICE`、本文件、`THIRD_PARTY_LICENSES.html` 和 `TRADEMARKS.md`。
- 如本文件与第三方组件附带的原始许可证冲突，以原始许可证为准。
