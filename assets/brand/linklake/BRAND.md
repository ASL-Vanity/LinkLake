# LinkLake 品牌标志规范

## 标志含义

“双岸”由两枚相向的 L 形几何组成，分别对应 **Link** 与 **Lake**。中央负空间形成贯通两岸的通道，表达本地服务与公网之间的稳定连接。

## 标准颜色

- Lake Cyan：`#0896A6`
- Link Blue：`#3568E8`
- Deep Navy：`#07131F`
- Light Surface：`#F5FAFC`
- Monochrome Dark：`#0B2234`
- Monochrome Light：`#F2FBFC`

WebUI 可以继续使用 `#43D9DD` 作为高亮或光效颜色，但不作为浅色背景上的标准 Logo 主色。

## 使用规则

- 正式字标固定写作 `LinkLake`。
- “管理控制台”等描述属于界面副标题，不并入正式 Logo。
- 图标四周安全留白至少为图形实际高度的 25%。
- 独立图标最低使用尺寸为 16px，常规界面建议不低于 24px。
- 16px、20px、24px、32px 场景优先使用 `linklake-mark-micro.svg`。
- 深色复杂背景使用浅色单色版；浅色复杂背景使用深色单色版。
- 应用图标和 favicon 可以使用专用深色底板，透明母版不得焊死背景。

## 禁止方式

- 禁止拉伸、压缩、旋转或改变两岸比例。
- 禁止缩窄中央通道。
- 禁止添加描边、阴影、发光、立体或复杂渐变。
- 禁止在图标内部加入文字。
- 禁止把两部分任意更换为低对比颜色。
- 禁止放置在无法保证辨识度的杂乱背景上。

## 文件用途

- `linklake-mark.svg`：透明背景标准双色主标。
- `linklake-mark-micro.svg`：小尺寸光学校正版。
- `linklake-mark-mono-dark.svg`：浅色背景单色版。
- `linklake-mark-mono-light.svg`：深色背景单色版。
- `linklake-lockup-on-light.svg`：浅色背景横向字标。
- `linklake-lockup-on-dark.svg`：深色背景横向字标。
- `linklake-app-icon.svg`：常规应用图标母版。
- `linklake-maskable-icon.svg`：Android/PWA maskable 图标母版。
- `favicon.svg`：浏览器 SVG favicon。
