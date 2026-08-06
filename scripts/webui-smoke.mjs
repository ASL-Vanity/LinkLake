import { createRequire } from 'node:module';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';

const require = createRequire(import.meta.url);
const { chromium, firefox, webkit } = require('playwright');

const baseUrl = process.env.LINKLAKE_SMOKE_BASE_URL;
const username = process.env.LINKLAKE_SMOKE_USERNAME;
const password = process.env.LINKLAKE_SMOKE_PASSWORD;
const chromePath = process.env.LINKLAKE_SMOKE_CHROME;
const outputDir = process.env.LINKLAKE_SMOKE_OUTPUT;
const browserEngine = process.env.LINKLAKE_SMOKE_BROWSER_ENGINE || 'chromium';
const browserLabel = process.env.LINKLAKE_SMOKE_BROWSER_LABEL || browserEngine;

if (!baseUrl || !username || !password || !outputDir) {
  throw new Error('缺少 LinkLake WebUI 冒烟测试环境变量');
}
if (!['chromium', 'firefox', 'webkit'].includes(browserEngine)) throw new Error(`不支持的浏览器引擎：${browserEngine}`);

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

await mkdir(outputDir, { recursive: true });
const browserType = { chromium, firefox, webkit }[browserEngine];
const launchOptions = { headless: true };
if (chromePath) launchOptions.executablePath = chromePath;
const browser = await browserType.launch(launchOptions);
const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
const page = await context.newPage();
const pageErrors = [];
const consoleErrors = [];
page.on('pageerror', error => pageErrors.push(error.message));
page.on('console', message => { if (message.type() === 'error') consoleErrors.push(message.text()); });

async function waitForWorkspace() {
  await page.locator('#workspace:not(.hidden)').waitFor({ timeout: 15_000 });
  await page.locator('#account-button').waitFor({ state: 'visible' });
}

async function openRoute(hash) {
  await page.evaluate(value => { location.hash = value; }, hash);
  await page.waitForFunction(value => location.hash === value, hash);
}

async function editPolicy(route, editedName) {
  await openRoute(`#/services/${route}`);
  await page.locator('#service-list .service-card').first().waitFor({ timeout: 15_000 });
  await page.locator('#service-list [data-action="edit-policy"]').first().click();
  await page.locator('#policy-drawer:not(.hidden)').waitFor();
  const name = page.locator('#policy-form [name="name"]');
  await name.fill(editedName);
  await page.locator('#drawer-submit').click();
  await page.locator('#policy-drawer').waitFor({ state: 'hidden', timeout: 15_000 });
  await page.waitForFunction(
    expected => document.querySelector('#service-list')?.textContent?.includes(expected),
    editedName,
  );
}

async function loginPage(targetPage, loginUsername, loginPassword) {
  await targetPage.goto(`${baseUrl}/#/overview`, { waitUntil: 'domcontentloaded' });
  await targetPage.locator('#username').fill(loginUsername);
  await targetPage.locator('#password').fill(loginPassword);
  await targetPage.locator('#login button[type="submit"]').click();
  await targetPage.locator('#workspace:not(.hidden)').waitFor({ timeout: 15_000 });
}

async function pageApi(targetPage, url, options = {}) {
  return targetPage.evaluate(async ({ url, options }) => {
    const response = await fetch(url, { ...options, headers: { 'Content-Type': 'application/json', 'X-LinkLake-CSRF': '1', ...(options.headers || {}) } });
    return { status: response.status, body: await response.json().catch(() => null) };
  }, { url, options });
}

function parseRgb(value) {
  const channels = value.match(/[\d.]+/g)?.map(Number);
  if (!channels || channels.length < 3) throw new Error(`无法解析颜色：${value}`);
  return channels.slice(0, 3);
}

function relativeLuminance(value) {
  const channels = parseRgb(value).map(channel => {
    const normalized = channel / 255;
    return normalized <= 0.04045 ? normalized / 12.92 : ((normalized + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2];
}

function contrastRatio(foreground, background) {
  const first = relativeLuminance(foreground);
  const second = relativeLuminance(background);
  return (Math.max(first, second) + 0.05) / (Math.min(first, second) + 0.05);
}

const acceptanceManifest = {
  schemaVersion: 1,
  generatedAt: new Date().toISOString(),
  browser: { engine: browserEngine, label: browserLabel },
  combinations: [],
  preferenceChecks: {},
  switchStress: {},
};

async function captureThemeAcceptance({ palette, scheme, viewportName, viewport }) {
  await page.setViewportSize(viewport);
  await openRoute('#/overview');
  await page.locator('#traffic-chart').waitFor({ state: 'visible' });
  const screenshotName = `theme-${palette}-${scheme}-${viewportName}-${viewport.width}x${viewport.height}.png`;
  const snapshot = await page.evaluate(() => {
    const root = document.documentElement;
    const rootStyle = getComputedStyle(root);
    const panelStyle = getComputedStyle(document.querySelector('.chart-panel'));
    const topbarStyle = getComputedStyle(document.querySelector('.utility-bar'));
    const sidebarStyle = getComputedStyle(document.querySelector('.sidebar'));
    const menuStyle = getComputedStyle(document.querySelector('.popover'));
    const inputStyle = getComputedStyle(document.querySelector('input'));
    const tableHeaderStyle = getComputedStyle(document.querySelector('.data-table th'));
    const bodyStyle = getComputedStyle(document.body);
    const bodyTexture = getComputedStyle(document.body, '::after');
    const probe = document.createElement('span');
    probe.style.cssText = 'position:fixed;left:-10000px;top:-10000px;';
    document.body.append(probe);
    const resolveColor = value => {
      probe.className = '';
      probe.removeAttribute('style');
      probe.style.cssText = `position:fixed;left:-10000px;top:-10000px;color:${value}`;
      return getComputedStyle(probe).color;
    };
    const probeClass = className => {
      probe.removeAttribute('style');
      probe.style.cssText = 'position:fixed;left:-10000px;top:-10000px;';
      probe.className = className;
      const style = getComputedStyle(probe);
      return { color: style.color, background: style.backgroundColor };
    };
    const primaryButton = probeClass('primary-button');
    const dangerButton = probeClass('danger-button');
    const successStatus = probeClass('badge online');
    const warningStatus = probeClass('badge warning');
    const colors = {
      text: resolveColor('var(--text)'),
      background: resolveColor('var(--bg)'),
      card: resolveColor('var(--surface)'),
      statusSurface: resolveColor('var(--surface-3)'),
      danger: resolveColor('var(--danger)'),
      primaryButton,
      dangerButton,
      successStatus,
      warningStatus,
    };
    probe.remove();
    return {
      palette: root.dataset.palette,
      scheme: root.dataset.scheme,
      material: rootStyle.getPropertyValue('--material-name').trim(),
      supports: {
        colorMix: CSS.supports('color', 'color-mix(in srgb, #000 50%, #fff)'),
        backdropFilter: CSS.supports('backdrop-filter', 'blur(1px)') || CSS.supports('-webkit-backdrop-filter', 'blur(1px)'),
        layeredGradient: CSS.supports('background', 'radial-gradient(circle, #000, transparent), linear-gradient(#000, #fff)'),
      },
      viewport: { width: innerWidth, height: innerHeight, deviceScaleFactor: devicePixelRatio },
      overflow: {
        html: document.documentElement.scrollWidth - document.documentElement.clientWidth,
        body: document.body.scrollWidth - document.body.clientWidth,
      },
      styles: {
        bodyColor: bodyStyle.color,
        bodyBackgroundColor: bodyStyle.backgroundColor,
        bodyBackgroundImage: bodyStyle.backgroundImage,
        texture: bodyTexture.backgroundImage,
        cardBackgroundColor: panelStyle.backgroundColor,
        cardBackgroundImage: panelStyle.backgroundImage,
        cardBorder: `${panelStyle.borderWidth} ${panelStyle.borderStyle} ${panelStyle.borderColor}`,
        cardRadius: panelStyle.borderRadius,
        cardShadow: panelStyle.boxShadow,
        cardBackdropFilter: panelStyle.backdropFilter || panelStyle.webkitBackdropFilter,
        topbarBackground: `${topbarStyle.backgroundImage} ${topbarStyle.backgroundColor}`,
        sidebarBackground: `${sidebarStyle.backgroundImage} ${sidebarStyle.backgroundColor}`,
        menuBackground: `${menuStyle.backgroundImage} ${menuStyle.backgroundColor}`,
        inputBackground: `${inputStyle.backgroundImage} ${inputStyle.backgroundColor}`,
        tableHeaderBackground: `${tableHeaderStyle.backgroundImage} ${tableHeaderStyle.backgroundColor}`,
        chartGridDash: rootStyle.getPropertyValue('--chart-grid-dash').trim(),
        chartStrokeWidth: rootStyle.getPropertyValue('--chart-stroke-width').trim(),
        density: rootStyle.getPropertyValue('--density-space').trim(),
        hoverLift: rootStyle.getPropertyValue('--hover-lift').trim(),
      },
      colors,
    };
  });

  assert(snapshot.palette === palette && snapshot.scheme === scheme, `主题组合未正确应用：${palette}/${scheme}`);
  assert(snapshot.overflow.html === 0 && snapshot.overflow.body === 0, `${palette}/${scheme}/${viewportName} 横向溢出：${JSON.stringify(snapshot.overflow)}`);
  const threshold = palette === 'contrast' ? 7 : 4.5;
  const contrastChecks = [
    ['backgroundText', snapshot.colors.text, snapshot.colors.background],
    ['cardText', snapshot.colors.text, snapshot.colors.card],
    ['primaryButton', snapshot.colors.primaryButton.color, snapshot.colors.primaryButton.background],
    ['dangerButton', snapshot.colors.dangerButton.color, snapshot.colors.dangerButton.background],
    ['successStatus', snapshot.colors.successStatus.color, snapshot.colors.successStatus.background],
    ['warningStatus', snapshot.colors.warningStatus.color, snapshot.colors.warningStatus.background],
    ['dangerStatus', snapshot.colors.danger, snapshot.colors.statusSurface],
  ].map(([name, foreground, background]) => ({
    name,
    foreground,
    background,
    ratio: Number(contrastRatio(foreground, background).toFixed(2)),
    threshold,
    passed: contrastRatio(foreground, background) >= threshold,
  }));
  await page.screenshot({ path: path.join(outputDir, screenshotName), fullPage: true });
  acceptanceManifest.combinations.push({ ...snapshot, viewportName, contrastChecks, screenshot: screenshotName });
  return snapshot;
}

try {
  await page.goto(`${baseUrl}/#/overview`, { waitUntil: 'domcontentloaded' });
  assert(await page.locator('link[rel~="icon"]').count() > 0, '页面缺少 favicon');
  assert(await page.locator('#login-shell .login-brand .brand-mark').count() > 0, '登录页缺少品牌 Logo');

  await page.locator('#username').fill(username);
  await page.locator('#password').fill(password);
  await page.locator('#login button[type="submit"]').click();
  await waitForWorkspace();
  assert((await page.locator('#account-name').textContent())?.trim() === username, '账户菜单未显示当前用户名');
  assert(await page.locator('.utility-bar #utility-session').count() === 1, '服务状态和账户工具未放入顶部工具栏');
  await page.locator('#account-button').click();
  assert(await page.locator('#account-menu #account-appearance').count() === 0, '账户菜单仍重复显示外观选项');
  assert(await page.locator('#account-menu #account-language').count() === 0, '账户菜单仍重复显示语言选项');
  await page.locator('#account-button').click();

  // 刷新后必须通过 /auth/me 恢复账户，而不是依赖登录输入框或 localStorage。
  await page.reload({ waitUntil: 'domcontentloaded' });
  await waitForWorkspace();
  assert((await page.locator('#account-name').textContent())?.trim() === username, '刷新后未恢复当前账户');
  acceptanceManifest.preAuthenticationConsoleErrors = [...consoleErrors];
  pageErrors.length = 0;
  consoleErrors.length = 0;

  await page.locator('#global-search').fill('smoke-tcp');
  await page.locator('#global-search-results button').first().waitFor({ timeout: 15_000 });
  assert((await page.locator('#global-search-results').textContent()).includes('smoke-tcp'), '全局搜索没有返回策略');
  await page.locator('#global-search').fill('');

  await openRoute('#/clients');
  assert(await page.locator('#clients-view canvas').count() === 2, '客户端页面缺少状态和平台配置图表');
  assert(await page.locator('#client-insight-kpis .insight-kpi').count() === 5, '客户端状态摘要不是五项');
  assert(await page.locator('#clients-view > .section-heading').count() === 0, '客户端页面仍重复显示页面标题');
  const managedClientRow = page.locator('#clients-list tr').filter({ hasText: 'smoke-client' });
  await managedClientRow.waitFor({ timeout: 15_000 });
  await managedClientRow.getByRole('button', { name: /Edit client|编辑客户端/ }).click();
  await page.locator('#client-group').fill('QA');
  await page.locator('#client-tags').fill('windows, smoke');
  await page.locator('#client-notes').fill('Web UI smoke client');
  await page.locator('#client-form button[type="submit"]').click();
  await page.waitForFunction(() => document.querySelector('#clients-list')?.textContent?.includes('QA'));
  page.once('dialog', dialog => dialog.accept());
  await page.locator('#clients-list tr').filter({ hasText: 'smoke-client' }).getByRole('button', { name: /Rotate token|轮换令牌/ }).click();
  await page.locator('#client-token-modal:not(.hidden)').waitFor();
  assert((await page.locator('#client-token-value').inputValue()).startsWith('llc_'), '轮换后的客户端令牌格式错误');
  await page.locator('#client-token-done').click();

  const unusedClientRow = page.locator('#clients-list tr').filter({ hasText: 'unused-client' });
  await unusedClientRow.getByRole('button', { name: /Revoke|撤销/ }).click();
  await page.waitForFunction(() => document.querySelector('#clients-list')?.textContent?.includes('unused-client'));
  page.once('dialog', dialog => dialog.accept());
  await page.locator('#clients-list tr').filter({ hasText: 'unused-client' }).getByRole('button', { name: /Delete|删除/ }).click();
  await page.waitForFunction(() => !document.querySelector('#clients-list')?.textContent?.includes('unused-client'));

  // 验证五套完整材质语言、明暗模式独立性、系统跟随、降级动效和持久化。
  const palettes = ['lake', 'ocean', 'jade', 'violet', 'contrast'];
  async function chooseAppearance(mode, palette, keepOpen = false) {
    if (await page.locator('#appearance-popover').evaluate(node => node.classList.contains('hidden'))) {
      await page.locator('#appearance-button').click();
    }
    await page.locator(`[data-theme-choice="${mode}"]`).click();
    await page.locator(`[data-palette-choice="${palette}"]`).click();
    if (!keepOpen) await page.locator('#appearance-button').click();
    await page.waitForTimeout(320);
  }

  const acceptanceViewports = {
    desktop: { width: 1920, height: 1080 },
    mobile: { width: 390, height: 844 },
  };
  const visualStyles = [];
  for (const scheme of ['light', 'dark']) {
    for (const palette of palettes) {
      await chooseAppearance(scheme, palette);
      const desktopSnapshot = await captureThemeAcceptance({ palette, scheme, viewportName: 'desktop', viewport: acceptanceViewports.desktop });
      await captureThemeAcceptance({ palette, scheme, viewportName: 'mobile', viewport: acceptanceViewports.mobile });
      if (scheme === 'light') {
        visualStyles.push({
          palette,
          material: desktopSnapshot.material,
          cardBackground: `${desktopSnapshot.styles.cardBackgroundImage}${desktopSnapshot.styles.cardBackgroundColor}`,
          topbarBackground: desktopSnapshot.styles.topbarBackground,
          sidebarBackground: desktopSnapshot.styles.sidebarBackground,
          menuBackground: desktopSnapshot.styles.menuBackground,
          inputBackground: desktopSnapshot.styles.inputBackground,
          tableHeaderBackground: desktopSnapshot.styles.tableHeaderBackground,
          radius: desktopSnapshot.styles.cardRadius,
          border: desktopSnapshot.styles.cardBorder,
          shadow: desktopSnapshot.styles.cardShadow,
          backdropFilter: desktopSnapshot.styles.cardBackdropFilter,
          chartGridDash: desktopSnapshot.styles.chartGridDash,
          chartStrokeWidth: desktopSnapshot.styles.chartStrokeWidth,
        });
      }
    }
  }
  assert(acceptanceManifest.combinations.length === 20, `视觉验收组合数量异常：${acceptanceManifest.combinations.length}`);
  const contrastFailures = acceptanceManifest.combinations.flatMap(item => item.contrastChecks
    .filter(check => !check.passed)
    .map(check => `${item.palette}/${item.scheme}/${check.name}=${check.ratio}<${check.threshold}`));
  assert(contrastFailures.length === 0, `WCAG 对比检查失败：${contrastFailures.join(', ')}`);

  await page.setViewportSize(acceptanceViewports.desktop);
  await chooseAppearance('light', 'lake', true);
  await page.screenshot({ path: path.join(outputDir, 'theme-picker-material-previews.png') });
  await page.locator('#appearance-button').click();

  assert(new Set(visualStyles.map(style => style.material)).size === 5, '五套主题缺少唯一的材质身份 token');
  assert(new Set(visualStyles.map(style => style.cardBackground)).size === 5, '五套主题的卡片材质没有实质差异');
  assert(new Set(visualStyles.map(style => style.topbarBackground)).size >= 4, '顶栏材质差异不足');
  assert(new Set(visualStyles.map(style => style.sidebarBackground)).size >= 4, '侧栏材质差异不足');
  assert(new Set(visualStyles.map(style => style.menuBackground)).size >= 4, '菜单材质差异不足');
  assert(new Set(visualStyles.map(style => style.inputBackground)).size >= 4, '输入框材质差异不足');
  assert(new Set(visualStyles.map(style => style.tableHeaderBackground)).size >= 4, '表格材质差异不足');
  assert(new Set(visualStyles.map(style => style.radius)).size >= 4, '视觉风格仍只是换色，没有改变圆角体系');
  assert(new Set(visualStyles.map(style => style.shadow)).size >= 4, '视觉风格没有建立不同阴影层级');
  assert(new Set(visualStyles.map(style => style.backdropFilter)).size >= 3, '玻璃、实体和辉光主题的滤镜差异不足');
  assert(new Set(visualStyles.map(style => style.chartGridDash)).size === 5, '五套主题没有独立图表网格节奏');
  assert(new Set(visualStyles.map(style => style.chartStrokeWidth)).size === 5, '五套主题没有独立图表线条粗细');
  assert(new Set(visualStyles.map(style => style.border)).size >= 2, '高对比主题没有使用更强边框');
  assert(await page.locator('.theme-preview .preview-card').count() === 5, '主题选择器缺少卡片材质缩略预览');
  assert(await page.locator('.theme-preview .preview-chart').count() === 5, '主题选择器缺少图表材质缩略预览');

  await chooseAppearance('dark', 'contrast');
  await page.waitForTimeout(250);
  const contrastOnPrimary = await page.locator('.nav-link.active').evaluate(node => ({ color: getComputedStyle(node).color, background: getComputedStyle(node).backgroundColor }));
  assert(contrastOnPrimary.color === 'rgb(0, 0, 0)' && contrastOnPrimary.background === 'rgb(255, 230, 0)', `高对比深色主题主色文字不可读：${JSON.stringify(contrastOnPrimary)}`);

  await page.emulateMedia({ colorScheme: 'dark', reducedMotion: 'reduce' });
  await chooseAppearance('system', 'jade');
  assert(await page.evaluate(() => document.documentElement.dataset.scheme === 'dark'), '跟随系统未响应深色偏好');
  assert(await page.evaluate(() => document.documentElement.dataset.palette === 'jade'), '切换跟随系统时材质主题被意外改变');
  const reducedMotion = await page.locator('#overview-view').evaluate(node => getComputedStyle(node).animationDuration);
  assert(Number.parseFloat(reducedMotion) <= 0.01, `reduced-motion 未关闭主题动效：${reducedMotion}`);
  acceptanceManifest.preferenceChecks.reducedMotion = { requested: 'reduce', animationDuration: reducedMotion, passed: true };
  acceptanceManifest.preferenceChecks.systemDark = { requested: 'dark', resolved: 'dark', palette: 'jade', passed: true };
  await page.emulateMedia({ colorScheme: 'light', reducedMotion: 'no-preference' });
  await page.waitForFunction(() => document.documentElement.dataset.scheme === 'light');
  assert(await page.evaluate(() => document.documentElement.dataset.palette === 'jade'), '系统明暗变化不应改变材质主题');
  acceptanceManifest.preferenceChecks.systemLight = { requested: 'light', resolved: 'light', palette: 'jade', passed: true };

  const switchStress = await page.evaluate(() => {
    const modes = ['light', 'dark', 'system'];
    const palettes = ['lake', 'ocean', 'jade', 'violet', 'contrast'];
    const started = performance.now();
    let finalMode = modes[0];
    let finalPalette = palettes[0];
    for (let index = 0; index < 75; index += 1) {
      finalMode = modes[index % modes.length];
      finalPalette = palettes[index % palettes.length];
      document.querySelector(`[data-theme-choice="${finalMode}"]`).click();
      document.querySelector(`[data-palette-choice="${finalPalette}"]`).click();
    }
    return { count: 75, durationMs: Number((performance.now() - started).toFixed(2)), finalMode, finalPalette };
  });
  await page.waitForTimeout(400);
  const finalTheme = await page.evaluate(() => ({ mode: document.documentElement.dataset.themeMode, palette: document.documentElement.dataset.palette }));
  assert(finalTheme.mode === switchStress.finalMode && finalTheme.palette === switchStress.finalPalette, `快速主题切换最终状态错误：${JSON.stringify({ switchStress, finalTheme })}`);
  assert(pageErrors.length === 0 && consoleErrors.length === 0, `快速主题切换产生错误：${[...pageErrors, ...consoleErrors].join(' | ')}`);
  acceptanceManifest.switchStress = { ...switchStress, finalTheme, passed: true };

  await page.setViewportSize({ width: 1440, height: 1000 });
  await chooseAppearance('light', 'violet');
  assert(await page.evaluate(() => document.documentElement.dataset.scheme === 'light'), '浅色主题未生效');
  assert(await page.evaluate(() => document.documentElement.dataset.palette === 'violet'), '紫罗兰配色未生效');
  await page.reload({ waitUntil: 'domcontentloaded' });
  await waitForWorkspace();
  assert(await page.evaluate(() => document.documentElement.dataset.scheme === 'light'), '刷新后浅色主题未保留');
  assert(await page.evaluate(() => document.documentElement.dataset.palette === 'violet'), '刷新后配色未保留');

  await openRoute('#/overview');
  await page.locator('#traffic-chart').waitFor({ state: 'visible' });
  await page.locator('#overview-alert-panel:not(.hidden)').waitFor({ state: 'visible', timeout: 15_000 });
  await page.locator('#overview-alert-more').waitFor({ state: 'visible', timeout: 15_000 });
  assert(await page.locator('#overview-kpis .kpi-card').count() === 5, '总览不是五个核心 KPI');
  assert(await page.locator('[data-trend-range]').evaluateAll(nodes => nodes.map(node => node.dataset.trendRange).join(',')) === '1h,12h,1d,7d,30d', '流量范围不是 1h/12h/1d/7d/30d');
  assert(await page.locator('[data-trend-range="1h"]').evaluate(node => node.classList.contains('active')), '流量范围默认值不是 1h');
  assert(await page.locator('#service-health-summary').textContent().then(text => !/\d+\s*\/\s*\d+/.test(text)), '服务健康仍使用含义不清的分数表达');
  assert(await page.locator('#overview-alerts .alert-item').count() <= 5, '总览告警超过最近五条');
  assert(await page.locator('#overview-alert-more').isVisible(), '总览缺少告警“更多”入口');
  await page.screenshot({ path: path.join(outputDir, 'overview-desktop.png'), fullPage: true });

  await openRoute('#/metrics');
  await page.locator('#metrics-dashboard').waitFor({ state: 'visible' });
  assert(await page.locator('details.metric-details').count() === 0, '运行指标仍存在“详细指标”折叠层');

  // 八类协议均验证真实编辑流程和 PUT 保存。
  const policies = [
    ['tcp', 'smoke-tcp-edited'],
    ['udp', 'smoke-udp-edited'],
    ['ports', 'smoke-ports-edited'],
    ['http', 'smoke-http-edited'],
    ['sni', 'smoke-sni-edited'],
    ['secret', 'smoke-secret-edited'],
    ['socks5', 'smoke-socks5-edited'],
    ['http-proxy', 'smoke-http-proxy-edited'],
  ];
  for (const [route, editedName] of policies) await editPolicy(route, editedName);

  await openRoute('#/services/tcp');
  assert(await page.locator('#services-view canvas').count() === 2, 'TCP 页面缺少协议趋势或策略状态图');
  assert(await page.locator('#service-insight-kpis .insight-kpi').count() === 5, 'TCP 页面摘要不是五项');
  assert(await page.locator('#service-list details.action-menu').count() > 0, '策略低频操作没有收纳到更多菜单');
  assert(await page.locator('#workspace-service-actions:not(.hidden)').count() === 1, '策略操作没有并入页面顶部标题栏');
  assert(await page.locator('#services-view h2').count() === 0, '协议页仍重复显示页面标题');
  await page.locator('#service-list .policy-select input').first().check();
  assert(!(await page.locator('#bulk-disable-policies').isDisabled()), '选择策略后批量操作仍被禁用');
  await page.locator('#bulk-disable-policies').click();
  await page.waitForFunction(() => document.querySelector('#service-list')?.textContent?.includes('Disabled') || document.querySelector('#service-list')?.textContent?.includes('已停用'));
  assert(await page.locator('#export-policies').isVisible(), '策略导出入口不可见');
  assert(await page.locator('#import-policies').isVisible(), '策略导入入口不可见');

  await openRoute('#/fleet');
  await page.locator('#fleet-view:not(.hidden)').waitFor();
  assert(await page.locator('#workspace-fleet-actions:not(.hidden)').count() === 1, '多云操作没有并入页面顶部标题栏');
  await page.locator('#preview-fleet-sync').click();
  await page.waitForTimeout(250);
  assert(pageErrors.length === 0, `多云同步预览触发页面错误：${pageErrors.join('; ')}`);

  // 管理员通过真实界面创建、编辑、重置和撤销用户会话。
  await openRoute('#/users');
  assert(await page.locator('#workspace-user-actions:not(.hidden)').count() === 1, '用户操作没有并入页面顶部标题栏');
  await page.locator('#new-user').click();
  await page.locator('#user-username').fill('smoke_operator');
  await page.locator('#user-display-name').fill('Smoke Operator');
  await page.locator('#user-role').selectOption('operator');
  await page.locator('#user-password').fill('LinkLake-Operator-2026!');
  const createOperatorResponse = page.waitForResponse(response => response.url().endsWith('/api/v1/users') && response.request().method() === 'POST', { timeout: 30_000 });
  await page.locator('#user-form button[type="submit"]').click();
  assert((await createOperatorResponse).ok(), '创建运维用户的界面请求失败');
  const operatorRow = page.locator('#users-list tr').filter({ hasText: 'smoke_operator' });
  await operatorRow.waitFor({ state: 'visible', timeout: 30_000 });
  await operatorRow.getByRole('button', { name: /Edit|编辑/ }).click();
  await page.locator('#user-display-name').fill('Smoke Operations');
  const updateOperatorResponse = page.waitForResponse(response => response.url().endsWith('/api/v1/users/smoke_operator') && response.request().method() === 'PUT', { timeout: 30_000 });
  await page.locator('#user-form button[type="submit"]').click();
  assert((await updateOperatorResponse).ok(), '编辑运维用户的界面请求失败');
  await page.waitForFunction(() => document.querySelector('#users-list')?.textContent?.includes('Smoke Operations'), null, { timeout: 30_000 });
  await page.locator('#users-list tr').filter({ hasText: 'smoke_operator' }).getByRole('button', { name: /Reset password|重置密码/ }).click();
  await page.locator('#reset-password-value').fill('LinkLake-Operator-Updated-2026!');
  await page.locator('#reset-force-change').uncheck();
  const resetOperatorResponse = page.waitForResponse(response => response.url().endsWith('/api/v1/users/smoke_operator/reset-password') && response.request().method() === 'POST', { timeout: 30_000 });
  await page.locator('#reset-password-form button[type="submit"]').click();
  assert((await resetOperatorResponse).ok(), '重置运维用户密码的界面请求失败');

  const auditorCreate = await pageApi(page, '/api/v1/users', { method: 'POST', body: JSON.stringify({ username: 'smoke_auditor', display_name: 'Smoke Auditor', role: 'auditor', password: 'LinkLake-Auditor-2026!', force_password_change: false }) });
  assert(auditorCreate.status === 201, `创建审计用户失败：${auditorCreate.status}`);

  // 审计人员只读；运维人员可修改策略但不能管理用户。
  const auditorContext = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  const auditorPage = await auditorContext.newPage();
  await loginPage(auditorPage, 'smoke_auditor', 'LinkLake-Auditor-2026!');
  assert(await auditorPage.locator('.admin-only:not(.hidden)').count() === 0, '审计人员仍能看到用户管理入口');
  const auditorRead = await pageApi(auditorPage, '/api/v1/metrics');
  const auditorWrite = await pageApi(auditorPage, '/api/v1/acme/config', { method: 'PUT', body: '{}' });
  assert(auditorRead.status === 200, `审计人员读取指标失败：${auditorRead.status}`);
  assert(auditorWrite.status === 403, `审计人员写操作未被拒绝：${auditorWrite.status}`);
  await auditorContext.close();

  const operatorContext = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  const operatorPage = await operatorContext.newPage();
  await loginPage(operatorPage, 'smoke_operator', 'LinkLake-Operator-Updated-2026!');
  const operatorUsers = await pageApi(operatorPage, '/api/v1/users');
  assert(operatorUsers.status === 403, `运维人员仍可读取用户管理：${operatorUsers.status}`);
  const tcpPolicies = await pageApi(operatorPage, '/api/v1/tcp-tunnels');
  const operatorWrite = await pageApi(operatorPage, `/api/v1/tcp-tunnels/${tcpPolicies.body[0].id}/enabled`, { method: 'POST', body: JSON.stringify({ enabled: true }) });
  assert(operatorWrite.status === 204, `运维人员无法修改策略：${operatorWrite.status}`);
  await operatorContext.close();

  await openRoute('#/sessions');
  await page.locator('#sessions-list tr').first().waitFor({ timeout: 15_000 });
  assert(await page.locator('#sessions-list').textContent().then(text => text.includes(username)), '会话页没有显示当前登录用户');

  await openRoute('#/activity');
  await page.locator('#audit-list .audit-item').first().waitFor({ timeout: 15_000 });
  assert(await page.locator('#audit-list .audit-item').count() >= 8, '活动列表未显示策略变更事件');
  await page.locator('#audit-list .audit-summary').first().click();
  assert(await page.locator('#audit-list .audit-detail:not(.hidden)').count() > 0, '活动详情无法展开');

  await page.evaluate(() => { location.hash = '#/not-a-real-page'; });
  await page.waitForFunction(() => location.hash === '#/overview');

  // 宽屏、普通桌面与移动端都不能出现横向溢出。
  await page.setViewportSize({ width: 2560, height: 1440 });
  await openRoute('#/overview');
  const wideLayout = await page.locator('#workspace').evaluate(node => ({ width: node.getBoundingClientRect().width, columns: getComputedStyle(node).gridTemplateColumns }));
  assert(wideLayout.width > 2450, `超宽屏布局仍留有过多空白：${JSON.stringify(wideLayout)}`);
  assert((await page.locator('#overview-kpis .kpi-card').count()) === 5, '宽屏 KPI 数量异常');
  await page.screenshot({ path: path.join(outputDir, 'overview-wide-2560.png'), fullPage: true });

  await page.setViewportSize({ width: 390, height: 844 });
  await openRoute('#/overview');
  await page.locator('#traffic-chart').waitFor({ state: 'visible' });
  const overflow = await page.evaluate(() => ({
    html: document.documentElement.scrollWidth - document.documentElement.clientWidth,
    body: document.body.scrollWidth - document.body.clientWidth,
  }));
  assert(overflow.html === 0 && overflow.body === 0, `移动端横向溢出：${JSON.stringify(overflow)}`);
  await page.screenshot({ path: path.join(outputDir, 'overview-mobile-390.png'), fullPage: true });

  await openRoute('#/users');
  await page.locator('#users-view:not(.hidden)').waitFor({ state: 'visible' });
  const userOverflow = await page.evaluate(() => ({
    html: document.documentElement.scrollWidth - document.documentElement.clientWidth,
    body: document.body.scrollWidth - document.body.clientWidth,
    tableScrollable: document.querySelector('#users-view .data-table-wrap').scrollWidth > document.querySelector('#users-view .data-table-wrap').clientWidth,
  }));
  assert(userOverflow.html === 0 && userOverflow.body === 0, `用户管理移动端横向溢出：${JSON.stringify(userOverflow)}`);
  await page.screenshot({ path: path.join(outputDir, 'users-mobile-390.png'), fullPage: true });

  await openRoute('#/services/tcp');
  const serviceOverflow = await page.evaluate(() => ({
    html: document.documentElement.scrollWidth - document.documentElement.clientWidth,
    body: document.body.scrollWidth - document.body.clientWidth,
  }));
  assert(serviceOverflow.html === 0 && serviceOverflow.body === 0, `协议页移动端横向溢出：${JSON.stringify(serviceOverflow)}`);

  assert(pageErrors.length === 0, `浏览器出现脚本异常：${pageErrors.join(' | ')}`);
  assert(consoleErrors.length === 0, `浏览器控制台出现错误：${consoleErrors.join(' | ')}`);
  acceptanceManifest.summary = {
    ok: true,
    combinations: acceptanceManifest.combinations.length,
    screenshots: acceptanceManifest.combinations.length + 5,
    contrastChecks: acceptanceManifest.combinations.reduce((total, item) => total + item.contrastChecks.length, 0),
    pageErrors: pageErrors.length,
    consoleErrors: consoleErrors.length,
  };
  console.log(JSON.stringify({ ok: true, browser: acceptanceManifest.browser, editedPolicies: policies.length, rbac: true, themeSurfaces: true, visualStyles, manifest: path.join(outputDir, 'theme-acceptance-manifest.json'), pageErrors, consoleErrors, overflow, userOverflow, serviceOverflow, wideLayout }, null, 2));
} finally {
  acceptanceManifest.pageErrors = pageErrors;
  acceptanceManifest.consoleErrors = consoleErrors;
  await writeFile(path.join(outputDir, 'theme-acceptance-manifest.json'), `${JSON.stringify(acceptanceManifest, null, 2)}\n`, 'utf8');
  await browser.close();
}
