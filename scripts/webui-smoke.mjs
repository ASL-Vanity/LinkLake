import { createRequire } from 'node:module';
import path from 'node:path';

const require = createRequire(import.meta.url);
const { chromium } = require('playwright');

const baseUrl = process.env.LINKLAKE_SMOKE_BASE_URL;
const username = process.env.LINKLAKE_SMOKE_USERNAME;
const password = process.env.LINKLAKE_SMOKE_PASSWORD;
const chromePath = process.env.LINKLAKE_SMOKE_CHROME;
const outputDir = process.env.LINKLAKE_SMOKE_OUTPUT;

if (!baseUrl || !username || !password || !chromePath || !outputDir) {
  throw new Error('缺少 LinkLake WebUI 冒烟测试环境变量');
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

const browser = await chromium.launch({ headless: true, executablePath: chromePath });
const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
const page = await context.newPage();
const pageErrors = [];
page.on('pageerror', error => pageErrors.push(error.message));

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
    const response = await fetch(url, { ...options, headers: { 'Content-Type': 'application/json', ...(options.headers || {}) } });
    return { status: response.status, body: await response.json().catch(() => null) };
  }, { url, options });
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

  await page.locator('#global-search').fill('smoke-tcp');
  await page.locator('#global-search-results button').first().waitFor({ timeout: 15_000 });
  assert((await page.locator('#global-search-results').textContent()).includes('smoke-tcp'), '全局搜索没有返回策略');
  await page.locator('#global-search').fill('');

  await openRoute('#/clients');
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

  // 验证主题模式与配色持久化。
  await page.locator('#appearance-button').click();
  await page.locator('[data-theme-choice="light"]').click();
  await page.locator('[data-palette-choice="lake"]').click();
  const lakeTheme = await page.evaluate(() => {
    const style = getComputedStyle(document.documentElement);
    return ['--bg', '--surface', '--line'].map(name => style.getPropertyValue(name).trim());
  });
  await page.locator('[data-palette-choice="violet"]').click();
  const violetTheme = await page.evaluate(() => {
    const style = getComputedStyle(document.documentElement);
    return ['--bg', '--surface', '--line'].map(name => style.getPropertyValue(name).trim());
  });
  assert(lakeTheme.every((value, index) => value !== violetTheme[index]), '配色切换没有同时改变背景、表面和边框');
  assert(await page.evaluate(() => document.documentElement.dataset.scheme === 'light'), '浅色主题未生效');
  assert(await page.evaluate(() => document.documentElement.dataset.palette === 'violet'), '紫罗兰配色未生效');
  await page.reload({ waitUntil: 'domcontentloaded' });
  await waitForWorkspace();
  assert(await page.evaluate(() => document.documentElement.dataset.scheme === 'light'), '刷新后浅色主题未保留');
  assert(await page.evaluate(() => document.documentElement.dataset.palette === 'violet'), '刷新后配色未保留');

  await openRoute('#/overview');
  await page.locator('#traffic-chart').waitFor({ state: 'visible' });
  assert(await page.locator('#overview-kpis .kpi-card').count() === 5, '总览不是五个核心 KPI');
  assert(await page.locator('[data-trend-range]').evaluateAll(nodes => nodes.map(node => node.dataset.trendRange).join(',')) === '1h,12h,1d,7d,30d', '流量范围不是 1h/12h/1d/7d/30d');
  assert(await page.locator('[data-trend-range="1h"]').evaluate(node => node.classList.contains('active')), '流量范围默认值不是 1h');
  assert(await page.locator('#service-health-summary').textContent().then(text => !/\d+\s*\/\s*\d+/.test(text)), '服务健康仍使用含义不清的分数表达');
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
  await page.locator('#service-list .policy-select input').first().check();
  assert(!(await page.locator('#bulk-disable-policies').isDisabled()), '选择策略后批量操作仍被禁用');
  await page.locator('#bulk-disable-policies').click();
  await page.waitForFunction(() => document.querySelector('#service-list')?.textContent?.includes('Disabled') || document.querySelector('#service-list')?.textContent?.includes('已停用'));
  assert(await page.locator('#export-policies').isVisible(), '策略导出入口不可见');
  assert(await page.locator('#import-policies').isVisible(), '策略导入入口不可见');

  // 管理员通过真实界面创建、编辑、重置和撤销用户会话。
  await openRoute('#/users');
  await page.locator('#new-user').click();
  await page.locator('#user-username').fill('smoke_operator');
  await page.locator('#user-display-name').fill('Smoke Operator');
  await page.locator('#user-role').selectOption('operator');
  await page.locator('#user-password').fill('LinkLake-Operator-2026!');
  await page.locator('#user-form button[type="submit"]').click();
  const operatorRow = page.locator('#users-list tr').filter({ hasText: 'smoke_operator' });
  await operatorRow.waitFor({ timeout: 15_000 });
  await operatorRow.getByRole('button', { name: /Edit|编辑/ }).click();
  await page.locator('#user-display-name').fill('Smoke Operations');
  await page.locator('#user-form button[type="submit"]').click();
  await page.waitForFunction(() => document.querySelector('#users-list')?.textContent?.includes('Smoke Operations'));
  await page.locator('#users-list tr').filter({ hasText: 'smoke_operator' }).getByRole('button', { name: /Reset password|重置密码/ }).click();
  await page.locator('#reset-password-value').fill('LinkLake-Operator-Updated-2026!');
  await page.locator('#reset-force-change').uncheck();
  await page.locator('#reset-password-form button[type="submit"]').click();

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
  await page.setViewportSize({ width: 2048, height: 1152 });
  await openRoute('#/overview');
  const wideLayout = await page.locator('#workspace').evaluate(node => ({ width: node.getBoundingClientRect().width, columns: getComputedStyle(node).gridTemplateColumns }));
  assert(wideLayout.width > 1900, `宽屏布局仍留有过多空白：${JSON.stringify(wideLayout)}`);
  assert((await page.locator('#overview-kpis .kpi-card').count()) === 5, '宽屏 KPI 数量异常');
  await page.screenshot({ path: path.join(outputDir, 'overview-wide-2048.png'), fullPage: true });

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

  assert(pageErrors.length === 0, `浏览器出现脚本异常：${pageErrors.join(' | ')}`);
  console.log(JSON.stringify({ ok: true, editedPolicies: policies.length, rbac: true, themeSurfaces: true, pageErrors, overflow, userOverflow, wideLayout }, null, 2));
} finally {
  await browser.close();
}
