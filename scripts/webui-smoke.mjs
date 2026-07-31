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

try {
  await page.goto(`${baseUrl}/#/overview`, { waitUntil: 'domcontentloaded' });
  assert(await page.locator('link[rel~="icon"]').count() > 0, '页面缺少 favicon');
  assert(await page.locator('#login-shell .login-brand .brand-mark').count() > 0, '登录页缺少品牌 Logo');

  await page.locator('#username').fill(username);
  await page.locator('#password').fill(password);
  await page.locator('#login button[type="submit"]').click();
  await waitForWorkspace();
  assert((await page.locator('#account-name').textContent())?.trim() === username, '账户菜单未显示当前用户名');

  // 刷新后必须通过 /auth/me 恢复账户，而不是依赖登录输入框或 localStorage。
  await page.reload({ waitUntil: 'domcontentloaded' });
  await waitForWorkspace();
  assert((await page.locator('#account-name').textContent())?.trim() === username, '刷新后未恢复当前账户');

  // 验证主题模式与配色持久化。
  await page.locator('#appearance-button').click();
  await page.locator('[data-theme-choice="light"]').click();
  await page.locator('[data-palette-choice="violet"]').click();
  assert(await page.evaluate(() => document.documentElement.dataset.scheme === 'light'), '浅色主题未生效');
  assert(await page.evaluate(() => document.documentElement.dataset.palette === 'violet'), '紫罗兰配色未生效');
  await page.reload({ waitUntil: 'domcontentloaded' });
  await waitForWorkspace();
  assert(await page.evaluate(() => document.documentElement.dataset.scheme === 'light'), '刷新后浅色主题未保留');
  assert(await page.evaluate(() => document.documentElement.dataset.palette === 'violet'), '刷新后配色未保留');

  await openRoute('#/overview');
  await page.locator('#traffic-chart').waitFor({ state: 'visible' });
  assert(await page.locator('#overview-kpis .kpi-card').count() === 4, '总览不是四个核心 KPI');
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

  await openRoute('#/activity');
  await page.locator('#audit-list .audit-item').first().waitFor({ timeout: 15_000 });
  assert(await page.locator('#audit-list .audit-item').count() >= 8, '活动列表未显示策略变更事件');
  await page.locator('#audit-list .audit-summary').first().click();
  assert(await page.locator('#audit-list .audit-detail:not(.hidden)').count() > 0, '活动详情无法展开');

  await page.evaluate(() => { location.hash = '#/not-a-real-page'; });
  await page.waitForFunction(() => location.hash === '#/overview');

  // 移动端必须只允许导航容器内部滚动，整页不能横向溢出。
  await page.setViewportSize({ width: 390, height: 844 });
  await openRoute('#/overview');
  await page.locator('#traffic-chart').waitFor({ state: 'visible' });
  const overflow = await page.evaluate(() => ({
    html: document.documentElement.scrollWidth - document.documentElement.clientWidth,
    body: document.body.scrollWidth - document.body.clientWidth,
  }));
  assert(overflow.html === 0 && overflow.body === 0, `移动端横向溢出：${JSON.stringify(overflow)}`);
  await page.screenshot({ path: path.join(outputDir, 'overview-mobile-390.png'), fullPage: true });

  assert(pageErrors.length === 0, `浏览器出现脚本异常：${pageErrors.join(' | ')}`);
  console.log(JSON.stringify({ ok: true, editedPolicies: policies.length, pageErrors, overflow }, null, 2));
} finally {
  await browser.close();
}
