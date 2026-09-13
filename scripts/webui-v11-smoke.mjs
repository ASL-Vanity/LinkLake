import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';

const require = createRequire(import.meta.url);
const { chromium, firefox, webkit } = require('playwright');
const baseUrl = process.env.LINKLAKE_SMOKE_BASE_URL;
const username = process.env.LINKLAKE_SMOKE_USERNAME;
const password = process.env.LINKLAKE_SMOKE_PASSWORD;
const outputDir = process.env.LINKLAKE_SMOKE_OUTPUT;
assert(baseUrl && username && password && outputDir, 'Missing WebUI smoke fixture environment');
assert(['localhost', '127.0.0.1', '[::1]'].includes(new URL(baseUrl).hostname), 'Only isolated local fixtures are supported');

await mkdir(outputDir, { recursive: true });
const browserEngine = process.env.LINKLAKE_SMOKE_BROWSER_ENGINE || 'chromium';
assert(['chromium', 'firefox', 'webkit'].includes(browserEngine), 'Unsupported smoke browser engine');
const browser = await ({ chromium, firefox, webkit })[browserEngine].launch({
  headless: true,
  ...(process.env.LINKLAKE_SMOKE_CHROME ? { executablePath: process.env.LINKLAKE_SMOKE_CHROME } : {}),
});
const report = { ok: false, checks: [], pageErrors: [], consoleErrors: [], screenshots: [] };
const expectedFields = ['enabled', 'environment', 'directory_url', 'contact_email', 'terms_accepted', 'challenge_type', 'renew_before_days'].sort();
const requestConfig = (config) => Object.fromEntries(expectedFields.map(key => [key, config[key]]));

async function api(page, endpoint, method = 'GET', data) {
  const response = await page.request.fetch(`${baseUrl}${endpoint}`, {
    method,
    timeout: 15_000,
    headers: { 'X-LinkLake-CSRF': '1', 'Content-Type': 'application/json' },
    ...(data === undefined ? {} : { data }),
  });
  return { status: response.status(), body: await response.json().catch(() => null) };
}

async function login(loginUsername, loginPassword) {
  const context = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  const page = await context.newPage();
  page.setDefaultTimeout(15_000);
  page.setDefaultNavigationTimeout(20_000);
  await page.goto(`${baseUrl}/#/overview`);
  await page.locator('#username').fill(loginUsername);
  await page.locator('#password').fill(loginPassword);
  await page.locator('#login button[type="submit"]').click();
  await page.locator('#workspace:not(.hidden)').waitFor({ timeout: 15_000 });
  page.on('pageerror', error => report.pageErrors.push(error.message));
  page.on('console', message => {
    if (message.type() === 'error') report.consoleErrors.push({ message: message.text(), url: message.location().url });
  });
  if ((await page.locator('#language').textContent()).trim() !== 'ZH') await page.locator('#language').click();
  return { context, page };
}

async function openAcme(page) {
  console.log('Opening ACME settings');
  const loaded = page.waitForResponse(response => response.url().endsWith('/api/v1/acme/config') && response.request().method() === 'GET');
  await page.locator('a[href="#/services/acme"]').click();
  const response = await loaded;
  assert.equal(response.status(), 200);
  await page.locator('#acme-page form').waitFor({ state: 'visible' });
  return response.json();
}

async function saveAcme(page, expectedStatus = 200) {
  console.log(`Saving ACME settings (expected HTTP ${expectedStatus})`);
  const saved = page.waitForResponse(response => response.url().endsWith('/api/v1/acme/config') && response.request().method() === 'PUT');
  await page.locator('#acme-page button[type="submit"]').click();
  const response = await saved;
  console.log(`ACME save returned HTTP ${response.status()}`);
  assert.equal(response.status(), expectedStatus);
  assert.deepEqual(Object.keys(response.request().postDataJSON()).sort(), expectedFields, 'Readiness or secret fields entered the ACME request');
  console.log('ACME request fields verified; waiting for form availability');
  await page.waitForFunction(() => !document.querySelector('#acme-page button[type="submit"]').disabled, null, { timeout: 15_000 });
  console.log('ACME form available; verifying persisted configuration');
  // 成功保存的界面不读取 PUT 正文；用后续 GET 验证持久化结果。
  if (expectedStatus === 200) {
    const persisted = await api(page, '/api/v1/acme/config');
    assert.equal(persisted.status, 200);
    return persisted.body;
  }
  let timeout;
  try {
    return await Promise.race([response.json(), new Promise((_, reject) => {
      timeout = setTimeout(() => reject(new Error('ACME response body timed out')), 5000);
    })]);
  } finally {
    clearTimeout(timeout);
  }
}

async function captureNarrow(page, name) {
  await page.setViewportSize({ width: 390, height: 844 });
  const overflow = await page.evaluate(() => ({
    html: document.documentElement.scrollWidth - document.documentElement.clientWidth,
    body: document.body.scrollWidth - document.body.clientWidth,
  }));
  assert.deepEqual(overflow, { html: 0, body: 0 }, `${name}: horizontal overflow`);
  await page.screenshot({ path: path.join(outputDir, `${name}.png`), fullPage: true });
  report.screenshots.push(`${name}.png`);
  await page.setViewportSize({ width: 1280, height: 900 });
}

async function verifySharedPages(page, role) {
  const haLoaded = page.waitForResponse(response => response.url().endsWith('/api/v1/ha/overview') && response.request().method() === 'GET');
  await page.locator('a[href="#/ha"]').click();
  assert.equal((await haLoaded).status(), 200);
  await page.locator('#ha-view:not(.hidden)').waitFor();
  assert.match(await page.locator('#ha-view').textContent(), /SQLite|PostgreSQL/);
  assert.equal(await page.locator('#ha-view button, #ha-view input, #ha-view select').count(), 0);
  await captureNarrow(page, `v11-ha-${role}-390`);

  const generationsLoaded = page.waitForResponse(response => response.url().endsWith('/api/v1/fleet/v2/generations'));
  const conflictsLoaded = page.waitForResponse(response => response.url().endsWith('/api/v1/fleet/v2/conflicts'));
  await page.locator('a[href="#/fleet-ledger"]').click();
  const generations = await generationsLoaded;
  const conflicts = await conflictsLoaded;
  assert.equal(generations.status(), 200);
  assert.equal(conflicts.status(), 200);
  assert(Array.isArray(await generations.json()));
  assert(Array.isArray(await conflicts.json()));
  await page.locator('#fleet-ledger-view:not(.hidden)').waitFor();
  assert.match(await page.locator('#fleet-generation-list').textContent(), /generation/i);
  await captureNarrow(page, `v11-fleet-${role}-390`);
  report.checks.push(`${role}: HA and Fleet API reads, read-only HA and narrow empty-catalog rendering`);
}

let admin;
let originalConfig;
let configTouched = false;
try {
  admin = await login(username, password);
  console.log('Administrator signed in');
  originalConfig = await openAcme(admin.page);
  assert.equal(originalConfig.enabled, false, 'This test never disables an active ACME setup');
  const form = admin.page.locator('#acme-page form');
  assert.deepEqual(await form.locator('[name]').evaluateAll(fields => fields.map(field => field.name).sort()), expectedFields);
  assert.equal(typeof originalConfig.material_key_configured, 'boolean');
  assert.match(await admin.page.locator('#acme-key-status').textContent(), originalConfig.material_key_configured ? /ready or not required/ : /not configured/);
  assert.match(await admin.page.locator('#acme-dns-status').textContent(), originalConfig.cloudflare_token_configured ? /token: configured/ : /not configured or status unavailable/);

  await form.locator('[name="challenge_type"]').selectOption('dns-01');
  await form.locator('[name="contact_email"]').fill('acme-smoke@example.test');
  await form.locator('[name="renew_before_days"]').fill('31');
  await admin.page.locator('#language').click();
  console.log('Checking dirty settings after language switch');
  assert.equal(await form.locator('[name="challenge_type"]').inputValue(), 'dns-01');
  assert.equal(await form.locator('[name="contact_email"]').inputValue(), 'acme-smoke@example.test');
  assert.equal(await form.locator('[name="renew_before_days"]').inputValue(), '31');
  await admin.page.locator('#language').click();
  configTouched = true;
  const saved = await saveAcme(admin.page);
  assert.equal(saved.challenge_type, 'dns-01');
  assert.equal(saved.enabled, false);
  console.log('Reloading saved ACME configuration');
  await admin.page.reload({ waitUntil: 'domcontentloaded', timeout: 20_000 });
  await admin.page.locator('#acme-page form').waitFor({ state: 'visible' });
  await admin.page.waitForFunction(() => document.querySelector('#acme-page [name="challenge_type"]')?.value === 'dns-01');
  assert.equal((await api(admin.page, '/api/v1/acme/config')).body.renew_before_days, 31);
  await captureNarrow(admin.page, 'v11-acme-admin-390');
  report.checks.push('ACME readiness, exact request fields, DNS-01 save/reload, dirty values across languages and narrow layout');

  // 缺少 DNS 凭据时必须拒绝启用，且已有关闭配置保持不变。
  if (!originalConfig.cloudflare_token_configured) {
    await form.locator('[name="enabled"]').check();
    await form.locator('[name="terms_accepted"]').check();
    const rejected = await saveAcme(admin.page, 409);
    assert.equal(rejected.code, 'cloudflare_token_not_configured');
    assert.equal((await api(admin.page, '/api/v1/acme/config')).body.enabled, false);
    await form.locator('[name="enabled"]').uncheck();
    await saveAcme(admin.page);
    // 这个 409 是预期的负向用例，不计入意外控制台错误。
    report.consoleErrors = report.consoleErrors.filter(error => !(error.message.includes('409 (Conflict)') && error.url === `${baseUrl}/api/v1/acme/config`));
    report.checks.push('Missing Cloudflare token rejects enablement and preserves the disabled configuration');
  }
  await verifySharedPages(admin.page, 'administrator');

  const nonce = Date.now().toString();
  for (const role of ['operator', 'auditor']) {
    const testUsername = `v11_${role}_${nonce}`;
    const testPassword = `LinkLake-V11-${nonce}!`;
    const created = await api(admin.page, '/api/v1/users', 'POST', {
      username: testUsername, display_name: `V11 ${role}`, role, password: testPassword, force_password_change: false,
    });
    assert.equal(created.status, 201);
    const session = await login(testUsername, testPassword);
    const config = await openAcme(session.page);
    const controls = session.page.locator('#acme-page input, #acme-page select, #acme-page button');
    assert(await controls.evaluateAll((fields, readonly) => fields.every(field => field.disabled === readonly), role === 'auditor'));
    if (role === 'operator') {
      await session.page.locator('#acme-page [name="renew_before_days"]').fill('32');
      assert.equal((await saveAcme(session.page)).renew_before_days, 32);
      report.checks.push('Operator can save ACME configuration through the form');
    } else {
      assert.equal((await api(session.page, '/api/v1/acme/config', 'PUT', requestConfig(config))).status, 403);
      report.checks.push('Auditor sees disabled ACME controls and the server rejects mutations');
    }
    await verifySharedPages(session.page, role);
    await session.context.close();
  }
  assert.deepEqual(report.pageErrors, []);
  assert.deepEqual(report.consoleErrors, []);
  report.ok = true;
} catch (error) {
  report.error = error.message;
  console.error(`V1.1 smoke failed: ${error.message}`);
  if (admin?.page && !admin.page.isClosed()) {
    await admin.page.screenshot({ path: path.join(outputDir, 'v11-failure.png'), fullPage: true, timeout: 5000 }).catch(() => {});
  }
  throw error;
} finally {
  try {
    if (admin && originalConfig && configTouched) {
      const restored = await api(admin.page, '/api/v1/acme/config', 'PUT', requestConfig(originalConfig));
      assert.equal(restored.status, 200, 'Could not restore the isolated ACME fixture');
    }
    await writeFile(path.join(outputDir, 'v11-management-acceptance.json'), `${JSON.stringify(report, null, 2)}\n`);
  } finally {
    await browser.close();
  }
}
console.log(JSON.stringify(report, null, 2));
