import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const root = process.cwd();
const webRoot = join(root, 'crates', 'linklake-server', 'web');
const html = readFileSync(join(webRoot, 'index.html'), 'utf8');
const css = readFileSync(join(webRoot, 'linklake.css'), 'utf8');
const app = readFileSync(join(webRoot, 'linklake.js'), 'utf8');
const bootstrap = readFileSync(join(webRoot, 'theme-bootstrap.js'), 'utf8');

function ensure(condition, message) {
  if (!condition) throw new Error(message);
}

// 页面必须保持离线可部署：所有运行资产均由同一服务端二进制提供。
for (const asset of ['/assets/theme-bootstrap.js', '/assets/linklake.css', '/assets/linklake.js']) {
  ensure(html.includes(asset), `missing embedded asset reference: ${asset}`);
}
ensure(!html.includes('<style>'), 'inline stylesheet returned to index.html');
ensure(!html.includes('<script>'), 'inline script returned to index.html');
ensure(![html, css, app, bootstrap].some(source => /https:\/\/(?:cdn\.|unpkg\.)/i.test(source)), 'external CDN dependency detected');

// 防止模块拆分后元素注册表与 HTML 漂移。
const ids = [...html.matchAll(/\sid="([^"]+)"/g)].map(match => match[1]);
ensure(new Set(ids).size === ids.length, 'duplicate HTML element ID detected');
const registry = app.match(/const elements = Object\.fromEntries\(\[([\s\S]*?)\]\.map\(id =>/);
ensure(registry, 'element registry not found');
for (const [, id] of registry[1].matchAll(/'([^']+)'/g)) {
  ensure(ids.includes(id), `registered element is missing from HTML: ${id}`);
}

// 图表必须跟随真实容器和设备像素比，并由浏览器刷新帧调度。
for (const marker of ['new ResizeObserver(', 'window.devicePixelRatio || 1', 'requestAnimationFrame(() => {', 'chartResizeObserver.observe(elements.workspace)']) {
  ensure(app.includes(marker), `responsive chart contract missing: ${marker}`);
}

// 更新中心只暴露生产签名、禁止降级且需要明确确认的入口。
for (const marker of [
  'href="#/updates"',
  '/api/v1/updates/server/check',
  '/api/v1/updates/server/download',
  '/api/v1/updates/server/apply',
  "promptForUpdateConfirmation('confirmDownloadUpdate', 'DOWNLOAD')",
  "promptForUpdateConfirmation('confirmApplyUpdate', 'UPDATE')",
  'operation_active',
  'state.dashboard.updateOverview.operation_active = true',
  '/api/v1/updates/clients/tasks',
  "check: 'CHECK', download: 'DOWNLOAD', apply: 'UPDATE', status: 'STATUS', recover: 'RECOVER', rollback: 'ROLLBACK'",
  "promptForUpdateConfirmation('confirmCancelRemoteUpdate', 'CANCEL')",
  "{ name: 'grpc_backend_transport'",
  "{ name: 'grpc_backend_server_name'",
  "{ name: 'grpc_backend_trust_profile'"
]) {
  ensure(`${html}\n${app}`.includes(marker), `secure update contract missing: ${marker}`);
}
ensure(!app.includes('development_signature: true'), 'Web UI enables development signing');
ensure(!app.includes('allow_downgrade: true'), 'Web UI enables downgrade');

for (const theme of ['aurora-glass', 'minimal-solid', 'jade-paper', 'neon-space', 'industrial-panel']) {
  ensure(css.includes(`--material-name: ${theme}`), `material theme missing: ${theme}`);
}

console.log(`WebUI contract passed: ${ids.length} unique IDs, modular assets, responsive charts and secure updates.`);
