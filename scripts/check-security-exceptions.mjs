#!/usr/bin/env node
// 校验安全例外清单、扫描器配置和到期日是否严格一致。

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const advisoryPattern = /^RUSTSEC-\d{4}-\d{4}$/;

function read(relativePath) {
  return fs.readFileSync(path.join(root, relativePath), 'utf8');
}

function fail(message) {
  console.error(`security exception validation failed: ${message}`);
  process.exit(1);
}

function extractBlocks(text, header) {
  const marker = `[[${header}]]`;
  return text
    .split(marker)
    .slice(1)
    .map((part) => part.split(/^\[\[|^\[/m, 1)[0]);
}

function quoted(block, key) {
  const match = block.match(new RegExp(`^${key}\\s*=\\s*"([^"]*)"\\s*$`, 'm'));
  return match?.[1];
}

function dateValue(block, key) {
  const match = block.match(new RegExp(`^${key}\\s*=\\s*(\\d{4}-\\d{2}-\\d{2})\\s*$`, 'm'));
  return match?.[1];
}

function isoTodayUtc() {
  return new Date().toISOString().slice(0, 10);
}

function compareVersions(left, right) {
  const parts = (value) => value.split('-', 1)[0].split('.').map((part) => Number(part));
  const leftParts = parts(left);
  const rightParts = parts(right);
  const length = Math.max(leftParts.length, rightParts.length);
  for (let index = 0; index < length; index += 1) {
    const difference = (leftParts[index] ?? 0) - (rightParts[index] ?? 0);
    if (difference !== 0) return Math.sign(difference);
  }
  return 0;
}

const canonicalText = read('security/exceptions.toml');
if (!/^schema_version\s*=\s*1\s*$/m.test(canonicalText)) {
  fail('security/exceptions.toml 的 schema_version 必须为 1');
}

const exceptions = extractBlocks(canonicalText, 'exception').map((block) => ({
  id: quoted(block, 'id'),
  reason: quoted(block, 'reason'),
  expires: dateValue(block, 'expires'),
}));

if (exceptions.length === 0) {
  fail('security/exceptions.toml 必须包含至少一个 [[exception]]');
}

const seen = new Set();
const today = isoTodayUtc();
for (const item of exceptions) {
  if (!item.id || !advisoryPattern.test(item.id)) {
    fail(`漏洞编号格式不合法：${item.id ?? '<missing>'}`);
  }
  if (seen.has(item.id)) {
    fail(`漏洞编号重复：${item.id}`);
  }
  seen.add(item.id);
  if (!item.reason || item.reason.trim().length < 40) {
    fail(`${item.id} 的原因缺失或过短`);
  }
  if (!item.expires) {
    fail(`${item.id} 缺少 TOML 日期 expires`);
  }
  if (today >= item.expires) {
    fail(`${item.id} 已于 ${item.expires} 到期`);
  }
}

const lockPackages = extractBlocks(read('Cargo.lock'), 'package').map((block) => ({
  name: quoted(block, 'name'),
  version: quoted(block, 'version'),
}));
const retiredAdvisories = [
  {
    ids: ['RUSTSEC-2026-0118', 'RUSTSEC-2026-0119'],
    package: 'hickory-proto',
    affected: (version) => compareVersions(version, '0.26.1') < 0,
  },
  {
    ids: ['RUSTSEC-2026-0002'],
    package: 'lru',
    affected: (version) =>
      compareVersions(version, '0.9.0') >= 0 && compareVersions(version, '0.16.3') < 0,
  },
  {
    ids: ['RUSTSEC-2025-0134'],
    package: 'rustls-pemfile',
    affected: () => true,
  },
  {
    ids: ['RUSTSEC-2023-0089'],
    package: 'atomic-polyfill',
    affected: () => true,
  },
  {
    ids: ['RUSTSEC-2024-0384'],
    package: 'instant',
    affected: () => true,
  },
];
for (const retired of retiredAdvisories) {
  const staleException = retired.ids.find((id) => seen.has(id));
  if (staleException) {
    fail(`${staleException} 已完成依赖迁移，不得继续保留例外`);
  }
  const affectedVersions = lockPackages
    .filter((pkg) => pkg.name === retired.package && pkg.version && retired.affected(pkg.version))
    .map((pkg) => pkg.version);
  if (affectedVersions.length > 0) {
    fail(
      `${retired.ids.join('/')} 的旧依赖 ${retired.package} ${affectedVersions.join(', ')} 重新进入 Cargo.lock`,
    );
  }
}

const wildcardExceptions = extractBlocks(canonicalText, 'wildcard_exception').map((block) => ({
  crate: quoted(block, 'crate'),
  dependency: quoted(block, 'dependency'),
  manifest: quoted(block, 'manifest'),
  reason: quoted(block, 'reason'),
  expires: dateValue(block, 'expires'),
}));
const wildcardIdentities = new Set();
for (const item of wildcardExceptions) {
  const identity = `${item.crate}|${item.dependency}|${item.manifest}`;
  if (!item.crate || !item.dependency || !item.manifest || wildcardIdentities.has(identity)) {
    fail(`wildcard 例外字段缺失或重复：${identity}`);
  }
  wildcardIdentities.add(identity);
  if (!item.reason || item.reason.trim().length < 40 || !item.expires) {
    fail(`${identity} 缺少充分原因或到期日`);
  }
  if (today >= item.expires) {
    fail(`${identity} 已于 ${item.expires} 到期`);
  }
}

let metadata;
try {
  metadata = JSON.parse(
    execFileSync('cargo', ['metadata', '--format-version', '1', '--no-deps'], {
      cwd: root,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    }),
  );
} catch (error) {
  fail(`无法读取 cargo metadata：${error.message}`);
}
const workspaceMembers = new Set(metadata.workspace_members);
const actualWildcards = metadata.packages
  .filter((pkg) => workspaceMembers.has(pkg.id))
  .flatMap((pkg) =>
    pkg.dependencies
      .filter((dependency) => dependency.req === '*' && dependency.path && dependency.kind !== 'dev')
      .map((dependency) => ({
        crate: pkg.name,
        dependency: dependency.name,
        manifest: path.relative(root, pkg.manifest_path).replaceAll('\\', '/'),
      })),
  )
  .sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right)));
const expectedWildcards = wildcardExceptions
  .map(({ crate, dependency, manifest }) => ({ crate, dependency, manifest }))
  .sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right)));
if (JSON.stringify(actualWildcards) !== JSON.stringify(expectedWildcards)) {
  fail(
    `cargo wildcard path 依赖与精确例外不一致：actual=${JSON.stringify(actualWildcards)} expected=${JSON.stringify(expectedWildcards)}`,
  );
}

const expectedIds = exceptions.map((item) => item.id);
const auditIds = [...read('.cargo/audit.toml').matchAll(/"(RUSTSEC-\d{4}-\d{4})"/g)].map(
  (match) => match[1],
);
if (JSON.stringify(auditIds) !== JSON.stringify(expectedIds)) {
  fail('.cargo/audit.toml 的忽略列表与 canonical 清单顺序或内容不一致');
}

const denyText = read('deny.toml');
const advisorySection = denyText.match(/\[advisories\]([\s\S]*?)(?=^\[licenses\])/m)?.[1] ?? '';
const denyEntries = [...advisorySection.matchAll(/\{\s*id\s*=\s*"([^"]+)",\s*reason\s*=\s*"([^"]+)"\s*\}/g)].map(
  (match) => ({ id: match[1], reason: match[2] }),
);
const expectedReasons = exceptions.map(({ id, reason }) => ({ id, reason }));
if (JSON.stringify(denyEntries) !== JSON.stringify(expectedReasons)) {
  fail('deny.toml 的漏洞编号或原因与 canonical 清单不一致');
}

const osvEntries = extractBlocks(read('osv-scanner.toml'), 'IgnoredVulns').map((block) => ({
  id: quoted(block, 'id'),
  reason: quoted(block, 'reason'),
  expires: dateValue(block, 'ignoreUntil'),
}));
if (JSON.stringify(osvEntries) !== JSON.stringify(exceptions)) {
  fail('osv-scanner.toml 的编号、原因或到期日与 canonical 清单不一致');
}

let zizmorCount = 0;
const zizmorPath = path.join(root, '.github', 'zizmor.yml');
if (fs.existsSync(zizmorPath)) {
  const ignorePattern = /^\s*-\s+[^#]+#\s*reason:\s*(.+?);\s*expires:\s*(\d{4}-\d{2}-\d{2})\s*$/;
  read('.github/zizmor.yml')
    .split(/\r?\n/)
    .forEach((line, index) => {
      if (!/^\s*-\s+[^#]+/.test(line)) return;
      const match = line.match(ignorePattern);
      if (!match) {
        fail(`.github/zizmor.yml:${index + 1} 缺少逐项 reason 或 expires`);
      }
      if (match[1].trim().length < 20) {
        fail(`.github/zizmor.yml:${index + 1} 的原因过短`);
      }
      if (today >= match[2]) {
        fail(`.github/zizmor.yml:${index + 1} 已于 ${match[2]} 到期`);
      }
      zizmorCount += 1;
    });
}

let gitleaksCount = 0;
const gitleaksPath = path.join(root, '.gitleaksignore');
if (fs.existsSync(gitleaksPath)) {
  const fingerprintPattern = /^([0-9a-f]{40}:.+:[^:]+:\d+)$/;
  const reasonPattern = /^#\s*reason:\s*(.+?);\s*expires:\s*(\d{4}-\d{2}-\d{2})\s*$/;
  const fingerprints = new Set();
  const lines = read('.gitleaksignore').split(/\r?\n/).filter((line) => line.trim());
  for (let index = 0; index < lines.length; index += 2) {
    const reason = lines[index]?.match(reasonPattern);
    const fingerprint = lines[index + 1]?.match(fingerprintPattern);
    if (!reason || !fingerprint) {
      fail(`.gitleaksignore 第 ${index + 1}-${index + 2} 行必须是 reason/expires 注释和精确 commit fingerprint`);
    }
    if (fingerprints.has(fingerprint[1])) {
      fail(`.gitleaksignore fingerprint 重复：${fingerprint[1]}`);
    }
    fingerprints.add(fingerprint[1]);
    if (reason[1].trim().length < 20) {
      fail(`.gitleaksignore fingerprint 原因过短：${fingerprint[1]}`);
    }
    if (today >= reason[2]) {
      fail(`.gitleaksignore fingerprint 已于 ${reason[2]} 到期：${fingerprint[1]}`);
    }
    gitleaksCount += 1;
  }
}

let trivyCount = 0;
const trivyPath = path.join(root, '.trivyignore.yaml');
if (fs.existsSync(trivyPath)) {
  const trivyText = read('.trivyignore.yaml');
  const topLevel = [...trivyText.matchAll(/^([A-Za-z][A-Za-z0-9_-]*):\s*$/gm)].map(
    (match) => match[1],
  );
  if (JSON.stringify(topLevel) !== JSON.stringify(['vulnerabilities'])) {
    fail('.trivyignore.yaml 只允许逐项 vulnerabilities 例外');
  }
  const blocks = trivyText.split(/^\s{2}- id:\s*/m).slice(1);
  if (blocks.length !== 1) {
    fail('.trivyignore.yaml 当前必须且只能包含一个已验证漏洞例外');
  }
  const block = blocks[0];
  const id = block.match(/^([^\r\n]+)$/m)?.[1].trim();
  const paths = [...block.matchAll(/^\s{6}-\s+(Cargo\.lock)\s*$/gm)].map((match) => match[1]);
  const purls = [...block.matchAll(/^\s{6}-\s+(pkg:cargo\/[^\s]+)\s*$/gm)].map(
    (match) => match[1],
  );
  const statement = block.match(/^\s{4}statement:\s+(.+)$/m)?.[1].trim();
  const expires = block.match(/^\s{4}expired_at:\s+(\d{4}-\d{2}-\d{2})\s*$/m)?.[1];
  const advisoryReason = exceptions.find((item) => item.id === 'RUSTSEC-2026-0118')?.reason;
  if (
    id !== 'GHSA-3v94-mw7p-v465' ||
    JSON.stringify(paths) !== JSON.stringify(['Cargo.lock']) ||
    JSON.stringify(purls) !== JSON.stringify(['pkg:cargo/hickory-proto@0.25.2']) ||
    statement !== advisoryReason ||
    !expires
  ) {
    fail('.trivyignore.yaml 必须精确限定 hickory-proto 0.25.2、Cargo.lock、原因和到期日');
  }
  if (today >= expires) {
    fail(`.trivyignore.yaml 漏洞例外已于 ${expires} 到期`);
  }
  trivyCount = 1;
}
if (!fs.existsSync(trivyPath) && /^\s*trivyignores:/m.test(read('.github/workflows/security.yml'))) {
  fail('security workflow 仍引用已删除的 .trivyignore.yaml');
}

console.log(
  `validated ${exceptions.length} advisory exceptions, ${wildcardExceptions.length} wildcard exceptions, ${zizmorCount} exact zizmor suppressions, ${gitleaksCount} gitleaks fingerprints, and ${trivyCount} Trivy exception`,
);
