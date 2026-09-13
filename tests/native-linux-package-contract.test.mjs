import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (relative) => fs.readFileSync(path.join(root, relative), 'utf8');

function workflowJob(text, jobId) {
  const lines = text.split(/\r?\n/);
  const start = lines.findIndex((line) => line === `  ${jobId}:`);
  assert.notEqual(start, -1, `workflow is missing ${jobId}`);
  let end = lines.length;
  for (let index = start + 1; index < lines.length; index += 1) {
    if (/^  [A-Za-z0-9_-]+:\s*$/.test(lines[index])) {
      end = index;
      break;
    }
  }
  return lines.slice(start, end).join('\n');
}

test('native Linux DEB and RPM release contracts are isolated, pinned, and before signing', () => {
  const release = read('.github/workflows/release.yml');
  const security = read('.github/workflows/security.yml');
  const linuxJob = workflowJob(release, 'linux-package');
  const runner = read('tests/run-native-linux-package-contracts.sh');
  const contract = read('tests/native-linux-package-contract.sh');

  const packageVerification = linuxJob.indexOf('Verify DEB and RPM packages');
  const debGate = linuxJob.indexOf('Verify native DEB package install and upgrade contract');
  const rpmGate = linuxJob.indexOf('Verify native RPM package install and upgrade contract');
  const signing = linuxJob.indexOf('Sign Linux release packages with OpenPGP');
  assert.ok(packageVerification >= 0 && debGate > packageVerification && rpmGate > debGate && signing > rpmGate);
  assert.match(linuxJob, /sh tests\/run-native-linux-package-contracts\.sh deb/);
  assert.match(linuxJob, /sh tests\/run-native-linux-package-contracts\.sh rpm/);
  assert.match(security, /tests\/native-linux-package-contract\.test\.mjs/);

  for (const marker of [
    'timeout --foreground 600 docker build',
    'timeout --foreground 300 docker run',
    '--pull=false',
    '--network none',
    '--user 0:0',
    '--security-opt no-new-privileges:true',
    '--memory 1g',
    '--pids-limit 256',
    'readonly',
    '--tmpfs /tmp:exec,mode=1777,size=1g',
    'mktemp -d',
  ]) {
    assert.ok(runner.includes(marker), `native package runner is missing ${marker}`);
  }
  assert.doesNotMatch(runner, /(?:--env|-e)\s+(?:LINKLAKE_|GITHUB_TOKEN|GH_TOKEN)/);
  assert.doesNotMatch(runner, /LINKLAKE_(?:LINUX_GPG|RELEASE_SIGNING)_/);
  assert.match(runner, /cp "\$dockerfile" "\$context\/Dockerfile"/);
  assert.match(contract, /mktemp -d/);
  assert.match(contract, /Run this native package contract test as root inside a disposable container/);
  assert.match(contract, /assert_new_installation_ready/);
  assert.match(contract, /assert_operator_configuration_is_preserved/);
  assert.match(contract, /assert_failed_activation_rolls_back/);
  assert.match(contract, /remove_package/);
  assert.match(contract, /preserve-user-data/);
  assert.match(contract, /systemd-analyze verify/);

  const packaging = read('scripts/package-native-linux.sh');
  for (const marker of [
    'packaging/linux/package-lifecycle.sh',
    'set -- prepare-upgrade',
    "s/%/%%/g' packaging/linux/package-lifecycle.sh",
    'package-lifecycle activate',
    'package-lifecycle remove',
    '%preun',
    '%postun',
    'DEBIAN/prerm',
    'DEBIAN/postrm',
  ]) {
    assert.ok(packaging.includes(marker), `native package lifecycle is missing ${marker}`);
  }
  const lifecycle = read('packaging/linux/package-lifecycle.sh');
  for (const marker of [
    'validate_installation',
    'rollback_upgrade',
    'restore_recorded_services',
    'rolled-back',
    'refusing symbolic-link',
    'candidate-started',
    'automatic binary rollback is unsafe after a database migration',
  ]) {
    assert.ok(lifecycle.includes(marker), `package lifecycle helper is missing ${marker}`);
  }

  for (const relative of [
    'tests/native-linux-package-contract-deb.Dockerfile',
    'tests/native-linux-package-contract-rpm.Dockerfile',
  ]) {
    const dockerfile = read(relative);
    assert.match(dockerfile, /^FROM\s+[^\s]+@sha256:[a-f0-9]{64}$/m);
    assert.doesNotMatch(dockerfile, /^\s*(?:ADD|COPY)\s+/m);
    assert.match(dockerfile, /^USER\s+65534:65534$/m);
  }
  assert.match(read('tests/native-linux-package-contract-deb.Dockerfile'), /apt-get .*Acquire::Retries=3/);
  assert.match(read('tests/native-linux-package-contract-rpm.Dockerfile'), /dnf .*--setopt=retries=3/);
});

// 只运行原脚本函数，目录全部替换为临时夹具；服务和 Linux 所有权操作使用 stub。
// 这里验证恢复边界，不把 Windows 文件权限或 stub 当成原生包安装验证。
const shell = process.platform === 'win32'
  ? path.join(process.env.ProgramFiles || 'C:\\Program Files', 'Git', 'bin', 'bash.exe')
  : '/bin/sh';
const shellAvailable = fs.existsSync(shell);
const shellQuote = (value) => "'" + value.replaceAll('\\', '/').replaceAll("'", "'\\''") + "'";

function lifecycleFixture(t) {
  const temporaryParent = path.resolve(os.tmpdir());
  const fixture = fs.mkdtempSync(path.join(temporaryParent, 'linklake-package-lifecycle-'));
  assert.equal(path.dirname(path.resolve(fixture)), temporaryParent, 'fixture escaped its temporary parent');
  t.after(() => fs.rmSync(fixture, { recursive: true, force: true }));
  const runtime = path.join(fixture, 'runtime');
  const units = path.join(fixture, 'units');
  const mocks = path.join(fixture, 'mocks');
  for (const directory of [runtime, units, mocks]) fs.mkdirSync(directory);
  const original = '#!/bin/sh\n# original runtime\nexit 0\n';
  const candidate = '#!/bin/sh\n# candidate runtime\nexit 0\n';
  for (const name of ['linklake-server', 'linklake-client']) {
    fs.writeFileSync(path.join(runtime, name), original, { mode: 0o755 });
  }
  for (const name of ['linklake-server.service', 'linklake-client.service', 'linklake-update-resume.service']) {
    fs.writeFileSync(path.join(units, name), 'fixture unit\n');
  }
  fs.writeFileSync(path.join(mocks, 'systemd-analyze'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
  const source = read('packaging/linux/package-lifecycle.sh').replaceAll('\r\n', '\n');
  const dispatch = source.lastIndexOf('\ncase "' + '$' + '{1:-}" in');
  assert.ok(dispatch > 0, 'could not isolate the lifecycle functions from their production command dispatch');
  const harness = path.join(fixture, 'harness.sh');
  fs.writeFileSync(harness, source.slice(0, dispatch) + '\n' + [
    'state_root=' + shellQuote(path.join(fixture, 'state')),
    'pending_root="$state_root/pending"',
    'state_file="$pending_root/service-state"',
    'binary_root=' + shellQuote(runtime),
    'unit_root=' + shellQuote(units),
    'event_file=' + shellQuote(path.join(fixture, 'events')),
    'PATH=' + shellQuote(mocks) + ':"$PATH"',
    'export PATH',
    'fail_server_start="$2"',
    'install() {',
    '  if [ "$1" = -d ]; then',
    '    shift; while [ "$#" -gt 1 ]; do shift 2; done',
    '    mkdir -p -- "$1"',
    '  else',
    '    while [ "$#" -gt 2 ]; do shift 2; done',
    '    command cp -- "$1" "$2"',
    '  fi',
    '}',
    'cp() { if [ "$1" = -p ]; then shift; fi; command cp "$@"; }',
    'chmod() { :; }',
    'systemctl() {',
    '  printf "%s\\n" "$*" >>"$event_file"',
    '  if [ "$1" = restart ] && [ "$2" = linklake-server.service ] && [ "$fail_server_start" = 1 ]; then return 42; fi',
    '  return 0',
    '}',
    'case "$1" in',
    '  prepare-upgrade) prepare_upgrade ;;',
    '  activate) activate upgrade ;;',
    '  rollback) rollback_upgrade ;;',
    '  *) exit 2 ;;',
    'esac',
  ].join('\n') + '\n');
  const run = (action, fail = false) => {
    const result = spawnSync(shell, [harness, action, fail ? '1' : '0'], {
      encoding: 'utf8',
      timeout: 15_000,
    });
    assert.ifError(result.error);
    return result;
  };
  const pending = path.join(fixture, 'state', 'pending');
  return { fixture, runtime, original, candidate, pending, run };
}

test('Linux package validation failure restores the old runtime before candidate start', { skip: !shellAvailable }, (t) => {
  const fixture = lifecycleFixture(t);
  assert.equal(fixture.run('prepare-upgrade').status, 0);
  fs.writeFileSync(path.join(fixture.runtime, 'linklake-server'), '#!/bin/sh\nexit 42\n');
  const result = fixture.run('activate');
  assert.equal(result.status, 1, result.stderr);
  assert.match(result.stderr, /new package validation failed/);
  assert.equal(fs.readFileSync(path.join(fixture.runtime, 'linklake-server'), 'utf8'), fixture.original);
  assert.ok(fs.existsSync(path.join(fixture.pending, 'rolled-back')));
  assert.ok(!fs.existsSync(path.join(fixture.pending, 'candidate-started')));
});

test('Linux candidate startup failure preserves both runtime generations and rejects automatic retry rollback', { skip: !shellAvailable }, (t) => {
  const fixture = lifecycleFixture(t);
  assert.equal(fixture.run('prepare-upgrade').status, 0);
  fs.writeFileSync(path.join(fixture.runtime, 'linklake-server'), fixture.candidate);
  const result = fixture.run('activate', true);
  assert.equal(result.status, 1, result.stderr);
  assert.match(result.stderr, /automatic binary rollback is unsafe/);
  const preserved = () => {
    assert.equal(fs.readFileSync(path.join(fixture.runtime, 'linklake-server'), 'utf8'), fixture.candidate);
    assert.equal(fs.readFileSync(path.join(fixture.pending, 'bin', 'linklake-server'), 'utf8'), fixture.original);
    assert.ok(fs.existsSync(path.join(fixture.pending, 'candidate-started')));
    assert.ok(!fs.existsSync(path.join(fixture.pending, 'rolled-back')));
  };
  preserved();
  for (const action of ['rollback', 'prepare-upgrade']) {
    const retry = fixture.run(action);
    assert.equal(retry.status, 1, retry.stderr);
    assert.match(retry.stderr, /candidate service activation has started/);
    preserved();
  }
});

test('Linux successful candidate activation clears the completed package backup', { skip: !shellAvailable }, (t) => {
  const fixture = lifecycleFixture(t);
  assert.equal(fixture.run('prepare-upgrade').status, 0);
  fs.writeFileSync(path.join(fixture.runtime, 'linklake-server'), fixture.candidate);
  const result = fixture.run('activate');
  assert.equal(result.status, 0, result.stderr);
  assert.equal(fs.readFileSync(path.join(fixture.runtime, 'linklake-server'), 'utf8'), fixture.candidate);
  assert.ok(!fs.existsSync(fixture.pending));
});
