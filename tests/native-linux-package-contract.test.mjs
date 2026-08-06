import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
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
  assert.match(contract, /systemd-analyze verify/);

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
