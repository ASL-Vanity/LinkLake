import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (relative) => fs.readFileSync(path.join(root, relative), 'utf8');

test('macOS signing keeps certificate passwords out of command arguments', () => {
  const setup = read('scripts/setup-macos-signing.sh');
  const importer = read('scripts/import-macos-p12.swift');
  assert.match(importer, /SecPKCS12Import/);
  assert.match(importer, /ProcessInfo\.processInfo\.environment/);
  assert.doesNotMatch(setup, /security\s+import/);
  assert.doesNotMatch(setup, /-P\s+["']?\$LINKLAKE_MACOS_SIGNING_CERT_PASSWORD/);
  assert.doesNotMatch(setup, /--password/);
});

test('macOS release packages require hardened signing, notarization, and stapling', () => {
  const core = read('scripts/package-macos.sh');
  const manager = read('scripts/package-manager-macos.sh');
  const notarize = read('scripts/notarize-macos-artifact.sh');
  const verifyManager = read('scripts/verify-manager-macos.sh');
  for (const source of [core, manager]) {
    assert.match(source, /--options runtime/);
    assert.match(source, /--timestamp/);
    assert.match(source, /notarize-macos-artifact\.sh/);
  }
  assert.match(notarize, /notarytool submit/);
  assert.match(notarize, /stapler staple/);
  assert.match(verifyManager, /stapler validate/);
  assert.match(verifyManager, /spctl --assess/);
});
