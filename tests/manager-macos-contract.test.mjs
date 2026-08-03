import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function read(relativePath) {
  return fs.readFileSync(path.join(root, relativePath), 'utf8');
}

test('macOS Manager exposes tray and launch-at-login capabilities', () => {
  const lifecycle = read('apps/linklake_manager/lib/desktop_lifecycle.dart');
  const macBlock = lifecycle.match(/if \(Platform\.isMacOS\) \{([\s\S]*?)\n    \}/)?.[1] ?? '';
  assert.match(macBlock, /windowLifecycle:\s*true/);
  assert.match(macBlock, /tray:\s*true/);
  assert.match(macBlock, /launchAtStartup:\s*true/);

  const main = read('apps/linklake_manager/lib/main.dart');
  assert.match(main, /登录 macOS 后自动启动/);
  assert.doesNotMatch(main, /does not integrate LaunchAtLogin/);
});

test('macOS host implements the launch_at_startup channel without forced casts', () => {
  const swift = read('apps/linklake_manager/macos/Runner/MainFlutterWindow.swift');
  assert.match(swift, /import LaunchAtLogin/);
  assert.match(swift, /name:\s*"launch_at_startup"/);
  assert.match(swift, /case "launchAtStartupIsEnabled"/);
  assert.match(swift, /case "launchAtStartupSetEnabled"/);
  assert.match(swift, /LaunchAtLogin\.migrateIfNeeded\(\)/);
  assert.match(swift, /FlutterError\(/);
  assert.doesNotMatch(swift, /as!\s*Bool/);
});

test('Xcode project pins LaunchAtLogin and copies the legacy helper after resources', () => {
  const project = read('apps/linklake_manager/macos/Runner.xcodeproj/project.pbxproj');
  assert.match(project, /repositoryURL = "https:\/\/github\.com\/sindresorhus\/LaunchAtLogin"/);
  assert.match(
    project,
    /kind = revision;\s+revision = 9a894d799269cb591037f9f9cb0961510d4dca81;/,
  );
  assert.doesNotMatch(project, /LaunchAtLogin[\s\S]{0,300}branch = main/);
  assert.match(project, /LaunchAtLogin in Frameworks/);
  assert.match(project, /copy-helper-swiftpm\.sh/);

  const runnerPhases = project.match(
    /33CC10EC2044A3C60003C045 \/\* Runner \*\/ = \{[\s\S]*?buildPhases = \(([\s\S]*?)\);/,
  )?.[1];
  assert.ok(runnerPhases);
  assert.ok(runnerPhases.indexOf('33CC10EB2044A3C60003C045') >= 0);
  assert.ok(runnerPhases.indexOf('4C4C4D010000000000000004') > runnerPhases.indexOf('33CC10EB2044A3C60003C045'));

  const config = read('apps/linklake_manager/macos/Runner/Configs/AppInfo.xcconfig');
  assert.match(config, /ENABLE_USER_SCRIPT_SANDBOXING = NO/);
});
