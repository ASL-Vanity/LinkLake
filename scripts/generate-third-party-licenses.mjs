import { spawnSync } from 'node:child_process';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const projectRoot = resolve(scriptDirectory, '..');
const output = resolve(projectRoot, process.argv[2] ?? 'THIRD_PARTY_LICENSES.html');
const temporaryOutput = `${output}.tmp`;
const cargo = process.platform === 'win32' ? 'cargo.exe' : 'cargo';

mkdirSync(dirname(output), { recursive: true });

// 先让 cargo-about 生成完整许可证，再只规范化换行和行尾空白，保证跨平台输出一致。
const result = spawnSync(
  cargo,
  [
    'about',
    'generate',
    'scripts/third-party-licenses.hbs',
    '--workspace',
    '--locked',
    '--all-features',
    '--fail',
    '--output-file',
    temporaryOutput,
  ],
  { cwd: projectRoot, stdio: 'inherit' },
);

if (result.status !== 0) {
  rmSync(temporaryOutput, { force: true });
  process.exit(result.status ?? 1);
}

const normalized = readFileSync(temporaryOutput, 'utf8')
  .replace(/\r\n/g, '\n')
  .replace(/[\t ]+$/gm, '')
  .replace(/\n*$/, '\n');

writeFileSync(output, normalized, 'utf8');
rmSync(temporaryOutput, { force: true });
console.log(`Generated ${output}`);
