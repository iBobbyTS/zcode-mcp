import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';

const root = path.resolve(import.meta.dirname, '../..');
const binary = path.join(root, 'npm/native/darwin-arm64/zcode-agentd');

test('macOS arm64 daemon payload is present and executable', () => {
  const stat = fs.statSync(binary);
  assert.equal(stat.mode & 0o777, 0o755);
  assert.ok(stat.size > 0);
});

test('npm files whitelist includes the native payload directory', () => {
  const packageJson = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  assert.ok(packageJson.files.includes('npm/'));
});
