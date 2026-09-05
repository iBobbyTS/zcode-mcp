import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

const cli = path.resolve('bin/zcode-as-subagent.mjs');

function run(home, args) {
  return spawnSync(process.execPath, [cli, ...args], {
    encoding: 'utf8',
    env: { ...process.env, HOME: home, ZCODE_AS_SUBAGENT_TEST_PLATFORM: 'win32' },
  });
}

test('Windows help and version work without creating anything', () => {
  for (const args of [['--help'], ['version']]) {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'zcode-as-subagent-win-basic-'));
    const result = run(home, args);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(fs.readdirSync(home).length, 0);
  }
});

test('every business command is rejected structurally before filesystem side effects', () => {
  const commands = ['init', 'config', 'status', 'diagnose', 'backup', 'restore', 'start', 'stop', 'uninstall', 'purge', 'cleanup-legacy', 'create', 'get', 'list', 'send', 'respond', 'cancel', 'result', 'close'];
  for (const command of commands) {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), `zcode-as-subagent-win-${command}-`));
    const result = run(home, [command]);
    assert.equal(result.status, 1, `${command}: ${result.stderr}`);
    assert.equal(JSON.parse(result.stderr).error.code, 'UNSUPPORTED_PLATFORM');
    assert.deepEqual(fs.readdirSync(home), []);
  }
});
