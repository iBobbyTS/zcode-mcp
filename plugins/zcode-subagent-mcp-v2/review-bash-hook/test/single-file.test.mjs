import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

const modular = new URL('../hooks/check-bash-readonly.mjs', import.meta.url).pathname;
const bundled = new URL('../single-file/check-bash-status.mjs', import.meta.url).pathname;

function run(script, input) {
  const proc = spawnSync(process.execPath, [script], {
    input: `${JSON.stringify(input)}\n`,
    encoding: 'utf8',
    env: process.env,
  });
  assert.equal(proc.status, 0, proc.stderr);
  return JSON.parse(proc.stdout);
}

test('single-file replacement remains behaviorally identical to modular hook', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'zcode-single-file-'));
  fs.writeFileSync(path.join(root, 'README.md'), 'needle\n');
  for (const command of [
    'git status --short',
    `rg -n 'needle|other' README.md`,
    'find . -delete',
    'cat ~/.ssh/id_rsa',
  ]) {
    const input = {
      cwd: root,
      hook_event_name: 'PreToolUse',
      tool_name: 'Bash',
      tool_input: { command },
    };
    assert.deepEqual(run(bundled, input), run(modular, input), command);
  }
});
