import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { ZCODE_RUNTIME } from '../../cli/constants.mjs';

test('macOS dry-run remains PATH-independent and side-effect free', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'zcode-as-subagent-mac-'));
  const result = spawnSync(process.execPath, [path.resolve('bin/zcode-as-subagent.mjs'), 'init', '--dry-run'], {
    encoding: 'utf8', env: { HOME: home, PATH: '', ZCODE_AS_SUBAGENT_TEST_PLATFORM: 'darwin' },
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).plan[0].path, ZCODE_RUNTIME);
  assert.deepEqual(fs.readdirSync(home), []);
});
