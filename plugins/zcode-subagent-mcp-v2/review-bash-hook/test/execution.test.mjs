import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { evaluateCommand } from '../lib/readonly-bash-policy.mjs';

function run(program, args, options = {}) {
  const proc = spawnSync(program, args, { encoding: 'utf8', ...options });
  assert.equal(proc.status, 0, `${program} ${args.join(' ')}\n${proc.stdout}\n${proc.stderr}`);
  return proc;
}

function gitFixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'zcode-bash-exec-'));
  run('git', ['init', '-q'], { cwd: root });
  run('git', ['config', 'user.email', 'test@example.invalid'], { cwd: root });
  run('git', ['config', 'user.name', 'Test'], { cwd: root });
  fs.mkdirSync(path.join(root, 'src'));
  fs.writeFileSync(path.join(root, 'README.md'), 'needle\n');
  fs.writeFileSync(path.join(root, 'src', 'a.js'), 'const needle = 1;\n');
  run('git', ['add', '.'], { cwd: root });
  run('git', ['commit', '-qm', 'fixture'], { cwd: root });
  return root;
}

test('canonical allowed commands execute without changing tracked or staged state', () => {
  const root = gitFixture();
  const commands = [
    'git status --short',
    'git log --oneline -n 1',
    'git diff --stat HEAD~0 HEAD',
    'git show --stat HEAD',
    'git rev-parse --verify HEAD',
    'git cat-file -t HEAD',
    'git ls-files -- src',
    'git branch --show-current',
    `rg -n 'needle' src`,
    `sed -n '1,5p' README.md`,
    `find . -maxdepth 2 -type f -name '*.js'`,
    'shasum -a 256 README.md',
  ];

  for (const command of commands) {
    const evaluated = evaluateCommand({ command, cwd: root });
    assert.equal(evaluated.decision, 'allow', `${command}: ${evaluated.code}`);
    const proc = spawnSync('/bin/sh', ['-c', evaluated.canonicalCommand], { cwd: root, encoding: 'utf8' });
    assert.equal(proc.status, 0, `${command}\n${proc.stdout}\n${proc.stderr}`);
    const status = run('git', ['status', '--porcelain=v1'], { cwd: root }).stdout;
    assert.equal(status, '', `${command} changed repository state: ${status}`);
  }
});
