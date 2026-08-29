import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { evaluateCommand } from '../lib/readonly-bash-policy.mjs';

function rootFixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'zcode-bash-fuzz-'));
  fs.writeFileSync(path.join(root, 'README.md'), 'needle\n');
  fs.mkdirSync(path.join(root, 'src'));
  fs.writeFileSync(path.join(root, 'src', 'a.js'), 'needle\n');
  return root;
}

function prng(seed) {
  let state = seed >>> 0;
  return () => {
    state = (1664525 * state + 1013904223) >>> 0;
    return state / 0x100000000;
  };
}

test('metacharacter mutation corpus never upgrades to allow', () => {
  const root = rootFixture();
  const bases = ['git status --short', 'rg -n needle src', 'cat README.md', 'find . -maxdepth 2 -type f -print'];
  const injections = ['; touch pwn', ' & touch pwn', ' && touch pwn', ' | cat', ' > out', ' < in', ' $(id)', ' `id`', ' *.js', ' # comment'];
  for (const base of bases) {
    for (const injection of injections) {
      const result = evaluateCommand({ command: `${base}${injection}`, cwd: root });
      assert.notEqual(result.decision, 'allow', `${base}${injection}`);
    }
  }
});

test('deterministic random dangerous mutations remain denied', () => {
  const root = rootFixture();
  const random = prng(0x5a17c0de);
  const fragments = [';', '&', '&&', '|', '>', '<', '$(', '`', '*', '?', '[', '#'];
  const safe = ['git status --short', 'rg -n needle src', 'cat README.md'];
  for (let i = 0; i < 2000; i += 1) {
    const base = safe[Math.floor(random() * safe.length)];
    const fragment = fragments[Math.floor(random() * fragments.length)];
    const position = Math.floor(random() * (base.length + 1));
    const mutated = `${base.slice(0, position)}${fragment}${base.slice(position)}`;
    const result = evaluateCommand({ command: mutated, cwd: root });
    assert.notEqual(result.decision, 'allow', mutated);
  }
});

test('dangerous find and Git mutation option families remain denied', () => {
  const root = rootFixture();
  for (const option of ['-delete', '-exec', '-execdir', '-ok', '-okdir', '-fprint', '-fprintf', '-fls']) {
    const suffix = ['-exec', '-execdir', '-ok', '-okdir'].includes(option) ? ` ${option} 'rm' '{}' +` : ` ${option} out`;
    assert.equal(evaluateCommand({ command: `find .${suffix}`, cwd: root }).decision, 'deny');
  }
  for (const command of ['git branch -d x', 'git branch -D x', 'git branch -m x', 'git diff --output=x', 'git diff --ext-diff', 'git show --textconv HEAD']) {
    assert.equal(evaluateCommand({ command, cwd: root }).decision, 'deny', command);
  }
});
