import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { evaluateCommand } from '../lib/readonly-bash-policy.mjs';

const corpus = JSON.parse(fs.readFileSync(new URL('../policy-corpus.json', import.meta.url), 'utf8'));

function reasonClass(result, command) {
  if (result.decision === 'allow') return 'allow';
  if (result.code === 'git_operand_sensitive_path') return 'path';
  if (result.code.startsWith('git_')) return 'git';
  if (result.code.startsWith('shell_')) return 'shell';
  if (command.startsWith('git ')) return 'git';
  if (result.code.endsWith('_path_required') || result.code === 'grep_path_required' || result.code === 'stdin_path') return 'stdin';
  if (result.code.includes('path') || result.code.startsWith('sensitive_') || result.code.startsWith('symlink_')) return 'path';
  return 'stdin';
}

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'zcode-policy-corpus-'));
  fs.mkdirSync(path.join(root, 'src'));
  fs.mkdirSync(path.join(root, '.agent-work', 'reviews'), { recursive: true });
  fs.writeFileSync(path.join(root, 'README.md'), 'needle\n');
  fs.writeFileSync(path.join(root, 'src', 'lib.rs'), 'fn main() {}\n');
  fs.writeFileSync(path.join(root, '.env'), 'SECRET=x\n');
  fs.writeFileSync(path.join(root, '.agent-work', 'reviews', 'old.md'), 'old\n');
  return root;
}

test('Rust and JavaScript evaluate the shared bounded policy corpus', () => {
  const root = fixture();
  for (const entry of corpus.allow) {
    const result = evaluateCommand({ command: entry.command, cwd: root });
    assert.equal(result.decision, 'allow', `${entry.command}: ${result.code} ${result.reason}`);
    assert.equal(reasonClass(result, entry.command), entry.reason_class, entry.command);
  }
  for (const entry of corpus.deny) {
    const result = evaluateCommand({ command: entry.command, cwd: root });
    assert.equal(result.decision, 'deny', `${entry.command}: unexpectedly ${result.code}`);
    assert.equal(reasonClass(result, entry.command), entry.reason_class, `${entry.command}: ${result.code}`);
  }
});
