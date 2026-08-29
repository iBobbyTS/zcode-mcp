import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { evaluate } from './review-bash-policy.mjs';

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'zcode-policy-'));
fs.writeFileSync(path.join(root, 'src.txt'), 'ok\n');
const input = (command) => evaluate({ tool_name: 'Bash', cwd: root, worktree: root, tool_input: { command } });
for (const command of [
  'find . -delete', 'find . -exec rm -rf {} +', 'git branch -D victim',
  'git diff --output=x', 'openssl x -out x', 'git status && pwd', 'rg ok | head',
  'cat /etc/passwd', 'cat ~/.zshrc', 'cat ../secret', 'cd /tmp',
]) assert.equal(input(command).allowed, false, command);
for (const command of ['pwd', 'ls .', 'rg ok src.txt', 'sed -n 1,2p src.txt', 'git status --short', 'git diff --stat', 'git log --oneline']) {
  assert.equal(input(command).allowed, true, command);
}
console.log('review Bash policy corpus: PASS');
