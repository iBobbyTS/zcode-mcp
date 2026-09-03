import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { spawnSync } from 'node:child_process';
import { evaluateAgentFileInput } from '../../lib/agent-file-policy.mjs';

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'zcode-agent-file-'));
  fs.mkdirSync(path.join(root, 'src'), { recursive: true });
  fs.writeFileSync(path.join(root, 'src', 'ok.txt'), 'ok');
  return root;
}

function env(root, manifest = []) {
  return {
    ZCODE_AGENT_POLICY: '1',
    ZCODE_AGENT_WORKTREE_ROOT: root,
    ZCODE_AGENT_WRITE_MANIFEST: JSON.stringify(manifest),
  };
}

test('supports snake_case and camelCase hook payloads while redacting paths', () => {
  const root = fixture();
  const e = env(root);
  assert.equal(evaluateAgentFileInput({ tool_name: 'Read', tool_input: { file_path: 'src/ok.txt' }, cwd: root }, e).decision, 'allow');
  assert.equal(evaluateAgentFileInput({ toolName: 'Read', toolInput: { filePath: path.join(root, 'src/ok.txt') }, workingDirectory: root }, e).decision, 'allow');
  const denied = evaluateAgentFileInput({ tool_name: 'Read', tool_input: { file_path: '/etc/passwd' }, cwd: root }, e);
  assert.equal(denied.decision, 'deny');
  assert.equal(denied.reason.includes(root), false);
});

test('requires marker and canonical root, and rejects traversal/symlink escape', () => {
  const root = fixture();
  assert.equal(evaluateAgentFileInput({ tool_name: 'Read', tool_input: { path: 'src/ok.txt' } }, {}).code, 'policy_marker_missing');
  assert.equal(evaluateAgentFileInput({ tool_name: 'Read', tool_input: { path: 'src/ok.txt' } }, { ZCODE_AGENT_POLICY: '1' }).code, 'worktree_root_missing');
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'zcode-agent-outside-'));
  fs.writeFileSync(path.join(outside, 'secret.txt'), 'secret');
  fs.symlinkSync(outside, path.join(root, 'link'));
  const e = env(root);
  assert.equal(evaluateAgentFileInput({ tool_name: 'Read', tool_input: { path: '../secret.txt' }, cwd: root }, e).decision, 'deny');
  assert.equal(evaluateAgentFileInput({ tool_name: 'Read', tool_input: { path: 'link/secret.txt' }, cwd: root }, e).decision, 'deny');
});

test('permits explicitly configured bootstrap reads but never bootstrap writes', () => {
  const root = fixture();
  const bootstrap = fs.mkdtempSync(path.join(os.tmpdir(), 'zcode-agent-bootstrap-'));
  fs.writeFileSync(path.join(bootstrap, 'runtime.js'), 'runtime');
  const e = { ...env(root), ZCODE_AGENT_BOOTSTRAP_ROOTS: bootstrap };
  assert.equal(evaluateAgentFileInput({ tool_name: 'Read', tool_input: { file_path: path.join(bootstrap, 'runtime.js') }, cwd: root }, e).decision, 'allow');
  assert.equal(evaluateAgentFileInput({ tool_name: 'Read', tool_input: { file_path: '/etc/hosts' }, cwd: root }, e).decision, 'deny');
  assert.equal(evaluateAgentFileInput({ tool_name: 'Write', tool_input: { file_path: path.join(bootstrap, 'new.js') }, cwd: root }, e).code, 'write_not_allowlisted');
  assert.equal(evaluateAgentFileInput({ tool_name: 'Read', tool_input: { file_path: path.join(bootstrap, '.env') }, cwd: root }, e).decision, 'deny');
  assert.equal(evaluateAgentFileInput({ tool_name: 'Read', tool_input: { file_path: path.join(bootstrap, 'missing') }, cwd: root }, { ...env(root), ZCODE_AGENT_BOOTSTRAP_ROOTS: JSON.stringify([path.join(root, '.zcode')]) }).code, 'bootstrap_roots_invalid');
});

test('read-only denies mutations and workspace-write is manifest confined', () => {
  const root = fixture();
  const readonly = env(root, []);
  assert.equal(evaluateAgentFileInput({ tool_name: 'Write', tool_input: { file_path: 'src/new.txt' }, cwd: root }, readonly).code, 'write_not_allowlisted');
  const writable = env(root, ['src']);
  assert.equal(evaluateAgentFileInput({ toolName: 'Edit', toolInput: { filePath: 'src/ok.txt' }, workingDirectory: root }, writable).decision, 'allow');
  assert.equal(evaluateAgentFileInput({ tool_name: 'Delete', tool_input: { path: 'other.txt' }, cwd: root }, writable).code, 'write_not_allowlisted');
  assert.equal(evaluateAgentFileInput({ tool_name: 'Move', tool_input: { source: 'src/ok.txt', destination: 'other.txt' }, cwd: root }, writable).code, 'write_not_allowlisted');
});

test('rejects protected metadata and secrets for reads and manifests', () => {
  const root = fixture();
  fs.mkdirSync(path.join(root, '.git'), { recursive: true });
  fs.writeFileSync(path.join(root, '.env'), 'TOKEN=secret');
  const e = env(root);
  assert.equal(evaluateAgentFileInput({ tool_name: 'Read', tool_input: { path: '.git/config' }, cwd: root }, e).code, 'path_outside_root');
  assert.equal(evaluateAgentFileInput({ tool_name: 'Read', tool_input: { path: '.env' }, cwd: root }, e).code, 'path_outside_root');
  assert.equal(evaluateAgentFileInput({ tool_name: 'Write', tool_input: { path: 'src/api_key.txt' }, cwd: root }, env(root, ['src'])).code, 'path_outside_root');
});

test('standalone process hook fails closed without echoing malformed input', () => {
  const script = path.resolve(new URL('../../hooks/check-agent-files.mjs', import.meta.url).pathname);
  const proc = spawnSync(process.execPath, [script], { input: '{"tool_name":"Read","tool_input":{"path":"/private/secret"}', encoding: 'utf8' });
  assert.equal(proc.status, 0);
  assert.match(proc.stdout, /"permissionDecision":"deny"/u);
  assert.equal(proc.stdout.includes('/private/secret'), false);
});

test('installer adds recognized matcher while preserving Bash and Post hooks', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'zcode-agent-install-'));
  const config = path.join(directory, 'config.json');
  const provenance = path.join(directory, 'provenance.json');
  fs.writeFileSync(config, JSON.stringify({
    unrelated: { keep: true },
    hooks: {
      enabled: true,
      events: {
        PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'process', command: 'node', args: ['/custom/bash.mjs'] }] }],
        PostToolUse: [{ matcher: 'Bash', hooks: [{ type: 'process', command: 'node', args: ['/custom/post.mjs'] }] }],
      },
    },
  }));
  const installer = path.resolve(new URL('../../scripts/install-agent-policy-hook.mjs', import.meta.url).pathname);
  const proc = spawnSync(process.execPath, [installer, config, provenance], { encoding: 'utf8' });
  assert.equal(proc.status, 0, proc.stderr);
  const installed = JSON.parse(fs.readFileSync(config, 'utf8'));
  assert.deepEqual(installed.unrelated, { keep: true });
  assert.equal(installed.hooks.events.PreToolUse.some((entry) => entry.matcher === 'Bash'), true);
  const policy = installed.hooks.events.PreToolUse.find((entry) => entry.matcher === '^(Read|Grep|Glob|Write|Edit|Delete|Move)$');
  assert.equal(policy.matcher, '^(Read|Grep|Glob|Write|Edit|Delete|Move)$');
  assert.equal(policy.hooks[0].args[0].endsWith('/hooks/check-agent-files.mjs'), true);
  assert.equal(installed.hooks.events.PostToolUse[0].hooks[0].args[0], '/custom/post.mjs');
  assert.equal(JSON.parse(fs.readFileSync(provenance, 'utf8')).config_sha256.length, 64);
});
