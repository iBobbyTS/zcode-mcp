import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

const hook = new URL('../hooks/check-bash-readonly.mjs', import.meta.url);
const auditHook = new URL('../hooks/audit-bash-result.mjs', import.meta.url);

function runHook(command, cwd, env = {}) {
  const input = {
    session_id: 'session-test',
    cwd,
    hook_event_name: 'PreToolUse',
    tool_name: 'Bash',
    tool_input: { command, description: 'test' },
    tool_use_id: 'tool-test',
  };
  const proc = spawnSync(process.execPath, [hook.pathname], {
    input: `${JSON.stringify(input)}\n`,
    encoding: 'utf8',
    env: { ...process.env, ...env },
  });
  assert.equal(proc.status, 0, proc.stderr);
  return JSON.parse(proc.stdout);
}

test('hook allows and rewrites a safe Git command', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'zcode-hook-'));
  const output = runHook('git status --short', root);
  assert.equal(output.hookSpecificOutput.permissionDecision, 'allow');
  assert.match(output.hookSpecificOutput.updatedInput.command, /^GIT_OPTIONAL_LOCKS=0 GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=\/dev\/null GIT_ATTR_NOSYSTEM=1 \/.*\/git /u);
  assert.equal(output.hookSpecificOutput.updatedInput.description, 'test');
});

test('hook denies shell composition', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'zcode-hook-'));
  const output = runHook('git status & touch /tmp/pwn', root);
  assert.equal(output.hookSpecificOutput.permissionDecision, 'deny');
  assert.match(output.hookSpecificOutput.permissionDecisionReason, /shell_background/u);
  assert.equal('updatedInput' in output.hookSpecificOutput, false);
});

test('hook supports ask for unsupported commands when explicitly configured', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'zcode-hook-'));
  fs.writeFileSync(path.join(root, 'README.md'), 'x');
  const output = runHook('file README.md', root, { ZCODE_READONLY_BASH_UNKNOWN_DECISION: 'ask' });
  assert.equal(output.hookSpecificOutput.permissionDecision, 'ask');
});

test('shipped plugin discovers the default guard and both audit hooks', () => {
  const packageRoot = path.dirname(new URL('../package.json', import.meta.url).pathname);
  const hooks = JSON.parse(fs.readFileSync(path.join(packageRoot, 'hooks', 'hooks.json'), 'utf8'));
  assert.deepEqual(Object.keys(hooks.hooks).sort(), [
    'PostToolUse',
    'PostToolUseFailure',
    'PreToolUse',
  ]);
  for (const event of Object.values(hooks.hooks)) {
    assert.equal(event.length, 1);
    assert.equal(event[0].matcher, 'Bash');
    const script = event[0].hooks[0].args[0].replace('${ZCODE_PLUGIN_ROOT}/', '');
    assert.equal(fs.existsSync(path.join(packageRoot, script)), true, script);
  }

  const outerRoot = path.resolve(packageRoot, '..');
  const outer = JSON.parse(fs.readFileSync(path.join(outerRoot, '.codex-plugin', 'plugin.json'), 'utf8'));
  const outerHooks = JSON.parse(fs.readFileSync(path.join(outerRoot, 'hooks', 'hooks.json'), 'utf8'));
  assert.equal(outer.hooks, './hooks/hooks.json');
  assert.deepEqual(Object.keys(outerHooks.hooks).sort(), ['PostToolUse', 'PostToolUseFailure', 'PreToolUse']);
  for (const event of Object.values(outerHooks.hooks)) {
    assert.equal(event[0].matcher, 'Bash');
    const script = event[0].hooks[0].args[0].replace('${ZCODE_PLUGIN_ROOT}/', '');
    assert.equal(fs.existsSync(path.join(outerRoot, script)), true, script);
  }
  const policyPath = path.resolve(outerRoot, outer.reviewPolicy.resource);
  assert.equal(fs.existsSync(policyPath), true);
  assert.equal(outer.reviewPolicy.postToolUseAudit, true);
});

test('default PostToolUse audit writes bounded metadata without raw output', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'zcode-hook-audit-root-'));
  const data = fs.mkdtempSync(path.join(os.tmpdir(), 'zcode-hook-audit-data-'));
  fs.writeFileSync(path.join(root, 'README.md'), 'needle\n');
  const input = {
    session_id: 'session-audit',
    tool_use_id: 'tool-audit',
    hook_event_name: 'PostToolUse',
    tool_name: 'Bash',
    cwd: root,
    duration_ms: 17,
    tool_input: { command: 'cat README.md' },
    tool_response: { status_code: 0, stdout: 'sensitive output', stderr: '' },
  };
  const proc = spawnSync(process.execPath, [auditHook.pathname], {
    input: `${JSON.stringify(input)}\n`,
    encoding: 'utf8',
    env: { ...process.env, ZCODE_PLUGIN_DATA: data },
  });
  assert.equal(proc.status, 0, proc.stderr);
  const raw = fs.readFileSync(path.join(data, 'readonly-bash-audit.jsonl'), 'utf8');
  const record = JSON.parse(raw.trim());
  assert.equal(record.tool_use_id, 'tool-audit');
  assert.equal(record.status_code, 0);
  assert.equal(record.duration_ms, 17);
  assert.match(record.canonical_argv.at(-2), /\/cat$/u);
  assert.equal(record.canonical_argv.at(-1), 'README.md');
  assert.match(record.stdout_sha256, /^[a-f0-9]{64}$/u);
  assert.equal(raw.includes('sensitive output'), false);
});
