#!/usr/bin/env node
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

const pluginRoot = path.resolve(new URL('..', import.meta.url).pathname);
const configPath = process.argv[process.argv.indexOf('--config') + 1];
const provenanceIndex = process.argv.indexOf('--provenance');
const provenancePath = provenanceIndex >= 0 ? process.argv[provenanceIndex + 1] : path.join(path.dirname(configPath ?? ''), 'review-bash-hook-provenance.json');
if (!configPath || configPath.startsWith('--')) process.exit(2);
const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
const events = config?.hooks?.events ?? {};
assert.equal(config?.hooks?.enabled, true, 'hooks are disabled');
const entries = {};
for (const event of ['PreToolUse', 'PostToolUse', 'PostToolUseFailure']) {
  entries[event] = events[event]?.find((entry) => entry.matcher === 'Bash' && entry.description === `review-bash-hook:${event}`);
  assert.ok(entries[event], `missing ${event} hook`);
  assert.equal(entries[event].hooks?.length, 1, `${event} hook shape changed`);
  assert.equal(entries[event].hooks[0].command, process.execPath, `${event} command changed`);
  assert.equal(entries[event].hooks[0].args?.length, 1, `${event} args changed`);
}
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'review-hook-preflight-'));
fs.writeFileSync(path.join(root, 'README.md'), 'safe\n');
const canary = path.join(root, 'canary');
fs.writeFileSync(canary, 'unchanged\n');
const guardWrapper = entries.PreToolUse.hooks[0].args[0];
assert.equal(guardWrapper, path.join(pluginRoot, 'review-bash-hook', 'hooks', 'check-bash-readonly.mjs'));
const run = (command) => spawnSync(entries.PreToolUse.hooks[0].command, [guardWrapper], {
  input: `${JSON.stringify({ tool_name: 'Bash', cwd: root, tool_input: { command } })}\n`, encoding: 'utf8',
});
const safe = run('cat README.md');
assert.equal(JSON.parse(safe.stdout).hookSpecificOutput.permissionDecision, 'allow');
const dangerous = run(`find . -delete`);
assert.equal(JSON.parse(dangerous.stdout).hookSpecificOutput.permissionDecision, 'deny');
assert.equal(fs.readFileSync(canary, 'utf8'), 'unchanged\n');
const generation = JSON.parse(fs.readFileSync(provenancePath, 'utf8'));
const hashFile = (file) => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
assert.equal(generation.effective_config_path, path.resolve(configPath));
assert.equal(generation.effective_config_sha256, hashFile(configPath));
assert.equal(generation.effective_guard_wrapper_path, guardWrapper);
assert.equal(generation.effective_guard_wrapper_sha256, hashFile(guardWrapper));
assert.equal(generation.effective_audit_wrapper_path, entries.PostToolUse.hooks[0].args[0]);
assert.equal(generation.effective_audit_wrapper_sha256, hashFile(entries.PostToolUse.hooks[0].args[0]));
generation.hook_activation_verified = true;
const temporary = `${provenancePath}.tmp-${process.pid}`;
fs.writeFileSync(temporary, `${JSON.stringify(generation, null, 2)}\n`, { mode: 0o600 });
fs.renameSync(temporary, provenancePath);
console.log(JSON.stringify({ ok: true, code: 'REVIEW_BASH_POLICY_VERIFIED', activation_generation: generation.activation_generation }));
