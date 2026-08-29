#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const pluginRoot = path.resolve(new URL('..', import.meta.url).pathname);
const hookRoot = path.join(pluginRoot, 'review-bash-hook');
const configPath = process.argv[process.argv.indexOf('--config') + 1];
const provenanceIndex = process.argv.indexOf('--provenance');
const provenancePath = provenanceIndex >= 0 ? process.argv[provenanceIndex + 1] : path.join(path.dirname(configPath ?? ''), 'review-bash-hook-provenance.json');
if (!configPath || configPath.startsWith('--')) process.exit(2);
let config;
let provenance;
try {
  config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  provenance = JSON.parse(fs.readFileSync(provenancePath, 'utf8'));
} catch {
  console.log(JSON.stringify({ ok: false, code: 'REVIEW_BASH_POLICY_UNVERIFIED' }));
  process.exit(1);
}
const expectedScripts = {
  PreToolUse: path.join(hookRoot, 'hooks', 'check-bash-readonly.mjs'),
  PostToolUse: path.join(hookRoot, 'hooks', 'audit-bash-result.mjs'),
  PostToolUseFailure: path.join(hookRoot, 'hooks', 'audit-bash-result.mjs'),
};
const events = config?.hooks?.events ?? {};
const active = config?.hooks?.enabled === true && Object.entries(expectedScripts).every(([event, expectedScript]) =>
  Array.isArray(events[event]) && events[event].some((entry) =>
    entry.matcher === 'Bash' && entry.description === `review-bash-hook:${event}` &&
    entry.hooks?.length === 1 && entry.hooks[0].type === 'process' &&
    entry.hooks[0].command === process.execPath && entry.hooks[0].timeoutMs === 5000 &&
    entry.hooks[0].args?.length === 1 && entry.hooks[0].args[0] === expectedScript));
const hashFile = (file) => {
  try { return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'); } catch { return null; }
};
const ok = active && provenance.hook_activation_verified === true &&
  provenance.effective_hook_version === provenance.expected_hook_version &&
  provenance.effective_hook_sha256 === provenance.expected_hook_sha256 &&
  provenance.effective_hook_sha256 === hashFile(provenance.effective_hook_path) &&
  provenance.effective_config_path === path.resolve(configPath) &&
  provenance.effective_config_sha256 === hashFile(configPath) &&
  provenance.effective_guard_wrapper_path === expectedScripts.PreToolUse &&
  provenance.effective_guard_wrapper_sha256 === hashFile(expectedScripts.PreToolUse) &&
  provenance.effective_audit_wrapper_path === expectedScripts.PostToolUse &&
  provenance.effective_audit_wrapper_sha256 === hashFile(expectedScripts.PostToolUse);
console.log(JSON.stringify({ ok: Boolean(ok), code: ok ? 'REVIEW_BASH_POLICY_VERIFIED' : 'REVIEW_BASH_POLICY_UNVERIFIED', provenance }));
process.exit(ok ? 0 : 1);
