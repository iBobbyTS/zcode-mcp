#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const pluginRoot = path.resolve(new URL('..', import.meta.url).pathname);
const hookRoot = pluginRoot;
const configPath = process.argv[process.argv.indexOf('--config') + 1];
const provenanceIndex = process.argv.indexOf('--provenance');
const provenancePath = provenanceIndex >= 0 ? process.argv[provenanceIndex + 1] : path.join(path.dirname(configPath ?? ''), 'zcode-agent-hook-provenance.json');
if (!configPath || configPath.startsWith('--')) process.exit(2);
let config;
let provenance;
try {
  config = JSON.parse(fs.readFileSync(configPath, 'utf8'));
  provenance = JSON.parse(fs.readFileSync(provenancePath, 'utf8'));
} catch {
  console.log(JSON.stringify({ ok: false, code: 'AGENT_BASH_POLICY_UNVERIFIED' }));
  process.exit(1);
}
const expectedScripts = {
  PreToolUse: [
    ['Bash', path.join(hookRoot, 'hooks', 'check-bash-readonly.mjs')],
    ['^(Read|Grep|Glob|Write|Edit|Delete|Move)$', path.join(hookRoot, 'hooks', 'check-agent-files.mjs')],
  ],
  PostToolUse: [['Bash', path.join(hookRoot, 'hooks', 'audit-bash-result.mjs')]],
  PostToolUseFailure: [['Bash', path.join(hookRoot, 'hooks', 'audit-bash-result.mjs')]],
};
const events = config?.hooks?.events ?? {};
const active = config?.hooks?.enabled === true && Object.entries(expectedScripts).every(([event, expectedEntries]) => {
  if (!Array.isArray(events[event])) return false;
  return expectedEntries.every(([matcher, expectedScript]) => {
    const matching = events[event].filter((entry) => entry?.matcher === matcher);
    if (matching.length !== 1) return false;
    const [entry] = matching;
    return !Object.hasOwn(entry, 'description') &&
      entry.hooks?.length === 1 && entry.hooks[0].type === 'process' &&
      entry.hooks[0].command === process.execPath && entry.hooks[0].timeoutMs === 5000 &&
      entry.hooks[0].args?.length === 1 && entry.hooks[0].args[0] === expectedScript;
  });
});
const hashFile = (file) => {
  try { return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex'); } catch { return null; }
};
const ok = active && provenance.hook_activation_verified === true &&
  provenance.effective_hook_version === provenance.expected_hook_version &&
  provenance.effective_hook_sha256 === provenance.expected_hook_sha256 &&
  provenance.effective_hook_sha256 === hashFile(provenance.effective_hook_path) &&
  provenance.effective_file_policy_sha256 === hashFile(provenance.effective_file_policy_path) &&
  provenance.effective_config_path === path.resolve(configPath) &&
  provenance.effective_config_sha256 === hashFile(configPath) &&
  provenance.effective_guard_wrapper_path === expectedScripts.PreToolUse[0][1] &&
  provenance.effective_guard_wrapper_sha256 === hashFile(expectedScripts.PreToolUse[0][1]) &&
  provenance.effective_audit_wrapper_path === expectedScripts.PostToolUse[0][1] &&
  provenance.effective_audit_wrapper_sha256 === hashFile(expectedScripts.PostToolUse[0][1]) &&
  provenance.effective_file_wrapper_path === expectedScripts.PreToolUse[1][1] &&
  provenance.effective_file_wrapper_sha256 === hashFile(expectedScripts.PreToolUse[1][1]);
console.log(JSON.stringify({ ok: Boolean(ok), code: ok ? 'AGENT_BASH_POLICY_VERIFIED' : 'AGENT_BASH_POLICY_UNVERIFIED', provenance }));
process.exit(ok ? 0 : 1);
