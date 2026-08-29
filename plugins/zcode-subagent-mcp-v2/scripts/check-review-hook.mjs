#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

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
const events = config?.hooks?.events ?? {};
const active = ['PreToolUse', 'PostToolUse', 'PostToolUseFailure'].every((event) =>
  Array.isArray(events[event]) && events[event].some((entry) =>
    entry.matcher === 'Bash' && entry.description === `review-bash-hook:${event}` &&
    entry.hooks?.[0]?.args?.[0] && fs.existsSync(entry.hooks[0].args[0])));
let artifactHash = null;
try {
  artifactHash = crypto.createHash('sha256').update(fs.readFileSync(provenance.effective_hook_path)).digest('hex');
} catch {}
const ok = active && provenance.hook_activation_verified === true &&
  provenance.effective_hook_version === provenance.expected_hook_version &&
  provenance.effective_hook_sha256 === provenance.expected_hook_sha256 &&
  provenance.effective_hook_sha256 === artifactHash;
console.log(JSON.stringify({ ok: Boolean(ok), code: ok ? 'REVIEW_BASH_POLICY_VERIFIED' : 'REVIEW_BASH_POLICY_UNVERIFIED', provenance }));
process.exit(ok ? 0 : 1);
