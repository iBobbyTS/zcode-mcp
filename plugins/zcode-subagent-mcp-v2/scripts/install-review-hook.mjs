#!/usr/bin/env node
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const pluginRoot = path.resolve(new URL('..', import.meta.url).pathname);
const hookRoot = path.join(pluginRoot, 'review-bash-hook');
const configPath = process.argv[process.argv.indexOf('--config') + 1];
if (!configPath || configPath.startsWith('--')) {
  console.error('usage: node install-review-hook.mjs --config /absolute/config.json [--provenance /absolute/provenance.json]');
  process.exit(2);
}
const provenanceIndex = process.argv.indexOf('--provenance');
const provenancePath = provenanceIndex >= 0
  ? process.argv[provenanceIndex + 1]
  : path.join(path.dirname(configPath), 'review-bash-hook-provenance.json');

function readJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch (error) {
    if (error?.code === 'ENOENT') return fallback;
    throw error;
  }
}

function atomicWrite(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const temporary = `${file}.tmp-${process.pid}`;
  fs.writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  fs.renameSync(temporary, file);
}

const config = readJson(configPath, {});
if (!config || typeof config !== 'object' || Array.isArray(config)) throw new Error('config must be a JSON object');
const next = structuredClone(config);
next.hooks ??= {};
next.hooks.enabled = true;
next.hooks.events ??= {};
const events = {
  PreToolUse: { script: 'check-bash-readonly.mjs' },
  PostToolUse: { script: 'audit-bash-result.mjs' },
  PostToolUseFailure: { script: 'audit-bash-result.mjs' },
};

function processHookArgs(candidate) {
  if (!candidate || candidate.matcher !== 'Bash' || !Array.isArray(candidate.hooks)) return [];
  return candidate.hooks
    .filter((hook) => hook?.type === 'process' && Array.isArray(hook.args))
    .flatMap((hook) => hook.args)
    .filter((arg) => typeof arg === 'string');
}

function isRecognizedReviewHook(candidate, event, expectedScript) {
  if (candidate?.matcher !== 'Bash') return false;
  if (candidate.description === `review-bash-hook:${event}`) return true;
  const args = processHookArgs(candidate);
  return args.some((arg) => path.resolve(arg) === expectedScript || path.basename(arg) === 'check-bash-status.mjs');
}

for (const [event, { script }] of Object.entries(events)) {
  const existing = Array.isArray(next.hooks.events[event]) ? next.hooks.events[event] : [];
  const expectedScript = path.join(hookRoot, 'hooks', script);
  const bashEntries = existing.filter((candidate) => candidate?.matcher === 'Bash');
  const unknownBashEntries = bashEntries.filter((candidate) => !isRecognizedReviewHook(candidate, event, expectedScript));
  if (unknownBashEntries.length > 0) {
    throw new Error(`${event} contains an unknown Bash hook; refusing to modify configuration`);
  }
  const entry = {
    matcher: 'Bash',
    hooks: [{ type: 'process', command: process.execPath, args: [expectedScript], timeoutMs: 5000 }],
  };
  // ZCode 0.16.5 accepts one Bash matcher per event and rejects the
  // description field. Replace only recognized review hooks (including the
  // legacy check-bash-status wrapper) while preserving unrelated matchers.
  const unrelated = existing.filter((candidate) => candidate?.matcher !== 'Bash');
  next.hooks.events[event] = [...unrelated, entry];
}
atomicWrite(configPath, next);

const effectiveConfigPath = path.resolve(configPath);
const effectiveHookPath = path.join(hookRoot, 'lib', 'readonly-bash-policy.mjs');
const guardWrapperPath = path.join(hookRoot, 'hooks', 'check-bash-readonly.mjs');
const auditWrapperPath = path.join(hookRoot, 'hooks', 'audit-bash-result.mjs');
const hashFile = (file) => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const hookSource = fs.readFileSync(effectiveHookPath);
const hookSha256 = crypto.createHash('sha256').update(hookSource).digest('hex');
const daemonSource = fs.readFileSync(path.join(pluginRoot, '..', '..', 'crates', 'review-preparation', 'src', 'policy.rs'));
const daemonSha256 = crypto.createHash('sha256').update(daemonSource).digest('hex');
atomicWrite(provenancePath, {
  daemon_policy_version: 'zcode-readonly-bash/v1.0.0',
  daemon_policy_sha256: daemonSha256,
  expected_hook_version: 'zcode-readonly-bash/v1.0.0',
  expected_hook_sha256: hookSha256,
  effective_hook_version: 'zcode-readonly-bash/v1.0.0',
  effective_hook_sha256: hookSha256,
  effective_hook_path: effectiveHookPath,
  effective_config_path: effectiveConfigPath,
  effective_config_sha256: hashFile(effectiveConfigPath),
  effective_guard_wrapper_path: guardWrapperPath,
  effective_guard_wrapper_sha256: hashFile(guardWrapperPath),
  effective_audit_wrapper_path: auditWrapperPath,
  effective_audit_wrapper_sha256: hashFile(auditWrapperPath),
  hook_activation_verified: false,
  activation_method: 'outer-plugin-install',
  activation_generation: `${Date.now()}-${hookSha256.slice(0, 12)}`,
});
console.log(JSON.stringify({ config: path.resolve(configPath), provenance: path.resolve(provenancePath), hook_sha256: hookSha256 }));
