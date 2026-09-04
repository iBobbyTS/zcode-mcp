#!/usr/bin/env node
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const pluginRoot = path.resolve(new URL('..', import.meta.url).pathname);
const hookRoot = pluginRoot;
const configPath = process.argv[process.argv.indexOf('--config') + 1];
if (!configPath || configPath.startsWith('--')) {
  console.error('usage: node install-agent-hooks.mjs --config /absolute/config.json [--provenance /absolute/provenance.json]');
  process.exit(2);
}
const provenanceIndex = process.argv.indexOf('--provenance');
const provenancePath = provenanceIndex >= 0
  ? process.argv[provenanceIndex + 1]
  : path.join(path.dirname(configPath), 'zcode-agent-hook-provenance.json');

function readJson(file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch (error) {
    if (error?.code === 'ENOENT') return fallback;
    throw error;
  }
}

function atomicWriteBytes(file, bytes) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const temporary = `${file}.tmp-${process.pid}`;
  try {
    fs.writeFileSync(temporary, bytes, { mode: 0o600 });
    fs.renameSync(temporary, file);
  } finally {
    try { fs.unlinkSync(temporary); } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
    }
  }
}

const encodeJson = (value) => `${JSON.stringify(value, null, 2)}\n`;
const atomicWrite = (file, value) => atomicWriteBytes(file, encodeJson(value));

const config = readJson(configPath, {});
if (!config || typeof config !== 'object' || Array.isArray(config)) throw new Error('config must be a JSON object');
const next = structuredClone(config);
next.hooks ??= {};
next.hooks.enabled = true;
next.hooks.events ??= {};
const hashFile = (file) => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
// Resolve every shipped decision owner before mutating the caller's config.
// A copied or incomplete plugin must fail without leaving a partial install.
const effectiveConfigPath = path.resolve(configPath);
const effectiveHookPath = path.join(hookRoot, 'lib', 'bash-policy.mjs');
const effectiveFilePolicyPath = path.join(hookRoot, 'lib', 'agent-file-policy.mjs');
const guardWrapperPath = path.join(hookRoot, 'hooks', 'check-bash-readonly.mjs');
const auditWrapperPath = path.join(hookRoot, 'hooks', 'audit-bash-result.mjs');
const fileWrapperPath = path.join(hookRoot, 'hooks', 'check-agent-files.mjs');
const daemonSourcePath = path.join(pluginRoot, '..', '..', 'crates', 'zcode-agent-preparation', 'src', 'policy.rs');
const hookSource = fs.readFileSync(effectiveHookPath);
const hookSha256 = crypto.createHash('sha256').update(hookSource).digest('hex');
const filePolicySha256 = hashFile(effectiveFilePolicyPath);
const daemonSource = fs.readFileSync(daemonSourcePath);
const daemonSha256 = crypto.createHash('sha256').update(daemonSource).digest('hex');
const priorProvenance = readJson(provenancePath, null);
const serviceGeneration = typeof priorProvenance?.service_generation === 'string' && priorProvenance.service_generation.length > 0
  ? priorProvenance.service_generation
  : crypto.randomBytes(16).toString('hex');
if (effectiveConfigPath === path.resolve(provenancePath)) throw new Error('config and provenance paths must differ');
const events = {
  PreToolUse: [
    { matcher: 'Bash', script: 'hooks/check-bash-readonly.mjs' },
    { matcher: '^(Read|Grep|Glob|Write|Edit|Delete|Move)$', script: 'hooks/check-agent-files.mjs' },
  ],
  PostToolUse: [{ matcher: 'Bash', script: 'hooks/audit-bash-result.mjs' }],
  PostToolUseFailure: [{ matcher: 'Bash', script: 'hooks/audit-bash-result.mjs' }],
};

function processHookArgs(candidate) {
  if (!candidate || !Array.isArray(candidate.hooks)) return [];
  return candidate.hooks
    .filter((hook) => hook?.type === 'process' && Array.isArray(hook.args))
    .flatMap((hook) => hook.args)
    .filter((arg) => typeof arg === 'string');
}

function isRecognizedAgentHook(candidate, matcher, expectedScript) {
  if (candidate?.matcher !== matcher) return false;
  const args = processHookArgs(candidate);
  return args.some((arg) => path.resolve(arg) === expectedScript);
}

for (const [event, expectedEntries] of Object.entries(events)) {
  const existing = Array.isArray(next.hooks.events[event]) ? next.hooks.events[event] : [];
  for (const { matcher, script } of expectedEntries) {
    const expectedScript = path.join(hookRoot, script);
    const managedEntries = existing.filter((candidate) => candidate?.matcher === matcher);
    const unknownEntries = managedEntries.filter((candidate) => !isRecognizedAgentHook(candidate, matcher, expectedScript));
    if (unknownEntries.length > 0) {
      throw new Error(`${event} contains an unknown managed hook; refusing to modify configuration`);
    }
  }
  const unrelated = existing.filter((candidate) => !expectedEntries.some(({ matcher }) => candidate?.matcher === matcher));
  next.hooks.events[event] = [
    ...unrelated,
    ...expectedEntries.map(({ matcher, script }) => ({
      matcher,
      hooks: [{ type: 'process', command: process.execPath, args: [path.join(hookRoot, script)], timeoutMs: 5000 }],
    })),
  ];
}
const nextConfigBytes = encodeJson(next);
const nextProvenance = {
  daemon_policy_version: 'zcode-agent-bash/v1.0.0',
  daemon_policy_sha256: daemonSha256,
  expected_hook_version: 'zcode-agent-bash/v1.0.0',
  expected_hook_sha256: hookSha256,
  effective_hook_version: 'zcode-agent-bash/v1.0.0',
  effective_hook_sha256: hookSha256,
  effective_hook_path: effectiveHookPath,
  effective_file_policy_version: 'zcode-agent-file-policy/v1.0.0',
  effective_file_policy_sha256: filePolicySha256,
  effective_file_policy_path: effectiveFilePolicyPath,
  effective_config_path: effectiveConfigPath,
  effective_config_sha256: crypto.createHash('sha256').update(nextConfigBytes).digest('hex'),
  effective_guard_wrapper_path: guardWrapperPath,
  effective_guard_wrapper_sha256: hashFile(guardWrapperPath),
  effective_audit_wrapper_path: auditWrapperPath,
  effective_audit_wrapper_sha256: hashFile(auditWrapperPath),
  effective_file_wrapper_path: fileWrapperPath,
  effective_file_wrapper_sha256: hashFile(fileWrapperPath),
  hook_activation_verified: false,
  activation_method: 'outer-plugin-install',
  activation_generation: `${Date.now()}-${hookSha256.slice(0, 12)}`,
  service_generation: serviceGeneration,
};
const previousProvenance = fs.existsSync(provenancePath) ? fs.readFileSync(provenancePath) : null;
atomicWrite(provenancePath, nextProvenance);
try {
  atomicWriteBytes(configPath, nextConfigBytes);
} catch (error) {
  if (previousProvenance === null) {
    try { fs.unlinkSync(provenancePath); } catch (unlinkError) {
      if (unlinkError?.code !== 'ENOENT') throw unlinkError;
    }
  } else {
    atomicWriteBytes(provenancePath, previousProvenance);
  }
  throw error;
}
console.log(JSON.stringify({ config: effectiveConfigPath, provenance: path.resolve(provenancePath), hook_sha256: hookSha256, file_policy_sha256: filePolicySha256, service_generation: serviceGeneration }));
