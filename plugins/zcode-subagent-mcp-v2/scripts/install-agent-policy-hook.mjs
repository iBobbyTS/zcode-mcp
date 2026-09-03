#!/usr/bin/env node
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const pluginRoot = path.resolve(new URL('..', import.meta.url).pathname);
const hookPath = path.join(pluginRoot, 'hooks', 'check-agent-files.mjs');
const policyPath = path.join(pluginRoot, 'lib', 'agent-file-policy.mjs');
const configPath = process.argv[2] ?? path.join(os.homedir(), '.zcode', 'cli', 'config.json');
const provenancePath = process.argv[3] ?? path.join(path.dirname(configPath), 'zcode-agent-policy-provenance.json');
const nodePath = process.execPath;
const matcher = '^(Read|Grep|Glob|Write|Edit|Delete|Move)$';

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function processHook() {
  return { type: 'process', command: nodePath, args: [hookPath], timeoutMs: 5000 };
}

function isManaged(entry) {
  return entry?.matcher === matcher && entry?.hooks?.some((hook) => hook?.type === 'process' && hook?.args?.[0] === hookPath);
}

if (!fs.existsSync(configPath)) throw new Error(`config does not exist: ${configPath}`);
const before = fs.readFileSync(configPath);
let config;
try { config = JSON.parse(before); } catch { throw new Error('config is not valid JSON'); }
const next = structuredClone(config);
next.hooks ??= {};
next.hooks.enabled = true;
next.hooks.events ??= {};
const existing = Array.isArray(next.hooks.events.PreToolUse) ? next.hooks.events.PreToolUse : [];
next.hooks.events.PreToolUse = [
  ...existing.filter((entry) => !isManaged(entry)),
  { matcher, hooks: [processHook()] },
];
const serialized = `${JSON.stringify(next, null, 2)}\n`;
fs.writeFileSync(configPath, serialized, { mode: 0o600 });
const configHash = sha256(Buffer.from(serialized));
const hookHash = sha256(fs.readFileSync(hookPath));
const policyHash = sha256(fs.readFileSync(policyPath));
const provenance = {
  schema: 'zcode-agent-policy-provenance/v1',
  mode: 'authorized-home-install',
  timestamp: new Date().toISOString(),
  config_path: path.resolve(configPath),
  config_sha256: configHash,
  hook_path: hookPath,
  hook_sha256: hookHash,
  policy_path: policyPath,
  policy_sha256: policyHash,
  hook_version: 'zcode-agent-file-policy/v1.0.0',
  marker: 'ZCODE_AGENT_POLICY=1',
  root_variable: 'ZCODE_AGENT_WORKTREE_ROOT',
  bootstrap_roots_variable: 'ZCODE_AGENT_BOOTSTRAP_ROOTS',
  write_manifest_variable: 'ZCODE_AGENT_WRITE_MANIFEST',
  matcher,
  preserved_events: Object.keys(config.hooks?.events ?? {}).filter((event) => event !== 'PreToolUse'),
};
fs.writeFileSync(provenancePath, `${JSON.stringify(provenance, null, 2)}\n`, { mode: 0o600 });
process.stdout.write(JSON.stringify({ config: path.resolve(configPath), provenance: path.resolve(provenancePath), config_sha256: configHash, hook_sha256: hookHash, policy_sha256: policyHash }) + '\n');
