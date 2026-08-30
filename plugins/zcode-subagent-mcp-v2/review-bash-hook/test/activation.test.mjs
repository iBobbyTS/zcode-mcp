import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { spawnSync } from 'node:child_process';

const pluginRoot = path.resolve(new URL('../..', import.meta.url).pathname);
const installScript = path.join(pluginRoot, 'scripts', 'install-review-hook.mjs');
const checkScript = path.join(pluginRoot, 'scripts', 'check-review-hook.mjs');
const preflightScript = path.join(pluginRoot, 'scripts', 'preflight-review-hook.mjs');

function run(script, args) {
  return spawnSync(process.execPath, [script, ...args], { encoding: 'utf8' });
}

test('install/check/preflight are idempotent, isolated, and provenance-aware', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'review-hook-install-'));
  const config = path.join(directory, 'config.json');
  const provenance = path.join(directory, 'provenance.json');
  const legacy = path.join(directory, 'legacy', 'check-bash-status.mjs');
  fs.mkdirSync(path.dirname(legacy), { recursive: true });
  fs.copyFileSync(path.join(pluginRoot, 'review-bash-hook', 'single-file', 'check-bash-status.mjs'), legacy);
  fs.writeFileSync(config, JSON.stringify({
    unrelated: { keep: true },
    hooks: {
      events: {
        Other: [{ matcher: 'Other' }],
        PreToolUse: [
          { matcher: 'Bash', hooks: [{ type: 'process', command: 'node', args: [legacy], timeoutMs: 5000 }] },
          { matcher: 'Bash', description: 'review-bash-hook:PreToolUse', hooks: [{ type: 'process', command: 'node', args: ['/old/other.mjs'], timeoutMs: 5000 }] },
        ],
      },
    },
  }));

  const install = run(installScript, ['--config', config, '--provenance', provenance]);
  assert.equal(install.status, 0, install.stderr);
  const installed = JSON.parse(fs.readFileSync(config, 'utf8'));
  assert.deepEqual(installed.unrelated, { keep: true });
  assert.deepEqual(installed.hooks.events.Other, [{ matcher: 'Other' }]);
  assert.equal(installed.hooks.enabled, true);
  for (const event of ['PreToolUse', 'PostToolUse', 'PostToolUseFailure']) {
    const bashEntries = installed.hooks.events[event].filter((entry) => entry.matcher === 'Bash');
    assert.equal(bashEntries.length, 1);
    assert.equal(Object.hasOwn(bashEntries[0], 'description'), false);
    assert.equal(bashEntries[0].hooks.length, 1);
    assert.equal(bashEntries[0].hooks[0].args[0].endsWith(event === 'PreToolUse' ? 'check-bash-readonly.mjs' : 'audit-bash-result.mjs'), true);
  }
  const installedBytes = fs.readFileSync(config);
  assert.equal(run(installScript, ['--config', config, '--provenance', provenance]).status, 0);
  assert.deepEqual(fs.readFileSync(config), installedBytes);
  assert.equal(run(checkScript, ['--config', config, '--provenance', provenance]).status, 1);

  const preflight = run(preflightScript, ['--config', config, '--provenance', provenance]);
  assert.equal(preflight.status, 0, preflight.stderr);
  assert.equal(run(checkScript, ['--config', config, '--provenance', provenance]).status, 0);

  const driftedConfig = JSON.parse(fs.readFileSync(config, 'utf8'));
  for (const event of ['PreToolUse', 'PostToolUse', 'PostToolUseFailure']) {
    const entry = driftedConfig.hooks.events[event].find((candidate) => candidate.matcher === 'Bash');
    entry.hooks[0].args = ['/usr/bin/true'];
  }
  fs.writeFileSync(config, JSON.stringify(driftedConfig));
  assert.equal(run(checkScript, ['--config', config, '--provenance', provenance]).status, 1);
  assert.notEqual(run(preflightScript, ['--config', config, '--provenance', provenance]).status, 0);

  assert.notEqual(run(installScript, ['--config', config, '--provenance', provenance]).status, 0);
  fs.writeFileSync(config, installedBytes);
  assert.equal(run(preflightScript, ['--config', config, '--provenance', provenance]).status, 0);
  assert.equal(run(checkScript, ['--config', config, '--provenance', provenance]).status, 0);

  const disabledConfig = JSON.parse(fs.readFileSync(config, 'utf8'));
  disabledConfig.hooks.enabled = false;
  fs.writeFileSync(config, JSON.stringify(disabledConfig));
  assert.equal(run(checkScript, ['--config', config, '--provenance', provenance]).status, 1);
  assert.equal(run(installScript, ['--config', config, '--provenance', provenance]).status, 0);
  assert.equal(run(preflightScript, ['--config', config, '--provenance', provenance]).status, 0);

  const tampered = JSON.parse(fs.readFileSync(provenance, 'utf8'));
  tampered.effective_hook_sha256 = '0'.repeat(64);
  fs.writeFileSync(provenance, JSON.stringify(tampered));
  assert.equal(run(checkScript, ['--config', config, '--provenance', provenance]).status, 1);

  tampered.effective_hook_sha256 = tampered.expected_hook_sha256;
  tampered.hook_activation_verified = false;
  fs.writeFileSync(provenance, JSON.stringify(tampered));
  assert.equal(run(checkScript, ['--config', config, '--provenance', provenance]).status, 1);

  tampered.hook_activation_verified = true;
  tampered.effective_hook_version = 'zcode-readonly-bash/v0.9.0';
  fs.writeFileSync(provenance, JSON.stringify(tampered));
  assert.equal(run(checkScript, ['--config', config, '--provenance', provenance]).status, 1);

  tampered.effective_hook_version = tampered.expected_hook_version;
  tampered.effective_hook_path = path.join(directory, 'missing-hook.mjs');
  fs.writeFileSync(provenance, JSON.stringify(tampered));
  assert.equal(run(checkScript, ['--config', config, '--provenance', provenance]).status, 1);
});

test('fails closed without changing config when an unknown Bash hook is present', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'review-hook-unknown-'));
  const config = path.join(directory, 'config.json');
  const provenance = path.join(directory, 'provenance.json');
  const original = {
    hooks: {
      enabled: true,
      events: {
        PreToolUse: [
          { matcher: 'Bash', hooks: [{ type: 'process', command: 'node', args: ['/user/custom-bash-hook.mjs'], timeoutMs: 5000 }] },
          { matcher: 'Other', hooks: [] },
        ],
      },
    },
  };
  fs.writeFileSync(config, JSON.stringify(original, null, 2));
  const before = fs.readFileSync(config);
  const result = run(installScript, ['--config', config, '--provenance', provenance]);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /unknown Bash hook/);
  assert.deepEqual(fs.readFileSync(config), before);
  assert.deepEqual(JSON.parse(fs.readFileSync(config, 'utf8')), original);
  assert.equal(fs.existsSync(provenance), false);
});

test('does not replace an unknown same-name Bash hook', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'review-hook-same-name-'));
  const config = path.join(directory, 'config.json');
  const provenance = path.join(directory, 'provenance.json');
  const customHook = path.join('/user/custom', 'check-bash-status.mjs');
  const original = {
    hooks: {
      enabled: true,
      events: {
        PreToolUse: [
          { matcher: 'Bash', hooks: [{ type: 'process', command: 'node', args: [customHook], timeoutMs: 5000 }] },
        ],
      },
    },
  };
  fs.writeFileSync(config, JSON.stringify(original, null, 2));
  const before = fs.readFileSync(config);
  const result = run(installScript, ['--config', config, '--provenance', provenance]);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /unknown Bash hook/);
  assert.deepEqual(fs.readFileSync(config), before);
  assert.equal(fs.existsSync(provenance), false);
});

test('does not treat the guard single-file as an audit hook', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'review-hook-event-'));
  const config = path.join(directory, 'config.json');
  const provenance = path.join(directory, 'provenance.json');
  const legacyHook = path.join(directory, 'check-bash-status.mjs');
  fs.copyFileSync(path.join(pluginRoot, 'review-bash-hook', 'single-file', 'check-bash-status.mjs'), legacyHook);
  const original = {
    hooks: {
      enabled: true,
      events: {
        PostToolUse: [
          { matcher: 'Bash', hooks: [{ type: 'process', command: 'node', args: [legacyHook], timeoutMs: 5000 }] },
        ],
      },
    },
  };
  fs.writeFileSync(config, JSON.stringify(original, null, 2));
  const before = fs.readFileSync(config);
  const result = run(installScript, ['--config', config, '--provenance', provenance]);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /unknown Bash hook/);
  assert.deepEqual(fs.readFileSync(config), before);
  assert.equal(fs.existsSync(provenance), false);
});
