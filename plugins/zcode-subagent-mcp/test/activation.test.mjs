import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { spawnSync } from 'node:child_process';

const pluginRoot = path.resolve(new URL('..', import.meta.url).pathname);
const installScript = path.join(pluginRoot, 'scripts', 'install-agent-hooks.mjs');
const checkScript = path.join(pluginRoot, 'scripts', 'check-agent-hooks.mjs');
const preflightScript = path.join(pluginRoot, 'scripts', 'preflight-agent-hooks.mjs');

function run(script, args, env = {}) {
  return spawnSync(process.execPath, [script, ...args], {
    encoding: 'utf8',
    env: { ...process.env, ...env },
  });
}

test('install/check/preflight are idempotent, isolated, and provenance-aware', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-hooks-install-'));
  const config = path.join(directory, 'config.json');
  const provenance = path.join(directory, 'provenance.json');
  fs.writeFileSync(config, JSON.stringify({
    unrelated: { keep: true },
    hooks: {
      events: {
        Other: [{ matcher: 'Other' }],
        PreToolUse: [
          { matcher: 'Bash', hooks: [{ type: 'process', command: 'node', args: [path.join(pluginRoot, 'hooks', 'check-bash-readonly.mjs')], timeoutMs: 5000 }] },
          { matcher: '^(Read|Grep|Glob|Write|Edit|Delete|Move)$', hooks: [{ type: 'process', command: 'node', args: [path.join(pluginRoot, 'hooks', 'check-agent-files.mjs')], timeoutMs: 5000 }] },
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
    const entries = installed.hooks.events[event];
    assert.equal(entries.filter((entry) => entry.matcher === 'Bash').length, 1);
    if (event === 'PreToolUse') assert.equal(entries.filter((entry) => entry.matcher.startsWith('^(')).length, 1);
    for (const entry of entries.filter((candidate) => candidate.matcher === 'Bash' || candidate.matcher.startsWith('^('))) {
      assert.equal(Object.hasOwn(entry, 'description'), false);
      assert.equal(entry.hooks.length, 1);
      assert.equal(entry.hooks[0].command, process.execPath);
      assert.equal(fs.existsSync(entry.hooks[0].args[0]), true);
    }
  }
  const installedBytes = fs.readFileSync(config);
  assert.equal(run(installScript, ['--config', config, '--provenance', provenance]).status, 0);
  assert.deepEqual(fs.readFileSync(config), installedBytes);
  assert.equal(run(checkScript, ['--config', config, '--provenance', provenance]).status, 1);

  const preflight = run(preflightScript, ['--config', config, '--provenance', provenance]);
  assert.equal(preflight.status, 0, preflight.stderr);
  const activated = JSON.parse(fs.readFileSync(provenance, 'utf8'));
  assert.equal(activated.effective_file_policy_version, 'zcode-agent-file-policy/v1.0.0');
  assert.equal(activated.effective_file_policy_sha256.length, 64);
  assert.equal(activated.effective_file_wrapper_path.endsWith('/hooks/check-agent-files.mjs'), true);
  assert.equal(run(checkScript, ['--config', config, '--provenance', provenance]).status, 0);

  const driftedConfig = JSON.parse(fs.readFileSync(config, 'utf8'));
  for (const event of ['PreToolUse', 'PostToolUse', 'PostToolUseFailure']) {
    const entry = driftedConfig.hooks.events[event].find((candidate) => candidate.matcher === 'Bash');
    entry.hooks[0].args = ['/usr/bin/true'];
  }
  fs.writeFileSync(config, JSON.stringify(driftedConfig));
  assert.equal(run(checkScript, ['--config', config, '--provenance', provenance]).status, 1);
  assert.notEqual(run(preflightScript, ['--config', config, '--provenance', provenance]).status, 0);

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
});

test('fails closed without changing config when an unknown managed hook is present', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-hooks-unknown-'));
  const config = path.join(directory, 'config.json');
  const provenance = path.join(directory, 'provenance.json');
  const original = {
    hooks: {
      enabled: true,
      events: {
        PreToolUse: [
          { matcher: 'Bash', hooks: [{ type: 'process', command: 'node', args: ['/user/custom-bash-hook.mjs'], timeoutMs: 5000 }] },
          { matcher: '^(Read|Grep|Glob|Write|Edit|Delete|Move)$', hooks: [{ type: 'process', command: 'node', args: ['/user/custom-file-hook.mjs'], timeoutMs: 5000 }] },
        ],
      },
    },
  };
  fs.writeFileSync(config, JSON.stringify(original, null, 2));
  const before = fs.readFileSync(config);
  const result = run(installScript, ['--config', config, '--provenance', provenance]);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /unknown managed hook/);
  assert.deepEqual(fs.readFileSync(config), before);
  assert.equal(fs.existsSync(provenance), false);
});
