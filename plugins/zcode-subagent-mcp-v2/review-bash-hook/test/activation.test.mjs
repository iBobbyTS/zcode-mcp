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
  fs.writeFileSync(config, JSON.stringify({ unrelated: { keep: true }, hooks: { events: { Other: [{ matcher: 'Other' }] } } }));

  const install = run(installScript, ['--config', config, '--provenance', provenance]);
  assert.equal(install.status, 0, install.stderr);
  const installed = JSON.parse(fs.readFileSync(config, 'utf8'));
  assert.deepEqual(installed.unrelated, { keep: true });
  assert.deepEqual(installed.hooks.events.Other, [{ matcher: 'Other' }]);
  assert.equal(installed.hooks.enabled, true);
  assert.equal(run(checkScript, ['--config', config, '--provenance', provenance]).status, 1);

  const preflight = run(preflightScript, ['--config', config, '--provenance', provenance]);
  assert.equal(preflight.status, 0, preflight.stderr);
  assert.equal(run(checkScript, ['--config', config, '--provenance', provenance]).status, 0);

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
