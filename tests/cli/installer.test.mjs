import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { installPlan, runInit } from '../../cli/installer.mjs';
import { productPaths } from '../../cli/paths.mjs';
import { ZCODE_RUNTIME } from '../../cli/constants.mjs';

test('dry-run reports the entire plan and creates nothing', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'zcode-as-subagent-init-'));
  const paths = productPaths(home);
  const result = runInit({ paths, dryRun: true });
  assert.deepEqual(result.plan.map((step) => step.id), [
    'probe-runtime', 'create-data', 'configure-models', 'write-product-config', 'install-launch-agent',
  ]);
  assert.equal(result.plan[0].path, ZCODE_RUNTIME);
  assert.equal(fs.readdirSync(home).length, 0);
});

test('resume skips completed steps', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'zcode-as-subagent-resume-'));
  const paths = productPaths(home);
  fs.mkdirSync(paths.data, { recursive: true });
  fs.writeFileSync(paths.state, JSON.stringify({ schema_version: 1, completed: ['probe-runtime', 'create-data', 'configure-models'] }));
  const result = runInit({ paths, resume: true, skipRuntimeProbe: true, skipNativeProbe: true });
  assert.equal(result.resumed, true);
  assert.equal(result.completed.filter((id) => id === 'configure-models').length, 1);
  assert.equal(fs.existsSync(paths.zcodeConfig), false);
  assert.equal(fs.existsSync(paths.launchAgent), true);
});

test('plan uses no PATH lookup and points only at fixed bundle runtime', () => {
  const rendered = JSON.stringify(installPlan(productPaths('/tmp/isolated-home')));
  assert.match(rendered, /\/Applications\/ZCode\.app\/Contents\/Resources\/glm\/zcode\.cjs/);
  assert.doesNotMatch(rendered, /which|\/usr\/bin\/env|ZCODE_RUNTIME_PATH/);
});
