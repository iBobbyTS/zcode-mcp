import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { patchCatalog, restoreCatalog } from '../../cli/catalog.mjs';
import { sha256 } from '../../cli/fs-atomic.mjs';

const fixture = () => fs.mkdtempSync(path.join(os.tmpdir(), 'zcode-as-subagent-catalog-'));

test('catalog patch preserves unrelated configuration and restores exact original bytes', () => {
  const root = fixture();
  const config = path.join(root, '.zcode', 'cli', 'config.json');
  const provenance = path.join(root, 'data', 'provenance.json');
  fs.mkdirSync(path.dirname(config), { recursive: true });
  const original = Buffer.from('{\n  "credentials": {"keep": true},\n  "provider": {"zai": {"models": {"other": {"name": "Other"}}}}\n}\n');
  fs.writeFileSync(config, original);

  const record = patchCatalog(config, provenance);
  const installed = JSON.parse(fs.readFileSync(config, 'utf8'));
  assert.equal(installed.model.main, 'zai/glm-5.3');
  assert.equal(installed.model.lite, 'zai/glm-5.3-flash');
  assert.ok(installed.provider.zai.models['glm-5.3']);
  assert.ok(installed.provider.zai.models['glm-5.3-flash']);
  assert.deepEqual(installed.credentials, { keep: true });
  assert.ok(installed.provider.zai.models.other);
  assert.equal(record.original_sha256, sha256(original));

  const restored = restoreCatalog(config, provenance);
  assert.equal(restored.restored_sha256, sha256(original));
  assert.deepEqual(fs.readFileSync(config), original);
  assert.equal(fs.existsSync(provenance), false);
});

test('both model IDs are replaceable without exposing an arbitrary editor', () => {
  const root = fixture();
  const config = path.join(root, 'config.json');
  const provenance = path.join(root, 'provenance.json');
  patchCatalog(config, provenance, { mainModel: 'glm-main-test', liteModel: 'glm-lite-test' });
  const installed = JSON.parse(fs.readFileSync(config, 'utf8'));
  assert.equal(installed.model.main, 'zai/glm-main-test');
  assert.equal(installed.model.lite, 'zai/glm-lite-test');
  assert.ok(installed.provider.zai.models['glm-main-test']);
  assert.ok(installed.provider.zai.models['glm-lite-test']);
});

test('a failed transaction restores config and provenance byte-for-byte', () => {
  const root = fixture();
  const config = path.join(root, 'config.json');
  const provenance = path.join(root, 'provenance.json');
  const original = Buffer.from('{"original":true}\n');
  const priorProvenance = Buffer.from('{"prior":true}\n');
  fs.writeFileSync(config, original);
  fs.writeFileSync(provenance, priorProvenance);
  assert.throws(() => patchCatalog(config, provenance, {
    _afterConfigWrite() { throw new Error('injected failure'); },
  }), /injected failure/);
  assert.deepEqual(fs.readFileSync(config), original);
  assert.deepEqual(fs.readFileSync(provenance), priorProvenance);
});

test('restore refuses drift instead of overwriting user changes', () => {
  const root = fixture();
  const config = path.join(root, 'config.json');
  const provenance = path.join(root, 'provenance.json');
  patchCatalog(config, provenance);
  fs.appendFileSync(config, ' ');
  assert.throws(() => restoreCatalog(config, provenance), (error) => error.code === 'CONFIG_CHANGED');
});
