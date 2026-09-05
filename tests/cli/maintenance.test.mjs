import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { backupData, cleanupLegacy, purge, restoreData, uninstall } from '../../cli/maintenance.mjs';
import { productPaths } from '../../cli/paths.mjs';

test('backup verifies bytes and restore replaces product data', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'zcode-as-subagent-data-'));
  const paths = productPaths(home);
  fs.mkdirSync(paths.data, { recursive: true });
  fs.writeFileSync(path.join(paths.data, 'state.bin'), Buffer.from([0, 1, 2, 255]));
  const backup = path.join(home, 'backup');
  assert.equal(backupData(backup, paths).files, 1);
  fs.writeFileSync(path.join(paths.data, 'state.bin'), 'changed');
  assert.equal(restoreData(backup, paths).files, 1);
  assert.deepEqual(fs.readFileSync(path.join(paths.data, 'state.bin')), Buffer.from([0, 1, 2, 255]));
});

test('restore detects corrupted backup before replacing data', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'zcode-as-subagent-corrupt-'));
  const paths = productPaths(home);
  fs.mkdirSync(paths.data, { recursive: true });
  fs.writeFileSync(path.join(paths.data, 'state'), 'original');
  const backup = path.join(home, 'backup');
  backupData(backup, paths);
  fs.writeFileSync(path.join(backup, 'data', 'state'), 'corrupt');
  fs.writeFileSync(path.join(paths.data, 'state'), 'current');
  assert.throws(() => restoreData(backup, paths), (error) => error.code === 'BACKUP_CORRUPT');
  assert.equal(fs.readFileSync(path.join(paths.data, 'state'), 'utf8'), 'current');
});

test('backup rejects a destination inside product data before creating files', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'zcode-as-subagent-nested-backup-'));
  const paths = productPaths(home);
  fs.mkdirSync(paths.data, { recursive: true });
  fs.writeFileSync(path.join(paths.data, 'state'), 'original');
  const destination = path.join(paths.data, 'backup');

  assert.throws(() => backupData(destination, paths), (error) => error.code === 'BACKUP_DESTINATION_IN_DATA');
  assert.equal(fs.existsSync(destination), false);
  assert.equal(fs.readFileSync(path.join(paths.data, 'state'), 'utf8'), 'original');
});

test('uninstall retains data, while purge is an explicit separate operation', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'zcode-as-subagent-retain-'));
  const paths = productPaths(home);
  fs.mkdirSync(paths.data, { recursive: true });
  fs.mkdirSync(path.dirname(paths.launchAgent), { recursive: true });
  fs.writeFileSync(paths.launchAgent, 'plist');
  assert.equal(uninstall(paths).data_retained, true);
  assert.equal(fs.existsSync(paths.data), true);
  assert.equal(fs.existsSync(paths.launchAgent), false);
  purge(paths);
  assert.equal(fs.existsSync(paths.data), false);
});

test('legacy cleanup removes only enumerated old paths and creates no alias or migration', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'zcode-as-subagent-legacy-'));
  const old = path.join(home, '.local', 'bin', 'zcode-reviewd');
  fs.mkdirSync(path.dirname(old), { recursive: true });
  fs.writeFileSync(old, 'old');
  const result = cleanupLegacy(home);
  assert.equal(result.migration, false);
  assert.deepEqual(result.aliases_created, []);
  assert.equal(fs.existsSync(old), false);
});
