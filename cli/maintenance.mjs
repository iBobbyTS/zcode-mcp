import fs from 'node:fs';
import path from 'node:path';
import { CliError } from './errors.mjs';
import { jsonBytes, sha256 } from './fs-atomic.mjs';
import { legacyPaths, productPaths } from './paths.mjs';

function copyTree(source, destination, records, root = source) {
  if (!fs.existsSync(source)) return;
  for (const entry of fs.readdirSync(source, { withFileTypes: true })) {
    const from = path.join(source, entry.name);
    const relative = path.relative(root, from);
    const to = path.join(destination, relative);
    if (entry.isSymbolicLink()) throw new CliError('UNSAFE_BACKUP_ENTRY', `refusing symlink: ${from}`);
    if (entry.isDirectory()) copyTree(from, destination, records, root);
    else if (entry.isFile()) {
      fs.mkdirSync(path.dirname(to), { recursive: true, mode: 0o700 });
      const bytes = fs.readFileSync(from);
      fs.writeFileSync(to, bytes, { mode: 0o600 });
      records.push({ path: relative, bytes: bytes.length, sha256: sha256(bytes) });
    }
  }
}

export function backupData(destination, paths = productPaths()) {
  const resolved = path.resolve(destination);
  if (fs.existsSync(resolved)) throw new CliError('BACKUP_EXISTS', 'backup destination already exists');
  fs.mkdirSync(resolved, { recursive: false, mode: 0o700 });
  const records = [];
  copyTree(paths.data, path.join(resolved, 'data'), records);
  const manifest = { schema_version: 1, product: 'zcode-as-subagent', files: records.sort((a, b) => a.path.localeCompare(b.path)) };
  fs.writeFileSync(path.join(resolved, 'manifest.json'), jsonBytes(manifest), { mode: 0o600 });
  return { destination: resolved, files: records.length };
}

export function restoreData(source, paths = productPaths()) {
  const resolved = path.resolve(source);
  const manifest = JSON.parse(fs.readFileSync(path.join(resolved, 'manifest.json'), 'utf8'));
  if (manifest.product !== 'zcode-as-subagent' || !Array.isArray(manifest.files)) throw new CliError('BACKUP_INVALID', 'backup manifest is invalid');
  for (const record of manifest.files) {
    if (path.isAbsolute(record.path) || record.path.split(path.sep).includes('..')) throw new CliError('BACKUP_INVALID', 'backup contains an unsafe path');
    const bytes = fs.readFileSync(path.join(resolved, 'data', record.path));
    if (bytes.length !== record.bytes || sha256(bytes) !== record.sha256) throw new CliError('BACKUP_CORRUPT', `backup verification failed: ${record.path}`);
  }
  const temporary = `${paths.data}.restore-${process.pid}`;
  if (fs.existsSync(temporary)) fs.rmSync(temporary, { recursive: true });
  fs.mkdirSync(temporary, { recursive: true, mode: 0o700 });
  copyTree(path.join(resolved, 'data'), temporary, []);
  const displaced = `${paths.data}.previous-${process.pid}`;
  try {
    if (fs.existsSync(paths.data)) fs.renameSync(paths.data, displaced);
    fs.renameSync(temporary, paths.data);
    if (fs.existsSync(displaced)) fs.rmSync(displaced, { recursive: true });
  } catch (error) {
    if (!fs.existsSync(paths.data) && fs.existsSync(displaced)) fs.renameSync(displaced, paths.data);
    throw error;
  }
  return { restored: true, files: manifest.files.length };
}

function removeOne(target) {
  try {
    const stat = fs.lstatSync(target);
    if (stat.isDirectory() && !stat.isSymbolicLink()) fs.rmSync(target, { recursive: true });
    else fs.unlinkSync(target);
    return true;
  } catch (error) {
    if (error?.code === 'ENOENT') return false;
    throw error;
  }
}

export function uninstall(paths = productPaths()) {
  return { removed_launch_agent: removeOne(paths.launchAgent), data_retained: true, data: paths.data };
}

export function purge(paths = productPaths()) {
  return { purged: removeOne(paths.data), logs_purged: removeOne(paths.logs) };
}

export function cleanupLegacy(home) {
  const removed = legacyPaths(home).filter(removeOne);
  return { migration: false, aliases_created: [], removed };
}
