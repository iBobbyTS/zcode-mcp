import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');
export const jsonBytes = (value) => Buffer.from(`${JSON.stringify(value, null, 2)}\n`);

export function atomicWrite(file, bytes, mode = 0o600) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const temporary = path.join(path.dirname(file), `.${path.basename(file)}.${process.pid}.${crypto.randomUUID()}.tmp`);
  try {
    fs.writeFileSync(temporary, bytes, { mode, flag: 'wx' });
    fs.renameSync(temporary, file);
  } finally {
    try { fs.unlinkSync(temporary); } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
    }
  }
}

export function readOptional(file) {
  try { return fs.readFileSync(file); } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
}

export function restoreOptional(file, bytes) {
  if (bytes === null) {
    try { fs.unlinkSync(file); } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
    }
  } else {
    atomicWrite(file, bytes);
  }
}
