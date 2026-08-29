#!/usr/bin/env node
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const files = [];
for (const entry of fs.readdirSync(root, { recursive: true, withFileTypes: true })) {
  const relative = path.relative(root, path.join(entry.parentPath, entry.name));
  if (entry.isFile() && relative !== 'SHA256SUMS.txt') files.push(relative);
}
files.sort();
const lines = files.map((relative) => {
  const hash = crypto.createHash('sha256').update(fs.readFileSync(path.join(root, relative))).digest('hex');
  return `${hash}  ./${relative}`;
});
fs.writeFileSync(path.join(root, 'SHA256SUMS.txt'), `${lines.join('\n')}\n`);
