#!/usr/bin/env node

import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const facade = path.join(packageRoot, 'npm', 'native', 'darwin-arm64', 'zcode-subagent-mcp');
const child = spawn(facade, process.argv.slice(2), { stdio: 'inherit', env: process.env });
child.on('error', (error) => {
  console.error(error.message);
  process.exitCode = 1;
});
child.on('exit', (code, signal) => {
  process.exitCode = code ?? (signal ? 1 : 0);
});
