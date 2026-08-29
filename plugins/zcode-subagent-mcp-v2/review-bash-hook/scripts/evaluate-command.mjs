#!/usr/bin/env node
import { evaluateCommand } from '../lib/readonly-bash-policy.mjs';

const command = process.argv.slice(2).join(' ');
if (!command) {
  process.stderr.write('usage: node scripts/evaluate-command.mjs <command>\n');
  process.exit(2);
}
const result = evaluateCommand({
  command,
  cwd: process.cwd(),
  root: process.env.ZCODE_READONLY_BASH_ROOT || undefined,
  unknownDecision: process.env.ZCODE_READONLY_BASH_UNKNOWN_DECISION || 'deny',
  trustedBinDirs: process.env.ZCODE_READONLY_BASH_TRUSTED_BIN_DIRS
    ? process.env.ZCODE_READONLY_BASH_TRUSTED_BIN_DIRS.split(':').filter(Boolean)
    : undefined,
});
process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
process.exit(result.decision === 'allow' ? 0 : 1);
