import { spawnSync } from 'node:child_process';
import { CliError } from './errors.mjs';

function launchctl(args) {
  const result = spawnSync('/bin/launchctl', args, { encoding: 'utf8' });
  if (result.error || result.status !== 0) {
    throw new CliError('DAEMON_CONTROL_FAILED', (result.stderr || result.error?.message || 'launchctl failed').trim());
  }
  return { action: args[0], status: result.status };
}

export function startService(paths, uid = process.getuid()) {
  return launchctl(['bootstrap', `gui/${uid}`, paths.launchAgent]);
}

export function stopService(_paths, uid = process.getuid()) {
  return launchctl(['bootout', `gui/${uid}/com.zcode-as-subagent.daemon`]);
}
