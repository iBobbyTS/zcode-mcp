import os from 'node:os';
import path from 'node:path';
import { LAUNCH_AGENT_LABEL } from './constants.mjs';

export function platform() {
  return process.env.ZCODE_AS_SUBAGENT_TEST_PLATFORM || process.platform;
}

export function productPaths(home = os.homedir()) {
  const data = path.join(home, 'Library', 'Application Support', 'zcode-as-subagent');
  return {
    home,
    data,
    config: path.join(data, 'config.json'),
    state: path.join(data, 'install-state.json'),
    provenance: path.join(data, 'model-catalog-provenance.json'),
    database: path.join(data, 'zcode-as-subagent.sqlite3'),
    socket: path.join(data, 'zcode-as-subagent.sock'),
    logs: path.join(home, 'Library', 'Logs', 'zcode-as-subagent'),
    launchAgent: path.join(home, 'Library', 'LaunchAgents', `${LAUNCH_AGENT_LABEL}.plist`),
    zcodeConfig: path.join(home, '.zcode', 'cli', 'config.json'),
  };
}

export function legacyPaths(home = os.homedir()) {
  return [
    path.join(home, 'Library', 'LaunchAgents', 'com.zcode-reviewd.plist'),
    path.join(home, 'Library', 'LaunchAgents', 'com.zcode-review-mcp.plist'),
    path.join(home, 'Library', 'Logs', 'zcode-reviewd'),
    path.join(home, 'Library', 'Application Support', 'zcode-review-mcp'),
    path.join(home, 'Library', 'Application Support', 'zcode-reviewd'),
    path.join(home, '.local', 'bin', 'zcode-reviewd'),
    path.join(home, '.local', 'bin', 'zcode-review-mcp'),
  ];
}
