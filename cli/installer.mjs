import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { LAUNCH_AGENT_LABEL, ZCODE_RUNTIME } from './constants.mjs';
import { CliError } from './errors.mjs';
import { atomicWrite, jsonBytes, readOptional, restoreOptional } from './fs-atomic.mjs';
import { patchCatalog } from './catalog.mjs';
import { productPaths } from './paths.mjs';

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

export function nativeBinary(name) {
  return path.join(packageRoot, 'npm', 'native', 'darwin-arm64', name);
}

export function installPlan(paths = productPaths(), options = {}) {
  return [
    { id: 'probe-runtime', action: 'verify fixed ZCode runtime', path: ZCODE_RUNTIME },
    { id: 'create-data', action: 'create private product data and log directories', paths: [paths.data, paths.logs] },
    { id: 'configure-models', action: 'patch ZCode model catalog atomically', path: paths.zcodeConfig, main_model: options.mainModel, lite_model: options.liteModel },
    { id: 'write-product-config', action: 'write product paths and fixed runtime', path: paths.config },
    { id: 'install-launch-agent', action: 'install daemon LaunchAgent', path: paths.launchAgent, label: LAUNCH_AGENT_LABEL },
  ];
}

function plist(paths) {
  const daemon = nativeBinary('zcode-agentd');
  const esc = (value) => value.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
  return Buffer.from(`<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0"><dict>\n<key>Label</key><string>${LAUNCH_AGENT_LABEL}</string>\n<key>ProgramArguments</key><array><string>${esc(daemon)}</string><string>--database</string><string>${esc(paths.database)}</string><string>--socket</string><string>${esc(paths.socket)}</string><string>--runtime</string><string>${esc(ZCODE_RUNTIME)}</string></array>\n<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>\n<key>StandardOutPath</key><string>${esc(path.join(paths.logs, 'daemon.log'))}</string>\n<key>StandardErrorPath</key><string>${esc(path.join(paths.logs, 'daemon-error.log'))}</string>\n</dict></plist>\n`);
}

function loadState(file) {
  const bytes = readOptional(file);
  if (bytes === null) return { schema_version: 1, completed: [] };
  try { return JSON.parse(bytes); } catch { throw new CliError('INVALID_INSTALL_STATE', 'install state is invalid JSON'); }
}

export function runInit(options = {}) {
  const paths = options.paths || productPaths();
  const plan = installPlan(paths, options);
  if (options.dryRun) return { dry_run: true, plan };
  if (!fs.existsSync(ZCODE_RUNTIME) && !options.skipRuntimeProbe) {
    throw new CliError('ZCODE_RUNTIME_NOT_FOUND', `required ZCode runtime is missing: ${ZCODE_RUNTIME}`);
  }
  if (!fs.existsSync(nativeBinary('zcode-agentd')) && !options.skipNativeProbe) {
    throw new CliError('NATIVE_BINARY_NOT_FOUND', 'npm package does not contain the macOS daemon binary');
  }
  const prior = { config: readOptional(paths.config), launchAgent: readOptional(paths.launchAgent) };
  const state = options.resume ? loadState(paths.state) : { schema_version: 1, completed: [] };
  const completed = new Set(state.completed || []);
  const mark = (id) => {
    completed.add(id);
    atomicWrite(paths.state, jsonBytes({ schema_version: 1, completed: [...completed] }));
  };
  try {
    if (!completed.has('probe-runtime')) mark('probe-runtime');
    if (!completed.has('create-data')) {
      fs.mkdirSync(paths.data, { recursive: true, mode: 0o700 });
      fs.mkdirSync(paths.logs, { recursive: true, mode: 0o700 });
      mark('create-data');
    }
    if (!completed.has('configure-models')) {
      patchCatalog(paths.zcodeConfig, paths.provenance, options);
      mark('configure-models');
    }
    if (!completed.has('write-product-config')) {
      atomicWrite(paths.config, jsonBytes({ schema_version: 1, runtime: ZCODE_RUNTIME, database: paths.database, socket: paths.socket }));
      mark('write-product-config');
    }
    if (!completed.has('install-launch-agent')) {
      atomicWrite(paths.launchAgent, plist(paths), 0o600);
      mark('install-launch-agent');
    }
  } catch (error) {
    restoreOptional(paths.config, prior.config);
    restoreOptional(paths.launchAgent, prior.launchAgent);
    throw error;
  }
  return { installed: true, resumed: Boolean(options.resume), completed: [...completed], runtime: ZCODE_RUNTIME };
}
