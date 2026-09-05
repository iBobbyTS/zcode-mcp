import fs from 'node:fs';
import { BUSINESS_COMMANDS, PRODUCT_NAME, VERSION, ZCODE_RUNTIME } from './constants.mjs';
import { CliError } from './errors.mjs';
import { patchCatalog, restoreCatalog, verifyCatalog } from './catalog.mjs';
import { runInit, installPlan, nativeBinary } from './installer.mjs';
import { backupData, cleanupLegacy, purge, restoreData, uninstall } from './maintenance.mjs';
import { platform, productPaths } from './paths.mjs';
import { startService, stopService } from './service.mjs';

const HELP = `zcode-as-subagent ${VERSION}\n\nUsage: zcode-as-subagent <command> [options]\n\nCommands:\n  help, version               Show basic product information\n  init [--dry-run] [--resume] Install and configure the local service\n  config models               Install or restore the ZCode model catalog\n  status, diagnose            Inspect local service and runtime state\n  backup --output <dir>       Back up retained product data\n  restore --input <dir>       Verify and restore product data\n  uninstall                   Remove service registration; retain data\n  purge --yes                 Explicitly delete new product data\n  cleanup-legacy --yes        Delete old unpublished installation (no migration)\n`;

function value(args, name) {
  const index = args.indexOf(name);
  if (index < 0) return undefined;
  const result = args[index + 1];
  if (!result || result.startsWith('--')) throw new CliError('INVALID_ARGUMENT', `${name} requires a value`, 2);
  return result;
}

function modelOptions(args) {
  return { mainModel: value(args, '--main-model'), liteModel: value(args, '--lite-model') };
}

function output(valueToWrite) {
  process.stdout.write(`${JSON.stringify({ ok: true, product: PRODUCT_NAME, ...valueToWrite }, null, 2)}\n`);
}

export async function main(args) {
  const command = args[0] || 'help';
  if (command === 'help' || command === '--help' || command === '-h') {
    process.stdout.write(HELP); return;
  }
  if (command === 'version' || command === '--version' || command === '-v') {
    process.stdout.write(`${VERSION}\n`); return;
  }
  if (!BUSINESS_COMMANDS.has(command)) throw new CliError('UNKNOWN_COMMAND', `unknown command: ${command}`, 2);
  if (platform() !== 'darwin') throw new CliError('UNSUPPORTED_PLATFORM', `${command} is supported only on macOS`);

  const paths = productPaths();
  const models = modelOptions(args);
  if (command === 'init') {
    output(runInit({ paths, dryRun: args.includes('--dry-run'), resume: args.includes('--resume'), ...models })); return;
  }
  if (command === 'config') {
    if (args[1] !== 'models') throw new CliError('INVALID_ARGUMENT', 'usage: config models [--restore] [--main-model ID] [--lite-model ID]', 2);
    output(args.includes('--restore') ? restoreCatalog(paths.zcodeConfig, paths.provenance) : patchCatalog(paths.zcodeConfig, paths.provenance, models)); return;
  }
  if (command === 'status') {
    output({ installed: fs.existsSync(paths.state), launch_agent: fs.existsSync(paths.launchAgent), data: fs.existsSync(paths.data) }); return;
  }
  if (command === 'diagnose') {
    let catalog = false;
    try { catalog = verifyCatalog(JSON.parse(fs.readFileSync(paths.zcodeConfig, 'utf8')), models); } catch {}
    output({ platform: platform(), runtime: ZCODE_RUNTIME, runtime_exists: fs.existsSync(ZCODE_RUNTIME), daemon_binary: nativeBinary('zcode-agentd'), daemon_binary_exists: fs.existsSync(nativeBinary('zcode-agentd')), catalog }); return;
  }
  if (command === 'backup') { output(backupData(value(args, '--output'), paths)); return; }
  if (command === 'restore') { output(restoreData(value(args, '--input'), paths)); return; }
  if (command === 'start') { output(startService(paths)); return; }
  if (command === 'stop') { output(stopService(paths)); return; }
  if (command === 'uninstall') { output(uninstall(paths)); return; }
  if (command === 'purge') {
    if (!args.includes('--yes')) throw new CliError('CONFIRMATION_REQUIRED', 'purge requires --yes');
    output(purge(paths)); return;
  }
  if (command === 'cleanup-legacy') {
    if (!args.includes('--yes')) throw new CliError('CONFIRMATION_REQUIRED', 'cleanup-legacy requires --yes');
    output(cleanupLegacy(paths.home)); return;
  }
  throw new CliError('NOT_IMPLEMENTED', `${command} is reserved for the local daemon client`);
}

export { HELP, installPlan };
