export const PRODUCT_NAME = 'zcode-as-subagent';
export const PRODUCT_ID = 'zcode_as_subagent';
export const VERSION = '0.1.0';
export const LAUNCH_AGENT_LABEL = 'com.zcode-as-subagent.daemon';
export const ZCODE_RUNTIME = '/Applications/ZCode.app/Contents/Resources/glm/zcode.cjs';
export const DEFAULT_MAIN_MODEL = 'glm-5.3';
export const DEFAULT_LITE_MODEL = 'glm-5.3-flash';

export const BUSINESS_COMMANDS = new Set([
  'init', 'config', 'status', 'diagnose', 'backup', 'restore', 'start', 'stop',
  'uninstall', 'purge', 'cleanup-legacy', 'create', 'get', 'list', 'send',
  'respond', 'cancel', 'result', 'close',
]);
