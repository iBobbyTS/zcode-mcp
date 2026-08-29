import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export const POLICY_VERSION = 'zcode-readonly-bash/v1.0.0';
export const MAX_COMMAND_BYTES = 16 * 1024;
export const MAX_ARGUMENTS = 128;
export const MAX_PATH_ARGUMENTS = 64;
export const DEFAULT_TRUSTED_BIN_DIRS = Object.freeze([
  '/usr/bin', '/bin', '/usr/sbin', '/sbin', '/opt/homebrew/bin', '/usr/local/bin'
]);

const POLICY_DESCRIPTOR = Object.freeze({
  version: POLICY_VERSION,
  model: 'single-simple-command + command-specific argv policy + workspace confinement',
  programs: [
    'pwd', 'ls', 'stat', 'wc', 'head', 'tail', 'cat', 'grep', 'rg', 'sed',
    'find', 'shasum', 'cksum', 'git'
  ],
  shellComposition: 'deny',
  unknownDefault: 'deny',
  pathScope: 'hook cwd or ZCODE_READONLY_BASH_ROOT',
  executableResolution: 'fixed trusted directories; never caller PATH',
  gitHardening: ['GIT_OPTIONAL_LOCKS=0', 'core.fsmonitor=false', 'core.untrackedCache=false', '--no-pager'],
});

function stableJson(value) {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

export const POLICY_SHA256 = crypto
  .createHash('sha256')
  .update(stableJson(POLICY_DESCRIPTOR))
  .digest('hex');

const SAFE_BARE_ARG = /^[A-Za-z0-9_@%+=:,./^~-]+$/u;
const SAFE_PROGRAM = /^[a-z][a-z0-9-]*$/u;
const CONTROL_CHAR = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u;
const URL_SCHEME = /^[A-Za-z][A-Za-z0-9+.-]*:\/\//u;

const SHELL_META_CODES = new Map([
  [';', 'shell_sequence'],
  ['&', 'shell_background_or_and'],
  ['|', 'shell_pipeline_or_or'],
  ['<', 'shell_input_or_process_substitution'],
  ['>', 'shell_redirection'],
  ['(', 'shell_subshell'],
  [')', 'shell_subshell'],
  ['{', 'shell_brace_expansion'],
  ['}', 'shell_brace_expansion'],
  ['$', 'shell_expansion'],
  ['`', 'shell_command_substitution'],
  ['*', 'shell_glob'],
  ['?', 'shell_glob'],
  ['[', 'shell_glob'],
  [']', 'shell_glob'],
  ['#', 'shell_comment'],
  ['!', 'shell_history_or_negation'],
]);

const SECRET_DIR_NAMES = new Set([
  '.git',
  '.agent-work',
  '.ssh',
  '.gnupg',
  '.aws',
  '.azure',
  '.kube',
  '.docker',
  '.config/gcloud',
  'Library/Keychains',
]);

const SECRET_FILE_NAMES = new Set([
  '.netrc',
  '.npmrc',
  '.pypirc',
  'credentials.json',
  'credentials',
  'secrets.json',
  'secret.json',
  'service-account.json',
  'service_account.json',
  'id_rsa',
  'id_dsa',
  'id_ecdsa',
  'id_ed25519',
  'known_hosts',
  'authorized_keys',
  'cookies.sqlite',
  'cookies',
  'login data',
  'keychain-db',
]);

const SECRET_EXTENSIONS = new Set([
  '.pem', '.key', '.p12', '.pfx', '.jks', '.keystore', '.kdbx'
]);

function result(decision, code, reason, extra = {}) {
  return {
    decision,
    code,
    reason,
    policyVersion: POLICY_VERSION,
    policySha256: POLICY_SHA256,
    ...extra,
  };
}

function hardDeny(code, reason, extra = {}) {
  return result('deny', code, reason, extra);
}

function unsupported(context, code, reason, extra = {}) {
  return result(context.unknownDecision, code, reason, extra);
}

function allow(code, reason, argv, extra = {}) {
  return result('allow', code, reason, {
    argv,
    canonicalCommand: renderCanonicalCommand(argv, extra.environmentAssignments ?? []),
    ...extra,
  });
}

export function renderCanonicalCommand(argv, environmentAssignments = []) {
  const prefix = environmentAssignments.map(([key, value]) => `${key}=${shellQuote(value)}`);
  return [...prefix, ...argv.map(shellQuote)].join(' ');
}

export function shellQuote(value) {
  const text = String(value);
  if (text.length > 0 && SAFE_BARE_ARG.test(text)) return text;
  return `'${text.replaceAll("'", `'\"'\"'`)}'`;
}

export function tokenizeSimpleCommand(source) {
  if (typeof source !== 'string') {
    return hardDeny('command_not_string', 'Bash command must be a string');
  }
  if (Buffer.byteLength(source, 'utf8') > MAX_COMMAND_BYTES) {
    return hardDeny('command_too_large', `command exceeds ${MAX_COMMAND_BYTES} UTF-8 bytes`);
  }
  if (source.includes('\0') || CONTROL_CHAR.test(source)) {
    return hardDeny('command_control_character', 'command contains a control character');
  }
  if (source.includes('\n') || source.includes('\r')) {
    return hardDeny('command_multiline', 'multiline shell input is not allowed');
  }

  const tokens = [];
  let value = '';
  let started = false;
  let protectedByQuote = false;
  let quote = null;

  const push = () => {
    if (!started) return;
    tokens.push({ value, protected: protectedByQuote });
    value = '';
    started = false;
    protectedByQuote = false;
  };

  for (let i = 0; i < source.length; i += 1) {
    const ch = source[i];

    if (quote === "'") {
      if (ch === "'") {
        quote = null;
        protectedByQuote = true;
      } else {
        value += ch;
        started = true;
      }
      continue;
    }

    if (quote === '"') {
      if (ch === '"') {
        quote = null;
        protectedByQuote = true;
        continue;
      }
      if (ch === '$' || ch === '`') {
        return hardDeny('double_quote_expansion', 'parameter and command expansion are not allowed inside double quotes');
      }
      if (ch === '\\') {
        const next = source[i + 1];
        if (next === undefined || next === '\n' || next === '\r') {
          return hardDeny('invalid_escape', 'invalid or multiline escape');
        }
        if (!['"', '\\'].includes(next)) {
          return hardDeny('ambiguous_double_quote_escape', 'only quote and backslash escapes are accepted inside double quotes');
        }
        value += next;
        started = true;
        protectedByQuote = true;
        i += 1;
        continue;
      }
      value += ch;
      started = true;
      continue;
    }

    if (ch === ' ' || ch === '\t') {
      push();
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      started = true;
      protectedByQuote = true;
      continue;
    }
    if (ch === '\\') {
      const next = source[i + 1];
      if (next === undefined || next === '\n' || next === '\r') {
        return hardDeny('invalid_escape', 'invalid or multiline escape');
      }
      value += next;
      started = true;
      protectedByQuote = true;
      i += 1;
      continue;
    }
    if (SHELL_META_CODES.has(ch)) {
      return hardDeny(SHELL_META_CODES.get(ch), `unquoted shell metacharacter ${JSON.stringify(ch)} is not allowed`);
    }
    value += ch;
    started = true;
  }

  if (quote !== null) {
    return hardDeny('unclosed_quote', 'command contains an unclosed quote');
  }
  push();

  if (tokens.length === 0) return hardDeny('empty_command', 'empty command is not allowed');
  if (tokens.length > MAX_ARGUMENTS) {
    return hardDeny('too_many_arguments', `command exceeds ${MAX_ARGUMENTS} arguments`);
  }
  if (/^[A-Za-z_][A-Za-z0-9_]*=/u.test(tokens[0].value)) {
    return hardDeny('environment_assignment', 'caller-supplied environment assignments are not allowed');
  }
  return result('parsed', 'parsed', 'simple command parsed', { tokens });
}

function realpathOrNull(target) {
  try {
    return fs.realpathSync.native(target);
  } catch (error) {
    if (error && ['ENOENT', 'ENOTDIR'].includes(error.code)) return null;
    throw error;
  }
}

function pathInside(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}

function deepestExistingAncestor(candidate) {
  let current = candidate;
  for (;;) {
    if (fs.existsSync(current)) return current;
    const parent = path.dirname(current);
    if (parent === current) return current;
    current = parent;
  }
}

function secretPathReason(relativePath) {
  const posix = relativePath.split(path.sep).join('/');
  const lower = posix.toLowerCase();
  const components = lower.split('/').filter(Boolean);

  for (const denied of SECRET_DIR_NAMES) {
    const d = denied.toLowerCase();
    if (lower === d || lower.startsWith(`${d}/`) || lower.includes(`/${d}/`) || lower.endsWith(`/${d}`)) {
      return `path enters sensitive directory ${denied}`;
    }
  }

  const basename = components.at(-1) ?? '';
  if (SECRET_FILE_NAMES.has(basename)) return `path targets sensitive file ${basename}`;

  if (basename === '.env' || (basename.startsWith('.env.') && !/\.(example|sample|template|dist)$/u.test(basename))) {
    return `path targets sensitive environment file ${basename}`;
  }

  if (SECRET_EXTENSIONS.has(path.extname(basename))) {
    return `path targets sensitive key/certificate extension ${path.extname(basename)}`;
  }

  return null;
}

export function createPathContext(cwdInput, rootInput) {
  if (typeof cwdInput !== 'string' || cwdInput.length === 0) {
    return hardDeny('cwd_missing', 'hook input must include a nonempty cwd');
  }
  const cwd = realpathOrNull(path.resolve(cwdInput));
  if (!cwd) return hardDeny('cwd_not_found', 'hook cwd does not exist');

  const rootCandidate = rootInput ? path.resolve(rootInput) : cwd;
  const root = realpathOrNull(rootCandidate);
  if (!root) return hardDeny('root_not_found', 'configured read root does not exist');
  if (!pathInside(root, cwd)) return hardDeny('cwd_outside_root', 'hook cwd is outside the configured read root');
  return result('parsed', 'path_context_ready', 'path context ready', { cwd, root });
}

export function validatePathArgument(raw, context, options = {}) {
  const value = String(raw);
  if (value.length === 0) return hardDeny('empty_path', 'empty path is not allowed');
  if (value === '-') return hardDeny('stdin_path', 'stdin pseudo-path is not allowed');
  if (value.includes('\0') || CONTROL_CHAR.test(value)) return hardDeny('path_control_character', 'path contains a control character');
  if (URL_SCHEME.test(value)) return hardDeny('url_path', 'URL arguments are not allowed');
  if (value.startsWith('~')) return hardDeny('tilde_path', 'tilde expansion is not allowed');
  if (path.isAbsolute(value)) return hardDeny('absolute_path', 'absolute path arguments are not allowed');
  if (value.startsWith(':(')) return hardDeny('git_magic_pathspec', 'Git magic pathspecs are not allowed');

  const candidate = path.resolve(context.cwd, value);
  if (!pathInside(context.root, candidate)) {
    return hardDeny('path_escape', 'path escapes the configured review root');
  }

  const ancestor = deepestExistingAncestor(candidate);
  const realAncestor = realpathOrNull(ancestor);
  if (!realAncestor || !pathInside(context.root, realAncestor)) {
    return hardDeny('symlink_escape', 'path resolves through a symlink outside the configured review root');
  }

  const realCandidate = realpathOrNull(candidate);
  if (realCandidate && !pathInside(context.root, realCandidate)) {
    return hardDeny('symlink_escape', 'path resolves outside the configured review root');
  }

  const rootRelative = path.relative(context.root, candidate) || '.';
  const realRootRelative = realCandidate ? (path.relative(context.root, realCandidate) || '.') : rootRelative;
  const secret = secretPathReason(rootRelative) ?? secretPathReason(realRootRelative);
  if (secret && !options.allowSensitive) return hardDeny('sensitive_path', secret);

  if (options.mustExist && !realCandidate) return hardDeny('path_not_found', 'path must exist for this read operation');
  if (realCandidate && Array.isArray(options.allowedTypes) && options.allowedTypes.length > 0) {
    const stat = fs.statSync(realCandidate);
    const type = stat.isFile() ? 'file' : stat.isDirectory() ? 'directory' : 'special';
    if (!options.allowedTypes.includes(type)) {
      return hardDeny('path_type_denied', `path type ${type} is not allowed for this command`);
    }
  }

  const cwdRelative = path.relative(context.cwd, candidate) || '.';
  return result('parsed', 'path_allowed', 'path is confined', {
    normalizedPath: cwdRelative.split(path.sep).join('/'),
    absolutePath: candidate,
  });
}

function normalizePaths(values, context, options = {}) {
  if (values.length > MAX_PATH_ARGUMENTS) {
    return hardDeny('too_many_paths', `command exceeds ${MAX_PATH_ARGUMENTS} path arguments`);
  }
  const normalized = [];
  for (const value of values) {
    const checked = validatePathArgument(value, context, options);
    if (checked.decision === 'deny') return checked;
    normalized.push(checked.normalizedPath);
  }
  return result('parsed', 'paths_allowed', 'paths are confined', { normalizedPaths: normalized });
}

function positiveInteger(value, max, label) {
  if (!/^[0-9]+$/u.test(String(value))) return hardDeny('invalid_numeric_option', `${label} must be a nonnegative integer`);
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number > max) return hardDeny('numeric_option_too_large', `${label} exceeds ${max}`);
  return result('parsed', 'numeric_option_allowed', `${label} is within bounds`, { number });
}

function parseLongOption(token) {
  const index = token.indexOf('=');
  if (index < 0) return { name: token, inlineValue: undefined };
  return { name: token.slice(0, index), inlineValue: token.slice(index + 1) };
}

function takeOptionValue(args, index, inlineValue, optionName) {
  if (inlineValue !== undefined) return { value: inlineValue, nextIndex: index };
  if (index + 1 >= args.length) return { error: hardDeny('missing_option_value', `${optionName} requires a value`) };
  return { value: args[index + 1].value, nextIndex: index + 1 };
}

function resolveTrustedProgram(program, trustedBinDirs) {
  const directories = Array.isArray(trustedBinDirs) && trustedBinDirs.length > 0
    ? trustedBinDirs
    : DEFAULT_TRUSTED_BIN_DIRS;
  for (const directory of directories) {
    if (typeof directory !== 'string' || !path.isAbsolute(directory)) continue;
    const candidate = path.join(directory, program);
    try {
      const stat = fs.statSync(candidate);
      if (!stat.isFile() || (stat.mode & 0o111) === 0) continue;
      return fs.realpathSync.native(candidate);
    } catch (error) {
      if (error && ['ENOENT', 'ENOTDIR', 'EACCES'].includes(error.code)) continue;
      throw error;
    }
  }
  return null;
}

function assertSafeProgram(program) {
  if (!SAFE_PROGRAM.test(program) || program.includes('/')) {
    return hardDeny('program_not_allowlisted', 'program must be a bare allowlisted executable name');
  }
  return null;
}

function validatePwd(args, context) {
  if (args.length > 1 || args.some((arg) => !['-L', '-P'].includes(arg.value))) {
    return unsupported(context, 'pwd_option_not_allowlisted', 'pwd accepts only -L or -P');
  }
  return allow('readonly_pwd', 'pwd is a bounded read-only inspection', ['pwd', ...args.map((arg) => arg.value)]);
}

function validateLs(args, context) {
  const allowedLong = new Set([
    '--all', '--almost-all', '--directory', '--human-readable', '--inode',
    '--numeric-uid-gid', '--color=never', '--group-directories-first'
  ]);
  const shortAllowed = new Set('aAldhni1G'.split(''));
  const argv = ['ls'];
  const paths = [];
  let optionsEnded = false;

  for (const arg of args) {
    const token = arg.value;
    if (!optionsEnded && token === '--') {
      optionsEnded = true;
      argv.push('--');
      continue;
    }
    if (!optionsEnded && token.startsWith('--')) {
      if (token.startsWith('--time-style=')) {
        const value = token.slice('--time-style='.length);
        if (!['full-iso', 'long-iso', 'iso'].includes(value)) {
          return unsupported(context, 'ls_time_style_not_allowlisted', 'unsupported ls --time-style value');
        }
      } else if (!allowedLong.has(token)) {
        return unsupported(context, 'ls_option_not_allowlisted', `unsupported ls option ${token}`);
      }
      argv.push(token);
      continue;
    }
    if (!optionsEnded && /^-[^-]+$/u.test(token)) {
      for (const flag of token.slice(1)) {
        if (!shortAllowed.has(flag)) return unsupported(context, 'ls_option_not_allowlisted', `unsupported ls flag -${flag}`);
      }
      argv.push(token);
      continue;
    }
    paths.push(token);
  }

  const normalized = normalizePaths(paths, context);
  if (normalized.decision === 'deny') return normalized;
  argv.push(...normalized.normalizedPaths);
  return allow('readonly_ls', 'ls options and paths are read-only and confined', argv);
}

function validateStat(args, context) {
  const argv = ['stat'];
  const paths = [];
  let optionsEnded = false;
  for (let i = 0; i < args.length; i += 1) {
    const token = args[i].value;
    if (!optionsEnded && token === '--') {
      optionsEnded = true;
      argv.push('--');
      continue;
    }
    if (!optionsEnded && ['-L', '-x', '--dereference', '--file-system', '--terse'].includes(token)) {
      argv.push(token);
      continue;
    }
    if (!optionsEnded && ['-f', '-c', '--format', '--printf'].some((name) => token === name || token.startsWith(`${name}=`))) {
      const { name, inlineValue } = parseLongOption(token);
      const taken = takeOptionValue(args, i, inlineValue, name);
      if (taken.error) return taken.error;
      argv.push(inlineValue === undefined ? name : `${name}=${taken.value}`);
      if (inlineValue === undefined) argv.push(taken.value);
      i = taken.nextIndex;
      continue;
    }
    if (!optionsEnded && token.startsWith('-')) return unsupported(context, 'stat_option_not_allowlisted', `unsupported stat option ${token}`);
    paths.push(token);
  }
  if (paths.length === 0) return hardDeny('stat_path_required', 'stat requires at least one confined path');
  const normalized = normalizePaths(paths, context);
  if (normalized.decision === 'deny') return normalized;
  argv.push(...normalized.normalizedPaths);
  return allow('readonly_stat', 'stat options and paths are read-only and confined', argv);
}

function validateWc(args, context) {
  const argv = ['wc'];
  const paths = [];
  const allowed = new Set('clmwL'.split(''));
  let optionsEnded = false;
  for (const arg of args) {
    const token = arg.value;
    if (!optionsEnded && token === '--') {
      optionsEnded = true;
      argv.push('--');
      continue;
    }
    if (!optionsEnded && /^-[^-]+$/u.test(token)) {
      for (const flag of token.slice(1)) if (!allowed.has(flag)) return unsupported(context, 'wc_option_not_allowlisted', `unsupported wc flag -${flag}`);
      argv.push(token);
      continue;
    }
    if (!optionsEnded && token.startsWith('--')) {
      if (!['--bytes', '--chars', '--lines', '--max-line-length', '--words'].includes(token)) {
        return unsupported(context, 'wc_option_not_allowlisted', `unsupported wc option ${token}`);
      }
      argv.push(token);
      continue;
    }
    paths.push(token);
  }
  if (paths.length === 0) return hardDeny('wc_path_required', 'wc may not read from stdin');
  const normalized = normalizePaths(paths, context, { mustExist: true, allowedTypes: ['file'] });
  if (normalized.decision === 'deny') return normalized;
  argv.push(...normalized.normalizedPaths);
  return allow('readonly_wc', 'wc reads confined files only', argv);
}

function validateCat(args, context) {
  const argv = ['cat'];
  const paths = [];
  const allowed = new Set('AbEnstTuv'.split(''));
  let optionsEnded = false;
  for (const arg of args) {
    const token = arg.value;
    if (!optionsEnded && token === '--') {
      optionsEnded = true;
      argv.push('--');
      continue;
    }
    if (!optionsEnded && /^-[^-]+$/u.test(token)) {
      for (const flag of token.slice(1)) if (!allowed.has(flag)) return unsupported(context, 'cat_option_not_allowlisted', `unsupported cat flag -${flag}`);
      argv.push(token);
      continue;
    }
    if (!optionsEnded && token.startsWith('--')) {
      if (!['--number', '--number-nonblank', '--show-all', '--show-ends', '--show-tabs', '--squeeze-blank'].includes(token)) {
        return unsupported(context, 'cat_option_not_allowlisted', `unsupported cat option ${token}`);
      }
      argv.push(token);
      continue;
    }
    paths.push(token);
  }
  if (paths.length === 0) return hardDeny('cat_path_required', 'cat may not read from stdin');
  const normalized = normalizePaths(paths, context, { mustExist: true, allowedTypes: ['file'] });
  if (normalized.decision === 'deny') return normalized;
  argv.push(...normalized.normalizedPaths);
  return allow('readonly_cat', 'cat reads confined files only', argv);
}

function validateHeadTail(program, args, context) {
  const argv = [program];
  const paths = [];
  let optionsEnded = false;
  for (let i = 0; i < args.length; i += 1) {
    const token = args[i].value;
    if (!optionsEnded && token === '--') {
      optionsEnded = true;
      argv.push('--');
      continue;
    }
    if (!optionsEnded && program === 'tail' && (token === '-f' || token === '-F' || token === '--follow' || token.startsWith('--follow=') || token === '--retry')) {
      return hardDeny('tail_follow_denied', 'tail follow/retry modes are unbounded and not allowed');
    }
    if (!optionsEnded && ['-q', '-v', '--quiet', '--silent', '--verbose'].includes(token)) {
      argv.push(token);
      continue;
    }
    if (!optionsEnded && /^-[0-9]+$/u.test(token)) {
      const checked = positiveInteger(token.slice(1), 10000, `${program} line count`);
      if (checked.decision === 'deny') return checked;
      argv.push(token);
      continue;
    }
    if (!optionsEnded && ['-n', '--lines', '-c', '--bytes'].some((name) => token === name || token.startsWith(`${name}=`))) {
      const { name, inlineValue } = parseLongOption(token);
      const taken = takeOptionValue(args, i, inlineValue, name);
      if (taken.error) return taken.error;
      const rawNumber = String(taken.value).replace(/^\+/u, '');
      const checked = positiveInteger(rawNumber, name === '-c' || name === '--bytes' ? 1_048_576 : 10000, `${program} ${name}`);
      if (checked.decision === 'deny') return checked;
      argv.push(inlineValue === undefined ? name : `${name}=${taken.value}`);
      if (inlineValue === undefined) argv.push(taken.value);
      i = taken.nextIndex;
      continue;
    }
    if (!optionsEnded && token.startsWith('-')) return unsupported(context, `${program}_option_not_allowlisted`, `unsupported ${program} option ${token}`);
    paths.push(token);
  }
  if (paths.length === 0) return hardDeny(`${program}_path_required`, `${program} may not read from stdin`);
  const normalized = normalizePaths(paths, context, { mustExist: true, allowedTypes: ['file'] });
  if (normalized.decision === 'deny') return normalized;
  argv.push(...normalized.normalizedPaths);
  return allow(`readonly_${program}`, `${program} reads bounded content from confined files`, argv);
}

function parseGrepLike(program, args, context, mode) {
  const argv = [program];
  const paths = [];
  let patternSpecified = false;
  let filesMode = false;
  let optionsEnded = false;
  const booleanShort = new Set((mode === 'grep' ? 'HhIiLnqsvEFPowx' : 'nHhIiSsFUlcvqwo').split(''));
  const valueShort = new Set((mode === 'grep' ? 'efmABC' : 'egtmABC').split(''));
  const booleanLong = new Set(mode === 'grep' ? [
    '--with-filename', '--no-filename', '--ignore-case', '--no-messages', '--invert-match',
    '--line-number', '--files-with-matches', '--files-without-match', '--count', '--only-matching',
    '--word-regexp', '--line-regexp', '--fixed-strings', '--extended-regexp', '--perl-regexp',
    '--binary-files=without-match', '--binary-files=text', '--color=never'
  ] : [
    '--line-number', '--with-filename', '--no-filename', '--ignore-case', '--case-sensitive',
    '--smart-case', '--fixed-strings', '--files',
    '--files-with-matches', '--files-without-match', '--count', '--count-matches', '--only-matching',
    '--word-regexp', '--line-regexp', '--json', '--stats', '--heading', '--no-heading', '--column',
    '--pcre2', '--color=never'
  ]);
  const valueLong = new Set(mode === 'grep' ? [
    '--regexp', '--file', '--max-count', '--after-context', '--before-context', '--context',
    '--include', '--exclude', '--exclude-dir', '--exclude-from', '--directories', '--devices'
  ] : [
    '--regexp', '--glob', '--type', '--type-not', '--max-count', '--after-context',
    '--before-context', '--context', '--file', '--ignore-file', '--encoding', '--sort', '--sortr'
  ]);
  const deniedLongPrefixes = mode === 'rg' ? ['--pre', '--pre-glob', '--follow'] : [];

  for (let i = 0; i < args.length; i += 1) {
    const token = args[i].value;
    if (!optionsEnded && token === '--') {
      optionsEnded = true;
      argv.push('--');
      continue;
    }
    if (!optionsEnded && deniedLongPrefixes.some((prefix) => token === prefix || token.startsWith(`${prefix}=`))) {
      return hardDeny(`${mode}_execution_option_denied`, `${token} can invoke external processing or follow paths outside the review root`);
    }
    if (!optionsEnded && token.startsWith('--')) {
      const { name, inlineValue } = parseLongOption(token);
      if (booleanLong.has(token)) {
        if (token === '--files') filesMode = true;
        argv.push(token);
        continue;
      }
      if (!valueLong.has(name)) return unsupported(context, `${mode}_option_not_allowlisted`, `unsupported ${mode} option ${token}`);
      const taken = takeOptionValue(args, i, inlineValue, name);
      if (taken.error) return taken.error;
      let value = taken.value;
      if (['--file', '--ignore-file', '--exclude-from'].includes(name)) {
        const checked = validatePathArgument(value, context, { mustExist: true, allowedTypes: ['file'] });
        if (checked.decision === 'deny') return checked;
        value = checked.normalizedPath;
      }
      if (['--max-count', '--after-context', '--before-context', '--context'].includes(name)) {
        const checked = positiveInteger(value, 10000, `${mode} ${name}`);
        if (checked.decision === 'deny') return checked;
      }
      if (name === '--regexp' || name === '--file') patternSpecified = true;
      argv.push(inlineValue === undefined ? name : `${name}=${value}`);
      if (inlineValue === undefined) argv.push(value);
      i = taken.nextIndex;
      continue;
    }
    if (!optionsEnded && /^-[^-]+$/u.test(token)) {
      const cluster = token.slice(1);
      if (cluster.length === 1 && valueShort.has(cluster)) {
        if (i + 1 >= args.length) return hardDeny('missing_option_value', `${token} requires a value`);
        let value = args[i + 1].value;
        if (cluster === 'f') {
          const checked = validatePathArgument(value, context, { mustExist: true, allowedTypes: ['file'] });
          if (checked.decision === 'deny') return checked;
          value = checked.normalizedPath;
          patternSpecified = true;
        }
        if ('mABC'.includes(cluster)) {
          const checked = positiveInteger(value, 10000, `${mode} ${token}`);
          if (checked.decision === 'deny') return checked;
        }
        if (cluster === 'e') patternSpecified = true;
        argv.push(token, value);
        i += 1;
        continue;
      }
      for (const flag of cluster) {
        if (!booleanShort.has(flag)) {
          return unsupported(context, `${mode}_option_not_allowlisted`, `unsupported or value-bearing ${mode} flag -${flag}; pass value-bearing flags separately`);
        }
      }
      argv.push(token);
      continue;
    }

    if (filesMode || patternSpecified) {
      paths.push(token);
    } else {
      patternSpecified = true;
      argv.push(token);
    }
  }

  if (!filesMode && !patternSpecified) return hardDeny(`${mode}_pattern_required`, `${mode} requires a search pattern`);
  if (mode === 'grep' && paths.length === 0) return hardDeny('grep_path_required', 'grep may not read from stdin; provide at least one confined path');
  const normalized = normalizePaths(paths, context, { mustExist: true, allowedTypes: ['file', 'directory'] });
  if (normalized.decision === 'deny') return normalized;
  argv.push(...normalized.normalizedPaths);
  return allow(`readonly_${mode}`, `${mode} uses an allowlisted inspection grammar and confined paths`, argv);
}

function validateSed(args, context) {
  if (args.length < 3 || !['-n', '--quiet', '--silent'].includes(args[0].value)) {
    return unsupported(context, 'sed_form_not_allowlisted', 'sed is allowed only as: sed -n Np|N,Mp <confined files>');
  }
  const script = args[1].value;
  const match = /^(\d{1,7})(?:,(\d{1,7}))?p$/u.exec(script);
  if (!match) return hardDeny('sed_script_denied', 'sed script must be a bounded numeric print range');
  const start = Number(match[1]);
  const end = Number(match[2] ?? match[1]);
  if (start < 1 || end < start || end > 100000) return hardDeny('sed_range_invalid', 'sed print range is invalid or too large');
  const paths = args.slice(2).map((arg) => arg.value);
  const normalized = normalizePaths(paths, context, { mustExist: true, allowedTypes: ['file'] });
  if (normalized.decision === 'deny') return normalized;
  return allow('readonly_sed_print', 'sed is restricted to bounded numeric print ranges', ['sed', args[0].value, script, ...normalized.normalizedPaths]);
}

function validateFind(args, context) {
  const actionDeny = new Set([
    '-delete', '-exec', '-execdir', '-ok', '-okdir', '-print', '-print0',
    '-fprint', '-fprint0', '-fprintf', '-fls'
  ]);
  const argv = ['find'];
  const roots = [];
  let i = 0;
  while (i < args.length && !args[i].value.startsWith('-')) {
    roots.push(args[i].value);
    i += 1;
  }
  if (roots.length === 0) return hardDeny('find_root_required', 'find requires at least one confined starting path');
  const normalizedRoots = normalizePaths(roots, context, { mustExist: true, allowedTypes: ['file', 'directory'] });
  if (normalizedRoots.decision === 'deny') return normalizedRoots;
  argv.push(...normalizedRoots.normalizedPaths);

  while (i < args.length) {
    const token = args[i].value;
    if (actionDeny.has(token)) return hardDeny('find_action_denied', `${token} can write, delete, or execute commands`);
    if (['-L', '-H'].includes(token)) return hardDeny('find_symlink_follow_denied', `${token} may follow symlinks outside the review root`);
    if (['-maxdepth', '-mindepth'].includes(token)) {
      if (i + 1 >= args.length) return hardDeny('missing_option_value', `${token} requires a value`);
      const checked = positiveInteger(args[i + 1].value, 50, `find ${token}`);
      if (checked.decision === 'deny') return checked;
      argv.push(token, args[i + 1].value);
      i += 2;
      continue;
    }
    if (token === '-type') {
      if (i + 1 >= args.length || !/^[fdlpsbc]$/u.test(args[i + 1].value)) return hardDeny('find_type_invalid', 'find -type requires one standard file type letter');
      argv.push(token, args[i + 1].value);
      i += 2;
      continue;
    }
    if (['-name', '-iname', '-path', '-ipath', '-size', '-mtime', '-mmin'].includes(token)) {
      if (i + 1 >= args.length) return hardDeny('missing_option_value', `${token} requires a value`);
      argv.push(token, args[i + 1].value);
      i += 2;
      continue;
    }
    if (token === '-newer') {
      if (i + 1 >= args.length) return hardDeny('missing_option_value', '-newer requires a confined path');
      const checked = validatePathArgument(args[i + 1].value, context, { mustExist: true, allowedTypes: ['file'] });
      if (checked.decision === 'deny') return checked;
      argv.push(token, checked.normalizedPath);
      i += 2;
      continue;
    }
    if (['-empty', '-readable', '-quit'].includes(token)) {
      argv.push(token);
      i += 1;
      continue;
    }
    return unsupported(context, 'find_predicate_not_allowlisted', `unsupported find predicate/action ${token}`);
  }
  return allow('readonly_find', 'find uses a closed predicate grammar without execution, deletion, or output actions', argv);
}

function validateChecksum(program, args, context) {
  const argv = [program];
  const paths = [];
  let optionsEnded = false;
  for (let i = 0; i < args.length; i += 1) {
    const token = args[i].value;
    if (!optionsEnded && token === '--') {
      optionsEnded = true;
      argv.push('--');
      continue;
    }
    if (!optionsEnded && program === 'shasum' && ['-a', '--algorithm'].some((name) => token === name || token.startsWith(`${name}=`))) {
      const { name, inlineValue } = parseLongOption(token);
      const taken = takeOptionValue(args, i, inlineValue, name);
      if (taken.error) return taken.error;
      if (!['1', '224', '256', '384', '512'].includes(taken.value)) return hardDeny('shasum_algorithm_denied', 'unsupported shasum algorithm');
      argv.push(inlineValue === undefined ? name : `${name}=${taken.value}`);
      if (inlineValue === undefined) argv.push(taken.value);
      i = taken.nextIndex;
      continue;
    }
    if (!optionsEnded && program === 'shasum' && ['-b', '-t', '-U'].includes(token)) {
      argv.push(token);
      continue;
    }
    if (!optionsEnded && program === 'shasum' && ['-c', '--check'].includes(token)) {
      return hardDeny('checksum_check_file_denied', 'checksum check mode can reference paths outside the review root');
    }
    if (!optionsEnded && program === 'cksum' && ['-a', '--algorithm'].some((name) => token === name || token.startsWith(`${name}=`))) {
      const { name, inlineValue } = parseLongOption(token);
      const taken = takeOptionValue(args, i, inlineValue, name);
      if (taken.error) return taken.error;
      if (!/^[A-Za-z0-9_-]{1,32}$/u.test(taken.value)) return hardDeny('cksum_algorithm_invalid', 'invalid cksum algorithm name');
      argv.push(inlineValue === undefined ? name : `${name}=${taken.value}`);
      if (inlineValue === undefined) argv.push(taken.value);
      i = taken.nextIndex;
      continue;
    }
    if (!optionsEnded && program === 'cksum' && ['--tag', '--untagged', '--raw'].includes(token)) {
      argv.push(token);
      continue;
    }
    if (!optionsEnded && token.startsWith('-')) return unsupported(context, `${program}_option_not_allowlisted`, `unsupported ${program} option ${token}`);
    paths.push(token);
  }
  if (paths.length === 0) return hardDeny(`${program}_path_required`, `${program} may not read from stdin`);
  const normalized = normalizePaths(paths, context, { mustExist: true, allowedTypes: ['file'] });
  if (normalized.decision === 'deny') return normalized;
  argv.push(...normalized.normalizedPaths);
  return allow(`readonly_${program}`, `${program} hashes confined files only`, argv);
}

const GIT_COMMON_ENV = [
  ['GIT_OPTIONAL_LOCKS', '0'],
  ['GIT_CONFIG_NOSYSTEM', '1'],
  ['GIT_CONFIG_GLOBAL', '/dev/null'],
  ['GIT_ATTR_NOSYSTEM', '1'],
];
const GIT_PREFIX = ['git', '-c', 'core.fsmonitor=false', '-c', 'core.untrackedCache=false', '--no-pager'];

function gitOperandSafety(token) {
  if (token.startsWith('/') || token.startsWith('~') || token === '..' || token.startsWith('../') || token.includes('/../')) {
    return hardDeny('git_operand_path_escape', 'Git operand may not address paths outside the repository');
  }
  const colon = token.indexOf(':');
  if (colon > 0 && colon + 1 < token.length) {
    const objectPath = token.slice(colon + 1);
    if (objectPath.startsWith('/') || objectPath.startsWith('~') || objectPath === '..' || objectPath.startsWith('../') || objectPath.includes('/../')) {
      return hardDeny('git_object_path_escape', 'Git object path may not escape the repository');
    }
    const secret = secretPathReason(objectPath);
    if (secret) return hardDeny('git_object_sensitive_path', secret);
  }
  return null;
}

function validateGitStatus(args, context) {
  const argv = [...GIT_PREFIX, 'status'];
  const shortAllowed = new Set('sbuz'.split(''));
  for (const arg of args) {
    const token = arg.value;
    if (/^-[^-]+$/u.test(token)) {
      for (const flag of token.slice(1)) if (!shortAllowed.has(flag)) return unsupported(context, 'git_status_option_not_allowlisted', `unsupported git status flag -${flag}`);
      argv.push(token);
      continue;
    }
    if (token.startsWith('--')) {
      if (
        ['--short', '--branch', '--show-stash', '--ahead-behind', '--no-ahead-behind', '--renames', '--no-renames'].includes(token)
        || /^--porcelain(?:=v[12])?$/u.test(token)
        || /^--untracked-files=(?:no|normal|all)$/u.test(token)
        || /^--ignored=(?:traditional|matching|no)$/u.test(token)
        || /^--find-renames(?:=[0-9]+%)?$/u.test(token)
        || token === '--column=no'
      ) {
        argv.push(token);
        continue;
      }
    }
    return unsupported(context, 'git_status_argument_denied', 'git status accepts only allowlisted status options and no path operands');
  }
  return allow('readonly_git_status', 'git status is rewritten with no optional locks and no pager', argv, { environmentAssignments: GIT_COMMON_ENV });
}

const GIT_DIFF_BOOLEAN = new Set([
  '--cached', '--staged', '--stat', '--shortstat', '--numstat', '--name-only', '--name-status',
  '--check', '--binary', '--full-index', '--no-color', '--minimal', '--patience', '--histogram',
  '--ignore-space-change', '--ignore-all-space', '--ignore-blank-lines', '--exit-code', '--quiet',
  '--find-renames', '--find-copies', '--relative', '--merge-base', '--word-diff', '--no-renames',
]);
const GIT_DIFF_VALUE = new Set([
  '--unified', '--diff-filter', '--submodule', '--word-diff', '--word-diff-regex', '--find-renames',
  '--find-copies', '--color', '--src-prefix', '--dst-prefix', '--line-prefix', '--inter-hunk-context'
]);
const GIT_LOG_BOOLEAN = new Set([
  '--oneline', '--graph', '--all', '--branches', '--tags', '--remotes', '--reverse', '--topo-order',
  '--date-order', '--author-date-order', '--first-parent', '--merges', '--no-merges', '--follow',
  '--name-only', '--name-status', '--stat', '--shortstat', '--numstat', '--patch', '--no-patch',
  '--decorate', '--no-decorate', '--full-history', '--simplify-merges', '--dense', '--sparse',
  '--boundary', '--left-right', '--cherry-pick', '--cherry-mark', '--ancestry-path', '--bisect',
]);
const GIT_LOG_VALUE = new Set([
  '--max-count', '--skip', '--since', '--until', '--after', '--before', '--author', '--committer',
  '--grep', '--pretty', '--format', '--date', '--decorate', '--diff-filter', '--unified', '--color'
]);

function validateGitDiffLike(subcommand, args, context) {
  const argv = [...GIT_PREFIX, subcommand, '--no-ext-diff', '--no-textconv'];
  let pathsMode = false;
  for (let i = 0; i < args.length; i += 1) {
    const token = args[i].value;
    if (token === '--') {
      pathsMode = true;
      argv.push('--');
      continue;
    }
    if (pathsMode) {
      const checked = validatePathArgument(token, context);
      if (checked.decision === 'deny') return checked;
      argv.push(checked.normalizedPath);
      continue;
    }
    if (['--output', '--ext-diff', '--textconv', '--no-index', '--show-signature', '--exec'].some((name) => token === name || token.startsWith(`${name}=`))) {
      return hardDeny('git_execution_or_output_option_denied', `${token} can write output, execute helpers, or escape the repository`);
    }
    if (subcommand === 'diff') {
      if (GIT_DIFF_BOOLEAN.has(token) || /^-[wbp]$/u.test(token) || /^-U[0-9]+$/u.test(token) || /^--color=(?:never|always|auto)$/u.test(token)) {
        argv.push(token);
        continue;
      }
      const { name, inlineValue } = parseLongOption(token);
      if (GIT_DIFF_VALUE.has(name)) {
        const taken = takeOptionValue(args, i, inlineValue, name);
        if (taken.error) return taken.error;
        argv.push(inlineValue === undefined ? name : `${name}=${taken.value}`);
        if (inlineValue === undefined) argv.push(taken.value);
        i = taken.nextIndex;
        continue;
      }
    } else {
      if (GIT_LOG_BOOLEAN.has(token) || /^-p$/u.test(token) || /^-n[0-9]+$/u.test(token)) {
        argv.push(token);
        continue;
      }
      const { name, inlineValue } = parseLongOption(token);
      if (GIT_LOG_VALUE.has(name) || token === '-n') {
        const taken = takeOptionValue(args, i, inlineValue, name);
        if (taken.error) return taken.error;
        if (name === '--max-count' || name === '--skip' || token === '-n') {
          const checked = positiveInteger(taken.value, 100000, `git ${subcommand} ${name}`);
          if (checked.decision === 'deny') return checked;
        }
        argv.push(inlineValue === undefined ? name : `${name}=${taken.value}`);
        if (inlineValue === undefined) argv.push(taken.value);
        i = taken.nextIndex;
        continue;
      }
    }
    if (token.startsWith('-')) return unsupported(context, `git_${subcommand}_option_not_allowlisted`, `unsupported git ${subcommand} option ${token}`);
    const unsafe = gitOperandSafety(token);
    if (unsafe) return unsafe;
    argv.push(token);
  }
  return allow(`readonly_git_${subcommand}`, `git ${subcommand} is rewritten to disable pagers, external diff, textconv, fsmonitor, and optional locks`, argv, { environmentAssignments: GIT_COMMON_ENV });
}

function validateGitRevParse(args, context) {
  const argv = [...GIT_PREFIX, 'rev-parse'];
  const allowedBoolean = new Set([
    '--verify', '--quiet', '-q', '--symbolic', '--symbolic-full-name', '--show-toplevel',
    '--show-prefix', '--show-cdup', '--show-superproject-working-tree', '--is-inside-work-tree',
    '--is-bare-repository', '--is-shallow-repository', '--show-object-format', '--show-ref-format'
  ]);
  for (let i = 0; i < args.length; i += 1) {
    const token = args[i].value;
    if (allowedBoolean.has(token) || /^--short(?:=[0-9]+)?$/u.test(token) || /^--abbrev-ref(?:=(?:strict|loose))?$/u.test(token)) {
      argv.push(token);
      continue;
    }
    if (token.startsWith('-')) return unsupported(context, 'git_rev_parse_option_not_allowlisted', `unsupported git rev-parse option ${token}`);
    const unsafe = gitOperandSafety(token);
    if (unsafe) return unsafe;
    argv.push(token);
  }
  if (args.length === 0) return hardDeny('git_rev_parse_operand_required', 'git rev-parse requires an explicit query or revision');
  return allow('readonly_git_rev_parse', 'git rev-parse uses an allowlisted query grammar', argv, { environmentAssignments: GIT_COMMON_ENV });
}

function validateGitCatFile(args, context) {
  if (args.length !== 2 || !['-e', '-p', '-t', '-s'].includes(args[0].value)) {
    return unsupported(context, 'git_cat_file_form_not_allowlisted', 'git cat-file is allowed only as -e|-p|-t|-s <object>');
  }
  const unsafe = gitOperandSafety(args[1].value);
  if (unsafe) return unsafe;
  return allow('readonly_git_cat_file', 'git cat-file reads one repository object', [...GIT_PREFIX, 'cat-file', args[0].value, args[1].value], { environmentAssignments: GIT_COMMON_ENV });
}

function validateGitLsFiles(args, context) {
  const argv = [...GIT_PREFIX, 'ls-files'];
  let pathsMode = false;
  for (let i = 0; i < args.length; i += 1) {
    const token = args[i].value;
    if (token === '--') {
      pathsMode = true;
      argv.push('--');
      continue;
    }
    if (pathsMode) {
      const checked = validatePathArgument(token, context);
      if (checked.decision === 'deny') return checked;
      argv.push(checked.normalizedPath);
      continue;
    }
    if ([
      '--cached', '--deleted', '--modified', '--others', '--ignored', '--stage', '--unmerged',
      '--killed', '--directory', '--empty-directory', '--full-name', '--error-unmatch', '--deduplicate'
    ].includes(token) || /^-[cdmoiustk]$/u.test(token)) {
      argv.push(token);
      continue;
    }
    if (['--exclude', '--exclude-from', '--exclude-per-directory'].some((name) => token === name || token.startsWith(`${name}=`))) {
      const { name, inlineValue } = parseLongOption(token);
      const taken = takeOptionValue(args, i, inlineValue, name);
      if (taken.error) return taken.error;
      let value = taken.value;
      if (name === '--exclude-from') {
        const checked = validatePathArgument(value, context, { mustExist: true, allowedTypes: ['file'] });
        if (checked.decision === 'deny') return checked;
        value = checked.normalizedPath;
      }
      argv.push(inlineValue === undefined ? name : `${name}=${value}`);
      if (inlineValue === undefined) argv.push(value);
      i = taken.nextIndex;
      continue;
    }
    if (token.startsWith('-')) return unsupported(context, 'git_ls_files_option_not_allowlisted', `unsupported git ls-files option ${token}`);
    const unsafe = gitOperandSafety(token);
    if (unsafe) return unsafe;
    argv.push(token);
  }
  return allow('readonly_git_ls_files', 'git ls-files uses a read-only index query grammar', argv, { environmentAssignments: GIT_COMMON_ENV });
}

function validateGitBranch(args, context) {
  const argv = [...GIT_PREFIX, 'branch'];
  let listMode = args.length === 0;
  for (let i = 0; i < args.length; i += 1) {
    const token = args[i].value;
    if (['--show-current', '--all', '--remotes', '--verbose', '-a', '-r', '-v', '-vv'].includes(token)) {
      listMode = true;
      argv.push(token);
      continue;
    }
    if (token === '--list') {
      listMode = true;
      argv.push(token);
      continue;
    }
    if (['--contains', '--no-contains', '--merged', '--no-merged', '--points-at', '--sort', '--format'].some((name) => token === name || token.startsWith(`${name}=`))) {
      const { name, inlineValue } = parseLongOption(token);
      const taken = takeOptionValue(args, i, inlineValue, name);
      if (taken.error) return taken.error;
      argv.push(inlineValue === undefined ? name : `${name}=${taken.value}`);
      if (inlineValue === undefined) argv.push(taken.value);
      i = taken.nextIndex;
      listMode = true;
      continue;
    }
    if (token.startsWith('-')) return hardDeny('git_branch_mutation_or_unknown_option', `git branch option ${token} is not in the read-only list grammar`);
    if (!listMode) return hardDeny('git_branch_positional_mutation', 'a positional branch name without --list would create or modify a branch');
    argv.push(token);
  }
  return allow('readonly_git_branch', 'git branch is restricted to listing/query forms', argv, { environmentAssignments: GIT_COMMON_ENV });
}

function validateGit(args, context) {
  const original = args.map((arg) => arg.value);
  let index = 0;
  if (original[index] === '--no-pager') index += 1;
  if (index >= original.length) return hardDeny('git_subcommand_required', 'git requires an allowlisted subcommand');
  if (original[index].startsWith('-')) {
    return hardDeny('git_global_option_denied', 'caller-supplied Git global options such as -C, -c, --git-dir, and --work-tree are not allowed');
  }
  const subcommand = original[index];
  const subArgs = args.slice(index + 1);
  switch (subcommand) {
    case 'status': return validateGitStatus(subArgs, context);
    case 'diff': return validateGitDiffLike('diff', subArgs, context);
    case 'show': return validateGitDiffLike('show', subArgs, context);
    case 'log': return validateGitDiffLike('log', subArgs, context);
    case 'rev-parse': return validateGitRevParse(subArgs, context);
    case 'cat-file': return validateGitCatFile(subArgs, context);
    case 'ls-files': return validateGitLsFiles(subArgs, context);
    case 'branch': return validateGitBranch(subArgs, context);
    default: return unsupported(context, 'git_subcommand_not_allowlisted', `git subcommand ${subcommand} is not in the read-only allowlist`);
  }
}

const VALIDATORS = new Map([
  ['pwd', validatePwd],
  ['ls', validateLs],
  ['stat', validateStat],
  ['wc', validateWc],
  ['head', (args, context) => validateHeadTail('head', args, context)],
  ['tail', (args, context) => validateHeadTail('tail', args, context)],
  ['cat', validateCat],
  ['grep', (args, context) => parseGrepLike('grep', args, context, 'grep')],
  ['rg', (args, context) => parseGrepLike('rg', args, context, 'rg')],
  ['sed', validateSed],
  ['find', validateFind],
  ['shasum', (args, context) => validateChecksum('shasum', args, context)],
  ['cksum', (args, context) => validateChecksum('cksum', args, context)],
  ['git', validateGit],
]);

export function evaluateCommand({ command, cwd, root, unknownDecision = 'deny', trustedBinDirs }) {
  const parsed = tokenizeSimpleCommand(command);
  if (parsed.decision === 'deny') return parsed;
  const pathContext = createPathContext(cwd, root);
  if (pathContext.decision === 'deny') return pathContext;
  const context = {
    cwd: pathContext.cwd,
    root: pathContext.root,
    unknownDecision: unknownDecision === 'ask' ? 'ask' : 'deny',
    trustedBinDirs,
  };

  const [programToken, ...args] = parsed.tokens;
  const invalidProgram = assertSafeProgram(programToken.value);
  if (invalidProgram) return invalidProgram;
  const validator = VALIDATORS.get(programToken.value);
  if (!validator) return unsupported(context, 'program_not_allowlisted', `program ${programToken.value} is not in the read-only allowlist`);
  const evaluated = validator(args, context);
  if (evaluated.decision === 'allow') {
    const resolvedProgram = resolveTrustedProgram(programToken.value, trustedBinDirs);
    if (!resolvedProgram) return hardDeny('trusted_executable_not_found', `no trusted executable found for ${programToken.value}`);
    const argv = [...evaluated.argv];
    argv[0] = resolvedProgram;
    return {
      ...evaluated,
      argv,
      canonicalCommand: renderCanonicalCommand(argv, evaluated.environmentAssignments ?? []),
      originalCommand: command,
      cwd: context.cwd,
      root: context.root,
    };
  }
  return evaluated;
}

export function evaluateHookInput(input, env = process.env) {
  const tool = input?.tool_name ?? input?.toolName ?? '';
  const hookEventName = input?.hook_event_name ?? input?.hookEventName ?? 'PreToolUse';
  const toolInput = input?.tool_input ?? input?.input ?? {};
  const command = toolInput?.command;
  const cwd = input?.cwd;
  if (tool !== 'Bash') {
    return hardDeny('unexpected_tool', `hook only evaluates Bash, received ${String(tool)}`, { hookEventName, toolInput });
  }
  const evaluated = evaluateCommand({
    command,
    cwd,
    root: env.ZCODE_READONLY_BASH_ROOT || undefined,
    unknownDecision: env.ZCODE_READONLY_BASH_UNKNOWN_DECISION || 'deny',
    trustedBinDirs: env.ZCODE_READONLY_BASH_TRUSTED_BIN_DIRS
      ? env.ZCODE_READONLY_BASH_TRUSTED_BIN_DIRS.split(path.delimiter).filter(Boolean)
      : undefined,
  });
  return { ...evaluated, hookEventName, toolInput };
}

export function createHookOutput(evaluated) {
  const reason = `${evaluated.policyVersion ?? POLICY_VERSION}@${(evaluated.policySha256 ?? POLICY_SHA256).slice(0, 12)} ${evaluated.code}: ${evaluated.reason}`;
  const output = {
    hookSpecificOutput: {
      hookEventName: evaluated.hookEventName ?? 'PreToolUse',
      permissionDecision: evaluated.decision,
      permissionDecisionReason: reason,
    },
  };
  if (evaluated.decision === 'allow' && evaluated.canonicalCommand) {
    output.hookSpecificOutput.updatedInput = {
      ...(evaluated.toolInput ?? {}),
      command: evaluated.canonicalCommand,
    };
  }
  return output;
}

export function policyMetadata() {
  return {
    version: POLICY_VERSION,
    sha256: POLICY_SHA256,
    descriptor: POLICY_DESCRIPTOR,
  };
}
