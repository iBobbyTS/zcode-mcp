import fs from 'node:fs';
import path from 'node:path';

export const AGENT_FILE_POLICY_VERSION = 'zcode-agent-file-policy/v1.0.0';
const MAX_MANIFEST_BYTES = 64 * 1024;
const MAX_MANIFEST_ENTRIES = 256;
const MAX_BOOTSTRAP_ROOTS = 8;
const MAX_PATH_BYTES = 4096;
const WRITE_TOOLS = new Set(['Write', 'Edit', 'Delete', 'Move']);
const READ_TOOLS = new Set(['Read', 'Grep', 'Glob']);
const PATH_KEYS = new Set([
  'path', 'file_path', 'filePath', 'directory', 'directory_path', 'directoryPath',
  'source', 'source_path', 'sourcePath', 'destination', 'destination_path', 'destinationPath',
  'old_path', 'oldPath', 'new_path', 'newPath', 'from', 'to',
]);
const SECRET_NAME = /(^|[._/\\-])(\.env(?:\.|$)|credentials?(?:\.|$)|secrets?(?:\.|$)|.*(?:api[_-]?key|access[_-]?key|auth[_-]?token|password|passwd|private[_-]?key|client[_-]?secret|oauth|cookie|session)[^/\\]*$)|(^|[._-])(id_rsa|id_ed25519)(?:\.|$)|\.(?:pem|key|p12|pfx)$/iu;
const PROTECTED_PART = /^(?:\.git|\.gitmodules|\.zcode|\.codex|\.agent-work)$/u;

function deny(code) {
  return { decision: 'deny', code, reason: `${AGENT_FILE_POLICY_VERSION}: ${code}` };
}

function allow() {
  return { decision: 'allow', code: 'ok', reason: `${AGENT_FILE_POLICY_VERSION}: allowed` };
}

function envRequired(env) {
  if (env?.ZCODE_AGENT_POLICY !== '1') return deny('policy_marker_missing');
  const rawRoot = env?.ZCODE_AGENT_WORKTREE_ROOT;
  if (typeof rawRoot !== 'string' || rawRoot.length === 0 || !path.isAbsolute(rawRoot)) {
    return deny('worktree_root_missing');
  }
  let root;
  try {
    root = fs.realpathSync.native(rawRoot);
    if (!fs.statSync(root).isDirectory()) return deny('worktree_root_invalid');
  } catch {
    return deny('worktree_root_invalid');
  }
  let manifest = [];
  const rawManifest = env?.ZCODE_AGENT_WRITE_MANIFEST;
  if (typeof rawManifest !== 'string' || Buffer.byteLength(rawManifest, 'utf8') > MAX_MANIFEST_BYTES) {
    return deny('write_manifest_invalid');
  }
  try {
    const parsed = rawManifest.length === 0 ? [] : JSON.parse(rawManifest);
    if (!Array.isArray(parsed) || parsed.length > MAX_MANIFEST_ENTRIES) return deny('write_manifest_invalid');
    manifest = parsed.map((item) => {
      if (typeof item !== 'string' || item.length === 0 || Buffer.byteLength(item, 'utf8') > MAX_PATH_BYTES) {
        throw new Error('manifest path');
      }
      const candidate = path.posix.normalize(item.replaceAll('\\', '/'));
      if (path.posix.isAbsolute(candidate) || candidate === '..' || candidate.startsWith('../') || candidate.includes('\0')) {
        throw new Error('manifest traversal');
      }
      if (candidate.split('/').some((part) => PROTECTED_PART.test(part) || SECRET_NAME.test(part))) {
        throw new Error('manifest protected');
      }
      return candidate === '.' ? '' : candidate;
    });
  } catch {
    return deny('write_manifest_invalid');
  }
  let bootstrapRoots = [];
  const rawBootstrapRoots = env?.ZCODE_AGENT_BOOTSTRAP_ROOTS;
  if (rawBootstrapRoots !== undefined) {
    if (typeof rawBootstrapRoots !== 'string' || Buffer.byteLength(rawBootstrapRoots, 'utf8') > MAX_MANIFEST_BYTES) {
      return deny('bootstrap_roots_invalid');
    }
    try {
      const parsed = rawBootstrapRoots.trimStart().startsWith('[')
        ? JSON.parse(rawBootstrapRoots)
        : [rawBootstrapRoots];
      if (!Array.isArray(parsed) || parsed.length > MAX_BOOTSTRAP_ROOTS) throw new Error('bootstrap roots');
      bootstrapRoots = parsed.map((item) => {
        if (typeof item !== 'string' || !path.isAbsolute(item) || item.length > MAX_PATH_BYTES || item.includes('\0') || hasParentTraversal(item)) {
          throw new Error('bootstrap root path');
        }
        if (item.split(/[\\/]/u).some((part) => PROTECTED_PART.test(part) || SECRET_NAME.test(part))) {
          throw new Error('bootstrap protected');
        }
        try {
          if (!fs.statSync(item).isDirectory()) throw new Error('bootstrap not directory');
          return fs.realpathSync.native(item);
        } catch {
          // A missing optional bootstrap root is inert; reads under it remain denied.
          return item;
        }
      });
    } catch {
      return deny('bootstrap_roots_invalid');
    }
  }
  return { root, manifest, bootstrapRoots };
}

function collectPaths(value, key = '') {
  if (typeof value === 'string') return PATH_KEYS.has(key) ? [value] : [];
  if (!value || typeof value !== 'object') return [];
  if (Array.isArray(value)) return value.flatMap((item) => collectPaths(item, key));
  return Object.entries(value).flatMap(([childKey, child]) => collectPaths(child, childKey));
}

function hasParentTraversal(value) {
  return value.split(/[\\/]/u).some((part) => part === '..');
}

function confinedPath(root, value) {
  if (typeof value !== 'string' || value.length === 0 || Buffer.byteLength(value, 'utf8') > MAX_PATH_BYTES) {
    return false;
  }
  if (value.includes('\0') || hasParentTraversal(value)) return false;
  const canonicalCandidate = resolveCanonicalPath(root, value);
  if (!canonicalCandidate) return false;
  return canonicalCandidate === root || canonicalCandidate.startsWith(`${root}${path.sep}`);
}

function resolveCanonicalPath(root, value) {
  if (typeof value !== 'string' || value.length === 0 || Buffer.byteLength(value, 'utf8') > MAX_PATH_BYTES) {
    return null;
  }
  if (value.includes('\0') || hasParentTraversal(value)) return null;
  const candidate = path.isAbsolute(value) ? value : path.join(root, value);
  const lexical = path.normalize(candidate);
  let existing = lexical;
  const missing = [];
  while (!fs.existsSync(existing)) {
    const parent = path.dirname(existing);
    if (parent === existing) return null;
    missing.unshift(path.basename(existing));
    existing = parent;
  }
  try {
    const canonical = fs.realpathSync.native(existing);
    return missing.length > 0 ? path.join(canonical, ...missing) : canonical;
  } catch {
    return null;
  }
}

function protectedPath(root, value) {
  const relative = path.isAbsolute(value) ? path.relative(root, value) : value;
  const lexicalProtected = relative.split(/[\\/]/u).some((part) => PROTECTED_PART.test(part) || SECRET_NAME.test(part));
  if (lexicalProtected) return true;
  const canonical = resolveCanonicalPath(root, value);
  if (!canonical) return false;
  return path.relative(root, canonical)
    .split(/[\\/]/u)
    .some((part) => PROTECTED_PART.test(part) || SECRET_NAME.test(part));
}

function pathAllowedForRead(state, value) {
  // Relative paths are daemon-worktree paths.  Never reinterpret a relative
  // payload against a bootstrap root (that would turn a worktree symlink into
  // an apparently safe bootstrap path).  Bootstrap roots are absolute-only.
  if (!path.isAbsolute(value)) {
    return confinedPath(state.root, value) && !protectedPath(state.root, value);
  }
  return [state.root, ...state.bootstrapRoots].some(
    (root) => confinedPath(root, value) && !protectedPath(root, value),
  );
}

function withinManifest(root, value, manifest) {
  const candidate = path.normalize(path.isAbsolute(value) ? value : path.join(root, value));
  return manifest.some((entry) => {
    const target = path.normalize(path.join(root, entry));
    return candidate === target || candidate.startsWith(`${target}${path.sep}`);
  });
}

export function evaluateAgentFileInput(input, env = process.env) {
  const state = envRequired(env);
  if (state.decision) return state;
  const tool = input?.tool_name ?? input?.toolName ?? input?.name;
  if (typeof tool !== 'string' || (!READ_TOOLS.has(tool) && !WRITE_TOOLS.has(tool))) {
    return deny('unsupported_tool');
  }
  const toolInput = input?.tool_input ?? input?.toolInput ?? input?.input ?? {};
  const paths = collectPaths(toolInput);
  // An omitted path is valid for a search rooted at cwd, but a file mutation must name a target.
  if (WRITE_TOOLS.has(tool) && paths.length === 0) return deny('path_missing');
  const cwd = input?.cwd ?? input?.working_directory ?? input?.workingDirectory ?? state.root;
  if (!confinedPath(state.root, cwd) || protectedPath(state.root, cwd)) return deny('cwd_outside_root');
  for (const value of paths.length ? paths : [cwd]) {
    if (!pathAllowedForRead(state, value)) return deny('path_outside_root');
    if (WRITE_TOOLS.has(tool) && !withinManifest(state.root, value, state.manifest)) return deny('write_not_allowlisted');
  }
  return allow();
}

export function createAgentFileHookOutput(result) {
  return {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: result.decision,
      permissionDecisionReason: result.reason,
    },
  };
}
