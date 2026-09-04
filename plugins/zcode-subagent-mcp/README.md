# ZCode Subagent MCP hooks

This plugin provides the local generic ZCode Subagent MCP facade and its
fail-closed Bash and file policy hooks. The daemon remains the lifecycle and
durable owner; the hooks only enforce tool permissions and write metadata-only
audit records.

## Layout

```text
.codex-plugin/plugin.json
.mcp.json
hooks/hooks.json
hooks/check-bash-readonly.mjs
hooks/check-agent-files.mjs
hooks/audit-bash-result.mjs
lib/bash-policy.mjs
lib/agent-file-policy.mjs
policy-corpus.json
scripts/install-agent-hooks.mjs
scripts/check-agent-hooks.mjs
scripts/preflight-agent-hooks.mjs
test/
```

## Verification

Node.js 20 or later is required. No npm dependencies are needed.

```bash
npm run verify
```

For an isolated config, use the three repo-local scripts in order:

```bash
node scripts/install-agent-hooks.mjs --config /absolute/config.json \
  --provenance /absolute/zcode-agent-hook-provenance.json
node scripts/preflight-agent-hooks.mjs --config /absolute/config.json \
  --provenance /absolute/zcode-agent-hook-provenance.json
node scripts/check-agent-hooks.mjs --config /absolute/config.json \
  --provenance /absolute/zcode-agent-hook-provenance.json
```

The installer is idempotent and preserves unrelated hook matchers. It refuses
to replace an unknown managed Bash or file hook. Preflight invokes a safe read,
denies a destructive canary, and records the installed artifact identity.
`ZCODE_AGENT_HOOK_PROVENANCE` is the only provenance path consumed by the
daemon. Export the installer's `service_generation` result as
`ZCODE_AGENT_SERVICE_GENERATION` for the daemon. A missing, stale, tampered,
or generation-mismatched record prevents daemon startup.

## Security contract

The Bash policy allows only a closed set of simple read-only commands with
canonical path confinement. Shell composition, writes, executable wrappers,
secrets, Git mutations, path traversal, symlink escape, and ambiguous options
are denied. The file policy requires `ZCODE_AGENT_POLICY=1`, a canonical
`ZCODE_AGENT_WORKTREE_ROOT`, and a frozen `ZCODE_AGENT_WRITE_MANIFEST` for
mutations. Bootstrap roots are explicit read-only inputs.

The policy never trusts the caller's `PATH`, command arguments are bounded, and
the PostToolUse hooks persist only hashes, bounded argv metadata, status and
duration. They never persist raw commands, tool output, credentials, cwd or
reasoning content.

## Environment

- `ZCODE_AGENT_BASH_ROOT` optionally pins the Bash read root.
- `ZCODE_AGENT_BASH_TRUSTED_BIN_DIRS` optionally sets trusted executable dirs.
- `ZCODE_AGENT_BASH_UNKNOWN_DECISION=ask` enables an interactive fallback only
  for unsupported but non-dangerous commands; hard denials remain denied.
- `ZCODE_PLUGIN_DATA` enables metadata-only Bash audit output.

The MCP server uses `ZCODE_AGENTD_SOCKET`; the daemon uses
`ZCODE_AGENTD_STORE` and `ZCODE_AGENTD_SOCKET` as documented in `docs/setup.md`.
