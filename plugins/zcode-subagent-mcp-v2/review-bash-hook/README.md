# ZCode Read-Only Bash Guard

A fail-closed `PreToolUse` hook for ZCode review sessions. It automatically allows a deliberately small set of read-only inspection commands and denies shell composition, writes, execution hooks, out-of-workspace paths, and secret-like files.

The package provides two deployment forms:

- **Plugin form:** install this directory as a local ZCode plugin. ZCode auto-discovers `hooks/hooks.json`.
- **Single-file form:** copy [`single-file/check-bash-status.mjs`](single-file/check-bash-status.mjs) over an existing user-level hook.

## Why this replaces the old hook

The prior regex-based hook could allow commands such as `find . -delete`, `git branch -D`, `git diff --output=...`, and `git log & touch ...`, while rejecting useful read-only commands such as `rg` and bounded `sed`. This implementation instead uses:

```text
limited shell tokenizer
→ command-specific argv grammar
→ canonical path confinement
→ secret-path checks
→ canonical command rewrite
```

Allowed commands are rewritten before execution. Git commands receive a fixed safety prefix that disables optional locks, system/global configuration, fsmonitor, the untracked cache, pagers, external diff helpers, and text conversion where applicable.

## Quick verification

```bash
cd /path/to/zcode-readonly-bash-hook
npm run verify
```

No npm dependencies are required. Node.js 20 or later is required.

The latest executed validation record is available at [`VALIDATION.md`](VALIDATION.md).

## Plugin installation

The authoritative install surface is the parent `zcode-subagent-mcp-v2` plugin. Its
manifest points at `hooks/hooks.json`, which activates this package's guard and
metadata audit. For an isolated config (recommended for tests or a new host):

```bash
node ../scripts/install-review-hook.mjs --config /absolute/config.json \
  --provenance /absolute/review-bash-hook-provenance.json
node ../scripts/preflight-review-hook.mjs --config /absolute/config.json \
  --provenance /absolute/review-bash-hook-provenance.json
node ../scripts/check-review-hook.mjs --config /absolute/config.json \
  --provenance /absolute/review-bash-hook-provenance.json
```

Installation and checking are separate and idempotent. The installer replaces
only a recognized review hook (the historical `review-bash-hook:<event>` marker,
the legacy `check-bash-status.mjs` wrapper, or this package's current wrapper)
and preserves unrelated matchers. If an event contains an unknown `Bash`
matcher, installation fails closed without writing the configuration; merge that
hook explicitly before retrying. The installed entry is deliberately
description-free because ZCode 0.16.5 accepts only one `Bash` matcher per event
and rejects the `description` field.
Preflight starts a fresh isolated session-shaped hook invocation, allows a safe
read, denies a destructive canary, and verifies the canary file is unchanged.
The resulting provenance file is the only source accepted as an effective hook
identity by the daemon.

Start the daemon with both the verified file and its generation bound to the
current service process:

```bash
export ZCODE_REVIEW_HOOK_PROVENANCE=/absolute/review-bash-hook-provenance.json
```

The daemon creates a fresh opaque `service_generation` for every process
lifetime. Do not derive it from `activation_generation`: the latter identifies
the installed/preflighted hook artifact and remains independent of daemon
restart identity. A disabled config entry, an older/tampered artifact, or a
config that no longer references the hook remains unverified and structured
review startup fails closed with `REVIEW_BASH_POLICY_UNVERIFIED`.

When installing through the plugin UI:

1. Add the parent directory as a local plugin source and enable it.
2. Confirm the `Bash` `PreToolUse` hook appears in **Settings → Hooks**.
3. Start a **new Sol session**. Hook configuration is snapshotted at session start.
4. Do not leave an older user-level Bash hook enabled at the same time unless its behavior is intentional. Hook decisions aggregate, and a deny from either hook wins.

## Single-file replacement

```bash
cp single-file/check-bash-status.mjs ~/.zcode/hooks/check-bash-status.mjs
node --check ~/.zcode/hooks/check-bash-status.mjs
```

Keep the existing user config entry that runs Node with this absolute file path. A ready-to-merge fragment is provided at [`examples/user-config.fragment.json`](examples/user-config.fragment.json).

## Defaults

| Setting | Default |
|---|---|
| Review root | Hook `cwd` |
| Unknown program/option | `deny` |
| Shell composition | always `deny` |
| Absolute/tilde/out-of-root paths | always `deny` |
| Secret-like paths | always `deny` |
| Tests/builds/arbitrary executables | never auto-allowed |

Environment variables:

- `ZCODE_READONLY_BASH_ROOT`: optional fixed root. The hook `cwd` must be inside it.
- `ZCODE_READONLY_BASH_TRUSTED_BIN_DIRS`: optional POSIX path-delimited trusted executable directories. The hook never searches caller `PATH`; default directories cover system, Homebrew, and `/usr/local` binaries.
- `ZCODE_READONLY_BASH_UNKNOWN_DECISION=ask`: ask instead of deny for an unsupported but not intrinsically dangerous command. Hard-deny findings remain denied.
- `ZCODE_PLUGIN_DATA`: when supplied by ZCode, the default PostToolUse hooks append metadata-only records to `readonly-bash-audit.jsonl` below this directory.

## Supported command families

```text
pwd
ls
stat
wc
head
tail
cat
grep
rg
sed -n <numeric print range>
find <confined roots> <closed predicate grammar>
shasum
cksum
git status/log/diff/show/rev-parse/cat-file/ls-files/branch
```

The exact option grammar is documented in [`docs/POLICY.md`](docs/POLICY.md).

## Boundary

This hook is a permission classifier, not an operating-system sandbox. It should be combined with:

- a disposable read-only review worktree;
- ZCode/MCP write-path policy;
- daemon-owned named checks for tests, builds, Docker, or repository scripts;
- bounded output, time, and process cleanup.

Do **not** broaden this hook to auto-allow test/build commands. Those execute repository code and belong in the named-command path.
