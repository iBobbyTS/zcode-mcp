# Integration Guide

The hook's `activation_generation` identifies its installed/preflighted artifact;
the daemon independently creates a fresh opaque `service_generation` on every
restart. Do not export `ZCODE_REVIEW_SERVICE_GENERATION` from the hook
provenance record.

## Option A — Install as a local ZCode plugin

The repository root is already a valid plugin:

```text
.zcode-plugin/plugin.json
hooks/hooks.json
hooks/check-bash-readonly.mjs
lib/readonly-bash-policy.mjs
```

Add the directory as a local plugin source, install it, and enable it. The standard `hooks/hooks.json` path is discovered automatically.

After installation:

1. Open **Settings → Hooks**.
2. Confirm a `PreToolUse` process hook with matcher `Bash`.
3. Start a new session.
4. Ask ZCode to execute:
   ```text
   git status --short
   rg -n 'TODO|FIXME' src
   ```
5. Confirm both run without a permission prompt.
6. Ask it to execute `find . -delete`; confirm the hook denies it.

## Option B — Replace the existing user-level script

Copy the generated standalone file:

```bash
mkdir -p ~/.zcode/hooks
cp single-file/check-bash-status.mjs ~/.zcode/hooks/check-bash-status.mjs
node --check ~/.zcode/hooks/check-bash-status.mjs
```

Merge [`../examples/user-config.fragment.json`](../examples/user-config.fragment.json) into `~/.zcode/cli/config.json`. Do not overwrite unrelated user configuration.

The important shape is:

```json
{
  "hooks": {
    "enabled": true,
    "events": {
      "PreToolUse": [
        {
          "matcher": "Bash",
          "hooks": [
            {
              "type": "process",
              "command": "node",
              "args": ["/absolute/path/to/check-bash-status.mjs"],
              "timeoutMs": 5000
            }
          ]
        }
      ]
    }
  }
}
```

Start a new session after any hook/config change.

## Root selection

By default, the hook uses the input `cwd` as the only readable root. This is the recommended behavior when the daemon starts ZCode directly in its prepared disposable review worktree.

To pin a broader parent root:

```bash
export ZCODE_READONLY_BASH_ROOT=/absolute/canonical/review/root
```

The hook denies the tool if `cwd` is outside that root.

Do not set the root to the user's home directory or `/`.

## Trusted executables

The hook does not use caller `PATH`. It searches this default ordered set:

```text
/usr/bin
/bin
/usr/sbin
/sbin
/opt/homebrew/bin
/usr/local/bin
```

Override only when necessary:

```bash
export ZCODE_READONLY_BASH_TRUSTED_BIN_DIRS=/usr/bin:/bin:/opt/homebrew/bin
```

Every allowed command is rewritten with the resolved absolute executable path.

## Unknown commands

Default:

```text
unsupported → deny
```

Interactive fallback:

```bash
export ZCODE_READONLY_BASH_UNKNOWN_DECISION=ask
```

Hard-denied syntax, paths, and options remain denied.

For unattended review jobs, keep the default `deny`.

## Metadata-only audit

The default plugin manifest registers `PostToolUse` and `PostToolUseFailure`
for Bash. When ZCode supplies `ZCODE_PLUGIN_DATA`, the hook appends bounded
metadata to:

```text
$ZCODE_PLUGIN_DATA/readonly-bash-audit.jsonl
```

It records hashes, canonical argv, exit status, duration-related hook fields when available, and observed output digests. It does not persist full stdout/stderr, the raw command, or the plaintext cwd.

## Integration with ZCode Subagent MCP

Recommended split:

```text
Bash hook:
  autonomous, narrowly read-only repository inspection

private daemon-owned run_check(command_id):
  tests, builds, Docker, repository scripts, and other executable validation
```

The review packet/control prompt should tell ZCode:

- a denied Bash operation is final for that operation;
- do not retry an equivalent denied command;
- use available static evidence;
- record unavailable validation as an evidence gap;
- finalize the review rather than looping on denied tools.

The MCP/daemon records daemon policy identity separately from expected and
effective installed-hook identity. Effective hook version/hash are populated
only after the install/check/preflight path has verified the actual artifact;
otherwise provenance is explicitly `REVIEW_BASH_POLICY_UNVERIFIED` and does not
emit a combined digest.

## Rollback

Before replacing a user script/config:

```bash
cp ~/.zcode/hooks/check-bash-status.mjs ~/.zcode/hooks/check-bash-status.mjs.before-readonly-v1
cp ~/.zcode/cli/config.json ~/.zcode/cli/config.json.before-readonly-v1
```

Rollback by restoring both files and starting a new session.
