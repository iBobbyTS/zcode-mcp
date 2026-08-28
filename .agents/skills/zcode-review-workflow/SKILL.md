---
name: zcode-review-workflow
description: "Run and diagnose the repository's official ZCode structured-review experiments, including external daemon/socket startup fallback and evidence capture."
---

# ZCode Review Workflow

Use this skill for the repository's read-only ZCode structured-review experiments.
It covers the corrected historical fixture harness and the tiny diagnostic harness;
it does not authorize product-code changes, oracle access, a second reviewer, or
permission-policy broadening.

## Run Contract

Run cases sequentially with the public V2 structured-review path. Keep each run in
a fresh `/private/tmp` root and preserve the raw JSON-RPC transcript, daemon log,
SQLite store, normalized state, result, artifact chunks/hash, and close evidence.
Use the harness's wait-first polling and respond to every typed pending request
immediately after the `pending_request` event. Do not treat an empty pending file
as evidence unless the corresponding public `get` call succeeded.

Typical commands from the repository root:

```bash
SUITE=/Users/ibobby/Projects/zcode-mcp-agent-live-test-workspace
RUN_ROOT=$(mktemp -d /private/tmp/zcode-historical-fixed.XXXXXX)
python3 "$SUITE/audit/run_historical.py" "$RUN_ROOT"
```

For the smallest diagnostic first:

```bash
RUN_ROOT=$(mktemp -d /private/tmp/zcode-harness-tiny.XXXXXX)
python3 /Users/ibobby/Projects/zcode-mcp-agent-live-test-workspace/audit/live_harness.py --out "$RUN_ROOT"
```

Before each historical case, run its `scripts/reset.sh` and `scripts/verify.sh`.
Use one fresh review per case, a 15-minute wall budget, and at most one fixed
bounded nudge. Never start ZCode through a generic/legacy spawn path.

## Socket Startup Fallback

The normal harness starts `zcode-reviewd` with an isolated socket and database.
If it reports `TimeoutError: daemon socket did not appear`, preserve the run root,
daemon log, SQLite files, exact command, PID, return code, and timestamp. This is
an infrastructure observation, not proof of a product defect.

When the harness cannot start the daemon reliably from its child process, rerun
the *same* isolated command in an external terminal so the process owns a visible
interactive session. Do not reuse a socket or database from another run:

```bash
RUN_ROOT=/private/tmp/<preserved-run-root>
SOCKET="$RUN_ROOT/socket-external/d.sock"
DATABASE="$RUN_ROOT/external.sqlite3"
mkdir -p "$RUN_ROOT/socket-external"
ZCODE_REVIEWD_SOCKET="$SOCKET" \
ZCODE_REVIEWD_DATABASE="$DATABASE" \
ZCODE_RUNTIME_PATH="/Applications/ZCode.app/Contents/Resources/glm/zcode.cjs" \
/Users/ibobby/Projects/zcode-mcp/target/release/zcode-reviewd \
  >"$RUN_ROOT/external-daemon.log" 2>&1
```

In a second external terminal, verify startup before invoking the MCP facade:

```bash
test -S "$SOCKET" && echo socket_exists=yes || echo socket_exists=no
pgrep -fl zcode-reviewd
tail -100 "$RUN_ROOT/external-daemon.log"
```

Record `socket_exists`, process liveness, daemon return code, and the exact
startup error. If the process exits before publishing the socket, classify the
attempt as startup evidence (`UNKNOWN_INSUFFICIENT_EVIDENCE` until the log gives
a more specific cause) and do not silently fall back to another runtime.

## Evidence Rules

Parse public MCP responses from `result.structuredContent`; use text only as a
fallback. Distinguish meaningful progress from event-cursor movement: phase,
new semantic pending work, pending resolution, ledger revisions/counts, report
revision, finalization, and terminal result. A public `FAILED` result after a
successful `review_finalize` may be the review evidence gate (for example missing
validation), so inspect the store and terminal event before assigning blame to
MCP or ZCode runtime.
