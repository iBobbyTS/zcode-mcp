---
name: zcode-review-workflow
description: "Run and diagnose the repository's official ZCode structured-review experiments, including external daemon/socket startup fallback and evidence capture."
---

# ZCode Review Workflow

Use this skill for the repository's read-only ZCode structured-review experiments.
It covers the corrected historical fixture harness and the small fake-runtime harness;
it does not authorize product-code changes, oracle access, a second reviewer, or
permission-policy broadening.

## Run Contract

Run cases sequentially with the public V2 structured-review path. Complex source
fixtures live under `tests/live-agent/git-based/` and are local/ignored. Never run
against those source directories directly. The tracked harness materializes every
case into a fresh directory beneath `tests/live-agent/workspace/` before reset,
verification, review, or evidence collection. Preserve the raw JSON-RPC transcript,
daemon log, SQLite store, normalized state, result, artifact chunks/hash, and close evidence there.
Use the harness's wait-first polling and respond to every typed pending request
immediately after the `pending_request` event. Do not treat an empty pending file
as evidence unless the corresponding public `get` call succeeded.

Run the committed small-scale tests from the repository root:

```bash
PYTHONPATH=tests/live-agent/non-git-based \
python3 -m unittest discover -s tests/live-agent/non-git-based -p 'test_*.py'
```

Run the complex official matrix only when the local Git-based fixtures are installed:

```bash
python3 tests/live-agent/non-git-based/run_matrix.py --official
```

The harness creates `tests/live-agent/workspace/official-runtime-conformance-*`
and copies all three cases there. An explicit `--output` or `--ledger` must also
resolve beneath `tests/live-agent/workspace/`. The canonical redacted audit pack
may still be finalized at its separately authorized external destination.

Before each copied historical case, run its `scripts/reset.sh` and `scripts/verify.sh`.
Use one fresh review per case, a 15-minute wall budget, and at most one fixed
bounded nudge. Never start ZCode through a generic/legacy spawn path.

## Socket Startup Fallback

The normal harness starts `zcode-reviewd` with an isolated socket and database.
If it reports `TimeoutError: daemon socket did not appear`, preserve the run root,
daemon log, SQLite files, exact command, PID, return code, and timestamp. This is
an infrastructure observation, not proof of a product defect.

When the harness cannot start the daemon reliably from its child process, rerun
the *same* isolated command in an external terminal so the process owns a visible
interactive session. Use the exact preserved execution directory under
`tests/live-agent/workspace/`; do not reuse a socket or database from another run:

```bash
RUN_ROOT=/Users/ibobby/Projects/zcode-mcp/tests/live-agent/workspace/<preserved-run-root>
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
