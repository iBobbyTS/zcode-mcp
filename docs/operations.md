# Operations

## Normal lifecycle

1. Start `zcode-reviewd` with absolute database/socket/runtime paths.
2. Start Codex or `zcode-review-mcp` with the same socket path.
3. Submit one validated manifest and retain its `agent_id`.
4. Poll with `status`, `wait`, or ordered `events` pages.
5. Inspect sanitized pending requests. Respond only when `respondable=true`.
6. Queue a next-turn message or use `interrupt_and_continue` to stop the current
   turn before sending the next instruction.
7. Read partial/final reports through `result`; verify `integrity=valid`.
8. Use `stop` to cancel while preserving resources/history, then `close` when
   runtime resources should be reaped.

`wait` accepts 1-5000 ms and a no-change timeout succeeds with
`timed_out=true`. Event/list limits are 1-100. Result previews are 0-8192
bytes. For complete evidence use the confined report artifact and verify its
returned expected/observed SHA-256 and byte count; the preview is not the full
report.

## Public states

Job states are `QUEUED`, `STARTING`, `RUNNING`, `STOPPING`, `COMPLETED`,
`CANCELLED`, `FAILED`, `FAILED_RUNTIME_LOST`, `ORPHANED`, and `CLOSED`. Turn
states are `IDLE`, `ACTIVE`, and `FAILED`. Process spawn alone does not make a
job `RUNNING`; a real session and initial turn must be established.

Message dispositions are `queued`, `delivered`,
`interrupted_then_delivered`, `already_delivered`, and `failed`. Reuse the same
`message_id` only for the exact same intent; different content conflicts.
Permission dispositions are `responded`, `already_responded`, and `in_flight`.
Always inspect `effective_decision`, because local policy may override allow to
deny.

## Monitoring and errors

Use `zcode_review_list` with `scope=active` for active work; the Store performs
the active filter before applying the limit. `recent` and `all` are bounded
views, not ownership scans. Ordered event cursors use `after_sequence` and must
not be replaced with a private runtime identifier.

Public error classes are redacted and stable: validation, daemon unavailable,
protocol version mismatch, timeout, oversized frame, not found, conflict,
runtime lost, and protocol failure. Inspect daemon stderr and durable events for
operator diagnostics; never expect raw private failure text on public MCP.

The facade may be restarted freely. A replacement process with the same socket
can access the existing job by `agent_id`. Do not run two daemons against the
same database. If the daemon exits, follow `docs/recovery.md`.

## Shadow operation

Shadow is optional and non-authoritative. Start the daemon, set
`ZCODE_REVIEW_MCP_PATH` and `ZCODE_REVIEWD_SOCKET`, then run
`sectioned-shadow /absolute/path/shadow-config.json`. A counted full review
requires a created Agent, a fresh nonempty session, exact provenance, a valid
final report, supported evidence, and successful reap. Duplicate/resumed runs
cannot count as new independent evidence; DELTA is consultation only.

Keep GPT and GLM RAW/admission/provenance artifacts separate. Main Codex alone
admits findings and controls Clean counts, repair caps, recovery, sequencing,
and acceptance.
