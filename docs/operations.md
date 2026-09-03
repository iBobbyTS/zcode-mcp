# Operations

## Generic lifecycle

1. Call `zcode_agent_spawn` with `read_only` or `workspace_write`.
2. Call `zcode_agent_poll` with the returned `agent_id`, `after_revision`, and bounded `timeout_ms`.
3. Reuse `next_revision`; do not restart polling from zero.
4. Answer only daemon-published typed requests through `zcode_agent_respond`.
5. Queue clarification with `zcode_agent_send`. A terminal task cannot continue; create a new Agent.
6. Read final text, verified checks, changed files, patch, and bounded artifact chunks through `zcode_agent_result`.
7. Use `zcode_agent_cancel` for authoritative stop/kill/reap and `zcode_agent_close` for idempotent cleanup.

`zcode_agent_list` requires repository, feature, or ownership scope. Filtering occurs in the Store before the limit.

## Activity

Poll exposes bounded visible text, active tool classes, model request clocks, and rolling 60-second counts. Reasoning content, tool arguments, cwd, command output, and absolute internal paths are never public. Runtime activity is liveness evidence, not semantic progress.

Pending requests and terminal transitions wake long polls immediately. Unknown telemetry shapes degrade telemetry status without failing the Agent.

## Completion and timeouts

A matching `turn.completed` automatically finalizes only when no queued message or unresolved typed request exists. Read-only finalization verifies zero tracked/staged diff. Workspace-write finalization verifies the write manifest, executes required named checks against the final tree, and emits a detached commit and patch.

Timeout classes are `RUNTIME_ACTIVITY_IDLE_TIMEOUT`, `MODEL_STREAM_IDLE_TIMEOUT`, `TOOL_CALL_TIMEOUT`, `INPUT_WAIT_TIMEOUT`, and `WALL_TIME_DEADLINE_EXCEEDED`. Turn and tool-count exhaustion remain independent budget outcomes. Timeout and cancellation fence late events before result and artifact persistence.

`COMPLETED` means the runtime turn ended and daemon finalization succeeded. It does not mean a review is clean, a patch is correct, or the change is mergeable.
