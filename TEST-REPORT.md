# Test Report

## Evidence identity

- Product/test head: `e2fc9b0d9010a7652b6022cfa220764af8ae5c62`
- Date: 2026-08-24
- Host: macOS 26.5.1 (Darwin 25.5.0, arm64)
- Rust: `rustc 1.97.1 (8bab26f4f 2026-07-14)`
- Cargo: `cargo 1.97.1 (c980f4866 2026-06-30)`
- Runtime environment: official ZCode 3.8.1 entry supplied explicitly for the
  real-runtime matrix

## Exact final gates

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | PASS |
| `cargo check --workspace --all-targets` | PASS |
| `cargo clippy --workspace --all-targets -- -D warnings` | PASS |
| `cargo test --workspace --all-targets` | PASS, 155 tests, 0 failed |
| official `runtime-preflight` | PASS, strict NDJSON `workspace/readState` tested |

The workspace run exercised every target once at the exact product/test head.
The long `review-ledger` aggregate overflow test completed successfully; no
test was ignored.

## Required process and integrity evidence

The same full workspace run included these named fixtures:

- Daemon process smoke:
  `daemon_auto_claims_is_single_instance_reconnects_and_handles_sigterm` and
  `signal_before_daemon_start_exits_without_socket_runtime_or_durable_activation`.
- Private RPC/session smoke:
  `real_fake_session_delivers_responses_fifo_interrupt_and_distinct_close`,
  `concurrent_transport_stop_close_reap_kills_driver_owned_group`, and the
  complete internal fake review orchestration tests.
- Public MCP process smoke:
  `stdio_is_clean_and_modern_and_legacy_clients_discover_exact_tools` and
  `public_stdio_submit_returns_before_claim_and_survives_facade_restart`.
- Manifest/worktree integrity: all 13 `review-preparation` tests, including
  immutable refs, dirty source rejection, path confinement, symlink behavior,
  bounded diagnostics, policy precedence, and recoverable cleanup.
- Report integrity: all 10 `review-ledger` tests plus the public process flow,
  covering partial publication, atomic rendering, replacement/missing/binary
  classification, expected/observed SHA-256 and byte counts, and finalization.
- Shadow process: one official-rmcp child-process fixture and ten adapter tests,
  including fresh-session/provenance classification, separate artifacts,
  unsupported evidence, calibration, and schema parity.
- Consumer patch: the checked-in patch applied to the exact pre-S08 backup;
  `cmp` against the installed consumer passed and both outputs hashed to
  `8c324dd3846a711c6adf96b05a528c1269b05dc51a43d59b5fa7e926d7f0f7f8`.

## Coverage summary

The 155-test workspace gate includes three environment-gated official-runtime
fixtures, which skip successfully when the explicit path is absent. The same
fixtures were separately executed against the official runtime. That targeted
matrix proved nested workspace state,
runtime-preferences response, create/subscribe/send, stop and later send,
offered-option permission denial, unsupported input, queue delivery,
session-level ledger MCP, partial/final report integrity, and process-group
reap. The final workspace count is recorded after the exact-head gate.

The executed fake-runtime and official-runtime paths cover spawn and group reap,
request/response correlation, session create/subscribe/send/stop, message FIFO,
interrupt-and-continue, permission hard-deny override, unsupported user input,
durable lifecycle/recovery, continuous report publication, and public MCP
projection.

## Exact-head rule

The final behavioral checks cover the compatibility-delta product/test head.
Any later product or test change requires bounded closure of that changed range.
