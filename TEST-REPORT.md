# Test Report

## Evidence identity

- Product/test head: `b8da3d250732b7788c6522dc36f5b723a1eed17d`
- Date: 2026-08-24
- Host: macOS 26.5.1 (Darwin 25.5.0, arm64)
- Rust: `rustc 1.97.1 (8bab26f4f 2026-07-14)`
- Cargo: `cargo 1.97.1 (c980f4866 2026-06-30)`
- Runtime environment: `ZCODE_RUNTIME_PATH` absent

## Exact final gates

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | PASS |
| `cargo check --workspace --all-targets` | PASS |
| `cargo clippy --workspace --all-targets -- -D warnings` | PASS |
| `cargo test --workspace --all-targets` | PASS, 151 tests, 0 failed |
| `env -u ZCODE_RUNTIME_PATH cargo run -q -p runtime-preflight` | PASS, `compatibility_status=untested`, `reason=ZCODE_RUNTIME_PATH is unset` |

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

The 151 tests comprise: ledger 10, preparation 13, Store 16, runtime preflight
7, shadow process/adapter 11, Driver 17, fake runtime 4, protocol 11, public MCP
8, review daemon/RPC 54, for 151 total. Zero-test library/binary harnesses are
not included in the count.

The executed fake-runtime paths cover runtime spawn and process-group reap,
request/response correlation, session create/subscribe/send/stop, message FIFO,
interrupt-and-continue, permission hard-deny override, unsupported user input,
durable lifecycle/recovery, continuous report publication, and public MCP
projection. They do not establish compatibility with an unavailable official
runtime.

## Exact-head rule

The behavioral checks cover `b8da3d2` exactly. S09 changes only documentation
and configuration examples, so the active workflow permits reuse of this
evidence after the docs-only commit. Documentation consistency and CodeGraph
are checked after that commit. Any later product or test change invalidates
this reuse and requires bounded closure of that changed range.
