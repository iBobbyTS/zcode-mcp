# Setup

## Build

Requirements are Rust 1.97 or compatible, Cargo, Git, and macOS or a compatible
Unix host. Build the local binaries without installing a runtime:

```text
cargo build --release -p zcode-reviewd -p zcode-review-mcp -p sectioned-shadow
```

The project never downloads ZCode. Set `ZCODE_RUNTIME_PATH` only to an explicit
official local app-server executable or supported JavaScript entry point.

## Start the daemon

Choose private absolute paths. Keep the database and socket out of the reviewed
repository:

```text
export ZCODE_REVIEWD_DATABASE=/absolute/private/zcode-review.sqlite3
export ZCODE_REVIEWD_SOCKET=/absolute/private/zcode-reviewd.sock
export ZCODE_RUNTIME_PATH=/absolute/official/zcode-runtime
./target/release/zcode-reviewd
```

`--database`, `--socket`, and `--runtime` are equivalent explicit CLI options.
The daemon runs in the foreground, handles SIGINT/SIGTERM, owns the claim loop,
and must be running before the facade is useful. Only one daemon may own a
canonical database. The socket is not published until migration and startup
reconciliation finish. Production runtime bootstrap uses the verified 90-second
window; public submission remains asynchronous and returns after durable enqueue
rather than waiting for that window. Synchronous message, interrupt, stop, and
close controls each use one five-second internal budget, leaving one second for
the facade's six-second daemon-call deadline and response framing. Core session
bootstrap starts with `session/create`; `workspace/readState` is an optional
`runtime-preflight` model-catalog diagnostic and is not a production prerequisite.

If the runtime is unavailable, omit `ZCODE_RUNTIME_PATH` only for facade/store
inspection and deterministic fake-runtime development. Official ZCode 3.8.1 is
verified only for entry SHA-256 `9318f60f...e4274`.

## Configure Codex

Choose exactly one startup-static public catalog per facade process:

- `config/codex-zcode-review-mcp.toml` keeps the standalone-default
  `legacy_review_v1` catalog with its exact ten existing tools.
- `config/codex-zcode-subagent-mcp-v2.toml` selects `subagent_v2` explicitly
  and permits exactly the fourteen high-level system, Agent, and review tools.

Copy the values, not the file paths, into `~/.codex/config.toml` and replace the
absolute placeholders. Both modes use the same stateless binary and may point
at the same daemon/Store. A process never mixes catalogs. Empty, unknown, or
combined `ZCODE_PUBLIC_API_MODE` values fail startup.

The configuration allows exactly the accepted ten tools, gives the MCP process
10 seconds to initialize and each call 10 seconds, and keeps mutating or
destructive operations prompt-gated. Restart Codex after editing its config,
then confirm the tool inventory before submitting a manifest.

The repo-local plugin under `plugins/zcode-subagent-mcp-v2` is an alternative
V2 entry point. It expects `zcode-review-mcp` on `PATH`, forwards the existing
`ZCODE_REVIEWD_SOCKET`, and pins `ZCODE_PUBLIC_API_MODE=subagent_v2`. It is not
installed automatically and does not start or own the daemon.

Before spawning work in V2, call `zcode_system_ensure_ready` with a bounded
timeout. `ready=false` is an evidence-bearing result: start or repair the
configured runtime rather than treating facade discovery as runtime readiness.

V2 general and structured-review inputs are supplied directly as strict tool
arguments. Repository/base/head identities are immutable commit inputs;
continuations need only the stable `agent_id`/`review_id`, new base/head,
frozen finding IDs, idempotency key, optional attachments, and optional budget.
The daemon reconstructs parent-owned scope and immutable context.

## Submit

Create a manifest that validates against `schemas/review-manifest.schema.json`.
Its repository, plan/context/scope, immutable base/head commits, scratch/report
roots, model, network policy, and idempotency key must describe one review. Call
`zcode_review_spawn` with only:

```json
{"manifest_path":"/absolute/path/review-manifest.json"}
```

Spawn performs bounded preparation and durable enqueue, then returns before
runtime/session bootstrap. Keep the returned `agent_id`; every later public
operation uses it.
