# Compatibility Report

## Official runtime status

Status: `VERIFIED_ZCODE_3_8_1_GLM_5_3`.

The signed official `/Applications/ZCode.app` is version 3.8.1, bundle
`dev.zcode.app`, Team ID `8A5X4JJ39T`. Its embedded app-server entry SHA-256 is
`9318f60fb8c2c3bc83ce62da10220ebcdc9a99786df0a9abb1a4435ba66e4274`.
No runtime was downloaded, copied, patched, decompiled, or redistributed.

```json
{"compatibility_status":"tested","observed_methods":["workspace/readState"]}
```

The product-owner matrix observed a real `sess_*` session using GLM-5.3, queue
delivery, stop/later-send interruption behavior, offered-option policy
responses, unsupported input, ledger checkpoints/validation/finalization,
valid final report bytes/hash, and process-group reap.

The prior compatibility product/test head was
`9c5276e8acbece92dc9f8272a426de767b504466`. The audit-remediation product/test head H is
`1b5cf12834ce1b9b74e77e853b8ba90d7572fc99`; its S03 exact-head official matrix
and final bounded evidence are recorded in the remediation handoff/review ledger. Its fresh real
`interrupt_and_continue` oracle passed in 192.92 seconds and distinguished a
real stop-current-turn boundary from natural completion by observing an active
turn immediately before the call and one exact stop-boundary increment before
the next active turn. The later S03 repair preserved this contract and passed the exact official matrix at H.

## Pinned seam

The typed request/event seam follows the observed research reference
`jpalmae/zcode-acp@42fe149d4b501469343c01f23ba3801832306d53`:
strict non-JSON-RPC envelopes, integer/string wire IDs, camelCase session
parameters, optional diagnostic `workspace/readState`, `session/create`,
`session/subscribe`, `session/send`, `session/stop`, the supported close path,
`session/event` lifecycle events, and `interaction/requestPermission` responses.

The bounded official 3.8.1 gate proved that `session/create` succeeds without a
preceding read-state call, so production bootstrap no longer makes that unused
diagnostic a hard prerequisite. Runtime preflight now consumes the same
Driver/protocol request, strict-NDJSON, and process cleanup owner. Session
provenance accepts only `result.session.sessionId`; the independently observed
`result.projection.sessionId` is ignored and never used as a fallback. Model
provenance accepts only `result.settings.model.current.modelId`, with
`result.session.model.modelId` as optional equal-only consistency evidence.
Malformed authoritative values, conflicts, and unobserved direct/top-level
fallbacks fail closed.

`interaction/requestUserInput` is retained as an unsupported, non-respondable
pending request. It causes shadow evidence to be incomplete. The implementation
does not invent a response method. `live_steer=false` and `resume=false` remain
truthful.

## MCP compatibility

The public facade uses exact `rmcp = 3.1.4` and `rmcp-macros = 3.1.4` rather
than a hand-written public transport. Initialization and tool discovery pass
for protocol versions `2026-07-28` and `2024-11-05`. Structured content and
generated output schemas are supplied for all ten tools; concise text content
is retained for legacy clients through rmcp's response handling.

The exact Codex config in `config/codex-zcode-review-mcp.toml` uses a local
stdio command, an exact ten-tool allowlist, bounded startup/tool timeouts, and
per-tool approval modes. Its field names were checked against the official
OpenAI Codex configuration reference at
`https://developers.openai.com/codex/config-reference/` and local
`codex-cli 0.145.0`.

## Store and private RPC compatibility

- Store schema: v4.
- Migration evidence: accepted v1 job/event/artifact/message/request rows are
  preserved; accepted v3 jobs reopen with empty v4 review tables.
- Forward boundary: a database with `user_version > 4` is rejected.
- Private RPC: v5, local Unix socket only, maximum frame 128 KiB.
- Public facade timeout: six seconds total per daemon RPC; public wait itself is
  capped at five seconds.
- Facade restart: supported; a new facade process addresses the same daemon job
  by `agent_id`.
- Daemon restart: live session reconnect is not supported; startup recovery
  retains partial evidence and classifies runtime loss/orphaning explicitly.

## Platform status

| Environment | Status |
|---|---|
| macOS 26.5.1 arm64, fake runtime | verified |
| Official ZCode 3.8.1 / GLM-5.3 | verified |
| Linux | unverified in this execution |
| Windows named pipes | unsupported |
| Remote/public daemon endpoint | unsupported |

## References and licenses

`REFERENCES.lock` pins seven research-only repositories at exact commits.
`docs/reference-license-matrix.md` records that no source files were copied and
that license files were not fetched. Those references therefore do not supply
the official runtime and do not create a redistribution claim.

`Cargo.lock` pins the resolved Rust dependency graph, including `rmcp 3.1.4`,
`rmcp-macros 3.1.4`, `rusqlite 0.32.1`, `tokio 1.53.1`, `serde 1.0.229`, and
`sha2 0.10.9`. The repository has a top-level MIT `LICENSE` (SHA-256
`896a6f2cea528ff8046c268b290f90d47907ecbaff081f4d140b104f7d17917b`).
All ten local Cargo packages inherit `license = "MIT"`; `docs/dependency-licenses.md` records the exact Cargo.lock-derived 189-package declared-license inventory, including eight legacy slash expressions retained raw and normalized with deprecation notes.

## Real-runtime smoke matrix

The executed matrix covered identity/hash and app-server start; nested workspace
state; create with the three-false runtime-preference response; subscribe/send;
queue; stop and later send; permission offered-option allow plus local hard
deny; unsupported input; ledger MCP; partial/final report integrity; optional
close; and process-group reap. GLM-5.3 was temporarily added to the existing
authenticated provider catalog without reading or copying credentials. The
original config SHA-256 was restored to
`400b4836a700ca8eca974d3cb45dc06dbfd692058d34320543cb75d06882ffdf`.
