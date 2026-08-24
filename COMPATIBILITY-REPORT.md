# Compatibility Report

## Official runtime status

Status: `UNVERIFIED_NOT_AVAILABLE`.

`ZCODE_RUNTIME_PATH` was unset. No unambiguous official executable was present
in `PATH`, `/Applications`, or `/Users/ibobby/Applications`. No runtime was
downloaded, extracted from a community project, vendored, patched, decompiled,
or redistributed. The exact preflight result was:

```json
{"compatibility_status":"untested","reason":"ZCODE_RUNTIME_PATH is unset"}
```

Fake-runtime acceptance is mergeability evidence for this repository's typed
seam; it is not real-runtime compatibility evidence.

## Pinned seam

The typed request/event seam follows the observed research reference
`jpalmae/zcode-acp@42fe149d4b501469343c01f23ba3801832306d53`:
strict non-JSON-RPC envelopes, integer/string wire IDs, camelCase session
parameters, `workspace/readState`, `session/create`, `session/subscribe`,
`session/send`, `session/stop`, the supported close path, `session/event`
lifecycle events, and `interaction/requestPermission` responses.

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
| Official local ZCode runtime | unverified, unavailable |
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
`sha2 0.10.9`. This repository currently has no top-level license and its local
Cargo packages have no `license` metadata. A distribution/release decision must
add project licensing and perform a complete dependency license audit; S09 does
not infer one from build success.

## Real-runtime smoke matrix

When an explicit official `ZCODE_RUNTIME_PATH` becomes available, execute and
record separately: identity/hash and app-server start; workspace state;
session create/subscribe/send; queue; interrupt-and-continue; permission allow
and local hard-deny; unsupported input classification; ledger MCP injection;
partial/final report integrity; stop; close; and process-group reap. A
contradiction in any required core operation is a hard stop, not a documented
compatibility exception.
