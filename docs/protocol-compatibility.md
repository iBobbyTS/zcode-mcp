# Runtime Protocol Compatibility

## Evidence boundary

Compatibility evidence is about the locally installed official runtime only.
Fake app-server tests in later sections are kept separate and never imply real
runtime compatibility. The runtime is never downloaded or modified by this
project.

## Preflight command

```text
cargo run -p runtime-preflight
```

The command reads `ZCODE_RUNTIME_PATH` only. It emits JSON with a redacted
redacted path token, byte size, SHA-256, Node version, and an app-server probe result.
Authentication tokens and provider secrets are not read or emitted.

## Pinned 3.8.1 event and request shapes

This tracked section is the source for the deterministic fake. The evidence
snapshot is content-addressed as follows:

- Official ZCode 3.8.1 runtime SHA-256:
  `9318f60fb8c2c3bc83ce62da10220ebcdc9a99786df0a9abb1a4435ba66e4274`.
- Event inventory SHA-256:
  `3bfb920a01630830bbfb59491da8abd6225177db50f6ec087a03bb479ab04dc7`.
- Request-shape locator `zcode-3.8.1-black-box-request-shapes/v1`, SHA-256:
  `aaff1addb4d95f9b9ff443519da2c3f9cccbab264ebb9cf2c40c4aec003651b1`.
- Response-shape locator `zcode-3.8.1-black-box-response-shapes/v1`, SHA-256:
  `99df5e616bfb10e562861f7b5a00e45bf2197c352bb01dd568d4f356dc34f5ba`.

The ignored files under `.agent-work/probes/zcode-3.8.1/` are local supporting
evidence for this checkout, not source material available in a fresh clone.
The stable locators, hashes, and observed shapes recorded here are the tracked
compatibility source.

The observed event inventory includes `state.updated`, `session.titleUpdated`,
`session.updated`, `turn.started`, `model.streaming`, `tool.updated`,
`permission.requested`, `permission.resolved`, `streamRecovery.updated`,
`turn.completed`, and `v4/telemetry/event`. No separate permission
acknowledgement event is synthesized or classified as known. Permission
decisions return the exact response object from the selected option offered by
`interaction/requestPermission`, whose observed parameter keys are `input`,
`options`, `reason`, `requestId`, `riskLevel`, `sessionId`, `toolCallId`,
`toolName`, and `turnId`. Completion is established by the terminal turn
lifecycle. Events without typed product semantics continue through the bounded,
redacted `raw.unknown` path.

Observed client request parameters are:

- `workspace/readState`: exactly `workspace`, containing exactly string
  `workspaceKey` and `workspacePath`.
- `session/create`: `workspace` with the same nested shape, plus the observed
  optional `mcpServers` variant whose entries contain exactly `name`, `command`,
  `args`, and `env`.
- `session/subscribe`: exactly `sessionId`, `deliveryKind`, and
  `includeSnapshot`.
- `session/send`: exactly `sessionId` and `content`.
- `session/stop`: exactly `sessionId`.

The fake rejects unobserved extra keys, including `afterSeq`, `inputId`, and
`queryId`.

When the variable is absent, or the path is not a regular file, the result is
`compatibility_status: "untested"` with a reason. This is an explicit evidence
gap, not a compatibility claim.

When a regular file is supplied, the probe starts `node <runtime> app-server`,
sends the current strict-NDJSON nested-workspace `workspace/readState` request,
and records only
observed response method/event names. It uses a bounded timeout and classifies
startup, malformed output, timeout, and non-zero exit as `failed` or
`incompatible`; payloads are never persisted. A successful exchange is marked
`tested` only when a valid JSON response is observed.

`runtime_version` is `unknown` unless the runtime itself exposes a version in a
future explicit probe. Current and available model IDs are emitted only when
the workspace response exposes them. The record includes Node `node_version`
for provenance. The implementation and tests are Rust-only.
