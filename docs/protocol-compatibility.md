# Runtime Protocol Compatibility

## Private daemon/facade compatibility

The generic facade and daemon use fail-closed private RPC version 12. A facade
or daemon with a different private version is rejected before method dispatch;
there is no version negotiation or mixed-version fallback.

This private version is not the public MCP protocol version. One facade process
exposes the fixed nine-tool generic catalog; there is no catalog selector or
legacy RPC surface.

## Evidence boundary

Compatibility evidence is about the locally installed official runtime only.
Fake app-server tests in later sections are kept separate and never imply real
runtime compatibility. The runtime is never downloaded or modified by this
project.

## Compatibility checks

Runtime protocol shapes and cleanup behavior are exercised through the Driver
and daemon test suites. There is no separate production preflight executable;
the generic `zcode_subagent_status` tool reports bounded daemon status without
starting an additional ZCode runtime.

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

Production session bootstrap does not require this diagnostic. The pinned
3.8.1 create-without-readState gate succeeded, including the three-false
`session/requestRuntimePreferences` response and complete process-group reap,
so the core path begins with `session/create`.

For `session/create`, session provenance is only
`result.session.sessionId`. `result.projection.sessionId` is an independent
projection identifier and is ignored even when it differs or is malformed; it
is never a fallback. The requested runtime model is only
`result.settings.model.current.modelId`; optional
`result.session.model.modelId` is consistency-only and must normalize equal
when present. Direct/top-level legacy alternates, missing or malformed
authoritative session data, consistency-only model fallback, and conflicting
model values fail closed.

Current and available model IDs are accepted only from the typed protocol
projections described above. The deterministic implementation and tests are
Rust-only.
