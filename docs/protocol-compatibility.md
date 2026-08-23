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

When the variable is absent, or the path is not a regular file, the result is
`compatibility_status: "untested"` with a reason. This is an explicit evidence
gap, not a compatibility claim.

When a regular file is supplied, the probe starts `node <runtime> app-server`,
sends the smallest read-only `workspace/readState` request, and records only
observed response method/event names. It uses a bounded timeout and classifies
startup, malformed output, timeout, and non-zero exit as `failed` or
`incompatible`; payloads are never persisted. A successful exchange is marked
`tested` only when a valid JSON response is observed.

`runtime_version` is `unknown` unless the runtime itself exposes a version in a
future explicit probe. The record includes the installed Node `node_version`
for provenance. The implementation and tests are Rust-only.
