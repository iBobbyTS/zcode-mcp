# Security Report

## Boundary and ownership

This is a local, single-user control plane. It does not claim protection from a
hostile process running as the same UID, a multi-tenant boundary, or a remote
network service. There is one daemon (`zcode-reviewd`), one durable writer
(`review-store`), and one actual runtime/stdio owner (`zcode-driver`). The MCP
facade and sectioned shadow adapter own no durable lifecycle state.

No supervisor shim, grant file, HMAC/challenge authority, second journal, live
session reconnect, credential service, or true live-steering mechanism exists
in the accepted product tree.

## Input and filesystem controls

- Public spawn accepts one absolute manifest path that must be a regular,
  non-symlink file, valid UTF-8 JSON, and at most 128 KiB.
- The daemon revalidates the typed manifest, immutable base/head commits,
  canonical paths, source cleanliness, forbidden prior-review artifacts, and
  policy constraints. Facade parsing is not authoritative.
- Reviews run in disposable detached worktrees. Scratch/report roots are
  confined, source integrity is rechecked, symlink targets are evaluated by
  operation type, and cleanup records bind to repository/job/head roots.
- Credential-oriented paths and commands are rejected. Report/ledger input
  rejects hidden-reasoning and secret-bearing markers.
- Network isolation capability is reported truthfully; the Darwin execution
  does not claim OS-enforced network isolation or a general sandbox.

## Process and transport controls

- `zcode-driver` creates and owns an isolated process group and validates
  PID/PGID/UID/start identity before signalling. Normal stop performs bounded
  TERM/KILL escalation and verifies descendant-group death.
- Restart cleanup fails closed when identity is absent, ambiguous, reused, or
  otherwise unverifiable. Unknown processes are not signalled.
- The private daemon socket is local Unix IPC, published only after startup
  reconciliation. Database-keyed singleton locking prevents two durable owners.
- Private RPC frames are capped at 128 KiB and connections use bounded total
  deadlines. The public facade has a six-second total daemon call timeout.
- Public MCP stdout is reserved for valid rmcp framing; daemon/facade
  operational output does not share the public protocol stream.

## Public data minimization

The ten public tools omit workspace paths, runtime Agent IDs, owner epochs,
initial prompts, raw failure messages, raw permission/input payloads, raw
correlation IDs, PID/PGID/start identity, environment, credentials, and private
orchestration flags. Events expose only bounded type/sequence/redaction level.
Pending requests expose a sanitized target/command summary and policy preview;
unsupported user input is non-respondable.

Report result calls re-open and hash the actual bytes. They distinguish valid,
missing, replaced, binary, invalid, and legacy-unverified artifacts instead of
trusting stale database metadata. Partial and final reports remain bounded in
the public projection.

Public error text is stable, bounded, and redacted for validation, daemon
unavailability, version mismatch, timeout, oversized frame, not found,
conflict, runtime loss, and protocol failure. Tests inject private paths, PIDs,
and sentinel secret text and assert they do not cross the projection.

## Permission semantics

External permission decisions are not authoritative over local policy. A caller
allow may become an effective deny; `zcode_review_respond` returns requested and
effective decisions, `policy_overrode`, and a bounded reason code. Duplicate
responses return the persisted effective decision. Unsupported user input is
never fabricated into a permission response.

The example Codex configuration defaults tools to `prompt`, auto-approves only
the five read-only projection tools, and keeps spawn/message/respond/stop/close
at `prompt`. The exact ten-tool allowlist prevents accidental exposure of
private enqueue/start/reap/review-tool or low-level ZCode operations.

## Durable recovery and destructive behavior

Stop and close are marked destructive in the MCP tool annotations. Stop
cancels but preserves durable history. Close may stop and reap runtime
resources, while retaining history and artifacts. Repeated operations converge
through persisted idempotency rather than a second facade-owned state source.

SQLite uses WAL and transactional mutations. Store migration preserves
accepted old rows and rejects newer unknown schema versions. Report publication
is atomic; an unrenderable oversized candidate rolls its database transaction
back.

## Residual risks

- Official ZCode 3.8.1 behavior was verified locally. Compatibility remains
  hash/version-specific and does not imply future runtime compatibility.
- Same-UID tampering, workstation compromise, and malicious replacement of
  configured binaries are outside the supported threat model.
- Darwin network isolation is capability reporting, not enforcement.
- Linux behavior was not executed; Windows is unsupported.
- A runtime crash cannot resume the original live session; partial evidence is
  retained and runtime loss is classified.
- The repository has a top-level MIT license, but Cargo package license metadata
  and a complete dependency license report remain outstanding.
