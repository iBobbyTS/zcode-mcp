# Execution Report

## Release identity

- Feature: `zcode-review-mcp`
- Branch: `codex/zcode-review-mcp`
- Feature base: `73c379e04a09015c29591214eb29093da7300e10`
- Final product/test head: `e2fc9b0bc1bb9df617d808935428b206af79a3da`
- Authoritative PLAN-FULL SHA-256:
  `3d12938489faf5629bde074cd277799b1d0de9352d9e273c00d85ed6397270f8`
- S09 documentation is a later docs-only commit. Its exact Git identity is
  recorded in `.agent-work/sections/S09-HANDOFF.md` and the final audit record;
  a Git commit cannot contain its own hash.
- Readiness: `mergeable` for the accepted fake-runtime contract.
- Real official ZCode runtime: `VERIFIED_ZCODE_3_8_1_GLM_5_3`.
- Audit pack: finalized separately by the workflow orchestrator after S09
  acceptance; this report does not claim pack completion.

## Accepted section heads

| Section | Accepted head | Result |
|---|---|---|
| S00 | `d09f3e090f758efaa2d53386ce7a57cf5798953e` | runtime/reference boundary accepted |
| S01 | `e533f121b66d9600467fb9fe3c985a4b968083a3` | protocol/driver/fake runtime accepted |
| S02 | `8bd2eb532c97a87a1641c7773026b8872360d728` | durable owner/private RPC accepted |
| S03 | `6108e1fe306fde219e299cd059f78b1e50fbfa05` | session command plane accepted |
| S04 | `bb09e48ab5f75a8f6d39c8870777054a5604c225` | manifest/worktree/policy accepted |
| S05 | `9cdee589ef20f4908561290bbfe6d0ba28e101b4` | ledger/report accepted |
| S06 | `af74e67a932be707677e7405f070098454b887fd` | internal orchestration accepted |
| S07 | `20ee37c2f4c70c9acd98ba53b48aeba2199a8f14` | public MCP accepted |
| S08 | `b8da3d250732b7788c6522dc36f5b723a1eed17d` | shadow integration accepted |
| S09 compatibility delta | `e2fc9b0bc1bb9df617d808935428b206af79a3da` | official ZCode 3.8.1 candidate |

The historical S02 supervisor commits remain visible in Git as unaccepted
evidence. The accepted tree contains no `zcode-supervisor` product owner.

## Implemented system

`zcode-reviewd` is the sole daemon and durable lifecycle owner. `review-store`
is its SQLite WAL-backed source of truth. `zcode-driver` owns the actual ZCode
child process, process group, stdio, request correlation, and event stream. The
`zcode-review-mcp` process is a stateless `rmcp = 3.1.4` stdio facade over the
bounded private Unix RPC v5. The `sectioned-shadow` adapter consumes the public
facade as optional evidence and never owns admission or durable state.

The public surface contains exactly ten tools:

1. `zcode_review_spawn`
2. `zcode_review_status`
3. `zcode_review_events`
4. `zcode_review_wait`
5. `zcode_review_message`
6. `zcode_review_respond`
7. `zcode_review_stop`
8. `zcode_review_result`
9. `zcode_review_list`
10. `zcode_review_close`

Public capabilities are `queue_message=true`,
`interrupt_and_continue=true`, `permission_response=true`,
`user_input_response=false`, `live_steer=false`, `resume=false`, `stop=true`,
and `close=true`. Event pages are capped at 100, waits at 5000 ms, and report
previews at 8192 bytes.

## Exact accepted commit sequence

The command below reproduces the complete feature sequence through the final
product/test head:

```text
git log --reverse --format='%H%x09%s' \
  73c379e04a09015c29591214eb29093da7300e10..b8da3d250732b7788c6522dc36f5b723a1eed17d
```

The section-closing commits, in dependency order, are:

```text
d09f3e090f758efaa2d53386ce7a57cf5798953e docs(runtime): clarify redacted preflight path
e533f121b66d9600467fb9fe3c985a4b968083a3 fix(protocol): drain child diagnostics
8a752143eed965f7076c1bc69245360299535953 fix(reviewd): bound driver exit handoff
9f52da1f8c8169d7e3372475782a3006a0d63b21 fix(reviewd): latch sink failures and redact events
8bd2eb532c97a87a1641c7773026b8872360d728 fix(reviewd): close bounded RPC ownership gaps
6108e1fe306fde219e299cd059f78b1e50fbfa05 fix(reviewd): handle signals before daemon startup
bb09e48ab5f75a8f6d39c8870777054a5604c225 fix(review): distinguish path entry operations
9cdee589ef20f4908561290bbfe6d0ba28e101b4 fix(reporting): reject unrenderable ledger snapshots
af74e67a932be707677e7405f070098454b887fd fix(review): complete S06 internal composition
20ee37c2f4c70c9acd98ba53b48aeba2199a8f14 test(mcp): prove claimed public review flow
b8da3d250732b7788c6522dc36f5b723a1eed17d fix(shadow): require complete matching evidence
e2fc9b0bc1bb9df617d808935428b206af79a3da fix(runtime): support official ZCode 3.8.1
```

The full Git sequence, including intermediate repair commits and preserved
unaccepted historical evidence, is authoritative; no history was squashed,
rebuilt, or relabelled.

## Migration and recovery

The Store schema is version 4. Opening an accepted v1 or v3 database migrates
it transactionally while preserving accepted durable rows; a database newer
than v4 fails closed. Facade restart reconnects to the same daemon and durable
Agent by `agent_id`. Daemon restart performs startup reconciliation before
publishing its socket; live session reconnect is not promised. Active work is
retained as partial evidence and classified `FAILED_RUNTIME_LOST` or
`ORPHANED` when ownership cannot be recovered safely.

Stop and close are distinct. Stop records cancellation and stops the active
session without erasing history. Close may cancel if necessary, reaps runtime
resources, and retains durable events and artifacts. See
`docs/recovery.md` for operator procedures.

## Consumer installation

- Consumer path:
  `/Users/ibobby/.codex/skills/sectioned-feature-development/SKILL.md`
- Git-managed: no
- Installation status: `installed`
- Pre-change SHA-256:
  `d0a8d11d7daa4a1d5a65322a5371a47739aec765e59a906c7b90fbeb62d051f3`
- Installed SHA-256:
  `8c324dd3846a711c6adf96b05a528c1269b05dc51a43d59b5fa7e926d7f0f7f8`
- Deterministic patch SHA-256:
  `ef091ba16364415bdc385a0a8c97d2c610c5e76e16b9f31659181fd6713c8066`
- Recoverable backup:
  `.agent-work/consumer-backups/sectioned-feature-development-pre-S08/SKILL.md`

Patch replay against the exact backup produced bytes identical to the installed
consumer and the installed hash above. The consumer remains non-authoritative:
GPT and GLM evidence stay separate and main Codex remains the only admission
owner.

## Final composition

`unproven_composition = []` for the accepted fake-runtime scope. The exact-head
workspace suite includes the complete internal fake review, official-rmcp
public facade process flow, daemon restart/lifecycle fixtures, manifest and
worktree integrity, report hash revalidation, sectioned shadow process flow,
and deterministic consumer patch replay. A redundant integration reviewer is
therefore not required by the active workflow.

## Limitations

- Official ZCode 3.8.1 was verified through the current Driver, RuntimeOwner,
  scheduler, ledger, and report owners. The local GLM-5.3 catalog entry remains
  an operator workaround; the original config was restored byte-equivalently.
- `interaction/requestUserInput` is visible as non-respondable and becomes
  `evidence_incomplete`; no response method is invented.
- Same-turn live steering and session resume are unsupported.
- Darwin is the executed platform. Linux-specific execution is unverified.
- Network isolation and a hostile same-UID boundary are not claimed.
- The project has a top-level MIT `LICENSE`, but Cargo package license metadata
  and a complete dependency license audit are not present. Research references
  are pinned but not copied.
