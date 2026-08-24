# Sectioned shadow integration

`sectioned-shadow` is an optional, non-authoritative consumer of the ten public
`zcode-review-mcp` tools. It starts the existing stateless facade through the
official Rust MCP SDK and never opens the review database or owns runtime,
session, report, or lifecycle state.

## Evidence boundary

A full plan or code shadow run is independent evidence only when submission is
`created`, the daemon reports a fresh nonempty ZCode session ID, and the
finalized report passes its public integrity projection. A compatible duplicate,
missing session, unsupported input, runtime failure, or incomplete report is
`evidence_incomplete`. `REPAIR_DELTA` and resumed invocations are consultation
only and never count as a fresh clean review.

The manifest plan/context inputs are rejected when they include prior GPT or GLM
RAW, ADMISSION, review conclusion, or session-transcript artifacts. The adapter
does not decide whether a finding is admitted and does not alter Clean A/Clean B,
repair caps, recovery, section sequencing, or acceptance state.

## Artifacts

Each shadow round keeps these separate names:

- `*-GPT-RAW.md`
- `*-GPT-ADMISSION.md`
- `*-GLM-RAW.md`
- `*-GLM-PROVENANCE.json`
- `*-GLM-ADMISSION.md`

The adapter writes only GLM RAW and provenance. It reads the complete confined
report target named by the validated manifest and accepts it only when its bytes
match the public result SHA-256 and size; the public preview is never presented
as a complete RAW artifact. Main Codex remains the sole writer of GLM admission
decisions. The calibration projection is descriptive;
it records unique/duplicate and admitted/rejected/deferred findings,
unsupported-evidence and runtime-failure rates, report-schema compliance, wall
time, and checkpoint count.

## Invocation

Create a manifest using `schemas/review-manifest.schema.json` and a config based
on `config/sectioned-shadow.example.json`, then run:

```text
ZCODE_REVIEW_MCP_PATH=/absolute/path/zcode-review-mcp \
ZCODE_REVIEWD_SOCKET=/absolute/path/zcode-reviewd.sock \
sectioned-shadow /absolute/path/shadow-config.json
```

The daemon must already be running. The process prints only the bounded
provenance JSON to stdout; operational failures go to stderr through the normal
Rust process error path. Shadow rollout is optional and never a required gate.
