# S02 Resume Handoff

## Base and scope

- Resumed from accepted product projection head `3c1b456`.
- Product crates and S01 fixtures/reset logic remain untouched.
- Bounded repair scope is `live-tests/conformance.py`, `live-tests/run_matrix.py`,
  and `live-tests/test_s02.py`; no daemon, ZCode, or official runtime was
  started or called.

## Public V2 conformance closure

- The stdio client uses the public MCP JSON-RPC `initialize`, `tools/list`, and
  `tools/call` path and reads `structuredContent` when present.
- Catalog evidence preserves duplicate tool names and only reports exact when
  all 14 required names are present once, with no unexpected names.
- Lifecycle polling is wait-first and bounded by the effective wall budget,
  capped at 1800 seconds; no 30-second lifecycle constant remains.
- Typed pending permission fields are required and responded immediately;
  Case C also exercises idempotent queue-message replay.
- Public progress validation consumes only `stage`, `summary`, `counters`,
  `last_progress_at`, `semantic_idle_ms`, and `nudge_sent`; private/legacy
  aliases are rejected. Event sequences are checked per attempt and terminal
  result/review evidence is required before artifact reads.
- Artifacts are reconstructed completely, sampled at first/middle/tail offsets,
  checked against authoritative SHA-256/size metadata, and invalid zero,
  over-limit, and EOF offsets must return stable public validation errors.
- Close is checked for `CLOSED` plus `resources_reaped`, replay is idempotent,
  and post-close agent/system reads are retained as restart/cleanup evidence.

## Safety and accounting

- Fatal MCP/protocol/semantic errors freeze later cases. Only identical
  transport/observation failures can use one retry slot.
- Launch reservations are persisted with per-process tokens. A successful
  public response commits its reservation; an unobservable transport/MCP error
  rolls back only that token, avoiding cross-worker counter corruption.
- Normal-HOME identity records hashes/provenance only; no HOME/config mutation
  or credential bytes are copied.
- Pack finalization rejects empty rendered reports, unsafe/symlink/cache/secret
  content, arbitrary filenames, and publishes only after temporary archive
  verification. Tracked fixture manifests are included as redacted evidence.

## Verification

- `python3 -m unittest discover -s live-tests -v`: 15 passed.
- `python3 -m py_compile live-tests/*.py`: passed.
- `git diff --check`: passed.
- `codegraph sync`: passed.
