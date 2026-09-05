# Release gates

Run from the integrated feature head:

```bash
cargo test --workspace -q
npm test
npm pack --dry-run
python tests/live-agent/non-git-based/run_matrix.py --help
git diff --check
```

For the macOS release payload, run `sh scripts/release/check-native-tarball.sh`
and `sh scripts/release/test-installed-tarball.sh`. The latter installs the
generated tarball into a fresh prefix and HOME, then checks the installed CLI,
daemon path, and LaunchAgent plist. A daemon process also requires the existing
plugin hook provenance and `ZCODE_AGENT_SERVICE_GENERATION`; missing or stale
provenance must remain a fail-closed result.

The pack must exclude `.DS_Store`, `__MACOSX`, `__pycache__`, `.agent-work`,
raw sessions/reasoning, build output, and caches. Native daemon/runtime payload
presence is checked separately; when unavailable, record `EVIDENCE_GAP` and do
not claim a real installation or model run.

The 50-call ledger is `.agent-work/audit/zcode-as-subagent-productization/TRACE.jsonl`.
Each `real_model_call` records `event_id`, `scenario_id`, `phase`, requested
and observed model, start/end timestamps, outcome, counted flag, and
`attempt_id`. Reservation is atomic and fail-closed at 50; successful,
failed, timed-out, and cancelled model calls count once, while dispatch
infrastructure failures before model invocation do not. Verify 49→50→51,
concurrent reservation, and retry-after-failure cases without invoking a real
model during local tests.

## Out-of-scope matrix

| Constraint | Evidence oracle |
| --- | --- |
| No migration/old aliases | catalog grep and CLI command rejection |
| No auto-download/upgrade | installer source and isolated HOME |
| No provider/credential management | public command/schema catalog |
| No remote daemon/multi-tenant/second supervisor | command surface and process fixture |
| No Windows daemon/GUI/Rosetta | Windows isolated HOME unsupported matrix |
| No Git/worktree/base_ref/access_mode | public schema and live runner grep |
