# S02 Repair Handoff

## Scope

Bounded test-only repair for the exact-head FINAL review blockers. Product
crates, public MCP schema, daemon/runtime implementation, and official calls
were not changed or exercised.

## Repairs

- Case A permission validation now checks only fields exposed by public
  `AgentRespondOutput`; input `reason` is not treated as an output field.
- Hook canary validation no longer requires non-public filesystem path fields
  in public provenance. It uses the harness-owned repository Hook candidate
  only when the public digest attests the same artifact.
- `_computed_case_conclusion` maps unknown mandatory gate statuses to
  `NOT_EXERCISED`.
- Continuation conclusion validation compares `agent_id`, `review_id`, and
  `attempt_sequence == spawn.attempt_sequence + 1`.

## Validation

```text
PYTHONPATH=live-tests python3 -m unittest test_s02  # 43 passed
python3 -m py_compile live-tests/run_matrix.py live-tests/conformance.py live-tests/test_s02.py
git diff --check
```

## Boundary

No official ZCode calls were made. The parent agent must perform the required
exact-head FINAL review after admitting this repair delta.
