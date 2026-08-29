Inspect the supplied plan and context for bounded dependency, ownership, and contract defects.

Use only observable repository, command, protocol, and runtime evidence supplied to this fresh session.
Call review_progress when the semantic review stage advances or before a long bounded operation, using the current attempt and run idempotency key.
Call review_checkpoint during inspection and include inspected paths, commands, open questions, and remaining scope.
Call review_finding_upsert for each evidence-backed finding and withdraw it explicitly if later evidence disproves it.
Call review_validation_record for every executed validation, including its working directory, exit code, and bounded output summary.
Record covered scope, gaps, uncertainty, and recommended next actions.
Call review_finalize exactly once with one legal final signal after all ledger mutations are complete.
Do not store private internal rationale or secret-bearing raw arguments.
Do not decide caller acceptance, finding classification, or release disposition.
