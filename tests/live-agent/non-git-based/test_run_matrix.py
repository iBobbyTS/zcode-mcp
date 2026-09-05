from __future__ import annotations

import unittest

from conformance import ConformanceError
from run_matrix import (
    EVIDENCE_SCHEMA,
    minimal_evidence,
    source_integrity_unchanged,
    source_identity_unchanged,
    validate_evidence_identity,
)


class SourceIntegrityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clean = {
            "head": "a" * 40,
            "tracked_diff": "",
            "staged_diff": "",
            "status": "",
        }

    def test_read_only_rejects_preexisting_tracked_or_staged_diff(self) -> None:
        for field in ("tracked_diff", "staged_diff"):
            with self.subTest(field=field):
                before = dict(self.clean, **{field: "dirty"})
                after = dict(before)
                self.assertTrue(source_integrity_unchanged(before, after))

    def test_read_only_rejects_tracked_or_staged_diff_after_run(self) -> None:
        for field in ("tracked_diff", "staged_diff"):
            with self.subTest(field=field):
                after = dict(self.clean, **{field: "dirty"})
                self.assertFalse(source_integrity_unchanged(self.clean, after))

    def test_read_only_accepts_clean_identity_with_untracked_diagnostics(self) -> None:
        after = dict(self.clean, status="?? .agent-work/artifacts/manifest.json")

        self.assertTrue(source_integrity_unchanged(self.clean, after))

    def test_workspace_write_preserves_before_after_change_semantics(self) -> None:
        dirty = dict(self.clean, tracked_diff="existing change")

        self.assertTrue(source_integrity_unchanged(dirty, dict(dirty)))
        self.assertFalse(
            source_integrity_unchanged(dirty, dict(dirty, tracked_diff="new change"))
        )

    def test_workspace_write_allows_unstaged_changes_without_ref_mutation(self) -> None:
        after = dict(self.clean, tracked_diff="expected workspace edit")
        self.assertTrue(source_identity_unchanged(self.clean, after))
        self.assertFalse(source_identity_unchanged(self.clean, dict(after, staged_diff="staged")))
        self.assertFalse(source_identity_unchanged(self.clean, dict(after, head="b" * 40)))


class EvidenceIdentityTests(unittest.TestCase):
    def test_rejects_stale_pre_identity_evidence(self) -> None:
        identity = {
            "repository_head": "a" * 40,
            "runner_sha256": "b" * 64,
            "daemon_sha256": "c" * 64,
            "facade_sha256": "d" * 64,
            "runtime_sha256": "e" * 64,
        }

        with self.assertRaisesRegex(ConformanceError, "schema.*stale"):
            validate_evidence_identity({"source_unchanged": True}, identity)

        validate_evidence_identity(
            {"schema": EVIDENCE_SCHEMA, "identity": identity}, identity
        )

        with self.assertRaisesRegex(ConformanceError, "exact head"):
            validate_evidence_identity(
                {"schema": EVIDENCE_SCHEMA, "identity": dict(identity, repository_head="f" * 40)},
                identity,
            )

    def test_minimal_evidence_redacts_text_tools_paths_and_raw_diffs(self) -> None:
        output = {
            "schema": EVIDENCE_SCHEMA,
            "identity": {"repository_head": "a" * 40},
            "execution_root": "/absolute/private/path",
            "result": {
                "task": {"agent_id": "agent-secret", "phase": "TERMINAL"},
                "result": {"outcome": "SUCCEEDED", "final_text": "secret output",
                           "changed_files": [], "checks": [], "result_sha256": "b" * 64},
            },
            "closed": {"task": {"closed": True, "resources_reaped": True}},
            "activity_samples": [{"activity": {
                "latest_text_tail": "secret reasoning", "active_tools": [{"tool_call_id": "id"}],
                "window_60s": {"read_calls": 1, "other_tool_calls": 0,
                               "tool_calls_failed": 1},
            }}],
            "permission_responses": [], "artifact_verification": [],
            "source_before": {"tracked_diff": "secret diff"},
            "source_unchanged": True, "poll_start_intervals_seconds": [],
        }

        encoded = str(minimal_evidence(output))
        for forbidden in ("/absolute", "secret output", "secret reasoning", "secret diff", "tool_call_id"):
            self.assertNotIn(forbidden, encoded)


if __name__ == "__main__":
    unittest.main()
