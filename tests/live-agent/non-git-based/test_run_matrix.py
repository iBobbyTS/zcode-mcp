from __future__ import annotations

import unittest

from conformance import ConformanceError
from run_matrix import (
    EVIDENCE_SCHEMA,
    source_integrity_unchanged,
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
                self.assertFalse(source_integrity_unchanged(before, after, "read_only"))

    def test_read_only_rejects_tracked_or_staged_diff_after_run(self) -> None:
        for field in ("tracked_diff", "staged_diff"):
            with self.subTest(field=field):
                after = dict(self.clean, **{field: "dirty"})
                self.assertFalse(source_integrity_unchanged(self.clean, after, "read_only"))

    def test_read_only_accepts_clean_identity_with_untracked_diagnostics(self) -> None:
        after = dict(self.clean, status="?? .agent-work/artifacts/manifest.json")

        self.assertTrue(source_integrity_unchanged(self.clean, after, "read_only"))

    def test_workspace_write_preserves_before_after_change_semantics(self) -> None:
        dirty = dict(self.clean, tracked_diff="existing change")

        self.assertTrue(source_integrity_unchanged(dirty, dict(dirty), "workspace_write"))
        self.assertFalse(
            source_integrity_unchanged(dirty, dict(dirty, tracked_diff="new change"), "workspace_write")
        )


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


if __name__ == "__main__":
    unittest.main()
