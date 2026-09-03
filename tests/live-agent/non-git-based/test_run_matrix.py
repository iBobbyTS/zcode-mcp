from __future__ import annotations

import unittest

from run_matrix import source_integrity_unchanged


class SourceIntegrityTests(unittest.TestCase):
    def test_ignores_untracked_runtime_artifacts(self) -> None:
        before = {
            "head": "a" * 40,
            "tracked_diff": "",
            "staged_diff": "",
            "status": "",
        }
        after = dict(before, status="?? .agent-work/artifacts/manifest.json")

        self.assertTrue(source_integrity_unchanged(before, after))

    def test_rejects_head_tracked_or_staged_changes(self) -> None:
        baseline = {
            "head": "a" * 40,
            "tracked_diff": "",
            "staged_diff": "",
            "status": "",
        }

        for field, value in (
            ("head", "b" * 40),
            ("tracked_diff", "tracked"),
            ("staged_diff", "staged"),
        ):
            with self.subTest(field=field):
                self.assertFalse(
                    source_integrity_unchanged(baseline, dict(baseline, **{field: value}))
                )


if __name__ == "__main__":
    unittest.main()
