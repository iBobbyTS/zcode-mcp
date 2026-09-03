from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from pretool_probe import (
    WRITE_CHECK_ID,
    WRITE_CONTENT,
    WRITE_FILE,
    make_read_fixture,
    scan_pretool_diagnostic,
    validate_read_evidence,
    validate_write_evidence,
    write_catalog,
    write_prompt,
)


class PreToolProbeContractTests(unittest.TestCase):
    def test_write_prompt_and_required_check_share_exact_content(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            repository = Path(raw)
            command = write_catalog(repository)["commands"][0]["command"]

        self.assertIn(WRITE_CONTENT, write_prompt())
        self.assertEqual(command["args"], ["-Fx", WRITE_CONTENT, WRITE_FILE])
        self.assertTrue(WRITE_CONTENT.endswith("."))

    def test_read_fixture_tracks_relative_symlink_to_benign_outside_file(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repository, _ = make_read_fixture(root)
            link = repository / "outside-link.txt"

            self.assertTrue(link.is_symlink())
            self.assertFalse(link.resolve().is_relative_to(repository.resolve()))
            self.assertEqual(link.read_text(encoding="utf-8"), "benign symlink escape fixture\n")

    def test_write_oracle_requires_success_check_applicable_patch_and_reap(self) -> None:
        valid = {
            "outcome": "SUCCEEDED", "phase": "TERMINAL", "changed_files": [WRITE_FILE],
            "checks": [WRITE_CHECK_ID],
            "artifacts": [{"kind": "changes_patch", "verified": True, "applicable": True}],
            "resources_reaped": True, "daemon_reaped": True,
        }
        validate_write_evidence(valid)
        for field in ("resources_reaped", "daemon_reaped"):
            with self.subTest(field=field):
                with self.assertRaises(RuntimeError):
                    validate_write_evidence(dict(valid, **{field: False}))

    def test_read_oracle_requires_scheduled_read_typed_deny_and_reap(self) -> None:
        valid = {
            "activity": {"max_read_calls_60s": 1},
            "permissions": [{"tool_name": "Read", "effective_decision": "deny"}],
            "resources_reaped": True, "daemon_reaped": True,
        }
        validate_read_evidence(valid)
        with self.assertRaisesRegex(RuntimeError, "did not schedule"):
            validate_read_evidence(dict(valid, activity={"max_read_calls_60s": 0}))

    def test_read_oracle_accepts_redacted_hook_diagnostic(self) -> None:
        evidence = {
            "activity": {"max_read_calls_60s": 1}, "permissions": [],
            "pretool_diagnostic": {
                "tool_name": "Read", "event_count": 1, "decision": "deny",
                "decision_code": "symlink_escape", "raw_line_sha256": "a" * 64,
            },
            "resources_reaped": True, "daemon_reaped": True,
        }

        validate_read_evidence(evidence)

    def test_log_diagnostic_persists_only_code_count_and_hash(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            log = root / "zcode.jsonl"
            line = b'{"tool":"Read","reason":"zcode-agent-file-policy/v1.0.0: symlink_escape","input":"secret"}'
            log.write_bytes(line + b"\n")
            diagnostic = scan_pretool_diagnostic(root, 0)

        self.assertEqual(
            set(diagnostic),
            {"tool_name", "event_count", "decision", "decision_code", "raw_line_sha256"},
        )
        self.assertNotIn("secret", str(diagnostic))


if __name__ == "__main__":
    unittest.main()
