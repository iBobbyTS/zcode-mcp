import json
import tempfile
import unittest
from pathlib import Path

from conformance import (FakeRuntime, LaunchBudgetExceeded, LaunchLedger,
                         PublicV2Client, REQUIRED_TOOLS, collect_artifact,
                         finalize_pack, normalize, redact, validate_artifact_chunk)
from run_matrix import CASE_C_BUDGET, _call_case


class S02Tests(unittest.TestCase):
    def test_atomic_ledger_budget_and_retry_slots(self):
        with tempfile.TemporaryDirectory() as d:
            ledger = LaunchLedger(Path(d) / "launch-ledger.json")
            for _ in range(5):
                ledger.reserve()
            for _ in range(3):
                ledger.reserve(retry=True)
            with self.assertRaises(LaunchBudgetExceeded):
                ledger.reserve()
            self.assertEqual(json.loads(ledger.path.read_text())["count"], 8)

    def test_catalog_is_catalog_only(self):
        runtime = FakeRuntime()
        client = PublicV2Client(runtime)
        result = client.catalog()
        self.assertEqual(set(result["tools"]), REQUIRED_TOOLS)
        self.assertEqual([name for name, _ in runtime.calls], ["zcode_system_status"])

    def test_redaction_and_normalization(self):
        value = {"api_key": "secret", "path": "/Users/alice/private/x", "events": [
            {"kind": "attempt_started", "sequence": 1}, {"kind": "noise", "sequence": 2},
            {"kind": "terminal", "sequence": 3}]}
        out = normalize("A", value)
        self.assertEqual(out["api_key"], "[REDACTED]")
        self.assertEqual(len(out["events"]), 2)
        self.assertTrue(out["event_sequence_monotonic"])
        self.assertNotIn("/Users", json.dumps(out))

    def test_fake_negative_paths_do_not_use_ledger(self):
        runtime = FakeRuntime("no-progress")
        with tempfile.TemporaryDirectory() as d:
            ledger = LaunchLedger(Path(d) / "ledger.json")
            client = PublicV2Client(runtime, ledger)
            self.assertEqual(client.call("zcode_agent_wait")["status"], "timeout")
            self.assertEqual(ledger.count, 0)
        runtime = FakeRuntime("restart-loss")
        self.assertEqual(PublicV2Client(runtime).call("zcode_agent_get")["error_class"], "SERVICE_GENERATION_MISMATCH")

    def test_pack_finalizer_is_atomic_and_excludes_junk(self):
        with tempfile.TemporaryDirectory() as d:
            source, destination = Path(d) / "pack", Path(d) / "pack.zip"
            source.mkdir()
            for name in ("SUMMARY.md", "SYSTEM-IDENTITY.md", "SCENARIO-MATRIX.md", "PERMISSION-MATRIX.md",
                         "PROGRESS-TIMELINE.md", "EVENT-METRICS.md", "RESULT-ARTIFACT-MATRIX.md",
                         "RESTART-CLEANUP.md", "KNOWN-GAPS.md"):
                (source / name).write_text("redacted\n")
            (source / ".DS_Store").write_bytes(b"junk")
            _, digest = finalize_pack(source, destination)
            self.assertEqual(len(digest), 64)
            import zipfile
            with zipfile.ZipFile(destination) as zf:
                self.assertNotIn(".DS_Store", zf.namelist())

    def test_artifact_chunk_rejects_bad_ranges(self):
        import base64
        chunk = {"artifact_id": "a", "sha256": "h", "data": base64.b64encode(b"x").decode(),
                 "returned_bytes": 1, "offset": 0, "next_offset": 1}
        self.assertEqual(validate_artifact_chunk(chunk, artifact_id="a", sha256="h", size=1, offset=0, limit=1), b"x")
        with self.assertRaisesRegex(ValueError, "INVALID_ARTIFACT_RANGE"):
            validate_artifact_chunk(chunk, artifact_id="a", sha256="h", size=1, offset=0, limit=0)

    def test_fake_case_c_continuation_and_full_artifact_reconstruction(self):
        runtime = FakeRuntime("case-c")
        client = PublicV2Client(runtime, LaunchLedger(Path(tempfile.mkdtemp()) / "ledger.json"))
        manifest = json.loads((Path(__file__).parents[1] / "case-03-agent-control-lifecycle/fixture-manifest.json").read_text())
        with tempfile.TemporaryDirectory() as d:
            evidence = _call_case(client, Path(__file__).parents[1] / "case-03-agent-control-lifecycle", manifest, Path(d))
        self.assertEqual(evidence["spawn"]["effective_budget"], CASE_C_BUDGET)
        self.assertEqual(evidence["continuation"]["agent_id"], evidence["spawn"]["agent_id"])
        self.assertEqual(evidence["continuation"]["review_id"], evidence["spawn"]["review_id"])
        self.assertFalse(evidence["continuation"]["counts_as_independent"])
        self.assertNotEqual(evidence["continuation"]["provenance"]["zcode_session_id"], evidence["spawn"]["provenance"]["zcode_session_id"])
        self.assertTrue(all(item["reconstructed"] for item in evidence["artifact_chunks"]))
        self.assertTrue(evidence["permissions"])
        self.assertEqual(evidence["permissions"][0]["response"]["effective_decision"], "deny")
        self.assertEqual(evidence["close"]["task"]["phase"], "CLOSED")
        self.assertEqual(evidence["close_replay"]["task"]["phase"], "CLOSED")

    def test_pack_rejects_arbitrary_root_filename_and_free_text_secret(self):
        with tempfile.TemporaryDirectory() as d:
            source = Path(d) / "pack"
            source.mkdir()
            for name in ("SUMMARY.md", "SYSTEM-IDENTITY.md", "SCENARIO-MATRIX.md", "PERMISSION-MATRIX.md",
                         "PROGRESS-TIMELINE.md", "EVENT-METRICS.md", "RESULT-ARTIFACT-MATRIX.md",
                         "RESTART-CLEANUP.md", "KNOWN-GAPS.md"):
                (source / name).write_text("redacted\n")
            normalized = source / "normalized"
            normalized.mkdir()
            (normalized / "arbitrary.txt").write_text("safe\n")
            with self.assertRaisesRegex(ValueError, "unexpected pack filename"):
                finalize_pack(source, Path(d) / "pack.zip")
            (normalized / "arbitrary.txt").unlink()
            (normalized / "case-a.json").write_text("token leaked-value\n")
            with self.assertRaisesRegex(ValueError, "unredacted secret"):
                finalize_pack(source, Path(d) / "pack.zip")

    def test_fatal_case_error_propagates_and_freezes_matrix(self):
        class FailingRuntime(FakeRuntime):
            def call(self, tool, args):
                if tool == "zcode_agent_events":
                    return {"isError": True, "error": {"code": "PROTOCOL", "message": "fatal"}}
                return super().call(tool, args)
        runtime = FailingRuntime()
        client = PublicV2Client(runtime, LaunchLedger(Path(tempfile.mkdtemp()) / "ledger.json"))
        manifest = json.loads((Path(__file__).parents[1] / "case-01-user-fuzzy-search/fixture-manifest.json").read_text())
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(Exception):
                _call_case(client, Path(__file__).parents[1] / "case-01-user-fuzzy-search", manifest, Path(d))
            self.assertTrue((Path(d) / "case-01-user-fuzzy-search.json").is_file())


if __name__ == "__main__":
    unittest.main()
