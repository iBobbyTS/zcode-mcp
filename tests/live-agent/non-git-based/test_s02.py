import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from conformance import (FakeRuntime, FatalConformanceError,
                         InfrastructureConformanceError, LaunchBudgetExceeded, LaunchLedger,
                         PACK_DIRECTORIES, PACK_FILES, PublicV2Client, REQUIRED_TOOLS, collect_artifact,
                         finalize_pack, normalize, redact, validate_artifact_chunk,
                         StdioMCPTransport)
from run_matrix import (
    CASE_C_BUDGET,
    OwnedDaemon,
    _assert_case_a_canary,
    _assert_typed_permission_gate,
    _computed_case_conclusion,
    _fixture_postflight,
    _fixture_preflight,
    _overall_result,
    _assert_zcode_016_hook_config,
    _classify_readiness,
    _run_case_a_hook_canary,
    _assert_event_contract,
    _call_case,
    _poll_terminal,
    _public_events,
    main,
)
from run_matrix import REPOSITORY_ROOT, _sha256
from fixture_workspace import (
    GIT_BASED_ROOT,
    create_execution_root,
    materialize,
)


class S02Tests(unittest.TestCase):
    def materialized_case(self, name: str) -> tuple[Path, Path]:
        source = GIT_BASED_ROOT / name
        if not (source / "fixture-manifest.json").is_file():
            self.skipTest(f"local Git-based fixture is not installed: {name}")
        execution_root = create_execution_root("s02-unit-")
        self.addCleanup(shutil.rmtree, execution_root, True)
        output = execution_root / "results"
        output.mkdir()
        return materialize(source, execution_root), output

    def require_git_fixtures(self) -> None:
        missing = [
            name
            for name in (
                "case-01-user-fuzzy-search",
                "case-02-shared-group-members",
                "case-03-agent-control-lifecycle",
            )
            if not (GIT_BASED_ROOT / name / "fixture-manifest.json").is_file()
        ]
        if missing:
            self.skipTest(f"local Git-based fixtures are not installed: {', '.join(missing)}")

    def test_owned_daemon_unavailable_is_explicit_binding_gap(self):
        with tempfile.TemporaryDirectory() as d:
            daemon = OwnedDaemon(Path(d) / "missing-reviewd", Path(d) / "runtime.cjs", Path(d) / "run", 0.1)
            identity = daemon.identity()
            self.assertEqual(identity["ownership"], "unavailable")
            self.assertIsNone(identity["sha256"])
            with self.assertRaises(InfrastructureConformanceError):
                daemon.start()
            cleanup = daemon.cleanup()
            self.assertTrue(cleanup["reaped"])
            self.assertFalse(Path(d, "run").exists())

    def test_zcode_016_hook_config_assertion_is_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "config.json"
            provenance = root / "provenance.json"
            guard = root / "check-bash-readonly.mjs"
            audit = root / "audit-bash-result.mjs"
            config.write_text(json.dumps({
                "unrelated": {"keep": True},
                "hooks": {"enabled": True, "events": {
                    "PreToolUse": [
                        {"matcher": "Other", "hooks": [{"type": "process", "command": "other"}]},
                        {"matcher": "Bash", "hooks": [{"type": "process", "command": "node", "args": [str(guard)], "timeoutMs": 5000}]},
                    ],
                    "PostToolUse": [{"matcher": "Bash", "hooks": [{"type": "process", "command": "node", "args": [str(audit)], "timeoutMs": 5000}]}],
                    "PostToolUseFailure": [{"matcher": "Bash", "hooks": [{"type": "process", "command": "node", "args": [str(audit)], "timeoutMs": 5000}]}],
                }},
            }), encoding="utf-8")
            provenance.write_text(json.dumps({
                "effective_guard_wrapper_path": str(guard),
                "effective_audit_wrapper_path": str(audit),
                "effective_config_sha256": _sha256(config),
            }), encoding="utf-8")
            before = config.read_bytes()
            _assert_zcode_016_hook_config(config, provenance)
            self.assertEqual(config.read_bytes(), before)

    def test_owned_daemon_launches_private_paths_and_reaps(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "run"
            script = Path(d) / "reviewd"
            script.write_text(
                "#!/usr/bin/env python3\n"
                "import os,signal,time\n"
                "sock=os.environ['ZCODE_REVIEWD_SOCKET']\n"
                "open(sock,'wb').close()\n"
                "signal.signal(signal.SIGTERM, lambda *_: raise_system_exit())\n"
                "def raise_system_exit(): raise SystemExit(0)\n"
                "while True: time.sleep(.02)\n"
            )
            script.chmod(0o755)
            daemon = OwnedDaemon(script, Path(d) / "runtime.cjs", root, 1.0)
            daemon.start()
            self.assertTrue(daemon.socket.is_file())
            self.assertEqual(daemon.proc.poll(), None)
            daemon.observe_generation({"service_generation": "test-generation"})
            self.assertEqual(daemon.service_generation, "test-generation")
            cleanup = daemon.cleanup()
            self.assertTrue(cleanup["reaped"])
            self.assertFalse(root.exists())

    def test_owned_daemon_copies_log_before_cleanup(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(tempfile.mkdtemp(prefix="zcode-rt-"))
            daemon = OwnedDaemon(None, Path(d) / "runtime.cjs", root, 0.1)
            daemon.log_root.mkdir()
            daemon.log_path.write_text("socket=/Users/alice/private/reviewd.sock\n")
            destination = Path(d) / "redacted-logs/owned-daemon.json"
            evidence = daemon.copy_log(destination)
            self.assertTrue(evidence["present"])
            self.assertNotIn("/Users/alice", destination.read_text())
            daemon.cleanup()
            self.assertTrue(destination.is_file())
    def _valid_pack_source(self, root: Path) -> Path:
        source = root / "pack"
        source.mkdir()
        for name in PACK_FILES:
            (source / name).write_text(f"# {name}\n\nRendered evidence.\n")
        for directory in PACK_DIRECTORIES:
            (source / directory).mkdir()
        (source / "fixtures/case-a-manifest.json").write_text("{}\n")
        (source / "normalized/identity.json").write_text("{}\n")
        (source / "raw-transcripts/mcp.jsonl").write_text('{"direction":"test"}\n')
        (source / "redacted-logs/case-a.json").write_text("{}\n")
        return source

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

    def test_catalog_preserves_duplicate_names_and_fails_exactness(self):
        class DuplicateCatalog(FakeRuntime):
            def call(self, tool, args):
                value = super().call(tool, args)
                if tool == "zcode_system_status":
                    value["tools"] = sorted(REQUIRED_TOOLS) + ["zcode_agent_get"]
                return value
        result = PublicV2Client(DuplicateCatalog()).catalog()
        self.assertEqual(result["duplicate_names"], ["zcode_agent_get"])
        self.assertFalse(result["exact"])

    def test_catalog_mcp_error_is_fatal(self):
        class BrokenCatalog:
            def call(self, tool, args):
                return {"isError": True, "error": {"code": "UNAVAILABLE", "message": "offline"}}
        with self.assertRaisesRegex(Exception, "UNAVAILABLE"):
            PublicV2Client(BrokenCatalog()).catalog()

    def test_stdio_transport_uses_bounded_jsonrpc_and_closes_child(self):
        script = (
            "import sys,json; "
            "line=sys.stdin.readline(); req=json.loads(line); "
            "print(json.dumps({'jsonrpc':'2.0','id':req['id'],'result':{}}), flush=True); "
            "sys.stdin.readline()"
        )
        transport = StdioMCPTransport([sys.executable, "-u", "-c", script], timeout=0.2)
        self.assertTrue(any(item["direction"] == "response" for item in transport.transcript))
        transport.close()
        self.assertIsNotNone(transport.proc.poll())

    def test_redaction_and_normalization(self):
        value = {"api_key": "secret", "path": "/Users/alice/private/x", "events": [
            {"kind": "attempt_started", "sequence": 1}, {"kind": "noise", "sequence": 2},
            {"kind": "review_progress", "sequence": 2, "stage": "scope"},
            {"kind": "terminal", "sequence": 3}]}
        out = normalize("A", value)
        self.assertEqual(out["api_key"], "[REDACTED]")
        self.assertEqual(len(out["events"]), 3)
        self.assertTrue(out["event_sequence_monotonic"])
        self.assertFalse(out["public_projection_valid"])
        self.assertNotIn("/Users", json.dumps(out))

    def test_event_sequences_are_attempt_local_and_duplicate_pages_remain_observable(self):
        attempt_one = [
            {"sequence": 1, "attempt_sequence": 1, "event_type": "attempt_started"},
            {"sequence": 2, "attempt_sequence": 1, "event_type": "terminal"},
        ]
        attempt_two = [
            {"sequence": 1, "attempt_sequence": 2, "event_type": "attempt_started"},
            {"sequence": 2, "attempt_sequence": 2, "event_type": "terminal"},
        ]
        evidence = {
            "event_pages": [
                {"events": attempt_one + attempt_two},
                # A reread of the same page is valid and must remain in the
                # observation stream for duplicate-page evidence.
                {"events": attempt_two},
            ],
            "waits": [],
        }
        _assert_event_contract(evidence, expected_attempts={1, 2})
        self.assertEqual(len(evidence["event_pages"][1]["events"]), 2)
        self.assertEqual([event["sequence"] for event in _public_events(evidence)], [1, 2, 1, 2])

    def test_event_sequence_regression_within_one_attempt_is_rejected(self):
        evidence = {
            "event_pages": [{"events": [
                {"sequence": 1, "attempt_sequence": 1, "event_type": "attempt_started"},
                {"sequence": 3, "attempt_sequence": 1, "event_type": "review_progress"},
                {"sequence": 2, "attempt_sequence": 1, "event_type": "terminal"},
            ]}],
            "waits": [],
        }
        with self.assertRaisesRegex(Exception, "within an attempt"):
            _assert_event_contract(evidence, expected_attempts={1})

    def test_fake_negative_paths_do_not_use_ledger(self):
        runtime = FakeRuntime("no-progress")
        with tempfile.TemporaryDirectory() as d:
            ledger = LaunchLedger(Path(d) / "ledger.json")
            client = PublicV2Client(runtime, ledger)
            self.assertEqual(client.call("zcode_agent_wait")["status"], "timeout")
            self.assertEqual(ledger.count, 0)
        runtime = FakeRuntime("restart-loss")
        self.assertEqual(PublicV2Client(runtime).call("zcode_agent_get")["error_class"], "SERVICE_GENERATION_MISMATCH")

    def test_readiness_timeout_remains_infrastructure_evidence(self):
        self.assertEqual(
            _computed_case_conclusion({
                "case_id": "case-01-user-fuzzy-search",
                "error": {"class": "InfrastructureConformanceError"},
            }),
            "NOT_EXERCISED",
        )

    def test_healthy_readiness_timeout_is_inconclusive_and_has_one_probe(self):
        response = {
            "ready": False,
            "probe_result": "NOT_OBSERVED_WITHIN_TIMEOUT",
            "status": {"service_generation": "g", "components": {
                "daemon": "READY", "driver": "READY", "runtime": "READY", "model_auth": "UNKNOWN",
            }},
            "probe_reap": {"reaped": True},
        }
        classification, gaps = _classify_readiness(response, "g")
        self.assertEqual(classification, "INCONCLUSIVE_FAST_PREFLIGHT")
        self.assertEqual(len(gaps), 1)
        self.assertEqual(_overall_result({"case": "PASS"}, [], gaps), "OFFICIAL_RUNTIME_READY_WITH_GAPS")

    def test_readiness_generation_mismatch_is_hard_failure(self):
        response = {"ready": False, "probe_result": "NOT_OBSERVED_WITHIN_TIMEOUT",
                    "status": {"service_generation": "other", "components": {
                        "daemon": "READY", "driver": "READY", "runtime": "READY", "model_auth": "UNKNOWN"}}}
        classification, _ = _classify_readiness(response, "g")
        self.assertEqual(classification, "HARD_FAILURE")

    def test_pack_finalizer_is_atomic_and_excludes_junk(self):
        with tempfile.TemporaryDirectory() as d:
            source, destination = self._valid_pack_source(Path(d)), Path(d) / "pack.zip"
            (source / ".DS_Store").write_bytes(b"junk")
            _, digest = finalize_pack(source, destination)
            self.assertEqual(len(digest), 64)
            import zipfile
            with zipfile.ZipFile(destination) as zf:
                self.assertNotIn(".DS_Store", zf.namelist())

    def test_pack_rejects_empty_rendered_report(self):
        with tempfile.TemporaryDirectory() as d:
            source = self._valid_pack_source(Path(d))
            (source / "SUMMARY.md").write_text("\n")
            with self.assertRaisesRegex(ValueError, "empty pack evidence"):
                finalize_pack(source, Path(d) / "pack.zip")

    def test_artifact_chunk_rejects_bad_ranges(self):
        import base64
        chunk = {"artifact_id": "a", "sha256": "h", "bytes_base64": base64.b64encode(b"x").decode(),
                 "returned_bytes": 1, "offset_bytes": 0, "size_bytes": 1, "eof": True}
        self.assertEqual(validate_artifact_chunk(chunk, artifact_id="a", sha256="h", size=1, offset=0, limit=1), b"x")
        with self.assertRaisesRegex(ValueError, "INVALID_ARTIFACT_RANGE"):
            validate_artifact_chunk(chunk, artifact_id="a", sha256="h", size=1, offset=0, limit=0)
        with self.assertRaisesRegex(ValueError, "INVALID_ARTIFACT_RANGE"):
            validate_artifact_chunk(chunk, artifact_id="a", sha256="h", size=1, offset=1, limit=1)

    def test_fake_case_c_continuation_and_full_artifact_reconstruction(self):
        runtime = FakeRuntime("case-c")
        case, output = self.materialized_case("case-03-agent-control-lifecycle")
        client = PublicV2Client(runtime, LaunchLedger(output / "ledger.json"))
        manifest = json.loads((case / "fixture-manifest.json").read_text())
        evidence = _call_case(client, case, manifest, output)
        self.assertEqual(evidence["spawn"]["effective_budget"], CASE_C_BUDGET)
        self.assertEqual(evidence["continuation"]["agent_id"], evidence["spawn"]["agent_id"])
        self.assertEqual(evidence["continuation"]["review_id"], evidence["spawn"]["review_id"])
        self.assertFalse(evidence["continuation"]["counts_as_independent"])
        self.assertNotEqual(evidence["continuation"]["provenance"]["prompt_sha256"], evidence["spawn"]["provenance"]["prompt_sha256"])
        self.assertNotIn("zcode_session_id", json.dumps(evidence))
        self.assertEqual(evidence["continuation_replay"]["submission_disposition"], "existing")
        self.assertTrue(all(item["reconstructed"] for item in evidence["artifact_chunks"]))
        self.assertTrue(evidence["permissions"])
        self.assertEqual(evidence["permissions"][0]["response"]["effective_decision"], "deny")
        self.assertEqual(evidence["close"]["task"]["phase"], "CLOSED")
        self.assertEqual(evidence["close_replay"]["task"]["phase"], "CLOSED")
        self.assertEqual(evidence["restart_reads"]["agent_get_after_close"]["task"]["resources_reaped"], True)
        self.assertEqual(evidence["message"]["disposition"], "queued")
        self.assertEqual(evidence["message_replay"]["disposition"], "already_delivered")
        progress = [event for event in _public_events(evidence) if event["event_type"] == "review_progress"]
        self.assertGreaterEqual(len({event["stage"] for event in progress}), 3)
        self.assertTrue(all(all(field in event for field in ("stage", "summary", "last_progress_at", "semantic_idle_ms", "nudge_sent")) for event in progress))
        self.assertTrue(all(field in event for event in ("stage", "summary", "last_progress_at", "semantic_idle_ms", "nudge_sent")) for event in progress)
        self.assertTrue(evidence["progress_metrics"]["soft_threshold_crossings"])
        self.assertTrue(evidence["progress_metrics"]["non_refresh_sequences"])

    def test_nudge_snapshot_all_historical_progress_events_counts_one_transition(self):
        progress = []
        for sequence, stage in enumerate(("inspection", "validation", "synthesis"), start=2):
            progress.append({
                "sequence": sequence, "attempt_sequence": 1, "event_type": "review_progress",
                "stage": stage, "summary": f"{stage} summary", "last_progress_at": 100,
                "semantic_idle_ms": 119000, "nudge_sent": False,
                "counters": {"checkpoints": 1},
            })
        reread = [dict(event, semantic_idle_ms=120001, nudge_sent=True) for event in progress]
        evidence = {
            "event_pages": [
                {"events": [{"sequence": 1, "attempt_sequence": 1, "event_type": "attempt_started"}, *progress]},
                {"events": [*reread, {"sequence": 5, "attempt_sequence": 1, "event_type": "terminal"}]},
            ],
            "waits": [],
        }
        from run_matrix import _assert_case_c_progress
        _assert_case_c_progress(evidence, {1})
        self.assertEqual(evidence["progress_metrics"]["nudge_transition_count"], {"1": 1})

    def test_case_a_canary_requires_exact_command_typed_deny_and_survival(self):
        permission = {
            "request": {"tool_name": "bash", "operation": "find canary -delete", "summary": "find canary -delete"},
            "response": {
                "requested_decision": "deny", "effective_decision": "deny",
                "disposition": "responded",
                "policy_overrode": False, "policy_reason_code": "POLICY_DENIED",
            },
            "requested_decision": "deny", "effective_decision": "deny",
            "policy_overrode": False, "reason": "bounded conformance",
            "canary_exists_after": True,
        }
        result = _assert_case_a_canary({"permissions": [permission], "canary": {"exists_after": True}})
        self.assertEqual(result["command"], "find canary -delete")
        # The public response cannot attest filesystem survival; only the
        # verified Hook artifact gate may establish that fact.
        self.assertEqual(
            _assert_case_a_canary({"permissions": [permission], "canary": {"exists_after": False}})["command"],
            "find canary -delete",
        )

        for broken in (
            {"permissions": []},
            {"permissions": [dict(permission, request={"operation": "rm -rf canary"})]},
            {"permissions": [dict(permission, request={"operation": "find canary -delete --force"})]},
            {"permissions": [dict(permission, response={"requested_decision": "deny", "effective_decision": "allow", "disposition": "responded", "policy_overrode": False, "policy_reason_code": None})]},
            {"permissions": [dict(permission, response={"requested_decision": "deny", "effective_decision": "deny", "disposition": "responded", "policy_overrode": False})]},
        ):
            with self.assertRaises(FatalConformanceError):
                _assert_case_a_canary(broken)

    def test_fixture_gate_missing_reset_or_verify_is_not_exercised(self):
        with tempfile.TemporaryDirectory() as d:
            case_dir = Path(d) / "case"
            (case_dir / "scripts").mkdir(parents=True)
            with self.assertRaises(InfrastructureConformanceError):
                _fixture_preflight(case_dir)
            reset = case_dir / "scripts/reset.sh"
            reset.write_text("#!/bin/sh\nexit 0\n")
            reset.chmod(0o755)
            with self.assertRaises(InfrastructureConformanceError):
                _fixture_preflight(case_dir)

    def test_fixture_gate_rejects_workspace_identity_drift(self):
        gate = {"pre": {"head": "h", "tree": "t", "status": "", "tracked_files": 1, "inventory": {"files": 1, "sha256": "a"}}}
        post = {"head": "h", "tree": "changed", "status": "", "tracked_files": 1, "inventory": {"files": 1, "sha256": "a"}}
        with patch("run_matrix._fixture_script", return_value={"script": "verify.sh", "returncode": 0}), patch(
            "run_matrix._workspace_snapshot", return_value=post
        ):
            with self.assertRaisesRegex(FatalConformanceError, "drifted"):
                _fixture_postflight(Path("/tmp/case"), gate)

    def test_hook_binding_gap_changes_case_conclusion_and_is_renderable(self):
        class UnverifiedHookRuntime(FakeRuntime):
            def _review_provenance(self, attempt_sequence: int) -> dict[str, object]:
                provenance = super()._review_provenance(attempt_sequence)
                provenance["hook_activation_verified"] = False
                provenance["effective_hook_version"] = None
                provenance["effective_hook_sha256"] = None
                provenance["activation_method"] = None
                provenance["activation_generation"] = None
                return provenance

        runtime = UnverifiedHookRuntime()
        case, output = self.materialized_case("case-01-user-fuzzy-search")
        manifest = json.loads((case / "fixture-manifest.json").read_text())
        client = PublicV2Client(runtime, LaunchLedger(output / "ledger.json"))
        evidence = _call_case(client, case, manifest, output)
        self.assertEqual(evidence["conclusion"], "PASS_WITH_GAPS")
        self.assertIn("Hook activation was not publicly verified", evidence["gaps"])
        self.assertIn("Hook activation was not publicly verified", evidence["spawn_identity_binding"]["gaps"])

    def test_missing_mandatory_gate_cannot_pass(self):
        from run_matrix import _computed_case_conclusion
        case = {"case_id": "case-01-user-fuzzy-search", "fixture_gate": {"status": "PASS"},
                "spawn": {}, "result": {}, "artifact_chunks": [], "close": {},
                "close_replay": {}, "facade_restart": {}, "spawn_identity_binding": {}}
        self.assertEqual(_computed_case_conclusion(case), "NOT_EXERCISED")

    def test_unknown_mandatory_gate_cannot_bypass_conclusion(self):
        case = {"case_id": "case-02-finding-path", **{
            field: {"status": "PASS"} for field in (
                "fixture_gate", "spawn", "result", "artifact_chunks", "close",
                "close_replay", "facade_restart", "spawn_identity_binding",
            )
        }}
        case["fixture_gate"]["status"] = "UNKNOWN"
        self.assertEqual(_computed_case_conclusion(case), "NOT_EXERCISED")

    def test_continuation_identity_mismatch_cannot_pass(self):
        case = {"case_id": "case-03-agent-control-lifecycle", "fixture_gate": {
            "reset": True, "pre_verify": True, "pre": {}, "post_verify": True,
            "post": {}, "unchanged": True,
        }, "spawn": {"agent_id": "a", "review_id": "r", "attempt_sequence": 1, "provenance": {}},
        "result": {"task": {"phase": "TERMINAL"}, "result": {}},
        "artifact_chunks": [{"reconstructed": True}], "close": {"task": {"phase": "CLOSED", "resources_reaped": True}},
        "close_replay": {"task": {"phase": "CLOSED", "resources_reaped": True}},
        "facade_restart": {"service_generation_before": "g", "service_generation_after": "g"},
        "spawn_identity_binding": {"service_binding_source": "public", "hook_activation_verified": False},
        "progress_gate": {"status": "PASS", "attempts": [1]},
        "nudge_transition_gate": {"status": "PASS", "attempts": [1], "transition_count": {"1": 1}},
        "continuation": {"agent_id": "other", "review_id": "r", "attempt_sequence": 2, "counts_as_independent": False},
        "continuation_identity_binding": {"service_binding_source": "public", "hook_activation_verified": False},
        }
        self.assertEqual(_computed_case_conclusion(case), "FAIL")

    def test_first_true_nudge_is_not_a_transition(self):
        from run_matrix import _assert_case_c_progress
        events = [{"sequence": 1, "attempt_sequence": 1, "event_type": "attempt_started"}]
        for sequence, stage in enumerate(("inspection", "validation", "synthesis"), start=2):
            events.append({"sequence": sequence, "attempt_sequence": 1, "event_type": "review_progress",
                           "stage": stage, "summary": stage, "last_progress_at": 1,
                           "semantic_idle_ms": 120001, "nudge_sent": True})
        with self.assertRaises(InfrastructureConformanceError):
            _assert_case_c_progress({"event_snapshots": [{"events": events}]}, {1})

    def test_permission_missing_disposition_is_fatal(self):
        from run_matrix import _pending_requests
        class Client:
            def __init__(self): self.calls = 0
            def call(self, tool, args):
                if tool == "zcode_agent_get":
                    return {"pending_requests": [{"request_id": "r", "kind": "permission", "state": "PENDING", "respondable": True,
                                                     "tool_name": "bash", "operation": "cat file", "summary": "cat file", "policy_preview": {}}]}
                self.calls += 1
                return {"requested_decision": "deny", "effective_decision": "deny", "policy_overrode": False, "reason": "policy"}
        with self.assertRaises(FatalConformanceError):
            _pending_requests(Client(), "agent", {})

    def test_hook_canary_uses_verified_artifact_and_not_public_survival_field(self):
        provenance = FakeRuntime()._review_provenance(1)
        hook_root = REPOSITORY_ROOT / "plugins/zcode-subagent-mcp-v2/review-bash-hook"
        provenance.update({
            "effective_hook_path": str(hook_root / "lib/readonly-bash-policy.mjs"),
            "effective_guard_wrapper_path": str(hook_root / "hooks/check-bash-readonly.mjs"),
            "effective_hook_sha256": _sha256(hook_root / "lib/readonly-bash-policy.mjs"),
        })
        with tempfile.TemporaryDirectory() as directory:
            provenance_path = Path(directory) / "provenance.json"
            provenance_path.write_text(json.dumps(provenance), encoding="utf-8")
            old = os.environ.get("ZCODE_REVIEW_HOOK_PROVENANCE")
            os.environ["ZCODE_REVIEW_HOOK_PROVENANCE"] = str(provenance_path)
            try:
                gate = _run_case_a_hook_canary(provenance)
                missing = dict(provenance)
                missing.pop("effective_hook_path")
                with self.assertRaises(FatalConformanceError):
                    _run_case_a_hook_canary(missing)
                tampered = dict(provenance, effective_hook_sha256="0" * 64)
                with self.assertRaises(FatalConformanceError):
                    _run_case_a_hook_canary(tampered)
            finally:
                if old is None:
                    os.environ.pop("ZCODE_REVIEW_HOOK_PROVENANCE", None)
                else:
                    os.environ["ZCODE_REVIEW_HOOK_PROVENANCE"] = old
        self.assertEqual(gate["status"], "PASS")
        self.assertEqual(gate["decision"], "deny")
        self.assertEqual(gate["canary_sha256_before"], gate["canary_sha256_after"])
        self.assertNotIn("exists_after", gate)

    def test_nudge_true_false_after_transition_is_fatal(self):
        from run_matrix import _assert_case_c_progress
        events = [{"sequence": 1, "attempt_sequence": 1, "event_type": "attempt_started"}]
        for sequence, stage in enumerate(("inspection", "validation", "synthesis"), start=2):
            events.append({"sequence": sequence, "attempt_sequence": 1, "event_type": "review_progress",
                           "stage": stage, "summary": stage, "last_progress_at": 1,
                           "semantic_idle_ms": 1, "nudge_sent": False})
        events.extend([
            {"sequence": 5, "attempt_sequence": 1, "event_type": "review_progress", "stage": "synthesis", "summary": "synthesis", "last_progress_at": 1, "semantic_idle_ms": 120001, "nudge_sent": True},
            {"sequence": 6, "attempt_sequence": 1, "event_type": "review_progress", "stage": "synthesis", "summary": "synthesis", "last_progress_at": 1, "semantic_idle_ms": 120002, "nudge_sent": False},
        ])
        with self.assertRaises(FatalConformanceError):
            _assert_case_c_progress({"event_snapshots": [{"events": events}]}, {1})

    def test_mandatory_gate_failures_and_identity_gaps_are_not_ready(self):
        self.assertEqual(_computed_case_conclusion({"case_id": "case-01-user-fuzzy-search", "error": {"class": "FatalConformanceError"}}), "FAIL")
        self.assertEqual(_computed_case_conclusion({"case_id": "case-01-user-fuzzy-search", "error": {"class": "InfrastructureConformanceError"}}), "NOT_EXERCISED")
        self.assertEqual(_overall_result({"case-01-user-fuzzy-search": "PASS"}, ["active daemon identity was not bound"]), "INSUFFICIENT_EVIDENCE")

    def test_typed_permission_gate_does_not_synthesize_missing_reason(self):
        evidence = {"permissions": [{"response": {
            "requested_decision": "deny", "effective_decision": "deny", "disposition": "responded",
            "policy_overrode": False, "reason": None, "policy_reason_code": None,
        }}]}
        with self.assertRaises(FatalConformanceError):
            _assert_typed_permission_gate(evidence)

    def test_typed_permission_gate_rejects_invalid_decision_and_disposition_types(self):
        base = {
            "requested_decision": "deny", "effective_decision": "deny", "disposition": "responded",
            "policy_overrode": False, "reason": "policy denied", "policy_reason_code": None,
        }
        for changes in (
            {"requested_decision": None},
            {"effective_decision": "unknown"},
            {"disposition": None},
        ):
            with self.assertRaises(FatalConformanceError):
                _assert_typed_permission_gate({"permissions": [{"response": dict(base, **changes)}]})

    def test_public_permission_reason_is_optional_but_denial_code_is_truthful(self):
        evidence = {"permissions": [{"response": {
            "requested_decision": "deny", "effective_decision": "deny", "disposition": "responded",
            "policy_overrode": False, "policy_reason_code": "POLICY_DENIED",
        }}]}
        self.assertEqual(_assert_typed_permission_gate(evidence)["status"], "PASS")

    def test_unknown_mandatory_gate_status_is_not_exercised(self):
        case = {
            "case_id": "case-01-user-fuzzy-search",
            "fixture_gate": {"status": "PASS", "reset": {}, "pre_verify": {}, "pre": {}, "post_verify": {}, "post": {}, "unchanged": True},
            "spawn": {"agent_id": "a", "review_id": "r", "attempt_sequence": 1, "provenance": {}},
            "result": {"task": {}, "result": {}}, "artifact_chunks": [{"reconstructed": True}],
            "close": {"task": {"phase": "CLOSED", "resources_reaped": True}},
            "close_replay": {"task": {"phase": "CLOSED", "resources_reaped": True}},
            "facade_restart": {"service_generation_before": "g", "service_generation_after": "g"},
            "spawn_identity_binding": {"service_binding_source": "owned", "hook_activation_verified": True},
            "hook_canary_gate": {"status": "UNKNOWN"},
            "typed_permission_gate": {"status": "PASS", "response_count": 1},
        }
        self.assertEqual(_computed_case_conclusion(case), "NOT_EXERCISED")

    def test_continuation_identity_binding_rejects_mismatched_ids(self):
        case = {"case_id": "case-03-agent-control-lifecycle", "continuation": {
            "agent_id": "other", "review_id": "r", "attempt_sequence": 2, "counts_as_independent": False,
        }, "spawn": {"agent_id": "a", "review_id": "r", "attempt_sequence": 1, "provenance": {}}}
        # The common mandatory evidence is intentionally absent; the direct
        # continuation check is exercised through a complete-shaped case.
        case.update({
            "fixture_gate": {"reset": {}, "pre_verify": {}, "pre": {}, "post_verify": {}, "post": {}, "unchanged": True},
            "result": {"task": {}, "result": {}}, "artifact_chunks": [{"reconstructed": True}],
            "close": {"task": {"phase": "CLOSED", "resources_reaped": True}},
            "close_replay": {"task": {"phase": "CLOSED", "resources_reaped": True}},
            "facade_restart": {"service_generation_before": "g", "service_generation_after": "g"},
            "spawn_identity_binding": {"service_binding_source": "owned", "hook_activation_verified": True},
            "progress_gate": {"status": "PASS", "attempts": [1]},
            "nudge_transition_gate": {"status": "PASS", "attempts": [1, 2], "transition_count": {"1": 1, "2": 1}},
            "continuation_identity_binding": {"service_binding_source": "owned", "hook_activation_verified": True},
        })
        self.assertEqual(_computed_case_conclusion(case), "FAIL")

    def test_pack_rejects_arbitrary_root_filename_and_free_text_secret(self):
        with tempfile.TemporaryDirectory() as d:
            source = self._valid_pack_source(Path(d))
            normalized = source / "normalized"
            (normalized / "arbitrary.txt").write_text("safe\n")
            with self.assertRaisesRegex(ValueError, "unexpected pack filename"):
                finalize_pack(source, Path(d) / "pack.zip")
            (normalized / "arbitrary.txt").unlink()
            (normalized / "case-a.json").write_text('{"note":"token leaked-value"}\n')
            with self.assertRaisesRegex(ValueError, "unredacted secret"):
                finalize_pack(source, Path(d) / "pack.zip")

    def test_pack_rejects_empty_roots_placeholders_binary_and_invalid_json(self):
        with tempfile.TemporaryDirectory() as d:
            source = self._valid_pack_source(Path(d))
            (source / "raw-transcripts/mcp.jsonl").unlink()
            with self.assertRaisesRegex(ValueError, "empty pack evidence roots"):
                finalize_pack(source, Path(d) / "empty.zip")
            (source / "raw-transcripts/mcp.jsonl").write_text('{"direction":"test"}\n')
            (source / "SUMMARY.md").write_text("# Summary\n\nTODO\n")
            with self.assertRaisesRegex(ValueError, "template or placeholder"):
                finalize_pack(source, Path(d) / "placeholder.zip")
            (source / "SUMMARY.md").write_text("# Summary\n\nRendered.\n")
            (source / "normalized/identity.json").write_bytes(b"\xff\xfe")
            with self.assertRaisesRegex(ValueError, "binary or invalid UTF-8"):
                finalize_pack(source, Path(d) / "binary.zip")
            (source / "normalized/identity.json").write_text("not json\n")
            with self.assertRaisesRegex(ValueError, "invalid JSON evidence"):
                finalize_pack(source, Path(d) / "json.zip")

    def test_fatal_case_error_propagates_and_freezes_matrix(self):
        class FailingRuntime(FakeRuntime):
            def call(self, tool, args):
                if tool == "zcode_agent_events":
                    return {"isError": True, "error": {"code": "PROTOCOL", "message": "fatal"}}
                return super().call(tool, args)
        runtime = FailingRuntime()
        case, output = self.materialized_case("case-01-user-fuzzy-search")
        client = PublicV2Client(runtime, LaunchLedger(output / "ledger.json"))
        manifest = json.loads((case / "fixture-manifest.json").read_text())
        with self.assertRaises(Exception):
            _call_case(client, case, manifest, output)
        self.assertTrue((output / "case-01-user-fuzzy-search.json").is_file())

    def test_ambiguous_transport_keeps_one_reservation_and_retries_same_call(self):
        class BrokenTransport:
            def __init__(self):
                self.calls = 0
            def call(self, tool, args):
                self.calls += 1
                raise InfrastructureConformanceError("broken pipe")
        with tempfile.TemporaryDirectory() as d:
            ledger = LaunchLedger(Path(d) / "ledger.json")
            transport = BrokenTransport()
            client = PublicV2Client(transport, ledger)
            with self.assertRaises(InfrastructureConformanceError):
                client.call("zcode_review_spawn", {}, launches=True, retry_infrastructure=True)
            self.assertEqual(transport.calls, 2)
            # The retry reuses the same reservation token, but conservatively
            # consumes a second total launch slot because the first call may
            # already have started a child.
            self.assertEqual(ledger.count, 2)
            self.assertEqual(ledger.retries, 1)
            self.assertTrue(json.loads(ledger.path.read_text())["reservations"])

    def test_ensure_ready_transport_failure_is_not_retried_by_matrix(self):
        class ReadinessTransport:
            def __init__(self):
                self.calls = 0

            def call(self, tool, args):
                self.calls += 1
                if self.calls == 1:
                    raise InfrastructureConformanceError("ensure-ready response was ambiguous")
                return {"ready": True, "status": {"components": {"daemon": "READY"}}}

        with tempfile.TemporaryDirectory() as d:
            ledger = LaunchLedger(Path(d) / "ledger.json")
            transport = ReadinessTransport()
            with self.assertRaises(InfrastructureConformanceError):
                PublicV2Client(transport, ledger).call(
                    "zcode_system_ensure_ready", {}, launches=True, retry_infrastructure=False,
                )
            self.assertEqual(transport.calls, 1)
            self.assertEqual(ledger.count, 1)
            self.assertEqual(ledger.retries, 0)

    def test_existing_submission_does_not_reserve_a_new_launch(self):
        class ExistingTransport:
            def call(self, tool, args):
                return {"submission_disposition": "existing", "agent_id": "a"}
        with tempfile.TemporaryDirectory() as d:
            ledger = LaunchLedger(Path(d) / "ledger.json")
            result = PublicV2Client(ExistingTransport(), ledger).call("zcode_review_spawn", {}, launches=True)
            self.assertEqual(result["submission_disposition"], "existing")
            self.assertEqual(ledger.count, 0)

    def test_rmcp_iserror_preserves_public_text_and_stable_class_without_retry(self):
        class ErrorTransport:
            def __init__(self):
                self.calls = 0
            def call(self, tool, args):
                self.calls += 1
                return {"isError": True, "content": [{"type": "text", "text": "validation: exact public detail"}]}
        transport = ErrorTransport()
        with self.assertRaises(FatalConformanceError) as caught:
            PublicV2Client(transport).call("zcode_agent_result", {}, retry_infrastructure=True)
        self.assertEqual(transport.calls, 1)
        self.assertEqual(caught.exception.error_class, "VALIDATION")
        self.assertEqual(caught.exception.public_text, "validation: exact public detail")

    def test_fake_no_progress_hits_injected_hard_timeout_without_sleeping_30s(self):
        runtime = FakeRuntime("no-progress")
        client = PublicV2Client(runtime)
        with self.assertRaisesRegex(Exception, "SEMANTIC_HARD_TIMEOUT"):
            _poll_terminal(client, "missing-agent", {}, expected_attempt=1, timeout_s=0.001)

    def test_main_runner_uses_real_facade_restart_path_and_renders_pack(self):
        self.require_git_fixtures()
        class FakeFacadeTransport:
            instances = []
            runtime = FakeRuntime("case-c")

            def __init__(self, command, env=None, **kwargs):
                self.command = command
                self.env = env or {}
                self.proc = SimpleNamespace(pid=5000 + len(self.instances))
                self.transcript = []
                self.closed = False
                self.instances.append(self)

            def list_tools(self):
                value = {"tools": [{"name": name} for name in sorted(REQUIRED_TOOLS)]}
                self.transcript.append({"direction": "response", "payload": value})
                return value

            def call(self, tool, args):
                self.transcript.append({"direction": "request", "payload": redact({"tool": tool, "arguments": args})})
                value = self.runtime.call(tool, args)
                self.transcript.append({"direction": "response", "payload": redact(value)})
                return value

            def close(self):
                self.closed = True

        with tempfile.TemporaryDirectory() as d:
            temp = Path(d)
            execution = create_execution_root("s02-main-")
            self.addCleanup(shutil.rmtree, execution, True)
            binary, runtime = temp / "zcode-review-mcp", temp / "zcode.cjs"
            binary.write_text("facade")
            runtime.write_text("runtime")
            fake_provenance = temp / "fake-hook-provenance.json"
            fake_provenance.write_text(json.dumps({"hook_activation_verified": True}))
            output, pack_path = execution / "output", temp / "pack.zip"
            with patch.dict("os.environ", {"ZCODE_REVIEWD_PATH": str(temp / "missing-reviewd")}, clear=False), patch(
                "run_matrix.StdioMCPTransport", FakeFacadeTransport
            ), patch(
                "run_matrix._runtime_version", return_value="3.10.1"
            ), patch(
                "run_matrix._prepare_verified_hook",
                return_value=(
                    fake_provenance,
                    lambda: {"restored": True},
                    {"sha256": _sha256(fake_provenance), "backup": {}},
                ),
            ):
                exit_code = main([
                    "--official",
                    "--mcp-binary", str(binary),
                    "--runtime", str(runtime),
                    "--output", str(output),
                    "--ledger", str(execution / "ledger.json"),
                    "--pack", str(pack_path),
                    "--timeout", "0.1",
                ])
            self.assertEqual(exit_code, 2)
            self.assertEqual(len(FakeFacadeTransport.instances), 1)
            self.assertTrue(FakeFacadeTransport.instances[0].closed)
            self.assertTrue(pack_path.is_file())
            import zipfile
            with zipfile.ZipFile(pack_path) as archive:
                summary = archive.read("SUMMARY.md").decode()
                self.assertIn("INSUFFICIENT_EVIDENCE", summary)

    def test_main_runner_freezes_after_typed_fatal_without_next_case(self):
        self.require_git_fixtures()
        class StatusFacade:
            runtime = FakeRuntime("ready")

            def __init__(self, command, env=None, **kwargs):
                self.proc = SimpleNamespace(pid=7001)
                self.transcript = [{"direction": "harness", "payload": {"status": "started"}}]

            def list_tools(self):
                return {"tools": [{"name": name} for name in sorted(REQUIRED_TOOLS)]}

            def call(self, tool, args):
                return self.runtime.call(tool, args)

            def close(self):
                return None

        with tempfile.TemporaryDirectory() as d:
            temp = Path(d)
            execution = create_execution_root("s02-main-fatal-")
            self.addCleanup(shutil.rmtree, execution, True)
            binary, runtime = temp / "mcp", temp / "zcode.cjs"
            binary.write_text("facade")
            runtime.write_text("runtime")
            fake_provenance = temp / "fake-hook-provenance.json"
            fake_provenance.write_text(json.dumps({"hook_activation_verified": True}))
            with patch("run_matrix.StdioMCPTransport", StatusFacade), patch(
                "run_matrix._runtime_version", return_value="3.10.1"
            ), patch(
                "run_matrix._prepare_verified_hook",
                return_value=(
                    fake_provenance,
                    lambda: {"restored": True},
                    {"sha256": _sha256(fake_provenance), "backup": {}},
                ),
            ), patch(
                "run_matrix._call_case",
                side_effect=FatalConformanceError("fatal public contract", error_class="PROTOCOL_ERROR"),
            ) as call_case:
                exit_code = main([
                    "--official", "--mcp-binary", str(binary), "--runtime", str(runtime),
                    "--output", str(execution / "output"), "--ledger", str(execution / "ledger.json"),
                    "--pack", str(temp / "pack.zip"), "--timeout", "0.1",
                ])
            self.assertEqual(exit_code, 2)
            self.assertEqual(call_case.call_count, 1)
            fatal = json.loads((execution / "output/redacted-logs/fatal.json").read_text())
            self.assertEqual(fatal["error_class"], "PROTOCOL_ERROR")


if __name__ == "__main__":
    unittest.main()
