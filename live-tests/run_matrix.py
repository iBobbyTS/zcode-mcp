#!/usr/bin/env python3
"""Run the bounded public V2 A/B/C matrix.

Nothing in this module starts ``zcode-reviewd`` or edits normal HOME.  With
``--official`` it starts only the configured public ``zcode-review-mcp`` stdio
facade, wires the existing daemon socket, and records redacted evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import plistlib
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Mapping
from copy import deepcopy

try:
    from .conformance import (
        FatalConformanceError,
        InfrastructureConformanceError,
        LaunchBudgetExceeded,
        LaunchLedger,
        PublicV2Client,
        StdioMCPTransport,
        finalize_pack,
        normalize,
        redact,
        collect_artifact,
        validate_artifact_chunk,
        PUBLIC_EVENT_TYPES,
    )
except ImportError:  # script execution from live-tests/
    from conformance import (  # type: ignore
        FatalConformanceError,
        InfrastructureConformanceError,
        LaunchBudgetExceeded,
        LaunchLedger,
        PublicV2Client,
        StdioMCPTransport,
        finalize_pack,
        normalize,
        redact,
        collect_artifact,
        validate_artifact_chunk,
        PUBLIC_EVENT_TYPES,
    )


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RUNTIME = Path("/Applications/ZCode.app/Contents/Resources/glm/zcode.cjs")
DEFAULT_PACK = Path.home() / "Desktop/audit-pack/zcode-mcp-official-runtime-conformance.zip"
EXPECTED_RUNTIME_VERSION = "3.10.1"
CASE_C_BUDGET = {
    "wall_time_ms": 1_800_000,
    "semantic_soft_timeout_ms": 120_000,
    "semantic_hard_timeout_ms": 300_000,
    "max_turns": 10,
    "max_tool_calls": 100,
    "max_context_bytes": 4_000_000,
    "max_result_bytes": 1_000_000,
    "max_artifact_bytes": 4_000_000,
}
DEFAULT_LIFECYCLE_TIMEOUT_S = 300.0
MAX_LIFECYCLE_TIMEOUT_S = 1800.0


def _sha256(path: Path) -> str | None:
    try:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()
    except OSError:
        return None


def _git_head(path: Path) -> str | None:
    try:
        return subprocess.run(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(redact(value), ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _case_args(root: Path, case_dir: Path, manifest: Mapping[str, Any], output: Path) -> dict[str, Any]:
    workspace = (case_dir / "workspace").resolve()
    requirements = (case_dir / "requirements/REQUIREMENTS.md").resolve()
    scope = (case_dir / "requirements/SCOPE-MANIFEST.md").resolve()
    args = {
        "review_kind": "initial_bounded",
        "repository": str(workspace),
        "base_ref": str(manifest.get("base_sha", "HEAD^")),
        "head_ref": str(manifest.get("feat_sha", "HEAD")),
        "scope_manifest": [str(scope)],
        "requirements_path": str(requirements),
        "plan_path": str((root / ".agent-work/PLAN-FULL.md").resolve()),
        "report_path": str((output / f"{manifest.get('case_id', case_dir.name)}-report.md").resolve()),
        "feature_id": "official-runtime-conformance",
        "section_id": "S02",
        "ownership_token": f"s02-{manifest.get('case_id', case_dir.name)}",
        "idempotency_key": f"official-runtime-conformance:S02:{manifest.get('case_id', case_dir.name)}:initial",
        "read_only": True,
        "attachments": [],
    }
    if manifest.get("case_id") == "case-03-agent-control-lifecycle":
        args["budget"] = dict(CASE_C_BUDGET)
    return args


def _task_phase(value: Any) -> str | None:
    if not isinstance(value, Mapping):
        return None
    task = value.get("task")
    return task.get("phase") if isinstance(task, Mapping) else None


def _pending_requests(client: PublicV2Client, agent_id: str, evidence: dict[str, Any]) -> None:
    """Answer each typed pending request as soon as it becomes observable."""
    state = client.call("zcode_agent_get", {"agent_id": agent_id})
    evidence.setdefault("get", state)
    evidence.setdefault("get_snapshots", []).append(state)
    pending = state.get("pending_requests", []) if isinstance(state, Mapping) else []
    already_answered = set(evidence.get("responded_request_ids", []))
    for request in pending if isinstance(pending, list) else []:
        if not isinstance(request, Mapping) or request.get("respondable") is False:
            continue
        required = ("request_id", "kind", "state", "respondable", "tool_name", "operation", "summary", "policy_preview")
        if any(field not in request for field in required) or request.get("kind") != "permission":
            raise FatalConformanceError("pending request omitted typed public permission fields")
        request_id = request.get("request_id")
        if not isinstance(request_id, str):
            raise FatalConformanceError("pending request omitted request_id")
        if request_id in already_answered:
            continue
        started = time.monotonic()
        response = client.call("zcode_agent_respond", {
            "agent_id": agent_id, "request_id": request_id,
            "decision": "deny", "reason": "bounded conformance",
        })
        evidence.setdefault("permissions", []).append({
            "request": dict(request), "response": response,
            "latency_ms": round((time.monotonic() - started) * 1000, 3),
        })
        evidence.setdefault("responded_request_ids", []).append(request_id)
        already_answered.add(request_id)
        replay = client.call("zcode_agent_respond", {
            "agent_id": agent_id, "request_id": request_id,
            "decision": "deny", "reason": "bounded conformance",
        })
        evidence.setdefault("permission_replays", []).append(replay)


def _snapshot_events(client: PublicV2Client, agent_id: str, evidence: dict[str, Any]) -> None:
    """Read the public event stream from zero, preserving dynamic snapshots."""
    cursor = 0
    while True:
        page = client.call("zcode_agent_events", {"agent_id": agent_id, "after_sequence": cursor, "limit": 100})
        evidence.setdefault("event_snapshots", []).append(page)
        if not isinstance(page, Mapping):
            raise FatalConformanceError("public event snapshot is not an object")
        events = page.get("events", [])
        next_cursor = page.get("next_sequence", cursor)
        if not isinstance(next_cursor, int) or next_cursor < cursor:
            raise FatalConformanceError("public event snapshot cursor regressed")
        if events:
            _pending_requests(client, agent_id, evidence)
        if page.get("has_more") is True and next_cursor == cursor:
            raise FatalConformanceError("public event snapshot made no pagination progress")
        cursor = next_cursor
        if page.get("has_more") is not True:
            return


def _poll_terminal(
    client: PublicV2Client,
    agent_id: str,
    evidence: dict[str, Any],
    *,
    expected_attempt: int,
    timeout_s: float = DEFAULT_LIFECYCLE_TIMEOUT_S,
) -> Mapping[str, Any]:
    """Wait first, drain ordered pages, and stop at the requested attempt."""
    cursor = 0
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        wait_result = client.call("zcode_agent_wait", {"agent_id": agent_id, "after_sequence": cursor, "timeout_ms": 500})
        evidence.setdefault("waits", []).append(wait_result)
        wait_events = wait_result.get("events", []) if isinstance(wait_result, Mapping) else []
        if isinstance(wait_result, Mapping):
            cursor = int(wait_result.get("next_sequence", cursor))
        if wait_events:
            _pending_requests(client, agent_id, evidence)
        phase = _task_phase(wait_result)
        if phase in {"TERMINAL", "COMPLETED", "FAILED", "CANCELLED", "CLOSED"}:
            task = wait_result.get("task") if isinstance(wait_result, Mapping) else None
            if not isinstance(task, Mapping) or task.get("attempt_sequence") != expected_attempt:
                raise FatalConformanceError("terminal wait returned the wrong attempt_sequence")
            _snapshot_events(client, agent_id, evidence)
            return wait_result
        if isinstance(wait_result, Mapping) and wait_result.get("has_more") is True:
            events_result = client.call("zcode_agent_events", {"agent_id": agent_id, "after_sequence": cursor, "limit": 100})
            evidence.setdefault("event_pages", []).append(events_result)
            events = events_result.get("events", []) if isinstance(events_result, Mapping) else []
            if isinstance(events_result, Mapping):
                cursor = int(events_result.get("next_sequence", cursor))
            if events:
                _pending_requests(client, agent_id, evidence)
            continue
        if isinstance(wait_result, Mapping) and wait_result.get("timed_out") is True:
            # A no-change timeout is an observation, not terminal success; keep
            # polling until the bounded lifecycle deadline expires.
            continue
    raise FatalConformanceError(f"SEMANTIC_HARD_TIMEOUT: agent {agent_id} did not reach terminal state within {timeout_s}s")


def _assert_case_c_budget(spawned: Mapping[str, Any], args: Mapping[str, Any]) -> None:
    effective = spawned.get("effective_budget")
    if not isinstance(effective, Mapping):
        raise FatalConformanceError("Case C spawn omitted effective_budget")
    for key, expected in CASE_C_BUDGET.items():
        if int(effective.get(key, -1)) != expected:
            raise FatalConformanceError(f"Case C effective budget mismatch for {key}")


def _assert_case_c_progress(evidence: dict[str, Any], expected_attempts: set[int]) -> None:
    events = _public_events(evidence)
    progress_events = [event for event in events if event.get("event_type") == "review_progress"]
    required = ("stage", "summary", "last_progress_at", "semantic_idle_ms", "nudge_sent")
    if any(not all(field in event for field in required) for event in progress_events):
        raise FatalConformanceError("Case C review_progress omitted a required public field")
    if any("counters" in event and not isinstance(event.get("counters"), Mapping) for event in progress_events):
        raise FatalConformanceError("Case C review_progress counters are not a public mapping")
    if any(key in event for event in progress_events for key in ("semantic_stage", "lease_refreshed", "nudge")):
        raise FatalConformanceError("Case C event leaked non-public progress fields")
    for attempt in expected_attempts:
        stages = {str(event.get("stage")) for event in progress_events if event.get("attempt_sequence") == attempt}
        if len(stages) < 3:
            raise FatalConformanceError(f"Case C attempt {attempt} did not expose three semantic progress stages")
    if any(not isinstance(event.get("semantic_idle_ms"), int) for event in progress_events):
        raise FatalConformanceError("Case C progress event did not carry read-time semantic idle snapshot")
    observations = _public_event_observations(evidence)
    histories: dict[tuple[int, int], list[Mapping[str, Any]]] = {}
    for event in observations:
        if event.get("event_type") == "review_progress" and isinstance(event.get("attempt_sequence"), int) and isinstance(event.get("sequence"), int):
            histories.setdefault((event["attempt_sequence"], event["sequence"]), []).append(event)
    nudge_sequences: dict[int, set[int]] = {attempt: set() for attempt in expected_attempts}
    threshold_crossings: list[dict[str, int]] = []
    non_refresh_sequences: list[dict[str, int]] = []
    for (attempt, sequence), snapshots in histories.items():
        if any(snapshot.get("nudge_sent") is True for snapshot in snapshots):
            nudge_sequences.setdefault(attempt, set()).add(sequence)
        for earlier, later in zip(snapshots, snapshots[1:]):
            earlier_idle, later_idle = earlier.get("semantic_idle_ms"), later.get("semantic_idle_ms")
            if isinstance(earlier_idle, int) and isinstance(later_idle, int) and earlier_idle < CASE_C_BUDGET["semantic_soft_timeout_ms"] <= later_idle:
                threshold_crossings.append({"attempt_sequence": attempt, "sequence": sequence})
            if (
                earlier.get("stage") == later.get("stage")
                and earlier.get("summary") == later.get("summary")
                and earlier.get("counters") == later.get("counters")
                and earlier.get("last_progress_at") == later.get("last_progress_at")
                and isinstance(earlier_idle, int)
                and isinstance(later_idle, int)
                and later_idle > earlier_idle
            ):
                non_refresh_sequences.append({"attempt_sequence": attempt, "sequence": sequence})
    if any(len(sequences) > 1 for sequences in nudge_sequences.values()):
        raise FatalConformanceError("Case C emitted more than one public soft-timeout nudge per attempt")
    if not threshold_crossings:
        raise FatalConformanceError("Case C lacks public-field evidence of a soft-threshold crossing")
    if not non_refresh_sequences:
        raise FatalConformanceError("Case C lacks public-field evidence that cosmetic churn did not refresh the lease")
    evidence["progress_metrics"] = {
        "unique_progress_events": len(progress_events),
        "nudge_sequences": {str(attempt): sorted(sequences) for attempt, sequences in nudge_sequences.items()},
        "soft_threshold_crossings": threshold_crossings,
        "non_refresh_sequences": non_refresh_sequences,
        "public_fields_only": True,
    }


def _public_event_observations(evidence: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    events: list[Mapping[str, Any]] = []
    for key in ("event_pages", "waits", "event_snapshots"):
        pages = evidence.get(key)
        if not isinstance(pages, list):
            continue
        for page in pages:
            if isinstance(page, Mapping) and isinstance(page.get("events"), list):
                events.extend(event for event in page["events"] if isinstance(event, Mapping))
    return events


def _public_events(evidence: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    # Pages and waits can repeat the same event.  Keep the newest snapshot for
    # each attempt-local sequence (so semantic_idle_ms/nudge_sent can advance)
    # while preserving the first-observed page order.  Sequence values are not
    # compared across continuation attempts.
    latest: dict[tuple[int, int], Mapping[str, Any]] = {}
    order: list[tuple[int, int]] = []
    for event in _public_event_observations(evidence):
        attempt, sequence = event.get("attempt_sequence"), event.get("sequence")
        if isinstance(attempt, int) and isinstance(sequence, int):
            key = (attempt, sequence)
            if key not in latest:
                order.append(key)
            latest[key] = event
    return [latest[key] for key in order]


def _assert_event_contract(evidence: Mapping[str, Any], *, expected_attempts: set[int]) -> None:
    observations = _public_event_observations(evidence)
    events = _public_events(evidence)
    if len(events) > 500:
        raise FatalConformanceError("public event rate exceeded 500 events per bounded run")
    seen: dict[tuple[int, int], Mapping[str, Any]] = {}
    observed_sequences_by_attempt: dict[int, list[int]] = {}
    for event in observations:
        sequence = event.get("sequence")
        attempt = event.get("attempt_sequence")
        if not isinstance(sequence, int) or not isinstance(attempt, int):
            raise FatalConformanceError("public event sequence/attempt is invalid")
        key = (attempt, sequence)
        previous = seen.get(key)
        if previous is not None:
            stable_fields = ("event_type", "redaction_level", "pending_request_id", "stage", "summary", "counters", "last_progress_at")
            if any(previous.get(field) != event.get(field) for field in stable_fields):
                raise FatalConformanceError("public event sequence changed immutable public fields")
            previous_idle, current_idle = previous.get("semantic_idle_ms"), event.get("semantic_idle_ms")
            if isinstance(previous_idle, int) and isinstance(current_idle, int) and current_idle < previous_idle:
                raise FatalConformanceError("public semantic_idle_ms regressed on reread")
            if previous.get("nudge_sent") is True and event.get("nudge_sent") is False:
                raise FatalConformanceError("public nudge_sent regressed on reread")
            seen[key] = event
            continue
        seen[key] = event
        observed_sequences_by_attempt.setdefault(attempt, []).append(sequence)
    if any(
        any(a >= b for a, b in zip(sequences, sequences[1:]))
        for sequences in observed_sequences_by_attempt.values()
    ):
        raise FatalConformanceError("public event sequence is not strictly monotonic within an attempt")
    observed_attempts = {event.get("attempt_sequence") for event in events}
    if not expected_attempts.issubset(observed_attempts):
        raise FatalConformanceError("public event stream omitted an expected attempt")
    for attempt in expected_attempts:
        attempt_types = {event.get("event_type") for event in events if event.get("attempt_sequence") == attempt}
        if not {"attempt_started", "terminal"}.issubset(attempt_types):
            raise FatalConformanceError(f"public event stream did not validate attempt {attempt}")
    for event in events:
        if event.get("event_type") not in PUBLIC_EVENT_TYPES:
            raise FatalConformanceError("public event type is outside the closed V2 set")
    for wait in evidence.get("waits", []) if isinstance(evidence.get("waits"), list) else []:
        if not isinstance(wait, Mapping):
            continue
        if not wait.get("events") and _task_phase(wait) not in {"TERMINAL", "COMPLETED", "FAILED", "CANCELLED", "CLOSED"} and wait.get("timed_out") is not True:
            raise FatalConformanceError("no-change public wait did not report timed_out=true")


def _assert_terminal_result(result: Any) -> None:
    """Require the public result projection to carry terminal review evidence."""
    if not isinstance(result, Mapping):
        raise FatalConformanceError("agent_result response is not an object")
    task = result.get("task")
    if not isinstance(task, Mapping) or task.get("phase") not in {"TERMINAL", "CLOSED"}:
        raise FatalConformanceError("terminal result did not expose a terminal task phase")
    public_result = result.get("result")
    if not isinstance(public_result, Mapping):
        raise FatalConformanceError("terminal result omitted result projection")
    required = ("outcome", "summary", "result_sha256", "review_evidence")
    if any(field not in public_result for field in required):
        raise FatalConformanceError("terminal result omitted required public fields")
    evidence = public_result.get("review_evidence")
    if not isinstance(evidence, Mapping):
        raise FatalConformanceError("terminal result omitted review evidence")
    for field in ("final_signal", "finalized", "report_revision", "finalization_revision", "artifact", "counts", "independence", "validation_provenance"):
        if field not in evidence:
            raise FatalConformanceError(f"terminal review evidence omitted {field}")
    if not isinstance(evidence.get("final_signal"), str) or not evidence["final_signal"] or evidence.get("finalized") is not True:
        raise FatalConformanceError("terminal review evidence is not finalized")
    if not isinstance(evidence.get("report_revision"), int) or not isinstance(evidence.get("finalization_revision"), int):
        raise FatalConformanceError("terminal review evidence revisions are invalid")
    counts = evidence.get("counts")
    independence = evidence.get("independence")
    if not isinstance(counts, Mapping) or any(not isinstance(counts.get(field), int) for field in ("checkpoints", "findings", "open_findings", "validations")):
        raise FatalConformanceError("terminal review evidence counts are incomplete")
    if not isinstance(independence, Mapping) or any(field not in independence for field in ("independent_evidence", "fresh_session_observed", "counts_as_independent")):
        raise FatalConformanceError("terminal review evidence independence is incomplete")
    validation = evidence.get("validation_provenance")
    daemon_verification = validation.get("daemon_verification") if isinstance(validation, Mapping) else None
    if not isinstance(daemon_verification, Mapping) or any(
        daemon_verification.get(field) is not True
        for field in (
            "source_integrity_verified",
            "finalized_report_verified",
            "artifact_digest_verified",
            "validation_records_structurally_verified",
        )
    ):
        raise FatalConformanceError("terminal result lacks verified public daemon provenance")
    artifact = evidence.get("artifact")
    artifacts = result.get("artifacts")
    if not isinstance(artifact, Mapping) or not isinstance(artifacts, list):
        raise FatalConformanceError("terminal artifact metadata is incomplete")
    match = next((item for item in artifacts if isinstance(item, Mapping) and item.get("artifact_id") == artifact.get("artifact_id")), None)
    if match is None or any(match.get(key) != artifact.get(key) for key in ("sha256", "size_bytes")):
        raise FatalConformanceError("terminal artifact metadata disagrees with result evidence")


_PUBLIC_REVIEW_PROVENANCE_FIELDS = {
    "review_kind",
    "manifest_sha256",
    "prepared_sha256",
    "prompt_sha256",
    "base_sha",
    "head_sha",
    "requested_model",
    "fresh_session_observed",
    "policy_version",
    "policy_sha256",
    "daemon_policy_version",
    "daemon_policy_sha256",
    "expected_hook_version",
    "expected_hook_sha256",
    "effective_hook_version",
    "effective_hook_sha256",
    "hook_activation_verified",
    "activation_method",
    "activation_generation",
}


def _validate_review_submission(
    value: Any,
    *,
    expected_agent_id: str | None = None,
    expected_review_id: str | None = None,
    expected_attempt: int | None = None,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise FatalConformanceError("review submission response is not an object")
    if value.get("submission_disposition") not in {"created", "existing"}:
        raise FatalConformanceError("review submission omitted public disposition")
    if expected_agent_id is not None and value.get("agent_id") != expected_agent_id:
        raise FatalConformanceError("review submission changed agent identity")
    if expected_review_id is not None and value.get("review_id") != expected_review_id:
        raise FatalConformanceError("review submission changed review identity")
    if expected_attempt is not None and value.get("attempt_sequence") != expected_attempt:
        raise FatalConformanceError("review submission returned the wrong attempt_sequence")
    provenance = value.get("provenance")
    if not isinstance(provenance, Mapping):
        raise FatalConformanceError("review submission omitted public provenance")
    if any(field not in provenance for field in _PUBLIC_REVIEW_PROVENANCE_FIELDS):
        raise FatalConformanceError("review submission public provenance is incomplete")
    if "zcode_session_id" in json.dumps(provenance, sort_keys=True):
        raise FatalConformanceError("review submission used a non-public session identifier")
    for field in (
        "manifest_sha256",
        "prepared_sha256",
        "prompt_sha256",
        "daemon_policy_sha256",
        "expected_hook_sha256",
    ):
        if not isinstance(provenance.get(field), str) or not provenance[field]:
            raise FatalConformanceError(f"review submission omitted {field}")
    if provenance.get("fresh_session_observed") is not True:
        raise FatalConformanceError("review submission did not publicly attest a fresh session")
    gaps: list[str] = []
    hook_verified = provenance.get("hook_activation_verified") is True
    if hook_verified:
        if not isinstance(provenance.get("policy_sha256"), str) or not provenance["policy_sha256"]:
            raise FatalConformanceError("verified Hook provenance omitted policy_sha256")
        if provenance.get("effective_hook_version") != provenance.get("expected_hook_version"):
            raise FatalConformanceError("effective Hook version disagrees with public provenance")
        if provenance.get("effective_hook_sha256") != provenance.get("expected_hook_sha256"):
            raise FatalConformanceError("effective Hook digest disagrees with public provenance")
    else:
        gaps.append("Hook activation was not publicly verified")
    return {
        "service_binding_source": "public_review_submission",
        "hook_activation_verified": hook_verified,
        "hook_version": provenance.get("effective_hook_version"),
        "hook_sha256": provenance.get("effective_hook_sha256"),
        "policy_version": provenance.get("policy_version"),
        "policy_sha256": provenance.get("policy_sha256"),
        "activation_method": provenance.get("activation_method"),
        "activation_generation": provenance.get("activation_generation"),
        "gaps": gaps,
    }


def _propagate_binding_gaps(evidence: dict[str, Any], binding: Mapping[str, Any] | None) -> None:
    """Carry unverifiable public identity claims into case evidence.

    A binding gap is an evidence limitation, not proof that the Hook is active.
    Keeping it on the case makes the computed conclusion and rendered
    KNOWN-GAPS report truthful for both initial spawn and continuation.
    """
    if not isinstance(binding, Mapping):
        return
    gaps = binding.get("gaps")
    if not isinstance(gaps, list):
        return
    target = evidence.setdefault("gaps", [])
    if not isinstance(target, list):
        target = []
        evidence["gaps"] = target
    for gap in gaps:
        if isinstance(gap, str) and gap and gap not in target:
            target.append(gap)


def _runtime_version(path: Path) -> str | None:
    # Standard app layout: ZCode.app/Contents/Resources/glm/zcode.cjs.
    info = path.parents[2] / "Info.plist" if len(path.parents) > 2 else None
    if info is None or not info.is_file():
        return None
    try:
        value = plistlib.loads(info.read_bytes()).get("CFBundleShortVersionString")
    except (OSError, ValueError, plistlib.InvalidFileException):
        return None
    return str(value) if value is not None else None


def _effective_home_identity() -> dict[str, Any]:
    """Capture hashes for the effective normal-HOME configuration only.

    We record provenance and digests, never copy configuration bytes.  An
    explicit environment override is useful in CI; otherwise the normal
    ``~/.codex``/``~/.zcode`` locations are observed read-only.
    """
    home = Path.home()
    config_candidates = [
        Path(os.environ["ZCODE_EFFECTIVE_MCP_CONFIG"])
        if os.environ.get("ZCODE_EFFECTIVE_MCP_CONFIG") else None,
        home / ".codex/config.toml",
    ]
    config = next((path for path in config_candidates if path is not None and path.is_file()), None)
    hook_candidates = [
        Path(os.environ["ZCODE_REVIEW_HOOK_PROVENANCE"])
        if os.environ.get("ZCODE_REVIEW_HOOK_PROVENANCE") else None,
        home / ".zcode/hooks/check-bash-status.mjs",
    ]
    hook = next((path for path in hook_candidates if path is not None and path.is_file()), None)
    zcode_config = home / ".zcode/cli/config.json"
    return {
        "home_mode": "normal",
        "mcp_config_source": (
            "explicit-environment" if config and os.environ.get("ZCODE_EFFECTIVE_MCP_CONFIG")
            else "normal-home" if config
            else "not-observed"
        ),
        "mcp_config_sha256": _sha256(config) if config else None,
        "zcode_cli_config_sha256": _sha256(zcode_config),
        "hook_source": "normal-home" if hook else "not-observed",
        "hook_sha256": _sha256(hook) if hook else None,
        "hook_provenance_sha256": _sha256(Path(os.environ["ZCODE_REVIEW_HOOK_PROVENANCE"])) if os.environ.get("ZCODE_REVIEW_HOOK_PROVENANCE") and Path(os.environ["ZCODE_REVIEW_HOOK_PROVENANCE"]).is_file() else None,
    }


def _collect_result_artifacts(client: PublicV2Client, agent_id: str, result: Any, *, attempt: int | None = None) -> list[dict[str, Any]]:
    artifacts = result.get("artifacts", []) if isinstance(result, Mapping) else []
    collected: list[dict[str, Any]] = []
    for artifact in artifacts if isinstance(artifacts, list) else []:
        if not isinstance(artifact, Mapping):
            raise FatalConformanceError("artifact entry is not an object")
        artifact_id, digest, size = artifact.get("artifact_id"), artifact.get("sha256"), artifact.get("size_bytes")
        if not isinstance(artifact_id, str) or not isinstance(digest, str) or not isinstance(size, int) or size <= 0:
            raise FatalConformanceError("artifact metadata is incomplete")
        reconstructed = collect_artifact(client, agent_id, artifact_id=artifact_id, sha256=digest, size=size, attempt_sequence=attempt)
        samples: list[dict[str, Any]] = []
        sample_offsets = {0, size // 2, max(0, size - min(4096, size))}
        for offset in sorted(sample_offsets):
            limit = min(8192, size - offset)
            sample_args: dict[str, Any] = {
                "agent_id": agent_id, "artifact_id": artifact_id,
                "offset_bytes": offset, "limit_bytes": limit,
            }
            if attempt is not None:
                sample_args["attempt_sequence"] = attempt
            sample_result = client.call("zcode_agent_result", sample_args)
            chunk = sample_result.get("artifact_chunk") if isinstance(sample_result, Mapping) else None
            if not isinstance(chunk, Mapping):
                raise FatalConformanceError("artifact sample omitted artifact_chunk")
            data = validate_artifact_chunk(chunk, artifact_id=artifact_id, sha256=digest, size=size, offset=offset, limit=limit)
            samples.append({"offset_bytes": offset, "returned_bytes": len(data), "eof": bool(chunk.get("eof"))})
        range_errors: list[dict[str, str]] = []
        for label, invalid_args, expected in (
            ("zero_limit", {"offset_bytes": 0, "limit_bytes": 0}, "outside the allowed range"),
            ("over_limit", {"offset_bytes": 0, "limit_bytes": 8193}, "outside the allowed range"),
            ("offset_eof", {"offset_bytes": size, "limit_bytes": 1}, "does not permit non-empty progress"),
        ):
            probe_args: dict[str, Any] = {"agent_id": agent_id, "artifact_id": artifact_id, **invalid_args}
            if attempt is not None:
                probe_args["attempt_sequence"] = attempt
            try:
                client.call("zcode_agent_result", probe_args)
            except FatalConformanceError as error:
                if expected not in str(error):
                    raise FatalConformanceError(f"artifact {label} returned unstable public error: {error}") from error
                range_errors.append({"kind": label, "error": str(error)})
            else:
                raise FatalConformanceError(f"artifact {label} was accepted unexpectedly")
        collected.append({"artifact_id": artifact_id, "size_bytes": len(reconstructed), "sha256": hashlib.sha256(reconstructed).hexdigest(), "reconstructed": True, "attempt_sequence": attempt, "samples": samples, "invalid_range_errors": range_errors})
    return collected


def _call_case(
    client: PublicV2Client,
    case_dir: Path,
    manifest: Mapping[str, Any],
    output: Path,
    *,
    facade_restart: Callable[[], tuple[PublicV2Client, Mapping[str, Any]]] | None = None,
) -> dict[str, Any]:
    args = _case_args(REPOSITORY_ROOT, case_dir, manifest, output)
    evidence: dict[str, Any] = {"case_id": manifest.get("case_id", case_dir.name), "calls": []}
    agent_id: str | None = None
    review_id: str | None = None
    try:
        spawned = client.call("zcode_review_spawn", args, launches=True, retry_infrastructure=True)
        evidence["spawn"] = spawned
        evidence["spawn_identity_binding"] = _validate_review_submission(spawned)
        _propagate_binding_gaps(evidence, evidence["spawn_identity_binding"])
        # Same idempotency key must return the original durable submission and
        # must not consume another official launch slot.
        evidence["idempotency_replay"] = client.call("zcode_review_spawn", args)
        agent_id = spawned.get("agent_id") if isinstance(spawned, Mapping) else None
        review_id = spawned.get("review_id") if isinstance(spawned, Mapping) else None
        if not isinstance(agent_id, str):
            raise FatalConformanceError("spawn response did not contain agent_id")
        if not isinstance(review_id, str):
            raise FatalConformanceError("spawn response did not contain review_id")
        spawn_attempt = int(spawned.get("attempt_sequence", 0)) if isinstance(spawned, Mapping) else 0
        if spawn_attempt <= 0:
            raise FatalConformanceError("spawn response did not contain a positive attempt_sequence")
        _validate_review_submission(
            evidence["idempotency_replay"],
            expected_agent_id=agent_id,
            expected_review_id=review_id,
            expected_attempt=spawn_attempt,
        )
        if evidence["idempotency_replay"].get("submission_disposition") != "existing":
            raise FatalConformanceError("spawn idempotency replay did not return existing")
        if manifest.get("case_id") == "case-03-agent-control-lifecycle":
            if not isinstance(spawned, Mapping):
                raise FatalConformanceError("Case C spawn response is not an object")
            _assert_case_c_budget(spawned, args)
        # Permission requests are drained immediately after spawn/get, before
        # unrelated lifecycle calls.  Later pending events are drained by the
        # polling helper as soon as they appear.
        _pending_requests(client, agent_id, evidence)
        if manifest.get("case_id") == "case-03-agent-control-lifecycle":
            # Exercise the public message path while the attempt is running;
            # the identical message id must be idempotent and not create a
            # second semantic request.
            message_args = {
                "agent_id": agent_id,
                "message_id": f"{agent_id}-s02-message",
                "mode": "queue",
                "content": "bounded continuation context",
            }
            evidence["message"] = client.call("zcode_agent_message", message_args)
            evidence["message_replay"] = client.call("zcode_agent_message", message_args)
            if evidence["message"].get("disposition") not in {"queued", "delivered", "interrupted_then_delivered"}:
                raise FatalConformanceError("Case C message was not accepted")
            if evidence["message_replay"].get("disposition") != "already_delivered":
                raise FatalConformanceError("Case C message replay was not idempotent")
        evidence["list"] = client.call("zcode_agent_list", {"feature_id": "official-runtime-conformance", "limit": 100})
        effective_budget = spawned.get("effective_budget", {}) if isinstance(spawned, Mapping) else {}
        wall_ms = effective_budget.get("wall_time_ms") if isinstance(effective_budget, Mapping) else None
        lifecycle_timeout = min(MAX_LIFECYCLE_TIMEOUT_S, max(DEFAULT_LIFECYCLE_TIMEOUT_S, float(wall_ms) / 1000.0)) if isinstance(wall_ms, (int, float)) and wall_ms > 0 else DEFAULT_LIFECYCLE_TIMEOUT_S
        terminal = _poll_terminal(client, agent_id, evidence, expected_attempt=spawn_attempt, timeout_s=lifecycle_timeout)
        evidence["terminal"] = terminal
        _assert_event_contract(evidence, expected_attempts={spawn_attempt})
        result_before = client.call("zcode_agent_result", {"agent_id": agent_id})
        _assert_terminal_result(result_before)
        result_before_copy = deepcopy(result_before)
        evidence["result_before_continuation"] = result_before_copy
        if manifest.get("case_id") == "case-03-agent-control-lifecycle":
            evidence["artifacts_before_continuation"] = _collect_result_artifacts(client, agent_id, result_before, attempt=spawn_attempt)
        if manifest.get("case_id") == "case-03-agent-control-lifecycle" and isinstance(review_id, str):
            continue_args = {
                "agent_id": agent_id,
                "review_id": review_id,
                "base_ref": args["base_ref"],
                "head_ref": args["head_ref"],
                "frozen_finding_ids": [],
                "idempotency_key": args["idempotency_key"] + ":continuation",
                "attachments": [],
                "budget": dict(CASE_C_BUDGET),
            }
            continuation = client.call("zcode_review_continue", continue_args, launches=True, retry_infrastructure=True)
            evidence["continuation"] = continuation
            if not isinstance(continuation, Mapping):
                raise FatalConformanceError("Case C continuation response is not an object")
            if continuation.get("agent_id") != agent_id or continuation.get("review_id") != review_id:
                raise FatalConformanceError("Case C continuation changed agent/review identity")
            if int(continuation.get("attempt_sequence", 0)) != int((spawned or {}).get("attempt_sequence", 1)) + 1:
                raise FatalConformanceError("Case C continuation did not increment attempt_sequence")
            if continuation.get("counts_as_independent") is not False:
                raise FatalConformanceError("Case C continuation incorrectly counts as independent")
            continuation_attempt = spawn_attempt + 1
            evidence["continuation_identity_binding"] = _validate_review_submission(
                continuation,
                expected_agent_id=agent_id,
                expected_review_id=review_id,
                expected_attempt=continuation_attempt,
            )
            _propagate_binding_gaps(evidence, evidence["continuation_identity_binding"])
            spawn_provenance = spawned.get("provenance", {}) if isinstance(spawned, Mapping) else {}
            continuation_provenance = continuation.get("provenance", {})
            if continuation_provenance.get("prompt_sha256") == spawn_provenance.get("prompt_sha256"):
                raise FatalConformanceError("Case C continuation did not expose new public prompt provenance")
            evidence["continuation_replay"] = client.call("zcode_review_continue", continue_args)
            _validate_review_submission(
                evidence["continuation_replay"],
                expected_agent_id=agent_id,
                expected_review_id=review_id,
                expected_attempt=continuation_attempt,
            )
            if evidence["continuation_replay"].get("submission_disposition") != "existing":
                raise FatalConformanceError("continuation idempotency replay did not return existing")
            _poll_terminal(client, agent_id, evidence, expected_attempt=continuation_attempt, timeout_s=lifecycle_timeout)
            _assert_event_contract(evidence, expected_attempts={spawn_attempt, continuation_attempt})
            _assert_case_c_progress(evidence, {spawn_attempt, continuation_attempt})
            result_after = client.call("zcode_agent_result", {"agent_id": agent_id, "attempt_sequence": continuation["attempt_sequence"]})
            _assert_terminal_result(result_after)
            old_result_recheck = client.call("zcode_agent_result", {"agent_id": agent_id, "attempt_sequence": spawned["attempt_sequence"]})
            if old_result_recheck != result_before_copy:
                raise FatalConformanceError("previous result mutated during continuation")
            evidence["result_before_recheck"] = old_result_recheck
            evidence["result"] = result_after
            evidence["continuation_result"] = result_after
        else:
            evidence["result"] = result_before

        # Reconstruct every advertised artifact, not just sample offsets, and
        # retain per-artifact digest/byte-count evidence.
        result_value = evidence["result"]
        final_attempt = (evidence.get("continuation") or {}).get("attempt_sequence") if isinstance(evidence.get("continuation"), Mapping) else int((spawned or {}).get("attempt_sequence", 1))
        evidence["artifact_chunks"] = _collect_result_artifacts(client, agent_id, result_value, attempt=final_attempt)
        evidence["close"] = client.call("zcode_agent_close", {"agent_id": agent_id})
        evidence["close_replay"] = client.call("zcode_agent_close", {"agent_id": agent_id})
        close_task = evidence["close"].get("task") if isinstance(evidence.get("close"), Mapping) else None
        replay_task = evidence["close_replay"].get("task") if isinstance(evidence.get("close_replay"), Mapping) else None
        if not isinstance(close_task, Mapping) or close_task.get("phase") != "CLOSED" or close_task.get("closed") is not True or close_task.get("resources_reaped") is not True:
            raise FatalConformanceError("close did not report closed/reaped resources")
        if not isinstance(replay_task, Mapping) or replay_task.get("phase") != "CLOSED" or replay_task.get("closed") is not True or replay_task.get("resources_reaped") is not True:
            raise FatalConformanceError("close replay did not preserve idempotent cleanup state")
        before_restart = client.call("zcode_system_status", {})
        if facade_restart is not None:
            client, restart_process = facade_restart()
            restart_kind = "actual_facade_process_restart"
            if restart_process.get("process_changed") is not True:
                raise FatalConformanceError("facade restart did not replace the MCP process")
        else:
            client = PublicV2Client(client.transport, client.ledger)
            restart_process = {"kind": "deterministic_fake_facade_rebind"}
            restart_kind = "deterministic_fake_facade_rebind"
        after_restart = client.call("zcode_system_status", {})
        if not isinstance(before_restart, Mapping) or not isinstance(after_restart, Mapping):
            raise FatalConformanceError("facade restart status evidence is incomplete")
        if before_restart.get("service_generation") != after_restart.get("service_generation"):
            raise FatalConformanceError("facade restart unexpectedly changed daemon service_generation")
        evidence["facade_restart"] = {
            "kind": restart_kind,
            "process": dict(restart_process),
            "service_generation_before": before_restart.get("service_generation"),
            "service_generation_after": after_restart.get("service_generation"),
        }
        evidence["restart_reads"] = {
            "agent_get_after_close": client.call("zcode_agent_get", {"agent_id": agent_id}),
            "system_status_after_close": after_restart,
        }
    except (FatalConformanceError, LaunchBudgetExceeded, InfrastructureConformanceError, TimeoutError, OSError, RuntimeError) as exc:
        evidence["error"] = {"class": type(exc).__name__, "message": str(exc)}
        evidence["conclusion"] = "FAIL" if isinstance(exc, FatalConformanceError) else "NOT_EXERCISED"
        if agent_id and not isinstance(exc, FatalConformanceError):
            try:
                evidence["cleanup_after_error"] = client.call("zcode_agent_close", {"agent_id": agent_id})
            except Exception:
                evidence["cleanup_after_error"] = {"status": "not_observed"}
        # A typed product/protocol failure freezes immediately. Infrastructure
        # lifecycle failures may attempt one close, but never rerun the case.
        normalized = normalize(str(manifest.get("case_id", case_dir.name)), evidence)
        output.mkdir(parents=True, exist_ok=True)
        (output / f"{manifest.get('case_id', case_dir.name)}.json").write_text(json.dumps(normalized, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        raise
    else:
        evidence["conclusion"] = "PASS_WITH_GAPS" if evidence.get("gaps") else "PASS"
    return normalize(str(manifest.get("case_id", case_dir.name)), evidence)


CASE_CONCLUSIONS = {"PASS", "PASS_WITH_GAPS", "FAIL", "NOT_EXERCISED"}
OVERALL_RESULTS = {
    "OFFICIAL_RUNTIME_READY",
    "OFFICIAL_RUNTIME_READY_WITH_GAPS",
    "OFFICIAL_RUNTIME_NOT_READY",
    "INSUFFICIENT_EVIDENCE",
}


def _load_object(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"normalized evidence is not an object: {path.name}")
    return value


def _case_gaps(case: Mapping[str, Any]) -> list[str]:
    """Return all evidence gaps, including binding gaps from older packs."""
    gaps: list[str] = []
    raw = case.get("gaps")
    if isinstance(raw, list):
        gaps.extend(item for item in raw if isinstance(item, str) and item)
    for binding_name in ("spawn_identity_binding", "continuation_identity_binding"):
        binding = case.get(binding_name)
        binding_gaps = binding.get("gaps") if isinstance(binding, Mapping) else None
        if isinstance(binding_gaps, list):
            for gap in binding_gaps:
                if isinstance(gap, str) and gap and gap not in gaps:
                    gaps.append(gap)
    return gaps


def _computed_case_conclusion(case: Mapping[str, Any] | None) -> str:
    if case is None:
        return "NOT_EXERCISED"
    error = case.get("error")
    if isinstance(error, Mapping):
        return "FAIL" if error.get("class") == "FatalConformanceError" else "NOT_EXERCISED"
    required = ("spawn", "result", "artifact_chunks", "close", "close_replay", "facade_restart")
    if any(field not in case for field in required):
        return "NOT_EXERCISED"
    return "PASS_WITH_GAPS" if _case_gaps(case) else "PASS"


def _overall_result(conclusions: Mapping[str, str], identity_gaps: list[str]) -> str:
    values = list(conclusions.values())
    if any(value not in CASE_CONCLUSIONS for value in values):
        raise ValueError("invalid case conclusion enum")
    if "FAIL" in values:
        result = "OFFICIAL_RUNTIME_NOT_READY"
    elif "NOT_EXERCISED" in values:
        result = "INSUFFICIENT_EVIDENCE"
    elif "PASS_WITH_GAPS" in values or identity_gaps:
        result = "OFFICIAL_RUNTIME_READY_WITH_GAPS"
    else:
        result = "OFFICIAL_RUNTIME_READY"
    if result not in OVERALL_RESULTS:
        raise ValueError("invalid overall result enum")
    return result


def _json_block(value: Any) -> str:
    return "```json\n" + json.dumps(redact(value), ensure_ascii=False, indent=2, sort_keys=True) + "\n```"


def _render_reports(root: Path, output: Path, destination: Path) -> dict[str, Any]:
    """Render every report from normalized evidence; templates supply titles only."""
    template = root / "live-tests/pack-template"
    titles: dict[str, str] = {}
    for name in (
        "SUMMARY.md", "SYSTEM-IDENTITY.md", "SCENARIO-MATRIX.md", "PERMISSION-MATRIX.md",
        "PROGRESS-TIMELINE.md", "EVENT-METRICS.md", "RESULT-ARTIFACT-MATRIX.md",
        "RESTART-CLEANUP.md", "KNOWN-GAPS.md",
    ):
        lines = (template / name).read_text(encoding="utf-8").splitlines()
        if not lines or not lines[0].startswith("# "):
            raise ValueError(f"pack template lacks a title: {name}")
        titles[name] = lines[0]

    identity = _load_object(output / "normalized/identity.json") or {}
    catalog = _load_object(output / "normalized/catalog.json") or {}
    readiness = _load_object(output / "normalized/readiness.json") or {}
    case_ids = [path.parent.name for path in sorted(root.glob("case-*/fixture-manifest.json"))]
    cases = {case_id: _load_object(output / "normalized" / f"{case_id}.json") for case_id in case_ids}
    conclusions = {case_id: _computed_case_conclusion(value) for case_id, value in cases.items()}
    identity_gaps = [str(item) for item in identity.get("binding_gaps", [])] if isinstance(identity.get("binding_gaps"), list) else []
    overall = _overall_result(conclusions, identity_gaps)

    summary = {
        "overall": overall,
        "case_conclusions": conclusions,
        "public_catalog_exact": catalog.get("exact"),
        "readiness": (readiness.get("readiness") or {}).get("probe_result") if isinstance(readiness.get("readiness"), Mapping) else None,
    }
    reports: dict[str, str] = {
        "SUMMARY.md": f"{titles['SUMMARY.md']}\n\nOverall: `{overall}`\n\n{_json_block(summary)}\n",
        "SYSTEM-IDENTITY.md": f"{titles['SYSTEM-IDENTITY.md']}\n\n{_json_block({'identity': identity, 'catalog': catalog, 'readiness': readiness})}\n",
        "SCENARIO-MATRIX.md": titles["SCENARIO-MATRIX.md"] + "\n\n| Case | Conclusion |\n|---|---|\n" + "".join(
            f"| {case_id} | `{conclusions[case_id]}` |\n" for case_id in case_ids
        ),
    }

    permissions: list[dict[str, Any]] = []
    progress: list[dict[str, Any]] = []
    event_metrics: dict[str, Any] = {}
    result_artifacts: dict[str, Any] = {}
    restart_cleanup: dict[str, Any] = {}
    gaps = list(identity_gaps)
    for case_id, case in cases.items():
        if not isinstance(case, Mapping):
            gaps.append(f"{case_id}: normalized case evidence was not produced")
            continue
        permissions.extend(
            {"case": case_id, **dict(item)} for item in case.get("permissions", []) if isinstance(item, Mapping)
        )
        unique_events = _public_events(case)
        progress.extend({"case": case_id, **dict(event)} for event in unique_events if event.get("event_type") == "review_progress")
        counts: dict[str, int] = {}
        for event in unique_events:
            event_type = str(event.get("event_type"))
            counts[event_type] = counts.get(event_type, 0) + 1
        event_metrics[case_id] = {
            "unique_event_count": len(unique_events),
            "types": counts,
            "progress_metrics": case.get("progress_metrics"),
        }
        result_artifacts[case_id] = {
            "result": case.get("result"),
            "artifact_chunks": case.get("artifact_chunks"),
        }
        restart_cleanup[case_id] = {
            "continuation": case.get("continuation"),
            "facade_restart": case.get("facade_restart"),
            "close": case.get("close"),
            "close_replay": case.get("close_replay"),
            "restart_reads": case.get("restart_reads"),
        }
        gaps.extend(f"{case_id}: {item}" for item in _case_gaps(case))
    gaps.append("Finding-quality judgment is outside this conformance harness")

    reports.update({
        "PERMISSION-MATRIX.md": f"{titles['PERMISSION-MATRIX.md']}\n\n{_json_block(permissions)}\n",
        "PROGRESS-TIMELINE.md": f"{titles['PROGRESS-TIMELINE.md']}\n\n{_json_block(progress)}\n",
        "EVENT-METRICS.md": f"{titles['EVENT-METRICS.md']}\n\n{_json_block(event_metrics)}\n",
        "RESULT-ARTIFACT-MATRIX.md": f"{titles['RESULT-ARTIFACT-MATRIX.md']}\n\n{_json_block(result_artifacts)}\n",
        "RESTART-CLEANUP.md": f"{titles['RESTART-CLEANUP.md']}\n\n{_json_block(restart_cleanup)}\n",
        "KNOWN-GAPS.md": f"{titles['KNOWN-GAPS.md']}\n\n" + "".join(f"- {redact(item)}\n" for item in gaps),
    })
    if set(reports) != set(titles):
        raise ValueError("not all nine pack reports were rendered")
    for name, content in reports.items():
        (destination / name).write_text(content, encoding="utf-8")
    return summary


def _copy_pack_inputs(root: Path, output: Path) -> Path:
    source = output / "pack-input"
    if source.exists():
        shutil.rmtree(source)
    source.mkdir(parents=True, exist_ok=True)
    summary = _render_reports(root, output, source)
    for directory in ("fixtures", "normalized", "raw-transcripts", "redacted-logs"):
        target = source / directory
        target.mkdir(parents=True, exist_ok=True)
        source_dir = output / directory
        if source_dir.exists():
            for item in source_dir.rglob("*"):
                if item.is_file() and not item.is_symlink():
                    relative = item.relative_to(source_dir)
                    (target / relative).parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(item, target / relative)
        if directory == "fixtures" and not any(target.iterdir()):
            for manifest_path in sorted(root.glob("case-*/fixture-manifest.json")):
                shutil.copyfile(manifest_path, target / f"{manifest_path.parent.name}-manifest.json")
    _write_json(output / "redacted-logs/case-matrix.json", summary)
    shutil.copyfile(output / "redacted-logs/case-matrix.json", source / "redacted-logs/case-matrix.json")
    return source


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--official", action="store_true", help="required gate for real MCP calls")
    parser.add_argument("--mcp-binary", type=Path, default=None)
    parser.add_argument("--socket", type=Path, default=None)
    parser.add_argument("--runtime", type=Path, default=DEFAULT_RUNTIME)
    parser.add_argument("--output", type=Path, default=REPOSITORY_ROOT / ".agent-work/s02-normalized")
    parser.add_argument("--ledger", type=Path, default=None)
    parser.add_argument("--pack", type=Path, default=DEFAULT_PACK)
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args(argv)
    if not args.official:
        parser.error("refusing official calls without explicit --official")

    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    for name in ("normalized", "raw-transcripts", "redacted-logs", "fixtures"):
        (output / name).mkdir(parents=True, exist_ok=True)
    ledger_path = (args.ledger or (output / "launch-ledger.json")).resolve()
    ledger = LaunchLedger(ledger_path)
    binary = args.mcp_binary or (Path(os.environ["ZCODE_REVIEW_MCP_PATH"]) if os.environ.get("ZCODE_REVIEW_MCP_PATH") else None)
    if binary is None:
        for candidate in (REPOSITORY_ROOT / "target/release/zcode-review-mcp", REPOSITORY_ROOT / "target/debug/zcode-review-mcp"):
            if candidate.is_file():
                binary = candidate
                break
    if binary is None or not binary.is_file():
        raise SystemExit("configured zcode-review-mcp binary is missing (use --mcp-binary)")
    socket = (args.socket or (Path(os.environ["ZCODE_REVIEWD_SOCKET"]) if os.environ.get("ZCODE_REVIEWD_SOCKET") else output / "reviewd.sock")).resolve()
    if not socket.is_absolute():
        raise SystemExit("ZCODE_REVIEWD_SOCKET must be absolute")
    env = dict(os.environ)
    env["ZCODE_REVIEWD_SOCKET"] = str(socket)
    env["ZCODE_PUBLIC_API_MODE"] = "subagent_v2"
    env["ZCODE_RUNTIME_PATH"] = str(args.runtime.resolve())
    # A pre-existing daemon is reached only through the public socket.  A
    # repository build artifact is not proof of the active daemon binary.
    daemon_binary_candidate = Path(os.environ["ZCODE_REVIEWD_PATH"]) if os.environ.get("ZCODE_REVIEWD_PATH") else None
    hook_root = REPOSITORY_ROOT / "plugins/zcode-subagent-mcp-v2/review-bash-hook"
    hook_manifest = hook_root / ".zcode-plugin/plugin.json"
    hook_checksums = hook_root / "SHA256SUMS.txt"
    hook_policy = hook_root / "POLICY.md"
    identity = {
        "repository_head": _git_head(REPOSITORY_ROOT),
        "mcp_facade": {
            "binary": str(binary),
            "sha256": _sha256(binary),
            "binding": "actual_spawn_command",
        },
        "runtime_candidate": {
            "path": str(args.runtime),
            "sha256": _sha256(args.runtime),
            "present": args.runtime.is_file(),
            "version_expected": EXPECTED_RUNTIME_VERSION,
            "version_observed": _runtime_version(args.runtime),
            "version_match": _runtime_version(args.runtime) == EXPECTED_RUNTIME_VERSION,
            "binding": "facade_environment_candidate_not_public_daemon_identity",
        },
        "repository_config_candidate": {
            "path": str((REPOSITORY_ROOT / "config/codex-zcode-subagent-mcp-v2.toml").resolve()),
            "sha256": _sha256(REPOSITORY_ROOT / "config/codex-zcode-subagent-mcp-v2.toml"),
            "binding": "repository_candidate_only",
        },
        "daemon_binary_candidate": {
            "path": str(daemon_binary_candidate) if daemon_binary_candidate else None,
            "sha256": _sha256(daemon_binary_candidate) if daemon_binary_candidate else None,
            "source": "explicit_environment" if daemon_binary_candidate else "not_observed",
            "publicly_bound": False,
        },
        "hook_repository_candidate": {
            "version": (json.loads(hook_manifest.read_text(encoding="utf-8")).get("version") if hook_manifest.is_file() else None),
            "policy_sha256": _sha256(hook_policy),
            "checksums_sha256": _sha256(hook_checksums),
            "binding": "repository_candidate_only_until_public_review_provenance",
        },
        "service_socket": str(socket),
        "public_api_mode": env["ZCODE_PUBLIC_API_MODE"],
        "runtime_candidate_exported_to_facade": env["ZCODE_RUNTIME_PATH"],
        "binding_gaps": [
            "The public status surface does not expose the active daemon binary digest",
            "The public status surface does not bind the active runtime to the local runtime candidate digest",
            "The effective MCP config digest is observed locally but is not projected by public status",
        ],
    }
    identity["effective_normal_home"] = _effective_home_identity()
    _write_json(output / "normalized/identity.json", identity)

    transports: list[StdioMCPTransport] = []
    exit_code = 0
    fatal: Exception | None = None

    def start_facade() -> PublicV2Client:
        transport = StdioMCPTransport([str(binary)], env, timeout=args.timeout)
        transports.append(transport)
        return PublicV2Client(transport, ledger)

    def restart_facade() -> tuple[PublicV2Client, Mapping[str, Any]]:
        if not transports:
            raise FatalConformanceError("facade restart requested before facade startup")
        previous = transports[-1]
        previous_pid = previous.proc.pid
        previous.close()
        restarted = start_facade()
        current_transport = transports[-1]
        return restarted, {
            "previous_pid": previous_pid,
            "current_pid": current_transport.proc.pid,
            "process_changed": previous_pid != current_transport.proc.pid,
        }

    try:
        client = start_facade()
        catalog = client.catalog()
        _write_json(output / "normalized/catalog.json", catalog)
        if not catalog.get("exact"):
            raise FatalConformanceError(f"public tools/list catalog is not exact: {catalog}")
        status = client.call("zcode_system_status")
        if not isinstance(status, Mapping) or status.get("api_surface") != "subagent_v2" or not isinstance(status.get("service_generation"), str) or not status.get("service_generation"):
            raise FatalConformanceError("public system status omitted service identity")
        components = status.get("components")
        if not isinstance(components, Mapping) or components.get("daemon") != "READY":
            raise FatalConformanceError("public system status did not bind a READY daemon")
        identity["public_service"] = {
            "service_generation": status.get("service_generation"),
            "protocol_version": status.get("protocol_version"),
            "api_surface": status.get("api_surface"),
            "daemon_state": components.get("daemon"),
            "runtime_state": components.get("runtime"),
            "binding": "public_system_status",
        }
        _write_json(output / "normalized/identity.json", identity)
        if identity["runtime_candidate"]["version_match"] is not True:
            raise FatalConformanceError(f"official runtime version is not {EXPECTED_RUNTIME_VERSION}")
        readiness_args = {"timeout_ms": min(5000, max(1, int(args.timeout * 1000)))}
        readiness = client.call(
            "zcode_system_ensure_ready",
            readiness_args,
            launches=True,
            retry_infrastructure=True,
        )
        readiness_status = readiness.get("status") if isinstance(readiness, Mapping) else None
        readiness_components = readiness_status.get("components") if isinstance(readiness_status, Mapping) else None
        if not isinstance(readiness_status, Mapping) or readiness_status.get("service_generation") != status.get("service_generation"):
            raise FatalConformanceError("readiness response was not bound to the observed public service generation")
        if not isinstance(readiness_components, Mapping) or readiness_components.get("daemon") != "READY":
            raise FatalConformanceError("readiness response did not retain a READY public daemon")
        identity["public_service"]["runtime_state_after_readiness"] = readiness_components.get("runtime")
        identity["public_service"]["model_auth_state_after_readiness"] = readiness_components.get("model_auth")
        _write_json(output / "normalized/identity.json", identity)
        _write_json(output / "normalized/readiness.json", {"status": status, "readiness": readiness})
        if isinstance(readiness, Mapping) and readiness.get("ready") is not True:
            raise FatalConformanceError("official runtime did not report READY")
        for case_dir in sorted(REPOSITORY_ROOT.glob("case-*/fixture-manifest.json")):
            manifest = json.loads(case_dir.read_text(encoding="utf-8"))
            case_root = case_dir.parent
            evidence = _call_case(
                client,
                case_root,
                manifest,
                output / "normalized",
                facade_restart=restart_facade if manifest.get("case_id") == "case-03-agent-control-lifecycle" else None,
            )
            _write_json(output / "normalized" / f"{manifest['case_id']}.json", evidence)
            for binding_name in ("spawn_identity_binding", "continuation_identity_binding"):
                binding = evidence.get(binding_name)
                if isinstance(binding, Mapping):
                    identity.setdefault("public_review_bindings", []).append(binding)
            _write_json(output / "normalized/identity.json", identity)
    except Exception as exc:
        fatal = exc
        detail = {"class": type(exc).__name__, "message": str(exc)}
        if isinstance(exc, FatalConformanceError):
            detail["error_class"] = exc.error_class
            detail["public_text"] = exc.public_text
        _write_json(output / "redacted-logs/fatal.json", detail)
        exit_code = 2
    finally:
        transcript_path = output / "raw-transcripts/mcp.jsonl"
        with transcript_path.open("w", encoding="utf-8") as stream:
            for index, transport in enumerate(transports, start=1):
                for item in transport.transcript:
                    stream.write(json.dumps({"facade_sequence": index, **item}, ensure_ascii=False, sort_keys=True) + "\n")
            if not transports:
                stream.write(json.dumps({"direction": "harness", "payload": {"transport": "not_initialized", "fatal": type(fatal).__name__ if fatal else None}}, sort_keys=True) + "\n")
        for transport in transports:
            transport.close()

    pack_source = _copy_pack_inputs(REPOSITORY_ROOT, output)
    destination, digest = finalize_pack(pack_source, args.pack.expanduser().resolve())
    print(json.dumps({"pack": str(destination), "sha256": digest, "launches": ledger.count, "retries": ledger.retries, "exit_code": exit_code}, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
