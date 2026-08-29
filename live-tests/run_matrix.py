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
from typing import Any, Mapping
from copy import deepcopy

try:
    from .conformance import (
        FatalConformanceError,
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
    for request in pending if isinstance(pending, list) else []:
        if not isinstance(request, Mapping) or request.get("respondable") is False:
            continue
        required = ("request_id", "kind", "state", "respondable", "tool_name", "operation", "summary", "policy_preview")
        if any(field not in request for field in required) or request.get("kind") != "permission":
            raise FatalConformanceError("pending request omitted typed public permission fields")
        request_id = request.get("request_id")
        if not isinstance(request_id, str):
            raise FatalConformanceError("pending request omitted request_id")
        started = time.monotonic()
        response = client.call("zcode_agent_respond", {
            "agent_id": agent_id, "request_id": request_id,
            "decision": "deny", "reason": "bounded conformance",
        })
        evidence.setdefault("permissions", []).append({
            "request": dict(request), "response": response,
            "latency_ms": round((time.monotonic() - started) * 1000, 3),
        })
        replay = client.call("zcode_agent_respond", {
            "agent_id": agent_id, "request_id": request_id,
            "decision": "deny", "reason": "bounded conformance",
        })
        evidence.setdefault("permission_replays", []).append(replay)


def _poll_terminal(client: PublicV2Client, agent_id: str, evidence: dict[str, Any], *, timeout_s: float = DEFAULT_LIFECYCLE_TIMEOUT_S) -> Mapping[str, Any]:
    """Poll ordered events and wait until a terminal task state is observed."""
    cursor = 0
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        events_result = client.call("zcode_agent_events", {"agent_id": agent_id, "after_sequence": cursor, "limit": 100})
        evidence.setdefault("event_pages", []).append(events_result)
        if "events" not in evidence:
            evidence["events"] = events_result
        events = events_result.get("events", []) if isinstance(events_result, Mapping) else []
        if isinstance(events_result, Mapping):
            cursor = int(events_result.get("next_sequence", cursor))
        if events:
            _pending_requests(client, agent_id, evidence)
        wait_result = client.call("zcode_agent_wait", {"agent_id": agent_id, "after_sequence": cursor, "timeout_ms": 500})
        evidence.setdefault("waits", []).append(wait_result)
        wait_events = wait_result.get("events", []) if isinstance(wait_result, Mapping) else []
        if isinstance(wait_result, Mapping):
            cursor = int(wait_result.get("next_sequence", cursor))
        if wait_events:
            _pending_requests(client, agent_id, evidence)
        phase = _task_phase(wait_result)
        if phase in {"TERMINAL", "COMPLETED", "FAILED", "CANCELLED", "CLOSED"}:
            return wait_result
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


def _assert_case_c_progress(evidence: Mapping[str, Any]) -> None:
    events: list[Mapping[str, Any]] = []
    for page in evidence.get("event_pages", []) if isinstance(evidence.get("event_pages"), list) else []:
        if isinstance(page, Mapping) and isinstance(page.get("events"), list):
            events.extend(event for event in page["events"] if isinstance(event, Mapping))
    for page in evidence.get("waits", []) if isinstance(evidence.get("waits"), list) else []:
        if isinstance(page, Mapping) and isinstance(page.get("events"), list):
            events.extend(event for event in page["events"] if isinstance(event, Mapping))
    progress_events = [event for event in events if event.get("event_type") == "review_progress"]
    required = ("stage", "summary", "counters", "last_progress_at", "semantic_idle_ms", "nudge_sent")
    if any(not all(field in event for field in required) for event in progress_events):
        raise FatalConformanceError("Case C review_progress omitted a required public field")
    if any(key in event for event in progress_events for key in ("semantic_stage", "lease_refreshed", "nudge")):
        raise FatalConformanceError("Case C event leaked non-public progress fields")
    stages = {str(event.get("stage")) for event in progress_events}
    if len(stages) < 3:
        raise FatalConformanceError("Case C did not expose three semantic progress stages")
    nudges = [event for event in progress_events if event.get("nudge_sent") is True]
    if len(nudges) > 1:
        raise FatalConformanceError("Case C emitted more than one soft-timeout nudge")
    if any(not isinstance(event.get("semantic_idle_ms"), int) for event in progress_events):
        raise FatalConformanceError("Case C progress event did not carry read-time semantic idle snapshot")


def _public_events(evidence: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    events: list[Mapping[str, Any]] = []
    for key in ("event_pages", "waits"):
        pages = evidence.get(key)
        if not isinstance(pages, list):
            continue
        for page in pages:
            if isinstance(page, Mapping) and isinstance(page.get("events"), list):
                events.extend(event for event in page["events"] if isinstance(event, Mapping))
    return events


def _assert_event_contract(evidence: Mapping[str, Any]) -> None:
    events = _public_events(evidence)
    if len(events) > 500:
        raise FatalConformanceError("public event rate exceeded 500 events per bounded run")
    grouped: dict[Any, list[int]] = {}
    seen: dict[Any, dict[int, Mapping[str, Any]]] = {}
    for event in events:
        sequence = event.get("sequence")
        attempt = event.get("attempt_sequence")
        if not isinstance(sequence, int) or not isinstance(attempt, int):
            raise FatalConformanceError("public event sequence/attempt is invalid")
        previous = seen.setdefault(attempt, {}).get(sequence)
        if previous is not None:
            if previous != event:
                raise FatalConformanceError("public event sequence was reused with different content")
            continue
        seen[attempt][sequence] = event
        grouped.setdefault(attempt, []).append(sequence)
    if any(any(a >= b for a, b in zip(sequences, sequences[1:])) for sequences in grouped.values()):
        raise FatalConformanceError("public event sequence is not strictly monotonic within an attempt")
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
    for field in ("final_signal", "finalized", "report_revision", "finalization_revision", "artifact", "counts", "independence"):
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
    artifact = evidence.get("artifact")
    artifacts = result.get("artifacts")
    if not isinstance(artifact, Mapping) or not isinstance(artifacts, list):
        raise FatalConformanceError("terminal artifact metadata is incomplete")
    match = next((item for item in artifacts if isinstance(item, Mapping) and item.get("artifact_id") == artifact.get("artifact_id")), None)
    if match is None or any(match.get(key) != artifact.get(key) for key in ("sha256", "size_bytes")):
        raise FatalConformanceError("terminal artifact metadata disagrees with result evidence")


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
        REPOSITORY_ROOT / "config/codex-zcode-subagent-mcp-v2.toml",
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
        "mcp_config_source": "normal-home" if config and config != REPOSITORY_ROOT / "config/codex-zcode-subagent-mcp-v2.toml" else "repository-fallback",
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


def _call_case(client: PublicV2Client, case_dir: Path, manifest: Mapping[str, Any], output: Path, *, retry_launch: bool = False) -> dict[str, Any]:
    args = _case_args(REPOSITORY_ROOT, case_dir, manifest, output)
    evidence: dict[str, Any] = {"case_id": manifest.get("case_id", case_dir.name), "calls": []}
    agent_id: str | None = None
    review_id: str | None = None
    try:
        spawned = client.call("zcode_review_spawn", args, launches=True, retry=retry_launch)
        evidence["spawn"] = spawned
        # Same idempotency key must return the original durable submission and
        # must not consume another official launch slot.
        evidence["idempotency_replay"] = client.call("zcode_review_spawn", args)
        agent_id = spawned.get("agent_id") if isinstance(spawned, Mapping) else None
        review_id = spawned.get("review_id") if isinstance(spawned, Mapping) else None
        if not isinstance(agent_id, str):
            raise FatalConformanceError("spawn response did not contain agent_id")
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
        terminal = _poll_terminal(client, agent_id, evidence, timeout_s=lifecycle_timeout)
        evidence["terminal"] = terminal
        _assert_event_contract(evidence)
        result_before = client.call("zcode_agent_result", {"agent_id": agent_id})
        _assert_terminal_result(result_before)
        result_before_copy = deepcopy(result_before)
        evidence["result_before_continuation"] = result_before_copy
        if manifest.get("case_id") == "case-03-agent-control-lifecycle":
            _assert_case_c_progress(evidence)
            evidence["artifacts_before_continuation"] = _collect_result_artifacts(client, agent_id, result_before, attempt=int((spawned or {}).get("attempt_sequence", 1)))
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
            continuation = client.call("zcode_review_continue", continue_args, launches=True)
            evidence["continuation"] = continuation
            if not isinstance(continuation, Mapping):
                raise FatalConformanceError("Case C continuation response is not an object")
            if continuation.get("agent_id") != agent_id or continuation.get("review_id") != review_id:
                raise FatalConformanceError("Case C continuation changed agent/review identity")
            if int(continuation.get("attempt_sequence", 0)) != int((spawned or {}).get("attempt_sequence", 1)) + 1:
                raise FatalConformanceError("Case C continuation did not increment attempt_sequence")
            if continuation.get("counts_as_independent") is not False:
                raise FatalConformanceError("Case C continuation incorrectly counts as independent")
            provenance = continuation.get("provenance")
            if not isinstance(provenance, Mapping) or provenance.get("fresh_session_observed") is not True:
                raise FatalConformanceError("Case C continuation lacks fresh session provenance")
            if provenance.get("zcode_session_id") == (spawned.get("provenance", {}) if isinstance(spawned, Mapping) else {}).get("zcode_session_id"):
                raise FatalConformanceError("Case C continuation reused session provenance")
            _poll_terminal(client, agent_id, evidence, timeout_s=lifecycle_timeout)
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
        evidence["restart_reads"] = {
            "agent_get_after_close": client.call("zcode_agent_get", {"agent_id": agent_id}),
            "system_status_after_close": client.call("zcode_system_status", {}),
        }
    except (FatalConformanceError, LaunchBudgetExceeded, TimeoutError, OSError, RuntimeError) as exc:
        evidence["error"] = {"class": type(exc).__name__, "message": str(exc)}
        evidence["conclusion"] = "FAIL" if isinstance(exc, FatalConformanceError) else "NOT_EXERCISED"
        if agent_id:
            try:
                evidence["cleanup_after_error"] = client.call("zcode_agent_close", {"agent_id": agent_id})
            except Exception:
                evidence["cleanup_after_error"] = {"status": "not_observed"}
        # A case-level product/protocol failure freezes the matrix.  Persist
        # this case's redacted evidence, then propagate so no later case or
        # official launch can run.  Cleanup above is the only permitted call.
        normalized = normalize(str(manifest.get("case_id", case_dir.name)), evidence)
        output.mkdir(parents=True, exist_ok=True)
        (output / f"{manifest.get('case_id', case_dir.name)}.json").write_text(json.dumps(normalized, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        raise
    else:
        evidence["conclusion"] = "PASS_WITH_GAPS"
    return normalize(str(manifest.get("case_id", case_dir.name)), evidence)


def _copy_pack_inputs(root: Path, output: Path) -> Path:
    source = output / "pack-input"
    if source.exists():
        shutil.rmtree(source)
    source.mkdir(parents=True, exist_ok=True)
    template = root / "live-tests/pack-template"
    for report in sorted(template.glob("*.md")):
        shutil.copyfile(report, source / report.name)
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
    daemon_binary = Path(os.environ["ZCODE_REVIEWD_PATH"]) if os.environ.get("ZCODE_REVIEWD_PATH") else None
    if daemon_binary is None:
        for candidate in (REPOSITORY_ROOT / "target/release/zcode-reviewd", REPOSITORY_ROOT / "target/debug/zcode-reviewd"):
            if candidate.is_file():
                daemon_binary = candidate
                break
    hook_root = REPOSITORY_ROOT / "plugins/zcode-subagent-mcp-v2/review-bash-hook"
    hook_manifest = hook_root / ".zcode-plugin/plugin.json"
    hook_checksums = hook_root / "SHA256SUMS.txt"
    hook_policy = hook_root / "POLICY.md"
    identity = {
        "repository_head": _git_head(REPOSITORY_ROOT),
        "mcp_binary": str(binary),
        "mcp_binary_sha256": _sha256(binary),
        "official_runtime": str(args.runtime),
        "official_runtime_path": "ZCode.app/Contents/Resources/glm/zcode.cjs" if args.runtime.name == "zcode.cjs" else args.runtime.name,
        "official_runtime_sha256": _sha256(args.runtime),
        "official_runtime_present": args.runtime.is_file(),
        "mcp_config_sha256": _sha256(REPOSITORY_ROOT / "config/codex-zcode-subagent-mcp-v2.toml"),
        "mcp_config_path": str((REPOSITORY_ROOT / "config/codex-zcode-subagent-mcp-v2.toml").resolve()),
        "effective_config": {"sha256": _sha256(REPOSITORY_ROOT / "config/codex-zcode-subagent-mcp-v2.toml")},
        "daemon_binary": str(daemon_binary) if daemon_binary else None,
        "daemon_binary_sha256": _sha256(daemon_binary) if daemon_binary else None,
        "runtime_version_expected": EXPECTED_RUNTIME_VERSION,
        "runtime_version_observed": _runtime_version(args.runtime),
        "runtime_version_match": _runtime_version(args.runtime) == EXPECTED_RUNTIME_VERSION,
        "hook_policy_version": (json.loads(hook_manifest.read_text(encoding="utf-8")).get("version") if hook_manifest.is_file() else None),
        "hook_policy_sha256": _sha256(hook_policy),
        "hook_checksums_sha256": _sha256(hook_checksums),
        "service_socket": str(socket),
        "public_api_mode": env["ZCODE_PUBLIC_API_MODE"],
        "runtime_env_exported": env["ZCODE_RUNTIME_PATH"],
    }
    identity["effective_normal_home"] = _effective_home_identity()
    _write_json(output / "normalized/identity.json", identity)

    transport: StdioMCPTransport | None = None
    exit_code = 0
    try:
        transport = StdioMCPTransport([str(binary)], env, timeout=args.timeout)
        client = PublicV2Client(transport, ledger)
        catalog = client.catalog()
        _write_json(output / "normalized/catalog.json", catalog)
        if not catalog.get("exact"):
            raise FatalConformanceError(f"public tools/list catalog is not exact: {catalog}")
        status = client.call("zcode_system_status")
        identity["service_generation"] = status.get("service_generation") if isinstance(status, Mapping) else None
        identity["daemon_status"] = status.get("components", {}).get("daemon") if isinstance(status, Mapping) and isinstance(status.get("components"), Mapping) else None
        _write_json(output / "normalized/identity.json", identity)
        if identity["runtime_version_match"] is not True:
            raise FatalConformanceError(f"official runtime version is not {EXPECTED_RUNTIME_VERSION}")
        readiness_args = {"timeout_ms": min(5000, max(1, int(args.timeout * 1000)))}
        try:
            readiness = client.call("zcode_system_ensure_ready", readiness_args, launches=True)
        except (TimeoutError, OSError, RuntimeError):
            # A transport/observation failure is infrastructure evidence.  It
            # may consume exactly one retry slot, unlike a typed runtime or
            # configuration failure returned by the public tool.
            readiness = client.call("zcode_system_ensure_ready", readiness_args, launches=True, retry=True)
        if isinstance(readiness, Mapping) and readiness.get("ready") is not True and readiness.get("probe_result") == "NOT_OBSERVED_WITHIN_TIMEOUT":
            readiness = client.call("zcode_system_ensure_ready", readiness_args, launches=True, retry=True)
        _write_json(output / "normalized/readiness.json", {"status": status, "readiness": readiness})
        if isinstance(readiness, Mapping) and readiness.get("ready") is not True:
            raise FatalConformanceError("official runtime did not report READY")
        for case_dir in sorted(REPOSITORY_ROOT.glob("case-*/fixture-manifest.json")):
            manifest = json.loads(case_dir.read_text(encoding="utf-8"))
            case_root = case_dir.parent
            try:
                evidence = _call_case(client, case_root, manifest, output / "normalized")
            except (TimeoutError, OSError, RuntimeError) as first_error:
                # Only an identical infrastructure failure is retryable, and
                # only once. Product/protocol/semantic failures propagate
                # immediately and freeze all subsequent cases.
                try:
                    evidence = _call_case(client, case_root, manifest, output / "normalized", retry_launch=True)
                except (TimeoutError, OSError, RuntimeError) as second_error:
                    if (type(second_error), str(second_error)) == (type(first_error), str(first_error)):
                        raise
                    raise
            _write_json(output / "normalized" / f"{manifest['case_id']}.json", evidence)
    except Exception as exc:
        _write_json(output / "redacted-logs/fatal.json", {"class": type(exc).__name__, "message": str(exc)})
        exit_code = 2
    finally:
        if transport is not None:
            transport.write_transcript(output / "raw-transcripts/mcp.jsonl")
            transport.close()

    pack_source = _copy_pack_inputs(REPOSITORY_ROOT, output)
    destination, digest = finalize_pack(pack_source, args.pack.expanduser().resolve())
    print(json.dumps({"pack": str(destination), "sha256": digest, "launches": ledger.count, "retries": ledger.retries, "exit_code": exit_code}, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
