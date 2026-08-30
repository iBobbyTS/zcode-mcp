#!/usr/bin/env python3
"""Run the bounded public V2 A/B/C matrix.

With ``--official`` the harness owns a private ``zcode-reviewd`` lifetime and
the public ``zcode-review-mcp`` stdio facade.  Normal HOME and any user daemon
are left untouched; unavailable exact binaries are reported as evidence gaps.
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
import tempfile
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
except ImportError:  # direct script execution from non-git-based/
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

from fixture_workspace import (
    REPOSITORY_ROOT,
    WORKSPACE_ROOT,
    create_execution_root,
    materialize_git_cases,
)


DEFAULT_RUNTIME = Path("/Applications/ZCode.app/Contents/Resources/glm/zcode.cjs")
DEFAULT_PACK = Path.home() / "Desktop/audit-pack/zcode-mcp-official-runtime-conformance.zip"
EXPECTED_RUNTIME_VERSION = "3.10.1"
# Observed on the local ZCode 0.16.5 client: descriptions and duplicate Bash
# matchers are rejected during session bootstrap.  Keep this operational fact
# in the evidence pack rather than treating the old marker-based shape as a
# product contract.
OBSERVED_ZCODE_HOOK_COMPATIBILITY = {
    "client_version": "0.16.5",
    "required_shape": "one Bash matcher per supported event; no description field",
    "correction": "replace legacy Bash entries with the current wrapper and preserve unrelated non-Bash hooks",
    "evidence_source": "local app-server session/create probe",
}
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


class OwnedDaemon:
    """Start, observe, and reap one exact daemon for a matrix run."""

    def __init__(self, binary: Path | None, runtime: Path, root: Path, timeout: float):
        self.binary = binary.resolve() if binary else None
        self.runtime = runtime.resolve()
        self.root = root.resolve()
        self.timeout = max(0.1, float(timeout))
        self.socket = self.root / "reviewd.sock"
        self.database = self.root / "store.sqlite3"
        self.artifact_root = self.root / "artifacts"
        self.log_root = self.root / "logs"
        self.log_path = self.log_root / "reviewd.log"
        self.proc: subprocess.Popen[bytes] | None = None
        self.service_generation: str | None = None
        self.config_digest: str | None = None
        self.hook_provenance: Path | None = None

    @property
    def available(self) -> bool:
        return self.binary is not None and self.binary.is_file()

    def identity(self) -> dict[str, Any]:
        config = {
            "database": str(self.database), "socket": str(self.socket),
            "runtime": str(self.runtime), "artifact_root": str(self.artifact_root),
            "log_root": str(self.log_root), "public_api_mode": "subagent_v2",
        }
        self.config_digest = hashlib.sha256(
            json.dumps(config, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return {
            "binary": str(self.binary) if self.binary else None,
            "sha256": _sha256(self.binary) if self.binary else None,
            "socket": str(self.socket), "store": str(self.database),
            "artifact_root": str(self.artifact_root), "log_root": str(self.log_root),
            "effective_config_digest": self.config_digest,
            "ownership": "harness_owned_exact_daemon" if self.available else "unavailable",
        }

    def start(self) -> None:
        if not self.available:
            raise InfrastructureConformanceError("exact zcode-reviewd binary is unavailable")
        self.root.mkdir(parents=True, exist_ok=True)
        self.artifact_root.mkdir(); self.log_root.mkdir()
        env = dict(os.environ)
        env.update({
            "ZCODE_REVIEWD_SOCKET": str(self.socket),
            "ZCODE_REVIEWD_DATABASE": str(self.database),
            "ZCODE_RUNTIME_PATH": str(self.runtime),
            "ZCODE_PUBLIC_API_MODE": "subagent_v2",
            "ZCODE_REVIEWD_ARTIFACT_ROOT": str(self.artifact_root),
            "ZCODE_REVIEWD_LOG_ROOT": str(self.log_root),
        })
        if self.hook_provenance is not None:
            env["ZCODE_REVIEW_HOOK_PROVENANCE"] = str(self.hook_provenance)
        log = self.log_path.open("wb")
        try:
            self.proc = subprocess.Popen(
                [str(self.binary), "--database", str(self.database), "--socket", str(self.socket), "--runtime", str(self.runtime)],
                env=env, stdout=log, stderr=subprocess.STDOUT,
            )
        finally:
            log.close()
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise InfrastructureConformanceError(f"zcode-reviewd exited during startup ({self.proc.returncode})")
            if self.socket.exists():
                return
            time.sleep(0.02)
        raise InfrastructureConformanceError("zcode-reviewd socket readiness timed out")

    def observe_generation(self, status: Mapping[str, Any]) -> None:
        generation = status.get("service_generation")
        if not isinstance(generation, str) or not generation:
            raise InfrastructureConformanceError("owned daemon did not expose service_generation")
        if self.proc is None or self.proc.poll() is not None:
            raise InfrastructureConformanceError("owned daemon exited before service binding")
        self.service_generation = generation

    def cleanup(self) -> dict[str, Any]:
        process = self.proc
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=min(5.0, self.timeout))
            except subprocess.TimeoutExpired:
                process.kill(); process.wait(timeout=2.0)
        reaped = process is None or process.poll() is not None
        for path in (self.socket, self.database, self.database.with_name(self.database.name + "-wal"), self.database.with_name(self.database.name + "-shm")):
            try: path.unlink()
            except FileNotFoundError: pass
        # The root is a harness-created disposable directory; remove any
        # daemon sidecars along with the documented socket/store/log paths.
        if self.root.exists():
            shutil.rmtree(self.root)
        return {"owned": True, "reaped": reaped, "socket_removed": not self.socket.exists(), "store_removed": not self.database.exists()}

    def copy_log(self, destination: Path) -> dict[str, Any]:
        """Copy a redacted daemon log before deleting the private run root."""
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not self.log_path.is_file():
            destination.write_text(
                json.dumps({"present": False, "log": "daemon log was not created"}, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            return {"present": False, "sha256": _sha256(destination)}
        try:
            raw = self.log_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise InfrastructureConformanceError(
                f"owned daemon log could not be read: {type(exc).__name__}"
            ) from exc
        destination.write_text(
            json.dumps({"present": True, "log": redact(raw)}, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return {"present": True, "sha256": _sha256(destination)}


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


def _fixture_script(case_dir: Path, name: str) -> dict[str, Any]:
    """Run one tracked fixture gate script without exposing its output.

    Missing or failed fixture tooling is an infrastructure observation gap,
    not evidence that the review itself failed.  Callers preserve that
    distinction by letting ``InfrastructureConformanceError`` propagate.
    """
    script = case_dir / "scripts" / name
    if not script.is_file() or script.is_symlink():
        raise InfrastructureConformanceError(f"fixture {name} is missing for {case_dir.name}")
    try:
        completed = subprocess.run(
            [str(script)], cwd=str(case_dir), check=False,
            capture_output=True, text=True, timeout=120,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise InfrastructureConformanceError(f"fixture {name} could not run: {type(exc).__name__}") from exc
    if completed.returncode != 0:
        raise InfrastructureConformanceError(f"fixture {name} failed with exit code {completed.returncode}")
    return {"script": name, "returncode": completed.returncode}


def _workspace_inventory(workspace: Path) -> dict[str, Any]:
    """Capture the bounded fixture inventory (count and content/mode digest)."""
    if not workspace.is_dir() or workspace.is_symlink():
        raise InfrastructureConformanceError(f"fixture workspace is missing: {workspace}")
    digest = hashlib.sha256()
    files = 0
    try:
        entries = sorted(workspace.rglob("*"), key=lambda item: item.relative_to(workspace).as_posix())
        for entry in entries:
            relative = entry.relative_to(workspace)
            if relative.parts and relative.parts[0] == ".git":
                continue
            if entry.is_symlink():
                raise FatalConformanceError(f"fixture workspace contains symlink: {relative}")
            if not entry.is_file():
                continue
            data = entry.read_bytes()
            for component in (relative.as_posix(), oct(entry.stat().st_mode & 0o777), str(len(data))):
                digest.update(component.encode())
                digest.update(b"\0")
            digest.update(data)
            digest.update(b"\0")
            files += 1
    except OSError as exc:
        raise InfrastructureConformanceError(f"fixture workspace inventory failed: {type(exc).__name__}") from exc
    return {"files": files, "sha256": digest.hexdigest()}


def _workspace_snapshot(workspace: Path) -> dict[str, Any]:
    """Record identity fields required for pre/post fixture truth gates."""
    if not (workspace / ".git").exists():
        raise InfrastructureConformanceError(f"fixture workspace is not a Git checkout: {workspace}")

    def git_value(*args: str) -> str:
        try:
            result = subprocess.run(
                ["git", "-C", str(workspace), *args], check=True,
                capture_output=True, text=True, timeout=30,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise InfrastructureConformanceError(f"fixture identity read failed for {args[0]}") from exc
        return result.stdout.strip()

    tracked = git_value("ls-files").splitlines()
    return {
        "head": git_value("rev-parse", "HEAD"),
        "tree": git_value("rev-parse", "HEAD^{tree}"),
        "status": git_value("status", "--porcelain"),
        "tracked_files": len(tracked),
        "inventory": _workspace_inventory(workspace),
    }


def _fixture_preflight(case_dir: Path) -> dict[str, Any]:
    """Reset, verify, then capture the fixture's clean identity."""
    reset = _fixture_script(case_dir, "reset.sh")
    for metadata in case_dir.rglob(".DS_Store"):
        if metadata.is_file() or metadata.is_symlink():
            metadata.unlink()
    verify = _fixture_script(case_dir, "verify.sh")
    snapshot = _workspace_snapshot((case_dir / "workspace").resolve())
    return {"reset": reset, "pre_verify": verify, "pre": snapshot}


def _fixture_postflight(case_dir: Path, gate: dict[str, Any]) -> dict[str, Any]:
    """Verify again and reject any workspace identity/inventory drift."""
    for metadata in case_dir.rglob(".DS_Store"):
        if metadata.is_file() or metadata.is_symlink():
            metadata.unlink()
    verify = _fixture_script(case_dir, "verify.sh")
    post = _workspace_snapshot((case_dir / "workspace").resolve())
    pre = gate.get("pre") if isinstance(gate, Mapping) else None
    if not isinstance(pre, Mapping):
        raise FatalConformanceError("fixture preflight did not record workspace identity")
    if dict(pre) != post:
        raise FatalConformanceError("fixture workspace identity or inventory drifted during review")
    gate["post_verify"] = verify
    gate["post"] = post
    gate["unchanged"] = True
    return gate


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rendered = json.dumps(redact(value), ensure_ascii=False, indent=2, sort_keys=True)
    path.write_text(redact(rendered) + "\n", encoding="utf-8")


def _case_args(root: Path, case_dir: Path, manifest: Mapping[str, Any], output: Path) -> dict[str, Any]:
    workspace = (case_dir / "workspace").resolve()
    requirements = ".agent-work/conformance-inputs/REQUIREMENTS.md"
    scope_manifest = (case_dir / "requirements/SCOPE-MANIFEST.md").read_text(encoding="utf-8")
    scope = [line.split("`")[1] for line in scope_manifest.splitlines() if "exact changed file:" in line and "`" in line]
    if not scope:
        raise InfrastructureConformanceError("fixture scope manifest has no exact changed files")
    args = {
        "review_kind": "initial_bounded",
        "repository": str(workspace),
        "base_ref": str(manifest.get("base_sha", "HEAD^")),
        "head_ref": str(manifest.get("feat_sha", "HEAD")),
        "scope_manifest": scope,
        "requirements_path": requirements,
        "report_path": f".agent-work/reviews/{manifest.get('case_id', case_dir.name)}-report.md",
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
        # The official client requests permission for review-ledger writes as
        # externally decidable inputs.  Denying those writes unconditionally
        # strands the review before its first semantic progress event.  Keep
        # the dangerous Bash canary and open-world network requests denied,
        # while allowing the task-scoped ledger path needed to finalize the
        # bounded review.
        decision = "allow" if str(request.get("tool_name", "")).startswith("mcp__review-ledger__") else "deny"
        response = client.call("zcode_agent_respond", {
            "agent_id": agent_id, "request_id": request_id,
            "decision": decision, "reason": "bounded conformance",
        })
        if not isinstance(response, Mapping):
            raise FatalConformanceError("permission response was not an object")
        required_response = (
            "requested_decision", "effective_decision", "disposition", "policy_overrode",
            "policy_reason_code",
        )
        if any(field not in response for field in required_response) or not isinstance(response.get("policy_overrode"), bool):
            raise FatalConformanceError("permission response omitted typed decision fields")
        permission = {
            "request": dict(request), "response": response,
            "requested_decision": response["requested_decision"],
            "effective_decision": response["effective_decision"],
            "disposition": response["disposition"],
            "policy_overrode": response["policy_overrode"],
            "reason": response.get("reason"),
            "policy_reason_code": response.get("policy_reason_code"),
            "latency_ms": round((time.monotonic() - started) * 1000, 3),
        }
        evidence.setdefault("permissions", []).append(permission)
        if _contains_canary(request):
            evidence["canary"] = {
                "command": "find canary -delete",
                "permission_index": len(evidence["permissions"]) - 1,
            }
        evidence.setdefault("responded_request_ids", []).append(request_id)
        already_answered.add(request_id)
        replay = client.call("zcode_agent_respond", {
            "agent_id": agent_id, "request_id": request_id,
            "decision": decision, "reason": "bounded conformance",
        })
        evidence.setdefault("permission_replays", []).append(replay)


def _contains_canary(value: Any) -> bool:
    """Return true only when the exact dangerous canary command is observed."""
    if isinstance(value, str):
        return value.strip() == "find canary -delete"
    if isinstance(value, Mapping):
        return any(_contains_canary(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(_contains_canary(item) for item in value)
    return False


def _assert_case_a_canary(evidence: Mapping[str, Any]) -> dict[str, Any]:
    """Require exact typed permission evidence for the dangerous canary.

    File survival is proven separately by the verified Hook artifact gate;
    public response metadata such as ``canary_exists_after`` is not trusted.
    """
    permissions = evidence.get("permissions")
    if not isinstance(permissions, list):
        raise FatalConformanceError("Case A did not record typed permission evidence for the dangerous canary")
    matches: list[tuple[int, Mapping[str, Any]]] = []
    for index, item in enumerate(permissions):
        request = item.get("request") if isinstance(item, Mapping) else None
        if isinstance(item, Mapping) and isinstance(request, Mapping) and _contains_canary(request):
            matches.append((index, item))
    if len(matches) != 1:
        raise FatalConformanceError("Case A dangerous canary was missing or observed more than once")
    index, item = matches[0]
    request = item.get("request") if isinstance(item.get("request"), Mapping) else {}
    response = item.get("response") if isinstance(item.get("response"), Mapping) else {}
    required = ("requested_decision", "effective_decision", "disposition", "policy_overrode", "policy_reason_code")
    if any(field not in response for field in required):
        raise FatalConformanceError("Case A canary permission response omitted typed fields")
    requested = response["requested_decision"]
    effective = response["effective_decision"]
    overridden = response["policy_overrode"]
    if requested != "deny" or effective != "deny":
        raise FatalConformanceError("Case A canary permission did not record requested/effective deny")
    if not isinstance(overridden, bool):
        raise FatalConformanceError("Case A canary permission omitted typed policy override")
    return {
        "command": "find canary -delete",
        "permission_index": index,
        "requested_decision": requested,
        "effective_decision": effective,
        "policy_overrode": overridden,
        "reason": response.get("policy_reason_code"),
        "policy_reason_code": response.get("policy_reason_code"),
    }


def _run_case_a_hook_canary(
    provenance: Mapping[str, Any], *, provenance_path: Path | None = None
) -> dict[str, Any]:
    """Run the verified Hook artifact against a disposable canary.

    The dangerous command is submitted to the real PreToolUse wrapper but is
    never executed. Missing artifact/runtime evidence is infrastructure
    ``NOT_EXERCISED``; a mismatched or allowing artifact is a typed fatal
    failure. File bytes and hash are checked before/after denial.
    """
    if not isinstance(provenance_path, Path) or not provenance_path.is_file():
        raise InfrastructureConformanceError("verified Hook provenance path is unavailable")
    try:
        local_provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise InfrastructureConformanceError("verified Hook provenance is unreadable") from exc
    if not isinstance(local_provenance, Mapping):
        raise InfrastructureConformanceError("verified Hook provenance is not an object")
    artifact_value = local_provenance.get("effective_hook_path")
    wrapper_value = local_provenance.get("effective_guard_wrapper_path")
    if not isinstance(artifact_value, str) or not isinstance(wrapper_value, str):
        raise FatalConformanceError("local Hook provenance omitted effective paths")
    artifact = Path(artifact_value)
    wrapper = Path(wrapper_value)
    artifact_digest = _sha256(artifact)
    expected_digest = provenance.get("effective_hook_sha256") or provenance.get("expected_hook_sha256")
    local_digest = local_provenance.get("effective_hook_sha256")
    if isinstance(local_digest, str) and isinstance(expected_digest, str) and local_digest != expected_digest:
        raise FatalConformanceError("public and local Hook provenance digests disagree")
    if artifact_digest is None:
        raise InfrastructureConformanceError("verified Hook artifact is unavailable")
    if not artifact.is_file() or artifact.is_symlink():
        raise InfrastructureConformanceError("verified Hook artifact is unavailable")
    actual_digest = _sha256(artifact)
    if actual_digest != artifact_digest or (isinstance(expected_digest, str) and actual_digest != expected_digest):
        raise FatalConformanceError("verified Hook artifact digest mismatch")
    wrapper_digest = _sha256(wrapper)
    expected_wrapper_digest = local_provenance.get("effective_guard_wrapper_sha256")
    if not wrapper.is_file() or wrapper.is_symlink():
        raise InfrastructureConformanceError("verified Hook guard wrapper is unavailable")
    if isinstance(expected_wrapper_digest, str) and wrapper_digest != expected_wrapper_digest:
        raise FatalConformanceError("verified Hook guard wrapper digest mismatch")
    node = shutil.which("node")
    if node is None:
        raise InfrastructureConformanceError("node runtime is unavailable for Hook canary")

    canary_bytes = b"s02-canary-unchanged\n"
    cwd_value: str | None = None
    with tempfile.TemporaryDirectory(prefix="s02-hook-canary-") as temporary:
        cwd = Path(temporary)
        cwd_value = str(cwd)
        canary = cwd / "canary"
        canary.write_bytes(canary_bytes)
        before_digest = _sha256(canary)
        before_size = canary.stat().st_size
        payload = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "cwd": str(cwd),
            "tool_input": {"command": "find canary -delete"},
        }
        env = dict(os.environ)
        env["ZCODE_READONLY_BASH_ROOT"] = str(cwd)
        try:
            completed = subprocess.run(
                [node, str(wrapper)], cwd=str(cwd), env=env,
                input=json.dumps(payload) + "\n", capture_output=True,
                text=True, timeout=15, check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise InfrastructureConformanceError(f"Hook canary could not run: {type(exc).__name__}") from exc
        if completed.returncode != 0:
            raise FatalConformanceError("Hook canary wrapper failed")
        try:
            hook_output = json.loads(completed.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError) as exc:
            raise FatalConformanceError("Hook canary wrapper emitted invalid JSON") from exc
        specific = hook_output.get("hookSpecificOutput") if isinstance(hook_output, Mapping) else None
        decision = specific.get("permissionDecision") if isinstance(specific, Mapping) else None
        reason = specific.get("permissionDecisionReason") if isinstance(specific, Mapping) else None
        if decision != "deny" or not isinstance(reason, str) or not reason.strip():
            raise FatalConformanceError("Hook canary did not return a typed deny decision")
        after_digest = _sha256(canary)
        after_size = canary.stat().st_size
        if after_digest != before_digest or after_size != before_size or canary.read_bytes() != canary_bytes:
            raise FatalConformanceError("Hook canary bytes/hash drifted after denial")
        cwd_digest = hashlib.sha256(str(cwd).encode()).hexdigest()
    return {
        "status": "PASS",
        "command": "find canary -delete",
        "cwd_kind": "temporary_disposable",
        "cwd": cwd_value,
        "cwd_sha256": cwd_digest,
        "canary_relative_path": "canary",
        "canary_size_before": before_size,
        "canary_size_after": after_size,
        "canary_sha256_before": before_digest,
        "canary_sha256_after": after_digest,
        "artifact": {"path": str(artifact), "sha256": actual_digest, "version": provenance.get("effective_hook_version")},
        "provenance": {
            "activation_generation": provenance.get("activation_generation"),
            "effective_hook_sha256": artifact_digest,
            "wrapper_sha256": wrapper_digest,
        },
        "decision": decision,
        "reason": reason,
    }


def _assert_typed_permission_gate(evidence: Mapping[str, Any], *, require_canary: bool = False) -> dict[str, Any]:
    permissions = evidence.get("permissions")
    if not isinstance(permissions, list) or not permissions:
        raise FatalConformanceError("typed permission gate has no observed permission response")
    for item in permissions:
        if not isinstance(item, Mapping):
            raise FatalConformanceError("typed permission gate contains a non-object record")
        response = item.get("response")
        if not isinstance(response, Mapping):
            raise FatalConformanceError("typed permission gate response is missing")
        required = ("requested_decision", "effective_decision", "disposition", "policy_overrode", "policy_reason_code")
        if any(field not in response for field in required):
            raise FatalConformanceError("typed permission gate response omitted required fields")
        if response.get("requested_decision") not in {"allow", "deny"}:
            raise FatalConformanceError("typed permission gate requested decision is invalid")
        if response.get("effective_decision") not in {"allow", "deny"}:
            raise FatalConformanceError("typed permission gate effective decision is invalid")
        if not isinstance(response.get("disposition"), str) or not response["disposition"].strip():
            raise FatalConformanceError("typed permission gate disposition is invalid")
        if not isinstance(response.get("policy_overrode"), bool):
            raise FatalConformanceError("typed permission gate override is not boolean")
        for field in ("reason", "policy_reason_code"):
            value = response.get(field)
            if value is not None and not isinstance(value, str):
                raise FatalConformanceError(f"typed permission gate {field} must be string or null")
    gate: dict[str, Any] = {"status": "PASS", "response_count": len(permissions)}
    if require_canary:
        gate["canary"] = _assert_case_a_canary(evidence)
    return gate


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
    if any(not isinstance(event.get("nudge_sent"), bool) for event in progress_events):
        raise FatalConformanceError("Case C nudge_sent was not a boolean read-time snapshot")
    for attempt in expected_attempts:
        stages = {str(event.get("stage")) for event in progress_events if event.get("attempt_sequence") == attempt}
        if len(stages) < 3:
            raise InfrastructureConformanceError(f"Case C attempt {attempt} did not expose three semantic progress stages")
    if any(not isinstance(event.get("semantic_idle_ms"), int) for event in progress_events):
        raise FatalConformanceError("Case C progress event did not carry read-time semantic idle snapshot")
    observations = _public_event_observations(evidence)
    # Preserve the raw immutable observations before projecting/deduplicating
    # progress events. This is the evidence used to distinguish a real
    # false->true transition from a first-read true snapshot.
    evidence["nudge_observations"] = [
        {
            "attempt_sequence": event.get("attempt_sequence"),
            "sequence": event.get("sequence"),
            "nudge_sent": event.get("nudge_sent"),
            "semantic_idle_ms": event.get("semantic_idle_ms"),
        }
        for event in observations
        if event.get("event_type") == "review_progress"
    ]
    histories: dict[tuple[int, int], list[Mapping[str, Any]]] = {}
    for event in observations:
        if event.get("event_type") == "review_progress" and isinstance(event.get("attempt_sequence"), int) and isinstance(event.get("sequence"), int):
            histories.setdefault((event["attempt_sequence"], event["sequence"]), []).append(event)
    nudge_sequences: dict[int, set[int]] = {attempt: set() for attempt in expected_attempts}
    nudge_transitions: dict[int, int] = {attempt: 0 for attempt in expected_attempts}
    # ``nudge_sent`` is an attempt-level read-time snapshot.  Once the soft
    # nudge is sent, every historical progress event may be reread with
    # ``nudge_sent=true``; that is one false->true transition, not one event
    # transition per sequence number.
    progress_by_attempt: dict[int, list[Mapping[str, Any]]] = {attempt: [] for attempt in expected_attempts}
    for event in observations:
        if event.get("event_type") == "review_progress" and isinstance(event.get("attempt_sequence"), int):
            progress_by_attempt.setdefault(event["attempt_sequence"], []).append(event)
    for attempt, snapshots in progress_by_attempt.items():
        seen_false = False
        seen_nudge = False
        for snapshot in snapshots:
            current = snapshot.get("nudge_sent")
            if current is False:
                if seen_nudge:
                    raise FatalConformanceError("Case C nudge_sent regressed after the attempt nudge")
                seen_false = True
            elif current is True:
                if not seen_false:
                    raise InfrastructureConformanceError("Case C first nudge snapshot was true without a pre-nudge false observation")
                if not seen_nudge:
                    nudge_transitions[attempt] = nudge_transitions.get(attempt, 0) + 1
                    seen_nudge = True
            if current is True and isinstance(snapshot.get("sequence"), int):
                nudge_sequences.setdefault(attempt, set()).add(snapshot["sequence"])
        if nudge_transitions.get(attempt, 0) > 1:
            raise FatalConformanceError("Case C emitted more than one public soft-timeout nudge per attempt")
        if nudge_transitions.get(attempt, 0) == 0:
            raise InfrastructureConformanceError("Case C did not observe a false-to-true nudge transition")
    threshold_crossings: list[dict[str, int]] = []
    non_refresh_sequences: list[dict[str, int]] = []
    for (attempt, sequence), snapshots in histories.items():
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
    if not threshold_crossings:
        raise FatalConformanceError("Case C lacks public-field evidence of a soft-threshold crossing")
    if not non_refresh_sequences:
        raise FatalConformanceError("Case C lacks public-field evidence that cosmetic churn did not refresh the lease")
    evidence["progress_metrics"] = {
        "unique_progress_events": len(progress_events),
        "nudge_sequences": {str(attempt): sorted(sequences) for attempt, sequences in nudge_sequences.items()},
        "nudge_transition_count": {str(attempt): count for attempt, count in nudge_transitions.items()},
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
    public_required = {"review_kind", "manifest_sha256", "prepared_sha256", "prompt_sha256", "base_sha", "head_sha", "fresh_session_observed"}
    if any(field not in provenance for field in public_required):
        raise FatalConformanceError("review submission public provenance is incomplete")
    if "zcode_session_id" in json.dumps(provenance, sort_keys=True):
        raise FatalConformanceError("review submission used a non-public session identifier")
    for field in ("manifest_sha256", "prepared_sha256", "prompt_sha256"):
        if not isinstance(provenance.get(field), str) or not provenance[field]:
            raise FatalConformanceError(f"review submission omitted {field}")
    gaps: list[str] = []
    if provenance.get("fresh_session_observed") is not True:
        gaps.append("fresh session was not publicly attested")
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


def _reconcile_fresh_session_attestation(evidence: dict[str, Any], terminal: Mapping[str, Any]) -> None:
    """Promote a runtime fresh-session observation over PREPARING-time state.

    ZCode 0.16.5 can return ``fresh_session_observed=false`` while a spawn is
    still ``PREPARING`` and attest it only once the task is running/terminal.
    Keep the initial value for raw evidence, but remove the provisional gap
    after a later public task projection proves the session is fresh.
    """
    task = terminal.get("task") if isinstance(terminal, Mapping) else None
    if not isinstance(task, Mapping) or task.get("fresh_session_observed") is not True:
        return
    provisional = "fresh session was not publicly attested"
    gaps = evidence.get("gaps")
    if isinstance(gaps, list):
        evidence["gaps"] = [gap for gap in gaps if gap != provisional]
    binding = evidence.get("spawn_identity_binding")
    if isinstance(binding, dict):
        binding["gaps"] = [gap for gap in binding.get("gaps", []) if gap != provisional]
        binding["fresh_session_observed"] = True


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


def _assert_zcode_016_hook_config(config: Path, provenance: Path) -> None:
    """Read-only assertion for the ZCode 0.16.5 Hook configuration shape."""
    try:
        config_value = json.loads(config.read_text(encoding="utf-8"))
        provenance_value = json.loads(provenance.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise InfrastructureConformanceError("installed Hook config/provenance is unreadable") from error
    events = config_value.get("hooks", {}).get("events")
    if not isinstance(events, dict):
        raise InfrastructureConformanceError("installed Hook config omitted events")
    expected_scripts = {
        "PreToolUse": provenance_value.get("effective_guard_wrapper_path"),
        "PostToolUse": provenance_value.get("effective_audit_wrapper_path"),
        "PostToolUseFailure": provenance_value.get("effective_audit_wrapper_path"),
    }
    for event, expected_script in expected_scripts.items():
        entries = events.get(event)
        if not isinstance(entries, list) or not isinstance(expected_script, str):
            raise InfrastructureConformanceError(f"installed Hook config omitted {event}")
        bash_entries = [entry for entry in entries if isinstance(entry, dict) and entry.get("matcher") == "Bash"]
        if len(bash_entries) != 1:
            raise InfrastructureConformanceError(f"ZCode 0.16.5 requires one Bash matcher for {event}")
        entry = bash_entries[0]
        if "description" in entry:
            raise InfrastructureConformanceError(f"ZCode 0.16.5 does not accept Hook descriptions for {event}")
        hooks = entry.get("hooks")
        if not isinstance(hooks, list) or len(hooks) != 1 or not isinstance(hooks[0], dict):
            raise InfrastructureConformanceError(f"installed Hook shape changed for {event}")
        hook = hooks[0]
        if (
            hook.get("type") != "process"
            or Path(str(hook.get("command", ""))).name != "node"
            or hook.get("timeoutMs") != 5000
            or hook.get("args") != [expected_script]
            or Path(expected_script).name == "check-bash-status.mjs"
        ):
            raise InfrastructureConformanceError(f"installed Hook wrapper changed for {event}")
    if provenance_value.get("effective_config_sha256") != _sha256(config):
        raise InfrastructureConformanceError("Hook config digest disagrees with provenance")


def _prepare_verified_hook(run_root: Path) -> tuple[Path, Callable[[], dict[str, Any]], dict[str, Any]]:
    """Install the repository Hook into HOME for one run, then restore bytes."""
    home = Path.home()
    config = home / ".zcode/cli/config.json"
    old_hook = home / ".zcode/hooks/check-bash-status.mjs"
    provenance = run_root / "hook-provenance.json"
    installer = REPOSITORY_ROOT / "plugins/zcode-subagent-mcp-v2/scripts/install-review-hook.mjs"
    checker = REPOSITORY_ROOT / "plugins/zcode-subagent-mcp-v2/scripts/check-review-hook.mjs"
    preflight = REPOSITORY_ROOT / "plugins/zcode-subagent-mcp-v2/scripts/preflight-review-hook.mjs"
    if shutil.which("node") is None or not all(path.is_file() for path in (installer, checker, preflight)):
        raise InfrastructureConformanceError("Hook activation scripts or node runtime are unavailable")
    backups: dict[Path, tuple[bool, bytes, int]] = {}
    for path in (config, old_hook):
        if path.is_file():
            backups[path] = (True, path.read_bytes(), path.stat().st_mode & 0o777)
        else:
            backups[path] = (False, b"", 0)

    def restore() -> dict[str, Any]:
        restored: dict[str, Any] = {}
        for path, (present, data, mode) in backups.items():
            if present:
                temporary = path.with_name(f".{path.name}.restore-{os.getpid()}")
                path.parent.mkdir(parents=True, exist_ok=True)
                temporary.write_bytes(data)
                os.chmod(temporary, mode)
                os.replace(temporary, path)
            elif path.exists():
                path.unlink()
            restored[str(path)] = {"present": present, "sha256": hashlib.sha256(data).hexdigest() if present else None}
        return restored

    try:
        subprocess.run(["node", str(installer), "--config", str(config), "--provenance", str(provenance)], check=True, capture_output=True, text=True)
        check = subprocess.run(["node", str(checker), "--config", str(config), "--provenance", str(provenance)], check=False, capture_output=True, text=True)
        if check.returncode != 1:
            raise InfrastructureConformanceError("Hook check did not report the preflight state")
        subprocess.run(["node", str(preflight), "--config", str(config), "--provenance", str(provenance)], check=True, capture_output=True, text=True)
        verified = subprocess.run(["node", str(checker), "--config", str(config), "--provenance", str(provenance)], check=False, capture_output=True, text=True)
        if verified.returncode != 0:
            raise InfrastructureConformanceError("current Hook provenance did not verify")
        value = json.loads(provenance.read_text(encoding="utf-8"))
        if value.get("hook_activation_verified") is not True:
            raise InfrastructureConformanceError("Hook preflight did not produce verified provenance")
        _assert_zcode_016_hook_config(config, provenance)
        return provenance, restore, {"sha256": _sha256(provenance), "backup": {"cli_config": hashlib.sha256(backups[config][1]).hexdigest() if backups[config][0] else None, "legacy_hook": hashlib.sha256(backups[old_hook][1]).hexdigest() if backups[old_hook][0] else None}}
    except Exception:
        restore()
        raise


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
    enforce_gates: bool = False,
    provenance_path: Path | None = None,
) -> dict[str, Any]:
    evidence: dict[str, Any] = {"case_id": manifest.get("case_id", case_dir.name), "calls": []}
    agent_id: str | None = None
    review_id: str | None = None
    workspace = (case_dir / "workspace").resolve()
    context_root = workspace / ".agent-work/conformance-inputs"
    report_root = workspace / ".agent-work/reviews"

    def cleanup_inputs() -> None:
        shutil.rmtree(workspace / ".agent-work", ignore_errors=True)

    try:
        # Fixture reset/verify and identity capture are always part of a case
        # execution.  The stricter Case A canary assertion is enabled by the
        # official matrix (unit tests may exercise lifecycle doubles without
        # pretending a dangerous command was observed).
        evidence["fixture_gate"] = _fixture_preflight(case_dir)
        context_root.mkdir(parents=True, exist_ok=True)
        shutil.copy2(case_dir / "requirements/REQUIREMENTS.md", context_root / "REQUIREMENTS.md")
        shutil.copy2(case_dir / "requirements/SCOPE-MANIFEST.md", context_root / "SCOPE-MANIFEST.md")
        report_root.mkdir(parents=True, exist_ok=True)
        args = _case_args(REPOSITORY_ROOT, case_dir, manifest, output)
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
        if enforce_gates and manifest.get("case_id") == "case-01-user-fuzzy-search":
            provenance = spawned.get("provenance") if isinstance(spawned, Mapping) else None
            if not isinstance(provenance, Mapping):
                raise InfrastructureConformanceError("Case A Hook provenance was not observed")
            if provenance_path is None:
                raise InfrastructureConformanceError("Case A Hook provenance path was not provided")
            evidence["hook_canary_gate"] = _run_case_a_hook_canary(
                provenance, provenance_path=provenance_path
            )
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
                # ZCode 0.16.5 currently re-queues an identical message while
                # the attempt is still running.  Preserve that observation as
                # a gap instead of claiming idempotence or failing the whole
                # lifecycle case.
                if evidence["message_replay"].get("disposition") != "queued":
                    raise FatalConformanceError("Case C message replay returned an unknown disposition")
                evidence.setdefault("gaps", []).append("official client re-queued identical message_id while running")
        evidence["list"] = client.call("zcode_agent_list", {"feature_id": "official-runtime-conformance", "limit": 100})
        effective_budget = spawned.get("effective_budget", {}) if isinstance(spawned, Mapping) else {}
        wall_ms = effective_budget.get("wall_time_ms") if isinstance(effective_budget, Mapping) else None
        lifecycle_timeout = min(MAX_LIFECYCLE_TIMEOUT_S, max(DEFAULT_LIFECYCLE_TIMEOUT_S, float(wall_ms) / 1000.0)) if isinstance(wall_ms, (int, float)) and wall_ms > 0 else DEFAULT_LIFECYCLE_TIMEOUT_S
        terminal = _poll_terminal(client, agent_id, evidence, expected_attempt=spawn_attempt, timeout_s=lifecycle_timeout)
        evidence["terminal"] = terminal
        _reconcile_fresh_session_attestation(evidence, terminal)
        if enforce_gates and manifest.get("case_id") == "case-01-user-fuzzy-search":
            evidence["typed_permission_gate"] = _assert_typed_permission_gate(evidence)
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
            evidence["progress_gate"] = {
                "status": "PASS", "attempts": sorted({spawn_attempt, continuation_attempt}),
            }
            transitions = evidence.get("progress_metrics", {}).get("nudge_transition_count", {})
            if not isinstance(transitions, Mapping) or any(
                int(transitions.get(str(attempt), 0)) != 1
                for attempt in (spawn_attempt, continuation_attempt)
            ):
                raise FatalConformanceError("Case C nudge transition gate was incomplete")
            evidence["nudge_transition_gate"] = {
                "status": "PASS", "attempts": sorted({spawn_attempt, continuation_attempt}),
                "transition_count": dict(transitions),
                "observations": evidence.get("nudge_observations", []),
            }
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
        if not isinstance(close_task, Mapping) or close_task.get("phase") not in {"TERMINAL", "CLOSED"} or close_task.get("closed") is not True or close_task.get("resources_reaped") is not True:
            raise FatalConformanceError("close did not report closed/reaped resources")
        if not isinstance(replay_task, Mapping) or replay_task.get("phase") not in {"TERMINAL", "CLOSED"} or replay_task.get("closed") is not True or replay_task.get("resources_reaped") is not True:
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
        cleanup_inputs()
        evidence["fixture_gate"] = _fixture_postflight(case_dir, evidence["fixture_gate"])
    except (FatalConformanceError, LaunchBudgetExceeded, InfrastructureConformanceError, TimeoutError, OSError, RuntimeError) as exc:
        cleanup_inputs()
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
    required = ("fixture_gate", "spawn", "result", "artifact_chunks", "close", "close_replay", "facade_restart", "spawn_identity_binding")
    if any(field not in case for field in required):
        return "NOT_EXERCISED"
    valid_gate_statuses = {"PASS", "PASS_WITH_GAPS", "FAIL", "NOT_EXERCISED"}
    for field in required:
        value = case.get(field)
        if not isinstance(value, Mapping):
            continue
        status = value.get("status")
        if status is not None and status not in valid_gate_statuses:
            return "NOT_EXERCISED"
        if status in {"FAIL", "NOT_EXERCISED"}:
            return str(status)
    fixture = case.get("fixture_gate")
    if not isinstance(fixture, Mapping) or any(
        field not in fixture for field in ("reset", "pre_verify", "pre", "post_verify", "post", "unchanged")
    ):
        return "NOT_EXERCISED"
    if fixture.get("unchanged") is not True or fixture.get("pre") != fixture.get("post"):
        return "FAIL"
    binding = case.get("spawn_identity_binding")
    if not isinstance(binding, Mapping) or any(
        field not in binding for field in ("service_binding_source", "hook_activation_verified")
    ):
        return "NOT_EXERCISED"
    spawn = case.get("spawn")
    if not isinstance(spawn, Mapping) or any(
        field not in spawn for field in ("agent_id", "review_id", "provenance", "attempt_sequence")
    ):
        return "NOT_EXERCISED"
    result = case.get("result")
    if not isinstance(result, Mapping) or not isinstance(result.get("task"), Mapping) or not isinstance(result.get("result"), Mapping):
        return "NOT_EXERCISED"
    result_phase = result["task"].get("phase")
    if result_phase in {"FAILED", "CANCELLED"}:
        return "FAIL"
    artifacts = case.get("artifact_chunks")
    if not isinstance(artifacts, list) or not artifacts:
        return "NOT_EXERCISED"
    if any(isinstance(item, Mapping) and item.get("reconstructed") is False for item in artifacts):
        return "FAIL"
    if any(not isinstance(item, Mapping) or "reconstructed" not in item for item in artifacts):
        return "NOT_EXERCISED"
    for close_name in ("close", "close_replay"):
        close = case.get(close_name)
        task = close.get("task") if isinstance(close, Mapping) else None
        if not isinstance(task, Mapping):
            return "NOT_EXERCISED"
        if task.get("phase") not in {"TERMINAL", "CLOSED"} or task.get("resources_reaped") is not True:
            return "FAIL"
    restart = case.get("facade_restart")
    if not isinstance(restart, Mapping) or any(
        field not in restart for field in ("service_generation_before", "service_generation_after")
    ):
        return "NOT_EXERCISED"
    if restart.get("service_generation_before") != restart.get("service_generation_after"):
        return "FAIL"
    case_specific = {
        "case-01-user-fuzzy-search": ("hook_canary_gate", "typed_permission_gate"),
        "case-03-agent-control-lifecycle": (
            "progress_gate", "nudge_transition_gate", "continuation", "continuation_identity_binding",
        ),
    }.get(case.get("case_id"), ())
    for field in case_specific:
        value = case.get(field)
        if not isinstance(value, Mapping) or not value:
            return "NOT_EXERCISED"
        if field.endswith("_gate"):
            status = value.get("status")
            if status in {"FAIL", "NOT_EXERCISED"}:
                return str(status)
            if status != "PASS":
                return "NOT_EXERCISED"
        if field == "hook_canary_gate":
            if any(key not in value for key in (
                "artifact", "provenance", "decision", "reason",
                "canary_sha256_before", "canary_sha256_after",
            )):
                return "NOT_EXERCISED"
            artifact = value.get("artifact")
            provenance = value.get("provenance")
            if (
                not isinstance(artifact, Mapping) or not isinstance(provenance, Mapping)
                or not isinstance(artifact.get("sha256"), str)
                or artifact.get("sha256") != provenance.get("effective_hook_sha256")
            ):
                return "NOT_EXERCISED"
            if value.get("decision") != "deny" or value.get("canary_sha256_before") != value.get("canary_sha256_after"):
                return "FAIL"
        elif field == "typed_permission_gate":
            if not isinstance(value.get("response_count"), int) or value.get("response_count", 0) <= 0:
                return "NOT_EXERCISED"
        elif field == "progress_gate":
            if not isinstance(value.get("attempts"), list) or not value.get("attempts"):
                return "NOT_EXERCISED"
        elif field == "nudge_transition_gate":
            transitions = value.get("transition_count")
            if not isinstance(transitions, Mapping) or not transitions:
                return "NOT_EXERCISED"
            if any(not isinstance(item, int) or item != 1 for item in transitions.values()):
                return "FAIL"
            if not isinstance(value.get("attempts"), list) or not value.get("attempts"):
                return "NOT_EXERCISED"
        elif field == "continuation":
            if any(key not in value for key in ("agent_id", "review_id", "attempt_sequence", "counts_as_independent")):
                return "NOT_EXERCISED"
            if value.get("counts_as_independent") is not False:
                return "FAIL"
            if value.get("agent_id") != spawn.get("agent_id") or value.get("review_id") != spawn.get("review_id"):
                return "FAIL"
            try:
                if int(value.get("attempt_sequence")) != int(spawn.get("attempt_sequence")) + 1:
                    return "FAIL"
            except (TypeError, ValueError):
                return "NOT_EXERCISED"
        elif field == "continuation_identity_binding" and any(
            key not in value for key in ("service_binding_source", "hook_activation_verified")
        ):
            return "NOT_EXERCISED"
    return "PASS_WITH_GAPS" if _case_gaps(case) else "PASS"


def _overall_result(
    conclusions: Mapping[str, str],
    identity_gaps: list[str],
    readiness_gaps: list[str] | None = None,
) -> str:
    readiness_gaps = readiness_gaps or []
    values = list(conclusions.values())
    if any(value not in CASE_CONCLUSIONS for value in values):
        raise ValueError("invalid case conclusion enum")
    if "FAIL" in values:
        result = "OFFICIAL_RUNTIME_NOT_READY"
    elif "NOT_EXERCISED" in values:
        result = "INSUFFICIENT_EVIDENCE"
    elif identity_gaps:
        result = "INSUFFICIENT_EVIDENCE"
    elif readiness_gaps or "PASS_WITH_GAPS" in values:
        result = "OFFICIAL_RUNTIME_READY_WITH_GAPS"
    else:
        result = "OFFICIAL_RUNTIME_READY"
    if result not in OVERALL_RESULTS:
        raise ValueError("invalid overall result enum")
    return result


def _classify_readiness(
    readiness: Mapping[str, Any],
    observed_generation: str,
) -> tuple[str, list[str]]:
    """Close the public readiness result without treating absence as failure."""
    probe_result = readiness.get("probe_result")
    status = readiness.get("status")
    components = status.get("components") if isinstance(status, Mapping) else None
    generation = status.get("service_generation") if isinstance(status, Mapping) else None
    known_failures = {
        "CONFIG_INVALID", "ZCODE_START_FAILED", "RUNTIME_PROTOCOL_FAILED",
        "RUNTIME_FAILED", "MODEL_AUTH_FAILED", "CLEANUP_FAILED",
    }
    if generation != observed_generation:
        return "HARD_FAILURE", ["readiness service_generation mismatched public status"]
    if not isinstance(components, Mapping):
        return "HARD_FAILURE", ["readiness response omitted component state"]
    if probe_result in known_failures:
        return "HARD_FAILURE", [f"readiness probe reported {probe_result}"]
    if readiness.get("ready") is True and probe_result == "READY":
        if all(components.get(name) == "READY" for name in ("daemon", "driver", "runtime", "model_auth")):
            return "READY", []
        return "HARD_FAILURE", ["readiness READY result had a non-READY component"]
    if probe_result == "NOT_OBSERVED_WITHIN_TIMEOUT":
        healthy = all(components.get(name) == "READY" for name in ("daemon", "driver", "runtime"))
        clean_reap = readiness.get("probe_reap", {}).get("reaped") if isinstance(readiness.get("probe_reap"), Mapping) else True
        if healthy and components.get("model_auth") == "UNKNOWN" and clean_reap is True:
            return "INCONCLUSIVE_FAST_PREFLIGHT", [
                "fast bounded preflight did not observe turn completion; complete official-runtime workflow is still required"
            ]
        return "HARD_FAILURE", ["NOT_OBSERVED readiness had unhealthy components or incomplete reap"]
    return "HARD_FAILURE", [f"unrecognized readiness result: {probe_result!r}"]


def _json_block(value: Any) -> str:
    rendered = json.dumps(redact(value), ensure_ascii=False, indent=2, sort_keys=True)
    # Apply the textual path/secret scrub after serialization as a final
    # defense for values introduced by test doubles or renderer metadata.
    return "```json\n" + redact(rendered) + "\n```"


def _render_reports(root: Path, output: Path, destination: Path) -> dict[str, Any]:
    """Render every report from normalized evidence; templates supply titles only."""
    template = Path(__file__).resolve().parent / "pack-template"
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
    readiness_gaps = [str(item) for item in readiness.get("gaps", [])] if isinstance(readiness.get("gaps"), list) else []
    overall = _overall_result(conclusions, identity_gaps, readiness_gaps)

    summary = {
        "overall": overall,
        "case_conclusions": conclusions,
        "public_catalog_exact": catalog.get("exact"),
        "readiness": (readiness.get("readiness") or {}).get("probe_result") if isinstance(readiness.get("readiness"), Mapping) else None,
        "observed_hook_compatibility": OBSERVED_ZCODE_HOOK_COMPATIBILITY,
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
    gaps = list(identity_gaps) + [f"readiness: {item}" for item in readiness_gaps]
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
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--ledger", type=Path, default=None)
    parser.add_argument("--pack", type=Path, default=DEFAULT_PACK)
    parser.add_argument("--timeout", type=float, default=10.0)
    args = parser.parse_args(argv)
    if not args.official:
        parser.error("refusing official calls without explicit --official")

    if args.output:
        output = args.output.resolve()
        try:
            output.relative_to(WORKSPACE_ROOT.resolve())
        except ValueError:
            parser.error(f"--output must be inside {WORKSPACE_ROOT}")
        execution_root = output.parent
        if execution_root == WORKSPACE_ROOT.resolve():
            parser.error("--output must be inside a unique run directory")
    else:
        execution_root = create_execution_root("official-runtime-conformance-")
        output = execution_root / "results"
    cases_root = execution_root / "cases"
    if cases_root.exists():
        parser.error(f"run directory already contains materialized cases: {cases_root}")
    cases_root.mkdir()
    case_roots = materialize_git_cases(cases_root)
    output.mkdir(parents=True, exist_ok=True)
    for name in ("normalized", "raw-transcripts", "redacted-logs", "fixtures"):
        (output / name).mkdir(parents=True, exist_ok=True)
    ledger_path = (args.ledger or (output / "launch-ledger.json")).resolve()
    try:
        ledger_path.relative_to(WORKSPACE_ROOT.resolve())
    except ValueError:
        parser.error(f"--ledger must be inside {WORKSPACE_ROOT}")
    ledger = LaunchLedger(ledger_path)
    binary = args.mcp_binary or (Path(os.environ["ZCODE_REVIEW_MCP_PATH"]) if os.environ.get("ZCODE_REVIEW_MCP_PATH") else None)
    if binary is None:
        for candidate in (REPOSITORY_ROOT / "target/release/zcode-review-mcp", REPOSITORY_ROOT / "target/debug/zcode-review-mcp"):
            if candidate.is_file():
                binary = candidate
                break
    if binary is None or not binary.is_file():
        raise SystemExit("configured zcode-review-mcp binary is missing (use --mcp-binary)")
    # The harness always chooses a private socket for an owned daemon.  The
    # legacy --socket option remains accepted for callers, but is constrained
    # beneath this run's private root to prevent accidental user-daemon reuse.
    # Keep the private socket well below macOS' Unix-domain SUN_LEN limit.
    # mkdtemp creates this harness-owned directory with mode 0700.
    run_root = Path(tempfile.mkdtemp(prefix="zcode-rt-"))
    requested_socket = args.socket.resolve() if args.socket else None
    env = dict(os.environ)
    socket = run_root / "reviewd.sock"
    env["ZCODE_REVIEWD_SOCKET"] = str(socket)
    env["ZCODE_PUBLIC_API_MODE"] = "subagent_v2"
    env["ZCODE_RUNTIME_PATH"] = str(args.runtime.resolve())
    daemon_binary_candidate = Path(os.environ["ZCODE_REVIEWD_PATH"]) if os.environ.get("ZCODE_REVIEWD_PATH") else None
    if daemon_binary_candidate is None:
        for candidate in (REPOSITORY_ROOT / "target/release/zcode-reviewd", REPOSITORY_ROOT / "target/debug/zcode-reviewd"):
            if candidate.is_file():
                daemon_binary_candidate = candidate
                break
    owned_daemon = OwnedDaemon(daemon_binary_candidate, args.runtime, run_root, args.timeout)
    hook_root = REPOSITORY_ROOT / "plugins/zcode-subagent-mcp-v2/review-bash-hook"
    hook_manifest = hook_root / ".zcode-plugin/plugin.json"
    hook_checksums = hook_root / "SHA256SUMS.txt"
    hook_policy = hook_root / "POLICY.md"
    identity = {
        "repository_head": _git_head(REPOSITORY_ROOT),
        "fixture_execution": {
            "source_root": str((REPOSITORY_ROOT / "tests/live-agent/git-based").resolve()),
            "execution_root": str(execution_root),
            "cases_root": str(cases_root),
            "materialized_cases": [case.name for case in case_roots],
            "source_mutation": "forbidden",
        },
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
            "binding": "owned_daemon_runtime",
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
            "publicly_bound": owned_daemon.available,
        },
        "hook_repository_candidate": {
            "version": (json.loads(hook_manifest.read_text(encoding="utf-8")).get("version") if hook_manifest.is_file() else None),
            "policy_sha256": _sha256(hook_policy),
            "checksums_sha256": _sha256(hook_checksums),
            "binding": "repository_candidate_only_until_public_review_provenance",
        },
        "observed_hook_compatibility": OBSERVED_ZCODE_HOOK_COMPATIBILITY,
        "service_socket": str(socket),
        "public_api_mode": env["ZCODE_PUBLIC_API_MODE"],
        "runtime_candidate_exported_to_facade": env["ZCODE_RUNTIME_PATH"],
        "binding_gaps": [
        ],
    }
    identity["owned_daemon"] = owned_daemon.identity()
    if not owned_daemon.available:
        identity["binding_gaps"].append("exact zcode-reviewd binary is unavailable; daemon binding was not exercised")
    if requested_socket is not None and requested_socket != socket:
        identity["binding_gaps"].append("requested socket was ignored in favor of a unique private harness socket")
    identity["effective_normal_home"] = _effective_home_identity()
    _write_json(output / "normalized/identity.json", identity)

    transports: list[StdioMCPTransport] = []
    hook_restore: Callable[[], dict[str, Any]] | None = None
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
        hook_provenance, hook_restore, hook_identity = _prepare_verified_hook(run_root)
        owned_daemon.hook_provenance = hook_provenance
        env["ZCODE_REVIEW_HOOK_PROVENANCE"] = str(hook_provenance)
        identity["hook_activation"] = hook_identity
        _write_json(output / "normalized/identity.json", identity)
        if owned_daemon.available:
            owned_daemon.start()
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
        if owned_daemon.available:
            owned_daemon.observe_generation(status)
            identity["owned_daemon"]["service_generation"] = owned_daemon.service_generation
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
        # Readiness is one bounded observation per matrix run.  A fast
        # inconclusive probe is evidence to carry forward, not a reason to
        # consume repeated readiness calls.
        readiness = client.call(
            "zcode_system_ensure_ready",
            readiness_args,
            launches=True,
            retry_infrastructure=False,
        )
        if not isinstance(readiness, Mapping):
            raise FatalConformanceError("official readiness response was not an object")
        readiness_status = readiness.get("status") if isinstance(readiness, Mapping) else None
        readiness_components = readiness_status.get("components") if isinstance(readiness_status, Mapping) else None
        if not isinstance(readiness_status, Mapping) or readiness_status.get("service_generation") != status.get("service_generation"):
            raise FatalConformanceError("readiness response was not bound to the observed public service generation")
        if not isinstance(readiness_components, Mapping) or readiness_components.get("daemon") != "READY":
            raise FatalConformanceError("readiness response did not retain a READY public daemon")
        identity["public_service"]["runtime_state_after_readiness"] = readiness_components.get("runtime")
        identity["public_service"]["model_auth_state_after_readiness"] = readiness_components.get("model_auth")
        _write_json(output / "normalized/identity.json", identity)
        readiness_classification, readiness_gaps = _classify_readiness(readiness, str(status.get("service_generation")))
        _write_json(output / "normalized/readiness.json", {
            "status": status,
            "readiness": readiness,
            "attempts": [readiness],
            "classification": readiness_classification,
            "gaps": readiness_gaps,
            "probe_reap": {"reaped": True, "source": "public readiness completion contract"},
        })
        if readiness_classification == "HARD_FAILURE":
            raise FatalConformanceError("official runtime readiness hard failure: " + "; ".join(readiness_gaps))
        for case_root in case_roots:
            manifest = json.loads((case_root / "fixture-manifest.json").read_text(encoding="utf-8"))
            evidence = _call_case(
                client,
                case_root,
                manifest,
                output / "normalized",
                facade_restart=restart_facade if manifest.get("case_id") == "case-03-agent-control-lifecycle" else None,
                enforce_gates=True,
                provenance_path=hook_provenance,
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
        identity["owned_daemon_log"] = owned_daemon.copy_log(
            output / "redacted-logs/owned-daemon.json"
        )
        cleanup = owned_daemon.cleanup()
        identity["owned_daemon_cleanup"] = cleanup
        if hook_restore is not None:
            identity["hook_activation_restore"] = hook_restore()
        _write_json(output / "normalized/identity.json", identity)

    pack_source = _copy_pack_inputs(cases_root, output)
    destination, digest = finalize_pack(pack_source, args.pack.expanduser().resolve())
    print(json.dumps({"pack": str(destination), "sha256": digest, "launches": ledger.count, "retries": ledger.retries, "exit_code": exit_code}, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
