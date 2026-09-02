#!/usr/bin/env python3
"""Feasibility probe: one review prompt, MCP-owned polling, terminal result on stdout.

This intentionally does not use the matrix's event/progress oracle, message path,
continuation, or pack renderer.  The MCP facade is the observer and returns the
agent's terminal result to the caller; temporary review inputs are disposable.
The daemon-side mirror writes every runtime wire event (including reasoning
deltas and tool lifecycle updates) to a local JSONL analysis file.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any, Mapping

from conformance import PublicV2Client, StdioMCPTransport, _tool_payload
from fixture_workspace import GIT_BASED_ROOT, create_execution_root, materialize
from run_matrix import CASE_C_BUDGET, OwnedDaemon, REPOSITORY_ROOT, _case_args, _prepare_verified_hook, _sha256


RUNTIME = Path("/Applications/ZCode.app/Contents/Resources/glm/zcode.cjs")


def _binary(name: str, env_name: str) -> Path:
    configured = os.environ.get(env_name)
    if configured:
        return Path(configured).resolve()
    for profile in ("release", "debug"):
        candidate = REPOSITORY_ROOT / f"target/{profile}/{name}"
        if candidate.is_file():
            return candidate.resolve()
    raise RuntimeError(f"{name} is unavailable; set {env_name}")


def _scope(path: Path) -> list[str]:
    text = (path / "requirements/SCOPE-MANIFEST.md").read_text(encoding="utf-8")
    return [line.split("`")[1] for line in text.splitlines() if "exact changed file:" in line and "`" in line]


def _pending_permissions(client: PublicV2Client, agent_id: str, handled_ids: set[str]) -> int:
    state = client.call("zcode_agent_get", {"agent_id": agent_id})
    handled = 0
    for request in state.get("pending_requests", []) if isinstance(state, Mapping) else []:
        if not isinstance(request, Mapping) or request.get("respondable") is False:
            continue
        request_id = request.get("request_id")
        if not isinstance(request_id, str) or request_id in handled_ids:
            continue
        decision = "allow" if str(request.get("tool_name", "")).startswith("mcp__review-ledger__") else "deny"
        client.call("zcode_agent_respond", {
            "agent_id": agent_id,
            "request_id": request_id,
            "decision": decision,
            "reason": "poll-only feasibility probe",
        })
        handled_ids.add(request_id)
        handled += 1
    return handled


def _capture_summary(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"path": str(path), "exists": False}
    lines = 0
    with path.open("rb") as stream:
        for _ in stream:
            lines += 1
    return {
        "path": str(path),
        "exists": True,
        "lines": lines,
        "bytes": path.stat().st_size,
        "sha256": _sha256(path),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prompt", default=(
        "审查当前工作区的改动。只在开始接受这一条任务指令；不要主动汇报进度， "
        "不要发送状态消息。完成检查后，把最终审查结果作为你的最后回答并结束。"
    ))
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--lifecycle-timeout", type=float, default=900.0)
    parser.add_argument(
        "--capture",
        type=Path,
        default=None,
        help="Runtime event mirror path (default: timestamped file under tests/live-agent/workspace)",
    )
    args = parser.parse_args()

    source = GIT_BASED_ROOT / "case-03-agent-control-lifecycle"
    if not (source / "fixture-manifest.json").is_file():
        raise RuntimeError(f"fixture is unavailable: {source}")
    execution_root = create_execution_root("poll-only-case3-")
    case_dir = materialize(source, execution_root)
    workspace = case_dir / "workspace"
    input_root = workspace / ".agent-work/conformance-inputs"
    input_root.mkdir(parents=True)
    prompt_path = input_root / "REQUIREMENTS.md"
    original_requirements = (case_dir / "requirements/REQUIREMENTS.md").read_text(encoding="utf-8")
    prompt_path.write_text(original_requirements + "\n\n" + args.prompt + "\n", encoding="utf-8")
    manifest = json.loads((case_dir / "fixture-manifest.json").read_text(encoding="utf-8"))

    run_root = Path(tempfile.mkdtemp(prefix="zcode-poll-only-"))
    runtime = RUNTIME.resolve()
    capture_path = args.capture or (
        REPOSITORY_ROOT
        / "tests/live-agent/workspace"
        / f"case3-runtime-events-{time.strftime('%Y%m%d-%H%M%S')}.jsonl"
    )
    capture_path.parent.mkdir(parents=True, exist_ok=True)
    daemon = OwnedDaemon(_binary("zcode-reviewd", "ZCODE_REVIEWD_PATH"), runtime, run_root, args.timeout)
    mcp_binary = _binary("zcode-review-mcp", "ZCODE_REVIEW_MCP_PATH")
    transports: list[StdioMCPTransport] = []
    env = dict(os.environ)
    env.update({
        "ZCODE_REVIEWD_SOCKET": str(daemon.socket),
        "ZCODE_PUBLIC_API_MODE": "subagent_v2",
        "ZCODE_RUNTIME_PATH": str(runtime),
        "ZCODE_REVIEWD_DATABASE": str(daemon.database),
        "ZCODE_REVIEWD_ARTIFACT_ROOT": str(daemon.artifact_root),
        "ZCODE_REVIEWD_LOG_ROOT": str(daemon.log_root),
    })
    client: PublicV2Client | None = None
    agent_id: str | None = None
    hook_restore = None
    started = time.monotonic()
    previous_capture_env = os.environ.get("ZCODE_RUNTIME_EVENT_CAPTURE_PATH")
    try:
        # OwnedDaemon inherits the parent environment; the daemon-side sink reads this variable.
        os.environ["ZCODE_RUNTIME_EVENT_CAPTURE_PATH"] = str(capture_path)
        env["ZCODE_RUNTIME_EVENT_CAPTURE_PATH"] = str(capture_path)
        hook_provenance, hook_restore, _ = _prepare_verified_hook(run_root)
        daemon.hook_provenance = hook_provenance
        env["ZCODE_REVIEW_HOOK_PROVENANCE"] = str(hook_provenance)
        daemon.start()
        transport = StdioMCPTransport([str(mcp_binary)], env, timeout=args.timeout)
        transports.append(transport)
        client = PublicV2Client(transport)
        status = client.call("zcode_system_status", {})
        daemon.observe_generation(status)
        client.call("zcode_system_ensure_ready", {"timeout_ms": min(5000, int(args.timeout * 1000))})
        spawn_args = _case_args(REPOSITORY_ROOT, case_dir, manifest, execution_root / "results")
        # Feasibility probe: let the daemon apply its validated default budget.
        # The matrix's Case C budget is intentionally not part of this probe.
        spawn_args.pop("budget", None)
        raw_spawn = transport.call("zcode_review_spawn", spawn_args)
        if isinstance(raw_spawn, Mapping) and raw_spawn.get("isError"):
            print(json.dumps(raw_spawn, ensure_ascii=False, sort_keys=True), flush=True)
            raise RuntimeError("spawn rejected by MCP")
        spawn = _tool_payload(raw_spawn)
        agent_id = str(spawn["agent_id"])
        deadline = time.monotonic() + args.lifecycle_timeout
        polls = permission_responses = 0
        handled_permission_ids: set[str] = set()
        phase = "UNKNOWN"
        while time.monotonic() < deadline:
            permission_responses += _pending_permissions(client, agent_id, handled_permission_ids)
            waited = client.call("zcode_agent_wait", {
                "agent_id": agent_id, "after_sequence": 0, "timeout_ms": 1000,
            })
            polls += 1
            task = waited.get("task", {}) if isinstance(waited, Mapping) else {}
            phase = str(task.get("phase", "UNKNOWN")) if isinstance(task, Mapping) else "UNKNOWN"
            if phase in {"TERMINAL", "COMPLETED", "FAILED", "CANCELLED", "CLOSED"}:
                result = client.call("zcode_agent_result", {"agent_id": agent_id})
                print(json.dumps({
                    "mode": "single_prompt_mcp_polling",
                    "agent_id": agent_id,
                    "review_id": spawn.get("review_id"),
                    "phase": phase,
                    "result": result,
                    "polls": polls,
                    "permission_responses": permission_responses,
                    "elapsed_seconds": round(time.monotonic() - started, 3),
                    "runtime_event_capture": _capture_summary(capture_path),
                    "runtime": {"path": str(runtime), "sha256": _sha256(runtime)},
                    "mcp": {"path": str(mcp_binary), "sha256": _sha256(mcp_binary)},
                }, ensure_ascii=False, sort_keys=True))
                return 0
        raise TimeoutError(f"MCP polling deadline expired; last phase={phase}")
    finally:
        if previous_capture_env is None:
            os.environ.pop("ZCODE_RUNTIME_EVENT_CAPTURE_PATH", None)
        else:
            os.environ["ZCODE_RUNTIME_EVENT_CAPTURE_PATH"] = previous_capture_env
        for transport in transports:
            transport.close()
        daemon.cleanup()
        if hook_restore is not None:
            hook_restore()
        shutil.rmtree(execution_root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
