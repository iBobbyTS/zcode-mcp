#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import time
from pathlib import Path

from conformance import ConformanceError, StdioMCPTransport, collect_artifact, validate_catalog
from fixture_workspace import create_execution_root


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run one generic ZCode Agent lifecycle")
    parser.add_argument("--daemon", type=Path, required=True)
    parser.add_argument("--facade", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--base-ref", required=True)
    parser.add_argument("--prompt", required=True)
    parser.add_argument("--access-mode", choices=["read_only", "workspace_write"], default="read_only")
    parser.add_argument("--feature-id", default="official-generic-agent")
    parser.add_argument("--ownership-token", default="live-agent-harness")
    parser.add_argument("--idempotency-key", required=True)
    parser.add_argument("--write-manifest", action="append", default=[])
    parser.add_argument("--allowed-command-id", action="append", default=[])
    parser.add_argument("--required-command-id", action="append", default=[])
    parser.add_argument("--command-catalog", type=Path)
    parser.add_argument("--poll-timeout-ms", type=int, default=5000)
    parser.add_argument("--poll-interval-seconds", type=float, default=15.0)
    parser.add_argument("--max-polls", type=int, default=360)
    parser.add_argument("--permission-decision", choices=["allow", "deny"], default="allow")
    return parser.parse_args()


def git_snapshot(repository: Path) -> dict[str, str]:
    def git(*arguments: str) -> str:
        return subprocess.check_output(
            ["git", "-C", str(repository), *arguments], text=True
        ).strip()

    return {
        "head": git("rev-parse", "HEAD"),
        "tracked_diff": git("diff", "--binary", "HEAD"),
        "staged_diff": git("diff", "--cached", "--binary", "HEAD"),
        "status": git("status", "--porcelain=v1", "--untracked-files=all"),
    }


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def source_integrity_unchanged(before: dict[str, str], after: dict[str, str]) -> bool:
    return all(before[field] == after[field] for field in ("head", "tracked_diff", "staged_diff"))


def main() -> int:
    args = parse_args()
    if not 0 <= args.poll_timeout_ms <= 5000:
        raise ConformanceError("poll timeout must be between 0 and 5000 ms")
    if not 15 <= args.poll_interval_seconds <= 30:
        raise ConformanceError("poll interval must be between 15 and 30 seconds")
    root = create_execution_root("official-generic-agent-")
    evidence_path = root / "evidence.json"
    daemon_log_path = root / "daemon.log"
    source_before = git_snapshot(args.repository.resolve())
    with daemon_log_path.open("wb") as daemon_log:
        socket = root / "daemon.sock"
        database = root / "store.sqlite3"
        env = dict(os.environ)
        env.update({
            "ZCODE_REVIEWD_SOCKET": str(socket),
            "ZCODE_REVIEWD_DATABASE": str(database),
            "ZCODE_RUNTIME_PATH": str(args.runtime.resolve()),
        })
        if args.command_catalog is not None:
            env["ZCODE_REVIEWD_COMMAND_CATALOG"] = str(args.command_catalog.resolve())
        daemon = subprocess.Popen(
            [str(args.daemon.resolve())], env=env, stdout=daemon_log,
            stderr=subprocess.STDOUT,
        )
        transport = None
        agent_id = None
        output = None
        try:
            deadline = time.monotonic() + 10
            while not socket.exists() and daemon.poll() is None and time.monotonic() < deadline:
                time.sleep(0.02)
            if not socket.exists():
                raise ConformanceError("daemon socket did not become ready")
            transport = StdioMCPTransport(args.facade.resolve(), socket)
            validate_catalog(transport)
            status = transport.call("zcode_system_status", {})
            spawn = transport.call("zcode_agent_spawn", {
                "repository": str(args.repository.resolve()),
                "base_ref": args.base_ref,
                "prompt": args.prompt,
                "access_mode": args.access_mode,
                "feature_id": args.feature_id,
                "ownership_token": args.ownership_token,
                "idempotency_key": args.idempotency_key,
                "write_manifest": args.write_manifest,
                "allowed_command_ids": args.allowed_command_id,
                "required_command_ids": args.required_command_id,
            })
            agent_id = str(spawn["agent_id"])
            revision = 0
            terminal = False
            activity_samples = []
            permission_responses = []
            poll_started_at = []
            for _ in range(args.max_polls):
                started = time.monotonic()
                poll_started_at.append(started)
                poll = transport.call("zcode_agent_poll", {
                    "agent_id": agent_id,
                    "after_revision": revision,
                    "timeout_ms": args.poll_timeout_ms,
                })
                revision = int(poll.get("next_revision", revision))
                activity_samples.append({
                    "elapsed_seconds": round(time.monotonic() - poll_started_at[0], 3),
                    "revision": poll.get("revision"),
                    "next_revision": poll.get("next_revision"),
                    "timed_out": poll.get("timed_out"),
                    "activity": poll.get("activity", {}),
                })
                responded_this_poll = False
                for request in poll.get("pending_requests", []):
                    if not request.get("respondable") or request.get("state") != "pending":
                        continue
                    response = transport.call("zcode_agent_respond", {
                        "agent_id": agent_id,
                        "request_id": request["request_id"],
                        "decision": args.permission_decision,
                        "reason": "official generic Agent conformance probe",
                    })
                    permission_responses.append({"request": request, "response": response})
                    responded_this_poll = True
                if poll.get("task", {}).get("phase") == "TERMINAL":
                    terminal = True
                    break
                if responded_this_poll:
                    continue
                elapsed = time.monotonic() - started
                time.sleep(max(0.0, args.poll_interval_seconds - elapsed))
            if not terminal:
                raise ConformanceError("agent did not reach a terminal phase")
            result = transport.call("zcode_agent_result", {"agent_id": agent_id})
            task = result["task"]
            artifact_verification = []
            for artifact in result.get("artifacts", []):
                content = collect_artifact(
                    transport, agent_id, int(task["attempt_sequence"]), artifact
                )
                artifact_verification.append({
                    "artifact_id": artifact["artifact_id"],
                    "kind": artifact["kind"],
                    "size_bytes": len(content),
                    "sha256": sha256(content),
                    "verified": sha256(content) == artifact["sha256"],
                })
            closed = transport.call("zcode_agent_close", {"agent_id": agent_id})
            source_after = git_snapshot(args.repository.resolve())
            source_unchanged = source_integrity_unchanged(source_before, source_after)
            output = {
                "execution_root": str(root),
                "status": status,
                "spawn": spawn,
                "result": result,
                "closed": closed,
                "activity_samples": activity_samples,
                "poll_start_intervals_seconds": [
                    round(current - previous, 3)
                    for previous, current in zip(poll_started_at, poll_started_at[1:])
                ],
                "permission_responses": permission_responses,
                "artifact_verification": artifact_verification,
                "source_before": source_before,
                "source_after": source_after,
                "source_unchanged": source_unchanged,
                "source_status_unchanged": source_before["status"] == source_after["status"],
            }
            evidence_path.write_text(
                json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            print(json.dumps({
                "agent_id": agent_id,
                "execution_root": str(root),
                "outcome": result.get("result", {}).get("outcome"),
                "phase": result.get("task", {}).get("phase"),
                "permission_responses": len(permission_responses),
                "source_unchanged": source_unchanged,
            }, sort_keys=True))
            return 0
        finally:
            if transport is not None:
                if agent_id is not None:
                    try:
                        transport.call("zcode_agent_close", {"agent_id": agent_id})
                    except Exception:
                        pass
                transport.close()
            if daemon.poll() is None:
                daemon.terminate()
                try:
                    daemon.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    daemon.kill()
                    daemon.wait(timeout=2)
            if output is not None:
                output["daemon_reaped"] = daemon.poll() is not None
                output["daemon_returncode"] = daemon.returncode
                evidence_path.write_text(
                    json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8"
                )


if __name__ == "__main__":
    raise SystemExit(main())
