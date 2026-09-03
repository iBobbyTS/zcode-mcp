#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path

from conformance import ConformanceError, StdioMCPTransport, collect_artifact, validate_catalog


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
    parser.add_argument("--poll-timeout-ms", type=int, default=5000)
    parser.add_argument("--max-polls", type=int, default=360)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    with tempfile.TemporaryDirectory(prefix="zcode-agent-live-") as raw_root:
        root = Path(raw_root)
        socket = root / "daemon.sock"
        database = root / "store.sqlite3"
        env = dict(os.environ)
        env.update({
            "ZCODE_REVIEWD_SOCKET": str(socket),
            "ZCODE_REVIEWD_DATABASE": str(database),
            "ZCODE_RUNTIME_PATH": str(args.runtime.resolve()),
        })
        daemon = subprocess.Popen([str(args.daemon.resolve())], env=env)
        transport = None
        agent_id = None
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
            for _ in range(args.max_polls):
                poll = transport.call("zcode_agent_poll", {
                    "agent_id": agent_id,
                    "after_revision": revision,
                    "timeout_ms": args.poll_timeout_ms,
                })
                revision = int(poll.get("next_revision", revision))
                activity_samples.append(poll.get("activity", {}))
                if poll.get("task", {}).get("phase") == "TERMINAL":
                    terminal = True
                    break
            if not terminal:
                raise ConformanceError("agent did not reach a terminal phase")
            result = transport.call("zcode_agent_result", {"agent_id": agent_id})
            task = result["task"]
            for artifact in result.get("artifacts", []):
                collect_artifact(transport, agent_id, int(task["attempt_sequence"]), artifact)
            closed = transport.call("zcode_agent_close", {"agent_id": agent_id})
            output = {
                "status": status,
                "spawn": spawn,
                "result": result,
                "closed": closed,
                "activity_samples": activity_samples,
            }
            print(json.dumps(output, sort_keys=True))
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


if __name__ == "__main__":
    raise SystemExit(main())
