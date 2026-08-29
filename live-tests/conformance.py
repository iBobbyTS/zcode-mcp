from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import time
import zipfile
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping

MAX_OFFICIAL_LAUNCHES = 8
REQUIRED_TOOLS = {
    "zcode_system_ensure_ready", "zcode_system_status", "zcode_agent_list",
    "zcode_agent_get", "zcode_agent_events", "zcode_agent_wait",
    "zcode_agent_respond", "zcode_agent_message", "zcode_agent_result",
    "zcode_agent_close", "zcode_review_spawn", "zcode_review_continue",
    "zcode_agent_spawn", "zcode_agent_cancel",
}


class LaunchBudgetExceeded(RuntimeError):
    pass


class FatalConformanceError(RuntimeError):
    pass


@dataclass
class LaunchLedger:
    """Crash-safe, single-writer ledger for actual official child launches."""
    path: Path
    limit: int = MAX_OFFICIAL_LAUNCHES
    count: int = 0
    retries: int = 0

    def __post_init__(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            data = json.loads(self.path.read_text())
            self.count, self.retries = int(data.get("count", 0)), int(data.get("retries", 0))

    def reserve(self, *, retry: bool = False) -> int:
        if self.count >= self.limit:
            raise LaunchBudgetExceeded(f"official launch budget exhausted ({self.limit})")
        if retry and self.retries >= self.limit - 5:
            raise LaunchBudgetExceeded("retry slots exhausted")
        self.count += 1
        if retry:
            self.retries += 1
        payload = json.dumps({"count": self.count, "retries": self.retries}, sort_keys=True) + "\n"
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=self.path.name + ".", text=True)
        try:
            with os.fdopen(fd, "w") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        return self.count


class PublicV2Client:
    """Small transport-neutral client; transport must expose ``call(tool,args)``."""
    def __init__(self, transport: Any, ledger: LaunchLedger | None = None):
        self.transport, self.ledger = transport, ledger

    def call(self, tool: str, args: Mapping[str, Any] | None = None, *, launches: bool = False,
             retry: bool = False) -> Any:
        if launches and self.ledger:
            self.ledger.reserve(retry=retry)
        result = self.transport.call(tool, dict(args or {}))
        if isinstance(result, Mapping) and result.get("isError"):
            raise FatalConformanceError(f"MCP error from {tool}")
        return result

    def catalog(self) -> dict[str, Any]:
        catalog = self.call("zcode_system_status")
        tools = sorted(set(catalog.get("tools", catalog.get("tool_catalog", [])))) if isinstance(catalog, Mapping) else []
        missing = sorted(REQUIRED_TOOLS - set(tools))
        return {"tools": tools, "missing": missing,
                "sha256": hashlib.sha256(json.dumps(tools, separators=(",", ":")).encode()).hexdigest()}


class StdioMCPTransport:
    """Minimal MCP JSON-RPC stdio transport for the public server process.

    It intentionally speaks only initialize/tools/list and tools/call; no private RPCs.
    """
    def __init__(self, command: list[str], env: Mapping[str, str] | None = None):
        self.proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, text=True, env=dict(env or os.environ))
        self._id = 0
        self._id = 1
        self._send({"jsonrpc": "2.0", "id": self._id, "method": "initialize",
                    "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                               "clientInfo": {"name": "zcode-s02-harness", "version": "1"}}})
        self._read_response(self._id)
        self._notify("notifications/initialized", {})

    def _notify(self, method: str, params: Mapping[str, Any]) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": dict(params)})

    def _send(self, payload: Mapping[str, Any]) -> None:
        if not self.proc.stdin:
            raise RuntimeError("MCP stdin unavailable")
        self.proc.stdin.write(json.dumps(payload, separators=(",", ":")) + "\n")
        self.proc.stdin.flush()

    def call(self, tool: str, args: dict[str, Any]) -> Any:
        self._id += 1
        self._send({"jsonrpc": "2.0", "id": self._id, "method": "tools/call",
                    "params": {"name": tool, "arguments": args}})
        if not self.proc.stdout:
            raise RuntimeError("MCP stdout unavailable")
        return self._read_response(self._id)

    def _read_response(self, request_id: int) -> Any:
        if not self.proc.stdout:
            raise RuntimeError("MCP stdout unavailable")
        while True:
            line = self.proc.stdout.readline()
            if not line:
                raise RuntimeError("MCP process exited before response")
            message = json.loads(line)
            if message.get("id") != request_id:
                continue
            if "error" in message:
                return {"isError": True, "error": message["error"]}
            return message.get("result", {})

    def close(self) -> None:
        self.proc.terminate()
        self.proc.wait(timeout=5)


_SECRET = re.compile(r"(?i)(token|password|secret|api[_-]?key|authorization)\\s*[:=]\\s*[^\\s,}]+")
_ABS = re.compile(r"/(?:Users|private|var|tmp)/[^\\s\"']+")


def redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(k): ("[REDACTED]" if re.search(r"(?i)(token|password|secret|api[_-]?key|authorization)", str(k)) else redact(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    if isinstance(value, str):
        return _ABS.sub("[PATH]", _SECRET.sub(r"\1=[REDACTED]", value))
    return value


def normalize(case: str, observations: Mapping[str, Any]) -> dict[str, Any]:
    out = redact(dict(observations))
    out.update({"case": case, "schema": "s02-normalized-v1", "normalized_at": "runtime"})
    if "events" in out:
        events = out["events"] or []
        allowed = {"attempt_started", "review_progress", "pending_request", "review_finalized", "terminal"}
        out["events"] = [e for e in events if e.get("kind") in allowed]
        out["event_sequence_monotonic"] = all(a.get("sequence", 0) < b.get("sequence", 0) for a, b in zip(out["events"], out["events"][1:]))
    return out


@dataclass
class FakeRuntime:
    mode: str = "ready"
    calls: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    def call(self, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((tool, args))
        if self.mode == "no-progress" and tool == "zcode_agent_wait":
            return {"status": "timeout", "progress": []}
        if self.mode == "restart-loss" and tool == "zcode_agent_get":
            return {"status": "not_found", "error_class": "SERVICE_GENERATION_MISMATCH"}
        if tool == "zcode_system_status":
            return {"ready": self.mode == "ready", "tools": sorted(REQUIRED_TOOLS)}
        return {"ok": True}


def validate_artifact_chunk(chunk: Mapping[str, Any], *, artifact_id: str, sha256: str,
                            size: int, offset: int, limit: int) -> bytes:
    """Validate one public V2 artifact chunk; rejects unsafe offsets/limits."""
    import base64
    if offset < 0 or limit <= 0 or limit > 1_048_576 or offset > size:
        raise ValueError("INVALID_ARTIFACT_RANGE")
    if chunk.get("artifact_id") != artifact_id or chunk.get("sha256") != sha256:
        raise ValueError("ARTIFACT_METADATA_MISMATCH")
    data = base64.b64decode(chunk.get("data", ""), validate=True)
    returned = int(chunk.get("returned_bytes", len(data)))
    if returned != len(data) or returned <= 0 and offset < size:
        raise ValueError("INVALID_ARTIFACT_CHUNK")
    if int(chunk.get("offset", offset)) != offset or int(chunk.get("next_offset", offset + returned)) != offset + returned:
        raise ValueError("INVALID_ARTIFACT_PROGRESS")
    if returned > limit or offset + returned > size:
        raise ValueError("INVALID_ARTIFACT_CHUNK")
    return data


PACK_FILES = ("SUMMARY.md", "SYSTEM-IDENTITY.md", "SCENARIO-MATRIX.md", "PERMISSION-MATRIX.md",
              "PROGRESS-TIMELINE.md", "EVENT-METRICS.md", "RESULT-ARTIFACT-MATRIX.md",
              "RESTART-CLEANUP.md", "KNOWN-GAPS.md")


def finalize_pack(source: Path, destination: Path) -> tuple[Path, str]:
    missing = [name for name in PACK_FILES if not (source / name).is_file()]
    if missing:
        raise ValueError("missing pack reports: " + ", ".join(missing))
    forbidden = {".DS_Store", "__MACOSX", "credentials", "config.toml"}
    files = [p for p in source.rglob("*") if p.is_file() and not any(x in p.parts for x in forbidden)]
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp = destination.with_suffix(destination.suffix + ".tmp")
    with zipfile.ZipFile(temp, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(files):
            archive.write(path, path.relative_to(source).as_posix())
    os.replace(temp, destination)
    return destination, hashlib.sha256(destination.read_bytes()).hexdigest()
