from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import select
import subprocess
import tempfile
import time
import zipfile
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Mapping

MAX_OFFICIAL_LAUNCHES = 8
NOMINAL_OFFICIAL_LAUNCHES = 5
MAX_RETRY_LAUNCHES = MAX_OFFICIAL_LAUNCHES - NOMINAL_OFFICIAL_LAUNCHES
MAX_ARTIFACT_CHUNK_BYTES = 8192

REQUIRED_TOOLS = {
    "zcode_system_ensure_ready",
    "zcode_system_status",
    "zcode_agent_list",
    "zcode_agent_get",
    "zcode_agent_events",
    "zcode_agent_wait",
    "zcode_agent_respond",
    "zcode_agent_message",
    "zcode_agent_result",
    "zcode_agent_close",
    "zcode_review_spawn",
    "zcode_review_continue",
    "zcode_agent_spawn",
    "zcode_agent_cancel",
}
PUBLIC_EVENT_TYPES = {
    "attempt_started",
    "review_progress",
    "pending_request",
    "review_finalized",
    "terminal",
}


class LaunchBudgetExceeded(RuntimeError):
    pass


class FatalConformanceError(RuntimeError):
    pass


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"invalid launch ledger: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError("invalid launch ledger: expected object")
    return value


@dataclass
class LaunchLedger:
    """Crash-safe, inter-process locked ledger for actual official launches."""

    path: Path
    limit: int = MAX_OFFICIAL_LAUNCHES
    count: int = 0
    retries: int = 0

    def __post_init__(self) -> None:
        if self.limit <= 0:
            raise ValueError("launch ledger limit must be positive")
        self.path = Path(self.path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock_path = self.path.with_name(self.path.name + ".lock")
        if self.path.exists():
            state = _read_json(self.path)
            self.count, self.retries = int(state.get("count", 0)), int(state.get("retries", 0))
        self._validate_state()

    def _validate_state(self) -> None:
        if self.count < 0 or self.retries < 0 or self.retries > self.count:
            raise ValueError("invalid launch ledger counters")

    @contextmanager
    def _locked(self) -> Iterator[None]:
        lock_stream = self._lock_path.open("a+")
        try:
            try:
                import fcntl

                fcntl.flock(lock_stream.fileno(), fcntl.LOCK_EX)
            except ImportError:  # pragma: no cover - Windows fallback
                pass
            yield
        finally:
            try:
                import fcntl

                fcntl.flock(lock_stream.fileno(), fcntl.LOCK_UN)
            except ImportError:  # pragma: no cover
                pass
            lock_stream.close()

    def _persist(self, count: int, retries: int) -> None:
        payload = json.dumps({"count": count, "limit": self.limit, "retries": retries}, sort_keys=True) + "\n"
        fd, temporary = tempfile.mkstemp(dir=self.path.parent, prefix=f".{self.path.name}.", suffix=".tmp", text=True)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            try:
                directory_fd = os.open(self.path.parent, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except OSError:
                pass
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def reserve(self, *, retry: bool = False) -> int:
        # Re-read while holding the lock so stale instances cannot permit a ninth
        # launch when several workers reserve concurrently.
        with self._locked():
            if self.path.exists():
                state = _read_json(self.path)
                count, retries = int(state.get("count", 0)), int(state.get("retries", 0))
            else:
                count, retries = 0, 0
            if count >= self.limit:
                raise LaunchBudgetExceeded(f"official launch budget exhausted ({self.limit})")
            retry_limit = min(MAX_RETRY_LAUNCHES, max(0, self.limit - NOMINAL_OFFICIAL_LAUNCHES))
            if retry and retries >= retry_limit:
                raise LaunchBudgetExceeded(f"retry slots exhausted ({retry_limit})")
            count += 1
            if retry:
                retries += 1
            self._persist(count, retries)
            self.count, self.retries = count, retries
            return count


def _tool_payload(value: Any) -> Any:
    if isinstance(value, Mapping) and "structuredContent" in value:
        structured = value.get("structuredContent")
        if structured is not None:
            return structured
    return value


class PublicV2Client:
    """Public V2 adapter; no private daemon RPCs are exposed."""

    def __init__(self, transport: Any, ledger: LaunchLedger | None = None):
        self.transport, self.ledger = transport, ledger

    def call(
        self,
        tool: str,
        args: Mapping[str, Any] | None = None,
        *,
        launches: bool = False,
        retry: bool = False,
    ) -> Any:
        if launches:
            if self.ledger is None:
                raise RuntimeError("LaunchLedger is mandatory for official launch paths")
            self.ledger.reserve(retry=retry)
        result = self.transport.call(tool, dict(args or {}))
        if isinstance(result, Mapping) and result.get("isError") is True:
            raise FatalConformanceError(f"MCP error from {tool}")
        result = _tool_payload(result)
        if isinstance(result, Mapping) and result.get("isError") is True:
            raise FatalConformanceError(f"MCP error from {tool}")
        return result

    def catalog(self) -> dict[str, Any]:
        if hasattr(self.transport, "list_tools"):
            raw = self.transport.list_tools()
        elif hasattr(self.transport, "calls"):
            # Legacy in-process doubles predate tools/list and expose only the
            # status catalog.  Real stdio transports always take the branch above.
            raw = self.transport.call("zcode_system_status", {})
        else:
            raw = self.transport.call("tools/list", {})
        raw = _tool_payload(raw)
        tools_value = raw.get("tools", []) if isinstance(raw, Mapping) else []
        names: list[str] = []
        if isinstance(tools_value, list):
            for item in tools_value:
                if isinstance(item, str):
                    names.append(item)
                elif isinstance(item, Mapping) and isinstance(item.get("name"), str):
                    names.append(item["name"])
        if not names and hasattr(self.transport, "calls"):
            status = _tool_payload(raw)
            if isinstance(status, Mapping):
                candidate = status.get("tools", status.get("tool_catalog", []))
                names = [
                    item if isinstance(item, str) else item["name"]
                    for item in (candidate if isinstance(candidate, list) else [])
                    if isinstance(item, str) or isinstance(item, Mapping) and isinstance(item.get("name"), str)
                ]
        tools = sorted(set(names))
        missing = sorted(REQUIRED_TOOLS - set(tools))
        unexpected = sorted(set(tools) - REQUIRED_TOOLS)
        return {
            "tools": tools,
            "missing": missing,
            "unexpected": unexpected,
            "exact": not missing and not unexpected and len(tools) == 14,
            "sha256": hashlib.sha256(json.dumps(tools, separators=(",", ":")).encode()).hexdigest(),
        }


class StdioMCPTransport:
    """Bounded newline-delimited JSON-RPC transport for public MCP."""

    def __init__(
        self,
        command: list[str],
        env: Mapping[str, str] | None = None,
        *,
        timeout: float = 10.0,
        max_frame_bytes: int = 4 * 1024 * 1024,
    ):
        if not command:
            raise ValueError("MCP command cannot be empty")
        self.timeout = max(0.1, float(timeout))
        self.max_frame_bytes = max_frame_bytes
        self.proc = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=dict(env or os.environ),
            bufsize=0,
        )
        self._id = 0
        self._read_buffer = bytearray()
        self.transcript: list[dict[str, Any]] = []
        try:
            self._request("initialize", {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "zcode-s02-harness", "version": "1"},
            })
            self._notify("notifications/initialized", {})
        except Exception:
            self.close()
            raise

    def _record(self, direction: str, payload: Mapping[str, Any]) -> None:
        self.transcript.append({"direction": direction, "payload": redact(dict(payload))})

    def _write(self, payload: Mapping[str, Any]) -> None:
        if self.proc.stdin is None:
            raise RuntimeError("MCP stdin unavailable")
        encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"
        if len(encoded) > self.max_frame_bytes:
            raise RuntimeError("MCP request frame exceeds limit")
        self._record("request", payload)
        fd = self.proc.stdin.fileno()
        view = memoryview(encoded)
        deadline = time.monotonic() + self.timeout
        while view:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("MCP stdin write timed out")
            _, writable, _ = select.select([], [fd], [], remaining)
            if not writable:
                continue
            try:
                written = os.write(fd, view)
            except BrokenPipeError as exc:
                raise RuntimeError("MCP process closed stdin") from exc
            view = view[written:]

    def _read_line(self) -> Mapping[str, Any]:
        if self.proc.stdout is None:
            raise RuntimeError("MCP stdout unavailable")
        fd = self.proc.stdout.fileno()
        deadline = time.monotonic() + self.timeout
        while b"\n" not in self._read_buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("MCP response timed out")
            readable, _, _ = select.select([fd], [], [], remaining)
            if not readable:
                continue
            chunk = os.read(fd, 65536)
            if not chunk:
                raise RuntimeError("MCP process exited before response")
            self._read_buffer.extend(chunk)
            if len(self._read_buffer) > self.max_frame_bytes:
                raise RuntimeError("MCP response frame exceeds limit")
        line, _, remainder = self._read_buffer.partition(b"\n")
        self._read_buffer = bytearray(remainder)
        try:
            message = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise RuntimeError("MCP emitted invalid JSON") from exc
        if not isinstance(message, Mapping):
            raise RuntimeError("MCP emitted a non-object response")
        self._record("response", message)
        return message

    def _notify(self, method: str, params: Mapping[str, Any]) -> None:
        self._write({"jsonrpc": "2.0", "method": method, "params": dict(params)})

    def _request(self, method: str, params: Mapping[str, Any]) -> Any:
        self._id += 1
        request_id = self._id
        self._write({"jsonrpc": "2.0", "id": request_id, "method": method, "params": dict(params)})
        while True:
            message = self._read_line()
            if message.get("id") != request_id:
                continue
            if "error" in message:
                return {"isError": True, "error": message["error"]}
            return message.get("result", {})

    def list_tools(self) -> Any:
        return self._request("tools/list", {})

    def call(self, tool: str, args: dict[str, Any]) -> Any:
        return self._request("tools/call", {"name": tool, "arguments": dict(args)})

    def close(self) -> None:
        process = getattr(self, "proc", None)
        if process is None:
            return
        try:
            if process.stdin is not None:
                process.stdin.close()
        except OSError:
            pass
        if process.poll() is None:
            try:
                process.wait(timeout=self.timeout)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=min(1.0, self.timeout))
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=1.0)
        for stream in (process.stdout, process.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass

    def write_transcript(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as stream:
            for item in self.transcript:
                stream.write(json.dumps(item, ensure_ascii=False, sort_keys=True) + "\n")


_SECRET = re.compile(
    r"(?ix)\b(token|password|secret|api[_-]?key|authorization|cookie|credential)\b"
    r"(\s*[:=]\s*)(?:bearer\s+)?(?:\"[^\"]*\"|'[^']*'|[^\s,;}\"']+)"
)
_SECRET_PROSE = re.compile(
    r"(?i)\b(token|password|secret|api[_-]?key|authorization)\s+(?:bearer\s+)?([A-Za-z0-9][A-Za-z0-9._~+/=-]{7,})"
)
_BEARER = re.compile(r"(?i)\b(?:bearer)\s+[A-Za-z0-9._~+/=-]{8,}")
_TOKEN_SHAPES = re.compile(r"\b(?:sk|ghp|gho|xox[baprs])-[A-Za-z0-9_-]{12,}\b")
_ABS = re.compile(
    r"(?<![A-Za-z0-9])(?:/(?:Users|private|var|tmp|home|Volumes|opt|etc|srv|workspace|absolute)/[^\s\"'`<>;,}]*)"
    r"|(?:[A-Za-z]:\\(?:Users|private|Temp|tmp)\\[^\s\"'`<>;,}]*)"
)
_ANY_ABS = re.compile(r"(?<![A-Za-z0-9])/(?:[^/\s\"'`<>]+/)+[^\s\"'`<>;,}]*")


def _redact_text(value: str) -> str:
    value = _ABS.sub("[PATH]", value)
    value = _ANY_ABS.sub("[PATH]", value)
    value = _SECRET.sub(lambda match: f"{match.group(1)}{match.group(2)}[REDACTED]", value)
    value = _SECRET_PROSE.sub(lambda match: f"{match.group(1)} [REDACTED]", value)
    value = _BEARER.sub("Bearer [REDACTED]", value)
    value = _TOKEN_SHAPES.sub("[REDACTED]", value)
    return value


def redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        output: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if re.search(r"(?i)(token|password|secret|api[_-]?key|authorization|cookie|credential)", key_text):
                output[key_text] = "[REDACTED]"
            else:
                output[key_text] = redact(item)
        return output
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return [redact(item) for item in value]
    if isinstance(value, str):
        return _redact_text(value)
    return value


def normalize(case: str, observations: Mapping[str, Any]) -> dict[str, Any]:
    out = redact(dict(observations))
    out.update({"case": case, "schema": "s02-normalized-v2", "normalized_at": "runtime"})
    if "events" in out:
        events = out.get("events") or []
        retained = []
        for event in events if isinstance(events, list) else []:
            if not isinstance(event, Mapping):
                continue
            event_type = event.get("event_type", event.get("kind"))
            if event_type in PUBLIC_EVENT_TYPES:
                normalized_event = dict(event)
                normalized_event["event_type"] = event_type
                retained.append(normalized_event)
        out["events"] = retained
        sequences = [event.get("sequence") for event in retained]
        out["event_types"] = [event.get("event_type") for event in retained]
        out["event_sequence_monotonic"] = all(
            isinstance(a, int) and isinstance(b, int) and a < b
            for a, b in zip(sequences, sequences[1:])
        )
        out["event_count"] = len(retained)
    return out


@dataclass
class FakeRuntime:
    """Deterministic public-surface double for negatives and Case C."""

    mode: str = "ready"
    calls: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    agents: dict[str, dict[str, Any]] = field(default_factory=dict)
    idempotencies: dict[str, str] = field(default_factory=dict)
    service_generation: str = "fake-generation-1"
    _sequence: int = 0

    def _events(self) -> list[dict[str, Any]]:
        if self.mode == "no-progress":
            return []
        self._sequence += 1
        events = [{"sequence": self._sequence, "attempt_sequence": 1, "event_type": "attempt_started"}]
        if self.mode in {"progress", "case-c"}:
            for stage in ("inspection", "analysis", "finalization"):
                self._sequence += 1
                events.append({"sequence": self._sequence, "attempt_sequence": 1, "event_type": "review_progress", "stage": stage})
        return events

    def call(self, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((tool, args))
        if self.mode == "restart-loss" and tool == "zcode_agent_get":
            return {"status": "not_found", "error_class": "SERVICE_GENERATION_MISMATCH"}
        if tool == "zcode_system_status":
            return {
                "api_surface": "subagent_v2",
                "protocol_version": 2,
                "service_generation": self.service_generation,
                "components": {"daemon": "ready" if self.mode != "readiness-failure" else "unavailable"},
                "capabilities": {},
                "tools": sorted(REQUIRED_TOOLS),
            }
        if tool == "zcode_system_ensure_ready":
            if self.mode in {"no-progress", "readiness-timeout"}:
                return {"ready": False, "probe_result": "NOT_OBSERVED_WITHIN_TIMEOUT", "reason_code": "NOT_OBSERVED_WITHIN_TIMEOUT"}
            if self.mode == "readiness-failure":
                return {"ready": False, "probe_result": "RUNTIME_FAILED", "reason_code": "RUNTIME_FAILED"}
            return {"ready": True, "probe_result": "READY", "reason_code": None}
        if tool in {"zcode_review_spawn", "zcode_agent_spawn"}:
            key = str(args.get("idempotency_key", ""))
            if key in self.idempotencies:
                agent_id = self.idempotencies[key]
                return {"agent_id": agent_id, "review_id": f"review-{agent_id}", "submission_disposition": "existing", "phase": "QUEUED", "attempt_sequence": 1}
            agent_id = f"fake-agent-{len(self.agents) + 1}"
            self.idempotencies[key] = agent_id
            self.agents[agent_id] = {"attempt_sequence": 1, "closed": False, "events": self._events()}
            return {"agent_id": agent_id, "review_id": f"review-{agent_id}", "submission_disposition": "created", "phase": "QUEUED", "attempt_sequence": 1}
        if tool == "zcode_review_continue":
            agent_id = str(args.get("agent_id"))
            task = self.agents.setdefault(agent_id, {"attempt_sequence": 1, "closed": False, "events": []})
            task["attempt_sequence"] += 1
            task["events"] = self._events()
            return {"agent_id": agent_id, "review_id": str(args.get("review_id")), "submission_disposition": "created", "phase": "QUEUED", "attempt_sequence": task["attempt_sequence"], "counts_as_independent": False}
        if tool == "zcode_agent_events":
            task = self.agents.setdefault(str(args.get("agent_id")), {"attempt_sequence": 1, "closed": False, "events": []})
            after = int(args.get("after_sequence", 0))
            events = [event for event in task.get("events", []) if event["sequence"] > after]
            return {"events": events[: int(args.get("limit", 100))], "next_sequence": events[-1]["sequence"] if events else after, "has_more": False}
        if tool == "zcode_agent_wait":
            after = int(args.get("after_sequence", 0))
            if self.mode == "no-progress":
                return {"task": {"phase": "RUNNING"}, "events": [], "next_sequence": after, "has_more": False, "timed_out": True, "status": "timeout", "progress": []}
            return {"task": {"phase": "TERMINAL"}, "events": [], "next_sequence": after, "has_more": False, "timed_out": False}
        if tool == "zcode_agent_respond":
            return {"disposition": "responded", "requested_decision": "deny", "effective_decision": "deny", "policy_overrode": False, "policy_reason_code": None, "attempt_sequence": 1}
        if tool == "zcode_agent_result":
            artifact = b"fake report\n"
            digest = hashlib.sha256(artifact).hexdigest()
            chunk = None
            if args.get("offset_bytes") is not None and args.get("limit_bytes") is not None:
                offset, limit = int(args["offset_bytes"]), int(args["limit_bytes"])
                data = artifact[offset : offset + limit]
                chunk = {"artifact_id": "fake-artifact", "offset_bytes": offset, "returned_bytes": len(data), "eof": offset + len(data) == len(artifact), "sha256": digest, "size_bytes": len(artifact), "bytes_base64": base64.b64encode(data).decode()}
            return {"task": {"phase": "TERMINAL", "attempt_sequence": 1}, "result": {"outcome": "SUCCEEDED", "summary": "fake", "review_evidence": {"artifact": {"artifact_id": "fake-artifact", "sha256": digest, "size_bytes": len(artifact)}}}, "artifacts": [{"artifact_id": "fake-artifact", "kind": "report_markdown", "sha256": digest, "size_bytes": len(artifact)}], "artifact_chunk": chunk}
        if tool == "zcode_agent_close":
            return {"task": {"phase": "TERMINAL", "closed": True, "resources_reaped": True}}
        if tool == "zcode_agent_get":
            return {"task": {"phase": "RUNNING", "attempt_sequence": 1}, "result": None, "artifacts": [], "pending_requests": []}
        if tool == "zcode_agent_list":
            return {"tasks": [], "next_cursor": None}
        return {"ok": True}


def validate_artifact_chunk(
    chunk: Mapping[str, Any],
    *,
    artifact_id: str,
    sha256: str,
    size: int,
    offset: int,
    limit: int,
) -> bytes:
    """Validate authoritative V2 artifact chunk metadata and bytes."""
    if isinstance(chunk.get("artifact_chunk"), Mapping):
        chunk = chunk["artifact_chunk"]  # type: ignore[assignment]
    if offset < 0 or limit <= 0 or limit > MAX_ARTIFACT_CHUNK_BYTES or offset >= size:
        raise ValueError("INVALID_ARTIFACT_RANGE")
    if chunk.get("artifact_id") != artifact_id or chunk.get("sha256") != sha256:
        raise ValueError("ARTIFACT_METADATA_MISMATCH")
    if int(chunk.get("size_bytes", size)) != size or int(chunk.get("offset_bytes", chunk.get("offset", -1))) != offset:
        raise ValueError("INVALID_ARTIFACT_PROGRESS")
    encoded = chunk.get("bytes_base64", chunk.get("data", ""))
    try:
        data = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("INVALID_ARTIFACT_CHUNK") from exc
    returned = int(chunk.get("returned_bytes", len(data)))
    if returned != len(data) or returned <= 0 or returned > limit or offset + returned > size:
        raise ValueError("INVALID_ARTIFACT_CHUNK")
    eof = bool(chunk.get("eof", offset + returned == size))
    if eof != (offset + returned == size):
        raise ValueError("INVALID_ARTIFACT_PROGRESS")
    return data


def collect_artifact(
    client: PublicV2Client,
    agent_id: str,
    *,
    artifact_id: str,
    sha256: str,
    size: int,
    attempt_sequence: int | None = None,
) -> bytes:
    """Read an artifact sequentially through the V2 bounded chunk endpoint."""
    if size < 0:
        raise ValueError("INVALID_ARTIFACT_RANGE")
    offset = 0
    chunks: list[bytes] = []
    while offset < size:
        arguments: dict[str, Any] = {
            "agent_id": agent_id,
            "artifact_id": artifact_id,
            "offset_bytes": offset,
            "limit_bytes": min(MAX_ARTIFACT_CHUNK_BYTES, size - offset),
        }
        if attempt_sequence is not None:
            arguments["attempt_sequence"] = attempt_sequence
        result = client.call("zcode_agent_result", arguments)
        chunk = result.get("artifact_chunk") if isinstance(result, Mapping) else None
        if not isinstance(chunk, Mapping):
            raise ValueError("INVALID_ARTIFACT_CHUNK")
        data = validate_artifact_chunk(
            chunk,
            artifact_id=artifact_id,
            sha256=sha256,
            size=size,
            offset=offset,
            limit=arguments["limit_bytes"],
        )
        chunks.append(data)
        offset += len(data)
        if chunk.get("eof") is True and offset != size:
            raise ValueError("INVALID_ARTIFACT_PROGRESS")
    data = b"".join(chunks)
    if hashlib.sha256(data).hexdigest() != sha256:
        raise ValueError("ARTIFACT_DIGEST_MISMATCH")
    return data


PACK_FILES = (
    "SUMMARY.md", "SYSTEM-IDENTITY.md", "SCENARIO-MATRIX.md", "PERMISSION-MATRIX.md",
    "PROGRESS-TIMELINE.md", "EVENT-METRICS.md", "RESULT-ARTIFACT-MATRIX.md",
    "RESTART-CLEANUP.md", "KNOWN-GAPS.md",
)
PACK_DIRECTORIES = ("fixtures", "normalized", "raw-transcripts", "redacted-logs")
_BENIGN_EXCLUDED_NAMES = {".DS_Store", "__MACOSX", "__pycache__"}
_FORBIDDEN_CONTENT = re.compile(r"(?i)(?:password|secret|api[_-]?key|authorization|bearer\s+[A-Za-z0-9._~+/=-]{8,})\s*[:=]")


def _check_pack_content(path: Path, data: bytes) -> None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return
    if _FORBIDDEN_CONTENT.search(text) or _ABS.search(text) or _ANY_ABS.search(text):
        raise ValueError(f"unredacted secret or path in pack content: {path}")


def _pack_members(source: Path) -> list[Path]:
    if not source.is_dir() or source.is_symlink():
        raise ValueError("pack source must be a real directory")
    missing = [name for name in PACK_FILES if not (source / name).is_file() or (source / name).is_symlink()]
    if missing:
        raise ValueError("missing pack reports: " + ", ".join(missing))
    members: list[Path] = []
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source)
        if path.is_symlink():
            raise ValueError(f"symlink is not allowed in pack: {relative}")
        if path.name in _BENIGN_EXCLUDED_NAMES or any(part in _BENIGN_EXCLUDED_NAMES for part in relative.parts):
            continue
        if path.is_dir():
            if len(relative.parts) == 1 and relative.name in PACK_DIRECTORIES:
                continue
            if len(relative.parts) > 1 and relative.parts[0] in PACK_DIRECTORIES:
                continue
            raise ValueError(f"unexpected pack directory: {relative}")
        if not path.is_file():
            raise ValueError(f"unsupported pack entry: {relative}")
        if len(relative.parts) == 1:
            if relative.name not in PACK_FILES:
                raise ValueError(f"unexpected pack file: {relative}")
        elif relative.parts[0] not in PACK_DIRECTORIES:
            raise ValueError(f"unexpected pack path: {relative}")
        data = path.read_bytes()
        _check_pack_content(path, data)
        members.append(path)
    return members


def verify_pack(destination: Path, expected_digest: str | None = None) -> str:
    destination = Path(destination)
    with zipfile.ZipFile(destination) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise ValueError("pack contains duplicate entries")
        required_roots = set(PACK_FILES)
        required_dirs = {f"{directory}/" for directory in PACK_DIRECTORIES}
        if not required_roots.issubset(names) or not required_dirs.issubset(names):
            raise ValueError("pack is missing required report or directory")
        for name in names:
            pure = Path(name)
            if pure.is_absolute() or ".." in pure.parts:
                raise ValueError("pack contains unsafe path")
            if name in _BENIGN_EXCLUDED_NAMES or any(part in _BENIGN_EXCLUDED_NAMES for part in pure.parts):
                raise ValueError("pack contains excluded cache entry")
            info = archive.getinfo(name)
            if info.external_attr >> 16 & 0o170000 == 0o120000:
                raise ValueError("pack contains symlink")
            if not name.endswith("/") and len(pure.parts) == 1 and name not in PACK_FILES:
                raise ValueError(f"pack contains unexpected root file: {name}")
            if name.endswith("/") and len(pure.parts) == 1 and name not in required_dirs:
                raise ValueError(f"pack contains unexpected root directory: {name}")
            if len(pure.parts) > 1 and pure.parts[0] not in PACK_DIRECTORIES:
                raise ValueError(f"pack contains unexpected path: {name}")
            if not name.endswith("/"):
                _check_pack_content(Path(name), archive.read(name))
    digest = hashlib.sha256(destination.read_bytes()).hexdigest()
    if expected_digest is not None and digest != expected_digest:
        raise ValueError("pack digest mismatch")
    return digest


def finalize_pack(source: Path, destination: Path) -> tuple[Path, str]:
    source, destination = Path(source), Path(destination)
    members = _pack_members(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(dir=destination.parent, prefix=f".{destination.name}.", suffix=".tmp")
    os.close(fd)
    temporary = Path(temporary_name)
    try:
        with zipfile.ZipFile(temporary, "w", zipfile.ZIP_DEFLATED) as archive:
            for directory in PACK_DIRECTORIES:
                info = zipfile.ZipInfo(f"{directory}/")
                info.date_time = (1980, 1, 1, 0, 0, 0)
                info.external_attr = 0o40755 << 16
                archive.writestr(info, b"")
            for path in members:
                info = zipfile.ZipInfo(path.relative_to(source).as_posix())
                info.date_time = (1980, 1, 1, 0, 0, 0)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o100644 << 16
                archive.writestr(info, path.read_bytes())
        # Verify the complete temporary archive before publishing it.  A
        # malformed archive therefore cannot replace a previously good pack.
        digest = verify_pack(temporary)
        os.replace(temporary, destination)
        digest = verify_pack(destination, digest)
        return destination, digest
    finally:
        if temporary.exists():
            temporary.unlink()
