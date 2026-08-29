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
import uuid
from copy import deepcopy
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
    """A typed public-contract failure that always freezes the matrix."""

    def __init__(
        self,
        message: str,
        *,
        error_class: str = "CONFORMANCE",
        public_text: str | None = None,
    ) -> None:
        super().__init__(message)
        self.error_class = error_class
        self.public_text = public_text


class InfrastructureConformanceError(RuntimeError):
    """A classified transport/observation failure eligible for one call retry."""


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
        self._last_reservation: str | None = None
        self._reservations: dict[str, bool] = {}
        if self.path.exists():
            state = _read_json(self.path)
            self.count, self.retries = int(state.get("count", 0)), int(state.get("retries", 0))
            reservations = state.get("reservations", {})
            if isinstance(reservations, Mapping):
                self._reservations = {str(token): bool(is_retry) for token, is_retry in reservations.items()}
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

    def _persist(self, count: int, retries: int, reservations: Mapping[str, bool] | None = None) -> None:
        payload = json.dumps({"count": count, "limit": self.limit, "retries": retries, "reservations": dict(reservations or {})}, sort_keys=True) + "\n"
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
        _, count = self.reserve_with_token(retry=retry)
        return count

    def reserve_with_token(self, *, retry: bool = False) -> tuple[str, int]:
        # Re-read while holding the lock so stale instances cannot permit a ninth
        # launch when several workers reserve concurrently.
        with self._locked():
            if self.path.exists():
                state = _read_json(self.path)
                count, retries = int(state.get("count", 0)), int(state.get("retries", 0))
                raw_reservations = state.get("reservations", {})
                reservations = {str(token): bool(is_retry) for token, is_retry in raw_reservations.items()} if isinstance(raw_reservations, Mapping) else {}
            else:
                count, retries = 0, 0
                reservations = {}
            if count >= self.limit:
                raise LaunchBudgetExceeded(f"official launch budget exhausted ({self.limit})")
            retry_limit = min(MAX_RETRY_LAUNCHES, max(0, self.limit - NOMINAL_OFFICIAL_LAUNCHES))
            if retry and retries >= retry_limit:
                raise LaunchBudgetExceeded(f"retry slots exhausted ({retry_limit})")
            count += 1
            if retry:
                retries += 1
            token = f"{os.getpid()}-{uuid.uuid4().hex}"
            reservations[token] = retry
            self._persist(count, retries, reservations)
            self.count, self.retries = count, retries
            self._last_reservation = token
            self._reservations = reservations
            return token, count

    def commit(self, token: str | None = None) -> None:
        """Mark an observable launch complete without changing its count."""
        token = token or self._last_reservation
        if token is None:
            return
        with self._locked():
            if not self.path.exists():
                return
            state = _read_json(self.path)
            count, retries = int(state.get("count", 0)), int(state.get("retries", 0))
            raw = state.get("reservations", {})
            reservations = {str(key): bool(value) for key, value in raw.items()} if isinstance(raw, Mapping) else {}
            if token not in reservations:
                return
            reservations.pop(token, None)
            self._persist(count, retries, reservations)
            self._reservations = reservations

    def mark_retry(self, token: str) -> None:
        """Consume one retry allowance without reserving a second launch.

        An ambiguous transport failure may already have launched the child.  A
        retry of the same idempotent public submission therefore reuses the
        original conservative reservation instead of claiming a second launch.
        """
        with self._locked():
            state = _read_json(self.path)
            count, retries = int(state.get("count", 0)), int(state.get("retries", 0))
            raw = state.get("reservations", {})
            reservations = {str(key): bool(value) for key, value in raw.items()} if isinstance(raw, Mapping) else {}
            if token not in reservations:
                raise ValueError("launch reservation is no longer active")
            if reservations[token]:
                return
            retry_limit = min(MAX_RETRY_LAUNCHES, max(0, self.limit - NOMINAL_OFFICIAL_LAUNCHES))
            if retries >= retry_limit:
                raise LaunchBudgetExceeded(f"retry slots exhausted ({retry_limit})")
            reservations[token] = True
            retries += 1
            self._persist(count, retries, reservations)
            self.count, self.retries = count, retries
            self._reservations = reservations

    def rollback(self, *, retry: bool = False, token: str | None = None) -> None:
        """Release a reservation only after public evidence proves no launch.

        Transport failures are ambiguous and must never call this method.  The
        current legitimate use is an immediate ``submission_disposition`` of
        ``existing`` before any ambiguous retry occurred.
        """
        token = token or self._last_reservation
        with self._locked():
            if not self.path.exists():
                return
            state = _read_json(self.path)
            count, retries = int(state.get("count", 0)), int(state.get("retries", 0))
            raw = state.get("reservations", {})
            reservations = {str(key): bool(value) for key, value in raw.items()} if isinstance(raw, Mapping) else {}
            if token is None or token not in reservations:
                return
            reservation_retry = reservations.pop(token)
            if count <= 0 or (reservation_retry and retries <= 0):
                return
            count -= 1
            if reservation_retry:
                retries -= 1
            self._persist(count, retries, reservations)
            self.count, self.retries = count, retries
            self._reservations = reservations


def _tool_payload(value: Any) -> Any:
    if isinstance(value, Mapping) and "structuredContent" in value:
        structured = value.get("structuredContent")
        if structured is not None:
            return structured
    return value


def _rmcp_error(value: Any) -> tuple[str, str] | None:
    """Return stable public error class and complete rmcp text fallback."""
    if not isinstance(value, Mapping) or value.get("isError") is not True:
        return None
    texts: list[str] = []
    content = value.get("content")
    if isinstance(content, list):
        for item in content:
            if isinstance(item, Mapping) and item.get("type") == "text" and isinstance(item.get("text"), str):
                texts.append(item["text"])
    error = value.get("error")
    if isinstance(error, Mapping):
        code = str(error.get("code", "")).strip()
        message = str(error.get("message", "")).strip()
        if message:
            texts.append(message)
    public_text = "\n".join(text for text in texts if text).strip() or "MCP tool returned isError"
    prefix = public_text.split(":", 1)[0].strip().lower().replace("-", "_").replace(" ", "_")
    stable = {
        "validation": "VALIDATION",
        "not_found": "NOT_FOUND",
        "conflict": "CONFLICT",
        "daemon_unavailable": "DAEMON_UNAVAILABLE",
        "runtime_failure": "RUNTIME_FAILURE",
        "protocol_error": "PROTOCOL_ERROR",
        "persistence": "PERSISTENCE",
        "unavailable": "UNAVAILABLE",
    }.get(prefix)
    if stable is None and isinstance(error, Mapping) and error.get("code") is not None:
        stable = re.sub(r"[^A-Z0-9]+", "_", str(error["code"]).upper()).strip("_") or "MCP_ERROR"
    return stable or "MCP_ERROR", public_text


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
        retry_infrastructure: bool = False,
    ) -> Any:
        reservation_token: str | None = None
        if launches:
            if self.ledger is None:
                raise RuntimeError("LaunchLedger is mandatory for official launch paths")
            reservation_token, _ = self.ledger.reserve_with_token()
        ambiguous_retry = False
        while True:
            try:
                result = self.transport.call(tool, dict(args or {}))
                break
            except FatalConformanceError:
                raise
            except InfrastructureConformanceError as exc:
                error = exc
            except (TimeoutError, OSError) as exc:
                error = exc
            except RuntimeError:
                # Generic RuntimeError is a harness/protocol defect, never an
                # infrastructure retry classification.
                raise
            if retry_infrastructure and not ambiguous_retry and reservation_token is not None and self.ledger is not None:
                self.ledger.mark_retry(reservation_token)
                ambiguous_retry = True
                continue
            raise InfrastructureConformanceError(str(error)) from error
        public_error = _rmcp_error(result)
        if public_error is not None:
            error_class, public_text = public_error
            raise FatalConformanceError(
                f"MCP error from {tool}: {error_class}: {public_text}",
                error_class=error_class,
                public_text=public_text,
            )
        result = _tool_payload(result)
        public_error = _rmcp_error(result)
        if public_error is not None:
            error_class, public_text = public_error
            raise FatalConformanceError(
                f"MCP error from {tool}: {error_class}: {public_text}",
                error_class=error_class,
                public_text=public_text,
            )
        if reservation_token is not None and self.ledger is not None:
            disposition = result.get("submission_disposition") if isinstance(result, Mapping) else None
            if disposition == "existing" and not ambiguous_retry:
                self.ledger.rollback(token=reservation_token)
            else:
                self.ledger.commit(reservation_token)
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
        if isinstance(raw, Mapping) and raw.get("isError") is True:
            error = raw.get("error")
            detail = f": {error.get('code', 'UNKNOWN')}: {error.get('message', '')}" if isinstance(error, Mapping) else ""
            public_error = _rmcp_error(raw)
            if public_error is not None:
                error_class, public_text = public_error
                raise FatalConformanceError(
                    f"MCP error from tools/list: {error_class}: {public_text}",
                    error_class=error_class,
                    public_text=public_text,
                )
            raise FatalConformanceError(f"MCP error from tools/list{detail}")
        raw = _tool_payload(raw)
        public_error = _rmcp_error(raw)
        if public_error is not None:
            error_class, public_text = public_error
            raise FatalConformanceError(
                f"MCP error from tools/list: {error_class}: {public_text}",
                error_class=error_class,
                public_text=public_text,
            )
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
        tools = sorted(names)
        unique_tools = set(tools)
        duplicate_names = sorted({name for name in tools if tools.count(name) > 1})
        missing = sorted(REQUIRED_TOOLS - unique_tools)
        unexpected = sorted(unique_tools - REQUIRED_TOOLS)
        return {
            "tools": tools,
            "duplicate_names": duplicate_names,
            "missing": missing,
            "unexpected": unexpected,
            "exact": not missing and not unexpected and not duplicate_names and len(tools) == 14,
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
            raise FatalConformanceError("MCP stdin unavailable", error_class="HARNESS_STATE")
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
                raise InfrastructureConformanceError("MCP stdin write timed out")
            _, writable, _ = select.select([], [fd], [], remaining)
            if not writable:
                continue
            try:
                written = os.write(fd, view)
            except BrokenPipeError as exc:
                raise InfrastructureConformanceError("MCP process closed stdin") from exc
            view = view[written:]

    def _read_line(self) -> Mapping[str, Any]:
        if self.proc.stdout is None:
            raise FatalConformanceError("MCP stdout unavailable", error_class="HARNESS_STATE")
        fd = self.proc.stdout.fileno()
        deadline = time.monotonic() + self.timeout
        while b"\n" not in self._read_buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise InfrastructureConformanceError("MCP response timed out")
            readable, _, _ = select.select([fd], [], [], remaining)
            if not readable:
                continue
            chunk = os.read(fd, 65536)
            if not chunk:
                raise InfrastructureConformanceError("MCP process exited before response")
            self._read_buffer.extend(chunk)
            if len(self._read_buffer) > self.max_frame_bytes:
                raise FatalConformanceError("MCP response frame exceeds limit", error_class="PROTOCOL_ERROR")
        line, _, remainder = self._read_buffer.partition(b"\n")
        self._read_buffer = bytearray(remainder)
        try:
            message = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise FatalConformanceError("MCP emitted invalid JSON", error_class="PROTOCOL_ERROR") from exc
        if not isinstance(message, Mapping):
            raise FatalConformanceError("MCP emitted a non-object response", error_class="PROTOCOL_ERROR")
        if message.get("jsonrpc") != "2.0":
            raise FatalConformanceError("MCP emitted an incompatible JSON-RPC version", error_class="PROTOCOL_ERROR")
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
            if "result" not in message:
                raise FatalConformanceError("MCP response omitted result/error", error_class="PROTOCOL_ERROR")
            return message["result"]

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
_ANY_ABS = re.compile(r"(?<![A-Za-z0-9\]])/(?:[^/\s\"'`<>]+/)+[^\s\"'`<>;,}]*")


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
        public_fields = {
            "sequence", "attempt_sequence", "event_type", "redaction_level",
            "pending_request_id", "stage", "summary", "counters",
            "last_progress_at", "semantic_idle_ms", "nudge_sent",
        }
        projection_valid = True
        for event in events if isinstance(events, list) else []:
            if not isinstance(event, Mapping):
                continue
            event_type = event.get("event_type", event.get("kind"))
            if event_type in PUBLIC_EVENT_TYPES:
                # Keep precisely the public projection.  Private Store/event
                # payload keys must never become part of normalized evidence.
                normalized_event = {key: value for key, value in event.items() if key in public_fields}
                normalized_event["event_type"] = event_type
                if event_type == "review_progress":
                    required = ("stage", "summary", "last_progress_at", "semantic_idle_ms", "nudge_sent")
                    projection_valid = projection_valid and all(key in event for key in required)
                    projection_valid = projection_valid and (
                        "counters" not in event or isinstance(event.get("counters"), Mapping)
                    )
                retained.append(normalized_event)
        out["events"] = retained
        sequences = [event.get("sequence") for event in retained]
        out["event_types"] = [event.get("event_type") for event in retained]
        out["event_sequence_monotonic"] = all(
            isinstance(a, int) and isinstance(b, int) and a < b
            for a, b in zip(sequences, sequences[1:])
        )
        out["event_count"] = len(retained)
        out["public_projection_valid"] = projection_valid
    return out


@dataclass
class FakeRuntime:
    """Deterministic public-surface double for negatives and Case C."""

    mode: str = "ready"
    calls: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    agents: dict[str, dict[str, Any]] = field(default_factory=dict)
    idempotencies: dict[str, str] = field(default_factory=dict)
    continuations: dict[str, tuple[str, int]] = field(default_factory=dict)
    service_generation: str = "fake-generation-1"
    _sequence: int = 0
    _pending: dict[str, dict[str, Any]] = field(default_factory=dict)
    _closed: set[str] = field(default_factory=set)
    _terminal: set[str] = field(default_factory=set)
    _results: dict[tuple[str, int], dict[str, Any]] = field(default_factory=dict)

    def _review_provenance(self, attempt_sequence: int) -> dict[str, Any]:
        digest = lambda label: hashlib.sha256(f"{label}-{attempt_sequence}".encode()).hexdigest()
        return {
            "review_kind": "initial_bounded",
            "manifest_sha256": digest("manifest"),
            "prepared_sha256": digest("prepared"),
            "prompt_sha256": digest("prompt"),
            "base_sha": "a" * 40,
            "head_sha": "b" * 40,
            "requested_model": "sol",
            "fresh_session_observed": True,
            "policy_version": "review-bash-policy-v1",
            "policy_sha256": digest("policy"),
            "daemon_policy_version": "review-bash-policy-v1",
            "daemon_policy_sha256": digest("policy"),
            "expected_hook_version": "1",
            "expected_hook_sha256": digest("hook"),
            "effective_hook_version": "1",
            "effective_hook_sha256": digest("hook"),
            "hook_activation_verified": True,
            "activation_method": "fake",
            "activation_generation": "fake-hook-generation",
        }

    def _events(self, agent_id: str, attempt_sequence: int = 1) -> list[dict[str, Any]]:
        if self.mode == "no-progress":
            return []
        self._sequence += 1
        events = [{"sequence": self._sequence, "attempt_sequence": attempt_sequence, "event_type": "attempt_started", "redaction_level": "allowlisted"}]
        if self.mode in {"progress", "case-c"}:
            self._sequence += 1
            request_id = f"fake-request-{agent_id}-{attempt_sequence}"
            events.append({
                "sequence": self._sequence,
                "attempt_sequence": attempt_sequence,
                "event_type": "pending_request",
                "pending_request_id": request_id,
                "redaction_level": "allowlisted",
            })
            self._pending[request_id] = {
                "request_id": request_id,
                "kind": "permission",
                "state": "pending",
                "respondable": True,
                "tool_name": "bash",
                "operation": "command",
                "summary": "run bounded read-only check",
                "policy_preview": "externally_decidable",
                "responded": False,
            }
        if self.mode in {"progress", "case-c"}:
            for index, stage in enumerate(("inspection", "validation", "synthesis")):
                self._sequence += 1
                event = {
                    "sequence": self._sequence,
                    "attempt_sequence": attempt_sequence,
                    "event_type": "review_progress",
                    "redaction_level": "allowlisted",
                    "stage": stage,
                    "summary": f"fake {stage} progress",
                    "last_progress_at": int(time.time() * 1000),
                    "semantic_idle_ms": 0,
                    "nudge_sent": False,
                }
                if index != 1:  # counters are optional on the public schema
                    event["counters"] = {"checkpoints": 1}
                events.append(event)
        return events

    def call(self, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((tool, args))
        if self.mode == "restart-loss" and tool == "zcode_agent_get":
            return {"status": "not_found", "error_class": "SERVICE_GENERATION_MISMATCH"}
        if tool == "zcode_system_status":
            return {
                "api_surface": "subagent_v2",
                "protocol_version": 10,
                "service_generation": self.service_generation,
                "components": {
                    "daemon": "READY" if self.mode != "readiness-failure" else "UNAVAILABLE",
                    "runtime": "READY" if self.mode != "readiness-failure" else "UNAVAILABLE",
                    "store": "READY",
                    "scheduler": "READY",
                    "driver": "READY",
                    "facade": "UNKNOWN",
                    "model_auth": "READY",
                },
                "capabilities": {},
                "tools": sorted(REQUIRED_TOOLS),
            }
        if tool == "zcode_system_ensure_ready":
            if self.mode in {"no-progress", "readiness-timeout"}:
                status = self.call("zcode_system_status", {})
                return {"ready": False, "status": status, "probe_result": "NOT_OBSERVED_WITHIN_TIMEOUT", "reason_code": "NOT_OBSERVED_WITHIN_TIMEOUT"}
            if self.mode == "readiness-failure":
                status = self.call("zcode_system_status", {})
                return {"ready": False, "status": status, "probe_result": "RUNTIME_FAILED", "reason_code": "RUNTIME_FAILED"}
            return {"ready": True, "status": self.call("zcode_system_status", {}), "probe_result": "READY", "reason_code": None}
        if tool in {"zcode_review_spawn", "zcode_agent_spawn"}:
            key = str(args.get("idempotency_key", ""))
            if key in self.idempotencies:
                agent_id = self.idempotencies[key]
                task = self.agents.get(agent_id, {})
                return {
                    "agent_id": agent_id,
                    "review_id": f"review-{agent_id}",
                    "submission_disposition": "existing",
                    "phase": task.get("phase", "RUNNING"),
                    "attempt_sequence": task.get("attempt_sequence", 1),
                    "effective_budget": task.get("effective_budget", {}),
                    "provenance": self._review_provenance(task.get("attempt_sequence", 1)),
                    "counts_as_independent": False,
                }
            agent_id = f"fake-agent-{len(self.agents) + 1}"
            self.idempotencies[key] = agent_id
            self.agents[agent_id] = {
                "attempt_sequence": 1,
                "closed": False,
                "phase": "RUNNING",
                "review_id": f"review-{agent_id}",
                "events": self._events(agent_id),
                "responded_requests": set(),
                "nudge_count": 0,
                "wait_calls": 0,
            }
            budget = args.get("budget") or {
                "wall_time_ms": 300000,
                "semantic_soft_timeout_ms": 120000,
                "semantic_hard_timeout_ms": 300000,
                "max_turns": 10,
                "max_tool_calls": 100,
                "max_context_bytes": 4000000,
                "max_result_bytes": 1000000,
                "max_artifact_bytes": 4000000,
            }
            self.agents[agent_id]["effective_budget"] = budget
            return {
                "agent_id": agent_id,
                "review_id": f"review-{agent_id}",
                "submission_disposition": "created",
                "phase": "RUNNING",
                "attempt_sequence": 1,
                "effective_budget": budget,
                "provenance": self._review_provenance(1),
                "counts_as_independent": True,
            }
        if tool == "zcode_review_continue":
            agent_id = str(args.get("agent_id"))
            task = self.agents.setdefault(agent_id, {"attempt_sequence": 1, "closed": False, "events": []})
            if task.get("closed"):
                return {"isError": True, "content": [{"type": "text", "text": "conflict: agent is closed"}]}
            key = str(args.get("idempotency_key", ""))
            if key in self.continuations:
                _, attempt = self.continuations[key]
                return {
                    "agent_id": agent_id,
                    "review_id": str(args.get("review_id")),
                    "submission_disposition": "existing",
                    "phase": task.get("phase", "RUNNING"),
                    "attempt_sequence": attempt,
                    "effective_budget": task.get("effective_budget", {}),
                    "counts_as_independent": False,
                    "provenance": self._review_provenance(attempt),
                }
            task["attempt_sequence"] += 1
            task["phase"] = "RUNNING"
            task["wait_calls"] = 0
            self.continuations[key] = (agent_id, task["attempt_sequence"])
            task["events"].extend(self._events(agent_id, task["attempt_sequence"]))
            return {
                "agent_id": agent_id,
                "review_id": str(args.get("review_id")),
                "submission_disposition": "created",
                "phase": "RUNNING",
                "attempt_sequence": task["attempt_sequence"],
                "effective_budget": task.get("effective_budget", {}),
                "counts_as_independent": False,
                "provenance": self._review_provenance(task["attempt_sequence"]),
            }
        if tool == "zcode_agent_events":
            task = self.agents.setdefault(str(args.get("agent_id")), {"attempt_sequence": 1, "closed": False, "events": []})
            after = int(args.get("after_sequence", 0))
            events = [deepcopy(event) for event in task.get("events", []) if event["sequence"] > after]
            limit = int(args.get("limit", 100))
            page = events[:limit]
            return {"events": page, "next_sequence": page[-1]["sequence"] if page else after, "has_more": len(events) > len(page)}
        if tool == "zcode_agent_wait":
            after = int(args.get("after_sequence", 0))
            if self.mode == "no-progress":
                return {"task": {"phase": "RUNNING"}, "events": [], "next_sequence": after, "has_more": False, "timed_out": True, "status": "timeout", "progress": []}
            agent_id = str(args.get("agent_id"))
            task = self.agents.get(agent_id, {})
            if task.get("phase") == "TERMINAL":
                return {"task": {"phase": "TERMINAL", "attempt_sequence": task.get("attempt_sequence", 1)}, "events": [], "next_sequence": after, "has_more": False, "timed_out": False}
            current_events = task.get("events", [])
            if task.get("wait_calls", 0) == 0:
                task["wait_calls"] = 1
                visible = [deepcopy(event) for event in current_events if event["sequence"] > after]
                page = visible[:100]
                return {
                    "task": {"phase": "RUNNING", "attempt_sequence": task.get("attempt_sequence", 1)},
                    "events": page,
                    "next_sequence": page[-1]["sequence"] if page else after,
                    "has_more": len(visible) > len(page),
                    "timed_out": False,
                }
            progress = [event for event in current_events if event.get("event_type") == "review_progress" and event.get("attempt_sequence") == task.get("attempt_sequence", 1)]
            for event in progress:
                event["semantic_idle_ms"] = 120001
            if progress:
                progress[-1]["nudge_sent"] = True
            self._sequence += 1
            terminal_sequence = self._sequence
            task["phase"] = "TERMINAL"
            self._terminal.add(agent_id)
            terminal = {"sequence": terminal_sequence, "attempt_sequence": task.get("attempt_sequence", 1), "event_type": "terminal", "redaction_level": "allowlisted"}
            task["events"] = [*current_events, terminal]
            visible = [deepcopy(event) for event in task["events"] if event["sequence"] > after]
            page = visible[:100]
            return {
                "task": {"phase": "TERMINAL", "attempt_sequence": task.get("attempt_sequence", 1)},
                "events": page,
                "next_sequence": page[-1]["sequence"] if page else after,
                "has_more": len(visible) > len(page),
                "timed_out": False,
            }
        if tool == "zcode_agent_respond":
            request_id = str(args.get("request_id"))
            request = self._pending.get(request_id)
            if request is None:
                return {"isError": True, "content": [{"type": "text", "text": "not_found: request not found"}]}
            if request.get("responded"):
                disposition = "already_responded"
            else:
                request["responded"] = True
                disposition = "responded"
            agent_id = str(args.get("agent_id"))
            attempt = self.agents.get(agent_id, {}).get("attempt_sequence", 1)
            return {"disposition": disposition, "requested_decision": args.get("decision", "deny"), "effective_decision": "deny", "policy_overrode": False, "policy_reason_code": None, "attempt_sequence": attempt}
        if tool == "zcode_agent_message":
            agent_id = str(args.get("agent_id"))
            message_id = str(args.get("message_id"))
            task = self.agents.get(agent_id, {})
            delivered = task.setdefault("messages", {})
            if message_id in delivered:
                disposition = "already_delivered"
            else:
                delivered[message_id] = {
                    "mode": args.get("mode"),
                    "content": args.get("content"),
                }
                disposition = "queued"
            return {"disposition": disposition, "attempt_sequence": task.get("attempt_sequence", 1)}
        if tool == "zcode_agent_result":
            agent_id = str(args.get("agent_id"))
            task = self.agents.get(agent_id, {})
            attempt = int(args.get("attempt_sequence") or task.get("attempt_sequence", 1))
            artifact = (f"fake report attempt {attempt}\n").encode()
            artifact_id = f"fake-artifact-{attempt}"
            digest = hashlib.sha256(artifact).hexdigest()
            chunk = None
            if args.get("offset_bytes") is not None and args.get("limit_bytes") is not None:
                offset, limit = int(args["offset_bytes"]), int(args["limit_bytes"])
                if limit <= 0 or limit > MAX_ARTIFACT_CHUNK_BYTES:
                    return {"isError": True, "content": [{"type": "text", "text": "validation: artifact chunk size is outside the allowed range"}]}
                if offset < 0 or offset >= len(artifact):
                    return {"isError": True, "content": [{"type": "text", "text": "validation: artifact offset does not permit non-empty progress"}]}
                data = artifact[offset : offset + limit]
                chunk = {"artifact_id": artifact_id, "offset_bytes": offset, "returned_bytes": len(data), "eof": offset + len(data) == len(artifact), "sha256": digest, "size_bytes": len(artifact), "bytes_base64": base64.b64encode(data).decode()}
            return {
                "task": {"phase": "TERMINAL", "attempt_sequence": attempt, "effective_budget": task.get("effective_budget", {})},
                "result": {"outcome": "SUCCEEDED", "summary": "fake", "result_sha256": digest, "review_evidence": {
                    "final_signal": "PASS", "finalized": True, "report_revision": attempt,
                    "finalization_revision": attempt, "artifact": {"artifact_id": artifact_id, "sha256": digest, "size_bytes": len(artifact)},
                    "counts": {"checkpoints": 1, "findings": 0, "open_findings": 0, "validations": 1},
                    "independence": {"independent_evidence": attempt == 1, "fresh_session_observed": True, "counts_as_independent": attempt == 1},
                    "validation_provenance": {
                        "daemon_verification": {
                            "source_integrity_verified": True,
                            "finalized_report_verified": True,
                            "artifact_digest_verified": True,
                            "validation_records_structurally_verified": True,
                        },
                        "model_attestation": {"present": True, "validation_record_count": 1},
                    },
                }},
                "artifacts": [{"artifact_id": artifact_id, "kind": "report_markdown", "sha256": digest, "size_bytes": len(artifact)}],
                "artifact_chunk": chunk,
            }
        if tool == "zcode_agent_close":
            agent_id = str(args.get("agent_id"))
            task = self.agents.setdefault(agent_id, {"attempt_sequence": 1, "closed": False, "events": []})
            task["closed"] = True
            task["phase"] = "CLOSED"
            self._closed.add(agent_id)
            return {"task": {"phase": "CLOSED", "closed": True, "resources_reaped": True}}
        if tool == "zcode_agent_get":
            agent_id = str(args.get("agent_id"))
            task = self.agents.get(agent_id, {"phase": "RUNNING", "attempt_sequence": 1, "closed": False, "events": []})
            pending = [dict(value, respondable=not value.get("responded", False)) for value in self._pending.values() if not value.get("responded")]
            return {"task": {"phase": task.get("phase", "RUNNING"), "attempt_sequence": task.get("attempt_sequence", 1), "closed": task.get("closed", False), "resources_reaped": task.get("closed", False)}, "result": None, "artifacts": [], "pending_requests": pending}
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
    required_fields = {"artifact_id", "offset_bytes", "returned_bytes", "eof", "sha256", "size_bytes", "bytes_base64"}
    if not required_fields.issubset(chunk):
        raise ValueError("INVALID_ARTIFACT_CHUNK")
    if chunk.get("artifact_id") != artifact_id or chunk.get("sha256") != sha256:
        raise ValueError("ARTIFACT_METADATA_MISMATCH")
    if int(chunk.get("size_bytes", -1)) != size or int(chunk.get("offset_bytes", -1)) != offset:
        raise ValueError("INVALID_ARTIFACT_PROGRESS")
    encoded = chunk.get("bytes_base64", "")
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
_FORBIDDEN_CONTENT = re.compile(
    r"(?ix)(?:password|secret|api[_-]?key|authorization|cookie|credential)\s*[:=]"
    r"|\bbearer\s+[A-Za-z0-9._~+/=-]{8,}\b"
    r"|\b(?:token|password|secret|api[_-]?key|authorization)\s+[A-Za-z0-9._~+/=-]{8,}\b"
    r"|-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----"
)
_PLACEHOLDER_CONTENT = re.compile(
    r"(?im)(?:\{\{[^\n}]+\}\}|<placeholder>|\bTODO\b|\bTBD\b|"
    r"until a bounded official matrix is run|^Record (?:requested|continuation|artifact))"
)

# Pack roots are intentionally narrow.  This prevents a collector from
# silently smuggling arbitrary files into an otherwise valid evidence pack.
_PACK_ROOT_FILES: dict[str, tuple[re.Pattern[str], ...]] = {
    "fixtures": (re.compile(r"case-[0-9a-z-]+(?:-manifest)?\.json$"),),
    "normalized": (re.compile(r"(?:identity|catalog|readiness|case-[0-9a-z-]+)\.json$"),),
    "raw-transcripts": (re.compile(r"mcp\.jsonl$"),),
    "redacted-logs": (re.compile(r"(?:fatal|case-[0-9a-z-]+)\.json$"),),
}


def _check_pack_content(path: Path, data: bytes, *, relative: Path | None = None) -> None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"binary or invalid UTF-8 pack content: {path}") from exc
    if not text.strip():
        raise ValueError(f"empty pack evidence: {path}")
    if _FORBIDDEN_CONTENT.search(text) or _ABS.search(text):
        raise ValueError(f"unredacted secret or path in pack content: {path}")
    relative = relative or path
    if len(relative.parts) == 1:
        if _PLACEHOLDER_CONTENT.search(text):
            raise ValueError(f"template or placeholder content in rendered report: {relative}")
        return
    root = relative.parts[0]
    if root in {"fixtures", "normalized", "redacted-logs"}:
        try:
            value = json.loads(text)
        except ValueError as exc:
            raise ValueError(f"invalid JSON evidence: {relative}") from exc
        if not isinstance(value, Mapping):
            raise ValueError(f"JSON evidence root must be an object: {relative}")
    elif root == "raw-transcripts":
        lines = [line for line in text.splitlines() if line.strip()]
        if not lines:
            raise ValueError(f"empty JSONL evidence: {relative}")
        for line in lines:
            try:
                value = json.loads(line)
            except ValueError as exc:
                raise ValueError(f"invalid JSONL evidence: {relative}") from exc
            if not isinstance(value, Mapping):
                raise ValueError(f"JSONL evidence entry must be an object: {relative}")


def _check_pack_filename(relative: Path) -> None:
    if len(relative.parts) < 2:
        return
    root = relative.parts[0]
    patterns = _PACK_ROOT_FILES.get(root)
    if patterns is None:
        raise ValueError(f"unexpected pack root: {root}")
    if len(relative.parts) != 2:
        raise ValueError(f"nested pack path is not allowed: {relative}")
    if not any(pattern.fullmatch(relative.name) for pattern in patterns):
        raise ValueError(f"unexpected pack filename: {relative}")


def _pack_members(source: Path) -> list[Path]:
    if not source.is_dir() or source.is_symlink():
        raise ValueError("pack source must be a real directory")
    missing = [name for name in PACK_FILES if not (source / name).is_file() or (source / name).is_symlink()]
    if missing:
        raise ValueError("missing pack reports: " + ", ".join(missing))
    missing_directories = [name for name in PACK_DIRECTORIES if not (source / name).is_dir() or (source / name).is_symlink()]
    if missing_directories:
        raise ValueError("missing pack evidence roots: " + ", ".join(missing_directories))
    members: list[Path] = []
    root_counts = {name: 0 for name in PACK_DIRECTORIES}
    for path in sorted(source.rglob("*")):
        relative = path.relative_to(source)
        if path.is_symlink():
            raise ValueError(f"symlink is not allowed in pack: {relative}")
        if path.name in _BENIGN_EXCLUDED_NAMES or any(part in _BENIGN_EXCLUDED_NAMES for part in relative.parts):
            if len(relative.parts) > 1:
                raise ValueError(f"cache entry is not allowed in pack: {relative}")
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
        else:
            _check_pack_filename(relative)
        data = path.read_bytes()
        _check_pack_content(path, data, relative=relative)
        if len(relative.parts) > 1:
            root_counts[relative.parts[0]] += 1
        members.append(path)
    empty_roots = [name for name, count in root_counts.items() if count == 0]
    if empty_roots:
        raise ValueError("empty pack evidence roots: " + ", ".join(empty_roots))
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
        root_counts = {directory: 0 for directory in PACK_DIRECTORIES}
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
            if len(pure.parts) > 1:
                _check_pack_filename(pure)
            if not name.endswith("/"):
                _check_pack_content(Path(name), archive.read(name), relative=pure)
                if len(pure.parts) > 1:
                    root_counts[pure.parts[0]] += 1
        empty_roots = [name for name, count in root_counts.items() if count == 0]
        if empty_roots:
            raise ValueError("pack contains empty evidence roots: " + ", ".join(empty_roots))
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
