from __future__ import annotations

import base64
import hashlib
import json
import os
import select
import subprocess
import time
from pathlib import Path
from typing import Any, Mapping

REQUIRED_TOOLS = {
    "zcode_subagent_status",
    "zcode_subagent_spawn",
    "zcode_subagent_poll",
    "zcode_subagent_list",
    "zcode_subagent_send",
    "zcode_subagent_respond",
    "zcode_subagent_cancel",
    "zcode_subagent_result",
    "zcode_subagent_close",
}
MAX_ARTIFACT_CHUNK_BYTES = 8192


class ConformanceError(RuntimeError):
    pass


class StdioMCPTransport:
    def __init__(self, binary: Path, socket: Path, timeout_s: float = 10.0):
        self.timeout_s = timeout_s
        env = dict(os.environ)
        env["ZCODE_AGENTD_SOCKET"] = str(socket)
        self.process = subprocess.Popen(
            [str(binary)],
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self.sequence = 0
        self._request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "generic-live-agent", "version": "1"},
        })
        self._notify("notifications/initialized", {})

    def _notify(self, method: str, params: Mapping[str, Any]) -> None:
        self._write({"jsonrpc": "2.0", "method": method, "params": dict(params)})

    def _write(self, payload: Mapping[str, Any]) -> None:
        if self.process.stdin is None:
            raise ConformanceError("facade stdin is unavailable")
        self.process.stdin.write(json.dumps(payload, separators=(",", ":")) + "\n")
        self.process.stdin.flush()

    def _request(self, method: str, params: Mapping[str, Any]) -> dict[str, Any]:
        self.sequence += 1
        request_id = self.sequence
        self._write({"jsonrpc": "2.0", "id": request_id, "method": method, "params": dict(params)})
        deadline = time.monotonic() + self.timeout_s
        if self.process.stdout is None:
            raise ConformanceError("facade stdout is unavailable")
        while time.monotonic() < deadline:
            ready, _, _ = select.select([self.process.stdout], [], [], max(0.0, deadline - time.monotonic()))
            if not ready:
                break
            line = self.process.stdout.readline()
            if not line:
                break
            value = json.loads(line)
            if value.get("id") != request_id:
                continue
            if "error" in value:
                raise ConformanceError(f"MCP error: {value['error']}")
            return value["result"]
        raise ConformanceError(f"MCP request timed out: {method}")

    def tools(self) -> set[str]:
        result = self._request("tools/list", {})
        return {tool["name"] for tool in result.get("tools", [])}

    def call(self, tool: str, arguments: Mapping[str, Any]) -> dict[str, Any]:
        result = self._request("tools/call", {"name": tool, "arguments": dict(arguments)})
        if result.get("isError"):
            raise ConformanceError(f"tool failed: {tool}")
        structured = result.get("structuredContent")
        if not isinstance(structured, dict):
            raise ConformanceError(f"tool omitted structuredContent: {tool}")
        return structured

    def close(self) -> None:
        if self.process.stdin is not None:
            self.process.stdin.close()
        try:
            self.process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            self.process.wait(timeout=2)


def validate_catalog(transport: StdioMCPTransport) -> None:
    observed = transport.tools()
    if observed != REQUIRED_TOOLS:
        raise ConformanceError(f"unexpected catalog: {sorted(observed)}")


def collect_artifact(
    transport: StdioMCPTransport,
    agent_id: str,
    metadata: Mapping[str, Any],
) -> bytes:
    artifact_id = str(metadata["artifact_id"])
    size = int(metadata["size_bytes"])
    expected_sha = str(metadata["sha256"])
    data = bytearray()
    while len(data) < size:
        limit = min(MAX_ARTIFACT_CHUNK_BYTES, size - len(data))
        result = transport.call("zcode_subagent_result", {
            "agent_id": agent_id,
            "artifact_id": artifact_id,
            "offset_bytes": len(data),
            "limit_bytes": limit,
        })
        chunk = result.get("artifact_chunk")
        if not isinstance(chunk, dict):
            raise ConformanceError("artifact chunk is missing")
        if chunk.get("sha256") != expected_sha or int(chunk.get("size_bytes", -1)) != size:
            raise ConformanceError("artifact metadata changed during retrieval")
        decoded = base64.b64decode(chunk["bytes_base64"], validate=True)
        if not decoded:
            raise ConformanceError("artifact retrieval made no progress")
        data.extend(decoded)
    if len(data) != size or hashlib.sha256(data).hexdigest() != expected_sha:
        raise ConformanceError("artifact final digest mismatch")
    return bytes(data)
