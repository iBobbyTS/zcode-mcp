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
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping

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
        validate_artifact_chunk,
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
        validate_artifact_chunk,
    )


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RUNTIME = Path("/Applications/ZCode.app/Contents/Resources/glm/zcode.cjs")
DEFAULT_PACK = Path.home() / "Desktop/audit-pack/zcode-mcp-official-runtime-conformance.zip"


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
    return {
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


def _call_case(client: PublicV2Client, case_dir: Path, manifest: Mapping[str, Any], output: Path) -> dict[str, Any]:
    args = _case_args(REPOSITORY_ROOT, case_dir, manifest, output)
    evidence: dict[str, Any] = {"case_id": manifest.get("case_id", case_dir.name), "calls": []}
    agent_id: str | None = None
    try:
        spawned = client.call("zcode_review_spawn", args, launches=True)
        evidence["spawn"] = spawned
        # Same idempotency key must return the original durable submission and
        # must not consume another official launch slot.
        evidence["idempotency_replay"] = client.call("zcode_review_spawn", args)
        agent_id = spawned.get("agent_id") if isinstance(spawned, Mapping) else None
        review_id = spawned.get("review_id") if isinstance(spawned, Mapping) else None
        if not isinstance(agent_id, str):
            raise FatalConformanceError("spawn response did not contain agent_id")
        evidence["get"] = client.call("zcode_agent_get", {"agent_id": agent_id})
        pending = evidence["get"].get("pending_requests", []) if isinstance(evidence["get"], Mapping) else []
        if pending:
            request = pending[0]
            request_id = request.get("request_id") if isinstance(request, Mapping) else None
            if isinstance(request_id, str):
                evidence["permission"] = client.call("zcode_agent_respond", {"agent_id": agent_id, "request_id": request_id, "decision": "deny", "reason": "bounded conformance"})
                evidence["permission_replay"] = client.call("zcode_agent_respond", {"agent_id": agent_id, "request_id": request_id, "decision": "deny", "reason": "bounded conformance"})
        evidence["list"] = client.call("zcode_agent_list", {"feature_id": "official-runtime-conformance", "limit": 100})
        events = client.call("zcode_agent_events", {"agent_id": agent_id, "after_sequence": 0, "limit": 100})
        evidence["events"] = events
        next_sequence = int(events.get("next_sequence", 0)) if isinstance(events, Mapping) else 0
        evidence["wait"] = client.call("zcode_agent_wait", {"agent_id": agent_id, "after_sequence": next_sequence, "timeout_ms": 100})
        if manifest.get("case_id") == "case-03-agent-control-lifecycle" and isinstance(review_id, str):
            continue_args = {
                "agent_id": agent_id,
                "review_id": review_id,
                "base_ref": args["base_ref"],
                "head_ref": args["head_ref"],
                "frozen_finding_ids": [],
                "idempotency_key": args["idempotency_key"] + ":continuation",
                "attachments": [],
            }
            # Case C is the fifth nominal launch (ensure-ready + A/B/C + C
            # continuation).  It preserves public identity while incrementing
            # attempt_sequence and is not independent evidence.
            evidence["continuation"] = client.call("zcode_review_continue", continue_args, launches=True)
        evidence["result"] = client.call("zcode_agent_result", {"agent_id": agent_id})
        # Verify first/middle/tail chunks against authoritative metadata.  The
        # chunks are bounded public calls and never consume launch slots.
        chunks: list[dict[str, Any]] = []
        result_value = evidence["result"]
        artifacts = result_value.get("artifacts", []) if isinstance(result_value, Mapping) else []
        for artifact in artifacts if isinstance(artifacts, list) else []:
            if not isinstance(artifact, Mapping):
                continue
            artifact_id, digest, size = artifact.get("artifact_id"), artifact.get("sha256"), artifact.get("size_bytes")
            if not isinstance(artifact_id, str) or not isinstance(digest, str) or not isinstance(size, int) or size <= 0:
                continue
            offsets = sorted({0, size // 2, size - 1})
            for offset in offsets:
                chunk_result = client.call("zcode_agent_result", {"agent_id": agent_id, "artifact_id": artifact_id, "offset_bytes": offset, "limit_bytes": min(8192, size - offset)})
                chunk = chunk_result.get("artifact_chunk") if isinstance(chunk_result, Mapping) else None
                if not isinstance(chunk, Mapping):
                    raise FatalConformanceError("artifact response omitted artifact_chunk")
                validate_artifact_chunk(chunk, artifact_id=artifact_id, sha256=digest, size=size, offset=offset, limit=min(8192, size - offset))
                chunks.append({"offset_bytes": offset, "artifact_id": artifact_id, "eof": chunk.get("eof"), "returned_bytes": chunk.get("returned_bytes")})
        evidence["artifact_chunks"] = chunks
        evidence["close"] = client.call("zcode_agent_close", {"agent_id": agent_id})
        evidence["close_replay"] = client.call("zcode_agent_close", {"agent_id": agent_id})
    except (FatalConformanceError, LaunchBudgetExceeded, TimeoutError, OSError, RuntimeError) as exc:
        evidence["error"] = {"class": type(exc).__name__, "message": str(exc)}
        evidence["conclusion"] = "FAIL" if isinstance(exc, FatalConformanceError) else "NOT_EXERCISED"
        if agent_id:
            try:
                evidence["cleanup_after_error"] = client.call("zcode_agent_close", {"agent_id": agent_id})
            except Exception:
                evidence["cleanup_after_error"] = {"status": "not_observed"}
    else:
        evidence["conclusion"] = "PASS_WITH_GAPS"
    return normalize(str(manifest.get("case_id", case_dir.name)), evidence)


def _copy_pack_inputs(root: Path, output: Path) -> Path:
    source = output / "pack-input"
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
    identity = {
        "repository_head": _git_head(REPOSITORY_ROOT),
        "mcp_binary": str(binary),
        "mcp_binary_sha256": _sha256(binary),
        "official_runtime": str(args.runtime),
        "official_runtime_sha256": _sha256(args.runtime),
        "official_runtime_present": args.runtime.is_file(),
        "mcp_config_sha256": _sha256(REPOSITORY_ROOT / "config/codex-zcode-subagent-mcp-v2.toml"),
        "service_socket": str(socket),
        "public_api_mode": env["ZCODE_PUBLIC_API_MODE"],
    }
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
        readiness = client.call("zcode_system_ensure_ready", {"timeout_ms": min(5000, max(1, int(args.timeout * 1000)))}, launches=True)
        _write_json(output / "normalized/readiness.json", {"status": status, "readiness": readiness})
        if isinstance(readiness, Mapping) and readiness.get("ready") is not True:
            raise FatalConformanceError("official runtime did not report READY")
        for case_dir in sorted(REPOSITORY_ROOT.glob("case-*/fixture-manifest.json")):
            manifest = json.loads(case_dir.read_text(encoding="utf-8"))
            case_root = case_dir.parent
            evidence = _call_case(client, case_root, manifest, output / "normalized")
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
