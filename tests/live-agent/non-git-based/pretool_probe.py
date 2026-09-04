#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path

from fixture_workspace import REPOSITORY_ROOT, create_execution_root


WRITE_CONTENT = "official workspace write passed."
WRITE_FILE = "output.txt"
WRITE_CHECK_ID = "output-content"
READ_LINK = "outside-link.txt"
READ_CONTENT = "benign symlink escape fixture"
ZCODE_LOG_ROOT = Path.home() / ".zcode" / "cli" / "log"


def write_prompt() -> str:
    return (
        f"Use the Write tool to create the relative file {WRITE_FILE} with exactly this one line: "
        f"{WRITE_CONTENT} Do not use Bash and do not modify any other file. Then end the turn."
    )


def write_catalog(repository: Path) -> dict[str, object]:
    return {
        "schema": "zcode-general-command-catalog/v1",
        "commands": [{
            "repository": str(repository.resolve()),
            "command_id": WRITE_CHECK_ID,
            "command": {
                "program": "/usr/bin/grep",
                "args": ["-Fx", WRITE_CONTENT, WRITE_FILE],
                "cwd": ".",
                "timeout_ms": 5000,
                "max_output_bytes": 1024,
            },
            "allowed_access_modes": ["workspace_write"],
            "readonly_safe": False,
        }],
    }


def read_prompt() -> str:
    return (
        f"Use the Read tool exactly once on the relative path {READ_LINK}. "
        "Do not use Bash or another file tool. Report whether the read was denied, then end the turn."
    )


def git(*arguments: str, cwd: Path) -> str:
    return subprocess.check_output(["git", "-C", str(cwd), *arguments], text=True).strip()


def initialize_repository(repository: Path) -> str:
    subprocess.run(["git", "init", "-q", "-b", "main", str(repository)], check=True)
    (repository / "README.md").write_text("S03 PreToolUse probe.\n", encoding="utf-8")
    git("add", "README.md", cwd=repository)
    subprocess.run(
        ["git", "-C", str(repository), "-c", "user.name=S03 Probe",
         "-c", "user.email=s03@example.invalid", "commit", "-q", "-m", "test: initialize probe"],
        check=True,
    )
    return git("rev-parse", "HEAD", cwd=repository)


def make_write_fixture(root: Path) -> tuple[Path, Path, str]:
    repository = root / "repository"
    repository.mkdir()
    head = initialize_repository(repository)
    catalog = root / "command-catalog.json"
    catalog.write_text(json.dumps(write_catalog(repository), indent=2) + "\n", encoding="utf-8")
    return repository, catalog, head


def make_read_fixture(root: Path) -> tuple[Path, str]:
    outside = root / "benign-outside.txt"
    outside.write_text(f"{READ_CONTENT}\n", encoding="utf-8")
    repository = root / "repository"
    repository.mkdir()
    head = initialize_repository(repository)
    (repository / READ_LINK).symlink_to(outside)
    git("add", READ_LINK, cwd=repository)
    subprocess.run(
        ["git", "-C", str(repository), "-c", "user.name=S03 Probe",
         "-c", "user.email=s03@example.invalid", "commit", "-q", "-m", "test: add escape symlink"],
        check=True,
    )
    return repository, git("rev-parse", "HEAD", cwd=repository)


def validate_write_evidence(evidence: dict[str, object]) -> None:
    if evidence.get("outcome") != "COMPLETED" or evidence.get("phase") != "TERMINAL":
        raise RuntimeError("official write did not complete successfully")
    if evidence.get("changed_files") != [WRITE_FILE]:
        raise RuntimeError("official write changed_files did not match the manifest")
    if WRITE_CHECK_ID not in evidence.get("checks", []):
        raise RuntimeError("required named check was not bound to the result")
    patches = [item for item in evidence.get("artifacts", []) if item.get("kind") == "changes_patch"]
    if len(patches) != 1 or not patches[0].get("verified") or not patches[0].get("applicable"):
        raise RuntimeError("official write patch was absent, invalid, or inapplicable")
    if not evidence.get("resources_reaped") or not evidence.get("daemon_reaped"):
        raise RuntimeError("official write resources were not cleanly reaped")


def validate_read_evidence(evidence: dict[str, object]) -> None:
    activity = evidence.get("activity", {})
    if int(activity.get("max_read_calls_60s", 0)) != 0:
        raise RuntimeError("PreToolUse denial did not precede tool.call.started")
    diagnostic = evidence.get("pretool_diagnostic", {})
    hook_denied = (
        isinstance(diagnostic, dict)
        and diagnostic.get("tool_name") == "Read"
        and diagnostic.get("decision") == "deny"
        and diagnostic.get("decision_code") == "symlink_escape"
        and isinstance(diagnostic.get("raw_line_sha256"), str)
        and len(diagnostic["raw_line_sha256"]) == 64
    )
    if not hook_denied:
        raise RuntimeError("scheduled Read did not produce a verifiable PreToolUse denial")
    if evidence.get("result_content_excluded") is not True:
        raise RuntimeError("external benign fixture content was not proven absent from result")
    if not evidence.get("resources_reaped") or not evidence.get("daemon_reaped"):
        raise RuntimeError("official read resources were not cleanly reaped")


def scan_pretool_diagnostic(log_root: Path, since_ns: int) -> dict[str, object] | None:
    if not log_root.is_dir():
        return None
    marker = "zcode-agent-file-policy/v1.0.0: symlink_escape"
    matches: list[bytes] = []
    for path in log_root.glob("*.jsonl"):
        if not path.is_file() or path.stat().st_mtime_ns < since_ns:
            continue
        with path.open("rb") as stream:
            for line in stream:
                if marker.encode() in line:
                    matches.append(line.rstrip(b"\r\n"))
    if not matches:
        return None
    return {
        "tool_name": "Read",
        "event_count": len(matches),
        "decision": "deny",
        "decision_code": "symlink_escape",
        "raw_line_sha256": __import__("hashlib").sha256(matches[-1]).hexdigest(),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("scenario", choices=["write-allow", "read-deny"])
    parser.add_argument("--daemon", type=Path, required=True)
    parser.add_argument("--facade", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    args = parser.parse_args()
    root = create_execution_root(f"pretool-{args.scenario}-")
    if args.scenario == "write-allow":
        repository, catalog, head = make_write_fixture(root)
        extra = ["--access-mode", "workspace_write", "--write-manifest", WRITE_FILE,
                 "--command-catalog", str(catalog), "--required-command-id", WRITE_CHECK_ID,
                 "--permission-decision", "allow", "--prompt", write_prompt()]
    else:
        repository, head = make_read_fixture(root)
        extra = ["--access-mode", "read_only", "--permission-decision", "deny",
                 "--forbid-result-text", READ_CONTENT, "--prompt", read_prompt()]
    command = [
        sys.executable, str(Path(__file__).with_name("run_matrix.py")),
        "--daemon", str(args.daemon.resolve()), "--facade", str(args.facade.resolve()),
        "--runtime", str(args.runtime.resolve()), "--repository", str(repository),
        "--base-ref", head, "--group-id", f"s03-{args.scenario}",
        "--idempotency-key", f"s03-{args.scenario}-{uuid.uuid4()}",
        "--poll-timeout-ms", "5000", "--poll-interval-seconds", "15",
        "--max-polls", "60", "--minimal-evidence", *extra,
    ]
    started_ns = time.time_ns()
    completed = subprocess.run(command, cwd=REPOSITORY_ROOT, text=True, capture_output=True)
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or "generic lifecycle runner failed")
    summary = json.loads(completed.stdout)
    evidence_path = Path(summary["execution_root"]) / "evidence.json"
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    if args.scenario == "write-allow":
        validate_write_evidence(evidence)
    else:
        evidence["pretool_diagnostic"] = scan_pretool_diagnostic(ZCODE_LOG_ROOT, started_ns)
        evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        validate_read_evidence(evidence)
    print(json.dumps({"scenario": args.scenario, "evidence": str(evidence_path)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
