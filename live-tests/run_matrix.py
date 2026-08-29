#!/usr/bin/env python3
"""Bounded S02 matrix entry point. Real calls require --official and are never implicit."""
from __future__ import annotations
import argparse, hashlib, json, subprocess
from pathlib import Path
from conformance import LaunchLedger, PublicV2Client, normalize

RUNTIME = Path("/Applications/ZCode.app/Contents/Resources/glm/zcode.cjs")

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--official", action="store_true")
    parser.add_argument("--output", type=Path, default=Path(".agent-work/s02-normalized"))
    args = parser.parse_args()
    if not args.official:
        parser.error("refusing official calls without explicit --official")
    if not RUNTIME.is_file():
        raise SystemExit(f"official runtime missing: {RUNTIME}")
    args.output.mkdir(parents=True, exist_ok=True)
    identity = {"runtime_path": str(RUNTIME), "runtime_sha256": hashlib.sha256(RUNTIME.read_bytes()).hexdigest()}
    (args.output / "identity.json").write_text(json.dumps(identity, indent=2) + "\n")
    # Transport wiring is deliberately injected by the real Codex test environment.
    print("S02 matrix requires an injected public MCP transport; identity captured")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
