"""Directly executable regression tests for the S01 fixture contract."""
from __future__ import annotations

import json
import hashlib
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CASES = ("case-01-user-fuzzy-search", "case-02-shared-group-members", "case-03-agent-control-lifecycle")
SOURCE_ROOT = Path("/Users/ibobby/Projects/zcode-mcp-agent-live-test-workspace")


def readonly_snapshot(root: Path) -> str:
    """Hash source paths/content without copying or mutating evaluator material."""
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            kind, payload = "L", os.readlink(path).encode()
        elif path.is_dir():
            kind, payload = "D", b""
        elif path.is_file():
            kind, payload = "F", path.read_bytes()
        else:
            kind, payload = "?", b""
        digest.update(kind.encode() + b"\0" + relative.encode() + b"\0")
        digest.update(str(stat.S_IMODE(path.lstat().st_mode)).encode() + b"\0")
        digest.update(str(len(payload)).encode() + b"\0" + payload + b"\0")
    return digest.hexdigest()


class FixtureContractTests(unittest.TestCase):
    def run_script(self, case: Path, command: str) -> dict:
        result = subprocess.run([str(case / "scripts" / f"{command}.sh")], check=True, capture_output=True, text=True)
        return json.loads(result.stdout)

    def test_reset_verify_is_deterministic_for_all_cases(self) -> None:
        for name in CASES:
            with self.subTest(case=name):
                case = ROOT / name
                outputs = []
                for _ in range(3):
                    subprocess.run([str(case / "scripts" / "reset.sh")], check=True, capture_output=True, text=True)
                    outputs.append(self.run_script(case, "verify"))
                self.assertEqual(outputs[0], outputs[1])
                self.assertEqual(outputs[1], outputs[2])
                self.assertEqual(outputs[0]["tracked_files"], json.loads((case / "fixture-manifest.json").read_text())["expected_reset_identity"]["tracked_files"])

    def test_verify_works_without_nested_git_checkout(self) -> None:
        for name in CASES:
            with self.subTest(case=name):
                case = ROOT / name
                subprocess.run([str(case / "scripts" / "reset.sh")], check=True, capture_output=True, text=True)
                nested_git = case / "workspace" / ".git"
                detached = ROOT / f".{name}-git-test-backup"
                nested_git.rename(detached)
                try:
                    result = subprocess.run([str(case / "scripts" / "verify.sh")], check=True, capture_output=True, text=True)
                    output = json.loads(result.stdout)
                    self.assertEqual(output["tracked_files"], json.loads((case / "fixture-manifest.json").read_text())["expected_reset_identity"]["tracked_files"])
                finally:
                    detached.rename(nested_git)

    def test_case_shapes_and_source_allowlist_are_complete(self) -> None:
        for name in CASES:
            case = ROOT / name
            manifest = json.loads((case / "fixture-manifest.json").read_text())
            self.assertEqual(manifest["source_allowlist"]["root"], "workspace")
            self.assertEqual(manifest["source_allowlist"]["exclude"], ["workspace/.git/**"])
            shape = manifest["shape"]
            self.assertIn("changed_files", shape)
            self.assertIn("owners", shape, name)
            if name == CASES[0]:
                self.assertIn("diff_lines", shape)
            elif name == CASES[1]:
                self.assertIn("diff_lines", shape)
                self.assertTrue(shape["historical_path"])
            else:
                self.assertTrue(shape["continuation"]["required"])
                self.assertEqual(shape["thresholds"]["max_retry_count"], 2)
                self.assertTrue((case / shape["continuation"]["hook"]).is_file())

    def assert_verify_rejects(self, case: Path, relative: str, content: bytes = b"injected") -> None:
        target = case / relative
        self.assertFalse(target.exists(), target)
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            target.write_bytes(content)
            result = subprocess.run([str(case / "scripts" / "verify.sh")], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0, result.stdout)
        finally:
            target.unlink(missing_ok=True)
            parent = target.parent
            while parent != case and parent != ROOT:
                try:
                    parent.rmdir()
                except OSError:
                    break
                parent = parent.parent

    def test_negative_forbidden_path_content_symlink_and_inventory_injections(self) -> None:
        for name in CASES:
            with self.subTest(case=name):
                case = ROOT / name
                subprocess.run([str(case / "scripts" / "reset.sh")], check=True, capture_output=True, text=True)
                self.assert_verify_rejects(case, "workspace/__MACOSX/injected")
                self.assert_verify_rejects(case, "workspace/credentials.txt", b"-----BEGIN RSA PRIVATE KEY-----")
                self.assert_verify_rejects(case, "workspace/inventory-injected.txt")
                empty = case / "workspace" / "empty-directory"
                empty.mkdir()
                try:
                    result = subprocess.run([str(case / "scripts" / "verify.sh")], capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                finally:
                    empty.rmdir()
                outer = case / "future-fix-empty"
                outer.mkdir()
                try:
                    result = subprocess.run([str(case / "scripts" / "verify.sh")], capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                finally:
                    outer.rmdir()
                singular = case / "workspace" / "selected-fix-empty"
                singular.mkdir()
                try:
                    result = subprocess.run([str(case / "scripts" / "verify.sh")], capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                finally:
                    singular.rmdir()
                link = case / "workspace" / "injected-link"
                link.symlink_to(tempfile.gettempdir())
                try:
                    result = subprocess.run([str(case / "scripts" / "verify.sh")], capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                finally:
                    link.unlink(missing_ok=True)
                git_cache = case / "workspace" / ".git" / "audit-cache"
                git_cache.mkdir(parents=True)
                try:
                    result = subprocess.run([str(case / "scripts" / "verify.sh")], capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                finally:
                    git_cache.rmdir()

    def test_source_inventory_digest_is_immutable_across_verify(self) -> None:
        for name in CASES:
            with self.subTest(case=name):
                case = ROOT / name
                subprocess.run([str(case / "scripts" / "reset.sh")], check=True, capture_output=True, text=True)
                before = self.run_script(case, "verify")["workspace_sha256"]
                after = self.run_script(case, "verify")["workspace_sha256"]
                self.assertEqual(before, after)

    def test_source_snapshot_is_read_only_and_unchanged(self) -> None:
        self.assertTrue(SOURCE_ROOT.is_dir(), SOURCE_ROOT)
        before = readonly_snapshot(SOURCE_ROOT)
        for name in CASES:
            subprocess.run([str(ROOT / name / "scripts" / "reset.sh")], check=True, capture_output=True, text=True)
        after = readonly_snapshot(SOURCE_ROOT)
        self.assertEqual(before, after)

    def test_manifest_and_context_checksums_reject_regression(self) -> None:
        for name in CASES:
            with self.subTest(case=name):
                case = ROOT / name
                subprocess.run([str(case / "scripts" / "reset.sh")], check=True, capture_output=True, text=True)
                manifest = case / "fixture-manifest.json"
                original = manifest.read_bytes()
                try:
                    tampered = original.replace(b'"manifest_sha256": "', b'"manifest_sha256": "0', 1)
                    manifest.write_bytes(tampered)
                    result = subprocess.run([str(case / "scripts" / "verify.sh")], capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                finally:
                    manifest.write_bytes(original)
                context = case / "requirements" / "REQUIREMENTS.md"
                original_context = context.read_bytes()
                try:
                    context.write_bytes(original_context + b"\nfuture-ref injection\n")
                    result = subprocess.run([str(case / "scripts" / "verify.sh")], capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                finally:
                    context.write_bytes(original_context)


if __name__ == "__main__":
    unittest.main(verbosity=2)
