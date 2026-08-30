"""Regression tests for live-agent fixture materialization and contracts."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LIVE_AGENT_CODE = ROOT / "tests" / "live-agent" / "non-git-based"
sys.path.insert(0, str(LIVE_AGENT_CODE))

from fixture_workspace import (  # noqa: E402
    GIT_BASED_ROOT,
    NON_GIT_BASED_ROOT,
    WORKSPACE_ROOT,
    create_execution_root,
    materialize,
    materialize_git_cases,
)


CASES = (
    "case-01-user-fuzzy-search",
    "case-02-shared-group-members",
    "case-03-agent-control-lifecycle",
)
GIT_FIXTURES_AVAILABLE = all(
    (GIT_BASED_ROOT / name / "fixture-manifest.json").is_file() for name in CASES
)


def readonly_snapshot(root: Path) -> str:
    """Hash source paths and content without mutating scenario material."""
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


class FixtureWorkspaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.execution_root = create_execution_root("unit-materialize-")

    def tearDown(self) -> None:
        shutil.rmtree(self.execution_root, ignore_errors=True)

    def test_non_git_scenario_is_copied_before_mutation(self) -> None:
        source = NON_GIT_BASED_ROOT / "fixtures" / "tiny-agent"
        before = readonly_snapshot(source)
        copied = materialize(source, self.execution_root)
        (copied / "input.txt").write_text("changed only in execution\n", encoding="utf-8")
        self.assertEqual(readonly_snapshot(source), before)
        self.assertNotEqual((source / "input.txt").read_bytes(), (copied / "input.txt").read_bytes())
        self.assertEqual(copied.parent, self.execution_root)
        self.assertFalse(any(copied.rglob(".DS_Store")))

    def test_materializer_rejects_source_and_execution_escape(self) -> None:
        source = NON_GIT_BASED_ROOT / "fixtures" / "tiny-agent"
        with tempfile.TemporaryDirectory() as outside:
            with self.assertRaisesRegex(ValueError, "outside live-agent workspace"):
                materialize(source, Path(outside))
            with self.assertRaisesRegex(ValueError, "outside live-agent source roots"):
                materialize(Path(outside), self.execution_root)


@unittest.skipUnless(GIT_FIXTURES_AVAILABLE, "local Git-based live-agent fixtures are not installed")
class FixtureContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.source_snapshot = readonly_snapshot(GIT_BASED_ROOT)
        self.execution_root = create_execution_root("fixture-contract-")
        self.cases = {
            case.name: case for case in materialize_git_cases(self.execution_root, CASES)
        }

    def tearDown(self) -> None:
        self.assertEqual(readonly_snapshot(GIT_BASED_ROOT), self.source_snapshot)
        shutil.rmtree(self.execution_root, ignore_errors=True)

    def run_script(self, case: Path, command: str) -> dict:
        result = subprocess.run(
            [str(case / "scripts" / f"{command}.sh")],
            check=True,
            capture_output=True,
            text=True,
        )
        return json.loads(result.stdout)

    def test_reset_verify_is_deterministic_for_all_cases(self) -> None:
        for name in CASES:
            with self.subTest(case=name):
                case = self.cases[name]
                outputs = []
                for _ in range(3):
                    subprocess.run(
                        [str(case / "scripts" / "reset.sh")],
                        check=True,
                        capture_output=True,
                        text=True,
                    )
                    outputs.append(self.run_script(case, "verify"))
                self.assertEqual(outputs[0], outputs[1])
                self.assertEqual(outputs[1], outputs[2])
                expected = json.loads((case / "fixture-manifest.json").read_text())
                self.assertEqual(
                    outputs[0]["tracked_files"],
                    expected["expected_reset_identity"]["tracked_files"],
                )

    def test_verify_works_without_nested_git_checkout(self) -> None:
        for name in CASES:
            with self.subTest(case=name):
                case = self.cases[name]
                subprocess.run(
                    [str(case / "scripts" / "reset.sh")],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                nested_git = case / "workspace" / ".git"
                detached = self.execution_root / f".{name}-git-test-backup"
                nested_git.rename(detached)
                try:
                    output = self.run_script(case, "verify")
                    expected = json.loads((case / "fixture-manifest.json").read_text())
                    self.assertEqual(
                        output["tracked_files"],
                        expected["expected_reset_identity"]["tracked_files"],
                    )
                finally:
                    detached.rename(nested_git)

    def test_case_shapes_and_source_allowlist_are_complete(self) -> None:
        for name in CASES:
            case = self.cases[name]
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

    def assert_verify_rejects(
        self,
        case: Path,
        relative: str,
        content: bytes = b"injected",
    ) -> None:
        target = case / relative
        self.assertFalse(target.exists(), target)
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            target.write_bytes(content)
            result = subprocess.run(
                [str(case / "scripts" / "verify.sh")], capture_output=True, text=True
            )
            self.assertNotEqual(result.returncode, 0, result.stdout)
        finally:
            target.unlink(missing_ok=True)
            parent = target.parent
            while parent != case and parent != self.execution_root:
                try:
                    parent.rmdir()
                except OSError:
                    break
                parent = parent.parent

    def test_negative_forbidden_path_content_symlink_and_inventory_injections(self) -> None:
        for name in CASES:
            with self.subTest(case=name):
                case = self.cases[name]
                subprocess.run(
                    [str(case / "scripts" / "reset.sh")],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                self.assert_verify_rejects(case, "workspace/__MACOSX/injected")
                self.assert_verify_rejects(
                    case,
                    "workspace/credentials.txt",
                    b"-----BEGIN RSA PRIVATE KEY-----",
                )
                self.assert_verify_rejects(case, "workspace/inventory-injected.txt")
                for relative in (
                    "workspace/empty-directory",
                    "future-fix-empty",
                    "workspace/selected-fix-empty",
                ):
                    empty = case / relative
                    empty.mkdir()
                    try:
                        result = subprocess.run(
                            [str(case / "scripts" / "verify.sh")],
                            capture_output=True,
                            text=True,
                        )
                        self.assertNotEqual(result.returncode, 0, result.stdout)
                    finally:
                        empty.rmdir()
                link = case / "workspace" / "injected-link"
                link.symlink_to(tempfile.gettempdir())
                try:
                    result = subprocess.run(
                        [str(case / "scripts" / "verify.sh")],
                        capture_output=True,
                        text=True,
                    )
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                finally:
                    link.unlink(missing_ok=True)
                git_cache = case / "workspace" / ".git" / "audit-cache"
                git_cache.mkdir(parents=True)
                try:
                    result = subprocess.run(
                        [str(case / "scripts" / "verify.sh")],
                        capture_output=True,
                        text=True,
                    )
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                finally:
                    git_cache.rmdir()

    def test_source_inventory_digest_is_immutable_across_verify(self) -> None:
        for name in CASES:
            with self.subTest(case=name):
                case = self.cases[name]
                subprocess.run(
                    [str(case / "scripts" / "reset.sh")],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                before = self.run_script(case, "verify")["workspace_sha256"]
                after = self.run_script(case, "verify")["workspace_sha256"]
                self.assertEqual(before, after)

    def test_manifest_and_context_checksums_reject_regression(self) -> None:
        for name in CASES:
            with self.subTest(case=name):
                case = self.cases[name]
                subprocess.run(
                    [str(case / "scripts" / "reset.sh")],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                manifest = case / "fixture-manifest.json"
                original = manifest.read_bytes()
                try:
                    manifest.write_bytes(
                        original.replace(b'"manifest_sha256": "', b'"manifest_sha256": "0', 1)
                    )
                    result = subprocess.run(
                        [str(case / "scripts" / "verify.sh")],
                        capture_output=True,
                        text=True,
                    )
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                finally:
                    manifest.write_bytes(original)
                context = case / "requirements" / "REQUIREMENTS.md"
                original_context = context.read_bytes()
                try:
                    context.write_bytes(original_context + b"\nfuture-ref injection\n")
                    result = subprocess.run(
                        [str(case / "scripts" / "verify.sh")],
                        capture_output=True,
                        text=True,
                    )
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                finally:
                    context.write_bytes(original_context)


if __name__ == "__main__":
    unittest.main(verbosity=2)
