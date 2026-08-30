"""Materialize live-agent scenarios into the ignored execution workspace."""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import Iterable


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
LIVE_AGENT_ROOT = REPOSITORY_ROOT / "tests" / "live-agent"
NON_GIT_BASED_ROOT = LIVE_AGENT_ROOT / "non-git-based"
GIT_BASED_ROOT = LIVE_AGENT_ROOT / "git-based"
WORKSPACE_ROOT = LIVE_AGENT_ROOT / "workspace"


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def create_execution_root(prefix: str = "run-") -> Path:
    """Create one unique execution root beneath the ignored workspace."""
    WORKSPACE_ROOT.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix=prefix, dir=WORKSPACE_ROOT)).resolve()


def materialize(source: Path, execution_root: Path) -> Path:
    """Copy one immutable scenario source into an execution root."""
    source = source.resolve()
    execution_root = execution_root.resolve()
    allowed_sources = (NON_GIT_BASED_ROOT.resolve(), GIT_BASED_ROOT.resolve())
    if not any(_is_relative_to(source, root) for root in allowed_sources):
        raise ValueError(f"scenario source is outside live-agent source roots: {source}")
    if not _is_relative_to(execution_root, WORKSPACE_ROOT.resolve()):
        raise ValueError(f"execution root is outside live-agent workspace: {execution_root}")
    if not source.is_dir():
        raise FileNotFoundError(f"scenario source is missing: {source}")
    for path in source.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"scenario source contains a symlink: {path}")

    target = execution_root / source.name
    if target.exists():
        raise FileExistsError(f"scenario execution target already exists: {target}")
    shutil.copytree(
        source,
        target,
        copy_function=shutil.copy2,
        ignore=shutil.ignore_patterns(".DS_Store", "__pycache__", "*.pyc", "*.pyo"),
    )
    return target


def materialize_git_cases(
    execution_root: Path,
    names: Iterable[str] | None = None,
) -> list[Path]:
    """Copy every requested local Git-based case into one execution root."""
    selected = list(names) if names is not None else sorted(
        path.parent.name for path in GIT_BASED_ROOT.glob("case-*/fixture-manifest.json")
    )
    if not selected:
        raise FileNotFoundError(f"no Git-based live-agent cases found in {GIT_BASED_ROOT}")
    return [materialize(GIT_BASED_ROOT / name, execution_root) for name in selected]
