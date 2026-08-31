"""Compatibility and dependency guards for the split config loader."""

from __future__ import annotations

import ast
import hashlib
import os
import subprocess
import sys
from pathlib import Path

from kiro_crew.config import loader, resolution, sections

_HISTORICAL_REEXPORT_SNAPSHOTS = {
    "kiro_crew.config.sections": (
        184,
        "28c2cc9387985bd58d94c88437e85823fd770edf0ffc6f4e631058a7e97636e4",
    ),
    "kiro_crew.config.resolution": (
        11,
        "5f593eb9442e1b5f984a87a2352b85fe0d8fe9d7d94027199b3196a7e5e68a54",
    ),
}


def _loader_reexports(module_name: str) -> set[str]:
    """Names explicitly imported from *module_name* by the compatibility facade."""
    tree = ast.parse(Path(loader.__file__).read_text(encoding="utf-8"))
    return {
        alias.asname or alias.name
        for node in tree.body
        if isinstance(node, ast.ImportFrom) and node.module == module_name
        for alias in node.names
    }


def _snapshot(names: set[str]) -> tuple[int, str]:
    payload = "\0".join(sorted(names)).encode()
    return len(names), hashlib.sha256(payload).hexdigest()


def test_loader_reexports_historical_snapshot_by_identity() -> None:
    """Historical aliases stay frozen without exporting future module internals."""
    reexports = {
        module.__name__: _loader_reexports(module.__name__) for module in (sections, resolution)
    }
    assert {
        name: _snapshot(names) for name, names in reexports.items()
    } == _HISTORICAL_REEXPORT_SNAPSHOTS

    mismatches = [
        f"{module.__name__}.{name}"
        for module in (sections, resolution)
        for name in sorted(reexports[module.__name__])
        if getattr(loader, name, None) is not getattr(module, name)
    ]
    assert mismatches == []


def test_extracted_modules_do_not_import_the_loader() -> None:
    """The facade owns orchestration; extracted modules cannot depend back on it."""
    code = (
        "import sys\n"
        "import kiro_crew.config.sections\n"
        "import kiro_crew.config.resolution\n"
        "forbidden = (\n"
        "    'kiro_crew.config.loader',\n"
        "    'kiro_crew.config.schema',\n"
        "    'kiro_crew.config.validation',\n"
        ")\n"
        "print(','.join(name for name in forbidden if name in sys.modules))\n"
    )
    src_dir = str(Path(__file__).resolve().parents[1] / "src")
    env = dict(os.environ)
    env["PYTHONPATH"] = src_dir + os.pathsep + env.get("PYTHONPATH", "")
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
        env=env,
    )
    assert result.stdout.strip() == ""
