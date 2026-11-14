"""Walk addon trees and run every engine."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Iterable, List

from .finding import Finding
from .python_checks import check_python_source
from .qweb_checks import check_xml_source
from .rules import RULES

SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".tox", "build", "dist"}
SEMGREP_PACK = Path(__file__).with_name("semgrep")
SEMGREP_ID_RE = re.compile(r"(ods\d{3})", re.I)


def iter_files(paths: Iterable[str]) -> Iterable[Path]:
    for p in paths:
        p = Path(p)
        if p.is_file():
            yield p
            continue
        for root, dirs, files in os.walk(p):
            dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
            for name in sorted(files):
                if name.endswith((".py", ".xml")):
                    yield Path(root) / name


def scan_paths(paths: Iterable[str], base: str = ".") -> List[Finding]:
    findings: List[Finding] = []
    for f in iter_files(paths):
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = os.path.relpath(f, base)
        if f.suffix == ".py":
            findings += check_python_source(rel, text)
        elif f.suffix == ".xml":
            findings += check_xml_source(rel, text)
    return sorted(set(findings))


def semgrep_available() -> bool:
    return shutil.which("semgrep") is not None


def run_semgrep(paths: Iterable[str], base: str = ".") -> List[Finding]:
    """Run the bundled Semgrep pack and map results onto ODS rule ids."""
    cmd = ["semgrep", "scan", "--config", str(SEMGREP_PACK), "--json", "--quiet",
           "--metrics=off", "--disable-version-check", *paths]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode not in (0, 1):
        raise RuntimeError(f"semgrep failed ({proc.returncode}): {proc.stderr.strip()[:500]}")
    data = json.loads(proc.stdout or "{}")
    out = []
    for r in data.get("results", []):
        m = SEMGREP_ID_RE.search(r.get("check_id", ""))
        if not m or m.group(1).upper() not in RULES:
            continue
        sev = {"ERROR": "error", "WARNING": "warning", "INFO": "note"}.get(r["extra"].get("severity"), "")
        out.append(Finding(os.path.relpath(r["path"], base), r["start"]["line"], r["start"]["col"],
                           m.group(1).upper(), r["extra"].get("message", "").strip().splitlines()[0],
                           sev, engine="semgrep"))
    return out


def merge(primary: List[Finding], extra: List[Finding]) -> List[Finding]:
    """Add Semgrep findings that the AST engine did not already report on the same line."""
    seen = {(f.path, f.line, f.rule_id) for f in primary}
    return sorted(primary + [f for f in extra if (f.path, f.line, f.rule_id) not in seen])
