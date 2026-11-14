"""Runs the Semgrep pack's own tests and checks parity with the AST engine (skipped without semgrep)."""

import subprocess
from collections import Counter
from pathlib import Path

import pytest

from odoo_sast.scanner import run_semgrep, scan_paths, semgrep_available, semgrep_binary

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(not semgrep_available(), reason="semgrep not installed")


def test_semgrep_annotations():
    proc = subprocess.run(
        [semgrep_binary(), "--test", "--metrics=off", "--config", "src/odoo_sast/semgrep", "tests/semgrep"],
        cwd=ROOT, capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_semgrep_matches_ast_engine_on_fixtures():
    for addon in ("vulnerable_addon", "fixed_addon"):
        path = str(ROOT / "tests" / "fixtures" / addon)
        sg = Counter(f.rule_id for f in run_semgrep([path], base=str(ROOT)))
        ast = Counter(f.rule_id for f in scan_paths([path], base=str(ROOT)))
        assert sg == ast, addon
