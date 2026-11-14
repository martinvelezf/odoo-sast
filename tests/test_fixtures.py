"""Every rule fires on the vulnerable addon and nothing fires on the fixed one."""

from collections import Counter
from pathlib import Path

import pytest

from odoo_sast.rules import RULES
from odoo_sast.scanner import scan_paths

FIX = Path(__file__).parent / "fixtures"

# rule -> number of expected findings in the vulnerable addon
EXPECTED = {
    "ODS001": 2,
    "ODS002": 1,
    "ODS003": 1,
    "ODS004": 1,
    "ODS005": 4,
    "ODS006": 2,
    "ODS101": 2,
    "ODS102": 1,
}


def test_every_rule_has_an_expectation():
    assert set(EXPECTED) == set(RULES)


@pytest.mark.parametrize("rule_id", sorted(EXPECTED))
def test_rule_fires_on_vulnerable_addon(rule_id):
    counts = Counter(f.rule_id for f in scan_paths([str(FIX / "vulnerable_addon")]))
    assert counts[rule_id] == EXPECTED[rule_id]


@pytest.mark.parametrize("rule_id", sorted(EXPECTED))
def test_rule_silent_on_fixed_addon(rule_id):
    hits = [f for f in scan_paths([str(FIX / "fixed_addon")]) if f.rule_id == rule_id]
    assert hits == []
