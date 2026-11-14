"""SARIF 2.1.0 writer (GitHub code scanning compatible)."""

from __future__ import annotations

from typing import Iterable, List

from . import __version__
from .finding import Finding
from .rules import RULES

LEVEL = {"error": "error", "warning": "warning", "note": "note"}
SECURITY_SEVERITY = {"error": "8.0", "warning": "5.0", "note": "2.0"}


def to_sarif(findings: Iterable[Finding]) -> dict:
    findings = list(findings)
    rule_ids: List[str] = sorted(RULES)
    rules = [
        {
            "id": r.id,
            "name": r.name,
            "shortDescription": {"text": r.short},
            "fullDescription": {"text": r.help},
            "help": {"text": r.help},
            "defaultConfiguration": {"level": LEVEL[r.severity]},
            "properties": {
                "tags": ["security", "odoo", r.cwe],
                "security-severity": SECURITY_SEVERITY[r.severity],
            },
        }
        for r in (RULES[i] for i in rule_ids)
    ]
    results = [
        {
            "ruleId": f.rule_id,
            "ruleIndex": rule_ids.index(f.rule_id),
            "level": LEVEL.get(f.severity, "warning"),
            "message": {"text": f.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.path.replace("\\", "/"), "uriBaseId": "%SRCROOT%"},
                        "region": {"startLine": f.line, "startColumn": max(f.col, 1)},
                    }
                }
            ],
            "properties": {"engine": f.engine},
        }
        for f in findings
        if f.rule_id in RULES
    ]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "odoo-sast",
                        "version": __version__,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
