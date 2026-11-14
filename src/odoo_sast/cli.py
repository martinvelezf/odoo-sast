"""Command line entry point: `odoo-sast scan ADDONS...`."""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import __version__
from .finding import Finding
from .rules import RULES, SEVERITY_RANK
from .sarif import to_sarif
from .scanner import merge, run_semgrep, scan_paths, semgrep_available


def format_text(findings: List[Finding]) -> str:
    out = [f"{f.path}:{f.line}:{f.col}: {f.rule_id} [{f.severity}] {f.message}" for f in findings]
    counts = {s: sum(1 for f in findings if f.severity == s) for s in ("error", "warning", "note")}
    out.append(f"\n{len(findings)} finding(s): {counts['error']} error, {counts['warning']} warning, "
               f"{counts['note']} note")
    return "\n".join(out)


def cmd_scan(args) -> int:
    findings = scan_paths(args.paths)
    if args.semgrep:
        if not semgrep_available():
            print("odoo-sast: --semgrep given but semgrep is not on PATH (pip install semgrep)", file=sys.stderr)
            return 2
        findings = merge(findings, run_semgrep(args.paths))
    if args.select:
        wanted = {s.strip().upper() for s in args.select.split(",")}
        findings = [f for f in findings if f.rule_id in wanted]

    if args.format == "sarif":
        text = json.dumps(to_sarif(findings), indent=2)
    elif args.format == "json":
        text = json.dumps([f.to_dict() for f in findings], indent=2)
    else:
        text = format_text(findings)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    else:
        print(text)

    if args.fail_on == "never":
        return 0
    threshold = SEVERITY_RANK[args.fail_on]
    return 1 if any(SEVERITY_RANK.get(f.severity, 1) >= threshold for f in findings) else 0


def cmd_rules(_args) -> int:
    for r in RULES.values():
        print(f"{r.id}  {r.severity:<7}  {r.cwe:<8}  {r.name}\n        {r.short}")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="odoo-sast", description="Security static analysis for Odoo addons.")
    p.add_argument("--version", action="version", version=f"odoo-sast {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan addon directories or files")
    s.add_argument("paths", nargs="+")
    s.add_argument("-f", "--format", choices=("text", "json", "sarif"), default="text")
    s.add_argument("-o", "--output", help="write the report to this file")
    s.add_argument("--fail-on", choices=("error", "warning", "note", "never"), default="warning",
                   help="exit 1 when a finding at or above this severity exists (default: warning)")
    s.add_argument("--select", help="comma-separated rule ids to keep, e.g. ODS001,ODS005")
    s.add_argument("--semgrep", action="store_true", help="also run the bundled Semgrep rule pack")
    s.set_defaults(func=cmd_scan)

    r = sub.add_parser("rules", help="list rules")
    r.set_defaults(func=cmd_rules)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
