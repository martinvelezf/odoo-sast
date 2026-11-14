"""QWeb / XML template checks (ODS101-ODS102), stdlib expat for line numbers."""

from __future__ import annotations

import re
import xml.parsers.expat
from typing import List

from .finding import Finding
from .python_checks import SUPPRESS_RE

EXPR_ATTR_RE = re.compile(r"^t-(out|esc|raw|att(-[\w-]+)?|attf-[\w-]+|value|set)$")
MARKUP_CALL_RE = re.compile(r"\bMarkup\s*\(")


def check_xml_source(path: str, source: str) -> List[Finding]:
    findings: List[Finding] = []
    lines = source.splitlines()
    parser = xml.parsers.expat.ParserCreate()

    def suppressed(line: int, rule_id: str) -> bool:
        # an XML comment `<!-- odoo-sast: ignore[ODS101] -->` on the same or previous line
        for ln in (line, line - 1):
            if 0 < ln <= len(lines):
                m = SUPPRESS_RE.search(lines[ln - 1].replace("<!--", "#"))
                if m and (m.group(1) is None or rule_id in m.group(1)):
                    return True
        return False

    def add(rule_id: str, msg: str) -> None:
        line, col = parser.CurrentLineNumber, parser.CurrentColumnNumber + 1
        if not suppressed(line, rule_id):
            findings.append(Finding(path, line, col, rule_id, msg))

    def start(name, attrs):
        raw = attrs.get("t-raw")
        if raw is not None and raw.strip() != "0":
            add("ODS101", f"<{name} t-raw=\"{raw}\"> renders without escaping; use t-out")
        for attr, value in attrs.items():
            if EXPR_ATTR_RE.match(attr) and MARKUP_CALL_RE.search(value):
                add("ODS102", f"{attr}=\"{value}\" wraps the value in Markup() inside the template")

    parser.StartElementHandler = start
    try:
        parser.Parse(source.encode("utf-8") if isinstance(source, str) else source, True)
    except xml.parsers.expat.ExpatError:
        pass  # half-parsed files still yield what was seen before the error
    return findings
