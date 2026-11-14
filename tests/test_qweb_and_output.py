import json
import subprocess
import sys
from pathlib import Path

from odoo_sast.cli import main
from odoo_sast.qweb_checks import check_xml_source
from odoo_sast.rules import RULES
from odoo_sast.sarif import to_sarif
from odoo_sast.scanner import scan_paths

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures"


def xml_ids(src):
    return [f.rule_id for f in check_xml_source("v.xml", src)]


def test_t_raw_flagged_but_not_t_raw_zero():
    assert xml_ids('<odoo><t t-raw="x"/><t t-raw="0"/><t t-out="x"/></odoo>') == ["ODS101"]


def test_markup_in_attribute_expression():
    assert xml_ids('<odoo><p t-att-title="Markup(x)"/><p t-attf-class="Markup"/></odoo>') == ["ODS102"]


def test_xml_suppression_comment():
    src = '<odoo>\n<!-- odoo-sast: ignore[ODS101] -->\n<t t-raw="trusted_html"/>\n</odoo>'
    assert xml_ids(src) == []


def test_line_numbers():
    f = check_xml_source("v.xml", '<odoo>\n\n  <div t-raw="x"/>\n</odoo>')[0]
    assert (f.line, f.col) == (3, 3)


def test_broken_xml_keeps_partial_results():
    assert xml_ids('<odoo><t t-raw="x"/><unclosed></odoo>') == ["ODS101"]


def test_sarif_shape():
    findings = scan_paths([str(FIX / "vulnerable_addon")], base=str(ROOT))
    doc = to_sarif(findings)
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert {r["id"] for r in run["tool"]["driver"]["rules"]} == set(RULES)
    assert len(run["results"]) == len(findings)
    res = run["results"][0]
    assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith("tests/fixtures/")
    rules = run["tool"]["driver"]["rules"]
    assert rules[res["ruleIndex"]]["id"] == res["ruleId"]
    assert all("security-severity" in r["properties"] for r in rules)


def test_cli_exit_codes(tmp_path, capsys):
    assert main(["scan", str(FIX / "fixed_addon")]) == 0
    assert main(["scan", str(FIX / "vulnerable_addon")]) == 1
    assert main(["scan", "--fail-on", "never", str(FIX / "vulnerable_addon")]) == 0
    # only warnings selected, fail threshold error -> 0
    assert main(["scan", "--select", "ODS101", "--fail-on", "error", str(FIX / "vulnerable_addon")]) == 0
    out = tmp_path / "r.sarif"
    main(["scan", "-f", "sarif", "-o", str(out), str(FIX / "vulnerable_addon")])
    assert json.loads(out.read_text())["runs"][0]["results"]
    capsys.readouterr()


def test_module_entry_point():
    proc = subprocess.run([sys.executable, "-m", "odoo_sast", "rules"], capture_output=True, text=True,
                          env={"PYTHONPATH": str(ROOT / "src")})
    assert proc.returncode == 0 and "ODS001" in proc.stdout
