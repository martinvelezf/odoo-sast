"""Rule registry: one entry per check, shared by every output format."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: str  # "error" | "warning" | "note"
    cwe: str
    short: str
    help: str


RULES: Dict[str, Rule] = {
    r.id: r
    for r in [
        Rule(
            "ODS001",
            "sudo-on-user-controlled-id",
            "error",
            "CWE-639",
            "Record fetched with sudo() using an id or domain the client controls",
            "A controller reads or writes records as superuser, selected by a value that comes "
            "from the request (route argument, kwargs, request.params). Any visitor can pick any "
            "record. Drop sudo(), or verify access first: _document_check_access(), "
            "check_access_rights()/check_access_rule() (check_access() on 18+), or a constant-time "
            "access_token comparison with consteq().",
        ),
        Rule(
            "ODS002",
            "public-route-sudo",
            "warning",
            "CWE-285",
            "Route with auth='public' or auth='none' elevates to sudo()",
            "Anonymous visitors reach this code and it bypasses ir.model.access and record rules. "
            "Make sure only fields meant to be public are read and that no record selection comes "
            "from the request. Prefer auth='user' or a narrow, explicit read with a field list.",
        ),
        Rule(
            "ODS003",
            "csrf-disabled-state-change",
            "error",
            "CWE-352",
            "type='http' route with csrf=False changes state",
            "The route turns off Odoo's CSRF token check and then calls create/write/unlink or an "
            "action_* method. A third-party page can make a logged-in user's browser call it. Keep "
            "CSRF on and send csrf_token from the form; for machine-to-machine webhooks use "
            "auth='none' or 'bearer' with a signature check instead of a browser session.",
        ),
        Rule(
            "ODS004",
            "portal-idor",
            "error",
            "CWE-639",
            "Record browsed by a client-supplied id, then elevated without an access check",
            "The route browses a record by an id from the request and later calls sudo() on it "
            "without checking that the current user may see it. This is the classic portal IDOR: "
            "change the id in the URL, read someone else's order or invoice. Use "
            "CustomerPortal._document_check_access(model, id, access_token) before sudo().",
        ),
        Rule(
            "ODS005",
            "sql-string-formatting",
            "error",
            "CWE-89",
            "cr.execute() query built with string formatting",
            "The SQL text is built with an f-string, %, .format() or concatenation, so values are "
            "not escaped by psycopg2. Pass values as the second argument "
            "(cr.execute(query, params)) and build identifiers with psycopg2.sql or odoo.tools.SQL.",
        ),
        Rule(
            "ODS006",
            "markup-on-dynamic-data",
            "warning",
            "CWE-79",
            "Markup() wraps a non-literal value",
            "markupsafe.Markup marks its argument as already safe HTML, so QWeb and the web client "
            "render it unescaped. Wrapping data that can come from a user (names, descriptions, "
            "request values) is stored XSS. Use Markup('<b>%s</b>') % value or html_escape(); "
            "reserve Markup(x) for trusted, server-built HTML. Error when the value comes from the request.",
        ),
        Rule(
            "ODS101",
            "qweb-t-raw",
            "warning",
            "CWE-79",
            "QWeb t-raw renders its expression without escaping",
            "t-raw outputs HTML as-is (and is deprecated since 15.0). If the expression can contain "
            "user data this is XSS. Use t-out (escapes unless the value is Markup) or t-esc. "
            "t-raw=\"0\" (the caller's body) is not reported.",
        ),
        Rule(
            "ODS102",
            "qweb-markup-in-template",
            "warning",
            "CWE-79",
            "QWeb expression wraps a value in Markup()",
            "Calling Markup() inside a t-out/t-esc/t-att expression disables escaping for that "
            "value right in the template. Pre-sanitize on the server (fields.Html(sanitize=True)) "
            "or keep the value escaped.",
        ),
    ]
}

SEVERITY_RANK = {"note": 0, "warning": 1, "error": 2}
