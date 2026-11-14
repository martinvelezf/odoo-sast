"""Unit tests for the AST engine: one positive and one negative case per behaviour."""

import textwrap

from odoo_sast.python_checks import check_python_source


def ids(src):
    return sorted(f.rule_id for f in check_python_source("m.py", textwrap.dedent(src)))


HEAD = "from odoo import http\nfrom odoo.http import request\n"


def route(body, deco='@http.route("/x", auth="user")', sig="self, rec_id, **kw"):
    return HEAD + f"class C(http.Controller):\n    {deco}\n    def r({sig}):\n" + textwrap.indent(
        textwrap.dedent(body), "        "
    )


# ODS001 --------------------------------------------------------------------
def test_ods001_sudo_browse_route_arg():
    assert ids(route('return request.env["a.b"].sudo().browse(rec_id).name\n')) == ["ODS001"]


def test_ods001_through_kwargs_and_int():
    body = 'i = int(kw.get("id"))\nreturn request.env["a.b"].sudo().search([("id", "=", i)])\n'
    assert ids(route(body)) == ["ODS001"]


def test_ods001_with_user_superuser():
    body = 'return request.env["a.b"].with_user(SUPERUSER_ID).browse(rec_id)\n'
    assert ids(route(body)) == ["ODS001"]


def test_ods001_not_outside_routes():
    src = HEAD + "def helper(env, rec_id):\n    return env['a.b'].sudo().browse(rec_id)\n"
    assert ids(src) == []


def test_ods001_access_check_silences():
    body = ('self._document_check_access("a.b", rec_id, kw.get("access_token"))\n'
            'return request.env["a.b"].sudo().browse(rec_id)\n')
    assert ids(route(body)) == []


def test_ods001_constant_id_is_fine():
    assert ids(route('return request.env["a.b"].sudo().browse(1)\n')) == []


def test_ods001_sudo_false_is_not_elevation():
    assert ids(route('return request.env["a.b"].sudo(False).browse(rec_id)\n')) == []


# ODS002 --------------------------------------------------------------------
def test_ods002_public_route_sudo_once_per_function():
    body = 'a = request.env["a"].sudo()\nb = request.env["b"].sudo()\nreturn a, b\n'
    assert ids(route(body, deco='@http.route("/x", auth="public")', sig="self")) == ["ODS002"]


def test_ods002_none_route():
    body = 'return request.env["a"].sudo().search([])\n'
    assert ids(route(body, deco='@http.route("/x", auth="none")', sig="self")) == ["ODS002"]


def test_ods002_user_route_silent():
    assert ids(route('return request.env["a"].sudo().search([])\n', sig="self")) == []


# ODS003 --------------------------------------------------------------------
def test_ods003_csrf_false_write():
    body = 'request.env["a"].browse(1).write({"x": 1})\n'
    assert ids(route(body, deco='@http.route("/x", auth="user", csrf=False)', sig="self")) == ["ODS003"]


def test_ods003_action_method():
    body = 'request.env["a"].browse(1).action_confirm()\n'
    assert ids(route(body, deco='@http.route("/x", auth="user", csrf=False)', sig="self")) == ["ODS003"]


def test_ods003_json_route_silent():
    body = 'request.env["a"].browse(1).write({"x": 1})\n'
    deco = '@http.route("/x", auth="user", type="json", csrf=False)'
    assert ids(route(body, deco=deco, sig="self")) == []


def test_ods003_read_only_silent():
    body = 'return request.env["a"].search_read([])\n'
    assert ids(route(body, deco='@http.route("/x", auth="user", csrf=False)', sig="self")) == []


def test_ods003_csrf_on_silent():
    body = 'request.env["a"].browse(1).write({"x": 1})\n'
    assert ids(route(body, sig="self")) == []


# ODS004 --------------------------------------------------------------------
def test_ods004_browse_then_sudo():
    body = 'rec = request.env["a.b"].browse(rec_id)\nreturn rec.sudo().name\n'
    assert ids(route(body)) == ["ODS004"]


def test_ods004_inline_chain():
    assert ids(route('return request.env["a.b"].browse(rec_id).sudo().name\n')) == ["ODS004"]


def test_ods004_checked():
    body = ('rec = request.env["a.b"].browse(rec_id)\nrec.check_access_rule("read")\n'
            'return rec.sudo().name\n')
    assert ids(route(body)) == []


def test_ods004_constant_browse_silent():
    assert ids(route('return request.env["a.b"].browse(1).sudo().name\n')) == []


# ODS005 --------------------------------------------------------------------
def model(body):
    return "from odoo import models\nclass M(models.Model):\n    _name = 'm'\n    def f(self, v, t):\n" + \
        textwrap.indent(textwrap.dedent(body), "        ")


def test_ods005_variants():
    body = """
    self.env.cr.execute(f"SELECT {v}")
    self._cr.execute("SELECT %s" % v)
    self.env.cr.execute("SELECT {}".format(v))
    self.env.cr.execute("SELECT " + v)
    q = "SELECT * FROM %s" % t
    self.env.cr.execute(q)
    q2 = "SELECT 1"
    q2 += " WHERE x = " + v
    self.env.cr.execute(q2)
    """
    assert ids(model(body)) == ["ODS005"] * 6


def test_ods005_safe():
    body = """
    self.env.cr.execute("SELECT %s", (v,))
    self.env.cr.execute(SQL("SELECT %s", v))
    self.env.cr.execute(f"SELECT 1")
    self.env.cr.execute("SELECT 1" + " FROM t")
    q = "SELECT %s"
    self.env.cr.execute(q, [v])
    """
    assert ids(model(body)) == []


def test_ods005_ignores_non_cursor_execute():
    assert ids(model('self.executor.execute(f"run {v}")\n')) == []


# ODS006 --------------------------------------------------------------------
def test_ods006_model_warning_and_route_error():
    m = check_python_source("m.py", model("return Markup(self.note)\n"))
    assert [(f.rule_id, f.severity) for f in m] == [("ODS006", "warning")]
    r = check_python_source("c.py", route("return Markup(kw.get('msg'))\n"))
    assert [(f.rule_id, f.severity) for f in r] == [("ODS006", "error")]


def test_ods006_safe_forms():
    body = """
    a = Markup("<b>%s</b>") % self.note
    b = Markup(_("<b>Hi</b>"))
    c = Markup(html_escape(self.note))
    d = Markup(f"<br/>")
    """
    assert ids(model(body)) == []


# suppression / robustness ----------------------------------------------------
def test_inline_suppression():
    body = 'return request.env["a.b"].sudo().browse(rec_id)  # odoo-sast: ignore[ODS001]\n'
    assert ids(route(body)) == []


def test_suppression_of_other_rule_does_not_hide():
    body = 'return request.env["a.b"].sudo().browse(rec_id)  # odoo-sast: ignore[ODS005]\n'
    assert ids(route(body)) == ["ODS001"]


def test_syntax_error_is_skipped():
    assert check_python_source("bad.py", "def (:\n") == []


# ODS005: variable state is looked up at the execute() line ------------------
def test_ods005_reassigned_constant_does_not_hide_earlier_formatted_sql():
    body = ('q = f"SELECT * FROM t WHERE id = {rec_id}"\n'
            'request.env.cr.execute(q)\n'
            'q = "SELECT 1"\n'
            'request.env.cr.execute(q)\n')
    found = check_python_source("m.py", textwrap.dedent(route(body)))
    assert [(f.rule_id, f.line) for f in found] == [("ODS005", 7)]


def test_ods005_constant_variable_formatted_with_percent():
    body = 'q = "SELECT * FROM t WHERE id = %s"\nrequest.env.cr.execute(q % kw["id"])\n'
    assert ids(route(body)) == ["ODS005"]


def test_ods005_augassign_with_literal_keeps_query_constant():
    body = ('q = "SELECT * FROM t WHERE id = %s"\nq += " AND active"\n'
            'request.env.cr.execute(q, (rec_id,))\n')
    assert ids(route(body)) == []


def test_ods005_augassign_with_variable_is_formatting():
    body = 'q = "SELECT * FROM t WHERE "\nq += kw["where"]\nrequest.env.cr.execute(q)\n'
    assert ids(route(body)) == ["ODS005"]
