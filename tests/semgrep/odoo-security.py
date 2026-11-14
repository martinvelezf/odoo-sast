# Semgrep test target: `semgrep --test --config src/odoo_sast/semgrep tests/semgrep`
from markupsafe import Markup

from odoo import _, http
from odoo.http import request
from odoo.tools import SQL, html_escape


class C(http.Controller):

    @http.route("/a/<int:rec_id>", auth="user")
    def sudo_browse(self, rec_id, **kw):
        # ruleid: ods001-sudo-on-user-controlled-id
        rec = request.env["x.y"].sudo().browse(rec_id)
        return rec.name

    @http.route("/b", auth="user", type="json")
    def sudo_search(self, **kw):
        Model = request.env["x.y"].sudo()
        pid = int(request.params.get("pid"))
        # ruleid: ods001-sudo-on-user-controlled-id
        return Model.search_read([("partner_id", "=", pid)], ["name"])

    @http.route("/c/<int:rec_id>", auth="user")
    def checked(self, rec_id, access_token=None, **kw):
        rec = self._document_check_access("x.y", rec_id, access_token)
        # ok: ods001-sudo-on-user-controlled-id
        other = request.env["x.y"].sudo().browse(rec_id)
        return rec.name + other.name

    @http.route("/d/<int:rec_id>", auth="user")
    def no_sudo(self, rec_id, **kw):
        # ok: ods001-sudo-on-user-controlled-id
        return request.env["x.y"].browse(rec_id).name

    @http.route("/e", auth="public")
    def public_sudo(self, **kw):
        # ruleid: ods002-public-route-sudo
        cfg = request.env["ir.config_parameter"].sudo()
        return cfg.get_param("web.base.url")

    @http.route("/f", auth="user")
    def user_sudo(self, **kw):
        # ok: ods002-public-route-sudo
        return request.env["ir.config_parameter"].sudo().get_param("web.base.url")

    @http.route("/g", auth="user", methods=["POST"], csrf=False)
    def csrf_off(self, rec_id, **post):
        rec = request.env["x.y"].browse(int(rec_id))
        # ruleid: ods003-csrf-disabled-state-change
        rec.write({"name": post.get("name")})

    @http.route("/h", auth="user", methods=["POST"])
    def csrf_on(self, rec_id, **post):
        rec = request.env["x.y"].browse(int(rec_id))
        # ok: ods003-csrf-disabled-state-change
        rec.write({"name": post.get("name")})

    @http.route("/i", auth="user", type="json", csrf=False)
    def csrf_json(self, rec_id):
        # ok: ods003-csrf-disabled-state-change
        request.env["x.y"].browse(rec_id).write({"active": False})

    @http.route("/j/<int:rec_id>", auth="user")
    def idor(self, rec_id, **kw):
        rec = request.env["x.y"].browse(rec_id)
        # ruleid: ods004-portal-idor
        return rec.sudo().name

    @http.route("/k/<int:rec_id>", auth="user")
    def idor_checked(self, rec_id, access_token=None, **kw):
        rec = request.env["x.y"].browse(rec_id)
        rec.check_access_rule("read")
        # ok: ods004-portal-idor
        return rec.sudo().name

    @http.route("/l", auth="user")
    def markup_param(self, message="", **kw):
        # ruleid: ods006-markup-on-dynamic-data
        return Markup(message)


def sql(self, state, table, rec_id, name):
    # ruleid: ods005-sql-string-formatting
    self.env.cr.execute(f"SELECT id FROM t WHERE state = '{state}'")
    # ruleid: ods005-sql-string-formatting
    self._cr.execute("SELECT id FROM t WHERE state = '%s'" % state)
    # ruleid: ods005-sql-string-formatting
    self.env.cr.execute("DELETE FROM {}".format(table))
    # ruleid: ods005-sql-string-formatting
    self.env.cr.execute("UPDATE t SET a = 1 WHERE id = " + str(rec_id))
    query = "SELECT id FROM t WHERE name = '%s'" % name
    # ruleid: ods005-sql-string-formatting
    self.env.cr.execute(query)
    # ok: ods005-sql-string-formatting
    self.env.cr.execute("SELECT id FROM t WHERE state = %s", (state,))
    # ok: ods005-sql-string-formatting
    self.env.cr.execute(SQL("SELECT id FROM t WHERE name = %s", name))


def markup(self):
    # ruleid: ods006-markup-on-dynamic-data
    a = Markup(self.note)
    # ok: ods006-markup-on-dynamic-data
    b = Markup("<p>%s</p>") % self.note
    # ok: ods006-markup-on-dynamic-data
    c = Markup(_("<b>Hi</b>"))
    # ok: ods006-markup-on-dynamic-data
    d = Markup(html_escape(self.name))
    return a + b + c + d
