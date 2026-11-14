# Synthetic vulnerable controller. Every route below has a known flaw.
from markupsafe import Markup

from odoo import http
from odoo.http import request


class LibraryPortal(http.Controller):

    # ODS001 + ODS002: anonymous visitor picks any loan id, read as superuser
    @http.route("/library/loan/<int:loan_id>", auth="public", website=True)
    def loan_public(self, loan_id, **kw):
        loan = request.env["library.loan"].sudo().browse(loan_id)
        return request.render("library_portal.loan_page", {"loan": loan})

    # ODS001: search domain built from request params, run as superuser
    @http.route("/library/loans/search", auth="user", type="json")
    def loan_search(self, **kw):
        partner_id = int(request.params.get("partner_id"))
        Loans = request.env["library.loan"].sudo()
        return Loans.search_read([("partner_id", "=", partner_id)], ["name", "state"])

    # ODS004: classic portal IDOR - browse by URL id, then sudo() with no check
    @http.route("/my/loans/<int:loan_id>/pdf", auth="user", website=True)
    def loan_pdf(self, loan_id, access_token=None, **kw):
        loan = request.env["library.loan"].browse(loan_id)
        report = loan.sudo()._render_receipt()
        return request.make_response(report, headers=[("Content-Type", "application/pdf")])

    # ODS003: CSRF disabled on a browser route that writes
    @http.route("/library/loan/renew", auth="user", methods=["POST"], csrf=False)
    def loan_renew(self, loan_id, **post):
        loan = request.env["library.loan"].browse(int(loan_id))
        loan.write({"due_date": post.get("due_date")})
        return request.redirect("/my/loans")

    # ODS006 (error): request data wrapped in Markup
    @http.route("/library/notice", auth="user", website=True)
    def notice(self, message="", **kw):
        return request.render("library_portal.notice", {"message": Markup(message)})
