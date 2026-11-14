# Synthetic fixed controller: same routes as the vulnerable fixture, done right.
from odoo import http
from odoo.addons.portal.controllers.portal import CustomerPortal
from odoo.exceptions import AccessError, MissingError
from odoo.http import request


class LibraryPortal(CustomerPortal):

    # access token checked by the portal helper before anything is read as superuser
    @http.route("/library/loan/<int:loan_id>", auth="public", website=True)
    def loan_public(self, loan_id, access_token=None, **kw):
        try:
            loan_sudo = self._document_check_access("library.loan", loan_id, access_token)
        except (AccessError, MissingError):
            return request.redirect("/my")
        return request.render("library_portal.loan_page", {"loan": loan_sudo})

    # no sudo: ir.rule restricts the search to the user's own loans
    @http.route("/library/loans/search", auth="user", type="json")
    def loan_search(self, **kw):
        partner_id = int(request.params.get("partner_id"))
        Loans = request.env["library.loan"]
        return Loans.search_read([("partner_id", "=", partner_id)], ["name", "state"])

    @http.route("/my/loans/<int:loan_id>/pdf", auth="user", website=True)
    def loan_pdf(self, loan_id, access_token=None, **kw):
        loan_sudo = self._document_check_access("library.loan", loan_id, access_token)
        report = loan_sudo._render_receipt()
        return request.make_response(report, headers=[("Content-Type", "application/pdf")])

    # CSRF stays on; the form posts csrf_token
    @http.route("/library/loan/renew", auth="user", methods=["POST"])
    def loan_renew(self, loan_id, **post):
        loan = request.env["library.loan"].browse(int(loan_id))
        loan.write({"due_date": post.get("due_date")})
        return request.redirect("/my/loans")

    # plain string, escaped by t-out
    @http.route("/library/notice", auth="user", website=True)
    def notice(self, message="", **kw):
        return request.render("library_portal.notice", {"message": message})

    # public catalogue without elevation: public user + record rules
    @http.route("/library/books", auth="public", website=True)
    def books(self, **kw):
        books = request.env["library.book"].search([("is_published", "=", True)])
        return request.render("library_portal.books", {"books": books})
