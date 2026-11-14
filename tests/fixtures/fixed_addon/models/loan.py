# Synthetic fixed model.
from markupsafe import Markup

from odoo import _, fields, models
from odoo.tools import SQL, html_escape


class LibraryLoan(models.Model):
    _name = "library.loan"
    _description = "Book loan"

    name = fields.Char(required=True)
    partner_id = fields.Many2one("res.partner")
    note = fields.Text()
    due_date = fields.Date()
    state = fields.Selection([("open", "Open"), ("late", "Late"), ("done", "Returned")])

    def _late_count(self, state):
        self.env.cr.execute("SELECT count(*) FROM library_loan WHERE state = %s", (state,))
        return self.env.cr.fetchone()[0]

    def _loans_for(self, partner_name):
        query = SQL(
            "SELECT l.id FROM library_loan l JOIN res_partner p ON p.id = l.partner_id WHERE p.name = %s",
            partner_name,
        )
        self._cr.execute(query)
        return [r[0] for r in self._cr.fetchall()]

    def _purge(self, days):
        self.env.cr.execute(
            "DELETE FROM library_loan WHERE create_date < now() - %s * interval '1 day'", (days,)
        )
        self.env.cr.execute("UPDATE library_loan SET state = 'late' WHERE id = %s", (self.id,))

    def _note_html(self):
        # Markup with a literal template escapes the interpolated value
        return Markup("<p>%s</p>") % self.note

    def _title_html(self):
        return Markup(_("<b>Loan</b>")) + Markup(html_escape(self.name))
