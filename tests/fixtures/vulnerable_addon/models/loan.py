# Synthetic vulnerable model.
from markupsafe import Markup

from odoo import fields, models


class LibraryLoan(models.Model):
    _name = "library.loan"
    _description = "Book loan"

    name = fields.Char(required=True)
    partner_id = fields.Many2one("res.partner")
    note = fields.Text()
    due_date = fields.Date()
    state = fields.Selection([("open", "Open"), ("late", "Late"), ("done", "Returned")])

    # ODS005: f-string SQL
    def _late_count(self, state):
        self.env.cr.execute(f"SELECT count(*) FROM library_loan WHERE state = '{state}'")
        return self.env.cr.fetchone()[0]

    # ODS005: % formatting via an intermediate variable
    def _loans_for(self, partner_name):
        query = "SELECT l.id FROM library_loan l JOIN res_partner p ON p.id = l.partner_id WHERE p.name = '%s'" % partner_name
        self._cr.execute(query)
        return [r[0] for r in self._cr.fetchall()]

    # ODS005: .format() and concatenation
    def _purge(self, table, days):
        self.env.cr.execute("DELETE FROM {} WHERE create_date < now() - interval '{} days'".format(table, days))
        self.env.cr.execute("UPDATE library_loan SET state = 'late' WHERE id = " + str(self.id))

    # ODS006 (warning): user-editable text marked safe
    def _note_html(self):
        return Markup(self.note)
