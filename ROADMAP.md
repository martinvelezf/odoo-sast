# Roadmap

## v0.2
- Follow request values one call deep into helper methods on the same controller/model (ODS001/ODS004).
- Order-aware access checks: the check must run before the `sudo()` and on the same model/id.
- More rules from the original MVP list:
  - mass assignment: `write(request.params)` / `create(kw)` (with or without sudo)
  - `ir.attachment` created with `public=True` from request data
  - `safe_eval` / `eval` on request data
  - routes without an explicit `auth=`
  - `with_user(SUPERUSER_ID)` or `env.su` in controllers
  - access-token comparison with `==` instead of `consteq`
  - open redirects through `request.redirect(kw['url'])`
- Data-file checks (CSV/XML): models without `ir.model.access` lines, `ir.rule` with
  `[(1, '=', 1)]` on portal/public groups, public write ACLs.
- Rule ranges per Odoo series (14.0–19.0), read from `__manifest__.py` `version`.
- `--baseline` file to adopt the tool on an existing codebase without fixing everything at once.
- Semgrep Registry submission once the rules have been run against real code.

## Later
- Benchmark against odooscan and pylint-odoo on Odoo Community + OCA repos; publish the
  false-positive rate.
- Report on popular free App Store modules (scanned locally, findings sent to maintainers
  privately first, with a disclosure delay).
- VS Code problem matcher / LSP wrapper.
