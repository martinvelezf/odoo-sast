# odoo-sast

Security static analysis for **your own** Odoo addons. A zero-dependency Python checker
(AST + QWeb) plus a matching **Semgrep rule pack**, with text/JSON/**SARIF** output, a
**pre-commit** hook and a **GitHub Action** that uploads to code scanning.

It targets the bugs that actually show up in Odoo advisories and audits: access control
mistakes around `sudo()`, public routes, portal IDOR and CSRF. General Python linters can't
see these because they don't know Odoo's idioms.

| Rule | Severity | CWE | What it catches |
|---|---|---|---|
| `ODS001` sudo-on-user-controlled-id | error | 639 | `sudo().browse/search(...)` driven by a route argument, `kw`, or `request.params`, with no access check in the route |
| `ODS002` public-route-sudo | warning | 285 | `auth='public'` / `auth='none'` route that elevates with `sudo()` / `with_user(SUPERUSER_ID)` |
| `ODS003` csrf-disabled-state-change | error | 352 | `type='http'` route with `csrf=False` that calls `create/write/unlink/action_*` |
| `ODS004` portal-idor | error | 639 | record `browse(<id from URL>)` then `.sudo()` on it without `_document_check_access()` / `check_access*` |
| `ODS005` sql-string-formatting | error | 89 | `cr.execute()` with an f-string, `%`, `.format()` or `+`, directly or through a variable |
| `ODS006` markup-on-dynamic-data | warning (error on request data) | 79 | `Markup(x)` where `x` isn't a literal |
| `ODS101` qweb-t-raw | warning | 79 | `t-raw="expr"` in QWeb (except `t-raw="0"`) |
| `ODS102` qweb-markup-in-template | warning | 79 | `Markup(...)` inside a `t-out` / `t-esc` / `t-att*` expression |

An access check anywhere in the route (`_document_check_access`, `check_access_rights`,
`check_access_rule`, `check_access`, `has_access`, `consteq`, ...) silences ODS001/ODS004 for
that route. The check is deliberately simple; see [Limitations](#limitations).

## Install and run

```sh
pip install .                 # stdlib only
pip install ".[semgrep]"      # optional: also run the Semgrep pack

odoo-sast scan path/to/addons                   # text, exit 1 on warning or worse
odoo-sast scan -f sarif -o odoo-sast.sarif addons/
odoo-sast scan --semgrep --fail-on error addons/  # AST + Semgrep, merged and de-duplicated
odoo-sast scan --select ODS001,ODS004 addons/
odoo-sast rules
```

To suppress a finding you have reviewed, add `# odoo-sast: ignore[ODS002]` to the Python line, or
put `<!-- odoo-sast: ignore[ODS101] -->` on the XML line or the line above it.

### Semgrep pack only

The rules in `src/odoo_sast/semgrep/` are plain Semgrep YAML. If your pipeline already runs
Semgrep, use them as they are:

```sh
semgrep scan --config src/odoo_sast/semgrep/ path/to/addons
```

### pre-commit

```yaml
repos:
  - repo: https://github.com/<you>/odoo-sast
    rev: v0.1.0
    hooks:
      - id: odoo-sast          # or odoo-sast-semgrep
```

### GitHub Action

```yaml
permissions:
  contents: read
  security-events: write
jobs:
  odoo-sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: <you>/odoo-sast@v0.1.0
        with:
          paths: addons
          fail-on: error      # error | warning | note | never
          semgrep: "false"
```

Findings appear in the Security → Code scanning tab and as PR annotations.

## Demo

`tests/fixtures/` has two synthetic addons: `vulnerable_addon` (one route per flaw) and
`fixed_addon` (the same routes written correctly). Actual output:

```console
$ cd tests/fixtures && odoo-sast scan vulnerable_addon
vulnerable_addon/controllers/main.py:13:16: ODS001 [error] request.env['library.loan'].sudo().browse(...) runs as superuser on a value taken from the request, with no access check in this route
vulnerable_addon/controllers/main.py:13:16: ODS002 [warning] auth='public' route elevates with sudo(); anonymous visitors reach this code
vulnerable_addon/controllers/main.py:21:16: ODS001 [error] Loans.search_read(...) runs as superuser on a value taken from the request, with no access check in this route
vulnerable_addon/controllers/main.py:27:18: ODS004 [error] loan was selected by a request id and is elevated with sudo() without _document_check_access()/check_access
vulnerable_addon/controllers/main.py:34:9: ODS003 [error] csrf=False route 'loan_renew' (line 31) calls loan.write(); a cross-site form can trigger it
vulnerable_addon/controllers/main.py:40:68: ODS006 [error] Markup() wraps request data: this renders attacker HTML unescaped
vulnerable_addon/models/loan.py:19:9: ODS005 [error] SQL passed to cr.execute() is built with string formatting; pass values as query parameters
vulnerable_addon/models/loan.py:25:9: ODS005 [error] SQL passed to cr.execute() is built with string formatting; pass values as query parameters
vulnerable_addon/models/loan.py:30:9: ODS005 [error] SQL passed to cr.execute() is built with string formatting; pass values as query parameters
vulnerable_addon/models/loan.py:31:9: ODS005 [error] SQL passed to cr.execute() is built with string formatting; pass values as query parameters
vulnerable_addon/models/loan.py:35:16: ODS006 [warning] Markup() wraps a non-literal value (self.note); make sure it is trusted HTML, or use Markup('...%s...') % value
vulnerable_addon/views/templates.xml:7:13: ODS101 [warning] <div t-raw="loan.note"> renders without escaping; use t-out
vulnerable_addon/views/templates.xml:9:13: ODS102 [warning] t-out="Markup(loan.partner_id.comment)" wraps the value in Markup() inside the template
vulnerable_addon/views/templates.xml:14:13: ODS101 [warning] <div t-raw="message"> renders without escaping; use t-out

14 finding(s): 9 error, 5 warning, 0 note
$ echo $?
1

$ odoo-sast scan fixed_addon
0 finding(s): 0 error, 0 warning, 0 note
```

The flaw at line 27 and its fix:

```python
# vulnerable: any logged-in portal user can download any loan receipt by changing the id
loan = request.env["library.loan"].browse(loan_id)
report = loan.sudo()._render_receipt()

# fixed
loan_sudo = self._document_check_access("library.loan", loan_id, access_token)
report = loan_sudo._render_receipt()
```

The same finding in SARIF (`-f sarif`):

```json
{
  "ruleId": "ODS004",
  "ruleIndex": 3,
  "level": "error",
  "message": {"text": "loan was selected by a request id and is elevated with sudo() without _document_check_access()/check_access"},
  "locations": [{"physicalLocation": {
    "artifactLocation": {"uri": "vulnerable_addon/controllers/main.py", "uriBaseId": "%SRCROOT%"},
    "region": {"startLine": 27, "startColumn": 18}}}],
  "properties": {"engine": "odoo-sast"}
}
```

The Semgrep pack reports the same 14 findings on the vulnerable addon and none on the fixed one.
A test checks this.

## Tests

```sh
pip install -e ".[test,semgrep]"
python -m pytest -q                                                     # 54 tests
semgrep --test --config src/odoo_sast/semgrep tests/semgrep             # rule annotations
```

`tests/test_fixtures.py` checks that each rule fires the expected number of times on
`vulnerable_addon` and never on `fixed_addon`. `tests/semgrep/` holds `# ruleid:` / `# ok:`
annotated targets for every Semgrep rule. The Semgrep tests are skipped when Semgrep isn't
installed.

## Why this exists / prior art

The most common serious bugs in custom Odoo code are authorization bugs: a portal or public
controller reads records as superuser using an id the visitor chose. The standard linters
mostly don't look for them. Existing work I know of:

- **[pylint-odoo](https://pypi.org/project/pylint-odoo/)** (OCA): the standard Odoo linter.
  It has a `sql-injection` check (E8103) but nothing for `sudo()` on request data, public
  routes, CSRF or portal IDOR. odoo-sast is meant to run next to it, not replace it.
- **[odooscan](https://github.com/avanserv/odooscan)** (MIT, Rust, first released October
  2026): the closest and much broader tool. It has about 130 rules and a cross-module index,
  and its security rules include public-route sudo (OD111), csrf-disabled (OD112), t-raw
  (OD307), SQL/markup injection flows (OD701/OD703) and sudo record exposure (OD712–OD716). It
  also outputs SARIF. **If you want depth and cross-module checks, use odooscan.** odoo-sast
  differs in three ways. Its checks are a plain **Semgrep YAML pack** that runs in pipelines
  that already use Semgrep, without adding a binary. The engine is small, dependency-free
  Python that's easy to fork for in-house rules. And each rule comes with a **vulnerable and
  a fixed addon**, so the repo works as teaching and audit material. I haven't benchmarked the
  two against each other.
- **[avanserv/semgrep-odoo](https://github.com/avanserv/semgrep-odoo)** (archived and replaced
  by odooscan) and **[sbidoul/semgrep-odoo](https://github.com/sbidoul/semgrep-odoo)** (a 2021
  experiment using Semgrep as a pylint-odoo replacement): earlier Semgrep rule sets for Odoo,
  mostly about deprecations, with one or two security rules.
- **[UCLouvain master's thesis (2023)](https://thesis.dial.uclouvain.be/entities/masterthesis/f5fd800e-6377-420e-a851-88f43a5785a4)**
  on using Semgrep to analyze Odoo: an academic study that applied Semgrep to the Odoo codebase
  and refined its rules with feedback from Odoo's security team. It's the main source showing
  that pattern-based SAST works on Odoo code. I haven't reviewed its rule set in detail, and I
  don't know of a maintained pack published from it.
- **Generic Semgrep/CodeQL Python rules** find SQL injection and some XSS, but they don't model
  `sudo()`, `auth=`, `csrf=`, `_document_check_access` or QWeb.

## Limitations

- The analysis is local to one function. A request value passed into a helper method that then
  calls `sudo().browse()` is not followed (the Semgrep taint rules follow a little more).
- An access check anywhere in the route silences ODS001/ODS004, even when it runs after the
  `sudo()` or checks a different record.
- ODS002 is a review prompt, not proof of a bug. Many legitimate public routes use `sudo()` to
  read published data.
- QWeb checks are syntactic: they don't know whether a `t-raw` expression holds trusted HTML.
- Rules don't depend on the Odoo series yet. They apply the same way to 14.0 through 19.0.

See [ROADMAP.md](ROADMAP.md).

## Responsible use

odoo-sast is meant for code you own or are authorized to review: your addons, your company's
addons, or a third-party module before you install it. If you find a vulnerability in someone
else's published module, report it to the maintainer privately before disclosing it.

## Español (resumen)

**odoo-sast** es un analizador estático de seguridad para tus propios módulos de Odoo. Detecta
`sudo()` sobre ids que controla el usuario, rutas `auth='public'`/`'none'` con `sudo()`,
`csrf=False` en rutas que modifican datos, IDOR de portal (`browse(id)` seguido de `sudo()` sin
`_document_check_access`), SQL armado con f-strings, `%` o `.format()` en `cr.execute()`, y XSS
por `t-raw` o `Markup()` sobre datos del usuario.

- Uso: `pip install .` y luego `odoo-sast scan ruta/addons` (`-f sarif` para GitHub code scanning).
- Incluye un paquete de reglas Semgrep, un hook de pre-commit y una GitHub Action.
- `tests/fixtures` trae un addon vulnerable y su versión corregida.
- La alternativa más completa es **odooscan** (Rust). odoo-sast es más liviano, está pensado para
  equipos que ya usan Semgrep, y sirve como material de auditoría y enseñanza.

## License

Apache-2.0. See [LICENSE](LICENSE).
