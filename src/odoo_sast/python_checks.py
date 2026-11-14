"""AST checks for Odoo controller and model code (ODS001-ODS006).

The analysis is deliberately local: one function at a time, with a small
"taint-lite" pass that marks names derived from request data. It trades
recall for very few false positives, which is what a pre-commit hook needs.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Set

from .finding import Finding

RECORD_FETCHERS = {
    "browse", "search", "search_read", "search_count", "search_fetch",
    "read_group", "_read_group", "_search", "name_search",
}
STATE_CHANGERS = {"create", "write", "unlink", "copy", "toggle_active", "action_archive", "action_unarchive"}
STATE_CHANGER_PREFIXES = ("action_", "button_")
ACCESS_CHECKS = {
    "_document_check_access", "check_access_rights", "check_access_rule", "check_access",
    "has_access", "_check_access", "consteq", "_check_access_token", "check_access_token",
    "_check_portal_access",
}
REQUEST_SOURCES = (
    "request.params", "request.httprequest", "request.jsonrequest",
    "request.get_json_data", "request.get_http_params",
)
CURSOR_NAMES = {"cr", "_cr", "cursor"}
SAFE_MARKUP_WRAPPERS = {"_", "_lt", "html_escape", "escape", "plaintext2html", "html_sanitize"}
SUPPRESS_RE = re.compile(r"#\s*odoo-sast:\s*ignore(?:\[([A-Z0-9_, ]+)\])?")


def dotted(node: ast.AST) -> str:
    """Best-effort dotted name for Name/Attribute/Call chains (calls render as 'x()')."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{dotted(node.value)}.{node.attr}"
    if isinstance(node, ast.Call):
        return f"{dotted(node.func)}()"
    if isinstance(node, ast.Subscript):
        idx = node.slice
        inner = repr(idx.value) if isinstance(idx, ast.Constant) else ""
        return f"{dotted(node.value)}[{inner}]"
    return "?"


def call_name(call: ast.Call) -> str:
    f = call.func
    if isinstance(f, ast.Attribute):
        return f.attr
    if isinstance(f, ast.Name):
        return f.id
    return ""


def is_str_const(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


@dataclass
class RouteInfo:
    auth: str = "user"
    csrf: bool = True
    type: str = "http"
    methods: Optional[List[str]] = None
    lineno: int = 0


def route_info(fn: ast.AST) -> Optional[RouteInfo]:
    for dec in getattr(fn, "decorator_list", []):
        if not isinstance(dec, ast.Call):
            continue
        name = dotted(dec.func)
        if not (name == "route" or name.endswith(".route")):
            continue
        info = RouteInfo(lineno=dec.lineno)
        for kw in dec.keywords:
            v = kw.value
            if kw.arg == "auth" and is_str_const(v):
                info.auth = v.value
            elif kw.arg == "csrf" and isinstance(v, ast.Constant):
                info.csrf = bool(v.value)
            elif kw.arg == "type" and is_str_const(v):
                info.type = v.value
            elif kw.arg == "methods" and isinstance(v, (ast.List, ast.Tuple)):
                info.methods = [e.value.upper() for e in v.elts if is_str_const(e)]
        return info
    return None


@dataclass
class FunctionFacts:
    tainted: Set[str] = field(default_factory=set)
    sudo_vars: Set[str] = field(default_factory=set)
    browsed_vars: Set[str] = field(default_factory=set)  # records browsed by a tainted id, no sudo
    formatted_sql_vars: Set[str] = field(default_factory=set)
    has_access_check: bool = False


class _Analyzer:
    def __init__(self, path: str, source: str):
        self.path = path
        self.source_lines = source.splitlines()
        self.findings: List[Finding] = []

    # -- helpers -------------------------------------------------------------
    def report(self, node: ast.AST, rule_id: str, message: str, severity: str = "") -> None:
        line = getattr(node, "lineno", 1)
        if self._suppressed(line, rule_id):
            return
        self.findings.append(
            Finding(self.path, line, getattr(node, "col_offset", 0) + 1, rule_id, message, severity)
        )

    def _suppressed(self, line: int, rule_id: str) -> bool:
        if 0 < line <= len(self.source_lines):
            m = SUPPRESS_RE.search(self.source_lines[line - 1])
            if m:
                return m.group(1) is None or rule_id in {x.strip() for x in m.group(1).split(",")}
        return False

    @staticmethod
    def is_request_source(node: ast.AST) -> bool:
        for sub in ast.walk(node):
            if isinstance(sub, (ast.Attribute, ast.Call)):
                d = dotted(sub.func if isinstance(sub, ast.Call) else sub)
                if d.startswith(REQUEST_SOURCES):
                    return True
        return False

    def is_tainted(self, node: ast.AST, facts: FunctionFacts) -> bool:
        if self.is_request_source(node):
            return True
        return any(
            isinstance(n, ast.Name) and n.id in facts.tainted for n in ast.walk(node)
        )

    @staticmethod
    def has_sudo(node: ast.AST, facts: FunctionFacts) -> bool:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call):
                n = call_name(sub)
                if n == "sudo":
                    # sudo(False) drops privileges, it does not elevate
                    if sub.args and isinstance(sub.args[0], ast.Constant) and sub.args[0].value is False:
                        continue
                    return True
                if n == "with_user" and sub.args and dotted(sub.args[0]).endswith("SUPERUSER_ID"):
                    return True
            if isinstance(sub, ast.Name) and sub.id in facts.sudo_vars:
                return True
        return False

    @staticmethod
    def is_formatted_sql(node: ast.AST, facts: FunctionFacts) -> bool:
        if isinstance(node, ast.JoinedStr):
            return any(isinstance(v, ast.FormattedValue) for v in node.values)
        if isinstance(node, ast.BinOp):
            if isinstance(node.op, ast.Mod) and (is_str_const(node.left) or isinstance(node.left, ast.JoinedStr)):
                return True
            if isinstance(node.op, ast.Add):
                sides = (node.left, node.right)
                strish = any(is_str_const(s) or isinstance(s, ast.JoinedStr) for s in sides)
                all_const = all(is_str_const(s) for s in sides)
                if strish and not all_const:
                    return True
                return any(_Analyzer.is_formatted_sql(s, facts) for s in sides)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "format" and is_str_const(node.func.value):
                return True
        if isinstance(node, ast.Name):
            return node.id in facts.formatted_sql_vars
        return False

    # -- driver --------------------------------------------------------------
    def run(self, tree: ast.Module) -> List[Finding]:
        functions = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        for fn in functions:
            self.check_function(fn)
        return self.findings

    def collect_facts(self, fn: ast.AST, route: Optional[RouteInfo]) -> FunctionFacts:
        facts = FunctionFacts()
        if route:
            args = fn.args
            params = args.posonlyargs + args.args + args.kwonlyargs
            facts.tainted |= {a.arg for a in params if a.arg not in ("self", "cls")}
            if args.vararg:
                facts.tainted.add(args.vararg.arg)
            if args.kwarg:
                facts.tainted.add(args.kwarg.arg)

        stmts = sorted(
            (n for n in ast.walk(fn) if isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.For))),
            key=lambda n: (n.lineno, n.col_offset),
        )
        for _ in range(2):  # two passes reach simple chains defined out of order
            for st in stmts:
                if isinstance(st, ast.For):
                    targets, value = [st.target], st.iter
                elif isinstance(st, ast.Assign):
                    targets, value = st.targets, st.value
                else:
                    targets, value = [st.target], st.value
                if value is None:
                    continue
                names = {n.id for t in targets for n in ast.walk(t) if isinstance(n, ast.Name)}
                if route and self.is_tainted(value, facts):
                    facts.tainted |= names
                if self.has_sudo(value, facts):
                    facts.sudo_vars |= names
                if route and self._browse_by_tainted(value, facts) and not self.has_sudo(value, facts):
                    facts.browsed_vars |= names
                if self.is_formatted_sql(value, facts):
                    facts.formatted_sql_vars |= names
                elif is_str_const(value) and not isinstance(st, ast.AugAssign):
                    facts.formatted_sql_vars -= names

        facts.has_access_check = any(
            isinstance(n, ast.Call) and call_name(n) in ACCESS_CHECKS for n in ast.walk(fn)
        )
        return facts

    def _browse_by_tainted(self, node: ast.AST, facts: FunctionFacts) -> bool:
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call) and call_name(sub) == "browse":
                if any(self.is_tainted(a, facts) for a in sub.args):
                    return True
        return False

    def check_function(self, fn: ast.AST) -> None:
        route = route_info(fn)
        facts = self.collect_facts(fn, route)
        own_nodes = list(self._own_walk(fn))

        if route:
            self.check_route(fn, route, facts, own_nodes)

        for node in own_nodes:
            if not isinstance(node, ast.Call):
                continue
            # ODS005: SQL built with string formatting
            if call_name(node) == "execute" and isinstance(node.func, ast.Attribute):
                recv = dotted(node.func.value).split(".")[-1]
                if recv in CURSOR_NAMES and node.args and self.is_formatted_sql(node.args[0], facts):
                    self.report(node, "ODS005",
                                "SQL passed to cr.execute() is built with string formatting; "
                                "pass values as query parameters")
            # ODS006: Markup() on dynamic data
            if call_name(node) == "Markup" and node.args:
                arg = node.args[0]
                if self._markup_arg_is_safe(arg):
                    continue
                if route and self.is_tainted(arg, facts):
                    self.report(node, "ODS006",
                                "Markup() wraps request data: this renders attacker HTML unescaped",
                                severity="error")
                else:
                    self.report(node, "ODS006",
                                f"Markup() wraps a non-literal value ({dotted(arg)}); make sure it is "
                                "trusted HTML, or use Markup('...%s...') % value")

    @staticmethod
    def _own_walk(fn: ast.AST) -> Iterable[ast.AST]:
        """Walk fn's body without descending into nested functions/classes (they get their own pass)."""
        stack = list(ast.iter_child_nodes(fn))
        while stack:
            node = stack.pop()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                continue
            yield node
            stack.extend(ast.iter_child_nodes(node))

    @staticmethod
    def _markup_arg_is_safe(arg: ast.AST) -> bool:
        if is_str_const(arg):
            return True
        if isinstance(arg, ast.JoinedStr):
            return not any(isinstance(v, ast.FormattedValue) for v in arg.values)
        if isinstance(arg, ast.Call) and call_name(arg) in SAFE_MARKUP_WRAPPERS:
            return all(is_str_const(a) for a in arg.args) or call_name(arg) in {"html_escape", "escape", "html_sanitize"}
        return False

    def check_route(self, fn, route: RouteInfo, facts: FunctionFacts, nodes: List[ast.AST]) -> None:
        calls = sorted((n for n in nodes if isinstance(n, ast.Call)), key=lambda n: (n.lineno, n.col_offset))

        # ODS001: sudo() + record selection driven by request data
        if not facts.has_access_check:
            for c in calls:
                if call_name(c) in RECORD_FETCHERS and isinstance(c.func, ast.Attribute):
                    if self.has_sudo(c.func.value, facts):
                        argv = list(c.args) + [k.value for k in c.keywords]
                        if any(self.is_tainted(a, facts) for a in argv):
                            self.report(c, "ODS001",
                                        f"{dotted(c.func)}(...) runs as superuser on a value taken "
                                        "from the request, with no access check in this route")

        # ODS004: browse(user id) then .sudo() on that record, no access check
        if not facts.has_access_check:
            for c in calls:
                if call_name(c) != "sudo" or not isinstance(c.func, ast.Attribute):
                    continue
                recv = c.func.value
                hit = (isinstance(recv, ast.Name) and recv.id in facts.browsed_vars) or (
                    isinstance(recv, ast.Call) and call_name(recv) == "browse"
                    and any(self.is_tainted(a, facts) for a in recv.args)
                    and not self.has_sudo(recv, facts)
                )
                if hit:
                    self.report(c, "ODS004",
                                f"{dotted(recv)} was selected by a request id and is elevated with "
                                "sudo() without _document_check_access()/check_access")

        # ODS002: public/none route that uses sudo()
        if route.auth in ("public", "none"):
            for c in calls:
                if self.has_sudo(c, FunctionFacts()) and call_name(c) in ("sudo", "with_user"):
                    self.report(c, "ODS002",
                                f"auth='{route.auth}' route elevates with {call_name(c)}(); anonymous "
                                "visitors reach this code")
                    break

        # ODS003: csrf=False on an http route that changes state
        if not route.csrf and route.type == "http":
            if route.methods and set(route.methods) <= {"GET", "HEAD", "OPTIONS"}:
                return
            for c in calls:
                n = call_name(c)
                if isinstance(c.func, ast.Attribute) and (n in STATE_CHANGERS or n.startswith(STATE_CHANGER_PREFIXES)):
                    self.report(c, "ODS003",
                                f"csrf=False route '{fn.name}' (line {route.lineno}) calls "
                                f"{dotted(c.func)}(); a cross-site form can trigger it")
                    break


def check_python_source(path: str, source: str) -> List[Finding]:
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError:
        return []
    return _Analyzer(path, source).run(tree)
