"""Static self-check that the code base only performs allowlisted reads.

Run with ``python3 -m analyzer audit-readonly``. It parses (never imports or executes) every module in ``analyzer/``
and the scripts in ``hooks/`` and ``tools/``. It is a regression check against honest mistakes and careless edits,
not a sandbox: whoever can edit the code can always hide something from a static check, so the read-only IAM policy
you scan with stays the real guarantee. It checks that

* only ``awscli.py`` starts processes: no other file imports ``subprocess``/``multiprocessing``/``asyncio``/``pty``
  ..., uses ``os.system``/``os.popen``/``os.exec*``/``os.spawn*``/``os.posix_spawn*``/``os.fork`` (also through an
  alias: ``import os as o``, ``from os import system``), or reaches the chokepoint's raw executor
  (``_subprocess_executor``, ``AwsCli._executor``), which runs an argv without the read-only guard,
* every import is on a fixed allowlist of standard-library modules (or is the project's own), so a module that loads
  code, starts processes or opens connections (``importlib``, ``ctypes``, ``socket``, ``http``, ``urllib``,
  ``boto3`` ...) cannot come in without a review of this file,
* nothing runs or imports code dynamically: no ``eval``/``exec``/``compile``/``__import__``/``globals``/``vars``,
  no ``getattr`` with a computed or forbidden name, no ``sys.modules``, no frame or class introspection
  (``__subclasses__``, ``__globals__`` ...); ``os``/``sys`` are only used as ``os.<name>``, never passed around,
* nothing outside ``awscli.py``/``allowlist.py`` rebinds or mutates the guard (``allowlist.ALLOWED[...] = ...``,
  ``AwsCli.call = ...``) or changes ``os.environ`` (the AWS CLI's environment is built in ``awscli.py``),
* every AWS call site passes the service and operation as string *literals* (so it can be verified statically), the
  pair is allowlisted and passes the read-only guard, and ``.aws``/``.call`` are only ever called, never stored or
  passed around; a call of an operation whose answer holds a secret (``allowlist.QUERY_REQUIRED``) passes
  ``"--query"`` literally; ``hooks/`` and ``tools/`` make no AWS calls at all,
* (informational) which allowlist entries no code uses any more, so the generated IAM policy stays minimal,
* the HTML viewer never makes network requests (no backend, no phoning home) and never navigates to a web address.
  The page's Content-Security-Policy blocks scripted requests and sub-resources, but no CSP directive blocks a
  top-level navigation, so navigation sinks (``location``, ``open()``, links, forms, meta refresh, HTML strings,
  absolute URLs ...) are looked for here. That scan is a best-effort heuristic over the source text; the element
  factories in ``viewer/js/util.js`` also refuse navigating elements and URL attributes at run time.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import allowlist, vendor
from .awscli import ReadOnlyViolation, check_command

PKG_DIR = Path(__file__).resolve().parent
ROOT = PKG_DIR.parent
CHOKEPOINT = "awscli.py"
GUARD_FILES = {"awscli.py", "allowlist.py"}     # the guard's code and tables; only these may change them
SCRIPT_DIRS = ("hooks", "tools")                # standalone scripts next to the package, audited with the same rules
CHOKEPOINT_MAY_USE = "subprocess"               # the one process module, and only in CHOKEPOINT

_PROCESS = "starts processes; only awscli.py may"
_SDK = "runs AWS in-process; all AWS access goes through awscli.py"
_CODE = "loads or runs code dynamically"
_NET = "opens network connections"
# Modules, or members by dotted prefix, that no audited file may use (CHOKEPOINT may use CHOKEPOINT_MAY_USE).
FORBIDDEN_MODULES = {
    **dict.fromkeys(("subprocess", "_posixsubprocess", "_winapi", "posix", "nt", "pty", "pexpect", "sh", "plumbum",
                     "multiprocessing", "_multiprocessing", "asyncio", "concurrent.futures.process",
                     "concurrent.futures.ProcessPoolExecutor", "pydoc", "webbrowser", "mailcap", "distutils",
                     "ensurepip", "venv"), _PROCESS),
    **dict.fromkeys(("boto3", "botocore", "aioboto3", "aiobotocore", "s3transfer", "awscli"), _SDK),
    **dict.fromkeys(("importlib", "imp", "runpy", "ctypes", "_ctypes", "cffi", "code", "codeop", "zipimport",
                     "builtins", "gc", "pickle", "_pickle", "marshal", "shelve"), _CODE),
    **dict.fromkeys(("socket", "_socket", "ssl", "_ssl", "http", "urllib", "urllib3", "requests", "httpx", "aiohttp",
                     "ftplib", "smtplib", "poplib", "imaplib", "nntplib", "telnetlib", "xmlrpc", "socketserver"), _NET),
}
FORBIDDEN_OS_ATTRS = {"system", "popen", "fork", "forkpty", "openpty", "startfile", "putenv", "unsetenv"}
FORBIDDEN_OS_PREFIXES = ("exec", "spawn", "posix_spawn")
FORBIDDEN_SYS_ATTRS = {"modules", "_getframe", "meta_path", "path_hooks", "path_importer_cache", "settrace", "setprofile"}
# Every import must be the project's own or start with one of these (checked after FORBIDDEN_MODULES). None of them can
# start a process, load code or open a connection. Add a module here only after checking exactly that.
IMPORT_ALLOWLIST = frozenset("""
__future__ abc argparse array ast base64 binascii bisect bz2 calendar codecs collections colorsys concurrent.futures
contextlib contextvars copy csv dataclasses datetime decimal difflib enum errno filecmp fnmatch fractions functools
glob graphlib grp gzip hashlib heapq hmac html io ipaddress itertools json keyword lzma math mimetypes numbers os pathlib
pprint pwd queue random re reprlib secrets shlex shutil stat statistics string struct sys tarfile tempfile textwrap
threading time tokenize tomllib traceback typing unicodedata warnings weakref zipfile zlib zoneinfo
""".split())
_NOT_ALLOWLISTED = "import of '{}' is not on the import allowlist (review it, then add it to IMPORT_ALLOWLIST in analyzer/audit.py)"
FORBIDDEN_NAMES = {"eval", "exec", "compile", "__import__", "globals", "locals", "vars", "__builtins__", "__loader__",
                   "__spec__"}
# attributes that reach modules, globals, frames or classes the audit cannot follow (CHOKEPOINT may use them)
INTROSPECTION_ATTRS = {"__dict__", "__globals__", "__builtins__", "__subclasses__", "__bases__", "__base__", "__mro__",
                       "__class__", "__code__", "__closure__", "__self__", "__func__", "__getattribute__",
                       "__setattr__", "__delattr__", "__loader__", "__spec__", "__import__", "__reduce__",
                       "__reduce_ex__", "f_globals", "f_locals", "f_builtins", "f_back", "tb_frame", "gi_frame",
                       "cr_frame", "ag_frame"}
VALUE_GUARDED = {"os", "sys", "concurrent", "concurrent.futures"}   # modules with forbidden members: os.<name> only
MUTATORS = {"update", "add", "discard", "remove", "pop", "popitem", "clear", "setdefault", "append", "extend",
            "insert", "sort", "reverse", "__setitem__", "__delitem__"}
# The chokepoint's raw executor: it runs any argv without the guard. These names are always protected; run_audit
# adds every function in CHOKEPOINT that uses subprocess, and every private attribute such a function is stored in.
EXECUTOR_NAMES = {"_subprocess_executor", "_executor"}
CALL_ATTRS = {"aws", "call"}  # ctx.aws(...) / cli.call(...)
# The one generic wrapper (Ctx.aws) forwards non-literal names to AwsCli.call,
# which still runs the runtime guard. It must carry this marker, in this file only.
PASSTHROUGH_MARK = "audit: passthrough"
PASSTHROUGH_FILES = {"analyzer/scan.py"}


@dataclass
class AuditReport:
    violations: list[str] = field(default_factory=list)
    used: set[tuple[str, str]] = field(default_factory=set)
    unused: list[tuple[str, str]] = field(default_factory=list)
    files: int = 0

    @property
    def ok(self) -> bool:
        return not self.violations


def forbidden(dotted: str) -> str | None:
    """Why the module or member ``dotted`` (``os.system``, ``concurrent.futures.process``) may not be used, or None."""
    parts = dotted.split(".")
    for i in range(1, len(parts) + 1):
        reason = FORBIDDEN_MODULES.get(".".join(parts[:i]))
        if reason:
            return reason
    if len(parts) > 1 and parts[0] == "os" and (parts[1] in FORBIDDEN_OS_ATTRS or parts[1].startswith(FORBIDDEN_OS_PREFIXES)):
        return "changes the AWS CLI's environment" if parts[1] in {"putenv", "unsetenv"} else _PROCESS
    if len(parts) > 1 and parts[0] == "sys" and parts[1] in FORBIDDEN_SYS_ATTRS:
        return "reaches loaded modules or frames"
    return None


def _import_allowed(dotted: str) -> bool:
    parts = dotted.split(".")
    return any(".".join(parts[:i]) in IMPORT_ALLOWLIST for i in range(1, len(parts) + 1))


def _dotted(node: ast.AST, binds: dict[str, str]) -> str | None:
    """``o.system`` -> ``os.system`` when ``o`` was bound by ``import os as o``; None if the root is not an import."""
    attrs: list[str] = []
    while isinstance(node, ast.Attribute):
        attrs.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name) and node.id in binds:
        return ".".join([binds[node.id], *reversed(attrs)])
    return None


def _mentions(node: ast.AST, names: set[str]) -> bool:
    return any(isinstance(n, ast.Name) and n.id in names for n in ast.walk(node))


def executor_names(chokepoint: Path) -> frozenset[str]:
    """EXECUTOR_NAMES plus what CHOKEPOINT currently calls its raw executor (so a rename there stays protected)."""
    names = set(EXECUTOR_NAMES)
    try:
        tree = ast.parse(chokepoint.read_text(encoding="utf-8"))
    except (OSError, SyntaxError, ValueError):
        return frozenset(names)
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and _mentions(node, {CHOKEPOINT_MAY_USE}):
            names.add(node.name)
    for node in tree.body:                                      # a module-level alias: _RAW = _subprocess_executor
        if isinstance(node, ast.Assign) and _mentions(node.value, names):
            names.update(t.id for t in node.targets if isinstance(t, ast.Name) and t.id.startswith("_"))
    for cls in (n for n in tree.body if isinstance(n, ast.ClassDef)):
        for node in ast.walk(cls):
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None and _mentions(node.value, names):
                for t in (node.targets if isinstance(node, ast.Assign) else [node.target]):
                    if isinstance(t, ast.Attribute) and t.attr.startswith("_"):
                        names.add(t.attr)
                        if t.attr.startswith("__") and not t.attr.endswith("__"):
                            names.add(f"_{cls.name.lstrip('_')}{t.attr}")     # name mangling: _AwsCli__executor
    return frozenset(names)


def _bindings(tree: ast.AST, rel: str, project: set[str]) -> tuple[dict[str, str], list[tuple[ast.AST, str, str, bool]]]:
    """Every name an import binds -> the dotted module/member it refers to, plus (node, imported, base, is_project)."""
    pkg_parts = rel.replace("\\", "/").split("/")[:-1]
    binds: dict[str, str] = {}
    imports: list[tuple[ast.AST, str, str, bool]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                binds[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
                imports.append((node, a.name, a.name, a.name.split(".")[0] in project))
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base_parts = pkg_parts[:len(pkg_parts) - (node.level - 1)] if node.level > 1 else pkg_parts
                base = ".".join(base_parts + ([node.module] if node.module else []))
                is_project = True
            else:
                base = node.module or ""
                is_project = base.split(".")[0] in project
            for a in node.names:
                if a.name != "*":
                    binds[a.asname or a.name] = f"{base}.{a.name}"
                imports.append((node, a.name, base, is_project))
    return binds, imports


class _FileAudit:
    """The checks for one parsed file. ``role`` is "chokepoint", "guard" (allowlist.py), "package" or "script"."""

    def __init__(self, tree: ast.AST, text: str, rel: str, report: AuditReport, role: str, project: set[str],
                 executors: frozenset[str]):
        self.rel, self.report, self.role, self.executors = rel, report, role, executors
        self.choke = role == "chokepoint"
        self.owns_guard = role in ("chokepoint", "guard")
        self.guards = tuple(f"{p}.{f[:-3]}" for p in sorted(project) for f in sorted(GUARD_FILES))
        self.src_lines = text.splitlines()
        self.parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
        self.binds, self.imports = _bindings(tree, rel, project)
        self.tree = tree

    def flag(self, node: ast.AST, msg: str) -> None:
        self.report.violations.append(f"{self.rel}:{getattr(node, 'lineno', 0)}: {msg}")

    def is_guard(self, dotted: str | None) -> bool:
        return bool(dotted) and any(dotted == g or dotted.startswith(g + ".") for g in self.guards)

    def process_ok(self, dotted: str) -> bool:
        """The chokepoint's one exemption."""
        return self.choke and dotted.split(".")[0] == CHOKEPOINT_MAY_USE

    def run(self) -> None:
        self.check_imports()
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Name):
                self.check_name(node)
            elif isinstance(node, ast.Attribute):
                self.check_attribute(node)
            elif isinstance(node, ast.Call):
                self.check_call(node)
            elif isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign, ast.Delete)):
                self.check_assignment(node)

    def check_imports(self) -> None:
        reported: set[int] = set()                    # one violation per `from x import a, b`
        for node, name, base, is_project in self.imports:
            if name == "*":
                self.flag(node, f"star import from '{base}' (hides which names are used)")
            elif is_project:
                if name in self.executors and not self.choke:
                    self.flag(node, f"imports the chokepoint's raw executor '{name}' (it runs a process without the read-only guard)")
            elif isinstance(node, ast.Import):
                reason = forbidden(name)
                if reason and not self.process_ok(name):
                    self.flag(node, f"forbidden import '{name}' ({reason})")
                elif not reason and not _import_allowed(name):
                    self.flag(node, _NOT_ALLOWLISTED.format(name))
            elif forbidden(base):
                if not self.process_ok(base) and id(node) not in reported:
                    self.flag(node, f"forbidden import from '{base}' ({forbidden(base)})")
                reported.add(id(node))
            elif forbidden(f"{base}.{name}"):
                self.flag(node, f"forbidden import '{base}.{name}' ({forbidden(f'{base}.{name}')})")
            elif not (_import_allowed(base) or _import_allowed(f"{base}.{name}")) and id(node) not in reported:
                self.flag(node, _NOT_ALLOWLISTED.format(base))
                reported.add(id(node))

    def check_name(self, node: ast.Name) -> None:
        if node.id in FORBIDDEN_NAMES and isinstance(node.ctx, ast.Load):
            self.flag(node, f"forbidden name '{node.id}' ({_CODE})")
        if node.id in self.executors and not self.choke:
            self.flag(node, f"uses the chokepoint's raw executor '{node.id}' (it runs a process without the read-only guard)")
        target = self.binds.get(node.id)
        parent = self.parents.get(node)
        if (target in VALUE_GUARDED or (target in self.guards and not self.owns_guard)) and not (
                isinstance(parent, ast.Attribute) and parent.value is node):
            self.flag(node, f"module '{target}' used as a value (write {target}.<name> so this audit can see which member is used)")

    def check_attribute(self, node: ast.Attribute) -> None:
        parent = self.parents.get(node)
        if not (isinstance(parent, ast.Attribute) and parent.value is node):      # each chain once, in full
            dotted = _dotted(node, self.binds)
            reason = forbidden(dotted) if dotted else None
            if reason and not self.process_ok(dotted):
                self.flag(node, f"forbidden {dotted} ({reason})")
        if self.choke:
            return
        if node.attr in INTROSPECTION_ATTRS:
            self.flag(node, f"introspection '.{node.attr}' (reaches code or modules this audit cannot follow)")
        if node.attr in self.executors:
            self.flag(node, f"uses the chokepoint's raw executor '.{node.attr}' (it runs a process without the read-only guard)")
        if node.attr in CALL_ATTRS and not (isinstance(parent, ast.Call) and parent.func is node):
            self.flag(node, f"'.{node.attr}' used without calling it (every AWS call site must be a direct literal call)")

    def check_call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in CALL_ATTRS:
            if self.choke:
                return
            if self.role == "script":
                self.flag(node, f"hooks/ and tools/ make no AWS calls ('.{func.attr}(...)')")
                return
            line = self.src_lines[node.lineno - 1] if node.lineno <= len(self.src_lines) else ""
            if PASSTHROUGH_MARK in line and self.rel.replace("\\", "/") in PASSTHROUGH_FILES:
                return
            _audit_call(node, self.rel, self.report)
        elif isinstance(func, ast.Attribute) and func.attr in MUTATORS:
            self.check_change(node, _dotted(func.value, self.binds))
        elif isinstance(func, ast.Name) and func.id in {"getattr", "setattr", "delattr"} and len(node.args) >= 2:
            name = node.args[1]
            literal = name.value if isinstance(name, ast.Constant) and isinstance(name.value, str) else None
            hidden = self.executors | CALL_ATTRS | INTROSPECTION_ATTRS | FORBIDDEN_OS_ATTRS | FORBIDDEN_SYS_ATTRS
            if literal is not None and (literal in hidden or literal.startswith(FORBIDDEN_OS_PREFIXES)):
                self.flag(node, f"{func.id}(..., '{literal}') reaches a forbidden attribute by name")
            if func.id == "getattr" and literal is None:
                self.flag(node, "getattr with a computed attribute name (this audit cannot see what it reaches)")
            if func.id != "getattr":
                dotted = _dotted(node.args[0], self.binds)
                self.check_change(node, dotted)
                if dotted and literal is None and not self.is_guard(dotted):
                    self.flag(node, f"{func.id} on '{dotted}' with a computed attribute name")

    def check_assignment(self, node: ast.AST) -> None:
        targets = node.targets if isinstance(node, (ast.Assign, ast.Delete)) else [node.target]
        for t in (x for tgt in targets for x in ast.walk(tgt) if isinstance(x, (ast.Attribute, ast.Subscript))):
            self.check_change(t, _dotted(t.value if isinstance(t, ast.Subscript) else t, self.binds))

    def check_change(self, node: ast.AST, dotted: str | None) -> None:
        """``node`` writes to ``dotted``: never to the guard, and never to os.environ outside the chokepoint."""
        if self.is_guard(dotted) and not self.owns_guard:
            self.flag(node, f"changes the read-only guard '{dotted}' (only {CHOKEPOINT} and allowlist.py may)")
        if dotted == "os.environ" and not self.choke:
            self.flag(node, f"changes os.environ (the AWS CLI's environment is built in {CHOKEPOINT} only)")



def _audit_source(path: Path, rel: str, report: AuditReport, *, role: str | None = None,
                  project: set[str] | None = None, executors: frozenset[str] | None = None) -> None:
    try:
        text = path.read_text(encoding="utf-8")
        tree = ast.parse(text, filename=rel)
    except (SyntaxError, ValueError, UnicodeDecodeError) as e:
        report.violations.append(f"{rel}: syntax error {e}")
        return
    if role is None:
        role = "chokepoint" if path.name == CHOKEPOINT and path.parent == PKG_DIR else "package"
    _FileAudit(tree, text, rel, report, role, project or {"analyzer"},
               executors if executors is not None else frozenset(EXECUTOR_NAMES)).run()


def _audit_call(node: ast.Call, rel: str, report: AuditReport) -> None:
    pos = node.args
    if len(pos) < 2:
        report.violations.append(f"{rel}:{node.lineno}: AWS call without literal service/operation")
        return
    s, o = pos[0], pos[1]
    if not (isinstance(s, ast.Constant) and isinstance(s.value, str)
            and isinstance(o, ast.Constant) and isinstance(o.value, str)):
        report.violations.append(
            f"{rel}:{node.lineno}: AWS call must pass service and operation as string literals"
        )
        return
    pair = (s.value, o.value)
    report.used.add(pair)
    try:
        check_command(*pair)
    except ReadOnlyViolation as e:
        report.violations.append(f"{rel}:{node.lineno}: {e}")
    if pair in allowlist.QUERY_REQUIRED and not _passes_query(node):
        report.violations.append(f"{rel}:{node.lineno}: '{pair[0]} {pair[1]}' answers with secret fields; pass "
                                 "\"--query\" (and its projection) literally in the argument list")


def _passes_query(node: ast.Call) -> bool:
    """The call's argument list (3rd positional or ``args=``) is a literal list/tuple holding "--query" or "--query=..."."""
    args = node.args[2] if len(node.args) > 2 else next((k.value for k in node.keywords if k.arg == "args"), None)
    if not isinstance(args, (ast.List, ast.Tuple)):
        return False
    for e in args.elts:
        if isinstance(e, ast.Constant) and isinstance(e.value, str) and (e.value == "--query" or e.value.startswith("--query=")):
            return True
        if (isinstance(e, ast.JoinedStr) and e.values and isinstance(e.values[0], ast.Constant)
                and str(e.values[0].value).startswith("--query=")):
            return True
    return False


# ---- viewer ---------------------------------------------------------------------------------------------------------
# Best-effort patterns over the raw source text (comments and strings included, so nothing can hide in them; a false
# positive is fixed by rewording). (regex, label). Matches on an exact line listed in _VIEWER_FACTORY_LINES are allowed.
_GLOBALS = r"(?:window|self|top|parent|opener|frames|globalThis|document|navigator)"
_NET_PATTERNS = [
    # network primitives (connect-src 'none' blocks them at run time too; this keeps them out of the code)
    (re.compile(r"\bfetch\b"), "fetch()"),
    (re.compile(r"XMLHttpRequest"), "XMLHttpRequest"),
    (re.compile(r"\bnew\s+WebSocket\b|\bWebSocket\s*\("), "WebSocket"),    # not the words in a label
    (re.compile(r"\bsendBeacon\b"), "sendBeacon"),
    (re.compile(r"\bimportScripts\b"), "importScripts"),
    (re.compile(r"\bEventSource\b|\bRTCPeerConnection\b|\bWebTransport\b"), "EventSource/WebRTC/WebTransport"),
    (re.compile(r"\b(?:Shared)?Worker\s*\(|\bserviceWorker\b"), "a worker"),
    (re.compile(r"(?<![\w$.])import\s*\("), "dynamic import()"),
    (re.compile(r"""<(?:script|link|img|iframe)[^>]+(?:src|href)\s*=\s*["']https?://""", re.I), "remote resource"),
    (re.compile(r"@import\b|\burl\(\s*(?![\"']?(?:data:|#))"), "CSS url()/@import of a resource"),
    # dynamic code: what it builds cannot be checked here (script-src without 'unsafe-eval' also blocks it)
    (re.compile(r"(?<![\w$.])eval\s*\(|\bnew\s+Function\b|(?<![\w$.])Function\s*\(|\bset(?:Timeout|Interval)\s*\(\s*['\"`]"),
     "dynamic code (eval, Function, string timer)"),
    # navigation: no CSP directive blocks a top-level navigation, so a URL carrying data must never be opened
    (re.compile(r"\blocation\b(?!\s*\.\s*hash\b)"), "location (navigation; only location.hash is allowed)"),
    (re.compile(r"(?<![\w$.])open\s*\(|\b" + _GLOBALS + r"\s*\.\s*open\b"), "window.open / open() (navigation)"),
    (re.compile(r"\bopener\b|\bpostMessage\b|\b(?:defaultView|contentWindow|contentDocument|ownerDocument)\b"),
     "another window"),
    (re.compile(r"\.\s*navigate\s*\(|\bnavigation\s*(?:\?\.\s*)?\[|[=(,:?]\s*navigation\s*(?=[;,)}\]:]|$)", re.M),
     "the Navigation API (navigation.navigate)"),
    (re.compile(r"\b" + _GLOBALS + r"\s*(?:\?\.\s*)?\["), "computed property of a global object"),
    (re.compile(r"[=(,:?]\s*(?:window|globalThis|self|frames|opener)\s*(?=[;,)}\]:]|$)", re.M), "window used as a value"),
    (re.compile(r"[=(,:?]\s*document\s*(?=[;,)}\]:]|$)", re.M), "document used as a value"),
    # an attribute name the audit cannot read: computed object keys ({['hr' + 'ef']: u}) and setAttribute with anything
    # but one plain string literal as the name ('hr' + 'ef', a variable); setAttributeNS only in the factories
    (re.compile(r"[{,]\s*\[[^\[\]\n]*\]\s*:"), "a computed key in an object literal (an attribute name built at run time)"),
    (re.compile(r"""\bsetAttribute\s*\(\s*(?!['"][\w:.-]+['"]\s*,)"""), "setAttribute with a computed name"),
    (re.compile(r"\bsetAttributeNS\b"), "setAttributeNS"),
    (re.compile(r"""\[\s*['"`](?:location|href|open|assign|replace|fetch|eval|submit|click|action|src|innerHTML|"""
                r"""outerHTML|write|setAttribute|createElement)['"`]\s*\]"""), "computed access to a navigation member"),
    (re.compile(r"""http-equiv(?!\s*=\s*["']?x-dns-prefetch-control["'\s>])""", re.I), "http-equiv (meta refresh)"),
    (re.compile(r"""['"`]\s*refresh\s*['"`]|\d\s*;\s*url\s*=""", re.I), "meta refresh"),
    (re.compile(r"""<(?:a|area)\s[^<>]*\bhref\b|<(?:form|base|iframe|frame|object|embed|portal)\b""", re.I),
     "navigating element in markup"),
    (re.compile(r"""\bh\s*\(\s*['"`](?:a|area|base|meta|link|script|form|iframe|frame|object|embed|portal)['"`]"""),
     "the element factory building a navigating element"),
    (re.compile(r"""createElement(?:NS)?\s*\((?!\s*['"`](?:canvas|div|span|b|i|em|strong|small|p|ul|ol|li|br)['"`]\s*\))"""),
     "createElement outside the element factories (A.h / A.svg)"),
    (re.compile(r"\b(?:inner|outer)HTML\b|insertAdjacentHTML|\bdocument\s*\.\s*write|\bDOMParser\b|"
                r"createContextualFragment|\bsrcdoc\b|\b(?:set|parse)HTMLUnsafe\b"), "an HTML string sink"),
    (re.compile(r"""setAttribute(?:NS)?\s*\(\s*(?:['"`](?:href|xlink:href|src|srcset|action|formaction|ping|"""
                r"""http-equiv|content|target)['"`]|(?!['"`]))"""), "setAttribute of a URL attribute or a computed name"),
    (re.compile(r"\.\s*(?:href|src|srcset|action|formAction|ping|httpEquiv|target)\s*=(?!=)"), "a URL property assignment"),
    (re.compile(r"\bhref\b['\"`]?\s*:"), "an href attribute"),
    (re.compile(r"\.\s*(?:submit|requestSubmit)\s*\("), "form submission"),
    # any absolute address in our own code (a link to click, a form to submit ...); XML namespace names are not fetched
    (re.compile(r"""["'`(=]\s*(?:https?|ftp|wss?|file|javascript|vbscript|mailto)\s*:(?!//www\.w3\.org/)""", re.I),
     "absolute http(s) URL or URL scheme"),
    (re.compile(r"""["'`(=]\s*//[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+"""), "protocol-relative URL"),
]
# The element factories themselves and the one local download link (a blob: URL, built outside A.h, which refuses
# every <a>), as exact code lines.
_VIEWER_FACTORY_LINES = {
    "js/util.js": {
        "const el = document.createElement(tag);",
        "const el = document.createElementNS(SVG_NS, tag);",
        "else el.setAttribute(k, v === true ? '' : v);",
        "el.setAttribute(k, s);",
        "const a = document.createElement('a');",
        "a.setAttribute('href', url);",
    },
}


def _code_line(text: str, pos: int) -> str:
    """The source line holding ``pos``, without a trailing ``//`` comment, stripped."""
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    line = text[start:end if end != -1 else len(text)]
    return re.sub(r"\s+//[^'\"`]*$", "", line).strip()


def audit_viewer(report: AuditReport, viewer_dir: Path | None = None, pins: dict[str, str | None] | None = None) -> None:
    """The viewer must be fully offline: no network primitives and no navigation sinks in our own code.

    Third-party code under ``vendor/`` is exempt from the pattern scan only when it is pinned in ``analyzer/vendor.py``
    and matches its SHA-256 byte for byte (``None`` pins are documentation files, which must not be code). Anything
    else in that folder is a violation, so the exemption cannot be used to smuggle code in.
    """
    viewer_dir = viewer_dir or ROOT / "viewer"
    if not viewer_dir.is_dir():
        return
    pins = vendor.pinned_files() if pins is None else pins
    for p in sorted(viewer_dir.rglob("*")):
        if not p.is_file():
            continue
        if "vendor" in p.relative_to(viewer_dir).parts:
            rel = p.relative_to(viewer_dir / "vendor").as_posix() if (viewer_dir / "vendor") in p.parents else p.name
            if rel not in pins:
                report.violations.append(f"{p.relative_to(viewer_dir)}: vendored file is not pinned in analyzer/vendor.py")
            elif pins[rel] is None:
                if p.suffix in {".js", ".mjs", ".html", ".css", ".wasm"}:
                    report.violations.append(f"{p.relative_to(viewer_dir)}: unpinned code in the vendor folder")
            elif vendor.sha256(p) != pins[rel]:
                report.violations.append(f"{p.relative_to(viewer_dir)}: vendored file does not match its pinned SHA-256")
            continue
        if p.suffix not in {".js", ".mjs", ".html", ".htm", ".css", ".svg"}:
            continue
        rel = p.relative_to(viewer_dir).as_posix()
        text = p.read_text(encoding="utf-8", errors="replace")
        allowed = _VIEWER_FACTORY_LINES.get(rel, set())
        for rx, label in _NET_PATTERNS:
            if any(_code_line(text, m.start()) not in allowed for m in rx.finditer(text)):
                report.violations.append(f"{p.relative_to(viewer_dir)}: viewer uses {label} (must stay offline)")


def run_audit(pkg_dir: Path | None = None, viewer_dir: Path | None = None,
              script_dirs: list[Path] | None = None) -> AuditReport:
    """Audit the package, the scripts next to it (``hooks/``, ``tools/``) and the viewer."""
    pkg_dir = pkg_dir or PKG_DIR
    script_dirs = [pkg_dir.parent / d for d in SCRIPT_DIRS] if script_dirs is None else script_dirs
    project = {"analyzer", pkg_dir.name}
    executors = executor_names(pkg_dir / CHOKEPOINT)
    report = AuditReport()
    files = [(p, "package") for p in sorted(pkg_dir.rglob("*.py"))]
    files += [(p, "script") for d in script_dirs if d.is_dir() for p in sorted(d.rglob("*.py"))]
    for path, role in files:
        if "__pycache__" in path.parts:
            continue
        if role == "package" and path.parent == pkg_dir and path.name in GUARD_FILES:
            role = "chokepoint" if path.name == CHOKEPOINT else "guard"
        report.files += 1
        _audit_source(path, str(path.relative_to(pkg_dir.parent)), report, role=role, project=project,
                      executors=executors)
    report.unused = sorted(set(allowlist.ALLOWED) - report.used)
    audit_viewer(report, viewer_dir)
    return report
