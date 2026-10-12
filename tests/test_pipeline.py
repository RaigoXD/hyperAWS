"""Scan orchestration, safety properties of the output, and the full demo end to end."""

import contextlib
import io
import json
import re
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from analyzer import cli, collectors, costexplorer, report, vendor
from analyzer.analysis.config import load_config
from analyzer.analysis.engine import analyze
from analyzer.awscli import AuthError, AwsCli, ReadOnlyViolation
from analyzer.demo import ACCOUNT, demo_executor
from analyzer.fakeaws import FakeAws, FakeError
from analyzer.scan import ScanOptions, run_scan, select_collectors

READ = re.compile(r"^(describe|list|get|batch-get)-[a-z0-9-]+$")
SECRETS = ("definitely-not-for-the-report", "DB_PASSWORD", "ops@example.com", "AKIAALICE00000000001", "AKIABOB0000000000002",
           "AKIACIBOT000000000003", "demo-sns-webhook-token-7f3a91c2")


def cli_for(fake, **kw):
    return AwsCli("t", executor=fake, aws_bin="aws", sleep=lambda s: None, **kw)


def quiet(**kw):
    return ScanOptions(quiet=True, **kw)


class TestScan(unittest.TestCase):
    def base_fake(self):
        f = FakeAws()
        f.set("sts", "get-caller-identity", {"Account": "111122223333", "Arn": "arn:aws:iam::111122223333:user/x"})
        f.set("ec2", "describe-regions", {"Regions": [{"RegionName": "us-east-1"}, {"RegionName": "eu-west-1"}]})
        return f

    def test_dry_run_sends_nothing_and_plans_only_reads(self):
        boom = mock.Mock(side_effect=AssertionError("dry run must not execute aws"))
        scan = run_scan(["p"], quiet(regions=["us-east-1"]), cli=AwsCli("p", executor=boom, aws_bin="aws", dry_run=True))
        boom.assert_not_called()
        self.assertTrue(scan["audit"])
        self.assertEqual({c["status"] for c in scan["audit"]}, {"planned"})
        self.assertTrue(all(READ.match(c["op"]) for c in scan["audit"]))
        planned = {(c["service"], c["op"]) for c in scan["audit"]}
        self.assertIn(("ec2", "describe-instances"), planned)
        self.assertEqual(scan["resources"], [])

    def test_gaps_are_aggregated_and_never_fatal(self):
        f = self.base_fake()
        f.set("s3api", "list-buckets", {"Buckets": [{"Name": f"b{i}", "CreationDate": "2024-01-01T00:00:00Z", "BucketRegion": "us-east-1"} for i in range(3)]})

        def deny(region, args):
            raise FakeError("AccessDenied", "nope")
        f.set("s3api", "get-bucket-versioning", deny)
        f.set("ec2", "describe-vpcs", {"Vpcs": [{"VpcId": "vpc-1"}]})
        scan = run_scan(["p"], quiet(regions=["us-east-1"], metrics=False, services=["s3", "ec2_net"]), cli=cli_for(f))
        gap = [g for g in scan["gaps"] if g["op"] == "get-bucket-versioning"]
        self.assertEqual(len(gap), 1)
        self.assertEqual((gap[0]["count"], gap[0]["code"]), (3, "AccessDenied"))
        self.assertEqual(len([r for r in scan["resources"] if r["type"] == "s3:bucket"]), 3)   # data still collected
        self.assertTrue(any(r["type"] == "ec2:vpc" for r in scan["resources"]))

    def test_expired_credentials_abort_the_scan(self):
        f = FakeAws()

        def expired(region, args):
            raise FakeError("ExpiredToken", "token expired")
        f.set("sts", "get-caller-identity", expired)
        with self.assertRaises(AuthError):
            run_scan(["p"], quiet(), cli=cli_for(f))

    def test_write_attempt_by_a_collector_is_fatal(self):
        bad = types.SimpleNamespace(NAME="evil", GROUP="evil", SCOPE="regional", collect=lambda ctx: ctx.aws("ec2", "delete-volume", ["--volume-id", "v"]))
        with mock.patch.object(collectors, "ALL", [bad]):
            with self.assertRaises(ReadOnlyViolation):
                run_scan(["p"], quiet(regions=["us-east-1"]), cli=cli_for(self.base_fake()))

    def test_collector_crash_is_recorded_not_fatal(self):
        def crash(ctx):
            raise KeyError("surprise")
        bad = types.SimpleNamespace(NAME="flaky", GROUP="flaky", SCOPE="regional", collect=crash)
        with mock.patch.object(collectors, "ALL", [bad]):
            scan = run_scan(["p"], quiet(regions=["us-east-1"]), cli=cli_for(self.base_fake()))
        self.assertEqual([(g["service"], g["code"]) for g in scan["gaps"]], [("flaky", "CollectorError")])

    def test_same_account_via_two_profiles_is_scanned_once(self):
        scan = run_scan(["a", "b"], quiet(regions=["us-east-1"], metrics=False, services=["ec2_net"]), cli=cli_for(self.base_fake()))
        self.assertEqual(len(scan["accounts"]), 1)

    def test_services_filter_always_keeps_tagging(self):
        names = {c.NAME for c in select_collectors(["data"])}
        self.assertIn("tagging", names)
        self.assertIn("rds", names)
        self.assertNotIn("ec2_net", names)
        with self.assertRaises(SystemExit):
            select_collectors(["nope"])

    def test_cost_explorer_makes_three_calls_and_parses(self):
        f = self.base_fake()
        f.set("ce", "get-cost-and-usage", lambda reg, args: {"ResultsByTime": [{"Groups": [
            {"Keys": ["Amazon EC2" if "SERVICE" in " ".join(args) else "Project$shop"], "Metrics": {"UnblendedCost": {"Amount": "120.5"}}}]}]})
        f.set("ce", "get-rightsizing-recommendation", {"RightsizingRecommendations": [{
            "RightsizingType": "MODIFY", "CurrentInstance": {"ResourceId": "i-1", "ResourceDetails": {"EC2ResourceDetails": {"InstanceType": "m5.2xlarge"}}},
            "ModifyRecommendationDetail": {"TargetInstances": [{"EstimatedMonthlySavings": "55.1", "ResourceDetails": {"EC2ResourceDetails": {"InstanceType": "m5.xlarge"}}}]}}]})
        scan = run_scan(["p"], quiet(regions=["us-east-1"], metrics=False, services=["ec2_net"], cost_explorer=True), cli=cli_for(f))
        ce = scan["cost_explorer"][0]
        self.assertEqual(sum(1 for c in scan["audit"] if c["service"] == "ce"), costexplorer.CALLS)
        self.assertEqual(ce["by_service"][0], {"name": "Amazon EC2", "usd": 120.5})
        self.assertEqual(ce["by_tag"]["groups"][0]["name"], "shop")
        self.assertEqual(ce["rightsizing"][0], {"id": "i-1", "action": "Modify", "current": "m5.2xlarge", "recommended": "m5.xlarge", "saving": 55.1})

    def test_cost_explorer_denied_is_reported_not_crashing(self):
        f = self.base_fake()

        def deny(region, args):
            raise FakeError("AccessDeniedException", "no ce")
        f.set("ce", "get-cost-and-usage", deny)
        scan = run_scan(["p"], quiet(regions=["us-east-1"], metrics=False, services=["ec2_net"], cost_explorer=True), cli=cli_for(f))
        self.assertIn("error", scan["cost_explorer"][0])


class TestDemoEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        executor, cls.world = demo_executor()
        cls.cli = AwsCli("demo", executor=executor, aws_bin="aws")
        cls.scan = run_scan(["demo"], quiet(), cli=cls.cli)
        cls.analysis = analyze(json.loads(json.dumps(cls.scan)), load_config())
        cls.executor = executor

    def test_every_api_call_was_a_read(self):
        self.assertGreater(len(self.scan["audit"]), 100)
        self.assertEqual([c for c in self.scan["audit"] if not READ.match(c["op"])], [])
        self.assertEqual([op for _s, op, _r, _a in self.executor.calls if not READ.match(op)], [])
        self.assertEqual(self.scan["gaps"], [])

    def test_no_secret_reaches_any_output(self):
        for name, blob in (("scan", json.dumps(self.scan)), ("analysis", json.dumps(self.analysis)),
                           ("html", report.build_html(self.analysis))):
            for secret in SECRETS:
                self.assertNotIn(secret, blob, f"{secret!r} leaked into the {name}")

    def test_expected_findings_are_present(self):
        rules = {f["rule"] for f in self.analysis["findings"]}
        for expected in ("ec2.eip.unassociated", "ec2.volume.unattached", "ec2.instance.idle", "ec2.instance.stopped", "ec2.nat.idle",
                         "elb.lb.no-targets", "elb.clb.no-instances", "rds.instance.stopped", "rds.instance.multi-az-nonprod", "eks.extended-support",
                         "ddb.table.overprovisioned", "ddb.table.idle", "sec.sg.world-open", "sec.rds.public", "sec.r53.dangling",
                         "lambda.runtime.deprecated", "logs.no-retention", "cost.ebs.gp2-to-gp3", "cost.nonprod-schedule", "net.vpc.empty",
                         "ec2.snapshot.orphaned-ami", "r53.zone.empty", "s3.bucket.no-lifecycle", "sec.iam.key-unused"):
            self.assertIn(expected, rules)
        summary = self.analysis["summary"]
        self.assertGreater(summary["potential_savings_confident_usd"], 0)
        self.assertGreaterEqual(summary["potential_savings_usd"], summary["potential_savings_confident_usd"])
        self.assertGreater(summary["est_monthly_usd"], summary["potential_savings_usd"])

    def test_projects_are_discovered(self):
        names = {p["name"] for p in self.analysis["projects"]}
        self.assertTrue({"shop", "analytics", "platform", "marketing", "Unassigned"} <= names)
        shop = next(p for p in self.analysis["projects"] if p["name"] == "shop")
        self.assertGreater(shop["resources"], 30)
        self.assertIn("inherited", shop["sources"])

    def test_report_is_self_contained_and_offline(self):
        html = report.build_html(self.analysis)
        self.assertNotIn("<!--@", html, "all template markers must be replaced")
        outside_data = re.sub(r'<script id="aws-data".*?</script>', "", html, flags=re.S)
        # the only exemption is the pinned third-party block, byte for byte (three.js contains unused loaders)
        start, end = outside_data.index(vendor.BEGIN), outside_data.index(vendor.END) + len(vendor.END)
        self.assertEqual(outside_data[start:end], vendor.three_factory_js())
        ours = outside_data[:start] + outside_data[end:]
        self.assertNotRegex(ours, r'<(?:script|link|img|iframe)[^>]+(?:src|href)\s*=\s*["\']https?://')
        self.assertNotRegex(ours, r"\bfetch\s*\(|XMLHttpRequest|\bnew\s+WebSocket\b|sendBeacon")
        m = re.search(r'<script id="aws-data" type="application/json">(.*?)</script>', html, flags=re.S)
        data = json.loads(m.group(1))     # exactly what the browser's JSON.parse will see
        self.assertEqual(len(data["resources"]), len(self.analysis["resources"]))

    def test_csp_forbids_network_and_pins_the_script(self):
        html = report.build_html(self.analysis)
        m = re.search(r'<meta http-equiv="Content-Security-Policy" content="([^"]+)">', html)
        self.assertIsNotNone(m)
        self.assertLess(m.start(), html.index("<script"), "the CSP must come before any script")
        csp = dict(d.strip().split(" ", 1) for d in m.group(1).split(";"))
        for directive in ("default-src", "connect-src", "frame-src", "worker-src", "object-src", "form-action", "base-uri"):
            self.assertEqual(csp[directive], "'none'", directive)
        self.assertNotIn("unsafe", csp["script-src"])
        # Trusted Types: HTML/script sinks (innerHTML ...) throw, so untrusted names can only ever become text
        self.assertEqual((csp["require-trusted-types-for"], csp["trusted-types"]), ("'script'", "'none'"))
        app = re.search(r"<script>(.*?)</script>", html, flags=re.S).group(1)
        self.assertEqual(csp["script-src"], f"'{report.script_hash(app)}'", "the hash must match the inline app script")
        self.assertEqual(html.count("<script"), 2)

    def test_build_refuses_html_breaking_viewer_code(self):
        d = Path(tempfile.mkdtemp())
        (d / "js").mkdir()
        (d / "vendor").mkdir()
        for f in (report.VIEWER / "vendor").iterdir():
            (d / "vendor" / f.name).write_bytes(f.read_bytes())
        (d / "index.html").write_text((report.VIEWER / "index.html").read_text())
        (d / "styles.css").write_text("")
        for n in report.JS_ORDER:
            (d / "js" / n).write_text("/* ok */")
        (d / "js" / "app.js").write_text("var s = '</script><script>alert(1)';")
        with self.assertRaises(report.BuildError):
            report.build_html(None, viewer_dir=d)

    def test_json_embedding_is_inert(self):
        evil = {"resources": [{"name": "</script><script>alert(1)</script><!-- x"}]}
        html = report.build_html(evil)
        data_block = re.search(r'<script id="aws-data" type="application/json">(.*?)</script>', html, flags=re.S).group(1)
        self.assertNotIn("</script", data_block)
        self.assertNotIn("<!--", data_block)
        self.assertNotRegex(data_block, r"(?i)<script")
        self.assertEqual(json.loads(data_block), evil)                   # and it round-trips losslessly
        self.assertEqual(html.count("<script"), 2)   # the data block + the app, nothing injected

    def test_empty_viewer_builds(self):
        self.assertIn('type="application/json">null</script>', report.build_html(None))


class TestCli(unittest.TestCase):
    def test_scan_requires_an_explicit_profile(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as cm:
                cli.main(["scan", "--out-dir", tempfile.mkdtemp()])
        self.assertIn("--profile is required", str(cm.exception))

    def test_dry_run_cli_does_not_call_aws(self):
        out = io.StringIO()
        with mock.patch("analyzer.awscli._subprocess_executor", side_effect=AssertionError("must not run")), \
                mock.patch("analyzer.awscli.AwsCli._bin", return_value="aws"), contextlib.redirect_stdout(out):
            rc = cli.main(["scan", "--profile", "x", "--regions", "us-east-1", "--dry-run", "-q", "--out-dir", tempfile.mkdtemp()])
        self.assertEqual(rc, 0)
        self.assertIn("DRY RUN: nothing was sent to AWS", out.getvalue())

    def test_demo_command_writes_scan_analysis_and_report(self):
        d = Path(tempfile.mkdtemp())
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.main(["demo", "--out-dir", str(d)]), 0)
        names = sorted(p.name.split("-")[0].split(".")[0] for p in (d / "demo").iterdir())
        self.assertEqual(names, ["analysis", "report", "report", "scan"])
        self.assertIn(ACCOUNT, next((d / "demo").glob("scan-*.json")).name)


if __name__ == "__main__":
    unittest.main()
