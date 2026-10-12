"""Regression tests for the security audit findings in the CLI / output-file group.

SECRETS-2, CODE-6 (private, atomic output files and safe input selection), SECRETS-4, CODE-5 (analyze/report never
overwrite their input), SECRETS-5, CODE-11 (summary output is sanitised), CODE-9 (--regions validation), CODE-10
(config validation), VIEWER-3 (strict JSON), VIEWER-4 (Trusted Types) and SECRETS-6 (credentials in free text).
"""

import contextlib
import io
import json
import os
import re
import stat
import tempfile
import textwrap
import unittest
from dataclasses import asdict
from pathlib import Path
from unittest import mock

from analyzer import cli, report
from analyzer.analysis import grouping
from analyzer.analysis.config import ConfigError, load_config
from analyzer.analysis.engine import analyze
from analyzer.awscli import AwsCli
from analyzer.fakeaws import FakeAws
from analyzer.fsutil import UnsafeOutputPath, write_private
from analyzer.model import Resource, make_key, mask_secrets
from analyzer.scan import ScanOptions, run_scan
from tests.test_audit_fixes import ACCT, NOW, ago, mk

KEY_ID = "AKIAIOSFODNN7EXAMPLE"
SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def tmp() -> Path:
    return Path(tempfile.mkdtemp())


def mode(p: Path) -> int:
    return stat.S_IMODE(os.lstat(p).st_mode)


def scan_dict(resources=None) -> dict:
    resources = resources or [mk("ec2:volume", "vol-1", state="available", size_gb=10, vol_type="gp3", created=ago(30))]
    return {"resources": [asdict(r) for r in resources], "gaps": [], "options": {}, "audit": [],
            "scanned_at": NOW.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "accounts": [{"account": ACCT, "profile": "t", "arn": "arn:aws:iam::1:user/x", "regions": ["us-east-1"]}]}


def run_cli(argv) -> tuple[int | None, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = cli.main(argv)
    return rc, out.getvalue(), err.getvalue()


# --------------------------------------------------------------------------- SECRETS-2 / CODE-6


class TestPrivateWrites(unittest.TestCase):
    def test_demo_first_flow_makes_every_created_folder_private(self):
        out = tmp() / "fresh" / "output"
        rc, _, _ = run_cli(["demo", "--out-dir", str(out)])
        self.assertEqual(rc, 0)
        self.assertEqual(mode(out.parent), 0o700, "intermediate folders are created 0700, not with the umask")
        self.assertEqual(mode(out), 0o700, "output/ itself: a later real scan writes into it")
        self.assertEqual(mode(out / "demo"), 0o700)

    def test_an_existing_loose_output_folder_is_tightened(self):
        d = tmp() / "shared"
        d.mkdir()
        os.chmod(d, 0o755)
        write_private(d / "scan.json", "{}")
        self.assertEqual(mode(d), 0o700)
        self.assertEqual(mode(d / "scan.json"), 0o600)

    def test_a_symlink_at_the_target_is_refused_and_its_target_untouched(self):
        d = tmp()
        victim = d / "victim_rc"
        victim.write_text("export PATH=...\n")
        os.chmod(victim, 0o644)
        (d / "out").mkdir(mode=0o700)
        (d / "out" / "report.html").symlink_to(victim)
        with self.assertRaises(UnsafeOutputPath):
            write_private(d / "out" / "report.html", "<html>REPORT</html>")
        self.assertEqual(victim.read_text(), "export PATH=...\n")
        self.assertEqual(mode(victim), 0o644)
        self.assertEqual([p.name for p in (d / "out").iterdir()], ["report.html"], "no temporary file is left behind")

    def test_a_hard_linked_target_is_refused(self):
        d = tmp()
        other = d / "elsewhere.txt"
        other.write_text("keep")
        (d / "out").mkdir(mode=0o700)
        os.link(other, d / "out" / "report.html")
        with self.assertRaises(UnsafeOutputPath):
            write_private(d / "out" / "report.html", "new")
        self.assertEqual(other.read_text(), "keep")

    def test_a_symlinked_or_foreign_output_folder_is_refused(self):
        d = tmp()
        (d / "real").mkdir()
        (d / "link").symlink_to(d / "real")
        with self.assertRaises(UnsafeOutputPath):
            write_private(d / "link" / "scan.json", "{}")
        self.assertEqual(list((d / "real").iterdir()), [])
        with mock.patch("os.getuid", return_value=os.getuid() + 1), self.assertRaises(UnsafeOutputPath):
            write_private(d / "real" / "scan.json", "{}")
        self.assertEqual(list((d / "real").iterdir()), [])

    def test_a_reader_of_the_old_file_never_sees_the_new_content(self):
        p = tmp() / "report.html"
        p.write_text("old public text")
        os.chmod(p, 0o644)
        with open(p) as reader:
            write_private(p, "SECRET-NEW-CONTENT")
            self.assertEqual(reader.read(), "old public text", "the new data goes to a new 0600 inode")
        self.assertEqual(p.read_text(), "SECRET-NEW-CONTENT")
        self.assertEqual(mode(p), 0o600)

    def test_a_failed_write_keeps_the_previous_file(self):
        p = tmp() / "report.html"
        write_private(p, "x" * 11000)
        with self.assertRaises(UnicodeEncodeError):
            write_private(p, "broken \ud800 text")
        self.assertEqual(p.read_text(), "x" * 11000)
        self.assertEqual([q.name for q in p.parent.iterdir()], ["report.html"])

    def test_latest_ignores_symlinks_and_files_of_other_users(self):
        d = tmp()
        real = d / "analysis-1-20260101T000000Z.json"
        real.write_text("{}")
        planted = d / "planted.json"
        planted.write_text("{}")
        (d / "analysis-zzzz.json").symlink_to(planted)
        os.utime(real, (1, 1))           # the symlink (and its target) are newer
        self.assertEqual(report.latest(d, "analysis"), real)
        with mock.patch("os.getuid", return_value=os.getuid() + 1):
            self.assertIsNone(report.latest(d, "analysis"), "a file owned by someone else is never picked up")


# --------------------------------------------------------------------------- SECRETS-4 / CODE-5


class TestStageOutputNames(unittest.TestCase):
    def setUp(self):
        self.src, self.out = tmp(), tmp() / "out"

    def test_analyze_never_overwrites_a_scan_without_the_prefix(self):
        scan = self.src / "myscan.json"
        scan.write_text(json.dumps(scan_dict()))
        before = scan.read_bytes()
        rc, _, err = run_cli(["analyze", str(scan), "--out-dir", str(self.out)])
        self.assertEqual(rc, 0)
        self.assertEqual(scan.read_bytes(), before, "the raw scan must survive")
        produced = self.out / "analysis-myscan.json"
        self.assertIn("findings", json.loads(produced.read_text()))
        self.assertIn(str(produced), err)
        self.assertEqual(sorted(p.name for p in self.src.iterdir()), ["myscan.json"], "--out-dir is honoured for explicit inputs")

    def test_report_never_overwrites_an_analysis_without_the_prefix_or_extension(self):
        data = self.src / "data"
        data.write_text(json.dumps(analyze(scan_dict(), load_config(), now=NOW)))
        before = data.read_bytes()
        rc, _, _ = run_cli(["report", str(data), "--out-dir", str(self.out)])
        self.assertEqual(rc, 0)
        self.assertEqual(data.read_bytes(), before)
        self.assertTrue((self.out / "report-data.html").read_text().startswith("<!doctype html>"))
        self.assertTrue((self.out / "report.html").exists())

    def test_standard_names_keep_their_stamp(self):
        scan = self.src / f"scan-{ACCT}-20261001T000000Z.json"
        scan.write_text(json.dumps(scan_dict()))
        run_cli(["analyze", str(scan), "--out-dir", str(self.out)])
        run_cli(["report", "--out-dir", str(self.out)])
        self.assertEqual(sorted(p.name for p in self.out.iterdir()),
                         [f"analysis-{ACCT}-20261001T000000Z.json", f"report-{ACCT}-20261001T000000Z.html", "report.html"])

    def test_output_equal_to_input_is_refused(self):
        self.out.mkdir()
        a = self.out / "analysis-x.json"           # `analyze` pointed at an analysis that lives in the output folder
        a.write_text(json.dumps(scan_dict()))
        before = a.read_bytes()
        with self.assertRaises(SystemExit) as cm, contextlib.redirect_stderr(io.StringIO()):
            cli.main(["analyze", str(a), "--out-dir", str(self.out)])
        self.assertIn("refusing to overwrite the input", str(cm.exception))
        self.assertEqual(a.read_bytes(), before)
        latest = self.out / "report.html"           # `report` pointed at the folder's latest-copy name
        latest.write_text(json.dumps(analyze(scan_dict(), load_config(), now=NOW)))
        before = latest.read_bytes()
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            cli.main(["report", str(latest), "--out-dir", str(self.out)])
        self.assertEqual(latest.read_bytes(), before)


# --------------------------------------------------------------------------- SECRETS-5 / CODE-11


class TestSummarySanitising(unittest.TestCase):
    def write(self, mutate) -> Path:
        d = tmp()
        res = analyze(scan_dict(), load_config(), now=NOW)
        mutate(res)
        p = d / "analysis-evil.json"
        p.write_text(json.dumps(res))
        return p

    def test_every_printed_field_is_sanitised(self):
        esc = "\x1b]0;PWNED\x07\x1b[2K\rfake line\x1b]52;c;ZXZpbA==\x07"

        def mutate(res):
            res["accounts"][0]["account"] = "123" + esc
            res["scanned_at"] = "\x1b[8mhidden\x1b[0m"
            res["summary"]["severities"] = {"high" + esc: 1}
            for f in res["findings"]:
                f["severity"], f["confidence"], f["in_total"], f["savings_usd"] = "high" + esc, "low" + esc, True, 5
            res["gaps"] = [{"service": "s3" + esc, "op": "x", "region": "r", "code": "c", "count": 1}]
        rc, out, _ = run_cli(["summary", str(self.write(mutate))])
        self.assertEqual(rc, 0)
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\x07", out)
        self.assertNotIn("\r", out)
        self.assertIn("accounts: 123?]0;PWNED?", out)

    def test_text_in_a_numeric_field_fails_cleanly(self):
        def mutate(res):
            res["summary"]["gaps"] = "\x1b[2J0"
            res["projects"][0]["resources"] = "\x1b]0;x\x07"
        with self.assertRaises(SystemExit) as cm, contextlib.redirect_stdout(io.StringIO()) as out:
            cli.main(["summary", str(self.write(mutate))])
        self.assertIn("does not look like an analysis file", str(cm.exception))
        self.assertNotIn("\x1b", str(cm.exception) + out.getvalue())


# --------------------------------------------------------------------------- CODE-9


class TestRegionsOption(unittest.TestCase):
    def options(self, value):
        seen = {}

        def fake_run_scan(profiles, opts, cli=None):
            seen["regions"] = opts.regions
            return {"audit": []}
        with mock.patch("analyzer.scan.run_scan", side_effect=fake_run_scan), mock.patch("analyzer.awscli.AwsCli._bin", return_value="aws"):
            run_cli(["scan", "--profile", "x", "--regions", value, "--dry-run", "-q", "--out-dir", str(tmp())])
        return seen["regions"]

    def test_duplicates_are_dropped_and_all_means_every_region(self):
        self.assertEqual(self.options("us-east-1, us-east-1,eu-west-1"), ["us-east-1", "eu-west-1"])
        self.assertEqual(self.options("us-gov-west-1"), ["us-gov-west-1"])
        self.assertIsNone(self.options("all"))

    def test_empty_and_malformed_entries_are_rejected_before_any_call(self):
        for bad in ("us-east-1, ,eu-west-1", "", "--debug", "us-east-1,--endpoint-url=https://x", "all,us-east-1", "US-EAST-1"):
            with self.subTest(bad=bad), mock.patch("analyzer.scan.run_scan", side_effect=AssertionError("must not scan")):
                with self.assertRaises(SystemExit) as cm, contextlib.redirect_stderr(io.StringIO()):
                    cli.main(["scan", "--profile", "x", f"--regions={bad}", "--dry-run", "-q", "--out-dir", str(tmp())])
                self.assertIn("--regions", str(cm.exception))


# --------------------------------------------------------------------------- CODE-10


class TestConfigValidation(unittest.TestCase):
    def cfg(self, text: str) -> Path:
        p = tmp() / "analyzer.toml"
        p.write_text(textwrap.dedent(text))
        return p

    def assertConfigError(self, text: str, needle: str):
        p = self.cfg(text)
        with self.assertRaises(ConfigError) as cm:
            load_config(p)
        self.assertIn(str(p), str(cm.exception))
        self.assertIn(needle, str(cm.exception))

    def test_wrong_types_and_bad_patterns_are_clear_errors(self):
        rule = '[[rules]]\nproject = "p"\n[rules.match]\n'
        self.assertConfigError(rule + 'name_regex = "("', "not a valid regular expression")
        self.assertConfigError(rule + f'name_regex = "{"a" * 300}"', "longer than")
        self.assertConfigError(rule + 'tags = { Team = ["a"] }', "match.tags.Team must be a string")
        self.assertConfigError(rule + 'stack = 5', "match.stack must be a string")
        self.assertConfigError(rule + 'name_prefix = [""]', "empty prefix")
        self.assertConfigError(rule + 'servics = ["ec2"]', "unknown match keys")
        self.assertConfigError('[[rules]]\nproject = "p"\n', "non-empty [rules.match]")
        self.assertConfigError('[thresholds]\nidle_cpu_avg = "5"\n', "thresholds.idle_cpu_avg must be a number")
        self.assertConfigError('[thresholds]\nidle_cpu_avg = nan\n', "thresholds.idle_cpu_avg must be a number")
        self.assertConfigError('[thresholds]\nidel_cpu_avg = 5\n', "unknown key")
        self.assertConfigError('[assumptions]\nnonprod_schedule_saving = 65\n', "between 0 and 1")
        self.assertConfigError('[projects]\nuse_stack_name = "yes"\n', "true or false")
        self.assertConfigError('[projects]\ntag_keys = [1, 2]\n', "list of strings")
        self.assertConfigError('[project]\ntag_keys = ["a"]\n', "unknown section")
        self.assertConfigError('rules = "x"\n', "[[rules]] tables")
        self.assertConfigError('[thresholds\n', "not valid TOML")

    def test_a_single_string_is_a_one_item_list_not_its_characters(self):
        cfg = load_config(self.cfg('''
            [assumptions]
            nonprod_envs = "dev"
            [[rules]]
            project = "checkout"
            [rules.match]
            name_prefix = "chk-"
            services = "ec2"
            accounts = [11122223333]
        '''))
        self.assertEqual(cfg["assumptions"]["nonprod_envs"], ["dev"])
        m = cfg["rules"][0]["match"]
        self.assertEqual((m["name_prefix"], m["services"], m["accounts"]), (["chk-"], ["ec2"], ["011122223333"]))
        ci, chk = (mk("ec2:instance", n, name=n) for n in ("ci-bot", "chk-api"))
        for r in (ci, chk):                      # the account id written as a TOML integer still matches
            r.account = "011122223333"
        grouping.assign([ci, chk], cfg)
        self.assertEqual((chk.project, chk.project_source), ("checkout", "rule"))
        self.assertNotEqual(ci.project_source, "rule", "'ci-bot' must not match the prefix 'chk-' character by character")

    def test_the_cli_reports_config_errors_before_any_aws_call(self):
        bad = self.cfg('[thresholds]\nidle_cpu_avg = "5"\n')
        scan = tmp() / "scan-1-x.json"
        scan.write_text(json.dumps(scan_dict()))
        for argv in (["analyze", str(scan)], ["run", "--profile", "x"], ["demo"], ["suggest-projects", str(scan)]):
            with self.subTest(argv=argv[0]), mock.patch("analyzer.cli._do_scan", side_effect=AssertionError("must not scan")):
                with self.assertRaises(SystemExit) as cm, contextlib.redirect_stderr(io.StringIO()):
                    cli.main(argv + ["--config", str(bad), "--out-dir", str(tmp())])
                self.assertIn("config error", str(cm.exception))
                self.assertIn("idle_cpu_avg", str(cm.exception))
        with self.assertRaises(SystemExit) as cm, contextlib.redirect_stderr(io.StringIO()):
            cli.main(["analyze", str(scan), "--config", str(tmp() / "missing.toml")])
        self.assertIn("config file not found", str(cm.exception))

    def test_shipped_example_still_loads(self):
        cfg = load_config(Path(__file__).resolve().parent.parent / "config" / "analyzer.example.toml")
        self.assertEqual(cfg["rules"][1]["match"]["name_prefix"], ["checkout-", "chk-"])


# --------------------------------------------------------------------------- VIEWER-3 / VIEWER-4


def strict_loads(text: str):
    def reject(c):
        raise ValueError(f"non-standard JSON constant {c}")
    return json.loads(text, parse_constant=reject)


def data_block(html: str) -> str:
    return re.search(r'<script id="aws-data" type="application/json">(.*?)</script>', html, flags=re.S).group(1)


class TestReportJson(unittest.TestCase):
    def test_nan_and_infinity_become_null(self):
        data = {"resources": [], "v": float("nan"), "nested": [{"w": float("inf"), "x": -float("inf"), "ok": 1.5}]}
        parsed = strict_loads(report._embed_json(data))
        self.assertEqual(parsed, {"resources": [], "v": None, "nested": [{"w": None, "x": None, "ok": 1.5}]})
        parsed = strict_loads(data_block(report.build_html(data)))   # what the browser's JSON.parse sees
        self.assertIsNone(parsed["v"])

    def test_lone_surrogates_are_escaped_not_fatal(self):
        data = {"resources": [{"name": "a\ud800b", "pair": "😀", "emoji": "😀", "ü": "é"}]}
        html = report.build_html(data)
        html.encode("utf-8")                                         # used to raise UnicodeEncodeError
        self.assertEqual(json.loads(data_block(html)), data)        # and it still round-trips exactly
        self.assertIn("😀", data_block(html), "valid non-ASCII text stays readable")

    def test_a_bad_value_never_destroys_an_existing_report(self):
        out = tmp() / "report.html"
        report.write_report({"resources": []}, out)
        report.write_report({"resources": [{"name": "\ud800"}], "x": float("nan")}, out)
        self.assertEqual(strict_loads(data_block(out.read_text()))["resources"][0]["name"], "\ud800")

    def test_the_analysis_file_is_strict_json(self):
        src, out = tmp(), tmp()
        scan = src / "scan-1-x.json"
        scan.write_text(json.dumps(scan_dict()))
        real = analyze

        def with_nan(*a, **kw):
            res = real(*a, **kw)
            res["summary"]["odd"] = float("nan")
            return res
        with mock.patch("analyzer.analysis.engine.analyze", side_effect=with_nan):
            run_cli(["analyze", str(scan), "--out-dir", str(out)])
        self.assertIsNone(strict_loads((out / "analysis-1-x.json").read_text())["summary"]["odd"])

    def test_csp_enforces_trusted_types(self):
        html = report.build_html(None)
        csp = re.search(r'<meta http-equiv="Content-Security-Policy" content="([^"]+)">', html).group(1)
        directives = dict(d.strip().split(" ", 1) for d in csp.split(";"))
        self.assertEqual(directives["require-trusted-types-for"], "'script'")
        self.assertEqual(directives["trusted-types"], "'none'", "no policy may be created: no HTML sink is ever needed")

    def test_viewer_code_uses_no_html_or_script_sinks(self):
        sinks = re.compile(r"\.(?:innerHTML|outerHTML)\s*=|insertAdjacentHTML|document\.write|createContextualFragment"
                           r"|parseFromString|srcdoc|\bnew\s+Function\b|\beval\s*\(|setAttribute\(\s*['\"]on")
        for js in sorted((report.VIEWER / "js").glob("*.js")):
            self.assertIsNone(sinks.search(js.read_text()), f"{js.name}: Trusted Types would block this sink")


# --------------------------------------------------------------------------- SECRETS-6


class TestCredentialsInFreeText(unittest.TestCase):
    def test_key_ids_and_their_secret_are_masked_in_names_tags_and_descriptions(self):
        rid = "sg-0abc"
        r = Resource(key=make_key(ACCT, "us-east-1", "ec2:security-group", rid), rid=rid, type="ec2:security-group",
                     service="ec2", account=ACCT, region="us-east-1", arn=f"arn:aws:ec2:us-east-1:{ACCT}:security-group/{rid}",
                     name=f"deploy_{KEY_ID}",
                     tags={"deploy-key": f"{KEY_ID}:{SECRET}", f"old_{KEY_ID}_x": "v", "Project": "shop"},
                     attrs={"description": f"temp creds {KEY_ID} {SECRET}", "vpc": "vpc-1"})
        blob = json.dumps(asdict(r))
        self.assertNotIn(KEY_ID, blob)
        self.assertNotIn(SECRET, blob)
        self.assertEqual(r.name, "deploy_AKIA…MPLE")
        self.assertEqual(r.tags["deploy-key"], "AKIA…MPLE:…redacted…")
        self.assertEqual((r.rid, r.tags["Project"], r.attrs["vpc"]), (rid, "shop", "vpc-1"), "ids and ordinary text are untouched")
        again = Resource(**asdict(r))                       # analyze rebuilds resources from the scan: idempotent
        self.assertEqual(asdict(again), asdict(r))

    def test_text_without_a_key_id_is_left_alone(self):
        cdk_like = "MyStackMyFunctionServiceRole1A2B3C4D5E6F"   # 40 characters, but no key id anywhere
        self.assertEqual(len(cdk_like), 40)
        r = mk("lambda:function", "f", name=cdk_like, tags={"note": cdk_like})
        self.assertEqual((r.name, r.tags["note"]), (cdk_like, cdk_like))
        self.assertEqual(mask_secrets("ASIAABCDEFGHIJKLMNOP and x_AKIAABCDEFGHIJKLMNOP"), "ASIA…MNOP and x_AKIA…MNOP")

    def test_nothing_reaches_scan_analysis_or_report(self):
        f = FakeAws()
        f.set("sts", "get-caller-identity", {"Account": ACCT, "Arn": f"arn:aws:iam::{ACCT}:user/x"})
        f.set("ec2", "describe-security-groups", {"SecurityGroups": [{
            "GroupId": "sg-1", "GroupName": "web", "VpcId": "vpc-1", "Description": f"rotated key {KEY_ID}",
            "Tags": [{"Key": "Name", "Value": f"web {KEY_ID}"}, {"Key": "deploy", "Value": f"{KEY_ID}:{SECRET}"}]}]})
        scan = run_scan(["t"], ScanOptions(quiet=True, regions=["us-east-1"], metrics=False, services=["ec2_net"]),
                        cli=AwsCli("t", executor=f, aws_bin="aws", sleep=lambda s: None))
        analysis = analyze(json.loads(json.dumps(scan)), load_config())
        for name, blob in (("scan", json.dumps(scan)), ("analysis", json.dumps(analysis)), ("html", report.build_html(analysis))):
            for secret in (KEY_ID, SECRET):
                self.assertNotIn(secret, blob, f"{secret!r} leaked into the {name}")
        sg = next(r for r in scan["resources"] if r["type"] == "ec2:security-group")
        self.assertEqual((sg["rid"], sg["name"], sg["attrs"]["description"]), ("sg-1", "web AKIA…MPLE", "rotated key AKIA…MPLE"))


if __name__ == "__main__":
    unittest.main()
