"""Security audit fixes for the guard (awscli.py) and the collectors that feed it.

CODE-1 / SECRETS-3 / READONLY-3  resource names that look like flags cannot abort the scan or become flags
SECRETS-1 / CODE-3 / READONLY-2  file:// in --flag=value form and in shorthand Key@=file://... is refused
READONLY-1                       every abbreviation of a reserved flag is refused (also --e, --d, --p ...)
CODE-2 / READONLY-8              the aws process ignores endpoint/CA/model overrides and gets no stdin
READONLY-4                       the executor re-checks the argv itself (nothing can bypass AwsCli.call)
READONLY-7                       --query projections keep secret fields out of the process
CODE-8                           the aws binary is resolved once, verified (v2, not planted) and recorded

Nothing here runs the real aws binary: subprocess.run is mocked wherever the real executor is exercised.
"""

import contextlib
import json
import os
import re
import shutil
import subprocess  # tests only: the real executor is exercised with subprocess.run mocked
import sys
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path
from unittest import mock

import analyzer.awscli as aw
from analyzer import allowlist
from analyzer.collectors import containers, dynamodb, edge, iam, s3, serverless
from analyzer.fakeaws import FakeAws, arg_value
from analyzer.scan import Ctx, ScanOptions, run_scan

ACCT = "111122223333"
ROOT = Path(__file__).resolve().parent.parent


def cli_for(fake, **kw):
    return aw.AwsCli("t", executor=fake, aws_bin="aws", sleep=lambda s: None, **kw)


def base_fake():
    f = FakeAws()
    f.set("sts", "get-caller-identity", {"Account": ACCT, "Arn": f"arn:aws:iam::{ACCT}:user/x"})
    f.set("ec2", "describe-regions", {"Regions": [{"RegionName": "eu-west-1"}]})
    return f


def refused(service, op, args):
    """'ok', 'value' (UnsafeArgument) or 'fatal' (any other ReadOnlyViolation)."""
    try:
        aw.check_command(service, op, args)
    except aw.ReadOnlyViolation as e:
        return "value" if isinstance(e, getattr(aw, "UnsafeArgument", ())) else "fatal"
    return "ok"


# --------------------------------------------------------------------------- CODE-1 / SECRETS-3 / READONLY-3


class TestFlagLikeResourceNames(unittest.TestCase):
    TABLES = ["orders", "--debug", "--profile", "--re", "--d", "--shadow-db", "--", "--endpoint-url=https://x"]

    def fake(self):
        f = base_fake()
        f.set("dynamodb", "list-tables", {"TableNames": self.TABLES})
        f.set("dynamodb", "describe-table", lambda reg, a: {"Table": {
            "TableName": arg_value(a, "--table-name"), "TableStatus": "ACTIVE",
            "TableArn": f"arn:aws:dynamodb:eu-west-1:{ACCT}:table/x"}})
        f.set("iam", "list-users", {"Users": [{"UserName": "--profile", "Arn": "arn:u1"}, {"UserName": "--", "Arn": "arn:u2"}]})
        f.set("iam", "list-access-keys", lambda reg, a: {"AccessKeyMetadata": [
            {"AccessKeyId": "AKIA" + ("1" if arg_value(a, "--user-name") == "--profile" else "2") * 16, "Status": "Active"}]})
        f.set("iam", "list-roles", {"Roles": [{"RoleName": "--region", "Path": "/", "Arn": "arn:r"}]})
        f.set("iam", "get-role", lambda reg, a: {"Role": {"RoleName": arg_value(a, "--role-name"), "Path": "/", "Arn": "arn:r"}})
        return f

    def test_scan_completes_and_every_name_stays_a_value(self):
        f = self.fake()
        scan = run_scan(["p"], ScanOptions(quiet=True, metrics=False, services=["dynamodb", "iam"], regions=["eu-west-1"]),
                        cli=cli_for(f))
        tables = sorted(r["name"] for r in scan["resources"] if r["type"] == "dynamodb:table")
        self.assertEqual(tables, sorted(self.TABLES))
        users = {r["name"]: r["attrs"]["access_keys"] for r in scan["resources"] if r["type"] == "iam:user"}
        self.assertEqual(set(users), {"--profile", "--"})
        self.assertTrue(all(len(k) == 1 for k in users.values()), "each user's access keys were listed")
        self.assertEqual([r["name"] for r in scan["resources"] if r["type"] == "iam:role"], ["--region"])
        self.assertEqual(scan["gaps"], [])
        # the value is glued to its flag: argparse can never read it as an option
        for _s, op, _r, args in f.calls:
            if op == "describe-table":
                self.assertEqual(len(args), 1)
                self.assertTrue(args[0].startswith("--table-name="), args)

    def test_unsafe_value_from_aws_is_a_gap_not_an_abort(self):
        f = self.fake()
        f.set("dynamodb", "list-tables", {"TableNames": ["orders", "file:///Users/me/.aws/credentials"]})
        f.set("s3api", "list-buckets", {"Buckets": [{"Name": "odd", "BucketRegion": "--debug"}]})
        cli = cli_for(f)
        scan = run_scan(["p"], ScanOptions(quiet=True, metrics=False, services=["dynamodb", "s3"], regions=["eu-west-1"]), cli=cli)
        self.assertEqual([r["name"] for r in scan["resources"] if r["type"] == "dynamodb:table"], ["orders"])
        gaps = {(g["service"], g["op"]): g for g in scan["gaps"]}
        self.assertEqual(gaps[("dynamodb", "describe-table")]["code"], "UnsafeArgument")
        self.assertEqual(gaps[("s3api", "get-bucket-versioning")]["code"], "UnsafeArgument")   # region from data
        # refused before any process: the fake never saw it, the audit log shows it
        self.assertFalse([a for _s, op, _r, a in f.calls if op == "describe-table" and "file://" in " ".join(a)])
        self.assertIn("refused", {c["status"] for c in scan["audit"]})

    def test_code_level_violations_stay_fatal(self):
        ctx = Ctx(cli_for(self.fake()), ACCT, "eu-west-1")
        for op, args in (("delete-table", ["--table-name=x"]), ("list-tables", ["--endpoint-url=https://x"]), ("list-tables", ["--e"])):
            with self.subTest(op=op, args=args):
                with self.assertRaises(aw.ReadOnlyViolation) as cm:
                    ctx.aws("dynamodb", op, args)
                self.assertNotIsInstance(cm.exception, getattr(aw, "UnsafeArgument", ()))
        self.assertEqual(ctx.gaps, [])


# --------------------------------------------------------------------------- SECRETS-1 / CODE-3 / READONLY-2


class TestLocalFileValues(unittest.TestCase):
    def test_file_values_after_equals_are_refused(self):
        for args in (["--table-name=file:///etc/hosts"], ["--table-name=FILEB:///x"], ["--filters=file:///etc/passwd"],
                     ["--query=fileb://x"], ["--table-name= file://~/.aws/credentials"], ["--attribute-names=fileb://~/.ssh/id_rsa"]):
            with self.subTest(args=args):
                self.assertEqual(refused("dynamodb", "describe-table", args), "value")

    def test_shorthand_key_loaded_from_file_is_refused(self):
        """AWS CLI v2 shorthand: Key@=file://path loads that one value from a local file."""
        for args in (["--filters", "Name@=file:///etc/passwd"], ["--filters=Name=tag:x,Values@=fileb://~/.aws/credentials"],
                     ["--filters", "Name=x,Values@ = file://y"]):
            with self.subTest(args=args):
                self.assertEqual(refused("ec2", "describe-instances", args), "value")

    def test_ordinary_values_with_at_or_file_words_pass(self):
        for args in (["--filters", "Name=tag:owner,Values=me@example.com"], ["--table-name=file-index"],
                     ["--metric-data-queries", '[{"Id":"m0","Label":"@=file://x"}]'],   # JSON: no shorthand file loading
                     ["--user-name=a=b"], ["--role-name=x@y"]):
            with self.subTest(args=args):
                self.assertEqual(refused("ec2", "describe-instances", args), "ok")

    def test_hook_blocks_the_equals_forms(self):
        sys.path.insert(0, str(ROOT / "hooks"))
        try:
            import block_aws_writes as hook
        finally:
            sys.path.remove(str(ROOT / "hooks"))
        for cmd in ("aws dynamodb describe-table --table-name=file:///Users/me/.aws/credentials",
                    "aws sqs get-queue-attributes --queue-url https://sqs.x/1/q --attribute-names=fileb:///Users/me/.ssh/id_rsa",
                    "aws ec2 describe-instances --filters=file://~/.aws/credentials",
                    "aws dynamodb list-tables --e https://attacker.example"):
            with self.subTest(cmd=cmd):
                self.assertTrue(hook.violations(cmd), cmd)


# --------------------------------------------------------------------------- READONLY-1


class TestFlagAbbreviations(unittest.TestCase):
    def test_short_abbreviations_are_refused(self):
        for args in (["--e", "https://attacker.example"], ["--e=https://attacker.example"], ["--d"], ["--p", "other"],
                     ["--r", "eu-west-1"], ["--o", "text"], ["--v"], ["--no", "x"], ["--c"], ["--"], ["--=x"]):
            with self.subTest(args=args):
                self.assertEqual(refused("dynamodb", "list-tables", args), "fatal")

    def test_every_prefix_of_every_reserved_flag_is_refused(self):
        for flag in sorted(allowlist.FORBIDDEN_FLAGS):
            for n in range(3, len(flag) + 1):
                with self.subTest(prefix=flag[:n]):
                    self.assertEqual(refused("dynamodb", "list-tables", [flag[:n]]), "fatal")
                    self.assertEqual(refused("dynamodb", "list-tables", [flag[:n] + "=x"]), "fatal")

    def test_every_flag_the_code_passes_is_accepted(self):
        """No literal flag a collector, metrics or Cost Explorer uses may be mistaken for a reserved one."""
        files = [*(ROOT / "analyzer" / "collectors").glob("*.py"), ROOT / "analyzer" / "metrics.py",
                 ROOT / "analyzer" / "costexplorer.py"]
        flags = {"--max-items"}                                      # doctor's probes (cli.py)
        for p in files:
            flags |= set(re.findall(r"""["'](--[a-z][a-z0-9-]*)[="']""", p.read_text()))
        self.assertGreater(len(flags), 20)
        for f in sorted(flags):
            with self.subTest(flag=f):
                self.assertEqual(refused("ec2", "describe-instances", [f, "x"]), "ok")
                self.assertEqual(refused("ec2", "describe-instances", [f + "=x"]), "ok")

    def test_global_option_table_matches_the_installed_cli(self):
        """A new global option in a newer AWS CLI must be classified (forbidden or safe) here first."""
        found = shutil.which("aws")
        data = Path(os.path.realpath(found)).parent / "awscli" / "data" / "cli.json" if found else None
        if not data or not data.is_file():
            self.skipTest("AWS CLI v2 data files not found")
        options = {"--" + k for k in json.loads(data.read_text())["options"]} | {"--version"}
        self.assertEqual(options, allowlist.CLI_GLOBAL_FLAGS)
        self.assertEqual(allowlist.CLI_GLOBAL_FLAGS - allowlist.SAFE_GLOBAL_FLAGS, allowlist.FORBIDDEN_FLAGS & allowlist.CLI_GLOBAL_FLAGS)


# --------------------------------------------------------------------------- CODE-2 / READONLY-8


class TestEnvironment(unittest.TestCase):
    HOSTILE = {"AWS_ENDPOINT_URL": "https://evil", "AWS_ENDPOINT_URL_EC2": "https://evil", "AWS_CA_BUNDLE": "/tmp/evil-ca.pem",
               "AWS_DATA_PATH": "/tmp/models", "AWS_CLI_AUTO_PROMPT": "on", "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS": "false",
               "AWS_PROFILE": "other", "AWS_CONFIG_FILE": "/tmp/attacker-config"}

    def test_clean_env_ignores_endpoint_ca_and_model_overrides(self):
        with mock.patch.dict(os.environ, self.HOSTILE):
            env = aw._clean_env()
        for k in ("AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_EC2", "AWS_CA_BUNDLE", "AWS_DATA_PATH", "AWS_PROFILE"):
            self.assertNotIn(k, env)
        self.assertEqual(env["AWS_IGNORE_CONFIGURED_ENDPOINT_URLS"], "true")   # also endpoint_url in any config file
        self.assertEqual(env["AWS_CLI_AUTO_PROMPT"], "off")

    def test_process_gets_no_stdin(self):
        run = mock.Mock(return_value=subprocess.CompletedProcess([], 0, "{}", ""))
        exe = "/opt/test-bin/aws"
        aw._TRUSTED_BINS.add(exe)
        self.addCleanup(aw._TRUSTED_BINS.discard, exe)
        with mock.patch.object(aw.subprocess, "run", run):
            aw._subprocess_executor(aw._build_argv(exe, "ec2", "describe-regions", [], "us-east-1", "p"), {}, 5)
        self.assertIs(run.call_args.kwargs["stdin"], subprocess.DEVNULL)
        self.assertFalse(run.call_args.kwargs["shell"])

    def test_unanswerable_mfa_prompt_is_an_auth_error(self):
        err = aw.classify_error("Enter MFA code for arn:aws:iam::111122223333:mfa/me: \nEOF when reading a line\n")
        self.assertIsInstance(err, aw.AuthError)


# --------------------------------------------------------------------------- READONLY-4


class TestExecutorRecheck(unittest.TestCase):
    EXE = "/opt/test-bin/aws"

    def setUp(self):
        aw._TRUSTED_BINS.add(self.EXE)
        self.addCleanup(aw._TRUSTED_BINS.discard, self.EXE)
        self.run = mock.Mock(return_value=subprocess.CompletedProcess([], 0, "{}", ""))
        patcher = mock.patch.object(aw.subprocess, "run", self.run)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_direct_executor_use_cannot_run_writes_or_other_programs(self):
        own = list(aw._OWN_FLAGS)
        for argv in ([self.EXE, "ec2", "terminate-instances", "--instance-ids", "i-1", *own],
                     [self.EXE, "ec2", "describe-instances", "--endpoint-url=https://x", *own],
                     [self.EXE, "ec2", "describe-instances", *own, "--endpoint-url=https://x"],
                     [self.EXE, "ec2", "describe-instances", *own, "--region=--debug"],
                     [self.EXE, "ec2", "describe-instances"],                   # without the analyzer's own flags
                     [self.EXE, "configure", "set", "region", "x"],
                     ["/bin/sh", "-c", "id"], ["/usr/local/bin/aws", "ec2", "describe-instances", *own],   # not the verified binary
                     ["aws", "--version"], "aws ec2 describe-instances"):
            with self.subTest(argv=argv), self.assertRaises(aw.ReadOnlyViolation):
                aw._subprocess_executor(argv, {}, 5)
        self.run.assert_not_called()

    def test_default_executor_of_awscli_is_guarded(self):
        cli = aw.AwsCli("p")
        with self.assertRaises(aw.ReadOnlyViolation):
            cli._executor([self.EXE, "ec2", "terminate-instances", "--instance-ids", "i-1", *aw._OWN_FLAGS], {}, 5)
        self.run.assert_not_called()

    def test_everything_awscli_builds_is_accepted(self):
        for o in allowlist.OPERATIONS:
            args = ["--max-items", "1", *(["--query", "x"] if (o.service, o.op) in allowlist.QUERY_REQUIRED else [])]
            for region, profile in ((None, None), ("eu-west-1", "prod"), ("us-gov-west-1", "my profile")):
                aw._recheck_argv(aw._build_argv(self.EXE, o.service, o.op, args, region, profile))
        for local in (["--version"], ["configure", "list-profiles"]):
            aw._recheck_argv([self.EXE, *local])


# --------------------------------------------------------------------------- READONLY-7


class MiniJmes:
    """The JMESPath subset our --query strings use: identifiers, a.b, a[] (flatten projection), {k: expr, ...}."""

    _ID = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

    def __init__(self, text):
        self.s, self.i = text, 0
        self.tree = self._chain()
        assert self.i == len(self.s), f"unparsed: {self.s[self.i:]!r}"

    def _chain(self):
        steps = [self._atom()]
        while self.i < len(self.s) and self.s[self.i] in ".[":
            if self.s.startswith("[]", self.i):
                self.i += 2
                steps.append(("flatten",))
            else:
                self.i += 1
                steps.append(self._atom())
        return ("chain", steps)

    def _atom(self):
        if self.s[self.i] == "{":
            self.i += 1
            items = []
            while True:
                m = self._ID.match(self.s, self.i)
                assert m and self.s[m.end()] == ":", self.s[self.i:]
                self.i = m.end() + 1
                items.append((m.group(0), self._chain()))
                if self.s[self.i] == ",":
                    self.i += 1
                    continue
                assert self.s[self.i] == "}", self.s[self.i:]
                self.i += 1
                return ("hash", items)
        m = self._ID.match(self.s, self.i)
        assert m, self.s[self.i:]
        self.i = m.end()
        return ("field", m.group(0))

    def search(self, data):
        return self._eval(self.tree, data)

    def _eval(self, node, data):
        if node[0] == "field":
            return data.get(node[1]) if isinstance(data, dict) else None
        if node[0] == "hash":
            return None if data is None else {k: self._eval(v, data) for k, v in node[1]}
        return self._steps(node[1], data)

    def _steps(self, steps, cur):
        for n, st in enumerate(steps):
            if st[0] == "flatten":
                if not isinstance(cur, list):
                    return None
                flat = [y for x in cur for y in (x if isinstance(x, list) else [x])]
                rest = steps[n + 1:]
                return flat if not rest else [v for v in (self._steps(rest, x) for x in flat) if v is not None]
            cur = self._eval(st, cur)
        return cur


SECRET = "s3cr3t-must-never-reach-python"
RAW = {
    ("cloudfront", "list-distributions"): {"DistributionList": {"Marker": "", "MaxItems": 100, "IsTruncated": False, "Quantity": 2, "Items": [
        {"Id": "E1", "ARN": f"arn:aws:cloudfront::{ACCT}:distribution/E1", "Status": "Deployed", "LastModifiedTime": "2025-01-01T00:00:00Z",
         "DomainName": "d1.cloudfront.net", "Aliases": {"Quantity": 1, "Items": ["www.example.com"]}, "Comment": "site", "Enabled": True,
         "PriceClass": "PriceClass_All", "HttpVersion": "http2",
         "Origins": {"Quantity": 1, "Items": [{"Id": "o1", "DomainName": "origin.example.com", "OriginPath": "",
                                               "CustomHeaders": {"Quantity": 1, "Items": [{"HeaderName": "X-Origin-Verify", "HeaderValue": SECRET}]},
                                               "CustomOriginConfig": {"HTTPPort": 80, "HTTPSPort": 443}}]},
         "DefaultCacheBehavior": {"TargetOriginId": "o1"}},
        {"Id": "E2", "DomainName": "d2.cloudfront.net", "Enabled": False, "Aliases": {"Quantity": 0}, "Origins": {"Quantity": 0}}]}},
    ("lambda", "list-functions"): {"Functions": [
        {"FunctionName": "fn", "FunctionArn": f"arn:aws:lambda:eu-west-1:{ACCT}:function:fn", "Runtime": "python3.12",
         "Role": f"arn:aws:iam::{ACCT}:role/fn-role", "Handler": "app.handler", "CodeSize": 1234, "Timeout": 30, "MemorySize": 512,
         "LastModified": "2025-01-01T00:00:00.000+0000", "PackageType": "Zip", "Architectures": ["arm64"],
         "EphemeralStorage": {"Size": 512}, "VpcConfig": {"VpcId": "vpc-1", "SubnetIds": ["subnet-1"], "SecurityGroupIds": ["sg-1"]},
         "Environment": {"Variables": {"DB_PASSWORD": SECRET}}, "TracingConfig": {"Mode": "PassThrough"}},
        {"FunctionName": "bare", "FunctionArn": f"arn:aws:lambda:eu-west-1:{ACCT}:function:bare", "Runtime": "nodejs20.x",
         "Environment": {"Variables": {"TOKEN": SECRET}}}]},
    ("eks", "list-clusters"): {"clusters": ["c1"]},
    ("eks", "describe-cluster"): {"cluster": {
        "name": "c1", "arn": f"arn:aws:eks:eu-west-1:{ACCT}:cluster/c1", "createdAt": "2025-01-01T00:00:00Z", "version": "1.31",
        "endpoint": "https://abc.eks.amazonaws.com", "roleArn": f"arn:aws:iam::{ACCT}:role/eks", "status": "ACTIVE",
        "resourcesVpcConfig": {"vpcId": "vpc-1", "subnetIds": ["subnet-1"]}, "identity": {"oidc": {"issuer": "https://oidc"}},
        "certificateAuthority": {"data": SECRET}, "tags": {"Project": "p"}, "upgradePolicy": {"supportType": "STANDARD"},
        "connectorConfig": {"activationId": "a", "activationCode": SECRET, "provider": "OTHER"}, "computeConfig": {"enabled": True}}},
}


class ProjectingFake(FakeAws):
    """Answers like the AWS CLI does: the --query is applied to the full answer; records what the process prints."""

    def __init__(self, responses):
        super().__init__({k: (lambda raw: lambda region, args: self._project(raw, args))(v) for k, v in responses.items()})
        self.outputs = []

    @staticmethod
    def _project(raw, args):
        q = arg_value(args, "--query")
        return MiniJmes(q).search(raw) if q else raw

    def __call__(self, argv, env, timeout):
        rc, out, err = super().__call__(argv, env, timeout)
        self.outputs.append(out)
        return rc, out, err


class TestSecretProjections(unittest.TestCase):
    CASES = [(edge, True, ("cloudfront", "list-distributions")), (serverless, False, ("lambda", "list-functions")),
             (containers, False, ("eks", "describe-cluster"))]

    def collect(self, module, is_global, fake):
        ctx = Ctx(cli_for(fake), ACCT, "us-east-1" if is_global else "eu-west-1", is_global=is_global)
        return [asdict(r) for r in module.collect(ctx)], ctx.gaps

    def test_secret_fields_never_reach_the_process(self):
        for module, is_global, op in self.CASES:
            with self.subTest(op=op):
                fake = ProjectingFake(RAW)
                self.collect(module, is_global, fake)
                queries = [arg_value(list(a), "--query") for s, o, _r, a in fake.calls if (s, o) == op]
                self.assertTrue(queries and all(queries), f"{op} must be called with a --query projection")
                printed = "".join(fake.outputs)
                self.assertNotIn(SECRET, printed)
                for word in ("Environment", "CustomHeaders", "HeaderValue", "connectorConfig", "activationCode", "certificateAuthority"):
                    self.assertNotIn(word, queries[0])

    def test_projection_keeps_everything_the_collector_reads(self):
        for module, is_global, op in self.CASES:
            with self.subTest(op=op):
                projected, gaps = self.collect(module, is_global, ProjectingFake(RAW))
                raw, _ = self.collect(module, is_global, FakeAws(dict(RAW)))   # FakeAws ignores --query: the full answer
                self.assertEqual(gaps, [])
                self.assertTrue(projected)
                self.assertEqual(projected, raw)

    def test_every_query_in_the_collectors_parses(self):
        """Also checks the evaluator against the shapes the demo stores for the older projections."""
        for q in (edge._DISTRIBUTIONS_QUERY, serverless._FUNCTIONS_QUERY, containers._EKS_CLUSTER_QUERY,
                  serverless._ESM_QUERY, containers._TASKDEF_QUERY, containers._IMAGES_QUERY):
            MiniJmes(q)
        rows = MiniJmes(serverless._ESM_QUERY).search({"EventSourceMappings": [
            {"EventSourceArn": "arn:sqs", "FunctionArn": "arn:fn", "State": "Enabled", "BatchSize": 10, "FilterCriteria": {"Filters": [{"Pattern": SECRET}]}}]})
        self.assertEqual(rows, [{"src": "arn:sqs", "fn": "arn:fn", "state": "Enabled", "batch": 10, "fail": None}])


# --------------------------------------------------------------------------- CODE-8


class TestAwsBinary(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.aws = self.tmp / "aws"
        self.aws.write_text("")            # never executed: subprocess.run is mocked
        self.run = mock.Mock(side_effect=self._answer)
        self.version = "aws-cli/2.33.17 Python/3.13.11 Darwin/25.3.0 exe/arm64"
        for p in (mock.patch.object(aw.subprocess, "run", self.run), mock.patch.dict(os.environ, {}, clear=False)):
            p.start()
            self.addCleanup(p.stop)
        os.environ.pop(aw.AWS_BIN_ENV, None)
        self.addCleanup(lambda: [aw._TRUSTED_BINS.discard(b) for b in list(aw._TRUSTED_BINS) if b.startswith(str(self.tmp))])

    def _answer(self, argv, **kw):
        if argv[1:] == ["--version"]:
            return subprocess.CompletedProcess(argv, 0, self.version + "\n", "")
        return subprocess.CompletedProcess(argv, 0, json.dumps({"Account": ACCT, "Arn": "arn:aws:iam::1:user/x"}), "")

    def which(self, path):
        return mock.patch.object(aw.shutil, "which", return_value=str(path))

    def resolve(self):
        return aw.resolve_aws_bin(aw._clean_env())

    def test_verified_binary_is_used_and_recorded(self):
        with self.which(self.aws):
            cli = aw.AwsCli("p")
            cli.call("sts", "get-caller-identity", region="us-east-1")
            info = cli.binary_info()
        self.assertTrue(info["verified"])
        self.assertEqual(info["version"], "aws-cli/2.33.17")
        self.assertEqual(info["path"], str(self.aws))
        self.assertEqual(self.run.call_count, 2, "version probe once, then the call")
        argv, kw = self.run.call_args.args[0], self.run.call_args.kwargs
        self.assertEqual(argv[0], str(self.aws))
        self.assertEqual(kw["env"]["AWS_IGNORE_CONFIGURED_ENDPOINT_URLS"], "true")
        self.assertIn("aws-cli/2.33.17", cli.cli_version())
        self.assertIn(str(self.aws), cli.cli_version())

    def test_aws_cli_v1_is_refused(self):
        self.version = "aws-cli/1.29.0 Python/3.11.4 Darwin/23.0.0 botocore/1.31.0"
        with self.which(self.aws), self.assertRaises(aw.AuthError) as cm:
            aw.AwsCli("p").call("sts", "get-caller-identity", region="us-east-1")
        self.assertEqual(cm.exception.code, "AwsCliRefused")
        self.assertIn("v1", str(cm.exception))
        self.assertEqual(self.run.call_count, 1, "only the version probe ran")

    def test_unreadable_version_is_refused(self):
        self.version = "something else"
        with self.which(self.aws), self.assertRaises(aw.AuthError):
            self.resolve()

    def test_planted_binaries_are_refused(self):
        for found in ("aws", "./aws", str(ROOT / "tools" / "aws"), str(ROOT / "aws")):
            with self.subTest(found=found), self.which(found), self.assertRaises(aw.AuthError) as cm:
                self.resolve()
            self.assertEqual(cm.exception.code, "AwsCliRefused")
        with contextlib.chdir(self.tmp), self.which(self.aws), self.assertRaises(aw.AuthError):
            self.resolve()                                        # an `aws` in the current directory
        self.run.assert_not_called()

    def test_pin_must_be_absolute(self):
        os.environ[aw.AWS_BIN_ENV] = "aws"
        with self.assertRaises(aw.AuthError):
            self.resolve()
        os.environ[aw.AWS_BIN_ENV] = str(self.aws)
        with self.which("/nonexistent/aws"):
            self.assertEqual(self.resolve()["path"], str(self.aws))

    def test_a_real_client_cannot_be_pointed_at_another_binary(self):
        with self.assertRaises(ValueError):
            aw.AwsCli("p", aws_bin="/tmp/evil/aws")

    def test_dry_run_starts_no_process(self):
        with self.which(self.aws):
            info = aw.AwsCli("p", dry_run=True).binary_info()
        self.assertFalse(info["verified"])
        self.run.assert_not_called()

    def test_scan_records_the_binary(self):
        scan = run_scan(["p"], ScanOptions(quiet=True, metrics=False, services=["dynamodb"], regions=["eu-west-1"]), cli=cli_for(base_fake()))
        self.assertIn("aws_cli", scan)
        self.assertIn("aws_cli", scan["options"])
        self.assertFalse(scan["aws_cli"]["verified"])               # an offline executor ran, not a binary


if __name__ == "__main__":
    unittest.main()
