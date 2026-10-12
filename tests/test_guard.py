"""The read-only guarantee: the guard must block every write before a process starts."""

import json
import os
import unittest
from unittest import mock

from analyzer import allowlist
from analyzer.awscli import (
    AccessDenied, AuthError, AwsCli, AwsCliError, NotAvailable, ReadOnlyViolation,
    Throttled, check_command, classify_error,
)

WRITE_CALLS = [
    ("ec2", "delete-volume"), ("ec2", "release-address"), ("ec2", "run-instances"),
    ("ec2", "terminate-instances"), ("ec2", "stop-instances"), ("ec2", "create-tags"),
    ("ec2", "modify-instance-attribute"), ("ec2", "delete-snapshot"),
    ("ec2", "allocate-address"), ("ec2", "associate-address"), ("ec2", "delete-nat-gateway"),
    ("ec2", "authorize-security-group-ingress"), ("ec2", "deregister-image"),
    ("s3", "rm"), ("s3", "cp"), ("s3", "sync"), ("s3api", "put-object"),
    ("s3api", "delete-bucket"), ("s3api", "put-bucket-policy"),
    ("iam", "create-user"), ("iam", "delete-access-key"), ("iam", "attach-user-policy"),
    ("lambda", "invoke"), ("lambda", "delete-function"), ("sts", "assume-role"),
    ("rds", "delete-db-instance"), ("rds", "stop-db-instance"),
    ("dynamodb", "put-item"), ("dynamodb", "delete-table"), ("dynamodb", "scan"),
    ("sqs", "purge-queue"), ("sqs", "receive-message"), ("sns", "publish"),
    ("cloudformation", "delete-stack"), ("ecs", "update-service"), ("eks", "delete-cluster"),
    ("route53", "change-resource-record-sets"), ("kms", "decrypt"), ("kms", "schedule-key-deletion"),
    ("logs", "delete-log-group"), ("logs", "put-retention-policy"),
    ("configure", "set"), ("sso", "login"),
]

SENSITIVE_READS = [
    ("ecr", "get-authorization-token"), ("ecr", "get-login-password"),
    ("secretsmanager", "get-secret-value"), ("ssm", "get-parameter"),
    ("ssm", "get-parameters-by-path"), ("sts", "get-session-token"),
    ("sts", "get-federation-token"), ("lambda", "get-function"),
    ("s3api", "get-object"), ("s3api", "list-objects-v2"),
    ("iam", "get-credential-report"), ("ec2", "get-password-data"),
    ("ec2", "get-console-output"), ("ec2", "describe-instance-attribute"),
    ("dynamodb", "get-item"), ("dynamodb", "query"),
]


class TestGuard(unittest.TestCase):
    def test_every_allowlisted_op_passes_the_guard(self):
        for o in allowlist.OPERATIONS:
            with self.subTest(op=f"{o.service} {o.op}"):
                check_command(o.service, o.op)

    def test_every_allowlisted_op_is_a_read_verb(self):
        for o in allowlist.OPERATIONS:
            self.assertRegex(o.op, allowlist.READ_VERB, f"{o.service} {o.op}")

    def test_no_duplicate_entries(self):
        keys = [(o.service, o.op) for o in allowlist.OPERATIONS]
        self.assertEqual(len(keys), len(set(keys)))

    def test_write_calls_rejected(self):
        for svc, op in WRITE_CALLS:
            with self.subTest(call=f"{svc} {op}"):
                with self.assertRaises(ReadOnlyViolation):
                    check_command(svc, op)

    def test_sensitive_or_unlisted_reads_rejected(self):
        for svc, op in SENSITIVE_READS:
            with self.subTest(call=f"{svc} {op}"):
                with self.assertRaises(ReadOnlyViolation):
                    check_command(svc, op)

    def test_forbidden_flags_rejected(self):
        for flag in (["--endpoint-url", "http://evil"], ["--endpoint-url=http://evil"],
                     ["--profile", "x"], ["--region=eu-west-1"], ["--debug"],
                     ["--cli-input-json", "file://x"], ["--no-sign-request"], ["--output", "text"]):
            with self.subTest(flag=flag):
                with self.assertRaises(ReadOnlyViolation):
                    check_command("ec2", "describe-instances", flag)

    def test_flag_abbreviations_and_local_file_values_are_rejected(self):
        """The AWS CLI's argparse accepts unambiguous prefixes (--endpoint == --endpoint-url) and expands file:// values."""
        for args in (["--endpoint", "http://evil"], ["--endpoint=http://evil"], ["--end", "x"], ["--deb"], ["--no-sign"], ["--cli-input-j", "x"],
                     ["--ca", "/tmp/x"], ["--no-verify"], ["--cli-auto-prompt"], ["--filters", "file:///etc/passwd"], ["--query", "fileb:///tmp/x"],
                     ["--bucket", "FILE://x"]):
            with self.subTest(args=args):
                with self.assertRaises(ReadOnlyViolation):
                    check_command("ec2", "describe-instances", args)

    def test_legitimate_collector_flags_are_not_mistaken_for_abbreviations(self):
        for flags in (["--max-items", "1"], ["--owners", "self", "--include-disabled"], ["--owner-ids", "self"], ["--snapshot-type", "manual"],
                      ["--queue-url", "https://sqs.us-east-1.amazonaws.com/1/q"], ["--end-time", "x", "--start-time", "y"],
                      ["--query", "a.b"], ["--time-period", "Start=a,End=b"], ["--service", "AmazonEC2"], ["--include", "TAGS"], ["--output"][:0]):
            with self.subTest(flags=flags):
                check_command("ec2", "describe-instances", flags)

    def test_normal_flags_allowed(self):
        check_command("ec2", "describe-snapshots", ["--owner-ids", "self", "--max-items", "10"])
        check_command("ec2", "describe-instances", ["--filters", "Name=tag:Project,Values=x"])

    def test_malformed_names_rejected(self):
        for svc, op in [("ec2; rm -rf /", "describe-instances"), ("ec2", "describe-instances; id"),
                        ("EC2", "describe-instances"), ("ec2", "Describe"), ("", ""), ("ec2", "$(id)")]:
            with self.subTest(call=(svc, op)):
                with self.assertRaises(ReadOnlyViolation):
                    check_command(svc, op)

    def test_non_string_and_nul_args_rejected(self):
        with self.assertRaises(ReadOnlyViolation):
            check_command("ec2", "describe-instances", [1])  # type: ignore[list-item]
        with self.assertRaises(ReadOnlyViolation):
            check_command("ec2", "describe-instances", ["a\x00b"])


class FakeExec:
    """Scripted executor: returns the next (rc, out, err) and records argv/env."""

    def __init__(self, *results):
        self.results = list(results)
        self.calls = []

    def __call__(self, argv, env, timeout):
        self.calls.append((argv, env))
        return self.results.pop(0) if self.results else (0, "{}", "")


def err(code, op="DescribeInstances", msg="boom"):
    return (254, "", f"\nAn error occurred ({code}) when calling the {op} operation: {msg}\n")


class TestAwsCli(unittest.TestCase):
    def make(self, *results, **kw):
        ex = FakeExec(*results)
        return AwsCli("p", executor=ex, aws_bin="/usr/bin/aws", sleep=lambda s: None, **kw), ex

    def test_violation_happens_before_any_process(self):
        cli, ex = self.make()
        with self.assertRaises(ReadOnlyViolation):
            cli.call("ec2", "delete-volume", ["--volume-id", "vol-1"], region="us-east-1")
        self.assertEqual(ex.calls, [])

    def test_ok_call_builds_argv_without_shell_and_logs(self):
        cli, ex = self.make((0, json.dumps({"Reservations": []}), ""))
        data = cli.call("ec2", "describe-instances", ["--max-items", "5"], region="eu-west-1")
        self.assertEqual(data, {"Reservations": []})
        argv, env = ex.calls[0]
        self.assertEqual(argv[:3], ["/usr/bin/aws", "ec2", "describe-instances"])
        self.assertIn("--no-cli-pager", argv)
        self.assertIn("--region=eu-west-1", argv)          # the analyzer's own values are glued to their flag too
        self.assertIn("--profile=p", argv)
        self.assertEqual(env["AWS_PAGER"], "")
        log = cli.audit_log()
        self.assertEqual((log[0]["service"], log[0]["op"], log[0]["status"]), ("ec2", "describe-instances", "ok"))

    def test_environment_cannot_redirect_endpoint(self):
        with mock.patch.dict(os.environ, {"AWS_ENDPOINT_URL": "http://evil", "AWS_ENDPOINT_URL_S3": "http://evil"}):
            cli, ex = self.make((0, "{}", ""))
            cli.call("ec2", "describe-regions", region="us-east-1")
        env = ex.calls[0][1]
        self.assertNotIn("AWS_ENDPOINT_URL", env)
        self.assertNotIn("AWS_ENDPOINT_URL_S3", env)

    def test_dry_run_runs_nothing(self):
        cli, ex = self.make(dry_run=True)
        self.assertEqual(cli.call("ec2", "describe-instances", region="us-east-1"), {})
        self.assertEqual(ex.calls, [])
        self.assertEqual(cli.audit_log()[0]["status"], "planned")

    def test_access_denied_raises_and_is_logged(self):
        cli, _ = self.make(err("UnauthorizedOperation"))
        with self.assertRaises(AccessDenied):
            cli.call("ec2", "describe-instances", region="us-east-1")
        self.assertEqual(cli.audit_log()[0]["status"], "denied")

    def test_expected_error_returns_default(self):
        cli, _ = self.make(err("NoSuchLifecycleConfiguration", "GetBucketLifecycleConfiguration"))
        out = cli.call("s3api", "get-bucket-lifecycle-configuration", ["--bucket", "b"],
                       region="us-east-1", expect=["NoSuchLifecycleConfiguration"], default="NONE")
        self.assertEqual(out, "NONE")
        self.assertEqual(cli.audit_log()[0]["status"], "empty")

    def test_throttling_is_retried_then_succeeds(self):
        cli, ex = self.make(err("Throttling"), err("RequestLimitExceeded"), (0, '{"ok":1}', ""))
        self.assertEqual(cli.call("ec2", "describe-instances", region="us-east-1"), {"ok": 1})
        self.assertEqual(len(ex.calls), 3)

    def test_throttling_gives_up(self):
        cli, ex = self.make(*[err("Throttling")] * 10, throttle_retries=2)
        with self.assertRaises(Throttled):
            cli.call("ec2", "describe-instances", region="us-east-1")
        self.assertEqual(len(ex.calls), 3)

    def test_error_classification(self):
        self.assertIsInstance(classify_error(err("OptInRequired")[2]), NotAvailable)
        self.assertIsInstance(classify_error(err("ExpiredToken")[2]), AuthError)
        self.assertIsInstance(classify_error("Unable to locate credentials. You can configure credentials by running"), AuthError)
        self.assertIsInstance(classify_error("The SSO session associated with this profile has expired"), AuthError)
        self.assertIsInstance(classify_error("Something odd"), AwsCliError)

    def test_bad_json_is_an_error(self):
        cli, _ = self.make((0, "not json", ""))
        with self.assertRaises(AwsCliError):
            cli.call("ec2", "describe-instances", region="us-east-1")

    def test_with_profile_shares_audit_log(self):
        cli, ex = self.make((0, "{}", ""), (0, "{}", ""))
        other = cli.with_profile("q")
        cli.call("ec2", "describe-regions", region="us-east-1")
        other.call("ec2", "describe-regions", region="us-east-1")
        self.assertEqual([r["profile"] for r in cli.audit_log()], ["p", "q"])


if __name__ == "__main__":
    unittest.main()
