"""The optional Claude Code hook must block aws writes and let reads and everything else through."""

import json
import os
import subprocess  # tests only: runs the hook script as Claude Code would (not part of the shipped package)
import sys
import tempfile
import unittest
from pathlib import Path

HOOK = Path(__file__).resolve().parent.parent / "hooks" / "block_aws_writes.py"
sys.path.insert(0, str(HOOK.parent))
import block_aws_writes as hook  # noqa: E402

# never read the real ~/.aws/cli/alias from the test suite (the subprocess runs get a temporary HOME)
hook._ALIAS_FILE = Path(__file__).resolve().parent / "no-such-dir" / "alias"

BLOCKED = [
    "aws ec2 delete-volume --volume-id vol-1",
    "aws --profile prod ec2 terminate-instances --instance-ids i-1",
    "aws s3 rm s3://bucket --recursive",
    "aws s3 sync . s3://bucket",
    "aws iam create-user --user-name x",
    "cd /tmp && aws ec2 release-address --allocation-id eipalloc-1",
    "echo hi; aws lambda invoke --function-name f out.json",
    "aws ec2 describe-instances | xargs aws ec2 stop-instances",
    "echo $(aws ssm get-parameter --name x --with-decryption)",
    "aws ecr get-login-password | docker login",
    "aws --region eu-west-1 --output json rds delete-db-instance --db-instance-identifier x",
    "aws ec2 describe-instances --endpoint-url http://evil",
    "AWS_PROFILE=x aws sts assume-role --role-arn r --role-session-name s",
    # constructs the first version missed (found by the red-team review)
    'for v in $(aws ec2 describe-volumes --query "Volumes[].VolumeId" --output text); do aws ec2 delete-volume --volume-id "$v"; done',
    'echo "$(aws iam delete-user --user-name bob)"',
    "timeout 30 aws ec2 terminate-instances --instance-ids i-1",
    "bash -lc 'aws s3 rb s3://b --force'",
    "{ aws ec2 terminate-instances --instance-ids i-1; }",
    "if true; then aws ec2 terminate-instances --instance-ids i-1; fi",
    "env -i aws ec2 terminate-instances --instance-ids i-1",
    "sudo -u root aws ec2 terminate-instances --instance-ids i-1",
    "nice -n 5 aws ec2 terminate-instances --instance-ids i-1",
    "aws${IFS}ec2${IFS}terminate-instances",
    "eval 'aws ec2 terminate-instances --instance-ids i-1'",
    "echo 'aws ec2 terminate-instances --instance-ids i-1' | bash",
    "python3 -c \"import os; os.system('aws ec2 delete-volume --volume-id v')\"",
    "docker run amazon/aws-cli ec2 delete-volume --volume-id v",
    "aws ec2 describe-instances --endpoint https://evil.example",
    "aws sts get-caller-identity --endpoint=https://evil.example",
    "aws ec2 describe-instances --instance-ids file://$HOME/.aws/credentials",
    "aws s3 ls",
    "aws configure set aws_access_key_id AKIAXXXX",
    "/usr/local/bin/aws ec2 delete-volume --volume-id v",
    "echo {aws,ec2,terminate-instances}",
]
ALLOWED = [
    "aws ec2 describe-instances --region us-east-1",
    "aws --profile prod ec2 describe-addresses",
    "aws sts get-caller-identity",
    "aws configure list-profiles",
    "aws --version",
    "python3 -m analyzer scan --profile prod --dry-run",
    "ls -la && which aws",
    "echo aws is a cloud",
    "git commit -m 'aws analyzer'",
]


class TestHook(unittest.TestCase):
    def test_blocked(self):
        for cmd in BLOCKED:
            with self.subTest(cmd=cmd):
                self.assertTrue(hook.violations(cmd), cmd)

    def test_allowed(self):
        for cmd in ALLOWED:
            with self.subTest(cmd=cmd):
                self.assertEqual(hook.violations(cmd), [], cmd)

    @classmethod
    def setUpClass(cls):
        cls._home = tempfile.TemporaryDirectory()
        cls.env = dict(os.environ, HOME=cls._home.name)

    @classmethod
    def tearDownClass(cls):
        cls._home.cleanup()

    def run_hook(self, payload):
        return subprocess.run([sys.executable, str(HOOK)], input=json.dumps(payload), capture_output=True, text=True,
                              env=self.env)

    def test_exit_codes_match_claude_code_contract(self):
        bad = self.run_hook({"tool_name": "Bash", "tool_input": {"command": "aws ec2 delete-volume --volume-id v"}})
        self.assertEqual(bad.returncode, 2)
        self.assertIn("BLOCKED", bad.stderr)
        self.assertEqual(self.run_hook({"tool_name": "Bash", "tool_input": {"command": "aws ec2 describe-vpcs"}}).returncode, 0)
        self.assertEqual(self.run_hook({"tool_name": "Read", "tool_input": {"file_path": "/repo/aws-analyzer/README.md"}}).returncode, 0)
        # any shell-capable tool is checked, not only Bash
        self.assertEqual(self.run_hook({"tool_name": "mcp__terminal__run_in_terminal", "tool_input": {"command": "aws ec2 delete-volume --volume-id v"}}).returncode, 2)
        self.assertEqual(self.run_hook({"tool_name": "Monitor", "tool_input": {"command": "aws ec2 terminate-instances --instance-ids i-1"}}).returncode, 2)
        # every string is scanned (HOOK-4); file contents are prose: the word aws is fine, a literal write call is not
        self.assertEqual(self.run_hook({"tool_name": "Write", "tool_input": {"file_path": "README.md", "content": "The AWS analyzer is read-only. Don't run aws by hand."}}).returncode, 0)
        self.assertEqual(self.run_hook({"tool_name": "Write", "tool_input": {"file_path": "x.sh", "content": "run aws ec2 delete-volume --volume-id v to clean up"}}).returncode, 2)
        # input that is not a JSON object fails closed, as documented (HOOK-5)
        self.assertEqual(subprocess.run([sys.executable, str(HOOK)], input="not json", capture_output=True, text=True, env=self.env).returncode, 2)


if __name__ == "__main__":
    unittest.main()
