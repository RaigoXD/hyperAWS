#!/usr/bin/env python3
"""Claude Code PreToolUse hook: block shell commands that run `aws` for anything but allowlisted reads.

BEST-EFFORT extra layer, NOT a guarantee. The analyzer itself is read-only because of analyzer/awscli.py
(exact allowlist, no shell) and, strongest, the read-only IAM policy you scan with. This hook only tries to stop a
*different* command (`aws ec2 delete-volume ...`, `aws s3 rm ...`) from being run by an agent in the same session.

How a tool call is judged (EVERY string in tool_input is checked, whatever the tool name or key):
  * The text is split the way a shell splits it: quotes, escapes, $'...', $(...), backticks, here-documents,
    `bash -c '...'`, `eval`, keywords and wrappers (sudo, env, timeout, xargs, npx ...). Wherever `aws` is the
    program that runs (`AWS`, `aws.exe`, `/usr/local/bin/AWS`, `"a"ws`, `\\aws` ...), its global options, service
    and operation must be plain words that form an allowlisted read (analyzer.awscli.check_command). Anything it
    cannot verify is BLOCKED (fail closed): abbreviated/unknown global options (`--reg`), --endpoint-url/--debug
    anywhere, quoted/escaped/variable service names, high-level commands (`s3 cp`, `ddb put`), unknown commands
    and commands redefined in ~/.aws/cli/alias.
  * Where `aws` is only an argument (`ssh host ...`, a wrapper the hook does not know), a literal AWS CLI call in
    the text is still judged; the plain word (`echo aws is a cloud`, a commit message) is not.
  * When the text mentions `aws`, constructs that hide what runs are blocked: eval, ${...}, base64, `| bash`,
    `python -c`, a program name taken from a variable or a glob, `NAME=aws`, `alias x=aws` ...
  * Setting AWS_ENDPOINT_URL*, AWS_CA_BUNDLE or AWS_DATA_PATH (the environment twins of --endpoint-url/--ca-bundle).
  * Even without the word `aws`: `curl --aws-sigv4`, terraform/tofu apply|destroy, cdk deploy|destroy, sam deploy,
    pulumi up|destroy, serverless deploy|remove (and similar), AWS CLI container images and boto3/aws-sdk code
    with a mutating call are blocked.
  * `description` and file-tool fields (content, new_string, file_path ...) are prose: only a literal AWS CLI call
    in them counts.

NOT detectable by design: a script run from a file (`bash x.sh`, `make deploy`, `npm run destroy`), a program name
assembled at run time without the word aws (`${X}s`, string concatenation inside python), a copied/renamed binary
used in a later call, SDK calls whose verb never appears literally. The IAM read-only policy is the real backstop.

Install (user-level, so it covers any working directory): add to ~/.claude/settings.json
  {"hooks": {"PreToolUse": [{"matcher": "Bash|Monitor|mcp__.*(terminal|shell|exec).*",
     "hooks": [{"type": "command", "command": "python3 /ABSOLUTE/PATH/TO/aws-analyzer/hooks/block_aws_writes.py"}]}]}}

Exit code 2 blocks the call and shows the message to Claude. Input that is not a UTF-8 JSON object and any internal
error also exit 2 (fail closed). If analyzer/ cannot be imported (hook copied elsewhere, package broken mid-edit),
every `aws` command is blocked.
"""

from __future__ import annotations

import fnmatch
import json
import re
import shlex
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
try:
    from analyzer.awscli import ReadOnlyViolation, alias_names, check_command  # noqa: E402
    _GUARD_ERROR = ""
except Exception as _e:  # noqa: BLE001 - fail closed: without the guard no aws command can be verified
    _GUARD_ERROR = f"{type(_e).__name__}: {_e}"

    class ReadOnlyViolation(Exception):  # type: ignore[no-redef]
        """Stand-in so the hook still loads and can refuse."""

    def check_command(service, op, args=()):  # type: ignore[no-redef]
        raise ReadOnlyViolation(f"the analyzer guard (analyzer/awscli.py) could not be loaded ({_GUARD_ERROR}), "
                                "so no aws command can be verified")

    def alias_names(text):  # type: ignore[no-redef]
        raise ValueError("the alias parser (analyzer/awscli.py) could not be loaded")

# AWS CLI v2 global options (awscli/data/cli.json) that are fine on a hand-typed read
_GLOBAL_VALUE_OK = {"--region", "--profile", "--output", "--query", "--color", "--cli-read-timeout",
                    "--cli-connect-timeout", "--cli-binary-format"}
_GLOBAL_BOOL_OK = {"--no-cli-pager", "--no-paginate", "--no-cli-auto-prompt", "--version"}
_HARMLESS_FLAGS = _GLOBAL_VALUE_OK | _GLOBAL_BOOL_OK      # not passed to check_command (it refuses the ones awscli.py sets)
# options that change where/how the CLI talks to AWS or read local input; their abbreviations (--e, --deb) count too
_RISKY_FLAGS = {"--debug", "--endpoint-url", "--no-verify-ssl", "--no-sign-request", "--ca-bundle", "--cli-auto-prompt",
                "--cli-input-json", "--cli-input-yaml", "--generate-cli-skeleton"}
_ALWAYS_OK = {("configure", "list-profiles")}          # local config read, no API call
_AWS_NAMES = {"aws", "aws2", "awscli"}                  # program basenames that are the AWS CLI (case-insensitive)
# Every AWS CLI command name (generated from the CLI's own model data). Only used where `aws` is an argument, to tell
# a literal CLI call (`ssh host aws ec2 ...`) from prose (`the aws team`). Where `aws` runs, any name is checked.
_SERVICES = frozenset("""
accessanalyzer account acm acm-pca aiops amp amplify amplifybackend amplifyuibuilder apigateway
apigatewaymanagementapi apigatewayv2 appconfig appconfigdata appfabric appflow appintegrations
application-autoscaling application-insights application-signals applicationcostprofiler appmesh apprunner appstream
appsync arc-region-switch arc-zonal-shift artifact athena auditmanager autoscaling autoscaling-plans b2bi backup
backup-gateway backupsearch batch bcm-dashboards bcm-data-exports bcm-pricing-calculator bcm-recommended-actions
bedrock bedrock-agent bedrock-agent-runtime bedrock-agentcore bedrock-agentcore-control bedrock-data-automation
bedrock-data-automation-runtime bedrock-runtime billing billingconductor braket budgets ce chatbot chime
chime-sdk-identity chime-sdk-media-pipelines chime-sdk-meetings chime-sdk-messaging chime-sdk-voice cleanrooms
cleanroomsml cloud9 cloudcontrol clouddirectory cloudformation cloudfront cloudfront-keyvaluestore cloudhsm
cloudhsmv2 cloudsearch cloudsearchdomain cloudtrail cloudtrail-data cloudwatch codeartifact codebuild codecatalyst
codecommit codeconnections codedeploy codeguru-reviewer codeguru-security codeguruprofiler codepipeline
codestar-connections codestar-notifications cognito-identity cognito-idp cognito-sync comprehend comprehendmedical
compute-optimizer compute-optimizer-automation config configservice configure connect connect-contact-lens
connectcampaigns connectcampaignsv2 connectcases connectparticipant controlcatalog controltower
cost-optimization-hub cur customer-profiles databrew dataexchange datapipeline datasync datazone dax ddb deadline
deploy detective devicefarm devops-guru directconnect discovery dlm dms docdb docdb-elastic drs ds ds-data dsql
dynamodb dynamodbstreams ebs ec2 ec2-instance-connect ecr ecr-public ecs efs eks eks-auth elasticache
elasticbeanstalk elb elbv2 emr emr-containers emr-serverless entityresolution es events evidently evs finspace
finspace-data firehose fis fms forecast forecastquery frauddetector freetier fsx gamelift gameliftstreams geo-maps
geo-places geo-routes glacier globalaccelerator glue grafana greengrass greengrassv2 groundstation guardduty health
healthlake history iam identitystore imagebuilder importexport inspector inspector-scan inspector2 internetmonitor
invoicing iot iot-data iot-jobs-data iot-managed-integrations iotanalytics iotdeviceadvisor iotevents iotevents-data
iotfleetwise iotsecuretunneling iotsitewise iotthingsgraph iottwinmaker iotwireless ivs ivs-realtime ivschat kafka
kafkaconnect kendra kendra-ranking keyspaces keyspacesstreams kinesis kinesis-video-archived-media
kinesis-video-media kinesis-video-signaling kinesis-video-webrtc-storage kinesisanalytics kinesisanalyticsv2
kinesisvideo kms lakeformation lambda launch-wizard lex-models lex-runtime lexv2-models lexv2-runtime
license-manager license-manager-linux-subscriptions license-manager-user-subscriptions lightsail location login
logout logs lookoutequipment m2 machinelearning macie2 mailmanager managedblockchain managedblockchain-query
marketplace-agreement marketplace-catalog marketplace-deployment marketplace-entitlement marketplace-reporting
marketplacecommerceanalytics mediaconnect mediaconvert medialive mediapackage mediapackage-vod mediapackagev2
mediastore mediastore-data mediatailor medical-imaging memorydb meteringmarketplace mgh mgn
migration-hub-refactor-spaces migrationhub-config migrationhuborchestrator migrationhubstrategy mpa mq mturk mwaa
mwaa-serverless neptune neptune-graph neptunedata network-firewall networkflowmonitor networkmanager networkmonitor
notifications notificationscontacts nova-act oam observabilityadmin odb omics opensearch opensearchserverless
organizations osis outposts panorama partnercentral-account partnercentral-benefits partnercentral-channel
partnercentral-selling payment-cryptography payment-cryptography-data pca-connector-ad pca-connector-scep pcs
personalize personalize-events personalize-runtime pi pinpoint pinpoint-email pinpoint-sms-voice
pinpoint-sms-voice-v2 pipes polly pricing proton qapps qbusiness qconnect quicksight ram rbin rds rds-data redshift
redshift-data redshift-serverless rekognition repostspace resiliencehub resource-explorer-2 resource-groups
resourcegroupstaggingapi rolesanywhere route53 route53-recovery-cluster route53-recovery-control-config
route53-recovery-readiness route53domains route53globalresolver route53profiles route53resolver rtbfabric rum s3
s3api s3control s3outposts s3tables s3vectors sagemaker sagemaker-a2i-runtime sagemaker-edge
sagemaker-featurestore-runtime sagemaker-geospatial sagemaker-metrics sagemaker-runtime savingsplans scheduler
schemas sdb secretsmanager security-ir securityhub securitylake serverlessrepo service-quotas servicecatalog
servicecatalog-appregistry servicediscovery ses sesv2 shield signer signin simspaceweaver snow-device-management
snowball sns socialmessaging sqs ssm ssm-contacts ssm-guiconnect ssm-incidents ssm-quicksetup ssm-sap sso sso-admin
sso-oidc stepfunctions storagegateway sts supplychain support support-app swf synthetics taxsettings textract
timestream-influxdb timestream-query timestream-write tnb transcribe transfer translate trustedadvisor
verifiedpermissions voice-id vpc-lattice waf waf-regional wafv2 wellarchitected wickr wisdom workdocs workmail
workmailmessageflow workspaces workspaces-instances workspaces-thin-client workspaces-web xray
""".split())
# single-word CLI subcommands (s3 cp, ddb put, lambda invoke ...): with a known service they make a literal call
_WORD_OPS = frozenset("""
cp mv rm sync mb rb ls presign website put select push register install uninstall deregister invoke publish
subscribe unsubscribe ssh get socks deploy package tail wait scan query list show set import sso login logout help
""".split())

_AWS_WORD = re.compile(r"(?<![\w.:@-])aws2?(?![\w:-])")     # aws, /bin/aws, aws.exe; not .aws/, arn:aws:, aws-x
_AWS_PKG = re.compile(r"(?<![\w/.@-])(?:aws-cli|awscli)(?![\w/.-])")   # package names (pip/pipx), not paths
_NAME = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
_OP_SHAPE = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)+")
_ASSIGN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?\+?=")
_ASSIGN_AWS = re.compile(r"(?:^|[\s;&|(`])[a-z_][a-z0-9_]*\+?=\s*aws2?(?![\w:-])")
_TAIL_END = re.compile(r"[;|&()`\n<>]")
_LTOK = re.compile(r"[^\s,\[\]{}]+")
_BRACE_EXPANSION = re.compile(r"\{[^{}]*(?:,|\.\.)[^{}]*\}")
# constructs a shell can use to hide a command; with the word `aws` present we cannot verify what runs
_UNVERIFIABLE = re.compile(
    r"\beval\b|\$\{|\$'|\bbase64\b|\|\s*(?:ba|z|da|k|mk|c|tc|fi|y)?sh\b|(?:\bsource|(?:^|[\s;&|])\.)\s+<\(|"
    r"\bpython[\d.]*\s+(?:-\w+\s+)*-\w*c\b|\b(?:node|nodejs|bun)\s+(?:-\S+\s+)*-(?:e|p|-eval|-print)\b|"
    r"\bperl\s+-\w*e\b|\bruby\s+-\w*e\b|-m\s+awscli\b|\{aws,|,aws[,}]", re.I)
_SIGV4 = re.compile(r"--aws-sigv4\b")
# the environment twins of --endpoint-url / --ca-bundle and an API-model override (the analyzer drops them for its own
# aws process): `AWS_ENDPOINT_URL=https://x aws sts ...`, `export AWS_ENDPOINT_URL_S3=...`, `env AWS_CA_BUNDLE=... aws`
_ENV_REDIRECT = re.compile(r"(?<![\w$])(AWS_ENDPOINT_URL\w*|AWS_CA_BUNDLE|AWS_DATA_PATH|AWS_IGNORE_CONFIGURED_ENDPOINT_URLS)"
                           r"\s*\+?=")
_CONTAINER = re.compile(r"\b(?:docker|podman|finch|nerdctl)\b[^\n]*(?:(?<![\w-])aws(?![\w-])|aws-?cli)")
_SDK = re.compile(r"\b(?:boto3|botocore|aioboto3|aiobotocore|awswrangler)\b|@aws-sdk/|\baws-sdk\b|\baws_sdk|\bAws::|"
                  r"github\.com/aws/aws-sdk", re.I)
_SDK_VERBS = ("delete|terminate|create|put|update|modify|remove|attach|detach|stop|start|reboot|run|invoke|publish|"
              "send|upload|copy|restore|revoke|authorize|associate|disassociate|release|allocate|register|deregister|"
              "enable|disable|reset|import|cancel|reject|accept|replace|execute|purge|transact|rotate|tag|untag|apply|"
              "promote|failover|abort|complete|initiate|admin")
_SDK_WRITE = re.compile(
    rf"(?<![A-Za-z])(?:{_SDK_VERBS}|batch_write|batch_delete|batch_execute|write)_[a-z](?!lient\b)"   # boto3 snake
    rf"|(?<![A-Za-z])(?:{_SDK_VERBS})[A-Z][a-z]"                                                    # js v2 camel
    rf"|(?<![A-Za-z])(?:{_SDK_VERBS.title()}|Set|BatchWrite|BatchDelete|BatchExecute)[A-Za-z0-9]*Command\b"  # js v3
    r"|\.(?:delete|put|terminate|reboot|invoke|purge)\s*\(")                                      # boto3 resources
_MAX_DEPTH = 20
_ALIAS_FILE: Path | None = None                         # None: ~/.aws/cli/alias (tests point it elsewhere)

# words that run the rest of the command line (`sudo -u root aws ...`, `then aws ...`); their options are skipped
_WRAPPERS = {
    "then", "do", "else", "elif", "if", "while", "until", "!", "function", "coproc",
    "sudo", "doas", "env", "timeout", "gtimeout", "nice", "ionice", "nohup", "time", "command", "exec", "builtin",
    "noglob", "nocorrect", "xargs", "stdbuf", "caffeinate", "unbuffer", "chronic", "strace", "ltrace", "setsid",
    "watch", "parallel", "flock", "chroot", "runuser", "script", "busybox", "aws-vault",
    "npx", "bunx", "pnpx", "npm", "pnpm", "yarn", "dlx", "uvx", "uv", "pipx", "poetry", "pipenv", "pdm", "hatch",
    "run",
}
_WRAPPER_VALUE_OPTS = {
    "sudo": {"-u", "-g", "-h", "-p", "-C", "-D", "-r", "-t", "-U", "-T", "-R", "--user", "--group", "--chdir"},
    "doas": {"-u", "-C"}, "env": {"-u", "-C", "-S", "-P", "--unset", "--chdir", "--split-string"},
    "timeout": {"-s", "-k", "--signal", "--kill-after"}, "gtimeout": {"-s", "-k", "--signal", "--kill-after"},
    "nice": {"-n", "--adjustment"}, "ionice": {"-c", "-n", "-p", "-t"}, "stdbuf": {"-i", "-o", "-e"},
    "xargs": {"-I", "-L", "-n", "-P", "-s", "-d", "-E", "-a", "-J", "-R", "-S"}, "watch": {"-n", "--interval"},
    "time": {"-f", "-o"}, "caffeinate": {"-t", "-w"}, "strace": {"-o", "-e", "-p", "-s", "-u"},
    "ltrace": {"-o", "-e", "-p", "-s", "-u"}, "exec": {"-a"}, "parallel": {"-j", "-S", "--jobs"},
    "flock": {"-w", "-E", "--timeout"}, "script": {"-t", "-T", "-F"}, "npx": {"-p", "--package"},
    "npm": {"-w", "--workspace", "--prefix"}, "pnpm": {"-C", "--dir", "--filter", "-F"}, "yarn": {"--cwd"},
    "uvx": {"--from", "--with", "-p", "--python"}, "uv": {"--with", "-p", "--python", "--project", "--directory"},
    "pipx": {"--spec", "--python"}, "aws-vault": {"-d", "--duration"},
}
_WRAPPER_POSITIONALS = {"timeout": 1, "gtimeout": 1, "flock": 1, "chroot": 1, "script": 1, "aws-vault": 2}
_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "yash", "fish", "tcsh", "csh"}
_INTERP = re.compile(r"(?:python|pypy)[\d.]*|node(?:js)?|deno|bun|perl|ruby|php|lua(?:jit)?|osascript|rscript|"
                     r"pwsh|powershell|[gmn]?awk|tclsh|expect|julia|groovy|jshell")
_BINDERS = {"alias", "hash", "export", "declare", "typeset", "local", "readonly", "enable"}
_COPIERS = {"ln", "link", "cp", "mv", "install", "rsync", "ditto"}
# programs that never execute their arguments: `aws` in their arguments is text (echo, grep, git commit -m below)
_INERT = {"echo", "printf", "print", "grep", "egrep", "fgrep", "rg", "ag", "ack", "true", "false", ":", "test", "[",
          "[[", "cat", "bat", "head", "tail", "wc", "cut", "tr", "column", "jq", "yq", "diff", "cmp", "ls", "which",
          "type", "whereis", "file", "stat", "basename", "dirname", "realpath", "readlink", "touch", "mkdir", "pwd",
          "cd", "sleep", "date", "tree"}
# infrastructure-as-code and other tools that change cloud resources; None = every use (signs arbitrary API calls)
_IAC_WRITES: dict[str, set[str] | None] = {
    **dict.fromkeys(("terraform", "tofu", "terragrunt"), {"apply", "destroy", "import", "taint", "untaint",
                                                          "force-unlock", "refresh", "rm", "mv", "push",
                                                          "replace-provider", "new", "delete"}),
    **dict.fromkeys(("cdk", "aws-cdk"), {"deploy", "destroy", "bootstrap", "import", "watch", "rollback", "gc",
                                         "migrate", "refactor"}),
    "cdktf": {"deploy", "destroy", "watch"},
    "sam": {"deploy", "delete", "sync", "package", "publish", "remote"},
    "pulumi": {"up", "update", "destroy", "import", "refresh", "cancel", "rm", "delete", "unprotect", "watch"},
    **dict.fromkeys(("serverless", "sls", "osls"), {"deploy", "remove", "rollback", "invoke"}),
    "sst": {"deploy", "remove", "dev"},
    "copilot": {"deploy", "delete"},
    "chalice": {"deploy", "delete"},
    "amplify": {"push", "publish", "delete"},
    "eb": {"create", "deploy", "terminate", "scale", "setenv", "restore", "abort", "swap", "upgrade", "clone"},
    "eksctl": {"create", "delete", "scale", "upgrade", "update", "set", "unset", "enable", "drain", "register",
               "deregister", "associate", "disassociate"},
    "zappa": {"deploy", "update", "undeploy", "rollback", "schedule", "unschedule", "certify", "invoke"},
    "rain": {"deploy", "rm"},
    "s3cmd": {"put", "del", "rm", "sync", "mb", "rb", "cp", "mv", "modify", "setacl", "setpolicy", "delpolicy",
              "setlifecycle", "dellifecycle", "setcors", "delcors", "expire", "restore", "abortmp", "setversioning"},
    "s5cmd": {"cp", "mv", "rm", "sync", "mb", "rb", "run", "pipe"},
    "awscurl": None, "aws-nuke": None, "cloud-nuke": None,
}
_IAC_WORD = re.compile(r"(?<![\w.@-])(" + "|".join(map(re.escape, sorted(_IAC_WRITES, key=len, reverse=True)))
                       + r")(?![\w-])")


# --------------------------------------------------------------------------
# A small shell lexer: words after quote removal plus what the shell would do to them at run time


class _Unparsed(Exception):
    """Text this hook cannot follow as shell syntax."""


class _Word:
    __slots__ = ("chars", "quoted", "dynamic", "split", "glob", "brace", "special_at")

    def __init__(self):
        self.chars: list[str] = []
        self.quoted = self.dynamic = self.split = self.glob = self.brace = False
        self.special_at: int | None = None      # length of the plain prefix (tells NAME=x from "NAME"=x)

    def mark(self):
        if self.special_at is None:
            self.special_at = len(self.value)

    @property
    def value(self) -> str:
        return "".join(self.chars)


class _Cmd:
    __slots__ = ("words", "heredocs", "comments", "writes")

    def __init__(self):
        self.words: list[_Word] = []
        self.heredocs: list[list] = []          # [delimiter, strip_tabs, quoted, body]
        self.comments: list[str] = []
        self.writes = False                     # output redirected to a file


class _Lexer:
    def __init__(self, text: str, depth: int = 0):
        self.s, self.depth, self.cmds = text, depth, []

    def parse(self) -> None:
        self._list(0, self.depth, None)

    def _list(self, i: int, depth: int, closer: str | None) -> int:
        """Commands from i to the end (or to an unmatched `)` when closer is set); returns the index after it."""
        if depth > _MAX_DEPTH:
            raise _Unparsed("nested too deeply")
        s, n = self.s, len(self.s)
        cmd, word, redirect = _Cmd(), None, ""
        pending: list[list] = []

        def end_cmd():
            nonlocal cmd
            end_word()
            if cmd.words or cmd.heredocs or cmd.comments:
                self.cmds.append(cmd)
            cmd = _Cmd()

        def end_word():
            nonlocal word, redirect
            w, word = word, None
            if w is None or not (w.chars or w.quoted or w.dynamic):
                return
            if redirect == "<<<":
                cmd.heredocs.append(["", False, True, w.value + "\n"])
            elif redirect:
                pass                                      # a redirection target is a file, not an argument
            elif not (w.quoted or w.dynamic) and w.value in ("{", "}"):
                redirect = ""
                end_cmd()                                 # `{ aws ...; }`, `f() { ... }`: a group starts/ends
                return
            else:
                cmd.words.append(w)
            redirect = ""

        while i < n:
            c = s[i]
            if c in " \t":
                end_word()
                i += 1
            elif c == "\n":
                end_cmd()
                i = self._bodies(i + 1, pending, depth)
                pending = []
            elif c == "#" and word is None:
                j = s.find("\n", i)
                j = n if j < 0 else j
                cmd.comments.append(s[i + 1:j])
                i = j
            elif c == "&" and s.startswith(">", i + 1):  # &> / &>> redirect both streams
                end_word()
                cmd.writes, redirect = True, ">"
                i += 3 if s.startswith(">>", i + 1) else 2
            elif c in ";&|":
                end_cmd()
                while i < n and s[i] in ";&|":
                    i += 1
            elif c == "(":
                end_cmd()                                 # subshell; also ends `f()` and `a=(...)`
                i = self._list(i + 1, depth + 1, ")")
            elif c == ")":
                end_cmd()
                if closer != ")":
                    raise _Unparsed("unbalanced )")
                return i + 1
            elif c in "<>":
                if word is not None and word.value.isdigit() and not (word.quoted or word.dynamic):
                    word = None                           # `2>`: the digits name a file descriptor
                end_word()
                if s.startswith("(", i + 1):              # <(...) >(...): process substitution, an argument
                    i = self._list(i + 2, depth + 1, ")")
                    word = _Word()
                    word.dynamic = True
                    word.chars.append("$")
                elif s.startswith("<<", i) and not s.startswith("<<<", i):
                    strip = s.startswith("<<-", i)
                    i += 3 if strip else 2
                    while i < n and s[i] in " \t":
                        i += 1
                    i, delim, quoted = self._delimiter(i)
                    entry = [delim, strip, quoted, ""]
                    cmd.heredocs.append(entry)
                    pending.append(entry)
                else:
                    start = i
                    i += 1
                    while i < n and (s[i] in "<>&" or (s[i] == "|" and s[i - 1] == ">")):
                        i += 1
                    redirect = s[start:i]
                    cmd.writes = cmd.writes or ">" in redirect
            else:
                if word is None:
                    word = _Word()
                i = self._char(i, word, depth)
        end_cmd()
        if pending:
            self._bodies(n, pending, depth)               # here-document without a body or terminator
        if closer:
            raise _Unparsed("missing )")
        return i

    def _char(self, i: int, word: _Word, depth: int) -> int:
        s = self.s
        c = s[i]
        if c == "'":
            j = s.find("'", i + 1)
            if j < 0:
                raise _Unparsed("unterminated '")
            word.mark()
            word.quoted = True
            word.chars.append(s[i + 1:j])
            return j + 1
        if c == '"':
            word.mark()
            word.quoted = True
            return self._dquote(i + 1, word, depth)
        if c == "\\":
            if s.startswith("\n", i + 1):
                return i + 2                              # line continuation
            word.mark()
            word.quoted = True
            word.chars.append(s[i + 1:i + 2])
            return i + 2
        if c == "$":
            return self._dollar(i, word, depth, quoted=False)
        if c == "`":
            return self._backtick(i, word, depth, quoted=False)
        if c in "*?[":
            word.glob = True
        elif c in "{}":
            word.brace = True
        word.chars.append(c)
        return i + 1

    def _dquote(self, i: int, word: _Word, depth: int) -> int:
        s, n = self.s, len(self.s)
        while i < n:
            c = s[i]
            if c == '"':
                return i + 1
            if c == "\\" and i + 1 < n and s[i + 1] in '$`"\\\n':
                if s[i + 1] != "\n":
                    word.chars.append(s[i + 1])
                i += 2
            elif c == "$":
                i = self._dollar(i, word, depth, quoted=True)
            elif c == "`":
                i = self._backtick(i, word, depth, quoted=True)
            else:
                word.chars.append(c)
                i += 1
        raise _Unparsed('unterminated "')

    def _dollar(self, i: int, word: _Word, depth: int, quoted: bool) -> int:
        s, n = self.s, len(self.s)
        nxt = s[i + 1:i + 2]
        if nxt == "'" and not quoted:                     # $'...': decode it, `$'\x61ws'` is aws
            word.mark()
            word.quoted = True
            j, text = _ansi_c(s, i + 2)
            word.chars.append(text)
            return j
        if nxt == '"' and not quoted:                     # $"..." locale string
            word.mark()
            word.quoted = True
            return self._dquote(i + 2, word, depth)
        if nxt == "(":
            j = self._list(i + 2, depth + 1, ")")
        elif nxt == "{":
            j = self._braced(i + 2, depth)
        elif nxt.isalpha() or nxt == "_":
            j = i + 1
            while j < n and (s[j].isalnum() or s[j] == "_"):
                j += 1
        elif nxt and (nxt.isdigit() or nxt in "@*#?$!-"):
            j = i + 2
        else:
            word.chars.append("$")                        # a lone `$` is literal
            return i + 1
        word.mark()
        word.dynamic = True
        word.split = word.split or not quoted             # unquoted: the result is split into several words
        word.chars.append("$")
        return j

    def _braced(self, i: int, depth: int) -> int:
        s, n, level = self.s, len(self.s), 1
        while i < n:
            c = s[i]
            if c == "\\":
                i += 2
                continue
            if c == "'":
                j = s.find("'", i + 1)
                if j < 0:
                    raise _Unparsed("unterminated '")
                i = j + 1
                continue
            if c == '"':
                i = self._dquote(i + 1, _Word(), depth)
                continue
            if c == "$" and s.startswith("(", i + 1):
                i = self._list(i + 2, depth + 1, ")")
                continue
            if c == "`":
                i = self._backtick(i, _Word(), depth, quoted=True)
                continue
            if c == "{":
                level += 1
            elif c == "}":
                level -= 1
                if level == 0:
                    return i + 1
            i += 1
        raise _Unparsed("unterminated ${")

    def _backtick(self, i: int, word: _Word, depth: int, quoted: bool) -> int:
        s, n = self.s, len(self.s)
        j, inner = i + 1, []
        while j < n and s[j] != "`":
            if s[j] == "\\" and j + 1 < n and s[j + 1] in "`\\$":
                inner.append(s[j + 1])
                j += 2
            else:
                inner.append(s[j])
                j += 1
        if j >= n:
            raise _Unparsed("unterminated `")
        sub = _Lexer("".join(inner), depth + 1)
        try:
            sub.parse()
        finally:
            self.cmds += sub.cmds
        word.mark()
        word.dynamic = True
        word.split = word.split or not quoted
        word.chars.append("$")
        return j + 1

    def _delimiter(self, i: int) -> tuple[int, str, bool]:
        s, n = self.s, len(self.s)
        out, quoted = [], False
        while i < n and s[i] not in " \t\n;&|()<>":
            c = s[i]
            if c in "'\"":
                j = s.find(c, i + 1)
                if j < 0:
                    raise _Unparsed("unterminated quote in a here-document delimiter")
                out.append(s[i + 1:j])
                quoted, i = True, j + 1
            elif c == "\\":
                out.append(s[i + 1:i + 2])
                quoted, i = True, i + 2
            else:
                out.append(c)
                i += 1
        if not out:
            raise _Unparsed("missing here-document delimiter")
        return i, "".join(out), quoted

    def _bodies(self, i: int, pending: list[list], depth: int) -> int:
        """Read the here-document bodies that start after a newline; $(...) in an unquoted one runs."""
        s, n = self.s, len(self.s)
        for entry in pending:
            delim, strip, lines = entry[0], entry[1], []
            while i < n:
                j = s.find("\n", i)
                line = s[i:] if j < 0 else s[i:j]
                i = n if j < 0 else j + 1
                if (line.lstrip("\t") if strip else line) == delim:
                    break
                lines.append(line)
            entry[3] = "".join(ln + "\n" for ln in lines)
            if not entry[2]:
                sub = _Lexer(entry[3], depth + 1)
                try:
                    sub.expansions()
                finally:
                    self.cmds += sub.cmds
        return i

    def expansions(self) -> None:
        """Only the $(...), `...` and ${...} parts of the text (an unquoted here-document body)."""
        s, n, i, w = self.s, len(self.s), 0, _Word()
        while i < n:
            if s[i] == "\\":
                i += 2
            elif s[i] == "$":
                i = self._dollar(i, w, self.depth, quoted=True)
            elif s[i] == "`":
                i = self._backtick(i, w, self.depth, quoted=True)
            else:
                i += 1


_ANSI = {"n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f", "v": "\v",
         "\\": "\\", "'": "'", '"': '"', "?": "?"}


def _ansi_c(s: str, i: int) -> tuple[int, str]:
    """Decode a $'...' string starting at i (after the quote); returns (index after the closing quote, text)."""
    out, n = [], len(s)
    while i < n:
        c = s[i]
        if c == "'":
            return i + 1, "".join(out)
        if c == "\\" and i + 1 < n:
            e = s[i + 1]
            m = (re.match(r"[0-9A-Fa-f]{1,2}", s[i + 2:]) if e == "x" else
                 re.match(r"[0-9A-Fa-f]{1,4}", s[i + 2:]) if e == "u" else
                 re.match(r"[0-9A-Fa-f]{1,8}", s[i + 2:]) if e == "U" else None)
            if e in _ANSI:
                out.append(_ANSI[e])
                i += 2
            elif m:
                out.append(chr(min(int(m.group(), 16), 0x10FFFF)))
                i += 2 + len(m.group())
            elif e in "01234567":
                d = re.match(r"[0-7]{1,3}", s[i + 1:]).group()
                out.append(chr(int(d, 8) & 0xFF))
                i += 1 + len(d)
            elif e == "c" and i + 2 < n:
                out.append(chr(ord(s[i + 2]) & 0x1F))
                i += 3
            else:
                out.append("\\" + e)
                i += 2
            continue
        out.append(c)
        i += 1
    raise _Unparsed("unterminated $'")


# --------------------------------------------------------------------------
# Judging


def _normalize(text: str) -> str:
    """Lowercase text with quotes and backslashes removed (`a""ws "e"c2` -> `aws ec2`), for the text checks."""
    return re.sub(r"[\"'\\]", "", text.replace("\\n", " ").replace("\\t", " ")).lower()


def _mentions(norm: str) -> bool:
    return bool(_AWS_WORD.search(norm) or _AWS_PKG.search(norm))


def _base(w: _Word) -> str:
    """Program name as the shell would look it up: no directory, lowercase (APFS is case-insensitive), no .exe."""
    v = re.split(r"[/\\]", w.value.lstrip("="))[-1].lower()    # zsh: `=aws` expands to the path of aws
    v = re.sub(r"\.(?:exe|cmd|bat)$", "", v)
    return re.sub(r"(?<=.)@[^/]*$", "", v)                     # npx aws-cdk@2 -> aws-cdk


def _is_aws(base: str) -> bool:
    return base in _AWS_NAMES


def _plain(w: _Word | None) -> bool:
    return w is not None and not (w.quoted or w.dynamic or w.glob or w.brace) and bool(_NAME.fullmatch(w.value))


def _is_assignment(w: _Word) -> bool:
    m = _ASSIGN.match(w.value)
    return bool(m) and (w.special_at is None or w.special_at >= m.end())


def _is_risky(flag: str) -> bool:
    return flag in _RISKY_FLAGS or (len(flag) > 2 and flag not in _HARMLESS_FLAGS
                                    and any(r.startswith(flag) for r in _RISKY_FLAGS))


def _extras(args: list[str]) -> list[str]:
    """The arguments check_command must see: options (minus the names of the harmless globals) and EVERY value, so its
    value rules apply to all of them (file://, fileb:// and shorthand ``Key@=file://...``, also after ``--x=``)."""
    out = []
    for a in args:
        if a.startswith("--"):
            name, eq, val = a.partition("=")
            if name not in _HARMLESS_FLAGS:
                out.append(a)                     # check_command checks the flag and the value after '=' separately
            elif eq:
                out.append(val)                   # --region=..., --query=...: only the value
        else:
            out.append(a)
    return out


def _flag_problem(flag: str) -> str:
    try:
        check_command("sts", "get-caller-identity", [flag])   # the analyzer guard's own forbidden/abbreviation rules
    except ReadOnlyViolation as e:
        return str(e)
    return f"global option {flag} is not an exact, harmless option (abbreviated or unknown), so the service " \
           "after it cannot be verified"


_alias_names = alias_names                                 # the analyzer's own parser (analyzer/awscli.py)


def _alias_shadow(service: str, op: str) -> str:
    """The AWS CLI lets ~/.aws/cli/alias redefine any command (even `sts`), so an allowed read must not be one."""
    try:
        path = _ALIAS_FILE if _ALIAS_FILE is not None else Path.home() / ".aws" / "cli" / "alias"
        if not path.is_file():
            return ""
        names = _alias_names(path.read_text(encoding="utf-8", errors="replace"))
    except Exception as e:  # noqa: BLE001 - fail closed
        return f"the AWS CLI alias file could not be read ({type(e).__name__}), so `aws {service}` may be redefined"
    if ("toplevel", service) in names:
        return f"`aws {service}` is redefined by an alias in {path}"
    if op and (f"command {service}", op) in names:
        return f"`aws {service} {op}` is redefined by an alias in {path}"
    return ""


def _check_op(service: str, op: str, args: list[str]) -> str:
    """'' when `aws <service> <op> <args>` is an allowlisted read, else the reason it is not."""
    risky = next((a.split("=", 1)[0] for a in args if a.startswith("--") and _is_risky(a.split("=", 1)[0])), None)
    if risky:
        return f"option {risky} (or what it abbreviates) changes where or how the CLI talks to AWS"
    if (service, op) not in _ALWAYS_OK and "help" not in (service, op):
        try:
            check_command(service, op, _extras(args))
        except ReadOnlyViolation as e:
            return str(e)
    return _alias_shadow(service, op)


def _judge_aws(args: list[_Word], out: list[str]) -> None:
    """`aws` is the program: everything up to the operation must parse as a plain, allowlisted read."""
    i = 0
    while i < len(args) and args[i].value.startswith("-"):
        w = args[i]
        name, eq, _ = w.value.partition("=")
        if w.dynamic or w.glob or w.brace:
            out.append(f"aws {w.value}: a global option built at run time cannot be verified")
            return
        if name in _GLOBAL_VALUE_OK:
            i += 1 if eq else 2
            if not eq and i - 1 < len(args) and args[i - 1].split:
                out.append(f"aws {name} $...: an unquoted variable can split into extra words (options, a "
                           "different service), so the command cannot be verified")
                return
        elif name in _GLOBAL_BOOL_OK and not eq:
            i += 1
        else:
            out.append(f"aws {name}: {_flag_problem(w.value)}")
            return
    if i >= len(args):
        return                                            # `aws`, `aws --version`: no API call
    svc, op = args[i], (args[i + 1] if i + 1 < len(args) else None)
    for part in (svc, op):
        if part is not None and not _plain(part):
            out.append(f"aws ... {part.value!r}: the service or operation is quoted, escaped, built at run time or "
                       "not a plain name, so it cannot be verified")
            return
    shown = f"aws {svc.value} {op.value if op else ''}".strip()
    problem = _check_op(svc.value, op.value if op else "", [a.value for a in args[i + 2:]])
    if problem:
        out.append(f"{shown}: {problem}")


def _looks_like_call(toks: list[str], j: int) -> bool:
    if j + 1 >= len(toks) or toks[j] not in _SERVICES:
        return False
    return bool(_OP_SHAPE.fullmatch(toks[j + 1])) or toks[j + 1] in _WORD_OPS


def _tails(norm: str, pattern: re.Pattern) -> list[tuple[re.Match, list[str]]]:
    """Each match with the words after it, up to a shell separator or the next match (linear in the text size)."""
    matches = list(pattern.finditer(norm))
    out = []
    for k, m in enumerate(matches):
        end = matches[k + 1].start() if k + 1 < len(matches) else len(norm)
        sep = _TAIL_END.search(norm, m.end(), end)
        out.append((m, _LTOK.findall(norm, m.end(), sep.start() if sep else end)))
    return out


def _lenient(text: str, out: list[str]) -> None:
    """`aws` as an argument or in prose: judge it only where it is followed by a literal CLI call."""
    for _m, toks in _tails(_normalize(text), _AWS_WORD):
        j = 0
        while j < len(toks) and toks[j].startswith("--"):
            # an option before the service; when the next word is not the service it may be this option's value
            takes = "=" not in toks[j] and toks[j] not in _GLOBAL_BOOL_OK and not _looks_like_call(toks, j + 1)
            j += 2 if takes else 1
        if not _looks_like_call(toks, j):
            continue                                      # `the aws team`: prose, not a CLI call
        svc, op = toks[j], toks[j + 1]
        bad = next((t.split("=", 1)[0] for t in toks[:j] if t.startswith("--")
                    and t.split("=", 1)[0] not in _HARMLESS_FLAGS), None)
        problem = _flag_problem(bad) if bad else _check_op(svc, op, toks[j + 2:])
        if problem:
            out.append(f"aws {svc} {op}: {problem}")


def _program_kind(w: _Word, mentions: bool) -> str:
    base = _base(w)
    if _is_aws(base):
        return "aws"
    if w.brace and _BRACE_EXPANSION.search(w.value):
        return "hidden"                                   # `{a,}ws`: brace expansion in the program name
    if w.glob and any(fnmatch.fnmatchcase(name, base) for name in ("aws", "aws2", "aws.exe")):
        return "hidden"                                   # `/usr/local/bin/a?s`
    if w.dynamic:
        return "hidden" if mentions else "other"         # `$A ec2 ...`
    if base in _SHELLS or base == "su":
        return "shell"
    if base in ("eval", "source", ".", "git", "find"):
        return base
    if base in _IAC_WRITES:
        return "iac"
    if _INTERP.fullmatch(base):
        return "interp"
    if base in _BINDERS or base in _COPIERS:
        return "binder"
    return "inert" if base in _INERT else "other"


def _judge_shell(base: str, args: list[_Word], cmd: _Cmd, out: list[str], mentions: bool, depth: int) -> bool:
    """`bash -c '...'`, `su -c`, `bash <<EOF`, `... | sh`. Returns True when here-documents were read as script."""
    if base == "su":
        for k, w in enumerate(args):
            if w.value in ("-c", "--command") and k + 1 < len(args):
                _script(args[k + 1], out, mentions, depth)
            elif w.value.startswith("--command="):
                _analyze(w.value.split("=", 1)[1], out, depth + 1, mentions)
        return False
    has_c = stdin = False
    j = 0
    while j < len(args):
        v = args[j].value
        if v in ("-o", "+o", "-O", "+O", "--rcfile", "--init-file"):
            j += 2
            continue
        if v == "--":
            j += 1
            break
        if v[:1] in "-+" and len(v) > 1:
            if v[0] == "-" and not v.startswith("--"):
                has_c, stdin = has_c or "c" in v[1:], stdin or "s" in v[1:]
            j += 1
            continue
        break
    if has_c:
        if j < len(args):
            _script(args[j], out, mentions, depth)
        elif mentions:
            out.append(f"`{base} -c` without a visible script (it comes from xargs or stdin) in a command that "
                       "mentions aws cannot be verified")
        return False
    if j < len(args) and not stdin:
        return False                                      # `bash file.sh`: the file is not visible here
    bodies = [h[3] for h in cmd.heredocs]
    for body in bodies:
        _analyze(body, out, depth + 1, mentions)
    if not bodies and mentions:
        out.append(f"text is fed into `{base}` from a pipe in a command that mentions aws; it cannot be verified")
    return True


def _script(w: _Word, out: list[str], mentions: bool, depth: int) -> None:
    if w.dynamic and mentions:
        out.append("a `sh -c` script built at run time ($VAR, $(...)) in a command that mentions aws cannot be "
                   "verified")
    _analyze(w.value, out, depth + 1, mentions)


def _inline_code(base: str, args: list[_Word]) -> bool:
    """`python -c`, `node -e`, `perl -e`, awk programs that run commands ...: code in the command line itself."""
    if base.endswith("awk"):                              # `aws ... | awk '{print $1}'` is fine; system() is not
        return any(re.search(r"\bsystem\s*\(|\|\s*getline|\|&|\|\s*\"", a.value) for a in args)
    if base == "deno" and args and args[0].value == "eval":
        return True
    skip = False
    for a in args:
        v = a.value
        if skip:
            skip = False
            continue
        if v in ("-W", "-X", "-r", "--require", "-I", "--import", "--loader"):
            skip = True
            continue
        if v == "--" or not v.startswith("-") or v == "-" or v.startswith("-m"):
            return False                                  # a script, a module or stdin follows
        flags = v.lstrip("-").split("=", 1)[0]
        if v.startswith("--"):
            if flags in ("eval", "print", "command", "exec"):
                return True
        elif base.startswith(("python", "pypy")):
            if "c" in flags:
                return True
        elif base in ("pwsh", "powershell"):
            if flags.lower() in ("c", "command", "e", "ec", "encodedcommand"):
                return True
        elif base == "php":
            if "r" in flags:
                return True
        elif "e" in flags or "E" in flags or flags in ("c", "p"):
            return True
    return False


def _git_text(args: list[_Word]) -> str:
    """git arguments without the commit/tag message (text, never run)."""
    kept, skip = [], False
    for a in args:
        v = a.value
        if skip:
            skip = False
        elif v in ("-m", "--message", "-F", "--file") or re.fullmatch(r"-[a-zA-Z]*m", v):
            skip = True
        elif not (v.startswith("--message=") or (v.startswith("-m") and len(v) > 2)):
            kept.append(v)
    return " ".join(kept)


def _env_redirect_problem(name: str) -> str:
    return f"sets {name}, which changes where or how every AWS CLI call is sent (like --endpoint-url or --ca-bundle)"


def _judge(cmd: _Cmd, out: list[str], mentions: bool, depth: int) -> None:
    words = cmd.words
    for w in words:                                       # decoded words too: env $'\x41WS_ENDPOINT_URL=...' aws ...
        m = _ENV_REDIRECT.match(w.value)
        if m:
            out.append(_env_redirect_problem(m.group(1)))
    k, wrapper, need, takes_value, chain = 0, "", 0, False, set()
    while k < len(words):                                 # skip NAME=value, wrappers and their options
        w = words[k]
        v = w.value
        if takes_value:
            takes_value = False                           # value of a wrapper option: `sudo -u root`, `nice -n 5`
        elif _is_assignment(w):
            name, _, value = v.partition("=")
            if _mentions(_normalize(value)):
                out.append(f"`{name}=...` stores `aws` in a variable; a later call through it cannot be verified")
        elif wrapper and need and not v.startswith("-"):
            need -= 1                                     # `timeout 30`, `aws-vault exec PROFILE`
        elif not w.dynamic and _base(w) in _WRAPPERS:
            wrapper, need = _base(w), _WRAPPER_POSITIONALS.get(_base(w), 0)
            chain.add(wrapper)
        elif wrapper and v == "--":
            need = 0
        elif wrapper and v[:1] in "-+" and len(v) > 1:
            takes_value = v in _WRAPPER_VALUE_OPTS.get(wrapper, ())
        else:
            break
        k += 1
    kind = "none"
    shell_read_bodies = False
    if k < len(words):
        w, rest = words[k], words[k + 1:]
        base = _base(w)
        kind = _program_kind(w, mentions)
        if kind == "aws" and chain & {"xargs", "parallel"}:
            out.append(f"`{'/'.join(sorted(chain & {'xargs', 'parallel'}))} aws` appends its input (service, "
                       "operation, options) to the aws command line; it cannot be verified")
        elif kind == "aws":
            _judge_aws(rest, out)
        elif kind == "find":                              # each -exec ... ; is a command of its own
            group: list[_Word] | None = None
            for a in rest + [None]:
                if group is None:
                    group = [] if a is not None and a.value in ("-exec", "-execdir", "-ok", "-okdir") else None
                elif a is None or (a.value in (";", "+") and not a.dynamic):
                    sub = _Cmd()
                    sub.words = group
                    _judge(sub, out, mentions, depth)
                    group = None
                else:
                    group.append(a)
        elif kind == "hidden":
            out.append(f"the program name {w.value!r} is built at run time (variable, glob or brace expansion) in a "
                       "command that may run aws; it cannot be verified")
        elif kind == "shell":
            shell_read_bodies = _judge_shell(base, rest, cmd, out, mentions, depth)
        elif kind == "eval":
            _analyze(" ".join(a.value for a in rest), out, depth + 1, mentions)
        elif kind in ("source", ".") and mentions and any(
                a.dynamic or a.value in ("-", "/dev/stdin") or a.value.startswith(("/dev/fd/", "/proc/")) for a in rest):
            out.append("commands are sourced from a pipe or process substitution in a command that mentions aws")
        elif kind == "iac":
            for a in rest:
                if a.value.startswith("-"):
                    continue
                if a.dynamic:
                    out.append(f"`{base}` with a subcommand taken from a variable cannot be verified")
                    break
                if _IAC_WRITES[base] is not None and a.value.lower() in _IAC_WRITES[base]:
                    out.append(f"`{base} {a.value}` changes cloud resources; run it yourself outside this session")
                    break
            else:
                if _IAC_WRITES[base] is None:
                    out.append(f"`{base}` sends signed AWS API requests (they can write); run it yourself outside "
                               "this session")
        elif kind == "interp" and mentions and _inline_code(base, rest):
            out.append(f"`{base}` runs inline code in a command that mentions aws; it cannot be verified")
        elif kind == "binder" and any(
                _is_aws(_base(a)) if base in _COPIERS else _mentions(_normalize(a.value)) for a in rest):
            out.append(f"`{base}` binds or copies `aws` under another name; a later call through it cannot be verified")
        elif kind == "git":
            _lenient(_git_text(rest), out)
    if kind not in ("aws", "shell", "eval", "inert", "git", "find"):
        _lenient(" ".join(a.value for a in words), out)   # a literal aws call anywhere in the arguments
    if not shell_read_bodies:
        for body in (h[3] for h in cmd.heredocs):
            if kind != "inert" or cmd.writes:             # `cat <<EOF > x.sh` writes a script; plain `cat` prints
                _lenient(body, out)
    for c in cmd.comments:
        _lenient(c, out)


def _analyze(text: str, out: list[str], depth: int = 0, outer_mentions: bool = False) -> None:
    """Full check of shell text (a command, a `bash -c` script, an eval string ...)."""
    if depth > _MAX_DEPTH:
        out.append("commands nested too deeply to verify")
        return
    norm = _normalize(text)
    mentions = outer_mentions or _mentions(norm)
    lexer = _Lexer(text, depth)
    try:
        lexer.parse()
        parsed = True
    except Exception:  # noqa: BLE001 - not shell syntax this hook can follow (prose, `case ... )`): see below
        parsed = False
    for cmd in lexer.cmds:                                # every complete command is judged strictly
        _judge(cmd, out, mentions, depth)
    if not parsed:                                        # the rest is still scanned for literal aws calls
        _lenient(text, out)
        if _ASSIGN_AWS.search(norm):
            out.append("stores `aws` in a variable (NAME=aws); a later call through it cannot be verified")
        for m, toks in _tails(norm, _IAC_WORD):
            verbs = _IAC_WRITES[m.group(1)]
            if verbs is None or any(t in verbs for t in toks):
                out.append(f"`{m.group(1)}` may change cloud resources here; run it yourself outside this session")
    if mentions and _UNVERIFIABLE.search(text):
        out.append("the command mentions `aws` and uses a construct that cannot be verified (eval, ${...}, base64, "
                   "pipe to a shell, python -c, brace expansion, xargs/-exec ...)")
    m = _ENV_REDIRECT.search(re.sub(r"[\"'\\]", "", text))      # also `"AWS_ENDPOINT_URL"=...` for env/export
    if m:
        out.append(_env_redirect_problem(m.group(1)))
    if _SIGV4.search(norm):
        out.append("`curl --aws-sigv4` sends signed AWS API requests (they can write); run it yourself outside this "
                   "session")
    if _CONTAINER.search(norm):
        out.append("runs the AWS CLI or mounts AWS credentials in a container; it cannot be verified")
    if _SDK.search(text) and _SDK_WRITE.search(text):
        out.append("AWS SDK code (boto3/aws-sdk) with a mutating call (delete_/put_/terminate_/...Command); run it "
                   "yourself outside this session")
    if ".aws/cli/alias" in norm:
        out.append("touches the AWS CLI alias file, which can redefine any `aws` command")


def violations(command: str) -> list[str]:
    """Why the shell text must be blocked (empty: allowed)."""
    out: list[str] = []
    _analyze(command, out)
    return list(dict.fromkeys(out))


def prose_violations(text: str) -> list[str]:
    """For descriptions and file contents: only a literal AWS CLI call counts."""
    out: list[str] = []
    _lenient(text, out)
    return list(dict.fromkeys(out))


# keys whose strings are prose or file data, never run: a tool description and the file tools' fields
_PROSE_KEYS = {"description", "content", "new_string", "old_string", "file_path", "notebook_path", "new_source",
               "path", "pattern", "glob"}


def _texts(value, prose: bool = False) -> list[tuple[str, bool]]:
    """Every string in tool_input (any key, any nesting) as (text, is_prose); an argv array also as one command."""
    if isinstance(value, str):
        return [(value, prose)]
    if isinstance(value, dict):
        return [t for k, v in value.items() for t in _texts(v, prose or k in _PROSE_KEYS)]
    if isinstance(value, list):
        texts = [t for v in value for t in _texts(v, prose)]
        if value and all(isinstance(v, str) for v in value):
            texts.append((" ".join(shlex.quote(v) for v in value), prose))
        return texts
    return []


def main() -> int:
    try:
        payload = json.loads(sys.stdin.buffer.read().decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("not a JSON object")
    except Exception as e:  # noqa: BLE001 - fail closed: the documented contract
        print(f"BLOCKED by aws-analyzer read-only hook: the hook input is not a UTF-8 JSON object "
              f"({type(e).__name__}).", file=sys.stderr)
        return 2
    try:
        bad: list[str] = []
        for text, prose in _texts(payload.get("tool_input")):
            bad += prose_violations(text) if prose else violations(text)
    except Exception as e:  # noqa: BLE001 - fail closed
        print(f"BLOCKED by aws-analyzer read-only hook: internal error while checking the command ({type(e).__name__}).", file=sys.stderr)
        return 2
    bad = list(dict.fromkeys(bad))
    if bad:
        note = f"\n(The analyzer guard could not be loaded: {_GUARD_ERROR}.)" if _GUARD_ERROR else ""
        print("BLOCKED by aws-analyzer read-only hook:\n  - " + "\n  - ".join(bad) +
              "\nThis project only runs read-only AWS calls through `python3 -m analyzer`. "
              "Make changes to your AWS account yourself, outside this session." + note, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
