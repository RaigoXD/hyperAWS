"""The complete, explicit list of AWS CLI operations this tool may ever run.

This file is the single source of truth for read-only enforcement:

* ``awscli.py`` refuses to start a process for anything not listed here.
* ``policy.py`` generates the least-privilege IAM policy from this list.
* ``audit.py`` statically checks that the code only calls pairs listed here.

Adding an entry is a deliberate, reviewable act. Every entry must be a pure
read (describe/list/get) and must not return secrets or object data. Where an
operation's answer does contain a secret field, the caller must project it away
with ``--query`` (listed in ``QUERY_REQUIRED``; awscli.py refuses such a call
without one and audit.py checks every call site), so the secret never reaches
this process.
"""

from __future__ import annotations

import re
from typing import NamedTuple

# Groups let optional features be granted separately in IAM.
CORE = "core"        # inventory (always on)
METRICS = "metrics"  # CloudWatch utilisation (disable with --no-metrics)
COST = "cost"        # Cost Explorer (only with --cost-explorer, billed per call)


class Op(NamedTuple):
    service: str
    op: str
    group: str = CORE
    iam: str | None = None  # explicit IAM action when it can't be derived


# CLI service name -> IAM service prefix, when they differ.
SERVICE_IAM_PREFIX = {
    "s3api": "s3",
    "elbv2": "elasticloadbalancing",
    "elb": "elasticloadbalancing",
    "stepfunctions": "states",
    "resourcegroupstaggingapi": "tag",
    "apigatewayv2": "apigateway",
}

# Operations that need no IAM permission at all.
NO_IAM = {("sts", "get-caller-identity")}

# fmt: off
OPERATIONS: list[Op] = [
    Op("sts", "get-caller-identity"),

    # --- compute + network core -------------------------------------------
    Op("ec2", "describe-regions"),
    Op("ec2", "describe-instances"),
    Op("ec2", "describe-volumes"),
    Op("ec2", "describe-snapshots"),
    Op("ec2", "describe-images"),
    Op("ec2", "describe-addresses"),
    Op("ec2", "describe-network-interfaces"),
    Op("ec2", "describe-nat-gateways"),
    Op("ec2", "describe-vpcs"),
    Op("ec2", "describe-subnets"),
    Op("ec2", "describe-route-tables"),
    Op("ec2", "describe-internet-gateways"),
    Op("ec2", "describe-vpc-endpoints"),
    Op("ec2", "describe-security-groups"),
    Op("elbv2", "describe-load-balancers"),
    Op("elbv2", "describe-target-groups"),
    Op("elbv2", "describe-target-health"),
    Op("elb", "describe-load-balancers"),

    # --- data stores -------------------------------------------------------
    Op("rds", "describe-db-instances"),
    Op("rds", "describe-db-clusters"),
    Op("rds", "describe-db-snapshots"),
    Op("rds", "describe-db-cluster-snapshots"),
    Op("dynamodb", "list-tables"),
    Op("dynamodb", "describe-table"),
    Op("s3api", "list-buckets", iam="s3:ListAllMyBuckets"),
    Op("s3api", "get-bucket-location"),
    Op("s3api", "get-bucket-tagging"),
    Op("s3api", "get-bucket-lifecycle-configuration", iam="s3:GetLifecycleConfiguration"),
    Op("s3api", "get-bucket-versioning"),
    Op("s3api", "get-public-access-block", iam="s3:GetBucketPublicAccessBlock"),
    Op("elasticache", "describe-cache-clusters"),
    Op("elasticache", "describe-replication-groups"),

    # --- serverless + containers ------------------------------------------
    Op("lambda", "list-functions"),              # always called with --query: never Environment (env vars)
    Op("lambda", "list-event-source-mappings"),  # always called with --query: ARNs, state, batch size only
    Op("apigateway", "get-rest-apis", iam="apigateway:GET"),
    Op("apigatewayv2", "get-apis", iam="apigateway:GET"),
    Op("sqs", "list-queues"),
    Op("sqs", "get-queue-attributes"),
    Op("sns", "list-topics"),
    Op("sns", "list-subscriptions"),
    Op("stepfunctions", "list-state-machines"),
    Op("ecs", "list-clusters"),
    Op("ecs", "describe-clusters"),
    Op("ecs", "list-services"),
    Op("ecs", "describe-services"),
    Op("ecs", "describe-task-definition"),  # always called with --query: cpu/memory/arch and role ARNs only
    Op("ecr", "describe-repositories"),
    Op("ecr", "get-lifecycle-policy"),
    Op("ecr", "describe-images"),
    Op("eks", "list-clusters"),
    Op("eks", "describe-cluster"),               # always called with --query: never connectorConfig or certificateAuthority
    Op("eks", "describe-cluster-versions"),
    Op("eks", "list-nodegroups"),
    Op("eks", "describe-nodegroup"),
    Op("eks", "list-fargate-profiles"),

    # --- edge, ops, security ----------------------------------------------
    Op("cloudfront", "list-distributions"),      # always called with --query: never origin CustomHeaders (shared secrets)
    Op("route53", "list-hosted-zones"),
    Op("route53", "list-resource-record-sets"),
    Op("logs", "describe-log-groups"),
    Op("kms", "list-keys"),
    Op("kms", "describe-key"),
    Op("kms", "list-aliases"),
    Op("iam", "list-users"),
    Op("iam", "list-access-keys"),
    Op("iam", "get-access-key-last-used"),
    Op("iam", "list-roles"),
    Op("iam", "get-role"),

    # --- tags catch-all (also finds resources we have no collector for) ---
    Op("resourcegroupstaggingapi", "get-resources"),

    # --- optional: CloudWatch utilisation ----------------------------------
    Op("cloudwatch", "get-metric-data", group=METRICS),

    # --- optional: Cost Explorer (billed ~$0.01 per call) ------------------
    Op("ce", "get-cost-and-usage", group=COST),
    Op("ce", "get-rightsizing-recommendation", group=COST),
]
# fmt: on

ALLOWED: dict[tuple[str, str], Op] = {(o.service, o.op): o for o in OPERATIONS}

# Operations whose full answer holds a secret (or more than the caller needs): every call must pass a --query
# projection. awscli.py refuses such a call without one before any process starts, and audit-readonly checks that
# each call site passes "--query" literally. (The projection's content is reviewed with the collector.)
QUERY_REQUIRED = frozenset({
    ("lambda", "list-functions"),               # Environment.Variables
    ("lambda", "list-event-source-mappings"),   # only ARNs, state and batch size are needed
    ("ecs", "describe-task-definition"),        # container environment, secrets references
    ("eks", "describe-cluster"),                # connectorConfig.activationCode, certificateAuthority
    ("cloudfront", "list-distributions"),       # origin CustomHeaders (often a shared secret with the origin)
})

# Defence in depth: even an allowlisted op must look like a read ...
READ_VERB = re.compile(r"^(describe|list|get|batch-get)-[a-z0-9-]+$")

# ... and must not be one of the "get-*" calls that hand back credentials,
# secrets, presigned URLs or object data. This applies even if somebody adds
# such an op to OPERATIONS by mistake.
DENY_OP = re.compile(
    r"(secret|token|password|credential|session|login|federation|presign"
    r"|object|parameter|console-output|console-screenshot)"
)
DENY_EXACT = {
    ("lambda", "get-function"),        # returns a presigned URL to the code
    ("lambda", "get-layer-version"),   # same
    ("iam", "get-credential-report"),
    ("iam", "generate-credential-report"),
}

# Every global option of AWS CLI v2 (the "options" of awscli/data/cli.json in the installed CLI, 2.33).
# The CLI's argparse also accepts any unambiguous PREFIX of them (--e is --endpoint-url, --d is --debug),
# anywhere on the command line, so the guard treats every prefix as the option itself.
CLI_GLOBAL_FLAGS = {
    "--ca-bundle", "--cli-auto-prompt", "--cli-binary-format", "--cli-connect-timeout", "--cli-read-timeout",
    "--color", "--debug", "--endpoint-url", "--no-cli-auto-prompt", "--no-cli-pager", "--no-paginate",
    "--no-sign-request", "--no-verify-ssl", "--output", "--profile", "--query", "--region", "--version",
}
# Global options a caller may pass: they only shape the answer (--query selects fields, and is how secret
# fields are kept out of the process, see edge.py/serverless.py/containers.py).
SAFE_GLOBAL_FLAGS = {"--query", "--no-paginate", "--cli-binary-format"}

# Flags awscli.py owns; collectors may not pass them, also not abbreviated (e.g. --endpoint-url could
# redirect signed requests to another host). The last three are per-operation options that read a whole
# request from a file or print a skeleton instead of calling AWS.
FORBIDDEN_FLAGS = (CLI_GLOBAL_FLAGS - SAFE_GLOBAL_FLAGS) | {
    "--cli-input-json", "--cli-input-yaml", "--generate-cli-skeleton",
}

# Argument values the AWS CLI itself expands: file:// and fileb:// read local files into the request. That
# holds for a value after a space (--x file://...), after '=' (--x=file://...) and for a shorthand key
# written key@=file://... (AWS CLI v2 loads that value from the file too).
LOCAL_FILE_PREFIXES = ("file://", "fileb://")

# Actions that are only safe when scoped to specific resources in the generated IAM policy.
# apigateway:GET on "*" would also allow reading API key values and stage variables; the two list
# calls we make only need the collection paths.
RESOURCE_SCOPES = {
    "apigateway:GET": ["arn:aws:apigateway:*::/restapis", "arn:aws:apigateway:*::/apis"],
}


def default_iam_action(op: Op) -> str | None:
    """Derive the IAM action for an operation (None if none is needed)."""
    if (op.service, op.op) in NO_IAM:
        return None
    if op.iam:
        return op.iam
    prefix = SERVICE_IAM_PREFIX.get(op.service, op.service)
    camel = "".join(p.capitalize() for p in op.op.split("-"))
    return f"{prefix}:{camel}"


def iam_actions(groups: set[str] | None = None) -> list[str]:
    """Sorted, de-duplicated IAM actions for the given groups (default: all)."""
    out = {
        a
        for o in OPERATIONS
        if (groups is None or o.group in groups)
        for a in [default_iam_action(o)]
        if a
    }
    return sorted(out)
