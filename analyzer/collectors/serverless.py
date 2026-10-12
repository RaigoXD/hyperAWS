"""Lambda, API Gateway, SQS, SNS, Step Functions.

Lambda's ``Environment`` (env vars) never even reaches this process: a ``--query``
on list-functions keeps only the fields read below, and attrs are a whitelist on
top. The same goes for event source mappings (a ``--query`` keeps only ARNs,
state and batch size: no filter criteria, no Kafka endpoints) and SNS
subscriptions (only SQS/Lambda ARNs are kept, never e-mail addresses, phone
numbers or webhook URLs).
"""

from __future__ import annotations

import json
import re

from ..model import Resource, to_iso
from ..scan import Failed

NAME = "serverless"
GROUP = "serverless"
SCOPE = "regional"

_SQS_ATTRS = ["QueueArn", "CreatedTimestamp", "ApproximateNumberOfMessages",
              "ApproximateNumberOfMessagesNotVisible", "FifoQueue", "MessageRetentionPeriod", "RedrivePolicy"]
# the CLI paginates first and applies --query once to the merged result, so the answer is a plain list
_ESM_QUERY = ("EventSourceMappings[].{src:EventSourceArn,fn:FunctionArn,state:State,batch:BatchSize,"
              "fail:DestinationConfig.OnFailure.Destination}")
# same shape as the API answer, minus Environment (env vars are often secrets) and everything else not read below;
# projected keys are kept as null when missing, hence the `or` defaults in _lambdas
_FUNCTIONS_QUERY = ("{Functions:Functions[].{FunctionName:FunctionName,FunctionArn:FunctionArn,Runtime:Runtime,Role:Role,"
                    "MemorySize:MemorySize,Timeout:Timeout,CodeSize:CodeSize,LastModified:LastModified,State:State,"
                    "PackageType:PackageType,Architectures:Architectures,EphemeralStorage:EphemeralStorage,"
                    "VpcConfig:VpcConfig}}")
MAX_EVENT_SOURCES = 20
MAX_SUBSCRIBERS = 50
# SNS endpoints we may keep: SQS queue / Lambda function ARNs. Anything else (e-mail, SMS, HTTP(S) URLs that often
# carry tokens, mobile push, Firehose ...) is personal data or a secret and is dropped.
_SUBSCRIBER_ARN = re.compile(r"^arn:aws[\w-]*:(sqs|lambda):[a-z0-9-]+:\d{12}:[\w.:-]+$")


def collect(ctx) -> list[Resource]:
    return _lambdas(ctx) + _api_gateways(ctx) + _sqs(ctx) + _sns(ctx) + _state_machines(ctx)


def _event_sources(ctx) -> dict[str, list[dict]] | None:
    """Event source mappings (SQS, DynamoDB/Kinesis streams, MSK ...) by function name; None if they could not be read."""
    rows = ctx.aws("lambda", "list-event-source-mappings", ["--query", _ESM_QUERY])
    if isinstance(rows, Failed):
        return None
    by_fn: dict[str, list[dict]] = {}
    for m in rows if isinstance(rows, list) else []:      # null / {} = the API answered: no mappings
        parts = (m.get("fn") or "").split(":") if isinstance(m, dict) else []
        if len(parts) < 7 or parts[5] != "function":
            continue
        # arn:aws:lambda:<region>:<acct>:function:<name>[:<alias or version>] -> <name>
        by_fn.setdefault(parts[6], []).append({"arn": m.get("src"), "state": m.get("state"),
                                               "batch": m.get("batch"), "on_failure": m.get("fail")})
    return by_fn


def _lambdas(ctx) -> list[Resource]:
    out = []
    functions = (ctx.aws("lambda", "list-functions", ["--query", _FUNCTIONS_QUERY]) or {}).get("Functions") or []
    sources = _event_sources(ctx) if functions else {}
    for f in functions:
        name = f["FunctionName"]
        vpc = f.get("VpcConfig") or {}
        arch = (f.get("Architectures") or ["x86_64"])[0]
        r = ctx.new("lambda:function", name, name=name, state=f.get("State") or "Active",
                    created=None, arn=f.get("FunctionArn"),
                    attrs={"runtime": f.get("Runtime"), "memory_mb": f.get("MemorySize"),
                           "timeout_s": f.get("Timeout"), "code_size": f.get("CodeSize"), "arch": arch,
                           "package_type": f.get("PackageType") or "Zip", "last_modified": to_iso(f.get("LastModified")),
                           "ephemeral_mb": (f.get("EphemeralStorage") or {}).get("Size"),
                           "vpc": vpc.get("VpcId") or None, "subnet_ids": vpc.get("SubnetIds", []),
                           "sg_ids": vpc.get("SecurityGroupIds", []),
                           "role": (f.get("Role") or "").split("/")[-1] or None,
                           # what triggers it (queues, streams): an unreadable list is "unknown", never "none"
                           "event_sources": (sources or {}).get(name, [])[:MAX_EVENT_SOURCES],
                           "event_sources_known": sources is not None})
        for s in vpc.get("SubnetIds", []):
            r.link(ctx.key("ec2:subnet", s), "in-subnet")
        for g in vpc.get("SecurityGroupIds", []):
            r.link(ctx.key("ec2:security-group", g), "uses-sg")
        out.append(r)
    return out


def _api_gateways(ctx) -> list[Resource]:
    out = []
    for a in ctx.aws("apigateway", "get-rest-apis").get("items", []):
        out.append(ctx.new("apigw:rest-api", a["id"], name=a.get("name", a["id"]), state="",
                           created=to_iso(a.get("createdDate")),
                           arn=f"arn:{ctx.partition}:apigateway:{ctx.region}::/restapis/{a['id']}",
                           attrs={"api_name": a.get("name"),
                                  "endpoint_types": (a.get("endpointConfiguration") or {}).get("types", [])}))
    for a in ctx.aws("apigatewayv2", "get-apis").get("Items", []):
        # get-apis returns HTTP and WEBSOCKET APIs; only HTTP APIs publish the `Count` metric the idle rule uses
        kind = "apigw:websocket-api" if a.get("ProtocolType") == "WEBSOCKET" else "apigw:http-api"
        out.append(ctx.new(kind, a["ApiId"], name=a.get("Name", a["ApiId"]), state="",
                           created=to_iso(a.get("CreatedDate")),
                           arn=f"arn:{ctx.partition}:apigateway:{ctx.region}::/apis/{a['ApiId']}",
                           attrs={"protocol": a.get("ProtocolType"), "endpoint": a.get("ApiEndpoint")}))
    return out


def _sqs(ctx) -> list[Resource]:
    urls = ctx.aws("sqs", "list-queues").get("QueueUrls", [])

    def attrs(u):
        return u, ctx.aws("sqs", "get-queue-attributes",
                          [f"--queue-url={u}", "--attribute-names", *_SQS_ATTRS]).get("Attributes", {})

    out = []
    for url, a in ctx.map(attrs, urls):
        name = url.rstrip("/").split("/")[-1]
        out.append(ctx.new("sqs:queue", name, name=name, state="",
                           created=to_iso(int(a["CreatedTimestamp"])) if a.get("CreatedTimestamp") else None,
                           arn=a.get("QueueArn") or ctx.arn("sqs", name),
                           attrs={"fifo": a.get("FifoQueue") == "true",
                                  "messages": int(a.get("ApproximateNumberOfMessages", 0)),
                                  "messages_in_flight": int(a.get("ApproximateNumberOfMessagesNotVisible", 0)),
                                  "retention_s": int(a.get("MessageRetentionPeriod", 0)),
                                  # this queue's dead-letter target: empty dead-letter queues are healthy, not idle
                                  "redrive_target": _redrive_target(a.get("RedrivePolicy"))}))
    return out


def _redrive_target(policy: str | None) -> str | None:
    try:
        return json.loads(policy).get("deadLetterTargetArn") if policy else None
    except (ValueError, AttributeError):
        return None


def _sns(ctx) -> list[Resource]:
    topics = ctx.aws("sns", "list-topics").get("Topics", [])
    subs: dict[str, int] = {}
    targets: dict[str, set[str]] = {}
    for s in ctx.aws("sns", "list-subscriptions").get("Subscriptions", []):
        topic = s.get("TopicArn", "")
        subs[topic] = subs.get(topic, 0) + 1
        # only SQS/Lambda ARNs are kept (for the topic -> subscriber relation); e-mail addresses, phone numbers,
        # HTTP(S) URLs and other endpoints never leave this function
        proto, endpoint = s.get("Protocol"), s.get("Endpoint")
        m = _SUBSCRIBER_ARN.fullmatch(endpoint) if proto in ("sqs", "lambda") and isinstance(endpoint, str) else None
        if m and m.group(1) == proto:
            targets.setdefault(topic, set()).add(endpoint)
    out = []
    for t in topics:
        arn = t["TopicArn"]
        name = arn.split(":")[-1]
        out.append(ctx.new("sns:topic", name, name=name, state="", arn=arn,
                           attrs={"subscriptions": subs.get(arn, 0), "fifo": name.endswith(".fifo"),
                                  "subscriber_arns": sorted(targets.get(arn, ()))[:MAX_SUBSCRIBERS]}))
    return out


def _state_machines(ctx) -> list[Resource]:
    out = []
    for m in ctx.aws("stepfunctions", "list-state-machines").get("stateMachines", []):
        out.append(ctx.new("sfn:state-machine", m["name"], name=m["name"], state="",
                           created=to_iso(m.get("creationDate")), arn=m.get("stateMachineArn"),
                           attrs={"sm_type": m.get("type")}))
    return out
