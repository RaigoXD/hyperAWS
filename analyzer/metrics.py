"""CloudWatch utilisation (still stage 1; read-only ``cloudwatch get-metric-data``).

Only resources that matter for idle/waste detection are queried, in batches,
with one daily datapoint per day aggregated client-side. A metric is only
written to ``resource.metrics`` when the API call succeeded, so rules can tell
"zero activity" (sum = 0) from "unknown" (key missing).

Cost: GetMetricData is billed ~$0.01 per 1,000 metrics requested (cents per scan).
"""

from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from typing import Callable, NamedTuple

from .model import Resource

DAY = 86400
LONG_DAYS = 30        # low-frequency services (Lambda, SQS, logs ...)
BATCH = 300           # metric queries per API call


class Spec(NamedTuple):
    name: str                                   # key in resource.metrics
    namespace: str
    metric: str
    stat: str                                   # CloudWatch stat
    agg: str                                    # sum | avg | max | last (how daily points combine)
    dims: Callable[[Resource], list[tuple[str, str]] | None]
    long: bool = False                          # use LONG_DAYS window (else opts.metrics_days)
    only: Callable[[Resource], bool] = lambda r: True


def _lb_suffix(r: Resource) -> str | None:
    return r.arn.split("loadbalancer/")[1] if r.arn and "loadbalancer/" in r.arn else None


def _s3(name: str, storage_type: str, metric: str = "BucketSizeBytes") -> Spec:
    return Spec(name, "AWS/S3", metric, "Average", "last",
                lambda r: [("BucketName", r.rid), ("StorageType", storage_type)],
                only=lambda r: r.attrs.get("region_known", True))   # metrics live in the bucket's region


def _apigw_name(r: Resource) -> str:
    """API Gateway strips non-ASCII characters from the ApiName dimension; an all-non-ASCII name becomes the API id."""
    return (r.attrs.get("api_name") or r.name or "").encode("ascii", "ignore").decode() or r.rid


SPECS: dict[str, list[Spec]] = {
    "ec2:instance": [
        Spec("cpu_avg", "AWS/EC2", "CPUUtilization", "Average", "avg", lambda r: [("InstanceId", r.rid)],
             only=lambda r: r.state == "running"),
        Spec("cpu_max", "AWS/EC2", "CPUUtilization", "Maximum", "max", lambda r: [("InstanceId", r.rid)],
             only=lambda r: r.state == "running"),
        # an instance with idle CPU but steady traffic (proxy, NAT/VPN appliance, bastion) is not idle
        Spec("net_in", "AWS/EC2", "NetworkIn", "Sum", "sum", lambda r: [("InstanceId", r.rid)], only=lambda r: r.state == "running"),
        Spec("net_out", "AWS/EC2", "NetworkOut", "Sum", "sum", lambda r: [("InstanceId", r.rid)], only=lambda r: r.state == "running"),
    ],
    "ec2:nat-gateway": [
        # data processing is billed on BytesInFromSource (client -> NAT) plus BytesInFromDestination (return traffic)
        Spec("bytes_in", "AWS/NATGateway", "BytesInFromSource", "Sum", "sum", lambda r: [("NatGatewayId", r.rid)],
             only=lambda r: r.state == "available" and r.attrs.get("availability_mode", "zonal") != "regional"),
        Spec("bytes_return", "AWS/NATGateway", "BytesInFromDestination", "Sum", "sum", lambda r: [("NatGatewayId", r.rid)],
             only=lambda r: r.state == "available" and r.attrs.get("availability_mode", "zonal") != "regional"),
    ],
    "elbv2:lb": [
        Spec("requests", "AWS/ApplicationELB", "RequestCount", "Sum", "sum",
             lambda r: [("LoadBalancer", _lb_suffix(r))] if _lb_suffix(r) else None,
             only=lambda r: r.attrs.get("lb_type") == "application"),
        Spec("flows", "AWS/NetworkELB", "NewFlowCount", "Sum", "sum",
             lambda r: [("LoadBalancer", _lb_suffix(r))] if _lb_suffix(r) else None,
             only=lambda r: r.attrs.get("lb_type") == "network"),
    ],
    "elb:clb": [Spec("requests", "AWS/ELB", "RequestCount", "Sum", "sum", lambda r: [("LoadBalancerName", r.rid)])],
    "rds:instance": [
        Spec("connections_max", "AWS/RDS", "DatabaseConnections", "Maximum", "max",
             lambda r: [("DBInstanceIdentifier", r.rid)], only=lambda r: r.state == "available"),
        Spec("cpu_avg", "AWS/RDS", "CPUUtilization", "Average", "avg",
             lambda r: [("DBInstanceIdentifier", r.rid)], only=lambda r: r.state == "available"),
    ],
    "elasticache:cluster": [
        Spec("connections_max", "AWS/ElastiCache", "CurrConnections", "Maximum", "max",
             lambda r: [("CacheClusterId", r.rid)], only=lambda r: r.state == "available"),
        Spec("cpu_avg", "AWS/ElastiCache", "CPUUtilization", "Average", "avg",
             lambda r: [("CacheClusterId", r.rid)], only=lambda r: r.state == "available"),
    ],
    "lambda:function": [Spec("invocations", "AWS/Lambda", "Invocations", "Sum", "sum",
                             lambda r: [("FunctionName", r.rid)], long=True)],
    "dynamodb:table": [
        Spec("read_units", "AWS/DynamoDB", "ConsumedReadCapacityUnits", "Sum", "sum",
             lambda r: [("TableName", r.rid)], long=True),
        Spec("write_units", "AWS/DynamoDB", "ConsumedWriteCapacityUnits", "Sum", "sum",
             lambda r: [("TableName", r.rid)], long=True),
    ],
    "sqs:queue": [Spec("sent", "AWS/SQS", "NumberOfMessagesSent", "Sum", "sum",
                       lambda r: [("QueueName", r.rid)], long=True)],
    "sns:topic": [Spec("published", "AWS/SNS", "NumberOfMessagesPublished", "Sum", "sum",
                       lambda r: [("TopicName", r.rid)], long=True)],
    "apigw:rest-api": [Spec("requests", "AWS/ApiGateway", "Count", "Sum", "sum",
                            lambda r: [("ApiName", _apigw_name(r))], long=True)],
    "apigw:http-api": [Spec("requests", "AWS/ApiGateway", "Count", "Sum", "sum",
                            lambda r: [("ApiId", r.rid)], long=True)],
    "cloudfront:distribution": [Spec("requests", "AWS/CloudFront", "Requests", "Sum", "sum",
                                     lambda r: [("DistributionId", r.rid), ("Region", "Global")], long=True)],
    "logs:log-group": [Spec("incoming_bytes", "AWS/Logs", "IncomingBytes", "Sum", "sum",
                            lambda r: [("LogGroupName", r.rid)], long=True)],
    "sfn:state-machine": [Spec("executions", "AWS/States", "ExecutionsStarted", "Sum", "sum",
                               lambda r: [("StateMachineArn", r.arn)] if r.arn else None, long=True)],
    "ecs:service": [Spec("cpu_avg", "AWS/ECS", "CPUUtilization", "Average", "avg",
                         lambda r: [("ClusterName", r.attrs.get("cluster")), ("ServiceName", r.name)],
                         only=lambda r: (r.attrs.get("desired") or 0) > 0)],
    "s3:bucket": [
        _s3("bytes_standard", "StandardStorage"), _s3("bytes_standard_ia", "StandardIAStorage"),
        _s3("bytes_onezone_ia", "OneZoneIAStorage"), _s3("bytes_it_fa", "IntelligentTieringFAStorage"),
        _s3("bytes_it_ia", "IntelligentTieringIAStorage"), _s3("bytes_it_aia", "IntelligentTieringAIAStorage"),
        _s3("bytes_it_aa", "IntelligentTieringAAStorage"), _s3("bytes_it_daa", "IntelligentTieringDAAStorage"),
        _s3("bytes_glacier_ir", "GlacierInstantRetrievalStorage"), _s3("bytes_glacier", "GlacierStorage"),
        _s3("bytes_deep_archive", "DeepArchiveStorage"), _s3("bytes_reduced_redundancy", "ReducedRedundancyStorage"),
        _s3("objects", "AllStorageTypes", "NumberOfObjects"),
    ],
}
S3_WINDOW_DAYS = 3  # storage metrics are daily; the latest point is what we want


def _aggregate(agg: str, points: list[tuple[str, float]]) -> float | None:
    if agg == "sum":
        return float(sum(v for _t, v in points))   # no datapoints == no activity == 0
    if not points:
        return None
    if agg == "avg":
        return sum(v for _t, v in points) / len(points)
    if agg == "max":
        return max(v for _t, v in points)
    if agg == "last":
        return max(points, key=lambda p: p[0])[1]
    raise ValueError(agg)


def _plan(resources: list[Resource], default_days: int):
    """-> {(call_region, window_days): [(Resource, Spec, dims), ...]}"""
    plan: dict[tuple[str, int], list] = {}
    for r in resources:
        for spec in SPECS.get(r.type, []):
            if not spec.only(r):
                continue
            dims = spec.dims(r)
            if not dims or any(not v for _n, v in dims):
                continue
            days = S3_WINDOW_DAYS if r.type == "s3:bucket" else (LONG_DAYS if spec.long else default_days)
            region = "us-east-1" if r.type == "cloudfront:distribution" else r.region
            plan.setdefault((region, days), []).append((r, spec, dims))
    return plan


def _batches(items: list):
    """Pack queries into batches of at most BATCH, keeping all queries of one resource together.

    (Decisions such as "this S3 bucket has no storage metrics at all" are made per batch, so a resource
    split across two API calls would be misjudged.)
    """
    groups: list[list] = []
    for it in items:
        if groups and groups[-1][0][0] is it[0]:
            groups[-1].append(it)
        else:
            groups.append([it])
    cur: list = []
    for g in groups:
        if cur and len(cur) + len(g) > BATCH:
            yield cur
            cur = []
        cur += g
    if cur:
        yield cur


def _older_than(r: Resource, days: int, now: datetime) -> bool:
    if not r.created:
        return False
    try:
        created = datetime.fromisoformat(r.created.replace("Z", "+00:00"))
    except ValueError:
        return False
    return now - created > timedelta(days=days)


def collect_metrics(cli, account, partition, resources, regions, opts, gaps, lock) -> None:
    from .scan import Ctx  # local import: scan imports this module lazily

    plan = _plan(resources, opts.metrics_days)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    jobs = []
    for (region, days), items in plan.items():
        for batch in _batches(items):
            jobs.append((region, days, batch))
    if not jobs:
        return

    def run(job):
        region, days, items = job
        ctx = Ctx(cli, account, region, partition=partition, gaps=gaps, lock=lock)
        queries = [{"Id": f"m{n}", "MetricStat": {
            "Metric": {"Namespace": spec.namespace, "MetricName": spec.metric,
                       "Dimensions": [{"Name": n_, "Value": v} for n_, v in dims]},
            "Period": DAY, "Stat": spec.stat}, "ReturnData": True} for n, (_r, spec, dims) in enumerate(items)]
        start = (now - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        end = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        # the queries hold resource names, but as a JSON list that always starts with '[': never readable as a CLI option
        resp = ctx.aws("cloudwatch", "get-metric-data",
                       ["--metric-data-queries", json.dumps(queries, separators=(",", ":")),
                        "--start-time", start, "--end-time", end])
        if not resp:  # failed (gap recorded) or dry run
            return
        # The CLI concatenates pages, so one Id can appear several times: merge them. A series is only trusted when AWS
        # says Complete; missing, Forbidden, InternalError or PartialData-only means "unknown", never "zero".
        merged: dict[str, dict] = {}
        for m in resp.get("MetricDataResults", []):
            e = merged.setdefault(m["Id"], {"ts": [], "vals": [], "status": []})
            e["ts"] += m.get("Timestamps", [])
            e["vals"] += m.get("Values", [])
            e["status"].append(m.get("StatusCode", "Complete"))
        got: dict[str, int] = {}
        incomplete: set[str] = set()
        for n, (r, spec, _dims) in enumerate(items):
            m = merged.get(f"m{n}")
            if m is None or "Complete" not in m["status"]:
                incomplete.add(r.key)
                continue
            pts = list(zip(m["ts"], m["vals"]))
            val = _aggregate(spec.agg, pts)
            if val is not None:
                got[r.key] = got.get(r.key, 0) + 1
                with lock:
                    r.metrics[spec.name] = round(val, 4)
                    r.metrics.setdefault("_days", {})[spec.name] = days
        # S3 emits no storage metrics at all for an empty (or very new) bucket.
        for r in {id(r): r for r, _s, _d in items if r.type == "s3:bucket"}.values():
            if r.key not in got and r.key not in incomplete and _older_than(r, 3, now):
                with lock:
                    r.metrics.update({"objects": 0.0, "bytes_standard": 0.0})

    with ThreadPoolExecutor(max_workers=min(opts.workers, len(jobs))) as ex:
        list(ex.map(run, jobs))
