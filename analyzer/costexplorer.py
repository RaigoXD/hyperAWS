"""Optional real spend from Cost Explorer (``--cost-explorer``). Read-only, but BILLED by AWS.

Cost Explorer charges about $0.01 per API request. This stage makes exactly three:
cost by service, cost by project tag, and EC2 rightsizing recommendations.
"""

from __future__ import annotations

import sys
from collections import Counter
from datetime import datetime, timedelta, timezone

CALLS = 3
DEFAULT_TAG_KEYS = ["Project", "project", "Application", "application", "App", "app", "Service", "Team", "Environment"]


def _money(x) -> float:
    try:
        return float(x)
    except (TypeError, ValueError):
        return 0.0


def pick_tag_key(resources) -> str:
    """The cost-allocation tag key most worth grouping by: the first default key that exists on resources."""
    seen = Counter(k for r in resources for k in r.tags)
    for k in DEFAULT_TAG_KEYS:
        if seen.get(k):
            return k
    return "Project"


def collect(cli, account, opts, gaps, lock, resources=()) -> dict:
    from .scan import Ctx  # local import: scan imports this module lazily

    ctx = Ctx(cli, account, "us-east-1", gaps=gaps, lock=lock)
    if not opts.quiet:
        print(f"[cost explorer] {CALLS} billed API calls (about ${CALLS * 0.01:.2f})", file=sys.stderr)
    end = datetime.now(timezone.utc).date()
    start = end - timedelta(days=30)
    period = f"Start={start.isoformat()},End={end.isoformat()}"
    base = ["--time-period", period, "--granularity", "MONTHLY", "--metrics", "UnblendedCost"]

    svc = ctx.aws("ce", "get-cost-and-usage", [*base, "--group-by", "Type=DIMENSION,Key=SERVICE"])
    if not svc.get("ResultsByTime"):
        return {"error": "no data (Cost Explorer not enabled for this account, or access denied: see coverage gaps)",
                "period": {"start": start.isoformat(), "end": end.isoformat()}, "account": account}
    by_service: Counter = Counter()
    for chunk in svc["ResultsByTime"]:
        for g in chunk.get("Groups", []):
            by_service[g["Keys"][0]] += _money(g["Metrics"]["UnblendedCost"]["Amount"])

    tag_key = pick_tag_key(resources)
    tagged = ctx.aws("ce", "get-cost-and-usage", [*base, "--group-by", f"Type=TAG,Key={tag_key}"])
    by_tag: Counter = Counter()
    for chunk in tagged.get("ResultsByTime", []):
        for g in chunk.get("Groups", []):
            name = g["Keys"][0].split("$", 1)[-1]
            by_tag[name] += _money(g["Metrics"]["UnblendedCost"]["Amount"])

    rs = ctx.aws("ce", "get-rightsizing-recommendation", ["--service", "AmazonEC2"])
    rightsizing = []
    for rec in rs.get("RightsizingRecommendations", []):
        cur = rec.get("CurrentInstance", {})
        details = (cur.get("ResourceDetails") or {}).get("EC2ResourceDetails", {})
        kind = rec.get("RightsizingType", "")
        if kind == "TERMINATE":
            saving = _money((rec.get("TerminateRecommendationDetail") or {}).get("EstimatedMonthlySavings"))
            target = "terminate"
        else:
            targets = (rec.get("ModifyRecommendationDetail") or {}).get("TargetInstances") or [{}]
            saving = _money(targets[0].get("EstimatedMonthlySavings"))
            target = ((targets[0].get("ResourceDetails") or {}).get("EC2ResourceDetails") or {}).get("InstanceType", "")
        rightsizing.append({"id": cur.get("ResourceId", ""), "action": kind.title(), "current": details.get("InstanceType", ""),
                            "recommended": target, "saving": round(saving, 2)})
    rightsizing.sort(key=lambda x: -x["saving"])

    return {
        "account": account,
        "period": {"start": start.isoformat(), "end": end.isoformat()},
        "total": round(sum(by_service.values()), 2),
        "by_service": [{"name": k, "usd": round(v, 2)} for k, v in by_service.most_common() if v >= 0.005],
        "by_tag": {"key": tag_key, "groups": [{"name": k, "usd": round(v, 2)} for k, v in by_tag.most_common() if v >= 0.005]},
        "rightsizing": rightsizing,
        "calls": CALLS,
    }
