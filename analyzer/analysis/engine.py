"""Stage 2: turn raw scan facts into projects, costs and findings. Fully offline."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import asdict
from datetime import datetime, timezone

from .. import SCHEMA_VERSION, __version__
from ..model import Resource
from . import coverage, cost, grouping, links, rules_compute, rules_data, rules_services
from .config import load_config
from .context import COSTED_TYPES, Analysis, ScanScope, potential_savings

SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def _scan_time(scan: dict) -> datetime:
    """Ages are measured at the moment of the scan, so re-analysing an old scan later gives the same answer."""
    try:
        return datetime.fromisoformat(scan["scanned_at"].replace("Z", "+00:00"))
    except (KeyError, ValueError, AttributeError):
        return datetime.now(timezone.utc)


def analyze(scan: dict, cfg: dict | None = None, *, now: datetime | None = None) -> dict:
    cfg = cfg or load_config()
    now = now or _scan_time(scan)
    # the scan runs collectors in parallel threads: sort so every later step (grouping ties, links) is deterministic
    resources = sorted((Resource(**r) for r in scan["resources"]), key=lambda r: r.key)

    gaps = scan.get("gaps", [])
    scope = ScanScope(scan.get("options"), scan.get("accounts"))
    links.resolve_links(resources, gaps, scope)
    source_stats = grouping.assign(resources, cfg)
    total_cost = cost.price_all(resources)

    a = Analysis(resources, cfg, now=now, accounts=scan.get("accounts", []), gaps=gaps, options=scan.get("options"))
    rules_compute.run(a)
    rules_data.run(a)
    rules_services.run(a)
    findings = sorted(a.findings, key=lambda f: (-f.savings_usd if f.in_total else 0, SEV_ORDER[f.severity], f.title))
    for f in findings:
        f.project = f.project or ""

    pricing = cost.load_pricing()["meta"]
    summary = build_summary(resources, findings, total_cost, source_stats, scan)
    return {
        "schema": SCHEMA_VERSION,
        "tool": "aws-analyzer",
        "version": __version__,
        "scanned_at": scan.get("scanned_at"),
        "analyzed_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scan_options": scan.get("options", {}),
        "accounts": scan.get("accounts", []),
        "gaps": scan.get("gaps", []),
        "audit": scan.get("audit", []),
        "cost_explorer": scan.get("cost_explorer", []),
        "pricing": pricing,
        "coverage": coverage.manifest(),
        "summary": summary,
        "projects": summary.pop("_projects"),
        "resources": [asdict(r) for r in resources],
        "findings": [asdict(f) for f in findings],
    }


# --------------------------------------------------------------------------- summary


def _norm_key(k: str) -> str:
    return re.sub(r"[-_ :./]", "", k.lower())


def build_summary(resources: list[Resource], findings, total_cost: float, source_stats: dict, scan: dict) -> dict:
    by_service: dict[str, dict] = defaultdict(lambda: {"count": 0, "est_monthly_usd": 0.0})
    by_type: dict[str, dict] = defaultdict(lambda: {"count": 0, "est_monthly_usd": 0.0})
    by_region: Counter = Counter()
    by_env: Counter = Counter()
    by_account: dict[str, dict] = defaultdict(lambda: {"count": 0, "est_monthly_usd": 0.0})
    projects: dict[str, dict] = {}
    for r in resources:
        for d, k in ((by_service, r.service), (by_type, r.type), (by_account, r.account)):
            d[k]["count"] += 1
            d[k]["est_monthly_usd"] += r.est_monthly_usd
        by_region[r.region] += 1
        by_env[r.env or "unknown"] += 1
        p = projects.setdefault(r.project, {"name": r.project, "resources": 0, "est_monthly_usd": 0.0, "savings_usd": 0.0,
                                            "envs": Counter(), "services": Counter(), "sources": Counter(), "regions": Counter(),
                                            "findings": 0})
        p["resources"] += 1
        p["est_monthly_usd"] += r.est_monthly_usd
        p["envs"][r.env or "unknown"] += 1
        p["services"][r.service] += 1
        p["sources"][r.project_source.split(":")[0] or "none"] += 1
        p["regions"][r.region] += 1
        p["findings"] += len(r.findings)

    best: dict[str, float] = {}
    for f in findings:
        if f.in_total:
            for k, v in f.breakdown.items():
                best[k] = max(best.get(k, 0.0), v)
    key_project = {r.key: r.project for r in resources}
    for k, v in best.items():
        if key_project.get(k) in projects:
            projects[key_project[k]]["savings_usd"] += v

    categories: dict[str, dict] = defaultdict(lambda: {"count": 0, "savings_usd": 0.0})
    severities: Counter = Counter()
    for f in findings:
        categories[f.category]["count"] += 1
        categories[f.category]["savings_usd"] += f.savings_usd if f.in_total else 0.0
        severities[f.severity] += 1

    taggable = [r for r in resources if not r.type.startswith("other:")]
    user_tagged = [r for r in taggable if any(not k.startswith("aws:") for k in r.tags)]
    project_tagged = [r for r in taggable if r.project_source.startswith(("tag", "rule"))]
    cov_by_service: dict[str, dict] = defaultdict(lambda: {"total": 0, "tagged": 0})
    for r in taggable:
        cov_by_service[r.service]["total"] += 1
        cov_by_service[r.service]["tagged"] += 1 if any(not k.startswith("aws:") for k in r.tags) else 0
    variants: dict[str, Counter] = defaultdict(Counter)
    key_counts: Counter = Counter()
    for r in resources:
        for k in r.tags:
            if not k.startswith("aws:"):
                variants[_norm_key(k)][k] += 1
                key_counts[k] += 1
    inconsistent = [{"variants": dict(c), "total": sum(c.values())} for c in variants.values() if len(c) > 1]

    proj_list = []
    for p in sorted(projects.values(), key=lambda x: (-x["est_monthly_usd"], x["name"].lower())):
        proj_list.append({**p, "est_monthly_usd": round(p["est_monthly_usd"], 2), "savings_usd": round(p["savings_usd"], 2),
                          "envs": dict(p["envs"]), "services": dict(p["services"]), "sources": dict(p["sources"]),
                          "regions": dict(p["regions"])})

    return {
        "resources": len(resources),
        "est_monthly_usd": round(total_cost, 2),
        "potential_savings_usd": potential_savings(findings),
        "potential_savings_confident_usd": potential_savings(findings, "medium"),
        "findings": len(findings),
        "severities": dict(severities),
        "categories": {k: {"count": v["count"], "savings_usd": round(v["savings_usd"], 2)} for k, v in categories.items()},
        "by_service": {k: {"count": v["count"], "est_monthly_usd": round(v["est_monthly_usd"], 2)} for k, v in sorted(by_service.items())},
        "by_type": {k: {"count": v["count"], "est_monthly_usd": round(v["est_monthly_usd"], 2)} for k, v in sorted(by_type.items())},
        "by_region": dict(by_region.most_common()),
        "by_env": dict(by_env.most_common()),
        "by_account": {k: {"count": v["count"], "est_monthly_usd": round(v["est_monthly_usd"], 2)} for k, v in by_account.items()},
        "grouping_sources": source_stats,
        "tags": {
            "taggable": len(taggable),
            "user_tagged": len(user_tagged),
            "user_tagged_pct": round(100 * len(user_tagged) / len(taggable), 1) if taggable else 0.0,
            "project_tagged": len(project_tagged),
            "project_tagged_pct": round(100 * len(project_tagged) / len(taggable), 1) if taggable else 0.0,
            "by_service": {k: dict(v) for k, v in sorted(cov_by_service.items())},
            "keys": dict(key_counts.most_common(60)),
            "inconsistent_keys": sorted(inconsistent, key=lambda x: -x["total"]),
        },
        "gaps": len(scan.get("gaps", [])),
        "unpriced": {"resources": sum(1 for r in resources if r.cost_conf == "none" and r.type in COSTED_TYPES),
                     "types": dict(Counter(r.attrs.get("instance_type") or r.attrs.get("instance_class") or r.attrs.get("node_type") or r.type
                                           for r in resources if r.cost_conf == "none" and r.type in COSTED_TYPES).most_common(12))},
        "_projects": proj_list,
    }
