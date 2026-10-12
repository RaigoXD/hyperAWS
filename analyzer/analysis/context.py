"""Shared state for analysis rules + the Finding model."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable

from ..model import Resource

SEVERITIES = ("high", "medium", "low", "info")
CATEGORIES = ("unused", "rightsizing", "cost-insight", "security", "hygiene")


# AWS CLI service -> the collector that reads it (to know what a --services-limited scan did NOT look at)
SERVICE_COLLECTOR = {
    "ec2": "ec2_net", "elbv2": "elb", "elb": "elb", "rds": "rds", "dynamodb": "dynamodb", "s3api": "s3",
    "elasticache": "elasticache", "lambda": "serverless", "apigateway": "serverless", "apigatewayv2": "serverless",
    "sqs": "serverless", "sns": "serverless", "stepfunctions": "serverless", "ecs": "containers", "ecr": "containers",
    "eks": "containers", "cloudfront": "edge", "route53": "edge", "logs": "ops", "kms": "ops", "iam": "iam",
    "resourcegroupstaggingapi": "tagging",
}
# types whose cost is a list-price estimate: an unknown price means savings are unknown, not zero
COSTED_TYPES = {"ec2:instance", "rds:instance", "elasticache:cluster", "ec2:volume", "ec2:nat-gateway", "elbv2:lb", "elb:clb"}


class ScanScope:
    """What the scan actually looked at. Anything outside it is *unknown*, never 'missing'."""

    def __init__(self, options: dict | None, accounts: list[dict] | None):
        options = options or {}
        self.regions = {r for a in (accounts or []) for r in a.get("regions", [])}
        services = options.get("services")
        self.unselected: set[str] = set()
        if services and services != "all":
            from .. import collectors            # local import: collectors import analyzer.scan
            wanted = {str(s).strip().lower() for s in services}
            self.unselected = {c.NAME for c in collectors.ALL
                               if not (c.NAME in wanted or c.GROUP in wanted or c.GROUP == "meta")}
        self.metrics = options.get("metrics", True)

    def service_blind(self, service: str) -> bool:
        """True if the collector that reads this CLI service was not part of the scan."""
        return SERVICE_COLLECTOR.get(service) in self.unselected

    def region_scanned(self, region: str) -> bool:
        return not self.regions or region == "global" or region in self.regions


@dataclass
class Finding:
    id: str
    rule: str
    category: str                    # unused | rightsizing | cost-insight | security | hygiene
    severity: str                    # high | medium | low | info
    confidence: str                  # high | medium | low
    title: str
    detail: str
    advice: str
    resources: list[str]             # resource keys (may be empty for account-level findings)
    account: str = ""
    region: str = ""
    service: str = ""
    project: str = ""
    savings_usd: float = 0.0         # per month
    basis: str = ""
    effort: str = "low"              # low | medium | high
    risk: str = "low"                # low | medium | high
    breakdown: dict[str, float] = field(default_factory=dict)   # resource key -> savings
    in_total: bool = True            # counted in the non-overlapping headline total
    priced: bool = True              # False when a resource's price is unknown: the saving is "unknown", not $0


class Analysis:
    """Indexes + helpers handed to every rule."""

    def __init__(self, resources: list[Resource], cfg: dict, *, now: datetime | None = None,
                 accounts: list[dict] | None = None, gaps: list[dict] | None = None, options: dict | None = None):
        self.resources = resources
        self.cfg = cfg
        self.th = cfg["thresholds"]
        self.assume = cfg["assumptions"]
        self.now = now or datetime.now(timezone.utc)
        self.accounts = accounts or []
        self.by_key = {r.key: r for r in resources}
        self._by_type: dict[str, list[Resource]] = {}
        for r in resources:
            self._by_type.setdefault(r.type, []).append(r)
        self._incoming: dict[str, list[tuple[Resource, str]]] = {}
        for r in resources:
            for rel in r.relations:
                self._incoming.setdefault(rel["to"], []).append((r, rel["kind"]))
        self.findings: list[Finding] = []
        self._seen: set[str] = set()
        # coverage gaps from the scan: calls that failed. Absence conclusions must not rely on them.
        self._gaps = {(g["account"], g["region"], g["service"], g["op"]) for g in (gaps or [])}
        self._gap_ops = {(g["service"], g["op"]) for g in (gaps or [])}
        self.scope = ScanScope(options, accounts)

    # -- queries --------------------------------------------------------
    def of(self, *types: str) -> list[Resource]:
        out: list[Resource] = []
        for t in types:
            out += self._by_type.get(t, [])
        return out

    def incoming(self, key: str, kind: str | None = None) -> list[Resource]:
        return [r for r, k in self._incoming.get(key, []) if kind is None or k == kind]

    def mature(self, r: Resource, days: float | None) -> bool:
        """True if the resource is older than the metrics window (a younger one has not had time to be busy)."""
        age = self.age_days(r.created)
        return age is None or days is None or age >= days

    def age_days(self, ts: str | None) -> float | None:
        if not ts:
            return None
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            return None
        return (self.now - dt).total_seconds() / 86400

    def is_nonprod(self, r: Resource) -> bool:
        return r.env in self.assume["nonprod_envs"]

    def blind(self, r: Resource, *ops: str) -> bool:
        """True if any ``"<service> <operation>"`` call failed for this resource's account+region.

        Rules that conclude "X is missing / unused" from an inventory (volumes, AMIs, route tables, ...)
        must check this first: a call that failed looks exactly like an empty answer.
        """
        for op in ops:
            svc, name = op.split(" ", 1)
            if (r.account, r.region, svc, name) in self._gaps or self.scope.service_blind(svc):
                return True
        return False

    def blind_anywhere(self, *ops: str) -> bool:
        """True if any of these calls failed in any region (for cross-region conclusions such as DNS targets)."""
        return any(tuple(op.split(" ", 1)) in self._gap_ops or self.scope.service_blind(op.split(" ", 1)[0]) for op in ops)

    # -- emitting findings ----------------------------------------------
    def add(self, rule: str, resources: Resource | Iterable[Resource] | None, *, category: str, severity: str,
            confidence: str, title: str, detail: str, advice: str, savings: float | dict[str, float] = 0.0,
            basis: str = "", effort: str = "low", risk: str = "low", in_total: bool = True,
            fid: str | None = None) -> Finding | None:
        rs: list[Resource] = [] if resources is None else ([resources] if isinstance(resources, Resource) else list(resources))
        fid = fid or f"{rule}|{rs[0].key if len(rs) == 1 else (rs[0].account if rs else 'acct')}"
        if fid in self._seen:
            return None
        self._seen.add(fid)
        if isinstance(savings, dict):
            breakdown = {k: round(v, 2) for k, v in savings.items() if v}
            total = round(sum(breakdown.values()), 2)
        else:
            total = round(float(savings), 2)
            breakdown = {rs[0].key: total} if (len(rs) == 1 and total) else {}
        first = rs[0] if rs else None
        regions = {r.region for r in rs}
        projects = {r.project for r in rs if r.project}
        f = Finding(
            id=fid, rule=rule, category=category, severity=severity, confidence=confidence, title=title,
            detail=detail, advice=advice, resources=[r.key for r in rs],
            account=first.account if first else (self.accounts[0]["account"] if self.accounts else ""),
            region=next(iter(regions)) if len(regions) == 1 else ("multiple" if regions else ""),
            service=first.service if first and len({r.service for r in rs}) == 1 else ("multiple" if rs else ""),
            project=next(iter(projects)) if len(projects) == 1 else ("multiple" if projects else ""),
            savings_usd=total, basis=basis, effort=effort, risk=risk, breakdown=breakdown, in_total=in_total,
            priced=not any(r.cost_conf == "none" and r.type in COSTED_TYPES for r in rs))
        self.findings.append(f)
        for r in rs:
            if fid not in r.findings:
                r.findings.append(fid)
        return f


CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1}


def potential_savings(findings: list[Finding], min_confidence: str = "low") -> float:
    """Headline total without double counting: per resource, the largest single saving.

    ``min_confidence`` restricts to findings at least that sure ("medium" => high+medium).
    """
    floor = CONFIDENCE_RANK[min_confidence]
    best: dict[str, float] = {}
    for f in findings:
        if not f.in_total or CONFIDENCE_RANK.get(f.confidence, 1) < floor:
            continue
        for key, usd in f.breakdown.items():
            best[key] = max(best.get(key, 0.0), usd)
    return round(sum(best.values()), 2)
