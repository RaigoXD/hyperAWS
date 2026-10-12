"""Stage 1: talk to AWS (read-only) and write raw facts.

A *unit* is one (collector, region) pair. Units run in a thread pool; every
AWS call goes through the guarded :class:`AwsCli`. A failed call never aborts
the scan: it becomes a *coverage gap* shown in the report (so "0 resources"
is never confused with "no permission").
"""

from __future__ import annotations

import json
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from . import SCHEMA_VERSION, __version__
from .awscli import AuthError, AwsCli, AwsCliError, ReadOnlyViolation, UnsafeArgument, redact
from .fsutil import write_private
from .model import GLOBAL, Resource, make_key, scrub_free_text

HOME_REGION = "us-east-1"  # where global services are called from


@dataclass
class Gap:
    account: str
    region: str
    service: str
    op: str
    code: str
    message: str


class Failed(dict):
    """What ``Ctx.aws`` returns when a call failed (the failure is recorded as a coverage gap).

    It is empty, so ``.get(...)`` still works, but a collector that must tell "nothing configured" from
    "could not read it" can test ``isinstance(x, Failed)``. A plain ``{}``/default means the API answered.
    """


class Ctx:
    """What a collector sees: one account, one region, a guarded AWS client."""

    def __init__(self, cli: AwsCli, account: str, region: str, *, partition: str = "aws",
                 is_global: bool = False, gaps: list[Gap] | None = None,
                 lock: threading.Lock | None = None, workers: int = 8):
        self.cli = cli
        self.account = account
        self.region = region          # region used for CLI calls
        self.partition = partition
        self.is_global = is_global
        self.gaps = gaps if gaps is not None else []
        self._lock = lock or threading.Lock()
        self.workers = workers

    # -- AWS access -------------------------------------------------------
    def aws(self, service: str, op: str, args: Iterable[str] = (), *, region: str | None = None,
            expect: Iterable[str] = (), default: Any = None) -> Any:
        """Guarded read. On any API error returns an empty :class:`Failed` (and records a coverage gap).

        Pass values that come from AWS glued to their flag (``f"--table-name={name}"``), never as their own
        argument: a resource named ``--debug`` then stays a value. A value the guard refuses (UnsafeArgument, e.g.
        a name starting with file://) only skips this call; any other ReadOnlyViolation is a code bug and fatal.
        """
        try:
            return self.cli.call(service, op, args, region=region or self.region,  # audit: passthrough
                                 expect=expect, default=default)
        except UnsafeArgument as e:
            code, msg = "UnsafeArgument", f"refused before any process started: {e}"
        except (AuthError, ReadOnlyViolation):
            raise
        except AwsCliError as e:
            code, msg = e.code, str(e)
        with self._lock:
            self.gaps.append(Gap(self.account, GLOBAL if self.is_global else (region or self.region),
                                 service, op, code, redact(msg)[:240]))
        return Failed()

    def map(self, fn: Callable[[Any], Any], items: Iterable[Any]) -> list[Any]:
        """Parallel map for per-resource follow-up calls (order preserved)."""
        items = list(items)
        if len(items) <= 1:
            return [fn(i) for i in items]
        with ThreadPoolExecutor(max_workers=min(self.workers, len(items))) as ex:
            return list(ex.map(fn, items))

    # -- resource helpers --------------------------------------------------
    @property
    def res_region(self) -> str:
        return GLOBAL if self.is_global else self.region

    def arn(self, service: str, resource: str, *, region: str | None = None, account: bool = True) -> str:
        reg = (region if region is not None else self.res_region)
        reg = "" if reg == GLOBAL else reg
        return f"arn:{self.partition}:{service}:{reg}:{self.account if account else ''}:{resource}"

    def new(self, rtype: str, rid: str, *, region: str | None = None, **kw: Any) -> Resource:
        reg = region or self.res_region
        return Resource(
            key=make_key(self.account, reg, rtype, rid), rid=rid, type=rtype,
            service=rtype.split(":")[0], account=self.account, region=reg, **kw,
        )

    def key(self, rtype: str, rid: str, *, region: str | None = None) -> str:
        return make_key(self.account, region or self.res_region, rtype, rid)


# --------------------------------------------------------------------------


@dataclass
class ScanOptions:
    regions: list[str] | None = None       # None = all enabled regions
    services: list[str] | None = None      # collector names/groups; None = all
    metrics: bool = True
    metrics_days: int = 14
    cost_explorer: bool = False
    workers: int = 8
    quiet: bool = False


def _log(opts: ScanOptions, msg: str) -> None:
    if not opts.quiet:
        print(msg, file=sys.stderr, flush=True)


def select_collectors(names: list[str] | None):
    """Collectors for ``--services`` (names or groups). The tag catch-all is always on."""
    from . import collectors

    if not names:
        return list(collectors.ALL)
    wanted = {n.strip().lower() for n in names}
    known = {c.NAME for c in collectors.ALL} | {c.GROUP for c in collectors.ALL}
    unknown = wanted - known
    if unknown:
        raise SystemExit(f"unknown service/group: {', '.join(sorted(unknown))}. "
                         f"Known: {', '.join(sorted(known))}")
    return [c for c in collectors.ALL if c.NAME in wanted or c.GROUP in wanted or c.GROUP == "meta"]


def scan_profile(cli: AwsCli, profile: str | None, opts: ScanOptions) -> dict:
    """Scan one profile (= one account). Returns {account, resources, gaps}."""
    ident = cli.call("sts", "get-caller-identity", region=HOME_REGION)
    account = ident.get("Account") or ("000000000000" if cli.dry_run else "")
    arn = ident.get("Arn", "")
    partition = arn.split(":")[1] if arn.count(":") >= 5 else "aws"
    if not account:
        raise AuthError("could not determine the account id", "NoAccount")

    if opts.regions:
        regions = list(opts.regions)
    elif cli.dry_run:
        regions = ["<every enabled region>"]
    else:
        regs = cli.call("ec2", "describe-regions", region=HOME_REGION).get("Regions", [])
        regions = sorted(r["RegionName"] for r in regs)
    collectors = select_collectors(opts.services)
    _log(opts, f"[{profile or 'default'}] account {account}: {len(regions)} regions, "
               f"{len(collectors)} collectors")

    gaps: list[Gap] = []
    lock = threading.Lock()
    units: list[tuple[Any, str, bool]] = []
    for c in collectors:
        if c.SCOPE == "global":
            units.append((c, HOME_REGION, True))
        else:
            units.extend((c, r, False) for r in regions)
            if c.GROUP == "meta" and HOME_REGION not in regions and not cli.dry_run:
                # the tagging API reports global resources (CloudFront, Route 53, IAM) only from us-east-1;
                # merge_tagging keeps just the global ones from this extra unit
                units.append((c, HOME_REGION, False))

    def run_unit(unit):
        c, region, is_global = unit
        ctx = Ctx(cli, account, region, partition=partition, is_global=is_global,
                  gaps=gaps, lock=lock, workers=opts.workers)
        t0 = time.time()
        try:
            res = c.collect(ctx)
        except (AuthError, ReadOnlyViolation):
            raise
        except Exception as e:  # a collector bug must not kill the whole scan
            with lock:
                gaps.append(Gap(account, GLOBAL if is_global else region, c.NAME, "collect",
                                "CollectorError", redact(f"{type(e).__name__}: {e}")[:240]))
            res = []
        return c.NAME, region, res, time.time() - t0

    resources: list[Resource] = []
    ex = ThreadPoolExecutor(max_workers=opts.workers)
    try:
        futs = [ex.submit(run_unit, u) for u in units]
        for f in as_completed(futs):
            name, region, res, secs = f.result()  # re-raises fatal errors
            resources.extend(res)
            if res:
                _log(opts, f"  {name:<12} {region:<16} {len(res):>5} resources  ({secs:.1f}s)")
    except BaseException:
        ex.shutdown(wait=False, cancel_futures=True)   # Ctrl-C / expired credentials: stop starting new aws processes
        raise
    else:
        ex.shutdown(wait=True)

    resources = merge_tagging(resources, regions)

    if opts.metrics:
        from . import metrics
        metrics.collect_metrics(cli, account, partition, resources, regions, opts, gaps, lock)

    cost = None
    if opts.cost_explorer:
        from . import costexplorer
        cost = costexplorer.collect(cli, account, opts, gaps, lock, resources)

    return {
        # the caller ARN is shown in the report: an SSO session name is often the operator's e-mail address
        "account": {"profile": profile, "account": account, "arn": redact(arn), "regions": regions},
        "resources": resources,
        "gaps": gaps,
        "cost_explorer": cost,
    }


def aggregate_gaps(gaps: list[Gap]) -> list[dict]:
    """One row per (account, region, service, op, code) with a count (e.g. 500 buckets denied -> 1 row)."""
    rows: dict[tuple, dict] = {}
    for g in gaps:
        k = (g.account, g.region, g.service, g.op, g.code)
        if k not in rows:
            rows[k] = {**asdict(g), "count": 0}
        rows[k]["count"] += 1
    return sorted(rows.values(), key=lambda r: (r["account"], r["service"], r["op"], r["region"]))


def merge_tagging(resources: list[Resource], regions: list[str] | None = None) -> list[Resource]:
    """Fold the tagging-API pseudo resources into real ones; keep the long tail.

    ``regions`` (when given) limits long-tail items to the scanned regions plus global ones.
    """
    real = [r for r in resources if not r.attrs.get("from_tagging")]
    by_arn = {r.arn: r for r in real if r.arn}
    seen_keys = {r.key for r in real}
    out = list(real)
    for t in (r for r in resources if r.attrs.get("from_tagging")):
        target = by_arn.get(t.arn)
        if target is not None:
            for k, v in t.tags.items():
                target.tags.setdefault(k, v)
            if target.name == target.rid and t.tags.get("Name"):
                target.name = t.tags["Name"]
        elif t.key not in seen_keys and (regions is None or t.region == GLOBAL or t.region in regions):
            seen_keys.add(t.key)
            out.append(t)
    return out


def _binary_summary(info: dict) -> str:
    if not info.get("verified"):
        return "; ".join(info.get("notes") or []) or "not verified"
    return f"{info['version']} at {info['path']}" + (f" -> {info['real_path']}" if info.get("real_path") != info["path"] else "")


def run_scan(profiles: list[str | None], opts: ScanOptions, *, cli: AwsCli | None = None) -> dict:
    cli = cli or AwsCli()
    started = time.time()
    # Resolve and verify the aws binary before anything else (refuses AWS CLI v1 and a planted `aws`); which binary ran
    # is part of the record, like the audit log.
    aws_cli = cli.binary_info()
    if aws_cli.get("verified"):
        _log(opts, f"aws cli: {_binary_summary(aws_cli)}")
        for note in aws_cli.get("notes", []) + aws_cli.get("environment", []):
            _log(opts, f"  ! {note}")
    accounts, resources, gaps, costs = [], [], [], []
    seen_accounts: set[str] = set()
    for prof in profiles:
        part = scan_profile(cli.with_profile(prof), prof, opts)
        acct = part["account"]["account"]
        if acct in seen_accounts:
            _log(opts, f"! profile {prof} is the same account as an earlier profile ({acct}); skipped")
            continue
        seen_accounts.add(acct)
        accounts.append(part["account"])
        resources.extend(part["resources"])
        gaps.extend(part["gaps"])
        if part["cost_explorer"]:
            costs.append({"account": acct, **part["cost_explorer"]})
    for r in resources:
        scrub_free_text(r)        # again at write time: also covers attrs and tags a collector added after new()
    return {
        "schema": SCHEMA_VERSION,
        "tool": "aws-analyzer",
        "version": __version__,
        "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "duration_s": round(time.time() - started, 1),
        "options": {"regions": opts.regions or "all-enabled", "services": opts.services or "all",
                    "metrics": opts.metrics, "metrics_days": opts.metrics_days,
                    "cost_explorer": opts.cost_explorer,
                    "aws_cli": _binary_summary(aws_cli)},   # shown in the report's Scan info tab
        "aws_cli": aws_cli,                                   # path, real path, version, owner, notes
        "accounts": accounts,
        "resources": [asdict(r) for r in resources],
        "gaps": aggregate_gaps(gaps),
        "cost_explorer": costs,
        "audit": cli.audit_log(),
    }


def write_scan(scan: dict, out_dir: Path) -> Path:
    accounts = [a["account"] for a in scan["accounts"]]
    acct = "+".join(accounts[:3]) + (f"+{len(accounts) - 3}more" if len(accounts) > 3 else "") if accounts else "none"
    stamp = scan["scanned_at"].replace("-", "").replace(":", "")
    path = out_dir / f"scan-{acct}-{stamp}.json"
    write_private(path, json.dumps(scan, indent=1))
    return path
