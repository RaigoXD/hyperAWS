"""Monthly cost *estimates* per resource from the reference price table.

Fixed/baseline charges only (instance-hours, GB-months, hourly fees). Usage
charges are excluded unless CloudWatch metrics let us project them (NAT data,
DynamoDB on-demand requests). Every estimate carries a human-readable basis and
a confidence so the report never pretends to be a bill.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from ..model import Resource

HOURS = 730
GB = 1e9
_USAGE_BASED = {"lambda:function", "sqs:queue", "sns:topic", "apigw:rest-api", "apigw:http-api",
                "sfn:state-machine", "cloudfront:distribution"}


@lru_cache(maxsize=1)
def load_pricing() -> dict:
    return json.loads((Path(__file__).with_name("pricing.json")).read_text())


def factor(p: dict, region: str, rtype: str) -> float:
    if rtype in p["no_region_factor"]:
        return 1.0
    rf = p["region_factor"]
    return rf.get(region, rf["default"])


def split_type(itype: str) -> tuple[str, str]:
    fam, _, size = (itype or "").partition(".")
    return fam, size


def ec2_hourly(p: dict, itype: str) -> float | None:
    fam, size = split_type(itype)
    base, mult = p["ec2_large_hourly"].get(fam), p["size_multiplier"].get(size)
    return base * mult if base is not None and mult is not None else None


def rds_hourly(p: dict, cls: str, engine: str) -> float | None:
    # "db.r5.large" -> family "db.r5", size "large"
    parts = (cls or "").split(".")
    if len(parts) != 3:
        return None
    fam, size = f"{parts[0]}.{parts[1]}", parts[2]
    table = p["rds_large_hourly"]["aurora" if (engine or "").startswith("aurora") else "mysql_postgres"]
    base, mult = table.get(fam), p["size_multiplier"].get(size)
    return base * mult if base is not None and mult is not None else None


def _window(r: Resource, metric: str) -> float:
    return float((r.metrics.get("_days") or {}).get(metric) or 30)


def estimate(r: Resource, p: dict | None = None, snap_counts: dict | None = None) -> tuple[float, str, str]:
    """-> (usd per month, basis, confidence). ``snap_counts``: snapshots per source volume (a chain shares the data)."""
    p = p or load_pricing()
    f = factor(p, r.region, r.type)
    a = r.attrs
    t = r.type

    if t == "ec2:instance":
        if r.state not in ("running", "pending"):
            return 0.0, f"{r.state}: no instance-hour charge (attached EBS billed separately)", "high"
        h = ec2_hourly(p, a.get("instance_type"))
        if h is None:
            return 0.0, f"no reference price for {a.get('instance_type')}", "none"
        spot = a.get("lifecycle") == "spot"
        usd = h * HOURS * f * (p["spot_price_fraction"] if spot else 1)
        return usd, (f"${h:.4f}/h × {HOURS}h × region {f:.2f}" + (f" × spot {p['spot_price_fraction']}" if spot else "")
                     + " (Linux on-demand)"), "medium" if spot else "high"

    if t == "ec2:volume":
        vt, size = a.get("vol_type") or "gp2", a.get("size_gb") or 0
        per = p["ebs_gb_month"].get(vt)
        if per is None:
            return 0.0, f"no reference price for volume type {vt}", "none"
        usd = size * per
        basis = f"{size} GB × ${per}/GB-mo"
        if vt == "gp3":
            ex = p["ebs_gp3_extra"]
            extra = max(0, (a.get("iops") or 0) - ex["free_iops"]) * ex["iops_month"] + \
                max(0, (a.get("throughput") or 0) - ex["free_throughput"]) * ex["throughput_month"]
            usd += extra
            if extra:
                basis += f" + ${extra:.2f} extra IOPS/throughput"
        elif vt in p["ebs_provisioned_iops_month"]:
            usd += (a.get("iops") or 0) * p["ebs_provisioned_iops_month"][vt]
            basis += f" + {a.get('iops') or 0} IOPS"
        return usd * f, basis + f" × region {f:.2f}", "high"

    if t == "ec2:snapshot":
        frac = p["snapshot_stored_fraction"]
        size = a.get("size_gb") or 0
        n = max(1, (snap_counts or {}).get((r.account, r.region, a.get("volume_id")), 1)) if a.get("volume_id") else 1
        usd = size * p["snapshot_gb_month"] * frac * f / n
        return usd, (f"{size} GB source × ${p['snapshot_gb_month']}/GB-mo × {frac:.0%} assumed stored"
                     + (f", shared by the {n} snapshots of this volume" if n > 1 else "")
                     + " (snapshots are incremental; real size unknown)"), "low"

    if t == "ec2:eip":
        usd = p["public_ipv4_hour"] * HOURS
        return usd, f"${p['public_ipv4_hour']}/h × {HOURS}h (public IPv4, in use or not)", "high"

    if t == "ec2:nat-gateway":
        if r.state != "available":
            return 0.0, f"state {r.state}", "medium"
        fixed = p["nat_hour"] * HOURS * f
        basis = f"${p['nat_hour']}/h × {HOURS}h × region {f:.2f}"
        usd, conf = fixed, "high"
        if "bytes_return" in r.metrics and "bytes_in" in r.metrics:
            gb = (r.metrics["bytes_in"] + r.metrics["bytes_return"]) / GB * (30 / _window(r, "bytes_in"))
            data = gb * p["nat_gb"] * f
            usd += data
            basis += f" + {gb:.1f} GB/mo processed × ${p['nat_gb']}/GB"
        else:
            basis += " (+ data processing, unknown)"
            conf = "medium"
        return usd, basis, conf

    if t == "ec2:vpc-endpoint":
        if a.get("ep_type") != "Interface":
            return 0.0, "gateway endpoints are free", "high"
        az = max(1, a.get("az_count") or 1)
        usd = p["vpc_endpoint_hour"] * HOURS * az * f
        return usd, f"${p['vpc_endpoint_hour']}/h × {HOURS}h × {az} AZ (+ per-GB data)", "high"

    if t in ("elbv2:lb", "elb:clb"):
        kind = a.get("lb_type") if t == "elbv2:lb" else "classic"
        h = p["lb_hour"].get(kind)
        if h is None:
            return 0.0, f"no price for load balancer type {kind}", "none"
        return h * HOURS * f, f"${h}/h × {HOURS}h × region {f:.2f} (+ LCU/data usage)", "high"

    if t == "rds:instance":
        stor = (a.get("storage_gb") or 0) * p["rds_storage_gb_month"].get(a.get("storage_type") or "gp2", 0.115)
        stor += (a.get("iops") or 0) * p["rds_provisioned_iops_month"].get(a.get("storage_type") or "", 0)   # io1/io2 are billed per IOPS
        mult = 2 if a.get("multi_az") else 1
        storage_usd = stor * mult
        if r.state == "stopped":
            return storage_usd * f, f"stopped: storage only ({a.get('storage_gb')} GB)", "medium"
        h = rds_hourly(p, a.get("instance_class"), a.get("engine"))
        if h is None:
            return storage_usd * f, f"no reference price for {a.get('instance_class')} ({a.get('engine')}); storage only", "low"
        usd = (h * HOURS * mult + storage_usd) * f
        return usd, (f"${h:.3f}/h × {HOURS}h × {mult}{' (Multi-AZ)' if mult == 2 else ''} + {a.get('storage_gb')} GB storage"
                     f" × region {f:.2f} (MySQL/PostgreSQL-class pricing)"), "medium"

    if t == "rds:cluster":
        if a.get("serverless_v2") and a.get("acu_min") is not None:
            n = max(1, a.get("members") or 1)
            usd = a["acu_min"] * n * p["aurora_serverless_v2_acu_hour"] * HOURS * f
            return usd, f"Serverless v2 floor: {a['acu_min']} ACU × {n} instance(s) × ${p['aurora_serverless_v2_acu_hour']}/ACU-h", "low"
        return 0.0, "Aurora instances are priced as rds:instance", "medium"

    if t in ("rds:snapshot", "rds:cluster-snapshot"):
        size = a.get("size_gb") or 0
        frac = p["snapshot_stored_fraction"]
        return size * p["rds_backup_gb_month"] * frac * f, f"{size} GB × ${p['rds_backup_gb_month']}/GB-mo × {frac:.0%} assumed stored", "low"

    if t == "dynamodb:table":
        d = p["dynamodb"]
        gb = (a.get("size_bytes") or 0) / GB
        per_gb = d["ia_storage_gb_month"] if a.get("table_class") == "STANDARD_INFREQUENT_ACCESS" else d["storage_gb_month"]
        storage = gb * per_gb          # the 25 GB free tier is per account (not per table): not subtracted here
        if a.get("billing_mode") == "PROVISIONED":
            rcu, wcu = a.get("rcu", 0) + a.get("gsi_rcu", 0), a.get("wcu", 0) + a.get("gsi_wcu", 0)
            cap = (rcu * d["rcu_hour"] + wcu * d["wcu_hour"]) * HOURS
            return (cap + storage) * f, f"{rcu} RCU + {wcu} WCU provisioned + {gb:.1f} GB storage", "high"
        basis, conf, usage = f"on-demand: {gb:.1f} GB storage", "medium", 0.0
        if "read_units" in r.metrics:
            k = 30 / _window(r, "read_units")
            usage = (r.metrics.get("read_units", 0) * k / 1e6 * d["on_demand_read_million"]
                     + r.metrics.get("write_units", 0) * k / 1e6 * d["on_demand_write_million"])
            basis += f" + ~${usage:.2f} request charges (projected from CloudWatch)"
        else:
            basis += " (+ request charges, unknown)"
            conf = "low"
        return (storage + usage) * f, basis, conf

    if t == "s3:bucket":
        names = [k for k in r.metrics if k.startswith("bytes_")]
        if not names:
            return 0.0, "no storage metrics (CloudWatch unavailable or bucket too new)", "none"
        usd, parts = 0.0, []
        for k in names:
            price = p["s3_gb_month"].get(k.removeprefix("bytes_"))
            if price and r.metrics[k]:
                usd += r.metrics[k] / GB * price
                parts.append(f"{r.metrics[k] / GB:.1f} GB {k.removeprefix('bytes_')}")
        return usd * f, (" + ".join(parts) or "empty") + " (storage only; requests/transfer excluded)", "medium"

    if t == "elasticache:cluster":
        fam, _, size = (a.get("node_type") or "").rpartition(".")
        base, mult = p["elasticache_large_hourly"].get(fam), p["size_multiplier"].get(size)
        if base is None or mult is None:
            return 0.0, f"no reference price for {a.get('node_type')}", "none"
        n = a.get("nodes") or 1
        return base * mult * n * HOURS * f, f"${base * mult:.3f}/h × {n} node(s) × {HOURS}h × region {f:.2f}", "high"

    if t == "ecs:service":
        providers = [x for x in (a.get("capacity_providers") or []) if x]
        fargate = a.get("launch_type") == "FARGATE" or (
            a.get("launch_type") == "CAPACITY_PROVIDER" and any(x.startswith("FARGATE") for x in providers))
        if not fargate or not a.get("task_cpu") or not a.get("task_memory"):
            return 0.0, "EC2-backed or unknown task size: cost is in the container instances", "medium"
        spot_only = bool(providers) and all(x == "FARGATE_SPOT" for x in providers)
        price = p["fargate"]["arm" if a.get("task_arch") == "ARM64" else "x86"]
        vcpu, gb, n = a["task_cpu"] / 1024, a["task_memory"] / 1024, a.get("running") or 0
        usd = n * (vcpu * price["vcpu_hour"] + gb * price["gb_hour"]) * HOURS * f * (0.3 if spot_only else 1)
        return usd, (f"{n} task(s) × ({vcpu:g} vCPU + {gb:g} GB) Fargate{' ARM' if a.get('task_arch') == 'ARM64' else ''}"
                     f"{' Spot (~70% off, approximate)' if spot_only else ''} × {HOURS}h"), "low" if providers else "medium"

    if t == "eks:cluster":
        extended = a.get("version_status") == "EXTENDED_SUPPORT"
        h = p["eks"]["extended_support_hour" if extended else "control_plane_hour"]
        return h * HOURS, f"control plane ${h}/h × {HOURS}h" + (" (EXTENDED SUPPORT surcharge)" if extended else ""), "high"

    if t == "ecr:repository":
        gb = (a.get("size_bytes") or 0) / GB
        return gb * p["ecr_gb_month"] * f, f"{gb:.2f} GB × ${p['ecr_gb_month']}/GB-mo", "medium"

    if t == "logs:log-group":
        gb = (a.get("stored_bytes") or 0) / GB
        return gb * p["logs_gb_month"] * f, f"{gb:.2f} GB stored × ${p['logs_gb_month']}/GB-mo (ingestion excluded)", "medium"

    if t == "kms:key":
        if r.state == "PendingDeletion":
            return 0.0, "pending deletion: not billed", "high"
        return p["kms_key_month"], f"customer-managed key ${p['kms_key_month']}/mo (+ requests)", "high"

    if t == "route53:hosted-zone":
        return p["route53_zone_month"], f"hosted zone ${p['route53_zone_month']}/mo (first 25; + queries)", "medium"

    if t in _USAGE_BASED:
        return 0.0, "usage-based service: no fixed monthly fee (not estimated)", "none"
    return 0.0, "", "none"


def price_all(resources: list[Resource]) -> float:
    p = load_pricing()
    total = 0.0
    snap_counts: dict = {}
    for r in resources:
        if r.type == "ec2:snapshot" and r.attrs.get("volume_id"):
            k = (r.account, r.region, r.attrs["volume_id"])
            snap_counts[k] = snap_counts.get(k, 0) + 1
    for r in resources:
        usd, basis, conf = estimate(r, p, snap_counts)
        r.est_monthly_usd, r.cost_basis, r.cost_conf = round(usd, 2), basis, conf
        total += usd
    return round(total, 2)
