"""Waste and hygiene rules for RDS, DynamoDB, S3 and ElastiCache."""

from __future__ import annotations

from . import cost
from .context import Analysis
from .data import PREVIOUS_GEN_RDS

GB = 1e9


def usd(x: float) -> str:
    return f"${x:,.2f}"


def run(a: Analysis) -> None:
    rds(a)
    dynamodb(a)
    s3(a)
    elasticache(a)


# --------------------------------------------------------------------------- RDS


def rds(a: Analysis) -> None:
    th = a.th
    instance_ids = {(d.account, d.region, d.rid) for d in a.of("rds:instance")}
    cluster_ids = {(c.account, c.region, c.rid) for c in a.of("rds:cluster")}
    for d in a.of("rds:instance"):
        if d.state == "stopped":
            a.add("rds.instance.stopped", d, category="unused", severity="medium", confidence="high", title="Stopped RDS instance",
                  detail=f"Stopped, but its {d.attrs.get('storage_gb')} GB of storage (and backups) are still billed. "
                         "AWS restarts stopped instances automatically after 7 days.",
                  advice="Take a final snapshot and delete it if it is not coming back; otherwise accept the storage cost knowingly.",
                  savings=d.est_monthly_usd, basis=d.cost_basis, risk="medium")
        elif (d.state == "available" and d.metrics.get("connections_max") == 0 and not d.attrs.get("cluster")
              and not d.attrs.get("read_replica_of") and d.attrs.get("instance_class") != "db.serverless"
              and a.mature(d, (d.metrics.get("_days") or {}).get("connections_max"))):
            # Aurora members and read replicas are idle by design (failover targets / DR copies): not flagged
            days = (d.metrics.get("_days") or {}).get("connections_max", "?")
            a.add("rds.instance.idle", d, category="unused", severity="high" if d.est_monthly_usd >= 50 else "medium", confidence="medium",
                  title="RDS instance with no connections",
                  detail=f"No client connections in {days} days (max DatabaseConnections = 0).",
                  advice="Confirm nothing connects (batch jobs may run less often), snapshot it and delete or stop it.",
                  savings=d.est_monthly_usd, basis=d.cost_basis, risk="medium")
        if d.state == "available" and d.attrs.get("multi_az") and a.is_nonprod(d) and d.metrics.get("connections_max") != 0:
            half = d.est_monthly_usd / 2
            a.add("rds.instance.multi-az-nonprod", d, category="rightsizing", severity="low", confidence="low",
                  title="Multi-AZ RDS in a non-production environment",
                  detail=f"Environment looks like '{d.env}' but the instance is Multi-AZ (2× compute and storage).",
                  advice="Single-AZ is normally enough for dev/test. Modify to Single-AZ (brief interruption).",
                  savings=half, basis=f"half of {usd(d.est_monthly_usd)}", effort="low", risk="medium")
        if d.attrs.get("public"):
            a.add("sec.rds.public", d, category="security", severity="high", confidence="medium", title="RDS instance is publicly accessible",
                  detail="PubliclyAccessible is true, so the endpoint resolves to a public IP (security groups still decide who can connect).",
                  advice="Disable public accessibility unless required; put the database in private subnets.", risk="medium")
        if d.attrs.get("storage_gb") and not d.attrs.get("encrypted"):
            a.add("sec.rds.unencrypted", d, category="security", severity="low", confidence="high", title="RDS storage is not encrypted",
                  detail="Encryption at rest cannot be turned on in place.",
                  advice="Restore a snapshot copy into an encrypted instance during a maintenance window.", effort="high", risk="medium")
        fam = ".".join((d.attrs.get("instance_class") or "").split(".")[:2])
        if fam in PREVIOUS_GEN_RDS and d.state == "available":
            a.add("rds.instance.previous-gen", d, category="cost-insight", severity="low", confidence="low",
                  title=f"Previous-generation RDS class {d.attrs.get('instance_class')}",
                  detail="Older classes have cheaper, faster replacements.", advice="Modify to a current class (t4g/m6g/m7g/r6g...).",
                  savings=d.est_monthly_usd * cost.load_pricing()["typical_discounts"]["previous_gen"], basis="~10% typical gain (approximate)",
                  effort="medium", risk="medium")

    for s in a.of("rds:snapshot", "rds:cluster-snapshot"):
        age = a.age_days(s.created)
        if age is None or s.attrs.get("source") is None:
            continue
        src_missing = (s.account, s.region, s.attrs["source"]) not in (instance_ids if s.type == "rds:snapshot" else cluster_ids)
        unreadable = a.blind(s, "rds describe-db-instances", "rds describe-db-clusters")
        if src_missing and age >= th["rds_snapshot_orphan_days"] and not unreadable and not s.attrs.get("source_region"):
            a.add("rds.snapshot.orphaned", s, category="unused", severity="low", confidence="medium", title="Manual RDS snapshot of a deleted database",
                  detail=f"Source '{s.attrs['source']}' no longer exists; the snapshot is {age:.0f} days old ({s.attrs.get('size_gb')} GB).",
                  advice="Keep it only if it is a deliberate final backup; otherwise delete it.",
                  savings=s.est_monthly_usd, basis=s.cost_basis)
        elif age >= th["rds_snapshot_old_days"]:
            a.add("rds.snapshot.old", s, category="unused", severity="low", confidence="low", title="Manual RDS snapshot older than a year",
                  detail=f"{age:.0f} days old ({s.attrs.get('size_gb')} GB). Manual snapshots never expire on their own.",
                  advice="Delete it or move to a retention policy (AWS Backup).", savings=s.est_monthly_usd, basis=s.cost_basis)


# --------------------------------------------------------------------------- DynamoDB


def dynamodb(a: Analysis) -> None:
    d = cost.load_pricing()["dynamodb"]
    for t in a.of("dynamodb:table"):
        reads, writes = t.metrics.get("read_units"), t.metrics.get("write_units")
        if reads is None or writes is None:
            continue
        days = (t.metrics.get("_days") or {}).get("read_units", 30)
        if not a.mature(t, days):
            continue
        if reads == 0 and writes == 0:
            a.add("ddb.table.idle", t, category="unused", severity="medium" if t.est_monthly_usd >= 5 else "low", confidence="medium",
                  title="DynamoDB table with no reads or writes",
                  detail=f"No consumed capacity in {days:.0f} days ({t.attrs.get('item_count', 0):,} items, "
                         f"{(t.attrs.get('size_bytes') or 0) / GB:.2f} GB).",
                  advice="Export/backup if needed and delete the table (or at least switch it to on-demand).",
                  savings=t.est_monthly_usd, basis=t.cost_basis, risk="medium")
            continue
        if t.attrs.get("billing_mode") == "PROVISIONED":
            rcu, wcu = t.attrs.get("rcu", 0) + t.attrs.get("gsi_rcu", 0), t.attrs.get("wcu", 0) + t.attrs.get("gsi_wcu", 0)
            secs = days * 86400
            util_r = (reads / secs) / rcu if rcu else 1
            util_w = (writes / secs) / wcu if wcu else 1
            if max(util_r, util_w) < a.th["ddb_overprovisioned_util"]:
                f = cost.factor(cost.load_pricing(), t.region, t.type)
                provisioned = (rcu * d["rcu_hour"] + wcu * d["wcu_hour"]) * cost.HOURS * f
                on_demand = (reads * 30 / days / 1e6 * d["on_demand_read_million"] + writes * 30 / days / 1e6 * d["on_demand_write_million"]) * f
                if provisioned - on_demand >= 1:
                    a.add("ddb.table.overprovisioned", t, category="rightsizing", severity="medium" if provisioned - on_demand >= 20 else "low",
                          confidence="medium", title="Over-provisioned DynamoDB capacity",
                          detail=f"Average utilisation is {util_r:.0%} (reads) / {util_w:.0%} (writes) of provisioned {rcu} RCU / {wcu} WCU. "
                                 "Averages hide peaks: check the CloudWatch max before changing.",
                          advice="Switch to on-demand capacity, or enable auto scaling / lower the provisioned values.",
                          savings=provisioned - on_demand,
                          basis=f"provisioned {usd(provisioned)} vs ~{usd(on_demand)} on-demand at observed volume", effort="low", risk="medium")


# --------------------------------------------------------------------------- S3


def s3(a: Analysis) -> None:
    th, p = a.th, cost.load_pricing()
    for b in a.of("s3:bucket"):
        at = b.attrs
        std = b.metrics.get("bytes_standard")
        total_bytes = sum(v for k, v in b.metrics.items() if k.startswith("bytes_") and isinstance(v, (int, float)))
        age = a.age_days(b.created)
        if b.metrics.get("objects") == 0 and total_bytes == 0 and age is not None and age >= th["unused_days_long"]:
            a.add("s3.bucket.empty", b, category="hygiene", severity="low", confidence="medium", title="Empty S3 bucket",
                  detail=f"No objects in the CloudWatch storage metrics; created {age:.0f} days ago. Versioned buckets can still hold delete markers.",
                  advice="Delete the bucket if it is no longer used (empty buckets cost nothing but may be referenced by DNS: subdomain-takeover risk if deleted without cleanup).")
        if at.get("lifecycle_rules") == 0 and std and std / GB >= th["s3_lifecycle_min_gb"]:
            gb = std / GB
            sav = gb * p["s3_gb_month"]["standard"] * cost.factor(p, b.region, b.type) * a.assume["s3_lifecycle_saving"]   # only the Standard-class bytes
            a.add("s3.bucket.no-lifecycle", b, category="rightsizing", severity="low", confidence="low", title="Large bucket without lifecycle rules",
                  detail=f"{gb:,.0f} GB in the Standard class and no lifecycle configuration.",
                  advice="Add rules to transition cold data to Standard-IA / Glacier Instant Retrieval (or enable Intelligent-Tiering), "
                         "expire temporary data and abort incomplete multipart uploads.",
                  savings=sav, basis=f"{a.assume['s3_lifecycle_saving']:.0%} of the {gb:,.0f} GB of Standard-class storage, assuming a share is cold (access pattern unknown)",
                  effort="low", risk="low")
        if at.get("versioning") == "Enabled" and at.get("lc_noncurrent_expiration") is False:
            a.add("s3.bucket.versioning-no-expiry", b, category="hygiene", severity="low", confidence="medium",
                  title="Versioned bucket never expires old versions",
                  detail="Versioning is on and no lifecycle rule expires noncurrent versions, so overwritten/deleted objects accumulate and keep being billed.",
                  advice="Add a NoncurrentVersionExpiration rule (e.g. 30–90 days) and clean up expired delete markers.")
        if at.get("public_access_blocked") is False:
            a.add("sec.s3.public-access", b, category="security", severity="low", confidence="medium",
                  title="S3 Block Public Access is not fully enabled",
                  detail="At least one of the four bucket-level Block Public Access settings is off (account-level settings may still protect it).",
                  advice="Enable all four settings on buckets that must stay private; verify the bucket policy and ACLs.")


# --------------------------------------------------------------------------- ElastiCache


def elasticache(a: Analysis) -> None:
    for c in a.of("elasticache:cluster"):
        conns = c.metrics.get("connections_max")
        if (c.state == "available" and conns is not None and conns <= a.th["cache_idle_connections"]
                and a.mature(c, (c.metrics.get("_days") or {}).get("connections_max"))):
            days = (c.metrics.get("_days") or {}).get("connections_max", "?")
            a.add("cache.cluster.idle", c, category="unused", severity="high" if c.est_monthly_usd >= 50 else "medium", confidence="medium",
                  title="ElastiCache node with no connections",
                  detail=f"At most {conns:.0f} connection(s) in {days} days (a few are monitoring/replication), so no client is using it.",
                  advice="Confirm nothing uses it (cache-aside apps may be down), then delete the cluster.",
                  savings=c.est_monthly_usd, basis=c.cost_basis, risk="medium")
