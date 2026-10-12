"""Waste, rightsizing and hygiene rules for EC2, EBS, network and load balancers."""

from __future__ import annotations

from ..model import Resource, make_key
from . import cost
from .context import Analysis
from .data import (GRAVITON_CANDIDATE_FAMILIES, PREVIOUS_GEN_EC2, SENSITIVE_PORTS)


def usd(x: float) -> str:
    return f"${x:,.2f}"


def run(a: Analysis) -> None:
    eip_unassociated(a)
    volume_unattached(a)
    instance_stopped(a)
    instance_idle_or_oversized(a)
    snapshots_and_amis(a)
    eni_unattached(a)
    nat_gateways(a)
    load_balancers(a)
    security_groups(a)
    network_hygiene(a)
    insights(a)


# --------------------------------------------------------------------------- IPs, volumes, instances


def eip_unassociated(a: Analysis) -> None:
    for r in a.of("ec2:eip"):
        if r.state != "unassociated":
            continue
        records = sorted({rel["label"] for z in a.incoming(r.key, "dns") for rel in z.relations
                          if rel["kind"] == "dns" and rel["to"] == r.key and rel.get("label")})
        detail = f"{r.attrs.get('public_ip')} is allocated to the account but not associated with any instance or network interface."
        if records:
            detail += f" DNS still points at it: {', '.join(records[:5])}."
        a.add("ec2.eip.unassociated", r, category="unused", severity="medium", confidence="high",
              title="Unassociated Elastic IP", detail=detail,
              advice="Release it if it is not reserved on purpose (update or remove DNS records that reference it first), "
                     "or associate it with the resource that needs it.",
              savings=r.est_monthly_usd, basis=r.cost_basis)


def volume_unattached(a: Analysis) -> None:
    snaps: dict[str, int] = {}
    for s in a.of("ec2:snapshot"):
        if s.attrs.get("volume_id"):
            snaps[s.attrs["volume_id"]] = snaps.get(s.attrs["volume_id"], 0) + 1
    for r in a.of("ec2:volume"):
        if r.state != "available":
            continue
        age = a.age_days(r.created)
        if age is not None and age < a.th["unattached_volume_days"]:
            continue
        n = snaps.get(r.rid, 0)
        detail = (f"{r.attrs.get('size_gb')} GB {r.attrs.get('vol_type')} volume is not attached to any instance"
                  + (f" (created {age:.0f} days ago)" if age is not None else "") + ".")
        detail += f" {n} snapshot(s) of it exist." if n else " No snapshot of it exists."
        a.add("ec2.volume.unattached", r, category="unused", severity="medium" if r.est_monthly_usd >= 5 else "low",
              confidence="high", title="Unattached EBS volume", detail=detail,
              advice="Snapshot it if the data might be needed (skip if a snapshot already exists), then delete the volume.",
              savings=r.est_monthly_usd, basis=r.cost_basis)


def instance_stopped(a: Analysis) -> None:
    for r in a.of("ec2:instance"):
        if r.state != "stopped":
            continue
        days = a.age_days(r.attrs.get("stopped_at"))
        if days is not None and days < a.th["stopped_instance_days"]:
            continue
        vols = [a.by_key.get(make_key(r.account, r.region, "ec2:volume", v)) for v in r.attrs.get("volume_ids", [])]
        vol_cost = sum(v.est_monthly_usd for v in vols if v)
        detail = (f"Stopped for {days:.0f} days" if days is not None else "Stopped (stop date unknown)") + \
                 f"; its {len([v for v in vols if v])} EBS volume(s) keep costing {usd(vol_cost)}/month."
        a.add("ec2.instance.stopped", r, category="unused", severity="medium" if vol_cost >= 10 else "low",
              confidence="high" if days is not None else "medium", title="Long-stopped EC2 instance", detail=detail,
              advice="If it is still needed, create an AMI and terminate the instance; otherwise terminate it and "
                     "delete its volumes. Stopped instances do not pay compute but their EBS storage is billed.",
              savings={v.key: v.est_monthly_usd for v in vols if v}, basis="attached EBS volumes: " + ", ".join(f"{v.rid} {usd(v.est_monthly_usd)}" for v in vols if v),
              effort="low", risk="medium")


def instance_idle_or_oversized(a: Analysis) -> None:
    th = a.th
    for r in a.of("ec2:instance"):
        avg, mx = r.metrics.get("cpu_avg"), r.metrics.get("cpu_max")
        if r.state != "running" or avg is None or mx is None:
            continue
        days = (r.metrics.get("_days") or {}).get("cpu_avg", "?")
        if not a.mature(r, days if isinstance(days, (int, float)) else None):
            continue                                      # launched inside the window: it has not had time to be busy
        extra = ""
        if r.tags.get("aws:autoscaling:groupName"):
            extra = " It belongs to an Auto Scaling group: adjust the group's size/min capacity instead of terminating it."
        elif r.tags.get("aws:eks:cluster-name") or r.tags.get("eks:cluster-name"):
            extra = " It looks like an EKS node: check cluster autoscaling / node group sizing."
        net = _network_per_day(r)
        if avg < th["idle_cpu_avg"] and mx < th["idle_cpu_max"] and (net is None or net < th["idle_network_bytes_per_day"]):
            a.add("ec2.instance.idle", r, category="unused", severity="high" if r.est_monthly_usd >= 50 else "medium",
                  confidence="medium", title="Idle EC2 instance",
                  detail=f"CPU averaged {avg:.1f}% (max {mx:.1f}%) over {days} days"
                         + (f" with about {net / 1e6:,.1f} MB/day of network traffic" if net is not None else " (network not measured)") + ". Memory was not checked.",
                  advice="Confirm nothing depends on it (check network traffic / connections), then stop or terminate it, or "
                         "move it to a much smaller type." + extra,
                  savings=r.est_monthly_usd, basis=r.cost_basis, effort="low", risk="medium")
        elif avg < th["oversized_cpu_avg"] and mx < th["oversized_cpu_max"] and _size_at_least_large(r):
            a.add("ec2.instance.oversized", r, category="rightsizing", severity="low", confidence="low",
                  title="Likely oversized EC2 instance",
                  detail=f"CPU averaged {avg:.1f}% (max {mx:.1f}%) over {days} days on {r.attrs.get('instance_type')}.",
                  advice="Try the next size down in the same family (about half the price). Check memory/network first; "
                         "AWS Compute Optimizer gives memory-aware advice." + extra,
                  savings=r.est_monthly_usd * 0.5, basis=f"half of {usd(r.est_monthly_usd)} (one size down)",
                  effort="medium", risk="medium")


def _size_at_least_large(r: Resource) -> bool:
    """Is there a smaller size to move to? Only burstable (t) families have a `medium` below `large`."""
    fam, _, size = (r.attrs.get("instance_type") or "").partition(".")
    if size in ("nano", "micro", "small", "medium", ""):
        return False
    return size != "large" or fam.startswith("t")


def _network_per_day(r: Resource) -> float | None:
    """Average bytes/day in+out over the metrics window, if NetworkIn/NetworkOut were read."""
    if "net_in" not in r.metrics or "net_out" not in r.metrics:
        return None
    days = (r.metrics.get("_days") or {}).get("net_in") or 14
    return (r.metrics["net_in"] + r.metrics["net_out"]) / days


def fleet_managed(r: Resource) -> bool:
    """Nodes launched by an Auto Scaling group, Karpenter, EKS or EMR: scale the fleet, do not schedule single nodes."""
    return any(k.startswith(("aws:autoscaling", "aws:eks", "eks:", "karpenter.sh/", "aws:elasticmapreduce", "kubernetes.io/cluster/")) for k in r.tags)


# --------------------------------------------------------------------------- snapshots / AMIs / ENIs


def snapshots_and_amis(a: Analysis) -> None:
    amis = {x.rid: x for x in a.of("ec2:ami")}
    used_amis = {i.attrs.get("ami") for i in a.of("ec2:instance")}
    snap_used_by_ami = {sid for am in amis.values() for sid in am.attrs.get("snapshot_ids", [])}
    volumes = {make_key(v.account, v.region, "ec2:volume", v.rid) for v in a.of("ec2:volume")}
    snap_by_key = {s.rid: s for s in a.of("ec2:snapshot")}
    for s in a.of("ec2:snapshot"):
        if s.rid in snap_used_by_ami or "aws:backup:source-resource" in s.tags or "dlm:managed" in s.tags:
            continue
        if a.blind(s, "ec2 describe-images"):      # an AMI we could not list might own this snapshot
            continue
        age = a.age_days(s.created)
        ami_id, vol_id = s.attrs.get("ami_id"), s.attrs.get("volume_id")
        if ami_id and ami_id not in amis:
            a.add("ec2.snapshot.orphaned-ami", s, category="unused", severity="low", confidence="medium",
                  title="Snapshot of a deregistered AMI",
                  detail=f"Created for {ami_id}, which no longer exists in this account/region ({s.attrs.get('size_gb')} GB source).",
                  advice="Delete it if you do not need the image data any more.",
                  savings=s.est_monthly_usd, basis=s.cost_basis)
        elif vol_id and make_key(s.account, s.region, "ec2:volume", vol_id) not in volumes and not a.blind(s, "ec2 describe-volumes") and \
                age is not None and age >= a.th["old_snapshot_days"] and not ami_id:
            a.add("ec2.snapshot.orphaned-volume", s, category="unused", severity="low", confidence="medium",
                  title="Old snapshot of a deleted volume",
                  detail=f"Source volume {vol_id} no longer exists and the snapshot is {age:.0f} days old.",
                  advice="Keep it only if it is an intentional long-term backup; otherwise delete it (consider a lifecycle policy).",
                  savings=s.est_monthly_usd, basis=s.cost_basis)
    for am in a.of("ec2:ami"):
        age = a.age_days(am.created)
        if am.rid in used_amis or age is None or age < a.th["ami_unused_days"] or a.blind(am, "ec2 describe-instances"):
            continue
        sn = [snap_by_key[sid] for sid in am.attrs.get("snapshot_ids", []) if sid in snap_by_key]
        sv = sum(x.est_monthly_usd for x in sn)
        a.add("ec2.ami.unused", am, category="unused", severity="low", confidence="low", title="AMI not used by any instance",
              detail=f"{age:.0f} days old; no running or stopped instance in this scan uses it. Backed by {len(sn)} snapshot(s).",
              advice="Check launch templates, Auto Scaling groups and other accounts that may use it, then deregister the AMI "
                     "and delete its snapshots.", savings=sv, basis="its snapshots: " + usd(sv))


def eni_unattached(a: Analysis) -> None:
    for r in a.of("ec2:eni"):
        if r.state != "available" or r.attrs.get("requester_managed"):
            continue
        has_ip = bool(r.attrs.get("public_ip"))
        a.add("ec2.eni.unattached", r, category="hygiene", severity="low", confidence="high",
              title="Unattached network interface",
              detail=f"Network interface in {r.attrs.get('subnet')} is not attached to anything"
                     + (f" but holds public IP {r.attrs.get('public_ip')}" if has_ip else "") + ".",
              advice="Delete it if it was left behind by a terminated instance. It reserves a private IP and may block deleting its subnet/security group.",
              savings=cost.load_pricing()["public_ipv4_hour"] * cost.HOURS if has_ip else 0.0, basis="public IPv4 charge" if has_ip else "")


# --------------------------------------------------------------------------- NAT / LB


def nat_gateways(a: Analysis) -> None:
    for r in a.of("ec2:nat-gateway"):
        if r.state != "available":
            continue
        fixed = cost.load_pricing()["nat_hour"] * cost.HOURS * cost.factor(cost.load_pricing(), r.region, r.type)
        moved = (r.metrics.get("bytes_in"), r.metrics.get("bytes_return"))
        if r.attrs.get("route_table_refs") == 0 and not a.blind(r, "ec2 describe-route-tables"):
            a.add("ec2.nat.no-routes", r, category="unused", severity="high", confidence="high", title="NAT Gateway nobody routes to",
                  detail="No route table sends traffic through this NAT Gateway.",
                  advice="Delete the NAT Gateway (and release its Elastic IP) if no workload needs outbound access through it.",
                  savings=fixed, basis=f"fixed hourly charge {usd(fixed)}/month", risk="medium")
        elif None not in moved and sum(moved) < a.th["nat_idle_bytes"] and a.mature(r, (r.metrics.get("_days") or {}).get("bytes_in")):
            days = (r.metrics.get("_days") or {}).get("bytes_in", "?")
            a.add("ec2.nat.idle", r, category="unused", severity="high", confidence="medium", title="NAT Gateway with no traffic",
                  detail=f"Under {a.th['nat_idle_bytes'] / 1e6:.0f} MB moved in {days} days.",
                  advice="Confirm the private subnets really need outbound internet, then remove the NAT Gateway or its routes.",
                  savings=fixed, basis=f"fixed hourly charge {usd(fixed)}/month", risk="medium")
    by_vpc: dict[str, list[Resource]] = {}
    for r in a.of("ec2:nat-gateway"):
        if r.state == "available" and r.attrs.get("vpc"):
            by_vpc.setdefault(r.key.rsplit(":", 1)[0] + ":" + r.attrs["vpc"], []).append(r)
    for vpc, nats in by_vpc.items():
        if len(nats) > 1 and all(a.is_nonprod(n) for n in nats):
            p = cost.load_pricing()
            fixed = p["nat_hour"] * cost.HOURS * cost.factor(p, nats[0].region, nats[0].type)   # not the data-processing part
            sav = {n.key: fixed for n in nats[1:]}
            a.add("net.nat.multi-az-nonprod", nats, category="rightsizing", severity="low", confidence="low",
                  title="One NAT Gateway per AZ in a non-production VPC",
                  detail=f"{len(nats)} NAT Gateways in {vpc.split(':')[-1]} (environment: {nats[0].env}).",
                  advice="Non-production traffic rarely needs AZ-redundant egress: a single NAT Gateway (or NAT instance) is much cheaper, "
                         "at the cost of cross-AZ traffic and a single point of failure.",
                  savings=sav, basis=f"{len(nats) - 1} fewer NAT Gateway(s) × ~{usd(fixed)}", effort="medium", risk="medium",
                  fid=f"net.nat.multi-az-nonprod|{vpc}")


def load_balancers(a: Analysis) -> None:
    for lb in a.of("elbv2:lb"):
        tgs = a.incoming(lb.key, "behind")
        total = sum(t.attrs.get("targets_total", 0) for t in tgs)
        healthy = sum(t.attrs.get("targets_healthy", 0) for t in tgs)
        traffic = lb.metrics.get("requests", lb.metrics.get("flows"))
        if a.blind(lb, "elbv2 describe-target-groups", "elbv2 describe-target-health"):
            # targets could not be read: only traffic evidence counts, and we say so
            if traffic == 0:
                a.add("elb.lb.no-traffic", lb, category="unused", severity="medium", confidence="low", title="Load balancer without traffic",
                      detail="No requests/connections in the metrics window (its target groups could not be read, so targets are unknown).",
                      advice="Check whether the service is still used and remove the load balancer if not.", savings=lb.est_monthly_usd, basis=lb.cost_basis)
            continue
        if total == 0:
            a.add("elb.lb.no-targets", lb, category="unused", severity="medium", confidence="high",
                  title="Load balancer with no registered targets",
                  detail=f"{len(tgs)} target group(s) attached, 0 registered targets." if tgs else "No target group is attached.",
                  advice="Delete the load balancer if the service it fronted is gone.", savings=lb.est_monthly_usd, basis=lb.cost_basis)
        elif traffic == 0 and a.mature(lb, (lb.metrics.get("_days") or {}).get("requests", (lb.metrics.get("_days") or {}).get("flows"))):
            days = (lb.metrics.get("_days") or {}).get("requests", (lb.metrics.get("_days") or {}).get("flows", "?"))
            a.add("elb.lb.no-traffic", lb, category="unused", severity="medium", confidence="medium",
                  title="Load balancer without traffic",
                  detail=f"No requests/connections in {days} days ({total} target(s) registered).",
                  advice="Check whether the service is still used (health checks alone do not count) and remove the load balancer if not.",
                  savings=lb.est_monthly_usd, basis=lb.cost_basis)
        elif healthy == 0:
            a.add("elb.lb.all-unhealthy", lb, category="hygiene", severity="medium", confidence="high",
                  title="All load balancer targets are unhealthy",
                  detail=f"{total} registered target(s), none healthy.", advice="Fix the health check or remove the dead targets.")
    for lb in a.of("elb:clb"):
        if not lb.attrs.get("instance_ids"):
            a.add("elb.clb.no-instances", lb, category="unused", severity="medium", confidence="high",
                  title="Classic load balancer with no instances", detail="No instances are registered.",
                  advice="Delete it; classic load balancers are also being retired in favour of ALB/NLB.",
                  savings=lb.est_monthly_usd, basis=lb.cost_basis)
        elif lb.metrics.get("requests") == 0:
            a.add("elb.clb.no-traffic", lb, category="unused", severity="medium", confidence="medium",
                  title="Classic load balancer without traffic", detail="No requests recorded in the metrics window.",
                  advice="Confirm it is unused and delete it.", savings=lb.est_monthly_usd, basis=lb.cost_basis)
    for tg in a.of("elbv2:target-group"):
        if (not tg.attrs.get("lb_arns") and tg.attrs.get("targets_total", 0) == 0 and not a.incoming(tg.key, "serves")
                and not a.blind(tg, "elbv2 describe-target-health")):
            a.add("elb.tg.orphaned", tg, category="hygiene", severity="low", confidence="medium",
                  title="Target group attached to nothing", detail="No load balancer, no service and no targets use it.",
                  advice="Delete it (target groups are free, but they clutter the account and block cleanup).")


# --------------------------------------------------------------------------- security groups / network hygiene


def _sg_key(r: Resource, sg_id: str) -> str:
    return make_key(r.account, r.region, "ec2:security-group", sg_id)


def security_groups(a: Analysis) -> None:
    used: set[str] = set()
    for r in a.resources:
        for sg_id in r.attrs.get("sg_ids", []) or []:
            used.add(_sg_key(r, sg_id))
    unused_by_region: dict[tuple[str, str], list[Resource]] = {}
    for sg in a.of("ec2:security-group"):
        in_use = sg.key in used or bool(sg.attrs.get("referenced_by"))
        unreadable = a.blind(sg, "ec2 describe-network-interfaces", "ec2 describe-instances", "rds describe-db-instances",
                             "elbv2 describe-load-balancers", "lambda list-functions")
        if sg.attrs.get("group_name") != "default" and not in_use and not unreadable:
            unused_by_region.setdefault((sg.account, sg.region), []).append(sg)
        _world_open(a, sg, in_use)
    for (acct, region), sgs in unused_by_region.items():
        a.add("ec2.sg.unused", sgs, category="hygiene", severity="low", confidence="medium",
              title=f"{len(sgs)} unused security group(s) in {region}",
              detail="Not attached to any network interface and not referenced by another group: " +
                     ", ".join(f"{s.rid} ({s.attrs.get('group_name')})" for s in sgs[:8]) + (" …" if len(sgs) > 8 else ""),
              advice="Delete the ones you recognise as leftovers (security groups are free; the benefit is a smaller attack surface "
                     "and easier audits). Check launch templates first.", fid=f"ec2.sg.unused|{acct}|{region}")


def _world_open(a: Analysis, sg: Resource, in_use: bool) -> None:
    risky: list[str] = []
    for proto, lo, hi in sg.attrs.get("world_open", []):
        if proto not in ("tcp", "all", "-1", "6"):
            continue
        if proto in ("all", "-1") or (lo == 0 and hi >= 65535):
            risky.append("ALL ports")
            continue
        for port, label in SENSITIVE_PORTS.items():
            if lo <= port <= hi and hi - lo < 1000:
                risky.append(f"{label} ({port})")
    if not risky:
        return
    risky = sorted(set(risky))
    critical = any(x.startswith(("ALL", "SSH", "RDP", "MySQL", "PostgreSQL", "SQL Server", "Oracle", "MongoDB", "Redis", "Elasticsearch", "Telnet")) for x in risky)
    a.add("sec.sg.world-open", sg, category="security", severity="high" if (critical and in_use) else "medium",
          confidence="high", title="Security group open to the internet on sensitive ports",
          detail=f"{sg.attrs.get('group_name')} allows 0.0.0.0/0 (or ::/0) on: {', '.join(risky)}."
                 + (" The group is in use." if in_use else " The group is not attached to anything."),
          advice="Restrict the source to known CIDRs/security groups, or use SSM Session Manager instead of SSH/RDP.",
          effort="low", risk="medium")


def network_hygiene(a: Analysis) -> None:
    occupied: set[str] = set()
    for r in a.resources:
        v = r.attrs.get("vpc")
        if v and r.type not in ("ec2:subnet", "ec2:security-group", "ec2:igw", "ec2:vpc"):
            occupied.add(make_key(r.account, r.region, "ec2:vpc", v))
    for vpc in a.of("ec2:vpc"):
        if (not vpc.attrs.get("is_default") and vpc.key not in occupied
                and not a.blind(vpc, "ec2 describe-network-interfaces", "ec2 describe-instances", "ec2 describe-nat-gateways", "ec2 describe-vpc-endpoints",
                                "elbv2 describe-load-balancers", "rds describe-db-instances", "lambda list-functions", "eks list-clusters")):
            a.add("net.vpc.empty", vpc, category="hygiene", severity="low", confidence="medium", title="VPC with no resources",
                  detail=f"Nothing in {vpc.attrs.get('cidr')} (no instances, network interfaces, NAT, endpoints or load balancers).",
                  advice="Delete the VPC and its subnets/route tables/IGW if it is a leftover (VPCs themselves are free).")
    for igw in a.of("ec2:igw"):
        if igw.state == "detached":
            a.add("net.igw.detached", igw, category="hygiene", severity="low", confidence="high", title="Internet gateway not attached to a VPC",
                  detail="Detached internet gateways do nothing.", advice="Delete it.")


# --------------------------------------------------------------------------- cost insights (aggregated)


def insights(a: Analysis) -> None:
    p = cost.load_pricing()
    minimum = a.th["min_insight_usd"]

    gp2 = [v for v in a.of("ec2:volume") if v.attrs.get("vol_type") == "gp2" and v.state != "available"]
    sav = {v.key: (v.attrs.get("size_gb") or 0) * (p["ebs_gb_month"]["gp2"] - p["ebs_gb_month"]["gp3"]) * cost.factor(p, v.region, v.type) for v in gp2}
    if sum(sav.values()) >= minimum:
        a.add("cost.ebs.gp2-to-gp3", [v for v in gp2], category="cost-insight", severity="medium", confidence="high",
              title=f"Convert {len(gp2)} gp2 volume(s) to gp3",
              detail=f"{sum(v.attrs.get('size_gb') or 0 for v in gp2):,} GB on gp2. gp3 is ~20% cheaper per GB and includes 3,000 IOPS / 125 MB/s.",
              advice="Change the volume type to gp3 (online, no downtime); verify peak IOPS/throughput first for volumes above 1 TB or with heavy I/O.",
              savings=sav, basis="size × ($0.10 − $0.08)/GB-month", effort="low", risk="low", fid="cost.ebs.gp2-to-gp3")

    running = [i for i in a.of("ec2:instance") if i.state == "running"]
    prev = {i.key: i.est_monthly_usd * p["typical_discounts"]["previous_gen"] for i in running
            if (i.attrs.get("instance_type") or "").split(".")[0] in PREVIOUS_GEN_EC2}
    if sum(prev.values()) >= minimum:
        a.add("cost.ec2.previous-gen", [a.by_key[k] for k in prev], category="cost-insight", severity="low", confidence="low",
              title=f"{len(prev)} instance(s) on previous-generation types",
              detail="Types such as t2/m4/c4/r4 are superseded by cheaper, faster generations.",
              advice="Move to the current generation (t3/t4g, m6i/m7i, c6i, r6i ...). Often a stop/start with a new instance type.",
              savings=prev, basis=f"~{p['typical_discounts']['previous_gen']:.0%} typical price/performance gain (approximate)",
              effort="medium", risk="medium", fid="cost.ec2.previous-gen")

    grav = {i.key: i.est_monthly_usd * p["typical_discounts"]["graviton"] for i in running
            if i.attrs.get("arch") == "x86_64" and (i.attrs.get("instance_type") or "").split(".")[0] in GRAVITON_CANDIDATE_FAMILIES
            and i.attrs.get("lifecycle") != "spot" and "windows" not in (i.attrs.get("platform") or "").lower()}
    if sum(grav.values()) >= minimum:
        a.add("cost.ec2.graviton", [a.by_key[k] for k in grav], category="cost-insight", severity="low", confidence="low",
              title=f"{len(grav)} x86 instance(s) could run on Graviton",
              detail="Graviton (arm64) equivalents (t4g, m6g/m7g, c6g/c7g, r6g/r7g) are about 20% cheaper for similar performance.",
              advice="Test your workload on arm64 (multi-arch images, recompiled binaries), then switch instance families.",
              savings=grav, basis=f"~{p['typical_discounts']['graviton']:.0%} typical saving (approximate)", effort="high", risk="medium",
              fid="cost.ec2.graviton")

    sched: dict[str, float] = {}
    for i in running:
        if a.is_nonprod(i) and not fleet_managed(i):
            sched[i.key] = i.est_monthly_usd * a.assume["nonprod_schedule_saving"]
    for d in a.of("rds:instance"):
        if d.state == "available" and a.is_nonprod(d) and not d.attrs.get("cluster") and not d.attrs.get("read_replica_of"):
            sched[d.key] = d.est_monthly_usd * a.assume["nonprod_schedule_saving"] * 0.8  # storage is billed even while stopped
    if sum(sched.values()) >= minimum:
        a.add("cost.nonprod-schedule", [a.by_key[k] for k in sched], category="cost-insight", severity="medium", confidence="low",
              title=f"Stop {len(sched)} non-production resource(s) outside working hours",
              detail=f"Dev/staging/test compute running 24/7. Running ~12h on weekdays only cuts runtime by about {a.assume['nonprod_schedule_saving']:.0%}.",
              advice="Use AWS Instance Scheduler, EventBridge Scheduler, or simple start/stop automation. Note RDS auto-restarts after 7 days stopped.",
              savings=sched, basis=f"{a.assume['nonprod_schedule_saving']:.0%} of current estimated cost (environment inferred from tags/names)",
              effort="medium", risk="low", fid="cost.nonprod-schedule")

    # public IPv4: every address costs money since Feb 2024, even when in use
    ips = {r.attrs["public_ip"] for r in a.of("ec2:eip") if r.attrs.get("public_ip")}
    ips |= {i.attrs["public_ip"] for i in a.of("ec2:instance") if i.attrs.get("public_ip") and i.state == "running"}
    lb_nodes = sum(lb.attrs.get("az_count", 1) for lb in a.of("elbv2:lb") if lb.attrs.get("scheme") == "internet-facing")
    n = len(ips) + lb_nodes
    if n:
        total = n * p["public_ipv4_hour"] * cost.HOURS
        a.add("cost.public-ipv4", None, category="cost-insight", severity="info", confidence="medium",
              title=f"{n} public IPv4 addresses ≈ {usd(total)}/month",
              detail=f"{len(ips)} on instances/Elastic IPs plus ~{lb_nodes} on internet-facing load balancer nodes. "
                     "AWS charges $0.005/hour per public IPv4 address, in use or not.",
              advice="Remove public IPs from instances that do not need them (use private subnets + NAT/SSM/VPC endpoints, or IPv6), "
                     "release unused Elastic IPs, and consider dual-stack/IPv6 where possible.",
              savings=0.0, basis=f"{n} × $0.005 × 730h", in_total=False, fid="cost.public-ipv4")

    steady = [i for i in running if i.attrs.get("lifecycle") != "spot" and (a.age_days(i.created) or 0) >= 30]
    steady += [d for d in a.of("rds:instance") if d.state == "available" and (a.age_days(d.created) or 0) >= 30]
    base = sum(x.est_monthly_usd for x in steady)
    if base >= 100:
        pct = p["typical_discounts"]["savings_plan_1yr_compute"]
        a.add("cost.commitment", steady, category="cost-insight", severity="medium", confidence="low",
              title=f"Steady compute ≈ {usd(base)}/month could be covered by a commitment",
              detail=f"{len(steady)} instance(s)/database(s) have been running for 30+ days on on-demand pricing.",
              advice="Evaluate a Compute Savings Plan (flexible) or RDS/EC2 Reserved Instances for the always-on baseline. "
                     "Check Cost Explorer's recommendations first; only commit to what you are sure to run.",
              savings=base * pct, basis=f"~{pct:.0%} typical 1-year no-upfront discount (approximate; 3-year/all-upfront saves more)",
              effort="low", risk="high", in_total=False, fid="cost.commitment")
