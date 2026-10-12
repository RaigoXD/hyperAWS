"""Rules for serverless, containers, edge/ops (CloudFront, Route 53, Logs, KMS) and IAM hygiene."""

from __future__ import annotations

from collections import defaultdict
from typing import Callable

from ..model import Resource, make_key
from . import cost
from .context import Analysis
from .data import DEPRECATED_LAMBDA_RUNTIMES, LAMBDA_ARM_OK_PREFIXES

GB = 1e9


def usd(x: float) -> str:
    return f"${x:,.2f}"


def run(a: Analysis) -> None:
    serverless(a)
    containers(a)
    edge(a)
    logs_and_kms(a)
    iam(a)


def _group_hygiene(a: Analysis, rtype: str, predicate: Callable[[Resource], bool], *, rule: str, title: str,
                   detail: str, advice: str, severity: str = "low") -> None:
    """One aggregated finding per (account, region) instead of hundreds of identical ones."""
    groups: dict[tuple[str, str], list[Resource]] = defaultdict(list)
    for r in a.of(rtype):
        if predicate(r):
            groups[(r.account, r.region)].append(r)
    for (acct, region), rs in groups.items():
        names = ", ".join(r.name for r in rs[:6]) + (" …" if len(rs) > 6 else "")
        a.add(rule, rs, category="hygiene", severity=severity, confidence="medium", title=f"{len(rs)} {title} in {region}",
              detail=f"{detail} {names}", advice=advice, fid=f"{rule}|{acct}|{region}")


# --------------------------------------------------------------------------- serverless


def serverless(a: Analysis) -> None:
    long_days = a.th["unused_days_long"]
    _group_hygiene(a, "lambda:function",
                   lambda f: f.metrics.get("invocations") == 0 and (a.age_days(f.attrs.get("last_modified")) or 999) >= long_days,
                   rule="lambda.unused", title="Lambda function(s) never invoked", detail=f"No invocations in {long_days}+ days:",
                   advice="Delete functions you no longer use (idle functions cost nothing, but they expand the attack surface and clutter ownership).")

    by_rt: dict[tuple[str, str], list[Resource]] = defaultdict(list)
    for f in a.of("lambda:function"):
        if f.attrs.get("runtime") in DEPRECATED_LAMBDA_RUNTIMES:
            by_rt[(f.account, f.attrs["runtime"])].append(f)
    for (acct, rt), fs in by_rt.items():
        a.add("lambda.runtime.deprecated", fs, category="security", severity="medium", confidence="high",
              title=f"{len(fs)} Lambda function(s) on deprecated runtime {rt}",
              detail="AWS no longer patches this runtime and may block updates: " + ", ".join(f.name for f in fs[:6]) + (" …" if len(fs) > 6 else ""),
              advice="Upgrade to a supported runtime. (List last reviewed 2026-06; check the Lambda runtimes page.)",
              effort="medium", risk="medium", fid=f"lambda.runtime.deprecated|{acct}|{rt}")

    arm = [f for f in a.of("lambda:function") if f.attrs.get("arch") == "x86_64" and f.attrs.get("package_type") == "Zip"
           and (f.attrs.get("runtime") or "").startswith(LAMBDA_ARM_OK_PREFIXES) and (f.metrics.get("invocations") or 0) > 0]
    if len(arm) >= 5:
        a.add("cost.lambda.arm64", arm, category="cost-insight", severity="info", confidence="low",
              title=f"{len(arm)} active x86 Lambda functions could use arm64",
              detail="Graviton2 Lambda is priced ~20% lower per GB-second and is often faster.",
              advice="Switch the architecture to arm64 after testing native dependencies (pure Python/Node usually just works).",
              in_total=False, effort="low", risk="low", fid="cost.lambda.arm64")

    dlq_arns = {q.attrs["redrive_target"] for q in a.of("sqs:queue") if q.attrs.get("redrive_target")}
    _group_hygiene(a, "sqs:queue", lambda q: (q.metrics.get("sent") == 0 and q.attrs.get("messages") == 0 and q.attrs.get("messages_in_flight") == 0
                                              and not a.blind(q, "sqs get-queue-attributes") and q.arn not in dlq_arns   # an empty dead-letter queue is healthy
                                              and a.mature(q, (q.metrics.get("_days") or {}).get("sent"))),
                   rule="sqs.idle", title="idle SQS queue(s)", detail=f"Nothing sent in {long_days}+ days and nothing waiting:",
                   advice="Delete queues nothing produces to or consumes from.")
    _group_hygiene(a, "sns:topic", lambda t: (t.attrs.get("subscriptions") == 0 and t.metrics.get("published") == 0
                                              and not a.blind(t, "sns list-subscriptions")),
                   rule="sns.idle", title="SNS topic(s) without subscribers or traffic", detail="No subscriptions and nothing published:",
                   advice="Delete unused topics.")
    _group_hygiene(a, "apigw:rest-api", lambda x: x.metrics.get("requests") == 0 and a.mature(x, 30), rule="apigw.rest.idle", title="REST API(s) without requests",
                   detail=f"No requests in {long_days}+ days:", advice="Delete or archive APIs that no client calls.")
    _group_hygiene(a, "apigw:http-api", lambda x: x.metrics.get("requests") == 0 and a.mature(x, 30), rule="apigw.http.idle", title="HTTP API(s) without requests",
                   detail=f"No requests in {long_days}+ days:", advice="Delete or archive APIs that no client calls.")
    _group_hygiene(a, "sfn:state-machine", lambda x: x.metrics.get("executions") == 0 and a.mature(x, 30), rule="sfn.idle", title="state machine(s) never executed",
                   detail=f"No executions in {long_days}+ days:", advice="Delete state machines you no longer run.")


# --------------------------------------------------------------------------- containers


def containers(a: Analysis) -> None:
    for s in a.of("ecs:service"):
        if s.state == "ACTIVE" and s.attrs.get("desired") == 0:
            a.add("ecs.service.zero-desired", s, category="hygiene", severity="info", confidence="high", title="ECS service scaled to zero",
                  detail=f"Service in cluster {s.attrs.get('cluster')} has desired count 0.", advice="Delete it if it will not be scaled up again.")
        elif s.est_monthly_usd and (s.metrics.get("cpu_avg") or 100) < a.th["ecs_low_cpu_avg"]:   # Fargate-backed (priced) services
            a.add("ecs.service.low-cpu", s, category="rightsizing", severity="low", confidence="low", title="Fargate tasks barely use their CPU",
                  detail=f"Average service CPU {s.metrics['cpu_avg']:.1f}% with {s.attrs.get('task_cpu')} CPU units / {s.attrs.get('task_memory')} MiB per task.",
                  advice="Try a smaller task size (check memory utilisation too), or fewer tasks if autoscaling allows.",
                  savings=s.est_monthly_usd * 0.5, basis=f"half of {usd(s.est_monthly_usd)} (one size down)", effort="medium", risk="medium")
    for c in a.of("ecs:cluster"):
        if not c.attrs.get("active_services") and not c.attrs.get("container_instances") and not c.attrs.get("running_tasks"):
            a.add("ecs.cluster.empty", c, category="hygiene", severity="low", confidence="high", title="Empty ECS cluster",
                  detail="No services, container instances or running tasks.", advice="Delete it (empty clusters are free, but clutter the account).")

    for c in a.of("eks:cluster"):
        if c.attrs.get("version_status") == "EXTENDED_SUPPORT":
            p = cost.load_pricing()["eks"]
            extra = (p["extended_support_hour"] - p["control_plane_hour"]) * cost.HOURS
            a.add("eks.extended-support", c, category="cost-insight", severity="high", confidence="high",
                  title=f"EKS {c.attrs.get('version')} is in extended support (6× control-plane price)",
                  detail=f"Standard support ended {c.attrs.get('end_of_standard_support') or 'earlier'}; extended support ends "
                         f"{c.attrs.get('end_of_extended_support') or 'later'}. You pay ${p['extended_support_hour']}/h instead of ${p['control_plane_hour']}/h.",
                  advice="Upgrade the control plane and node groups to a version in standard support.",
                  savings=extra, basis=f"(${p['extended_support_hour']} − ${p['control_plane_hour']})/h × {cost.HOURS}h", effort="high", risk="medium")
        has_nodes = any((i.tags.get("aws:eks:cluster-name") == c.rid or i.tags.get("eks:cluster-name") == c.rid
                         or f"kubernetes.io/cluster/{c.rid}" in i.tags) for i in a.of("ec2:instance") if i.state == "running")
        if (not has_nodes and not c.attrs.get("desired_nodes") and not c.attrs.get("fargate_profiles") and c.state == "ACTIVE"
                and not c.attrs.get("auto_mode") and not a.blind(c, "ec2 describe-instances", "eks list-nodegroups", "eks describe-nodegroup", "eks list-fargate-profiles")):   # Auto Mode nodes are not node groups
            a.add("eks.cluster.no-compute", c, category="unused", severity="high", confidence="medium", title="EKS cluster without worker nodes",
                  detail="No node group capacity, Fargate profile or running node found for this cluster; only the control plane is billed.",
                  advice="Delete the cluster if it is abandoned (confirm no Karpenter/self-managed nodes live in another account).",
                  savings=c.est_monthly_usd, basis=c.cost_basis, risk="medium")

    for r in a.of("ecr:repository"):
        at = r.attrs
        if at.get("has_lifecycle_policy") is False and (at.get("untagged_images") or (at.get("size_bytes") or 0) > 5 * GB):
            frac = (at["untagged_images"] / at["images"]) if at.get("images") and at.get("untagged_images") else 0
            a.add("ecr.no-lifecycle", r, category="rightsizing", severity="low", confidence="medium", title="ECR repository without lifecycle policy",
                  detail=f"{at.get('images')} images ({(at.get('size_bytes') or 0) / GB:.1f} GB), {at.get('untagged_images')} untagged, no lifecycle policy.",
                  advice="Add a lifecycle policy that expires untagged images and keeps only the last N tagged ones.",
                  savings=r.est_monthly_usd * frac, basis=f"{frac:.0%} untagged share of {usd(r.est_monthly_usd)}", effort="low", risk="low")


# --------------------------------------------------------------------------- edge


def edge(a: Analysis) -> None:
    for d in a.of("cloudfront:distribution"):
        if d.state == "disabled":
            a.add("cf.disabled", d, category="hygiene", severity="low", confidence="high", title="Disabled CloudFront distribution",
                  detail=f"{d.name} ({d.attrs.get('domain')}) is disabled.", advice="Delete it if it is no longer needed (check DNS first).")
        elif d.metrics.get("requests") == 0:
            a.add("cf.no-requests", d, category="hygiene", severity="low", confidence="medium", title="CloudFront distribution without requests",
                  detail=f"No requests in {(d.metrics.get('_days') or {}).get('requests', 30)} days.", advice="Disable and delete it if nothing uses it.")
    for z in a.of("route53:hosted-zone"):
        if z.attrs.get("record_count", 99) <= 2:
            a.add("r53.zone.empty", z, category="unused", severity="low", confidence="high", title="Route 53 hosted zone with no records",
                  detail="Only the default NS and SOA records exist.", advice="Delete it if the domain is not delegated to these name servers.",
                  savings=z.est_monthly_usd, basis=z.cost_basis)
        dang = z.attrs.get("dangling") or []
        if dang:
            a.add("sec.r53.dangling", z, category="security", severity="medium", confidence="low",
                  title=f"{len(dang)} DNS record(s) in {z.name} point at targets not found in the scanned accounts",
                  detail="; ".join(f"{d['name']} → {d['target']}: {d['reason']}" for d in dang[:5]) + (" …" if len(dang) > 5 else ""),
                  advice="Check each target first: it may live in another account or region this scan did not cover. If it is really gone, "
                         "delete or fix the record: dangling records can let someone else take over the subdomain.",
                  risk="medium")


def logs_and_kms(a: Analysis) -> None:
    minimum = a.th["log_min_gb"] * GB
    small: dict[tuple[str, str], list[Resource]] = defaultdict(list)
    for g in a.of("logs:log-group"):
        if g.attrs.get("retention_days") is not None:
            continue
        stored = g.attrs.get("stored_bytes") or 0
        if stored >= minimum:
            idle = g.metrics.get("incoming_bytes") == 0
            a.add("logs.no-retention", g, category="rightsizing", severity="medium" if g.est_monthly_usd >= 5 else "low",
                  confidence="medium" if idle else "low", title="Log group keeps logs forever",
                  detail=f"{stored / GB:.1f} GB stored with no retention policy" + (" and nothing ingested recently." if idle else "."),
                  advice="Set a retention period (e.g. 30–90 days) or export old logs to S3 and expire them.",
                  savings=g.est_monthly_usd * a.assume["log_retention_saving"],
                  basis=f"{a.assume['log_retention_saving']:.0%} of {usd(g.est_monthly_usd)} (share older than the retention you pick is unknown)",
                  effort="low", risk="low")
        else:
            small[(g.account, g.region)].append(g)
    for (acct, region), gs in small.items():
        if len(gs) >= 5:
            a.add("logs.no-retention-small", gs, category="hygiene", severity="info", confidence="high",
                  title=f"{len(gs)} small log groups without retention in {region}",
                  detail="Individually cheap, but they grow forever.", advice="Set a default retention (AWS Config rule / org policy) on new log groups.",
                  fid=f"logs.no-retention-small|{acct}|{region}")
    for k in a.of("kms:key"):
        if k.state == "Disabled":
            a.add("kms.key.disabled", k, category="unused", severity="low", confidence="medium", title="Disabled customer-managed KMS key",
                  detail="Disabled keys are still billed $1/month.", advice="If nothing needs the data it protected, schedule the key for deletion (7–30 day wait).",
                  savings=k.est_monthly_usd, basis=k.cost_basis, risk="high")


# --------------------------------------------------------------------------- IAM


def iam(a: Analysis) -> None:
    stale = a.th["stale_iam_days"]
    for acct in a.accounts:
        if str(acct.get("arn", "")).endswith(":root"):
            a.add("sec.iam.root-credentials-used", None, category="security", severity="high", confidence="high",
                  title="This scan ran with the account root credentials",
                  detail=f"Profile '{acct.get('profile')}' authenticates as the root user of account {acct['account']}. "
                         "Root has unrestricted access and cannot be limited by IAM policies, so the read-only guarantee relies only on this tool's own guards.",
                  advice="Create an IAM role/user with the generated read-only policy (python3 -m analyzer policy), use it for scans, "
                         "delete root access keys and enable MFA on root.", fid=f"sec.iam.root-credentials-used|{acct['account']}")
    unused_keys: dict[str, list[tuple[Resource, dict]]] = defaultdict(list)
    old_keys: dict[str, list[tuple[Resource, dict]]] = defaultdict(list)
    inactive: list[Resource] = []
    for u in a.of("iam:user"):
        if a.blind(u, "iam list-access-keys", "iam get-access-key-last-used"):
            continue                                     # key data unreadable: do not claim keys are unused
        active = [k for k in u.attrs.get("access_keys", []) if k.get("status") == "Active"]
        recent_key = False
        for k in active:
            used_age = a.age_days(k.get("last_used"))
            created_age = a.age_days(k.get("created")) or 0
            if (used_age is None and created_age >= stale) or (used_age is not None and used_age >= stale):
                unused_keys[u.account].append((u, k))
            else:
                recent_key = True
            if created_age >= stale:
                old_keys[u.account].append((u, k))
        login_age = a.age_days(u.attrs.get("password_last_used"))
        console_active = login_age is not None and login_age < stale
        if not recent_key and not console_active and (a.age_days(u.created) or 0) >= stale:
            inactive.append(u)
    for acct, items in unused_keys.items():
        a.add("sec.iam.key-unused", [u for u, _k in items], category="security", severity="medium", confidence="high",
              title=f"{len(items)} active access key(s) unused for {stale}+ days",
              detail="; ".join(f"{u.name} ({k['id']}, last used {k.get('last_used') or 'never'})" for u, k in items[:6]) + (" …" if len(items) > 6 else ""),
              advice="Deactivate, then delete, keys nobody uses. Long-lived unused keys are a common breach path.", fid=f"sec.iam.key-unused|{acct}")
    for acct, items in old_keys.items():
        users = {u.key: u for u, _k in items}
        a.add("sec.iam.key-old", list(users.values()), category="security", severity="low", confidence="high",
              title=f"{len(items)} access key(s) older than {stale} days",
              detail="; ".join(f"{u.name} ({k['id']}, created {(k.get('created') or '')[:10]})" for u, k in items[:6]) + (" …" if len(items) > 6 else ""),
              advice="Rotate keys regularly, or better, replace them with IAM roles / Identity Center.", fid=f"sec.iam.key-old|{acct}")
    if inactive:
        a.add("sec.iam.user-inactive", inactive, category="security", severity="low", confidence="medium",
              title=f"{len(inactive)} IAM user(s) inactive for {stale}+ days",
              detail=", ".join(u.name for u in inactive[:8]) + (" …" if len(inactive) > 8 else ""),
              advice="Disable or delete users who no longer sign in or use keys.", fid="sec.iam.user-inactive")
    stale_roles = [r for r in a.of("iam:role")
                   if not a.blind(r, "iam get-role") and (a.age_days(r.created) or 0) >= stale and ((a.age_days(r.attrs.get("last_used")) or 0) >= stale or not r.attrs.get("last_used"))
                   and not (r.attrs.get("path") or "").startswith("/aws-reserved/")]
    if stale_roles:
        a.add("sec.iam.role-unused", stale_roles, category="hygiene", severity="info", confidence="medium",
              title=f"{len(stale_roles)} IAM role(s) not used for {stale}+ days",
              detail=", ".join(r.name for r in stale_roles[:8]) + (" …" if len(stale_roles) > 8 else ""),
              advice="Review and delete roles that no workload assumes (IAM Access Analyzer's unused-access findings can help).", fid="sec.iam.role-unused")
