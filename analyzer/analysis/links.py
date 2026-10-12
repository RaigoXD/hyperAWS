"""Cross-collector relations that need the whole inventory (offline, no AWS calls).

Arrows point from the dependent resource to what it uses. Adds:

* CloudFront -> origin (S3, load balancer, API Gateway, EC2 by its public hostname, or any of those behind a
  Route 53 name in a scanned zone), Route 53 zone -> record targets, log group -> owner, instance -> EKS cluster;
* Lambda -> the queue/stream/table it ``consumes``; SNS topic -> the SQS/Lambda subscribers it ``delivers-to``;
  queue/Lambda -> where failed messages go (``dead-letter-to``); compute -> the IAM role it runs as (``uses-role``);
* ``may-connect``: resource -> resource a security-group rule lets through. It is evidence of *permission*, not of
  traffic, and it is never used for grouping or for deciding that something is in use.

Also detects dangling DNS records (kept on the zone as ``attrs["dangling"]``) for the security rules.
"""

from __future__ import annotations

import re

from ..model import GLOBAL, Resource, make_key

_S3_ORIGIN = re.compile(r"^(?P<bucket>.+?)\.s3[.-]")
_S3_WEBSITE = re.compile(r"^(?P<bucket>.+?)\.s3-website[.-]")
_EXECUTE_API = re.compile(r"^(?P<api>[a-z0-9]+)\.execute-api\.(?P<region>[a-z0-9-]+)\.amazonaws\.com(?:\.cn)?$")
# ec2-203-0-113-25.compute-1.amazonaws.com (us-east-1) / ec2-203-0-113-25.<region>.compute.amazonaws.com
_EC2_HOST = re.compile(r"^ec2-(?P<ip>\d{1,3}(?:-\d{1,3}){3})\.(?:compute-1|[a-z0-9-]+\.compute)\.amazonaws\.com(?:\.cn)?$")
_ELB_REGION = re.compile(r"\.([a-z]{2}(?:-[a-z]+)+-\d)\.elb\.")
MAX_DNS_LINKS = 200
MAX_MAY_CONNECT_PER_SOURCE = 25
MAX_MAY_CONNECT = 2000

API_TYPES = ("apigw:rest-api", "apigw:http-api", "apigw:websocket-api")
# resources whose attrs["sg_ids"] makes them members of a security group (an ENI only mirrors its owner's groups)
SG_MEMBER_TYPES = {"ec2:instance", "lambda:function", "rds:instance", "neptune:instance", "docdb:instance",
                   "elbv2:lb", "elb:clb", "ecs:service"}
# relations that already say "data flows between these two": a may-connect edge next to one is noise
FLOW_KINDS = {"behind", "targets", "serves", "origin", "consumes", "delivers-to", "replica-of"}
_ROLE_ATTRS = {"lambda:function": (("role", None),),
               "ecs:service": (("task_role", "task role"), ("exec_role", "execution role")),
               "eks:cluster": (("role", "cluster role"),),
               "eks:nodegroup": (("node_role", "node role"),)}


def _norm(target: str) -> str:
    t = (target or "").lower().rstrip(".")
    return t.removeprefix("dualstack.")


def norm_arn(arn: str | None) -> str:
    """Lambda ARNs lose their alias/version qualifier; stream (and stream consumer) ARNs become their table/stream ARN."""
    arn = arn or ""
    if ":dynamodb:" in arn:
        arn = arn.split("/stream/")[0]
    elif ":kinesis:" in arn:
        arn = arn.split("/consumer/")[0]
    parts = arn.split(":")
    if len(parts) > 7 and parts[2] == "lambda" and parts[5] == "function":
        arn = ":".join(parts[:7])
    return arn


class _Index:
    """Lookups shared by every handler (built once per analysis)."""

    def __init__(self, resources: list[Resource], gaps: list[dict] | None, scope):
        self.by_key = {r.key: r for r in resources}
        self.blind = {(g["service"], g["op"]) for g in (gaps or [])}      # inventories that could not be read
        if scope is not None:                                              # ... or that this scan was told not to read
            for svc, op in (("s3api", "list-buckets"), ("cloudfront", "list-distributions"),
                            ("elbv2", "describe-load-balancers"), ("elb", "describe-load-balancers")):
                if scope.service_blind(svc):
                    self.blind.add((svc, op))
        self.scope = scope
        self.lb_by_dns = {r.attrs["dns"].lower(): r for r in resources if r.type in ("elbv2:lb", "elb:clb") and r.attrs.get("dns")}
        self.cf_by_domain = {r.attrs["domain"].lower(): r for r in resources if r.type == "cloudfront:distribution" and r.attrs.get("domain")}
        self.buckets = {r.rid: r for r in resources if r.type == "s3:bucket"}
        self.eips = {r.attrs["public_ip"]: r for r in resources if r.type == "ec2:eip" and r.attrs.get("public_ip")}
        self.inst_ips = {r.attrs["public_ip"]: r for r in resources if r.type == "ec2:instance" and r.attrs.get("public_ip")}
        self.by_arn: dict[str, Resource] = {}
        self.apis: dict[tuple[str, str], Resource] = {}
        self.dns_names: dict[str, list[str]] = {}       # public record name -> targets (for CloudFront custom-domain origins)
        for r in resources:
            if r.arn:
                self.by_arn.setdefault(norm_arn(r.arn), r)
            if r.type in API_TYPES:
                self.apis.setdefault((r.region, r.rid), r)
            if r.type == "route53:hosted-zone" and not r.attrs.get("private"):
                for rec in r.attrs.get("records", []):
                    name, target = (rec.get("name") or "").lower().rstrip("."), _norm(rec.get("target"))
                    if name and target and not name.startswith("*"):
                        self.dns_names.setdefault(name, []).append(target)


def resolve_links(resources: list[Resource], gaps: list[dict] | None = None, scope=None) -> None:
    ix = _Index(resources, gaps, scope)
    for r in resources:
        for handler in HANDLERS.get(r.type, ()):
            handler(r, ix)
    _may_connect(resources, ix)          # last: it skips pairs that already have a direct data-flow relation


# --------------------------------------------------------------------------- DNS + edge


def _resolve_dns(target: str, ix: _Index) -> tuple[Resource | None, str | None]:
    """(inventoried resource a normalised DNS target / IP points at, reason it looks dangling). (None, None) = unknown."""
    if target in ix.lb_by_dns:
        return ix.lb_by_dns[target], None
    if target in ix.cf_by_domain:
        return ix.cf_by_domain[target], None
    if target in ix.eips:
        hit = ix.eips[target]
        return hit, (f"points to Elastic IP {target} that is not associated to anything" if hit.state == "unassociated" else None)
    if target in ix.inst_ips:
        return ix.inst_ips[target], None
    m = _S3_WEBSITE.match(target)
    if m:
        if m.group("bucket") in ix.buckets:
            return ix.buckets[m.group("bucket")], None
        if ("s3api", "list-buckets") not in ix.blind:
            return None, (f"S3 website bucket '{m.group('bucket')}' not found in the scanned accounts "
                          f"(if it exists nowhere, anyone could claim it: subdomain takeover)")
        return None, None
    if target.endswith(".cloudfront.net") and ("cloudfront", "list-distributions") not in ix.blind:
        return None, "CloudFront distribution not found in the scanned accounts"
    if (".elb." in target and target.endswith(".amazonaws.com")
            and ("elbv2", "describe-load-balancers") not in ix.blind and ("elb", "describe-load-balancers") not in ix.blind
            and _elb_region_scanned(target, ix.scope)):
        return None, "load balancer not found in the scanned accounts"
    return None, None


def _cloudfront(r: Resource, ix: _Index) -> None:
    for origin in r.attrs.get("origins", []):
        o = _norm(origin)
        hits: list[Resource] = []
        label = None
        m = _S3_WEBSITE.match(o) or _S3_ORIGIN.match(o)
        api, ec2 = _EXECUTE_API.match(o), _EC2_HOST.match(o)
        if o in ix.lb_by_dns:
            hits = [ix.lb_by_dns[o]]
        elif m and m.group("bucket") in ix.buckets:
            hits = [ix.buckets[m.group("bucket")]]
        elif api:                                       # <api id>.execute-api.<region>.amazonaws.com
            hit = ix.apis.get((api.group("region"), api.group("api")))
            hits = [hit] if hit else []
        elif ec2:                                       # an instance's public DNS name encodes its public IP
            ip = ec2.group("ip").replace("-", ".")
            hit = ix.inst_ips.get(ip) or ix.eips.get(ip)
            hits = [hit] if hit else []
        elif o in ix.dns_names:
            # a custom domain: follow one Route 53 hop with the same resolution the zone links use
            found = {h.key: h for h, _why in (_resolve_dns(t, ix) for t in ix.dns_names[o]) if h is not None and h.key != r.key}
            hits, label = [found[k] for k in sorted(found)], f"via {o}"
        for hit in hits:
            r.link(hit.key, "origin", label)


def _zone(z: Resource, ix: _Index) -> None:
    dangling, linked = [], 0
    for rec in z.attrs.get("records", []):
        target = _norm(rec["target"])
        if not target:
            continue
        hit, reason = _resolve_dns(target, ix)
        if reason:
            dangling.append({**rec, "reason": reason})
        if hit is not None and linked < MAX_DNS_LINKS:
            z.relations.append({"to": hit.key, "kind": "dns", "label": rec["name"]})
            linked += 1
    z.attrs["dangling"] = dangling


def _elb_region_scanned(target: str, scope) -> bool:
    """A load balancer hostname carries its region; a region this scan skipped proves nothing."""
    m = _ELB_REGION.search(target)
    return scope is None or m is None or scope.region_scanned(m.group(1))


# --------------------------------------------------------------------------- ownership


def _log_group(r: Resource, ix: _Index) -> None:
    name = r.rid
    acct, region = r.account, r.region
    target = None
    if name.startswith("/aws/lambda/"):
        target = make_key(acct, region, "lambda:function", name.split("/")[3])
    elif name.startswith("/aws/rds/instance/"):
        target = make_key(acct, region, "rds:instance", name.split("/")[4])
    elif name.startswith("/aws/rds/cluster/"):
        target = make_key(acct, region, "rds:cluster", name.split("/")[4])
    elif name.startswith("/aws/eks/"):
        target = make_key(acct, region, "eks:cluster", name.split("/")[3])
    elif name.startswith("API-Gateway-Execution-Logs_"):
        target = make_key(acct, region, "apigw:rest-api", name.split("_")[1].split("/")[0])
    if target and target in ix.by_key:
        r.link(target, "logs-of")


def _node_of(r: Resource, ix: _Index) -> None:
    name = r.tags.get("aws:eks:cluster-name") or r.tags.get("eks:cluster-name")
    if not name:
        name = next((k.split("/", 2)[2] for k in r.tags if k.startswith("kubernetes.io/cluster/")), None)
    if name:
        key = make_key(r.account, r.region, "eks:cluster", name)
        if key in ix.by_key:
            r.link(key, "node-of")


# --------------------------------------------------------------------------- messaging


def _consumes(r: Resource, ix: _Index) -> None:
    """Lambda -> the queue/stream/table its event source mappings poll."""
    # an alias and a version mapping of one function can poll the same source: label the road from all of them,
    # never from whichever the API listed first ("disabled" only when every mapping to that source is switched off)
    by_hit: dict[str, list[dict]] = {}
    for src in r.attrs.get("event_sources") or []:
        hit = ix.by_arn.get(norm_arn(src.get("arn")))
        if hit is not None and hit.key != r.key:
            by_hit.setdefault(hit.key, []).append(src)
    for key, srcs in by_hit.items():
        active = [s for s in srcs if s.get("state") != "Disabled"]
        batches = sorted({s["batch"] for s in active if isinstance(s.get("batch"), int) and s["batch"] > 0})
        label = "disabled" if not active else (f"batch {'/'.join(map(str, batches))}" if batches else None)
        r.link(key, "consumes", label)


def _delivers_to(r: Resource, ix: _Index) -> None:
    """SNS topic -> its SQS/Lambda subscribers (other endpoint kinds are never collected)."""
    for arn in r.attrs.get("subscriber_arns") or []:
        hit = ix.by_arn.get(norm_arn(arn))
        if hit is not None and hit.type in ("sqs:queue", "lambda:function"):
            r.link(hit.key, "delivers-to")


def _dead_letter(r: Resource, ix: _Index) -> None:
    """Queue -> its redrive (dead-letter) queue; Lambda -> where its event source mappings send failed batches."""
    if r.type == "sqs:queue":
        arns = [r.attrs.get("redrive_target")]
    else:
        arns = [s.get("on_failure") for s in r.attrs.get("event_sources") or []]
    for arn in arns:
        hit = ix.by_arn.get(norm_arn(arn)) if arn else None
        if hit is not None and hit.key != r.key and hit.type in ("sqs:queue", "sns:topic"):
            r.link(hit.key, "dead-letter-to")


# --------------------------------------------------------------------------- identity + network reachability


def _uses_role(r: Resource, ix: _Index) -> None:
    """Compute -> the IAM role it runs as, only when that role is in the inventory (IAM is global: region 'global')."""
    if r.type == "ec2:instance":
        # the instance profile name usually equals its role's name; describe-instances does not say which role it holds
        wanted = [(r.attrs.get("iam_profile"), "instance profile (same name)")]
    else:
        wanted = [(r.attrs.get(attr), label) for attr, label in _ROLE_ATTRS.get(r.type, ())]
    for name, label in wanted:
        key = make_key(r.account, GLOBAL, "iam:role", name) if name else None
        if key in ix.by_key:
            r.link(key, "uses-role", label)


def _may_connect(resources: list[Resource], ix: _Index) -> None:
    """Members of X -> members of G for every ingress rule of G that admits security group X (same account+region).

    Members are resources attached to the group (a ``uses-sg`` relation or ``attrs["sg_ids"]``), never ENIs. Pairs
    that already have a direct data-flow relation are skipped; the output is capped (per source and in total) in a
    stable order so the same scan always yields the same edges.
    """
    groups = sorted((g for g in resources if g.type == "ec2:security-group" and g.attrs.get("ingress_from")),
                    key=lambda g: g.key)
    if not groups:
        return
    members: dict[str, set[str]] = {}
    for r in resources:
        if r.type == "ec2:eni":
            continue
        for rel in r.relations:
            if rel["kind"] == "uses-sg":
                members.setdefault(rel["to"], set()).add(r.key)
        if r.type in SG_MEMBER_TYPES:
            for sg_id in r.attrs.get("sg_ids") or []:
                members.setdefault(make_key(r.account, r.region, "ec2:security-group", sg_id), set()).add(r.key)
    flows = {(r.key, rel["to"]) for r in resources for rel in r.relations if rel["kind"] in FLOW_KINDS}
    pairs: dict[tuple[str, str], list[str]] = {}
    for g in groups:
        targets = sorted(members.get(g.key, ()))
        ports_by_src: dict[str, list[str]] = {}
        for item in g.attrs.get("ingress_from") or []:
            if item.get("sg"):
                ports_by_src.setdefault(item["sg"], []).append(item.get("ports") or "all")
        for src_id in sorted(ports_by_src):
            if src_id == g.rid:                      # a group admitting itself says nothing about two different things
                continue
            for a in sorted(members.get(make_key(g.account, g.region, "ec2:security-group", src_id), ())):
                for b in targets:
                    if a == b or (a, b) in flows or (b, a) in flows:
                        continue
                    ports = pairs.setdefault((a, b), [])
                    ports += [p for p in ports_by_src[src_id] if p not in ports]
    per_source: dict[str, int] = {}
    total = 0
    for (a, b) in sorted(pairs):
        if total >= MAX_MAY_CONNECT:
            break
        if per_source.get(a, 0) >= MAX_MAY_CONNECT_PER_SOURCE:
            continue
        if ix.by_key[a].link(b, "may-connect", ", ".join(pairs[(a, b)])):
            per_source[a] = per_source.get(a, 0) + 1
            total += 1


# a resource type may need several handlers; may-connect runs separately, after all of them
HANDLERS = {
    "cloudfront:distribution": (_cloudfront,),
    "route53:hosted-zone": (_zone,),
    "logs:log-group": (_log_group,),
    "ec2:instance": (_node_of, _uses_role),
    "lambda:function": (_consumes, _dead_letter, _uses_role),
    "sns:topic": (_delivers_to,),
    "sqs:queue": (_dead_letter,),
    "ecs:service": (_uses_role,),
    "eks:cluster": (_uses_role,),
    "eks:nodegroup": (_uses_role,),
}
