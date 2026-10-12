"""Global edge services: CloudFront distributions and Route 53 zones/records."""

from __future__ import annotations

import re

from ..model import Resource, to_iso

NAME = "edge"
GROUP = "edge"
SCOPE = "global"

MAX_RECORDS_PER_ZONE = 400
_OCTAL = re.compile(r"\\(\d{3})")


def dns_name(name: str) -> str:
    """Route 53 returns names with octal escapes (wildcard * is \\052, IDN letters too); decode and drop the trailing dot."""
    return _OCTAL.sub(lambda m: chr(int(m.group(1), 8)), name).rstrip(".")


_RECORD_TYPES = {"A", "AAAA", "CNAME", "ALIAS"}
# Same shape as the API answer, minus everything not read below. Origins can carry CustomHeaders whose values are
# often the shared secret between CloudFront and the origin (X-Origin-Verify): those never reach this process.
# The CLI merges all pages first and applies --query once, and keeps projected keys (as null when missing).
_DISTRIBUTIONS_QUERY = ("{DistributionList:{Items:DistributionList.Items[].{Id:Id,ARN:ARN,DomainName:DomainName,"
                        "Comment:Comment,Enabled:Enabled,Status:Status,PriceClass:PriceClass,HttpVersion:HttpVersion,"
                        "LastModifiedTime:LastModifiedTime,Aliases:Aliases,Origins:{Items:Origins.Items[].{DomainName:DomainName}}}}}")


def collect(ctx) -> list[Resource]:
    return _cloudfront(ctx) + _route53(ctx)


def _cloudfront(ctx) -> list[Resource]:
    out = []
    resp = ctx.aws("cloudfront", "list-distributions", ["--query", _DISTRIBUTIONS_QUERY]) or {}
    items = (resp.get("DistributionList") or {}).get("Items") or []
    for d in items:
        aliases = (d.get("Aliases") or {}).get("Items") or []
        origins = [o.get("DomainName") for o in (d.get("Origins") or {}).get("Items") or [] if o.get("DomainName")]
        did = d["Id"]
        out.append(ctx.new("cloudfront:distribution", did, name=d.get("Comment") or (aliases[0] if aliases else d.get("DomainName") or did),
                           state="enabled" if d.get("Enabled") else "disabled", created=None,
                           arn=d.get("ARN"),
                           attrs={"domain": d.get("DomainName"), "aliases": aliases, "origins": origins,
                                  "price_class": d.get("PriceClass"), "status": d.get("Status"),
                                  "last_modified": to_iso(d.get("LastModifiedTime")),
                                  "http_version": d.get("HttpVersion")}))
    return out


def _route53(ctx) -> list[Resource]:
    zones = ctx.aws("route53", "list-hosted-zones").get("HostedZones", [])

    def records(z):
        zid = z["Id"].split("/")[-1]
        recs = ctx.aws("route53", "list-resource-record-sets", [f"--hosted-zone-id={zid}"]).get("ResourceRecordSets", [])
        return z, recs

    out = []
    for z, recs in ctx.map(records, zones):
        zid = z["Id"].split("/")[-1]
        slim = []
        for rec in recs:
            if rec.get("Type") not in _RECORD_TYPES:
                continue
            alias = (rec.get("AliasTarget") or {}).get("DNSName")
            vals = [v.get("Value") for v in rec.get("ResourceRecords", [])]
            slim.append({"name": dns_name(rec["Name"]), "type": "ALIAS" if alias else rec["Type"],
                         "target": dns_name(alias or (vals[0] if vals else ""))})
        out.append(ctx.new("route53:hosted-zone", zid, name=dns_name(z["Name"]), state="",
                           arn=f"arn:{ctx.partition}:route53:::hostedzone/{zid}",
                           attrs={"private": bool((z.get("Config") or {}).get("PrivateZone")),
                                  "record_count": z.get("ResourceRecordSetCount", len(recs)),
                                  "records": slim[:MAX_RECORDS_PER_ZONE],
                                  "records_truncated": len(slim) > MAX_RECORDS_PER_ZONE}))
    return out
