"""Resource Groups Tagging API: tags for everything + long-tail inventory.

Returns *pseudo* resources flagged ``from_tagging``; ``scan.merge_tagging``
folds their tags into the real resources (matched by ARN) and keeps the rest
as ``other:<service>:<type>`` so services without a dedicated collector still
show up in the inventory.
"""

from __future__ import annotations

from ..model import GLOBAL, Resource, name_from_tags, tags_from_list

NAME = "tagging"
GROUP = "meta"
SCOPE = "regional"


def parse_arn(arn: str) -> tuple[str, str, str, str]:
    """-> (service, region, account, resource)"""
    parts = arn.split(":", 5)
    if len(parts) < 6:
        return "unknown", "", "", arn
    return parts[2], parts[3], parts[4], parts[5]


def collect(ctx) -> list[Resource]:
    out = []
    for m in ctx.aws("resourcegroupstaggingapi", "get-resources").get("ResourceTagMappingList", []):
        arn = m.get("ResourceARN", "")
        service, region, _acct, resource = parse_arn(arn)
        resource = resource.lstrip("/")          # API Gateway: arn:aws:apigateway:<region>::/restapis/<id>/stages/<s>
        if resource.count("/") or resource.count(":"):
            sep = "/" if ("/" in resource and (":" not in resource or resource.index("/") < resource.index(":"))) else ":"
            rtype, _, rid = resource.partition(sep)
        else:
            rtype, rid = "resource", resource
        tags = tags_from_list(m.get("Tags"))
        r = ctx.new(f"other:{service}:{rtype}", rid or resource, region=region or GLOBAL, tags=tags,
                    name=name_from_tags(tags, rid or resource), arn=arn, attrs={"from_tagging": True})
        out.append(r)
    return out
