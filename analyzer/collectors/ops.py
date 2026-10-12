"""Regional operations resources: CloudWatch Logs groups and customer-managed KMS keys."""

from __future__ import annotations

from ..model import Resource, to_iso

NAME = "ops"
GROUP = "edge"
SCOPE = "regional"


def collect(ctx) -> list[Resource]:
    return _log_groups(ctx) + _kms(ctx)


def _log_groups(ctx) -> list[Resource]:
    out = []
    for g in ctx.aws("logs", "describe-log-groups").get("logGroups", []):
        name = g["logGroupName"]
        arn = (g.get("logGroupArn") or "").removesuffix(":*") or ctx.arn("logs", f"log-group:{name}")
        out.append(ctx.new("logs:log-group", name, name=name, state="", created=to_iso((g.get("creationTime") or 0) / 1000 or None),
                           arn=arn,
                           attrs={"retention_days": g.get("retentionInDays"),  # None = never expires
                                  "stored_bytes": g.get("storedBytes", 0), "class": g.get("logGroupClass", "STANDARD")}))
    return out


def _kms(ctx) -> list[Resource]:
    keys = ctx.aws("kms", "list-keys").get("Keys", [])
    if not keys:
        return []
    aliases: dict[str, list[str]] = {}
    for a in ctx.aws("kms", "list-aliases").get("Aliases", []):
        if a.get("TargetKeyId"):
            aliases.setdefault(a["TargetKeyId"], []).append(a["AliasName"])

    def meta(k):
        return ctx.aws("kms", "describe-key", [f"--key-id={k['KeyId']}"]).get("KeyMetadata") or {}

    out = []
    for m in ctx.map(meta, keys):
        if m.get("KeyManager") != "CUSTOMER":  # AWS-managed keys are free and uninteresting
            continue
        kid = m["KeyId"]
        al = aliases.get(kid, [])
        out.append(ctx.new("kms:key", kid, name=al[0].replace("alias/", "") if al else kid,
                           state=m.get("KeyState", ""), created=to_iso(m.get("CreationDate")), arn=m.get("Arn"),
                           attrs={"aliases": al, "enabled": bool(m.get("Enabled")), "key_spec": m.get("KeySpec"),
                                  "multi_region": bool(m.get("MultiRegion")),
                                  "deletion_date": to_iso(m.get("DeletionDate")),
                                  "description": (m.get("Description") or "")[:120]}))
    return out
