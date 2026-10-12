"""DynamoDB tables (metadata only; never reads items)."""

from __future__ import annotations

from ..model import Resource, to_iso

NAME = "dynamodb"
GROUP = "data"
SCOPE = "regional"


def collect(ctx) -> list[Resource]:
    names = ctx.aws("dynamodb", "list-tables").get("TableNames", [])
    tables = ctx.map(
        lambda n: ctx.aws("dynamodb", "describe-table", [f"--table-name={n}"]).get("Table"), names)
    out = []
    for t in tables:
        if not t:
            continue
        pt = t.get("ProvisionedThroughput") or {}
        billing = (t.get("BillingModeSummary") or {}).get("BillingMode") or (
            "PROVISIONED" if pt.get("ReadCapacityUnits") else "PAY_PER_REQUEST")
        gsis = t.get("GlobalSecondaryIndexes", [])
        out.append(ctx.new("dynamodb:table", t["TableName"], name=t["TableName"], state=t.get("TableStatus", ""),
                           created=to_iso(t.get("CreationDateTime")), arn=t.get("TableArn"),
                           attrs={"billing_mode": billing,
                                  "rcu": pt.get("ReadCapacityUnits", 0), "wcu": pt.get("WriteCapacityUnits", 0),
                                  "gsi_count": len(gsis),
                                  "gsi_rcu": sum((g.get("ProvisionedThroughput") or {}).get("ReadCapacityUnits", 0) for g in gsis),
                                  "gsi_wcu": sum((g.get("ProvisionedThroughput") or {}).get("WriteCapacityUnits", 0) for g in gsis),
                                  "size_bytes": t.get("TableSizeBytes", 0), "item_count": t.get("ItemCount", 0),
                                  "table_class": (t.get("TableClassSummary") or {}).get("TableClass", "STANDARD"),
                                  "streams": bool((t.get("StreamSpecification") or {}).get("StreamEnabled")),
                                  "deletion_protection": bool(t.get("DeletionProtectionEnabled"))}))
    return out
