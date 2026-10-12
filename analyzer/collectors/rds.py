"""RDS instances, Aurora clusters and manual snapshots."""

from __future__ import annotations

from ..model import Resource, tags_from_list, to_iso

NAME = "rds"
GROUP = "data"
SCOPE = "regional"


# describe-db-instances/-clusters/-snapshots also return Neptune and DocumentDB rows. They are not RDS: different
# pricing, different metrics namespace. Keep them visible under their own type but out of the RDS rules/prices.
_FOREIGN = {"neptune": "neptune", "docdb": "docdb"}


def _kind(engine: str | None, base: str) -> str:
    return f"{_FOREIGN[engine]}:{base}" if engine in _FOREIGN else f"rds:{base}"


def _is_aurora(engine: str | None) -> bool:
    return (engine or "").startswith("aurora")


def collect(ctx) -> list[Resource]:
    out: list[Resource] = []

    for d in ctx.aws("rds", "describe-db-instances").get("DBInstances", []):
        iid = d["DBInstanceIdentifier"]
        vpc = (d.get("DBSubnetGroup") or {}).get("VpcId")
        sgs = [g["VpcSecurityGroupId"] for g in d.get("VpcSecurityGroups", [])]
        r = ctx.new(_kind(d.get("Engine"), "instance"), iid, name=iid, state=d.get("DBInstanceStatus", ""),
                    created=to_iso(d.get("InstanceCreateTime")), arn=d.get("DBInstanceArn"),
                    tags=tags_from_list(d.get("TagList")),
                    attrs={"engine": d.get("Engine"), "engine_version": d.get("EngineVersion"),
                           "instance_class": d.get("DBInstanceClass"), "multi_az": bool(d.get("MultiAZ")),
                           # Aurora reports a placeholder AllocatedStorage: its storage is cluster-level and elastic
                           "storage_gb": None if _is_aurora(d.get("Engine")) else d.get("AllocatedStorage"),
                           "storage_type": d.get("StorageType"),
                           "iops": d.get("Iops"), "az": d.get("AvailabilityZone"),
                           "public": bool(d.get("PubliclyAccessible")), "vpc": vpc, "sg_ids": sgs,
                           "cluster": d.get("DBClusterIdentifier"),
                           "read_replica_of": d.get("ReadReplicaSourceDBInstanceIdentifier"),
                           "encrypted": bool(d.get("StorageEncrypted")),
                           "backup_retention_days": d.get("BackupRetentionPeriod"),
                           "license": d.get("LicenseModel")})
        if vpc:
            r.link(ctx.key("ec2:vpc", vpc), "in-vpc")
        for g in sgs:
            r.link(ctx.key("ec2:security-group", g), "uses-sg")
        if d.get("DBClusterIdentifier"):
            r.link(ctx.key("rds:cluster", d["DBClusterIdentifier"]), "member-of")
        if d.get("ReadReplicaSourceDBInstanceIdentifier"):
            r.link(ctx.key("rds:instance", d["ReadReplicaSourceDBInstanceIdentifier"]), "replica-of")
        out.append(r)

    for c in ctx.aws("rds", "describe-db-clusters").get("DBClusters", []):
        cid = c["DBClusterIdentifier"]
        sv2 = c.get("ServerlessV2ScalingConfiguration") or {}
        out.append(ctx.new(_kind(c.get("Engine"), "cluster"), cid, name=cid, state=c.get("Status", ""),
                           created=to_iso(c.get("ClusterCreateTime")), arn=c.get("DBClusterArn"),
                           tags=tags_from_list(c.get("TagList")),
                           attrs={"engine": c.get("Engine"), "engine_version": c.get("EngineVersion"),
                                  "multi_az": bool(c.get("MultiAZ")), "members": len(c.get("DBClusterMembers", [])),
                                  "serverless_v2": bool(sv2),
                                  "acu_min": sv2.get("MinCapacity"), "acu_max": sv2.get("MaxCapacity"),
                                  "storage_gb": None if _is_aurora(c.get("Engine")) else c.get("AllocatedStorage"),
                                  "storage_type": c.get("StorageType"),
                                  "encrypted": bool(c.get("StorageEncrypted"))}))

    for s in ctx.aws("rds", "describe-db-snapshots", ["--snapshot-type", "manual"]).get("DBSnapshots", []):
        sid = s["DBSnapshotIdentifier"]
        if s.get("Engine") in _FOREIGN:
            continue
        r = ctx.new("rds:snapshot", sid, name=sid, state=s.get("Status", ""),
                    created=to_iso(s.get("SnapshotCreateTime")), arn=s.get("DBSnapshotArn"),
                    tags=tags_from_list(s.get("TagList")),
                    attrs={"source": s.get("DBInstanceIdentifier"), "engine": s.get("Engine"),
                           "size_gb": None if _is_aurora(s.get("Engine")) else s.get("AllocatedStorage"),
                           "source_region": s.get("SourceRegion")})   # set on cross-region copies
        if s.get("DBInstanceIdentifier") and not s.get("SourceRegion"):
            r.link(ctx.key("rds:instance", s["DBInstanceIdentifier"]), "snapshot-of")
        out.append(r)

    for s in ctx.aws("rds", "describe-db-cluster-snapshots", ["--snapshot-type", "manual"]).get("DBClusterSnapshots", []):
        sid = s["DBClusterSnapshotIdentifier"]
        if s.get("Engine") in _FOREIGN:
            continue
        r = ctx.new("rds:cluster-snapshot", sid, name=sid, state=s.get("Status", ""),
                    created=to_iso(s.get("SnapshotCreateTime")), arn=s.get("DBClusterSnapshotArn"),
                    tags=tags_from_list(s.get("TagList")),
                    attrs={"source": s.get("DBClusterIdentifier"), "engine": s.get("Engine"),
                           "size_gb": None if _is_aurora(s.get("Engine")) else s.get("AllocatedStorage"),
                           "source_region": s.get("SourceRegion")})
        if s.get("DBClusterIdentifier") and not s.get("SourceRegion"):
            r.link(ctx.key("rds:cluster", s["DBClusterIdentifier"]), "snapshot-of")
        out.append(r)
    return out
