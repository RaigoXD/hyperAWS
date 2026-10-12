"""ElastiCache clusters (Redis/Valkey/Memcached) and replication groups."""

from __future__ import annotations

from ..model import Resource, to_iso

NAME = "elasticache"
GROUP = "data"
SCOPE = "regional"


def collect(ctx) -> list[Resource]:
    out = []
    for c in ctx.aws("elasticache", "describe-cache-clusters").get("CacheClusters", []):
        cid = c["CacheClusterId"]
        r = ctx.new("elasticache:cluster", cid, name=cid, state=c.get("CacheClusterStatus", ""),
                    created=to_iso(c.get("CacheClusterCreateTime")), arn=c.get("ARN"),
                    attrs={"engine": c.get("Engine"), "engine_version": c.get("EngineVersion"),
                           "node_type": c.get("CacheNodeType"), "nodes": c.get("NumCacheNodes", 1),
                           "replication_group": c.get("ReplicationGroupId"), "az": c.get("PreferredAvailabilityZone")})
        if c.get("ReplicationGroupId"):
            r.link(ctx.key("elasticache:replication-group", c["ReplicationGroupId"]), "member-of")
        out.append(r)
    for g in ctx.aws("elasticache", "describe-replication-groups").get("ReplicationGroups", []):
        gid = g["ReplicationGroupId"]
        out.append(ctx.new("elasticache:replication-group", gid, name=gid, state=g.get("Status", ""),
                           arn=g.get("ARN"),
                           attrs={"node_type": g.get("CacheNodeType"), "members": len(g.get("MemberClusters", [])),
                                  "cluster_mode": g.get("ClusterEnabled"), "multi_az": g.get("MultiAZ") == "enabled",
                                  "automatic_failover": g.get("AutomaticFailover")}))
    return out
