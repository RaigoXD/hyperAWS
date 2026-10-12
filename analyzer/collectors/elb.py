"""Application/Network/Gateway load balancers, target groups (+health), classic ELBs."""

from __future__ import annotations

from ..model import Resource, to_iso

NAME = "elb"
GROUP = "compute"
SCOPE = "regional"


def collect(ctx) -> list[Resource]:
    out: list[Resource] = []
    lb_key_by_arn: dict[str, str] = {}

    for lb in ctx.aws("elbv2", "describe-load-balancers").get("LoadBalancers", []):
        name = lb["LoadBalancerName"]
        azs = lb.get("AvailabilityZones", [])
        r = ctx.new("elbv2:lb", name, name=name, state=(lb.get("State") or {}).get("Code", ""),
                    created=to_iso(lb.get("CreatedTime")), arn=lb.get("LoadBalancerArn"),
                    attrs={"lb_type": lb.get("Type"), "scheme": lb.get("Scheme"),
                           "dns": lb.get("DNSName"), "vpc": lb.get("VpcId"),
                           "subnet_ids": [a["SubnetId"] for a in azs if a.get("SubnetId")],
                           "az_count": len(azs), "sg_ids": lb.get("SecurityGroups", []),
                           "ip_type": lb.get("IpAddressType")})
        for a in azs:
            if a.get("SubnetId"):
                r.link(ctx.key("ec2:subnet", a["SubnetId"]), "in-subnet")
        lb_key_by_arn[lb["LoadBalancerArn"]] = r.key
        out.append(r)

    tgs = ctx.aws("elbv2", "describe-target-groups").get("TargetGroups", [])

    def health(tg):
        return ctx.aws("elbv2", "describe-target-health",
                       [f"--target-group-arn={tg['TargetGroupArn']}"]).get("TargetHealthDescriptions", [])

    for tg, targets in zip(tgs, ctx.map(health, tgs)):
        states = [(t.get("TargetHealth") or {}).get("State") for t in targets]
        ttype = tg.get("TargetType", "instance")
        ids = [(t.get("Target") or {}).get("Id") for t in targets]
        r = ctx.new("elbv2:target-group", tg["TargetGroupName"], name=tg["TargetGroupName"],
                    state="", arn=tg["TargetGroupArn"],
                    attrs={"target_type": ttype, "protocol": tg.get("Protocol"), "port": tg.get("Port"),
                           "vpc": tg.get("VpcId"), "lb_arns": tg.get("LoadBalancerArns", []),
                           "targets_total": len(targets),
                           "targets_healthy": states.count("healthy"),
                           "targets_unhealthy": states.count("unhealthy"),
                           "target_ids": [i for i in ids if i][:50]})
        for arn in tg.get("LoadBalancerArns", []):
            if arn in lb_key_by_arn:
                r.link(lb_key_by_arn[arn], "behind")
        for tid in ids:
            if not tid:
                continue
            if ttype == "instance":
                r.link(ctx.key("ec2:instance", tid), "targets")
            elif ttype == "lambda" and ":function:" in tid:
                r.link(ctx.key("lambda:function", tid.split(":function:")[1].split(":")[0]), "targets")
        out.append(r)

    for lb in ctx.aws("elb", "describe-load-balancers").get("LoadBalancerDescriptions", []):
        name = lb["LoadBalancerName"]
        inst = [i["InstanceId"] for i in lb.get("Instances", [])]
        r = ctx.new("elb:clb", name, name=name, state="active", created=to_iso(lb.get("CreatedTime")),
                    arn=ctx.arn("elasticloadbalancing", f"loadbalancer/{name}"),
                    attrs={"scheme": lb.get("Scheme"), "dns": lb.get("DNSName"), "vpc": lb.get("VPCId"),
                           "subnet_ids": lb.get("Subnets", []), "sg_ids": lb.get("SecurityGroups", []),
                           "instance_ids": inst, "listeners": len(lb.get("ListenerDescriptions", []))})
        for i in inst:
            r.link(ctx.key("ec2:instance", i), "targets")
        for s in lb.get("Subnets", []):
            r.link(ctx.key("ec2:subnet", s), "in-subnet")
        out.append(r)
    return out
