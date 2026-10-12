"""EC2, EBS, snapshots, AMIs, Elastic IPs, ENIs, NAT, VPC, subnets, endpoints, SGs.

Relations always point from the dependent thing to the thing it depends on:
instance -> subnet, volume -> instance, eip -> instance/eni, nat -> subnet,
subnet -> vpc, subnet -> nat (egress), snapshot -> volume, ami -> snapshot.
"""

from __future__ import annotations

import re

from ..model import Resource, name_from_tags, tags_from_list, to_iso

NAME = "ec2_net"
GROUP = "compute"
SCOPE = "regional"

_STOP_RE = re.compile(r"\((\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) GMT\)")
_AMI_RE = re.compile(r"\bami-[0-9a-f]{8,17}\b")
MAX_INGRESS_FROM = 50
_PROTO_NAMES = {"6": "tcp", "17": "udp", "1": "icmp", "58": "icmpv6"}   # IpProtocol may be a number


def collect(ctx) -> list[Resource]:
    out: list[Resource] = []
    out += _vpcs(ctx)
    subnets = _subnets(ctx)
    out += subnets
    nat_routes = _route_links(ctx, subnets)  # also adds subnet -> nat egress relations
    out += _instances(ctx)
    out += _volumes(ctx)
    out += _snapshots(ctx)
    out += _images(ctx)
    out += _addresses(ctx)
    out += _enis(ctx)
    out += _nat_gateways(ctx, nat_routes)
    out += _igws(ctx)
    out += _endpoints(ctx)
    out += _security_groups(ctx)
    return out


# --------------------------------------------------------------------------


def _vpcs(ctx) -> list[Resource]:
    res = []
    for v in ctx.aws("ec2", "describe-vpcs").get("Vpcs", []):
        tags = tags_from_list(v.get("Tags"))
        r = ctx.new("ec2:vpc", v["VpcId"], tags=tags, state=v.get("State", ""),
                    name=name_from_tags(tags, v["VpcId"]),
                    arn=ctx.arn("ec2", f"vpc/{v['VpcId']}"),
                    attrs={"cidr": v.get("CidrBlock"), "is_default": bool(v.get("IsDefault"))})
        res.append(r)
    return res


def _subnets(ctx) -> list[Resource]:
    res = []
    for s in ctx.aws("ec2", "describe-subnets").get("Subnets", []):
        tags = tags_from_list(s.get("Tags"))
        r = ctx.new("ec2:subnet", s["SubnetId"], tags=tags, state=s.get("State", ""),
                    name=name_from_tags(tags, s["SubnetId"]),
                    arn=ctx.arn("ec2", f"subnet/{s['SubnetId']}"),
                    attrs={"vpc": s.get("VpcId"), "cidr": s.get("CidrBlock"),
                           "az": s.get("AvailabilityZone"),
                           "free_ips": s.get("AvailableIpAddressCount"),
                           "public_on_launch": bool(s.get("MapPublicIpOnLaunch")),
                           "is_default": bool(s.get("DefaultForAz"))})
        if s.get("VpcId"):
            r.link(ctx.key("ec2:vpc", s["VpcId"]), "in-vpc")
        res.append(r)
    return res


def _route_links(ctx, subnets: list[Resource]) -> dict[str, int]:
    """Derive subnet -> NAT egress links; returns {nat id: route tables pointing at it}.

    Route tables themselves are not emitted as resources (they cost nothing).
    """
    rts = ctx.aws("ec2", "describe-route-tables").get("RouteTables", [])
    by_id = {s.rid: s for s in subnets}
    subnets_by_vpc: dict[str, list[Resource]] = {}
    for s in subnets:
        subnets_by_vpc.setdefault(s.attrs.get("vpc"), []).append(s)
    explicit: set[str] = {a["SubnetId"] for rt in rts for a in rt.get("Associations", []) if a.get("SubnetId")}
    nat_routes: dict[str, int] = {}
    for rt in rts:
        nats = {r["NatGatewayId"] for r in rt.get("Routes", []) if r.get("NatGatewayId")}
        if not nats:
            continue
        targets: list[Resource] = []
        for a in rt.get("Associations", []):
            if a.get("SubnetId") in by_id:
                targets.append(by_id[a["SubnetId"]])
            elif a.get("Main"):
                targets += [s for s in subnets_by_vpc.get(rt.get("VpcId"), []) if s.rid not in explicit]
        for nat in nats:
            nat_routes[nat] = nat_routes.get(nat, 0) + 1
            for s in targets:
                s.link(ctx.key("ec2:nat-gateway", nat), "egress-via")
    return nat_routes


def _instances(ctx) -> list[Resource]:
    res = []
    for resv in ctx.aws("ec2", "describe-instances").get("Reservations", []):
        for i in resv.get("Instances", []):
            state = i.get("State", {}).get("Name", "")
            if state in ("terminated",):
                continue
            iid = i["InstanceId"]
            tags = tags_from_list(i.get("Tags"))
            stopped_at = None
            if state == "stopped":
                m = _STOP_RE.search(i.get("StateTransitionReason", "") or "")
                if m:
                    stopped_at = to_iso(m.group(1).replace(" ", "T") + "Z")
            sg_ids = [g["GroupId"] for g in i.get("SecurityGroups", [])]
            vol_ids = [b["Ebs"]["VolumeId"] for b in i.get("BlockDeviceMappings", []) if b.get("Ebs")]
            r = ctx.new("ec2:instance", iid, tags=tags, state=state,
                        name=name_from_tags(tags, iid), created=to_iso(i.get("LaunchTime")),
                        arn=ctx.arn("ec2", f"instance/{iid}"),
                        attrs={
                            "instance_type": i.get("InstanceType"),
                            "arch": i.get("Architecture"),
                            "platform": i.get("PlatformDetails") or i.get("Platform") or "Linux/UNIX",
                            "az": i.get("Placement", {}).get("AvailabilityZone"),
                            "vpc": i.get("VpcId"), "subnet": i.get("SubnetId"),
                            "private_ip": i.get("PrivateIpAddress"),
                            "public_ip": i.get("PublicIpAddress"),
                            "ami": i.get("ImageId"),
                            "lifecycle": i.get("InstanceLifecycle"),  # spot / scheduled / None
                            "stopped_at": stopped_at,
                            "sg_ids": sg_ids, "volume_ids": vol_ids,
                            "iam_profile": (i.get("IamInstanceProfile") or {}).get("Arn", "").split("/")[-1] or None,
                        })
            if i.get("SubnetId"):
                r.link(ctx.key("ec2:subnet", i["SubnetId"]), "in-subnet")
            for g in sg_ids:
                r.link(ctx.key("ec2:security-group", g), "uses-sg")
            res.append(r)
    return res


def _volumes(ctx) -> list[Resource]:
    res = []
    for v in ctx.aws("ec2", "describe-volumes").get("Volumes", []):
        vid = v["VolumeId"]
        tags = tags_from_list(v.get("Tags"))
        attach = [a for a in v.get("Attachments", []) if a.get("InstanceId")]
        r = ctx.new("ec2:volume", vid, tags=tags, state=v.get("State", ""),
                    name=name_from_tags(tags, vid), created=to_iso(v.get("CreateTime")),
                    arn=ctx.arn("ec2", f"volume/{vid}"),
                    attrs={"size_gb": v.get("Size"), "vol_type": v.get("VolumeType"),
                           "iops": v.get("Iops"), "throughput": v.get("Throughput"),
                           "encrypted": bool(v.get("Encrypted")), "az": v.get("AvailabilityZone"),
                           "snapshot_id": v.get("SnapshotId") or None,
                           "attached_to": [a["InstanceId"] for a in attach],
                           "delete_on_termination": any(a.get("DeleteOnTermination") for a in attach)})
        for a in attach:
            r.link(ctx.key("ec2:instance", a["InstanceId"]), "attached-to")
        res.append(r)
    return res


def _snapshots(ctx) -> list[Resource]:
    res = []
    for s in ctx.aws("ec2", "describe-snapshots", ["--owner-ids", "self"]).get("Snapshots", []):
        sid = s["SnapshotId"]
        tags = tags_from_list(s.get("Tags"))
        desc = (s.get("Description") or "")[:160]
        ami = _AMI_RE.search(desc)
        r = ctx.new("ec2:snapshot", sid, tags=tags, state=s.get("State", ""),
                    name=name_from_tags(tags, sid), created=to_iso(s.get("StartTime")),
                    arn=ctx.arn("ec2", f"snapshot/{sid}", account=False),
                    attrs={"volume_id": s.get("VolumeId") if s.get("VolumeId") not in (None, "vol-ffffffff") else None,
                           "size_gb": s.get("VolumeSize"), "description": desc,
                           "ami_id": ami.group(0) if ami else None,
                           "tier": s.get("StorageTier", "standard")})
        if r.attrs["volume_id"]:
            r.link(ctx.key("ec2:volume", r.attrs["volume_id"]), "snapshot-of")
        res.append(r)
    return res


def _images(ctx) -> list[Resource]:
    res = []
    for im in ctx.aws("ec2", "describe-images", ["--owners", "self", "--include-disabled"]).get("Images", []):
        iid = im["ImageId"]
        tags = tags_from_list(im.get("Tags"))
        snaps = [b["Ebs"]["SnapshotId"] for b in im.get("BlockDeviceMappings", [])
                 if b.get("Ebs", {}).get("SnapshotId")]
        r = ctx.new("ec2:ami", iid, tags=tags, state=im.get("State", ""),
                    name=im.get("Name") or name_from_tags(tags, iid), created=to_iso(im.get("CreationDate")),
                    arn=ctx.arn("ec2", f"image/{iid}", account=False),
                    attrs={"snapshot_ids": snaps, "public": bool(im.get("Public")),
                           "arch": im.get("Architecture"), "ami_name": im.get("Name")})
        for s in snaps:
            r.link(ctx.key("ec2:snapshot", s), "backed-by")
        res.append(r)
    return res


def _addresses(ctx) -> list[Resource]:
    res = []
    for a in ctx.aws("ec2", "describe-addresses").get("Addresses", []):
        rid = a.get("AllocationId") or a.get("PublicIp")
        tags = tags_from_list(a.get("Tags"))
        associated = bool(a.get("AssociationId") or a.get("InstanceId") or a.get("NetworkInterfaceId"))
        r = ctx.new("ec2:eip", rid, tags=tags, state="associated" if associated else "unassociated",
                    name=name_from_tags(tags, a.get("PublicIp") or rid),
                    arn=ctx.arn("ec2", f"elastic-ip/{rid}"),
                    attrs={"public_ip": a.get("PublicIp"), "domain": a.get("Domain"),
                           "instance_id": a.get("InstanceId"), "eni_id": a.get("NetworkInterfaceId"),
                           "private_ip": a.get("PrivateIpAddress")})
        if a.get("InstanceId"):
            r.link(ctx.key("ec2:instance", a["InstanceId"]), "associated-with")
        if a.get("NetworkInterfaceId"):
            r.link(ctx.key("ec2:eni", a["NetworkInterfaceId"]), "associated-with")
        res.append(r)
    return res


def _enis(ctx) -> list[Resource]:
    res = []
    for e in ctx.aws("ec2", "describe-network-interfaces").get("NetworkInterfaces", []):
        eid = e["NetworkInterfaceId"]
        tags = tags_from_list(e.get("TagSet"))
        att = e.get("Attachment") or {}
        sg_ids = [g["GroupId"] for g in e.get("Groups", [])]
        r = ctx.new("ec2:eni", eid, tags=tags, state=e.get("Status", ""),
                    name=name_from_tags(tags, eid),
                    arn=ctx.arn("ec2", f"network-interface/{eid}"),
                    attrs={"if_type": e.get("InterfaceType"), "description": (e.get("Description") or "")[:120],
                           "instance_id": att.get("InstanceId"), "requester_managed": bool(e.get("RequesterManaged")),
                           "private_ip": e.get("PrivateIpAddress"),
                           "public_ip": (e.get("Association") or {}).get("PublicIp"),
                           "subnet": e.get("SubnetId"), "vpc": e.get("VpcId"), "sg_ids": sg_ids})
        if att.get("InstanceId"):
            r.link(ctx.key("ec2:instance", att["InstanceId"]), "attached-to")
        if e.get("SubnetId"):
            r.link(ctx.key("ec2:subnet", e["SubnetId"]), "in-subnet")
        res.append(r)
    return res


def _nat_gateways(ctx, nat_routes: dict[str, int]) -> list[Resource]:
    res = []
    for n in ctx.aws("ec2", "describe-nat-gateways").get("NatGateways", []):
        if n.get("State") in ("deleted", "deleting"):
            continue
        nid = n["NatGatewayId"]
        tags = tags_from_list(n.get("Tags"))
        addrs = n.get("NatGatewayAddresses", [])
        r = ctx.new("ec2:nat-gateway", nid, tags=tags, state=n.get("State", ""),
                    name=name_from_tags(tags, nid), created=to_iso(n.get("CreateTime")),
                    arn=ctx.arn("ec2", f"natgateway/{nid}"),
                    attrs={"vpc": n.get("VpcId"), "subnet": n.get("SubnetId"),
                           "connectivity": n.get("ConnectivityType", "public"),
                           "availability_mode": n.get("AvailabilityMode", "zonal"),   # regional NATs publish per-AZ metrics
                           "public_ips": [a.get("PublicIp") for a in addrs if a.get("PublicIp")],
                           "route_table_refs": nat_routes.get(nid, 0)})
        if n.get("SubnetId"):
            r.link(ctx.key("ec2:subnet", n["SubnetId"]), "in-subnet")
        for a in addrs:
            if a.get("AllocationId"):
                r.link(ctx.key("ec2:eip", a["AllocationId"]), "uses-eip")
        res.append(r)
    return res


def _igws(ctx) -> list[Resource]:
    res = []
    for g in ctx.aws("ec2", "describe-internet-gateways").get("InternetGateways", []):
        gid = g["InternetGatewayId"]
        tags = tags_from_list(g.get("Tags"))
        vpcs = [a["VpcId"] for a in g.get("Attachments", []) if a.get("VpcId")]
        r = ctx.new("ec2:igw", gid, tags=tags, state="attached" if vpcs else "detached",
                    name=name_from_tags(tags, gid), arn=ctx.arn("ec2", f"internet-gateway/{gid}"),
                    attrs={"vpcs": vpcs})
        for v in vpcs:
            r.link(ctx.key("ec2:vpc", v), "attached-to")
        res.append(r)
    return res


def _endpoints(ctx) -> list[Resource]:
    res = []
    for e in ctx.aws("ec2", "describe-vpc-endpoints").get("VpcEndpoints", []):
        if e.get("State") in ("Deleted", "Deleting", "Expired", "Rejected"):   # EC2 keeps returning these for a while
            continue
        eid = e["VpcEndpointId"]
        tags = tags_from_list(e.get("Tags"))
        r = ctx.new("ec2:vpc-endpoint", eid, tags=tags, state=e.get("State", ""),
                    name=name_from_tags(tags, e.get("ServiceName", eid).split(".")[-1] or eid),
                    created=to_iso(e.get("CreationTimestamp")),
                    arn=ctx.arn("ec2", f"vpc-endpoint/{eid}"),
                    attrs={"ep_type": e.get("VpcEndpointType"), "service_name": e.get("ServiceName"),
                           "vpc": e.get("VpcId"), "subnet_ids": e.get("SubnetIds", []),
                           "az_count": len(e.get("SubnetIds", []))})
        if e.get("VpcId"):
            r.link(ctx.key("ec2:vpc", e["VpcId"]), "in-vpc")
        res.append(r)
    return res


def _security_groups(ctx) -> list[Resource]:
    groups = ctx.aws("ec2", "describe-security-groups").get("SecurityGroups", [])
    referenced_by: dict[str, set[str]] = {}
    for g in groups:
        for perm in g.get("IpPermissions", []) + g.get("IpPermissionsEgress", []):
            for pair in perm.get("UserIdGroupPairs", []):
                if pair.get("GroupId") and pair["GroupId"] != g["GroupId"]:
                    referenced_by.setdefault(pair["GroupId"], set()).add(g["GroupId"])
    res = []
    for g in groups:
        gid = g["GroupId"]
        tags = tags_from_list(g.get("Tags"))
        r = ctx.new("ec2:security-group", gid, tags=tags, state="",
                    name=name_from_tags(tags, g.get("GroupName", gid)),
                    arn=ctx.arn("ec2", f"security-group/{gid}"),
                    attrs={"group_name": g.get("GroupName"), "vpc": g.get("VpcId"),
                           "description": (g.get("Description") or "")[:120],
                           "world_open": _world_open(g.get("IpPermissions", [])),
                           "referenced_by": sorted(referenced_by.get(gid, ())),
                           "ingress_from": _ingress_from(gid, g.get("IpPermissions", []))[:MAX_INGRESS_FROM]})
        if g.get("VpcId"):
            r.link(ctx.key("ec2:vpc", g["VpcId"]), "in-vpc")
        res.append(r)
    return res


def _ports(perm: dict) -> str:
    """One ingress rule's protocol/ports as text: 'all', 'tcp 5432', 'tcp 8000-8100', 'udp 53', 'icmp'."""
    proto = str(perm.get("IpProtocol", ""))
    proto = _PROTO_NAMES.get(proto, proto)
    if proto in ("-1", "all", ""):
        return "all"
    if proto in ("icmp", "icmpv6"):
        return proto
    lo, hi = perm.get("FromPort"), perm.get("ToPort")
    if proto not in ("tcp", "udp"):
        return f"protocol {proto}"
    if lo is None or hi is None or (lo <= 0 and hi >= 65535) or lo == -1:
        return f"{proto} all"
    return f"{proto} {lo}" if lo == hi else f"{proto} {lo}-{hi}"


def _ingress_from(gid: str, perms: list[dict]) -> list[dict]:
    """Security groups this group admits traffic from (ingress only, self-references skipped), in rule order."""
    out: list[dict] = []
    for p in perms:
        ports = _ports(p)
        for pair in p.get("UserIdGroupPairs", []):
            src = pair.get("GroupId")
            item = {"sg": src, "ports": ports}
            if src and src != gid and item not in out:
                out.append(item)
    return out


def _world_open(perms: list[dict]) -> list[list]:
    """Ingress rules open to 0.0.0.0/0 or ::/0 as [protocol, from, to]."""
    out = []
    for p in perms:
        cidrs = [x.get("CidrIp") for x in p.get("IpRanges", [])] + [x.get("CidrIpv6") for x in p.get("Ipv6Ranges", [])]
        if not any(c in ("0.0.0.0/0", "::/0") for c in cidrs):
            continue
        proto = p.get("IpProtocol", "")
        if proto == "-1":
            out.append(["all", 0, 65535])
        else:
            out.append([proto, p.get("FromPort", 0), p.get("ToPort", 65535)])
    return out
