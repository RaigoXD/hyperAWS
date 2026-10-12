"""ec2_net / elb / tagging collectors against canned CLI output."""

import unittest

from analyzer.awscli import AwsCli
from analyzer.collectors import ec2_net, elb, tagging
from analyzer.fakeaws import FakeAws, FakeError, arg_value
from analyzer.scan import Ctx, Gap, merge_tagging

ACCT = "111122223333"


def ctx_for(fake, region="eu-west-1", is_global=False):
    cli = AwsCli("t", executor=fake, aws_bin="aws", sleep=lambda s: None)
    return Ctx(cli, ACCT, region, is_global=is_global)


def by_type(resources):
    d = {}
    for r in resources:
        d.setdefault(r.type, []).append(r)
    return d


class TestEc2Net(unittest.TestCase):
    def setUp(self):
        f = FakeAws()
        f.set("ec2", "describe-vpcs", {"Vpcs": [{"VpcId": "vpc-1", "CidrBlock": "10.0.0.0/16", "State": "available",
                                                 "Tags": [{"Key": "Name", "Value": "main"}]}]})
        f.set("ec2", "describe-subnets", {"Subnets": [
            {"SubnetId": "subnet-pub", "VpcId": "vpc-1", "CidrBlock": "10.0.1.0/24", "AvailabilityZone": "eu-west-1a"},
            {"SubnetId": "subnet-priv", "VpcId": "vpc-1", "CidrBlock": "10.0.2.0/24", "AvailabilityZone": "eu-west-1a"},
            {"SubnetId": "subnet-main", "VpcId": "vpc-1", "CidrBlock": "10.0.3.0/24", "AvailabilityZone": "eu-west-1b"}]})
        f.set("ec2", "describe-route-tables", {"RouteTables": [
            {"RouteTableId": "rtb-main", "VpcId": "vpc-1",
             "Associations": [{"Main": True}], "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": "nat-1"}]},
            {"RouteTableId": "rtb-pub", "VpcId": "vpc-1",
             "Associations": [{"SubnetId": "subnet-pub"}], "Routes": [{"GatewayId": "igw-1"}]},
            {"RouteTableId": "rtb-priv", "VpcId": "vpc-1",
             "Associations": [{"SubnetId": "subnet-priv"}], "Routes": [{"NatGatewayId": "nat-1"}]}]})
        f.set("ec2", "describe-instances", {"Reservations": [{"Instances": [
            {"InstanceId": "i-run", "InstanceType": "m5.large", "State": {"Name": "running"},
             "LaunchTime": "2025-01-02T03:04:05+00:00", "SubnetId": "subnet-priv", "VpcId": "vpc-1",
             "Placement": {"AvailabilityZone": "eu-west-1a"}, "PrivateIpAddress": "10.0.2.5",
             "SecurityGroups": [{"GroupId": "sg-app"}], "ImageId": "ami-1",
             "BlockDeviceMappings": [{"Ebs": {"VolumeId": "vol-root"}}],
             "Tags": [{"Key": "Name", "Value": "api-1"}, {"Key": "Project", "Value": "shop"}]},
            {"InstanceId": "i-stop", "InstanceType": "t3.micro", "State": {"Name": "stopped"},
             "StateTransitionReason": "User initiated (2025-02-03 04:05:06 GMT)", "SubnetId": "subnet-pub",
             "SecurityGroups": [], "BlockDeviceMappings": []},
            {"InstanceId": "i-gone", "State": {"Name": "terminated"}}]}]})
        f.set("ec2", "describe-volumes", {"Volumes": [
            {"VolumeId": "vol-root", "Size": 30, "VolumeType": "gp2", "State": "in-use",
             "Attachments": [{"InstanceId": "i-run", "DeleteOnTermination": True}], "CreateTime": "2025-01-02T03:04:05+00:00"},
            {"VolumeId": "vol-free", "Size": 100, "VolumeType": "gp3", "State": "available", "Attachments": []}]})
        f.set("ec2", "describe-snapshots", {"Snapshots": [
            {"SnapshotId": "snap-1", "VolumeId": "vol-root", "VolumeSize": 30, "StartTime": "2024-01-01T00:00:00Z",
             "State": "completed", "Description": "Created by CreateImage(i-x) for ami-0123456789abcdef0"},
            {"SnapshotId": "snap-2", "VolumeId": "vol-ffffffff", "VolumeSize": 8, "State": "completed"}]})
        f.set("ec2", "describe-images", {"Images": [
            {"ImageId": "ami-0123456789abcdef0", "Name": "golden", "CreationDate": "2024-01-01T00:00:00.000Z",
             "State": "available", "BlockDeviceMappings": [{"Ebs": {"SnapshotId": "snap-1"}}]}]})
        f.set("ec2", "describe-addresses", {"Addresses": [
            {"AllocationId": "eipalloc-used", "PublicIp": "3.3.3.3", "AssociationId": "eipassoc-1", "InstanceId": "i-run"},
            {"AllocationId": "eipalloc-free", "PublicIp": "4.4.4.4"}]})
        f.set("ec2", "describe-network-interfaces", {"NetworkInterfaces": [
            {"NetworkInterfaceId": "eni-1", "Status": "in-use", "InterfaceType": "interface", "SubnetId": "subnet-priv",
             "Attachment": {"InstanceId": "i-run"}, "Groups": [{"GroupId": "sg-app"}]},
            {"NetworkInterfaceId": "eni-2", "Status": "available", "InterfaceType": "interface", "SubnetId": "subnet-pub",
             "Groups": [{"GroupId": "sg-orphan"}], "Description": "left behind"}]})
        f.set("ec2", "describe-nat-gateways", {"NatGateways": [
            {"NatGatewayId": "nat-1", "State": "available", "SubnetId": "subnet-pub", "VpcId": "vpc-1",
             "NatGatewayAddresses": [{"AllocationId": "eipalloc-used", "PublicIp": "3.3.3.3"}]},
            {"NatGatewayId": "nat-dead", "State": "deleted"}]})
        f.set("ec2", "describe-internet-gateways", {"InternetGateways": [
            {"InternetGatewayId": "igw-1", "Attachments": [{"VpcId": "vpc-1", "State": "available"}]},
            {"InternetGatewayId": "igw-2", "Attachments": []}]})
        f.set("ec2", "describe-vpc-endpoints", {"VpcEndpoints": [
            {"VpcEndpointId": "vpce-1", "VpcEndpointType": "Interface", "ServiceName": "com.amazonaws.eu-west-1.ssm",
             "State": "available", "VpcId": "vpc-1", "SubnetIds": ["subnet-priv", "subnet-main"]}]})
        f.set("ec2", "describe-security-groups", {"SecurityGroups": [
            {"GroupId": "sg-app", "GroupName": "app", "VpcId": "vpc-1", "Description": "app",
             "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                               {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}]},
            {"GroupId": "sg-orphan", "GroupName": "orphan", "VpcId": "vpc-1",
             "IpPermissions": [{"IpProtocol": "-1", "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}]},
            {"GroupId": "sg-ref", "GroupName": "ref", "VpcId": "vpc-1",
             "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80,
                                "UserIdGroupPairs": [{"GroupId": "sg-orphan"}]}]}]})
        self.fake = f
        self.res = ec2_net.collect(ctx_for(f))
        self.t = by_type(self.res)
        self.by_key = {r.key: r for r in self.res}

    def get(self, rtype, rid):
        return self.by_key[f"{ACCT}:eu-west-1:{rtype}:{rid}"]

    def test_counts(self):
        counts = {k: len(v) for k, v in self.t.items()}
        self.assertEqual(counts, {
            "ec2:vpc": 1, "ec2:subnet": 3, "ec2:instance": 2, "ec2:volume": 2, "ec2:snapshot": 2,
            "ec2:ami": 1, "ec2:eip": 2, "ec2:eni": 2, "ec2:nat-gateway": 1, "ec2:igw": 2,
            "ec2:vpc-endpoint": 1, "ec2:security-group": 3})

    def test_instance_fields_and_tags(self):
        i = self.get("ec2:instance", "i-run")
        self.assertEqual(i.name, "api-1")
        self.assertEqual(i.tags["Project"], "shop")
        self.assertEqual(i.state, "running")
        self.assertEqual(i.attrs["instance_type"], "m5.large")
        self.assertEqual(i.created, "2025-01-02T03:04:05Z")
        self.assertEqual(i.arn, f"arn:aws:ec2:eu-west-1:{ACCT}:instance/i-run")
        kinds = {(r["kind"], r["to"].split(":")[-1]) for r in i.relations}
        self.assertIn(("in-subnet", "subnet-priv"), kinds)
        self.assertIn(("uses-sg", "sg-app"), kinds)

    def test_terminated_instances_skipped_and_stop_time_parsed(self):
        self.assertNotIn(f"{ACCT}:eu-west-1:ec2:instance:i-gone", self.by_key)
        self.assertEqual(self.get("ec2:instance", "i-stop").attrs["stopped_at"], "2025-02-03T04:05:06Z")

    def test_volumes(self):
        root, free = self.get("ec2:volume", "vol-root"), self.get("ec2:volume", "vol-free")
        self.assertEqual(root.attrs["attached_to"], ["i-run"])
        self.assertEqual(free.state, "available")
        self.assertEqual(free.relations, [])

    def test_snapshot_and_ami_links(self):
        s = self.get("ec2:snapshot", "snap-1")
        self.assertEqual(s.attrs["ami_id"], "ami-0123456789abcdef0")
        self.assertEqual(s.attrs["volume_id"], "vol-root")
        self.assertIsNone(self.get("ec2:snapshot", "snap-2").attrs["volume_id"])
        self.assertEqual(s.arn, "arn:aws:ec2:eu-west-1::snapshot/snap-1")  # snapshots have no account in the ARN
        self.assertEqual(self.get("ec2:ami", "ami-0123456789abcdef0").attrs["snapshot_ids"], ["snap-1"])

    def test_eip_states(self):
        self.assertEqual(self.get("ec2:eip", "eipalloc-used").state, "associated")
        self.assertEqual(self.get("ec2:eip", "eipalloc-free").state, "unassociated")

    def test_eni(self):
        self.assertEqual(self.get("ec2:eni", "eni-2").state, "available")
        self.assertEqual(self.get("ec2:eni", "eni-1").attrs["sg_ids"], ["sg-app"])

    def test_nat_skips_deleted_and_counts_routes(self):
        nat = self.get("ec2:nat-gateway", "nat-1")
        self.assertEqual(nat.attrs["route_table_refs"], 2)
        self.assertNotIn(f"{ACCT}:eu-west-1:ec2:nat-gateway:nat-dead", self.by_key)

    def test_subnet_egress_links_including_main_route_table(self):
        def egress(sid):
            return [r["to"].split(":")[-1] for r in self.get("ec2:subnet", sid).relations if r["kind"] == "egress-via"]
        self.assertEqual(egress("subnet-priv"), ["nat-1"])     # explicit association
        self.assertEqual(egress("subnet-main"), ["nat-1"])     # via main route table
        self.assertEqual(egress("subnet-pub"), [])             # routes to the IGW

    def test_igw_endpoint_sg(self):
        self.assertEqual(self.get("ec2:igw", "igw-2").state, "detached")
        self.assertEqual(self.get("ec2:vpc-endpoint", "vpce-1").attrs["az_count"], 2)
        self.assertEqual(self.get("ec2:security-group", "sg-app").attrs["world_open"], [["tcp", 22, 22]])
        orphan = self.get("ec2:security-group", "sg-orphan")
        self.assertEqual(orphan.attrs["world_open"], [["all", 0, 65535]])
        self.assertEqual(orphan.attrs["referenced_by"], ["sg-ref"])

    def test_only_read_operations_were_issued(self):
        for svc, op in self.fake.ops():
            self.assertRegex(op, r"^(describe|list|get)-")


class TestPartialFailure(unittest.TestCase):
    def test_denied_call_becomes_gap_and_rest_still_collected(self):
        f = FakeAws()
        f.set("ec2", "describe-vpcs", {"Vpcs": [{"VpcId": "vpc-1"}]})

        def deny(region, args):
            raise FakeError("UnauthorizedOperation", "not allowed")
        f.set("ec2", "describe-nat-gateways", deny)
        ctx = ctx_for(f)
        res = ec2_net.collect(ctx)
        self.assertEqual([r.rid for r in res if r.type == "ec2:vpc"], ["vpc-1"])
        self.assertEqual([(g.service, g.op, g.code) for g in ctx.gaps],
                         [("ec2", "describe-nat-gateways", "UnauthorizedOperation")])


class TestElb(unittest.TestCase):
    def test_alb_target_groups_and_classic(self):
        f = FakeAws()
        lb_arn = "arn:aws:elasticloadbalancing:eu-west-1:111122223333:loadbalancer/app/web/abc"
        tg_arn = "arn:aws:elasticloadbalancing:eu-west-1:111122223333:targetgroup/web-tg/def"
        f.set("elbv2", "describe-load-balancers", {"LoadBalancers": [{
            "LoadBalancerArn": lb_arn, "LoadBalancerName": "web", "Type": "application", "Scheme": "internet-facing",
            "State": {"Code": "active"}, "VpcId": "vpc-1", "CreatedTime": "2025-01-01T00:00:00Z",
            "AvailabilityZones": [{"SubnetId": "subnet-a"}, {"SubnetId": "subnet-b"}], "SecurityGroups": ["sg-1"]}]})
        f.set("elbv2", "describe-target-groups", {"TargetGroups": [
            {"TargetGroupArn": tg_arn, "TargetGroupName": "web-tg", "TargetType": "instance", "LoadBalancerArns": [lb_arn]},
            {"TargetGroupArn": tg_arn + "2", "TargetGroupName": "orphan-tg", "TargetType": "ip", "LoadBalancerArns": []}]})

        def health(region, args):
            if arg_value(args, "--target-group-arn").endswith("def"):
                return {"TargetHealthDescriptions": [
                    {"Target": {"Id": "i-1"}, "TargetHealth": {"State": "healthy"}},
                    {"Target": {"Id": "i-2"}, "TargetHealth": {"State": "unhealthy"}}]}
            return {"TargetHealthDescriptions": []}
        f.set("elbv2", "describe-target-health", health)
        f.set("elb", "describe-load-balancers", {"LoadBalancerDescriptions": [
            {"LoadBalancerName": "legacy", "DNSName": "legacy.elb", "Instances": [{"InstanceId": "i-9"}], "Subnets": ["subnet-a"]}]})
        res = elb.collect(ctx_for(f))
        t = by_type(res)
        self.assertEqual(len(t["elbv2:lb"]), 1)
        self.assertEqual(t["elbv2:lb"][0].attrs["az_count"], 2)
        tg = {r.rid: r for r in t["elbv2:target-group"]}
        self.assertEqual((tg["web-tg"].attrs["targets_total"], tg["web-tg"].attrs["targets_healthy"]), (2, 1))
        self.assertIn("behind", {r["kind"] for r in tg["web-tg"].relations})
        self.assertEqual(tg["orphan-tg"].relations, [])
        self.assertEqual(tg["orphan-tg"].attrs["targets_total"], 0)
        self.assertEqual(t["elb:clb"][0].attrs["instance_ids"], ["i-9"])


class TestTagging(unittest.TestCase):
    def test_merge_adds_tags_and_keeps_long_tail(self):
        f = FakeAws()
        f.set("ec2", "describe-vpcs", {"Vpcs": [{"VpcId": "vpc-1"}]})
        f.set("resourcegroupstaggingapi", "get-resources", {"ResourceTagMappingList": [
            {"ResourceARN": f"arn:aws:ec2:eu-west-1:{ACCT}:vpc/vpc-1", "Tags": [{"Key": "Project", "Value": "shop"}, {"Key": "Name", "Value": "main"}]},
            {"ResourceARN": f"arn:aws:cloudwatch:eu-west-1:{ACCT}:alarm:HighCPU", "Tags": [{"Key": "Project", "Value": "shop"}]},
            {"ResourceARN": "arn:aws:s3:::my-bucket", "Tags": []}]})
        ctx = ctx_for(f)
        merged = merge_tagging(ec2_net.collect(ctx) + tagging.collect(ctx))
        vpc = next(r for r in merged if r.type == "ec2:vpc")
        self.assertEqual(vpc.tags["Project"], "shop")
        self.assertEqual(vpc.name, "main")
        other = {r.type: r for r in merged if r.type.startswith("other:")}
        self.assertIn("other:cloudwatch:alarm", other)
        self.assertEqual(other["other:cloudwatch:alarm"].rid, "HighCPU")
        self.assertEqual(other["other:s3:resource"].rid, "my-bucket")
        self.assertEqual(sum(1 for r in merged if r.type == "ec2:vpc"), 1)  # no duplicate


if __name__ == "__main__":
    unittest.main()
