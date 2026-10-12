"""A synthetic AWS account ("Acme") served by :class:`FakeAws`: no network, no credentials.

It exists so the whole pipeline (collectors -> analysis -> report) can be tried,
tested and developed without touching a real account. The world has three
projects (shop, analytics, marketing) plus strays, with deliberate waste:
unassociated EIPs, unattached volumes, idle NAT/ELB/EC2/RDS, deprecated
runtimes, dangling DNS, EKS extended support, over-provisioned DynamoDB, etc.
It also wires the connections the map draws: Lambda event sources (SQS, a
DynamoDB stream, a Kinesis stream), an SNS topic fanning out to SQS + Lambda,
a dead-letter queue, IAM roles, security groups that admit other groups, and a
CloudFront distribution in front of API Gateway.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone

from .fakeaws import FakeAws, FakeError, arg_value

GLOBAL_SERVICES = {"s3api", "iam", "route53", "cloudfront"}
# operations whose canned answer is a dict keyed by the resource argument (flag below)
KEYED_OPS_FLAG = {"describe-table": "--table-name", "get-queue-attributes": "--queue-url", "get-bucket-tagging": "--bucket",
                  "get-bucket-lifecycle-configuration": "--bucket", "get-bucket-versioning": "--bucket",
                  "get-public-access-block": "--bucket", "list-access-keys": "--user-name",
                  "get-access-key-last-used": "--access-key-id", "get-role": "--role-name",
                  "list-resource-record-sets": "--hosted-zone-id", "describe-key": "--key-id"}
KEYED_OPS = {("dynamodb", "describe-table"), ("sqs", "get-queue-attributes"), ("s3api", "get-bucket-tagging"),
             ("s3api", "get-bucket-lifecycle-configuration"), ("s3api", "get-bucket-versioning"), ("s3api", "get-public-access-block"),
             ("iam", "list-access-keys"), ("iam", "get-access-key-last-used"), ("iam", "get-role"),
             ("route53", "list-resource-record-sets"), ("kms", "describe-key")}

ACCOUNT = "123456789012"
REGIONS = ["us-east-1", "eu-west-1", "eu-central-1", "ap-southeast-1"]
CALLER = f"arn:aws:iam::{ACCOUNT}:user/demo-readonly"
SHOP_API_ID = "a1b2c3d4e5"
WEBHOOK_TOKEN = "demo-sns-webhook-token-7f3a91c2"   # inside an https subscription URL: must never reach any output


def hid(name: str, prefix: str, n: int = 17) -> str:
    return f"{prefix}-" + hashlib.sha1(name.encode()).hexdigest()[:n]


def tags(**kw):
    return [{"Key": k.replace("_", ":") if k.startswith("aws_") else k, "Value": v} for k, v in kw.items()]


class Demo:
    def __init__(self, now: datetime | None = None):
        self.now = (now or datetime.now(timezone.utc)).replace(microsecond=0)
        self.d: dict[str, dict[tuple[str, str], dict | list]] = {r: {} for r in REGIONS}
        self.metric_idle: dict[str, dict] = {}   # dimension value -> {metric: [values]}
        self.build()

    # -- tiny helpers -------------------------------------------------------
    def ago(self, days: float) -> str:
        return (self.now - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")

    def put(self, region: str, svc: str, op: str, key: str, item) -> None:
        self.d[region].setdefault((svc, op), {}).setdefault(key, []).append(item)

    def resp(self, region: str, svc: str, op: str, key: str) -> list:
        return self.d.get(region, {}).get((svc, op), {}).get(key, [])

    # -- world ---------------------------------------------------------------
    def build(self) -> None:
        self.net("us-east-1", "shop", "10.10", azs=("a", "b"), env="prod", nats=2, idle_nat=False)
        self.net("us-east-1", "analytics", "10.20", azs=("a", "b"), env="prod", nats=1, idle_nat=False)
        self.net("us-east-1", "default", "172.31", azs=("a",), env="", nats=0, idle_nat=False, default=True)
        self.net("eu-west-1", "platform-dev", "10.30", azs=("a", "b"), env="dev", nats=2, idle_nat=True)
        self.net("eu-west-1", "marketing", "10.40", azs=("a",), env="prod", nats=0, idle_nat=False)
        self.shop()
        self.analytics()
        self.marketing()
        self.platform_dev()
        self.strays()
        self.iam_and_edge()

    # ---- networking ----------------------------------------------------------
    def net(self, region, name, cidr, azs, env, nats, idle_nat, default=False):
        vpc = hid(f"vpc-{name}", "vpc")
        t = [] if default else tags(Name=f"{name}-vpc", Project="platform" if name.startswith("platform") else name, Environment=env)
        self.put(region, "ec2", "describe-vpcs", "Vpcs", {"VpcId": vpc, "CidrBlock": f"{cidr}.0.0/16", "State": "available",
                                                           "IsDefault": default, "Tags": t})
        setattr(self, f"vpc_{name.replace('-', '_')}", vpc)
        subs = {}
        for i, az in enumerate(azs):
            for kind, off in (("public", i), ("private", 10 + i)):
                sid = hid(f"{name}-{kind}-{az}", "subnet")
                subs[(kind, az)] = sid
                self.put(region, "ec2", "describe-subnets", "Subnets", {
                    "SubnetId": sid, "VpcId": vpc, "CidrBlock": f"{cidr}.{off}.0/24", "AvailabilityZone": f"{region}{az}",
                    "AvailableIpAddressCount": 200, "MapPublicIpOnLaunch": kind == "public", "DefaultForAz": default,
                    "Tags": [] if default else tags(Name=f"{name}-{kind}-{az}")})
        setattr(self, f"subnets_{name.replace('-', '_')}", subs)
        igw = hid(f"igw-{name}", "igw")
        self.put(region, "ec2", "describe-internet-gateways", "InternetGateways",
                 {"InternetGatewayId": igw, "Attachments": [{"VpcId": vpc, "State": "available"}], "Tags": tags(Name=f"{name}-igw")})
        # a leftover detached IGW in the default VPC region
        nat_ids = []
        rts = []
        for i, az in enumerate(azs[:nats] if nats else []):
            nat = hid(f"nat-{name}-{az}", "nat")
            nat_ids.append(nat)
            alloc = hid(f"eip-nat-{name}-{az}", "eipalloc")
            ip = f"52.{20 + len(name)}.{i}.{10 + i}"
            self.put(region, "ec2", "describe-nat-gateways", "NatGateways", {
                "NatGatewayId": nat, "State": "available", "SubnetId": subs[("public", az)], "VpcId": vpc,
                "CreateTime": self.ago(400), "NatGatewayAddresses": [{"AllocationId": alloc, "PublicIp": ip}],
                "Tags": tags(Name=f"{name}-nat-{az}", Environment=env)})
            self.put(region, "ec2", "describe-addresses", "Addresses",
                     {"AllocationId": alloc, "PublicIp": ip, "AssociationId": hid(alloc, "eipassoc"), "NetworkInterfaceId": hid(alloc, "eni"),
                      "Domain": "vpc", "Tags": tags(Name=f"{name}-nat-{az}")})
            rts.append({"RouteTableId": hid(f"rtb-{name}-{az}", "rtb"), "VpcId": vpc,
                        "Associations": [{"SubnetId": subs[("private", az)]}],
                        "Routes": [{"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": nat}]})
            self.metric_idle[nat] = {"nat": idle_nat and i == nats - 1}   # the last NAT of an "idle" VPC has no traffic
        for rt in rts:
            self.put(region, "ec2", "describe-route-tables", "RouteTables", rt)
        setattr(self, f"nats_{name.replace('-', '_')}", nat_ids)

    def sg(self, region, name, vpc, ingress=(), world=(), desc="", env="", project="", from_sgs=()):
        sid = hid(f"sg-{name}", "sg")
        perms = [{"IpProtocol": "tcp", "FromPort": p, "ToPort": p, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]} for p in ingress]
        perms += [{"IpProtocol": "tcp", "FromPort": p, "ToPort": p, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]} for p in world]
        perms += [{"IpProtocol": "tcp", "FromPort": p, "ToPort": p, "UserIdGroupPairs": [{"GroupId": g, "UserId": ACCOUNT}]}
                  for g, p in from_sgs]
        self.put(region, "ec2", "describe-security-groups", "SecurityGroups", {
            "GroupId": sid, "GroupName": name, "VpcId": vpc, "Description": desc or name, "IpPermissions": perms,
            "Tags": tags(Name=name, Project=project) if project else []})
        return sid

    # ---- instances / volumes --------------------------------------------------
    def instance(self, region, name, itype, subnet, vpc, sg, *, project=None, env=None, state="running", launched=300,
                 stopped_days=None, vol_gb=30, vol_type="gp2", public_ip=None, spot=False, extra_tags=None, cpu=(35, 70),
                 ami="ami-0abc00000000000001", extra_vols=(), iam_profile=None):
        iid = hid(f"{region}-{name}", "i")
        t = {"Name": name}
        if project:
            t["Project"] = project
        if env:
            t["Environment"] = env
        t.update(extra_tags or {})
        vols = [(hid(f"root-{iid}", "vol"), vol_gb, vol_type, "/dev/xvda")] + [
            (hid(f"{extra}-{iid}", "vol"), gb, vt, f"/dev/sd{chr(102 + i)}") for i, (extra, gb, vt) in enumerate(extra_vols)]
        inst = {"InstanceId": iid, "InstanceType": itype, "State": {"Name": state}, "LaunchTime": self.ago(launched),
                "SubnetId": subnet, "VpcId": vpc, "Placement": {"AvailabilityZone": f"{region}a"}, "Architecture": "x86_64",
                "PrivateIpAddress": "10.0.0.5", "ImageId": ami, "PlatformDetails": "Linux/UNIX",
                "SecurityGroups": [{"GroupId": sg}], "Tags": [{"Key": k, "Value": v} for k, v in t.items()],
                "BlockDeviceMappings": [{"Ebs": {"VolumeId": v[0]}} for v in vols]}
        if public_ip:
            inst["PublicIpAddress"] = public_ip
        if spot:
            inst["InstanceLifecycle"] = "spot"
        if iam_profile:
            inst["IamInstanceProfile"] = {"Arn": f"arn:aws:iam::{ACCOUNT}:instance-profile/{iam_profile}"}
        if state == "stopped":
            when = (self.now - timedelta(days=stopped_days or 30)).strftime("%Y-%m-%d %H:%M:%S")
            inst["StateTransitionReason"] = f"User initiated ({when} GMT)"
        self.put(region, "ec2", "describe-instances", "Reservations", {"Instances": [inst]})
        for vid, gb, vt, dev in vols:
            self.put(region, "ec2", "describe-volumes", "Volumes", {
                "VolumeId": vid, "Size": gb, "VolumeType": vt, "State": "in-use", "CreateTime": self.ago(launched),
                "Attachments": [{"InstanceId": iid, "DeleteOnTermination": dev == "/dev/xvda"}], "Encrypted": True,
                "AvailabilityZone": f"{region}a", "Tags": tags(Name=f"{name}-{dev.split('/')[-1]}", **({"Project": project} if project else {}))})
        self.put(region, "ec2", "describe-network-interfaces", "NetworkInterfaces", {
            "NetworkInterfaceId": hid(iid, "eni"), "Status": "in-use", "InterfaceType": "interface", "SubnetId": subnet, "VpcId": vpc,
            "Attachment": {"InstanceId": iid}, "Groups": [{"GroupId": sg}], "PrivateIpAddress": "10.0.0.5"})
        self.metric_idle[iid] = {"cpu": cpu}
        return iid

    def volume(self, region, name, gb, vtype, *, age, project=None, tag_extra=None):
        vid = hid(f"{region}-{name}", "vol")
        self.put(region, "ec2", "describe-volumes", "Volumes", {
            "VolumeId": vid, "Size": gb, "VolumeType": vtype, "State": "available", "CreateTime": self.ago(age), "Attachments": [],
            "AvailabilityZone": f"{region}a", "Tags": tags(Name=name, **({"Project": project} if project else {}), **(tag_extra or {}))})
        return vid

    def eip(self, region, name, *, associated_to=None, project=None, ip=None):
        alloc = hid(f"eip-{name}", "eipalloc")
        ip = ip or f"54.{len(name) + 100}.{abs(hash(name)) % 200}.{abs(hash(name[::-1])) % 200}"
        a = {"AllocationId": alloc, "PublicIp": ip, "Domain": "vpc", "Tags": tags(Name=name, **({"Project": project} if project else {}))}
        if associated_to:
            a.update(InstanceId=associated_to, AssociationId=hid(alloc, "eipassoc"))
        self.put(region, "ec2", "describe-addresses", "Addresses", a)
        return ip

    def snapshot(self, region, name, gb, *, age, volume=None, desc="", project=None):
        sid = hid(f"snap-{region}-{name}", "snap")
        self.put(region, "ec2", "describe-snapshots", "Snapshots", {
            "SnapshotId": sid, "VolumeId": volume or "vol-ffffffff", "VolumeSize": gb, "StartTime": self.ago(age), "State": "completed",
            "Description": desc or f"Backup of {name}", "Tags": tags(Name=name, **({"Project": project} if project else {}))})
        return sid

    # ---- projects -------------------------------------------------------------
    def shop(self):
        r, vpc, subs = "us-east-1", self.vpc_shop, self.subnets_shop
        web_sg = self.sg(r, "shop-web", vpc, ingress=(80, 443), project="shop")
        app_sg = self.sg(r, "shop-app", vpc, ingress=(8080,), project="shop", from_sgs=((web_sg, 8080),))
        db_sg = self.sg(r, "shop-db", vpc, ingress=(5432,), world=(5432,), desc="postgres", project="shop",   # world-open DB!
                        from_sgs=((app_sg, 5432),))
        self.sg(r, "shop-old-experiment", vpc, ingress=(9000,))                                               # unused
        web = [self.instance(r, f"shop-web-{i}", "m5.large", subs[("private", "ab"[i % 2])], vpc, web_sg, project="shop", env="prod",
                             cpu=(38, 71)) for i in range(3)]
        self.instance(r, "shop-api-1", "c5.xlarge", subs[("private", "a")], vpc, app_sg, project="shop", env="prod", cpu=(22, 55))
        self.instance(r, "shop-api-2", "c5.xlarge", subs[("private", "b")], vpc, app_sg, project="shop", env="prod", cpu=(24, 58))
        self.instance(r, "shop-batch-1", "r5.2xlarge", subs[("private", "a")], vpc, app_sg, project="shop", env="prod", cpu=(3.2, 14),
                      extra_vols=(("data", 500, "gp2"),))                                                       # idle-ish big box
        self.instance(r, "shop-legacy-worker", "t2.medium", subs[("private", "a")], vpc, app_sg, project="shop", env="prod", cpu=(9, 28))
        bastion = self.instance(r, "shop-bastion", "t3.micro", subs[("public", "a")], vpc, web_sg, project="shop", env="prod",
                                public_ip="3.91.14.20", cpu=(1, 4))
        self.eip(r, "shop-bastion", associated_to=bastion, project="shop", ip="3.91.14.20")
        self.instance(r, "shop-staging-web-1", "m5.large", subs[("private", "a")], vpc, web_sg, project="shop", env="staging", cpu=(12, 35))
        self.instance(r, "shop-staging-api-1", "c5.xlarge", subs[("private", "a")], vpc, app_sg, project="shop", env="staging", cpu=(11, 30))
        # load balancer
        lb_arn = f"arn:aws:elasticloadbalancing:{r}:{ACCOUNT}:loadbalancer/app/shop-web-alb/50dc6c495c0c9188"
        tg_arn = f"arn:aws:elasticloadbalancing:{r}:{ACCOUNT}:targetgroup/shop-web-tg/73e2d6bc24d8a067"
        self.d[r][("elbv2", "describe-load-balancers")] = {"LoadBalancers": [{
            "LoadBalancerArn": lb_arn, "LoadBalancerName": "shop-web-alb", "Type": "application", "Scheme": "internet-facing",
            "State": {"Code": "active"}, "VpcId": vpc, "CreatedTime": self.ago(380), "DNSName": "shop-web-alb-1234567890.us-east-1.elb.amazonaws.com",
            "AvailabilityZones": [{"SubnetId": subs[("public", "a")]}, {"SubnetId": subs[("public", "b")]}], "SecurityGroups": [web_sg]}]}
        self.d[r][("elbv2", "describe-target-groups")] = {"TargetGroups": [
            {"TargetGroupArn": tg_arn, "TargetGroupName": "shop-web-tg", "TargetType": "instance", "VpcId": vpc, "LoadBalancerArns": [lb_arn]}]}
        self.d[r][("elbv2", "describe-target-health")] = {tg_arn: [
            {"Target": {"Id": w, "Port": 80}, "TargetHealth": {"State": "healthy"}} for w in web]}
        self.metric_idle["app/shop-web-alb/50dc6c495c0c9188"] = {"requests": 4_200_000}
        # database + cache
        self.put(r, "rds", "describe-db-instances", "DBInstances", {
            "DBInstanceIdentifier": "shop-prod-db", "DBInstanceClass": "db.r5.large", "Engine": "postgres", "EngineVersion": "15.4",
            "DBInstanceStatus": "available", "MultiAZ": True, "AllocatedStorage": 500, "StorageType": "gp2", "StorageEncrypted": True,
            "InstanceCreateTime": self.ago(500), "DBInstanceArn": f"arn:aws:rds:{r}:{ACCOUNT}:db:shop-prod-db",
            "DBSubnetGroup": {"VpcId": vpc}, "VpcSecurityGroups": [{"VpcSecurityGroupId": db_sg}], "PubliclyAccessible": True,
            "BackupRetentionPeriod": 7, "TagList": tags(Project="shop", Environment="prod")})
        self.put(r, "rds", "describe-db-instances", "DBInstances", {
            "DBInstanceIdentifier": "shop-staging-db", "DBInstanceClass": "db.m5.large", "Engine": "postgres", "DBInstanceStatus": "available",
            "MultiAZ": True, "AllocatedStorage": 100, "StorageType": "gp2", "StorageEncrypted": True, "InstanceCreateTime": self.ago(300),
            "DBInstanceArn": f"arn:aws:rds:{r}:{ACCOUNT}:db:shop-staging-db", "DBSubnetGroup": {"VpcId": vpc},
            "VpcSecurityGroups": [{"VpcSecurityGroupId": db_sg}], "TagList": tags(Project="shop", Environment="staging")})
        self.put(r, "rds", "describe-db-snapshots", "DBSnapshots", {
            "DBSnapshotIdentifier": "shop-prod-db-before-migration-2024", "DBInstanceIdentifier": "shop-prod-db", "SnapshotCreateTime": self.ago(700),
            "AllocatedStorage": 500, "Status": "available", "Engine": "postgres", "DBSnapshotArn": f"arn:aws:rds:{r}:{ACCOUNT}:snapshot:shop-prod-db-before-migration-2024"})
        self.put(r, "elasticache", "describe-cache-clusters", "CacheClusters", {
            "CacheClusterId": "shop-cache-001", "CacheNodeType": "cache.r5.large", "Engine": "redis", "CacheClusterStatus": "available",
            "NumCacheNodes": 1, "CacheClusterCreateTime": self.ago(450), "ARN": f"arn:aws:elasticache:{r}:{ACCOUNT}:cluster:shop-cache-001"})
        self.metric_idle["shop-cache-001"] = {"conn": 120}
        self.metric_idle["shop-prod-db"] = {"conn": 85, "cpu": (28, 60)}
        self.metric_idle["shop-staging-db"] = {"conn": 4, "cpu": (6, 20)}
        # serverless + data
        for name, rt, inv in (("shop-order-processor", "python3.12", 820_000), ("shop-image-resizer", "python3.8", 91_000),
                              ("shop-old-cron", "nodejs16.x", 0), ("shop-notify", "python3.12", 15_000), ("shop-export", "python3.11", 400)):
            self.lambda_fn(r, name, rt, inv, project="shop", role="service-role/shop-lambda-role")
        self.ddb(r, "shop-sessions", rcu=200, wcu=100, size_gb=3, reads=2_000_000, writes=900_000, project="shop")
        self.ddb(r, "shop-carts", rcu=0, wcu=0, size_gb=12, reads=40_000_000, writes=9_000_000, project="shop", ondemand=True,
                 stream=True)
        self.ddb(r, "shop-unused-table", rcu=5, wcu=5, size_gb=0.01, reads=0, writes=0, project=None)
        self.queue(r, "shop-orders", sent=900_000, project="shop", redrive_to="shop-orders-dlq")
        self.queue(r, "shop-orders-dlq", sent=0, project=None, messages=3)        # a few failed orders wait here
        self.queue(r, "shop-dead-letter-old", sent=0, project=None)
        self.put(r, "sns", "list-topics", "Topics", {"TopicArn": f"arn:aws:sns:{r}:{ACCOUNT}:shop-alerts"})
        self.put(r, "sns", "list-topics", "Topics", {"TopicArn": f"arn:aws:sns:{r}:{ACCOUNT}:shop-forgotten-topic"})
        self.put(r, "sns", "list-subscriptions", "Subscriptions", {"TopicArn": f"arn:aws:sns:{r}:{ACCOUNT}:shop-alerts", "Protocol": "email", "Endpoint": "ops@example.com"})
        self.metric_idle["shop-alerts"] = {"pub": 320}
        self.metric_idle["shop-forgotten-topic"] = {"pub": 0}
        # order events fan out to a queue and a Lambda alias; the webhook URL carries a token that must never be stored
        events = f"arn:aws:sns:{r}:{ACCOUNT}:shop-order-events"
        self.put(r, "sns", "list-topics", "Topics", {"TopicArn": events})
        for proto, endpoint in (("sqs", f"arn:aws:sqs:{r}:{ACCOUNT}:shop-orders"),
                                ("lambda", f"arn:aws:lambda:{r}:{ACCOUNT}:function:shop-notify:live"),
                                ("https", f"https://hooks.example.com/shop?token={WEBHOOK_TOKEN}")):
            self.put(r, "sns", "list-subscriptions", "Subscriptions", {"TopicArn": events, "Protocol": proto, "Endpoint": endpoint})
        self.metric_idle["shop-order-events"] = {"pub": 880_000}
        # what --query "EventSourceMappings[].{...}" returns: a plain list
        self.esm(r, "shop-order-processor", f"arn:aws:sqs:{r}:{ACCOUNT}:shop-orders", batch=10)
        self.esm(r, "shop-export", f"arn:aws:dynamodb:{r}:{ACCOUNT}:table/shop-carts/stream/2025-03-01T00:00:00.000", batch=100,
                 on_failure=f"arn:aws:sns:{r}:{ACCOUNT}:shop-alerts")
        self.d[r][("apigateway", "get-rest-apis")] = {"items": [
            {"id": SHOP_API_ID, "name": "shop-public-api", "createdDate": self.ago(320), "endpointConfiguration": {"types": ["REGIONAL"]}}]}
        # ECS
        cl = f"arn:aws:ecs:{r}:{ACCOUNT}:cluster/shop-cluster"
        svc = f"arn:aws:ecs:{r}:{ACCOUNT}:service/shop-cluster"
        self.d[r][("ecs", "list-clusters")] = {"clusterArns": [cl]}
        self.d[r][("ecs", "describe-clusters")] = {"clusters": [{"clusterArn": cl, "clusterName": "shop-cluster", "status": "ACTIVE",
                                                                  "activeServicesCount": 2, "runningTasksCount": 4, "tags": [{"key": "Project", "value": "shop"}]}]}
        self.d[r][("ecs", "describe-services")] = {"services": [
            {"serviceName": "shop-checkout", "serviceArn": f"{svc}/shop-checkout", "status": "ACTIVE", "desiredCount": 4,
             "runningCount": 4, "launchType": "FARGATE", "createdAt": self.ago(200), "taskDefinition": "shop-checkout:42",
             "loadBalancers": [{"targetGroupArn": tg_arn}], "tags": [{"key": "Project", "value": "shop"}],
             "networkConfiguration": {"awsvpcConfiguration": {"subnets": [subs[("private", "a")]], "securityGroups": [app_sg]}}},
            {"serviceName": "shop-staging-checkout", "serviceArn": f"{svc}/shop-staging-checkout", "status": "ACTIVE",
             "desiredCount": 0, "runningCount": 0, "launchType": "FARGATE", "createdAt": self.ago(150), "taskDefinition": "shop-checkout:42"}]}
        self.d[r][("ecs", "list-services")] = {"serviceArns": [f"{svc}/shop-checkout", f"{svc}/shop-staging-checkout"]}
        self.d[r][("ecs", "describe-task-definition")] = {"cpu": "1024", "memory": "4096", "arch": "ARM64",
                                                           "task_role": f"arn:aws:iam::{ACCOUNT}:role/shop-checkout-task",
                                                           "exec_role": f"arn:aws:iam::{ACCOUNT}:role/ecsTaskExecutionRole"}
        self.metric_idle["shop-checkout"] = {"cpu": (7.5, 20)}
        # waste: unattached volume, snapshots, EIPs, ENI
        self.volume(r, "shop-old-data", 200, "gp2", age=220, project="shop")
        self.volume(r, "scratch-vol-2", 50, "gp3", age=95)
        self.eip(r, "shop-old-lb")
        self.eip(r, "temp-migration", ip="44.201.77.15")
        self.snapshot(r, "shop-db-old", 500, age=420, volume=hid("us-east-1-gone-db-volume", "vol"), project="shop")
        self.snapshot(r, "ami-snap-gone", 30, age=380, desc="Created by CreateImage(i-0123456789abcdef0) for ami-0deadbeef0000000a")
        self.put(r, "ec2", "describe-network-interfaces", "NetworkInterfaces", {
            "NetworkInterfaceId": hid("leftover-eni", "eni"), "Status": "available", "InterfaceType": "interface", "SubnetId": subs[("private", "a")],
            "VpcId": vpc, "Groups": [{"GroupId": app_sg}], "Description": "left by terminated worker", "PrivateIpAddress": "10.10.10.99"})
        # S3 (global)
        self.bucket("shop-assets", "us-east-1", gb=820, lifecycle=False, versioning=False, project="shop", objects=12_000_000)
        self.bucket("shop-logs", "us-east-1", gb=2100, lifecycle=False, versioning=True, project="shop", objects=88_000_000)
        self.bucket("shop-backups", "us-east-1", gb=640, lifecycle=True, versioning=False, project="shop", objects=6_000, ia_gb=300)
        self.bucket("shop-old-website", "us-east-1", gb=0.4, lifecycle=False, versioning=False, project="shop", objects=200)

    def analytics(self):
        r, vpc, subs = "us-east-1", self.vpc_analytics, self.subnets_analytics
        sg = self.sg(r, "analytics-nodes", vpc, ingress=(443,), project="analytics")
        # EKS in extended support with managed node group (nodes tagged as EKS does)
        for i in range(3):
            self.instance(r, f"analytics-eks-node-{i}", "m5.xlarge", subs[("private", "ab"[i % 2])], vpc, sg, project="analytics", env="prod",
                          extra_tags={"aws:eks:cluster-name": "analytics-eks", "eks:nodegroup-name": "workers"}, cpu=(41, 77), launched=420,
                          iam_profile="eks-node-role")
        self.d[r][("eks", "list-clusters")] = {"clusters": ["analytics-eks"]}
        self.d[r][("eks", "describe-cluster-versions")] = {"clusterVersions": [
            {"clusterVersion": "1.29", "status": "EXTENDED_SUPPORT", "endOfStandardSupportDate": self.ago(280), "endOfExtendedSupportDate": self.ago(-85)},
            {"clusterVersion": "1.33", "status": "STANDARD_SUPPORT"}]}
        self.d[r][("eks", "describe-cluster")] = {"cluster": {
            "name": "analytics-eks", "arn": f"arn:aws:eks:{r}:{ACCOUNT}:cluster/analytics-eks", "version": "1.29", "status": "ACTIVE", "createdAt": self.ago(600),
            "resourcesVpcConfig": {"vpcId": vpc}, "tags": {"Project": "analytics"}, "upgradePolicy": {"supportType": "EXTENDED"},
            "roleArn": f"arn:aws:iam::{ACCOUNT}:role/analytics-eks-cluster-role"}}
        self.d[r][("eks", "list-nodegroups")] = {"nodegroups": ["workers"]}
        self.d[r][("eks", "describe-nodegroup")] = {"nodegroup": {
            "nodegroupName": "workers", "status": "ACTIVE", "instanceTypes": ["m5.xlarge"], "capacityType": "ON_DEMAND", "amiType": "AL2_x86_64",
            "scalingConfig": {"minSize": 2, "maxSize": 6, "desiredSize": 3}, "createdAt": self.ago(600),
            "nodegroupArn": f"arn:aws:eks:{r}:{ACCOUNT}:nodegroup/analytics-eks/workers/abc", "nodeRole": f"arn:aws:iam::{ACCOUNT}:role/eks-node-role"}}
        self.d[r][("eks", "list-fargate-profiles")] = {"fargateProfileNames": []}
        self.put(r, "rds", "describe-db-instances", "DBInstances", {
            "DBInstanceIdentifier": "analytics-warehouse", "DBInstanceClass": "db.r6g.xlarge", "Engine": "aurora-postgresql", "EngineVersion": "15.4",
            "DBInstanceStatus": "available", "MultiAZ": False, "AllocatedStorage": 1, "StorageType": "aurora", "StorageEncrypted": True,
            "InstanceCreateTime": self.ago(400), "DBInstanceArn": f"arn:aws:rds:{r}:{ACCOUNT}:db:analytics-warehouse", "DBClusterIdentifier": "analytics-cluster",
            "DBSubnetGroup": {"VpcId": vpc}, "VpcSecurityGroups": [{"VpcSecurityGroupId": sg}], "TagList": tags(Project="analytics", Environment="prod")})
        self.put(r, "rds", "describe-db-clusters", "DBClusters", {
            "DBClusterIdentifier": "analytics-cluster", "Status": "available", "Engine": "aurora-postgresql", "ClusterCreateTime": self.ago(400),
            "DBClusterArn": f"arn:aws:rds:{r}:{ACCOUNT}:cluster:analytics-cluster", "DBClusterMembers": [{}], "TagList": tags(Project="analytics")})
        self.metric_idle["analytics-warehouse"] = {"conn": 22, "cpu": (35, 80)}
        for name, rt, inv in (("analytics-ingest", "python3.12", 3_100_000), ("analytics-compact", "python3.9", 60_000), ("analytics-report", "python3.12", 9_000)):
            self.lambda_fn(r, name, rt, inv, project="analytics", arch="arm64" if name.endswith("ingest") else "x86_64")
        clicks = f"arn:aws:kinesis:{r}:{ACCOUNT}:stream/analytics-clicks"          # no collector: known through its tags
        self.esm(r, "analytics-ingest", clicks, batch=500, qualifier="live")
        self.esm(r, "analytics-compact", clicks, batch=100, state="Disabled")
        self.bucket("analytics-lake", "us-east-1", gb=12_400, lifecycle=False, versioning=False, project="analytics", objects=420_000_000)
        self.bucket("analytics-athena-results", "us-east-1", gb=180, lifecycle=False, versioning=False, project="analytics", objects=900_000)
        self.d[r][("ecr", "describe-repositories")] = {"repositories": [
            {"repositoryName": "analytics/etl", "repositoryArn": f"arn:aws:ecr:{r}:{ACCOUNT}:repository/analytics/etl", "createdAt": self.ago(500)}]}
        self.d[r][("ecr", "get-lifecycle-policy")] = {}
        self.d[r][("ecr", "describe-images")] = [{"s": 900_000_000, "p": float((self.now - timedelta(days=i * 3)).timestamp()), "t": None if i % 4 else ["v%d" % i]}
                                                   for i in range(120)]
        self.log_group(r, "/aws/eks/analytics-eks/cluster", gb=140, retention=None, ingest=1)
        self.log_group(r, "/analytics/ingest", gb=86, retention=None, ingest=1)
        self.log_group(r, "/analytics/old-etl", gb=22, retention=None, ingest=0)
        self.d[r][("kms", "list-keys")] = {"Keys": [{"KeyId": "11111111-aaaa"}, {"KeyId": "22222222-bbbb"}]}
        self.d[r][("kms", "list-aliases")] = {"Aliases": [{"AliasName": "alias/analytics-lake", "TargetKeyId": "11111111-aaaa"},
                                                           {"AliasName": "alias/old-project", "TargetKeyId": "22222222-bbbb"}]}
        self.d[r][("kms", "describe-key")] = {
            "11111111-aaaa": {"KeyMetadata": {"KeyId": "11111111-aaaa", "Arn": f"arn:aws:kms:{r}:{ACCOUNT}:key/11111111-aaaa", "KeyManager": "CUSTOMER", "KeyState": "Enabled", "Enabled": True}},
            "22222222-bbbb": {"KeyMetadata": {"KeyId": "22222222-bbbb", "Arn": f"arn:aws:kms:{r}:{ACCOUNT}:key/22222222-bbbb", "KeyManager": "CUSTOMER", "KeyState": "Disabled", "Enabled": False}}}

    def marketing(self):
        r = "eu-west-1"
        self.bucket("marketing-site", "eu-west-1", gb=2.2, lifecycle=False, versioning=False, project="marketing", objects=3_400, website=True)
        self.lambda_fn(r, "marketing-form-handler", "nodejs20.x", 12_000, project="marketing", arch="arm64")
        # same tag, three spellings: shows up in Tags & governance
        self.put(r, "ec2", "describe-volumes", "Volumes", {
            "VolumeId": hid("mkt-vol-a", "vol"), "Size": 8, "VolumeType": "gp3", "State": "available", "CreateTime": self.ago(40), "Attachments": [],
            "AvailabilityZone": f"{r}a", "Tags": [{"Key": "project", "Value": "marketing"}]})
        self.put(r, "ec2", "describe-volumes", "Volumes", {
            "VolumeId": hid("mkt-vol-b", "vol"), "Size": 8, "VolumeType": "gp3", "State": "available", "CreateTime": self.ago(40), "Attachments": [],
            "AvailabilityZone": f"{r}a", "Tags": [{"Key": "PROJECT", "Value": "Marketing"}]})
        self.log_group(r, "/aws/lambda/marketing-form-handler", gb=0.2, retention=30, ingest=1)
        self.eip(r, "marketing-legacy")

    def platform_dev(self):
        r, vpc, subs = "eu-west-1", self.vpc_platform_dev, self.subnets_platform_dev
        sg = self.sg(r, "platform-dev", vpc, ingress=(22,), world=(22,), project="platform")
        for i in range(4):
            self.instance(r, f"platform-dev-{i + 1}", "t3.medium", subs[("private", "ab"[i % 2])], vpc, sg, project="platform", env="dev", cpu=(6, 25))
        self.instance(r, "platform-ci-runner", "c5.2xlarge", subs[("private", "a")], vpc, sg, project="platform", env="dev", cpu=(4, 18), spot=True)
        self.put(r, "rds", "describe-db-instances", "DBInstances", {
            "DBInstanceIdentifier": "platform-dev-db", "DBInstanceClass": "db.t3.medium", "Engine": "mysql", "DBInstanceStatus": "available", "MultiAZ": True,
            "AllocatedStorage": 50, "StorageType": "gp2", "StorageEncrypted": True, "InstanceCreateTime": self.ago(240),
            "DBInstanceArn": f"arn:aws:rds:{r}:{ACCOUNT}:db:platform-dev-db", "DBSubnetGroup": {"VpcId": vpc}, "TagList": tags(Project="platform", Environment="dev")})
        self.metric_idle["platform-dev-db"] = {"conn": 3, "cpu": (4, 12)}
        # a forgotten VPC with nothing in it
        self.net(r, "old-poc", "10.99", azs=("a",), env="", nats=0, idle_nat=False)

    def strays(self):
        r, vpc, subs = "us-east-1", self.vpc_shop, self.subnets_shop
        wizard = self.sg(r, "launch-wizard-1", vpc, ingress=(22,), world=(22, 3389), desc="launch-wizard-1 created 2022")
        self.instance(r, "test-box", "t3.large", subs[("public", "a")], vpc, wizard, launched=500, cpu=(0.9, 3.5), public_ip="18.209.4.77")
        self.instance(r, "old-jenkins", "m4.large", subs[("private", "a")], vpc, wizard, launched=900, state="stopped", stopped_days=140,
                      vol_gb=500, vol_type="gp2")
        self.d[r][("elb", "describe-load-balancers")] = {"LoadBalancerDescriptions": [{
            "LoadBalancerName": "legacy-elb", "DNSName": "legacy-elb-55555.us-east-1.elb.amazonaws.com", "Instances": [], "Subnets": [subs[("public", "a")]],
            "CreatedTime": self.ago(1200), "Scheme": "internet-facing"}]}
        nlb_arn = f"arn:aws:elasticloadbalancing:{r}:{ACCOUNT}:loadbalancer/net/unused-nlb/aaaa1111bbbb2222"
        self.d[r][("elbv2", "describe-load-balancers")]["LoadBalancers"].append({
            "LoadBalancerArn": nlb_arn, "LoadBalancerName": "unused-nlb", "Type": "network", "Scheme": "internal", "State": {"Code": "active"}, "VpcId": vpc,
            "CreatedTime": self.ago(330), "DNSName": "unused-nlb-aaaa.elb.us-east-1.amazonaws.com",
            "AvailabilityZones": [{"SubnetId": subs[("private", "a")]}]})
        self.d[r][("elbv2", "describe-target-groups")]["TargetGroups"].append({
            "TargetGroupArn": f"arn:aws:elasticloadbalancing:{r}:{ACCOUNT}:targetgroup/unused-tg/ffff0000", "TargetGroupName": "unused-tg",
            "TargetType": "instance", "VpcId": vpc, "LoadBalancerArns": [nlb_arn]})
        self.d[r][("elbv2", "describe-target-health")][f"arn:aws:elasticloadbalancing:{r}:{ACCOUNT}:targetgroup/unused-tg/ffff0000"] = []
        self.metric_idle["net/unused-nlb/aaaa1111bbbb2222"] = {"flows": 0}
        self.put(r, "rds", "describe-db-instances", "DBInstances", {
            "DBInstanceIdentifier": "scratch-db", "DBInstanceClass": "db.t3.large", "Engine": "mysql", "DBInstanceStatus": "stopped", "MultiAZ": False,
            "AllocatedStorage": 300, "StorageType": "gp2", "StorageEncrypted": False, "InstanceCreateTime": self.ago(800),
            "DBInstanceArn": f"arn:aws:rds:{r}:{ACCOUNT}:db:scratch-db", "DBSubnetGroup": {"VpcId": vpc}})
        self.volume("eu-central-1", "frankfurt-orphan-volume", 1000, "gp2", age=330)
        self.eip("eu-central-1", "frankfurt-old-eip")
        self.log_group("eu-central-1", "/aws/lambda/forgotten", gb=3, retention=None, ingest=0)

    def iam_and_edge(self):
        g = "us-east-1"
        self.d[g][("iam", "list-users")] = {"Users": [
            {"UserName": "alice", "Arn": f"arn:aws:iam::{ACCOUNT}:user/alice", "CreateDate": self.ago(900), "PasswordLastUsed": self.ago(2)},
            {"UserName": "bob", "Arn": f"arn:aws:iam::{ACCOUNT}:user/bob", "CreateDate": self.ago(800)},
            {"UserName": "ci-bot", "Arn": f"arn:aws:iam::{ACCOUNT}:user/ci-bot", "CreateDate": self.ago(300)}]}
        self.d[g][("iam", "list-access-keys")] = {
            "alice": {"AccessKeyMetadata": [{"AccessKeyId": "AKIAALICE00000000001", "Status": "Active", "CreateDate": self.ago(500)}]},
            "bob": {"AccessKeyMetadata": [{"AccessKeyId": "AKIABOB0000000000002", "Status": "Active", "CreateDate": self.ago(780)}]},
            "ci-bot": {"AccessKeyMetadata": [{"AccessKeyId": "AKIACIBOT000000000003", "Status": "Active", "CreateDate": self.ago(60)}]}}
        self.d[g][("iam", "get-access-key-last-used")] = {
            "AKIAALICE00000000001": {"AccessKeyLastUsed": {"LastUsedDate": self.ago(1), "ServiceName": "s3"}},
            "AKIABOB0000000000002": {"AccessKeyLastUsed": {"LastUsedDate": self.ago(410), "ServiceName": "ec2"}},
            "AKIACIBOT000000000003": {"AccessKeyLastUsed": {"LastUsedDate": self.ago(0), "ServiceName": "ecr"}}}
        busy = ("analytics-lambda-role", "shop-checkout-task", "ecsTaskExecutionRole", "analytics-eks-cluster-role")
        self.d[g][("iam", "list-roles")] = {"Roles": [{"RoleName": "shop-lambda-role", "Path": "/service-role/"}] + [
            {"RoleName": n, "Path": "/"} for n in ("old-poc-role", "eks-node-role", *busy)]}
        self.d[g][("iam", "get-role")] = {
            "shop-lambda-role": {"Role": {"RoleName": "shop-lambda-role", "Path": "/service-role/", "Arn": f"arn:aws:iam::{ACCOUNT}:role/service-role/shop-lambda-role", "CreateDate": self.ago(500), "RoleLastUsed": {"LastUsedDate": self.ago(0)}, "Tags": tags(Project="shop")}},
            "old-poc-role": {"Role": {"RoleName": "old-poc-role", "Path": "/", "Arn": f"arn:aws:iam::{ACCOUNT}:role/old-poc-role", "CreateDate": self.ago(700), "RoleLastUsed": {}}},
            "eks-node-role": {"Role": {"RoleName": "eks-node-role", "Path": "/", "Arn": f"arn:aws:iam::{ACCOUNT}:role/eks-node-role", "CreateDate": self.ago(600), "RoleLastUsed": {"LastUsedDate": self.ago(0)}}},
            **{n: {"Role": {"RoleName": n, "Path": "/", "Arn": f"arn:aws:iam::{ACCOUNT}:role/{n}", "CreateDate": self.ago(400),
                            "RoleLastUsed": {"LastUsedDate": self.ago(1)}}} for n in busy}}
        # CloudFront + Route 53
        alb_dns = "shop-web-alb-1234567890.us-east-1.elb.amazonaws.com"
        self.d[g][("cloudfront", "list-distributions")] = {"DistributionList": {"Items": [
            {"Id": "E1SHOPASSETS", "ARN": f"arn:aws:cloudfront::{ACCOUNT}:distribution/E1SHOPASSETS", "DomainName": "d111111abcdef8.cloudfront.net", "Enabled": True,
             "Comment": "shop assets", "Aliases": {"Items": ["assets.shop.example.com"]}, "Origins": {"Items": [{"DomainName": "shop-assets.s3.us-east-1.amazonaws.com"}]},
             "PriceClass": "PriceClass_All"},
            {"Id": "E2SHOPAPP", "ARN": f"arn:aws:cloudfront::{ACCOUNT}:distribution/E2SHOPAPP", "DomainName": "d222222abcdef8.cloudfront.net", "Enabled": True,
             "Comment": "shop app", "Aliases": {"Items": ["www.shop.example.com"]}, "Origins": {"Items": [{"DomainName": alb_dns}]}},
            {"Id": "E3MKTG", "ARN": f"arn:aws:cloudfront::{ACCOUNT}:distribution/E3MKTG", "DomainName": "d333333abcdef8.cloudfront.net", "Enabled": True,
             "Comment": "marketing site", "Aliases": {"Items": ["www.acme-marketing.example.com"]},
             "Origins": {"Items": [{"DomainName": "marketing-site.s3.eu-west-1.amazonaws.com"}]}},
            {"Id": "E4OLD", "ARN": f"arn:aws:cloudfront::{ACCOUNT}:distribution/E4OLD", "DomainName": "d444444abcdef8.cloudfront.net", "Enabled": False,
             "Comment": "old campaign", "Aliases": {"Items": []}, "Origins": {"Items": [{"DomainName": "shop-old-website.s3.us-east-1.amazonaws.com"}]}},
            {"Id": "E5SHOPAPI", "ARN": f"arn:aws:cloudfront::{ACCOUNT}:distribution/E5SHOPAPI", "DomainName": "d555555abcdef8.cloudfront.net", "Enabled": True,
             "Comment": "shop public api", "Aliases": {"Items": ["public-api.shop.example.com"]},
             "Origins": {"Items": [{"DomainName": f"{SHOP_API_ID}.execute-api.us-east-1.amazonaws.com"}]}}]}}
        self.d[g][("route53", "list-hosted-zones")] = {"HostedZones": [
            {"Id": "/hostedzone/Z1SHOP", "Name": "shop.example.com.", "ResourceRecordSetCount": 7, "Config": {"PrivateZone": False}},
            {"Id": "/hostedzone/Z2MKTG", "Name": "acme-marketing.example.com.", "ResourceRecordSetCount": 4, "Config": {"PrivateZone": False}},
            {"Id": "/hostedzone/Z3EMPTY", "Name": "acme-experiment.example.net.", "ResourceRecordSetCount": 2, "Config": {"PrivateZone": False}}]}
        eip_free = next(a["PublicIp"] for a in self.resp(g, "ec2", "describe-addresses", "Addresses") if a["Tags"] and a["Tags"][0]["Value"] == "shop-old-lb")
        self.d[g][("route53", "list-resource-record-sets")] = {
            "Z1SHOP": {"ResourceRecordSets": [
                {"Name": "shop.example.com.", "Type": "NS", "ResourceRecords": [{"Value": "ns-1.awsdns.org"}]},
                {"Name": "api.shop.example.com.", "Type": "A", "AliasTarget": {"DNSName": f"dualstack.{alb_dns}.", "HostedZoneId": "Z35SXDOTRQ7X7K"}},
                {"Name": "www.shop.example.com.", "Type": "A", "AliasTarget": {"DNSName": "d222222abcdef8.cloudfront.net.", "HostedZoneId": "Z2FDTNDATAQYW2"}},
                {"Name": "assets.shop.example.com.", "Type": "A", "AliasTarget": {"DNSName": "d111111abcdef8.cloudfront.net.", "HostedZoneId": "Z2FDTNDATAQYW2"}},
                {"Name": "public-api.shop.example.com.", "Type": "A", "AliasTarget": {"DNSName": "d555555abcdef8.cloudfront.net.", "HostedZoneId": "Z2FDTNDATAQYW2"}},
                {"Name": "legacy.shop.example.com.", "Type": "A", "ResourceRecords": [{"Value": eip_free}], "TTL": 300},
                {"Name": "promo.shop.example.com.", "Type": "CNAME", "ResourceRecords": [{"Value": "shop-promo-2022.s3-website-us-east-1.amazonaws.com"}], "TTL": 300},
                {"Name": "old.shop.example.com.", "Type": "CNAME", "ResourceRecords": [{"Value": "dgone9999abcdef.cloudfront.net"}], "TTL": 300}]},
            "Z2MKTG": {"ResourceRecordSets": [
                {"Name": "acme-marketing.example.com.", "Type": "NS", "ResourceRecords": [{"Value": "ns-9.awsdns.org"}]},
                {"Name": "www.acme-marketing.example.com.", "Type": "A", "AliasTarget": {"DNSName": "d333333abcdef8.cloudfront.net.", "HostedZoneId": "Z2FDTNDATAQYW2"}}]},
            "Z3EMPTY": {"ResourceRecordSets": [{"Name": "acme-experiment.example.net.", "Type": "NS", "ResourceRecords": [{"Value": "ns-5.awsdns.org"}]}]}}

    # ---- builders for repeated shapes ------------------------------------------
    def lambda_fn(self, region, name, runtime, invocations, *, project=None, arch="x86_64", role=None):
        self.put(region, "lambda", "list-functions", "Functions", {
            "FunctionName": name, "FunctionArn": f"arn:aws:lambda:{region}:{ACCOUNT}:function:{name}", "Runtime": runtime, "MemorySize": 512, "Timeout": 30,
            "CodeSize": 4_000_000, "Architectures": [arch], "PackageType": "Zip", "LastModified": self.ago(200).replace("Z", ".000+0000"),
            "Role": f"arn:aws:iam::{ACCOUNT}:role/{role or (project or 'misc') + '-lambda-role'}",
            "Environment": {"Variables": {"DB_PASSWORD": "definitely-not-for-the-report"}}})
        self.metric_idle[name] = {"inv": invocations}

    def esm(self, region, function, source_arn, *, batch, state="Enabled", on_failure=None, qualifier=None):
        """One event source mapping, already projected the way the collector's --query shapes it."""
        fn = f"arn:aws:lambda:{region}:{ACCOUNT}:function:{function}" + (f":{qualifier}" if qualifier else "")
        self.d[region].setdefault(("lambda", "list-event-source-mappings"), []).append(
            {"src": source_arn, "fn": fn, "state": state, "batch": batch, "fail": on_failure})

    def ddb(self, region, name, *, rcu, wcu, size_gb, reads, writes, project, ondemand=False, stream=False):
        self.d[region].setdefault(("dynamodb", "list-tables"), {"TableNames": []})["TableNames"].append(name)
        table = {"TableName": name, "TableStatus": "ACTIVE", "TableSizeBytes": int(size_gb * 1e9), "ItemCount": int(size_gb * 1e6),
                 "TableArn": f"arn:aws:dynamodb:{region}:{ACCOUNT}:table/{name}", "CreationDateTime": self.ago(300),
                 "BillingModeSummary": {"BillingMode": "PAY_PER_REQUEST" if ondemand else "PROVISIONED"},
                 "ProvisionedThroughput": {"ReadCapacityUnits": rcu, "WriteCapacityUnits": wcu}}
        if stream:
            table["StreamSpecification"] = {"StreamEnabled": True, "StreamViewType": "NEW_AND_OLD_IMAGES"}
            table["LatestStreamArn"] = f"{table['TableArn']}/stream/2025-03-01T00:00:00.000"
        self.d[region].setdefault(("dynamodb", "describe-table"), {})[name] = {"Table": table}
        self.metric_idle[name] = {"ddb": (reads, writes)}

    def queue(self, region, name, *, sent, project, redrive_to=None, messages=0):
        url = f"https://sqs.{region}.amazonaws.com/{ACCOUNT}/{name}"
        self.d[region].setdefault(("sqs", "list-queues"), {"QueueUrls": []})["QueueUrls"].append(url)
        attrs = {"QueueArn": f"arn:aws:sqs:{region}:{ACCOUNT}:{name}", "CreatedTimestamp": str(int((self.now - timedelta(days=300)).timestamp())),
                 "ApproximateNumberOfMessages": str(messages), "ApproximateNumberOfMessagesNotVisible": "0"}
        if redrive_to:
            attrs["RedrivePolicy"] = json.dumps({"deadLetterTargetArn": f"arn:aws:sqs:{region}:{ACCOUNT}:{redrive_to}", "maxReceiveCount": 5})
        self.d[region].setdefault(("sqs", "get-queue-attributes"), {})[url] = {"Attributes": attrs}
        self.metric_idle[name] = {"sent": sent}

    def bucket(self, name, region, *, gb, lifecycle, versioning, project, objects, website=False, ia_gb=0):
        b = self.d["us-east-1"]
        b.setdefault(("s3api", "list-buckets"), {"Buckets": []})["Buckets"].append(
            {"Name": name, "CreationDate": self.ago(500), "BucketRegion": region})
        b.setdefault(("s3api", "get-bucket-tagging"), {})[name] = {"TagSet": tags(Project=project)} if project else None
        b.setdefault(("s3api", "get-bucket-lifecycle-configuration"), {})[name] = (
            {"Rules": [{"Status": "Enabled", "Transitions": [{"Days": 30, "StorageClass": "STANDARD_IA"}],
                        "Expiration": {"Days": 730}, "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 7}}]} if lifecycle else None)
        b.setdefault(("s3api", "get-bucket-versioning"), {})[name] = {"Status": "Enabled"} if versioning else {}
        b.setdefault(("s3api", "get-public-access-block"), {})[name] = (
            None if website else {"PublicAccessBlockConfiguration": {k: True for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")}})
        self.metric_idle[f"bucket:{name}"] = {"gb": gb, "objects": objects, "ia_gb": ia_gb}

    def log_group(self, region, name, *, gb, retention, ingest):
        g = {"logGroupName": name, "logGroupArn": f"arn:aws:logs:{region}:{ACCOUNT}:log-group:{name}:*", "storedBytes": int(gb * 1e9),
             "creationTime": int((self.now - timedelta(days=400)).timestamp() * 1000)}
        if retention:
            g["retentionInDays"] = retention
        self.put(region, "logs", "describe-log-groups", "logGroups", g)
        self.metric_idle[f"log:{name}"] = {"ingest": ingest * 1e9}

    # -- fake AWS plumbing --------------------------------------------------------
    def metric_response(self, queries: list[dict], start: str, end: str) -> dict:
        results = []
        days = max(1, round((datetime.fromisoformat(end.replace("Z", "+00:00")) - datetime.fromisoformat(start.replace("Z", "+00:00"))).days))
        stamps = [(self.now - timedelta(days=i + 1)).strftime("%Y-%m-%dT00:00:00Z") for i in range(days)]
        for q in queries:
            m = q["MetricStat"]["Metric"]
            dims = {d["Name"]: d["Value"] for d in m["Dimensions"]}
            vals = self._metric(m["MetricName"], q["MetricStat"]["Stat"], dims, days)
            results.append({"Id": q["Id"], "Timestamps": stamps[:len(vals)], "Values": vals})
        return {"MetricDataResults": results}

    def _metric(self, name: str, stat: str, dims: dict, days: int) -> list[float]:
        o = lambda key: self.metric_idle.get(key, {})  # noqa: E731
        if name == "CPUUtilization":
            for k in ("InstanceId", "DBInstanceIdentifier", "CacheClusterId", "ServiceName"):
                if k in dims and (c := o(dims[k]).get("cpu")):
                    v = c[0] if stat == "Average" else c[1]
                    return [v] * days
            return [30.0 if stat == "Average" else 60.0] * days
        if name in ("DatabaseConnections", "CurrConnections"):
            c = o(dims.get("DBInstanceIdentifier") or dims.get("CacheClusterId")).get("conn", 5)
            return [float(c)] * days
        if name in ("BytesInFromSource", "BytesInFromDestination"):
            idle = o(dims["NatGatewayId"]).get("nat", False)
            return [] if idle else [40e9] * days
        if name in ("NetworkIn", "NetworkOut"):
            cpu = o(dims["InstanceId"]).get("cpu", (30, 60))
            return [1e6] * days if cpu[0] < 5 else [5e8] * days      # idle-by-design instances also move no traffic
        if name == "RequestCount":
            return [o(dims["LoadBalancer"]).get("requests", 100_000) / days] * days if "LoadBalancer" in dims else []
        if name == "Requests":
            return [] if dims.get("DistributionId") == "E4OLD" else [1000.0] * 30
        if name == "NewFlowCount":
            f = o(dims["LoadBalancer"]).get("flows", 1000)
            return [f / days] * days if f else []
        if name == "Invocations":
            inv = o(dims["FunctionName"]).get("inv", 100)
            return [inv / 30] * 30 if inv else []
        if name in ("ConsumedReadCapacityUnits", "ConsumedWriteCapacityUnits"):
            r, w = o(dims["TableName"]).get("ddb", (10_000, 10_000))
            total = r if name.startswith("ConsumedRead") else w
            return [total / 30 * 1.0] * 30 if total else []
        if name == "Count":                                   # API Gateway requests
            return [2000.0] * days
        if name == "NumberOfMessagesSent":
            s = o(dims["QueueName"]).get("sent", 1000)
            return [s / 30] * 30 if s else []
        if name == "NumberOfMessagesPublished":
            s = o(dims["TopicName"]).get("pub", 100)
            return [s / 30] * 30 if s else []
        if name == "IncomingBytes":
            s = o(f"log:{dims['LogGroupName']}").get("ingest", 1e6)
            return [s / 30] * 30 if s else []
        if name in ("BucketSizeBytes", "NumberOfObjects"):
            b = o(f"bucket:{dims['BucketName']}")
            if not b:
                return []
            st = dims.get("StorageType")
            if name == "NumberOfObjects":
                return [float(b["objects"])] * 2
            if st == "StandardStorage":
                return [(b["gb"] - b["ia_gb"]) * 1e9] * 2
            if st == "StandardIAStorage" and b["ia_gb"]:
                return [b["ia_gb"] * 1e9] * 2
            return []
        return []

    def executor(self) -> FakeAws:
        f = FakeAws()
        f.set("sts", "get-caller-identity", {"Account": ACCOUNT, "UserId": "AIDADEMO", "Arn": CALLER})
        f.set("ec2", "describe-regions", {"Regions": [{"RegionName": r} for r in REGIONS]})

        def make(svc: str, op: str):
            def handler(region, args):
                reg = "us-east-1" if svc in GLOBAL_SERVICES else (region or "us-east-1")
                data = self.d.get(reg, {}).get((svc, op))
                if (svc, op) == ("ecr", "get-lifecycle-policy") and not data:
                    raise FakeError("LifecyclePolicyNotFoundException")
                if data is None:
                    return {}
                if (svc, op) == ("elbv2", "describe-target-health"):
                    return {"TargetHealthDescriptions": data.get(arg_value(args, "--target-group-arn"), [])}
                if (svc, op) in KEYED_OPS:
                    return self._keyed(op, data, args)
                return data
            return handler

        seen = {(s, o) for reg in self.d.values() for (s, o) in reg}
        for svc, op in seen:
            f.set(svc, op, make(svc, op))
        f.set("cloudwatch", "get-metric-data", lambda reg, args: self.metric_response(
            json.loads(arg_value(args, "--metric-data-queries")), arg_value(args, "--start-time"), arg_value(args, "--end-time")))
        f.set("resourcegroupstaggingapi", "get-resources", self._tagging)
        return f

    def _keyed(self, op, data, args):
        out = data.get(arg_value(args, KEYED_OPS_FLAG[op]))
        if out is None:
            raise FakeError({"get-bucket-tagging": "NoSuchTagSet", "get-bucket-lifecycle-configuration": "NoSuchLifecycleConfiguration",
                             "get-public-access-block": "NoSuchPublicAccessBlockConfiguration"}.get(op, "NoSuchEntity"))
        return out

    def _tagging(self, region, args):
        items = []
        for r in self.d.get(region or "us-east-1", {}).get(("ec2", "describe-instances"), {}).get("Reservations", []):
            for i in r["Instances"]:
                items.append({"ResourceARN": f"arn:aws:ec2:{region}:{ACCOUNT}:instance/{i['InstanceId']}", "Tags": i.get("Tags", [])})
        for v in self.d.get(region or "us-east-1", {}).get(("ec2", "describe-volumes"), {}).get("Volumes", []):
            if v.get("Tags"):
                items.append({"ResourceARN": f"arn:aws:ec2:{region}:{ACCOUNT}:volume/{v['VolumeId']}", "Tags": v["Tags"]})
        if (region or "us-east-1") == "us-east-1":
            items.append({"ResourceARN": f"arn:aws:cloudwatch:{region}:{ACCOUNT}:alarm:shop-high-5xx", "Tags": tags(Project="shop")})
            items.append({"ResourceARN": f"arn:aws:glue:{region}:{ACCOUNT}:database/analytics_catalog", "Tags": tags(Project="analytics")})
            items.append({"ResourceARN": f"arn:aws:kinesis:{region}:{ACCOUNT}:stream/analytics-clicks", "Tags": tags(Project="analytics")})
            items.append({"ResourceARN": f"arn:aws:secretsmanager:{region}:{ACCOUNT}:secret:shop/db-AbCdEf", "Tags": tags(Project="shop")})
        return {"ResourceTagMappingList": items}


def demo_executor(now: datetime | None = None) -> tuple[FakeAws, Demo]:
    d = Demo(now)
    return d.executor(), d
