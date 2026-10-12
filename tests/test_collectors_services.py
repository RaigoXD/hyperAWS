"""Data, serverless, container, edge, ops and IAM collectors + CloudWatch metrics."""

import json
import unittest
from datetime import datetime, timedelta, timezone

from analyzer import metrics
from analyzer.awscli import AwsCli
from analyzer.collectors import containers, dynamodb, edge, elasticache, iam, ops, rds, s3, serverless
from analyzer.fakeaws import FakeAws, FakeError, arg_value
from analyzer.scan import Ctx, ScanOptions

ACCT = "111122223333"


def ctx_for(fake, region="eu-west-1", is_global=False):
    cli = AwsCli("t", executor=fake, aws_bin="aws", sleep=lambda s: None)
    return Ctx(cli, ACCT, region, is_global=is_global)


def idx(resources):
    return {r.rid: r for r in resources}


class TestRds(unittest.TestCase):
    def test_instances_clusters_snapshots(self):
        f = FakeAws()
        f.set("rds", "describe-db-instances", {"DBInstances": [{
            "DBInstanceIdentifier": "shop-db", "DBInstanceClass": "db.m5.large", "Engine": "postgres", "MultiAZ": True,
            "DBInstanceStatus": "available", "AllocatedStorage": 100, "StorageType": "gp3",
            "DBInstanceArn": "arn:aws:rds:eu-west-1:111122223333:db:shop-db",
            "TagList": [{"Key": "Project", "Value": "shop"}], "DBSubnetGroup": {"VpcId": "vpc-1"},
            "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-db"}]}]})
        f.set("rds", "describe-db-clusters", {"DBClusters": [{"DBClusterIdentifier": "aur", "Status": "available",
                                                             "Engine": "aurora-postgresql",
                                                             "ServerlessV2ScalingConfiguration": {"MinCapacity": 0.5, "MaxCapacity": 4},
                                                             "DBClusterMembers": [{}, {}]}]})
        f.set("rds", "describe-db-snapshots", {"DBSnapshots": [{"DBSnapshotIdentifier": "snap", "DBInstanceIdentifier": "gone-db",
                                                               "SnapshotCreateTime": "2024-01-01T00:00:00Z", "AllocatedStorage": 50,
                                                               "Status": "available"}]})
        r = idx(rds.collect(ctx_for(f)))
        self.assertEqual(r["shop-db"].tags["Project"], "shop")
        self.assertEqual(r["shop-db"].attrs["instance_class"], "db.m5.large")
        self.assertTrue(r["shop-db"].attrs["multi_az"])
        self.assertEqual(r["aur"].attrs["acu_max"], 4)
        self.assertEqual(r["snap"].attrs["source"], "gone-db")
        self.assertEqual(r["snap"].created, "2024-01-01T00:00:00Z")
        self.assertIn(("--snapshot-type", "manual"), [(a[0], a[1]) for _s, o, _r, a in f.calls if o == "describe-db-snapshots"])


class TestDynamoDb(unittest.TestCase):
    def test_tables(self):
        f = FakeAws()
        f.set("dynamodb", "list-tables", {"TableNames": ["a", "b"]})
        f.set("dynamodb", "describe-table", lambda reg, args: {"Table": {
            "TableName": arg_value(args, "--table-name"), "TableStatus": "ACTIVE", "TableSizeBytes": 1000, "ItemCount": 10,
            "ProvisionedThroughput": {"ReadCapacityUnits": 5, "WriteCapacityUnits": 2},
            "TableArn": "arn:aws:dynamodb:eu-west-1:111122223333:table/" + arg_value(args, "--table-name")}
            if arg_value(args, "--table-name") == "a" else {
            "TableName": "b", "TableStatus": "ACTIVE", "BillingModeSummary": {"BillingMode": "PAY_PER_REQUEST"},
            "ProvisionedThroughput": {"ReadCapacityUnits": 0, "WriteCapacityUnits": 0}}})
        r = idx(dynamodb.collect(ctx_for(f)))
        self.assertEqual(r["a"].attrs["billing_mode"], "PROVISIONED")
        self.assertEqual((r["a"].attrs["rcu"], r["a"].attrs["wcu"]), (5, 2))
        self.assertEqual(r["b"].attrs["billing_mode"], "PAY_PER_REQUEST")


class TestS3(unittest.TestCase):
    def test_bucket_config_and_expected_errors(self):
        f = FakeAws()
        f.set("s3api", "list-buckets", {"Buckets": [{"Name": "logs-bkt", "CreationDate": "2023-05-01T00:00:00Z"},
                                                    {"Name": "site-bkt", "CreationDate": "2024-05-01T00:00:00Z", "BucketRegion": "eu-west-1"}]})
        f.set("s3api", "get-bucket-location", lambda reg, a: {"LocationConstraint": "eu-central-1"})

        def per_bucket(op, ok):
            def h(reg, args):
                if arg_value(args, "--bucket") == "logs-bkt":
                    raise FakeError(ok)
                return {}
            return h
        f.set("s3api", "get-bucket-tagging", per_bucket("t", "NoSuchTagSet"))
        f.set("s3api", "get-bucket-lifecycle-configuration", lambda reg, a: (_ for _ in ()).throw(FakeError("NoSuchLifecycleConfiguration"))
              if arg_value(a, "--bucket") == "logs-bkt" else {"Rules": [{"Status": "Enabled", "Expiration": {"Days": 30},
                                                                          "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 7}}]})
        f.set("s3api", "get-bucket-versioning", lambda reg, a: {"Status": "Enabled"} if arg_value(a, "--bucket") == "site-bkt" else {})
        f.set("s3api", "get-public-access-block", lambda reg, a: {"PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}}
              if arg_value(a, "--bucket") == "site-bkt" else (_ for _ in ()).throw(FakeError("NoSuchPublicAccessBlockConfiguration")))
        ctx = ctx_for(f, "us-east-1", is_global=True)
        r = idx(s3.collect(ctx))
        self.assertEqual(ctx.gaps, [], "expected 'nothing there' errors must not become gaps")
        logs, site = r["logs-bkt"], r["site-bkt"]
        self.assertEqual(logs.region, "eu-central-1")           # via get-bucket-location
        self.assertEqual(site.region, "eu-west-1")              # via BucketRegion
        self.assertEqual(logs.key, f"{ACCT}:global:s3:bucket:logs-bkt")
        self.assertEqual(logs.attrs["lifecycle_rules"], 0)
        self.assertFalse(logs.attrs["public_access_blocked"])
        self.assertEqual(site.attrs["lifecycle_rules"], 1)
        self.assertTrue(site.attrs["lc_expiration"] and site.attrs["lc_abort_multipart"])
        self.assertEqual(site.attrs["versioning"], "Enabled")
        self.assertTrue(site.attrs["public_access_blocked"])
        self.assertEqual(logs.attrs["versioning"], "Unversioned")


class TestElastiCache(unittest.TestCase):
    def test_clusters(self):
        f = FakeAws()
        f.set("elasticache", "describe-cache-clusters", {"CacheClusters": [
            {"CacheClusterId": "c-001", "CacheNodeType": "cache.t3.micro", "Engine": "redis", "CacheClusterStatus": "available",
             "NumCacheNodes": 1, "ReplicationGroupId": "rg"}]})
        f.set("elasticache", "describe-replication-groups", {"ReplicationGroups": [{"ReplicationGroupId": "rg", "Status": "available",
                                                                                  "MemberClusters": ["c-001"]}]})
        r = idx(elasticache.collect(ctx_for(f)))
        self.assertEqual(r["c-001"].relations[0]["kind"], "member-of")
        self.assertEqual(r["rg"].attrs["members"], 1)


class TestServerless(unittest.TestCase):
    def test_lambda_never_keeps_environment(self):
        f = FakeAws()
        f.set("lambda", "list-functions", {"Functions": [{
            "FunctionName": "orders", "FunctionArn": "arn:aws:lambda:eu-west-1:111122223333:function:orders",
            "Runtime": "python3.8", "MemorySize": 512, "Timeout": 30, "Architectures": ["arm64"],
            "Environment": {"Variables": {"DB_PASSWORD": "hunter2", "API_KEY": "sekrit"}},
            "Role": "arn:aws:iam::111122223333:role/orders-role", "LastModified": "2024-01-02T03:04:05.000+0000",
            "VpcConfig": {"VpcId": "vpc-1", "SubnetIds": ["subnet-a"], "SecurityGroupIds": ["sg-1"]}}]})
        f.set("sqs", "list-queues", {"QueueUrls": ["https://sqs.eu-west-1.amazonaws.com/111122223333/jobs"]})
        f.set("sqs", "get-queue-attributes", {"Attributes": {"QueueArn": "arn:aws:sqs:eu-west-1:111122223333:jobs",
                                                             "ApproximateNumberOfMessages": "7", "CreatedTimestamp": "1700000000"}})
        f.set("sns", "list-topics", {"Topics": [{"TopicArn": "arn:aws:sns:eu-west-1:111122223333:alerts"},
                                                {"TopicArn": "arn:aws:sns:eu-west-1:111122223333:orphan"}]})
        f.set("sns", "list-subscriptions", {"Subscriptions": [{"TopicArn": "arn:aws:sns:eu-west-1:111122223333:alerts",
                                                               "Endpoint": "someone@example.com", "Protocol": "email"}]})
        f.set("apigateway", "get-rest-apis", {"items": [{"id": "abc", "name": "orders-api"}]})
        f.set("apigatewayv2", "get-apis", {"Items": [{"ApiId": "xyz", "Name": "http-api", "ProtocolType": "HTTP"}]})
        f.set("stepfunctions", "list-state-machines", {"stateMachines": [{"name": "flow", "stateMachineArn": "arn:aws:states:eu-west-1:111122223333:stateMachine:flow", "type": "STANDARD"}]})
        res = serverless.collect(ctx_for(f))
        blob = json.dumps([r.__dict__ for r in res])
        for secret in ("hunter2", "sekrit", "DB_PASSWORD", "someone@example.com"):
            self.assertNotIn(secret, blob)
        r = idx(res)
        self.assertEqual(r["orders"].attrs["arch"], "arm64")
        self.assertEqual(r["orders"].attrs["role"], "orders-role")
        self.assertEqual(r["orders"].attrs["last_modified"], "2024-01-02T03:04:05Z")
        self.assertEqual({x["kind"] for x in r["orders"].relations}, {"in-subnet", "uses-sg"})
        self.assertEqual(r["jobs"].attrs["messages"], 7)
        self.assertEqual((r["alerts"].attrs["subscriptions"], r["orphan"].attrs["subscriptions"]), (1, 0))
        self.assertEqual({"apigw:rest-api", "apigw:http-api", "sfn:state-machine"}, {x.type for x in res if x.type.startswith(("apigw", "sfn"))})


class TestContainers(unittest.TestCase):
    def test_ecs_ecr_eks(self):
        f = FakeAws()
        f.set("ecs", "list-clusters", {"clusterArns": ["arn:aws:ecs:eu-west-1:111122223333:cluster/main"]})
        f.set("ecs", "describe-clusters", {"clusters": [{"clusterArn": "arn:aws:ecs:eu-west-1:111122223333:cluster/main", "clusterName": "main",
                                                         "status": "ACTIVE", "tags": [{"key": "Project", "value": "shop"}]}]})
        f.set("ecs", "list-services", {"serviceArns": ["arn:s1", "arn:s2"]})
        f.set("ecs", "describe-services", {"services": [
            {"serviceName": "web", "serviceArn": "arn:s1", "status": "ACTIVE", "desiredCount": 2, "runningCount": 2,
             "launchType": "FARGATE", "taskDefinition": "td:1",
             "loadBalancers": [{"targetGroupArn": "arn:aws:elasticloadbalancing:eu-west-1:111122223333:targetgroup/web-tg/abc"}],
             "networkConfiguration": {"awsvpcConfiguration": {"subnets": ["subnet-a"], "securityGroups": ["sg-1"]}}},
            {"serviceName": "idle", "serviceArn": "arn:s2", "status": "ACTIVE", "desiredCount": 0, "launchType": "FARGATE", "taskDefinition": "td:1"}]})
        f.set("ecs", "describe-task-definition", {"cpu": "512", "memory": "1024", "arch": "ARM64"})
        f.set("ecr", "describe-repositories", {"repositories": [{"repositoryName": "app", "repositoryArn": "arn:aws:ecr:eu-west-1:111122223333:repository/app"}]})
        f.set("ecr", "get-lifecycle-policy", lambda reg, a: (_ for _ in ()).throw(FakeError("LifecyclePolicyNotFoundException")))
        f.set("ecr", "describe-images", [{"s": 1000, "p": 1700000000.0, "t": ["v1"]}, {"s": 2000, "p": 1600000000.0, "t": None}])
        f.set("eks", "list-clusters", {"clusters": ["prod"]})
        f.set("eks", "describe-cluster-versions", {"clusterVersions": [{"clusterVersion": "1.29", "status": "EXTENDED_SUPPORT"}]})
        f.set("eks", "describe-cluster", {"cluster": {"name": "prod", "arn": "arn:eks", "version": "1.29", "status": "ACTIVE",
                                                      "resourcesVpcConfig": {"vpcId": "vpc-1"}, "tags": {"Project": "shop"}}})
        f.set("eks", "list-nodegroups", {"nodegroups": ["ng1"]})
        f.set("eks", "describe-nodegroup", {"nodegroup": {"nodegroupName": "ng1", "status": "ACTIVE", "instanceTypes": ["m5.large"],
                                                          "scalingConfig": {"minSize": 1, "maxSize": 4, "desiredSize": 3}}})
        f.set("eks", "list-fargate-profiles", {"fargateProfileNames": []})
        res = containers.collect(ctx_for(f))
        r = idx(res)
        self.assertEqual(r["main/web"].attrs["task_cpu"], 512)
        self.assertEqual(r["main/web"].attrs["task_arch"], "ARM64")
        self.assertEqual(r["main/idle"].attrs["desired"], 0)
        self.assertEqual(r["main"].tags["Project"], "shop")
        self.assertIn(("serves", f"{ACCT}:eu-west-1:elbv2:target-group:web-tg"), {(x["kind"], x["to"]) for x in r["main/web"].relations})
        self.assertIs(r["app"].attrs["has_lifecycle_policy"], False)
        self.assertEqual((r["app"].attrs["images"], r["app"].attrs["untagged_images"], r["app"].attrs["size_bytes"]), (2, 1, 3000))
        self.assertEqual(r["prod"].attrs["version_status"], "EXTENDED_SUPPORT")
        self.assertEqual(r["prod/ng1"].attrs["desired"], 3)
        self.assertEqual(r["prod"].attrs["desired_nodes"], 3)
        # task definitions must only ever be fetched through a --query projection
        for _s, op, _r, args in f.calls:
            if op == "describe-task-definition":
                self.assertIn("--query", args)

    def test_ecr_access_denied_is_unknown_not_missing(self):
        f = FakeAws()
        f.set("ecr", "describe-repositories", {"repositories": [{"repositoryName": "app"}]})
        f.set("ecr", "get-lifecycle-policy", lambda reg, a: (_ for _ in ()).throw(FakeError("AccessDeniedException")))
        ctx = ctx_for(f)
        r = idx(containers._ecr(ctx))
        self.assertIsNone(r["app"].attrs["has_lifecycle_policy"])
        self.assertEqual(len(ctx.gaps), 1)


class TestEdgeOpsIam(unittest.TestCase):
    def test_edge(self):
        f = FakeAws()
        f.set("cloudfront", "list-distributions", {"DistributionList": {"Items": [{
            "Id": "E1", "ARN": "arn:cf", "DomainName": "d1.cloudfront.net", "Enabled": False, "Comment": "old site",
            "Aliases": {"Items": ["www.example.com"]}, "Origins": {"Items": [{"DomainName": "bkt.s3.amazonaws.com"}]}}]}})
        f.set("route53", "list-hosted-zones", {"HostedZones": [{"Id": "/hostedzone/Z1", "Name": "example.com.", "ResourceRecordSetCount": 4}]})
        f.set("route53", "list-resource-record-sets", {"ResourceRecordSets": [
            {"Name": "example.com.", "Type": "NS", "ResourceRecords": [{"Value": "ns-1"}]},
            {"Name": "www.example.com.", "Type": "A", "AliasTarget": {"DNSName": "d1.cloudfront.net."}},
            {"Name": "api.example.com.", "Type": "A", "ResourceRecords": [{"Value": "3.3.3.3"}]},
            {"Name": "blog.example.com.", "Type": "CNAME", "ResourceRecords": [{"Value": "x.elb.amazonaws.com"}]}]})
        res = idx(edge.collect(ctx_for(f, "us-east-1", is_global=True)))
        self.assertEqual(res["E1"].state, "disabled")
        self.assertEqual(res["E1"].region, "global")
        recs = res["Z1"].attrs["records"]
        self.assertEqual({(x["name"], x["type"], x["target"]) for x in recs}, {
            ("www.example.com", "ALIAS", "d1.cloudfront.net"), ("api.example.com", "A", "3.3.3.3"),
            ("blog.example.com", "CNAME", "x.elb.amazonaws.com")})
        self.assertEqual(res["Z1"].name, "example.com")

    def test_ops(self):
        f = FakeAws()
        f.set("logs", "describe-log-groups", {"logGroups": [
            {"logGroupName": "/aws/lambda/a", "logGroupArn": "arn:aws:logs:eu-west-1:111122223333:log-group:/aws/lambda/a:*", "storedBytes": 5000, "creationTime": 1700000000000},
            {"logGroupName": "/app/b", "retentionInDays": 30, "storedBytes": 1}]})
        f.set("kms", "list-keys", {"Keys": [{"KeyId": "k1"}, {"KeyId": "k2"}]})
        f.set("kms", "list-aliases", {"Aliases": [{"AliasName": "alias/app", "TargetKeyId": "k1"}]})
        f.set("kms", "describe-key", lambda reg, a: {"KeyMetadata": {"KeyId": arg_value(a, "--key-id"), "Arn": "arn:k", "KeyManager":
                                                     "CUSTOMER" if arg_value(a, "--key-id") == "k1" else "AWS", "KeyState": "Enabled", "Enabled": True}})
        res = idx(ops.collect(ctx_for(f)))
        self.assertIsNone(res["/aws/lambda/a"].attrs["retention_days"])
        self.assertEqual(res["/aws/lambda/a"].arn, "arn:aws:logs:eu-west-1:111122223333:log-group:/aws/lambda/a")
        self.assertEqual(res["/app/b"].attrs["retention_days"], 30)
        self.assertEqual(res["k1"].name, "app")
        self.assertNotIn("k2", res)

    def test_iam_masks_key_ids_and_skips_service_roles(self):
        f = FakeAws()
        f.set("iam", "list-users", {"Users": [{"UserName": "alice", "CreateDate": "2022-01-01T00:00:00Z", "Arn": "arn:u"}]})
        f.set("iam", "list-access-keys", {"AccessKeyMetadata": [{"AccessKeyId": "AKIAABCDEFGHIJKLMNOP", "Status": "Active", "CreateDate": "2022-01-01T00:00:00Z"}]})
        f.set("iam", "get-access-key-last-used", {"AccessKeyLastUsed": {"LastUsedDate": "2022-02-01T00:00:00Z", "ServiceName": "s3"}})
        f.set("iam", "list-roles", {"Roles": [{"RoleName": "app-role", "Path": "/"}, {"RoleName": "AWSServiceRoleForX", "Path": "/aws-service-role/x/"}]})
        f.set("iam", "get-role", {"Role": {"RoleName": "app-role", "Path": "/", "Arn": "arn:r", "RoleLastUsed": {"LastUsedDate": "2025-01-01T00:00:00Z"}}})
        res = iam.collect(ctx_for(f, "us-east-1", is_global=True))
        blob = json.dumps([r.__dict__ for r in res])
        self.assertNotIn("AKIAABCDEFGHIJKLMNOP", blob)
        r = idx(res)
        self.assertEqual(r["alice"].attrs["access_keys"][0]["id"], "AKIA…MNOP")
        self.assertIn("app-role", r)
        self.assertNotIn("AWSServiceRoleForX", r)
        self.assertEqual(r["app-role"].attrs["last_used"], "2025-01-01T00:00:00Z")


class TestMetrics(unittest.TestCase):
    def _run(self, resources, handler):
        f = FakeAws({("cloudwatch", "get-metric-data"): handler})
        cli = AwsCli("t", executor=f, aws_bin="aws", sleep=lambda s: None)
        gaps, import_lock = [], __import__("threading").Lock()
        metrics.collect_metrics(cli, ACCT, "aws", resources, ["eu-west-1"], ScanOptions(quiet=True), gaps, import_lock)
        return f, gaps

    def _res(self, ctx, rtype, rid, **kw):
        return ctx.new(rtype, rid, **kw)

    def test_aggregation_and_unknown_vs_zero(self):
        ctx = ctx_for(FakeAws())
        inst = self._res(ctx, "ec2:instance", "i-1", state="running")
        stopped = self._res(ctx, "ec2:instance", "i-2", state="stopped")
        nat = self._res(ctx, "ec2:nat-gateway", "nat-1", state="available")
        fn = self._res(ctx, "lambda:function", "fn")

        def handler(region, args):
            queries = json.loads(arg_value(args, "--metric-data-queries"))
            out = []
            for q in queries:
                m = q["MetricStat"]["Metric"]["MetricName"]
                if m == "CPUUtilization" and q["MetricStat"]["Stat"] == "Average":
                    out.append({"Id": q["Id"], "Timestamps": ["2025-01-01", "2025-01-02"], "Values": [2.0, 4.0]})
                elif m == "CPUUtilization":
                    out.append({"Id": q["Id"], "Timestamps": ["2025-01-01", "2025-01-02"], "Values": [10.0, 30.0]})
                else:  # NAT + Lambda: no datapoints at all
                    out.append({"Id": q["Id"], "Timestamps": [], "Values": []})
            return {"MetricDataResults": out}
        f, gaps = self._run([inst, stopped, nat, fn], handler)
        self.assertEqual((inst.metrics["cpu_avg"], inst.metrics["cpu_max"]), (3.0, 30.0))
        self.assertEqual(stopped.metrics, {})                       # stopped instances are not queried
        self.assertEqual((nat.metrics["bytes_return"], nat.metrics["bytes_in"]), (0.0, 0.0))   # sums default to 0
        self.assertEqual(fn.metrics["invocations"], 0.0)
        self.assertEqual(inst.metrics["_days"]["cpu_avg"], 14)
        self.assertEqual(fn.metrics["_days"]["invocations"], 30)
        self.assertEqual(gaps, [])
        # two windows (14d and 30d) => at least two calls, all read-only
        self.assertGreaterEqual(len([c for c in f.calls if c[1] == "get-metric-data"]), 2)

    def test_failed_call_leaves_metrics_unknown(self):
        ctx = ctx_for(FakeAws())
        nat = self._res(ctx, "ec2:nat-gateway", "nat-1", state="available")

        def deny(region, args):
            raise FakeError("AccessDenied")
        _f, gaps = self._run([nat], deny)
        self.assertNotIn("bytes_out", nat.metrics)
        self.assertEqual(len(gaps), 1)

    def test_s3_uses_latest_point_and_empty_bucket_rule(self):
        ctx = ctx_for(FakeAws(), "us-east-1", is_global=True)
        old = datetime.now(timezone.utc) - timedelta(days=100)
        full = self._res(ctx, "s3:bucket", "full", region="eu-west-1", created=old.strftime("%Y-%m-%dT%H:%M:%SZ"))
        empty = self._res(ctx, "s3:bucket", "empty", region="eu-west-1", created=old.strftime("%Y-%m-%dT%H:%M:%SZ"))
        new = self._res(ctx, "s3:bucket", "new", region="eu-west-1", created=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))

        def handler(region, args):
            out = []
            for q in json.loads(arg_value(args, "--metric-data-queries")):
                dims = {d["Name"]: d["Value"] for d in q["MetricStat"]["Metric"]["Dimensions"]}
                if dims["BucketName"] == "full" and dims["StorageType"] == "StandardStorage":
                    out.append({"Id": q["Id"], "Timestamps": ["2025-01-01T00:00:00Z", "2025-01-03T00:00:00Z", "2025-01-02T00:00:00Z"],
                                "Values": [100.0, 300.0, 200.0]})
                elif dims["BucketName"] == "full" and dims["StorageType"] == "AllStorageTypes":
                    out.append({"Id": q["Id"], "Timestamps": ["2025-01-03T00:00:00Z"], "Values": [42.0]})
                else:
                    out.append({"Id": q["Id"], "Timestamps": [], "Values": []})
            return {"MetricDataResults": out}
        self._run([full, empty, new], handler)
        self.assertEqual(full.metrics["bytes_standard"], 300.0)   # latest timestamp wins
        self.assertEqual(full.metrics["objects"], 42.0)
        self.assertEqual(empty.metrics["objects"], 0.0)           # old bucket without any metrics == empty
        self.assertNotIn("objects", new.metrics)                  # too new to know

    def test_batches_stay_under_limit(self):
        ctx = ctx_for(FakeAws())
        fns = [self._res(ctx, "lambda:function", f"fn{i}") for i in range(metrics.BATCH * 2 + 5)]
        f, _ = self._run(fns, lambda reg, args: {"MetricDataResults": []})
        sizes = [len(json.loads(arg_value(c[3], "--metric-data-queries"))) for c in f.calls if c[1] == "get-metric-data"]
        self.assertEqual(sorted(sizes), [5, metrics.BATCH, metrics.BATCH])


if __name__ == "__main__":
    unittest.main()
