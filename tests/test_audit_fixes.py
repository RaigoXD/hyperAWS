"""Regression tests for the defects found by auditing the collectors against the AWS botocore models."""

import json
import threading
import unittest
from dataclasses import asdict
from datetime import datetime, timedelta, timezone

from analyzer import metrics
from analyzer.analysis.config import load_config
from analyzer.analysis.engine import analyze
from analyzer.awscli import AwsCli
from analyzer.collectors import containers, ec2_net, edge, iam, rds, s3, serverless, tagging
from analyzer.fakeaws import FakeAws, FakeError, arg_value
from analyzer.model import Resource, make_key
from analyzer.scan import Ctx, Failed, ScanOptions, merge_tagging, run_scan

ACCT = "111122223333"
NOW = datetime(2026, 10, 1, tzinfo=timezone.utc)


def ago(days):
    return (NOW - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def ctx_for(fake, region="us-east-1", is_global=False):
    return Ctx(AwsCli("t", executor=fake, aws_bin="aws", sleep=lambda s: None), ACCT, region, is_global=is_global)


def deny(code="AccessDenied"):
    def h(region, args):
        raise FakeError(code, "nope")
    return h


def mk(rtype, rid, *, region="us-east-1", tags=None, state="", name=None, created=None, metrics=None, **attrs):
    return Resource(key=make_key(ACCT, region, rtype, rid), rid=rid, type=rtype, service=rtype.split(":")[0], account=ACCT, region=region,
                    name=name or rid, state=state, created=created, tags=tags or {}, attrs=attrs, metrics=metrics or {})


def run(resources, gaps=()):
    scan = {"resources": [asdict(r) for r in resources], "gaps": list(gaps), "options": {}, "audit": [],
            "accounts": [{"account": ACCT, "profile": "t", "arn": "arn:aws:iam::1:user/x", "regions": ["us-east-1"]}]}
    return analyze(scan, load_config(), now=NOW)


def gap(service, op, region="us-east-1"):
    return {"account": ACCT, "region": region, "service": service, "op": op, "code": "AccessDenied", "message": "x", "count": 1}


def rules(res):
    return {f["rule"] for f in res["findings"]}


class TestFailedIsNotEmpty(unittest.TestCase):
    def test_failed_call_is_distinguishable_but_behaves_like_empty(self):
        ctx = ctx_for(FakeAws({("ec2", "describe-volumes"): deny("UnauthorizedOperation")}))
        out = ctx.aws("ec2", "describe-volumes")
        self.assertIsInstance(out, Failed)
        self.assertEqual(out.get("Volumes", []), [])
        self.assertEqual(len(ctx.gaps), 1)

    def test_expected_error_is_a_plain_empty_not_failed(self):
        ctx = ctx_for(FakeAws({("s3api", "get-bucket-tagging"): deny("NoSuchTagSet")}))
        out = ctx.aws("s3api", "get-bucket-tagging", ["--bucket", "b"], expect=["NoSuchTagSet"], default={})
        self.assertNotIsInstance(out, Failed)
        self.assertEqual(ctx.gaps, [])

    def test_s3_unreadable_config_is_unknown_not_missing(self):
        f = FakeAws()
        f.set("s3api", "list-buckets", {"Buckets": [{"Name": "b1", "CreationDate": ago(400)}]})
        f.set("s3api", "get-bucket-location", deny())
        for op in ("get-bucket-tagging", "get-bucket-lifecycle-configuration", "get-bucket-versioning", "get-public-access-block"):
            f.set("s3api", op, deny())
        b = s3.collect(ctx_for(f, is_global=True))[0]
        for key in ("lifecycle_rules", "versioning", "public_access_blocked", "lc_noncurrent_expiration"):
            self.assertIsNone(b.attrs[key], key)
        self.assertFalse(b.attrs["region_known"])
        res = run([b])
        self.assertFalse({"sec.s3.public-access", "s3.bucket.no-lifecycle", "s3.bucket.versioning-no-expiry", "s3.bucket.empty"} & rules(res))

    def test_metrics_for_buckets_with_unknown_region_are_not_requested(self):
        b = mk("s3:bucket", "b1", region="us-east-1", created=ago(400), region_known=False)
        self.assertEqual(metrics._plan([b], 14), {})


class TestGapAwareRules(unittest.TestCase):
    """If the call that lists the 'other side' failed, 'missing' must not be concluded."""

    def test_nat_without_route_tables_listing(self):
        nat = mk("ec2:nat-gateway", "nat-1", state="available", route_table_refs=0, vpc="vpc-1")
        self.assertIn("ec2.nat.no-routes", rules(run([nat])))
        self.assertNotIn("ec2.nat.no-routes", rules(run([nat], [gap("ec2", "describe-route-tables")])))

    def test_snapshot_rules_need_images_and_volumes(self):
        snaps = [mk("ec2:snapshot", "snap-ami", size_gb=8, created=ago(400), ami_id="ami-1", volume_id=None),
                 mk("ec2:snapshot", "snap-vol", size_gb=8, created=ago(400), volume_id="vol-gone")]
        self.assertEqual({"ec2.snapshot.orphaned-ami", "ec2.snapshot.orphaned-volume"}, rules(run(snaps)) & {"ec2.snapshot.orphaned-ami", "ec2.snapshot.orphaned-volume"})
        no_images = rules(run(snaps, [gap("ec2", "describe-images")]))
        self.assertFalse({"ec2.snapshot.orphaned-ami", "ec2.snapshot.orphaned-volume"} & no_images)
        no_volumes = rules(run(snaps, [gap("ec2", "describe-volumes")]))
        self.assertIn("ec2.snapshot.orphaned-ami", no_volumes)
        self.assertNotIn("ec2.snapshot.orphaned-volume", no_volumes)

    def test_gap_in_another_region_does_not_suppress(self):
        nat = mk("ec2:nat-gateway", "nat-1", state="available", route_table_refs=0, vpc="vpc-1")
        self.assertIn("ec2.nat.no-routes", rules(run([nat], [gap("ec2", "describe-route-tables", region="eu-west-1")])))

    def test_unused_security_group_and_empty_vpc_need_eni_listing(self):
        res = [mk("ec2:security-group", "sg-1", group_name="old", vpc="vpc-1", world_open=[], referenced_by=[]), mk("ec2:vpc", "vpc-1", is_default=False, cidr="10.0.0.0/16")]
        self.assertTrue({"ec2.sg.unused", "net.vpc.empty"} <= rules(run(res)))
        self.assertFalse({"ec2.sg.unused", "net.vpc.empty"} & rules(run(res, [gap("ec2", "describe-network-interfaces")])))

    def test_load_balancer_without_target_listing(self):
        lb = mk("elbv2:lb", "web", state="active", lb_type="application", az_count=2)
        self.assertIn("elb.lb.no-targets", rules(run([lb])))
        res = run([lb], [gap("elbv2", "describe-target-groups")])
        self.assertNotIn("elb.lb.no-targets", rules(res))

    def test_orphaned_rds_snapshot_needs_instance_listing_and_same_region_source(self):
        s = mk("rds:snapshot", "snap", created=ago(100), source="gone-db", size_gb=10, source_region=None)
        self.assertIn("rds.snapshot.orphaned", rules(run([s])))
        self.assertNotIn("rds.snapshot.orphaned", rules(run([s], [gap("rds", "describe-db-instances")])))
        copy = mk("rds:snapshot", "copy", created=ago(100), source="db-in-other-region", size_gb=10, source_region="eu-west-1")
        self.assertNotIn("rds.snapshot.orphaned", rules(run([copy])))

    def test_iam_conclusions_need_key_and_role_data(self):
        user = mk("iam:user", "bob", region="global", created=ago(500), password_last_used=None,
                  access_keys=[{"id": "AKIA…ABCD", "status": "Active", "created": ago(400), "last_used": None}])
        role = mk("iam:role", "r", region="global", created=ago(500), last_used=None, path="/")
        self.assertTrue({"sec.iam.key-unused", "sec.iam.role-unused"} <= rules(run([user, role])))
        blind = rules(run([user, role], [gap("iam", "list-access-keys", "global"), gap("iam", "get-role", "global")]))
        self.assertFalse({"sec.iam.key-unused", "sec.iam.key-old", "sec.iam.user-inactive", "sec.iam.role-unused"} & blind)

    def test_sqs_sns_idle_need_their_inventory_calls(self):
        q = mk("sqs:queue", "q", messages=0, messages_in_flight=0, metrics={"sent": 0.0, "_days": {"sent": 30}})
        t = mk("sns:topic", "t", subscriptions=0, metrics={"published": 0.0, "_days": {"published": 30}})
        self.assertTrue({"sqs.idle", "sns.idle"} <= rules(run([q, t])))
        self.assertFalse({"sqs.idle", "sns.idle"} & rules(run([q, t], [gap("sqs", "get-queue-attributes"), gap("sns", "list-subscriptions")])))

    def test_dangling_dns_needs_the_target_inventory(self):
        zone = mk("route53:hosted-zone", "Z1", region="global", name="example.com", record_count=5, records=[
            {"name": "old.example.com", "type": "CNAME", "target": "dgone.cloudfront.net"},
            {"name": "lb.example.com", "type": "ALIAS", "target": "x-1.us-east-1.elb.amazonaws.com"},
            {"name": "promo.example.com", "type": "CNAME", "target": "nobucket.s3-website-us-east-1.amazonaws.com"}])
        self.assertIn("sec.r53.dangling", rules(run([zone])))
        blind = [gap("cloudfront", "list-distributions", "global"), gap("elbv2", "describe-load-balancers"), gap("s3api", "list-buckets", "global")]
        self.assertNotIn("sec.r53.dangling", rules(run([zone], blind)))


class TestEc2Fixes(unittest.TestCase):
    def test_describe_images_includes_disabled_amis(self):
        f = FakeAws({("ec2", "describe-images"): {"Images": [{"ImageId": "ami-1", "State": "disabled"}]}})
        res = ec2_net.collect(ctx_for(f))
        self.assertIn("--include-disabled", next(c for c in f.calls if c[1] == "describe-images")[3])
        self.assertEqual(next(r for r in res if r.type == "ec2:ami").state, "disabled")

    def test_dead_vpc_endpoints_are_skipped(self):
        f = FakeAws({("ec2", "describe-vpc-endpoints"): {"VpcEndpoints": [
            {"VpcEndpointId": f"vpce-{s}", "State": s, "VpcEndpointType": "Interface", "ServiceName": "x.y.ssm"}
            for s in ("Available", "Deleted", "Deleting", "Rejected", "Expired", "Failed")]}})
        got = {r.rid for r in ec2_net.collect(ctx_for(f)) if r.type == "ec2:vpc-endpoint"}
        self.assertEqual(got, {"vpce-Available", "vpce-Failed"})

    def test_nat_records_availability_mode_and_regional_nats_get_no_metrics(self):
        f = FakeAws({("ec2", "describe-nat-gateways"): {"NatGateways": [
            {"NatGatewayId": "nat-z", "State": "available", "AvailabilityMode": "zonal"},
            {"NatGatewayId": "nat-r", "State": "available", "AvailabilityMode": "regional"},
            {"NatGatewayId": "nat-old", "State": "available"}]}})
        nats = {r.rid: r for r in ec2_net.collect(ctx_for(f)) if r.type == "ec2:nat-gateway"}
        self.assertEqual({k: v.attrs["availability_mode"] for k, v in nats.items()}, {"nat-z": "zonal", "nat-r": "regional", "nat-old": "zonal"})
        plan = metrics._plan(list(nats.values()), 14)
        self.assertEqual({r.rid for items in plan.values() for r, _s, _d in items}, {"nat-z", "nat-old"})


class TestRdsFixes(unittest.TestCase):
    def collect(self):
        f = FakeAws()
        f.set("rds", "describe-db-instances", {"DBInstances": [
            {"DBInstanceIdentifier": "pg", "Engine": "postgres", "AllocatedStorage": 100, "DBInstanceStatus": "available"},
            {"DBInstanceIdentifier": "aur-1", "Engine": "aurora-postgresql", "AllocatedStorage": 1, "DBInstanceStatus": "available"},
            {"DBInstanceIdentifier": "nep-1", "Engine": "neptune", "AllocatedStorage": 1, "DBInstanceStatus": "available"},
            {"DBInstanceIdentifier": "doc-1", "Engine": "docdb", "AllocatedStorage": 1, "DBInstanceStatus": "available"}]})
        f.set("rds", "describe-db-clusters", {"DBClusters": [
            {"DBClusterIdentifier": "aur", "Engine": "aurora-postgresql", "AllocatedStorage": 1}, {"DBClusterIdentifier": "doc", "Engine": "docdb"}]})
        f.set("rds", "describe-db-snapshots", {"DBSnapshots": [
            {"DBSnapshotIdentifier": "local", "DBInstanceIdentifier": "pg", "Engine": "postgres", "AllocatedStorage": 100},
            {"DBSnapshotIdentifier": "copy", "DBInstanceIdentifier": "pg", "Engine": "postgres", "AllocatedStorage": 100, "SourceRegion": "eu-west-1"},
            {"DBSnapshotIdentifier": "neptune-snap", "DBInstanceIdentifier": "nep-1", "Engine": "neptune"}]})
        return {r.rid: r for r in rds.collect(ctx_for(f))}

    def test_neptune_and_docdb_are_not_rds(self):
        got = self.collect()
        self.assertEqual(got["pg"].type, "rds:instance")
        self.assertEqual((got["nep-1"].type, got["doc-1"].type, got["doc"].type), ("neptune:instance", "docdb:instance", "docdb:cluster"))
        self.assertNotIn("neptune-snap", got)

    def test_aurora_storage_is_not_the_placeholder(self):
        got = self.collect()
        self.assertEqual(got["pg"].attrs["storage_gb"], 100)
        self.assertIsNone(got["aur-1"].attrs["storage_gb"])
        self.assertIsNone(got["aur"].attrs["storage_gb"])

    def test_cross_region_copy_keeps_source_region_and_no_local_link(self):
        got = self.collect()
        self.assertEqual(got["copy"].attrs["source_region"], "eu-west-1")
        self.assertEqual(got["copy"].relations, [])
        self.assertTrue(got["local"].relations)


class TestOtherCollectorFixes(unittest.TestCase):
    def test_websocket_apis_are_not_http_apis(self):
        f = FakeAws({("apigatewayv2", "get-apis"): {"Items": [{"ApiId": "h", "ProtocolType": "HTTP"}, {"ApiId": "w", "ProtocolType": "WEBSOCKET"}]}})
        got = {r.rid: r.type for r in serverless.collect(ctx_for(f)) if r.type.startswith("apigw")}
        self.assertEqual(got, {"h": "apigw:http-api", "w": "apigw:websocket-api"})
        self.assertNotIn("apigw:websocket-api", metrics.SPECS)

    def test_eks_version_status_and_auto_mode(self):
        f = FakeAws()
        f.set("eks", "list-clusters", {"clusters": ["a", "b"]})
        f.set("eks", "describe-cluster-versions", {"clusterVersions": [
            {"clusterVersion": "1.29", "versionStatus": "EXTENDED_SUPPORT", "status": "extended-support"},
            {"clusterVersion": "1.28", "status": "extended-support"}, {"clusterVersion": "1.33", "versionStatus": "STANDARD_SUPPORT"}]})
        f.set("eks", "describe-cluster", lambda reg, a: {"cluster": {"name": arg_value(a, "--name"), "version": "1.29" if arg_value(a, "--name") == "a" else "1.28",
                                                                    "status": "ACTIVE", "computeConfig": {"enabled": arg_value(a, "--name") == "b"}}})
        got = {r.rid: r for r in containers.collect(ctx_for(f)) if r.type == "eks:cluster"}
        self.assertEqual(got["a"].attrs["version_status"], "EXTENDED_SUPPORT")
        self.assertEqual(got["b"].attrs["version_status"], "EXTENDED_SUPPORT")     # falls back to the deprecated `status`, normalised
        self.assertEqual((got["a"].attrs["auto_mode"], got["b"].attrs["auto_mode"]), (False, True))
        res = run(list(got.values()))
        no_compute = {f["resources"][0].split(":")[-1] for f in res["findings"] if f["rule"] == "eks.cluster.no-compute"}
        self.assertEqual(no_compute, {"a"}, "an Auto Mode cluster has no node groups by design")

    def test_route53_octal_escapes_are_decoded(self):
        self.assertEqual(edge.dns_name("\\052.example.com."), "*.example.com")
        self.assertEqual(edge.dns_name("ex\\344mple.com."), "exämple.com")
        self.assertEqual(edge.dns_name("plain.example.com."), "plain.example.com")
        f = FakeAws()
        f.set("route53", "list-hosted-zones", {"HostedZones": [{"Id": "/hostedzone/Z1", "Name": "ex\\344mple.com."}]})
        f.set("route53", "list-resource-record-sets", {"ResourceRecordSets": [{"Name": "\\052.ex\\344mple.com.", "Type": "A", "ResourceRecords": [{"Value": "1.2.3.4"}]}]})
        z = next(r for r in edge.collect(ctx_for(f, is_global=True)) if r.type == "route53:hosted-zone")
        self.assertEqual((z.name, z.attrs["records"][0]["name"]), ("exämple.com", "*.exämple.com"))

    def test_iam_does_not_claim_console_access(self):
        f = FakeAws({("iam", "list-users"): {"Users": [{"UserName": "u", "CreateDate": ago(10)}]}})
        u = next(r for r in iam.collect(ctx_for(f, is_global=True)) if r.type == "iam:user")
        self.assertNotIn("console_access", u.attrs)

    def test_tagging_api_gateway_arns(self):
        f = FakeAws({("resourcegroupstaggingapi", "get-resources"): {"ResourceTagMappingList": [
            {"ResourceARN": "arn:aws:apigateway:us-east-1::/restapis/abc/stages/prod", "Tags": []},
            {"ResourceARN": "arn:aws:apigateway:us-east-1::/apikeys/k1", "Tags": []}]}})
        got = {r.type: r.rid for r in tagging.collect(ctx_for(f))}
        self.assertEqual(got, {"other:apigateway:restapis": "abc/stages/prod", "other:apigateway:apikeys": "k1"})


class TestTaggingRegionHandling(unittest.TestCase):
    def test_global_tags_are_read_from_us_east_1_even_when_it_is_not_scanned(self):
        f = FakeAws()
        f.set("sts", "get-caller-identity", {"Account": ACCT, "Arn": f"arn:aws:iam::{ACCT}:user/x"})
        f.set("cloudfront", "list-distributions", {"DistributionList": {"Items": [{"Id": "E1", "ARN": f"arn:aws:cloudfront::{ACCT}:distribution/E1", "DomainName": "d.cloudfront.net", "Enabled": True}]}})

        def tagging_api(region, args):
            if region == "us-east-1":
                return {"ResourceTagMappingList": [
                    {"ResourceARN": f"arn:aws:cloudfront::{ACCT}:distribution/E1", "Tags": [{"Key": "Project", "Value": "shop"}]},
                    {"ResourceARN": f"arn:aws:sqs:us-east-1:{ACCT}:left-out-region-queue", "Tags": []}]}
            return {"ResourceTagMappingList": [{"ResourceARN": f"arn:aws:sqs:eu-west-1:{ACCT}:wanted", "Tags": []}]}
        f.set("resourcegroupstaggingapi", "get-resources", tagging_api)
        cli = AwsCli("t", executor=f, aws_bin="aws", sleep=lambda s: None)
        scan = run_scan(["t"], ScanOptions(quiet=True, regions=["eu-west-1"], metrics=False, services=["edge"]), cli=cli)
        by_id = {r["rid"]: r for r in scan["resources"]}
        self.assertEqual(by_id["E1"]["tags"], {"Project": "shop"})                      # global tags merged
        self.assertIn("wanted", by_id)                                                  # scanned region kept
        self.assertNotIn("left-out-region-queue", by_id)                                # excluded region's long tail dropped

    def test_merge_tagging_region_filter(self):
        keep = mk("other:sqs:queue", "q1", region="eu-west-1", arn="arn:1")
        drop = mk("other:sqs:queue", "q2", region="us-east-1", arn="arn:2")
        glob = mk("other:iam:user", "u", region="global", arn="arn:3")
        for r in (keep, drop, glob):
            r.attrs["from_tagging"] = True
        self.assertEqual({r.rid for r in merge_tagging([keep, drop, glob], ["eu-west-1"])}, {"q1", "u"})
        self.assertEqual(len(merge_tagging([keep, drop, glob])), 3)


class TestMetricsFixes(unittest.TestCase):
    def run_metrics(self, resources, handler):
        f = FakeAws({("cloudwatch", "get-metric-data"): handler})
        cli = AwsCli("t", executor=f, aws_bin="aws", sleep=lambda s: None)
        gaps = []
        metrics.collect_metrics(cli, ACCT, "aws", resources, ["us-east-1"], ScanOptions(quiet=True), gaps, threading.Lock())
        return f, gaps

    def test_all_queries_of_one_bucket_stay_in_one_call(self):
        buckets = [mk("s3:bucket", f"b{i}", created=ago(400), region_known=True) for i in range(60)]
        seen = []

        def handler(region, args):
            qs = json.loads(arg_value(args, "--metric-data-queries"))
            seen.append({q["MetricStat"]["Metric"]["Dimensions"][0]["Value"] for q in qs})
            return {"MetricDataResults": [{"Id": q["Id"], "Timestamps": [], "Values": [], "StatusCode": "Complete"} for q in qs]}
        self.run_metrics(buckets, handler)
        self.assertGreater(len(seen), 1, "60 buckets x 14 queries must not fit in one call")
        names = [n for batch in seen for n in batch]
        self.assertEqual(len(names), len(set(names)), "a bucket's queries were split across API calls")

    def test_paged_results_are_merged_and_only_complete_series_are_trusted(self):
        a = mk("ec2:instance", "i-a", state="running")
        b = mk("ec2:instance", "i-b", state="running")
        c = mk("ec2:instance", "i-c", state="running")

        def handler(region, args):
            qs = json.loads(arg_value(args, "--metric-data-queries"))
            ids = {q["Id"]: q["MetricStat"]["Metric"]["Dimensions"][0]["Value"] for q in qs}
            out = []
            for qid, inst in ids.items():
                if inst == "i-a":           # same Id on two pages: values must be combined, not overwritten
                    out += [{"Id": qid, "Timestamps": ["t1"], "Values": [10.0], "StatusCode": "PartialData"},
                            {"Id": qid, "Timestamps": ["t2"], "Values": [30.0], "StatusCode": "Complete"}]
                elif inst == "i-b":         # AWS could not produce the data
                    out.append({"Id": qid, "Timestamps": [], "Values": [], "StatusCode": "InternalError"})
                # i-c: the Id is missing from the response entirely
            return {"MetricDataResults": out}
        self.run_metrics([a, b, c], handler)
        self.assertEqual(a.metrics["cpu_avg"], 20.0)
        self.assertEqual(a.metrics["cpu_max"], 30.0)
        self.assertNotIn("cpu_avg", b.metrics)
        self.assertNotIn("cpu_avg", c.metrics)

    def test_more_s3_storage_classes_and_apigw_name_normalisation(self):
        classes = {s.metric if s.metric != "BucketSizeBytes" else s.dims(mk("s3:bucket", "x"))[1][1] for s in metrics.SPECS["s3:bucket"]}
        for needed in ("IntelligentTieringAIAStorage", "IntelligentTieringAAStorage", "IntelligentTieringDAAStorage", "ReducedRedundancyStorage"):
            self.assertIn(needed, classes)
        from analyzer.analysis import cost
        for k in ("it_aia", "it_aa", "it_daa", "reduced_redundancy"):
            self.assertIn(k, cost.load_pricing()["s3_gb_month"])
        self.assertEqual(metrics._apigw_name(mk("apigw:rest-api", "id1", api_name="Café API")), "Caf API")
        self.assertEqual(metrics._apigw_name(mk("apigw:rest-api", "id2", api_name="日本語")), "id2")


if __name__ == "__main__":
    unittest.main()
