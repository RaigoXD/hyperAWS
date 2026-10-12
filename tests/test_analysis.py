"""Cost estimates, waste rules, grouping and link resolution on hand-built resources."""

import tempfile
import textwrap
import unittest
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from analyzer.analysis import cost, grouping
from analyzer.analysis.config import load_config
from analyzer.analysis.engine import analyze
from analyzer.model import Resource, make_key

ACCT = "111122223333"
NOW = datetime(2026, 10, 1, tzinfo=timezone.utc)


def ago(days):
    return (NOW - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


def mk(rtype, rid, *, region="us-east-1", tags=None, state="", name=None, created=None, metrics=None, rel=(), **attrs):
    r = Resource(key=make_key(ACCT, region, rtype, rid), rid=rid, type=rtype, service=rtype.split(":")[0], account=ACCT,
                 region=region, name=name or rid, state=state, created=created, tags=tags or {}, attrs=attrs, metrics=metrics or {})
    for kind, to in rel:
        r.link(to, kind)
    return r


def run(resources, cfg=None):
    scan = {"resources": [asdict(r) for r in resources], "accounts": [{"account": ACCT, "profile": "t", "arn": "arn:aws:iam::1:user/x", "regions": ["us-east-1"]}],
            "options": {}, "gaps": [], "audit": []}
    return analyze(scan, cfg or load_config(), now=NOW)


def rules(result):
    return {f["rule"] for f in result["findings"]}


def finding(result, rule):
    return next(f for f in result["findings"] if f["rule"] == rule)


def metrics(**kw):
    return {**kw, "_days": {k: 14 for k in kw}}


class TestCost(unittest.TestCase):
    def est(self, r):
        return cost.estimate(r)

    def test_ec2(self):
        self.assertAlmostEqual(self.est(mk("ec2:instance", "i-1", state="running", instance_type="m5.large"))[0], 0.096 * 730, places=2)
        self.assertAlmostEqual(self.est(mk("ec2:instance", "i-1", state="running", instance_type="m5.2xlarge"))[0], 0.096 * 4 * 730, places=2)
        self.assertAlmostEqual(self.est(mk("ec2:instance", "i-1", region="eu-west-1", state="running", instance_type="m5.large"))[0], 0.096 * 730 * 1.11, places=2)
        self.assertEqual(self.est(mk("ec2:instance", "i-1", state="stopped", instance_type="m5.large"))[0], 0)
        usd, basis, conf = self.est(mk("ec2:instance", "i-1", state="running", instance_type="p3.2xlarge"))
        self.assertEqual((usd, conf), (0.0, "none"))
        self.assertIn("no reference price", basis)
        spot = self.est(mk("ec2:instance", "i-1", state="running", instance_type="m5.large", lifecycle="spot"))[0]
        self.assertAlmostEqual(spot, 0.096 * 730 * 0.35, places=2)

    def test_ebs_and_fixed_prices(self):
        self.assertAlmostEqual(self.est(mk("ec2:volume", "v", size_gb=100, vol_type="gp3"))[0], 8.0)
        self.assertAlmostEqual(self.est(mk("ec2:volume", "v", size_gb=100, vol_type="gp2"))[0], 10.0)
        self.assertAlmostEqual(self.est(mk("ec2:volume", "v", size_gb=100, vol_type="gp3", iops=4000, throughput=250))[0], 8 + 5 + 5)
        self.assertAlmostEqual(self.est(mk("ec2:eip", "e"))[0], 3.65)
        nat = self.est(mk("ec2:nat-gateway", "n", state="available"))
        self.assertAlmostEqual(nat[0], 32.85)
        # data processing is billed on client->NAT bytes plus the return traffic, counted once each
        with_data = self.est(mk("ec2:nat-gateway", "n", state="available", metrics=metrics(bytes_in=60e9, bytes_return=40e9)))
        self.assertAlmostEqual(with_data[0], 32.85 + 100 * (30 / 14) * 0.045, places=1)

    def test_rds_eks_and_unknowns(self):
        db = mk("rds:instance", "d", state="available", instance_class="db.m5.large", engine="postgres", storage_gb=100, storage_type="gp2", multi_az=True)
        self.assertAlmostEqual(self.est(db)[0], (0.171 * 730 + 100 * 0.115) * 2, places=1)
        stopped = mk("rds:instance", "d", state="stopped", instance_class="db.m5.large", engine="postgres", storage_gb=100, storage_type="gp2")
        self.assertAlmostEqual(self.est(stopped)[0], 11.5, places=2)
        self.assertAlmostEqual(self.est(mk("eks:cluster", "c", version_status="STANDARD_SUPPORT"))[0], 73.0)
        self.assertAlmostEqual(self.est(mk("eks:cluster", "c", version_status="EXTENDED_SUPPORT"))[0], 438.0)
        self.assertEqual(self.est(mk("lambda:function", "f"))[2], "none")

    def test_fargate(self):
        s = mk("ecs:service", "s", launch_type="FARGATE", task_cpu=1024, task_memory=4096, running=2, task_arch="X86_64")
        self.assertAlmostEqual(self.est(s)[0], 2 * (1 * 0.04048 + 4 * 0.004445) * 730, places=2)


class TestRules(unittest.TestCase):
    def test_unassociated_eip_and_young_volume(self):
        res = run([mk("ec2:eip", "e1", state="unassociated", public_ip="1.1.1.1"), mk("ec2:eip", "e2", state="associated", public_ip="2.2.2.2"),
                   mk("ec2:volume", "v-old", state="available", size_gb=100, vol_type="gp3", created=ago(30)),
                   mk("ec2:volume", "v-new", state="available", size_gb=100, vol_type="gp3", created=ago(1))])
        f = [x for x in res["findings"] if x["rule"] == "ec2.eip.unassociated"]
        self.assertEqual(len(f), 1)
        self.assertAlmostEqual(f[0]["savings_usd"], 3.65)
        v = [x for x in res["findings"] if x["rule"] == "ec2.volume.unattached"]
        self.assertEqual(len(v), 1, "a volume younger than the threshold must not be flagged")
        self.assertIn("v-old", v[0]["resources"][0])

    def test_stopped_instance_threshold_and_volume_savings(self):
        vol = mk("ec2:volume", "v1", state="in-use", size_gb=500, vol_type="gp2")
        old = mk("ec2:instance", "i-old", state="stopped", instance_type="m5.large", stopped_at=ago(60), volume_ids=["v1"])
        recent = mk("ec2:instance", "i-recent", state="stopped", instance_type="m5.large", stopped_at=ago(3), volume_ids=[])
        res = run([vol, old, recent])
        fs = [x for x in res["findings"] if x["rule"] == "ec2.instance.stopped"]
        self.assertEqual(len(fs), 1)
        self.assertAlmostEqual(fs[0]["savings_usd"], 50.0)   # 500 GB gp2

    def test_idle_vs_oversized_vs_busy(self):
        res = run([
            mk("ec2:instance", "i-idle", state="running", instance_type="m5.xlarge", metrics=metrics(cpu_avg=1.0, cpu_max=6.0)),
            mk("ec2:instance", "i-big", state="running", instance_type="m5.xlarge", metrics=metrics(cpu_avg=10.0, cpu_max=30.0)),
            mk("ec2:instance", "i-busy", state="running", instance_type="m5.xlarge", metrics=metrics(cpu_avg=55.0, cpu_max=95.0)),
            mk("ec2:instance", "i-unknown", state="running", instance_type="m5.xlarge"),          # no metrics => no claim
            mk("ec2:instance", "i-tiny", state="running", instance_type="t3.micro", metrics=metrics(cpu_avg=10.0, cpu_max=30.0))])
        by_rule = {}
        for f in res["findings"]:
            by_rule.setdefault(f["rule"], []).append(f["resources"][0].split(":")[-1])
        self.assertEqual(by_rule.get("ec2.instance.idle"), ["i-idle"])
        self.assertEqual(by_rule.get("ec2.instance.oversized"), ["i-big"])

    def test_snapshots_and_amis(self):
        ami = mk("ec2:ami", "ami-keep", created=ago(10), snapshot_ids=["snap-in-ami"])
        res = run([
            ami,
            mk("ec2:snapshot", "snap-in-ami", size_gb=8, created=ago(400), ami_id="ami-keep", volume_id=None),
            mk("ec2:snapshot", "snap-dead-ami", size_gb=8, created=ago(400), ami_id="ami-gone", volume_id=None),
            mk("ec2:snapshot", "snap-no-vol", size_gb=50, created=ago(400), volume_id="vol-missing"),
            mk("ec2:snapshot", "snap-young", size_gb=50, created=ago(5), volume_id="vol-missing"),
            mk("ec2:snapshot", "snap-managed", size_gb=50, created=ago(400), volume_id="vol-missing", tags={"dlm:managed": "true"})])
        got = {f["rule"]: f["resources"][0].split(":")[-1] for f in res["findings"] if f["rule"].startswith("ec2.snapshot")}
        self.assertEqual(got, {"ec2.snapshot.orphaned-ami": "snap-dead-ami", "ec2.snapshot.orphaned-volume": "snap-no-vol"})

    def test_nat_lb_and_world_open_sg(self):
        nat_key = make_key(ACCT, "us-east-1", "ec2:nat-gateway", "nat-1")
        lb = mk("elbv2:lb", "web", state="active", lb_type="application", az_count=2)
        tg = mk("elbv2:target-group", "web-tg", targets_total=0, lb_arns=["x"], rel=[("behind", lb.key)])
        res = run([
            mk("ec2:nat-gateway", "nat-1", state="available", route_table_refs=0, vpc="vpc-1"),
            mk("ec2:nat-gateway", "nat-2", state="available", route_table_refs=2, vpc="vpc-1", metrics=metrics(bytes_in=10.0, bytes_return=10.0)),
            lb, tg,
            mk("ec2:instance", "i-1", state="running", instance_type="t3.micro", sg_ids=["sg-open"]),
            mk("ec2:security-group", "sg-open", group_name="web", vpc="vpc-1", world_open=[["tcp", 22, 22], ["tcp", 443, 443]], referenced_by=[]),
            mk("ec2:security-group", "sg-unused", group_name="old", vpc="vpc-1", world_open=[], referenced_by=[])])
        r = rules(res)
        self.assertIn("ec2.nat.no-routes", r)
        self.assertIn("ec2.nat.idle", r)
        self.assertIn("elb.lb.no-targets", r)
        self.assertIn("ec2.sg.unused", r)
        sg = finding(res, "sec.sg.world-open")
        self.assertEqual(sg["severity"], "high")
        self.assertIn("SSH (22)", sg["detail"])
        self.assertNotIn("443", sg["detail"].split("on:")[1])
        self.assertEqual(finding(res, "ec2.nat.no-routes")["resources"], [nat_key])

    def test_eks_extended_support_and_lambda_runtime(self):
        res = run([mk("eks:cluster", "c", version="1.29", version_status="EXTENDED_SUPPORT", nodegroups=1, desired_nodes=3),
                   mk("lambda:function", "old-fn", runtime="python3.8", arch="x86_64", package_type="Zip", metrics=metrics(invocations=10.0)),
                   mk("lambda:function", "new-fn", runtime="python3.12", arch="x86_64", package_type="Zip", metrics=metrics(invocations=10.0))])
        self.assertAlmostEqual(finding(res, "eks.extended-support")["savings_usd"], 365.0)
        dep = finding(res, "lambda.runtime.deprecated")
        self.assertEqual([k.split(":")[-1] for k in dep["resources"]], ["old-fn"])

    def test_s3_lifecycle_and_public_access(self):
        res = run([mk("s3:bucket", "big", region="us-east-1", created=ago(300), lifecycle_rules=0, versioning="Enabled", lc_noncurrent_expiration=False,
                      public_access_blocked=False, metrics={"bytes_standard": 500e9, "objects": 1e6}),
                   mk("s3:bucket", "ok", region="us-east-1", created=ago(300), lifecycle_rules=2, versioning="Unversioned", lc_noncurrent_expiration=False,
                      public_access_blocked=True, metrics={"bytes_standard": 500e9, "objects": 1e6})])
        got = {(f["rule"], f["resources"][0].split(":")[-1]) for f in res["findings"]}
        self.assertEqual(got, {("s3.bucket.no-lifecycle", "big"), ("s3.bucket.versioning-no-expiry", "big"), ("sec.s3.public-access", "big")})

    def test_dynamodb_overprovisioned_and_idle(self):
        res = run([mk("dynamodb:table", "hot", billing_mode="PROVISIONED", rcu=200, wcu=100, gsi_rcu=0, gsi_wcu=0, size_bytes=0, metrics={"read_units": 2e6, "write_units": 9e5, "_days": {"read_units": 30, "write_units": 30}}),
                   mk("dynamodb:table", "dead", billing_mode="PROVISIONED", rcu=5, wcu=5, gsi_rcu=0, gsi_wcu=0, size_bytes=0, metrics={"read_units": 0.0, "write_units": 0.0, "_days": {"read_units": 30, "write_units": 30}})])
        got = {f["rule"]: f["resources"][0].split(":")[-1] for f in res["findings"]}
        self.assertEqual(got, {"ddb.table.overprovisioned": "hot", "ddb.table.idle": "dead"})
        self.assertGreater(finding(res, "ddb.table.overprovisioned")["savings_usd"], 50)

    def test_root_credentials_finding(self):
        scan = {"resources": [], "accounts": [{"account": ACCT, "profile": "default", "arn": f"arn:aws:iam::{ACCT}:root", "regions": []}], "options": {}, "gaps": [], "audit": []}
        res = analyze(scan, load_config(), now=NOW)
        self.assertEqual([f["rule"] for f in res["findings"]], ["sec.iam.root-credentials-used"])
        self.assertEqual(res["findings"][0]["severity"], "high")

    def test_headline_total_never_double_counts(self):
        inst = mk("ec2:instance", "i-1", state="running", instance_type="m5.xlarge", arch="x86_64", tags={"Environment": "dev"},
                  metrics=metrics(cpu_avg=1.0, cpu_max=5.0), volume_ids=[])
        res = run([inst, mk("ec2:instance", "i-2", state="running", instance_type="m5.xlarge", arch="x86_64", tags={"Environment": "dev"},
                            metrics=metrics(cpu_avg=40.0, cpu_max=70.0))])
        total = res["summary"]["potential_savings_usd"]
        counted = sum(f["savings_usd"] for f in res["findings"] if f["in_total"])
        self.assertLess(total, counted, "idle + schedule + graviton on the same instance must not all add up")
        idle = finding(res, "ec2.instance.idle")
        biggest_i1 = max(f["breakdown"].get(inst.key, 0) for f in res["findings"] if f["in_total"])
        self.assertAlmostEqual(biggest_i1, idle["savings_usd"], places=1)   # the largest single saving wins
        self.assertLessEqual(res["summary"]["potential_savings_confident_usd"], total)


class TestGrouping(unittest.TestCase):
    def assign(self, rs, cfg=None):
        cfg = cfg or load_config()
        grouping.assign(rs, cfg)
        return {r.rid: (r.project, r.project_source, r.env) for r in rs}

    def test_tag_beats_name_and_case_is_merged(self):
        got = self.assign([mk("ec2:instance", "i-1", name="legacy-web-1", tags={"Project": "Shop"}),
                           mk("ec2:instance", "i-2", name="x", tags={"project": "shop"}), mk("ec2:instance", "i-3", name="y", tags={"Project": "shop"})])
        self.assertEqual({v[0] for v in got.values()}, {"shop"})
        self.assertTrue(all(v[1].startswith("tag:") for v in got.values()))

    def test_tag_keys_match_case_insensitively(self):
        got = self.assign([mk("ec2:instance", "i-1", tags={"PROJECT": "shop"}), mk("ec2:instance", "i-2", tags={"application": "ledger"})])
        self.assertEqual(got["i-1"][:2], ("shop", "tag:PROJECT"))
        self.assertEqual(got["i-2"][:2], ("ledger", "tag:application"))

    def test_console_generated_stack_names_are_cleaned(self):
        self.assertEqual(grouping.clean_stack_name("Infra-ECS-Cluster-vtn-front-test-c7fac607"), "vtn-front-test")
        self.assertEqual(grouping.clean_stack_name("shop-api-prod"), "shop-api-prod")
        got = self.assign([mk("ecs:cluster", "c", tags={"aws:cloudformation:stack-name": "Infra-ECS-Cluster-vtn-front-test-c7fac607"})])
        self.assertEqual(got["c"][:2], ("vtn-front-test", "stack"))

    def test_rules_win_and_validate(self):
        cfg = load_config()
        cfg["rules"] = [{"project": "billing", "env": "prod", "match": {"name_prefix": ["bil-"], "services": ["ec2"]}}]
        got = self.assign([mk("ec2:instance", "i-1", name="bil-api", tags={"Project": "other"}), mk("rds:instance", "bil-db", name="bil-db")], cfg)
        self.assertEqual(got["i-1"], ("billing", "rule", "prod"))
        self.assertNotEqual(got["bil-db"][0], "billing")           # services filter respected
        for bad in ([{"match": {"tags": {}}}], [{"project": "x", "match": {"nmae_prefix": ["a"]}}]):
            with self.assertRaises(ValueError):
                grouping.validate_rules(bad)

    def test_inheritance_through_attachment_but_not_shared_infra(self):
        inst = mk("ec2:instance", "i-1", name="api", tags={"Project": "shop"}, sg_ids=[])
        vol = mk("ec2:volume", "v-1", name="v-1", rel=[("attached-to", inst.key)])
        subnet = mk("ec2:subnet", "subnet-1", name="subnet-1")
        inst.link(subnet.key, "in-subnet")
        sg = mk("ec2:security-group", "sg-1", name="sg-1")
        got = self.assign([inst, vol, subnet, sg])
        self.assertEqual(got["v-1"][:2], ("shop", "inherited"))
        self.assertEqual(got["subnet-1"][0], grouping.SHARED)       # a subnet never takes a project from what lives in it
        self.assertEqual(got["sg-1"][0], grouping.SHARED)

    def test_name_match_and_prefix_inference(self):
        rs = [mk("ec2:instance", "i-1", name="x", tags={"Project": "shop"}), mk("rds:instance", "shop-db", name="shop-db"),
              mk("ec2:instance", "i-a", name="atlas-api-1"), mk("lambda:function", "atlas-worker", name="atlas-worker"),
              mk("sqs:queue", "atlas-jobs", name="atlas-jobs"), mk("sqs:queue", "lonely-queue", name="lonely-queue")]
        got = self.assign(rs)
        self.assertEqual(got["shop-db"][:2], ("shop", "name-match"))
        for rid in ("i-a", "atlas-worker", "atlas-jobs"):
            self.assertEqual(got[rid][:2], ("atlas", "name-prefix"))
        self.assertEqual(got["lonely-queue"][0], "Unassigned")

    def test_environment_from_tag_name_and_neighbours(self):
        inst = mk("ec2:instance", "i-1", name="web-prod-1")
        vol = mk("ec2:volume", "v-1", name="v-1", rel=[("attached-to", inst.key)])
        got = self.assign([inst, vol, mk("ec2:instance", "i-2", tags={"Env": "STG"}), mk("ec2:instance", "i-3", tags={"Environment": "Development"})])
        self.assertEqual(got["i-1"][2], "prod")
        self.assertEqual(got["v-1"][2], "prod")
        self.assertEqual(got["i-2"][2], "staging")
        self.assertEqual(got["i-3"][2], "dev")

    def test_shipped_example_config_loads_and_validates(self):
        cfg = load_config(Path(__file__).resolve().parent.parent / "config" / "analyzer.example.toml")
        grouping.validate_rules(cfg["rules"])
        self.assertEqual([r["project"] for r in cfg["rules"]], ["checkout", "checkout", "data-platform", "legacy-monolith"])
        got = self.assign([mk("ec2:instance", "i-1", name="chk-api"), mk("ec2:instance", "i-2", tags={"Team": "payments-eu"}),
                           mk("ec2:instance", "i-3", name="legacy-db", tags={"Project": "x"})], cfg)
        self.assertEqual(got["i-1"][:2], ("checkout", "rule"))
        self.assertEqual(got["i-2"], ("checkout", "rule", "prod"))
        self.assertEqual(got["i-3"][:2], ("legacy-monolith", "rule"))      # explicit rules beat tags

    def test_toml_config_and_suggestions(self):
        d = Path(tempfile.mkdtemp())
        (d / "a.toml").write_text(textwrap.dedent('''
            [thresholds]
            idle_cpu_avg = 9.5
            [[rules]]
            project = "checkout"
            [rules.match]
            tags = { Team = "pay*" }
        '''))
        cfg = load_config(d / "a.toml")
        self.assertEqual(cfg["thresholds"]["idle_cpu_avg"], 9.5)
        self.assertEqual(cfg["thresholds"]["idle_cpu_max"], 20.0)            # untouched defaults survive
        got = self.assign([mk("ec2:instance", "i-1", tags={"Team": "payments"})], cfg)
        self.assertEqual(got["i-1"][:2], ("checkout", "rule"))
        rs = [mk("ec2:instance", "i-1", tags={"Project": "shop"})]
        grouping.assign(rs, load_config())
        toml = grouping.rules_to_toml(grouping.suggest_rules(rs))
        self.assertIn('project = "shop"', toml)
        self.assertIn('tags = { "Project" = "shop" }', toml)
        with self.assertRaises(FileNotFoundError):
            load_config(d / "missing.toml")


class TestLinks(unittest.TestCase):
    def test_cloudfront_and_dns_links_and_dangling(self):
        bucket = mk("s3:bucket", "assets", region="us-east-1")
        bucket.key = make_key(ACCT, "global", "s3:bucket", "assets")
        lb = mk("elbv2:lb", "web", dns="web-1.us-east-1.elb.amazonaws.com", state="active", lb_type="application", az_count=1)
        cf = mk("cloudfront:distribution", "E1", region="global", domain="d1.cloudfront.net",
                origins=["assets.s3.us-east-1.amazonaws.com", "web-1.us-east-1.elb.amazonaws.com"], state="enabled")
        eip = mk("ec2:eip", "e1", state="unassociated", public_ip="9.9.9.9")
        zone = mk("route53:hosted-zone", "Z1", region="global", name="example.com", record_count=6, records=[
            {"name": "api.example.com", "type": "ALIAS", "target": "dualstack.web-1.us-east-1.elb.amazonaws.com"},
            {"name": "www.example.com", "type": "ALIAS", "target": "d1.cloudfront.net"},
            {"name": "legacy.example.com", "type": "A", "target": "9.9.9.9"},
            {"name": "promo.example.com", "type": "CNAME", "target": "promo-bucket.s3-website-us-east-1.amazonaws.com"},
            {"name": "old.example.com", "type": "CNAME", "target": "dgone.cloudfront.net"}])
        res = run([bucket, lb, cf, eip, zone])
        resources = {r["rid"]: r for r in res["resources"]}
        origins = {x["to"].split(":")[-1] for x in resources["E1"]["relations"] if x["kind"] == "origin"}
        self.assertEqual(origins, {"assets", "web"})
        dns = {(x["label"], x["to"].split(":")[-1]) for x in resources["Z1"]["relations"] if x["kind"] == "dns"}
        self.assertEqual(dns, {("api.example.com", "web"), ("www.example.com", "E1"), ("legacy.example.com", "e1")})
        reasons = " | ".join(d["reason"] for d in resources["Z1"]["attrs"]["dangling"])
        self.assertIn("promo-bucket", reasons)
        self.assertIn("subdomain takeover", reasons)
        self.assertIn("CloudFront distribution not found", reasons)
        self.assertIn("not associated", reasons)
        dang = finding(res, "sec.r53.dangling")
        self.assertEqual((dang["severity"], dang["confidence"]), ("medium", "low"))     # we cannot see other accounts/regions
        self.assertIn("another account or region", dang["advice"])
        self.assertIn("legacy.example.com", " ".join(d["detail"] for d in res["findings"] if d["rule"] == "ec2.eip.unassociated"), "EIP finding mentions the DNS record via the zone name")


if __name__ == "__main__":
    unittest.main()
