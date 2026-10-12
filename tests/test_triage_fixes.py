"""Regression tests for the issues reported by the second (adversarial hunting) review that were confirmed and fixed."""

import contextlib
import io
import json
import os
import stat
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path
from unittest import mock

from analyzer import cli
from analyzer.analysis.config import load_config
from analyzer.analysis.engine import analyze
from analyzer.awscli import AwsCli, redact
from analyzer.collectors import serverless
from analyzer.fakeaws import FakeAws, FakeError
from analyzer.fsutil import write_private
from analyzer.scan import ScanOptions, run_scan, write_scan
from tests.test_audit_fixes import ACCT, NOW, ago, ctx_for, gap, mk, rules
from tests.test_analysis import metrics as m


def run(resources, gaps=(), options=None, regions=("us-east-1",), scanned_at=None):
    scan = {"resources": [asdict(r) for r in resources], "gaps": list(gaps), "options": options or {}, "audit": [],
            "accounts": [{"account": ACCT, "profile": "t", "arn": "arn:aws:iam::1:user/x", "regions": list(regions)}]}
    if scanned_at:
        scan["scanned_at"] = scanned_at
    return analyze(scan, load_config(), now=None if scanned_at else NOW)


def findings(res, rule):
    return [f for f in res["findings"] if f["rule"] == rule]


class TestScanScope(unittest.TestCase):
    ZONE = dict(region="global", name="example.com", record_count=5, records=[
        {"name": "eu.example.com", "type": "ALIAS", "target": "shop-1.eu-west-1.elb.amazonaws.com"},
        {"name": "us.example.com", "type": "ALIAS", "target": "shop-2.us-east-1.elb.amazonaws.com"},
        {"name": "cdn.example.com", "type": "CNAME", "target": "dgone.cloudfront.net"}])

    def test_dns_targets_in_unscanned_regions_or_collectors_are_unknown_not_dangling(self):
        zone = mk("route53:hosted-zone", "Z1", **self.ZONE)
        full = findings(run([zone], regions=("us-east-1", "eu-west-1")), "sec.r53.dangling")
        self.assertEqual(len(full[0]["detail"].split(";")), 3)
        narrowed = findings(run([zone], regions=("us-east-1",), options={"services": ["edge"]}), "sec.r53.dangling")
        self.assertEqual(len(narrowed), 1)
        self.assertIn("cdn.example.com", narrowed[0]["detail"])                 # edge DID read CloudFront: a real conclusion
        self.assertNotIn(".elb.", narrowed[0]["detail"], "--services edge never read load balancers, so ELB targets are unknown")
        regions_only = findings(run([zone], regions=("us-east-1",)), "sec.r53.dangling")
        self.assertNotIn("eu.example.com", regions_only[0]["detail"], "the eu-west-1 load balancer is in a region we did not scan")
        self.assertIn("us.example.com", regions_only[0]["detail"])

    def test_partial_service_scans_do_not_report_unused_security_groups_or_empty_vpcs(self):
        res = [mk("ec2:security-group", "sg-db", group_name="db", vpc="vpc-1", world_open=[], referenced_by=[]),
               mk("ec2:vpc", "vpc-1", is_default=False, cidr="10.0.0.0/16")]
        self.assertTrue({"ec2.sg.unused", "net.vpc.empty"} <= rules(run(res)))
        self.assertFalse({"ec2.sg.unused", "net.vpc.empty"} & rules(run(res, options={"services": ["compute"]})))      # rds/lambda/eks not read
        self.assertTrue({"ec2.sg.unused", "net.vpc.empty"} <= rules(run(res, options={"services": ["compute", "data", "serverless", "containers"]})))

    def test_ages_are_measured_at_scan_time(self):
        old_scan = "2024-01-01T00:00:00Z"
        v = mk("ec2:volume", "v", state="available", size_gb=10, vol_type="gp3", created="2023-12-31T00:00:00Z")
        self.assertNotIn("ec2.volume.unattached", rules(run([v], scanned_at=old_scan)), "one day old at scan time")
        self.assertIn("ec2.volume.unattached", rules(run([v], scanned_at="2024-03-01T00:00:00Z")))


class TestAgeGates(unittest.TestCase):
    def test_instances_younger_than_the_window_are_not_idle(self):
        quiet = dict(state="running", instance_type="m5.xlarge", metrics=m(cpu_avg=1.0, cpu_max=5.0))
        res = run([mk("ec2:instance", "i-new", created=ago(3), **quiet), mk("ec2:instance", "i-old", created=ago(60), **quiet)])
        self.assertEqual([f["resources"][0].split(":")[-1] for f in findings(res, "ec2.instance.idle")], ["i-old"])

    def test_other_metric_rules_wait_for_a_full_window(self):
        young = ago(2)
        res = run([
            mk("rds:instance", "db", state="available", created=young, instance_class="db.m5.large", engine="postgres", storage_gb=10, metrics=m(connections_max=0.0)),
            mk("elasticache:cluster", "c", state="available", created=young, node_type="cache.t3.micro", nodes=1, metrics=m(connections_max=0.0)),
            mk("dynamodb:table", "t", created=young, billing_mode="PROVISIONED", rcu=5, wcu=5, gsi_rcu=0, gsi_wcu=0, size_bytes=0,
               metrics={"read_units": 0.0, "write_units": 0.0, "_days": {"read_units": 30, "write_units": 30}}),
            mk("sqs:queue", "q", created=young, messages=0, messages_in_flight=0, metrics={"sent": 0.0, "_days": {"sent": 30}}),
            mk("ec2:nat-gateway", "nat", created=young, state="available", route_table_refs=1, metrics=m(bytes_in=0.0, bytes_return=0.0))])
        self.assertEqual(rules(res) & {"rds.instance.idle", "cache.cluster.idle", "ddb.table.idle", "sqs.idle", "ec2.nat.idle"}, set())

    def test_network_traffic_keeps_a_low_cpu_instance_from_being_idle(self):
        base = dict(state="running", instance_type="m5.large", created=ago(60))
        quiet = mk("ec2:instance", "i-quiet", metrics=m(cpu_avg=1.0, cpu_max=5.0, net_in=1e6, net_out=1e6), **base)
        proxy = mk("ec2:instance", "i-proxy", metrics=m(cpu_avg=1.0, cpu_max=5.0, net_in=2e11, net_out=2e11), **base)
        unknown = mk("ec2:instance", "i-nonet", metrics=m(cpu_avg=1.0, cpu_max=5.0), **base)
        got = {f["resources"][0].split(":")[-1] for f in findings(run([quiet, proxy, unknown]), "ec2.instance.idle")}
        self.assertEqual(got, {"i-quiet", "i-nonet"})

    def test_oversized_only_when_a_smaller_size_exists(self):
        busy_ish = dict(state="running", created=ago(60), metrics=m(cpu_avg=10.0, cpu_max=30.0))
        res = run([mk("ec2:instance", "m5l", instance_type="m5.large", **busy_ish), mk("ec2:instance", "t3l", instance_type="t3.large", **busy_ish),
                   mk("ec2:instance", "m5xl", instance_type="m5.xlarge", **busy_ish)])
        self.assertEqual({f["resources"][0].split(":")[-1] for f in findings(res, "ec2.instance.oversized")}, {"t3l", "m5xl"})


class TestFalsePositiveRules(unittest.TestCase):
    def test_empty_dead_letter_queues_are_healthy(self):
        main = mk("sqs:queue", "orders", messages=5, messages_in_flight=0, redrive_target="arn:dlq", created=ago(400),
                  metrics={"sent": 100.0, "_days": {"sent": 30}})
        dlq = mk("sqs:queue", "orders-dlq", messages=0, messages_in_flight=0, redrive_target=None, created=ago(400),
                 metrics={"sent": 0.0, "_days": {"sent": 30}})
        stray = mk("sqs:queue", "old-jobs", messages=0, messages_in_flight=0, redrive_target=None, created=ago(400),
                   metrics={"sent": 0.0, "_days": {"sent": 30}})
        main.arn, dlq.arn, stray.arn = "arn:main", "arn:dlq", "arn:stray"
        res = run([main, dlq, stray])
        self.assertIn("old-jobs", findings(res, "sqs.idle")[0]["detail"])
        self.assertNotIn("orders-dlq", findings(res, "sqs.idle")[0]["detail"])

    def test_collector_reads_the_redrive_policy(self):
        f = FakeAws()
        f.set("sqs", "list-queues", {"QueueUrls": ["https://sqs.us-east-1.amazonaws.com/1/orders"]})
        f.set("sqs", "get-queue-attributes", {"Attributes": {"QueueArn": "arn:main", "RedrivePolicy": json.dumps({"deadLetterTargetArn": "arn:dlq", "maxReceiveCount": 5})}})
        q = next(r for r in serverless.collect(ctx_for(f)) if r.type == "sqs:queue")
        self.assertEqual(q.attrs["redrive_target"], "arn:dlq")
        self.assertIn("RedrivePolicy", next(c for c in f.calls if c[1] == "get-queue-attributes")[3])

    def test_aurora_readers_and_replicas_are_not_idle(self):
        quiet = dict(state="available", created=ago(200), instance_class="db.r5.large", storage_gb=None, metrics=m(connections_max=0.0))
        res = run([mk("rds:instance", "standalone", engine="postgres", cluster=None, read_replica_of=None, **quiet),
                   mk("rds:instance", "aurora-reader", engine="aurora-postgresql", cluster="aur", read_replica_of=None, **quiet),
                   mk("rds:instance", "dr-copy", engine="postgres", cluster=None, read_replica_of="primary", **quiet)])
        self.assertEqual([f["resources"][0].split(":")[-1] for f in findings(res, "rds.instance.idle")], ["standalone"])

    def test_graviton_skips_windows_and_schedule_skips_fleet_nodes(self):
        base = dict(state="running", instance_type="m5.xlarge", arch="x86_64", created=ago(100), volume_ids=[])
        res = run([mk("ec2:instance", "linux", tags={"Environment": "dev"}, platform="Linux/UNIX", **base),
                   mk("ec2:instance", "win", tags={"Environment": "dev"}, platform="Windows", **base),
                   mk("ec2:instance", "karp", tags={"Environment": "dev", "karpenter.sh/nodepool": "default"}, platform="Linux/UNIX", **base),
                   mk("ec2:instance", "asg", tags={"Environment": "dev", "aws:autoscaling:groupName": "g"}, platform="Linux/UNIX", **base)])
        grav = {k.split(":")[-1] for f in findings(res, "cost.ec2.graviton") for k in f["resources"]}
        sched = {k.split(":")[-1] for f in findings(res, "cost.nonprod-schedule") for k in f["resources"]}
        self.assertNotIn("win", grav)
        self.assertEqual(sched, {"linux", "win"})

    def test_elasticache_idle_tolerates_monitoring_connections(self):
        def cache(rid, conns):
            return mk("elasticache:cluster", rid, state="available", created=ago(100), node_type="cache.r5.large", nodes=1, metrics=m(connections_max=conns))
        got = {f["resources"][0].split(":")[-1] for f in findings(run([cache("quiet", 2.0), cache("used", 40.0)]), "cache.cluster.idle")}
        self.assertEqual(got, {"quiet"})


class TestNumbers(unittest.TestCase):
    def test_stopped_instance_volume_saving_competes_with_gp2_to_gp3_instead_of_adding(self):
        vol = mk("ec2:volume", "v1", state="in-use", size_gb=1000, vol_type="gp2")
        inst = mk("ec2:instance", "i", state="stopped", instance_type="m5.large", stopped_at=ago(90), volume_ids=["v1"], arch="x86_64")
        res = run([vol, inst])
        stopped = findings(res, "ec2.instance.stopped")[0]
        self.assertEqual(set(stopped["breakdown"]), {vol_key(vol)})
        self.assertAlmostEqual(res["summary"]["potential_savings_usd"], 100.0, places=1)    # the volume once ($100/mo), not $100 + $20

    def test_multi_az_nat_saving_is_the_fixed_charge_only(self):
        nats = [mk("ec2:nat-gateway", f"nat-{i}", state="available", vpc="vpc-1", route_table_refs=1, tags={"Environment": "dev"},
                   metrics=m(bytes_in=5e12, bytes_return=5e12)) for i in range(2)]
        f = findings(run(nats), "net.nat.multi-az-nonprod")[0]
        self.assertAlmostEqual(f["savings_usd"], 32.85, places=2)

    def test_s3_lifecycle_saving_uses_only_standard_class_bytes(self):
        b = mk("s3:bucket", "b", created=ago(500), lifecycle_rules=0, versioning="Unversioned", public_access_blocked=True,
               metrics={"bytes_standard": 200e9, "bytes_glacier": 5000e9, "objects": 1.0})
        f = findings(run([b]), "s3.bucket.no-lifecycle")[0]
        self.assertAlmostEqual(f["savings_usd"], 200 * 0.023 * 0.25, places=2)

    def test_unpriced_instances_are_reported_as_unpriced_not_free(self):
        gpu = mk("ec2:instance", "gpu", state="running", instance_type="p3.2xlarge", created=ago(90), arch="x86_64",
                 metrics=m(cpu_avg=1.0, cpu_max=3.0, net_in=1e6, net_out=1e6))
        res = run([gpu])
        f = findings(res, "ec2.instance.idle")[0]
        self.assertFalse(f["priced"])
        self.assertEqual(res["summary"]["unpriced"], {"resources": 1, "types": {"p3.2xlarge": 1}})
        priced = run([mk("ec2:instance", "ok", state="running", instance_type="m5.large", created=ago(90), arch="x86_64", metrics=m(cpu_avg=1.0, cpu_max=3.0))])
        self.assertTrue(findings(priced, "ec2.instance.idle")[0]["priced"])


def vol_key(r):
    return r.key


class TestCostModelCorrections(unittest.TestCase):
    def test_snapshot_chains_share_the_volumes_data(self):
        from analyzer.analysis import cost
        snaps = [mk("ec2:snapshot", f"s{i}", size_gb=100, volume_id="vol-1") for i in range(10)] + [mk("ec2:snapshot", "solo", size_gb=100, volume_id="vol-2")]
        cost.price_all(snaps)
        self.assertAlmostEqual(sum(r.est_monthly_usd for r in snaps[:10]), 100 * 0.05 * 0.5, places=1)      # one volume's worth, not 10x
        self.assertAlmostEqual(snaps[10].est_monthly_usd, 2.5, places=2)

    def test_rds_provisioned_iops_and_aurora_serverless_floor(self):
        from analyzer.analysis import cost
        base = dict(state="available", instance_class="db.m5.large", engine="postgres", storage_gb=100, multi_az=False)
        plain = cost.estimate(mk("rds:instance", "a", storage_type="io1", iops=0, **base))[0]
        piops = cost.estimate(mk("rds:instance", "b", storage_type="io1", iops=10000, **base))[0]
        self.assertAlmostEqual(piops - plain, 10000 * 0.10, places=1)
        sv2 = cost.estimate(mk("rds:cluster", "c", serverless_v2=True, acu_min=2, members=3))[0]
        self.assertAlmostEqual(sv2, 2 * 3 * 0.12 * 730, places=1)

    def test_dynamodb_storage_has_no_per_table_free_tier_and_ia_class_is_cheaper(self):
        from analyzer.analysis import cost
        std = cost.estimate(mk("dynamodb:table", "t", billing_mode="PAY_PER_REQUEST", size_bytes=10e9, table_class="STANDARD"))[0]
        ia = cost.estimate(mk("dynamodb:table", "t", billing_mode="PAY_PER_REQUEST", size_bytes=10e9, table_class="STANDARD_INFREQUENT_ACCESS"))[0]
        self.assertAlmostEqual(std, 10 * 0.25, places=2)
        self.assertAlmostEqual(ia, 10 * 0.10, places=2)

    def test_fargate_capacity_provider_services_are_priced(self):
        from analyzer.analysis import cost
        base = dict(launch_type="CAPACITY_PROVIDER", task_cpu=1024, task_memory=2048, running=2, task_arch="X86_64")
        on_demand = cost.estimate(mk("ecs:service", "a", capacity_providers=["FARGATE"], **base))[0]
        spot = cost.estimate(mk("ecs:service", "b", capacity_providers=["FARGATE_SPOT"], **base))[0]
        ec2 = cost.estimate(mk("ecs:service", "c", capacity_providers=["my-asg-provider"], **base))[0]
        self.assertGreater(on_demand, 0)
        self.assertAlmostEqual(spot, on_demand * 0.3, places=2)
        self.assertEqual(ec2, 0.0)


class TestMetricsCompleteness(unittest.TestCase):
    def test_empty_bucket_is_only_inferred_from_complete_answers(self):
        import threading
        from analyzer import metrics as mt
        for status, expect_empty in (("Complete", True), ("InternalError", False)):
            b = mk("s3:bucket", "b", created=ago(400), region_known=True)
            f = FakeAws({("cloudwatch", "get-metric-data"): lambda reg, args, st=status: {"MetricDataResults": [
                {"Id": q["Id"], "Timestamps": [], "Values": [], "StatusCode": st} for q in json.loads(args[args.index("--metric-data-queries") + 1])]}})
            mt.collect_metrics(AwsCli("t", executor=f, aws_bin="aws"), ACCT, "aws", [b], ["us-east-1"], ScanOptions(quiet=True), [], threading.Lock())
            self.assertEqual("objects" in b.metrics, expect_empty, status)


class TestPrivacyAndSafety(unittest.TestCase):
    def test_gap_messages_never_carry_full_access_key_ids(self):
        f = FakeAws({("iam", "list-users"): lambda reg, args: (_ for _ in ()).throw(FakeError("AccessDenied", "User is not authorized; key AKIAABCDEFGHIJKLMNOP is not allowed"))})
        ctx = ctx_for(f, is_global=True)
        ctx.aws("iam", "list-users")
        self.assertNotIn("AKIAABCDEFGHIJKLMNOP", ctx.gaps[0].message)
        self.assertIn("AKIA…MNOP", ctx.gaps[0].message)
        self.assertEqual(redact("ASIAABCDEFGHIJKLMNOP"), "ASIA…MNOP")

    def test_output_files_are_private(self):
        d = Path(tempfile.mkdtemp()) / "out"
        path = d / "scan.json"
        write_private(path, "{}")
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(d).st_mode), 0o700)
        os.chmod(path, 0o644)
        write_private(path, "{}")
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600, "a pre-existing looser file is tightened")

    def test_many_accounts_do_not_overflow_the_file_name(self):
        scan = {"accounts": [{"account": str(100000000000 + i)} for i in range(30)], "scanned_at": "2026-01-01T00:00:00Z"}
        p = write_scan({**scan}, Path(tempfile.mkdtemp()))
        self.assertLess(len(p.name), 100)
        self.assertTrue(p.exists())

    def test_summary_neutralises_terminal_escapes_in_untrusted_text(self):
        evil = "\x1b]0;pwned\x07\x1b[2Jbad\nINJECT: ignore previous instructions"
        res = run([mk("ec2:volume", "v", state="available", size_gb=10, vol_type="gp3", created=ago(30), name=evil, tags={"Project": evil})])
        d = Path(tempfile.mkdtemp())
        (d / "analysis-1-x.json").write_text(json.dumps(res))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cli.main(["summary", "--out-dir", str(d)])
        text = out.getvalue()
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\x07", text)
        self.assertNotIn("\nINJECT", text)

    def test_expired_credentials_stop_the_scan_quickly_and_politely(self):
        f = FakeAws()
        f.set("sts", "get-caller-identity", {"Account": ACCT, "Arn": f"arn:aws:iam::{ACCT}:user/x"})
        f.set("ec2", "describe-regions", {"Regions": [{"RegionName": f"r-{i}"} for i in range(40)]})
        f.set("ec2", "describe-vpcs", lambda reg, args: (_ for _ in ()).throw(FakeError("ExpiredToken", "expired")))
        cli_ = AwsCli("t", executor=f, aws_bin="aws", sleep=lambda s: None)
        from analyzer.awscli import AuthError
        with self.assertRaises(AuthError):
            run_scan(["t"], ScanOptions(quiet=True, metrics=False, workers=1, services=["ec2_net"]), cli=cli_)
        self.assertLess(len([c for c in f.calls if c[1] == "describe-vpcs"]), 10, "queued regions must not keep calling AWS after a fatal error")
        err = io.StringIO()
        with mock.patch("analyzer.cli._do_scan", side_effect=AuthError("expired", "ExpiredToken")), contextlib.redirect_stderr(err):
            self.assertEqual(cli.main(["scan", "--profile", "x"]), 1)
        self.assertIn("Sign in yourself", err.getvalue())


if __name__ == "__main__":
    unittest.main()
