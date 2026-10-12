"""Phase 2 connections: event sources, SNS fan-out, dead letters, IAM roles, security-group reachability, richer origins."""

import json
import unittest
from dataclasses import asdict
from datetime import datetime, timezone
from unittest import mock

from analyzer import allowlist, policy
from analyzer.analysis import grouping, links
from analyzer.analysis.config import load_config
from analyzer.analysis.engine import analyze
from analyzer.awscli import AwsCli, check_command
from analyzer.collectors import containers, ec2_net, serverless
from analyzer.demo import ACCOUNT, WEBHOOK_TOKEN, demo_executor
from analyzer.fakeaws import FakeAws, FakeError, arg_value
from analyzer.model import Resource, make_key
from analyzer.scan import Ctx, ScanOptions, run_scan
from tests.test_contract import produced_keys

ACCT = "111122223333"
REGION = "eu-west-1"
NOW = datetime(2026, 10, 1, tzinfo=timezone.utc)
NEW_KINDS = {"consumes", "delivers-to", "dead-letter-to", "uses-role", "may-connect"}


def ctx_for(fake, region=REGION):
    return Ctx(AwsCli("t", executor=fake, aws_bin="aws", sleep=lambda s: None), ACCT, region)


def idx(resources):
    return {r.rid: r for r in resources}


def mk(rtype, rid, *, region=REGION, account=ACCT, tags=None, state="", arn=None, rel=(), **attrs):
    r = Resource(key=make_key(account, region, rtype, rid), rid=rid, type=rtype, service=rtype.split(":")[0], account=account,
                 region=region, name=rid, state=state, arn=arn, tags=tags or {}, attrs=attrs)
    for kind, to in rel:
        r.link(to, kind)
    return r


def rels(r, kind):
    return {(x["to"].split(":", 2)[2], x.get("label")) for x in r.relations if x["kind"] == kind}


def sg_key(sg_id, region=REGION, account=ACCT):
    return make_key(account, region, "ec2:security-group", sg_id)


def lambda_arn(name, qualifier=""):
    return f"arn:aws:lambda:{REGION}:{ACCT}:function:{name}" + (f":{qualifier}" if qualifier else "")


def sqs_arn(name):
    return f"arn:aws:sqs:{REGION}:{ACCT}:{name}"


# --------------------------------------------------------------------------- collectors


class TestEventSourceMappings(unittest.TestCase):
    def fake(self, esm):
        f = FakeAws()
        f.set("lambda", "list-functions", {"Functions": [
            {"FunctionName": "orders", "FunctionArn": lambda_arn("orders"), "Role": f"arn:aws:iam::{ACCT}:role/service-role/orders-role"},
            {"FunctionName": "idle", "FunctionArn": lambda_arn("idle")}]})
        f.set("lambda", "list-event-source-mappings", esm)
        return f

    def test_known_mappings_are_grouped_by_function_name(self):
        f = self.fake([
            {"src": sqs_arn("jobs"), "fn": lambda_arn("orders", "live"), "state": "Enabled", "batch": 10, "fail": sqs_arn("jobs-dlq")},
            {"src": f"arn:aws:dynamodb:{REGION}:{ACCT}:table/carts/stream/2025-01-01T00:00:00.000", "fn": lambda_arn("orders", "7"),
             "state": "Disabled", "batch": 100, "fail": None},
            {"src": sqs_arn("x"), "fn": "not-an-arn", "state": "Enabled", "batch": 1, "fail": None}])
        ctx = ctx_for(f)
        r = idx(serverless._lambdas(ctx))
        self.assertEqual(r["orders"].attrs["role"], "orders-role")                 # /service-role/ path dropped
        self.assertTrue(r["orders"].attrs["event_sources_known"])
        self.assertEqual(r["orders"].attrs["event_sources"], [
            {"arn": sqs_arn("jobs"), "state": "Enabled", "batch": 10, "on_failure": sqs_arn("jobs-dlq")},
            {"arn": f"arn:aws:dynamodb:{REGION}:{ACCT}:table/carts/stream/2025-01-01T00:00:00.000", "state": "Disabled",
             "batch": 100, "on_failure": None}])
        self.assertEqual((r["idle"].attrs["event_sources"], r["idle"].attrs["event_sources_known"]), ([], True))
        self.assertEqual(ctx.gaps, [])
        # one call per region, and only through a projection (no filter criteria, no Kafka endpoints)
        calls = [a for _s, op, _r, a in f.calls if op == "list-event-source-mappings"]
        self.assertEqual(len(calls), 1)
        query = arg_value(list(calls[0]), "--query")
        self.assertTrue(query.startswith("EventSourceMappings[].{"))
        for forbidden in ("FilterCriteria", "SelfManagedEventSource", "SourceAccessConfigurations", "Endpoints"):
            self.assertNotIn(forbidden, query)
        check_command("lambda", "list-event-source-mappings", ["--query", query])

    def test_failed_call_is_unknown_not_empty(self):
        def deny(region, args):
            raise FakeError("AccessDeniedException")
        ctx = ctx_for(self.fake(deny))
        r = idx(serverless._lambdas(ctx))
        self.assertEqual((r["orders"].attrs["event_sources"], r["orders"].attrs["event_sources_known"]), ([], False))
        self.assertEqual([(g.service, g.op) for g in ctx.gaps], [("lambda", "list-event-source-mappings")])

    def test_null_or_empty_answers_mean_no_mappings(self):
        for answer in (None, [], {}):
            r = idx(serverless._lambdas(ctx_for(self.fake(answer))))
            self.assertEqual((r["orders"].attrs["event_sources"], r["orders"].attrs["event_sources_known"]), ([], True), answer)

    def test_cap_and_no_call_without_functions(self):
        many = [{"src": sqs_arn(f"q{i}"), "fn": lambda_arn("orders"), "state": "Enabled", "batch": 1, "fail": None} for i in range(30)]
        r = idx(serverless._lambdas(ctx_for(self.fake(many))))
        self.assertEqual(len(r["orders"].attrs["event_sources"]), serverless.MAX_EVENT_SOURCES)
        f = FakeAws()
        f.set("lambda", "list-functions", {"Functions": []})
        serverless._lambdas(ctx_for(f))
        self.assertNotIn(("lambda", "list-event-source-mappings"), f.ops())


class TestSnsSubscribers(unittest.TestCase):
    def test_only_sqs_and_lambda_arns_are_kept(self):
        topic = f"arn:aws:sns:{REGION}:{ACCT}:events"
        subs = [("email", "someone@example.com"), ("sms", "+15555550100"), ("https", "https://hooks.example.com/x?token=s3cr3t-token"),
                ("http", "http://10.0.0.1/hook"), ("application", f"arn:aws:sns:{REGION}:{ACCT}:endpoint/GCM/app/abc"),
                ("firehose", f"arn:aws:firehose:{REGION}:{ACCT}:deliverystream/s"),
                ("sqs", sqs_arn("jobs")), ("lambda", lambda_arn("worker", "live")),
                ("sqs", "https://sqs.eu-west-1.amazonaws.com/111122223333/jobs"),       # not an ARN
                ("lambda", sqs_arn("mismatch")),                                       # protocol and ARN service disagree
                ("sqs", sqs_arn("jobs") + "\nevil"), ("sqs", sqs_arn("jobs"))]         # junk / duplicate
        f = FakeAws()
        f.set("sns", "list-topics", {"Topics": [{"TopicArn": topic}]})
        f.set("sns", "list-subscriptions", {"Subscriptions": [{"TopicArn": topic, "Protocol": p, "Endpoint": e} for p, e in subs]})
        res = serverless._sns(ctx_for(f))
        t = idx(res)["events"]
        self.assertEqual(t.attrs["subscriptions"], len(subs))
        self.assertEqual(t.attrs["subscriber_arns"], sorted([lambda_arn("worker", "live"), sqs_arn("jobs")]))
        blob = json.dumps([asdict(r) for r in res])
        for leaked in ("someone@example.com", "+15555550100", "s3cr3t-token", "hooks.example.com", "10.0.0.1", "firehose", "GCM", "evil"):
            self.assertNotIn(leaked, blob)

    def test_subscriber_cap(self):
        topic = f"arn:aws:sns:{REGION}:{ACCT}:big"
        f = FakeAws()
        f.set("sns", "list-topics", {"Topics": [{"TopicArn": topic}]})
        f.set("sns", "list-subscriptions", {"Subscriptions": [{"TopicArn": topic, "Protocol": "sqs", "Endpoint": sqs_arn(f"q{i:03}")}
                                                              for i in range(80)]})
        t = idx(serverless._sns(ctx_for(f)))["big"]
        self.assertEqual(len(t.attrs["subscriber_arns"]), serverless.MAX_SUBSCRIBERS)
        self.assertEqual(t.attrs["subscriber_arns"], sorted(t.attrs["subscriber_arns"]))


class TestIngressFrom(unittest.TestCase):
    def test_ingress_only_no_self_ports_formatting(self):
        def pair(*ids):
            return [{"GroupId": i, "UserId": ACCT} for i in ids]
        f = FakeAws()
        f.set("ec2", "describe-security-groups", {"SecurityGroups": [
            {"GroupId": "sg-db", "GroupName": "db", "VpcId": "vpc-1",
             "IpPermissions": [
                 {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "UserIdGroupPairs": pair("sg-app", "sg-db")},   # + self
                 {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432, "UserIdGroupPairs": pair("sg-app")},            # duplicate
                 {"IpProtocol": "-1", "UserIdGroupPairs": pair("sg-admin")},
                 {"IpProtocol": "tcp", "FromPort": 8000, "ToPort": 8100, "UserIdGroupPairs": pair("sg-web")},
                 {"IpProtocol": "udp", "FromPort": 53, "ToPort": 53, "UserIdGroupPairs": pair("sg-dns")},
                 {"IpProtocol": "icmp", "FromPort": 8, "ToPort": -1, "UserIdGroupPairs": pair("sg-mon")},
                 {"IpProtocol": "6", "FromPort": 22, "ToPort": 22, "UserIdGroupPairs": pair("sg-ops")},
                 {"IpProtocol": "tcp", "FromPort": 0, "ToPort": 65535, "UserIdGroupPairs": pair("sg-batch")},
                 {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}],   # CIDR only
             "IpPermissionsEgress": [{"IpProtocol": "-1", "UserIdGroupPairs": pair("sg-egress-only")}]}]})
        sg = idx(ec2_net._security_groups(ctx_for(f)))["sg-db"]
        self.assertEqual(sg.attrs["ingress_from"], [
            {"sg": "sg-app", "ports": "tcp 5432"}, {"sg": "sg-admin", "ports": "all"}, {"sg": "sg-web", "ports": "tcp 8000-8100"},
            {"sg": "sg-dns", "ports": "udp 53"}, {"sg": "sg-mon", "ports": "icmp"}, {"sg": "sg-ops", "ports": "tcp 22"},
            {"sg": "sg-batch", "ports": "tcp all"}])

    def test_referenced_by_is_unchanged_and_still_counts_egress(self):
        f = FakeAws()
        f.set("ec2", "describe-security-groups", {"SecurityGroups": [
            {"GroupId": "sg-a", "IpPermissions": [], "IpPermissionsEgress": [{"IpProtocol": "-1", "UserIdGroupPairs": [{"GroupId": "sg-b"}]}]},
            {"GroupId": "sg-b", "IpPermissions": [], "IpPermissionsEgress": []}]})
        r = idx(ec2_net._security_groups(ctx_for(f)))
        self.assertEqual(r["sg-b"].attrs["referenced_by"], ["sg-a"])
        self.assertEqual((r["sg-a"].attrs["ingress_from"], r["sg-b"].attrs["ingress_from"]), ([], []))


class TestContainerRoles(unittest.TestCase):
    def test_ecs_task_and_execution_roles_eks_roles(self):
        f = FakeAws()
        f.set("ecs", "list-clusters", {"clusterArns": ["arn:aws:ecs:eu-west-1:111122223333:cluster/main"]})
        f.set("ecs", "describe-clusters", {"clusters": [{"clusterArn": "arn:aws:ecs:eu-west-1:111122223333:cluster/main", "clusterName": "main"}]})
        f.set("ecs", "list-services", {"serviceArns": ["arn:s1"]})
        f.set("ecs", "describe-services", {"services": [{"serviceName": "web", "serviceArn": "arn:s1", "taskDefinition": "td:1"}]})
        # FakeAws does not apply --query: anything beyond the projected keys must still be ignored by the collector
        f.set("ecs", "describe-task-definition", {"cpu": "256", "memory": "512", "task_role": f"arn:aws:iam::{ACCT}:role/service-role/web-task",
                                                  "exec_role": f"arn:aws:iam::{ACCT}:role/ecsTaskExecutionRole",
                                                  "containerDefinitions": [{"environment": [{"name": "DB_PASSWORD", "value": "hunter2"}]}]})
        f.set("eks", "list-clusters", {"clusters": ["prod"]})
        f.set("eks", "describe-cluster", {"cluster": {"name": "prod", "status": "ACTIVE", "roleArn": f"arn:aws:iam::{ACCT}:role/eks-cluster"}})
        f.set("eks", "list-nodegroups", {"nodegroups": ["ng1"]})
        f.set("eks", "describe-nodegroup", {"nodegroup": {"nodegroupName": "ng1", "nodeRole": f"arn:aws:iam::{ACCT}:role/nodes/eks-node"}})
        res = containers.collect(ctx_for(f))
        r = idx(res)
        self.assertEqual((r["main/web"].attrs["task_role"], r["main/web"].attrs["exec_role"]), ("web-task", "ecsTaskExecutionRole"))
        self.assertEqual(r["prod"].attrs["role"], "eks-cluster")
        self.assertEqual(r["prod/ng1"].attrs["node_role"], "eks-node")
        query = next(arg_value(list(a), "--query") for _s, op, _r, a in f.calls if op == "describe-task-definition")
        self.assertIn("taskRoleArn", query)
        self.assertNotIn("containerDefinitions", query)
        blob = json.dumps([asdict(x) for x in res])
        self.assertNotIn("hunter2", blob)
        self.assertNotIn("DB_PASSWORD", blob)


# --------------------------------------------------------------------------- links


class TestRoleLinks(unittest.TestCase):
    def test_uses_role_only_to_inventoried_roles(self):
        role = mk("iam:role", "x", region="global")
        task, execr = mk("iam:role", "task", region="global"), mk("iam:role", "exec", region="global")
        cl_role, node_role = mk("iam:role", "eks-cluster", region="global"), mk("iam:role", "eks-node", region="global")
        fn = mk("lambda:function", "fn", role="x")                     # collector: ".../role/service-role/x" -> "x"
        ghost = mk("lambda:function", "ghost", role="not-scanned")
        other_acct = mk("lambda:function", "far", account="999999999999", role="x")
        svc = mk("ecs:service", "c/web", task_role="task", exec_role="exec")
        same = mk("ecs:service", "c/same", task_role="task", exec_role="task")
        eks = mk("eks:cluster", "prod", role="eks-cluster")
        ng = mk("eks:nodegroup", "prod/ng", node_role="eks-node")
        inst = mk("ec2:instance", "i-1", iam_profile="x")
        inst_no_role = mk("ec2:instance", "i-2", iam_profile="profile-without-role")
        links.resolve_links([role, task, execr, cl_role, node_role, fn, ghost, other_acct, svc, same, eks, ng, inst, inst_no_role])
        self.assertEqual(rels(fn, "uses-role"), {("iam:role:x", None)})
        self.assertEqual(fn.relations[0]["to"], f"{ACCT}:global:iam:role:x")
        self.assertEqual(rels(ghost, "uses-role"), set())
        self.assertEqual(rels(other_acct, "uses-role"), set())        # a role of another account is a different role
        self.assertEqual(rels(svc, "uses-role"), {("iam:role:task", "task role"), ("iam:role:exec", "execution role")})
        self.assertEqual(rels(same, "uses-role"), {("iam:role:task", "task role")})
        self.assertEqual(rels(eks, "uses-role"), {("iam:role:eks-cluster", "cluster role")})
        self.assertEqual(rels(ng, "uses-role"), {("iam:role:eks-node", "node role")})
        self.assertEqual(rels(inst, "uses-role"), {("iam:role:x", "instance profile (same name)")})
        self.assertEqual(rels(inst_no_role, "uses-role"), set())


class TestMessagingLinks(unittest.TestCase):
    def setUp(self):
        self.jobs = mk("sqs:queue", "jobs", arn=sqs_arn("jobs"), redrive_target=sqs_arn("jobs-dlq"))
        self.dlq = mk("sqs:queue", "jobs-dlq", arn=sqs_arn("jobs-dlq"), redrive_target=None)
        self.loop = mk("sqs:queue", "loop", arn=sqs_arn("loop"), redrive_target=sqs_arn("loop"))      # nonsense: no self link
        self.table = mk("dynamodb:table", "carts", arn=f"arn:aws:dynamodb:{REGION}:{ACCT}:table/carts")
        self.stream = mk("other:kinesis:stream", "clicks", arn=f"arn:aws:kinesis:{REGION}:{ACCT}:stream/clicks", from_tagging=True)
        self.alerts = mk("sns:topic", "alerts", arn=f"arn:aws:sns:{REGION}:{ACCT}:alerts", subscriber_arns=[])
        self.bucket = mk("s3:bucket", "failures", region="global", arn="arn:aws:s3:::failures")
        self.fn = mk("lambda:function", "worker", arn=lambda_arn("worker"), event_sources=[
            {"arn": sqs_arn("jobs"), "state": "Enabled", "batch": 10, "on_failure": sqs_arn("jobs-dlq")},
            {"arn": f"arn:aws:dynamodb:{REGION}:{ACCT}:table/carts/stream/2025-01-01T00:00:00.000", "state": "Enabled",
             "batch": 100, "on_failure": f"arn:aws:sns:{REGION}:{ACCT}:alerts"},
            {"arn": f"arn:aws:kinesis:{REGION}:{ACCT}:stream/clicks/consumer/app:1700000000", "state": "Disabled", "batch": 500,
             "on_failure": "arn:aws:s3:::failures"},
            {"arn": sqs_arn("not-scanned"), "state": "Enabled", "batch": 1, "on_failure": None},
            {"arn": None, "state": "Enabled", "batch": 1, "on_failure": None}])      # self-managed Kafka: no ARN
        self.topic = mk("sns:topic", "events", arn=f"arn:aws:sns:{REGION}:{ACCT}:events",
                        subscriber_arns=[lambda_arn("worker", "live"), sqs_arn("jobs"), sqs_arn("elsewhere")])
        self.odd = mk("sns:topic", "odd", arn=f"arn:aws:sns:{REGION}:{ACCT}:odd", subscriber_arns=[f"arn:aws:sns:{REGION}:{ACCT}:alerts"])
        links.resolve_links([self.jobs, self.dlq, self.loop, self.table, self.stream, self.alerts, self.bucket, self.fn, self.topic, self.odd])

    def test_consumes_with_qualified_and_stream_arns(self):
        self.assertEqual(rels(self.fn, "consumes"), {("sqs:queue:jobs", "batch 10"), ("dynamodb:table:carts", "batch 100"),
                                                     ("other:kinesis:stream:clicks", "disabled")})

    def test_consumes_label_merges_mappings_to_one_source(self):
        # a trigger moved to an alias: the old unqualified mapping is Disabled, the alias one still polls the queue
        def label(*mappings):
            fn = mk("lambda:function", "mover", arn=lambda_arn("mover"),
                    event_sources=[{"arn": sqs_arn("jobs"), "state": s, "batch": b, "on_failure": None} for s, b in mappings])
            links.resolve_links([mk("sqs:queue", "jobs", arn=sqs_arn("jobs")), fn])
            self.assertEqual(len(fn.relations), 1)
            return rels(fn, "consumes")

        for order in ([("Disabled", 10), ("Enabled", 10)], [("Enabled", 10), ("Disabled", 10)]):
            self.assertEqual(label(*order), {("sqs:queue:jobs", "batch 10")}, order)
        self.assertEqual(label(("Disabled", 5), ("Enabled", 10)), {("sqs:queue:jobs", "batch 10")})   # a disabled batch size is not shown
        self.assertEqual(label(("Enabled", 100), ("Creating", 10)), {("sqs:queue:jobs", "batch 10/100")})
        self.assertEqual(label(("Enabled", 10), ("Updating", 100)), {("sqs:queue:jobs", "batch 10/100")})
        self.assertEqual(label(("Disabled", 10), ("Disabled", 100)), {("sqs:queue:jobs", "disabled")})
        self.assertEqual(label(("Enabled", None), ("Disabled", 10)), {("sqs:queue:jobs", None)})

    def test_delivers_to_only_queues_and_functions(self):
        self.assertEqual(rels(self.topic, "delivers-to"), {("lambda:function:worker", None), ("sqs:queue:jobs", None)})
        self.assertEqual(self.odd.relations, [])

    def test_dead_letter_targets(self):
        self.assertEqual(rels(self.jobs, "dead-letter-to"), {("sqs:queue:jobs-dlq", None)})
        self.assertEqual(rels(self.fn, "dead-letter-to"), {("sqs:queue:jobs-dlq", None), ("sns:topic:alerts", None)})   # not the bucket
        self.assertEqual(self.loop.relations, [])
        self.assertEqual(self.dlq.relations, [])

    def test_lambda_arn_normalisation(self):
        self.assertEqual(links.norm_arn(lambda_arn("worker", "live")), lambda_arn("worker"))
        self.assertEqual(links.norm_arn(lambda_arn("worker", "42")), lambda_arn("worker"))
        self.assertEqual(links.norm_arn(f"arn:aws:dynamodb:{REGION}:{ACCT}:table/t/stream/x"), f"arn:aws:dynamodb:{REGION}:{ACCT}:table/t")
        self.assertEqual(links.norm_arn(None), "")


class TestOriginLinks(unittest.TestCase):
    def setUp(self):
        self.rest = mk("apigw:rest-api", "abc123def4", region="us-east-1")
        self.http = mk("apigw:http-api", "zyx987", region="eu-west-1")
        self.inst = mk("ec2:instance", "i-web", region="us-east-1", public_ip="3.4.5.6", state="running")
        self.inst2 = mk("ec2:instance", "i-eu", region="eu-west-1", public_ip="52.1.2.3", state="running")
        self.alb = mk("elbv2:lb", "app", dns="app-1.eu-west-1.elb.amazonaws.com", state="active")
        self.zone = mk("route53:hosted-zone", "Z1", region="global", private=False, records=[
            {"name": "origin.example.com", "type": "ALIAS", "target": "dualstack.app-1.eu-west-1.elb.amazonaws.com."},
            {"name": "*.example.com", "type": "CNAME", "target": "app-1.eu-west-1.elb.amazonaws.com"},
            {"name": "gone.example.com", "type": "CNAME", "target": "missing-1.eu-west-1.elb.amazonaws.com"},
            {"name": "ip.example.com", "type": "A", "target": "52.1.2.3"},
            {"name": "self.example.com", "type": "ALIAS", "target": "d1.cloudfront.net"}])
        self.private = mk("route53:hosted-zone", "Z2", region="global", private=True, records=[
            {"name": "internal.example.com", "type": "ALIAS", "target": "app-1.eu-west-1.elb.amazonaws.com"}])
        self.cf = mk("cloudfront:distribution", "E1", region="global", domain="d1.cloudfront.net", state="enabled", origins=[
            "abc123def4.execute-api.us-east-1.amazonaws.com", "zyx987.execute-api.eu-west-1.amazonaws.com",
            "abc123def4.execute-api.eu-west-1.amazonaws.com",                     # right id, wrong region: not that API
            "ec2-3-4-5-6.compute-1.amazonaws.com", "ec2-52-1-2-3.eu-west-1.compute.amazonaws.com",
            "origin.example.com", "ip.example.com", "anything.example.com", "gone.example.com", "internal.example.com",
            "self.example.com"])
        res = [self.rest, self.http, self.inst, self.inst2, self.alb, self.zone, self.private, self.cf]
        links.resolve_links(res)

    def test_api_gateway_ec2_hostname_and_dns_hop_origins(self):
        self.assertEqual(rels(self.cf, "origin"), {
            ("apigw:rest-api:abc123def4", None), ("apigw:http-api:zyx987", None),
            ("ec2:instance:i-web", None), ("ec2:instance:i-eu", None),
            ("elbv2:lb:app", "via origin.example.com")})     # first label wins; ip.example.com -> i-eu already linked
        self.assertEqual(len([x for x in self.cf.relations if x["kind"] == "origin"]), 5)

    def test_dns_hop_label_and_zone_links_unchanged(self):
        cf = mk("cloudfront:distribution", "E9", region="global", domain="d9.cloudfront.net", origins=["ip.example.com"])
        inst = mk("ec2:instance", "i-eu", region="eu-west-1", public_ip="52.1.2.3")
        zone = mk("route53:hosted-zone", "Z1", region="global", records=[{"name": "ip.example.com", "type": "A", "target": "52.1.2.3"}])
        links.resolve_links([cf, inst, zone])
        self.assertEqual(rels(cf, "origin"), {("ec2:instance:i-eu", "via ip.example.com")})
        self.assertEqual(rels(zone, "dns"), {("ec2:instance:i-eu", "ip.example.com")})
        self.assertEqual(zone.attrs["dangling"], [])
        self.assertEqual([d["name"] for d in self.zone.attrs["dangling"]], ["gone.example.com"])   # same dangling logic as before


class TestMayConnect(unittest.TestCase):
    def world(self):
        web_sg = mk("ec2:security-group", "sg-web", ingress_from=[])
        app_sg = mk("ec2:security-group", "sg-app", ingress_from=[{"sg": "sg-web", "ports": "tcp 8080"}, {"sg": "sg-web", "ports": "tcp 8443"},
                                                                  {"sg": "sg-app", "ports": "all"}])
        db_sg = mk("ec2:security-group", "sg-db", ingress_from=[{"sg": "sg-app", "ports": "tcp 5432"}])
        lb = mk("elbv2:lb", "alb", sg_ids=["sg-web"])
        web = mk("ec2:instance", "i-web", sg_ids=["sg-web"], rel=[("uses-sg", sg_key("sg-web"))])
        api = mk("ec2:instance", "i-api", sg_ids=["sg-app"], rel=[("uses-sg", sg_key("sg-app"))])
        svc = mk("ecs:service", "c/api", sg_ids=["sg-app"])
        fn = mk("lambda:function", "fn", sg_ids=[], rel=[("uses-sg", sg_key("sg-app"))])     # membership through the relation only
        db = mk("rds:instance", "db", sg_ids=["sg-db"], rel=[("uses-sg", sg_key("sg-db"))])
        both = mk("ec2:instance", "i-both", sg_ids=["sg-app", "sg-db"])
        eni = mk("ec2:eni", "eni-1", sg_ids=["sg-web"])
        far = mk("ec2:instance", "i-far", region="us-east-1", sg_ids=["sg-web"])               # same id, other region
        clb = mk("elb:clb", "legacy", sg_ids=["sg-web"], rel=[("targets", make_key(ACCT, REGION, "ec2:instance", "i-api"))])
        return [web_sg, app_sg, db_sg, lb, web, api, svc, fn, db, both, eni, far, clb]

    def edges(self, res):
        return {(r.rid, x["to"].split(":")[-1], x.get("label")) for r in res for x in r.relations if x["kind"] == "may-connect"}

    def test_membership_ports_and_exclusions(self):
        res = self.world()
        links.resolve_links(res)
        got = self.edges(res)
        web_to_app = {(a, b, "tcp 8080, tcp 8443") for a in ("alb", "i-web", "legacy") for b in ("i-api", "c/api", "fn", "i-both")}
        web_to_app.discard(("legacy", "i-api", "tcp 8080, tcp 8443"))      # the CLB already targets i-api: a direct flow
        app_to_db = {(a, b, "tcp 5432") for a in ("i-api", "c/api", "fn", "i-both") for b in ("db", "i-both")} - {("i-both", "i-both", "tcp 5432")}
        self.assertEqual(got, web_to_app | app_to_db)
        self.assertFalse(any("eni-1" in (a, b) or "i-far" in (a, b) for a, b, _l in got))
        self.assertFalse(any(r.type == "ec2:security-group" for r in res if any(x["kind"] == "may-connect" for x in r.relations)))

    def test_old_scans_without_ingress_from_emit_nothing(self):
        res = self.world()
        for r in res:
            r.attrs.pop("ingress_from", None)
        links.resolve_links(res)
        self.assertEqual(self.edges(res), set())

    def test_caps_are_deterministic(self):
        def big():
            res = [mk("ec2:security-group", "sg-a", ingress_from=[]), mk("ec2:security-group", "sg-b", ingress_from=[{"sg": "sg-a", "ports": "all"}])]
            res += [mk("ec2:instance", f"i-a{i:02}", sg_ids=["sg-a"]) for i in range(30)]
            res += [mk("ec2:instance", f"i-b{i:02}", sg_ids=["sg-b"]) for i in range(30)]
            return res
        res = big()
        links.resolve_links(res)
        per_source = [sum(1 for x in r.relations if x["kind"] == "may-connect") for r in res if r.rid.startswith("i-a")]
        self.assertEqual(per_source, [links.MAX_MAY_CONNECT_PER_SOURCE] * 30)
        with mock.patch.object(links, "MAX_MAY_CONNECT", 40):
            first, second = big(), big()
            links.resolve_links(first)
            links.resolve_links(second)
        self.assertEqual(len(self.edges(first)), 40)
        self.assertEqual(self.edges(first), self.edges(second))
        self.assertEqual({a for a, _b, _l in self.edges(first)}, {"i-a00", "i-a01"})      # stable order: lowest keys first


# --------------------------------------------------------------------------- grouping + rules


class TestGroupingWithConnections(unittest.TestCase):
    def test_consumed_queue_and_its_dlq_inherit_but_roles_and_peers_do_not(self):
        fn = mk("lambda:function", "worker", tags={"Project": "shop"}, role="runner", sg_ids=["sg-1"], event_sources=[
            {"arn": sqs_arn("jobs"), "state": "Enabled", "batch": 10, "on_failure": None}])
        jobs = mk("sqs:queue", "jobs", arn=sqs_arn("jobs"), redrive_target=sqs_arn("failed-jobs"))
        dlq = mk("sqs:queue", "failed-jobs", arn=sqs_arn("failed-jobs"))
        topic = mk("sns:topic", "fanout", arn=f"arn:aws:sns:{REGION}:{ACCT}:fanout", subscriber_arns=[sqs_arn("jobs")])
        role = mk("iam:role", "runner", region="global")
        peer = mk("ec2:instance", "i-peer", sg_ids=["sg-2"])
        sg2 = mk("ec2:security-group", "sg-2", ingress_from=[{"sg": "sg-1", "ports": "tcp 80"}])
        res = [fn, jobs, dlq, topic, role, peer, sg2]
        links.resolve_links(res)
        self.assertTrue(rels(fn, "may-connect") and rels(fn, "uses-role"))
        grouping.assign(res, load_config())
        got = {r.rid: (r.project, r.project_source) for r in res}
        self.assertEqual(got["jobs"], ("shop", "inherited"))
        self.assertEqual(got["failed-jobs"], ("shop", "inherited"))         # via the queue it is the dead letter of
        self.assertEqual(got["fanout"], ("shop", "inherited"))
        self.assertEqual(got["runner"][0], grouping.SHARED)                 # a role never inherits a project
        self.assertEqual(got["i-peer"][0], grouping.UNASSIGNED)             # a security-group rule is not ownership
        self.assertNotIn("uses-role", grouping.INHERIT_KINDS)
        self.assertNotIn("may-connect", grouping.INHERIT_KINDS)


def run(resources):
    scan = {"resources": [asdict(r) for r in resources], "accounts": [{"account": ACCT, "profile": "t", "arn": "arn:aws:iam::1:user/x",
                                                                       "regions": [REGION]}], "options": {}, "gaps": [], "audit": []}
    return analyze(scan, load_config(), now=NOW)


class TestRulesIgnoreNewRelations(unittest.TestCase):
    def test_unused_sg_and_stale_role_findings_do_not_change(self):
        old = "2024-01-01T00:00:00Z"
        res = [mk("ec2:security-group", "sg-app", group_name="app", vpc="vpc-1", world_open=[], referenced_by=["sg-db"], ingress_from=[]),
               # sg-db admits sg-app, but nothing is attached to sg-db: still unused
               mk("ec2:security-group", "sg-db", group_name="db", vpc="vpc-1", world_open=[], referenced_by=[],
                  ingress_from=[{"sg": "sg-app", "ports": "tcp 5432"}]),
               mk("ec2:instance", "i-1", state="running", instance_type="t3.micro", sg_ids=["sg-app"], iam_profile="busy-role"),
               mk("ec2:instance", "i-2", state="running", instance_type="t3.micro", sg_ids=["sg-app"]),
               mk("lambda:function", "fn", role="stale-role", runtime="python3.12", arch="arm64", package_type="Zip"),
               mk("iam:role", "stale-role", region="global", path="/", last_used=old),      # referenced, yet unused for years
               mk("iam:role", "busy-role", region="global", path="/", last_used="2026-09-30T00:00:00Z")]
        for r in res:
            if r.type == "iam:role":
                r.created = old
        out = run(res)
        by_rid = {r["rid"]: r for r in out["resources"]}
        self.assertTrue(any(x["kind"] == "uses-role" for x in by_rid["fn"]["relations"]))
        sg_unused = next(f for f in out["findings"] if f["rule"] == "ec2.sg.unused")
        self.assertEqual([k.split(":")[-1] for k in sg_unused["resources"]], ["sg-db"])
        role_unused = next(f for f in out["findings"] if f["rule"] == "sec.iam.role-unused")
        self.assertEqual([k.split(":")[-1] for k in role_unused["resources"]], ["stale-role"])


class TestDemoConnections(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        executor, _world = demo_executor()
        cls.scan = json.loads(json.dumps(run_scan(["demo"], ScanOptions(quiet=True), cli=AwsCli("demo", executor=executor, aws_bin="aws"))))
        cls.analysis = analyze(json.loads(json.dumps(cls.scan)), load_config())
        cls.res = {r["key"]: r for r in cls.analysis["resources"]}

    def rel(self, kind):
        return {(self.res[r["key"]]["name"], self.res[x["to"]]["name"] if x["to"] in self.res else x["to"], x.get("label"))
                for r in self.analysis["resources"] for x in r["relations"] if x["kind"] == kind}

    def test_every_new_kind_appears(self):
        kinds = {x["kind"] for r in self.analysis["resources"] for x in r["relations"]}
        self.assertTrue(NEW_KINDS <= kinds, NEW_KINDS - kinds)
        self.assertEqual(self.scan["gaps"], [])
        self.assertIn(("shop-order-processor", "shop-orders", "batch 10"), self.rel("consumes"))
        self.assertIn(("shop-export", "shop-carts", "batch 100"), self.rel("consumes"))                 # DynamoDB stream -> table
        self.assertIn(("analytics-ingest", "analytics-clicks", "batch 500"), self.rel("consumes"))      # alias-qualified mapping
        self.assertIn(("analytics-compact", "analytics-clicks", "disabled"), self.rel("consumes"))
        self.assertEqual({(a, b) for a, b, _l in self.rel("delivers-to")}, {("shop-order-events", "shop-orders"), ("shop-order-events", "shop-notify")})
        self.assertIn(("shop-orders", "shop-orders-dlq", None), self.rel("dead-letter-to"))
        self.assertIn(("shop-order-processor", "shop-lambda-role", None), self.rel("uses-role"))      # role under /service-role/
        self.assertIn(("shop-checkout", "shop-checkout-task", "task role"), self.rel("uses-role"))
        self.assertIn(("shop public api", "shop-public-api", None), self.rel("origin"))
        self.assertIn(("shop-web-0", "shop-api-1", "tcp 8080"), self.rel("may-connect"))
        self.assertIn(("shop-checkout", "shop-prod-db", "tcp 5432"), self.rel("may-connect"))

    def test_dead_letter_queue_belongs_to_its_project(self):
        dlq = next(r for r in self.analysis["resources"] if r["name"] == "shop-orders-dlq")
        self.assertEqual(dlq["project"], "shop")

    def test_webhook_url_and_token_never_stored(self):
        for name, blob in (("scan", json.dumps(self.scan)), ("analysis", json.dumps(self.analysis))):
            for leaked in (WEBHOOK_TOKEN, "hooks.example.com"):
                self.assertNotIn(leaked, blob, f"{leaked!r} leaked into the {name}")

    def test_new_relations_change_no_finding(self):
        original = links.resolve_links

        def without_new_kinds(resources, *a, **kw):
            original(resources, *a, **kw)
            for r in resources:
                r.relations = [x for x in r.relations if x["kind"] not in NEW_KINDS]

        with mock.patch.object(links, "resolve_links", without_new_kinds):
            baseline = analyze(json.loads(json.dumps(self.scan)), load_config())

        def shape(a):
            return {f["id"]: {k: v for k, v in f.items() if k != "project"} for f in a["findings"]}
        self.assertEqual(shape(self.analysis), shape(baseline))


class TestAllowlistAndContract(unittest.TestCase):
    def test_only_the_event_source_listing_was_added(self):
        self.assertIn(("lambda", "list-event-source-mappings"), allowlist.ALLOWED)
        self.assertIn("lambda:ListEventSourceMappings", policy.all_actions(policy.build_policy()))
        lambda_ops = sorted(o.op for o in allowlist.OPERATIONS if o.service == "lambda")
        self.assertEqual(lambda_ops, ["list-event-source-mappings", "list-functions"])

    def test_new_attrs_are_produced_by_collectors(self):
        attrs, _metrics = produced_keys()
        for key in ("event_sources", "event_sources_known", "subscriber_arns", "ingress_from", "task_role", "exec_role", "node_role",
                    "role", "iam_profile", "redrive_target", "sg_ids"):
            self.assertIn(key, attrs)


if __name__ == "__main__":
    unittest.main()
