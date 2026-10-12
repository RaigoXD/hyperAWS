"""ECS (clusters/services), ECR repositories, EKS (clusters/node groups).

Names and ARNs from AWS are always passed glued to their flag (``--cluster=<arn>``), lists as one JSON value
(``--clusters=["arn",...]``), so no value can ever be read as a CLI option.
"""

from __future__ import annotations

import json

from ..model import Resource, to_iso

NAME = "containers"
GROUP = "containers"
SCOPE = "regional"

# never the container definitions (they hold environment variables and secret references)
_TASKDEF_QUERY = ("taskDefinition.{cpu:cpu,memory:memory,arch:runtimePlatform.cpuArchitecture,"
                  "task_role:taskRoleArn,exec_role:executionRoleArn}")
_IMAGES_QUERY = "imageDetails[].{s:imageSizeInBytes,p:imagePushedAt,t:imageTags}"
# same shape as the API answer, minus everything not read below: never connectorConfig (activation code of a
# connected cluster), certificateAuthority, identity or encryption settings
_EKS_CLUSTER_QUERY = ("{cluster:cluster.{name:name,arn:arn,version:version,status:status,createdAt:createdAt,"
                      "roleArn:roleArn,tags:tags,resourcesVpcConfig:{vpcId:resourcesVpcConfig.vpcId},"
                      "computeConfig:{enabled:computeConfig.enabled},upgradePolicy:{supportType:upgradePolicy.supportType}}}")


def _json_list(items) -> str:
    """A list argument as one JSON value (the AWS CLI accepts `--clusters='["a","b"]'`); it starts with '['."""
    return json.dumps(list(items), separators=(",", ":"))


def collect(ctx) -> list[Resource]:
    return _ecs(ctx) + _ecr(ctx) + _eks(ctx)


def _lower_tags(items) -> dict[str, str]:
    return {t["key"]: t.get("value", "") for t in (items or []) if "key" in t}


def _role_name(arn) -> str | None:
    """arn:aws:iam::<acct>:role/<path/>name -> name (role names are unique per account, whatever the path)."""
    if not isinstance(arn, str):
        return None
    return arn.split("/")[-1] or None


def _chunks(seq, n):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


# --------------------------------------------------------------------------- ECS


def _ecs(ctx) -> list[Resource]:
    out: list[Resource] = []
    arns = ctx.aws("ecs", "list-clusters").get("clusterArns", [])
    if not arns:
        return out
    clusters = []
    for chunk in _chunks(arns, 100):
        clusters += ctx.aws("ecs", "describe-clusters", [f"--clusters={_json_list(chunk)}", "--include", "TAGS"]).get("clusters", [])
    taskdefs: dict[str, dict] = {}
    for c in clusters:
        cname = c["clusterName"]
        out.append(ctx.new("ecs:cluster", cname, name=cname, state=c.get("status", ""), arn=c.get("clusterArn"),
                           tags=_lower_tags(c.get("tags")),
                           attrs={"container_instances": c.get("registeredContainerInstancesCount", 0),
                                  "running_tasks": c.get("runningTasksCount", 0),
                                  "active_services": c.get("activeServicesCount", 0)}))
        svc_arns = ctx.aws("ecs", "list-services", [f"--cluster={c['clusterArn']}"]).get("serviceArns", [])
        services = []
        for chunk in _chunks(svc_arns, 10):
            services += ctx.aws("ecs", "describe-services",
                                [f"--cluster={c['clusterArn']}", f"--services={_json_list(chunk)}", "--include", "TAGS"]).get("services", [])
        for td in sorted({s.get("taskDefinition") for s in services if s.get("taskDefinition")} - set(taskdefs)):
            taskdefs[td] = ctx.aws("ecs", "describe-task-definition",
                                   [f"--task-definition={td}", "--query", _TASKDEF_QUERY]) or {}
        for s in services:
            name = s["serviceName"]
            td = taskdefs.get(s.get("taskDefinition"), {})
            net = (s.get("networkConfiguration") or {}).get("awsvpcConfiguration") or {}
            launch = s.get("launchType") or ("CAPACITY_PROVIDER" if s.get("capacityProviderStrategy") else "EC2")
            r = ctx.new("ecs:service", f"{cname}/{name}", name=name, state=s.get("status", ""),
                        created=to_iso(s.get("createdAt")), arn=s.get("serviceArn"),
                        tags=_lower_tags(s.get("tags")),
                        attrs={"cluster": cname, "desired": s.get("desiredCount", 0),
                               "running": s.get("runningCount", 0), "pending": s.get("pendingCount", 0),
                               "launch_type": launch,
                               "capacity_providers": [p.get("capacityProvider") for p in s.get("capacityProviderStrategy", [])],
                               "task_cpu": int(td["cpu"]) if str(td.get("cpu", "")).isdigit() else None,
                               "task_memory": int(td["memory"]) if str(td.get("memory", "")).isdigit() else None,
                               "task_arch": td.get("arch") or "X86_64",
                               "task_role": _role_name(td.get("task_role")), "exec_role": _role_name(td.get("exec_role")),
                               "subnet_ids": net.get("subnets", []), "sg_ids": net.get("securityGroups", [])})
            r.link(ctx.key("ecs:cluster", cname), "in-cluster")
            for lb in s.get("loadBalancers", []):
                tg = lb.get("targetGroupArn", "")
                if "targetgroup/" in tg:
                    r.link(ctx.key("elbv2:target-group", tg.split("targetgroup/")[1].split("/")[0]), "serves")
            for sn in net.get("subnets", []):
                r.link(ctx.key("ec2:subnet", sn), "in-subnet")
            out.append(r)
    return out


# --------------------------------------------------------------------------- ECR


def _ecr(ctx) -> list[Resource]:
    repos = ctx.aws("ecr", "describe-repositories").get("repositories", [])

    def detail(repo):
        name = repo["repositoryName"]
        policy = ctx.aws("ecr", "get-lifecycle-policy", [f"--repository-name={name}"],
                         expect=["LifecyclePolicyNotFoundException"], default=None)
        images = ctx.aws("ecr", "describe-images", [f"--repository-name={name}", "--query", _IMAGES_QUERY],
                         expect=["RepositoryNotFoundException"], default=[])
        # True/False when known; None when the call failed (don't claim "no policy" on AccessDenied)
        has_policy = True if (policy and "lifecyclePolicyText" in policy) else (False if policy is None else None)
        return repo, has_policy, images if isinstance(images, list) else []

    out = []
    for repo, has_policy, images in ctx.map(detail, repos):
        name = repo["repositoryName"]
        pushed = sorted(i["p"] for i in images if i.get("p") is not None)
        out.append(ctx.new("ecr:repository", name, name=name, state="", created=to_iso(repo.get("createdAt")),
                           arn=repo.get("repositoryArn"),
                           attrs={"images": len(images), "untagged_images": sum(1 for i in images if not i.get("t")),
                                  "size_bytes": sum(i.get("s") or 0 for i in images),
                                  "last_push": to_iso(pushed[-1]) if pushed else None,
                                  "has_lifecycle_policy": has_policy,
                                  "scan_on_push": bool((repo.get("imageScanningConfiguration") or {}).get("scanOnPush"))}))
    return out


# --------------------------------------------------------------------------- EKS


def _eks(ctx) -> list[Resource]:
    names = ctx.aws("eks", "list-clusters").get("clusters", [])
    if not names:
        return []
    versions = {v["clusterVersion"]: v for v in
                ctx.aws("eks", "describe-cluster-versions").get("clusterVersions", [])}

    def detail(name):
        cl = (ctx.aws("eks", "describe-cluster", [f"--name={name}", "--query", _EKS_CLUSTER_QUERY]) or {}).get("cluster") or {}
        ngs = ctx.aws("eks", "list-nodegroups", [f"--cluster-name={name}"]).get("nodegroups", [])
        ng_details = [ctx.aws("eks", "describe-nodegroup", [f"--cluster-name={name}", f"--nodegroup-name={g}"]).get("nodegroup")
                      for g in ngs]
        fargate = ctx.aws("eks", "list-fargate-profiles", [f"--cluster-name={name}"]).get("fargateProfileNames", [])
        return name, cl, [g for g in ng_details if g], fargate

    out = []
    for name, cl, ngs, fargate in ctx.map(detail, names):
        if not cl:
            continue
        v = versions.get(cl.get("version"), {})
        vpc = (cl.get("resourcesVpcConfig") or {}).get("vpcId")
        desired = sum((g.get("scalingConfig") or {}).get("desiredSize", 0) for g in ngs)
        r = ctx.new("eks:cluster", name, name=name, state=cl.get("status") or "",   # a --query projection keeps keys, as null
                    created=to_iso(cl.get("createdAt")), arn=cl.get("arn"), tags=dict(cl.get("tags") or {}),
                    attrs={"version": cl.get("version"),
                           # `status` is deprecated (lowercase, hyphenated); `versionStatus` is UPPER_SNAKE
                           "version_status": (v.get("versionStatus") or v.get("status") or "").upper().replace("-", "_") or None,
                           "auto_mode": bool((cl.get("computeConfig") or {}).get("enabled")),   # EKS Auto Mode: no node groups
                           "end_of_standard_support": to_iso(v.get("endOfStandardSupportDate")),
                           "end_of_extended_support": to_iso(v.get("endOfExtendedSupportDate")),
                           "support_policy": (cl.get("upgradePolicy") or {}).get("supportType"),
                           "nodegroups": len(ngs), "fargate_profiles": len(fargate),
                           "desired_nodes": desired, "vpc": vpc, "role": _role_name(cl.get("roleArn"))})
        if vpc:
            r.link(ctx.key("ec2:vpc", vpc), "in-vpc")
        out.append(r)
        for g in ngs:
            sc = g.get("scalingConfig") or {}
            gr = ctx.new("eks:nodegroup", f"{name}/{g['nodegroupName']}", name=g["nodegroupName"],
                         state=g.get("status", ""), created=to_iso(g.get("createdAt")), arn=g.get("nodegroupArn"),
                         tags=dict(g.get("tags") or {}),
                         attrs={"cluster": name, "instance_types": g.get("instanceTypes", []),
                                "desired": sc.get("desiredSize", 0), "min": sc.get("minSize", 0),
                                "max": sc.get("maxSize", 0), "capacity_type": g.get("capacityType"),
                                "ami_type": g.get("amiType"), "disk_gb": g.get("diskSize"),
                                "node_role": _role_name(g.get("nodeRole"))})
            gr.link(r.key, "in-cluster")
            out.append(gr)
    return out
