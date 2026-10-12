"""Generate the least-privilege, read-only IAM policy from the allowlist."""

from __future__ import annotations

import json

from . import allowlist

IAM_MANAGED_POLICY_LIMIT = 6144  # characters, whitespace excluded


def build_policy(*, include_cost: bool = False, include_metrics: bool = True) -> dict:
    groups = {allowlist.CORE}
    if include_metrics:
        groups.add(allowlist.METRICS)
    if include_cost:
        groups.add(allowlist.COST)
    scoped = allowlist.RESOURCE_SCOPES
    statements = [
        {
            "Sid": "AwsAnalyzerReadOnly",
            "Effect": "Allow",
            "Action": [a for a in allowlist.iam_actions(groups) if a not in scoped],
            "Resource": "*",
        }
    ]
    for action in sorted(set(allowlist.iam_actions(groups)) & set(scoped)):
        statements.append({
            "Sid": "AwsAnalyzerScoped" + action.replace(":", "").replace("*", ""),
            "Effect": "Allow",
            "Action": [action],
            "Resource": scoped[action],
        })
    return {"Version": "2012-10-17", "Statement": statements}


def policy_size(policy: dict) -> int:
    return len(json.dumps(policy, separators=(",", ":")))


def all_actions(policy: dict) -> list[str]:
    """Every action across all statements (the policy has a main statement plus scoped ones)."""
    return sorted({a for st in policy["Statement"] for a in st["Action"]})


def render(policy: dict) -> str:
    return json.dumps(policy, indent=2) + "\n"
