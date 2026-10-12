"""Group components into projects and environments.

Resolution order (each assignment records *why*, so the UI can explain it):
  1. explicit ``[[rules]]`` from config           -> source "rule"
  2. project tags (Project/Application/...)       -> "tag:<key>"
  3. CloudFormation stack name                    -> "stack"
  4. name starts with an already-known project    -> "name-match"
  5. relationship inheritance (volume<-instance, TG<-LB, task<-cluster, queue<-consumer ...)  -> "inherited"
  6. common name prefix across several resources  -> "name-prefix"
  7. shared infrastructure (VPC, subnets, SGs, IAM ...) -> "shared"; the rest "Unassigned"
Shared infrastructure never *inherits* a project (a VPC serves many projects).
"""

from __future__ import annotations

import fnmatch
import re
from collections import Counter

from ..model import Resource
from .data import ENV_ALIASES

UNASSIGNED = "Unassigned"
SHARED = "(shared infrastructure)"
# uses-role and may-connect are deliberately absent: one role / one security-group rule often spans many projects
INHERIT_KINDS = {"attached-to", "associated-with", "snapshot-of", "backed-by", "behind", "targets", "serves",
                 "member-of", "in-cluster", "node-of", "logs-of", "replica-of", "uses-eip", "origin",
                 "consumes", "delivers-to", "dead-letter-to"}
SHARED_TYPES = {"ec2:vpc", "ec2:subnet", "ec2:security-group", "ec2:igw", "ec2:vpc-endpoint", "ec2:nat-gateway",
                "iam:user", "iam:role", "kms:key", "route53:hosted-zone"}
_MATCH_KEYS = {"tags", "name_prefix", "name_regex", "stack", "services", "regions", "accounts"}
_JUNK = {"", "none", "n/a", "na", "-", "unknown", "tbd", "null", "default"}
_SKIP_STACK_PREFIXES = ("aws-", "awseb-", "stackset-", "cdk", "serverless-application-repository")
_ID_NAME = re.compile(r"^(i|vol|sg|subnet|vpc|eni|snap|ami|rtb|nat|igw|eipalloc|vpce|lt|eipassoc)-[0-9a-f]+$|^[0-9a-f-]{12,}$|^\d")
_SPLIT = re.compile(r"[-_./: ]+")


# --------------------------------------------------------------------------- env


def norm_env(value: str | None) -> str:
    v = (value or "").strip().lower()
    if v in _JUNK:
        return ""
    return ENV_ALIASES.get(v, v)


def env_from_name(name: str) -> str:
    for tok in _SPLIT.split((name or "").lower()):
        if tok in ENV_ALIASES:
            return ENV_ALIASES[tok]
    return ""


# --------------------------------------------------------------------------- rules


_RULE_KEYS = {"project", "env", "match"}
_LIST_MATCH_KEYS = ("name_prefix", "services", "regions", "accounts")
MAX_PATTERN = 200   # longest name_regex / glob accepted: plenty for a project rule, and it bounds the matching cost


def validate_rules(rules: list[dict]) -> None:
    """Check the ``[[rules]]`` shape, types and patterns; raise ValueError naming the rule.

    Shorthands are normalised in place: a single string where a list is expected (``name_prefix = "chk-"`` must not
    be iterated character by character), and account ids written as TOML integers (leading zeros restored).
    """
    from .config import str_list
    if not isinstance(rules, list) or not all(isinstance(r, dict) for r in rules):
        raise ValueError("rules must be written as [[rules]] tables")
    for i, rule in enumerate(rules):
        if not rule.get("project") or not isinstance(rule["project"], str):
            raise ValueError(f"rules[{i}]: missing 'project' (a non-empty string)")
        where = f"rules[{i}] ({rule['project']})"
        unknown = set(rule) - _RULE_KEYS
        if unknown:
            raise ValueError(f"{where}: unknown key(s) {sorted(unknown)}; allowed: {sorted(_RULE_KEYS)}")
        if "env" in rule and not isinstance(rule["env"], str):
            raise ValueError(f"{where}: env must be a string")
        m = rule.get("match")
        if not isinstance(m, dict) or not m:
            raise ValueError(f"{where}: needs a non-empty [rules.match] table (a rule without conditions never matches)")
        unknown = set(m) - _MATCH_KEYS
        if unknown:
            raise ValueError(f"{where}: unknown match keys {sorted(unknown)}; allowed: {sorted(_MATCH_KEYS)}")
        if "accounts" in m:
            ids = m["accounts"] if isinstance(m["accounts"], list) else [m["accounts"]]
            m["accounts"] = [str(a).zfill(12) if isinstance(a, int) and not isinstance(a, bool) else a for a in ids]
        for key in _LIST_MATCH_KEYS:
            if key in m:
                m[key] = str_list(m[key], f"{where}: match.{key}")
        if any(p == "" for p in m.get("name_prefix", ())):
            raise ValueError(f"{where}: match.name_prefix contains an empty prefix (it would match everything)")
        if "tags" in m:
            if not isinstance(m["tags"], dict):
                raise ValueError(f'{where}: match.tags must be a table, e.g. {{ Team = "payments*" }}')
            for k, v in m["tags"].items():
                if isinstance(v, (int, float)) and not isinstance(v, bool):
                    v = m["tags"][k] = str(v)
                if not isinstance(v, str):
                    raise ValueError(f"{where}: match.tags.{k} must be a string (glob)")
        patterns = [("stack", m["stack"])] if "stack" in m else []
        patterns += [(f"tags.{k}", v) for k, v in m.get("tags", {}).items()]
        patterns += [("name_regex", m["name_regex"])] if "name_regex" in m else []
        patterns += [("name_prefix", v) for v in m.get("name_prefix", ())]
        for key, pat in patterns:
            if not isinstance(pat, str):
                raise ValueError(f"{where}: match.{key} must be a string")
            if len(pat) > MAX_PATTERN:
                raise ValueError(f"{where}: match.{key} is longer than {MAX_PATTERN} characters")
        if "name_regex" in m:
            try:
                re.compile(m["name_regex"], re.I)
            except re.error as e:
                raise ValueError(f"{where}: match.name_regex {m['name_regex']!r} is not a valid regular expression: {e}") from None


def _names(r: Resource) -> list[str]:
    return [n.lower() for n in {r.name, r.rid} if n]


def rule_matches(rule: dict, r: Resource) -> bool:
    m = rule.get("match", {})
    if not m:
        return False
    if "accounts" in m and r.account not in m["accounts"]:
        return False
    if "regions" in m and r.region not in m["regions"]:
        return False
    if "services" in m and not (r.service in m["services"] or r.type in m["services"]):
        return False
    if "tags" in m:
        lower = {k.lower(): v for k, v in r.tags.items()}
        for k, pat in m["tags"].items():
            v = lower.get(k.lower())
            if v is None or not fnmatch.fnmatch(v.lower(), str(pat).lower()):
                return False
    if "stack" in m:
        stack = r.tags.get("aws:cloudformation:stack-name", "")
        if not stack or not fnmatch.fnmatch(stack.lower(), m["stack"].lower()):
            return False
    if "name_prefix" in m and not any(n.startswith(p.lower()) for n in _names(r) for p in m["name_prefix"]):
        return False
    if "name_regex" in m and not any(re.search(m["name_regex"], n, re.I) for n in _names(r)):
        return False
    return True


# --------------------------------------------------------------------------- main


def assign(resources: list[Resource], cfg: dict) -> dict:
    pcfg = cfg["projects"]
    rules = cfg.get("rules", [])
    validate_rules(rules)
    for r in resources:
        r.project = r.project_source = r.env = ""

    _env_pass(resources, pcfg)
    _rules_pass(resources, rules)
    _tag_pass(resources, pcfg)
    if pcfg.get("use_stack_name", True):
        _stack_pass(resources)
    _name_match_pass(resources)
    _propagate(resources)
    if pcfg.get("use_name_prefix", True):
        _prefix_pass(resources, pcfg)
        _propagate(resources)
    for r in resources:
        if not r.project:
            r.project, r.project_source = (SHARED, "shared") if r.type in SHARED_TYPES else (UNASSIGNED, "")
    _canonical_case(resources)
    _propagate_env(resources)
    return summarize_sources(resources)


def _env_pass(resources: list[Resource], pcfg: dict) -> None:
    lower_keys = [k.lower() for k in pcfg["env_tag_keys"]]
    for r in resources:
        tags = {k.lower(): v for k, v in r.tags.items()}
        for k in lower_keys:
            e = norm_env(tags.get(k))
            if e:
                r.env = e
                break
        if not r.env:
            r.env = env_from_name(r.name) or env_from_name(r.rid)


def _rules_pass(resources: list[Resource], rules: list[dict]) -> None:
    for r in resources:
        for rule in rules:
            if rule_matches(rule, r):
                r.project, r.project_source = rule["project"], "rule"
                if rule.get("env"):
                    r.env = rule["env"]
                break


def _tag_pass(resources: list[Resource], pcfg: dict) -> None:
    """Project from tags; key matching ignores case (Project / project / PROJECT are the same intent)."""
    keys = list(dict.fromkeys(k.lower() for k in pcfg["tag_keys"]))
    for r in resources:
        if r.project:
            continue
        actual = {k.lower(): k for k in r.tags}
        for k in keys:
            if k not in actual:
                continue
            v = (r.tags[actual[k]] or "").strip()
            if v.lower() not in _JUNK:
                r.project, r.project_source = v, f"tag:{actual[k]}"
                break


_STACK_CONSOLE_PREFIX = re.compile(r"^Infra-ECS-(?:Cluster|Service)-", re.I)
_STACK_HASH_SUFFIX = re.compile(r"-[0-9a-f]{8}$")


def clean_stack_name(stack: str) -> str:
    """Console-generated stacks (Infra-ECS-Cluster-<name>-<hash>) -> the human part (<name>)."""
    cleaned = _STACK_HASH_SUFFIX.sub("", _STACK_CONSOLE_PREFIX.sub("", stack))
    return cleaned or stack


def _stack_pass(resources: list[Resource]) -> None:
    for r in resources:
        if r.project:
            continue
        stack = r.tags.get("aws:cloudformation:stack-name", "")
        if not stack or stack.lower().startswith(_SKIP_STACK_PREFIXES):
            continue
        if stack.lower().startswith("eksctl-"):
            stack = stack.split("-")[1] if stack.count("-") >= 2 else stack
        r.project, r.project_source = clean_stack_name(stack), "stack"


def _name_match_pass(resources: list[Resource]) -> None:
    known = {r.project.lower(): r.project for r in resources if r.project}
    if not known:
        return
    for r in resources:
        if r.project or r.type in SHARED_TYPES:
            continue
        for n in _names(r):
            toks = _SPLIT.split(n)
            for proj_l, proj in known.items():
                if n.startswith(proj_l + "-") or n.startswith(proj_l + "_") or n.startswith(proj_l + "/") \
                        or (len(proj_l) >= 4 and proj_l in toks):
                    r.project, r.project_source = proj, "name-match"
                    break
            if r.project:
                break


def _adjacency(resources: list[Resource]) -> dict[str, set[str]]:
    keys = {r.key for r in resources}
    adj: dict[str, set[str]] = {}
    for r in resources:
        for rel in r.relations:
            if rel["kind"] in INHERIT_KINDS and rel["to"] in keys:
                adj.setdefault(r.key, set()).add(rel["to"])
                adj.setdefault(rel["to"], set()).add(r.key)
    return adj


def _propagate(resources: list[Resource]) -> None:
    by_key = {r.key: r for r in resources}
    adj = _adjacency(resources)
    for _ in range(8):
        updates: dict[str, tuple[str, str]] = {}
        for r in sorted(resources, key=lambda x: x.key):
            if r.project or r.type in SHARED_TYPES or r.key not in adj:
                continue
            votes = Counter(by_key[k].project for k in sorted(adj[r.key]) if by_key[k].project
                            and by_key[k].type not in SHARED_TYPES)
            if not votes:
                continue
            top = votes.most_common(2)
            if len(top) == 2 and top[0][1] == top[1][1]:
                continue  # ambiguous: leave for explicit rules
            updates[r.key] = (top[0][0], "inherited")
        if not updates:
            break
        for k, (proj, src) in updates.items():
            by_key[k].project, by_key[k].project_source = proj, src


def _propagate_env(resources: list[Resource]) -> None:
    by_key = {r.key: r for r in resources}
    adj = _adjacency(resources)
    for _ in range(4):
        updates = {}
        for r in resources:
            if r.env or r.type in SHARED_TYPES or r.key not in adj:
                continue
            votes = Counter(by_key[k].env for k in adj[r.key] if by_key[k].env and by_key[k].type not in SHARED_TYPES)
            if len(votes) == 1:
                updates[r.key] = next(iter(votes))
        if not updates:
            break
        for k, e in updates.items():
            by_key[k].env = e


def _prefix_token(r: Resource, generic: set[str]) -> str | None:
    name = r.name or ""
    if not name or name == r.rid and _ID_NAME.match(name):
        return None
    if _ID_NAME.match(name):
        return None
    tok = _SPLIT.split(name.lower().lstrip("/"))[0]
    if len(tok) < 3 or tok in generic or tok in ENV_ALIASES or tok.isdigit() or _ID_NAME.match(tok):
        return None
    return tok


def _prefix_pass(resources: list[Resource], pcfg: dict) -> None:
    generic = set(pcfg["generic_tokens"])
    groups: dict[str, list[Resource]] = {}
    for r in resources:
        if r.project or r.type in SHARED_TYPES or r.type.startswith("other:"):
            continue
        tok = _prefix_token(r, generic)
        if tok:
            groups.setdefault(tok, []).append(r)
    for tok, rs in groups.items():
        if len(rs) >= pcfg["min_prefix_group"] and len({r.type for r in rs}) >= 2:
            for r in rs:
                r.project, r.project_source = tok, "name-prefix"


def _canonical_case(resources: list[Resource]) -> None:
    counts: dict[str, Counter] = {}
    for r in resources:
        if r.project and r.project not in (UNASSIGNED, SHARED):
            counts.setdefault(r.project.lower(), Counter())[r.project] += 1
    # most frequent spelling wins; ties go to the all-lowercase spelling, then alphabetical (never input order)
    canon = {low: min(c.items(), key=lambda kv: (-kv[1], kv[0] != kv[0].lower(), kv[0]))[0] for low, c in counts.items()}
    for r in resources:
        if r.project.lower() in canon:
            r.project = canon[r.project.lower()]


def summarize_sources(resources: list[Resource]) -> dict:
    c = Counter(r.project_source.split(":")[0] or "none" for r in resources)
    return dict(c)


# --------------------------------------------------------------------------- suggestions


def suggest_rules(resources: list[Resource]) -> list[dict]:
    """Rules that would reproduce the current tag/prefix-derived grouping (for bootstrapping config)."""
    out: list[dict] = []
    seen: set[tuple] = set()
    for r in sorted(resources, key=lambda x: (x.project.lower(), x.key)):
        if r.project in (UNASSIGNED, SHARED) or r.project_source == "rule":
            continue
        src = r.project_source.split(":")
        if src[0] == "tag":
            key = (r.project, "tag", src[1])
            if key not in seen:
                seen.add(key)
                out.append({"project": r.project, "match": {"tags": {src[1]: r.tags[src[1]]}}, "_why": "tag"})
        elif src[0] == "name-prefix":
            key = (r.project, "prefix")
            if key not in seen:
                seen.add(key)
                out.append({"project": r.project, "match": {"name_prefix": [r.project + "-"]}, "_why": "name prefix"})
        elif src[0] == "stack":
            key = (r.project, "stack")
            if key not in seen:
                seen.add(key)
                out.append({"project": r.project, "match": {"stack": r.project}, "_why": "CloudFormation stack"})
    return out


def rules_to_toml(rules: list[dict]) -> str:
    def q(s: str) -> str:
        return '"' + str(s).replace("\\", "\\\\").replace('"', '\\"') + '"'
    lines = ["# Suggested project rules (inferred). Review, rename and move into config/analyzer.toml.", ""]
    for rule in rules:
        lines.append(f"# inferred from: {rule['_why']}")
        lines.append("[[rules]]")
        lines.append(f"project = {q(rule['project'])}")
        lines.append("[rules.match]")
        for k, v in rule["match"].items():
            if k == "tags":
                lines.append("tags = { " + ", ".join(f"{q(a)} = {q(b)}" for a, b in v.items()) + " }")
            elif isinstance(v, list):
                lines.append(f"{k} = [" + ", ".join(q(x) for x in v) + "]")
            else:
                lines.append(f"{k} = {q(v)}")
        lines.append("")
    return "\n".join(lines)
