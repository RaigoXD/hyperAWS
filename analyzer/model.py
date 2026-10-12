"""Normalised resource model shared by collectors, analysis and the viewer."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

GLOBAL = "global"

# Free text that AWS stores verbatim (names, tag keys/values, descriptions) sometimes carries a pasted credential.
# Access-key-like ids are masked the way awscli.redact() masks them (AKIA…WXYZ), with boundaries that also catch
# "x_AKIA…" and "AKIA…_old" (``\b`` treats "_" as part of a word). Ids, keys, ARNs and relations are never touched.
_KEY_ID = re.compile(r"(?<![A-Z0-9])(AKIA|ASIA|AIDA|AROA|AGPA|ANPA)([A-Z0-9]{12,})(?![A-Z0-9])")
# a 40-character secret access key; only masked in a resource whose text also holds a key id
_SECRET_KEY = re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])")
# A name that says its value is a secret (DB_PASSWORD, api-key, ClientSecret, auth_token ...): such a tag's value is
# masked, and so is "<name>=<value>" / "<name>: <value>" inside free text. An ARN is a reference, never the secret.
_SECRET_WORDS = r"passw(?:or)?d|passwd|secret|token|api[-_]?key|private[-_]?key|credential|(?<![a-z])pwd(?![a-z])"
_SECRET_NAME = re.compile(_SECRET_WORDS, re.I)
_SECRET_ASSIGN = re.compile(r"(?<![\w.:/-])([\w.-]*?(?:" + _SECRET_WORDS + r")[\w.-]*)(\s*[=:]\s*)(?!arn:|…redacted…)"
                            r"(\"[^\"]*\"|'[^']*'|[^\s,;\"')\]}]+)", re.I)
# e-mail addresses (an SSO session name, an IAM user name) in the caller ARN and in AWS error messages
_EMAIL = re.compile(r"(?<![\w.%+-])([A-Za-z0-9])[A-Za-z0-9._%+-]*@(?=[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")
REDACTED = "…redacted…"
FREE_TEXT_ATTRS = ("description", "comment")


def mask_secrets(text: str, with_secret: bool = False) -> str:
    """Mask access-key-like ids in ``text`` (and, with ``with_secret``, 40-character secret-key-like tokens)."""
    out = _KEY_ID.sub(lambda m: f"{m.group(1)}…{m.group(2)[-4:]}", text)
    return _SECRET_KEY.sub(REDACTED, out) if with_secret else out


def mask_assignments(text: str) -> str:
    """``DB_PASSWORD=hunter2`` -> ``DB_PASSWORD=…redacted…`` (any secret-like name followed by = or :)."""
    return _SECRET_ASSIGN.sub(lambda m: m.group(1) + m.group(2) + REDACTED, text)


def mask_identity(text: str) -> str:
    """What is logged or saved about the caller and AWS errors: key ids masked, e-mail local parts shortened
    (``jane.doe@corp.example`` -> ``j…@corp.example``)."""
    return _EMAIL.sub(lambda m: m.group(1) + "…@", mask_secrets(text))


@dataclass
class Resource:
    """One AWS component. ``attrs`` holds a *curated whitelist* of fields.

    Collectors copy only the fields they need into ``attrs`` (never a raw API
    dump), so secrets such as Lambda environment variables can't reach disk.
    """

    key: str                       # unique: "<account>:<region>:<type>:<rid>"
    rid: str                       # native id / name (i-0abc, bucket name ...)
    type: str                      # "ec2:instance"
    service: str                   # "ec2"
    account: str
    region: str                    # region name or "global"
    name: str = ""
    state: str = ""
    created: str | None = None     # ISO-8601 UTC
    arn: str | None = None
    tags: dict[str, str] = field(default_factory=dict)
    attrs: dict[str, Any] = field(default_factory=dict)
    relations: list[dict[str, str]] = field(default_factory=list)  # {"to": key, "kind": "...", optional "label"}
    metrics: dict[str, Any] = field(default_factory=dict)
    # filled in by `analyze`
    project: str = ""
    project_source: str = ""
    env: str = ""
    est_monthly_usd: float = 0.0
    cost_basis: str = ""
    cost_conf: str = ""            # high | medium | low | none
    findings: list[str] = field(default_factory=list)  # finding ids

    def __post_init__(self) -> None:
        scrub_free_text(self)

    def link(self, to_key: str, kind: str, label: str | None = None) -> bool:
        """Add a relation once per (target, kind); the first label wins. Returns True if it was added."""
        if any(r["to"] == to_key and r["kind"] == kind for r in self.relations):
            return False
        rel = {"to": to_key, "kind": kind}
        if label:
            rel["label"] = label
        self.relations.append(rel)
        return True


def _strings(value: Any):
    """Every string inside ``value`` (nested lists and dicts; dict values only)."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _strings(v)


def _scrub_in_place(container: dict | list, clean) -> None:
    """Apply ``clean`` to every string inside ``container`` except ARNs, changing the same dict/list objects (a
    collector may still hold a reference to a nested list it fills later)."""
    for k, v in list(container.items() if isinstance(container, dict) else enumerate(container)):
        if isinstance(v, str):
            if not v.startswith("arn:") and clean(v) != v:
                container[k] = clean(v)
        elif isinstance(v, (dict, list)):
            _scrub_in_place(v, clean)


def scrub_free_text(r: Resource) -> None:
    """Mask credentials in a resource's name, tags and attrs (in place; idempotent).

    Access-key-like ids are masked anywhere in the name, tags and attrs (not in ARNs: ids, keys, ARNs and relations
    stay intact). The value of a tag whose key names a secret (``DB_PASSWORD``) and ``<secret-name>=<value>`` in the
    name, tags and description-like attrs are masked too. 40-character secret-key-like tokens are masked only in a
    resource that also holds a key id. Any other free text is kept as AWS returned it.
    """
    with_secret = any(isinstance(t, str) and _KEY_ID.search(t)
                      for t in (r.name, *r.tags, *_strings(r.tags), *_strings(r.attrs)))
    keys = lambda v: mask_secrets(v, with_secret)  # noqa: E731
    text = lambda v: mask_assignments(keys(v))     # noqa: E731
    if isinstance(r.name, str):
        r.name = text(r.name)

    def tag_value(k, v):
        if not isinstance(v, str):
            return v
        secret_key = isinstance(k, str) and _SECRET_NAME.search(k) and v and not v.startswith("arn:")
        return REDACTED if secret_key else text(v)

    masked = {(text(k) if isinstance(k, str) else k): tag_value(k, v) for k, v in r.tags.items()}
    if masked != r.tags:
        r.tags.clear()                  # same dict object: a collector may still hold a reference to it
        r.tags.update(masked)
    _scrub_in_place(r.attrs, keys)
    for k in FREE_TEXT_ATTRS:
        if isinstance(r.attrs.get(k), str):
            r.attrs[k] = text(r.attrs[k])


def make_key(account: str, region: str, rtype: str, rid: str) -> str:
    return f"{account}:{region}:{rtype}:{rid}"


def tags_from_list(items: list[dict] | None, k: str = "Key", v: str = "Value") -> dict[str, str]:
    """AWS tag lists ([{Key,Value}]) -> dict."""
    return {i[k]: i.get(v, "") for i in (items or []) if k in i}


def to_iso(value: Any) -> str | None:
    """Normalise the many timestamp shapes the CLI returns to ISO-8601 UTC."""
    if value in (None, "", 0):
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    s = str(value)
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return s
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def name_from_tags(tags: dict[str, str], fallback: str) -> str:
    return tags.get("Name") or tags.get("name") or fallback
