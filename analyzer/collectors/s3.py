"""S3 buckets: configuration only. Never lists or reads objects.

Bucket size/object counts come from CloudWatch daily storage metrics (see
metrics.py). The resource key uses the pseudo-region "global" because bucket
names are globally unique (CloudFront/Route53 links can then refer to them
without knowing the bucket's region); ``region`` is the bucket's real region.
"""

from __future__ import annotations

from ..model import GLOBAL, Resource, make_key, tags_from_list, to_iso
from ..scan import Failed

NAME = "s3"
GROUP = "data"
SCOPE = "global"

_NO_TAGS = ("NoSuchTagSet",)
_NO_LIFECYCLE = ("NoSuchLifecycleConfiguration",)
_NO_PAB = ("NoSuchPublicAccessBlockConfiguration",)


def bucket_key(account: str, name: str) -> str:
    return make_key(account, GLOBAL, "s3:bucket", name)


def _region(loc: str | None) -> str:
    if not loc:
        return "us-east-1"
    return "eu-west-1" if loc == "EU" else loc


def collect(ctx) -> list[Resource]:
    buckets = ctx.aws("s3api", "list-buckets").get("Buckets", [])

    def detail(b):
        name = b["Name"]
        region = b.get("BucketRegion")
        known = True
        if not region:
            loc = ctx.aws("s3api", "get-bucket-location", [f"--bucket={name}"])
            if isinstance(loc, Failed):
                region, known = "us-east-1", False           # unknown: never infer "empty bucket" from metrics we cannot place
            else:
                region = _region(loc.get("LocationConstraint"))
        kw = {"region": region}
        tags = ctx.aws("s3api", "get-bucket-tagging", [f"--bucket={name}"], expect=_NO_TAGS, default={}, **kw)
        lc = ctx.aws("s3api", "get-bucket-lifecycle-configuration", [f"--bucket={name}"],
                     expect=_NO_LIFECYCLE, default={}, **kw)
        ver = ctx.aws("s3api", "get-bucket-versioning", [f"--bucket={name}"], **kw)
        pab = ctx.aws("s3api", "get-public-access-block", [f"--bucket={name}"], expect=_NO_PAB, default={}, **kw)
        return b, region, known, tags, lc, ver, pab

    out = []
    for b, region, known, tags, lc, ver, pab in ctx.map(detail, buckets):
        name = b["Name"]
        # A failed call (AccessDenied, throttling...) is "unknown" (None), never "not configured": rules only act on False/0.
        rules = None if isinstance(lc, Failed) else [x for x in lc.get("Rules", []) if x.get("Status") == "Enabled"]
        pab_cfg = None if isinstance(pab, Failed) else pab.get("PublicAccessBlockConfiguration", {})
        r = ctx.new("s3:bucket", name, region=region, name=name, state="",
                    created=to_iso(b.get("CreationDate")), arn=f"arn:{ctx.partition}:s3:::{name}",
                    tags=tags_from_list(None if isinstance(tags, Failed) else tags.get("TagSet")),
                    attrs={"region_known": known,
                           "versioning": None if isinstance(ver, Failed) else ver.get("Status", "Unversioned"),
                           "lifecycle_rules": None if rules is None else len(rules),
                           "lc_expiration": None if rules is None else any("Expiration" in x for x in rules),
                           "lc_noncurrent_expiration": None if rules is None else any("NoncurrentVersionExpiration" in x for x in rules),
                           "lc_transition": None if rules is None else any(("Transitions" in x or "NoncurrentVersionTransitions" in x) for x in rules),
                           "lc_abort_multipart": None if rules is None else any("AbortIncompleteMultipartUpload" in x for x in rules),
                           "public_access_blocked": None if pab_cfg is None else (bool(pab_cfg) and all(
                               pab_cfg.get(k) for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")))})
        r.key = bucket_key(ctx.account, name)  # region-independent key (see module docstring)
        out.append(r)
    return out
