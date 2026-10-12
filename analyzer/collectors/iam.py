"""IAM users, access keys and roles: security hygiene (free, so no $ estimates).

Access key ids are masked; secrets are never available through these calls.
"""

from __future__ import annotations

from ..model import Resource, tags_from_list, to_iso

NAME = "iam"
GROUP = "security"
SCOPE = "global"


def _mask(key_id: str) -> str:
    return f"{key_id[:4]}…{key_id[-4:]}" if len(key_id) > 8 else "…"


def collect(ctx) -> list[Resource]:
    return _users(ctx) + _roles(ctx)


def _users(ctx) -> list[Resource]:
    users = ctx.aws("iam", "list-users").get("Users", [])

    def keys(u):
        out = []
        for k in ctx.aws("iam", "list-access-keys", [f"--user-name={u['UserName']}"]).get("AccessKeyMetadata", []):
            last = ctx.aws("iam", "get-access-key-last-used", [f"--access-key-id={k['AccessKeyId']}"]).get("AccessKeyLastUsed") or {}
            out.append({"id": _mask(k["AccessKeyId"]), "status": k.get("Status"), "created": to_iso(k.get("CreateDate")),
                        "last_used": to_iso(last.get("LastUsedDate")), "last_service": last.get("ServiceName")})
        return out

    out = []
    for u, ks in zip(users, ctx.map(keys, users)):
        out.append(ctx.new("iam:user", u["UserName"], name=u["UserName"], state="", created=to_iso(u.get("CreateDate")),
                           arn=u.get("Arn"),
                           # PasswordLastUsed says when a console password was last used, not whether one exists
                           attrs={"password_last_used": to_iso(u.get("PasswordLastUsed")), "access_keys": ks}))
    return out


def _roles(ctx) -> list[Resource]:
    roles = [r for r in ctx.aws("iam", "list-roles").get("Roles", [])
             if not r.get("Path", "/").startswith("/aws-service-role/")]

    def detail(r):
        return ctx.aws("iam", "get-role", [f"--role-name={r['RoleName']}"]).get("Role") or r

    out = []
    for r in ctx.map(detail, roles):
        used = r.get("RoleLastUsed") or {}
        out.append(ctx.new("iam:role", r["RoleName"], name=r["RoleName"], state="", created=to_iso(r.get("CreateDate")),
                           arn=r.get("Arn"), tags=tags_from_list(r.get("Tags")),
                           attrs={"last_used": to_iso(used.get("LastUsedDate")), "last_used_region": used.get("Region"),
                                  "path": r.get("Path"), "description": (r.get("Description") or "")[:120]}))
    return out
