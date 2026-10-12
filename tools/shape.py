#!/usr/bin/env python3
"""Print the exact response shape of an AWS operation from the AWS CLI's bundled botocore model.

Purely local: reads JSON files from the AWS CLI installation. Makes NO AWS calls and starts no `aws` process.

  python3 tools/shape.py ec2 describe-instances
  python3 tools/shape.py rds describe-db-instances --depth 4
  python3 tools/shape.py --find DBInstanceClass          # which services/operations mention a member name

Types are shown as botocore names: string, integer, long, boolean, timestamp, structure, list<...>, map<...>.
The AWS CLI v2 prints timestamps as ISO-8601 strings, except where a service returns epoch numbers itself.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

DATA = Path("/usr/local/aws-cli/awscli/botocore/data")
SERVICE_DIR = {"s3api": "s3", "stepfunctions": "stepfunctions", "cloudwatch": "cloudwatch"}


def load(service: str) -> dict:
    d = DATA / SERVICE_DIR.get(service, service)
    versions = sorted(p for p in d.iterdir() if p.is_dir())
    if not versions:
        raise SystemExit(f"no model for service {service!r} under {d}")
    f = versions[-1] / "service-2.json"
    if not f.exists():
        raise SystemExit(f"missing {f}")
    return json.loads(f.read_text())


def camel(op: str) -> str:
    return "".join(p.capitalize() for p in op.split("-"))


def describe(shapes: dict, name: str, depth: int, indent: int = 0, seen: tuple = ()) -> list[str]:
    sh = shapes[name]
    t = sh["type"]
    pad = "  " * indent
    if t == "structure":
        if name in seen or depth <= 0:
            return [f"{pad}(structure {name} …)"]
        out = []
        req = set(sh.get("required", []))
        for m, ref in sh.get("members", {}).items():
            tgt = shapes[ref["shape"]]
            label = _label(shapes, ref["shape"])
            out.append(f"{pad}{m}{'*' if m in req else ''}: {label}")
            if tgt["type"] in ("structure", "list", "map"):
                out += describe(shapes, ref["shape"], depth - 1, indent + 1, seen + (name,))
        return out
    if t == "list":
        inner = sh["member"]["shape"]
        return describe(shapes, inner, depth, indent, seen) if shapes[inner]["type"] in ("structure", "list", "map") else []
    if t == "map":
        v = sh["value"]["shape"]
        return describe(shapes, v, depth, indent, seen) if shapes[v]["type"] in ("structure", "list", "map") else []
    return []


def _label(shapes: dict, name: str) -> str:
    sh = shapes[name]
    t = sh["type"]
    if t == "list":
        return f"list<{_label(shapes, sh['member']['shape'])}>"
    if t == "map":
        return f"map<{_label(shapes, sh['key']['shape'])},{_label(shapes, sh['value']['shape'])}>"
    if t == "string" and sh.get("enum"):
        return "string(enum: " + "|".join(sh["enum"][:6]) + ("|…" if len(sh["enum"]) > 6 else "") + ")"
    return t


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("service", nargs="?")
    ap.add_argument("operation", nargs="?")
    ap.add_argument("--depth", type=int, default=5)
    ap.add_argument("--input", action="store_true", help="show the request shape instead")
    ap.add_argument("--find", help="member name to search for across all services' operation outputs")
    args = ap.parse_args()
    if args.find:
        for d in sorted(DATA.iterdir()):
            if not d.is_dir() or d.name.startswith("_"):
                continue
            try:
                m = load(d.name)
            except SystemExit:
                continue
            for op, spec in m["operations"].items():
                out = spec.get("output", {}).get("shape")
                if out and args.find in "\n".join(describe(m["shapes"], out, 6)):
                    print(f"{d.name} {op}")
        return 0
    if not (args.service and args.operation):
        ap.error("service and operation are required")
    m = load(args.service)
    op = m["operations"].get(camel(args.operation))
    if op is None:
        raise SystemExit(f"{args.service} has no operation {camel(args.operation)}; known: {', '.join(sorted(m['operations']))[:300]} ...")
    key = "input" if args.input else "output"
    shape = op.get(key, {}).get("shape")
    print(f"# {args.service} {args.operation} -> {key} ({m['metadata'].get('protocol')}, apiVersion {m['metadata'].get('apiVersion')})")
    if not shape:
        print("(empty)")
        return 0
    print("\n".join(describe(m["shapes"], shape, args.depth)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
