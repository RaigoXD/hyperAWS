"""Command line interface: ``python3 -m analyzer <command>``."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from . import __version__, allowlist, audit, policy
from .awscli import AccessDenied, AuthError, AwsCli, AwsCliError, NotAvailable
from .fsutil import UnsafeOutputPath, data_home, write_private

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = data_home() / "output"
# AuthError codes about the aws binary itself (awscli.resolve_aws_bin), which signing in would not fix
_AWS_CLI_HINTS = {
    "NoAwsCli": "Install AWS CLI v2 (https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html), "
                "or give its absolute path in AWS_ANALYZER_AWS_BIN.",
    "AwsCliRefused": "Nothing was sent to AWS. Fix what the message names (install AWS CLI v2 in a normal location, run "
                     "from another directory, or remove the alias), then run the command again.",
}


# --------------------------------------------------------------------------
# doctor


def cmd_doctor(args: argparse.Namespace) -> int:
    cli = AwsCli()
    try:
        version = cli.cli_version()
    except AuthError as e:
        print(f"✗ {e}\n  {_AWS_CLI_HINTS.get(e.code, _AWS_CLI_HINTS['NoAwsCli'])}")
        return 1
    print(f"✓ aws cli {version}")
    if not version.startswith("aws-cli/2"):
        print("  ! AWS CLI v2 is recommended (automatic pagination, SSO).")
    profiles = cli.local_profiles()
    print(f"✓ local profiles: {', '.join(profiles) or '(none)'}")
    wanted = args.profile
    if not wanted:
        print("\nNo AWS call was made. Choose the profile(s) to check explicitly, e.g.:\n"
              "  python3 -m analyzer doctor --profile <name>")
        return 0
    rc = 0
    for prof in wanted:
        rc |= _doctor_profile(cli.with_profile(prof), prof, profiles)
    print("\nThis tool only ever runs read-only calls from analyzer/allowlist.py.")
    print("For a hard guarantee, run it with a read-only IAM principal:  python3 -m analyzer policy")
    return rc


def _doctor_profile(cli: AwsCli, prof: str, known: list[str]) -> int:
    print(f"\n== profile: {prof} ==")
    if prof not in known:
        print(f"✗ profile '{prof}' is not configured locally")
        return 1
    try:
        ident = cli.call("sts", "get-caller-identity", region="us-east-1")
    except AuthError as e:
        if e.code in _AWS_CLI_HINTS:
            print(f"✗ {e}\n  {_AWS_CLI_HINTS[e.code]}")
            return 1
        print(f"✗ cannot authenticate: {e}")
        print(f"  Sign in yourself (this tool never does), e.g.:  aws sso login --profile {prof}")
        return 1
    except AwsCliError as e:
        print(f"✗ sts get-caller-identity failed: {e} ({e.code})")
        return 1
    print(f"✓ account {ident.get('Account')}  as  {ident.get('Arn')}")
    if str(ident.get("Arn", "")).endswith(":root"):
        print("  ! these are ROOT credentials. Please use a dedicated read-only principal.")
    try:
        regs = cli.call("ec2", "describe-regions", region="us-east-1").get("Regions", [])
    except AwsCliError as e:
        print(f"✗ ec2 describe-regions failed: {e} ({e.code})")
        return 1
    names = sorted(r["RegionName"] for r in regs)
    print(f"✓ {len(names)} enabled regions")
    home = "us-east-1" if "us-east-1" in names else names[0]
    one = ["--max-items", "1"]
    # Literal calls (not data-driven) so audit.py can verify every operation. Operations whose answer holds a secret
    # (allowlist.QUERY_REQUIRED) project it away with --query, here too: Lambda env vars, CloudFront origin headers.
    probes = [
        ("EC2", lambda: cli.call("ec2", "describe-addresses", region=home)),
        ("ELB", lambda: cli.call("elbv2", "describe-load-balancers", one, region=home)),
        ("RDS", lambda: cli.call("rds", "describe-db-instances", one, region=home)),
        ("DynamoDB", lambda: cli.call("dynamodb", "list-tables", one, region=home)),
        ("S3", lambda: cli.call("s3api", "list-buckets", region=home)),
        ("Lambda", lambda: cli.call("lambda", "list-functions", [*one, "--query", "Functions[].FunctionName"], region=home)),
        ("ECS", lambda: cli.call("ecs", "list-clusters", one, region=home)),
        ("CloudFront", lambda: cli.call("cloudfront", "list-distributions", ["--query", "DistributionList.Items[].Id"],
                                        region="us-east-1")),
        ("Route53", lambda: cli.call("route53", "list-hosted-zones", one, region="us-east-1")),
        ("IAM", lambda: cli.call("iam", "list-users", one, region="us-east-1")),
        ("CloudWatch Logs", lambda: cli.call("logs", "describe-log-groups", one, region=home)),
        ("Tagging API", lambda: cli.call("resourcegroupstaggingapi", "get-resources", one, region=home)),
    ]
    for label, probe in probes:
        try:
            probe()
            print(f"  ✓ {label}")
        except (AccessDenied, NotAvailable) as e:
            print(f"  ✗ {label}: {e.code} (will appear as a coverage gap)")
        except AwsCliError as e:
            print(f"  ✗ {label}: {e.code}: {str(e)[:100]}")
    return 0  # gaps are reported, not fatal



# --------------------------------------------------------------------------
# scan / analyze / report / run / demo


def _latest(prefix: str, out_dir: Path) -> Path:
    from .report import latest
    p = latest(out_dir, prefix)
    if p is None:
        raise SystemExit(f"no {prefix}-*.json found in {out_dir}; run the previous stage first")
    return p


# us-east-1, us-gov-west-1, us-isob-east-1, eusc-de-east-1 ... (the first part is not always two letters)
_REGION = re.compile(r"[a-z]{2,}(-[a-z]+)+-\d+")


def _parse_regions(value: str | None) -> list[str] | None:
    """``--regions``: None (or 'all') means every enabled region; otherwise distinct, well-formed region names."""
    if value is None or value.strip() == "all":
        return None
    regions: list[str] = []
    for r in (x.strip() for x in value.split(",")):
        if not r:
            raise SystemExit("--regions: empty entry; give comma-separated region names (e.g. us-east-1,eu-west-1) or 'all'")
        if not _REGION.fullmatch(r):
            raise SystemExit(f"--regions: {_safe(r)!r} is not a region name (e.g. us-east-1); use 'all' alone for every region")
        if r not in regions:          # a duplicate would scan (and count the cost of) every resource twice
            regions.append(r)
    return regions


def _scan_options(args: argparse.Namespace):
    from .scan import ScanOptions
    return ScanOptions(
        regions=_parse_regions(args.regions),
        services=[s.strip() for s in args.services.split(",")] if args.services else None,
        metrics=not args.no_metrics, metrics_days=args.metrics_days, cost_explorer=args.cost_explorer,
        workers=args.workers, quiet=args.quiet)


def _print_plan(scan: dict) -> None:
    from collections import Counter
    calls = Counter((c["service"], c["op"]) for c in scan["audit"])
    print("\nDRY RUN: nothing was sent to AWS. First-level read calls that WOULD be made "
          "(per-resource follow-ups such as per-bucket or per-table calls, and CloudWatch metric batches, add more):\n")
    for (svc, op), n in sorted(calls.items()):
        print(f"  aws {svc} {op:<40} x{n}")
    print(f"\n{sum(calls.values())} calls across {len(calls)} distinct read operations. All are on the read-only allowlist.")


def _config(args: argparse.Namespace) -> dict:
    """Load and validate analyzer.toml up front, so a bad config fails before any AWS call, with a readable message."""
    from .analysis.config import ConfigError, load_config
    try:
        return load_config(getattr(args, "config", None))
    except (ConfigError, FileNotFoundError) as e:
        raise SystemExit(f"config error: {e}")


_STAGE_PREFIX = re.compile(r"^(?:scan|analysis)-")


def _stage_out(src: Path, out_dir: Path, prefix: str, suffix: str) -> Path:
    """``<out_dir>/<prefix>-<stem><suffix>``, where stem is the input name without its extension and its scan-/analysis-
    prefix (scan-1-T.json -> analysis-1-T.json; myscan.json -> analysis-myscan.json). Never the input itself."""
    stem = _STAGE_PREFIX.sub("", src.stem) or "unnamed"
    out = out_dir / f"{prefix}-{stem}{suffix}"
    _refuse_overwrite(src, out)
    return out


def _refuse_overwrite(src: Path, out: Path) -> None:
    same = out.resolve() == src.resolve()
    if not same and out.exists():
        try:
            same = out.samefile(src)          # a hard link or another path to the same file
        except OSError:
            pass
    if same:
        raise SystemExit(f"refusing to overwrite the input {src} with its own output; pass a different --out-dir")


def _do_scan(args: argparse.Namespace, cli=None, *, profiles=None) -> dict | None:
    from .scan import run_scan, write_scan
    profiles = profiles or args.profile
    if not profiles:
        raise SystemExit("--profile is required: choose which AWS profile(s) to scan "
                         "(see `python3 -m analyzer doctor`). Nothing is scanned by default.")
    opts = _scan_options(args)
    cli = cli or AwsCli(dry_run=args.dry_run)
    scan = run_scan(profiles, opts, cli=cli)
    if args.dry_run:
        _print_plan(scan)
        return None
    path = write_scan(scan, Path(args.out_dir))
    print(f"scan: {len(scan['resources'])} resources, {len(scan['gaps'])} coverage gap(s), "
          f"{len(scan['audit'])} read-only API calls in {scan['duration_s']}s -> {path}", file=sys.stderr)
    scan["_path"] = str(path)
    return scan


def _do_analyze(scan: dict, scan_path: Path, args: argparse.Namespace, cfg: dict | None = None) -> dict:
    from .analysis.engine import analyze
    from .report import json_text
    out = _stage_out(scan_path, Path(args.out_dir), "analysis", ".json")
    result = analyze(scan, cfg if cfg is not None else _config(args))
    write_private(out, json_text(result, separators=(",", ":")))
    s = result["summary"]
    print(f"analysis: {s['resources']} resources in {len(result['projects'])} projects, est. ${s['est_monthly_usd']:,.0f}/month, "
          f"{s['findings']} findings, potential savings ${s['potential_savings_usd']:,.0f}/month -> {out}", file=sys.stderr)
    result["_path"] = str(out)
    return result


def _do_report(analysis: dict, analysis_path: Path, out_dir: Path) -> Path:
    from .report import write_report
    out = _stage_out(analysis_path, out_dir, "report", ".html")
    copy = out_dir / "report.html"
    _refuse_overwrite(analysis_path, copy)
    write_report(analysis, out)
    write_report(analysis, copy)
    print(f"report: {out}\n        (latest copy: {copy})", file=sys.stderr)
    _warn_stale_reports(out_dir)
    return out


def _warn_stale_reports(out_dir: Path) -> None:
    """Point out older report files in the folder that lack the current page protection (they are never deleted here:
    regenerating or deleting them is the user's choice)."""
    from .report import stale_reports
    stale = stale_reports(out_dir)
    if stale:
        names = ", ".join(_safe(p.name) for p in stale[:5]) + (f" and {len(stale) - 5} more" if len(stale) > 5 else "")
        print(f"! {len(stale)} older report file(s) in {_safe(out_dir)} were built by an earlier viewer without the current "
              f"Content-Security-Policy: {names}.\n  They hold the same kind of data with weaker browser protection; "
              "regenerate them (python3 -m analyzer report <its analysis-*.json>) or delete them.", file=sys.stderr)


def cmd_scan(args: argparse.Namespace) -> int:
    _do_scan(args)
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    cfg = _config(args)
    path = Path(args.scan) if args.scan else _latest("scan", Path(args.out_dir))
    _do_analyze(json.loads(path.read_text()), path, args, cfg)
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    if args.empty:
        from .report import write_report
        out = write_report(None, Path(args.out_dir) / "viewer.html")
        print(f"empty viewer (drop an analysis-*.json onto it): {out}")
        _warn_stale_reports(Path(args.out_dir))
        return 0
    path = Path(args.analysis) if args.analysis else _latest("analysis", Path(args.out_dir))
    _do_report(json.loads(path.read_text()), path, Path(args.out_dir))
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    cfg = _config(args)                 # a config mistake must not surface only after a long (and possibly billed) scan
    scan = _do_scan(args)
    if scan is None:
        return 0
    path = Path(scan.pop("_path"))
    analysis = _do_analyze(scan, path, args, cfg)
    _do_report(analysis, Path(analysis.pop("_path")), Path(args.out_dir))
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    """Run the full pipeline against a synthetic, offline AWS account (FakeAws)."""
    from .demo import CALLER, demo_executor
    cfg = _config(args)
    executor, _world = demo_executor()
    cli = AwsCli("demo", executor=executor, aws_bin="aws")
    args.out_dir = str(Path(args.out_dir) / "demo")
    args.profile, args.dry_run, args.regions, args.services = ["demo"], False, None, None
    args.no_metrics, args.metrics_days, args.cost_explorer, args.workers, args.quiet = False, 14, False, 8, True
    scan = _do_scan(args, cli=cli)
    path = Path(scan.pop("_path"))
    analysis = _do_analyze(scan, path, args, cfg)
    out = _do_report(analysis, Path(analysis.pop("_path")), Path(args.out_dir))
    print("\nThis is SYNTHETIC data (no AWS access was used). Open it with:  open " + str(out.parent / "report.html"))
    return 0



_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]")


def _safe(text) -> str:
    """Resource names/tags/messages are untrusted: strip control characters (terminal escapes, newlines) before printing."""
    return _CTRL.sub("?", str(text))[:300]


def cmd_summary(args: argparse.Namespace) -> int:
    """Plain-text digest of an analysis file (what the skill reads out; no AWS calls).

    The file may come from someone else: every printed text goes through _safe() and every number through int()/float(),
    so a crafted file can neither emit terminal escapes nor smuggle text into a numeric column.
    """
    path = Path(args.analysis) if args.analysis else _latest("analysis", Path(args.out_dir))
    try:
        lines = _summary_lines(json.loads(path.read_text()), _safe(path.name), args.top)
    except (KeyError, TypeError, ValueError, AttributeError) as e:
        raise SystemExit(f"{_safe(path.name)} does not look like an analysis file ({type(e).__name__}: {_safe(e)})")
    print("\n".join(lines))
    return 0


def _summary_lines(d: dict, name: str, top_n: int) -> list[str]:
    s = d["summary"]
    usd = lambda x: f"${float(x):,.0f}"  # noqa: E731
    sev = {_safe(k): int(v) for k, v in dict(s["severities"]).items()}
    out = [name,
           f"accounts: {', '.join(_safe(a['account']) for a in d['accounts'])}   scanned: {_safe(d.get('scanned_at'))}",
           f"resources: {int(s['resources'])}   projects: {len(d['projects'])}   estimated cost: {usd(s['est_monthly_usd'])}/month",
           f"potential savings: {usd(s['potential_savings_usd'])}/month ({usd(s['potential_savings_confident_usd'])} high/medium confidence)",
           f"findings: {int(s['findings'])}  {sev}   coverage gaps: {int(s['gaps'])}",
           "", "projects (estimated $/month):"]
    for p in d["projects"][:10]:
        out.append(f"  {_safe(p['name']):<28} {int(p['resources']):>4} resources  {usd(p['est_monthly_usd']):>8}  savings {usd(p['savings_usd'])}")
    top = [f for f in d["findings"] if f["in_total"] and float(f["savings_usd"]) > 0][:top_n]
    out += ["", f"top {len(top)} savings opportunities:"]
    for f in top:
        out.append(f"  {usd(f['savings_usd']):>7}/mo  [{_safe(f['severity'])}/{_safe(f['confidence'])}] {_safe(f['title'])}  "
                   f"({_safe(f['project'] or '-')} {_safe(f['region'] or '')})")
    sec = [f for f in d["findings"] if f["category"] == "security" and f["severity"] == "high"]
    if sec:
        out += ["", "high-severity security findings:"]
        out += [f"  - {_safe(f['title'])}" for f in sec[:8]]
    if d["gaps"]:
        out += ["", "coverage gaps (data missing, not zero):"]
        for g in d["gaps"][:8]:
            out.append(f"  - {_safe(g['service'])} {_safe(g['op'])} {_safe(g['region'])}: {_safe(g['code'])} x{int(g.get('count', 1))}")
    return out


def cmd_suggest(args: argparse.Namespace) -> int:
    from .analysis import grouping
    from .analysis.engine import analyze
    from .model import Resource
    cfg = _config(args)
    path = Path(args.file) if args.file else _latest("scan", Path(args.out_dir))
    data = json.loads(path.read_text())
    if "findings" not in data:
        data = analyze(data, cfg)
    resources = [Resource(**r) for r in data["resources"]]
    print(grouping.rules_to_toml(grouping.suggest_rules(resources)))
    return 0


# --------------------------------------------------------------------------
# policy / audit


def cmd_policy(args: argparse.Namespace) -> int:
    if args.write_config:
        cfg = ROOT / "config"
        cfg.mkdir(exist_ok=True)
        for name, kw in (("readonly-policy.json", {}), ("readonly-policy-with-cost.json", {"include_cost": True})):
            (cfg / name).write_text(policy.render(policy.build_policy(**kw)))
            print(f"wrote config/{name}")
        return 0
    pol = policy.build_policy(include_cost=args.with_cost, include_metrics=not args.no_metrics)
    size = policy.policy_size(pol)
    sys.stdout.write(policy.render(pol))
    print(f"# {len(policy.all_actions(pol))} read-only actions, {size} chars "
          f"(managed-policy limit {policy.IAM_MANAGED_POLICY_LIMIT})", file=sys.stderr)
    return 0 if size <= policy.IAM_MANAGED_POLICY_LIMIT else 1


def cmd_audit(args: argparse.Namespace) -> int:
    rep = audit.run_audit()
    print(f"audited {rep.files} python files; {len(rep.used)} distinct AWS operations in use; "
          f"{len(allowlist.ALLOWED)} allowlisted")
    if rep.unused:
        print("  note: allowlisted but unused (remove to keep the IAM policy minimal): "
              + ", ".join(f"{s} {o}" for s, o in rep.unused))
    if rep.violations:
        print("\n✗ READ-ONLY AUDIT FAILED:")
        for v in rep.violations:
            print("  -", v)
        return 1
    if rep.unused and args.strict:
        print("✗ strict mode: unused allowlist entries")
        return 1
    print("✓ read-only audit passed")
    return 0


# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="analyzer",
        description="Strictly read-only AWS inventory, waste and cost analyzer.",
    )
    p.add_argument("--version", action="version", version=f"aws-analyzer {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)


    def add_scan_args(sp):
        sp.add_argument("--profile", action="append", help="AWS profile to scan (repeatable). Required: nothing is scanned by default.")
        sp.add_argument("--regions", help="comma-separated regions, or 'all' (default: all enabled regions)")
        sp.add_argument("--services", help="comma-separated collectors or groups (compute,data,serverless,containers,edge,security)")
        sp.add_argument("--no-metrics", action="store_true", help="skip CloudWatch utilisation (faster, cheaper, no idle detection)")
        sp.add_argument("--metrics-days", type=int, default=14)
        sp.add_argument("--cost-explorer", action="store_true", help="also read Cost Explorer (billed ~$0.01 per API call)")
        sp.add_argument("--dry-run", action="store_true", help="show the read calls that would be made; send nothing")
        sp.add_argument("--workers", type=int, default=8)
        sp.add_argument("-q", "--quiet", action="store_true")
        sp.add_argument("--out-dir", default=str(DEFAULT_OUT))
        sp.add_argument("--config", help="analyzer.toml (thresholds + project rules)")

    sc = sub.add_parser("scan", help="read the account(s) and save raw facts (the only stage that calls AWS)")
    add_scan_args(sc)
    sc.set_defaults(fn=cmd_scan)

    an = sub.add_parser("analyze", help="offline: projects, cost estimates and findings from a saved scan")
    an.add_argument("scan", nargs="?", help="scan-*.json (default: newest in output/)")
    an.add_argument("--config")
    an.add_argument("--out-dir", default=str(DEFAULT_OUT), help="where analysis-<name>.json is written (default: output/)")
    an.set_defaults(fn=cmd_analyze)

    rp = sub.add_parser("report", help="offline: build the interactive HTML report")
    rp.add_argument("analysis", nargs="?", help="analysis-*.json (default: newest in output/)")
    rp.add_argument("--empty", action="store_true", help="build an empty viewer that loads a JSON by drag & drop")
    rp.add_argument("--out-dir", default=str(DEFAULT_OUT), help="where report-<name>.html and report.html are written (default: output/)")
    rp.set_defaults(fn=cmd_report)

    ru = sub.add_parser("run", help="scan + analyze + report")
    add_scan_args(ru)
    ru.set_defaults(fn=cmd_run)

    de = sub.add_parser("demo", help="full pipeline on a synthetic account (no AWS access needed)")
    de.add_argument("--config")
    de.add_argument("--out-dir", default=str(DEFAULT_OUT))
    de.set_defaults(fn=cmd_demo)

    sm = sub.add_parser("summary", help="plain-text digest of an analysis file (no AWS calls)")
    sm.add_argument("analysis", nargs="?")
    sm.add_argument("--top", type=int, default=10)
    sm.add_argument("--out-dir", default=str(DEFAULT_OUT))
    sm.set_defaults(fn=cmd_summary)

    su = sub.add_parser("suggest-projects", help="print project rules inferred from tags/names (TOML)")
    su.add_argument("file", nargs="?", help="scan-*.json or analysis-*.json")
    su.add_argument("--config")
    su.add_argument("--out-dir", default=str(DEFAULT_OUT))
    su.set_defaults(fn=cmd_suggest)

    d = sub.add_parser("doctor", help="check the aws cli, credentials and read access")
    d.add_argument("--profile", action="append", help="AWS profile (repeatable)")
    d.set_defaults(fn=cmd_doctor)

    po = sub.add_parser("policy", help="print the least-privilege read-only IAM policy")
    po.add_argument("--with-cost", action="store_true", help="include Cost Explorer (ce:*) read actions")
    po.add_argument("--no-metrics", action="store_true", help="omit CloudWatch GetMetricData")
    po.add_argument("--write-config", action="store_true",
                    help="regenerate config/readonly-policy*.json from the allowlist")
    po.set_defaults(fn=cmd_policy)

    a = sub.add_parser("audit-readonly", help="statically verify the code can only do allowlisted reads")
    a.add_argument("--strict", action="store_true", help="also fail on unused allowlist entries")
    a.set_defaults(fn=cmd_audit)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    except AuthError as e:
        if e.code in _AWS_CLI_HINTS:         # the aws binary itself (missing, refused): not a sign-in problem
            print(f"\n✗ {e}\n  {_AWS_CLI_HINTS[e.code]}", file=sys.stderr)
        else:
            print(f"\n✗ cannot authenticate: {e}\n  Sign in yourself (this tool never does), e.g.  aws sso login --profile NAME", file=sys.stderr)
        return 1
    except AwsCliError as e:
        print(f"\n✗ AWS call failed: {e} ({e.code})\n  Run  python3 -m analyzer doctor --profile NAME  to see what this profile can read.", file=sys.stderr)
        return 1
    except UnsafeOutputPath as e:
        print(f"\n✗ {e}", file=sys.stderr)
        return 1
