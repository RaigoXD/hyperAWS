# How AWS Analyzer works

Technical details behind the [README](../README.md): the read-only safety model, the pipeline, project mapping, the report,
the 3D map, cost estimates and the vendored code.

## Why you can trust it not to change anything

Defence in depth, in order of strength:

| Layer | What it does |
|---|---|
| **IAM (the real guarantee)** | `python3 -m analyzer policy` prints a least-privilege **read-only** policy generated from the allowlist (`apigateway:GET` is scoped to the two list paths). Attach it to a dedicated user/role and scan with that. Even a bug in this tool then cannot write. Note read-only is not secret-free: some allowed reads (e.g. Lambda `list-functions`) return environment variables to the process; the tool never stores them, but the principal can read them. |
| **One chokepoint** | `analyzer/awscli.py` is the only module that starts the `aws` process (argv list, no shell, no stdin), and its executor re-checks every command itself, so even a direct call into it cannot run a write or another program. |
| **Exact allowlist** | `analyzer/allowlist.py` lists every `(service, operation)` that may run. Anything else raises *before* a process starts. `aws s3 cp/rm/sync` do not exist for this tool. |
| **Verb + deny rules** | The operation must also be `describe-/list-/get-`, and credential/secret/object-yielding gets (`get-secret-value`, `get-object`, `ecr get-login-password`, Lambda `get-function` ...) are refused. |
| **Safe arguments** | `--endpoint-url`, `--profile`, `--debug`, `--cli-input-json` ... cannot be passed, nor any abbreviation the AWS CLI would expand to them (even `--e`). `file://`/`fileb://` values are refused in every form (`--x file://`, `--x=file://`, `Key@=file://`). Values that come from AWS (resource names) are glued to their flag (`--table-name=--debug`), so a hostile name can neither smuggle a flag nor stop the scan; a refused value becomes an `UnsafeArgument` coverage gap. The environment is cleaned: `AWS_ENDPOINT_URL*`, `AWS_CA_BUNDLE`, `AWS_DATA_PATH` and `AWS_PROFILE` are removed and endpoints configured in `~/.aws/config` are ignored (`AWS_IGNORE_CONFIGURED_ENDPOINT_URLS=true`); use `ca_bundle` in the profile if you need a custom CA. |
| **No secrets on disk** | Resource fields are a curated whitelist, never raw API dumps: Lambda environment variables, CloudFront origin header values and the EKS connector code are cut out by `--query` before they even reach the process; ECS env/secrets, user data, SNS endpoints are never kept; access-key ids, secret-looking tag values and `NAME=value` secrets in names/tags are masked, and emails shortened. Caveat: other free text typed into AWS (descriptions, names) is stored as is. Output files are written atomically, `0600`, in a folder forced to `0700`; symlinked targets and folders owned by someone else are refused, and `analyze`/`report` never overwrite their input. |
| **Browser-enforced offline page** | The report carries a Content-Security-Policy: `connect-src 'none'` (and `default-src`, `frame-src`, `form-action` ... `'none'`), and exactly one script allowed by its SHA-256. The browser itself refuses scripted requests and resource loads from the page, even from third-party code. CSP cannot stop a top-level navigation, so the audit also rejects navigation sinks (`location =`, `window.open` ...) and absolute URLs in the viewer. |
| **Audit log** | Every API call (service, operation, region, status, duration) is saved in the scan and shown in the report's *Scan info* tab, which recomputes live that all calls were describe/list/get. |
| **Static self-test** | `python3 -m analyzer audit-readonly` parses `analyzer/`, `hooks/` and `tools/`: nothing but `awscli.py` may start processes or open network connections (import aliases, `importlib`, `__import__`, `getattr(os, ...)`, `ctypes`, sockets ... are flagged); every call site must use literal, allowlisted operations (and `--query` where secrets must be cut out); the viewer may not make network requests or navigate; every file under `viewer/vendor/` must match its pinned SHA-256. It is a strong check, not a proof: deliberately obfuscated code could still evade it, which is why the IAM policy is the real guarantee. It runs in the test suite. |
| **Optional hook (best effort)** | `hooks/block_aws_writes.py` is a Claude Code `PreToolUse` hook that blocks shell commands that call the AWS CLI (in any letter case) unless they are allowlisted reads, and **fails closed** on anything it cannot verify: `eval`, `${...}`, `\| bash`, `python -c`, quoting tricks, abbreviated global flags, high-level commands like `s3 cp`/`ddb put`, endpoint/CA environment overrides, malformed input or a broken install. It also blocks the obvious non-CLI writers (`curl --aws-sigv4`, terraform/cdk/sam/pulumi/serverless deploys, the `amazon/aws-cli` container). It is a heuristic for the agent's shell tool, **not a guarantee**: a shell can always obfuscate. The IAM policy is the real backstop. |

**Caveat:** if you scan with root or admin credentials, IAM cannot enforce read-only; only the tool's own layers
do. `doctor` warns when it detects root credentials.

Also: the scan makes only free API calls (describe/list/get), except CloudWatch `GetMetricData` (about $0.01 per
1,000 metrics; cents per scan, on by default, disable with `--no-metrics`) and, only with `--cost-explorer`, three Cost Explorer
requests (about $0.03). S3 objects are never listed or read (bucket configuration and CloudWatch size metrics only).

## Pipeline

```
scan     (the only stage that touches AWS)  ->  output/scan-<account>-<time>.json      raw facts + audit log
analyze  (offline)                          ->  output/analysis-....json                projects, costs, findings
report   (offline)                          ->  output/report.html                      one self-contained file
```

Because `analyze` and `report` are offline, you can tune `config/analyzer.toml` (project rules, thresholds) and
re-run them in seconds without calling AWS again. The viewer can also open any `analysis-*.json` by drag and drop
(`python3 -m analyzer report --empty`).

## Mapping components to projects

Resolution order (the report shows *why* each resource got its project): your `[[rules]]` → project tags
(`Project`, `Application`, ..., case-insensitive) → CloudFormation stack → names that start with a known project →
relationships (volumes, ENIs, target groups, services in a cluster inherit) → shared name prefixes → *shared
infrastructure* (VPCs, subnets, security groups, NAT, IAM, DNS never inherit a project) → *Unassigned*.

```bash
python3 -m analyzer suggest-projects          # prints rules that reproduce the grouping inferred from tags/names/stacks
cp config/analyzer.example.toml config/analyzer.toml   # then edit
python3 -m analyzer analyze && python3 -m analyzer report
```

## The report

Overview · Inventory (virtualised table, filters, CSV export, detail drawer) · Project map (nested project → region →
VPC → subnet boxes with connections; click to highlight) · 3D map (the city: *View by* projects or network, height = cost
or size, layers for security permissions, waste and likely connections, a searchable directory that also works with the
keyboard and without WebGL, Save PNG) · Waste & findings (list, and a map of only the flagged
components) · Cost & optimization (ranked recommendations with the maths, project economics, Cost Explorer) ·
Tags & governance · Scan info (coverage gaps, audit log). Light, dark or automatic theme; filters are kept in the URL.

The report contains account ids, names and tags: **treat the file as sensitive.** `output/` is git-ignored.

## How estimates work (and their limits)

`analyzer/analysis/pricing.json` holds on-demand list prices for us-east-1 (Linux) with a coarse regional factor, dated
in the file. Estimates cover baseline charges (instance-hours, GB-months, hourly fees); they exclude data transfer,
requests, LCUs, commercial licences and discounts you already have (Savings Plans, RIs, EDP). Savings from "typical
discount" insights are approximate and say so. Idle detection uses CPU/connections/requests over 14–30 days: peaks
outside that window and memory/network use are not seen. Treat findings as *leads to verify*, not orders.
**Review `pricing.json` before relying on the numbers** (prices change).

## Code layout

```
analyzer/allowlist.py   the only operations that may run      analyzer/awscli.py   the chokepoint + audit log
analyzer/collectors/    one module per service group          analyzer/scan.py     orchestration, coverage gaps
analyzer/metrics.py     CloudWatch utilisation                analyzer/analysis/   links, grouping, cost, rules, engine
analyzer/demo.py        synthetic account (FakeAws)           analyzer/report.py   inlines viewer + data into one HTML
viewer/                 vanilla JS/CSS/SVG + city-*.js (3D)   hooks/               optional Claude Code hook (best effort)
viewer/vendor/          three.js r170, pinned (analyzer/vendor.py)
tools/shape.py          prints an AWS operation's response shape from the CLI's local models (no AWS calls)
config/                 generated IAM policies, example TOML  tests/               unittest suite
```

Run the tests with `python3 -m unittest discover -s tests -t .`. After changing `allowlist.py`, regenerate the IAM
policy files with `python3 -m analyzer policy --write-config` (a test fails if they drift).

A scan limited with `--services`/`--regions` is analysed honestly: conclusions that need an inventory the scan did not read
(DNS targets in other regions, unused security groups, empty VPCs ...) are suppressed rather than guessed, and so are conclusions that
need a call that failed (see the report's *Scan info* → coverage gaps). Idle findings also wait until a resource is older than the
metrics window, and ages are measured at scan time.

## The 3D map: how to read it (and what it does not claim)

Roads come from configuration the scan could read: load balancer → target group → instances/services, CloudFront →
origins, queues/streams → the Lambdas that consume them, SNS → subscribers, dead-letter queues, NAT egress, and the
Internet → every public entry point. Car density is the daily average of CloudWatch totals (requests, invocations,
messages, bytes); a road whose traffic was not measured has a few grey cars, a road measured at zero has cones and no cars.
Dashed lines are **not** observed traffic: orange = the firewall rules would allow it (security groups referencing each
other), grey = a guess from names and networks (*Likely connections*, off by default and always labelled as a guess).
A database or server whose security group is open to the whole Internet on a sensitive port gets a red arch and a red road.

The scan does not read application-level calls (which service queries which database), so those can only appear as
permissions or guesses. In *Network* view, regions that only contain the default network AWS creates are shown as small
"quiet regions" next to the map.

## Vendored code

`viewer/vendor/three.module.min.js` is three.js r170 from npm (`three@0.170.0`), kept byte for byte and pinned by SHA-256
in `analyzer/vendor.py` (provenance in `viewer/vendor/README.md`). At build time the ES module is wrapped into a factory
that only runs when the 3D tab is opened, with `fetch`/`XMLHttpRequest`/`WebSocket`/`Worker` shadowed inside it; the CSP
blocks network access anyway. `python3 tools/vendor_three.py verify` re-checks the files; upgrading means importing a new
tarball with `tools/vendor_three.py import` and updating the pins (r171+ ships as two modules and needs import rewriting).

## Not covered (yet)

AWS Organizations fan-out (scan each account with its own profile and merge by passing several `--profile`s), Compute
Optimizer, live Pricing API prices, EC2 Auto Scaling groups/launch templates (AMI and security-group "unused" findings
are therefore low confidence), and services without a dedicated collector appear only as tag-only inventory.
