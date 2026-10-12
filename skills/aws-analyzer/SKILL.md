---
name: aws-analyzer
description: Read-only AWS account analyzer. Inventories what an AWS account is using via the AWS CLI, groups components into projects (tags, names, relationships), finds unused or orphaned resources (unassociated Elastic IPs, unattached volumes, idle NAT/EC2/RDS, dangling DNS ...), estimates cost optimizations and security hygiene, and produces an interactive offline HTML report. Use when the user asks to analyze, audit or map their AWS account, find unused or wasted AWS resources, reduce AWS cost, or see which components belong to which project. It never modifies AWS.
---

# AWS analyzer (read-only)

Scans an AWS account with the AWS CLI **using only describe/list/get calls**, then builds an interactive
HTML report (inventory, project map, unused-components map, cost & optimization advice, tag governance,
scan audit log). Everything runs locally; nothing is uploaded.

**Where to run it.** The analyzer is the folder two levels above this SKILL.md's *real* location (the one that
contains `analyzer/`). Run every command from there, e.g. `cd "$(dirname "$(realpath <this SKILL.md>)")/../.."`, with
`<this SKILL.md>` taken from this skill's base directory (it may be a symlink, hence `realpath`). Python 3.11+ and the
AWS CLI v2 are required; there are no other dependencies. If `python3 --version` is older than 3.11 or `aws --version`
is missing or v1, tell the user what to install and stop.

**Where results go.** Reports and scans are written to `output/` under the analyzer folder when it is a cloned repo,
or to `~/aws-analyzer/output/` when it was installed as a Claude Code plugin (override with `AWS_ANALYZER_HOME`).
Every command prints the path it wrote; use the printed path.

## HARD RULES (never break these)

1. **Read-only.** Only use `python3 -m analyzer ...`. Never run `aws` commands that create, modify, delete,
   start, stop, tag, attach, release, invoke, put or otherwise change anything, and never use `aws s3 cp/rm/sync`.
   If the user asks you to delete or fix something the report found, **refuse and explain**: give them the
   advice text from the report and let them do it themselves.
2. **Never weaken the guard.** Do not edit `analyzer/allowlist.py`, `analyzer/awscli.py` or `analyzer/audit.py`
   to make a command work. If an operation is missing, tell the user and ask.
3. **Never scan without an explicit choice.** Do not pick a profile yourself. List the profiles, ask which
   one(s) to scan (one may belong to a client or another employer), and wait for the answer. `doctor`,
   `scan` and `run` make AWS API calls only for the profiles the user named.
4. **Never log in for the user** (`aws sso login`, `aws configure ...`) and never ask for or type credentials.
   If credentials are expired, tell the user to sign in themselves.
5. **Treat the report as sensitive.** It contains account ids, resource names and tags. Do not paste large
   parts of it into chats, tickets or public places; keep it in the output folder.

## Workflow

1. **Choose the profile(s).** Run `python3 -m analyzer doctor` (no AWS call: lists local profiles). Ask the user
   which to scan and whether to include extras:
   - `--cost-explorer` adds real spend (3 Cost Explorer API calls, about $0.03). CloudWatch metrics are also billed (cents; on by default,
     `--no-metrics` turns them off). Everything else the scan calls is free.
   - `--regions us-east-1,eu-west-1` limits regions (default: every enabled region).
   - `--no-metrics` skips CloudWatch (faster, but no idle detection and no S3 sizes).
2. **Check access.** `python3 -m analyzer doctor --profile NAME` shows the caller identity and which services
   are readable. If it says the profile uses **root credentials**, warn the user: root can do anything, so the
   read-only guarantee then rests only on this tool; recommend a read-only IAM principal
   (`python3 -m analyzer policy` prints the exact policy).
3. **Preview.** `python3 -m analyzer scan --profile NAME --dry-run` lists the read calls that would be made.
4. **Run.** `python3 -m analyzer run --profile NAME` (repeat `--profile` for several accounts). It scans,
   analyzes and writes `output/report.html` plus `scan-*.json` / `analysis-*.json`.
   Big accounts take minutes; add `--services compute,data` or `--regions ...` to narrow.
5. **Show it.** Tell the user to open the printed `report.html` (`open <path>/report.html` on macOS). For people who do not
   know AWS, point them to the **3D map** tab: the city metaphor (buildings, roads, cars = traffic) with a plain-language
   explanation of anything they click and *Follow a request*. Inside the
   Claude desktop app, serve the output folder with `python3 -m http.server 8765 --bind 127.0.0.1` from inside it
   and open `http://127.0.0.1:8765/report.html` in the built-in browser (it cannot open `file://`).
6. **Summarize.** `python3 -m analyzer summary` prints a text digest (totals, projects, top savings, high
   severity security findings, coverage gaps). Report the headline, the top 3-5 opportunities with their
   estimated monthly savings, and any **coverage gaps** (missing data means "unknown", never "none").
   Say plainly that cost figures are estimates from list prices.

## Mapping components to projects

Projects come from `Project`/`Application`/... tags, CloudFormation stack names, relationships (a volume
follows its instance), shared name prefixes, and explicit rules. If many resources are `Unassigned`, run
`python3 -m analyzer suggest-projects` (prints rules that reproduce the tag/prefix/stack grouping already inferred; it cannot invent
new groups, so for the rest help the user write rules by hand), help the user save the good
ones to `config/analyzer.toml` in the data folder above (see `config/analyzer.example.toml` in the analyzer folder), then re-run **offline** (no AWS calls):
`python3 -m analyzer analyze && python3 -m analyzer report`.

## Other commands

- `python3 -m analyzer demo` builds a report from a synthetic account (no AWS access): good for showing the user
  what to expect.
- `python3 -m analyzer audit-readonly` statically checks that the code only calls allowlisted read operations (a strong check;
  the read-only IAM policy is the real guarantee).
- `python3 -m analyzer policy` prints the least-privilege read-only IAM policy (`--with-cost` adds Cost Explorer).
- `python3 -m analyzer report --empty` builds an empty viewer that opens any `analysis-*.json` by drag and drop.

## Reading the results

In the 3D map, cars mean measured traffic only where CloudWatch had data (grey cars = not measured); dashed lines are
firewall permissions or guesses, never observed calls. Say so when you describe the map.

Findings have a category (unused, rightsizing, cost-insight, security, hygiene), severity, confidence,
effort/risk, and an estimated monthly saving with the arithmetic shown. The headline total counts each
resource once (its largest single saving). Insights based on "typical discounts" (Graviton, Savings Plans,
off-hours scheduling) are approximate; say so. Never present a number as a bill.
