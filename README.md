# AWS Analyzer for Claude Code

A **read-only** AWS account analyzer, packaged as a Claude Code skill. Ask Claude to *"analyze my AWS account"* and it
inventories what you run with the AWS CLI, groups it into projects, finds unused and insecure resources, estimates what
you could save, and builds one offline HTML report, including a **3D city map** that explains your systems to people
who don't know AWS. It never creates, changes or deletes anything in AWS.

## Features

- **Inventory** of EC2, EBS, VPC networking, load balancers, RDS/Aurora, DynamoDB, S3, ElastiCache, Lambda, API Gateway,
  SQS, SNS, Step Functions, ECS, ECR, EKS, CloudFront, Route 53, CloudWatch Logs, KMS and IAM, across every enabled region
- **Project map**: resources grouped by tags, CloudFormation stacks, names and relationships
- **Waste finder**: unattached Elastic IPs and volumes, idle NAT gateways, instances and databases, orphaned snapshots,
  empty VPCs, dangling DNS records, stale IAM keys, each with its evidence
- **Cost & optimization**: monthly estimates from list prices, savings per finding with the maths shown
  (gp2→gp3, Graviton, scheduling, public IPv4 ...), optional real spend from Cost Explorer
- **Security hygiene**: public databases, security groups open to the Internet, old access keys, root credentials
- **3D map**: every project or region is a city; servers are office towers, databases bank vaults, S3 buckets silos,
  IAM roles offices in a tower, and roads with cars show the measured traffic between them
- **One offline file**: no backend, no upload, and the browser itself blocks any network request from the report

## Installation

### Option 1: Claude Code plugin marketplace (recommended)

```
/plugin marketplace add OWNER/aws-analyzer
```

```
/plugin install aws-analyzer@aws-analyzer
```

Restart Claude Code if it asks you to. Reports are saved in `~/aws-analyzer/output/`.

### Option 2: Manual install

```bash
git clone https://github.com/OWNER/aws-analyzer.git ~/aws-analyzer-src
```

```bash
ln -s ~/aws-analyzer-src/skills/aws-analyzer ~/.claude/skills/aws-analyzer
```

Reports are saved in `~/aws-analyzer-src/output/`.

### Requirements

- **Python 3.11+** (no pip packages)
- **AWS CLI v2**, signed in to the account you want to analyze (`aws configure` or `aws sso login`)
- Recommended: a **read-only IAM user or role** for the scan. Claude can print the exact policy for you.

## Usage

Just ask Claude in plain words. It always asks which AWS profile to scan before touching anything.

```
Analyze my AWS account
```

```
Find unused AWS resources and tell me how much I can save
```

```
Which components belong to which project in my AWS account?
```

```
Show me a 3D map of my AWS systems
```

```
Run the AWS analyzer demo (no AWS access needed)
```

Then open the report Claude points you to. The **3D map** tab is the easiest place to start; click any building for a
plain-language explanation, or **Follow a request** to watch one visitor travel from the Internet through your systems.

### Without Claude

```bash
python3 -m analyzer demo
```

```bash
python3 -m analyzer run --profile YOUR_PROFILE
```

Run these from the analyzer folder. `python3 -m analyzer --help` lists every command: `doctor`, `scan --dry-run`,
`summary`, `policy`, `suggest-projects`, `audit-readonly` and more.

## Safety

- **Read-only by design**: only an explicit allowlist of 72 `describe`/`list`/`get` operations can run, checked before
  any process starts. Secret-returning calls are refused, and secret fields are cut out before they reach the tool.
- **Least-privilege IAM policy**: `python3 -m analyzer policy` prints it; attach it to a dedicated user or role and
  the read-only promise no longer depends on this code at all.
- **Every call is logged** in the report's *Scan info* tab.
- **Private outputs**: reports contain account ids, names and tags, so they are written `0600` in a `0700` folder.
  Treat them as sensitive.
- **Audited**: a static self-check (`python3 -m analyzer audit-readonly`) and 340+ tests run on every change. An
  independent multi-agent security audit found no critical or high issues, and all 38 findings it did raise are fixed.

Details: [docs/HOW-IT-WORKS.md](docs/HOW-IT-WORKS.md).

## Structure

```
aws-analyzer/
├── .claude-plugin/          # plugin + marketplace manifests
├── skills/aws-analyzer/     # SKILL.md: what Claude does and the rules it follows
├── analyzer/                # the Python tool (scan → analyze → report)
├── viewer/                  # the offline HTML report (vanilla JS + pinned three.js for the 3D map)
├── hooks/                   # optional hook that blocks AWS write commands in Claude Code
├── config/                  # generated read-only IAM policies, example project rules
├── tools/                   # maintenance scripts (no AWS calls)
├── tests/                   # 340+ tests
└── docs/HOW-IT-WORKS.md     # security model, pipeline, estimates, 3D map
```

## Cost of running

Inventory calls are free. CloudWatch metrics cost a few cents per scan (`--no-metrics` turns them off), and the optional
`--cost-explorer` flag adds about $0.03.
