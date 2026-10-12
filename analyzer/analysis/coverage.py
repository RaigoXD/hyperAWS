"""What this tool inventories, and what it cannot see. Shown in the report so an empty result is never over-trusted."""

from __future__ import annotations

COLLECTED = [
    ("Compute & network", "EC2 instances, EBS volumes/snapshots, AMIs, Elastic IPs, network interfaces, NAT gateways, VPCs, subnets, "
                          "VPC endpoints, internet gateways, security groups, load balancers"),
    ("Databases", "RDS and Aurora (Neptune/DocumentDB listed but not priced), DynamoDB, ElastiCache"),
    ("Storage", "S3 bucket configuration and size"),
    ("Serverless & messaging", "Lambda (incl. event source mappings: which queues/streams trigger it), API Gateway, "
                               "SQS (incl. dead-letter queues), SNS (incl. SQS/Lambda subscriptions; e-mail/SMS/HTTP endpoints are "
                               "never stored), Step Functions"),
    ("Containers", "ECS clusters/services (incl. task and execution role names), ECR, EKS (incl. cluster and node roles)"),
    ("Edge & operations", "CloudFront, Route 53, CloudWatch Logs, KMS keys"),
    ("Identity", "IAM users, access keys, roles"),
]

# Services with no dedicated collector. Their resources appear ONLY if they carry tags (via the Tagging API) and are
# then shown with no cost. Untagged ones are invisible. Ordered roughly by how often they hide real spend.
NOT_INVENTORIED = [
    "Redshift", "OpenSearch / Elasticsearch", "EMR", "MSK (Kafka)", "Kinesis / Firehose", "SageMaker / Bedrock",
    "EFS / FSx", "Secrets Manager (billed per secret)", "Auto Scaling groups & launch templates", "Transit Gateway / VPN / Direct Connect / peering",
    "Glue / Athena", "MQ / MemoryDB", "WAF / Shield", "GuardDuty / Security Hub / Config / CloudTrail", "AWS Backup (vaults, recovery points)",
    "CloudFormation stacks", "Cognito / SES", "CodeBuild / CodePipeline / CodeCommit", "EventBridge / Scheduler", "Batch / App Runner / Lightsail / Amplify",
    "Savings Plans / Reserved Instances (ownership and coverage)", "Marketplace, support plans, domains, data transfer",
]

NOTE = ("Resources of these services are not inventoried unless they carry tags, and then they show no cost or findings. "
        "To find spend this scan cannot see, re-run with --cost-explorer (about $0.03): the by-service spend lists every service "
        "that bills, including the ones above.")


def manifest() -> dict:
    return {"collected": [{"group": g, "what": w} for g, w in COLLECTED], "not_inventoried": NOT_INVENTORIED, "note": NOTE}
