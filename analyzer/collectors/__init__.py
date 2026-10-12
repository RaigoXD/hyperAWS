"""Collector registry. Each module exposes NAME, GROUP, SCOPE and collect(ctx)."""

from . import (containers, dynamodb, ec2_net, edge, elasticache, elb, iam, ops, rds,
               s3, serverless, tagging)

ALL = [ec2_net, elb, rds, dynamodb, s3, elasticache, serverless, containers, edge, ops, iam, tagging]
