"""Event-driven detection and remediation for AWS.

Deployed by terraform/aws: an EventBridge rule forwards CloudTrail management events
for risky API calls to this function. It rescans only the resource types the call
could have changed, applies auto-safe fixes, and publishes a summary to SNS.

Mean time to remediate drops from "next scheduled scan" to seconds.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import boto3

from palisade.collectors.aws import AwsCollector
from palisade.remediate import Status, remediate
from palisade.scanner import scan

log = logging.getLogger()
log.setLevel(logging.INFO)

# API call -> resource types whose rules it can break.
EVENT_MAP: dict[str, set[str]] = {
    # S3
    "PutBucketPolicy": {"s3_bucket"},
    "DeleteBucketPolicy": {"s3_bucket"},
    "PutBucketAcl": {"s3_bucket"},
    "PutBucketPublicAccessBlock": {"s3_bucket"},
    "DeleteBucketPublicAccessBlock": {"s3_bucket"},
    "PutBucketVersioning": {"s3_bucket"},
    "CreateBucket": {"s3_bucket"},
    # Account-level Block Public Access affects every bucket. CloudTrail has used both
    # the Account* and the bare names for these calls, so watch both.
    "DeleteAccountPublicAccessBlock": {"s3_bucket"},
    "PutAccountPublicAccessBlock": {"s3_bucket"},
    "DeletePublicAccessBlock": {"s3_bucket"},
    "PutPublicAccessBlock": {"s3_bucket"},
    # Network
    "AuthorizeSecurityGroupIngress": {"security_group"},
    "AuthorizeSecurityGroupEgress": {"security_group"},
    "ModifySecurityGroupRules": {"security_group"},
    "CreateSecurityGroup": {"security_group"},
    # Logging and encryption
    "StopLogging": {"cloudtrail", "aws_account"},
    "DeleteTrail": {"cloudtrail", "aws_account"},
    "UpdateTrail": {"cloudtrail", "aws_account"},
    "DisableKeyRotation": {"kms_key"},
    "DisableEbsEncryptionByDefault": {"ebs_settings"},
    # Identity (detected and alerted; fixes need a human)
    "CreateUser": {"iam_user"},
    "CreateLoginProfile": {"iam_user"},
    "CreateAccessKey": {"iam_user"},
    "AttachUserPolicy": {"iam_user"},
    "PutUserPolicy": {"iam_user"},
    "AttachRolePolicy": {"iam_role"},
    "PutRolePolicy": {"iam_role"},
    "UpdateAccountPasswordPolicy": {"aws_account"},
    "DeleteAccountPasswordPolicy": {"aws_account"},
}

# Account-level rules that a narrow event can legitimately re-check.
ACCOUNT_RULES_FOR = {
    "cloudtrail": {"AWS-CT-001"},
    "aws_account": {"AWS-CT-001", "AWS-IAM-006"},
}


def _is_self(detail: dict[str, Any]) -> bool:
    """Ignore API calls made by this function so its own fixes don't retrigger it."""
    self_role = os.environ.get("PALISADE_SELF_ROLE_NAME")
    arn = detail.get("userIdentity", {}).get("arn", "")
    return bool(self_role) and f"/{self_role}/" in arn


def handler(event: dict[str, Any], context: Any = None, session: boto3.session.Session | None = None) -> dict[str, Any]:
    detail = event.get("detail", {})
    name = detail.get("eventName", "")
    if detail.get("errorCode"):
        return {"status": "ignored", "reason": f"{name} failed with {detail['errorCode']}"}
    if _is_self(detail):
        return {"status": "ignored", "reason": "self-generated event"}
    types = EVENT_MAP.get(name)
    if not types:
        return {"status": "ignored", "reason": f"{name} is not monitored"}

    session = session or boto3.session.Session()
    region = detail.get("awsRegion") or session.region_name
    inventory = AwsCollector(session, regions=[region]).collect(include=types)
    result = scan(inventory, only_resource_types=types)

    allowed_account_rules = set().union(*(ACCOUNT_RULES_FOR.get(t, set()) for t in types))
    findings = [f for f in result.active if f.resource_type != "aws_account" or f.rule_id in allowed_account_rules]
    dry_run = os.environ.get("PALISADE_DRY_RUN", "false").lower() == "true"
    fixes = remediate(findings, inventory, session=session, apply=not dry_run)

    summary = {
        "status": "processed",
        "trigger": {
            "event": name,
            "actor": detail.get("userIdentity", {}).get("arn"),
            "source_ip": detail.get("sourceIPAddress"),
            "time": detail.get("eventTime"),
        },
        "findings": [f.to_dict() for f in findings],
        "remediation": [r.to_dict() for r in fixes],
    }
    log.info(json.dumps(summary, default=str))

    topic = os.environ.get("PALISADE_ALERT_TOPIC_ARN")
    if topic and findings:
        applied = sum(r.status == Status.APPLIED for r in fixes)
        worst = max(findings, key=lambda f: f.severity.rank).severity.value.upper()
        session.client("sns", region_name=region).publish(
            TopicArn=topic,
            Subject=f"[Palisade {worst}] {name}: {len(findings)} finding(s), {applied} auto-fixed"[:100],
            Message=json.dumps(summary, indent=2, default=str),
        )
    return summary
