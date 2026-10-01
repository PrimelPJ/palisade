"""Collect a normalized AWS inventory with boto3.

Works against a real account (default credential chain) or any boto3-compatible
endpoint, including moto's in-memory mock used by the tests and the demo.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import ClientError

from palisade.models import Inventory, Provider

log = logging.getLogger(__name__)

ADMIN_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


def _err_code(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code", "")


def _age_days(when: datetime | None) -> int | None:
    if when is None:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - when).days


def _as_doc(value: Any) -> dict[str, Any]:
    """IAM returns policy documents as dicts (boto3 decodes them) or URL-encoded JSON strings."""
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        from urllib.parse import unquote

        return json.loads(unquote(value))
    return {}


class AwsCollector:
    def __init__(self, session: boto3.session.Session | None = None, regions: list[str] | None = None):
        self.session = session or boto3.session.Session()
        self.regions = regions or [self.session.region_name or "us-east-1"]

    def collect(self, include: set[str] | None = None) -> Inventory:
        """Collect everything, or only the resource types in ``include`` (used by the
        event-driven Lambda to rescan just what a single API call could have changed)."""

        def want(t: str) -> bool:
            return include is None or t in include

        account_id = self.session.client("sts").get_caller_identity()["Account"]
        resources: dict[str, list[dict[str, Any]]] = {"aws_account": [self._account(account_id)]}
        if want("s3_bucket"):
            resources["s3_bucket"] = self._buckets()
        if want("iam_user"):
            resources["iam_user"] = self._users()
        if want("iam_role"):
            resources["iam_role"] = self._roles()
        for rtype in ("security_group", "ebs_settings", "kms_key"):
            if want(rtype):
                resources[rtype] = []
        for region in self.regions:
            if want("security_group"):
                resources["security_group"] += self._security_groups(region)
            if want("ebs_settings"):
                resources["ebs_settings"].append(self._ebs_settings(region))
            if want("kms_key"):
                resources["kms_key"] += self._kms_keys(region)
        # Account-level rules (e.g. "is any trail logging?") need trails, so always collect them.
        # Multi-region trails appear in every region, so list them once.
        resources["cloudtrail"] = self._trails(self.regions[0])
        return Inventory(provider=Provider.AWS, account=account_id, resources=resources)

    # ---- account-wide -------------------------------------------------------
    def _account(self, account_id: str) -> dict[str, Any]:
        iam = self.session.client("iam")
        summary = iam.get_account_summary().get("SummaryMap", {})
        try:
            policy = iam.get_account_password_policy()["PasswordPolicy"]
        except ClientError as exc:
            if _err_code(exc) != "NoSuchEntity":
                raise
            policy = None
        try:
            pab = self.session.client("s3control", region_name=self.regions[0]).get_public_access_block(
                AccountId=account_id
            )["PublicAccessBlockConfiguration"]
        except ClientError:
            pab = None
        return {
            "id": account_id,
            "root_mfa_enabled": bool(summary.get("AccountMFAEnabled", 0)),
            "password_policy": policy,
            "s3_public_access_block": pab,
        }

    # ---- S3 -----------------------------------------------------------------
    def _buckets(self) -> list[dict[str, Any]]:
        s3 = self.session.client("s3")
        out = []
        for bucket in s3.list_buckets().get("Buckets", []):
            name = bucket["Name"]
            record: dict[str, Any] = {"id": name, "name": name}
            try:
                record["public_access_block"] = s3.get_public_access_block(Bucket=name)[
                    "PublicAccessBlockConfiguration"
                ]
            except ClientError:
                record["public_access_block"] = None
            try:
                record["policy"] = json.loads(s3.get_bucket_policy(Bucket=name)["Policy"])
            except ClientError:
                record["policy"] = None
            record["acl_grants"] = s3.get_bucket_acl(Bucket=name).get("Grants", [])
            record["versioning"] = s3.get_bucket_versioning(Bucket=name).get("Status")
            try:
                record["encryption"] = s3.get_bucket_encryption(Bucket=name)["ServerSideEncryptionConfiguration"][
                    "Rules"
                ]
            except ClientError:
                record["encryption"] = None
            out.append(record)
        return out

    # ---- IAM ----------------------------------------------------------------
    def _users(self) -> list[dict[str, Any]]:
        iam = self.session.client("iam")
        out = []
        for page in iam.get_paginator("list_users").paginate():
            for user in page["Users"]:
                name = user["UserName"]
                try:
                    iam.get_login_profile(UserName=name)
                    password_enabled = True
                except ClientError:
                    password_enabled = False
                keys = [
                    {
                        "id": k["AccessKeyId"],
                        "status": k["Status"],
                        "age_days": _age_days(k.get("CreateDate")),
                    }
                    for k in iam.list_access_keys(UserName=name)["AccessKeyMetadata"]
                ]
                out.append(
                    {
                        "id": user["Arn"],
                        "name": name,
                        "password_enabled": password_enabled,
                        "mfa_devices": len(iam.list_mfa_devices(UserName=name)["MFADevices"]),
                        "access_keys": keys,
                        "attached_policies": [
                            p["PolicyArn"] for p in iam.list_attached_user_policies(UserName=name)["AttachedPolicies"]
                        ],
                        "inline_policies": [
                            _as_doc(iam.get_user_policy(UserName=name, PolicyName=p)["PolicyDocument"])
                            for p in iam.list_user_policies(UserName=name)["PolicyNames"]
                        ],
                    }
                )
        return out

    def _roles(self) -> list[dict[str, Any]]:
        iam = self.session.client("iam")
        out = []
        for page in iam.get_paginator("list_roles").paginate():
            for role in page["Roles"]:
                name = role["RoleName"]
                if role.get("Path", "/").startswith("/aws-service-role/"):
                    continue  # AWS-managed service-linked roles are out of scope
                out.append(
                    {
                        "id": role["Arn"],
                        "name": name,
                        "trust_policy": _as_doc(role.get("AssumeRolePolicyDocument", {})),
                        "attached_policies": [
                            p["PolicyArn"] for p in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]
                        ],
                        "inline_policies": [
                            _as_doc(iam.get_role_policy(RoleName=name, PolicyName=p)["PolicyDocument"])
                            for p in iam.list_role_policies(RoleName=name)["PolicyNames"]
                        ],
                    }
                )
        return out

    # ---- EC2 ----------------------------------------------------------------
    def _security_groups(self, region: str) -> list[dict[str, Any]]:
        ec2 = self.session.client("ec2", region_name=region)
        out = []
        for page in ec2.get_paginator("describe_security_groups").paginate():
            for sg in page["SecurityGroups"]:
                out.append(
                    {
                        "id": sg["GroupId"],
                        "name": sg["GroupName"],
                        "region": region,
                        "vpc_id": sg.get("VpcId"),
                        "ingress": sg.get("IpPermissions", []),
                        "egress": sg.get("IpPermissionsEgress", []),
                    }
                )
        return out

    def _ebs_settings(self, region: str) -> dict[str, Any]:
        ec2 = self.session.client("ec2", region_name=region)
        enabled = ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"]
        return {"id": f"ebs-defaults/{region}", "region": region, "encryption_by_default": enabled}

    # ---- CloudTrail / KMS ---------------------------------------------------
    def _trails(self, region: str) -> list[dict[str, Any]]:
        ct = self.session.client("cloudtrail", region_name=region)
        out = []
        for trail in ct.describe_trails(includeShadowTrails=False).get("trailList", []):
            status = ct.get_trail_status(Name=trail["TrailARN"])
            out.append(
                {
                    "id": trail["TrailARN"],
                    "name": trail["Name"],
                    "multi_region": trail.get("IsMultiRegionTrail", False),
                    "log_file_validation": trail.get("LogFileValidationEnabled", False),
                    "is_logging": status.get("IsLogging", False),
                    "kms_key_id": trail.get("KmsKeyId"),
                    "s3_bucket": trail.get("S3BucketName"),
                }
            )
        return out

    def _kms_keys(self, region: str) -> list[dict[str, Any]]:
        kms = self.session.client("kms", region_name=region)
        out = []
        for page in kms.get_paginator("list_keys").paginate():
            for key in page["Keys"]:
                meta = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
                if meta.get("KeyManager") != "CUSTOMER" or meta.get("KeyState") != "Enabled":
                    continue
                if meta.get("KeySpec", "SYMMETRIC_DEFAULT") != "SYMMETRIC_DEFAULT":
                    continue  # rotation only applies to symmetric keys
                rotation = kms.get_key_rotation_status(KeyId=key["KeyId"])["KeyRotationEnabled"]
                out.append(
                    {
                        "id": meta["Arn"],
                        "key_id": key["KeyId"],
                        "region": region,
                        "rotation_enabled": rotation,
                    }
                )
        return out
