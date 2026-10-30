"""AWS rules, mapped to the CIS AWS Foundations Benchmark v3.0."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from palisade.models import Provider, Severity
from palisade.registry import rule

AWS = Provider.AWS
OPEN_CIDRS_V4 = {"0.0.0.0/0"}
OPEN_CIDRS_V6 = {"::/0"}
ADMIN_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 3389: "RDP", 5985: "WinRM", 5986: "WinRM-HTTPS"}
PAB_FLAGS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
PUBLIC_GRANTEES = (
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
)


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _statement_is_public(stmt: dict[str, Any]) -> bool:
    if stmt.get("Effect") != "Allow" or stmt.get("Condition"):
        return False
    principal = stmt.get("Principal")
    if principal == "*":
        return True
    return isinstance(principal, dict) and "*" in _as_list(principal.get("AWS"))


def _grants_full_admin(doc: dict[str, Any]) -> bool:
    for stmt in _as_list(doc.get("Statement")):
        if stmt.get("Effect") != "Allow":
            continue
        if "*" in _as_list(stmt.get("Action")) and "*" in _as_list(stmt.get("Resource")):
            return True
    return False


# ---- S3 ---------------------------------------------------------------------


@rule(
    id="AWS-S3-001",
    title="S3 bucket Block Public Access is not fully enabled",
    severity=Severity.HIGH,
    provider=AWS,
    resource_type="s3_bucket",
    cis="2.1.4",
    remediation="Enable all four Block Public Access settings on the bucket (or account-wide).",
)
def s3_block_public_access(bucket: dict[str, Any], resources: dict[str, Any]) -> Iterator[str]:
    account_pab = (resources.get("aws_account") or [{}])[0].get("s3_public_access_block") or {}
    bucket_pab = bucket.get("public_access_block") or {}
    missing = [f for f in PAB_FLAGS if not (bucket_pab.get(f) or account_pab.get(f))]
    if missing:
        yield f"Block Public Access flags off: {', '.join(missing)}"


@rule(
    id="AWS-S3-002",
    title="S3 bucket policy does not enforce TLS",
    severity=Severity.MEDIUM,
    provider=AWS,
    resource_type="s3_bucket",
    cis="2.1.1",
    remediation="Add a Deny statement for all principals when aws:SecureTransport is false.",
)
def s3_require_tls(bucket: dict[str, Any], _: dict[str, Any]) -> Iterator[str]:
    for stmt in _as_list((bucket.get("policy") or {}).get("Statement")):
        cond = stmt.get("Condition", {}).get("Bool", {})
        if stmt.get("Effect") == "Deny" and str(cond.get("aws:SecureTransport")).lower() == "false":
            return
    yield "No Deny statement on aws:SecureTransport=false; plaintext HTTP requests are accepted"


@rule(
    id="AWS-S3-003",
    title="S3 bucket versioning is not enabled",
    severity=Severity.LOW,
    provider=AWS,
    resource_type="s3_bucket",
    cis="2.1.3",
    remediation="Enable versioning so deleted or ransomware-encrypted objects can be recovered.",
)
def s3_versioning(bucket: dict[str, Any], _: dict[str, Any]) -> Iterator[str]:
    if bucket.get("versioning") != "Enabled":
        yield f"Versioning status is {bucket.get('versioning') or 'never enabled'}"


@rule(
    id="AWS-S3-004",
    title="S3 bucket is publicly readable or writable",
    severity=Severity.CRITICAL,
    provider=AWS,
    resource_type="s3_bucket",
    cis="2.1.4",
    remediation="Remove public bucket policy statements and public ACL grants, then enable Block Public Access.",
)
def s3_public(bucket: dict[str, Any], resources: dict[str, Any]) -> Iterator[str]:
    account_pab = (resources.get("aws_account") or [{}])[0].get("s3_public_access_block") or {}
    pab = {f: (bucket.get("public_access_block") or {}).get(f) or account_pab.get(f) for f in PAB_FLAGS}
    if not pab["RestrictPublicBuckets"]:
        for stmt in _as_list((bucket.get("policy") or {}).get("Statement")):
            if _statement_is_public(stmt):
                yield f"Bucket policy allows {stmt.get('Action')} to Principal '*'"
    if not pab["IgnorePublicAcls"]:
        for grant in bucket.get("acl_grants", []):
            uri = grant.get("Grantee", {}).get("URI")
            if uri in PUBLIC_GRANTEES:
                yield f"ACL grants {grant.get('Permission')} to {uri.rsplit('/', 1)[-1]}"


# ---- IAM --------------------------------------------------------------------


@rule(
    id="AWS-IAM-001",
    title="Root account does not have MFA enabled",
    severity=Severity.CRITICAL,
    provider=AWS,
    resource_type="aws_account",
    cis="1.5",
    remediation="Enable a hardware or virtual MFA device on the root user and lock away the credentials.",
)
def root_mfa(account: dict[str, Any], _: dict[str, Any]) -> Iterator[str]:
    if not account.get("root_mfa_enabled"):
        yield "Root user can sign in with a password alone"


@rule(
    id="AWS-IAM-002",
    title="IAM user with console access has no MFA",
    severity=Severity.HIGH,
    provider=AWS,
    resource_type="iam_user",
    cis="1.10",
    remediation="Require MFA for every console user, ideally via IAM Identity Center instead of IAM users.",
)
def user_mfa(user: dict[str, Any], _: dict[str, Any]) -> Iterator[str]:
    if user.get("password_enabled") and user.get("mfa_devices", 0) == 0:
        yield f"User {user['name']} has a console password and no MFA device"


@rule(
    id="AWS-IAM-003",
    title="IAM access key is older than 90 days",
    severity=Severity.MEDIUM,
    provider=AWS,
    resource_type="iam_user",
    cis="1.14",
    remediation="Rotate the key, or better, replace long-lived keys with role-based temporary credentials.",
)
def key_rotation(user: dict[str, Any], _: dict[str, Any]) -> Iterator[str]:
    for key in user.get("access_keys", []):
        age = key.get("age_days")
        if key.get("status") == "Active" and age is not None and age > 90:
            yield f"Access key {key['id']} is {age} days old"


@rule(
    id="AWS-IAM-004",
    title="IAM principal has full administrative privileges",
    severity=Severity.HIGH,
    provider=AWS,
    resource_type="iam_user",
    cis="1.16",
    remediation="Replace AdministratorAccess or '*:*' policies with least-privilege, task-scoped policies.",
)
def user_admin(user: dict[str, Any], _: dict[str, Any]) -> Iterator[str]:
    yield from _admin_details(user)


@rule(
    id="AWS-IAM-005",
    title="IAM role has full administrative privileges",
    severity=Severity.HIGH,
    provider=AWS,
    resource_type="iam_role",
    cis="1.16",
    remediation="Scope the role's policies to the actions and resources its workload actually needs.",
)
def role_admin(role: dict[str, Any], _: dict[str, Any]) -> Iterator[str]:
    yield from _admin_details(role)


def _admin_details(principal: dict[str, Any]) -> Iterator[str]:
    if "arn:aws:iam::aws:policy/AdministratorAccess" in principal.get("attached_policies", []):
        yield f"{principal['name']} has the AdministratorAccess managed policy attached"
    if any(_grants_full_admin(doc) for doc in principal.get("inline_policies", [])):
        yield f"{principal['name']} has an inline policy allowing Action '*' on Resource '*'"


@rule(
    id="AWS-IAM-006",
    title="Account password policy is weak or missing",
    severity=Severity.MEDIUM,
    provider=AWS,
    resource_type="aws_account",
    cis="1.8",
    remediation="Set a password policy with minimum length 14 and reuse prevention of 24.",
)
def password_policy(account: dict[str, Any], _: dict[str, Any]) -> Iterator[str]:
    policy = account.get("password_policy")
    if not policy:
        yield "No account password policy is set"
        return
    if policy.get("MinimumPasswordLength", 0) < 14:
        yield f"Minimum password length is {policy.get('MinimumPasswordLength')} (CIS requires 14)"
    if policy.get("PasswordReusePrevention", 0) < 24:
        yield f"Password reuse prevention is {policy.get('PasswordReusePrevention', 0)} (CIS requires 24)"


# ---- EC2 / networking ---------------------------------------------------------


def _port_in_range(port: int, perm: dict[str, Any]) -> bool:
    if perm.get("IpProtocol") == "-1":
        return True
    lo, hi = perm.get("FromPort"), perm.get("ToPort")
    return lo is not None and hi is not None and lo <= port <= hi


@rule(
    id="AWS-EC2-001",
    title="Security group allows SSH or RDP from the internet",
    severity=Severity.HIGH,
    provider=AWS,
    resource_type="security_group",
    cis="5.2",
    remediation="Remove 0.0.0.0/0 and ::/0 admin ingress; use SSM Session Manager or a bastion behind a VPN.",
)
def sg_admin_ports(sg: dict[str, Any], _: dict[str, Any]) -> Iterator[str]:
    for perm in sg.get("ingress", []):
        open_v4 = [r["CidrIp"] for r in perm.get("IpRanges", []) if r.get("CidrIp") in OPEN_CIDRS_V4]
        open_v6 = [r["CidrIpv6"] for r in perm.get("Ipv6Ranges", []) if r.get("CidrIpv6") in OPEN_CIDRS_V6]
        for cidr in open_v4 + open_v6:
            for port, name in ADMIN_PORTS.items():
                if _port_in_range(port, perm):
                    yield f"{name} (port {port}) open to {cidr}"


@rule(
    id="AWS-EC2-002",
    title="Default security group allows traffic",
    severity=Severity.MEDIUM,
    provider=AWS,
    resource_type="security_group",
    cis="5.4",
    remediation="Strip all ingress and egress rules from every VPC's default security group.",
)
def default_sg(sg: dict[str, Any], _: dict[str, Any]) -> Iterator[str]:
    if sg.get("name") != "default":
        return
    if sg.get("ingress"):
        yield f"Default SG has {len(sg['ingress'])} ingress rule(s)"
    if sg.get("egress"):
        yield f"Default SG has {len(sg['egress'])} egress rule(s)"


@rule(
    id="AWS-EC2-003",
    title="EBS encryption by default is disabled",
    severity=Severity.MEDIUM,
    provider=AWS,
    resource_type="ebs_settings",
    cis="2.2.1",
    remediation="Turn on EBS encryption by default in every region you use.",
)
def ebs_default_encryption(settings: dict[str, Any], _: dict[str, Any]) -> Iterator[str]:
    if not settings.get("encryption_by_default"):
        yield f"New EBS volumes in {settings['region']} are created unencrypted"


# ---- Logging & keys -----------------------------------------------------------


@rule(
    id="AWS-CT-001",
    title="No multi-region CloudTrail trail is logging",
    severity=Severity.HIGH,
    provider=AWS,
    resource_type="aws_account",
    cis="3.1",
    remediation="Create a multi-region trail with management events and keep it logging.",
)
def cloudtrail_enabled(account: dict[str, Any], resources: dict[str, Any]) -> Iterator[str]:
    trails = resources.get("cloudtrail", [])
    if not any(t.get("multi_region") and t.get("is_logging") for t in trails):
        stopped = [t["name"] for t in trails if not t.get("is_logging")]
        suffix = f" (stopped trails: {', '.join(stopped)})" if stopped else ""
        yield f"API activity in this account is not being recorded in every region{suffix}"


@rule(
    id="AWS-CT-002",
    title="CloudTrail log file validation is disabled",
    severity=Severity.MEDIUM,
    provider=AWS,
    resource_type="cloudtrail",
    cis="3.2",
    remediation="Enable log file validation so tampering with delivered logs is detectable.",
)
def cloudtrail_validation(trail: dict[str, Any], _: dict[str, Any]) -> Iterator[str]:
    if not trail.get("log_file_validation"):
        yield f"Trail {trail['name']} logs can be altered without detection"


@rule(
    id="AWS-CT-003",
    title="CloudTrail logs are not encrypted with a KMS key",
    severity=Severity.MEDIUM,
    provider=AWS,
    resource_type="cloudtrail",
    cis="3.5",
    remediation="Configure SSE-KMS with a customer-managed key on the trail.",
)
def cloudtrail_kms(trail: dict[str, Any], _: dict[str, Any]) -> Iterator[str]:
    if not trail.get("kms_key_id"):
        yield f"Trail {trail['name']} uses default S3 encryption only"


@rule(
    id="AWS-KMS-001",
    title="Customer-managed KMS key rotation is disabled",
    severity=Severity.MEDIUM,
    provider=AWS,
    resource_type="kms_key",
    cis="3.6",
    remediation="Enable automatic annual rotation on the key.",
)
def kms_rotation(key: dict[str, Any], _: dict[str, Any]) -> Iterator[str]:
    if not key.get("rotation_enabled"):
        yield f"Key {key['key_id']} has never been rotated automatically"
