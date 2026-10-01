"""AWS remediators. Each takes a boto3 session, the inventory record and the finding."""

from __future__ import annotations

import json
from typing import Any

from botocore.exceptions import ClientError

from palisade.models import Finding
from palisade.remediate import register_plan_only, remediator
from palisade.rules.aws import (
    ADMIN_PORTS,
    OPEN_CIDRS_V4,
    OPEN_CIDRS_V6,
    PUBLIC_GRANTEES,
    _statement_is_public,
)

FULL_PAB = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}

TLS_STATEMENT_SID = "PalisadeDenyInsecureTransport"


def _bucket(res: dict[str, Any]) -> str:
    return res.get("name") or res["id"]


@remediator(
    "AWS-S3-001",
    "Enable all four S3 Block Public Access settings on the bucket",
    auto=True,
    command=lambda r, f: (
        f"aws s3api put-public-access-block --bucket {_bucket(r)} --public-access-block-configuration "
        "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
    ),
)
def fix_s3_pab(session: Any, res: dict[str, Any], f: Finding) -> str:
    session.client("s3").put_public_access_block(Bucket=_bucket(res), PublicAccessBlockConfiguration=FULL_PAB)
    return f"Block Public Access enabled on {_bucket(res)}"


@remediator(
    "AWS-S3-002",
    "Append a Deny statement for non-TLS requests to the bucket policy",
    auto=True,
)
def fix_s3_tls(session: Any, res: dict[str, Any], f: Finding) -> str:
    s3 = session.client("s3")
    name = _bucket(res)
    try:
        policy = json.loads(s3.get_bucket_policy(Bucket=name)["Policy"])
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchBucketPolicy":
            raise
        policy = {"Version": "2012-10-17", "Statement": []}
    statements = policy.setdefault("Statement", [])
    if not any(s.get("Sid") == TLS_STATEMENT_SID for s in statements):
        statements.append(
            {
                "Sid": TLS_STATEMENT_SID,
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": [f"arn:aws:s3:::{name}", f"arn:aws:s3:::{name}/*"],
                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
            }
        )
    s3.put_bucket_policy(Bucket=name, Policy=json.dumps(policy))
    return f"TLS-only policy applied to {name}"


@remediator(
    "AWS-S3-003",
    "Enable bucket versioning",
    auto=True,
    command=lambda r, f: (
        f"aws s3api put-bucket-versioning --bucket {_bucket(r)} --versioning-configuration Status=Enabled"
    ),
)
def fix_s3_versioning(session: Any, res: dict[str, Any], f: Finding) -> str:
    session.client("s3").put_bucket_versioning(Bucket=_bucket(res), VersioningConfiguration={"Status": "Enabled"})
    return f"Versioning enabled on {_bucket(res)}"


@remediator(
    "AWS-S3-004",
    "Strip public policy statements and ACL grants, then enable Block Public Access",
    auto=True,
)
def fix_s3_public(session: Any, res: dict[str, Any], f: Finding) -> str:
    s3 = session.client("s3")
    name = _bucket(res)
    actions = []
    policy = res.get("policy")
    if policy:
        kept = [s for s in policy.get("Statement", []) if not _statement_is_public(s)]
        if kept:
            s3.put_bucket_policy(Bucket=name, Policy=json.dumps({**policy, "Statement": kept}))
        else:
            s3.delete_bucket_policy(Bucket=name)
        actions.append(f"removed {len(policy.get('Statement', [])) - len(kept)} public policy statement(s)")
    if any(g.get("Grantee", {}).get("URI") in PUBLIC_GRANTEES for g in res.get("acl_grants", [])):
        s3.put_bucket_acl(Bucket=name, ACL="private")
        actions.append("reset ACL to private")
    s3.put_public_access_block(Bucket=name, PublicAccessBlockConfiguration=FULL_PAB)
    actions.append("enabled Block Public Access")
    return f"{name}: " + ", ".join(actions)


@remediator(
    "AWS-EC2-001",
    "Revoke internet-facing SSH/RDP ingress rules",
    auto=True,
    command=lambda r, f: (
        f"aws ec2 revoke-security-group-ingress --group-id {r['id']} --region {r.get('region', '')} "
        "--ip-permissions <offending rule>"
    ),
)
def fix_sg_admin_ports(session: Any, res: dict[str, Any], f: Finding) -> str:
    ec2 = session.client("ec2", region_name=res.get("region"))
    revoked = 0
    for perm in res.get("ingress", []):
        exposes_admin = perm.get("IpProtocol") == "-1" or any(
            perm.get("FromPort") is not None and perm["FromPort"] <= p <= perm["ToPort"] for p in ADMIN_PORTS
        )
        if not exposes_admin:
            continue
        v4 = [r for r in perm.get("IpRanges", []) if r.get("CidrIp") in OPEN_CIDRS_V4]
        v6 = [r for r in perm.get("Ipv6Ranges", []) if r.get("CidrIpv6") in OPEN_CIDRS_V6]
        if not (v4 or v6):
            continue
        target = {k: perm[k] for k in ("IpProtocol", "FromPort", "ToPort") if k in perm}
        if v4:
            target["IpRanges"] = [{"CidrIp": r["CidrIp"]} for r in v4]
        if v6:
            target["Ipv6Ranges"] = [{"CidrIpv6": r["CidrIpv6"]} for r in v6]
        ec2.revoke_security_group_ingress(GroupId=res["id"], IpPermissions=[target])
        revoked += 1
    return f"Revoked {revoked} internet-facing admin rule(s) on {res['id']}"


@remediator("AWS-EC2-002", "Remove all rules from the default security group", auto=True)
def fix_default_sg(session: Any, res: dict[str, Any], f: Finding) -> str:
    ec2 = session.client("ec2", region_name=res.get("region"))
    clean = [{k: v for k, v in p.items() if v not in ([], None)} for p in res.get("ingress", [])]
    if clean:
        ec2.revoke_security_group_ingress(GroupId=res["id"], IpPermissions=clean)
    clean = [{k: v for k, v in p.items() if v not in ([], None)} for p in res.get("egress", [])]
    if clean:
        ec2.revoke_security_group_egress(GroupId=res["id"], IpPermissions=clean)
    return f"Default SG {res['id']} emptied"


@remediator(
    "AWS-EC2-003",
    "Enable EBS encryption by default",
    auto=True,
    command=lambda r, f: f"aws ec2 enable-ebs-encryption-by-default --region {r.get('region')}",
)
def fix_ebs(session: Any, res: dict[str, Any], f: Finding) -> str:
    session.client("ec2", region_name=res["region"]).enable_ebs_encryption_by_default()
    return f"EBS default encryption on in {res['region']}"


@remediator(
    "AWS-CT-001",
    "Restart logging on stopped trails (creating a trail needs a log bucket, so that part is manual)",
    auto=True,
)
def fix_trail_logging(session: Any, res: dict[str, Any], f: Finding) -> str:
    ct = session.client("cloudtrail")
    restarted = []
    for trail in ct.describe_trails(includeShadowTrails=False).get("trailList", []):
        if not ct.get_trail_status(Name=trail["TrailARN"]).get("IsLogging"):
            ct.start_logging(Name=trail["TrailARN"])
            restarted.append(trail["Name"])
    if not restarted:
        raise RuntimeError("No stopped trail to restart; deploy terraform/aws to create one")
    return f"Restarted logging on: {', '.join(restarted)}"


@remediator(
    "AWS-CT-002",
    "Enable CloudTrail log file validation",
    auto=True,
    command=lambda r, f: f"aws cloudtrail update-trail --name {r.get('name')} --enable-log-file-validation",
)
def fix_trail_validation(session: Any, res: dict[str, Any], f: Finding) -> str:
    session.client("cloudtrail").update_trail(Name=res["id"], EnableLogFileValidation=True)
    return f"Log file validation enabled on {res.get('name')}"


@remediator(
    "AWS-KMS-001",
    "Enable automatic key rotation",
    auto=True,
    command=lambda r, f: f"aws kms enable-key-rotation --key-id {r.get('key_id')}",
)
def fix_kms_rotation(session: Any, res: dict[str, Any], f: Finding) -> str:
    session.client("kms", region_name=res.get("region")).enable_key_rotation(KeyId=res["key_id"])
    return f"Rotation enabled on {res['key_id']}"


@remediator("AWS-IAM-006", "Apply a CIS-compliant account password policy", auto=True)
def fix_password_policy(session: Any, res: dict[str, Any], f: Finding) -> str:
    session.client("iam").update_account_password_policy(
        MinimumPasswordLength=14,
        RequireSymbols=True,
        RequireNumbers=True,
        RequireUppercaseCharacters=True,
        RequireLowercaseCharacters=True,
        AllowUsersToChangePassword=True,
        PasswordReusePrevention=24,
    )
    return "Password policy set: length 14, reuse prevention 24"


# Identity changes can lock people or workloads out, so these are plan-only.
register_plan_only("AWS-IAM-001", "Enroll an MFA device on the root user (console only)")
register_plan_only("AWS-IAM-002", "Require MFA for the user, or migrate them to IAM Identity Center")
register_plan_only(
    "AWS-IAM-003",
    "Rotate the access key after confirming its consumers",
    command=lambda r, f: f"aws iam create-access-key --user-name {r.get('name')}  # then deactivate the old key",
)
register_plan_only(
    "AWS-IAM-004",
    "Replace AdministratorAccess with a least-privilege policy",
    command=lambda r, f: (
        f"aws iam detach-user-policy --user-name {r.get('name')} "
        "--policy-arn arn:aws:iam::aws:policy/AdministratorAccess"
    ),
)
register_plan_only("AWS-IAM-005", "Scope the role's policies to its workload's needs")
register_plan_only("AWS-CT-003", "Set a customer-managed KMS key on the trail (needs a key policy for CloudTrail)")
