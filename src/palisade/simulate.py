"""Attack simulation: misconfigure a hardened AWS environment like an attacker or a
careless change would, then prove Palisade detects and repairs it.

Runs against moto by default, so it is safe and free. Every scenario is tagged with
the MITRE ATT&CK for Cloud technique it emulates.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import boto3

from palisade.collectors.aws import AwsCollector
from palisade.remediate import RemediationResult, Status, remediate
from palisade.report import short_id
from palisade.scanner import ScanResult, Suppression, scan

REGION = "us-east-1"
APP_BUCKET = "palisade-demo-app-data"
LOG_BUCKET = "palisade-demo-cloudtrail-logs"
TRAIL = "palisade-org-trail"
APP_SG = "palisade-web"
FULL_PAB = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


def _tls_policy(bucket: str, extra: list[dict[str, Any]] | None = None) -> str:
    statements = [
        {
            "Sid": "DenyInsecureTransport",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            "Condition": {"Bool": {"aws:SecureTransport": "false"}},
        }
    ] + (extra or [])
    return json.dumps({"Version": "2012-10-17", "Statement": statements})


def build_baseline(session: boto3.session.Session) -> dict[str, str]:
    """Create the same hardened posture terraform/aws deploys. Returns ids the attacks need."""
    account = session.client("sts").get_caller_identity()["Account"]
    s3, ec2, iam = session.client("s3"), session.client("ec2"), session.client("iam")
    kms, ct = session.client("kms"), session.client("cloudtrail")

    session.client("s3control").put_public_access_block(AccountId=account, PublicAccessBlockConfiguration=FULL_PAB)
    key_id = kms.create_key(Description="palisade cloudtrail key")["KeyMetadata"]["KeyId"]
    kms.enable_key_rotation(KeyId=key_id)

    for bucket in (LOG_BUCKET, APP_BUCKET):
        s3.create_bucket(Bucket=bucket)
        s3.put_public_access_block(Bucket=bucket, PublicAccessBlockConfiguration=FULL_PAB)
        s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
        s3.put_bucket_encryption(
            Bucket=bucket,
            ServerSideEncryptionConfiguration={
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "aws:kms",
                            "KMSMasterKeyID": key_id,
                        }
                    }
                ]
            },
        )
        s3.put_bucket_policy(Bucket=bucket, Policy=_tls_policy(bucket))

    trail_arn = ct.create_trail(
        Name=TRAIL,
        S3BucketName=LOG_BUCKET,
        IsMultiRegionTrail=True,
        EnableLogFileValidation=True,
        KmsKeyId=key_id,
    )["TrailARN"]
    ct.start_logging(Name=trail_arn)

    iam.update_account_password_policy(
        MinimumPasswordLength=14, RequireSymbols=True, RequireNumbers=True, PasswordReusePrevention=24
    )
    ec2.enable_ebs_encryption_by_default()

    vpc_id = ec2.describe_vpcs()["Vpcs"][0]["VpcId"]
    for sg in ec2.describe_security_groups(Filters=[{"Name": "group-name", "Values": ["default"]}])["SecurityGroups"]:
        egress = [{k: v for k, v in p.items() if v} for p in sg["IpPermissionsEgress"]]
        if egress:
            ec2.revoke_security_group_egress(GroupId=sg["GroupId"], IpPermissions=egress)
    sg_id = ec2.create_security_group(GroupName=APP_SG, Description="Web tier, HTTPS only", VpcId=vpc_id)["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
    )

    iam.create_role(
        RoleName="palisade-app",
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "ec2.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
    )
    iam.put_role_policy(
        RoleName="palisade-app",
        PolicyName="read-app-data",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject"],
                        "Resource": f"arn:aws:s3:::{APP_BUCKET}/*",
                    }
                ],
            }
        ),
    )
    return {"account": account, "sg_id": sg_id, "trail_arn": trail_arn, "key_id": key_id}


@dataclass
class Scenario:
    name: str
    description: str
    attack_technique: str
    expected_rules: list[str]
    run: Callable[[boto3.session.Session, dict[str, str]], None]


def _public_bucket(session: boto3.session.Session, ids: dict[str, str]) -> None:
    s3 = session.client("s3")
    session.client("s3control").delete_public_access_block(AccountId=ids["account"])
    s3.delete_public_access_block(Bucket=APP_BUCKET)
    public_read = {
        "Sid": "PublicRead",
        "Effect": "Allow",
        "Principal": "*",
        "Action": "s3:GetObject",
        "Resource": f"arn:aws:s3:::{APP_BUCKET}/*",
    }
    s3.put_bucket_policy(Bucket=APP_BUCKET, Policy=_tls_policy(APP_BUCKET, [public_read]))


def _open_ssh(session: boto3.session.Session, ids: dict[str, str]) -> None:
    session.client("ec2").authorize_security_group_ingress(
        GroupId=ids["sg_id"],
        IpPermissions=[{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
    )


def _blind_logging(session: boto3.session.Session, ids: dict[str, str]) -> None:
    ct = session.client("cloudtrail")
    ct.stop_logging(Name=ids["trail_arn"])
    ct.update_trail(Name=ids["trail_arn"], EnableLogFileValidation=False)


def _backdoor_admin(session: boto3.session.Session, ids: dict[str, str]) -> None:
    iam = session.client("iam")
    iam.create_user(UserName="svc-backup")
    iam.create_login_profile(UserName="svc-backup", Password="Tr0ub4dor&3-not-real")  # noqa: S106
    iam.attach_user_policy(UserName="svc-backup", PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess")
    iam.create_access_key(UserName="svc-backup")


def _weaken_crypto(session: boto3.session.Session, ids: dict[str, str]) -> None:
    session.client("kms").disable_key_rotation(KeyId=ids["key_id"])
    session.client("ec2").disable_ebs_encryption_by_default()


def _weaken_passwords(session: boto3.session.Session, ids: dict[str, str]) -> None:
    session.client("iam").update_account_password_policy(MinimumPasswordLength=6, PasswordReusePrevention=1)


SCENARIOS: list[Scenario] = [
    Scenario(
        "public-bucket",
        "Disable Block Public Access and add a public-read bucket policy to the app data bucket",
        "T1530 Data from Cloud Storage",
        ["AWS-S3-001", "AWS-S3-004"],
        _public_bucket,
    ),
    Scenario(
        "open-ssh",
        "Open SSH to 0.0.0.0/0 on the web tier security group",
        "T1562.007 Disable or Modify Cloud Firewall",
        ["AWS-EC2-001"],
        _open_ssh,
    ),
    Scenario(
        "blind-logging",
        "Stop the organization trail and turn off log file validation",
        "T1562.008 Disable or Modify Cloud Logs",
        ["AWS-CT-001", "AWS-CT-002"],
        _blind_logging,
    ),
    Scenario(
        "backdoor-admin",
        "Create a console user with AdministratorAccess, no MFA, and an access key",
        "T1136.003 Create Cloud Account",
        ["AWS-IAM-002", "AWS-IAM-004"],
        _backdoor_admin,
    ),
    Scenario(
        "weaken-crypto",
        "Disable KMS key rotation and EBS default encryption",
        "T1562 Impair Defenses",
        ["AWS-KMS-001", "AWS-EC2-003"],
        _weaken_crypto,
    ),
    Scenario(
        "weaken-passwords",
        "Drop the password policy to 6 characters with no reuse prevention",
        "T1556 Modify Authentication Process",
        ["AWS-IAM-006"],
        _weaken_passwords,
    ),
]


@dataclass
class ScenarioOutcome:
    scenario: Scenario
    detected_rules: list[str]
    remediation: list[RemediationResult] = field(default_factory=list)
    resolved_rules: list[str] = field(default_factory=list)

    @property
    def detected(self) -> bool:
        return set(self.scenario.expected_rules) <= set(self.detected_rules)


@dataclass
class SimulationReport:
    baseline: ScanResult
    after_attack: ScanResult
    after_remediation: ScanResult
    outcomes: list[ScenarioOutcome]
    remediation: list[RemediationResult]
    seconds: dict[str, float]


def run_simulation(
    session: boto3.session.Session,
    scenarios: list[Scenario] | None = None,
    suppressions: list[Suppression] | None = None,
) -> SimulationReport:
    scenarios = scenarios or SCENARIOS
    collector = AwsCollector(session, regions=[REGION])
    timings: dict[str, float] = {}

    ids = build_baseline(session)
    baseline = scan(collector.collect(), suppressions)
    before = {f.key for f in baseline.active}

    for sc in scenarios:
        sc.run(session, ids)

    t0 = time.perf_counter()
    attacked_inv = collector.collect()
    after_attack = scan(attacked_inv, suppressions)
    timings["detect"] = time.perf_counter() - t0

    new = [f for f in after_attack.active if f.key not in before]
    outcomes = [
        ScenarioOutcome(sc, sorted({f.rule_id for f in new if f.rule_id in sc.expected_rules})) for sc in scenarios
    ]

    t0 = time.perf_counter()
    remediation = remediate(new, attacked_inv, session=session, apply=True)
    after_remediation = scan(collector.collect(), suppressions)
    timings["remediate"] = time.perf_counter() - t0

    still_open = {f.rule_id for f in after_remediation.active}
    for outcome in outcomes:
        outcome.remediation = [r for r in remediation if r.rule_id in outcome.scenario.expected_rules]
        outcome.resolved_rules = [r for r in outcome.detected_rules if r not in still_open]

    return SimulationReport(baseline, after_attack, after_remediation, outcomes, remediation, timings)


def render_report(report: SimulationReport) -> str:
    applied = sum(r.status == Status.APPLIED for r in report.remediation)
    planned = sum(r.status == Status.PLANNED for r in report.remediation)
    detected = sum(o.detected for o in report.outcomes)
    lines = [
        "# Attack simulation report",
        "",
        "Generated by `palisade simulate` against an in-memory AWS account (moto). "
        "A hardened baseline matching `terraform/aws` is built, every scenario is executed, "
        "then Palisade scans, auto-remediates what is safe, and rescans.",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Scenarios detected | {detected} / {len(report.outcomes)} |",
        f"| Active findings: baseline / after attack / after remediation | "
        f"{len(report.baseline.active)} / {len(report.after_attack.active)} / {len(report.after_remediation.active)} |",
        f"| Fixes auto-applied | {applied} |",
        f"| Fixes queued for human approval | {planned} |",
        f"| Detection scan time | {report.seconds['detect']:.2f}s |",
        f"| Remediate + verify time | {report.seconds['remediate']:.2f}s |",
        "",
        "## Scenarios",
        "",
        "| Scenario | ATT&CK technique | Detected by | Outcome |",
        "|---|---|---|---|",
    ]
    for o in report.outcomes:
        if not o.detected:
            outcome = "MISSED"
        elif set(o.resolved_rules) == set(o.detected_rules):
            outcome = "Auto-remediated"
        elif o.resolved_rules:
            outcome = f"Partially fixed ({', '.join(o.resolved_rules)}); rest queued for review"
        else:
            outcome = "Detected; fix queued for human approval"
        lines.append(
            f"| `{o.scenario.name}`: {o.scenario.description} | {o.scenario.attack_technique} | "
            f"{', '.join(o.detected_rules) or 'none'} | {outcome} |"
        )
    lines += ["", "## Remediation log", "", "| Status | Rule | Resource | Action |", "|---|---|---|---|"]
    for r in report.remediation:
        lines.append(f"| {r.status.value} | {r.rule_id} | `{short_id(r.resource_id)}` | {r.action} |")
    lines += [
        "",
        "## Why IAM fixes are not automatic",
        "",
        "Deleting a user or detaching a policy can take down a production workload, and a real "
        "attacker-created admin should trigger incident response (preserve evidence, find what the "
        "credentials touched) rather than a silent cleanup. Palisade raises those findings as high "
        "severity and emits the exact remediation commands for a human to run.",
        "",
    ]
    return "\n".join(lines)
