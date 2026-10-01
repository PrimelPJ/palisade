import json

from palisade.collectors.aws import AwsCollector
from palisade.collectors.azure import AzureSnapshotCollector
from palisade.remediate import Status, remediate
from palisade.scanner import Suppression, scan
from palisade.simulate import APP_BUCKET, SCENARIOS

ROOT_MFA = [Suppression("AWS-IAM-001", "*", "moto")]
BY_NAME = {s.name: s for s in SCENARIOS}


def attack_and_fix(session, ids, *names, apply=True, include_manual=False):
    for n in names:
        BY_NAME[n].run(session, ids)
    inv = AwsCollector(session).collect()
    results = remediate(scan(inv, ROOT_MFA).active, inv, session=session, apply=apply, include_manual=include_manual)
    after = {f.rule_id for f in scan(AwsCollector(session).collect(), ROOT_MFA).active}
    return results, after


def test_public_bucket_is_closed_and_tls_statement_kept(hardened):
    session, ids = hardened
    results, after = attack_and_fix(session, ids, "public-bucket")
    assert not after & {"AWS-S3-001", "AWS-S3-004"}
    statements = json.loads(session.client("s3").get_bucket_policy(Bucket=APP_BUCKET)["Policy"])["Statement"]
    assert [s["Sid"] for s in statements] == ["DenyInsecureTransport"]
    assert all(r.status == Status.APPLIED for r in results)


def test_open_ssh_is_revoked_but_https_survives(hardened):
    session, ids = hardened
    _, after = attack_and_fix(session, ids, "open-ssh")
    assert "AWS-EC2-001" not in after
    sg = session.client("ec2").describe_security_groups(GroupIds=[ids["sg_id"]])["SecurityGroups"][0]
    assert [(p["FromPort"], p["ToPort"]) for p in sg["IpPermissions"]] == [(443, 443)]


def test_trail_is_restarted(hardened):
    session, ids = hardened
    _, after = attack_and_fix(session, ids, "blind-logging")
    assert not after & {"AWS-CT-001", "AWS-CT-002"}
    assert session.client("cloudtrail").get_trail_status(Name=ids["trail_arn"])["IsLogging"]


def test_iam_backdoor_is_never_auto_fixed(hardened):
    session, ids = hardened
    results, after = attack_and_fix(session, ids, "backdoor-admin")
    iam_results = [r for r in results if r.rule_id.startswith("AWS-IAM")]
    assert iam_results and all(r.status == Status.PLANNED for r in iam_results)
    assert {"AWS-IAM-002", "AWS-IAM-004"} <= after
    # The user still exists: deleting attacker artifacts would destroy evidence.
    session.client("iam").get_user(UserName="svc-backup")


def test_dry_run_changes_nothing(hardened):
    session, ids = hardened
    results, after = attack_and_fix(session, ids, "open-ssh", "weaken-crypto", apply=False)
    assert all(r.status == Status.PLANNED for r in results)
    assert {"AWS-EC2-001", "AWS-KMS-001", "AWS-EC2-003"} <= after


def test_fresh_account_default_sg_and_password_policy(session):
    inv = AwsCollector(session).collect()
    remediate(scan(inv, ROOT_MFA).active, inv, session=session, apply=True)
    after = {f.rule_id for f in scan(AwsCollector(session).collect(), ROOT_MFA).active}
    assert not after & {"AWS-EC2-002", "AWS-IAM-006", "AWS-EC2-003"}
    assert "AWS-CT-001" in after  # no trail to restart; needs terraform


def test_trail_creation_is_reported_as_failed_not_silent(session):
    inv = AwsCollector(session).collect()
    results = remediate(scan(inv, ROOT_MFA).active, inv, session=session, apply=True)
    ct = next(r for r in results if r.rule_id == "AWS-CT-001")
    assert ct.status == Status.FAILED and "terraform" in ct.detail


def test_suppressed_findings_are_not_remediated(hardened):
    session, ids = hardened
    BY_NAME["open-ssh"].run(session, ids)
    inv = AwsCollector(session).collect()
    result = scan(inv, ROOT_MFA + [Suppression("AWS-EC2-001", "*", "bastion migration in progress")])
    results = remediate(result.findings, inv, session=session, apply=True)
    assert not any(r.rule_id == "AWS-EC2-001" for r in results)


def test_azure_plan_has_one_command_per_nsg_rule(azure_snapshot_path):
    inv = AzureSnapshotCollector.from_file(azure_snapshot_path).collect()
    results = remediate(scan(inv).active, inv)
    nsg = sorted(r.detail for r in results if r.rule_id == "AZ-NSG-001")
    assert nsg == [
        "az network nsg rule delete -g rg-legacy --nsg-name nsg-jumpbox -n allow-mgmt-range",
        "az network nsg rule delete -g rg-legacy --nsg-name nsg-jumpbox -n allow-rdp-anywhere",
    ]
    assert all(r.status == Status.PLANNED for r in results)
