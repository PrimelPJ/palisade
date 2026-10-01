import json

import pytest

from palisade.collectors.aws import AwsCollector
from palisade.scanner import Suppression, scan
from palisade.simulate import APP_BUCKET, SCENARIOS

ROOT_MFA = [Suppression("AWS-IAM-001", "*", "moto cannot emulate root MFA")]


def active_rules(session, **kw):
    result = scan(AwsCollector(session).collect(), ROOT_MFA, **kw)
    return {f.rule_id for f in result.active}, result


def test_hardened_baseline_is_clean(hardened):
    session, _ = hardened
    rules, result = active_rules(session)
    assert rules == set(), [f.detail for f in result.active]


def test_root_mfa_fires_without_suppression(hardened):
    session, _ = hardened
    result = scan(AwsCollector(session).collect())
    assert {f.rule_id for f in result.active} == {"AWS-IAM-001"}


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.name)
def test_every_attack_is_detected(hardened, scenario):
    session, ids = hardened
    scenario.run(session, ids)
    rules, _ = active_rules(session)
    assert set(scenario.expected_rules) <= rules


def test_public_acl_is_detected(hardened):
    session, ids = hardened
    s3 = session.client("s3")
    session.client("s3control").delete_public_access_block(AccountId=ids["account"])
    s3.delete_public_access_block(Bucket=APP_BUCKET)
    s3.put_bucket_acl(Bucket=APP_BUCKET, ACL="public-read")
    _, result = active_rules(session)
    details = [f.detail for f in result.active if f.rule_id == "AWS-S3-004"]
    assert any("AllUsers" in d for d in details)


def test_account_pab_alone_satisfies_bucket_rule(hardened):
    session, _ = hardened
    session.client("s3").delete_public_access_block(Bucket=APP_BUCKET)
    rules, _ = active_rules(session)
    assert "AWS-S3-001" not in rules  # account-level block still covers the bucket


def test_conditional_public_statement_is_not_public(hardened):
    session, ids = hardened
    s3 = session.client("s3")
    session.client("s3control").delete_public_access_block(AccountId=ids["account"])
    s3.delete_public_access_block(Bucket=APP_BUCKET)
    policy = json.loads(s3.get_bucket_policy(Bucket=APP_BUCKET)["Policy"])
    policy["Statement"].append(
        {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": f"arn:aws:s3:::{APP_BUCKET}/*",
            "Condition": {"StringEquals": {"aws:SourceVpce": "vpce-123"}},
        }
    )
    s3.put_bucket_policy(Bucket=APP_BUCKET, Policy=json.dumps(policy))
    rules, _ = active_rules(session)
    assert "AWS-S3-004" not in rules


def test_missing_tls_policy(hardened):
    session, _ = hardened
    session.client("s3").delete_bucket_policy(Bucket=APP_BUCKET)
    rules, _ = active_rules(session)
    assert "AWS-S3-002" in rules


def test_rdp_via_all_traffic_rule(hardened):
    session, ids = hardened
    session.client("ec2").authorize_security_group_ingress(
        GroupId=ids["sg_id"], IpPermissions=[{"IpProtocol": "-1", "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}]
    )
    _, result = active_rules(session)
    details = {f.detail for f in result.active if f.rule_id == "AWS-EC2-001"}
    assert details == {"SSH (port 22) open to ::/0", "RDP (port 3389) open to ::/0"}


def test_https_from_internet_is_allowed(hardened):
    session, _ = hardened
    rules, _ = active_rules(session)
    assert "AWS-EC2-001" not in rules  # baseline already exposes 443


def test_inline_star_policy_on_role(hardened):
    session, _ = hardened
    session.client("iam").put_role_policy(
        RoleName="palisade-app",
        PolicyName="oops",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        ),
    )
    rules, _ = active_rules(session)
    assert "AWS-IAM-005" in rules


def test_old_access_key(hardened, monkeypatch):
    session, _ = hardened
    iam = session.client("iam")
    iam.create_user(UserName="ci")
    iam.create_access_key(UserName="ci")
    inventory = AwsCollector(session).collect()
    for user in inventory.of("iam_user"):
        for key in user["access_keys"]:
            key["age_days"] = 120
    result = scan(inventory, ROOT_MFA)
    assert any(f.rule_id == "AWS-IAM-003" and "120 days" in f.detail for f in result.active)


def test_default_sg_with_rules(session):
    rules, _ = active_rules(session)  # fresh moto account: default SG allows all egress
    assert "AWS-EC2-002" in rules
    assert "AWS-CT-001" in rules
    assert "AWS-IAM-006" in rules
