import json

import pytest
from handler import handler  # functions/aws_lambda on sys.path via conftest
from remediator import plan_fixes  # functions/azure_function

from palisade.simulate import APP_BUCKET, SCENARIOS

BY_NAME = {s.name: s for s in SCENARIOS}


def cloudtrail_event(name, **detail):
    return {
        "source": "aws.s3",
        "detail-type": "AWS API Call via CloudTrail",
        "detail": {
            "eventName": name,
            "awsRegion": "us-east-1",
            "userIdentity": {"arn": "arn:aws:iam::123456789012:user/careless-dev"},
            "sourceIPAddress": "203.0.113.7",
            **detail,
        },
    }


def test_lambda_fixes_open_ssh_in_one_invocation(hardened):
    session, ids = hardened
    BY_NAME["open-ssh"].run(session, ids)
    out = handler(cloudtrail_event("AuthorizeSecurityGroupIngress"), session=session)
    assert out["status"] == "processed"
    assert [f["rule_id"] for f in out["findings"]] == ["AWS-EC2-001"]
    assert out["remediation"][0]["status"] == "applied"
    assert out["trigger"]["actor"].endswith("careless-dev")


def test_lambda_alerts_on_backdoor_without_fixing(hardened):
    session, ids = hardened
    sns = session.client("sns")
    topic = sns.create_topic(Name="palisade-alerts")["TopicArn"]
    BY_NAME["backdoor-admin"].run(session, ids)
    import os

    os.environ["PALISADE_ALERT_TOPIC_ARN"] = topic
    try:
        out = handler(cloudtrail_event("AttachUserPolicy"), session=session)
    finally:
        del os.environ["PALISADE_ALERT_TOPIC_ARN"]
    assert {f["rule_id"] for f in out["findings"]} == {"AWS-IAM-002", "AWS-IAM-004"}
    assert {r["status"] for r in out["remediation"]} == {"planned"}


def test_lambda_ignores_root_mfa_noise_on_narrow_events(hardened):
    session, _ = hardened
    out = handler(cloudtrail_event("PutBucketVersioning"), session=session)
    assert out["findings"] == []


def test_lambda_restarts_stopped_trail(hardened):
    session, ids = hardened
    BY_NAME["blind-logging"].run(session, ids)
    out = handler(cloudtrail_event("StopLogging"), session=session)
    assert {f["rule_id"] for f in out["findings"]} == {"AWS-CT-001", "AWS-CT-002"}
    assert session.client("cloudtrail").get_trail_status(Name=ids["trail_arn"])["IsLogging"]


@pytest.mark.parametrize(
    "event,reason",
    [
        (cloudtrail_event("GetObject"), "not monitored"),
        (cloudtrail_event("PutBucketPolicy", errorCode="AccessDenied"), "failed"),
    ],
)
def test_lambda_ignores_irrelevant_events(session, event, reason):
    out = handler(event, session=session)
    assert out["status"] == "ignored" and reason in out["reason"]


def test_lambda_ignores_its_own_calls(session, monkeypatch):
    monkeypatch.setenv("PALISADE_SELF_ROLE_NAME", "palisade-remediator")
    event = cloudtrail_event(
        "PutBucketPublicAccessBlock",
        userIdentity={"arn": "arn:aws:sts::123456789012:assumed-role/palisade-remediator/session"},
    )
    assert handler(event, session=session)["reason"] == "self-generated event"


def test_lambda_dry_run(hardened, monkeypatch):
    session, ids = hardened
    monkeypatch.setenv("PALISADE_DRY_RUN", "true")
    BY_NAME["public-bucket"].run(session, ids)
    out = handler(cloudtrail_event("PutBucketPolicy"), session=session)
    assert {r["status"] for r in out["remediation"]} == {"planned"}
    policy = json.loads(session.client("s3").get_bucket_policy(Bucket=APP_BUCKET)["Policy"])
    assert len(policy["Statement"]) == 2  # still public


# ---- Azure Function decision logic --------------------------------------------------

STG_ID = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/stleaky"
NSG_ID = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg-vm"


def test_azure_function_patches_storage_in_one_call():
    arm = {
        "id": STG_ID,
        "name": "stleaky",
        "properties": {
            "allowBlobPublicAccess": True,
            "supportsHttpsTrafficOnly": False,
            "minimumTlsVersion": "TLS1_0",
            "networkAcls": {"defaultAction": "Allow"},
        },
    }
    fixes = plan_fixes(arm)
    patch = next(f for f in fixes if f.kind == "patch_properties")
    assert patch.auto and patch.payload["properties"] == {
        "allowBlobPublicAccess": False,
        "supportsHttpsTrafficOnly": True,
        "minimumTlsVersion": "TLS1_2",
    }
    assert any(f.rule_id == "AZ-STG-004" and not f.auto for f in fixes)


def test_azure_function_deletes_only_bad_nsg_rules():
    arm = {
        "id": NSG_ID,
        "name": "nsg-vm",
        "properties": {
            "securityRules": [
                {
                    "name": "ssh-any",
                    "properties": {
                        "access": "Allow",
                        "direction": "Inbound",
                        "sourceAddressPrefix": "*",
                        "destinationPortRange": "22",
                    },
                },
                {
                    "name": "ssh-office",
                    "properties": {
                        "access": "Allow",
                        "direction": "Inbound",
                        "sourceAddressPrefix": "198.51.100.0/24",
                        "destinationPortRange": "22",
                    },
                },
            ]
        },
    }
    fixes = plan_fixes(arm)
    assert [(f.kind, f.payload.get("rule")) for f in fixes] == [("delete_nsg_rule", "ssh-any")]


def test_azure_function_ignores_unmonitored_types():
    assert plan_fixes({"id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Web/sites/app"}) == []
