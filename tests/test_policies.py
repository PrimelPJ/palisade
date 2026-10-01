import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(shutil.which("checkov") is None, reason="checkov not installed")


def checkov(directory: Path) -> dict:
    out = subprocess.run(
        [
            "checkov",
            "-d",
            str(directory),
            "--external-checks-dir",
            str(ROOT / "policies" / "checkov"),
            "--framework",
            "terraform",
            "-o",
            "json",
            "--skip-download",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    data = json.loads(out.stdout)
    return data if isinstance(data, dict) else data[0]


def test_custom_policies_reject_insecure_fixture():
    failed = {
        (c["check_id"], c["resource"])
        for c in checkov(ROOT / "tests" / "fixtures" / "terraform_insecure")["results"]["failed_checks"]
    }
    assert {
        ("CKV2_PAL_1", "azurerm_resource_group.untagged"),
        ("CKV2_PAL_1", "azurerm_storage_account.weak"),
        ("CKV2_PAL_2", "aws_cloudtrail.single_region"),
        ("CKV2_PAL_3", "azurerm_storage_account.weak"),
        ("CKV2_PAL_4", "aws_s3_bucket.disposable"),
    } <= failed


@pytest.mark.parametrize("stack", ["aws", "azure"])
def test_landing_zones_pass_every_check(stack):
    result = checkov(ROOT / "terraform" / stack)
    assert result["summary"]["parsing_errors"] == 0
    assert result["results"]["failed_checks"] == [], [
        (c["check_id"], c["resource"]) for c in result["results"]["failed_checks"]
    ]
