import os
import sys
from pathlib import Path

import boto3
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "functions" / "aws_lambda"))
sys.path.insert(0, str(ROOT / "functions" / "azure_function"))

# Never let a test touch a real account.
os.environ.update(
    {
        "AWS_ACCESS_KEY_ID": "testing",
        "AWS_SECRET_ACCESS_KEY": "testing",
        "AWS_SESSION_TOKEN": "testing",
        "AWS_DEFAULT_REGION": "us-east-1",
        "MOTO_IAM_LOAD_MANAGED_POLICIES": "true",
    }
)

from moto import mock_aws  # noqa: E402

from palisade.simulate import build_baseline  # noqa: E402

EXAMPLES = ROOT / "examples"


@pytest.fixture
def session():
    with mock_aws():
        yield boto3.session.Session(region_name="us-east-1")


@pytest.fixture
def hardened(session):
    """A moto account matching terraform/aws, plus the ids attacks need."""
    ids = build_baseline(session)
    return session, ids


@pytest.fixture
def azure_snapshot_path():
    return EXAMPLES / "azure-snapshot.json"
