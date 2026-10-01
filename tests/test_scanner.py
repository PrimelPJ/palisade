from datetime import date

import pytest

from palisade.collectors.azure import AzureSnapshotCollector
from palisade.models import Severity
from palisade.registry import all_rules
from palisade.scanner import load_suppressions, scan


def test_rule_ids_are_unique_and_documented():
    rules = all_rules()
    assert len({r.id for r in rules}) == len(rules) == 29
    for r in rules:
        assert r.cis and r.remediation and r.title


def test_suppression_file(tmp_path, azure_snapshot_path):
    f = tmp_path / "ignore.yaml"
    f.write_text(
        "suppressions:\n"
        "  - rule: AZ-KV-*\n    resource: '*kv-legacy'\n    reason: decommissioning in Q4\n    expires: 2099-01-01\n"
    )
    result = scan(AzureSnapshotCollector.from_file(azure_snapshot_path).collect(), load_suppressions(f))
    assert {x.rule_id for x in result.suppressed} == {"AZ-KV-001", "AZ-KV-002", "AZ-KV-003"}
    assert all(x.suppression_reason == "decommissioning in Q4" for x in result.suppressed)
    assert not any(x.rule_id.startswith("AZ-KV") for x in result.active)


def test_expired_suppression_stops_applying(tmp_path, azure_snapshot_path):
    f = tmp_path / "ignore.yaml"
    f.write_text("suppressions:\n  - rule: AZ-SQL-001\n    reason: temp\n    expires: 2026-01-01\n")
    result = scan(
        AzureSnapshotCollector.from_file(azure_snapshot_path).collect(),
        load_suppressions(f),
        today=date(2026, 6, 1),
    )
    assert any(x.rule_id == "AZ-SQL-001" for x in result.active)


def test_suppression_without_reason_is_rejected(tmp_path):
    f = tmp_path / "ignore.yaml"
    f.write_text("suppressions:\n  - rule: AZ-SQL-001\n")
    with pytest.raises(ValueError, match="missing a reason"):
        load_suppressions(f)


def test_threshold_and_ordering(azure_snapshot_path):
    result = scan(AzureSnapshotCollector.from_file(azure_snapshot_path).collect())
    assert result.fails_threshold(Severity.CRITICAL)
    ranks = [f.severity.rank for f in result.active]
    assert ranks == sorted(ranks, reverse=True)
    assert result.counts() == {"critical": 1, "high": 5, "medium": 5, "low": 2}
