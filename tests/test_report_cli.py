import json

from click.testing import CliRunner

from palisade.cli import main
from palisade.collectors.azure import AzureSnapshotCollector
from palisade.report import short_id, to_markdown, to_sarif
from palisade.scanner import Suppression, scan


def test_sarif_is_valid_for_github(azure_snapshot_path):
    result = scan(
        AzureSnapshotCollector.from_file(azure_snapshot_path).collect(),
        [Suppression("AZ-KV-003", "*", "migrating to RBAC")],
    )
    sarif = to_sarif(result)
    run = sarif["runs"][0]
    rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
    assert sarif["version"] == "2.1.0"
    for res in run["results"]:
        assert rule_ids[res["ruleIndex"]] == res["ruleId"]
        assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith("cloud/azure/")
        assert res["partialFingerprints"]["palisadeFindingKey"]
    assert any("suppressions" in r for r in run["results"])
    for rule in run["tool"]["driver"]["rules"]:
        assert 0 < float(rule["properties"]["security-severity"]) <= 10


def test_markdown_summary(azure_snapshot_path):
    md = to_markdown(scan(AzureSnapshotCollector.from_file(azure_snapshot_path).collect()))
    assert "| 1 | 5 | 5 | 2 | 0 |" in md
    assert "`sql-legacy`" in md


def test_short_id():
    assert short_id("/subscriptions/x/resourceGroups/rg/providers/Microsoft.Sql/servers/db") == "db"
    assert short_id("arn:aws:iam::123456789012:user/alice") == "user/alice"
    assert short_id("my-bucket") == "my-bucket"


def test_cli_fail_on_and_json(azure_snapshot_path, tmp_path):
    runner = CliRunner()
    out = tmp_path / "r.json"
    res = runner.invoke(
        main,
        [
            "scan",
            "azure",
            "--snapshot",
            str(azure_snapshot_path),
            "--format",
            "json",
            "-o",
            str(out),
            "--fail-on",
            "critical",
        ],
    )
    assert res.exit_code == 1
    assert json.loads(out.read_text())["summary"]["critical"] == 1


def test_cli_inventory_replay(azure_snapshot_path, tmp_path):
    runner = CliRunner()
    inv = tmp_path / "inv.json"
    runner.invoke(main, ["scan", "azure", "--snapshot", str(azure_snapshot_path), "--save-inventory", str(inv)])
    res = runner.invoke(main, ["scan", "azure", "--inventory", str(inv), "--format", "markdown"])
    assert res.exit_code == 0 and "AZ-SQL-001" in res.output


def test_cli_rejects_apply_without_live_session(azure_snapshot_path):
    res = CliRunner().invoke(main, ["remediate", "azure", "--snapshot", str(azure_snapshot_path), "--apply"])
    assert res.exit_code != 0 and "plan-only" in res.output
