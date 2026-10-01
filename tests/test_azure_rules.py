import json

from palisade.collectors.azure import AzureSnapshotCollector
from palisade.rules.azure import _port_matches
from palisade.scanner import scan


def findings(path):
    return scan(AzureSnapshotCollector.from_file(path).collect()).active


def test_example_snapshot_findings(azure_snapshot_path):
    got = sorted((f.rule_id, f.resource_id.rsplit("/", 1)[-1]) for f in findings(azure_snapshot_path))
    assert got == sorted(
        [
            ("AZ-SQL-001", "sql-legacy"),
            ("AZ-IAM-001", "11111111-1111-1111-1111-111111111111"),
            ("AZ-NSG-001", "nsg-jumpbox"),
            ("AZ-NSG-001", "nsg-jumpbox"),
            ("AZ-STG-001", "stlegacyreports"),
            ("AZ-STG-002", "stlegacyreports"),
            ("AZ-STG-003", "stlegacyreports"),
            ("AZ-STG-004", "stlegacyreports"),
            ("AZ-KV-001", "kv-legacy"),
            ("AZ-KV-002", "kv-legacy"),
            ("AZ-KV-003", "kv-legacy"),
            ("AZ-MON-001", "00000000-0000-0000-0000-000000000000"),
            ("AZ-DEF-001", "00000000-0000-0000-0000-000000000000"),
        ]
    )


def test_hardened_resources_are_clean(azure_snapshot_path):
    flagged = {f.resource_id.rsplit("/", 1)[-1] for f in findings(azure_snapshot_path)}
    assert not flagged & {
        "stpalisadeprod",
        "nsg-app",
        "kv-palisade-prod",
        "22222222-2222-2222-2222-222222222222",
    }


def test_nsg_port_range_catches_ssh(azure_snapshot_path):
    details = [f.detail for f in findings(azure_snapshot_path) if f.rule_id == "AZ-NSG-001"]
    assert "Rule 'allow-mgmt-range' allows SSH (port 22) from the internet" in details


def test_deny_rule_is_ignored():
    snap = {
        "nsgs": [
            {
                "id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/n",
                "securityRules": [
                    {
                        "name": "deny-ssh",
                        "access": "Deny",
                        "direction": "Inbound",
                        "sourceAddressPrefix": "*",
                        "destinationPortRange": "22",
                    }
                ],
            }
        ]
    }
    rules = {f.rule_id for f in scan(AzureSnapshotCollector(snap).collect()).active}
    assert "AZ-NSG-001" not in rules


def test_arm_nested_properties_are_read():
    """Raw ARM JSON nests rule fields under properties; az CLI flattens them."""
    snap = {
        "nsgs": [
            {
                "id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/n",
                "properties": {
                    "securityRules": [
                        {
                            "name": "ssh",
                            "properties": {
                                "access": "Allow",
                                "direction": "Inbound",
                                "sourceAddressPrefix": "Internet",
                                "destinationPortRange": "22",
                            },
                        }
                    ]
                },
            }
        ],
        "storage_accounts": [
            {
                "id": "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/st",
                "name": "st",
                "properties": {
                    "supportsHttpsTrafficOnly": False,
                    "minimumTlsVersion": "TLS1_2",
                    "networkAcls": {},
                    "networkRuleSet": {"defaultAction": "Deny"},
                },
            }
        ],
    }
    rules = {f.rule_id for f in scan(AzureSnapshotCollector(snap).collect()).active}
    assert {"AZ-NSG-001", "AZ-STG-002"} <= rules


def test_port_matching():
    assert _port_matches("*", 22)
    assert _port_matches("20-25", 22)
    assert _port_matches("3389", 3389)
    assert not _port_matches("443", 22)
    assert not _port_matches("1000-2000", 22)


def test_missing_defender_plan_counts_as_free(tmp_path):
    snap = {"defender_pricings": [{"name": "Arm", "pricingTier": "Standard"}]}
    p = tmp_path / "s.json"
    p.write_text(json.dumps(snap))
    detail = next(f.detail for f in findings(p) if f.rule_id == "AZ-DEF-001")
    assert "VirtualMachines" in detail and "Arm" not in detail
