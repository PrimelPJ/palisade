"""Decide which fixes an Azure resource needs. Pure logic, no SDK, fully unit-tested.

The Event Grid handler in function_app.py fetches the changed resource's ARM JSON,
runs it through the same Palisade rules the CLI uses, and turns failures into Fix
objects. Only reversible fixes are marked ``auto``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from palisade.collectors.azure import AzureSnapshotCollector
from palisade.scanner import scan

STORAGE = "microsoft.storage/storageaccounts"
NSG = "microsoft.network/networksecuritygroups"
VAULT = "microsoft.keyvault/vaults"

SNAPSHOT_KEY = {STORAGE: "storage_accounts", NSG: "nsgs", VAULT: "key_vaults"}

# Storage property patches that tighten a setting without data loss.
STORAGE_PATCH = {
    "AZ-STG-001": {"allowBlobPublicAccess": False},
    "AZ-STG-002": {"supportsHttpsTrafficOnly": True},
    "AZ-STG-003": {"minimumTlsVersion": "TLS1_2"},
}


@dataclass
class Fix:
    rule_id: str
    resource_id: str
    kind: str  # "patch_properties" | "delete_nsg_rule" | "alert_only"
    auto: bool
    payload: dict[str, Any] = field(default_factory=dict)
    reason: str = ""


def resource_type(resource_id: str) -> str:
    parts = resource_id.strip("/").split("/")
    try:
        i = parts.index("providers")
        return f"{parts[i + 1]}/{parts[i + 2]}".lower()
    except (ValueError, IndexError):
        return ""


def plan_fixes(arm_resource: dict[str, Any]) -> list[Fix]:
    rtype = resource_type(arm_resource.get("id", ""))
    key = SNAPSHOT_KEY.get(rtype)
    if key is None:
        return []
    snapshot = {"subscription_id": arm_resource["id"].split("/")[2], key: [arm_resource]}
    result = scan(AzureSnapshotCollector(snapshot).collect(), only_resource_types={_inventory_type(rtype)})

    fixes: list[Fix] = []
    storage_patch: dict[str, Any] = {}
    for f in result.active:
        if f.rule_id in STORAGE_PATCH:
            storage_patch.update(STORAGE_PATCH[f.rule_id])
        elif f.rule_id == "AZ-NSG-001":
            rule_name = f.detail.split("'")[1]
            fixes.append(Fix(f.rule_id, f.resource_id, "delete_nsg_rule", True, {"rule": rule_name}, f.detail))
        else:
            # Network lockdown, purge protection (irreversible) and RBAC migration need a human.
            fixes.append(Fix(f.rule_id, f.resource_id, "alert_only", False, reason=f.detail))
    if storage_patch:
        fixes.insert(
            0,
            Fix(
                "AZ-STG",
                arm_resource["id"],
                "patch_properties",
                True,
                {"properties": storage_patch},
                "storage hardening",
            ),
        )
    return fixes


def _inventory_type(rtype: str) -> str:
    return {STORAGE: "storage_account", NSG: "nsg", VAULT: "key_vault"}[rtype]
