"""Azure fixes are emitted as reviewed ``az`` CLI plans.

The scanner works from read-only snapshots, so Azure remediation produces the exact
commands to run. ``functions/azure_function`` applies the same fixes live from an
Event Grid trigger once deployed.
"""

from __future__ import annotations

from typing import Any

from palisade.models import Finding
from palisade.remediate import register_plan_only


def _rg(res: dict[str, Any]) -> str:
    parts = str(res.get("id", "")).split("/")
    try:
        return parts[parts.index("resourceGroups") + 1]
    except (ValueError, IndexError):
        return "<resource-group>"


def _stg(flags: str):
    return lambda r, f: f"az storage account update -n {r.get('name')} -g {_rg(r)} {flags}"


def _kv(flags: str):
    return lambda r, f: f"az keyvault update -n {r.get('name')} -g {_rg(r)} {flags}"


def _nsg_rule_name(f: Finding) -> str:
    return f.detail.split("'")[1] if "'" in f.detail else "<rule>"


def _sql_rule_name(f: Finding) -> str:
    return f.detail.split("'")[1] if "'" in f.detail else "<rule>"


register_plan_only("AZ-STG-001", "Disable anonymous blob access", _stg("--allow-blob-public-access false"))
register_plan_only("AZ-STG-002", "Require HTTPS", _stg("--https-only true"))
register_plan_only("AZ-STG-003", "Require TLS 1.2", _stg("--min-tls-version TLS1_2"))
register_plan_only("AZ-STG-004", "Deny network access by default", _stg("--default-action Deny"))
register_plan_only(
    "AZ-NSG-001",
    "Delete the internet-facing admin rule",
    lambda r, f: f"az network nsg rule delete -g {_rg(r)} --nsg-name {r.get('name')} -n {_nsg_rule_name(f)}",
)
register_plan_only("AZ-KV-001", "Enable purge protection (irreversible)", _kv("--enable-purge-protection true"))
register_plan_only("AZ-KV-002", "Disable public network access", _kv("--public-network-access Disabled"))
register_plan_only("AZ-KV-003", "Switch the vault to RBAC authorization", _kv("--enable-rbac-authorization true"))
register_plan_only(
    "AZ-IAM-001",
    "Replace subscription Owner with a scoped role",
    lambda r, f: f"az role assignment delete --ids {r.get('id')}  # after granting a scoped replacement",
)
register_plan_only(
    "AZ-SQL-001",
    "Delete the allow-all firewall rule",
    lambda r, f: f"az sql server firewall-rule delete -g {_rg(r)} -s {r.get('name')} -n {_sql_rule_name(f)}",
)
register_plan_only(
    "AZ-MON-001",
    "Export the activity log to Log Analytics",
    lambda r, f: (
        "az monitor diagnostic-settings subscription create -n palisade-activity "
        '--workspace <law-id> --logs \'[{"category":"Administrative","enabled":true},'
        '{"category":"Security","enabled":true},{"category":"Policy","enabled":true}]\''
    ),
)
register_plan_only(
    "AZ-DEF-001",
    "Enable Defender Standard tier",
    lambda r, f: (
        "for p in VirtualMachines StorageAccounts KeyVaults SqlServers Arm; "
        "do az security pricing create -n $p --tier Standard; done"
    ),
)
