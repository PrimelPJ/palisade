"""Build a normalized Azure inventory from an ``az`` CLI snapshot.

``scripts/export_azure_snapshot.sh`` captures the raw JSON with read-only ``az``
commands. Separating capture from evaluation means the scanner needs no Azure
SDK credentials at all, and snapshots can be diffed, archived as audit evidence,
or replayed in CI.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from palisade.models import Inventory, Provider


def _get(d: dict[str, Any], *path: str, default: Any = None) -> Any:
    """Read a key that ``az`` may emit either flattened or under ``properties``."""
    for candidate in (d, d.get("properties", {}) or {}):
        cur: Any = candidate
        for key in path:
            if not isinstance(cur, dict) or key not in cur:
                cur = None
                break
            cur = cur[key]
        if cur is not None:
            return cur
    return default


def _ports(rule: dict[str, Any]) -> list[str]:
    ports = [_get(rule, "destinationPortRange")] + list(_get(rule, "destinationPortRanges", default=[]) or [])
    return [str(p) for p in ports if p not in (None, "")]


def _sources(rule: dict[str, Any]) -> list[str]:
    sources = [_get(rule, "sourceAddressPrefix")] + list(_get(rule, "sourceAddressPrefixes", default=[]) or [])
    return [str(s) for s in sources if s not in (None, "")]


class AzureSnapshotCollector:
    def __init__(self, snapshot: dict[str, Any]):
        self.raw = snapshot

    @classmethod
    def from_file(cls, path: str | Path) -> AzureSnapshotCollector:
        return cls(json.loads(Path(path).read_text()))

    def collect(self) -> Inventory:
        raw = self.raw
        sub = raw.get("subscription_id", "unknown")
        resources = {
            "storage_account": [self._storage(s) for s in raw.get("storage_accounts", [])],
            "nsg": [self._nsg(n) for n in raw.get("nsgs", [])],
            "key_vault": [self._vault(v) for v in raw.get("key_vaults", [])],
            "role_assignment": [self._role(r) for r in raw.get("role_assignments", [])],
            "sql_server": [self._sql(s) for s in raw.get("sql_servers", [])],
            "subscription": [
                {
                    "id": f"/subscriptions/{sub}",
                    "activity_log_diagnostics": raw.get("activity_log_diagnostics", []),
                    "defender_pricings": [
                        {"name": p.get("name"), "tier": _get(p, "pricingTier", default="Free")}
                        for p in raw.get("defender_pricings", [])
                    ],
                }
            ],
        }
        return Inventory(provider=Provider.AZURE, account=sub, resources=resources)

    @staticmethod
    def _storage(s: dict[str, Any]) -> dict[str, Any]:
        # The az CLI says enableHttpsTrafficOnly; raw ARM JSON says supportsHttpsTrafficOnly.
        https_only = _get(s, "enableHttpsTrafficOnly")
        if https_only is None:
            https_only = _get(s, "supportsHttpsTrafficOnly", default=True)
        return {
            "id": s["id"],
            "name": s.get("name"),
            "allow_blob_public_access": bool(_get(s, "allowBlobPublicAccess", default=False)),
            "https_only": bool(https_only),
            "min_tls_version": _get(s, "minimumTlsVersion", default="TLS1_0"),
            "network_default_action": _get(s, "networkRuleSet", "defaultAction", default="Allow"),
            "shared_key_access": _get(s, "allowSharedKeyAccess", default=True),
        }

    @staticmethod
    def _nsg(n: dict[str, Any]) -> dict[str, Any]:
        rules = []
        for r in _get(n, "securityRules", default=[]) or []:
            rules.append(
                {
                    "name": r.get("name"),
                    "access": _get(r, "access"),
                    "direction": _get(r, "direction"),
                    "protocol": _get(r, "protocol"),
                    "priority": _get(r, "priority"),
                    "sources": _sources(r),
                    "ports": _ports(r),
                }
            )
        return {"id": n["id"], "name": n.get("name"), "rules": rules}

    @staticmethod
    def _vault(v: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": v["id"],
            "name": v.get("name"),
            "soft_delete": bool(_get(v, "enableSoftDelete", default=True)),
            "purge_protection": bool(_get(v, "enablePurgeProtection", default=False)),
            "public_network_access": _get(v, "publicNetworkAccess", default="Enabled"),
            "rbac_authorization": bool(_get(v, "enableRbacAuthorization", default=False)),
        }

    @staticmethod
    def _role(r: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": r["id"],
            "principal_name": r.get("principalName"),
            "principal_type": r.get("principalType"),
            "role": r.get("roleDefinitionName"),
            "scope": r.get("scope", ""),
        }

    @staticmethod
    def _sql(s: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": s["id"],
            "name": s.get("name"),
            "public_network_access": _get(s, "publicNetworkAccess", default="Enabled"),
            "firewall_rules": [
                {
                    "name": f.get("name"),
                    "start": _get(f, "startIpAddress"),
                    "end": _get(f, "endIpAddress"),
                }
                for f in s.get("firewallRules", [])
            ],
        }
