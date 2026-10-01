"""Azure rules, mapped to the CIS Microsoft Azure Foundations Benchmark v2.1."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from palisade.models import Provider, Severity
from palisade.registry import rule

AZ = Provider.AZURE
INTERNET_SOURCES = {"*", "0.0.0.0/0", "0.0.0.0", "internet", "any", "::/0"}
ADMIN_PORTS = {22: "SSH", 3389: "RDP"}
TLS_ORDER = {"TLS1_0": 0, "TLS1_1": 1, "TLS1_2": 2, "TLS1_3": 3}
# Defender plans that CIS expects on Standard for a typical workload subscription.
REQUIRED_DEFENDER_PLANS = {"VirtualMachines", "StorageAccounts", "KeyVaults", "SqlServers", "Arm"}


def _port_matches(spec: str, port: int) -> bool:
    spec = spec.strip()
    if spec == "*":
        return True
    if "-" in spec:
        lo, hi = spec.split("-", 1)
        return int(lo) <= port <= int(hi)
    return spec.isdigit() and int(spec) == port


# ---- Storage ----------------------------------------------------------------


@rule(
    id="AZ-STG-001",
    title="Storage account allows anonymous blob access",
    severity=Severity.HIGH,
    provider=AZ,
    resource_type="storage_account",
    cis="3.7",
    remediation="Set allowBlobPublicAccess to false on the storage account.",
)
def storage_public_blob(acct: dict[str, Any], _: dict[str, Any]) -> Iterator[str]:
    if acct.get("allow_blob_public_access"):
        yield f"{acct['name']} lets containers be set to anonymous (public) read"


@rule(
    id="AZ-STG-002",
    title="Storage account accepts plain HTTP",
    severity=Severity.HIGH,
    provider=AZ,
    resource_type="storage_account",
    cis="3.1",
    remediation="Enable 'Secure transfer required' (enableHttpsTrafficOnly).",
)
def storage_https(acct: dict[str, Any], _: dict[str, Any]) -> Iterator[str]:
    if not acct.get("https_only"):
        yield f"{acct['name']} accepts unencrypted HTTP requests"


@rule(
    id="AZ-STG-003",
    title="Storage account allows TLS older than 1.2",
    severity=Severity.MEDIUM,
    provider=AZ,
    resource_type="storage_account",
    cis="3.15",
    remediation="Set minimumTlsVersion to TLS1_2.",
)
def storage_tls(acct: dict[str, Any], _: dict[str, Any]) -> Iterator[str]:
    version = acct.get("min_tls_version") or "TLS1_0"
    if TLS_ORDER.get(version, 0) < TLS_ORDER["TLS1_2"]:
        yield f"{acct['name']} minimum TLS is {version}"


@rule(
    id="AZ-STG-004",
    title="Storage account network access is open to all networks",
    severity=Severity.MEDIUM,
    provider=AZ,
    resource_type="storage_account",
    cis="3.8",
    remediation="Set the network rule default action to Deny and allow only required VNets or private endpoints.",
)
def storage_network(acct: dict[str, Any], _: dict[str, Any]) -> Iterator[str]:
    if str(acct.get("network_default_action", "Allow")).lower() == "allow":
        yield f"{acct['name']} is reachable from any network"


# ---- Networking ---------------------------------------------------------------


@rule(
    id="AZ-NSG-001",
    title="NSG allows SSH or RDP from the internet",
    severity=Severity.HIGH,
    provider=AZ,
    resource_type="nsg",
    cis="6.1",
    remediation="Delete the rule and use Azure Bastion or just-in-time VM access instead.",
)
def nsg_admin_ports(nsg: dict[str, Any], _: dict[str, Any]) -> Iterator[str]:
    for r in nsg.get("rules", []):
        if str(r.get("access")).lower() != "allow" or str(r.get("direction")).lower() != "inbound":
            continue
        if not any(str(s).lower() in INTERNET_SOURCES for s in r.get("sources", [])):
            continue
        for port, name in ADMIN_PORTS.items():
            if any(_port_matches(p, port) for p in r.get("ports", [])):
                yield f"Rule '{r['name']}' allows {name} (port {port}) from the internet"


# ---- Key Vault ----------------------------------------------------------------


@rule(
    id="AZ-KV-001",
    title="Key Vault purge protection is disabled",
    severity=Severity.MEDIUM,
    provider=AZ,
    resource_type="key_vault",
    cis="8.5",
    remediation="Enable purge protection so deleted secrets cannot be permanently destroyed early.",
)
def kv_purge(vault: dict[str, Any], _: dict[str, Any]) -> Iterator[str]:
    if not vault.get("purge_protection"):
        yield f"{vault['name']} secrets and keys can be purged immediately after deletion"


@rule(
    id="AZ-KV-002",
    title="Key Vault is reachable from public networks",
    severity=Severity.LOW,
    provider=AZ,
    resource_type="key_vault",
    cis="8.7",
    remediation="Disable public network access and use a private endpoint.",
)
def kv_public(vault: dict[str, Any], _: dict[str, Any]) -> Iterator[str]:
    if str(vault.get("public_network_access", "Enabled")).lower() == "enabled":
        yield f"{vault['name']} accepts traffic from the public internet"


@rule(
    id="AZ-KV-003",
    title="Key Vault uses legacy access policies instead of RBAC",
    severity=Severity.LOW,
    provider=AZ,
    resource_type="key_vault",
    cis="8.6",
    remediation="Enable Azure RBAC authorization on the vault and migrate access policies to role assignments.",
)
def kv_rbac(vault: dict[str, Any], _: dict[str, Any]) -> Iterator[str]:
    if not vault.get("rbac_authorization"):
        yield f"{vault['name']} grants access through vault access policies"


# ---- Identity -------------------------------------------------------------------


@rule(
    id="AZ-IAM-001",
    title="Service principal holds Owner at subscription scope",
    severity=Severity.HIGH,
    provider=AZ,
    resource_type="role_assignment",
    cis="1.23",
    remediation="Scope automation identities to a resource group and a narrower role such as Contributor.",
)
def sp_owner(assignment: dict[str, Any], _: dict[str, Any]) -> Iterator[str]:
    scope = assignment.get("scope", "").rstrip("/")
    at_subscription = scope.count("/") == 2 and scope.lower().startswith("/subscriptions/")
    if assignment.get("role") == "Owner" and assignment.get("principal_type") == "ServicePrincipal" and at_subscription:
        yield f"{assignment.get('principal_name')} can modify everything, including access, in the subscription"


# ---- SQL --------------------------------------------------------------------------


@rule(
    id="AZ-SQL-001",
    title="SQL server firewall allows the entire internet",
    severity=Severity.CRITICAL,
    provider=AZ,
    resource_type="sql_server",
    cis="4.1.2",
    remediation="Remove the 0.0.0.0-255.255.255.255 rule and use private endpoints or specific IPs.",
)
def sql_firewall(server: dict[str, Any], _: dict[str, Any]) -> Iterator[str]:
    for fw in server.get("firewall_rules", []):
        if fw.get("start") == "0.0.0.0" and fw.get("end") == "255.255.255.255":
            yield f"Firewall rule '{fw['name']}' opens {server['name']} to every IPv4 address"


# ---- Subscription-level -------------------------------------------------------------


@rule(
    id="AZ-MON-001",
    title="Activity log is not exported to a workspace or storage",
    severity=Severity.MEDIUM,
    provider=AZ,
    resource_type="subscription",
    cis="5.1.1",
    remediation="Create a subscription diagnostic setting sending Administrative and Security logs to Log Analytics.",
)
def activity_log_export(sub: dict[str, Any], _: dict[str, Any]) -> Iterator[str]:
    if not sub.get("activity_log_diagnostics"):
        yield "Control-plane activity is kept only 90 days and is not available for alerting"


@rule(
    id="AZ-DEF-001",
    title="Microsoft Defender for Cloud plan is on the Free tier",
    severity=Severity.MEDIUM,
    provider=AZ,
    resource_type="subscription",
    cis="2.1",
    remediation="Enable the Standard tier for the listed Defender plans.",
)
def defender_plans(sub: dict[str, Any], _: dict[str, Any]) -> Iterator[str]:
    tiers = {p["name"]: p["tier"] for p in sub.get("defender_pricings", [])}
    free = sorted(p for p in REQUIRED_DEFENDER_PLANS if tiers.get(p, "Free") != "Standard")
    if free:
        yield f"Defender plans not on Standard: {', '.join(free)}"
