#!/usr/bin/env bash
# Capture a read-only Azure posture snapshot for `palisade scan azure --snapshot`.
#
# Needs only the built-in "Reader" role (plus "Security Reader" for Defender pricing).
# Usage: ./scripts/export_azure_snapshot.sh [subscription-id] > snapshot.json
set -euo pipefail

if [[ $# -ge 1 ]]; then
  az account set --subscription "$1"
fi
SUB=$(az account show --query id -o tsv)

# SQL firewall rules live on a separate endpoint, so fold them into each server object.
sql_servers() {
  local servers
  servers=$(az sql server list -o json)
  echo "$servers" | jq -c '.[]' | while read -r server; do
    rg=$(echo "$server" | jq -r '.resourceGroup')
    name=$(echo "$server" | jq -r '.name')
    rules=$(az sql server firewall-rule list -g "$rg" -s "$name" -o json)
    echo "$server" | jq --argjson r "$rules" '. + {firewallRules: $r}'
  done | jq -s '.'
}

# `az keyvault list` omits security properties; `show` returns them.
key_vaults() {
  az keyvault list --query '[].name' -o tsv | while read -r name; do
    az keyvault show -n "$name" -o json
  done | jq -s '.'
}

jq -n \
  --arg sub "$SUB" \
  --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --argjson storage "$(az storage account list -o json)" \
  --argjson nsgs "$(az network nsg list -o json)" \
  --argjson vaults "$(key_vaults)" \
  --argjson roles "$(az role assignment list --all -o json)" \
  --argjson sql "$(sql_servers)" \
  --argjson diag "$(az monitor diagnostic-settings subscription list -o json | jq '.value // .')" \
  --argjson defender "$(az security pricing list -o json | jq '.value // .')" \
  '{
    subscription_id: $sub,
    captured_at: $at,
    storage_accounts: $storage,
    nsgs: $nsgs,
    key_vaults: $vaults,
    role_assignments: $roles,
    sql_servers: $sql,
    activity_log_diagnostics: $diag,
    defender_pricings: $defender
  }'
