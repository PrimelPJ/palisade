"""Azure Function (Python v2 model): Event Grid -> scan changed resource -> fix.

terraform/azure subscribes this function to the subscription's
Microsoft.Resources.ResourceWriteSuccess events for storage accounts, NSGs and
Key Vaults. The function app's managed identity needs a custom role limited to
those resource types' write actions (see terraform/azure/remediation.tf).
"""

from __future__ import annotations

import json
import logging
import os

import azure.functions as func
from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import ResourceManagementClient
from remediator import NSG, STORAGE, VAULT, plan_fixes, resource_type

app = func.FunctionApp()

API_VERSIONS = {
    STORAGE: "2023-05-01",
    NSG: "2023-11-01",
    VAULT: "2023-07-01",
}
DRY_RUN = os.environ.get("PALISADE_DRY_RUN", "false").lower() == "true"


def _rg_and_name(resource_id: str) -> tuple[str, str]:
    parts = resource_id.strip("/").split("/")
    return parts[parts.index("resourceGroups") + 1], parts[-1]


@app.event_grid_trigger(arg_name="event")
def palisade_remediate(event: func.EventGridEvent) -> None:
    data = event.get_json()
    resource_id = data.get("resourceUri") or event.subject
    rtype = resource_type(resource_id)
    if rtype not in API_VERSIONS:
        return
    caller = (data.get("claims") or {}).get("appid", "")
    if caller and caller == os.environ.get("PALISADE_SELF_CLIENT_ID"):
        return  # our own fix generated this event

    sub = resource_id.split("/")[2]
    cred = DefaultAzureCredential()
    arm = ResourceManagementClient(cred, sub)
    resource = arm.resources.get_by_id(resource_id, API_VERSIONS[rtype]).as_dict()

    fixes = plan_fixes(resource)
    for fix in fixes:
        logging.warning(json.dumps({"rule": fix.rule_id, "kind": fix.kind, "auto": fix.auto, "reason": fix.reason}))
        if DRY_RUN or not fix.auto:
            continue
        if fix.kind == "patch_properties":
            arm.resources.begin_update_by_id(
                resource_id, API_VERSIONS[rtype], {"properties": fix.payload["properties"]}
            ).result()
        elif fix.kind == "delete_nsg_rule":
            rg, nsg_name = _rg_and_name(resource_id)
            NetworkManagementClient(cred, sub).security_rules.begin_delete(rg, nsg_name, fix.payload["rule"]).result()
