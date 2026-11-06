"""GCP rules, mapped to CIS Google Cloud Platform Foundation Benchmark v2.0."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from palisade.models import Provider, Severity
from palisade.registry import rule

GCP = Provider.GCP

PRIMITIVE_ROLES = {"roles/owner", "roles/editor", "roles/viewer"}


@rule(
    id="GCP-001",
    title="GCS bucket is publicly accessible",
    severity=Severity.CRITICAL,
    provider=GCP,
    resource_type="gcs_bucket",
    cis="5.1",
    remediation="Remove 'allUsers' and 'allAuthenticatedUsers' from the bucket's IAM policy.",
)
def gcs_bucket_public(resource: dict[str, Any], _: Any) -> Iterator[str]:
    for binding in resource.get("iam_bindings", []):
        members = binding.get("members", [])
        if "allUsers" in members or "allAuthenticatedUsers" in members:
            yield f"Bucket grants public access via role {binding['role']!r}"


@rule(
    id="GCP-002",
    title="Project uses primitive IAM roles",
    severity=Severity.HIGH,
    provider=GCP,
    resource_type="gcp_project",
    cis="1.2",
    remediation="Replace primitive roles (owner/editor/viewer) with predefined or custom roles.",
    id_field="project_id",
)
def project_primitive_iam(resource: dict[str, Any], _: Any) -> Iterator[str]:
    for binding in resource.get("iam_bindings", []):
        if binding.get("role") in PRIMITIVE_ROLES:
            members = binding.get("members", [])
            yield f"Primitive role {binding['role']!r} granted to {len(members)} member(s)"
