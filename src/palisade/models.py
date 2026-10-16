"""Core data model shared by collectors, rules, remediators and reporters."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[self.value]

    @classmethod
    def parse(cls, value: str) -> Severity:
        return cls(value.lower())


class Provider(str, Enum):
    AWS = "aws"
    AZURE = "azure"


@dataclass(frozen=True)
class Finding:
    """One rule failing against one resource."""

    rule_id: str
    title: str
    severity: Severity
    provider: Provider
    resource_type: str
    resource_id: str
    detail: str
    cis: str
    remediation: str
    auto_remediable: bool = False
    suppressed: bool = False
    suppression_reason: str | None = None

    @property
    def key(self) -> str:
        """Stable identity used for suppressions and diffing scans."""
        return f"{self.rule_id}:{self.resource_id}"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        data["provider"] = self.provider.value
        return data


@dataclass
class Inventory:
    """Normalized snapshot of a cloud environment.

    ``resources`` maps a resource type (e.g. ``s3_bucket``) to a list of plain dicts.
    Keeping inventory as plain data decouples collection from evaluation, so the
    same rules run against a live account, a mocked one, or a saved JSON snapshot.
    """

    provider: Provider
    account: str
    resources: dict[str, list[dict[str, Any]]] = field(default_factory=dict)

    def of(self, resource_type: str) -> list[dict[str, Any]]:
        return self.resources.get(resource_type, [])

    def to_dict(self) -> dict[str, Any]:
        return {"provider": self.provider.value, "account": self.account, "resources": self.resources}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Inventory:
        return cls(
            provider=Provider(data["provider"]),
            account=data.get("account", "unknown"),
            resources=data.get("resources", {}),
        )
