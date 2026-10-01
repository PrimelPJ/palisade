"""Run every applicable rule against an inventory and apply suppressions."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field, replace
from datetime import date
from pathlib import Path
from typing import Any

import yaml

from palisade.models import Finding, Inventory, Severity
from palisade.registry import all_rules
from palisade.remediate import is_auto_remediable


@dataclass
class Suppression:
    """A documented risk acceptance. Every suppression needs a reason and an expiry."""

    rule_id: str
    resource: str
    reason: str
    expires: date | None = None

    def matches(self, finding: Finding, today: date) -> bool:
        if self.expires and today > self.expires:
            return False
        return fnmatch.fnmatch(finding.rule_id, self.rule_id) and fnmatch.fnmatch(finding.resource_id, self.resource)


def load_suppressions(path: str | Path | None) -> list[Suppression]:
    if not path or not Path(path).exists():
        return []
    data = yaml.safe_load(Path(path).read_text()) or {}
    out = []
    for entry in data.get("suppressions", []):
        if not entry.get("reason"):
            raise ValueError(f"Suppression for {entry.get('rule')} is missing a reason")
        expires = entry.get("expires")
        if isinstance(expires, str):
            expires = date.fromisoformat(expires)
        out.append(Suppression(entry["rule"], entry.get("resource", "*"), entry["reason"], expires))
    return out


@dataclass
class ScanResult:
    inventory: Inventory
    findings: list[Finding] = field(default_factory=list)
    rules_evaluated: int = 0
    resources_evaluated: int = 0

    @property
    def active(self) -> list[Finding]:
        return [f for f in self.findings if not f.suppressed]

    @property
    def suppressed(self) -> list[Finding]:
        return [f for f in self.findings if f.suppressed]

    def counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.active:
            counts[f.severity.value] += 1
        return counts

    def fails_threshold(self, threshold: Severity) -> bool:
        return any(f.severity.rank >= threshold.rank for f in self.active)

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.inventory.provider.value,
            "account": self.inventory.account,
            "rules_evaluated": self.rules_evaluated,
            "resources_evaluated": self.resources_evaluated,
            "summary": self.counts(),
            "findings": [f.to_dict() for f in self.findings],
        }


def scan(
    inventory: Inventory,
    suppressions: list[Suppression] | None = None,
    only_resource_types: set[str] | None = None,
    today: date | None = None,
) -> ScanResult:
    today = today or date.today()
    suppressions = suppressions or []
    rules = [
        r
        for r in all_rules(inventory.provider)
        if only_resource_types is None or r.resource_type in only_resource_types
    ]
    result = ScanResult(inventory=inventory, rules_evaluated=len(rules))
    seen_resources: set[str] = set()
    for r in rules:
        for resource in inventory.of(r.resource_type):
            seen_resources.add(f"{r.resource_type}:{resource.get('id')}")
            for finding in r.evaluate(resource, inventory.resources):
                finding = replace(finding, auto_remediable=is_auto_remediable(finding.rule_id))
                match = next((s for s in suppressions if s.matches(finding, today)), None)
                if match:
                    finding = replace(finding, suppressed=True, suppression_reason=match.reason)
                result.findings.append(finding)
    result.resources_evaluated = len(seen_resources)
    result.findings.sort(key=lambda f: (-f.severity.rank, f.rule_id, f.resource_id))
    return result
