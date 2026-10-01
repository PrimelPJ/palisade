"""Rule registry. Rules are plain functions registered with ``@rule``."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from palisade.models import Finding, Provider, Severity

# A check receives one resource dict and the whole inventory resource map, and
# yields zero or more human-readable failure details for that resource.
CheckFn = Callable[[dict[str, Any], dict[str, list[dict[str, Any]]]], Iterable[str]]


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    provider: Provider
    resource_type: str
    cis: str
    remediation: str
    check: CheckFn
    id_field: str = "id"

    def evaluate(self, resource: dict[str, Any], resources: dict[str, list[dict[str, Any]]]) -> list[Finding]:
        resource_id = str(resource.get(self.id_field) or resource.get("name") or "unknown")
        return [
            Finding(
                rule_id=self.id,
                title=self.title,
                severity=self.severity,
                provider=self.provider,
                resource_type=self.resource_type,
                resource_id=resource_id,
                detail=detail,
                cis=self.cis,
                remediation=self.remediation,
            )
            for detail in self.check(resource, resources)
        ]


_REGISTRY: dict[str, Rule] = {}


def rule(
    *,
    id: str,  # noqa: A002 - mirrors the rule schema
    title: str,
    severity: Severity,
    provider: Provider,
    resource_type: str,
    cis: str,
    remediation: str,
    id_field: str = "id",
) -> Callable[[CheckFn], CheckFn]:
    def decorator(fn: CheckFn) -> CheckFn:
        if id in _REGISTRY:
            raise ValueError(f"Duplicate rule id {id}")
        _REGISTRY[id] = Rule(id, title, severity, provider, resource_type, cis, remediation, fn, id_field)
        return fn

    return decorator


def all_rules(provider: Provider | None = None) -> list[Rule]:
    _load_builtin_rules()
    rules = sorted(_REGISTRY.values(), key=lambda r: r.id)
    return [r for r in rules if provider is None or r.provider == provider]


def get_rule(rule_id: str) -> Rule:
    _load_builtin_rules()
    return _REGISTRY[rule_id]


def _load_builtin_rules() -> None:
    # Importing the modules runs their @rule decorators exactly once.
    from palisade.rules import aws, azure  # noqa: F401
