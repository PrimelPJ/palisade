"""Remediation registry and runner.

Each remediator is tagged ``auto`` (safe to apply without a human) or not.
Auto fixes are scoped, idempotent and non-destructive: they tighten a setting
rather than delete data or identities. Anything touching IAM permissions is
plan-only, because revoking access in production needs a human decision.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import Any

from palisade.models import Finding, Inventory, Provider


class Status(str, Enum):
    APPLIED = "applied"
    PLANNED = "planned"
    SKIPPED = "skipped"
    FAILED = "failed"


@dataclass(frozen=True)
class RemediationResult:
    finding_key: str
    rule_id: str
    resource_id: str
    status: Status
    action: str
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding": self.finding_key,
            "rule_id": self.rule_id,
            "resource_id": self.resource_id,
            "status": self.status.value,
            "action": self.action,
            "detail": self.detail,
        }


ApplyFn = Callable[[Any, dict[str, Any], Finding], str]


@dataclass(frozen=True)
class Remediator:
    rule_id: str
    action: str
    auto: bool
    apply: ApplyFn | None = None  # None means "plan only": we describe the fix, a human applies it
    command: Callable[[dict[str, Any], Finding], str] | None = None  # CLI equivalent shown in plans


_REMEDIATORS: dict[str, Remediator] = {}


def remediator(
    rule_id: str, action: str, *, auto: bool, command: Callable[[dict[str, Any], Finding], str] | None = None
) -> Callable[[ApplyFn], ApplyFn]:
    def decorator(fn: ApplyFn) -> ApplyFn:
        _REMEDIATORS[rule_id] = Remediator(rule_id, action, auto, fn, command)
        return fn

    return decorator


def register_plan_only(
    rule_id: str, action: str, command: Callable[[dict[str, Any], Finding], str] | None = None
) -> None:
    _REMEDIATORS[rule_id] = Remediator(rule_id, action, False, None, command)


def _load() -> None:
    from palisade.remediate import aws, azure  # noqa: F401


def get_remediator(rule_id: str) -> Remediator | None:
    _load()
    return _REMEDIATORS.get(rule_id)


def is_auto_remediable(rule_id: str) -> bool:
    r = get_remediator(rule_id)
    return bool(r and r.auto and r.apply)


def _find_resource(inventory: Inventory, finding: Finding) -> dict[str, Any]:
    for res in inventory.of(finding.resource_type):
        if str(res.get("id")) == finding.resource_id or str(res.get("name")) == finding.resource_id:
            return res
    return {"id": finding.resource_id}


def remediate(
    findings: list[Finding],
    inventory: Inventory,
    *,
    session: Any = None,
    apply: bool = False,
    include_manual: bool = False,
) -> list[RemediationResult]:
    """Fix (or plan fixes for) findings.

    ``apply=False`` is a dry run: every fix is reported as PLANNED. With
    ``apply=True`` only ``auto`` remediators run; the rest stay PLANNED so a
    human can review them, unless ``include_manual`` is set.
    """
    results: list[RemediationResult] = []
    done: set[tuple[str, str, str]] = set()
    for f in findings:
        if f.suppressed:
            continue
        r = get_remediator(f.rule_id)
        if r is None:
            results.append(RemediationResult(f.key, f.rule_id, f.resource_id, Status.SKIPPED, "No remediator"))
            continue
        resource = _find_resource(inventory, f)
        cmd = r.command(resource, f) if r.command else ""
        # Several findings (e.g. two open ports) can share one fix; run it once per resource,
        # but keep distinct fixes (e.g. two different NSG rules) separate.
        dedupe = (f.rule_id, f.resource_id, cmd)
        if dedupe in done:
            continue
        done.add(dedupe)
        can_apply = apply and r.apply is not None and (r.auto or include_manual)
        if not can_apply or inventory.provider == Provider.AZURE:
            reason = "dry run" if not apply else ("needs human approval" if not r.auto else "")
            results.append(RemediationResult(f.key, f.rule_id, f.resource_id, Status.PLANNED, r.action, cmd or reason))
            continue
        try:
            detail = r.apply(session, resource, f)
            results.append(RemediationResult(f.key, f.rule_id, f.resource_id, Status.APPLIED, r.action, detail))
        except Exception as exc:  # noqa: BLE001 - report every failure, keep remediating the rest
            results.append(RemediationResult(f.key, f.rule_id, f.resource_id, Status.FAILED, r.action, str(exc)))
    return results
