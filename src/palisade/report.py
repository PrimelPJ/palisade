"""Output formats: terminal table, JSON, Markdown and SARIF (GitHub code scanning)."""

from __future__ import annotations

import json
import re
from typing import Any

from rich.console import Console
from rich.table import Table

from palisade import __version__
from palisade.models import Severity
from palisade.registry import all_rules
from palisade.remediate import RemediationResult
from palisade.scanner import ScanResult

SEVERITY_STYLE = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan"}
# GitHub maps security-severity scores onto its own critical/high/medium/low badges.
SARIF_SCORE = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0"}
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def short_id(resource_id: str) -> str:
    """Azure ids and ARNs are long; the last segment is what a human recognises."""
    if resource_id.startswith("/subscriptions/") and resource_id.count("/") > 2:
        return resource_id.rstrip("/").rsplit("/", 1)[-1]
    if resource_id.startswith("arn:"):
        return resource_id.split(":", 5)[-1]
    return resource_id


def print_table(result: ScanResult, console: Console | None = None, show_suppressed: bool = False) -> None:
    console = console or Console()
    counts = result.counts()
    console.print(
        f"[bold]{result.inventory.provider.value.upper()}[/] account [bold]{result.inventory.account}[/]: "
        f"{result.rules_evaluated} rules, {result.resources_evaluated} resource checks, "
        + ", ".join(f"[{SEVERITY_STYLE[s]}]{n} {s}[/]" for s, n in counts.items())
        + (f", {len(result.suppressed)} suppressed" if result.suppressed else "")
    )
    rows = result.findings if show_suppressed else result.active
    if not rows:
        console.print("[green]No active findings.[/]")
        return
    table = Table(show_lines=False, header_style="bold")
    table.add_column("Severity")
    table.add_column("Rule")
    table.add_column("CIS")
    table.add_column("Resource", overflow="fold", max_width=42)
    table.add_column("Detail", overflow="fold")
    table.add_column("Fix")
    for f in rows:
        sev = f"[{SEVERITY_STYLE[f.severity.value]}]{f.severity.value}[/]"
        fix = "suppressed" if f.suppressed else ("auto" if f.auto_remediable else "manual")
        table.add_row(sev, f.rule_id, f.cis, short_id(f.resource_id), f.detail, fix)
    console.print(table)


def print_remediation(results: list[RemediationResult], console: Console | None = None) -> None:
    console = console or Console()
    if not results:
        console.print("Nothing to remediate.")
        return
    style = {"applied": "green", "planned": "yellow", "skipped": "dim", "failed": "bold red"}
    table = Table(header_style="bold")
    for col in ("Status", "Rule", "Resource", "Action", "Detail / command"):
        table.add_column(col, overflow="fold")
    for r in results:
        table.add_row(
            f"[{style[r.status.value]}]{r.status.value}[/]",
            r.rule_id,
            short_id(r.resource_id),
            r.action,
            r.detail,
        )
    console.print(table)


def to_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2, default=str)


def to_markdown(result: ScanResult) -> str:
    counts = result.counts()
    row = [counts["critical"], counts["high"], counts["medium"], counts["low"], len(result.suppressed)]
    lines = [
        f"### Palisade scan: {result.inventory.provider.value.upper()} `{result.inventory.account}`",
        "",
        "| Critical | High | Medium | Low | Suppressed |",
        "|---:|---:|---:|---:|---:|",
        "| " + " | ".join(str(n) for n in row) + " |",
        "",
    ]
    if result.active:
        lines += ["| Severity | Rule | CIS | Resource | Detail | Fix |", "|---|---|---|---|---|---|"]
        for f in result.active:
            fix = "auto" if f.auto_remediable else "manual"
            lines.append(
                f"| {f.severity.value} | {f.rule_id} | {f.cis} | `{short_id(f.resource_id)}` | {f.detail} | {fix} |"
            )
    else:
        lines.append("No active findings.")
    return "\n".join(lines) + "\n"


def _artifact_uri(provider: str, resource_type: str, resource_id: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", resource_id).strip("_")
    return f"cloud/{provider}/{resource_type}/{safe}"


def to_sarif(result: ScanResult) -> dict[str, Any]:
    provider = result.inventory.provider
    rules = all_rules(provider)
    index = {r.id: i for i, r in enumerate(rules)}
    sarif_rules = [
        {
            "id": r.id,
            "name": r.id.replace("-", ""),
            "shortDescription": {"text": r.title},
            "fullDescription": {"text": f"{r.title} (CIS {r.cis})"},
            "help": {"text": r.remediation, "markdown": f"**Remediation:** {r.remediation}"},
            "defaultConfiguration": {"level": SARIF_LEVEL[r.severity.value]},
            "properties": {
                "security-severity": SARIF_SCORE[r.severity.value],
                "tags": ["security", f"cis-{r.cis}", provider.value],
            },
        }
        for r in rules
    ]
    results = []
    for f in result.findings:
        entry: dict[str, Any] = {
            "ruleId": f.rule_id,
            "ruleIndex": index[f.rule_id],
            "level": SARIF_LEVEL[f.severity.value],
            "message": {"text": f"{f.detail} [{f.resource_id}]"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": _artifact_uri(provider.value, f.resource_type, f.resource_id)},
                        "region": {"startLine": 1},
                    },
                    "logicalLocations": [{"fullyQualifiedName": f.resource_id, "kind": f.resource_type}],
                }
            ],
            "partialFingerprints": {"palisadeFindingKey": f.key},
        }
        if f.suppressed:
            entry["suppressions"] = [{"kind": "external", "justification": f.suppression_reason or ""}]
        results.append(entry)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Palisade",
                        "version": __version__,
                        "informationUri": "https://github.com/PrimelPJ/palisade",
                        "rules": sarif_rules,
                    }
                },
                "results": results,
            }
        ],
    }


def severity_choices() -> list[str]:
    return [s.value for s in Severity]
