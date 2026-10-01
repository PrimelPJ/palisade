"""Command-line interface."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from palisade import __version__, report
from palisade.collectors.azure import AzureSnapshotCollector
from palisade.models import Inventory, Provider, Severity
from palisade.registry import all_rules
from palisade.remediate import Status, remediate
from palisade.scanner import ScanResult, load_suppressions, scan

console = Console()
DEFAULT_SUPPRESSIONS = ".palisade-ignore.yaml"


def _aws_session(profile: str | None, region: str | None):
    import boto3

    return boto3.session.Session(profile_name=profile, region_name=region)


def _collect(provider: str, profile, regions, snapshot, inventory_file) -> tuple[Inventory, object]:
    if inventory_file:
        return Inventory.from_dict(json.loads(Path(inventory_file).read_text())), None
    if provider == "azure":
        if not snapshot:
            raise click.UsageError("Azure scans need --snapshot (create one with scripts/export_azure_snapshot.sh)")
        return AzureSnapshotCollector.from_file(snapshot).collect(), None
    from palisade.collectors.aws import AwsCollector

    session = _aws_session(profile, regions[0] if regions else None)
    return AwsCollector(session, list(regions) or None).collect(), session


def _emit(result: ScanResult, fmt: str, output: str | None, show_suppressed: bool) -> None:
    if fmt == "table":
        report.print_table(result, console, show_suppressed)
        return
    text = {
        "json": lambda: report.to_json(result),
        "sarif": lambda: json.dumps(report.to_sarif(result), indent=2),
        "markdown": lambda: report.to_markdown(result),
    }[fmt]()
    if output:
        Path(output).write_text(text)
        console.print(f"Wrote {fmt} report to {output}", style="dim")
    else:
        click.echo(text)


common_scan_options = [
    click.argument("provider", type=click.Choice(["aws", "azure"])),
    click.option("--profile", help="AWS named profile."),
    click.option("--region", "regions", multiple=True, help="AWS region(s) to scan. Repeatable."),
    click.option("--snapshot", type=click.Path(exists=True), help="Azure snapshot JSON from export_azure_snapshot.sh."),
    click.option("--inventory", "inventory_file", type=click.Path(exists=True), help="Replay a saved inventory."),
    click.option("--suppressions", default=DEFAULT_SUPPRESSIONS, show_default=True, help="Risk-acceptance file."),
]


def with_options(options):
    def wrap(fn):
        for opt in reversed(options):
            fn = opt(fn)
        return fn

    return wrap


@click.group()
@click.version_option(__version__)
def main() -> None:
    """Palisade: multi-cloud security posture scanning, remediation and attack simulation."""


@main.command("scan")
@with_options(common_scan_options)
@click.option("--format", "fmt", type=click.Choice(["table", "json", "sarif", "markdown"]), default="table")
@click.option("--output", "-o", type=click.Path(), help="Write the report to a file.")
@click.option("--save-inventory", type=click.Path(), help="Save the collected inventory for replay or evidence.")
@click.option("--fail-on", type=click.Choice(report.severity_choices()), help="Exit 1 if findings at or above this.")
@click.option("--show-suppressed", is_flag=True)
def scan_cmd(
    provider,
    profile,
    regions,
    snapshot,
    inventory_file,
    suppressions,
    fmt,
    output,
    save_inventory,
    fail_on,
    show_suppressed,
):
    """Scan an AWS account or an Azure snapshot against CIS-mapped rules."""
    inventory, _ = _collect(provider, profile, regions, snapshot, inventory_file)
    if save_inventory:
        Path(save_inventory).write_text(json.dumps(inventory.to_dict(), indent=2, default=str))
    result = scan(inventory, load_suppressions(suppressions))
    _emit(result, fmt, output, show_suppressed)
    if fail_on and result.fails_threshold(Severity.parse(fail_on)):
        sys.exit(1)


@main.command("remediate")
@with_options(common_scan_options)
@click.option("--apply", is_flag=True, help="Apply auto-safe fixes. Without this flag nothing changes.")
@click.option("--include-manual", is_flag=True, help="Also apply fixes that normally need human approval.")
@click.option("--rule", "rule_ids", multiple=True, help="Only remediate these rule ids.")
def remediate_cmd(provider, profile, regions, snapshot, inventory_file, suppressions, apply, include_manual, rule_ids):
    """Plan (default) or apply fixes for current findings."""
    inventory, session = _collect(provider, profile, regions, snapshot, inventory_file)
    if apply and session is None:
        raise click.UsageError("--apply needs a live AWS session; Azure and replayed inventories are plan-only")
    result = scan(inventory, load_suppressions(suppressions))
    findings = [f for f in result.active if not rule_ids or f.rule_id in rule_ids]
    results = remediate(findings, inventory, session=session, apply=apply, include_manual=include_manual)
    report.print_remediation(results, console)
    if any(r.status == Status.FAILED for r in results):
        sys.exit(1)


@main.command("rules")
@click.option("--provider", type=click.Choice(["aws", "azure"]))
def rules_cmd(provider):
    """List every built-in rule."""
    from palisade.remediate import get_remediator

    table = Table(header_style="bold")
    for col in ("Rule", "Severity", "CIS", "Resource", "Title", "Fix"):
        table.add_column(col)
    for r in all_rules(Provider(provider) if provider else None):
        rem = get_remediator(r.id)
        fix = "auto" if rem and rem.auto and rem.apply else ("plan" if rem else "none")
        table.add_row(r.id, r.severity.value, r.cis, r.resource_type, r.title, fix)
    console.print(table)


@main.command("simulate")
@click.option("--report", "report_path", type=click.Path(), help="Write the markdown report here.")
@click.option("--suppressions", default="examples/suppressions.yaml", show_default=True)
def simulate_cmd(report_path, suppressions):
    """Run every attack scenario against a mocked AWS account and verify detection and repair."""
    import os

    # moto only knows AWS-managed policies such as AdministratorAccess when asked to load them.
    os.environ.setdefault("MOTO_IAM_LOAD_MANAGED_POLICIES", "true")
    try:
        from moto import mock_aws
    except ImportError as exc:
        raise click.ClickException("Install dev extras first: pip install -e '.[dev]'") from exc
    import boto3

    from palisade.simulate import REGION, render_report, run_simulation

    with mock_aws():
        session = boto3.session.Session(
            aws_access_key_id="testing",
            aws_secret_access_key="testing",
            region_name=REGION,  # noqa: S106
        )
        result = run_simulation(session, suppressions=load_suppressions(suppressions))

    table = Table(title="Attack simulation", header_style="bold")
    for col in ("Scenario", "ATT&CK", "Detected by", "Resolved"):
        table.add_column(col)
    for o in result.outcomes:
        status = "[green]yes[/]" if o.detected else "[bold red]MISSED[/]"
        resolved = ", ".join(o.resolved_rules) or "[yellow]queued for review[/]"
        table.add_row(o.scenario.name, o.scenario.attack_technique, f"{status} {', '.join(o.detected_rules)}", resolved)
    console.print(table)
    console.print(
        f"Findings: baseline {len(result.baseline.active)}, after attack {len(result.after_attack.active)}, "
        f"after remediation {len(result.after_remediation.active)}"
    )
    if report_path:
        Path(report_path).write_text(render_report(result))
        console.print(f"Wrote {report_path}", style="dim")
    if not all(o.detected for o in result.outcomes):
        sys.exit(1)


if __name__ == "__main__":
    main()
