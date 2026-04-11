"""
px_report.py — Renders cluster_summary.md, errors.json, remediation_steps.md.

Output files are written to: ~/downloads/<cluster_uuid>/reports/<timestamp>/

All three files are generated from the same findings list:
    cluster_summary.md   — Human-readable health overview with Smart Signals gap table
    errors.json          — Machine-readable structured findings with all metadata
    remediation_steps.md — Ordered runbook per finding
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich import box

from px_analyzer.engine import Finding

log = logging.getLogger(__name__)
console = Console()

OUTPUT_BASE = Path.home() / "downloads"

SEVERITY_COLOR = {
    "CRITICAL": "bold red",
    "WARNING":  "bold yellow",
    "INFO":     "dim",
}


def render_all(
    findings: list[Finding],
    cluster_uuid: str,
    cluster_info: dict,
    output_dir: Optional[Path] = None,
) -> dict[str, Path]:
    """
    Render all three output files.

    Args:
        findings     : Sorted list of Finding objects from engine
        cluster_uuid : Cluster UUID string
        cluster_info : Dict with cluster metadata keys:
                       name, uuid, node_analyzed, px_version, total_nodes,
                       os, kernel, uptime, memory_total_gib, license_info, metering_status
        output_dir   : Override output directory (default: ~/downloads/<uuid>/reports/<ts>/)

    Returns:
        Dict: {"summary": Path, "errors": Path, "remediation": Path}
    """
    if output_dir is None:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        output_dir = OUTPUT_BASE / cluster_uuid / "reports" / ts

    output_dir.mkdir(parents=True, exist_ok=True)

    paths = {
        "summary":     output_dir / "cluster_summary.md",
        "errors":      output_dir / "errors.json",
        "remediation": output_dir / "remediation_steps.md",
    }

    _write_cluster_summary(paths["summary"], findings, cluster_uuid, cluster_info)
    _write_errors_json(paths["errors"], findings)
    _write_remediation_steps(paths["remediation"], findings)
    _print_terminal_summary(findings, cluster_info, output_dir)

    return paths


def _write_cluster_summary(
    path: Path,
    findings: list[Finding],
    uuid: str,
    info: dict,
) -> None:
    """Write cluster_summary.md."""
    criticals = [f for f in findings if f.severity == "CRITICAL"]
    warnings  = [f for f in findings if f.severity == "WARNING"]
    infos     = [f for f in findings if f.severity == "INFO"]
    dark      = [f for f in findings if f.dark_to_smart_signals]

    health = "HEALTHY"
    if criticals:
        health = "DEGRADED" if len(criticals) <= 3 else "CRITICAL"
    elif warnings:
        health = "WARNING"

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines = [
        "# Portworx Cluster Diagnostic Summary",
        "",
        f"**Generated:** {now_str}",
        "",
        "## Cluster Identity",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| Cluster Name | {info.get('name', 'N/A')} |",
        f"| Cluster UUID | `{uuid}` |",
        f"| Node Analyzed | `{info.get('node_analyzed', 'N/A')}` |",
        f"| PX Version | {info.get('px_version', 'N/A')} |",
        f"| Total Nodes | {info.get('total_nodes', 'N/A')} |",
        f"| OS | {info.get('os', 'N/A')} |",
        f"| Kernel | {info.get('kernel', 'N/A')} |",
        f"| Node Uptime | {info.get('uptime', 'N/A')} |",
        f"| Memory | {info.get('memory_total_gib', 'N/A')} GiB total |",
        f"| License | {info.get('license_info', 'N/A')} |",
        f"| Metering | {info.get('metering_status', 'N/A')} |",
        "",
        "## Health Assessment",
        "",
        f"**Overall Health Score: {health}**",
        "",
        f"- CRITICAL findings: {len(criticals)}",
        f"- WARNING findings:  {len(warnings)}",
        f"- INFO findings:     {len(infos)}",
        "",
    ]

    # Smart Signals gap analysis
    if dark:
        lines += [
            "## Smart Signals Gap Analysis",
            "",
            f"> **{len(dark)} finding(s) are NOT visible to Pure Storage's Smart Signals monitoring.**",
            "> These issues exist only in local diagnostic data and will not trigger Portworx support alerts.",
            "",
            "| Finding ID | Label | Severity | Gap Note |",
            "|------------|-------|----------|----------|",
        ]
        for f in dark:
            label = f.extra.get("label", f.id)
            note  = (f.dark_note or "No deployed Smart Signal covers this pattern.")[:120]
            lines.append(f"| {f.id} | {label} | {f.severity} | {note} |")
        lines.append("")

    # All findings table
    lines += [
        "## All Findings",
        "",
        "| ID | Severity | Category | Count | Smart Signal | Monitored | First Seen |",
        "|----|----------|----------|-------|-------------|-----------|------------|",
    ]
    for f in findings:
        mon = "YES" if f.already_monitored else "**NO**"
        ss  = f.smart_signal or "—"
        lines.append(
            f"| {f.id} | {f.severity} | {f.category} | {f.count} | {ss} | {mon} | {f.first_seen} |"
        )

    # Per-finding details
    lines += ["", "## Finding Details", ""]
    for f in findings:
        lines += [
            f"### {f.id} — {f.severity}",
            "",
            f"**Category:** {f.category}  ",
            f"**Smart Signal:** {f.smart_signal or 'None (local-only)'}  ",
            f"**Alert Code:** {f.alert_code or 'N/A'}  ",
            f"**Alert Type:** {f.alert_type or 'N/A'}  ",
            f"**Already Monitored:** {'Yes' if f.already_monitored else 'No — dark to Smart Signals'}  ",
            f"**Count:** {f.count}  ",
            f"**First Seen:** {f.first_seen}  ",
            f"**Last Seen:** {f.last_seen}  ",
            f"**Source:** `{f.source_file}`  ",
            "",
            "**Log Excerpt:**",
            "```",
            f.log_excerpt[:500] if f.log_excerpt else "(no excerpt)",
            "```",
            "",
        ]
        if f.dark_note:
            lines += [f"> **Smart Signals Gap:** {f.dark_note}", ""]
        if f.correlated_with:
            lines += [f"**Correlated With:** {', '.join(f.correlated_with)}  ", ""]

    path.write_text("\n".join(lines), encoding="utf-8")
    log.info(f"Wrote: {path}")


def _write_errors_json(path: Path, findings: list[Finding]) -> None:
    """Write errors.json — machine-readable structured findings."""
    path.write_text(
        json.dumps([f.to_dict() for f in findings], indent=2, default=str),
        encoding="utf-8",
    )
    log.info(f"Wrote: {path}")


def _write_remediation_steps(path: Path, findings: list[Finding]) -> None:
    """Write remediation_steps.md — ordered runbook per finding."""
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        "# Portworx Remediation Runbook",
        "",
        f"**Generated:** {now_str}",
        "",
        "Findings ordered: CRITICAL → WARNING → INFO. "
        "Findings marked **NOT MONITORED** are invisible to Pure Storage's Smart Signals "
        "and require manual escalation to the Portworx TAM.",
        "",
        "---",
        "",
    ]

    for i, f in enumerate(findings, 1):
        status = (
            "Monitored by Pure Smart Signals"
            if f.already_monitored
            else "NOT MONITORED — Dark to Smart Signals"
        )

        lines += [
            f"## {i}. [{f.severity}] {f.id} — {f.smart_signal or f.category}",
            "",
            f"**Status:** {status}  ",
            f"**Count:** {f.count}  ",
            f"**First Seen:** {f.first_seen}  ",
            f"**Last Seen:** {f.last_seen}  ",
            f"**Source:** `{f.source_file}`  ",
            "",
        ]

        if f.dark_note:
            lines += [f"> **Gap Note:** {f.dark_note}", ""]

        if f.remediation_kb:
            lines += [f"**KB Article:** {f.remediation_kb}", ""]

        if f.remediation_steps:
            lines.append("**Steps:**")
            lines.append("")
            for step in f.remediation_steps:
                lines.append(f"1. {step}")
            lines.append("")

        if f.correlated_with:
            lines += [f"**Related Findings:** {', '.join(f.correlated_with)}", ""]

        lines += ["---", ""]

    path.write_text("\n".join(lines), encoding="utf-8")
    log.info(f"Wrote: {path}")


def _print_terminal_summary(
    findings: list[Finding],
    info: dict,
    output_dir: Path,
) -> None:
    """Print a rich-formatted summary table to the terminal."""
    console.print()
    console.print("[bold]Portworx Diagnostic Analysis Complete[/bold]")
    console.print(
        f"Cluster: [cyan]{info.get('name', 'N/A')}[/cyan]  "
        f"Node: [cyan]{info.get('node_analyzed', 'N/A')}[/cyan]"
    )
    console.print()

    table = Table(title="Findings", box=box.ROUNDED, show_lines=True)
    table.add_column("ID", style="bold")
    table.add_column("Severity")
    table.add_column("Category")
    table.add_column("Count", justify="right")
    table.add_column("Monitored?")
    table.add_column("First Seen")

    for f in findings:
        color   = SEVERITY_COLOR.get(f.severity, "")
        mon     = "[green]YES[/green]" if f.already_monitored else "[bold red]NO[/bold red]"
        sev_str = f"[{color}]{f.severity}[/{color}]" if color else f.severity
        table.add_row(f.id, sev_str, f.category, str(f.count), mon, f.first_seen)

    console.print(table)
    console.print()
    console.print(f"[bold]Output directory:[/bold] {output_dir}")
    console.print(f"  cluster_summary.md")
    console.print(f"  errors.json")
    console.print(f"  remediation_steps.md")
    console.print()
