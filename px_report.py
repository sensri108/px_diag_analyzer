"""
px_report.py — Renders all output files for px_diag_analyzer.

Output files:
    full_report.txt      — Perplexity-style sectioned text report (primary output)
    cluster_summary.md   — Markdown health overview with Smart Signals gap table
    errors.json          — Machine-readable structured findings
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

SEP  = "=" * 78
SEP2 = "-" * 78

SEVERITY_COLOR = {
    "CRITICAL": "bold red",
    "WARNING":  "bold yellow",
    "INFO":     "dim",
}

# Smart Signal metadata for report output
SMART_SIGNAL_META: dict[str, dict] = {
    "NodeStartFailure":          {"code": 10096, "signal": "px_init_failure",                  "audience": "Internal"},
    "NodeStateChange / NotInQuorum": {"code": 10109, "signal": "px_node_down_alert",           "audience": "Internal"},
    "ClusterManagerFailure":     {"code": 10096, "signal": "px_init_failure",                  "audience": "Internal"},
    "StorageFailure":            {"code": 10076, "signal": "pool_expand_failed_alert",          "audience": "Support"},
    "StoragePoolFailure":        {"code": 10076, "signal": "pool_expand_failed_alert",          "audience": "Support"},
    "KVDBBootstrapFailure":      {"code": 10192, "signal": "kvdb_out_of_space",                "audience": "Internal"},
    "VolumeSpaceLow":            {"code": 10081, "signal": "volume_space_low_alerts",           "audience": "Support"},
    "NodeMarkedDown":            {"code": 10109, "signal": "px_node_down_alert",               "audience": "Internal"},
    "VolumeCreationFailure":     {"code": 10074, "signal": "volume_creation_failure_alerts",    "audience": "Support"},
    "VolumeDeleteFailure":       {"code": 10101, "signal": "volume_delete_failure",             "audience": "Internal"},
    "CapacityAlert":             {"code": 10053, "signal": "capacity_alerts",                   "audience": "Support"},
    "SnapshotCreationFailure":   {"code": 10095, "signal": "snapshot_creation_failure_alert",  "audience": "Internal"},
    "SnapshotDeleteFailure":     {"code": 10099, "signal": "snapshot_delete_failure",          "audience": "Internal"},
    "LicenseExpiry":             {"code": 10068, "signal": "license_expiry_alerts",            "audience": "Support"},
    "StorageNodeTransition":     {"code": 10100, "signal": "storage_node_transition_failure_alert", "audience": "Internal"},
}

REMEDIATION_KB: dict[str, str] = {
    "NodeStartFailure":     "https://docs.portworx.com/operations/troubleshooting/",
    "NodeStateChange / NotInQuorum": "https://docs.portworx.com/operations/troubleshooting/",
    "VolumeSpaceLow":       "https://purestorage.atlassian.net/browse/PWX-41031",
    "VolumeCreationFailure":"https://pure.service-now.com/perc?id=kb_article&sysparm_article=KB0017845",
    "KVDBBootstrapFailure": "https://docs.portworx.com/operations/kvdb/",
    "StorageFailure":       "https://docs.portworx.com/operations/troubleshooting/",
    "StoragePoolFailure":   "https://docs.portworx.com/operations/troubleshooting/",
}


def render_all(
    findings: list[Finding],
    cluster_uuid: str,
    cluster_info: dict,
    output_dir: Optional[Path] = None,
) -> dict[str, Path]:
    """Render all output files. Returns dict of {name: Path}."""
    if output_dir is None:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        output_dir = OUTPUT_BASE / cluster_uuid / "reports" / ts

    output_dir.mkdir(parents=True, exist_ok=True)

    paths = {
        "report":      output_dir / "full_report.txt",
        "summary":     output_dir / "cluster_summary.md",
        "errors":      output_dir / "errors.json",
        "remediation": output_dir / "remediation_steps.md",
    }

    _write_full_report(paths["report"], findings, cluster_uuid, cluster_info)
    _write_cluster_summary(paths["summary"], findings, cluster_uuid, cluster_info)
    _write_errors_json(paths["errors"], findings)
    _write_remediation_steps(paths["remediation"], findings)
    _print_terminal_summary(findings, cluster_info, output_dir)

    return paths


# ── Full text report (Perplexity style) ──────────────────────────────────────

def _write_full_report(
    path: Path,
    findings: list[Finding],
    uuid: str,
    info: dict,
) -> None:
    lines: list[str] = []

    def section(title: str) -> None:
        lines.append("")
        lines.append(SEP)
        lines.append(f"  {title}")
        lines.append(SEP)

    def subsection(title: str) -> None:
        lines.append("")
        lines.append(SEP2)
        lines.append(f"  {title}")
        lines.append(SEP2)

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines += [SEP, "  PORTWORX DIAG BUNDLE ANALYSIS REPORT", f"  Generated: {now}", SEP]

    # ── 1. Node & Cluster Information ────────────────────────────────────────
    section("1. NODE & CLUSTER INFORMATION")
    px_running = info.get("px_running", False)
    lines += [
        f"  Hostname      : {info.get('hostname', info.get('node_analyzed', 'unknown'))}",
        f"  Cluster Name  : {info.get('name', 'unknown')}",
        f"  Cluster UUID  : {uuid}",
        f"  PX Version    : {info.get('px_version', 'unknown')}",
        f"  OS            : {info.get('os', 'unknown')}",
        f"  OCP Version   : {info.get('ocp_version', 'unknown')}",
        f"  Storage Type  : {info.get('storage_type', 'unknown')}",
        f"  Cloud Provider: {info.get('cloud_provider', 'unknown')}",
        f"  Data Iface    : {info.get('data_iface', 'unknown')}",
        f"  Mgmt Iface    : {info.get('mgmt_iface', 'unknown')}",
        f"  Fastpath      : {'ENABLED' if info.get('fastpath') else 'DISABLED/UNKNOWN'}",
        f"  Total Nodes   : {info.get('total_nodes', 'unknown')}",
        f"  Memory        : {info.get('memory_total_gib', 'unknown')} GiB",
        f"  Uptime        : {info.get('uptime', 'unknown')}",
        f"  PX Running    : {'YES' if px_running else 'NO  ← CRITICAL'}",
    ]

    # ── 2. Storage Pool Layout + Heap Dumps ──────────────────────────────────
    section("2. STORAGE & MEMORY HEALTH")

    heap_finding = next((f for f in findings if f.id == "LOCAL-HEAP-DUMP"), None)
    if heap_finding:
        extra = heap_finding.extra or {}
        lines.append(
            f"  ⚠  {extra.get('heap_count', 0)} heap dump(s) and "
            f"{extra.get('stack_count', 0)} stack dump(s) detected — MEMORY PRESSURE INDICATOR"
        )
        for fname in (extra.get("files") or [])[:8]:
            lines.append(f"     {fname}")
    else:
        lines.append("  No heap/stack dumps found.")

    # ── 3. Critical Alerts & Findings ────────────────────────────────────────
    section("3. CRITICAL ALERTS & FINDINGS")

    # Pull from volume.py findings which read the full NDJSON alerts.log
    # Also pull from node.py findings for node-level alerts
    alert_counts = _extract_alert_summary(findings)

    alarm_count = sum(v["count"] for v in alert_counts.values() if v["severity_str"] == "ALARM")
    warn_count  = sum(v["count"] for v in alert_counts.values() if v["severity_str"] == "WARNING")
    lines += [
        f"  Total ALARM   alerts: {alarm_count}",
        f"  Total WARNING alerts: {warn_count}",
        "",
    ]

    for name, data in sorted(alert_counts.items(), key=lambda x: -x[1]["count"]):
        if data["severity_str"] not in ("ALARM", "WARNING"):
            continue
        ss = SMART_SIGNAL_META.get(name, {})
        lines += [
            f"  [{data['severity_str']}] {name}  ({data['count']} occurrence(s))",
            f"    Smart Signal   : {ss.get('signal', 'No direct mapping') + (' (#' + str(ss['code']) + ')' if ss.get('code') else '')}",
            f"    Audience       : {ss.get('audience', 'Internal')}",
            f"    First Seen     : {data['first_seen']}",
            f"    Last Seen      : {data['last_seen']}",
            f"    Sample Message : {data['sample'][:160]}",
            "",
        ]

    # 3a: Volume full alerts
    vol_full = _get_volume_full_messages(findings)
    if vol_full:
        subsection(f"3a. VOLUME SPACE CRITICAL — {len(vol_full)} volume(s) at ≥80% capacity")
        for msg in vol_full[:50]:
            lines.append(f"  {msg}")

    # 3b: Peer node down events
    node_downs = _get_node_down_messages(findings)
    if node_downs:
        subsection(f"3b. PEER NODE DOWN EVENTS — {len(node_downs)} event(s)")
        for msg in node_downs[:40]:
            lines.append(f"  {msg}")

    # ── 4. Journal / Log Error Patterns ──────────────────────────────────────
    section("4. JOURNAL / LOG ERROR PATTERNS")
    journal_patterns = _extract_journal_patterns(findings)
    if journal_patterns:
        lines.append(f"  {'Pattern':<42} {'Count':>6}  Source")
        lines.append(f"  {'-'*42} {'-'*6}  {'-'*20}")
        for pat in journal_patterns:
            lines.append(f"  {pat['label']:<42} {pat['count']:>6}  {pat['source']}")
    else:
        lines.append("  No critical journal patterns detected.")

    # ── 5. pxctl Command Failures ─────────────────────────────────────────────
    section("5. PXCTL COMMAND FAILURES")
    pxctl_errors = _extract_pxctl_errors(findings)
    if pxctl_errors:
        for e in pxctl_errors:
            lines.append(f"  • {e}")
    else:
        lines.append("  No pxctl command failures recorded.")

    # ── 6. Root Cause Analysis ────────────────────────────────────────────────
    section("6. ROOT CAUSE ANALYSIS")
    rca = _build_root_cause_analysis(findings, info)
    if rca:
        for i, r in enumerate(rca, 1):
            lines += [
                f"  [{i}] {r['title']}",
                f"      Severity    : {r['severity']}",
                f"      Evidence    : {r['evidence']}",
                f"      Root Cause  : {r['root_cause']}",
                f"      Smart Signal: {r['smart_signal']}",
                "",
            ]
    else:
        lines.append("  No root causes identified.")

    # ── 7. Remediations ───────────────────────────────────────────────────────
    section("7. REMEDIATIONS")
    remediations = _build_remediations(findings, info)
    for i, r in enumerate(remediations, 1):
        lines += [
            f"  ── Remediation {i}: {r['title']} ──",
            f"  Priority   : {r['priority']}",
            f"  Finding    : {r['finding']}",
            "  Actions    :",
        ]
        for step in r["steps"]:
            lines.append(f"    • {step}")
        if r.get("kb"):
            lines.append(f"  KB / Docs  : {r['kb']}")
        lines.append("")

    # ── 8. Smart Signals Triggered ────────────────────────────────────────────
    section("8. SMART SIGNALS TRIGGERED BY THIS DIAG")
    ss_triggered = _collect_smart_signals(findings)
    if ss_triggered:
        lines.append(f"  {'Signal Name':<50} {'Code':>6}  Audience")
        lines.append(f"  {'-'*50} {'-'*6}  {'-'*10}")
        for ss in ss_triggered:
            code_str = str(ss.get("code", "N/A"))
            lines.append(f"  {ss['name']:<50} {code_str:>6}  {ss['audience']}")
    else:
        lines.append("  None triggered.")

    # ── 9. Troubleshooting doc matches (docs.portworx.com) ────────────────────
    section("9. TROUBLESHOOTING (PORTWORX DOCS)")
    ts_findings = [f for f in findings if f.id.startswith("TS-")]
    if ts_findings:
        for f in ts_findings:
            lines += [
                f"  [{f.severity}] {f.id}  ({f.count} match(es))",
                f"    Symptom    : {(f.symptom or '')[:150]}",
                f"    Cause      : {(f.cause or '')[:150]}",
                f"    Docs       : {f.docs_url or 'N/A'}",
            ]
            if f.diagnostic:
                lines.append(f"    Diagnostic : {f.diagnostic[0]}")
            lines.append("")
    else:
        lines.append("  No documented troubleshooting patterns matched this diag.")

    # ── 10. Related CNBU Portworx (PWX) Jira tickets ──────────────────────────
    linked = [f for f in findings if getattr(f, "jira_project", None)]
    if linked:
        project = linked[0].jira_project
        section(f"10. RELATED JIRA TICKETS ({project})")
        any_live = False
        for f in linked:
            tickets = getattr(f, "jira_tickets", None) or []
            if tickets:
                any_live = True
                lines.append(f"  {f.id}:")
                for t in tickets:
                    lines.append(f"    {t['key']:<12} [{t.get('status', '')}] {t.get('summary', '')[:80]}")
            elif getattr(f, "jira_search_url", None):
                lines.append(f"  {f.id}: {f.jira_search_url}")
        if not any_live:
            lines += [
                "",
                "  (dry-run — showing JQL search links; run with --jira-live and",
                "   JIRA_EMAIL / JIRA_API_TOKEN set to resolve matching issues.)",
            ]

    lines += ["", SEP, "  END OF REPORT", SEP]
    path.write_text("\n".join(lines), encoding="utf-8")
    log.info(f"Wrote: {path}")


# ── Helper: extract alert summary from all findings ───────────────────────────

def _extract_alert_summary(findings: list[Finding]) -> dict[str, dict]:
    """
    Build a summary dict keyed by alert_name with count/first/last/sample.
    Pulls from findings that were generated from the NDJSON alerts.log.
    """
    result: dict[str, dict] = {}

    for f in findings:
        extra = f.extra or {}
        alert_name = extra.get("alert_name", "")
        if not alert_name:
            continue

        count = f.count
        if alert_name not in result:
            result[alert_name] = {
                "count":        count,
                "severity_str": _sev_str(f.severity),
                "first_seen":   f.first_seen,
                "last_seen":    f.last_seen,
                "sample":       f.log_excerpt or "",
            }
        else:
            result[alert_name]["count"] += count

    # Also pull from LOCAL-NODE-* findings
    _LOCAL_ALERT_NAMES = {
        "LOCAL-NODE-QUORUM":   ("NodeStateChange / NotInQuorum", "ALARM"),
        "LOCAL-NODE-STARTFAIL":("NodeStartFailure",               "ALARM"),
        "LOCAL-CLUSTER-MGR":   ("ClusterManagerFailure",          "ALARM"),
        "LOCAL-STORAGE-FAIL":  ("StorageFailure",                 "ALARM"),
        "LOCAL-POOL-FAIL":     ("StoragePoolFailure",             "ALARM"),
    }
    for f in findings:
        if f.id in _LOCAL_ALERT_NAMES:
            name, sev = _LOCAL_ALERT_NAMES[f.id]
            if name not in result:
                result[name] = {
                    "count":        f.count,
                    "severity_str": sev,
                    "first_seen":   f.first_seen,
                    "last_seen":    f.last_seen,
                    "sample":       f.log_excerpt or "",
                }
            else:
                result[name]["count"] += f.count

    return result


def _sev_str(severity: str) -> str:
    return {"CRITICAL": "ALARM", "WARNING": "WARNING", "INFO": "INFO"}.get(severity, severity)


def _append_jira_block(lines: list, f: Finding) -> None:
    """Append PWX Jira linkage (Markdown) for a finding, if enrichment ran."""
    project = getattr(f, "jira_project", None)
    if not project:
        return
    tickets = getattr(f, "jira_tickets", None) or []
    if tickets:
        lines.append(f"**Related {project} Jira issues:**")
        for t in tickets:
            status = f" _({t['status']})_" if t.get("status") else ""
            lines.append(f"- [{t['key']}]({t['url']}) — {t.get('summary', '')}{status}")
        lines.append("")
    elif getattr(f, "jira_search_url", None):
        # Dry-run (or a live search with no matches): link the JQL search instead.
        lines += [f"**Search {project} Jira:** [{f.jira_query}]({f.jira_search_url})", ""]


def _get_volume_full_messages(findings: list[Finding]) -> list[str]:
    """Extract individual volume-full messages from SS-03 (VolumeSpaceLow) finding."""
    for f in findings:
        if f.id == "SS-03":
            msgs = f.extra.get("all_messages", [])
            if msgs:
                return [f"[{f.first_seen}] {m[:160]}" for m in msgs]
            # Fall back to log_excerpt
            if f.log_excerpt:
                return [f.log_excerpt[:160]]
    return []


def _get_node_down_messages(findings: list[Finding]) -> list[str]:
    """Extract node-down messages from NodeStateChange / NodeMarkedDown findings."""
    msgs = []
    for f in findings:
        if f.id in ("LOCAL-NODE-QUORUM", "SS-26") or (
            f.extra.get("alert_name", "") in ("NodeStateChange / NotInQuorum", "NodeMarkedDown")
        ):
            all_msgs = f.extra.get("all_messages", [])
            if all_msgs:
                msgs.extend(all_msgs[:20])
            elif f.log_excerpt:
                msgs.append(f.log_excerpt[:160])
    return msgs


def _extract_journal_patterns(findings: list[Finding]) -> list[dict]:
    """Extract journal error patterns from LOCAL-01 (STATUS_STORAGE_DOWN) and others."""
    patterns = []
    for f in findings:
        if f.id == "LOCAL-01":
            patterns.append({"label": "STATUS_STORAGE_DOWN", "count": f.count, "source": "px-jrnl-32min-*.log.gz"})
        elif f.id == "LOCAL-03":
            patterns.append({"label": "device-mapper thin error", "count": f.count, "source": "misc/dmesg.out"})
        elif f.id == "LOCAL-HEAP-DUMP":
            extra = f.extra or {}
            total = extra.get("heap_count", 0) + extra.get("stack_count", 0)
            patterns.append({"label": "Memory Heap/Stack Dumps", "count": total, "source": "var/cores/"})
    return sorted(patterns, key=lambda x: -x["count"])


def _extract_pxctl_errors(findings: list[Finding]) -> list[str]:
    """Extract pxctl command failure messages."""
    errors = []
    for f in findings:
        if f.id == "LOCAL-PX-DOWN":
            errors.append("pxctl status: PX daemon not running — all pxctl commands failed")
    return errors


# ── Root Cause Analysis ───────────────────────────────────────────────────────

def _build_root_cause_analysis(findings: list[Finding], info: dict) -> list[dict]:
    rca = []
    ids = {f.id for f in findings}
    extra_by_id = {f.id: (f.extra or {}) for f in findings}

    if "LOCAL-PX-DOWN" in ids:
        rca.append({
            "title":        "PX daemon is DOWN on this node",
            "severity":     "CRITICAL",
            "evidence":     "px-status.out: 'PX is not running on 127.0.0.1 host: Could not reach HealthMonitor'",
            "root_cause":   "Storage pool failed to load (pwx1/pxpool inaccessible), blocking PX startup. "
                            "Upstream trigger: gRPC EOF from internal KVDB/storage process.",
            "smart_signal": "px_init_failure (#10096), px_node_down_alert (#10109)",
        })

    if "LOCAL-POOL-FAIL" in ids or "LOCAL-STORAGE-FAIL" in ids:
        rca.append({
            "title":        "Storage pool load failure — pxpool inaccessible",
            "severity":     "CRITICAL",
            "evidence":     "alert_type=83: 'Datapool 1 load failed: failed to access pwx1/pxpool'; "
                            "alert_type=54: 'Storage initialization check failed'",
            "root_cause":   "The underlying block device or SAN path for the PX storage pool is "
                            "inaccessible. This is the most likely direct cause of the PX daemon failure.",
            "smart_signal": "pool_expand_failed_alert (#10076) — partial coverage only",
        })

    if "LOCAL-NODE-QUORUM" in ids:
        rca.append({
            "title":        "Node not in quorum — network isolation on port 17002",
            "severity":     "CRITICAL",
            "evidence":     "alert_type=11: 'Node is not in quorum. Waiting to connect to peer nodes on port 17002'",
            "root_cause":   "Port 17002 (PX cluster mesh) is blocked or unreachable. "
                            "This prevents the node from joining the cluster and contributes to PX not starting.",
            "smart_signal": "px_node_down_alert (#10109)",
        })

    if "LOCAL-NODE-STARTFAIL" in ids:
        extra = extra_by_id.get("LOCAL-NODE-STARTFAIL", {})
        sample = "Failed to Start driver: Error in grpc / ConfigMap is locked"
        rca.append({
            "title":        "Repeated PX start failures (NodeStartFailure)",
            "severity":     "CRITICAL",
            "evidence":     f"alert_type=9: {sample}",
            "root_cause":   "PX failed to initialize. Common causes: KVDB unavailable (gRPC EOF), "
                            "ConfigMap locked (Kubernetes API issue), or storage pool inaccessible.",
            "smart_signal": "px_init_failure (#10096)",
        })

    if "SS-03" in ids:
        vol_count = extra_by_id.get("SS-03", {}).get("total_count", 0)
        rca.append({
            "title":        f"Volume space low / full ({vol_count} alerts)",
            "severity":     "CRITICAL",
            "evidence":     "alert_type=30: Multiple PVCs at 80–100% capacity over several weeks",
            "root_cause":   "Applications are filling PX volumes faster than they are being expanded. "
                            "Root cause may be log accumulation, database growth, or missing auto-expand policy.",
            "smart_signal": "volume_space_low_alerts (#10081) — Support-facing, likely already triggered",
        })

    if "LOCAL-HEAP-DUMP" in ids:
        extra = extra_by_id.get("LOCAL-HEAP-DUMP", {})
        rca.append({
            "title":        f"Memory pressure — {extra.get('heap_count', 0)} heap dump(s) found",
            "severity":     "WARNING",
            "evidence":     f"Found {extra.get('heap_count', 0)} .heap.gz and {extra.get('stack_count', 0)} .stack.gz files in var/cores/",
            "root_cause":   "PX process experienced memory exhaustion events on this node. "
                            "These may correlate with the storage pool failures.",
            "smart_signal": "None — not monitored by any deployed Smart Signal",
        })

    return rca


# ── Remediations ──────────────────────────────────────────────────────────────

def _build_remediations(findings: list[Finding], info: dict) -> list[dict]:
    remediations = []
    ids = {f.id for f in findings}
    hostname = info.get("hostname", info.get("node_analyzed", "the affected node"))

    if "LOCAL-PX-DOWN" in ids:
        remediations.append({
            "title":    "Recover PX daemon",
            "priority": "P1 — CRITICAL",
            "finding":  "PX is not running; all volumes on this node are unavailable to pods",
            "steps": [
                f"SSH to node: ssh core@{hostname}",
                "Check PX service status: systemctl status portworx",
                "Review recent journal: journalctl -u portworx --since '2 hours ago' | tail -200",
                "Verify pool device: ls -la /dev/mapper/pwx* && lsblk | grep pwx",
                "If pool device missing, check FC/SAN connectivity: cat /sys/class/fc_host/host*/port_state",
                "If pool visible but PX won't start: pxctl service pool expand --operation=start",
                "Check KVDB: pxctl service kvdb members",
                "Restart PX after fixing underlying issue: systemctl restart portworx",
            ],
            "kb": "https://docs.portworx.com/operations/troubleshooting/",
        })

    if "LOCAL-NODE-QUORUM" in ids:
        remediations.append({
            "title":    "Restore cluster quorum — open port 17002",
            "priority": "P1 — CRITICAL",
            "finding":  "Node is not in quorum; PX cluster mesh unreachable",
            "steps": [
                "Verify port 17002 is listening: netstat -tlnp | grep 17002",
                "Check OVN-Kubernetes NetworkPolicy for port 17002 on OpenShift",
                "Test peer reachability: nc -zv <peer_node_ip> 17002",
                "If firewall is blocking: firewall-cmd --permanent --add-port=17002/tcp && firewall-cmd --reload",
                "After restoring connectivity: systemctl restart portworx",
            ],
            "kb": None,
        })

    if "LOCAL-POOL-FAIL" in ids or "LOCAL-STORAGE-FAIL" in ids:
        remediations.append({
            "title":    "Fix storage pool access failure",
            "priority": "P1 — CRITICAL",
            "finding":  "Datapool 1 failed to load: pwx1/pxpool inaccessible",
            "steps": [
                "Check block device visibility: lsblk | grep -E 'pwx|sd|nvme'",
                "Check FC multipath: multipathd show paths (look for failed paths)",
                "Check SAN zoning and LUN presentation from Pure storage array",
                "If device visible but corrupt: pxctl service pool show; pxctl service maintenance --enter",
                "Check pool status: pxctl service pool list",
                "If pool metadata corrupt, open P1 support case with Pure Storage — do NOT wipe without guidance",
            ],
            "kb": "https://docs.portworx.com/operations/troubleshooting/",
        })

    if "SS-03" in ids:
        vol_finding = next((f for f in findings if f.id == "SS-03"), None)
        vol_count = (vol_finding.extra or {}).get("total_count", "multiple") if vol_finding else "multiple"
        remediations.append({
            "title":    "Expand full volumes",
            "priority": "P2 — HIGH",
            "finding":  f"Volume space low alerts: {vol_count} PVCs at 80–100% capacity",
            "steps": [
                "List volumes by usage: pxctl volume list | grep -v '0 B'",
                "Expand a specific volume: pxctl volume update --size <new_GiB> <vol_id>",
                "Or resize PVC in Kubernetes: kubectl edit pvc <pvc_name> -n <namespace>",
                "Enable auto-expand: pxctl volume update --auto-fstrim=on <vol_id>",
                "Identify which apps are filling volumes and alert application owners",
                "Add storage nodes or expand pool capacity if cluster-level capacity is low",
            ],
            "kb": "https://purestorage.atlassian.net/browse/PWX-41031",
        })

    if "LOCAL-NODE-STARTFAIL" in ids:
        remediations.append({
            "title":    "Resolve PX startup failures (ConfigMap lock / gRPC EOF)",
            "priority": "P2 — HIGH",
            "finding":  "NodeStartFailure: ConfigMap is locked OR gRPC EOF from internal storage",
            "steps": [
                "Check for ConfigMap lock: kubectl get configmap -n kube-system | grep portworx",
                "If locked: kubectl delete configmap portworx-node-lock -n kube-system (CAUTION: confirm with team)",
                "Check Kubernetes API server reachability: curl -k https://172.73.0.1:443/healthz",
                "Check KVDB bootstrap: pxctl service kvdb members",
                "Review KVDB logs for EOF errors: journalctl -u portworx | grep -i 'kvdb\\|bootstrap\\|EOF'",
                "After fixing: systemctl restart portworx",
            ],
            "kb": None,
        })

    if "LOCAL-HEAP-DUMP" in ids:
        remediations.append({
            "title":    "Investigate memory pressure causing heap dumps",
            "priority": "P2 — HIGH",
            "finding":  "Multiple heap/stack dumps found — PX experienced memory exhaustion",
            "steps": [
                "Check current node memory: free -h; cat /proc/meminfo | grep MemAvailable",
                "Check PX memory usage: ps aux | grep portworx",
                "Review px_info.log in var/cores/ for crash context",
                "Check for OOM events: journalctl -k | grep -i 'oom\\|kill\\|memory'",
                "Attach all .heap.gz and .stack.gz files to a Pure Storage support case",
                "Consider adjusting PX memory limits or adding node memory",
            ],
            "kb": None,
        })

    return remediations


# ── Smart Signals Collection ──────────────────────────────────────────────────

def _collect_smart_signals(findings: list[Finding]) -> list[dict]:
    seen: set[str] = set()
    result = []
    for f in findings:
        if f.smart_signal and f.already_monitored:
            name = f.smart_signal
            if name not in seen:
                seen.add(name)
                result.append({
                    "name":     name,
                    "code":     f.alert_code,
                    "audience": "Support" if "support" in name.lower() else "Internal",
                })
    # Also from extra alert_name
    for f in findings:
        extra = f.extra or {}
        aname = extra.get("alert_name", "")
        ss = SMART_SIGNAL_META.get(aname, {})
        if ss and ss["signal"] not in seen:
            seen.add(ss["signal"])
            result.append({
                "name":     ss["signal"],
                "code":     ss.get("code"),
                "audience": ss.get("audience", "Internal"),
            })
    return sorted(result, key=lambda x: x["name"])


# ── Existing output files (unchanged structure) ───────────────────────────────

def _write_cluster_summary(
    path: Path, findings: list[Finding], uuid: str, info: dict,
) -> None:
    criticals = [f for f in findings if f.severity == "CRITICAL"]
    warnings  = [f for f in findings if f.severity == "WARNING"]
    dark      = [f for f in findings if f.dark_to_smart_signals]

    health = "CRITICAL" if criticals else ("WARNING" if warnings else "HEALTHY")
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
        f"| Hostname | `{info.get('hostname', info.get('node_analyzed', 'N/A'))}` |",
        f"| PX Version | {info.get('px_version', 'N/A')} |",
        f"| OS | {info.get('os', 'N/A')} |",
        f"| OCP Version | {info.get('ocp_version', 'N/A')} |",
        f"| Storage Type | {info.get('storage_type', 'N/A')} |",
        f"| Fastpath | {'ENABLED' if info.get('fastpath') else 'N/A'} |",
        f"| Total Nodes | {info.get('total_nodes', 'N/A')} |",
        f"| Node Uptime | {info.get('uptime', 'N/A')} |",
        f"| Memory | {info.get('memory_total_gib', 'N/A')} GiB |",
        f"| PX Running | {'YES' if info.get('px_running') else '**NO — CRITICAL**'} |",
        "",
        "## Health Assessment",
        "",
        f"**Overall Status: {health}**",
        "",
        f"- CRITICAL findings: {len(criticals)}",
        f"- WARNING findings:  {len(warnings)}",
        "",
    ]

    if dark:
        lines += [
            "## Smart Signals Gap Analysis",
            "",
            f"> **{len(dark)} finding(s) are NOT visible to Pure Storage's Smart Signals monitoring.**",
            "",
            "| Finding ID | Severity | Gap Note |",
            "|------------|----------|----------|",
        ]
        for f in dark:
            note = (f.dark_note or "No deployed Smart Signal covers this.")[:120]
            lines.append(f"| {f.id} | {f.severity} | {note} |")
        lines.append("")

    lines += [
        "## All Findings",
        "",
        "| ID | Severity | Category | Count | Smart Signal | Monitored | First Seen |",
        "|----|----------|----------|-------|-------------|-----------|------------|",
    ]
    for f in findings:
        mon = "YES" if f.already_monitored else "**NO**"
        ss  = f.smart_signal or "—"
        lines.append(f"| {f.id} | {f.severity} | {f.category} | {f.count} | {ss} | {mon} | {f.first_seen} |")

    # Troubleshooting-doc findings (TS-*) sourced from docs.portworx.com
    ts_findings = [f for f in findings if f.id.startswith("TS-")]
    if ts_findings:
        lines += [
            "",
            "## Troubleshooting (Portworx Docs)",
            "",
            "Findings matched against the Portworx Enterprise troubleshooting guide.",
            "",
            "| ID | Severity | Symptom | Doc |",
            "|----|----------|---------|-----|",
        ]
        for f in ts_findings:
            sym = (f.symptom or "")[:90].replace("|", "\\|")
            doc = f"[docs]({f.docs_url})" if f.docs_url else "—"
            lines.append(f"| {f.id} | {f.severity} | {sym} | {doc} |")

    # Related CNBU Portworx (PWX) Jira linkage, if enrichment ran
    linked = [f for f in findings if getattr(f, "jira_project", None)]
    if linked:
        project = linked[0].jira_project
        lines += [
            "",
            f"## Related Jira Tickets ({project})",
            "",
            f"Findings linked to the CNBU Portworx **{project}** project.",
            "",
            "| Finding | Related Issues |",
            "|---------|----------------|",
        ]
        for f in linked:
            tickets = getattr(f, "jira_tickets", None) or []
            if tickets:
                cell = ", ".join(f"[{t['key']}]({t['url']})" for t in tickets)
            elif getattr(f, "jira_search_url", None):
                cell = f"[search {project}]({f.jira_search_url})"
            else:
                cell = "—"
            lines.append(f"| {f.id} | {cell} |")

    path.write_text("\n".join(lines), encoding="utf-8")
    log.info(f"Wrote: {path}")


def _write_errors_json(path: Path, findings: list[Finding]) -> None:
    path.write_text(
        json.dumps([f.to_dict() for f in findings], indent=2, default=str),
        encoding="utf-8",
    )
    log.info(f"Wrote: {path}")


def _write_remediation_steps(path: Path, findings: list[Finding]) -> None:
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        "# Portworx Remediation Runbook",
        "",
        f"**Generated:** {now_str}",
        "",
        "Findings ordered: CRITICAL → WARNING. "
        "Findings marked **NOT MONITORED** are invisible to Pure Storage's Smart Signals.",
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
            "",
        ]
        if f.dark_note:
            lines += [f"> **Gap Note:** {f.dark_note}", ""]
        if getattr(f, "symptom", None):
            lines += [f"**Symptom:** {f.symptom}", ""]
        if getattr(f, "cause", None):
            lines += [f"**Cause:** {f.cause}", ""]
        if f.remediation_kb:
            lines += [f"**KB Article:** {f.remediation_kb}", ""]
        if getattr(f, "docs_url", None):
            lines += [f"**Portworx Docs:** {f.docs_url}", ""]
        if getattr(f, "diagnostic", None):
            lines.append("**Diagnostics:**")
            for cmd in f.diagnostic:
                lines.append(f"- `{cmd}`")
            lines.append("")
        if f.remediation_steps:
            lines.append("**Steps:**")
            for step in f.remediation_steps:
                lines.append(f"1. {step}")
            lines.append("")
        _append_jira_block(lines, f)
        lines += ["---", ""]

    path.write_text("\n".join(lines), encoding="utf-8")
    log.info(f"Wrote: {path}")


def _print_terminal_summary(
    findings: list[Finding], info: dict, output_dir: Path,
) -> None:
    console.print()
    console.print("[bold]Portworx Diagnostic Analysis Complete[/bold]")
    console.print(
        f"Cluster: [cyan]{info.get('name', 'N/A')}[/cyan]  "
        f"Node: [cyan]{info.get('hostname', info.get('node_analyzed', 'N/A'))}[/cyan]"
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
    for name in ("full_report.txt", "cluster_summary.md", "errors.json", "remediation_steps.md"):
        console.print(f"  {name}")
    console.print()
