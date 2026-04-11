"""
px_analyzer/volume.py — Smart Signals SS-01 through SS-11 and volume-level findings.

Primary source:
    var/cores/.alerts/alerts.log  — NDJSON, full historical record (2000+ lines, months of data)
                                    at the NODE ROOT level (NOT inside pwx_diag_*)

Fallback source:
    misc/px-alerts-show.out       — 5–10 most recent alerts at diag time

Also scans:
    var/cores/px_status/*-px-jrnl-32min-*.log.gz — snapshot I/O errors
"""
from __future__ import annotations

import logging
from pathlib import Path

from px_analyzer.engine import Finding, make_finding
from px_analyzer._base import (
    parse_alerts_show, parse_alerts_log,
    find_files, scan_file, find_node_root,
)

log = logging.getLogger(__name__)

# Alert_type → pattern ID (Smart Signal mapping)
# Types 9, 11, 22, 54, 83 are handled by node.py to avoid duplicates.
ALERT_TYPE_TO_PATTERN: dict[int, str] = {
    38:  "SS-01",   # volume creation failure
    30:  "SS-03",   # volume space low
    40:  "SS-05",   # volume delete failure
    212: "SS-06",   # volume device exists
    44:  "SS-08",   # volume unmount failure
    48:  "SS-10",   # snapshot creation failure
    63:  "SS-11",   # snapshot delete failure
    17:  "SS-24",   # PX init failure
    86:  "SS-27",   # storage node transition failure
    58:  "SS-19",   # license expiry
    29:  "SS-15",   # capacity alert
    106: "LOCAL-KVDB-BOOTSTRAP",  # KVDB bootstrap failure (not in original map)
    36:  "LOCAL-NODE-MARKED-DOWN",  # NodeMarkedDown
}


def analyze(extracted_path: Path, pattern_map: dict) -> list[Finding]:
    findings: list[Finding] = []

    # Locate the node root (has var/cores/.alerts/alerts.log)
    node_root = pattern_map.get("_node_root", find_node_root(extracted_path))

    alerts_log_path  = node_root / "var" / "cores" / ".alerts" / "alerts.log"
    alerts_show_path = extracted_path / "misc" / "px-alerts-show.out"

    # ── Load alerts: prefer NDJSON alerts.log (full history), fallback to px-alerts-show.out
    alerts = parse_alerts_log(alerts_log_path)
    if alerts:
        log.info(f"Loaded {len(alerts)} historical alerts from {alerts_log_path.name}")
    else:
        log.warning(f"alerts.log not found at {alerts_log_path}; falling back to px-alerts-show.out")
        alerts = parse_alerts_show(alerts_show_path)
        log.info(f"Loaded {len(alerts)} alerts from px-alerts-show.out")

    # ── Group by alert_type, skip INFO severity (3)
    by_type: dict[int, list[dict]] = {}
    for a in alerts:
        if a.get("severity", 3) == 3:
            continue  # skip informational
        at = a.get("alert_type", -1)
        if at == -1:
            continue
        by_type.setdefault(at, []).append(a)

    log.info(f"Alert types present (non-INFO): {sorted(by_type.keys())}")

    for at, entries in sorted(by_type.items()):
        pid = ALERT_TYPE_TO_PATTERN.get(at)
        if not pid or pid not in pattern_map:
            continue

        pd = pattern_map[pid]
        timestamps = [e["timestamp"] for e in entries if e.get("timestamp", "unknown") != "unknown"]
        uncleared  = [e for e in entries if not e.get("cleared", False)]
        effective_count = len(entries)  # use total count for full-history view

        # Build a useful excerpt (first message)
        first = entries[0]
        excerpt = first.get("message", f"alert_type={at}")

        findings.append(make_finding(
            pd,
            log_excerpt=excerpt,
            source_file="var/cores/.alerts/alerts.log",
            first_seen=min(timestamps) if timestamps else "unknown",
            last_seen=max(timestamps) if timestamps else "unknown",
            count=effective_count,
            extra={
                "alert_type":     at,
                "alert_name":     first.get("alert_name", ""),
                "total_count":    len(entries),
                "uncleared_count": len(uncleared),
                "all_messages":   [e["message"] for e in entries][:10],  # keep top 10
            },
        ))

    # ── SS-02: resize failures (pattern-based on alerts-show text)
    if "SS-02" in pattern_map:
        matches = scan_file(alerts_show_path, pattern_map["SS-02"]["pattern"])
        if matches:
            ts_list = [m["timestamp"] for m in matches if m["timestamp"] != "unknown"]
            findings.append(make_finding(
                pattern_map["SS-02"],
                log_excerpt=matches[0]["line"],
                source_file="misc/px-alerts-show.out",
                first_seen=min(ts_list) if ts_list else "unknown",
                last_seen=max(ts_list) if ts_list else "unknown",
                count=len(matches),
            ))

    # ── SS-04: mount failures (pattern-based)
    if "SS-04" in pattern_map:
        matches = scan_file(alerts_show_path, pattern_map["SS-04"]["pattern"])
        if matches:
            ts_list = [m["timestamp"] for m in matches if m["timestamp"] != "unknown"]
            findings.append(make_finding(
                pattern_map["SS-04"],
                log_excerpt=matches[0]["line"],
                source_file="misc/px-alerts-show.out",
                first_seen=min(ts_list) if ts_list else "unknown",
                last_seen=max(ts_list) if ts_list else "unknown",
                count=len(matches),
            ))

    # ── SS-10 supplement: snapshot I/O errors in journal logs
    jrnl_files = find_files(extracted_path, "var/cores/px_status/*-px-jrnl-32min-*.log.gz")
    snap_io_matches = []
    for jf in jrnl_files:
        snap_io_matches.extend(scan_file(jf, r'Snapshot.*Failed with status input/output error'))

    existing_ids = {f.id for f in findings}
    if snap_io_matches:
        if "SS-10" not in existing_ids and "SS-10" in pattern_map:
            ts_list = [m["timestamp"] for m in snap_io_matches if m["timestamp"] != "unknown"]
            findings.append(make_finding(
                pattern_map["SS-10"],
                log_excerpt=snap_io_matches[0]["line"],
                source_file="var/cores/px_status/*-px-jrnl-32min-*.log.gz",
                first_seen=min(ts_list) if ts_list else "unknown",
                last_seen=max(ts_list) if ts_list else "unknown",
                count=len(snap_io_matches),
                extra={"source": "jrnl_log"},
            ))
        elif "SS-10" in existing_ids:
            for f in findings:
                if f.id == "SS-10":
                    f.extra["jrnl_snapshot_io_errors"] = len(snap_io_matches)

    return findings
