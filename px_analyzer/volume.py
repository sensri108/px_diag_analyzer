"""
px_analyzer/volume.py — Smart Signals SS-01 through SS-11 (volume operations).

Scans:
    misc/px-alerts-show.out     — alert_type-based signals
    var/cores/.alerts/alerts.log — rolling alert log
    var/cores/px_status/*-px-jrnl-32min-*.log.gz — snapshot I/O errors
"""
from __future__ import annotations

import logging
from pathlib import Path

from px_analyzer.engine import Finding, make_finding
from px_analyzer._base import parse_alerts_show, find_files, scan_file

log = logging.getLogger(__name__)

# Map alert_type integers to pattern IDs.
# Note: alert_type 9, 11, 22, 54, 83 are handled by node.py (LOCAL-NODE-* patterns)
# to avoid duplicate findings.
ALERT_TYPE_MAP = {
    38:  "SS-01",           # volume creation failure
    30:  "SS-03",           # volume space low
    40:  "SS-05",           # volume delete failure
    212: "SS-06",           # volume device exists
    44:  "SS-08",           # volume unmount failure
    48:  "SS-10",           # snapshot creation failure
    63:  "SS-11",           # snapshot delete failure
    17:  "SS-24",           # PX init failure
    86:  "SS-27",           # node transition failure
    58:  "SS-19",           # license expiry
    29:  "SS-15",           # capacity alert
}


def analyze(extracted_path: Path, pattern_map: dict) -> list[Finding]:
    findings: list[Finding] = []

    alerts_show = extracted_path / "misc" / "px-alerts-show.out"
    alerts_log  = extracted_path / "var" / "cores" / ".alerts" / "alerts.log"

    # Parse all alerts from px-alerts-show.out
    alerts = parse_alerts_show(alerts_show)

    # Group by alert_type
    by_type: dict[int, list[dict]] = {}
    for a in alerts:
        at = a.get("alert_type", -1)
        if at == -1:
            continue
        by_type.setdefault(at, []).append(a)

    for at, entries in by_type.items():
        pid = ALERT_TYPE_MAP.get(at)
        if not pid or pid not in pattern_map:
            continue

        pd = pattern_map[pid]
        timestamps = [e["timestamp"] for e in entries if e.get("timestamp", "unknown") != "unknown"]
        uncleared  = [e for e in entries if not e.get("cleared", True)]

        # Count uncleared if any; else total
        effective_count = len(uncleared) if uncleared else len(entries)

        findings.append(make_finding(
            pd,
            log_excerpt=entries[0].get("raw", entries[0].get("message", ""))[:500],
            source_file="misc/px-alerts-show.out",
            first_seen=min(timestamps) if timestamps else "unknown",
            last_seen=max(timestamps) if timestamps else "unknown",
            count=effective_count,
            extra={
                "total_count": len(entries),
                "uncleared_count": len(uncleared),
                "alert_type": at,
            },
        ))

    # SS-02: resize failures (pattern-based, not alert_type)
    if "SS-02" in pattern_map:
        matches = scan_file(alerts_show, pattern_map["SS-02"]["pattern"])
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

    # SS-04: mount failures (pattern-based)
    if "SS-04" in pattern_map:
        for src in [alerts_show, alerts_log]:
            matches = scan_file(src, pattern_map["SS-04"]["pattern"])
            if matches:
                ts_list = [m["timestamp"] for m in matches if m["timestamp"] != "unknown"]
                findings.append(make_finding(
                    pattern_map["SS-04"],
                    log_excerpt=matches[0]["line"],
                    source_file=src.name,
                    first_seen=min(ts_list) if ts_list else "unknown",
                    last_seen=max(ts_list) if ts_list else "unknown",
                    count=len(matches),
                ))
                break

    # SS-10 supplement: snapshot I/O errors in journal logs
    jrnl_files = find_files(extracted_path, "var/cores/px_status/*-px-jrnl-32min-*.log.gz")
    snap_io_matches = []
    for jf in jrnl_files:
        snap_io_matches.extend(scan_file(jf, r'Snapshot.*Failed with status input/output error'))

    if snap_io_matches:
        existing_ids = {f.id for f in findings}
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
