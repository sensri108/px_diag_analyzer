"""
px_analyzer/infrastructure.py — SS-07 (stale mount), LOCAL-03 (device-mapper thin error).

Sources:
    var/cores/px_status/<node>-px-jrnl-32min-<ts>.log.gz  (SS-07 stale mount)
    misc/dmesg.out                                          (LOCAL-03 device-mapper thin)
"""
from __future__ import annotations

import logging
from pathlib import Path

from px_analyzer.engine import Finding, make_finding
from px_analyzer._base import find_files, scan_file

log = logging.getLogger(__name__)


def analyze(extracted_path: Path, pattern_map: dict) -> list[Finding]:
    findings: list[Finding] = []

    # SS-07: stale mount in journal logs
    if "SS-07" in pattern_map:
        jrnl_files = find_files(extracted_path, "var/cores/px_status/*-px-jrnl-32min-*.log.gz")
        matches = []
        for jf in jrnl_files:
            matches.extend(scan_file(jf, pattern_map["SS-07"]["pattern"]))
        if matches:
            ts_list = [m["timestamp"] for m in matches if m["timestamp"] != "unknown"]
            findings.append(make_finding(
                pattern_map["SS-07"],
                log_excerpt=matches[0]["line"],
                source_file="var/cores/px_status/*-px-jrnl-32min-*.log.gz",
                first_seen=min(ts_list) if ts_list else "unknown",
                last_seen=max(ts_list) if ts_list else "unknown",
                count=len(matches),
            ))

    # LOCAL-03: device-mapper thin metadata error in dmesg
    if "LOCAL-03" in pattern_map:
        dmesg = extracted_path / "misc" / "dmesg.out"
        matches = scan_file(dmesg, pattern_map["LOCAL-03"]["pattern"])
        if matches:
            ts_list = [m["timestamp"] for m in matches if m["timestamp"] != "unknown"]
            findings.append(make_finding(
                pattern_map["LOCAL-03"],
                log_excerpt=matches[0]["line"],
                source_file="misc/dmesg.out",
                first_seen=min(ts_list) if ts_list else "unknown",
                last_seen=max(ts_list) if ts_list else "unknown",
                count=len(matches),
            ))

    return findings
