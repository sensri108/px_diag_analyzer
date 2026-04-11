"""
px_analyzer/storage.py — LOCAL-01 (STATUS_STORAGE_DOWN) and correlated storage events.

Source: var/cores/px_status/<node>-px-jrnl-32min-<ts>.log.gz

Critical logic: If STATUS_STORAGE_DOWN and snapshot I/O errors appear within 5 minutes
of each other, they are correlated — snapshots are downstream, not independent root cause.
(Correlation is handled by engine._correlate after all analyzers run.)
"""
from __future__ import annotations

import logging
from pathlib import Path

from px_analyzer.engine import Finding, make_finding
from px_analyzer._base import find_files, scan_file

log = logging.getLogger(__name__)

STORAGE_PATTERNS = {
    "status_storage_down":  r"STATUS_STORAGE_DOWN",
    "snapshot_io_error":    r"Snapshot.*Failed with status input/output error",
    "kubevirt_vol_missing": r"Failed to get volume info.*not found",
    "kubevirt_label_retry": r"Failed to update Kubevirt volume labels.*retryCount=(\d+)",
}


def analyze(extracted_path: Path, pattern_map: dict) -> list[Finding]:
    findings: list[Finding] = []

    jrnl_files = find_files(extracted_path, "var/cores/px_status/*-px-jrnl-32min-*.log.gz")

    ssd_matches = []
    for jf in jrnl_files:
        ssd_matches.extend(scan_file(jf, STORAGE_PATTERNS["status_storage_down"]))

    if ssd_matches and "LOCAL-01" in pattern_map:
        ts_list = [m["timestamp"] for m in ssd_matches if m["timestamp"] != "unknown"]
        findings.append(make_finding(
            pattern_map["LOCAL-01"],
            log_excerpt=ssd_matches[0]["line"],
            source_file="var/cores/px_status/*-px-jrnl-32min-*.log.gz",
            first_seen=min(ts_list) if ts_list else "unknown",
            last_seen=max(ts_list) if ts_list else "unknown",
            count=len(ssd_matches),
        ))

    return findings
