"""
px_analyzer/network.py — SS-22 (NFS dependency install failure), MTU/bond checks.

Sources:
    misc/px-alerts-show.out
    var/cores/.alerts/alerts.log
"""
from __future__ import annotations

import logging
from pathlib import Path

from px_analyzer.engine import Finding, make_finding
from px_analyzer._base import scan_file

log = logging.getLogger(__name__)


def analyze(extracted_path: Path, pattern_map: dict) -> list[Finding]:
    findings: list[Finding] = []

    alerts_show = extracted_path / "misc" / "px-alerts-show.out"
    alerts_log  = extracted_path / "var" / "cores" / ".alerts" / "alerts.log"

    # SS-22: NFS dependency install failure
    if "SS-22" in pattern_map:
        for src in [alerts_show, alerts_log]:
            matches = scan_file(src, pattern_map["SS-22"]["pattern"])
            if matches:
                ts_list = [m["timestamp"] for m in matches if m["timestamp"] != "unknown"]
                findings.append(make_finding(
                    pattern_map["SS-22"],
                    log_excerpt=matches[0]["line"],
                    source_file=src.name,
                    first_seen=min(ts_list) if ts_list else "unknown",
                    last_seen=max(ts_list) if ts_list else "unknown",
                    count=len(matches),
                ))
                break

    return findings
