"""
px_analyzer/capacity.py — Smart Signals SS-15, SS-16, SS-17, SS-23.

Note: SS-15 (alert_type=29) is also handled by volume.py via ALERT_TYPE_MAP.
This module covers pool-expand failures and max-storage-nodes config checks.

Sources:
    misc/px-alerts-show.out
    var/cores/.alerts/alerts.log
    misc/px-cluster-options.out
    misc/px-status.out
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

from px_analyzer.engine import Finding, make_finding
from px_analyzer._base import scan_file, read_gz_or_plain

log = logging.getLogger(__name__)


def analyze(extracted_path: Path, pattern_map: dict) -> list[Finding]:
    findings: list[Finding] = []

    alerts_show  = extracted_path / "misc" / "px-alerts-show.out"
    alerts_log   = extracted_path / "var" / "cores" / ".alerts" / "alerts.log"
    cluster_opts = extracted_path / "misc" / "px-cluster-options.out"
    px_status    = extracted_path / "misc" / "px-status.out"

    # SS-16: pool expand failures (pattern-based)
    if "SS-16" in pattern_map:
        for src in [alerts_show, alerts_log]:
            matches = scan_file(src, pattern_map["SS-16"]["pattern"])
            if matches:
                ts_list = [m["timestamp"] for m in matches if m["timestamp"] != "unknown"]
                findings.append(make_finding(
                    pattern_map["SS-16"],
                    log_excerpt=matches[0]["line"],
                    source_file=src.name,
                    first_seen=min(ts_list) if ts_list else "unknown",
                    last_seen=max(ts_list) if ts_list else "unknown",
                    count=len(matches),
                ))
                break

    # SS-17: max_storage_nodes == 0 (possible misconfiguration)
    if "SS-17" in pattern_map and cluster_opts.exists():
        content = read_gz_or_plain(cluster_opts)
        m = re.search(r'max.storage.nodes\s*(?:per.zone)?\s*[=:]\s*(\d+)', content, re.IGNORECASE)
        if m and int(m.group(1)) == 0:
            findings.append(make_finding(
                pattern_map["SS-17"],
                log_excerpt=m.group(0),
                source_file="misc/px-cluster-options.out",
                count=1,
            ))

    # SS-23: max_storage_nodes_per_zone > total_nodes
    if "SS-23" in pattern_map and cluster_opts.exists() and px_status.exists():
        opts_content   = read_gz_or_plain(cluster_opts)
        status_content = read_gz_or_plain(px_status)
        mz = re.search(r'max.storage.nodes.per.zone\s*[=:]\s*(\d+)', opts_content, re.IGNORECASE)
        mn = re.search(r'Total\s+Nodes\s*:\s*(\d+)', status_content, re.IGNORECASE)
        if mz and mn and int(mz.group(1)) > int(mn.group(1)):
            findings.append(make_finding(
                pattern_map["SS-23"],
                log_excerpt=(
                    f"max_storage_nodes_per_zone={mz.group(1)} "
                    f"> total_nodes={mn.group(1)}"
                ),
                source_file="misc/px-cluster-options.out",
                count=1,
            ))

    return findings
