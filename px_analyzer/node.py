"""
px_analyzer/node.py — Smart Signals SS-18, SS-21, SS-25, SS-26, SS-27.

Sources:
    misc/px-status.out
    misc/uptime.out
    var/lib/osd/log/px_node_stats/<timestamp>
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

    px_status = extracted_path / "misc" / "px-status.out"

    # SS-18: high node count (> 300)
    if "SS-18" in pattern_map:
        content = read_gz_or_plain(px_status)
        m = re.search(r'Total\s+Nodes\s*:\s*(\d+)', content, re.IGNORECASE)
        if m and int(m.group(1)) > 300:
            findings.append(make_finding(
                pattern_map["SS-18"],
                log_excerpt=m.group(0),
                source_file="misc/px-status.out",
                count=int(m.group(1)),
            ))

    # SS-26: node down
    if "SS-26" in pattern_map:
        matches = scan_file(px_status, pattern_map["SS-26"]["pattern"])
        if matches:
            ts_list = [m["timestamp"] for m in matches if m["timestamp"] != "unknown"]
            findings.append(make_finding(
                pattern_map["SS-26"],
                log_excerpt=matches[0]["line"],
                source_file="misc/px-status.out",
                first_seen=min(ts_list) if ts_list else "unknown",
                last_seen=max(ts_list) if ts_list else "unknown",
                count=len(matches),
            ))

    # SS-21 + SS-25: node stats analysis
    stats_dir = extracted_path / "var" / "lib" / "osd" / "log" / "px_node_stats"
    if stats_dir.exists():
        stat_files = sorted(stats_dir.iterdir())
        _check_flush_latency(stat_files, pattern_map, findings)
        _check_stats_gaps(stat_files, pattern_map, findings)

    return findings


def _check_flush_latency(
    stat_files: list[Path],
    pattern_map: dict,
    findings: list[Finding],
) -> None:
    """
    SS-21: flush latency > 700ms for 15+ consecutive minutes.
    Parses timestamped node stats files, computes delta_flush_ms / delta_num_flushes
    between consecutive files. Flags if > 700ms for 18+ consecutive files.
    """
    if "SS-21" not in pattern_map:
        return

    flush_ms_pat = re.compile(r'flush_ms[=:\s]+(\d+(?:\.\d+)?)', re.IGNORECASE)
    flush_n_pat  = re.compile(r'num_flushes[=:\s]+(\d+(?:\.\d+)?)', re.IGNORECASE)

    prev_flush_ms = None
    prev_flush_n  = None
    high_latency_streak = 0
    first_high_ts = "unknown"

    for sf in stat_files:
        content = read_gz_or_plain(sf)
        m_ms = flush_ms_pat.search(content)
        m_n  = flush_n_pat.search(content)

        if not m_ms or not m_n:
            prev_flush_ms = prev_flush_n = None
            high_latency_streak = 0
            continue

        curr_ms = float(m_ms.group(1))
        curr_n  = float(m_n.group(1))

        if prev_flush_ms is not None and prev_flush_n is not None:
            delta_ms = curr_ms - prev_flush_ms
            delta_n  = curr_n  - prev_flush_n
            if delta_n > 0:
                avg_latency = delta_ms / delta_n
                if avg_latency > 700:
                    if high_latency_streak == 0:
                        first_high_ts = sf.name
                    high_latency_streak += 1
                else:
                    high_latency_streak = 0
            else:
                high_latency_streak = 0

        prev_flush_ms = curr_ms
        prev_flush_n  = curr_n

    if high_latency_streak >= 18:
        findings.append(make_finding(
            pattern_map["SS-21"],
            log_excerpt=f"flush latency > 700ms for {high_latency_streak} consecutive stat files",
            source_file="var/lib/osd/log/px_node_stats/",
            first_seen=first_high_ts,
            count=high_latency_streak,
        ))


def _check_stats_gaps(
    stat_files: list[Path],
    pattern_map: dict,
    findings: list[Finding],
) -> None:
    """
    SS-25: gap > 2100 seconds between consecutive node stat files.
    Parses unix timestamps from filenames.
    """
    if "SS-25" not in pattern_map:
        return

    ts_pat = re.compile(r'(\d{10,13})')

    timestamps = []
    for sf in stat_files:
        m = ts_pat.search(sf.name)
        if m:
            ts = int(m.group(1))
            if ts > 1e12:
                ts //= 1000  # milliseconds → seconds
            timestamps.append((ts, sf.name))

    timestamps.sort()
    gaps = []
    for i in range(1, len(timestamps)):
        gap = timestamps[i][0] - timestamps[i - 1][0]
        if gap > 2100:
            gaps.append({
                "gap_seconds": gap,
                "from": timestamps[i - 1][1],
                "to": timestamps[i][1],
            })

    if gaps:
        max_gap = max(g["gap_seconds"] for g in gaps)
        findings.append(make_finding(
            pattern_map["SS-25"],
            log_excerpt=f"{len(gaps)} gap(s) > 2100s; largest gap: {max_gap}s",
            source_file="var/lib/osd/log/px_node_stats/",
            count=len(gaps),
            extra={"gaps": gaps},
        ))
