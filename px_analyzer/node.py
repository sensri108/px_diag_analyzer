"""
px_analyzer/node.py — Node health analysis.

Covers Smart Signals SS-18, SS-21, SS-25, SS-26, SS-27 and local patterns:
    LOCAL-PX-DOWN          PX daemon not running
    LOCAL-NODE-QUORUM      Node not in quorum (alert_type=11)
    LOCAL-NODE-STARTFAIL   Node start / driver init failure (alert_type=9)
    LOCAL-CLUSTER-MGR      Cluster manager failure (alert_type=22)
    LOCAL-STORAGE-FAIL     Storage initialization failure (alert_type=54)
    LOCAL-POOL-FAIL        Storage pool / datapool load failure (alert_type=83)

Sources:
    misc/px-status.out
    misc/px-alerts-show.out
    var/lib/osd/log/px_node_stats/<HH:MM:SS_YYYY-MM-DD>
"""
from __future__ import annotations

import logging
import re
from datetime import datetime
from pathlib import Path

from px_analyzer.engine import Finding, make_finding
from px_analyzer._base import (
    scan_file, read_gz_or_plain, parse_alerts_show,
    parse_alerts_log, find_node_root,
)

log = logging.getLogger(__name__)

# Map alert_type integer → LOCAL pattern ID
# Populated from actual diag observations and PX alert type registry
_ALERT_TYPE_TO_PATTERN: dict[int, str] = {
    9:  "LOCAL-NODE-STARTFAIL",   # NodeStartFailure / Failed to start driver
    11: "LOCAL-NODE-QUORUM",      # NodeStateChange – not in quorum
    22: "LOCAL-CLUSTER-MGR",      # ClusterManagerFailure
    54: "LOCAL-STORAGE-FAIL",     # StorageFailure – storage init check failed
    83: "LOCAL-POOL-FAIL",        # StoragePoolFailure – datapool load failed
}


def analyze(extracted_path: Path, pattern_map: dict) -> list[Finding]:
    findings: list[Finding] = []

    node_root      = pattern_map.get("_node_root", find_node_root(extracted_path))
    px_status_path = extracted_path / "misc" / "px-status.out"
    px_alerts_path = extracted_path / "misc" / "px-alerts-show.out"
    alerts_log_path = node_root / "var" / "cores" / ".alerts" / "alerts.log"

    # ── 0. Heap/stack dump detection ─────────────────────────────────────────
    # These live in var/cores/ at the node root level, NOT in pwx_diag_*
    cores_dir = node_root / "var" / "cores"
    _check_heap_dumps(cores_dir, pattern_map, findings)

    # ── 1. PX daemon down ─────────────────────────────────────────────────────
    # "PX is not running" / "Could not reach 'HealthMonitor'" appears when the
    # PX process is not up.  This is the most critical CRITICAL finding.
    if "LOCAL-PX-DOWN" in pattern_map:
        matches = scan_file(px_status_path, pattern_map["LOCAL-PX-DOWN"]["pattern"])
        if matches:
            findings.append(make_finding(
                pattern_map["LOCAL-PX-DOWN"],
                log_excerpt=matches[0]["line"],
                source_file="misc/px-status.out",
                count=len(matches),
            ))

    # ── 2. Alert-type-based findings from alerts.log (NDJSON full history) ───
    # Prefer the full NDJSON log; fall back to px-alerts-show.out (5 alerts)
    alerts = parse_alerts_log(alerts_log_path)
    if alerts:
        log.info(f"Parsed {len(alerts)} historical alert(s) from {alerts_log_path.name}")
    else:
        alerts = parse_alerts_show(px_alerts_path)
        log.info(f"Parsed {len(alerts)} alert(s) from {px_alerts_path.name}")

    seen_types: set[int] = set()
    for alert in alerts:
        at = alert.get("alert_type", -1)
        if at < 0 or at in seen_types:
            continue  # skip duplicates (same alert_type already reported)

        pid = _ALERT_TYPE_TO_PATTERN.get(at)
        if pid and pid in pattern_map:
            seen_types.add(at)
            findings.append(make_finding(
                pattern_map[pid],
                log_excerpt=alert.get("message", f"alert_type={at}"),
                source_file="misc/px-alerts-show.out",
                first_seen=alert.get("timestamp", "unknown"),
                last_seen=alert.get("timestamp", "unknown"),
                count=int(alert.get("count", 1)),
                extra={"alert_type": at, "cleared": alert.get("cleared", False)},
            ))

    # ── 3. SS-26: node down (pattern-based scan of px-status.out) ────────────
    if "SS-26" in pattern_map:
        matches = scan_file(px_status_path, pattern_map["SS-26"]["pattern"])
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

    # ── 4. SS-18: high node count (> 300) ────────────────────────────────────
    if "SS-18" in pattern_map:
        content = read_gz_or_plain(px_status_path)
        m = re.search(r'Total\s+Nodes\s*:\s*(\d+)', content, re.IGNORECASE)
        if m and int(m.group(1)) > 300:
            findings.append(make_finding(
                pattern_map["SS-18"],
                log_excerpt=m.group(0),
                source_file="misc/px-status.out",
                count=int(m.group(1)),
            ))

    # ── 5. SS-21 + SS-25: node stats analysis ────────────────────────────────
    stats_dir = extracted_path / "var" / "lib" / "osd" / "log" / "px_node_stats"
    if stats_dir.exists():
        stat_files = sorted(stats_dir.iterdir())
        _check_flush_latency(stat_files, pattern_map, findings)
        _check_stats_gaps(stat_files, pattern_map, findings)

    return findings


def _check_heap_dumps(
    cores_dir: Path,
    pattern_map: dict,
    findings: list[Finding],
) -> None:
    """
    Detect heap and stack dump files in var/cores/.
    These indicate memory pressure / OOM events that caused PX to dump state.
    """
    if not cores_dir.exists():
        return

    heap_files  = sorted(cores_dir.glob("*.heap.gz"))
    stack_files = sorted(cores_dir.glob("*.stack.gz"))

    if not heap_files and not stack_files:
        return

    dump_list = (
        [f"[HEAP]  {f.name}" for f in heap_files] +
        [f"[STACK] {f.name}" for f in stack_files]
    )
    excerpt = (
        f"{len(heap_files)} heap dump(s) and {len(stack_files)} stack dump(s) found in var/cores/.\n"
        + "\n".join(dump_list[:8])
    )

    # Use LOCAL-PX-DOWN pattern as the closest match (memory dump → PX crashed)
    if "LOCAL-PX-DOWN" in pattern_map:
        # Create a separate heap-dump finding with its own label
        findings.append(Finding(
            id="LOCAL-HEAP-DUMP",
            smart_signal=None,
            alert_code=None,
            alert_type=None,
            severity="WARNING",
            category="node",
            pattern_matched="*.heap.gz / *.stack.gz",
            log_excerpt=excerpt,
            source_file="var/cores/",
            first_seen=heap_files[0].name if heap_files else stack_files[0].name,
            last_seen=(heap_files or stack_files)[-1].name,
            count=len(heap_files) + len(stack_files),
            already_monitored=False,
            dark_to_smart_signals=True,
            dark_note="Heap/stack dumps indicate PX memory pressure or crash events. Not monitored by any Smart Signal.",
            remediation_kb=None,
            remediation_steps=[
                f"Found {len(heap_files)} heap dump(s) and {len(stack_files)} stack dump(s) in var/cores/",
                "Heap dumps indicate PX ran out of memory or crashed — check node memory: free -h",
                "Review px_info.log in var/cores/ for the crash context",
                "Check node resource pressure: cat /proc/meminfo; top -b -n1 | head -20",
                "Open a Pure Storage support case and attach all .heap.gz and .stack.gz files",
                "Consider increasing node memory or reducing PX memory limits",
            ],
            extra={"heap_count": len(heap_files), "stack_count": len(stack_files), "files": dump_list},
        ))


def _check_flush_latency(
    stat_files: list[Path],
    pattern_map: dict,
    findings: list[Finding],
) -> None:
    """
    SS-21: flush latency > 700ms for 15+ consecutive minutes.

    Node stats files are JSON:
      {"nid": ..., "pool_stats": [{"pool_id": 1, "s": {"flush_ms": N, "num_flushes": N}}], ...}

    Computes per-pool avg latency = delta_flush_ms / delta_num_flushes between
    consecutive files. Flags if > 700ms for 18+ consecutive files (~15 min).
    """
    if "SS-21" not in pattern_map:
        return

    import json

    prev_flush_ms: dict[int, float] = {}
    prev_flush_n:  dict[int, float] = {}
    high_latency_streak = 0
    first_high_ts = "unknown"

    for sf in stat_files:
        content = read_gz_or_plain(sf)
        if not content:
            high_latency_streak = 0
            prev_flush_ms.clear()
            prev_flush_n.clear()
            continue

        try:
            data = json.loads(content)
        except (json.JSONDecodeError, ValueError):
            high_latency_streak = 0
            prev_flush_ms.clear()
            prev_flush_n.clear()
            continue

        pool_stats = data.get("pool_stats", [])
        any_high = False
        for ps in pool_stats:
            pool_id = ps.get("pool_id", 0)
            s = ps.get("s", {})
            curr_ms = float(s.get("flush_ms", 0))
            curr_n  = float(s.get("num_flushes", 0))

            if pool_id in prev_flush_ms:
                delta_ms = curr_ms - prev_flush_ms[pool_id]
                delta_n  = curr_n  - prev_flush_n[pool_id]
                if delta_n > 0 and (delta_ms / delta_n) > 700:
                    any_high = True

            prev_flush_ms[pool_id] = curr_ms
            prev_flush_n[pool_id]  = curr_n

        if any_high:
            if high_latency_streak == 0:
                first_high_ts = sf.name
            high_latency_streak += 1
        else:
            high_latency_streak = 0

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

    Filenames use the format HH:MM:SS_YYYY-MM-DD (e.g. 19:33:10_2026-04-09).
    Falls back to unix timestamp regex for older formats.
    """
    if "SS-25" not in pattern_map:
        return

    # Primary: HH:MM:SS_YYYY-MM-DD filename format
    hms_pat  = re.compile(r'^(\d{2}:\d{2}:\d{2})_(\d{4}-\d{2}-\d{2})$')
    # Fallback: unix timestamp in filename
    unix_pat = re.compile(r'(\d{10,13})')

    timestamps: list[tuple[int, str]] = []
    for sf in stat_files:
        name = sf.name
        m = hms_pat.match(name)
        if m:
            try:
                dt = datetime.strptime(f"{m.group(2)} {m.group(1)}", "%Y-%m-%d %H:%M:%S")
                timestamps.append((int(dt.timestamp()), name))
                continue
            except ValueError:
                pass
        m2 = unix_pat.search(name)
        if m2:
            ts = int(m2.group(1))
            if ts > 1e12:
                ts //= 1000
            timestamps.append((ts, name))

    timestamps.sort()
    gaps = []
    for i in range(1, len(timestamps)):
        gap = timestamps[i][0] - timestamps[i - 1][0]
        if gap > 2100:
            gaps.append({
                "gap_seconds": gap,
                "from": timestamps[i - 1][1],
                "to":   timestamps[i][1],
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
