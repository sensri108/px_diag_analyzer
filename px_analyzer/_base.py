"""
px_analyzer/_base.py — Shared scan utilities used by all analyzer modules.

Functions:
    find_diag_root(extracted_path) -> Path to actual diag content root
    scan_file(path, pattern)       -> list of {line, timestamp, lineno}
    find_files(root, glob)         -> list of matching Paths
    read_gz_or_plain(path)         -> str
    parse_alerts_show(path)        -> list of alert dicts
    ts_from_line(line)             -> ISO timestamp string or "unknown"
"""
from __future__ import annotations

import gzip
import json
import logging
import re
from pathlib import Path

log = logging.getLogger(__name__)


def find_node_root(diag_root: Path) -> Path:
    """
    Given the resolved pwx_diag_<id> root, walk UP to find the node-level
    extracted directory — the one that contains var/cores/.alerts/alerts.log,
    var/cores/*.heap.gz, etc.

    Structure after extraction + find_diag_root():
        <node>/                              ← node root (what we want here)
          var/cores/.alerts/alerts.log
          var/cores/*.heap.gz
          var/lib/osd/diagfiles/
            pwx_diag_<id>/                   ← diag_root (what find_diag_root returns)
              misc/px-status.out
              ...

    If diag_root already has var/cores/ as a child, return it unchanged.
    """
    # Already at node root?
    if (diag_root / "var" / "cores").exists():
        return diag_root

    # Walk up: pwx_diag_* → diagfiles → osd → lib → var → <node>
    candidate = diag_root
    for _ in range(6):
        candidate = candidate.parent
        if (candidate / "var" / "cores").exists():
            log.debug(f"find_node_root: resolved {diag_root.name} → {candidate.name}")
            return candidate

    log.warning(f"find_node_root: could not find var/cores above {diag_root}; using diag_root")
    return diag_root


def parse_alerts_log(path: Path) -> list[dict]:
    """
    Parse NDJSON var/cores/.alerts/alerts.log.

    Each line is a JSON object:
      {"severity": 1, "alert_type": 9, "message": "...",
       "timestamp": {"seconds": 1774156790}, "resource_id": "...", ...}

    severity: 1=ALARM, 2=WARNING, 3=INFO/NOTIFY
    Returns normalized dicts with keys: severity, severity_str, alert_type,
    alert_name, message, timestamp, resource_id, count, cleared
    """
    from datetime import datetime, timezone

    SEVERITY_MAP = {1: "ALARM", 2: "WARNING", 3: "INFO"}
    ALERT_TYPE_NAMES = {
        9:   "NodeStartFailure",
        10:  "NodeReady",
        11:  "NodeStateChange / NotInQuorum",
        22:  "ClusterManagerFailure",
        29:  "CapacityAlert",
        30:  "VolumeSpaceLow",
        36:  "NodeMarkedDown",
        37:  "VolumeCreated",
        38:  "VolumeCreationFailure",
        39:  "VolumeDeleted",
        40:  "VolumeDeleteFailure",
        44:  "VolumeUnmountFailure",
        47:  "SnapshotCreated",
        48:  "SnapshotCreationFailure",
        54:  "StorageFailure",
        58:  "LicenseExpiry",
        63:  "SnapshotDeleteFailure",
        65:  "VolumeSpaceRegained",
        83:  "StoragePoolFailure",
        86:  "StorageNodeTransition",
        104: "SIGTERMReceived",
        106: "KVDBBootstrapFailure",
        212: "VolumeDeviceExists",
        261: "DeviceReplicaRemoved",
    }

    if not path or not path.exists():
        return []

    alerts = []
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        sev_num  = int(obj.get("severity", 3))
        at       = int(obj.get("alert_type", -1))
        ts_block = obj.get("timestamp", {})
        if isinstance(ts_block, dict):
            ts_sec = ts_block.get("seconds", 0)
        else:
            ts_sec = int(ts_block) if ts_block else 0

        if ts_sec:
            try:
                ts_str = datetime.fromtimestamp(ts_sec, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            except (OSError, OverflowError):
                ts_str = str(ts_sec)
        else:
            ts_str = "unknown"

        cleared = bool(obj.get("cleared", False))
        alerts.append({
            "severity":     sev_num,
            "severity_str": SEVERITY_MAP.get(sev_num, str(sev_num)),
            "alert_type":   at,
            "alert_name":   ALERT_TYPE_NAMES.get(at, f"AlertType_{at}"),
            "message":      str(obj.get("message", "")),
            "timestamp":    ts_str,
            "resource_id":  str(obj.get("resource_id", "")),
            "count":        int(obj.get("count", 1)),
            "cleared":      cleared,
        })
    return alerts


def find_diag_root(extracted_path: Path) -> Path:
    """
    Find the actual diag content root inside an extracted auto-diag tarball.

    Auto-diag tarballs extract to:
        <node>/var/lib/osd/diagfiles/pwx_diag_<id>/misc/px-status.out
        <node>/var/lib/osd/diagfiles/pwx_diag_<id>/var/lib/osd/log/...

    After px_extract strips the hostname prefix, files land at:
        <extracted_root>/var/lib/osd/diagfiles/pwx_diag_<id>/misc/px-status.out

    This function resolves the pwx_diag_<id> subdirectory so that analyzers
    can look for misc/px-status.out relative to the returned path.

    Returns extracted_path unchanged if already at content root (misc/ exists).
    """
    # Already at content root (flat structure or previously resolved)
    if (extracted_path / "misc").is_dir():
        return extracted_path

    diagfiles_dir = extracted_path / "var" / "lib" / "osd" / "diagfiles"
    if diagfiles_dir.is_dir():
        candidates = sorted([
            d for d in diagfiles_dir.iterdir()
            if d.is_dir() and d.name.startswith("pwx_diag_")
        ])
        if candidates:
            chosen = candidates[-1]  # latest if multiple pwx_diag_* dirs
            log.info(f"Resolved diag root: {extracted_path.name} → {chosen.name}")
            return chosen

    log.warning(
        f"Could not find pwx_diag_* under {extracted_path}; using it as-is. "
        "Verify the tarball extracted correctly."
    )
    return extracted_path


# Timestamp patterns found in PX logs
_TS_PATTERNS = [
    re.compile(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)'),
    re.compile(r'(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})'),
    re.compile(r'([A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2})'),
]


def read_gz_or_plain(path: Path) -> str:
    """Read a .gz or plain text file, return contents as string."""
    if not path or not path.exists():
        return ""
    try:
        if path.suffix == ".gz":
            with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
                return f.read()
        else:
            return path.read_text(encoding="utf-8", errors="replace")
    except (OSError, gzip.BadGzipFile) as e:
        log.debug(f"Could not read {path}: {e}")
        return ""


def find_files(root: Path, glob_pattern: str) -> list[Path]:
    """
    Glob for files under root. Handles patterns with literal '<node>' placeholders
    by converting them to '*' wildcards.
    """
    safe_pattern = re.sub(r'<[^>]+>', '*', glob_pattern)
    return sorted(root.glob(safe_pattern))


def ts_from_line(line: str) -> str:
    """Extract the first timestamp found in a log line."""
    for pat in _TS_PATTERNS:
        m = pat.search(line)
        if m:
            return m.group(1)
    return "unknown"


def scan_file(path: Path, pattern: str) -> list[dict]:
    """
    Scan a file (plain or .gz) for lines matching regex pattern.

    Returns list of dicts: {line, timestamp, lineno}
    Returns [] if file not found or unreadable.
    """
    if not path or not path.exists():
        return []

    content = read_gz_or_plain(path)
    return scan_content(content, pattern)


def scan_content(content: str, pattern: str) -> list[dict]:
    """Same as scan_file but operates on an already-loaded string."""
    if not content:
        return []
    try:
        rx = re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        log.warning(f"Invalid regex '{pattern}': {e}")
        return []
    results = []
    for i, line in enumerate(content.splitlines(), 1):
        if rx.search(line):
            results.append({
                "line": line.strip(),
                "timestamp": ts_from_line(line),
                "lineno": i,
            })
    return results


def parse_alerts_show(path: Path) -> list[dict]:
    """
    Parse px-alerts-show.out into a list of alert dicts.

    The actual file format mixes non-JSON header lines with a JSON array:
        time="..." level=error msg="..."
        PX is not running on 127.0.0.1 host: ...
        [{
         "id": "0",
         "alert_type": "11",
         ...
        },{...}]
        Collected at: ...
        Error executing ...

    Tries four strategies (in order):
    0. Extract embedded JSON array by finding first '[' and last ']'
    1. Full JSON array parse (for clean files)
    2. Newline-delimited JSON objects (one per line)
    3. Multi-line regex: scan all lines for alert_type, then look ±3 lines for message

    Returns list of dicts with at least: alert_type, message, cleared, timestamp
    """
    if not path or not path.exists():
        return []

    content = read_gz_or_plain(path)
    if not content:
        return []

    # Strategy 0: extract the JSON array embedded in mixed content
    # Real file starts with error log lines, then a JSON array, then footer lines.
    start = content.find('[')
    end   = content.rfind(']')
    if start != -1 and end > start:
        try:
            data = json.loads(content[start:end + 1])
            if isinstance(data, list):
                result = [_normalize_alert(a) for a in data if isinstance(a, dict)]
                if result:
                    log.debug(f"parse_alerts_show: strategy 0 found {len(result)} alerts in {path.name}")
                    return result
        except json.JSONDecodeError:
            pass

    # Strategy 1: full JSON array parse
    try:
        data = json.loads(content)
        if isinstance(data, list):
            return [_normalize_alert(a) for a in data if isinstance(a, dict)]
    except json.JSONDecodeError:
        pass

    # Strategy 2: newline-delimited JSON objects
    alerts = []
    for line in content.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                alerts.append(_normalize_alert(obj))
        except json.JSONDecodeError:
            pass
    if alerts:
        return alerts

    # Strategy 3: multi-line regex fallback
    # Fields are on separate lines; scan all lines for alert_type then look nearby
    lines = content.splitlines()
    at_pat  = re.compile(r'"alert_type"\s*:\s*"?(\d+)"?')
    msg_pat = re.compile(r'"message"\s*:\s*"([^"]*)"')
    clr_pat = re.compile(r'"cleared"\s*:\s*(true|false)', re.IGNORECASE)
    ts_pat  = re.compile(r'"timestamp"\s*:\s*"([^"]*)"')
    cnt_pat = re.compile(r'"count"\s*:\s*"?(\d+)"?')

    alerts = []
    for i, line in enumerate(lines):
        at_m = at_pat.search(line)
        if not at_m:
            continue
        # Look in a ±8 line window for related fields
        window = "\n".join(lines[max(0, i - 2):i + 9])
        msg_m = msg_pat.search(window)
        clr_m = clr_pat.search(window)
        ts_m  = ts_pat.search(window)
        cnt_m = cnt_pat.search(window)
        alerts.append({
            "alert_type": int(at_m.group(1)),
            "message":    msg_m.group(1) if msg_m else "",
            "cleared":    clr_m.group(1).lower() == "true" if clr_m else False,
            "timestamp":  ts_m.group(1) if ts_m else ts_from_line(line),
            "count":      int(cnt_m.group(1)) if cnt_m else 1,
            "node_id":    "",
            "raw":        line.strip(),
        })
    return alerts


def _normalize_alert(a: dict) -> dict:
    """Normalize alert dict keys to consistent snake_case."""
    try:
        at = int(a.get("alert_type", a.get("alertType", -1)) or -1)
    except (ValueError, TypeError):
        at = -1
    return {
        "alert_type": at,
        "message": str(a.get("message", "")),
        "cleared": bool(a.get("cleared", False)),
        "timestamp": str(a.get("timestamp", a.get("ts", "unknown"))),
        "count": int(a.get("count", 1)),
        "node_id": str(a.get("resourceId", a.get("node_id", ""))),
        "raw": json.dumps(a),
    }
