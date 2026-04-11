"""
px_analyzer/_base.py — Shared scan utilities used by all analyzer modules.

Functions:
    scan_file(path, pattern)   -> list of {line, timestamp, lineno}
    find_files(root, glob)     -> list of matching Paths
    read_gz_or_plain(path)     -> str
    parse_alerts_show(path)    -> list of alert dicts
    ts_from_line(line)         -> ISO timestamp string or "unknown"
"""
from __future__ import annotations

import gzip
import json
import logging
import re
from pathlib import Path

log = logging.getLogger(__name__)

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

    Tries three strategies:
    1. Full JSON array parse
    2. Newline-delimited JSON objects (one per line)
    3. Regex fallback: extract alert_type, message, cleared fields

    Returns list of dicts with at least: alert_type, message, cleared, timestamp
    """
    if not path or not path.exists():
        return []

    content = read_gz_or_plain(path)
    if not content:
        return []

    # Strategy 1: full JSON array
    try:
        data = json.loads(content)
        if isinstance(data, list):
            return [_normalize_alert(a) for a in data if isinstance(a, dict)]
    except json.JSONDecodeError:
        pass

    # Strategy 2: newline-delimited JSON
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

    # Strategy 3: regex fallback
    alerts = []
    at_pat  = re.compile(r'"alert_type"\s*:\s*"?(\d+)"?')
    msg_pat = re.compile(r'"message"\s*:\s*"([^"]*)"')
    clr_pat = re.compile(r'"cleared"\s*:\s*(true|false)', re.IGNORECASE)

    for line in content.splitlines():
        at_m = at_pat.search(line)
        if not at_m:
            continue
        msg_m = msg_pat.search(line)
        clr_m = clr_pat.search(line)
        alerts.append({
            "alert_type": int(at_m.group(1)),
            "message": msg_m.group(1) if msg_m else "",
            "cleared": clr_m.group(1).lower() == "true" if clr_m else False,
            "timestamp": ts_from_line(line),
            "count": 1,
            "node_id": "",
            "raw": line.strip(),
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
