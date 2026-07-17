"""
px_analyzer/troubleshooting.py — doc-derived troubleshooting signals (TS-*).

Scans diag logs for the "common errors" and troubleshooting tips documented at
https://docs.portworx.com/portworx-enterprise/operations/troubleshooting .

Unlike the hand-written analyzers, this one is fully data-driven: it walks every
TS-* entry merged into pattern_map (from patterns/troubleshooting.yaml), globs the
entry's `source_files` under both the diag root and the node root, and emits a
Finding for any regex match. Each Finding carries the documented symptom, cause,
diagnostic commands, resolution steps, and doc URL (populated by make_finding()).
"""
from __future__ import annotations

import logging
from pathlib import Path

from px_analyzer.engine import Finding, make_finding
from px_analyzer._base import find_files, find_node_root, scan_file

log = logging.getLogger(__name__)


def analyze(extracted_path: Path, pattern_map: dict) -> list[Finding]:
    findings: list[Finding] = []

    # Doc-derived patterns may live under the diag root (misc/, var/lib/osd/log)
    # or the node root (journal/dmesg). Search both, de-duplicating paths.
    roots = [extracted_path]
    node_root = find_node_root(extracted_path)
    if node_root != extracted_path:
        roots.append(node_root)

    ts_ids = sorted(
        pid for pid, p in pattern_map.items()
        if isinstance(p, dict) and str(pid).startswith("TS-") and p.get("pattern")
    )

    for tid in ts_ids:
        pdef = pattern_map[tid]
        source_globs = pdef.get("source_files", [])
        matches: list[dict] = []
        matched_source = ""
        seen_files: set[Path] = set()

        for glob in source_globs:
            for root in roots:
                for fpath in find_files(root, glob):
                    if fpath in seen_files:
                        continue
                    seen_files.add(fpath)
                    hits = scan_file(fpath, pdef["pattern"])
                    if hits:
                        matches.extend(hits)
                        if not matched_source:
                            matched_source = glob

        if not matches:
            continue

        ts_list = [m["timestamp"] for m in matches if m["timestamp"] != "unknown"]
        findings.append(make_finding(
            pdef,
            log_excerpt=matches[0]["line"][:300],
            source_file=matched_source or (source_globs[0] if source_globs else "unknown"),
            first_seen=min(ts_list) if ts_list else "unknown",
            last_seen=max(ts_list) if ts_list else "unknown",
            count=len(matches),
        ))
        log.debug(f"{tid}: {len(matches)} match(es) in {matched_source}")

    return findings
