"""
px_analyzer/kvdb.py — Smart Signals SS-12, SS-13, SS-14.

Sources:
    misc/px-kvdb.out
    misc/px-status.out
    var/cores/px_status/<node>-px_etcd_watch-<ts>.log.gz
"""
from __future__ import annotations

import logging
from pathlib import Path

from px_analyzer.engine import Finding, make_finding
from px_analyzer._base import scan_file, find_files

log = logging.getLogger(__name__)

KVDB_PATTERNS = {
    "kvdb_out_of_space":    r"mvcc: database space exceeded|ResourceExhausted",
    "kvdb_transport_close": r"grpc.*transport is closing",
    "kvdb_no_endpoint":     r"Failed connect to kvdb instance \(\[\]\)",
    "kvdb_peer_fail":       r"failed to connect to kvdb peer",
    "kvdb_node_count":      r"kvdb.*node.*count|reduced.*kvdb",
}


def analyze(extracted_path: Path, pattern_map: dict) -> list[Finding]:
    findings: list[Finding] = []

    kvdb_out   = extracted_path / "misc" / "px-kvdb.out"
    px_status  = extracted_path / "misc" / "px-status.out"
    etcd_files = find_files(extracted_path, "var/cores/px_status/*-px_etcd_watch-*.log.gz")

    # SS-12: kvdb out of space
    if "SS-12" in pattern_map:
        matches = scan_file(kvdb_out, KVDB_PATTERNS["kvdb_out_of_space"])
        for ef in etcd_files:
            matches.extend(scan_file(ef, KVDB_PATTERNS["kvdb_out_of_space"]))
        if matches:
            ts_list = [m["timestamp"] for m in matches if m["timestamp"] != "unknown"]
            findings.append(make_finding(
                pattern_map["SS-12"],
                log_excerpt=matches[0]["line"],
                source_file="misc/px-kvdb.out",
                first_seen=min(ts_list) if ts_list else "unknown",
                last_seen=max(ts_list) if ts_list else "unknown",
                count=len(matches),
            ))

    # SS-13: kvdb reduced node count
    if "SS-13" in pattern_map:
        matches = scan_file(px_status, KVDB_PATTERNS["kvdb_node_count"])
        if not matches:
            matches = scan_file(kvdb_out, KVDB_PATTERNS["kvdb_node_count"])
        if matches:
            findings.append(make_finding(
                pattern_map["SS-13"],
                log_excerpt=matches[0]["line"],
                source_file="misc/px-status.out",
                count=len(matches),
            ))

    # SS-14: kvdb gRPC transport errors from etcd_watch logs
    # NOTE: "Failed connect to kvdb instance ([])" in px-kvdb.out is EXPECTED for
    # internal kvdb mode (embedded etcd) — log as INFO, do NOT create a finding.
    internal_matches = scan_file(kvdb_out, KVDB_PATTERNS["kvdb_no_endpoint"])
    if internal_matches:
        log.info(
            f"Internal kvdb mode: {len(internal_matches)} 'Failed connect to kvdb instance ([])' "
            "entries in px-kvdb.out. This is expected for embedded etcd — not an error."
        )

    grpc_matches = []
    for ef in etcd_files:
        grpc_matches.extend(scan_file(ef, KVDB_PATTERNS["kvdb_transport_close"]))

    if grpc_matches and "SS-14" in pattern_map:
        ts_list = [m["timestamp"] for m in grpc_matches if m["timestamp"] != "unknown"]
        findings.append(make_finding(
            pattern_map["SS-14"],
            log_excerpt=grpc_matches[0]["line"],
            source_file="var/cores/px_status/*-px_etcd_watch-*.log.gz",
            first_seen=min(ts_list) if ts_list else "unknown",
            last_seen=max(ts_list) if ts_list else "unknown",
            count=len(grpc_matches),
        ))

    return findings
