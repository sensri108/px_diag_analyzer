"""
px_analyzer/engine.py — Core orchestrator and Finding dataclass.

Imports all analyzer sub-modules, runs each against the extracted diag path,
merges findings, deduplicates, severity-ranks, and returns the final list.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

import yaml

log = logging.getLogger(__name__)

SEVERITY_RANK = {"CRITICAL": 0, "WARNING": 1, "INFO": 2}

PATTERNS_FILE = Path(__file__).parent.parent / "patterns" / "errors.yaml"


@dataclass
class Finding:
    id: str
    smart_signal: Optional[str]
    alert_code: Optional[int]
    alert_type: Optional[int]
    severity: str                     # CRITICAL / WARNING / INFO
    category: str
    pattern_matched: str
    log_excerpt: str
    source_file: str
    first_seen: str = "unknown"
    last_seen: str = "unknown"
    count: int = 1
    already_monitored: bool = False
    dark_to_smart_signals: bool = False
    dark_note: Optional[str] = None
    remediation_kb: Optional[str] = None
    remediation_steps: list = field(default_factory=list)
    correlated_with: list = field(default_factory=list)
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def load_patterns() -> list[dict]:
    """Load patterns/errors.yaml. Returns list of pattern dicts."""
    with open(PATTERNS_FILE, encoding="utf-8") as f:
        return yaml.safe_load(f) or []


def make_finding(
    pattern_def: dict,
    log_excerpt: str,
    source_file: str,
    first_seen: str = "unknown",
    last_seen: str = "unknown",
    count: int = 1,
    extra: dict | None = None,
) -> Finding:
    """
    Construct a Finding from a pattern definition dict (from errors.yaml)
    plus runtime scan results.
    """
    already_monitored = pattern_def.get("already_monitored", False)
    return Finding(
        id=pattern_def["id"],
        smart_signal=pattern_def.get("smart_signal"),
        alert_code=pattern_def.get("alert_code"),
        alert_type=pattern_def.get("alert_type"),
        severity=pattern_def.get("severity", "WARNING"),
        category=_infer_category(pattern_def),
        pattern_matched=pattern_def.get("pattern", ""),
        log_excerpt=log_excerpt,
        source_file=source_file,
        first_seen=first_seen,
        last_seen=last_seen,
        count=count,
        already_monitored=already_monitored,
        dark_to_smart_signals=not already_monitored,
        dark_note=pattern_def.get("dark_note"),
        remediation_kb=pattern_def.get("remediation_kb"),
        remediation_steps=pattern_def.get("remediation_steps", []),
        extra=extra or {},
    )


def _infer_category(p: dict) -> str:
    """Infer a category string from the pattern ID."""
    pid = p.get("id", "")
    sm = p.get("smart_signal", "") or ""
    if "volume" in sm or pid in ("SS-01", "SS-02", "SS-03", "SS-04", "SS-05",
                                  "SS-06", "SS-08", "SS-10", "SS-11"):
        return "volume"
    if "kvdb" in sm or pid in ("SS-12", "SS-13", "SS-14", "LOCAL-02"):
        return "kvdb"
    if "capacity" in sm or "pool" in sm or pid in ("SS-15", "SS-16", "SS-17",
                                                     "SS-23", "LOCAL-04"):
        return "capacity"
    if "node" in sm or pid in ("SS-18", "SS-21", "SS-25", "SS-26", "SS-27"):
        return "node"
    if "license" in sm or pid in ("SS-19", "SS-INVALID-LICENSE"):
        return "license"
    if "security" in sm or pid == "SS-09":
        return "security"
    if "nfs" in sm or "stale" in sm or pid in ("SS-07", "SS-22", "LOCAL-03"):
        return "infrastructure"
    if pid == "LOCAL-01":
        return "storage"
    if pid == "SS-24":
        return "init"
    return "other"


def _correlate(findings: list[Finding]) -> None:
    """
    Post-pass: link related findings.
    If LOCAL-01 (STATUS_STORAGE_DOWN) and SS-10 (snapshot I/O errors) both present,
    mark SS-10 as correlated with LOCAL-01 (downstream symptom, not root cause).
    """
    by_id = {f.id: f for f in findings}
    if "LOCAL-01" in by_id and "SS-10" in by_id:
        by_id["SS-10"].correlated_with.append("LOCAL-01")
        by_id["SS-10"].extra["note"] = (
            "Snapshot I/O errors are likely downstream of STATUS_STORAGE_DOWN"
        )


def run_analysis(extracted_path: Path, cluster_uuid: str) -> list[Finding]:
    """
    Run all analyzer modules against the extracted diag directory.
    Returns a severity-sorted, correlated list of Finding objects.
    """
    patterns = load_patterns()
    pattern_map = {p["id"]: p for p in patterns}

    # Import all analyzer modules
    from px_analyzer import (
        volume, kvdb, storage, node, capacity,
        license as lic, network, security, infrastructure, predictive,
    )

    analyzers = [
        volume.analyze,
        kvdb.analyze,
        storage.analyze,
        node.analyze,
        capacity.analyze,
        lic.analyze,
        network.analyze,
        security.analyze,
        infrastructure.analyze,
    ]

    all_findings: list[Finding] = []
    for fn in analyzers:
        try:
            results = fn(extracted_path, pattern_map)
            all_findings.extend(results)
        except Exception as e:
            log.warning(f"Analyzer {fn.__module__} failed: {e}", exc_info=True)

    # Predictive pass (depends on all prior findings)
    try:
        pf = predictive.analyze(extracted_path, all_findings, patterns)
        all_findings.extend(pf)
    except Exception as e:
        log.warning(f"Predictive analyzer failed: {e}", exc_info=True)

    # Correlate
    _correlate(all_findings)

    # Sort: CRITICAL first, then by count desc
    all_findings.sort(key=lambda f: (SEVERITY_RANK.get(f.severity, 99), -f.count))

    log.info(f"Analysis complete: {len(all_findings)} findings")
    return all_findings
