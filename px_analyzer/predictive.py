"""
px_analyzer/predictive.py — Sliding-window trend and frequency analysis.

Runs AFTER all other analyzers. Takes the merged findings list and emits
FORECAST-* findings if trend thresholds are met (defined in patterns/forecasts.yaml).

Forecast rules:
    FORECAST-CAPACITY      : volume at critical capacity → flag for proactive expansion
    FORECAST-KVDB-ERRORS   : kvdb error count >= threshold → rate escalation warning
    FORECAST-NODE-STATS-GAP: multiple node stats gaps → periodic PX degradation
    FORECAST-STORAGE-DOWN  : STATUS_STORAGE_DOWN >= cluster_threshold → active incident
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import yaml

from px_analyzer.engine import Finding

log = logging.getLogger(__name__)

FORECASTS_FILE = Path(__file__).parent.parent / "patterns" / "forecasts.yaml"


def analyze(
    extracted_path: Path,
    findings: list[Finding],
    patterns: list[dict],
) -> list[Finding]:
    """
    Generate predictive findings based on existing findings.

    Args:
        extracted_path: Root of extracted tarball (available for raw log access if needed)
        findings      : Already-analyzed findings from all other modules
        patterns      : Pattern defs from errors.yaml (for context)

    Returns:
        List of new FORECAST-* Finding objects (empty if no thresholds triggered)
    """
    try:
        with open(FORECASTS_FILE, encoding="utf-8") as f:
            rules = yaml.safe_load(f) or []
    except (OSError, yaml.YAMLError) as e:
        log.warning(f"Could not load forecasts.yaml: {e}")
        return []

    by_id = {f.id: f for f in findings}
    result: list[Finding] = []

    for rule in rules:
        trigger = by_id.get(rule.get("trigger_signal", ""))
        if not trigger:
            continue

        rid = rule.get("id", "")

        if rid == "FORECAST-CAPACITY":
            pf = _forecast_capacity(rule, trigger)
        elif rid == "FORECAST-KVDB-ERRORS":
            pf = _forecast_kvdb_errors(rule, trigger)
        elif rid == "FORECAST-NODE-STATS-GAP":
            pf = _forecast_stats_gaps(rule, trigger)
        elif rid == "FORECAST-STORAGE-DOWN":
            pf = _forecast_storage_down(rule, trigger)
        else:
            pf = None

        if pf:
            result.append(pf)

    return result


def _make_forecast(
    rule: dict,
    excerpt: str,
    count: int,
    source_id: str,
) -> Finding:
    """Construct a FORECAST Finding."""
    return Finding(
        id=rule["id"],
        smart_signal=None,
        alert_code=None,
        alert_type=None,
        severity=rule.get("severity", "WARNING"),
        category="predictive",
        pattern_matched=f"forecast:{rule.get('trigger_signal', '')}",
        log_excerpt=excerpt,
        source_file="(predictive analysis)",
        count=count,
        already_monitored=False,
        dark_to_smart_signals=True,
        dark_note="Predictive/trend finding — not a Smart Signal",
        remediation_steps=[rule.get("remediation", "Review trend and take preventive action.")],
        extra={"source_finding": source_id},
    )


def _forecast_capacity(rule: dict, trigger: Finding) -> Finding:
    excerpt = (
        f"Volume(s) at critical capacity ({trigger.count} alert(s)). "
        "Monitor growth rate — if consistently full, expand volumes proactively."
    )
    return _make_forecast(rule, excerpt, trigger.count, trigger.id)


def _forecast_kvdb_errors(rule: dict, trigger: Finding) -> Optional[Finding]:
    threshold = rule.get("count_threshold", 3)
    if trigger.count < threshold:
        return None
    excerpt = f"KVDB gRPC errors at elevated rate: {trigger.count} occurrences. Monitor for escalation."
    return _make_forecast(rule, excerpt, trigger.count, trigger.id)


def _forecast_stats_gaps(rule: dict, trigger: Finding) -> Optional[Finding]:
    threshold = rule.get("gap_count_threshold", 3)
    if trigger.count < threshold:
        return None
    excerpt = f"{trigger.count} node stats gaps detected. PX process may be periodically degraded."
    return _make_forecast(rule, excerpt, trigger.count, trigger.id)


def _forecast_storage_down(rule: dict, trigger: Finding) -> Optional[Finding]:
    threshold = rule.get("cluster_threshold", 5)
    if trigger.count < threshold:
        return None
    excerpt = (
        f"STATUS_STORAGE_DOWN x{trigger.count} exceeds clustering threshold ({threshold}). "
        "This is likely an active incident, not a historical artifact — escalate immediately."
    )
    return _make_forecast(rule, excerpt, trigger.count, trigger.id)
