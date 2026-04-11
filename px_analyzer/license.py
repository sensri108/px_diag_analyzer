"""
px_analyzer/license.py — Smart Signals SS-19 (expiry) and SS-INVALID-LICENSE (10231).

Sources:
    misc/px-status.out
    var/cores/px_status/<node>-px-jrnl-32min-<ts>.log.gz

Key logic:
    - SS-19: fires only if expiry < 7 days
    - SS-INVALID-LICENSE: fires if INVALID LICENSE found, OR if Metering: Disabled AND
      billing failures in journal (combined signal)
    - If "Metering: Disabled or Unhealthy" with NO journal billing failures
      → log as WARNING only (likely telemetry misconfiguration, not license risk)
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

from px_analyzer.engine import Finding, make_finding
from px_analyzer._base import scan_file, find_files, read_gz_or_plain

log = logging.getLogger(__name__)

LICENSE_PATTERNS = {
    "license_expiry_7d":  r"expires in (\d+) days",
    "license_invalid":    r"INVALID LICENSE",
    "metering_disabled":  r"Metering: Disabled or Unhealthy",
    "metering_failure":   r"meteringUsageError|callhome.*fail",
    "billing_grace":      r"grace period",
}


def analyze(extracted_path: Path, pattern_map: dict) -> list[Finding]:
    findings: list[Finding] = []

    px_status  = extracted_path / "misc" / "px-status.out"
    jrnl_files = find_files(extracted_path, "var/cores/px_status/*-px-jrnl-32min-*.log.gz")

    content = read_gz_or_plain(px_status)

    # SS-19: license expiry < 7 days
    if "SS-19" in pattern_map:
        m = re.search(LICENSE_PATTERNS["license_expiry_7d"], content, re.IGNORECASE)
        if m:
            days_remaining = int(m.group(1))
            if days_remaining < 7:
                findings.append(make_finding(
                    pattern_map["SS-19"],
                    log_excerpt=m.group(0),
                    source_file="misc/px-status.out",
                    count=1,
                    extra={"days_remaining": days_remaining},
                ))
            else:
                log.info(f"License healthy: expires in {days_remaining} days — no action needed.")

    # SS-INVALID-LICENSE: invalid license or metering failure
    if "SS-INVALID-LICENSE" in pattern_map:
        metering_match = re.search(LICENSE_PATTERNS["metering_disabled"], content, re.IGNORECASE)
        invalid_match  = re.search(LICENSE_PATTERNS["license_invalid"],   content, re.IGNORECASE)

        billing_failures = []
        for jf in jrnl_files:
            billing_failures.extend(scan_file(jf, LICENSE_PATTERNS["metering_failure"]))

        if invalid_match or (metering_match and billing_failures):
            trigger = invalid_match or metering_match
            findings.append(make_finding(
                pattern_map["SS-INVALID-LICENSE"],
                log_excerpt=trigger.group(0) if trigger else "",
                source_file="misc/px-status.out",
                count=len(billing_failures) + (1 if invalid_match else 0),
                extra={
                    "metering_disabled": bool(metering_match),
                    "billing_failure_count": len(billing_failures),
                    "invalid_license": bool(invalid_match),
                },
            ))
        elif metering_match:
            log.warning(
                "Metering: Disabled or Unhealthy detected in px-status.out, "
                "but no billing failures found in journal. "
                "Likely telemetry misconfiguration — monitor but lower risk."
            )

    return findings
