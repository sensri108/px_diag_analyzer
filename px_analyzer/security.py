"""
px_analyzer/security.py — SS-09 (in-tree volumes + K8s version security check).

Sources:
    misc/px-status.out
    misc/px-volumes.out
    misc/kubelet.out
    etc/pwx/config.json

Check: k8s_version < 1.32.1 (except 1.31.6) AND px_security_enabled AND in-tree volumes present.
Data loss risk during upgrades if this condition is true.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

from px_analyzer.engine import Finding, make_finding
from px_analyzer._base import read_gz_or_plain, scan_file

log = logging.getLogger(__name__)

# Regex for vulnerable K8s versions: 1.20-1.31 (but 1.31.6 is safe, 1.32+ is safe)
_VULNERABLE_K8S = re.compile(r'v1\.(2[0-9]|3[01])\.\d+')
_SAFE_EXCEPTIONS = re.compile(r'v1\.31\.6|v1\.3[2-9]\.|v1\.[4-9]\d+\.')


def analyze(extracted_path: Path, pattern_map: dict) -> list[Finding]:
    findings: list[Finding] = []

    if "SS-09" not in pattern_map:
        return findings

    kubelet_out = extracted_path / "misc" / "kubelet.out"
    px_volumes  = extracted_path / "misc" / "px-volumes.out"
    px_status   = extracted_path / "misc" / "px-status.out"

    # Detect K8s version from kubelet.out or px-status.out
    k8s_version = ""
    for src in [kubelet_out, px_status]:
        content = read_gz_or_plain(src)
        m = re.search(r'(v\d+\.\d+\.\d+)', content)
        if m:
            k8s_version = m.group(1)
            break

    # Check PX security enabled
    status_content = read_gz_or_plain(px_status)
    px_security_enabled = bool(
        re.search(r'Security\s*:\s*Enabled', status_content, re.IGNORECASE)
    )

    # Check in-tree volumes (pxd.portworx.com label indicates CSI migration pending)
    in_tree = bool(scan_file(px_volumes, r'pxd\.portworx\.com'))

    # Evaluate vulnerability
    is_vulnerable = (
        k8s_version
        and _VULNERABLE_K8S.search(k8s_version)
        and not _SAFE_EXCEPTIONS.search(k8s_version)
        and px_security_enabled
        and in_tree
    )

    if is_vulnerable:
        findings.append(make_finding(
            pattern_map["SS-09"],
            log_excerpt=(
                f"K8s {k8s_version}, PX security enabled, in-tree volumes detected. "
                "Data loss risk during K8s upgrade — migrate to CSI first."
            ),
            source_file="misc/px-volumes.out",
            count=1,
            extra={
                "k8s_version": k8s_version,
                "px_security_enabled": px_security_enabled,
                "in_tree_volumes": in_tree,
            },
        ))
    elif k8s_version:
        log.info(
            f"SS-09 check: K8s {k8s_version}, security={px_security_enabled}, "
            f"in-tree={in_tree} — not vulnerable."
        )

    return findings
