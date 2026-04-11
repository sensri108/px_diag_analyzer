"""
px_extract.py — Extract downloaded diag tarballs.

Extracts to: ~/downloads/<cluster_uuid>/<node_hostname>/
Writes a manifest.json with extraction metadata after successful extraction.

Tarball structure inside:
    <hostname>/misc/px-status.out
    <hostname>/var/cores/...
    etc.

The hostname prefix is stripped so paths become relative to the extraction root:
    misc/px-status.out
    var/cores/...
"""
from __future__ import annotations

import json
import logging
import tarfile
from datetime import datetime, timezone
from pathlib import Path

from tqdm import tqdm

log = logging.getLogger(__name__)

LOCAL_BASE = Path.home() / "downloads"


def extract_all(
    tarball_paths: list[Path],
    cluster_uuid: str,
    force: bool = False,
) -> list[Path]:
    """
    Extract all tarballs to ~/downloads/<cluster_uuid>/<node>/

    Args:
        tarball_paths : List of .tar.gz Paths to extract
        cluster_uuid  : Cluster UUID (used for output directory hierarchy)
        force         : Re-extract even if already done (default: False)

    Returns:
        List of Paths to successfully extracted directories
    """
    extracted_dirs: list[Path] = []

    for tarball in tarball_paths:
        try:
            dest = _extract_one(tarball, cluster_uuid, force=force)
            if dest:
                extracted_dirs.append(dest)
        except Exception as e:
            log.error(f"Extraction failed for {tarball.name}: {e}", exc_info=True)

    return extracted_dirs


def _extract_one(tarball: Path, cluster_uuid: str, force: bool = False) -> Path | None:
    """
    Extract a single tarball. Returns the extraction directory Path, or None on skip.

    Naming convention: <node>-auto-diags-<YYYYMMDDHHMMSS>.tar.gz
    Node name is extracted from everything before '-auto-diags-'.
    """
    # Derive node name from filename
    stem = tarball.name
    if stem.endswith(".tar.gz"):
        stem = stem[:-7]

    parts = stem.split("-auto-diags-")
    if len(parts) == 2:
        node_name = parts[0]
        ts_suffix = parts[1]
    else:
        node_name = stem
        ts_suffix = ""

    dest_dir      = LOCAL_BASE / cluster_uuid / node_name
    manifest_path = dest_dir / "manifest.json"

    if dest_dir.exists() and manifest_path.exists() and not force:
        log.info(f"Already extracted: {dest_dir} — skipping (use --force-extract to re-extract)")
        return dest_dir

    dest_dir.mkdir(parents=True, exist_ok=True)

    log.info(f"Extracting {tarball.name} → {dest_dir}")

    with tarfile.open(tarball, "r:gz") as tf:
        members = tf.getmembers()

        with tqdm(total=len(members), desc=f"Extracting {node_name}", unit="files") as pbar:
            for member in members:
                # Normalize: strip leading hostname component from path
                member.name = _normalize_member_name(member.name)
                if not member.name:
                    pbar.update(1)
                    continue
                try:
                    tf.extract(member, path=dest_dir)
                except Exception as e:
                    log.debug(f"Skipping member {member.name}: {e}")
                pbar.update(1)

    # Write manifest
    manifest = {
        "tarball": str(tarball),
        "node": node_name,
        "ts_suffix": ts_suffix,
        "cluster_uuid": cluster_uuid,
        "extracted_at": datetime.now(timezone.utc).isoformat(),
        "dest_dir": str(dest_dir),
    }
    manifest_path.write_text(json.dumps(manifest, indent=2))
    log.info(f"Extracted to: {dest_dir}")
    return dest_dir


def _normalize_member_name(name: str) -> str:
    """
    Strip leading path components from tar member names.

    Examples:
        'pxpvip1331919.gsm1900.org/misc/px-status.out'  → 'misc/px-status.out'
        '/misc/px-status.out'                            → 'misc/px-status.out'
        'misc/px-status.out'                             → 'misc/px-status.out'
    """
    # Remove leading slashes
    name = name.lstrip("/")
    if not name:
        return ""

    # Strip first path component if it looks like a hostname (contains a dot)
    parts = name.split("/", 1)
    if len(parts) == 2 and "." in parts[0]:
        return parts[1]

    return name
