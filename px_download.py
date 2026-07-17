"""
px_download.py — SFTP walk of /fuse2/px_aid/<UUID>/<date>/ to download diag tarballs.

Fuse2 path format (confirmed):
    /fuse2/px_aid/<CLUSTER_UUID>/<YYYY_MM_DD>/<NODE>-auto-diags-<YYYYMMDDHHMMSS>.tar.gz
    /fuse2/px_aid/<CLUSTER_UUID>/<YYYY_MM_DD>/<NODE>-diags-<YYYYMMDDHHMMSS>.tar.gz
    /fuse2/px_aid/<CLUSTER_UUID>/<YYYY_MM_DD>/<NODE>-px-kvdb-dump-diags-<ts>.log.gz

    Examples:
    .../2026_04_10/pxpvip1331919.gsm1900.org-auto-diags-20260410052348.tar.gz
    .../2026_07_16/ttpvip1340205.gsm1900.org-diags-20260716175809.tar.gz

    Two diag-bundle kinds are pulled:
      * auto-diags — scheduled bundles Portworx generates automatically
      * diags      — on-demand / manual bundles (e.g. `pxctl service diags`),
                     the same ones written to /var/cores/ on the node

    Note: date folders use underscores (2026_04_10), NOT dashes.

Strategy:
    1. List all date folders under /fuse2/px_aid/<UUID>/, sort descending (newest first)
    2. Walk folders newest-first; skip any that contain no diag tarballs
       (bundles are not always generated every day — fall back up to 7 days)
    3. If --date is specified, use only that folder (no fallback)
    4. If node_filter specified, only match files containing the hostname
    5. Per (node, kind), keep only the latest tarball (sorted by timestamp suffix)
       so a node's manual `-diags-` bundle is kept alongside its `-auto-diags-` one
    6. Download to ~/downloads/<UUID>/<YYYY_MM_DD>/<filename>
    7. Return list of local Paths to downloaded files
"""
from __future__ import annotations

import logging
import re
from collections import defaultdict
from pathlib import Path

import paramiko
from tqdm import tqdm

log = logging.getLogger(__name__)

FUSE_BASE = "/fuse2/px_aid"
LOCAL_BASE = Path.home() / "downloads"

_DATE_FOLDER_PAT = re.compile(r'^\d{4}_\d{2}_\d{2}$')

# Matches both diag-bundle kinds:
#   <node>-auto-diags-<YYYYMMDDHHMMSS>.tar.gz   (scheduled/automatic)
#   <node>-diags-<YYYYMMDDHHMMSS>.tar.gz        (on-demand/manual, from /var/cores)
# The <node> group is non-greedy so "auto" stays with the kind, not the hostname.
# The .tar.gz anchor excludes the -px-kvdb-dump-diags-<ts>.log.gz sidecar files.
_DIAG_TARBALL_PAT = re.compile(
    r'^(?P<node>.+?)-(?P<kind>auto-diags|diags)-(?P<ts>\d{14})\.tar\.gz$'
)


def _match_diag_tarball(name: str):
    """Return the regex match for a diag tarball filename, or None."""
    return _DIAG_TARBALL_PAT.match(name)


def _sftp_list(sftp: paramiko.SFTPClient, remote_path: str) -> list[str]:
    """List directory entries. Returns [] on error (warns with the reason)."""
    try:
        entries = sftp.listdir(remote_path)
        log.debug(f"Listed {remote_path}: {len(entries)} entries")
        return entries
    except IOError as e:
        log.warning(f"SFTP listdir failed for {remote_path}: {e}")
        return []
    except Exception as e:
        log.warning(f"Unexpected error listing {remote_path}: {type(e).__name__}: {e}")
        return []


def _get_date_folders_sorted(sftp: paramiko.SFTPClient, uuid: str) -> list[str]:
    """
    Return all date folder names (YYYY_MM_DD) under /fuse2/px_aid/<UUID>/,
    sorted descending (most recent first).
    """
    base = f"{FUSE_BASE}/{uuid}"
    log.info(f"Scanning for date folders under: {base}")
    entries = _sftp_list(sftp, base)
    if not entries:
        log.warning(
            f"No entries found under {base}. "
            "Check that the cluster UUID is correct and you have access to Fuse2."
        )
        return []
    date_folders = sorted(
        [e for e in entries if _DATE_FOLDER_PAT.match(e)],
        reverse=True,
    )
    non_date = [e for e in entries if not _DATE_FOLDER_PAT.match(e)]
    log.info(
        f"Found {len(date_folders)} date folder(s): {date_folders}"
        + (f" (non-date entries ignored: {non_date})" if non_date else "")
    )
    return date_folders


def _find_tarballs_in_folder(
    sftp: paramiko.SFTPClient,
    cluster_uuid: str,
    date_folder: str,
    node_filter: str | None,
) -> tuple[str, list[str]]:
    """
    List diag tarballs (both -auto-diags- and -diags-) inside a single date folder.

    Returns (remote_dir, tarballs) where tarballs is the filtered list.
    Returns (remote_dir, []) if the folder is empty or has no matching tarballs.
    """
    remote_dir = f"{FUSE_BASE}/{cluster_uuid}/{date_folder}"
    entries = _sftp_list(sftp, remote_dir)
    if not entries:
        log.warning(f"  {date_folder}: folder is empty or inaccessible")
        return remote_dir, []

    log.debug(f"  {date_folder}: {len(entries)} entries — {sorted(entries)}")

    tarballs = sorted([e for e in entries if _match_diag_tarball(e)])

    if not tarballs:
        log.warning(
            f"  {date_folder}: no diag tarballs (-auto-diags-/-diags-*.tar.gz) found "
            f"(other files present: {sorted(entries)})"
        )
        return remote_dir, []

    if node_filter:
        matched = [t for t in tarballs if node_filter in t]
        if not matched:
            log.warning(
                f"  {date_folder}: {len(tarballs)} tarball(s) found but none match "
                f"node filter '{node_filter}' — {tarballs}"
            )
            return remote_dir, []
        tarballs = matched

    log.info(
        f"  {date_folder}: found {len(tarballs)} matching tarball(s) — {tarballs}"
    )
    return remote_dir, tarballs


def download_diags(
    ssh_client: paramiko.SSHClient,
    cluster_uuid: str,
    node_filter: str | None = None,
    date_override: str | None = None,
    max_days_back: int = 7,
) -> list[Path]:
    """
    Walk Fuse2 and download diagnostic tarballs for the given cluster UUID.

    If the most recent date folder has no auto-diag files, automatically falls
    back to previous days (up to max_days_back days total).

    Args:
        ssh_client   : Open paramiko SSHClient (from px_auth.auth_flow)
        cluster_uuid : Cluster UUID string
        node_filter  : Optional hostname to limit download to one node
        date_override: Optional YYYY_MM_DD date folder to use (no fallback)
        max_days_back: How many date folders to check before giving up (default 7)

    Returns:
        List of local file Paths to downloaded .tar.gz files

    Raises:
        FileNotFoundError if no diag files are found in any checked folder
    """
    sftp = ssh_client.open_sftp()
    downloaded: list[Path] = []

    try:
        # Build ordered list of date folders to try
        if date_override:
            # Explicit date requested — try only that folder, no fallback
            log.info(f"Using explicit date override: {date_override}")
            date_folders_to_try = [date_override]
        else:
            date_folders_to_try = _get_date_folders_sorted(sftp, cluster_uuid)
            if not date_folders_to_try:
                raise FileNotFoundError(
                    f"No date folders found under {FUSE_BASE}/{cluster_uuid}/. "
                    "Check cluster UUID and Fuse2 access."
                )
            # Limit search to max_days_back most-recent folders
            date_folders_to_try = date_folders_to_try[:max_days_back]
            log.info(
                f"Will search up to {len(date_folders_to_try)} date folder(s) "
                f"for diag tarballs: {date_folders_to_try}"
            )

        # Walk date folders newest-first until tarballs are found
        date_folder: str | None = None
        remote_dir: str = ""
        tarballs: list[str] = []

        for candidate in date_folders_to_try:
            log.info(f"Checking date folder: {candidate}")
            remote_dir, tarballs = _find_tarballs_in_folder(
                sftp, cluster_uuid, candidate, node_filter
            )
            if tarballs:
                date_folder = candidate
                log.info(
                    f"✓ Using date folder: {date_folder} "
                    f"({len(tarballs)} tarball(s) found)"
                )
                break
            log.warning(
                f"  → No diag tarballs in {candidate}, "
                "falling back to previous day..."
            )

        if not tarballs or not date_folder:
            checked = ", ".join(date_folders_to_try)
            raise FileNotFoundError(
                f"No diag tarballs (-auto-diags-/-diags-) found in any of the "
                f"{len(date_folders_to_try)} most-recent date folder(s): [{checked}]"
                + (f" matching node '{node_filter}'" if node_filter else "")
                + f"\nFuse2 base: {FUSE_BASE}/{cluster_uuid}/"
            )

        # Group by (node hostname, kind), keep the latest tarball per group so a
        # node's manual `-diags-` bundle is retained alongside its `-auto-diags-`
        # one. The timestamp suffix sorts lexicographically == chronologically.
        grouped: dict[tuple[str, str], list[tuple[str, str]]] = defaultdict(list)
        for t in tarballs:
            m = _match_diag_tarball(t)
            if not m:
                continue
            key = (m.group("node"), m.group("kind"))
            grouped[key].append((m.group("ts"), t))

        selected: list[str] = [
            max(items)[1] for items in grouped.values()
        ]
        selected.sort()
        log.info(
            f"Downloading {len(selected)} tarball(s) from {remote_dir} "
            f"across {len(grouped)} (node, kind) group(s)"
        )

        # Local destination
        local_dir = LOCAL_BASE / cluster_uuid / date_folder
        local_dir.mkdir(parents=True, exist_ok=True)

        for filename in selected:
            remote_path = f"{remote_dir}/{filename}"
            local_path  = local_dir / filename

            if local_path.exists():
                log.info(f"Already downloaded: {local_path.name} — skipping")
                downloaded.append(local_path)
                continue

            try:
                stat = sftp.stat(remote_path)
                file_size = stat.st_size or 0
            except Exception:
                file_size = 0

            log.info(f"Downloading: {filename} ({file_size / (1024*1024):.1f} MB)")
            with tqdm(total=file_size, unit="B", unit_scale=True, desc=filename) as pbar:
                def _progress(transferred: int, total: int, _pbar: tqdm = pbar) -> None:
                    _pbar.update(transferred - _pbar.n)

                sftp.get(remote_path, str(local_path), callback=_progress)

            downloaded.append(local_path)
            log.info(f"Saved: {local_path}")

    finally:
        sftp.close()

    return downloaded
