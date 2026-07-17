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
    2. Walk ALL folders in the window (up to 7 days) newest-first, collecting the
       latest tarball per (node, kind). Both diag kinds must be pulled, and a
       node's `-auto-diags-` and `-diags-` bundles can live in different date
       folders — so we do not stop at the first folder with data.
    3. If --date is specified, use only that folder (no fallback)
    4. If node_filter specified, only match files containing the hostname
    5. Because folders are scanned newest-first, the first occurrence of a
       (node, kind) is that kind's latest tar; older duplicates are skipped.
    6. Download each selected bundle to ~/downloads/<UUID>/<its YYYY_MM_DD>/<filename>
    7. Return list of local Paths to downloaded files
"""
from __future__ import annotations

import logging
import re
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

        # Walk date folders newest-first, collecting the LATEST tarball for each
        # (node, kind). Scanning newest-first means the first time a (node, kind)
        # is seen it is that kind's latest bundle, so we record it and skip older
        # duplicates. We deliberately keep scanning past the first folder that has
        # data: a node's `-auto-diags-` and `-diags-` bundles can live in
        # different date folders, and BOTH kinds' latest tars must be pulled.
        #   selected[(node, kind)] = {"file", "remote_dir", "date_folder", "ts"}
        selected: dict[tuple[str, str], dict] = {}

        for candidate in date_folders_to_try:
            log.info(f"Checking date folder: {candidate}")
            remote_dir, tarballs = _find_tarballs_in_folder(
                sftp, cluster_uuid, candidate, node_filter
            )
            if not tarballs:
                log.info(f"  → No diag tarballs in {candidate}")
                continue

            new_here = 0
            for t in tarballs:
                m = _match_diag_tarball(t)
                if not m:
                    continue
                key = (m.group("node"), m.group("kind"))
                if key in selected:
                    continue  # already recorded this kind's latest (newest-first)
                selected[key] = {
                    "file": t,
                    "remote_dir": remote_dir,
                    "date_folder": candidate,
                    "ts": m.group("ts"),
                }
                new_here += 1
            log.info(
                f"  {candidate}: recorded {new_here} new (node, kind) bundle(s); "
                f"kinds so far: {sorted({k for _, k in selected})}"
            )

        if not selected:
            checked = ", ".join(date_folders_to_try)
            raise FileNotFoundError(
                f"No diag tarballs (-auto-diags-/-diags-) found in any of the "
                f"{len(date_folders_to_try)} most-recent date folder(s): [{checked}]"
                + (f" matching node '{node_filter}'" if node_filter else "")
                + f"\nFuse2 base: {FUSE_BASE}/{cluster_uuid}/"
            )

        kinds_found = sorted({k for _, k in selected})
        n_folders = len({e["date_folder"] for e in selected.values()})
        log.info(
            f"Downloading {len(selected)} tarball(s) across {n_folders} date "
            f"folder(s); kinds: {kinds_found}"
        )
        if len(kinds_found) < 2:
            log.warning(
                f"Only one diag kind present in the searched window ({kinds_found}); "
                "the other kind was not found."
            )

        # Download each selected bundle from its own source folder.
        for entry in sorted(selected.values(), key=lambda e: (e["date_folder"], e["file"])):
            filename    = entry["file"]
            remote_dir  = entry["remote_dir"]
            local_dir   = LOCAL_BASE / cluster_uuid / entry["date_folder"]
            local_dir.mkdir(parents=True, exist_ok=True)
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
