"""
px_download.py — SFTP walk of /fuse2/px_aid/<UUID>/<date>/ to download diag tarballs.

Fuse2 path format (confirmed):
    /fuse2/px_aid/<CLUSTER_UUID>/<YYYY_MM_DD>/<NODE>-auto-diags-<YYYYMMDDHHMMSS>.tar.gz
    /fuse2/px_aid/<CLUSTER_UUID>/<YYYY_MM_DD>/<NODE>-px-kvdb-dump-diags-<ts>.log.gz

    Example:
    /fuse2/px_aid/b9462820-8db9-4088-9801-563dcc31d237/2026_04_10/pxpvip1331919.gsm1900.org-auto-diags-20260410052348.tar.gz

    Note: date folders use underscores (2026_04_10), NOT dashes.

Strategy:
    1. List date folders under /fuse2/px_aid/<UUID>/, sort descending, pick latest
       (or use date_override if specified — format: YYYY_MM_DD with underscores)
    2. List all -auto-diags-*.tar.gz files in the date folder
    3. If node_filter specified, only download matching files
    4. Per node, keep only the latest tarball (sorted by timestamp suffix)
    5. Download to ~/downloads/<UUID>/<YYYY_MM_DD>/<filename>
    6. Return list of local Paths to downloaded files
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


def _latest_date_folder(sftp: paramiko.SFTPClient, uuid: str) -> str | None:
    """Return the latest date folder name (YYYY_MM_DD) under /fuse2/px_aid/<UUID>/."""
    base = f"{FUSE_BASE}/{uuid}"
    log.info(f"Scanning for date folders under: {base}")
    entries = _sftp_list(sftp, base)
    if not entries:
        log.warning(
            f"No entries found under {base}. "
            "Check that the cluster UUID is correct and you have access to Fuse2."
        )
        return None
    date_folders = sorted(
        [e for e in entries if _DATE_FOLDER_PAT.match(e)],
        reverse=True,
    )
    non_date = [e for e in entries if not _DATE_FOLDER_PAT.match(e)]
    log.info(
        f"Found {len(date_folders)} date folder(s) under {base}: {date_folders}"
        + (f" (ignored: {non_date})" if non_date else "")
    )
    return date_folders[0] if date_folders else None


def download_diags(
    ssh_client: paramiko.SSHClient,
    cluster_uuid: str,
    node_filter: str | None = None,
    date_override: str | None = None,
) -> list[Path]:
    """
    Walk Fuse2 and download diagnostic tarballs for the given cluster UUID.

    Args:
        ssh_client   : Open paramiko SSHClient (from px_auth.auth_flow)
        cluster_uuid : Cluster UUID string
        node_filter  : Optional hostname to limit download to one node
        date_override: Optional YYYY_MM_DD date folder name (default: latest)

    Returns:
        List of local file Paths to downloaded .tar.gz files

    Raises:
        FileNotFoundError if no diag files are found
    """
    sftp = ssh_client.open_sftp()
    downloaded: list[Path] = []

    try:
        # Determine date folder
        date_folder = date_override or _latest_date_folder(sftp, cluster_uuid)
        if not date_folder:
            raise FileNotFoundError(
                f"No date folders found under {FUSE_BASE}/{cluster_uuid}/"
            )

        remote_dir = f"{FUSE_BASE}/{cluster_uuid}/{date_folder}"
        log.info(f"Remote diag directory: {remote_dir}")

        entries = _sftp_list(sftp, remote_dir)
        if not entries:
            raise FileNotFoundError(
                f"No files found in {remote_dir}. "
                "Verify the cluster UUID and date folder on Fuse2."
            )

        log.info(f"All entries in {remote_dir} ({len(entries)}): {sorted(entries)}")

        # Filter to auto-diag tarballs: <node>-auto-diags-<ts>.tar.gz
        tarballs = sorted([
            e for e in entries
            if e.endswith(".tar.gz") and "-auto-diags-" in e
        ])

        log.info(
            f"Auto-diag tarballs found: {len(tarballs)}"
            + (f" — {tarballs}" if tarballs else "")
        )

        if node_filter:
            before = tarballs
            tarballs = [t for t in tarballs if node_filter in t]
            log.info(f"After node filter '{node_filter}': {tarballs} (was {before})")

        if not tarballs:
            raise FileNotFoundError(
                f"No -auto-diags- tarballs found in {remote_dir}"
                + (f" matching node '{node_filter}'" if node_filter else "")
                + f". All entries: {sorted(entries)}"
            )

        # Group by node hostname, keep latest tarball per node
        node_tarballs: dict[str, list[str]] = defaultdict(list)
        for t in tarballs:
            parts = t.split("-auto-diags-")
            if len(parts) == 2:
                node_tarballs[parts[0]].append(t)
            else:
                node_tarballs[t].append(t)

        selected: list[str] = []
        for node_name, files in node_tarballs.items():
            selected.append(sorted(files)[-1])  # latest by timestamp suffix

        log.info(f"Downloading {len(selected)} tarball(s) from {remote_dir}")

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

            # Get remote file size for progress bar
            try:
                stat = sftp.stat(remote_path)
                file_size = stat.st_size or 0
            except Exception:
                file_size = 0

            log.info(f"Downloading: {filename}")
            with tqdm(total=file_size, unit="B", unit_scale=True, desc=filename) as pbar:
                def _progress(transferred: int, total: int, _pbar: tqdm = pbar) -> None:
                    _pbar.update(transferred - _pbar.n)

                sftp.get(remote_path, str(local_path), callback=_progress)

            downloaded.append(local_path)
            log.info(f"Saved: {local_path}")

    finally:
        sftp.close()

    return downloaded
