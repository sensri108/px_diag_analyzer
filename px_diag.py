"""
px_diag.py — CLI entrypoint for px_diag_analyzer.

Usage:
    python px_diag.py --cluster-uuid <UUID>
    python px_diag.py --cluster-uuid <UUID> --node <hostname>
    python px_diag.py --cluster-uuid <UUID> --local-path ~/downloads/<UUID>/
    python px_diag.py --auth-only
    python px_diag.py --cluster-uuid <UUID> --date 2026_04_10

Flow:
    1. Parse args
    2. If --auth-only: run purelogin and exit
    3. If --local-path: skip download, go straight to extract + analyze
    4. Otherwise: auth → download → extract → analyze → report
"""
from __future__ import annotations

import argparse
import logging
import re
import sys
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler

console = Console()


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True)],
    )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="px_diag",
        description="Portworx diagnostic analyzer with Smart Signals mapping",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python px_diag.py --cluster-uuid b9462820-8db9-4088-9801-563dcc31d237
  python px_diag.py --cluster-uuid <UUID> --node pxpvip1331919.gsm1900.org
  python px_diag.py --cluster-uuid <UUID> --local-path ~/downloads/<UUID>/
  python px_diag.py --auth-only
  python px_diag.py --cluster-uuid <UUID> --date 2026_04_10
        """,
    )

    parser.add_argument(
        "--cluster-uuid", "-u",
        metavar="UUID",
        help="Portworx cluster UUID (required unless --auth-only)",
    )
    parser.add_argument(
        "--node", "-n",
        metavar="HOSTNAME",
        help="Limit download and analysis to a single node hostname",
    )
    parser.add_argument(
        "--local-path", "-l",
        metavar="PATH",
        type=Path,
        help="Path to already-downloaded/extracted diag directory (skips Fuse2 download)",
    )
    parser.add_argument(
        "--date",
        metavar="YYYY_MM_DD",
        help="Override date folder selection (default: latest available)",
    )
    parser.add_argument(
        "--auth-only",
        action="store_true",
        help="Run purelogin auth flow and exit (validates credentials only)",
    )
    parser.add_argument(
        "--skip-download",
        action="store_true",
        help="Skip Fuse2 download — use already-downloaded tarballs under ~/downloads/<UUID>/",
    )
    parser.add_argument(
        "--force-extract",
        action="store_true",
        help="Re-extract tarballs even if already extracted",
    )
    parser.add_argument(
        "--output-dir",
        metavar="PATH",
        type=Path,
        help="Override output directory for reports (default: ~/downloads/<UUID>/reports/<ts>/)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable debug logging",
    )

    return parser.parse_args()


def _collect_cluster_info(extracted_paths: list[Path]) -> dict:
    """
    Extract cluster metadata from px-status.out, px-version.out, config.json etc.

    Tarballs extract to:
        <node>/var/lib/osd/diagfiles/pwx_diag_<id>/misc/px-status.out

    We use find_diag_root() (same as engine.py) to resolve the actual content root
    before reading files, so metadata is found regardless of tarball structure.
    """
    import json as _json
    from px_analyzer._base import find_diag_root, find_node_root

    info = {
        "name":             "N/A",
        "uuid":             "N/A",
        "node_analyzed":    "N/A",
        "hostname":         "N/A",
        "px_version":       "N/A",
        "total_nodes":      "N/A",
        "os":               "N/A",
        "ocp_version":      "N/A",
        "kernel":           "N/A",
        "uptime":           "N/A",
        "memory_total_gib": "N/A",
        "license_info":     "N/A",
        "metering_status":  "OK",
        "storage_type":     "N/A",
        "cloud_provider":   "N/A",
        "data_iface":       "N/A",
        "mgmt_iface":       "N/A",
        "fastpath":         False,
        "px_running":       False,
    }

    if not extracted_paths:
        return info

    extracted_root = extracted_paths[0]
    info["node_analyzed"] = extracted_root.name

    # Resolve to the actual diag content root (handles pwx_diag_<id> nesting)
    root = find_diag_root(extracted_root)
    node_root = find_node_root(root)

    # px-version.out — most reliable version source
    version_file = root / "misc" / "px-version.out"
    if version_file.exists():
        v = version_file.read_text(errors="replace").strip()
        # "pxctl version 3.5.2.0-86e5708 (OCI)"
        m = re.search(r'version\s+(\S+)', v, re.IGNORECASE)
        if m:
            info["px_version"] = m.group(1)

    # config.json — reliable cluster name, storage type, interfaces, fastpath
    config_file = root / "etc" / "pwx" / "config.json"
    if config_file.exists():
        try:
            cfg = _json.loads(config_file.read_text(errors="replace"))
            if cfg.get("clusterid"):
                info["name"] = cfg["clusterid"]
            # Storage drives / type
            drives = cfg.get("storage", {}).get("devices", [])
            if drives:
                first = drives[0]
                if first.startswith("/dev/nvme"):
                    info["storage_type"] = "NVMe"
                elif first.startswith("/dev/sd"):
                    info["storage_type"] = "SSD/HDD"
                elif first.startswith("/dev/mapper") or first.startswith("/dev/dm"):
                    info["storage_type"] = "LVM"
                else:
                    info["storage_type"] = first
            # Network interfaces
            ifaces = cfg.get("network", {})
            if ifaces.get("dataInterface"):
                info["data_iface"] = ifaces["dataInterface"]
            if ifaces.get("managementInterface"):
                info["mgmt_iface"] = ifaces["managementInterface"]
            # Cloud provider / env
            provider = cfg.get("env", "") or cfg.get("cloud_provider", "")
            if provider:
                info["cloud_provider"] = provider
            # Fastpath (CSI fastpath or kernel module)
            fp = cfg.get("fastpath") or cfg.get("csi", {}).get("enable_csi_driver_grpc", False)
            if fp:
                info["fastpath"] = True
        except Exception:
            pass

    # px-status.out — remaining fields + px_running detection
    px_status = root / "misc" / "px-status.out"
    if px_status.exists():
        content = px_status.read_text(encoding="utf-8", errors="replace")
        # Detect if PX is running: "Status: PX is operational" or similar
        if re.search(r'Status\s*:\s*PX is (operational|running|OK)', content, re.IGNORECASE):
            info["px_running"] = True
        elif re.search(r'PX is not running', content, re.IGNORECASE):
            info["px_running"] = False
        else:
            # Heuristic: if we can read cluster info, PX was likely up
            info["px_running"] = bool(re.search(r'Cluster\s+(Name|ID)\s*:', content, re.IGNORECASE))

        field_patterns = {
            "name":            r"Cluster\s+Name\s*:\s*(.+)",
            "uuid":            r"Cluster\s+ID\s*:\s*([0-9a-f\-]+)",
            "px_version":      r"PX\s+Version\s*:\s*(\S+)",
            "total_nodes":     r"Total\s+Nodes\s*:\s*(\d+)",
            "os":              r"OS\s*:\s*(.+)",
            "kernel":          r"Kernel\s*:\s*(.+)",
            "license_info":    r"License\s*:\s*(.+)",
            "metering_status": r"Metering\s*:\s*(.+)",
        }
        for key, pat in field_patterns.items():
            m = re.search(pat, content, re.IGNORECASE | re.MULTILINE)
            if m:
                val = m.group(1).strip()
                # Only overwrite if not already set from a more-reliable source
                if info[key] == "N/A" or key not in ("name", "px_version"):
                    info[key] = val

        # Data/mgmt interfaces from px-status if not found in config.json
        if info["data_iface"] == "N/A":
            m = re.search(r'Data\s+IP\s*:\s*(\S+)', content, re.IGNORECASE)
            if m:
                info["data_iface"] = m.group(1)
        if info["mgmt_iface"] == "N/A":
            m = re.search(r'Mgmt\s+IP\s*:\s*(\S+)', content, re.IGNORECASE)
            if m:
                info["mgmt_iface"] = m.group(1)

        # Fastpath from status output
        if not info["fastpath"] and re.search(r'Fastpath\s*:\s*(enabled|yes|true)', content, re.IGNORECASE):
            info["fastpath"] = True

    # uname.out — hostname
    uname_file = root / "misc" / "uname.out"
    if uname_file.exists():
        uname = uname_file.read_text(errors="replace").strip()
        # uname -a: "Linux pxpvip1331823 5.14.0-427.37.1.el9_4.x86_64 ..."
        parts = uname.split()
        if len(parts) >= 2:
            info["hostname"] = parts[1]
        if info["kernel"] == "N/A" and len(parts) >= 3:
            info["kernel"] = parts[2]
    else:
        # Fallback: use node_root directory name as hostname
        info["hostname"] = node_root.name

    # OCP version — try host-os-release first, then /etc/os-release
    for os_release_path in [
        root / "log" / "extras" / "host-os-release",
        node_root / "etc" / "os-release",
        root / "etc" / "os-release",
    ]:
        if os_release_path.exists():
            content = os_release_path.read_text(errors="replace")
            # OpenShift: PRETTY_NAME="Red Hat Enterprise Linux CoreOS 414.92.202409..."
            m = re.search(r'OPENSHIFT_VERSION\s*=\s*"?([^"\n]+)"?', content, re.IGNORECASE)
            if m:
                info["ocp_version"] = m.group(1).strip()
                break
            m = re.search(r'PRETTY_NAME\s*=\s*"?([^"\n]+)"?', content)
            if m:
                pretty = m.group(1).strip()
                # Only set ocp_version if it mentions OpenShift/RHCOS
                if "openshift" in pretty.lower() or "coreos" in pretty.lower():
                    info["ocp_version"] = pretty
                elif info["os"] == "N/A":
                    info["os"] = pretty
                break

    uptime_file = root / "misc" / "uptime.out"
    if uptime_file.exists():
        txt = uptime_file.read_text(errors="replace").strip()
        info["uptime"] = txt.split("\n")[0][:80] if txt else "N/A"

    memory_file = root / "misc" / "memory.out"
    if memory_file.exists():
        m = re.search(
            r"MemTotal\s*:\s*(\d+)\s*kB",
            memory_file.read_text(errors="replace"),
            re.IGNORECASE,
        )
        if m:
            info["memory_total_gib"] = f"{int(m.group(1)) / (1024 * 1024):.0f}"

    return info


def main() -> int:
    args = _parse_args()
    _setup_logging(args.verbose)
    log = logging.getLogger(__name__)

    # ── auth-only mode ──────────────────────────────────────────────────────
    if args.auth_only:
        from px_auth import purelogin
        try:
            purelogin()
            console.print("[green]Auth successful.[/green]")
            return 0
        except Exception as e:
            console.print(f"[red]Auth failed: {e}[/red]")
            return 1

    # ── require cluster-uuid for all other modes ────────────────────────────
    if not args.cluster_uuid:
        console.print("[red]--cluster-uuid is required (unless --auth-only)[/red]")
        return 1

    cluster_uuid = args.cluster_uuid
    tarball_paths: list[Path] = []
    extracted_paths: list[Path] = []

    # ── local-path mode (skip download) ────────────────────────────────────
    if args.local_path:
        local_path = args.local_path.expanduser().resolve()
        if not local_path.exists():
            console.print(f"[red]--local-path does not exist: {local_path}[/red]")
            return 1
        log.info(f"Using local path: {local_path}")

        tarballs = list(local_path.rglob("*.tar.gz"))
        if tarballs:
            tarball_paths = tarballs
        else:
            # Already extracted — treat subdirs as node extraction roots
            subdirs = [d for d in local_path.iterdir() if d.is_dir() and d.name != "reports"]
            extracted_paths = subdirs if subdirs else [local_path]

    # ── download mode ───────────────────────────────────────────────────────
    elif not args.skip_download:
        from px_auth import auth_flow
        from px_download import download_diags
        try:
            ssh_client = auth_flow()
        except Exception as e:
            console.print(f"[red]Auth/connect failed: {e}[/red]")
            return 1
        try:
            tarball_paths = download_diags(
                ssh_client,
                cluster_uuid,
                node_filter=args.node,
                date_override=args.date,
            )
        except Exception as e:
            console.print(f"[red]Download failed: {e}[/red]")
            return 1
        finally:
            ssh_client.close()

    # ── skip-download: look for existing tarballs ───────────────────────────
    else:
        from px_download import LOCAL_BASE
        download_dir = LOCAL_BASE / cluster_uuid
        if not download_dir.exists():
            console.print(f"[red]No downloaded tarballs found at: {download_dir}[/red]")
            return 1
        tarball_paths = list(download_dir.rglob("*.tar.gz"))
        if not tarball_paths:
            console.print(f"[red]No .tar.gz files found under: {download_dir}[/red]")
            return 1

    # ── extract tarballs ────────────────────────────────────────────────────
    if tarball_paths:
        from px_extract import extract_all
        extracted_paths = extract_all(tarball_paths, cluster_uuid, force=args.force_extract)

    if not extracted_paths:
        console.print("[red]No extracted diag directories available for analysis.[/red]")
        return 1

    # ── analyze ─────────────────────────────────────────────────────────────
    from px_analyzer import run_analysis
    from px_analyzer.engine import SEVERITY_RANK

    all_findings = []
    for ep in extracted_paths:
        log.info(f"Analyzing: {ep}")
        try:
            findings = run_analysis(ep, cluster_uuid)
            all_findings.extend(findings)
        except Exception as e:
            log.error(f"Analysis failed for {ep}: {e}", exc_info=True)

    # Re-sort merged findings
    all_findings.sort(key=lambda f: (SEVERITY_RANK.get(f.severity, 99), -f.count))

    # ── collect cluster info ────────────────────────────────────────────────
    cluster_info = _collect_cluster_info(extracted_paths)
    cluster_info["uuid"] = cluster_uuid

    # ── report ──────────────────────────────────────────────────────────────
    import px_report
    paths = px_report.render_all(
        all_findings,
        cluster_uuid,
        cluster_info,
        output_dir=args.output_dir,
    )

    console.print("\n[bold green]Reports written:[/bold green]")
    for name, p in paths.items():
        console.print(f"  {name}: {p}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
