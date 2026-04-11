# px_diag_analyzer

A Python CLI tool that SSH/SFTP-connects to a Fuse2 jump host, downloads Portworx
diagnostic tarballs, analyzes them, and maps findings to Portworx Smart Signals.

## Requirements

- Python 3.10+
- `purelogin` CLI in PATH (for Fuse2 SSO auth)
- SSH agent running with key loaded for Fuse2 access (`ssh-add ~/.ssh/id_rsa`)

## Install

```bash
# Install the Prerequisites 
pip install -r requirements.txt
```
```bash
# Clone the repo locally 
git clone https://github.com/sensri108/px_diag_analyzer.git
cd px_diag_analyzer
```

## Usage

```bash
# Full pipeline (auth → download → extract → analyze → report)
python px_diag.py --cluster-uuid <UUID>

# Specific node only
python px_diag.py --cluster-uuid <UUID> --node <node name>

# Analyze already-downloaded/extracted local path (skip Fuse2)
python px_diag.py --cluster-uuid <UUID> --local-path ~/downloads/<UUID>/

# Validate auth only (does not download or analyze)
python px_diag.py --auth-only

# Specify date folder (default: latest)
python px_diag.py --cluster-uuid <UUID> --date 2026_04_10

# Re-extract tarballs even if already extracted
python px_diag.py --cluster-uuid <UUID> --local-path ~/downloads/<UUID>/ --force-extract

# Enable verbose/debug logging
python px_diag.py --cluster-uuid <UUID> --verbose
```

## Output

Reports are written to `~/downloads/<cluster-uuid>/reports/<timestamp>/`:

| File | Description |
|------|-------------|
| `cluster_summary.md` | Human-readable health overview with Smart Signals gap table |
| `errors.json` | Machine-readable structured findings with all Smart Signal metadata |
| `remediation_steps.md` | Ordered runbook for each finding, CRITICAL → WARNING → INFO |

## Smart Signals Coverage

The analyzer maps **31 deployed Portworx Smart Signals** plus **4 local-only patterns**
that are dark (invisible) to Pure's control plane.

Key dark findings not visible to Portworx's monitoring:

| ID | Label | Why It's Dark |
|----|-------|---------------|
| `LOCAL-01` | STATUS_STORAGE_DOWN | No deployed Smart Signal covers this pattern |
| `LOCAL-02` | kvdb_quorum_loss_alarm | SS-13 watches live count, not historical alarm logs |
| `LOCAL-03` | device_mapper_thin_error | Not covered by any Smart Signal |
| `LOCAL-04` | pool_offline_alarm | Proposed signal (Tom Felczynski) — not yet deployed |

The `already_monitored_by_smart_signal` field in `errors.json` is the leverage:
within 3 months of running this tool across your fleet, you will know exactly which
failure classes are invisible to Portworx's control plane. That gap list is a concrete
deliverable for TAM meetings.

## Project Structure

```
px_diag_analyzer/
├── px_diag.py           # CLI entrypoint (argparse orchestrator)
├── px_auth.py           # purelogin + paramiko SSH to Fuse2
├── px_download.py       # SFTP walk of /fuse2/px_aid/<UUID>/<date>/
├── px_extract.py        # Tarball extraction with path normalization
├── px_report.py         # Renders all three output files
├── px_analyzer/
│   ├── __init__.py
│   ├── engine.py        # Orchestrator + Finding dataclass + correlation
│   ├── _base.py         # Shared scan utilities (scan_file, parse_alerts_show, etc.)
│   ├── volume.py        # SS-01 through SS-11 (volume operations)
│   ├── kvdb.py          # SS-12, SS-13, SS-14 (kvdb/etcd)
│   ├── storage.py       # LOCAL-01 (STATUS_STORAGE_DOWN)
│   ├── node.py          # SS-18, SS-21, SS-25, SS-26, SS-27 (node health)
│   ├── capacity.py      # SS-15, SS-16, SS-17, SS-23 (capacity/pool)
│   ├── license.py       # SS-19, SS-INVALID-LICENSE
│   ├── network.py       # SS-22 (NFS dependency)
│   ├── security.py      # SS-09 (in-tree volumes + K8s version)
│   ├── infrastructure.py # SS-07 (stale mount), LOCAL-03 (device-mapper)
│   └── predictive.py    # Sliding-window trend analysis (FORECAST-* findings)
├── patterns/
│   ├── errors.yaml      # 31 Smart Signal patterns + 4 LOCAL patterns
│   └── forecasts.yaml   # Predictive threshold rules
└── requirements.txt
```

## Cluster Info

The analyzer was originally built for:

```
Cluster:  px-cluster-plnpevipspoke11
UUID:     b9462820-8db9-4088-9801-563dcc31d237
Node:     pxpvip1331919.gsm1900.org (192.168.11.113)
PX:       3.5.2.0-86e5708 | RHCOS 418.94 | OpenShift
```

Findings confirmed in the reference diag:
- **SS-03** (volume_space_low): 2 volumes at 99–100% capacity — monitored
- **LOCAL-01** (STATUS_STORAGE_DOWN): 28 occurrences — **dark to Pure**
- **LOCAL-02** (quorum_loss, alert_type=11): 3 nodes, uncleared — **dark to Pure**
- **LOCAL-04** (pool_offline, alert_type=83): neighbor node pxpvip1331823 — **dark**
- **SS-14** (kvdb gRPC errors): 3 occurrences — monitored
