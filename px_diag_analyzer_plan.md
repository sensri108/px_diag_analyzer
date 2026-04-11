# px-diag-analyzer — Operator Project Plan v2
## Now with PX Smart Signals Integration

**Cluster analyzed:** `px-cluster-plnpevipspoke11`  
**UUID:** `b9462820-8db9-4088-9801-563dcc31d237`  
**Node:** `pxpvip1331919.gsm1900.org` (192.168.11.113)  
**PX Version:** 3.5.2.0-86e5708 | **OS:** RHCOS 418.94 | **Scheduler:** Kubernetes (OpenShift)

---

## What Changed in v2

The analyzer is now **Smart Signals-aware**. Every finding it produces is mapped to a specific Portworx Smart Signal — its official alert code, the exact `alert_type` integer used in Octillion/Snowflake tables, the source log table it queries, and the severity thresholds Portworx engineering uses. This means:

- Your `errors.json` output now includes `smart_signal_code` and `alert_type` fields on every finding
- The `remediation_steps.md` cross-references the official KB article for that signal
- The `patterns/errors.yaml` pattern map is built directly from the 31 deployed signals
- The analyzer can flag findings as `"already_monitored_by_smart_signal": true` — so you know which issues Pure's control plane already sees vs. which are dark to them

---

## Part 1 — Auth Flow (Exact Commands)

```
Step 1:  purelogin --force-login        # Pure SSO credentials — prompts interactively
Step 2:  ssh -A fuse                    # Agent-forwarded SSH into Fuse2 jump host
Step 3:  Navigate /fuse2/px_aid/<UUID>/<DATE>/
```

Implemented via `paramiko` with `AgentRequestHandler`. Credentials are captured at runtime with `getpass.getpass()` — never written to disk beyond the active session.

---

## Part 2 — Fuse2 Path Format

```
/fuse2/px_aid/<CLUSTER_UUID>/<YYYY_MM_DD>/<NODE>-auto-diags-<YYYYMMDDHHMMSS>.tar.gz
```

**Live example:**
```
/fuse2/px_aid/b9462820-8db9-4088-9801-563dcc31d237/2026_04_10/pxpvip1331919.gsm1900.org-auto-diags-20260410052348.tar.gz
```

Note: date folder uses underscores (`2026_04_10`). The tool sorts date folders descending and selects the latest. Per-node diag files within the date folder are sorted by timestamp suffix — latest wins unless `--node` is specified.

**Also present in the same date folder (from your environment):**
- `<node>-px-kvdb-dump-diags-<ts>.log.gz` — separate kvdb dump logs per node, multiple per day
- Multiple auto-diag tarballs per node (one per scheduled diag interval)

---

## Part 3 — Project Structure

```
px-diag-analyzer/
├── px_diag.py                    # CLI entrypoint — argparse orchestrator
├── px_auth.py                    # purelogin + ssh -A fuse via paramiko
├── px_download.py                # SFTP walk of /fuse2/px_aid/<UUID>/<date>/
├── px_extract.py                 # tarball → ~/downloads/<UUID>/<node>/
├── px_analyzer/
│   ├── __init__.py
│   ├── engine.py                 # Orchestrator: runs all analyzers, merges findings
│   ├── kvdb.py                   # Smart Signals: 12, 13, 14 + kvdb slow drive (10089)
│   ├── storage.py                # Smart Signals: STATUS_STORAGE_DOWN, snapshot I/O
│   ├── volume.py                 # Smart Signals: 1,2,3,4,5,6,7,8,10,11
│   ├── node.py                   # Smart Signals: 26, 27, 21, 25
│   ├── capacity.py               # Smart Signals: 15, 16, 17, 23
│   ├── license.py                # Smart Signals: 19 (10068), invalid license (10231)
│   ├── network.py                # MTU, OVN-K Geneve, bond, NFS dependency (22)
│   ├── security.py               # Smart Signal: 9 (in-tree volumes + K8s version)
│   ├── infrastructure.py         # Smart Signals: 7 (stale mount), 22 (NFS)
│   └── predictive.py             # Sliding-window trend, frequency scoring
├── px_report.py                  # Renders all output files
├── patterns/
│   ├── errors.yaml               # 31 Smart Signal patterns + local log patterns
│   └── forecasts.yaml            # Threshold rules for predictive triggers
├── requirements.txt
└── README.md
```

---

## Part 4 — CLI

```bash
# Full pipeline
python px_diag.py --cluster-uuid b9462820-8db9-4088-9801-563dcc31d237

# Specific node
python px_diag.py --cluster-uuid <UUID> --node pxpvip1331919.gsm1900.org

# Analyze already-extracted local path (skip download)
python px_diag.py --cluster-uuid <UUID> --local-path ~/downloads/<UUID>/

# Auth only
python px_diag.py --auth-only
```

---

## Part 5 — Smart Signals Pattern Map (`patterns/errors.yaml`)

This is the core intelligence layer. Each entry maps a log pattern to its official Portworx Smart Signal, alert code, source file inside the diag tarball, and remediation reference.

```yaml
# ============================================================
# VOLUME OPERATIONS — Smart Signals 1–8, 10–11
# ============================================================

- id: SS-01
  smart_signal: volume_creation_failure_alerts
  alert_code: 10074
  alert_type: 38            # alert_type in alerts.log / px-alerts.log
  source_files:
    - misc/px-alerts-show.out
    - var/cores/.alerts/alerts.log
  severity: CRITICAL
  schedule: Daily 12:30 AM
  audience: Support
  pattern: '"alert_type":\s*"?38"?'
  sub_types:
    - Replication_Failed_Message
    - License_Expired_Message
    - Volume_Allocation_Failed_Message
    - Feature_Upgrade_Needed_Message
    - Cloudops_Config_Loading_Failed_Message
    - Failed_To_Get_Secret_Message
  threshold: count >= 1 in last 24h
  remediation_kb: https://pure.service-now.com/perc?id=kb_article&sysparm_article=KB0017845

- id: SS-02
  smart_signal: volume_resize_failure_alerts
  alert_code: 10075
  alert_type: null          # Multiple alert types — see sub_types
  source_files:
    - misc/px-alerts-show.out
  severity: WARNING
  schedule: Daily midnight
  pattern: 'resize.*fail|Pending FS resize|Filesystem errors|Provisioning errors|Volume expansion failed'
  threshold: fail_timestamp > success_timestamp AND count > 0
  remediation_kb: https://pure.service-now.com/kb_view.do?sys_kb_id=363f7ed293cf9e5c9e6dbccdfaba10a3

- id: SS-03
  smart_signal: volume_space_low_alerts
  alert_code: 10081
  alert_type: 30            # ← THIS FIRED IN YOUR DIAG (2 volumes at 99–100%)
  source_files:
    - misc/px-alerts-show.out
    - var/cores/.alerts/alerts.log
  severity: CRITICAL
  schedule: Daily midnight
  pattern: '"alert_type":\s*"?30"?'
  threshold: alert_type=30 within 24h (>80% used, <20% free)
  remediation_kb: https://purestorage.atlassian.net/browse/PWX-41031

- id: SS-04
  smart_signal: volume_mount_failure
  alert_code: 10103
  alert_type: null
  source_files:
    - misc/px-alerts-show.out
    - var/cores/.alerts/alerts.log
  severity: WARNING
  schedule: Daily midnight
  pattern: 'mount.*fail|failed to mount'
  threshold: fail_timestamp > success_timestamp AND fail_count >= 1
  remediation_kb: https://pure.service-now.com/kb_view.do?sys_kb_id=274ae414471e2a9415f79c8a516d436b

- id: SS-05
  smart_signal: volume_delete_failure
  alert_code: 10101
  alert_type: 40
  source_files:
    - var/cores/.alerts/alerts.log
  severity: WARNING
  schedule: Daily midnight
  pattern: '"alert_type":\s*"?40"?'
  threshold: count > 1 in last 24h
  remediation_kb: https://purestorage.atlassian.net/browse/PWX-41710

- id: SS-06
  smart_signal: volume_device_exist
  alert_code: 10121
  alert_type: 212
  source_files:
    - misc/px-alerts-show.out
  severity: WARNING
  schedule: Hourly
  pattern: '"alert_type":\s*"?212"?'
  threshold: count > 1 in last 1h
  remediation_kb: https://pure.service-now.com/kb_view.do?sys_kb_id=412bbb993b94e614b7a1c41864e45a57

- id: SS-07
  smart_signal: stale_mount_found
  alert_code: 10140
  alert_type: null
  source_files:
    - var/cores/px_status/<node>-px-jrnl-32min-<ts>.log.gz
  severity: WARNING
  schedule: Hourly
  pattern: 'Stale mount|file exists'
  threshold: any match in last 1h
  remediation_kb: https://purestorage.atlassian.net/browse/PWX-43561
  note: If found, schedule node reboot with customer

- id: SS-08
  smart_signal: volume_unmount_failure_alert
  alert_code: 10102
  alert_type: 44
  source_files:
    - var/cores/.alerts/alerts.log
  severity: WARNING
  schedule: Weekly Mon 1 AM
  pattern: '"alert_type":\s*"?44"?'
  threshold: count > 1 in last 7 days
  remediation_kb: https://purestorage.atlassian.net/browse/PWX-41737

- id: SS-10
  smart_signal: snapshot_creation_failure_alert
  alert_code: 10095
  alert_type: 48
  source_files:
    - var/cores/.alerts/alerts.log
    - var/cores/px_status/<node>-px-jrnl-32min-<ts>.log.gz
  severity: WARNING
  schedule: Weekly Mon
  pattern: |
    '"alert_type":\s*"?48"?'
    OR 'Snapshot.*Failed with status input/output error'
  threshold: count > 1000 in last 7 days (Portworx global threshold)
            OR any I/O error snapshots in local diag
  remediation_kb: https://purestorage.atlassian.net/browse/PWX-41503
  note: "12 I/O error snapshots found in this diag — correlates with STATUS_STORAGE_DOWN window"

- id: SS-11
  smart_signal: snapshot_delete_failure
  alert_code: 10099
  alert_type: 63
  source_files:
    - var/cores/.alerts/alerts.log
  severity: WARNING
  schedule: Daily midnight
  pattern: '"alert_type":\s*"?63"?'
  threshold: count > 1 in last 24h

# ============================================================
# KVDB — Smart Signals 12, 13, 14
# ============================================================

- id: SS-12
  smart_signal: kvdb_out_of_space
  alert_code: 10192
  alert_type: null
  source_files:
    - misc/px-kvdb.out
    - var/cores/px_status/<node>-px_etcd_watch-<ts>.log.gz
  severity: CRITICAL
  schedule: Every 30 min
  pattern: 'mvcc: database space exceeded|ResourceExhausted.*etcdserver'
  threshold: any match
  remediation_kb: pending KB

- id: SS-13
  smart_signal: kvdb_reduced_node_count_alert
  alert_code: 10110
  alert_type: null
  source_files:
    - misc/px-kvdb.out
    - misc/px-status.out
  severity: CRITICAL
  schedule: Hourly
  pattern: 'kvdb.*node.*count|reduced.*kvdb'
  threshold: node_count < 3 for > 5 min (WARNING) or < 2 (CRITICAL)
  remediation_kb: https://kb.purestorage.com/csm?sys_kb_id=fe70c1eb4784a694a74fef6c416d432b

- id: SS-14
  smart_signal: portworx_kvdb_errors
  alert_code: 10042
  alert_type: null
  source_files:
    - misc/px-kvdb.out
    - var/cores/px_status/<node>-px_etcd_watch-<ts>.log.gz
  severity: WARNING→CRITICAL
  schedule: Every 30 min
  pattern: |
    'Failed connect to kvdb instance'
    OR 'grpc.*transport is closing'
    OR 'kvdb.*error'
  threshold: |
    >= 50% nodes affected → WARNING (10042)
    100% nodes affected → CRITICAL (10051)
    issue duration > 1 hour
  remediation_kb: https://kb.purestorage.com/csm?sys_kb_id=96a2c5b12bbda2507b12f6c3d891bf56
  note: "kvdb endpoint list [] empty in this diag — internal kvdb mode, pxctl sv dump --kvdb expected to fail"

# ============================================================
# NODE & CLUSTER HEALTH — Smart Signals 18, 21, 25, 26, 27
# ============================================================

- id: SS-18
  smart_signal: high_node_count_alerts
  alert_code: 10079
  alert_type: null
  source_files:
    - misc/px-status.out
  severity: WARNING
  schedule: Every 30 min
  pattern: 'Total Nodes:\s*(\d+)'
  threshold: node_count > 300
  note: "This cluster has 21 nodes — well within limit"

- id: SS-21
  smart_signal: high_node_flush_latency_alert
  alert_code: 10133
  alert_type: null
  source_files:
    - var/lib/osd/log/px_node_stats/<timestamp>
  severity: WARNING
  schedule: Daily midnight
  pattern: 'flush_ms|flush_latency'
  threshold: (delta_flush_ms / delta_num_flushes) > 700ms for > 15 consecutive minutes
  note: "Node stats files present in diag — parse timestamped files under var/lib/osd/log/px_node_stats/"

- id: SS-25
  smart_signal: px_missing_node_stats_alert
  alert_code: 10145
  alert_type: null
  source_files:
    - var/lib/osd/log/px_node_stats/
  severity: WARNING
  schedule: Daily midnight
  pattern: gap between consecutive stat file timestamps
  threshold: gap > 2100 seconds (35 minutes)
  note: "Check timestamp gaps across the px_node_stats/ timestamped files"

- id: SS-26
  smart_signal: px_node_down_alert
  alert_code: 10109
  alert_type: null
  source_files:
    - misc/px-status.out
  severity: CRITICAL
  schedule: Daily midnight
  pattern: 'StorageStatus.*Down|Status.*Offline|node.*down'
  threshold: count > 12 in 24h OR duration > 3h
  remediation_kb: https://kb.purestorage.com/csm?sys_kb_id=20c0b72e3b5cee54b7a1c41864e45a00

- id: SS-27
  smart_signal: storage_node_transition_failure_alert
  alert_code: 10100
  alert_type: 86
  source_files:
    - var/cores/.alerts/alerts.log
    - misc/px-alerts-show.out
  severity: WARNING
  schedule: Weekly Mon 1 AM
  pattern: '"alert_type":\s*"?86"?'
  threshold: count > 1 in last 24h

# ============================================================
# CAPACITY & STORAGE — Smart Signals 15, 16, 17, 23
# ============================================================

- id: SS-15
  smart_signal: capacity_alerts
  alert_code: 10053
  alert_type: 29
  source_files:
    - var/cores/.alerts/alerts.log
    - misc/px-alerts-show.out
  severity: WARNING
  schedule: Hourly
  pattern: '"alert_type":\s*"?29"?'
  threshold: any match (cluster at 75%+ capacity)
  remediation_kb: https://kb.purestorage.com/csm?sys_kb_id=13c77d452b76f2900314fcb3d891bf20

- id: SS-16
  smart_signal: pool_expand_failed_alert
  alert_code: 10076
  alert_type: null
  source_files:
    - var/cores/.alerts/alerts.log
    - misc/px-alerts-show.out
  severity: WARNING
  schedule: Daily midnight
  pattern: 'pool.*expand.*fail|expansion.*fail'
  threshold: fail_timestamp > success_timestamp, count > 1 in 24h
  remediation_kb: https://pure.service-now.com/perc?id=kb_article&sysparm_article=KB0018284

- id: SS-17
  smart_signal: px_max_storage_nodes_alerts
  alert_code: 10054
  alert_type: null
  source_files:
    - misc/px-cluster-options.out
    - etc/pwx/config.json
  severity: WARNING
  schedule: Daily midnight
  check: max_storage_nodes == 0 AND max_storage_nodes_per_zone == 0 AND cloud devices present

- id: SS-23
  smart_signal: px-max-storage-nodes-exceeded-alert
  alert_code: 10123
  alert_type: null
  source_files:
    - misc/px-cluster-options.out
    - misc/px-status.out
  severity: WARNING
  schedule: Weekly Tue
  check: max_storage_nodes_per_zone > total_nodes
  remediation_kb: https://kb.purestorage.com/csm?sys_kb_id=9f77ad183bcda298f199009c24e45a18

# ============================================================
# LICENSE — Smart Signals 19, Invalid License (10231)
# ============================================================

- id: SS-19
  smart_signal: license_expiry_alerts
  alert_code: 10068
  alert_type: 58
  source_files:
    - misc/px-status.out
    - var/cores/.alerts/alerts.log
  severity: WARNING
  schedule: Daily midnight
  pattern: |
    '"alert_type":\s*"?58"?'
    OR 'expires in \d+ days'
  threshold: expiry within 7 days
  remediation_kb: https://pure.service-now.com/kb_view.do?sys_kb_id=1a0af770931e5a50c07f779d0bba107b
  note: "This cluster license expires in 1289 days — NO action needed"

- id: SS-INVALID-LICENSE
  smart_signal: px_invalid_license
  alert_code: 10231
  alert_type: null
  source_files:
    - misc/px-status.out
    - var/cores/px_status/<node>-px-jrnl-32min-<ts>.log.gz
  severity: CRITICAL
  schedule: Daily (Pending Deployment)
  pattern: |
    'INVALID LICENSE'
    OR 'License is expired'
    OR 'meteringUsageError.*failed to send telemetry'
    OR 'CallHomeFailure'
    OR 'Metering: Disabled or Unhealthy'
  threshold: any match
  remediation_kb: https://pure.service-now.com/kb_view.do?sys_kb_id=1a0af770931e5a50c07f779d0bba107b
  note: |
    Cluster enters read-only mode after billing_timeout_hours exceeded.
    Symptoms: metering failure alerts → grace period → INVALID LICENSE → no new volumes/apps.
    Check px-status.out for 'Metering: Disabled or Unhealthy'
    Check journal for 'meteringUsageError' or 'CallHomeFailure'

# ============================================================
# INFRASTRUCTURE — Smart Signals 7 (stale mount), 22 (NFS)
# ============================================================

- id: SS-22
  smart_signal: nfs_dependency_install_failure
  alert_code: 10071
  alert_type: null
  source_files:
    - var/cores/.alerts/alerts.log
    - misc/px-alerts-show.out
  severity: WARNING
  schedule: Daily midnight
  pattern: 'NFS.*fail|nfs.*install.*fail|nfs-utils.*fail'
  threshold: count > 5 in 5 minutes
  remediation_kb: https://kb.purestorage.com/csm?sys_kb_id=d0f5ec263b48ee5cb7a1c41864e45a9a

# ============================================================
# SECURITY — Smart Signal 9
# ============================================================

- id: SS-09
  smart_signal: px_security_in_tree_vol_clusters
  alert_code: 10130
  alert_type: null
  source_files:
    - misc/px-status.out
    - misc/px-volumes.out
    - etc/pwx/config.json
  severity: CRITICAL
  schedule: Weekly Sun
  check: |
    k8s_version < 1.32.1 (except 1.31.6)
    AND px_security_enabled
    AND in-tree volumes present (pxd.portworx.com label)
  note: "Data loss risk during upgrades — check K8s version from kubelet.out"

# ============================================================
# INIT — Smart Signal 24
# ============================================================

- id: SS-24
  smart_signal: px_init_failure
  alert_code: 10096
  alert_type: 17
  source_files:
    - var/cores/.alerts/alerts.log
    - misc/px-alerts-show.out
  severity: CRITICAL
  schedule: Daily midnight
  pattern: '"alert_type":\s*"?17"?'
  threshold: count > 10 in 24h

# ============================================================
# LOCAL-ONLY PATTERNS (not in Smart Signals — dark to Pure's control plane)
# ============================================================

- id: LOCAL-01
  smart_signal: null
  label: STATUS_STORAGE_DOWN
  alert_code: null
  source_files:
    - var/cores/px_status/<node>-px-jrnl-32min-<ts>.log.gz
  severity: CRITICAL
  pattern: 'STATUS_STORAGE_DOWN'
  threshold: any match
  note: "NOT monitored by any Smart Signal — only visible in local diag. Found 28x in this diag."

- id: LOCAL-02
  smart_signal: null
  label: kvdb_quorum_loss_alarm
  alert_code: null
  alert_type: 11
  source_files:
    - misc/px-alerts-show.out
  severity: CRITICAL
  pattern: '"alert_type":\s*"?11"?'
  note: |
    alert_type=11 = quorum loss alarm.
    Found on 3 nodes in this cluster — uncleared since 2026-04-06.
    Portworx Smart Signal 13 catches node count drops, but NOT the quorum alarm itself.

- id: LOCAL-03
  smart_signal: null
  label: device_mapper_thin_error
  source_files:
    - misc/dmesg.out
  severity: WARNING
  pattern: 'device-mapper: thin: release_metadata_snap message failed'
  note: "Seen at system boot — may indicate thin provisioning metadata issue during startup"

- id: LOCAL-04
  smart_signal: null
  label: pool_offline_alarm
  alert_type: 83
  source_files:
    - misc/px-alerts-show.out
  severity: CRITICAL
  pattern: '"alert_type":\s*"?83"?'
  note: |
    Proposed addition to Smart Signals (per Tom Felczynski comment in Smart Signals doc).
    Datapool load failure: "failed to access pwx1/pxpool"
    Found on pxpvip1331823 (node 51feb122) — 2026-04-09T18:08:33Z, uncleared.
    NOT yet a deployed Smart Signal.
```

---

## Part 6 — Analyzer Module Detail

### `px_analyzer/engine.py`

Orchestrates all sub-analyzers. Each returns a list of `Finding` objects. Engine merges, deduplicates, severity-ranks, and emits structured output.

```python
@dataclass
class Finding:
    id: str                          # e.g. "SS-03", "LOCAL-01"
    smart_signal: str | None         # signal name if mapped, else None
    alert_code: int | None           # Portworx alert code
    alert_type: int | None           # alert_type integer from alerts.log
    severity: str                    # CRITICAL / WARNING / INFO
    category: str                    # volume / kvdb / storage / node / capacity / license
    pattern_matched: str
    log_excerpt: str
    source_file: str
    first_seen: str                  # ISO timestamp
    last_seen: str
    count: int
    already_monitored: bool          # True if a deployed Smart Signal covers this
    remediation_kb: str | None
    remediation_steps: list[str]
```

### `px_analyzer/volume.py` — Smart Signals 1–8, 10–11

Key log sources inside the diag:
- `misc/px-alerts-show.out` — JSON alert objects with `alert_type`, `severity`, `message`, `cleared`, `count`
- `var/cores/.alerts/alerts.log` — rolling binary alert log (gzipped rotations)
- `var/cores/px_status/<node>-px-jrnl-32min-<ts>.log.gz` — snapshot I/O errors

What to scan for each signal:

| Signal | alert_type | Check |
|---|---|---|
| SS-01 volume_creation_failure | 38 | count in 24h |
| SS-03 volume_space_low | 30 | any match — **FIRED in this diag** |
| SS-05 volume_delete_failure | 40 | count > 1 in 24h |
| SS-06 volume_device_exist | 212 | count > 1 in 1h |
| SS-08 volume_unmount_failure | 44 | count > 1 in 7 days |
| SS-10 snapshot_creation_failure | 48 | count > 1000 in 7 days (+ local I/O errors) |
| SS-11 snapshot_delete_failure | 63 | count > 1 in 24h |
| LOCAL-02 quorum_loss | 11 | any uncleared — **FIRED in this diag** |
| LOCAL-04 pool_offline | 83 | any uncleared — **FIRED on neighbor node** |

### `px_analyzer/kvdb.py` — Smart Signals 12, 13, 14

Sources: `misc/px-kvdb.out`, `var/cores/px_status/<node>-px_etcd_watch-<ts>.log.gz`

```python
KVDB_PATTERNS = {
    "kvdb_out_of_space":    r"mvcc: database space exceeded|ResourceExhausted",
    "kvdb_transport_close": r"grpc.*transport is closing",
    "kvdb_no_endpoint":     r"Failed connect to kvdb instance \(\[\]\)",
    "kvdb_peer_fail":       r"failed to connect to kvdb peer",
    "kvdb_quorum_loss":     r"Node is not in quorum.*port 17002",
}
```

The `px-kvdb.out` shows `Failed connect to kvdb instance ([])` — this is expected for internal kvdb (embedded etcd on the dedicated metadata device `/dev/mapper/...bf7`). Log this as INFO, not an error, and annotate with `note: "internal kvdb mode — pxctl sv dump --kvdb expected to fail"`.

The `px_etcd_watch` logs show `grpc: Server.processUnaryRPC failed to write status: connection error: transport is closing` — map to SS-14.

### `px_analyzer/storage.py` — LOCAL-01 (STATUS_STORAGE_DOWN)

Source: `var/cores/px_status/<node>-px-jrnl-32min-<ts>.log.gz`

```python
STORAGE_PATTERNS = {
    "status_storage_down":  r"STATUS_STORAGE_DOWN",
    "snapshot_io_error":    r"Snapshot.*Failed with status input/output error",
    "kubevirt_vol_missing": r"Failed to get volume info.*not found",
    "kubevirt_label_retry": r"Failed to update Kubevirt volume labels.*retryCount=(\d+)",
}
```

**Critical logic:** If `STATUS_STORAGE_DOWN` and `snapshot I/O error` appear in the same time window (within 5 minutes of each other), emit a **correlated finding** — the snapshots are a downstream symptom, not an independent root cause.

### `px_analyzer/node.py` — Smart Signals 21, 25, 26, 27

Sources: `misc/px-status.out`, `misc/uptime.out`, `misc/memory.out`, `var/lib/osd/log/px_node_stats/`

For SS-21 (flush latency): Parse the timestamped node stats files — each file contains a snapshot of flush metrics. Compute `delta_flush_ms / delta_num_flushes` between consecutive files. Flag if > 700ms for > 15 consecutive minutes (18+ consecutive files if stats are every 30–60s apart).

For SS-25 (missing stats): Check gaps between consecutive stat file timestamps. Gap > 2100 seconds = alert.

### `px_analyzer/license.py` — Smart Signals 19, Invalid License (10231)

Sources: `misc/px-status.out`, `var/cores/px_status/<node>-px-jrnl-32min-<ts>.log.gz`

```python
LICENSE_PATTERNS = {
    "license_expiry_7d":    r"expires in (\d+) days",        # SS-19 fires if < 7
    "license_invalid":      r"INVALID LICENSE",               # SS-10231
    "metering_disabled":    r"Metering: Disabled or Unhealthy",
    "metering_failure":     r"meteringUsageError|callhome.*fail",
    "billing_grace":        r"grace period",
}
```

**From this diag:** License shows `expires in 1289 days` — healthy. `Metering: Disabled or Unhealthy` is present in `px-status.out` — this is a WARNING. Check journal for billing failures. If `Metering: Disabled or Unhealthy` + no journal billing errors → likely telemetry misconfiguration, not license risk.

---

## Part 7 — Output Files

### `cluster_summary.md`

```
Cluster ID:           px-cluster-plnpevipspoke11
Cluster UUID:         b9462820-8db9-4088-9801-563dcc31d237
Node analyzed:        pxpvip1331919.gsm1900.org (192.168.11.113)
PX Version:           3.5.2.0-86e5708
Total nodes:          21 (21 online)
Storage pools:        8 × 19 TiB (raid0, HIGH IO priority)
Storage devices:      8 × 20 TiB Pure FlashArray via FC multipath (all paths healthy)
Metadata device:      /dev/mapper/...bf7 (64 GiB, internal kvdb)
Mgmt iface:           bond0.504
Data iface:           bond1.25
OS:                   RHCOS 418.94.202602022246-0
Kernel:               5.14.0-427.109.1.el9_4.x86_64
Node uptime:          13 days 11h 40m
Memory:               792 GiB total / 715 GiB free
Load average:         3.53 / 4.78 / 4.29
License:              PX-Enterprise Metal Limited (expires 1289 days)
Metering:             Disabled or Unhealthy (investigate)

Health score:         DEGRADED
  CRITICAL: 4 findings
  WARNING:  3 findings
  INFO:     2 findings
```

### `errors.json` — Smart Signal-enriched structured output

```json
[
  {
    "id": "SS-03",
    "smart_signal": "volume_space_low_alerts",
    "alert_code": 10081,
    "alert_type": 30,
    "severity": "CRITICAL",
    "category": "volume_capacity",
    "already_monitored_by_smart_signal": true,
    "schedule": "Daily midnight",
    "audience": "Support",
    "count": 2,
    "first_seen": "2026-04-06T20:52:09Z",
    "cleared": false,
    "volumes": [
      "pvc-d499e662-f8c3-400c-a07a-a9b801ab2b16 (100% full, 0 bytes free)",
      "pvc-d522f0cd-6f10-4fc7-bea0-94c2816578d2 (99% full, 30 MiB free)"
    ],
    "remediation_kb": "https://purestorage.atlassian.net/browse/PWX-41031",
    "source_file": "misc/px-alerts-show.out"
  },
  {
    "id": "LOCAL-01",
    "smart_signal": null,
    "alert_code": null,
    "severity": "CRITICAL",
    "category": "storage",
    "already_monitored_by_smart_signal": false,
    "label": "STATUS_STORAGE_DOWN",
    "count": 28,
    "first_seen": "2026-04-10T05:05:55Z",
    "last_seen": "2026-04-10T05:07:05Z",
    "correlated_with": ["SS-10_snapshot_io_error"],
    "note": "NOT visible to Pure's Smart Signals — only in local diag. Escalate to Portworx TAM with this diag.",
    "source_file": "var/cores/px_status/pxpvip1331919.gsm1900.org-px-jrnl-32min-20260410050706.log.gz"
  },
  {
    "id": "LOCAL-02",
    "smart_signal": null,
    "alert_code": null,
    "alert_type": 11,
    "severity": "CRITICAL",
    "category": "kvdb_quorum",
    "already_monitored_by_smart_signal": false,
    "label": "quorum_loss_alarm_uncleared",
    "note": "SS-13 (kvdb_reduced_node_count) watches live count but does NOT parse historical quorum alarms from alerts-show.out. This is a gap.",
    "affected_nodes": [
      "pxpvip1332216 (2f70591d) — 2026-04-06T18:53:05Z",
      "pxpvip1331718 (dad512b5) — 2026-04-06T19:05:02Z",
      "pxpvip1332018 (00d7e6f8) — 2026-04-06T19:38:25Z"
    ],
    "cleared": false,
    "source_file": "misc/px-alerts-show.out"
  },
  {
    "id": "LOCAL-04",
    "smart_signal": null,
    "alert_code": null,
    "alert_type": 83,
    "severity": "CRITICAL",
    "category": "pool_offline",
    "already_monitored_by_smart_signal": false,
    "label": "pool_offline_alarm",
    "note": "Proposed Smart Signal (per Tom Felczynski in SS doc) — not yet deployed. Found on neighbor node pxpvip1331823 (51feb122). 2026-04-09T18:08:33Z uncleared.",
    "message": "Datapool 1 load failed: failed to access pwx1/pxpool",
    "source_file": "misc/px-alerts-show.out"
  },
  {
    "id": "SS-14",
    "smart_signal": "portworx_kvdb_errors",
    "alert_code": 10042,
    "severity": "WARNING",
    "already_monitored_by_smart_signal": true,
    "schedule": "Every 30 min",
    "pattern_matched": "grpc: Server.processUnaryRPC failed to write status: connection error: transport is closing",
    "count": 3,
    "source_file": "var/cores/px_status/pxpvip1331919.gsm1900.org-px_etcd_watch-20260410040705.log.gz",
    "remediation_kb": "https://kb.purestorage.com/csm?sys_kb_id=96a2c5b12bbda2507b12f6c3d891bf56"
  }
]
```

### `remediation_steps.md`

(Full per-finding runbook — same as v1 but each finding now shows its Smart Signal status)

---

## Part 8 — Smart Signals Gap Analysis (for your cluster)

This is the highest-leverage output of the v2 tool. It tells you what Pure's control plane can already see vs. what's dark.

| Finding | Smart Signal | Already Monitored? | Action |
|---|---|---|---|
| Volume capacity 100% (SS-03) | volume_space_low_alerts (10081) | YES — Daily midnight | Pure support should already know. Check if ticket opened. |
| STATUS_STORAGE_DOWN × 28 | None | **NO — Dark** | Share diag with Portworx TAM. This is invisible to Octillion. |
| Snapshot I/O errors × 12 | snapshot_creation_failure (10095) | Partial — threshold is 1000/week | Only 12 events here — won't trigger Portworx signal. Dark. |
| Quorum loss alerts (alert_type=11) | Partial — SS-13 watches live count | **Mostly Dark** | SS-13 doesn't parse historical `alerts-show` alarms. These 3 uncleared alarms are not visible. |
| kvdb gRPC transport closing | portworx_kvdb_errors (10042) | YES — Every 30 min | Pure monitoring active. |
| kvdb endpoint empty | portworx_kvdb_errors (10042) | YES (internal kvdb expected behavior) | INFO — not an error. |
| Pool offline (alert_type=83) on neighbor node | **Proposed — not deployed** | **NO** | Submit evidence to Portworx team to accelerate SS deployment per Tom Felczynski's request. |
| Metering: Disabled or Unhealthy | Invalid License signal (10231, pending) | Pending deployment | Monitor. If metering stays unhealthy, risk of grace period → read-only. |
| Multipath paths all healthy | N/A | N/A | INFO — no action. |
| License 1289 days remaining | license_expiry_alerts (10068) | YES — but threshold is 7 days | No alert expected. Good. |

---

## Part 9 — Build Sequence

| Day | Deliverable |
|-----|-------------|
| 1–2 | `px_auth.py` + `px_download.py` — validate Fuse2 SSH+SFTP, correct path traversal including kvdb-dump log discovery |
| 3 | `px_extract.py` — clean extraction, path normalization, manifest.json |
| 4 | `px_analyzer/volume.py` — parse all alert_type integers from `px-alerts-show.out`; map to SS-01 through SS-11 |
| 5 | `px_analyzer/kvdb.py` — etcd watch, kvdb.out, quorum alarms |
| 6 | `px_analyzer/storage.py` — STATUS_STORAGE_DOWN, snapshot I/O, correlation logic |
| 7 | `px_analyzer/node.py` + `px_analyzer/capacity.py` + `px_analyzer/license.py` |
| 8 | `px_analyzer/security.py` + `px_analyzer/infrastructure.py` + `px_analyzer/predictive.py` |
| 9 | `px_report.py` — render all three output files with Smart Signal enrichment |
| 10 | Gap analysis section in report — `already_monitored_by_smart_signal` field + gap table |
| 11 | Integration test against this diag + at least 2 other cluster diags |

---

## Part 10 — `requirements.txt`

```
paramiko>=3.4
tqdm>=4.66
pyyaml>=6.0
rich>=13.7
python-dateutil>=2.9
requests>=2.31
```

---

## Part 11 — The Asymmetric Move

The `already_monitored_by_smart_signal` field in `errors.json` is the leverage. Within 3 months of running this tool across your cluster fleet, you will know exactly which failure classes are invisible to Portworx's control plane. That gap list is a concrete deliverable you can hand to the Portworx TAM to accelerate Smart Signal deployment for T-Mobile — specifically:

- `STATUS_STORAGE_DOWN` has no Smart Signal. Your diag has 28 occurrences. That's evidence.
- `alert_type=83` (pool offline) has no deployed Smart Signal yet — Tom Felczynski requested it in the SS doc. Your diag has a live example. Submit it.
- Historical quorum loss alarms (`alert_type=11`) in `px-alerts-show.out` are not covered by SS-13 (which only watches live count). Another gap with live evidence.

Those three gaps, documented with real diag data, are worth more in a TAM meeting than any generic health check script.

---

*Living document — update `patterns/errors.yaml` after every new failure pattern discovered in production. The Smart Signals doc should be re-ingested whenever Portworx adds new signals.*
