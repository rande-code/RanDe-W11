# RanDe-W11 Feature Guide

## Why This Document Exists

The column names in RanDe-W11 may initially raise questions — particularly the indexed naming pattern (`runtime_0_event_count`, `runtime_1_event_count`, ..., `runtime_19_event_count`) and per-process flags (`proc0_anomalous_pattern_flag`, `proc1_anomalous_pattern_flag`, ...). This guide explains the design rationale, addresses potential data leakage concerns, and defines every feature domain.

---

## The Indexed Column Design: Why Ordered Slots?

Modern ransomware does not act as a single, atomic process. A single executable typically:

- **Spawns multiple child processes** in sequence, each potentially inheriting or escalating privileges
- **Contacts multiple DNS endpoints** as it checks for C2 availability, exfiltrates keys, or downloads payloads
- **Generates runtime events** that evolve in severity over the execution timeline

Any.run's sandbox captures this multi-entity, time-aware behavior as **ordered lists**. Rather than collapsing these into lossy aggregates (e.g., "total severity"), RanDe-W11 preserves the ordering as indexed feature slots. The first DNS endpoint contacted becomes `dns_endpoint_risk_profile_0`, the second becomes `dns_endpoint_risk_profile_1`, and so on up to 10 slots. Unfilled slots receive the value `0`.

**This is not data leakage.** The values in these columns are observations made *during execution* — identical in principle to what a real-time EDR system would capture. No label information is derived from, encoded in, or correlated with the slot index itself. The label columns (`ground_truth_family`, `ground_truth_binary`) are explicitly excluded from all feature matrices in the accompanying code.

The ordering matters because modern ransomware families show distinctive **behavioral trajectories**: LockBit initiates file system operations early with sparse network contact; WannaCry shows sustained high-severity runtime events from tick 0; Conti exhibits a build-up pattern across registry and process domains before file encryption begins. Flattening these to a single scalar would destroy the discriminative signal that separates families with similar aggregate counts.

---

## Why "Anomalous" and "Suspicious" Process Columns Are Not Leakage

Columns such as `proc_anomalous_behavior_count`, `proc0_anomalous_pattern_flag`, and `proc_irregular_activity_count` may appear to encode the answer (i.e., "this process is malicious"). They do not. These values are **sandbox-assigned behavioral tags** based on heuristic rules applied uniformly to all samples — benign and ransomware alike. A benign installer that triggers UAC elevation will receive the same `proc0_privilege_change_behavior = 1` as a ransomware sample performing the same action. The sandbox does not know the label; it reports what it observes.

Furthermore, many benign samples in RanDe-W11 (sourced from SnapFiles and PortableApps.com) trigger these flags legitimately — system utilities, archive managers, and productivity tools regularly spawn child processes, access registry keys, and make DNS queries. The anti-leakage verification in the accompanying code confirms that no column name beyond `ground_truth_family` and `ground_truth_binary` encodes label-derived information.

---

## Feature Domains

### 1. File System (3 features)

| Column | Type | Description |
|---|---|---|
| `fs_modified_file_count` | int | Total number of files modified during execution |
| `fs_modified_file_avg_size_bytes` | float | Mean size (bytes) of modified files |
| `fs_modified_file_max_size_bytes` | int | Maximum size (bytes) of a single modified file |

Ransomware typically modifies large numbers of files (encryption) with characteristic size distributions. Benign software modifies fewer files with more varied sizes.

---

### 2. Registry (4 features)

| Column | Type | Description |
|---|---|---|
| `reg_ops_total` | int | Total registry operations |
| `reg_ops_read` | int | Registry read operations |
| `reg_ops_write` | int | Registry write operations |
| `reg_ops_delete` | int | Registry delete operations |

Ransomware frequently writes persistence keys, modifies run entries, and deletes shadow copy references via registry operations. The ratio of write/delete to read is a discriminative signal.

---

### 3. Network (3 features)

| Column | Type | Description |
|---|---|---|
| `net_http_request_count` | int | HTTP/HTTPS requests made during execution |
| `net_dns_query_count` | int | DNS queries issued |
| `net_connection_count` | int | Total network connections established |

Network behavior separates ransomware strains: some (WannaCry) make extensive connection attempts for propagation; others (offline encryptors) show near-zero network activity.

---

### 4. Process Counts (4 features)

| Column | Type | Description |
|---|---|---|
| `proc_runtime_total_count` | int | Total processes spawned during execution |
| `proc_runtime_monitored_count` | int | Processes actively monitored by sandbox |
| `proc_anomalous_behavior_count` | int | Processes flagged for anomalous behavior patterns |
| `proc_irregular_activity_count` | int | Processes showing irregular activity sequences |

The distinction between monitored vs. anomalous captures LOLBin-style evasion: ransomware that delegates operations to legitimate system binaries (e.g., `cmd.exe`, `vssadmin.exe`) inflates monitored count while keeping its own process profile low.

---

### 5. API / DLL (4 features)

| Column | Type | Description |
|---|---|---|
| `api_category_count` | int | Number of distinct API categories invoked |
| `api_call_total` | int | Total API calls made |
| `api_dll_load_count` | int | Number of DLLs loaded |
| `api_file_drop_count` | int | Files dropped via API calls |

API diversity (`api_category_count`) is a strong signal: ransomware uses cryptographic, file I/O, and registry APIs in combination. Benign software typically concentrates in fewer categories.

---

### 6. Runtime Event Severity (20 features)

| Column Pattern | Type | Description |
|---|---|---|
| `runtime_N_event_severity` (N = 0–19) | float | Mean event severity at sandbox execution tick N |

These 20 slots capture the **temporal severity trajectory** of sandbox events across 20 ordered execution ticks. Each tick represents a checkpoint in the sandbox timeline. The sequence reveals how aggressive a sample's behavior escalates over time — a distinctive signature for ransomware that front-loads destructive operations vs. those that delay activation.

---

### 7. Runtime Event Count (20 features)

| Column Pattern | Type | Description |
|---|---|---|
| `runtime_N_event_count` (N = 0–19) | int | Event count at sandbox execution tick N |

Paired with severity, the count sequence shows whether high-severity behavior is concentrated (burst pattern, typical of crypto-ransomware) or distributed (sustained pattern, typical of worm-propagating strains like WannaCry).

---

### 8. DNS Reputation Profiles (10 features)

| Column Pattern | Type | Description |
|---|---|---|
| `dns_endpoint_risk_profile_N` (N = 0–9) | int | Risk profile score of the Nth contacted DNS endpoint |

Each slot records the reputation score of a DNS endpoint contacted during execution, in the order they were first contacted. Ransomware C2 domains consistently show elevated risk profiles (scores 3–5) while benign software primarily contacts known-good infrastructure (score 0). Up to 10 endpoints are captured; slots beyond the actual contact count are filled with 0.

---

### 9. Process Flags (35 features — 7 flags × 5 processes)

Per-process behavioral flags are recorded for up to 5 processes observed during execution. Each flag captures a specific behavioral property:

| Flag Suffix | Description |
|---|---|
| `_autostart_behavior` | Process registers or modifies autostart entries |
| `_anomalous_pattern_flag` | Sandbox detected anomalous behavioral pattern |
| `_data_access_behavior` | Process performs unusual data access operations |
| `_file_drop_behavior` | Process drops files to disk |
| `_network_activity_flag` | Process initiates network connections |
| `_debug_output_flag` | Process produces debug output (evasion indicator) |
| `_privilege_change_behavior` | Process attempts privilege escalation |

Columns follow the pattern `procN_flag_name` where N = 0–4 (0 = primary observed process). All values are binary (0/1) except where the sandbox assigns a categorical score.

---

## Label Columns

| Column | Values | Description |
|---|---|---|
| `ground_truth_family` | 31 string values | Ransomware family name, or `"Benign"` for goodware |
| `ground_truth_binary` | 0, 1 | Binary label: `0` = Benign, `1` = Ransomware |

These two columns must be excluded from all feature matrices. The accompanying code enforces this via `LABEL_COLS = ["ground_truth_family", "ground_truth_binary"]` with a secondary keyword-scan leakage check.

---

## Sample Validation (Anti-Leakage)

Each ransomware sample was retained only if it satisfied three VirusTotal criteria: (i) detection as malicious by ≥ 45 antivirus engines, (ii) explicit ransomware identification by ≥ 15 engines, and (iii) majority agreement on family classification. Benign samples were sourced from SnapFiles, PortableApps.com, and GitHub — established, community-vetted repositories. VirusTotal metadata were used only for ransomware curation and family-label verification, not for benign labeling, and no VirusTotal-derived values entered the feature space.

The `ground_truth_binary` label is derived from these external validation criteria — not from any behavioral feature in the dataset. No circular labeling exists.
