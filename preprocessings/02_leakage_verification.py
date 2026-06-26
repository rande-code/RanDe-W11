# =============================================================================
# RanDe-W11 | Step 2: Data Leakage Verification (Stages 1-2)
# =============================================================================
# Implements Stages 1 and 2 of the three-stage anti-leakage verification
# described in the paper (Section 3.5). Stage 3 (fold-safe scaling) is in
# 03_scale_and_split.py.
#
#   Stage 1 - Authoritative label exclusion:
#             ground_truth_family and ground_truth_binary are held out of the
#             feature matrix X by construction, so no label information can
#             cross the feature-target boundary.
#
#   Stage 2 - Keyword scan:
#             every remaining column name is scanned with an expanded leakage
#             keyword list to detect residual target proxies or sandbox-verdict
#             fields beyond the declared label columns. The two verdict fields
#             (threat_level, verdict_score) are already removed in step 01, so
#             this scan re-confirms their absence and flags anything else for
#             manual review. Behaviorally meaningful observations (e.g.
#             proc_anomalous_*) are retained because their values are runtime
#             telemetry, not class labels.
#
# Input : RanDe_W11_dataset_final.csv  (falls back to dataset/sample_preview.csv
#         so the check is runnable directly from the public repository)
# Output: console report (no file written). Exits non-zero if a sandbox-verdict
#         field survived into the feature space (enforced leakage gate).
# =============================================================================

import os
import sys
import pandas as pd

EXPECTED_FEATURES = 103
LABEL_COLS        = ['ground_truth_family', 'ground_truth_binary']
VERDICT_COLS      = ['threat_level', 'verdict_score']

# --- Resolve input (released file first, then schema preview) ---
CANDIDATES = [
    'RanDe_W11_dataset_final.csv',
    'dataset/sample_preview.csv',
    '../dataset/sample_preview.csv',
    'sample_preview.csv',
]
src = next((p for p in CANDIDATES if os.path.exists(p)), None)
if src is None:
    sys.exit("ERROR: no input found. Expected RanDe_W11_dataset_final.csv or "
             "dataset/sample_preview.csv.")

df = pd.read_csv(src)
using_preview = 'sample_preview' in src
print(f"Loaded  : {src}  |  Shape: {df.shape}"
      + ("   [schema preview]" if using_preview else ""))

# --- Stage 1: Authoritative label exclusion ---
FEAT_COLS = [c for c in df.columns if c not in LABEL_COLS]
X = df[FEAT_COLS].values
y = df['ground_truth_binary'].values

print(f"\n[Stage 1] Authoritative label exclusion")
print(f"  Feature matrix X : {X.shape}")
print(f"  Label vector y   : {y.shape}")
print(f"  Label cols excluded from X : {LABEL_COLS}")

# --- Stage 2: Keyword scan ---
# Expanded leakage keyword list (set matches paper Section 3.5 / Algorithm 1):
#   'truth', 'ground'                 -> ground_truth_* label columns
#   'binary','label','class','target' -> generic label naming patterns
#   'family'                          -> ground_truth_family / residual family col
#   'verdict'                         -> verdict_score (removed in step 01; re-checked)
#   'threat'                          -> threat_level  (removed in step 01; re-checked)
#   'malicious','suspicious'          -> sandbox judgment tags flagged for manual
#                                        review (NOT auto-excluded: proc_anomalous_*
#                                        and similar are valid behavioral features
#                                        when their values are sandbox observations,
#                                        not label derivatives)
LEAKAGE_KEYWORDS = [
    'truth',
    'ground',
    'binary',
    'label',
    'class',
    'target',
    'family',
    'verdict',
    'threat',
    'malicious',
    'suspicious',
]

leakage_flagged = [c for c in df.columns
                   if any(kw in c.lower() for kw in LEAKAGE_KEYWORDS)]
extra_leakage   = [c for c in leakage_flagged if c not in LABEL_COLS]

print(f"\n[Stage 2] Keyword scan")
print(f"  Columns flagged by keyword scan : {leakage_flagged}")
print(f"  (label columns above are expected and already excluded in Stage 1)")

if extra_leakage:
    print(f"\n  *** WARNING - potential leakage columns beyond LABEL_COLS detected:")
    for col in extra_leakage:
        print(f"      - {col}")
    print(f"  Exclude any sandbox-verdict or label-semantic column before use.")
    print(f"  Retain behavioral tags (e.g. proc_anomalous_*) only after manual")
    print(f"  confirmation that their values are runtime telemetry. ***")
else:
    print(f"  [OK] No leakage columns beyond LABEL_COLS.")
    print(f"  Feature matrix is clean for modelling.")

# --- Enforced gate: verdict fields must NOT survive into the feature space ---
survived = [c for c in VERDICT_COLS if c in FEAT_COLS]
if survived:
    sys.exit(f"\nLEAKAGE GATE FAILED: verdict field(s) {survived} present in the "
             f"feature matrix. Re-run 01_encode_boolean_features.py to remove them.")
print(f"  [gate] Verdict fields {VERDICT_COLS} confirmed absent from features.")

# --- Feature-count check (advisory on the preview, strict on the full file) ---
if len(FEAT_COLS) == EXPECTED_FEATURES:
    print(f"  [gate] Feature count = {EXPECTED_FEATURES} as expected.")
elif using_preview:
    print(f"  [note] Feature count = {len(FEAT_COLS)} (preview should also be "
          f"{EXPECTED_FEATURES}; check the preview if this differs).")
else:
    sys.exit(f"\nFEATURE-COUNT GATE FAILED: expected {EXPECTED_FEATURES} features, "
             f"found {len(FEAT_COLS)}.")
