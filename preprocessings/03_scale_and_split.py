# =============================================================================
# RanDe-W11 | Step 3: Feature Scaling and Cross-Validation Setup (Stage 3)
# =============================================================================
# Implements Stage 3 of the three-stage anti-leakage verification (paper
# Section 3.5): preprocessing-leakage prevention via fold-safe scaling, and
# sets up the unified 5-fold stratified CV protocol used in all experiments.
#
#   StandardScaler (zero mean, unit variance) : all classifier evaluations
#   RobustScaler   (median centering, IQR)    : behavioral radar fingerprints
#                                                only (outlier-resistant)
#
# Scaler-fitting protocol:
#   The full-dataset fits below are for inspection / verification ONLY and are
#   NOT used to report benchmark results. In the experimental pipeline, scaling
#   is applied STRICTLY inside each CV fold - the scaler is fit on the training
#   partition and applied to the test partition without refitting - so that no
#   test-set distributional statistics influence the scaling parameters across
#   folds. The per-fold demonstration at the end reproduces this protocol.
#
# Two stratified splits are configured, matching the two benchmark tasks:
#   Task I  - binary detection : stratified on ground_truth_binary
#   Task II - 31-class family  : stratified on ground_truth_family
# Both use shuffle=True, random_state=42. Splits requiring more members per
# class than are available (e.g. on the 10-row schema preview) are skipped
# with a note rather than raising.
#
# Input : RanDe_W11_dataset_final.csv  (falls back to dataset/sample_preview.csv
#         so the setup is runnable directly from the public repository)
# Output: console report (no file written)
# =============================================================================

import os
import sys
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.model_selection import StratifiedKFold

LABEL_COLS = ['ground_truth_family', 'ground_truth_binary']
MAX_SPLITS = 5
SEED       = 42

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

FEAT_COLS = [c for c in df.columns if c not in LABEL_COLS]
X   = df[FEAT_COLS].values.astype(float)
y   = df['ground_truth_binary'].values
y_f = df['ground_truth_family'].values

print(f"Loaded  : {src}" + ("   [schema preview]" if using_preview else ""))
print(f"Shape   : {df.shape}  |  Features: {len(FEAT_COLS)}")
print(f"Classes : binary={int((y==1).sum())} ransomware / {int((y==0).sum())} benign  "
      f"|  families={len(np.unique(y_f))}\n")

# --- StandardScaler (full-dataset fit - inspection only) ---
scaler = StandardScaler()
X_sc   = scaler.fit_transform(X)
print(f"StandardScaler applied (full-dataset fit - inspection only).")
print(f"  Mean range  : [{X_sc.mean(axis=0).min():.4f}, {X_sc.mean(axis=0).max():.4f}]")
print(f"  Std range   : [{X_sc.std(axis=0).min():.4f},  {X_sc.std(axis=0).max():.4f}]\n")

# --- RobustScaler (full-dataset fit - inspection only) ---
rob_scaler = RobustScaler()
X_rb       = rob_scaler.fit_transform(X)
print(f"RobustScaler applied (IQR-based, outlier-resistant - inspection only).")
print(f"  Median range: [{np.median(X_rb, axis=0).min():.4f}, "
      f"{np.median(X_rb, axis=0).max():.4f}]\n")


def make_skf(labels, max_splits=MAX_SPLITS, seed=SEED):
    """Return a StratifiedKFold sized to the data, or None if even 2-fold
    stratification is infeasible (smallest class < 2)."""
    min_count = int(pd.Series(labels).value_counts().min())
    if min_count < 2:
        return None, min_count, None
    k = min(max_splits, min_count)
    return StratifiedKFold(n_splits=k, shuffle=True, random_state=seed), min_count, k


def list_folds(skf, X, labels, title):
    print(f"{title}")
    print(f"  {'Fold':<6} {'Train':>8} {'Test':>8}")
    print("  " + "-" * 24)
    for i, (tr, te) in enumerate(skf.split(X, labels), 1):
        print(f"  {i:<6} {len(tr):>8} {len(te):>8}")
    print()


# --- Task I: binary-stratified CV ---
skf_bin, min_bin, k_bin = make_skf(y)
if skf_bin is not None:
    list_folds(skf_bin, X, y,
               f"Task I  - binary detection: {k_bin}-fold stratified CV (random_state={SEED})")
else:
    print(f"Task I  - binary detection: skipped (smallest class has {min_bin} "
          f"sample(s); needs >= 2 for stratified CV).\n")

# --- Task II: family-stratified CV ---
skf_fam, min_fam, k_fam = make_skf(y_f)
if skf_fam is not None:
    list_folds(skf_fam, X, y_f,
               f"Task II - 31-class family attribution: {k_fam}-fold stratified CV "
               f"(random_state={SEED})")
else:
    print(f"Task II - 31-class family attribution: skipped (smallest family has "
          f"{min_fam} sample(s); needs >= 2 for stratified CV).")
    print(f"          The 10-row schema preview cannot support family-stratified "
          f"folds; use the full dataset.\n")

# --- Stage 3: fold-safe scaling demonstration ---
# Reproduces the exact protocol used in every experiment: within each fold the
# scaler is fit on the TRAIN partition only and applied to the TEST partition
# without refitting, so no test-set statistics leak into training across folds.
demo_skf, demo_labels, demo_name = (
    (skf_bin, y, "binary") if skf_bin is not None
    else (skf_fam, y_f, "family") if skf_fam is not None
    else (None, None, None)
)
if demo_skf is not None:
    print(f"Fold-safe scaling check on the {demo_name} split "
          f"(fit on train, transform test - no refit):")
    for k, (tr_idx, te_idx) in enumerate(demo_skf.split(X, demo_labels), 1):
        fold_scaler = StandardScaler().fit(X[tr_idx])      # fit on TRAIN only
        _train = fold_scaler.transform(X[tr_idx])
        _test  = fold_scaler.transform(X[te_idx])          # transform TEST, no refit
        print(f"  Fold {k}: scaler fit on {len(tr_idx)} train rows, "
              f"applied to {len(te_idx)} test rows (no refit)")
else:
    print("Fold-safe scaling check: skipped (no feasible stratified split on this "
          "input; use the full dataset).")

print(f"\n  Unified protocol applied to: binary classification, multiclass")
print(f"  classification, learning curves, and group ablation experiments.\n")
print("Setup verified. Proceed to experimental pipeline.")
print("Reminder: scalers are fit inside each fold in the full pipeline.")
