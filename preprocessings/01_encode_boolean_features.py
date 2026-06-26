# =============================================================================
# RanDe-W11 | Step 1: Verdict-Field Removal and Boolean Feature Encoding
# =============================================================================
# Prepares the raw ANY.RUN sandbox export for machine learning by (1) removing
# the two sandbox verdict fields and (2) converting string booleans to integers.
#
# Pipeline (paper Section 3.5 / Algorithm 1, line 17):
#   audit TRUE/FALSE  ->  drop verdict fields (105 -> 103)  ->  encode  ->  save
#
# The verdict fields (threat_level, verdict_score) encode ANY.RUN's own
# maliciousness assessment rather than runtime behavior, so they are excluded
# from the predictive feature space. Removing them reduces the initial
# 105-column feature extraction to the final 103-feature behavioral matrix.
#
# Input : anyrun_sandbox_export_raw.csv   (raw merged ANY.RUN export:
#                                           105 feature columns + 2 label columns)
# Output: RanDe_W11_dataset_final.csv     (103 behavioral features + 2 label
#                                           columns, numerically encoded, ML-ready)
# =============================================================================

import pandas as pd

# --- Load ---
df = pd.read_csv('anyrun_sandbox_export_raw.csv')
print(f"Loaded  : anyrun_sandbox_export_raw.csv  |  Shape: {df.shape}")

# --- Pre-encoding audit (confirm exact count of each string literal) ---
true_count  = (df == 'TRUE').sum().sum()
false_count = (df == 'FALSE').sum().sum()
print(f"\nPre-encoding audit:")
print(f"  'TRUE'  values found : {true_count}")
print(f"  'FALSE' values found : {false_count}")

# --- Remove sandbox verdict fields (105 -> 103) ---
# threat_level and verdict_score are ANY.RUN's own maliciousness verdict, not
# behavioral observations, and are excluded from the predictive feature space.
VERDICT_COLS    = ['threat_level', 'verdict_score']
present_verdict = [c for c in VERDICT_COLS if c in df.columns]
df = df.drop(columns=present_verdict, errors='ignore')
print(f"\nVerdict fields removed : {present_verdict if present_verdict else 'none present'}")
print(f"  Shape after removal  : {df.shape}")

# --- Encode string booleans (TRUE -> 1, FALSE -> 0) across all columns ---
df_encoded = df.replace({'TRUE': 1, 'FALSE': 0})

# --- Save ---
df_encoded.to_csv('RanDe_W11_dataset_final.csv', index=False)

print(f"\nEncoding complete.")
print(f"  'TRUE'  -> 1 : {true_count} replacements")
print(f"  'FALSE' -> 0 : {false_count} replacements")
print(f"Output  : RanDe_W11_dataset_final.csv  |  Shape: {df_encoded.shape}")
