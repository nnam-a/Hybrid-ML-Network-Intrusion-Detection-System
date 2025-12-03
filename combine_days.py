import pandas as pd

# List all CSV files
files = [
    "monday_clean.csv",
    "Tuesday-WorkingHours_with_labels_2.csv",
    "Wednesday-WorkingHours_with_labels.csv",
    "Thursday-WorkingHours_with_labels_2.csv",
]

dfs = []
for f in files:
    df = pd.read_csv(f)
    df.columns = df.columns.str.strip()
    dfs.append(df)

full_df = pd.concat(dfs, ignore_index=True)
print(f"Total flows: {len(full_df):,}")

# Save
full_df.to_csv("cic_ids_2017_missing.csv", index=False)
print("Saved: cic_ids_2017_missing.csv")