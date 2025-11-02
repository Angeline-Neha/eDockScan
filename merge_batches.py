import pandas as pd
import glob

# Find all batch CSV files
csv_files = sorted(glob.glob('data/batch*.csv'))
print(f"Found {len(csv_files)} batch files:")
for f in csv_files:
    print(f"  - {f}")

# Read and combine all CSVs
dfs = [pd.read_csv(f) for f in csv_files]
final_df = pd.concat(dfs, ignore_index=True)

# Save merged file
output_file = 'data/all_docker_features.csv'
final_df.to_csv(output_file, index=False)

print(f"\n✅ Merged successfully!")
print(f"📊 Total images: {len(final_df)}")
print(f"   Safe (label=0): {len(final_df[final_df['label']==0])}")
print(f"   Risky (label=1): {len(final_df[final_df['label']==1])}")
print(f"💾 Output: {output_file}")
