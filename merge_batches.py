import pandas as pd

files = ['testing3.csv', 'testing4.csv', 'testing5.csv' , 'testing6.csv']  # list the specific CSVs you want
merged = pd.concat([pd.read_csv(f) for f in files], ignore_index=True)
merged.to_csv('merged.csv', index=False)
print("✅ Merged CSV saved as merged.csv")
