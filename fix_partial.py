#!/usr/bin/env python3
"""
Fix partial scans by intelligently filling missing values
"""

import pandas as pd
import numpy as np

def fix_partial_scans(input_csv, output_csv):
    """
    Fill missing values for partial scans using intelligent strategies
    """
    df = pd.read_csv(input_csv)
    
    print("="*70)
    print("🔧 FIXING PARTIAL SCANS")
    print("="*70)
    print(f"\nOriginal dataset:")
    print(f"  Total rows: {len(df)}")
    print(f"  Partial scans: {len(df[df['scan_status'] == 'partial'])}")
    print(f"  Success scans: {len(df[df['scan_status'] == 'success'])}")
    
    # Count nulls before
    null_counts_before = df.isnull().sum()
    print(f"\n📊 Null values before fix:")
    for col, count in null_counts_before.items():
        if count > 0:
            print(f"  {col}: {count} ({count/len(df)*100:.1f}%)")
    
    # Strategy 1: Fill based on label (safe vs risky)
    # For risky images (label=1), use conservative estimates
    # For safe images (label=0), use optimistic estimates
    
    for idx, row in df.iterrows():
        if row['scan_status'] != 'partial':
            continue
        
        label = row['label']
        
        # Mining pools: risky=1, safe=0
        if pd.isna(row['mining_pools']):
            df.at[idx, 'mining_pools'] = 1.0 if label == 1 else 0.0
        
        # Hardcoded secrets: risky=1, safe=0
        if pd.isna(row['hardcoded_secrets']):
            df.at[idx, 'hardcoded_secrets'] = 1.0 if label == 1 else 0.0
        
        # External calls: risky=1, safe=0
        if pd.isna(row['external_calls']):
            df.at[idx, 'external_calls'] = 1.0 if label == 1 else 0.0
        
        # Runs as root: assume 1 (most images run as root)
        if pd.isna(row['runs_as_root']):
            df.at[idx, 'runs_as_root'] = 1.0
        
        # Known CVEs: risky=high, safe=low
        if pd.isna(row['known_cves']):
            df.at[idx, 'known_cves'] = 30.0 if label == 1 else 5.0
        
        # Outdated base: risky=1, safe=0
        if pd.isna(row['outdated_base']):
            df.at[idx, 'outdated_base'] = 1.0 if label == 1 else 0.0
        
        # Typosquatting score: use median from successful scans
        if pd.isna(row['typosquatting_score']):
            median_typo = df[df['scan_status'] == 'success']['typosquatting_score'].median()
            df.at[idx, 'typosquatting_score'] = median_typo
        
        # Image age: use median from successful scans by label
        if pd.isna(row['image_age_days']):
            same_label_ages = df[(df['scan_status'] == 'success') & (df['label'] == label)]['image_age_days']
            if len(same_label_ages) > 0:
                df.at[idx, 'image_age_days'] = same_label_ages.median()
            else:
                df.at[idx, 'image_age_days'] = 365.0  # 1 year default
        
        # Suspicious ports: risky=3, safe=2
        if pd.isna(row['suspicious_ports']):
            df.at[idx, 'suspicious_ports'] = 3.0 if label == 1 else 2.0
    
    # Strategy 2: Fill remaining nulls with column median/mode
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    for col in numeric_cols:
        if col in ['label', 'confidence_score']:
            continue
        
        if df[col].isnull().any():
            # Use median for numeric features
            median_val = df[col].median()
            df[col].fillna(median_val, inplace=True)
            print(f"  Filled {col} with median: {median_val}")
    
    # Update scan_status for fixed partial scans
    df.loc[df['scan_status'] == 'partial', 'scan_status'] = 'imputed'
    
    # Update confidence scores for imputed rows (lower confidence)
    df.loc[df['scan_status'] == 'imputed', 'confidence_score'] = 0.75
    
    # Count nulls after
    null_counts_after = df.isnull().sum()
    print(f"\n📊 Null values after fix:")
    remaining_nulls = False
    for col, count in null_counts_after.items():
        if count > 0:
            print(f"  {col}: {count} ({count/len(df)*100:.1f}%)")
            remaining_nulls = True
    
    if not remaining_nulls:
        print("  ✅ No null values remaining!")
    
    # Save fixed dataset
    df.to_csv(output_csv, index=False)
    
    print(f"\n💾 Fixed dataset saved to: {output_csv}")
    print(f"\n📊 Final dataset stats:")
    print(f"  Total rows: {len(df)}")
    print(f"  Success: {len(df[df['scan_status'] == 'success'])}")
    print(f"  Imputed: {len(df[df['scan_status'] == 'imputed'])}")
    print(f"\n📈 Label distribution:")
    print(f"  Safe (0): {len(df[df['label'] == 0])}")
    print(f"  Risky (1): {len(df[df['label'] == 1])}")
    
    # Show sample of imputed rows
    imputed_df = df[df['scan_status'] == 'imputed']
    if len(imputed_df) > 0:
        print(f"\n📋 Sample of imputed rows:")
        print(imputed_df[['image_name', 'label', 'known_cves', 'runs_as_root', 'confidence_score']].head(10))
    
    return df

if __name__ == "__main__":
    input_file = 'data/all_docker_features.csv'
    output_file = 'data/docker_features_fixed.csv'
    
    df = fix_partial_scans(input_file, output_file)
    
    print("\n" + "="*70)
    print("✅ FIXING COMPLETE!")
    print("="*70)
    print(f"\nYou can now use: {output_file}")
    print("\nNext steps:")
    print("  1. Review the imputed values")
    print("  2. Use docker_features_fixed.csv for ML training")
    print("  3. Consider removing low-confidence rows if needed")