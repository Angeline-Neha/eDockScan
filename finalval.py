#!/usr/bin/env python3
"""
Merge Real and Synthetic Docker Security Datasets with Validation
"""

import pandas as pd
import numpy as np
import os
from datetime import datetime
import json

def analyze_dataset(df, name):
    """Analyze a dataset and return statistics"""
    print(f"\n{'='*70}")
    print(f"📊 {name} Dataset Analysis")
    print(f"{'='*70}")
    
    print(f"\n📐 Shape: {df.shape[0]} rows × {df.shape[1]} columns")
    
    # Class distribution
    if 'label' in df.columns:
        label_counts = df['label'].value_counts()
        print(f"\n🏷️  Class Distribution:")
        print(f"   Safe (label=0):  {label_counts.get(0, 0):4d} ({label_counts.get(0, 0)/len(df)*100:.1f}%)")
        print(f"   Risky (label=1): {label_counts.get(1, 0):4d} ({label_counts.get(1, 0)/len(df)*100:.1f}%)")
        
        if len(label_counts) == 2:
            imbalance = label_counts.max() / label_counts.min()
            print(f"   Imbalance ratio: {imbalance:.2f}:1")
    
    # Missing values
    missing = df.isnull().sum()
    if missing.sum() > 0:
        print(f"\n⚠️  Missing Values:")
        for col, count in missing[missing > 0].items():
            pct = count / len(df) * 100
            print(f"   {col}: {count} ({pct:.1f}%)")
    else:
        print(f"\n✅ No missing values")
    
    # Feature statistics
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    numeric_cols = [col for col in numeric_cols if col != 'label']
    
    if len(numeric_cols) > 0:
        print(f"\n📈 Feature Statistics (numeric):")
        stats = df[numeric_cols].describe().loc[['mean', 'std', 'min', 'max']]
        print(stats.to_string())
    
    # Check for duplicates
    dupes = df.duplicated().sum()
    if dupes > 0:
        print(f"\n⚠️  Duplicates: {dupes} rows")
    else:
        print(f"\n✅ No duplicate rows")
    
    return {
        'rows': len(df),
        'cols': len(df.columns),
        'class_0': label_counts.get(0, 0) if 'label' in df.columns else 0,
        'class_1': label_counts.get(1, 0) if 'label' in df.columns else 0,
        'missing_total': missing.sum(),
        'duplicates': dupes
    }

def validate_compatibility(df1, df2, name1, name2):
    """Check if two datasets can be safely merged"""
    print(f"\n{'='*70}")
    print(f"🔍 Compatibility Check: {name1} vs {name2}")
    print(f"{'='*70}")
    
    issues = []
    warnings = []
    
    # Check columns
    cols1 = set(df1.columns)
    cols2 = set(df2.columns)
    
    if cols1 != cols2:
        missing_in_2 = cols1 - cols2
        missing_in_1 = cols2 - cols1
        
        if missing_in_2:
            issues.append(f"Columns in {name1} but not {name2}: {missing_in_2}")
        if missing_in_1:
            issues.append(f"Columns in {name2} but not {name1}: {missing_in_1}")
    else:
        print("✅ Column names match")
    
    # Check column order
    if list(df1.columns) != list(df2.columns):
        warnings.append(f"Column order differs between datasets")
        print("⚠️  Column order differs")
    else:
        print("✅ Column order matches")
    
    # Check data types
    common_cols = list(cols1 & cols2)
    type_mismatches = []
    
    for col in common_cols:
        if df1[col].dtype != df2[col].dtype:
            type_mismatches.append(f"{col}: {df1[col].dtype} vs {df2[col].dtype}")
    
    if type_mismatches:
        warnings.append(f"Data type mismatches: {type_mismatches}")
        print(f"⚠️  Data type differences in {len(type_mismatches)} columns")
    else:
        print("✅ Data types match")
    
    # Check value ranges
    numeric_cols = [col for col in common_cols if col != 'label' and 
                    pd.api.types.is_numeric_dtype(df1[col]) and 
                    pd.api.types.is_numeric_dtype(df2[col])]
    
    range_issues = []
    for col in numeric_cols:
        range1 = (df1[col].min(), df1[col].max())
        range2 = (df2[col].min(), df2[col].max())
        
        # Check if ranges are vastly different
        if range1[1] > 0 and range2[1] > 0:
            ratio = max(range1[1], range2[1]) / min(range1[1], range2[1])
            if ratio > 10:  # More than 10x difference
                range_issues.append(f"{col}: {range1} vs {range2}")
    
    if range_issues:
        warnings.append(f"Large range differences: {range_issues[:3]}")
        print(f"⚠️  Large value range differences in {len(range_issues)} features")
    
    return issues, warnings

def clean_dataframe(df, name):
    """Clean and standardize a dataframe"""
    print(f"\n🧹 Cleaning {name} dataset...")
    
    df_clean = df.copy()
    changes = []
    
    # Round float columns to reasonable precision (3 decimals)
    numeric_cols = df_clean.select_dtypes(include=[np.number]).columns
    for col in numeric_cols:
        if col != 'label':
            df_clean[col] = df_clean[col].round(3)
            changes.append(f"Rounded {col} to 3 decimals")
    
    # Ensure label is integer
    if 'label' in df_clean.columns:
        df_clean['label'] = df_clean['label'].astype(int)
        changes.append("Converted label to integer")
    
    # Remove duplicates
    dupes_before = df_clean.duplicated().sum()
    if dupes_before > 0:
        df_clean = df_clean.drop_duplicates()
        changes.append(f"Removed {dupes_before} duplicate rows")
    
    # Fill NaN with 0 (if any)
    nan_count = df_clean.isnull().sum().sum()
    if nan_count > 0:
        df_clean = df_clean.fillna(0)
        changes.append(f"Filled {nan_count} NaN values with 0")
    
    print(f"   Applied {len(changes)} cleaning operations")
    for change in changes[:5]:  # Show first 5
        print(f"   - {change}")
    
    return df_clean

def merge_datasets(df1, df2, name1, name2, strategy='concat'):
    """Merge two datasets with specified strategy"""
    print(f"\n{'='*70}")
    print(f"🔗 Merging Datasets: {name1} + {name2}")
    print(f"{'='*70}")
    
    if strategy == 'concat':
        # Simple concatenation
        merged = pd.concat([df1, df2], ignore_index=True)
        print(f"✅ Concatenated datasets (simple append)")
    
    elif strategy == 'balanced':
        # Balance the classes
        min_class = min(
            len(df1[df1['label']==0]) + len(df2[df2['label']==0]),
            len(df1[df1['label']==1]) + len(df2[df2['label']==1])
        )
        
        # Combine both datasets first
        merged_temp = pd.concat([df1, df2], ignore_index=True)
        
        # Sample to balance
        class_0 = merged_temp[merged_temp['label']==0].sample(n=min_class, random_state=42)
        class_1 = merged_temp[merged_temp['label']==1].sample(n=min_class, random_state=42)
        
        merged = pd.concat([class_0, class_1], ignore_index=True)
        merged = merged.sample(frac=1, random_state=42).reset_index(drop=True)  # Shuffle
        
        print(f"✅ Balanced classes to {min_class} samples each")
    
    elif strategy == 'stratified':
        # Maintain original proportions but combine
        merged = pd.concat([df1, df2], ignore_index=True)
        merged = merged.sample(frac=1, random_state=42).reset_index(drop=True)  # Shuffle
        print(f"✅ Merged with stratified shuffling")
    
    print(f"\n📊 Merged Dataset:")
    print(f"   Total rows: {len(merged)}")
    print(f"   From {name1}: {len(df1)} rows")
    print(f"   From {name2}: {len(df2)} rows")
    
    return merged

def save_merged_dataset(df, output_path, metadata):
    """Save merged dataset with metadata"""
    print(f"\n{'='*70}")
    print(f"💾 Saving Merged Dataset")
    print(f"{'='*70}")
    
    # Create output directory
    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
    
    # Save CSV
    df.to_csv(output_path, index=False)
    print(f"✅ Saved CSV: {output_path}")
    
    # Save metadata
    metadata_path = output_path.replace('.csv', '_metadata.json')
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)
    print(f"✅ Saved metadata: {metadata_path}")
    
    # Save summary stats
    summary_path = output_path.replace('.csv', '_summary.txt')
    with open(summary_path, 'w') as f:
        f.write(f"Merged Dataset Summary\n")
        f.write(f"{'='*70}\n\n")
        f.write(f"Created: {metadata['merge_timestamp']}\n")
        f.write(f"Total rows: {len(df)}\n")
        f.write(f"Total columns: {len(df.columns)}\n\n")
        f.write(f"Class Distribution:\n")
        label_counts = df['label'].value_counts()
        f.write(f"  Safe (0):  {label_counts.get(0, 0)}\n")
        f.write(f"  Risky (1): {label_counts.get(1, 0)}\n\n")
        f.write(f"Feature Statistics:\n")
        f.write(df.describe().to_string())
    print(f"✅ Saved summary: {summary_path}")
    
    print(f"\n{'='*70}")
    print(f"✅ MERGE COMPLETE")
    print(f"{'='*70}")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Merge real and synthetic Docker security datasets',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic merge with default paths
  python merge_and_validate_datasets.py
  
  # Specify custom paths
  python merge_and_validate_datasets.py --real data/real.csv --synthetic data/synthetic.csv
  
  # Save to custom output
  python merge_and_validate_datasets.py --output data/merged_balanced.csv --strategy balanced
  
  # Different merge strategies
  python merge_and_validate_datasets.py --strategy concat      # Simple append
  python merge_and_validate_datasets.py --strategy balanced    # Balance classes
  python merge_and_validate_datasets.py --strategy stratified  # Shuffle only
        """
    )
    
    parser.add_argument('--real', default='merged.csv',
                        help='Path to real dataset CSV')
    parser.add_argument('--synthetic', default='synthetic_features.csv',
                        help='Path to synthetic dataset CSV')
    parser.add_argument('--output', default='data/merged_docker_features.csv',
                        help='Output path for merged CSV')
    parser.add_argument('--strategy', choices=['concat', 'balanced', 'stratified'],
                        default='stratified',
                        help='Merge strategy (default: stratified)')
    parser.add_argument('--skip-validation', action='store_true',
                        help='Skip validation and merge anyway')
    parser.add_argument('-y', '--yes', action='store_true',
                        help='Skip confirmation prompt')
    
    args = parser.parse_args()
    
    print("="*70)
    print("🔗 DATASET MERGER & VALIDATOR")
    print("="*70)
    
    # Load datasets
    print(f"\n📂 Loading datasets...")
    try:
        df_real = pd.read_csv(args.real)
        print(f"✅ Loaded real dataset: {args.real}")
    except Exception as e:
        print(f"❌ Failed to load real dataset: {e}")
        return
    
    try:
        df_synthetic = pd.read_csv(args.synthetic)
        print(f"✅ Loaded synthetic dataset: {args.synthetic}")
    except Exception as e:
        print(f"❌ Failed to load synthetic dataset: {e}")
        return
    
    # Analyze both datasets
    stats_real = analyze_dataset(df_real, "Real")
    stats_synthetic = analyze_dataset(df_synthetic, "Synthetic")
    
    # Validate compatibility
    if not args.skip_validation:
        issues, warnings = validate_compatibility(df_real, df_synthetic, "Real", "Synthetic")
        
        if issues:
            print(f"\n❌ CRITICAL ISSUES FOUND:")
            for issue in issues:
                print(f"   - {issue}")
            print(f"\nCannot merge datasets. Fix issues first or use --skip-validation")
            return
        
        if warnings:
            print(f"\n⚠️  WARNINGS:")
            for warning in warnings:
                print(f"   - {warning}")
    
    # Clean datasets
    df_real_clean = clean_dataframe(df_real, "Real")
    df_synthetic_clean = clean_dataframe(df_synthetic, "Synthetic")
    
    # Get confirmation
    if not args.yes:
        print(f"\n{'='*70}")
        print(f"Ready to merge:")
        print(f"  Real:      {len(df_real_clean)} rows")
        print(f"  Synthetic: {len(df_synthetic_clean)} rows")
        print(f"  Strategy:  {args.strategy}")
        print(f"  Output:    {args.output}")
        print(f"{'='*70}")
        
        response = input("\nProceed with merge? (yes/no): ").strip().lower()
        if response not in ['yes', 'y']:
            print("❌ Merge cancelled")
            return
    
    # Merge datasets
    df_merged = merge_datasets(
        df_real_clean, 
        df_synthetic_clean, 
        "Real", 
        "Synthetic", 
        strategy=args.strategy
    )
    
    # Create metadata
    metadata = {
        'merge_timestamp': datetime.now().isoformat(),
        'real_dataset': args.real,
        'synthetic_dataset': args.synthetic,
        'merge_strategy': args.strategy,
        'real_stats': stats_real,
        'synthetic_stats': stats_synthetic,
        'merged_stats': {
            'rows': len(df_merged),
            'cols': len(df_merged.columns),
            'class_0': len(df_merged[df_merged['label']==0]),
            'class_1': len(df_merged[df_merged['label']==1])
        }
    }
    
    # Analyze merged dataset
    analyze_dataset(df_merged, "Merged")
    
    # Save merged dataset
    save_merged_dataset(df_merged, args.output, metadata)
    
    print(f"\n🎉 SUCCESS! Ready to train your model with: {args.output}")

if __name__ == "__main__":
    main()