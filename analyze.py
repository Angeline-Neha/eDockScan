#!/usr/bin/env python3
"""
Dataset Analyzer - Inspect datasets before merging
Quick analysis tool to understand your data structure
"""

import pandas as pd
import numpy as np
from collections import Counter

def analyze_dataset(filepath: str):
    """Quick analysis of a dataset"""
    print("\n" + "="*70)
    print(f"ANALYZING: {filepath}")
    print("="*70)
    
    # Load data
    df = pd.read_csv(filepath)
    
    print(f"\n📊 BASIC INFO:")
    print(f"  Rows: {len(df)}")
    print(f"  Columns: {len(df.columns)}")
    
    print(f"\n📋 COLUMNS ({len(df.columns)}):")
    for i, col in enumerate(df.columns, 1):
        dtype = df[col].dtype
        null_count = df[col].isnull().sum()
        null_pct = null_count / len(df) * 100
        print(f"  {i:2d}. {col:30s} ({dtype:10s}) - {null_count:4d} nulls ({null_pct:5.1f}%)")
    
    # Check for label column
    print(f"\n🏷️  LABEL COLUMN:")
    if 'label' in df.columns:
        label_counts = df['label'].value_counts()
        print(f"  ✓ Label column found")
        print(f"    Safe (0):  {label_counts.get(0, 0)}")
        print(f"    Risky (1): {label_counts.get(1, 0)}")
        print(f"    Null: {df['label'].isnull().sum()}")
    else:
        print(f"  ✗ No 'label' column found - will need to infer labels")
    
    # Check for image_name column
    print(f"\n🐳 IMAGE NAMES:")
    if 'image_name' in df.columns:
        print(f"  ✓ image_name column found")
        print(f"    Unique images: {df['image_name'].nunique()}")
        print(f"    Sample images:")
        for img in df['image_name'].dropna().head(5):
            print(f"      - {img}")
    else:
        print(f"  ✗ No 'image_name' column found")
    
    # Sample data
    print(f"\n📄 SAMPLE DATA (first 3 rows):")
    print(df.head(3).to_string())
    
    # Detect risky patterns
    if 'image_name' in df.columns:
        print(f"\n🔍 DETECTED PATTERNS:")
        risky_indicators = ['14.04', '16.04', 'jessie', 'wheezy', '2.7', 
                           '5.6', 'dvwa', 'juice', 'x:', '1s:', '0s:']
        
        risky_found = []
        for indicator in risky_indicators:
            count = df['image_name'].str.contains(indicator, case=False, na=False).sum()
            if count > 0:
                risky_found.append(f"{indicator}: {count}")
        
        if risky_found:
            print(f"  Potential risky images:")
            for item in risky_found[:10]:
                print(f"    - {item}")
        else:
            print(f"  No obvious risky patterns detected")
    
    print("\n" + "="*70)


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python data_analyzer.py <dataset1.csv> [dataset2.csv] ...")
        print("\nExample:")
        print("  python data_analyzer.py data/original.csv data/my_data.csv")
        sys.exit(1)
    
    for filepath in sys.argv[1:]:
        try:
            analyze_dataset(filepath)
        except Exception as e:
            print(f"\n❌ Error analyzing {filepath}: {e}")