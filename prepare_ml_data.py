#!/usr/bin/env python3
"""
Prepare ML-ready dataset by removing metadata columns
"""

import pandas as pd
import numpy as np

def prepare_ml_dataset(input_csv, output_csv):
    """Remove metadata and create clean ML dataset"""
    
    print("="*70)
    print("🤖 PREPARING ML TRAINING DATASET")
    print("="*70)
    
    # Load data
    df = pd.read_csv(input_csv)
    print(f"\n📊 Original dataset: {len(df)} rows, {len(df.columns)} columns")
    
    # Define features for ML (exclude metadata)
    ml_features = [
        'cryptominer_binary',
        'mining_pools', 
        'hardcoded_secrets',
        'external_calls',
        'ssh_backdoor',
        'runs_as_root',
        'known_cves',
        'outdated_base',
        'typosquatting_score',
        'image_age_days',
        'suspicious_ports',
        'label'  # Target variable
    ]
    
    # Create ML dataset
    df_ml = df[ml_features].copy()
    
    # Check for any remaining nulls
    null_counts = df_ml.isnull().sum()
    if null_counts.any():
        print("\n⚠️  Warning: Found null values:")
        for col, count in null_counts.items():
            if count > 0:
                print(f"   {col}: {count}")
        print("\n   Filling remaining nulls with column median...")
        df_ml = df_ml.fillna(df_ml.median())
    
    # Verify no nulls remain
    assert df_ml.isnull().sum().sum() == 0, "Still have null values!"
    
    # Save ML dataset
    df_ml.to_csv(output_csv, index=False)
    
    # Print summary
    print(f"\n✅ ML dataset created!")
    print(f"\n📊 Dataset summary:")
    print(f"   Total samples: {len(df_ml)}")
    print(f"   Number of features: {len(ml_features) - 1}")
    print(f"   Target variable: label")
    
    print(f"\n📈 Class distribution:")
    print(f"   Safe (label=0): {len(df_ml[df_ml['label']==0])} ({len(df_ml[df_ml['label']==0])/len(df_ml)*100:.1f}%)")
    print(f"   Risky (label=1): {len(df_ml[df_ml['label']==1])} ({len(df_ml[df_ml['label']==1])/len(df_ml)*100:.1f}%)")
    
    print(f"\n📋 Features for training:")
    for i, feat in enumerate([f for f in ml_features if f != 'label'], 1):
        print(f"   {i}. {feat}")
    
    print(f"\n💾 Saved to: {output_csv}")
    
    # Show sample
    print(f"\n📄 Sample data (first 5 rows):")
    print(df_ml.head())
    
    # Feature statistics
    print(f"\n📊 Feature statistics:")
    print(df_ml.describe())
    
    return df_ml

if __name__ == "__main__":
    input_file = 'data/docker_features_fixed.csv'
    output_file = 'data/ml_training_data.csv'
    
    df_ml = prepare_ml_dataset(input_file, output_file)
    
    print("\n" + "="*70)
    print("✅ READY FOR ML TRAINING!")
    print("="*70)
    print(f"\nUse this file: {output_file}")
    print("\nNext steps:")
    print("  1. Split into train/test sets")
    print("  2. Train your ML model (Random Forest, XGBoost, etc.)")
    print("  3. Evaluate performance")