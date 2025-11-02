#!/usr/bin/env python3
"""
Analyze dataset and generate synthetic samples to balance classes
"""

import pandas as pd
import numpy as np
from collections import Counter

def analyze_dataset(csv_file):
    """Analyze dataset for imbalances"""
    
    df = pd.read_csv(csv_file)
    
    print("="*70)
    print("📊 DATASET ANALYSIS")
    print("="*70)
    
    # Basic info
    print(f"\n📈 Dataset size:")
    print(f"   Total samples: {len(df)}")
    print(f"   Features: {len(df.columns) - 1}")
    
    # Class distribution
    print(f"\n🏷️  Class distribution:")
    class_counts = df['label'].value_counts().sort_index()
    for label, count in class_counts.items():
        label_name = "Safe" if label == 0 else "Risky"
        pct = count / len(df) * 100
        print(f"   {label_name} (label={label}): {count} ({pct:.1f}%)")
    
    # Check imbalance ratio
    if len(class_counts) == 2:
        imbalance_ratio = class_counts.max() / class_counts.min()
        print(f"   Imbalance ratio: {imbalance_ratio:.2f}:1")
        
        if imbalance_ratio > 1.5:
            print(f"   ⚠️  Dataset is imbalanced (threshold: 1.5:1)")
        else:
            print(f"   ✅ Dataset is balanced")
    
    # Feature value distribution
    print(f"\n📋 Feature value distributions:")
    feature_cols = [col for col in df.columns if col != 'label']
    
    for col in feature_cols:
        unique_vals = df[col].nunique()
        if unique_vals <= 5:  # Binary or categorical
            value_counts = df[col].value_counts()
            zeros = value_counts.get(0, 0) + value_counts.get(0.0, 0)
            total = len(df)
            zero_pct = zeros / total * 100
            
            if zero_pct > 90:
                print(f"   ⚠️  {col}: {zero_pct:.1f}% are 0 (low variance)")
            elif zero_pct < 10:
                print(f"   ⚠️  {col}: {100-zero_pct:.1f}% are non-zero (low variance)")
    
    # Correlation with label
    print(f"\n🔗 Feature correlation with label:")
    correlations = df.corr()['label'].drop('label').sort_values(ascending=False)
    print("\n   Top 5 positive correlations:")
    for feat, corr in correlations.head(5).items():
        print(f"      {feat}: {corr:.3f}")
    
    print("\n   Top 5 negative correlations:")
    for feat, corr in correlations.tail(5).items():
        print(f"      {feat}: {corr:.3f}")
    
    return df, class_counts

def generate_synthetic_smote(df, target_ratio=1.0):
    """
    Generate synthetic samples using SMOTE-like technique
    target_ratio: 1.0 means equal classes, 0.8 means minority=80% of majority
    """
    
    print("\n" + "="*70)
    print("🧪 GENERATING SYNTHETIC SAMPLES")
    print("="*70)
    
    # Separate features and labels
    X = df.drop('label', axis=1)
    y = df['label']
    
    # Get class counts
    class_counts = y.value_counts()
    minority_class = class_counts.idxmin()
    majority_class = class_counts.idxmax()
    
    minority_count = class_counts[minority_class]
    majority_count = class_counts[majority_class]
    
    # Calculate how many synthetic samples needed
    target_minority_count = int(majority_count * target_ratio)
    samples_needed = max(0, target_minority_count - minority_count)
    
    print(f"\n📊 Current distribution:")
    print(f"   Majority class ({majority_class}): {majority_count}")
    print(f"   Minority class ({minority_class}): {minority_count}")
    print(f"\n🎯 Target distribution (ratio={target_ratio}):")
    print(f"   Minority class needs: {target_minority_count}")
    print(f"   Synthetic samples to generate: {samples_needed}")
    
    if samples_needed == 0:
        print("\n✅ Dataset is already balanced!")
        return df
    
    # Get minority class samples
    minority_samples = df[df['label'] == minority_class].drop('label', axis=1)
    
    # Generate synthetic samples
    synthetic_samples = []
    
    for _ in range(samples_needed):
        # Pick two random minority samples
        idx1, idx2 = np.random.choice(len(minority_samples), 2, replace=True)
        sample1 = minority_samples.iloc[idx1]
        sample2 = minority_samples.iloc[idx2]
        
        # Create synthetic sample (linear interpolation)
        alpha = np.random.random()
        synthetic = sample1 * alpha + sample2 * (1 - alpha)
        
        # Round binary features to 0 or 1
        binary_features = ['cryptominer_binary', 'ssh_backdoor', 'runs_as_root', 'outdated_base']
        for feat in binary_features:
            if feat in synthetic.index:
                synthetic[feat] = round(synthetic[feat])
        
        # Add to list
        synthetic_samples.append(synthetic)
    
    # Create DataFrame of synthetic samples
    synthetic_df = pd.DataFrame(synthetic_samples)
    synthetic_df['label'] = minority_class
    
    # Combine original and synthetic
    augmented_df = pd.concat([df, synthetic_df], ignore_index=True)
    
    print(f"\n✅ Synthetic generation complete!")
    print(f"\n📊 New distribution:")
    new_counts = augmented_df['label'].value_counts().sort_index()
    for label, count in new_counts.items():
        label_name = "Safe" if label == 0 else "Risky"
        pct = count / len(augmented_df) * 100
        print(f"   {label_name} (label={label}): {count} ({pct:.1f}%)")
    
    return augmented_df

def add_noise_to_features(df, noise_level=0.05):
    """
    Add small random noise to numeric features to increase variance
    """
    print("\n" + "="*70)
    print("🔊 ADDING FEATURE NOISE")
    print("="*70)
    
    df_noisy = df.copy()
    
    # Features to add noise to (exclude binary features)
    numeric_features = [
        'mining_pools', 'hardcoded_secrets', 'external_calls',
        'known_cves', 'typosquatting_score', 'image_age_days',
        'suspicious_ports'
    ]
    
    for col in numeric_features:
        if col in df_noisy.columns:
            # Add Gaussian noise
            noise = np.random.normal(0, noise_level * df_noisy[col].std(), len(df_noisy))
            df_noisy[col] = df_noisy[col] + noise
            
            # Clip to reasonable ranges
            df_noisy[col] = df_noisy[col].clip(lower=0)
            
            print(f"   ✓ Added noise to {col}")
    
    return df_noisy

def create_augmented_dataset(input_csv, output_csv, 
                            balance_ratio=0.9, 
                            add_noise=True,
                            noise_level=0.05):
    """
    Main function to create augmented dataset
    """
    
    # Analyze
    df, class_counts = analyze_dataset(input_csv)
    
    # Check if balancing needed
    if len(class_counts) == 2:
        imbalance_ratio = class_counts.max() / class_counts.min()
        
        if imbalance_ratio > 1.3:
            print(f"\n🔄 Balancing dataset...")
            df = generate_synthetic_smote(df, target_ratio=balance_ratio)
        else:
            print(f"\n✅ Dataset already balanced, skipping synthetic generation")
    
    # Add noise if requested
    if add_noise:
        df = add_noise_to_features(df, noise_level=noise_level)
    
    # Save
    df.to_csv(output_csv, index=False)
    
    print("\n" + "="*70)
    print("✅ AUGMENTATION COMPLETE")
    print("="*70)
    print(f"\n💾 Augmented dataset saved to: {output_csv}")
    print(f"   Total samples: {len(df)}")
    print(f"   Original samples: {len(class_counts) * min(class_counts)}")
    print(f"   Synthetic samples: {len(df) - len(class_counts) * min(class_counts)}")
    
    return df

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Analyze and augment ML dataset')
    parser.add_argument('--input', default='data/ml_training_data.csv',
                       help='Input CSV file')
    parser.add_argument('--output', default='data/ml_training_data_balanced.csv',
                       help='Output CSV file')
    parser.add_argument('--balance-ratio', type=float, default=0.9,
                       help='Target ratio for minority class (default: 0.9 = 90% of majority)')
    parser.add_argument('--no-noise', action='store_true',
                       help='Skip adding noise to features')
    parser.add_argument('--noise-level', type=float, default=0.05,
                       help='Noise level as fraction of std dev (default: 0.05)')
    parser.add_argument('--analyze-only', action='store_true',
                       help='Only analyze, do not augment')
    
    args = parser.parse_args()
    
    if args.analyze_only:
        analyze_dataset(args.input)
    else:
        create_augmented_dataset(
            args.input,
            args.output,
            balance_ratio=args.balance_ratio,
            add_noise=not args.no_noise,
            noise_level=args.noise_level
        )
    
    print("\n🎯 Next steps:")
    print("   1. Review the augmented dataset")
    print("   2. Split into train/test sets")
    print("   3. Train your ML model")
    print("   4. Evaluate performance")