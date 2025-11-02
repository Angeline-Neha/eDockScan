#!/usr/bin/env python3
"""
Generate realistic synthetic Docker image security data
Based on real-world patterns observed in container security
"""

import pandas as pd
import numpy as np
from typing import List, Dict
import random

class SyntheticDockerDataGenerator:
    """Generate realistic synthetic Docker security features"""
    
    def __init__(self, seed=42):
        np.random.seed(seed)
        random.seed(seed)
        
        # Real-world patterns learned from actual scans
        self.safe_patterns = {
            'cryptominer_binary': {'mean': 0.02, 'std': 0.1, 'max': 1},  # Very rare
            'mining_pools': {'mean': 0.05, 'std': 0.2, 'max': 2},
            'hardcoded_secrets': {'mean': 0.1, 'std': 0.3, 'max': 3},
            'external_calls': {'mean': 0.05, 'std': 0.2, 'max': 2},
            'ssh_backdoor': {'mean': 0.1, 'std': 0.25, 'max': 1},  # Sometimes for legitimate admin
            'runs_as_root': {'mean': 0.7, 'std': 0.3, 'max': 1},  # Common even in safe images
            'known_cves': {'mean': 5, 'std': 10, 'max': 25},  # Low but present
            'outdated_base': {'mean': 0.2, 'std': 0.3, 'max': 1},
            'typosquatting_score': {'mean': 0.6, 'std': 0.3, 'max': 1.0},  # Lower similarity
            'image_age_days': {'mean': 180, 'std': 200, 'max': 800},  # Relatively recent
            'suspicious_ports': {'mean': 2.5, 'std': 1, 'max': 4}
        }
        
        self.risky_patterns = {
            'cryptominer_binary': {'mean': 0.15, 'std': 0.3, 'max': 1},  # More common
            'mining_pools': {'mean': 0.4, 'std': 0.8, 'max': 5},
            'hardcoded_secrets': {'mean': 0.8, 'std': 1.5, 'max': 10},
            'external_calls': {'mean': 0.6, 'std': 1.0, 'max': 5},
            'ssh_backdoor': {'mean': 0.2, 'std': 0.35, 'max': 1},
            'runs_as_root': {'mean': 0.95, 'std': 0.15, 'max': 1},  # Almost always
            'known_cves': {'mean': 35, 'std': 15, 'max': 50},  # High CVE count
            'outdated_base': {'mean': 0.85, 'std': 0.25, 'max': 1},  # Very likely outdated
            'typosquatting_score': {'mean': 0.88, 'std': 0.1, 'max': 1.0},  # High similarity (typosquat)
            'image_age_days': {'mean': 1200, 'std': 800, 'max': 3500},  # Much older
            'suspicious_ports': {'mean': 3.5, 'std': 1.2, 'max': 5}
        }
    
    def generate_sample(self, is_risky: bool) -> Dict:
        """Generate one synthetic sample"""
        
        patterns = self.risky_patterns if is_risky else self.safe_patterns
        sample = {}
        
        for feature, params in patterns.items():
            # Generate value based on distribution
            if feature in ['cryptominer_binary', 'ssh_backdoor', 'runs_as_root', 'outdated_base']:
                # Binary features: use Bernoulli distribution
                prob = params['mean']
                value = 1.0 if np.random.random() < prob else 0.0
            
            elif feature in ['typosquatting_score']:
                # Continuous [0, 1]: use Beta distribution
                # Convert mean/std to alpha/beta parameters
                mean = params['mean']
                std = params['std']
                alpha = mean * ((mean * (1 - mean) / (std**2)) - 1)
                beta = (1 - mean) * ((mean * (1 - mean) / (std**2)) - 1)
                value = np.random.beta(max(0.5, alpha), max(0.5, beta))
                value = np.clip(value, 0, 1)
            
            elif feature in ['known_cves']:
                # Count data: use Poisson or Negative Binomial
                value = np.random.poisson(params['mean'])
                value = min(value, params['max'])
            
            elif feature in ['image_age_days']:
                # Age: use Gamma distribution (skewed positive)
                shape = (params['mean'] / params['std']) ** 2
                scale = params['std'] ** 2 / params['mean']
                value = np.random.gamma(shape, scale)
                value = max(0, min(value, params['max']))
            
            else:
                # Other numeric features: use truncated normal
                value = np.random.normal(params['mean'], params['std'])
                value = max(0, min(value, params['max']))
            
            sample[feature] = value
        
        sample['label'] = 1 if is_risky else 0
        
        # Add realistic correlations
        sample = self._add_correlations(sample, is_risky)
        
        return sample
    
    def _add_correlations(self, sample: Dict, is_risky: bool) -> Dict:
        """Add realistic feature correlations"""
        
        # Correlation 1: Old images have more CVEs
        if sample['outdated_base'] == 1:
            sample['known_cves'] = sample['known_cves'] * 1.5
            sample['known_cves'] = min(sample['known_cves'], 50)
        
        # Correlation 2: Cryptominers often have mining pools
        if sample['cryptominer_binary'] == 1:
            sample['mining_pools'] = max(sample['mining_pools'], 1)
        
        # Correlation 3: Very old images likely outdated
        if sample['image_age_days'] > 1000:
            sample['outdated_base'] = 1.0
        
        # Correlation 4: SSH backdoors often come with secrets
        if sample['ssh_backdoor'] == 1:
            sample['hardcoded_secrets'] = max(sample['hardcoded_secrets'], 1)
        
        # Correlation 5: High typosquatting score in risky images correlates with malicious features
        if is_risky and sample['typosquatting_score'] > 0.85:
            # Typosquatting images often have hidden miners
            if np.random.random() < 0.3:
                sample['cryptominer_binary'] = 1.0
                sample['mining_pools'] = max(sample['mining_pools'], 1)
        
        # Correlation 6: Running as root correlates with more suspicious ports
        if sample['runs_as_root'] == 1:
            sample['suspicious_ports'] = sample['suspicious_ports'] + np.random.uniform(0, 1)
            sample['suspicious_ports'] = min(sample['suspicious_ports'], 5)
        
        return sample
    
    def generate_dataset(self, n_safe: int, n_risky: int) -> pd.DataFrame:
        """Generate complete synthetic dataset"""
        
        print("="*70)
        print("🧪 SYNTHETIC DATA GENERATOR")
        print("="*70)
        print(f"\nGenerating synthetic Docker security data...")
        print(f"  Safe samples: {n_safe}")
        print(f"  Risky samples: {n_risky}")
        print(f"  Total: {n_safe + n_risky}")
        
        samples = []
        
        # Generate safe samples
        print(f"\n📦 Generating {n_safe} safe images...")
        for i in range(n_safe):
            sample = self.generate_sample(is_risky=False)
            samples.append(sample)
            if (i + 1) % 10 == 0:
                print(f"  Generated {i + 1}/{n_safe} safe samples")
        
        # Generate risky samples
        print(f"\n⚠️  Generating {n_risky} risky images...")
        for i in range(n_risky):
            sample = self.generate_sample(is_risky=True)
            samples.append(sample)
            if (i + 1) % 10 == 0:
                print(f"  Generated {i + 1}/{n_risky} risky samples")
        
        # Create DataFrame
        df = pd.DataFrame(samples)
        
        # Reorder columns
        feature_cols = [
            'cryptominer_binary', 'mining_pools', 'hardcoded_secrets',
            'external_calls', 'ssh_backdoor', 'runs_as_root',
            'known_cves', 'outdated_base', 'typosquatting_score',
            'image_age_days', 'suspicious_ports', 'label'
        ]
        df = df[feature_cols]
        
        # Shuffle rows
        df = df.sample(frac=1, random_state=42).reset_index(drop=True)
        
        print(f"\n✅ Generation complete!")
        
        return df
    
    def validate_synthetic_data(self, df: pd.DataFrame):
        """Validate that synthetic data looks realistic"""
        
        print("\n" + "="*70)
        print("🔍 VALIDATING SYNTHETIC DATA")
        print("="*70)
        
        # Check class distribution
        print(f"\n📊 Class distribution:")
        class_counts = df['label'].value_counts().sort_index()
        for label, count in class_counts.items():
            label_name = "Safe" if label == 0 else "Risky"
            pct = count / len(df) * 100
            print(f"   {label_name} (label={label}): {count} ({pct:.1f}%)")
        
        # Check feature ranges
        print(f"\n📏 Feature ranges:")
        for col in df.columns:
            if col == 'label':
                continue
            min_val = df[col].min()
            max_val = df[col].max()
            mean_val = df[col].mean()
            print(f"   {col}: [{min_val:.2f}, {max_val:.2f}] (mean: {mean_val:.2f})")
        
        # Check for differences between classes
        print(f"\n🔬 Feature differences (Risky - Safe):")
        safe_means = df[df['label'] == 0].mean()
        risky_means = df[df['label'] == 1].mean()
        
        for col in df.columns:
            if col == 'label':
                continue
            diff = risky_means[col] - safe_means[col]
            direction = "↑" if diff > 0 else "↓"
            print(f"   {col}: {diff:+.2f} {direction}")
        
        # Check correlations
        print(f"\n🔗 Top feature correlations with label:")
        correlations = df.corr()['label'].drop('label').sort_values(ascending=False)
        for feat, corr in correlations.head(5).items():
            print(f"   {feat}: {corr:.3f}")
        
        print(f"\n✅ Synthetic data validation complete!")


def merge_with_existing(existing_csv: str, synthetic_df: pd.DataFrame, 
                        output_csv: str) -> pd.DataFrame:
    """Merge synthetic data with existing real data"""
    
    print("\n" + "="*70)
    print("🔗 MERGING DATASETS")
    print("="*70)
    
    # Load existing data
    existing_df = pd.read_csv(existing_csv)
    print(f"\n📊 Existing data: {len(existing_df)} samples")
    print(f"🧪 Synthetic data: {len(synthetic_df)} samples")
    
    # Ensure same columns
    cols = existing_df.columns.tolist()
    synthetic_df = synthetic_df[cols]
    
    # Combine
    combined_df = pd.concat([existing_df, synthetic_df], ignore_index=True)
    
    # Shuffle
    combined_df = combined_df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    # Save
    combined_df.to_csv(output_csv, index=False)
    
    print(f"\n✅ Merged dataset created!")
    print(f"   Total samples: {len(combined_df)}")
    print(f"   Safe: {len(combined_df[combined_df['label']==0])}")
    print(f"   Risky: {len(combined_df[combined_df['label']==1])}")
    print(f"   Saved to: {output_csv}")
    
    return combined_df


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate synthetic Docker security data')
    parser.add_argument('--safe', type=int, default=50,
                       help='Number of safe samples to generate')
    parser.add_argument('--risky', type=int, default=50,
                       help='Number of risky samples to generate')
    parser.add_argument('--output', default='data/synthetic_data.csv',
                       help='Output CSV file for synthetic data')
    parser.add_argument('--merge-with', default=None,
                       help='Existing CSV to merge with (optional)')
    parser.add_argument('--merged-output', default='data/final_training_data.csv',
                       help='Output file for merged data')
    parser.add_argument('--seed', type=int, default=42,
                       help='Random seed for reproducibility')
    
    args = parser.parse_args()
    
    # Generate synthetic data
    generator = SyntheticDockerDataGenerator(seed=args.seed)
    synthetic_df = generator.generate_dataset(args.safe, args.risky)
    
    # Validate
    generator.validate_synthetic_data(synthetic_df)
    
    # Save synthetic data
    synthetic_df.to_csv(args.output, index=False)
    print(f"\n💾 Synthetic data saved to: {args.output}")
    
    # Merge if requested
    if args.merge_with:
        combined_df = merge_with_existing(
            args.merge_with,
            synthetic_df,
            args.merged_output
        )
    
    print("\n" + "="*70)
    print("✅ COMPLETE!")
    print("="*70)
    print("\n🎯 Next steps:")
    print("   1. Review the synthetic data")
    print("   2. Use for training ML models")
    print("   3. Compare model performance with/without synthetic data")
    print("\n📊 Generated data statistics:")
    print(synthetic_df.describe())