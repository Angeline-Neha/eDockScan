#!/usr/bin/env python3
"""
Complete pipeline: Merge rescanned data, generate synthetic samples, balance dataset
Updated to match your exact feature set including behavioral features
"""

import pandas as pd
import numpy as np
import logging
from pathlib import Path
from typing import Tuple, Dict, List
import random

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class EnhancedSyntheticGenerator:
    """Generate synthetic Docker security data matching your exact feature set"""
    
    def __init__(self, seed=42):
        np.random.seed(seed)
        random.seed(seed)
        
        # Patterns based on your actual data - SAFE images
        self.safe_patterns = {
            # Basic security features
            'cryptominer_binary': {'mean': 0.03, 'std': 0.15, 'binary': True},
            'mining_pools': {'mean': 0.08, 'std': 0.25, 'max': 3},
            'hardcoded_secrets': {'mean': 0.12, 'std': 0.35, 'max': 4},
            'external_calls': {'mean': 0.09, 'std': 0.28, 'max': 3},
            'ssh_backdoor': {'mean': 0.08, 'std': 0.22, 'binary': True},
            'runs_as_root': {'mean': 0.65, 'std': 0.35, 'binary': True},
            'known_cves': {'mean': 6, 'std': 12, 'max': 30},
            'outdated_base': {'mean': 0.18, 'std': 0.30, 'binary': True},
            'typosquatting_score': {'mean': 0.55, 'std': 0.25, 'range': (0, 1)},
            'image_age_days': {'mean': 200, 'std': 250, 'max': 900},
            
            # Behavioral features (NEW - matching your dataset)
            'avg_file_entropy': {'mean': 0.15, 'std': 0.35, 'range': (0, 1)},
            'high_entropy_ratio': {'mean': 0.02, 'std': 0.05, 'range': (0, 1)},
            'stratum_indicators': {'mean': 0.08, 'std': 0.02, 'range': (0, 0.24)},
            'raw_ip_connections': {'mean': 0.25, 'std': 0.35, 'range': (0, 1)},
            'suspicious_dns_queries': {'mean': 0.18, 'std': 0.28, 'range': (0, 1)},
            'stripped_binaries_ratio': {'mean': 0.01, 'std': 0.02, 'range': (0, 1)},
            'packed_binary_score': {'mean': 0.02, 'std': 0.05, 'range': (0, 1)},
            'layer_deletion_score': {'mean': 0.15, 'std': 0.25, 'range': (0, 1)},
            'temp_file_activity': {'mean': 0.05, 'std': 0.12, 'range': (0, 1)},
            'process_injection_risk': {'mean': 0.03, 'std': 0.08, 'range': (0, 1)},
            'privilege_escalation_risk': {'mean': 0.08, 'std': 0.18, 'range': (0, 1)},
            'crypto_mining_behavior': {'mean': 0.04, 'std': 0.08, 'range': (0, 0.3)},
            'anti_analysis_score': {'mean': 0.12, 'std': 0.18, 'range': (0, 1)},
        }
        
        # Patterns for RISKY images
        self.risky_patterns = {
            # Basic security features
            'cryptominer_binary': {'mean': 0.18, 'std': 0.35, 'binary': True},
            'mining_pools': {'mean': 0.45, 'std': 0.85, 'max': 6},
            'hardcoded_secrets': {'mean': 0.85, 'std': 1.2, 'max': 10},
            'external_calls': {'mean': 0.65, 'std': 1.1, 'max': 6},
            'ssh_backdoor': {'mean': 0.22, 'std': 0.38, 'binary': True},
            'runs_as_root': {'mean': 0.92, 'std': 0.18, 'binary': True},
            'known_cves': {'mean': 38, 'std': 18, 'max': 50},
            'outdated_base': {'mean': 0.88, 'std': 0.22, 'binary': True},
            'typosquatting_score': {'mean': 0.87, 'std': 0.12, 'range': (0, 1)},
            'image_age_days': {'mean': 1400, 'std': 900, 'max': 3500},
            
            # Behavioral features (RISKY patterns)
            'avg_file_entropy': {'mean': 0.05, 'std': 0.15, 'range': (0, 1)},
            'high_entropy_ratio': {'mean': 0.03, 'std': 0.08, 'range': (0, 1)},
            'stratum_indicators': {'mean': 0.14, 'std': 0.05, 'range': (0, 0.24)},
            'raw_ip_connections': {'mean': 0.85, 'std': 0.22, 'range': (0, 1)},
            'suspicious_dns_queries': {'mean': 0.68, 'std': 0.28, 'range': (0, 1)},
            'stripped_binaries_ratio': {'mean': 0.02, 'std': 0.05, 'range': (0, 1)},
            'packed_binary_score': {'mean': 0.05, 'std': 0.12, 'range': (0, 1)},
            'layer_deletion_score': {'mean': 0.35, 'std': 0.28, 'range': (0, 1)},
            'temp_file_activity': {'mean': 0.08, 'std': 0.18, 'range': (0, 1)},
            'process_injection_risk': {'mean': 0.38, 'std': 0.25, 'range': (0, 1)},
            'privilege_escalation_risk': {'mean': 0.52, 'std': 0.28, 'range': (0, 1)},
            'crypto_mining_behavior': {'mean': 0.22, 'std': 0.12, 'range': (0, 0.3)},
            'anti_analysis_score': {'mean': 0.68, 'std': 0.28, 'range': (0, 1)},
        }
    
    def generate_sample(self, is_risky: bool) -> Dict:
        """Generate one synthetic sample with all features"""
        
        patterns = self.risky_patterns if is_risky else self.safe_patterns
        sample = {}
        
        for feature, params in patterns.items():
            if params.get('binary', False):
                # Binary features (0 or 1)
                prob = params['mean']
                value = 1.0 if np.random.random() < prob else 0.0
            
            elif 'range' in params:
                # Continuous features with specific range
                min_val, max_val = params['range']
                # Use beta distribution for bounded [0,1] values
                mean = params['mean']
                std = params['std']
                
                # Prevent invalid alpha/beta
                if std > 0 and mean > 0 and mean < 1:
                    alpha = mean * ((mean * (1 - mean) / (std**2 + 0.001)) - 1)
                    beta = (1 - mean) * ((mean * (1 - mean) / (std**2 + 0.001)) - 1)
                    alpha = max(0.5, alpha)
                    beta = max(0.5, beta)
                    value = np.random.beta(alpha, beta)
                    value = value * (max_val - min_val) + min_val
                else:
                    value = np.random.normal(mean, std)
                    value = np.clip(value, min_val, max_val)
            
            elif feature == 'known_cves':
                # CVE count: use Poisson
                value = np.random.poisson(params['mean'])
                value = min(value, params.get('max', 50))
            
            elif feature == 'image_age_days':
                # Age: use Gamma distribution
                shape = max(1, (params['mean'] / params['std']) ** 2)
                scale = params['std'] ** 2 / params['mean']
                value = np.random.gamma(shape, scale)
                value = max(0, min(value, params.get('max', 5000)))
            
            else:
                # Other count features
                value = np.random.normal(params['mean'], params['std'])
                value = max(0, min(value, params.get('max', 10)))
            
            sample[feature] = round(value, 4) if not params.get('binary', False) else int(value)
        
        sample['label'] = 1 if is_risky else 0
        
        # Add realistic correlations
        sample = self._add_correlations(sample, is_risky)
        
        return sample
    
    def _add_correlations(self, sample: Dict, is_risky: bool) -> Dict:
        """Add realistic correlations between features"""
        
        # Correlation 1: Cryptominers have mining pools and crypto behavior
        if sample['cryptominer_binary'] == 1:
            sample['mining_pools'] = max(sample['mining_pools'], 1)
            sample['crypto_mining_behavior'] = max(sample['crypto_mining_behavior'], 0.15)
            sample['stratum_indicators'] = max(sample['stratum_indicators'], 0.12)
        
        # Correlation 2: Old images have more CVEs and likely outdated
        if sample['image_age_days'] > 1000:
            sample['outdated_base'] = 1
            sample['known_cves'] = min(sample['known_cves'] * 1.5, 50)
        
        # Correlation 3: SSH backdoors correlate with secrets and privilege escalation
        if sample['ssh_backdoor'] == 1:
            sample['hardcoded_secrets'] = max(sample['hardcoded_secrets'], 1)
            sample['privilege_escalation_risk'] = max(sample['privilege_escalation_risk'], 0.3)
        
        # Correlation 4: High crypto mining behavior correlates with stratum and raw IPs
        if sample['crypto_mining_behavior'] > 0.15:
            sample['stratum_indicators'] = max(sample['stratum_indicators'], 0.1)
            sample['raw_ip_connections'] = max(sample['raw_ip_connections'], 0.6)
        
        # Correlation 5: Running as root increases privilege escalation risk
        if sample['runs_as_root'] == 1:
            sample['privilege_escalation_risk'] = min(sample['privilege_escalation_risk'] * 1.3, 1.0)
        
        # Correlation 6: High typosquatting in risky images often means hidden malware
        if is_risky and sample['typosquatting_score'] > 0.85:
            if np.random.random() < 0.35:
                sample['cryptominer_binary'] = 1
                sample['mining_pools'] = max(sample['mining_pools'], 1)
                sample['anti_analysis_score'] = max(sample['anti_analysis_score'], 0.4)
        
        # Correlation 7: Packed binaries correlate with anti-analysis
        if sample['packed_binary_score'] > 0.1:
            sample['anti_analysis_score'] = max(sample['anti_analysis_score'], 0.3)
        
        # Correlation 8: Process injection risk correlates with temp file activity
        if sample['process_injection_risk'] > 0.3:
            sample['temp_file_activity'] = max(sample['temp_file_activity'], 0.2)
        
        return sample
    
    def generate_dataset(self, n_safe: int, n_risky: int) -> pd.DataFrame:
        """Generate complete synthetic dataset"""
        
        logger.info("="*70)
        logger.info("🧪 ENHANCED SYNTHETIC DATA GENERATOR")
        logger.info("="*70)
        logger.info(f"Generating synthetic samples...")
        logger.info(f"  Safe: {n_safe}")
        logger.info(f"  Risky: {n_risky}")
        logger.info(f"  Total: {n_safe + n_risky}")
        
        samples = []
        
        # Generate safe samples
        for i in range(n_safe):
            sample = self.generate_sample(is_risky=False)
            samples.append(sample)
        
        # Generate risky samples
        for i in range(n_risky):
            sample = self.generate_sample(is_risky=True)
            samples.append(sample)
        
        df = pd.DataFrame(samples)
        
        # Shuffle
        df = df.sample(frac=1, random_state=42).reset_index(drop=True)
        
        logger.info(f"✓ Generated {len(df)} synthetic samples")
        
        return df


def merge_all_datasets(
    original_csv: str = 'data/all_docker_features_behavioral.csv',
    rescanned_csv: str = 'data/rescanned_images.csv',
    n_synthetic_safe: int = 0,
    n_synthetic_risky: int = 0,
    output_csv: str = 'data/merged_complete.csv'
) -> pd.DataFrame:
    """
    Step 1: Merge original, rescanned, and optionally synthetic data
    """
    logger.info("="*70)
    logger.info("🔀 Step 1: Merging All Datasets")
    logger.info("="*70)
    
    # Load original
    df_original = pd.read_csv(original_csv)
    logger.info(f"✓ Original dataset: {len(df_original)} rows")
    
    # Load rescanned
    df_rescanned = pd.read_csv(rescanned_csv)
    logger.info(f"✓ Rescanned dataset: {len(df_rescanned)} rows")
    
    # Create lookup for rescanned data
    rescanned_dict = {row['image_name']: row for _, row in df_rescanned.iterrows()}
    
    # Update original with rescanned data
    updated_count = 0
    for idx, row in df_original.iterrows():
        image_name = row['image_name']
        
        if image_name in rescanned_dict:
            rescanned_row = rescanned_dict[image_name]
            
            for col in rescanned_row.index:
                if col != 'image_name':
                    df_original.at[idx, col] = rescanned_row[col]
            
            updated_count += 1
    
    logger.info(f"✓ Updated {updated_count} rows with rescanned data")
    
    # Generate and add synthetic data if requested
    if n_synthetic_safe > 0 or n_synthetic_risky > 0:
        logger.info(f"\n🧪 Generating synthetic data...")
        generator = EnhancedSyntheticGenerator()
        df_synthetic = generator.generate_dataset(n_synthetic_safe, n_synthetic_risky)
        
        # Match columns with original dataset (except image_name)
        original_cols = [col for col in df_original.columns if col != 'image_name']
        synthetic_cols = list(df_synthetic.columns)
        
        # Add missing columns to synthetic data
        for col in original_cols:
            if col not in synthetic_cols:
                df_synthetic[col] = np.nan
        
        # Remove extra columns from synthetic
        df_synthetic = df_synthetic[synthetic_cols]
        
        # Ensure column order matches (excluding image_name)
        feature_cols = [col for col in df_original.columns if col != 'image_name']
        df_synthetic = df_synthetic[[col for col in feature_cols if col in df_synthetic.columns]]
        
        # Add synthetic to original
        df_original = pd.concat([df_original, df_synthetic], ignore_index=True)
        logger.info(f"✓ Added {len(df_synthetic)} synthetic samples")
    
    # Save merged
    df_original.to_csv(output_csv, index=False)
    logger.info(f"✓ Merged dataset saved: {output_csv}")
    logger.info(f"✓ Total samples: {len(df_original)}")
    
    return df_original


def clean_dataset(df: pd.DataFrame) -> pd.DataFrame:
    """Step 2: Clean dataset"""
    logger.info("\n" + "="*70)
    logger.info("🧹 Step 2: Cleaning Dataset")
    logger.info("="*70)
    
    initial_count = len(df)
    
    # Filter: Keep only successful scans
    if 'scan_status' in df.columns:
        df_clean = df[df['scan_status'] == 'success'].copy()
        logger.info(f"✓ Removed failed/partial scans: {initial_count - len(df_clean)} rows")
    else:
        df_clean = df.copy()
    
    # Filter: Keep high confidence
    if 'confidence_score' in df_clean.columns:
        df_clean = df_clean[df_clean['confidence_score'] >= 0.9].copy()
        logger.info(f"✓ Kept high confidence: {len(df_clean)} rows")
    
    # Remove rows with missing labels
    df_clean = df_clean[df_clean['label'].notna()].copy()
    logger.info(f"✓ Removed missing labels: {len(df_clean)} rows")
    
    # Remove unnecessary columns
    cols_to_remove = ['image_name', 'scan_status', 'confidence_score']
    existing_remove = [col for col in cols_to_remove if col in df_clean.columns]
    df_clean = df_clean.drop(columns=existing_remove)
    
    logger.info(f"✓ Removed {len(existing_remove)} metadata columns")
    logger.info(f"✓ Final feature count: {len(df_clean.columns) - 1}")  # Exclude label
    
    return df_clean


def balance_with_noise(
    df: pd.DataFrame,
    target_ratio: float = 1.2,
    noise_level: float = 0.08,
    random_state: int = 42
) -> pd.DataFrame:
    """Step 3: Balance dataset with noise"""
    logger.info("\n" + "="*70)
    logger.info("⚖️  Step 3: Balancing Dataset")
    logger.info("="*70)
    
    np.random.seed(random_state)
    
    benign = len(df[df['label'] == 0])
    malicious = len(df[df['label'] == 1])
    
    logger.info(f"✓ Benign: {benign}")
    logger.info(f"✓ Malicious: {malicious}")
    logger.info(f"✓ Current ratio: {max(benign, malicious)/min(benign, malicious):.2f}:1")
    
    # Determine minority
    if benign < malicious:
        minority_df = df[df['label'] == 0].copy()
        minority_label = 0
        target_count = int(malicious / target_ratio)
    else:
        minority_df = df[df['label'] == 1].copy()
        minority_label = 1
        target_count = int(benign / target_ratio)
    
    samples_needed = max(0, target_count - len(minority_df))
    
    if samples_needed == 0:
        logger.info("✓ Dataset balanced, no synthetic samples needed")
        return df
    
    logger.info(f"✓ Adding {samples_needed} synthetic samples to class {minority_label}")
    
    # Generate synthetic samples
    synthetic_samples = []
    numeric_cols = minority_df.select_dtypes(include=[np.number]).columns.tolist()
    numeric_cols = [col for col in numeric_cols if col != 'label']
    
    for _ in range(samples_needed):
        base = minority_df.sample(n=1).iloc[0].copy()
        
        for col in numeric_cols:
            if pd.notna(base[col]):
                col_range = minority_df[col].max() - minority_df[col].min()
                
                if col_range > 0:
                    noise = np.random.normal(0, noise_level * col_range)
                    new_val = base[col] + noise
                    
                    # Clip appropriately
                    if col in ['cryptominer_binary', 'ssh_backdoor', 'runs_as_root', 'outdated_base']:
                        new_val = round(np.clip(new_val, 0, 1))
                    elif 'ratio' in col or 'score' in col or 'behavior' in col or 'risk' in col or 'entropy' in col:
                        new_val = np.clip(new_val, 0, 1)
                    else:
                        new_val = max(0, round(new_val))
                    
                    base[col] = new_val
        
        synthetic_samples.append(base)
    
    df_synthetic = pd.DataFrame(synthetic_samples)
    df_balanced = pd.concat([df, df_synthetic], ignore_index=True)
    df_balanced = df_balanced.sample(frac=1, random_state=random_state).reset_index(drop=True)
    
    final_benign = len(df_balanced[df_balanced['label'] == 0])
    final_malicious = len(df_balanced[df_balanced['label'] == 1])
    
    logger.info(f"✓ Final benign: {final_benign}")
    logger.info(f"✓ Final malicious: {final_malicious}")
    logger.info(f"✓ Final ratio: {max(final_benign, final_malicious)/min(final_benign, final_malicious):.2f}:1")
    
    return df_balanced


def handle_missing_values(df: pd.DataFrame, strategy: str = 'median') -> pd.DataFrame:
    """Step 4: Handle missing values"""
    logger.info("\n" + "="*70)
    logger.info("🔧 Step 4: Handling Missing Values")
    logger.info("="*70)
    
    missing = df.isnull().sum()
    cols_missing = missing[missing > 0]
    
    if len(cols_missing) == 0:
        logger.info("✓ No missing values")
        return df
    
    logger.info(f"✓ Missing values in {len(cols_missing)} columns")
    
    df_clean = df.copy()
    
    if strategy == 'drop':
        df_clean = df_clean.dropna()
        logger.info(f"✓ Dropped {len(df) - len(df_clean)} rows")
    else:
        numeric_cols = df_clean.select_dtypes(include=[np.number]).columns
        for col in numeric_cols:
            if col in cols_missing.index and col != 'label':
                fill_val = df_clean[col].median() if strategy == 'median' else df_clean[col].mean()
                df_clean[col].fillna(fill_val, inplace=True)
                logger.info(f"  ✓ Filled {col}: {fill_val:.3f}")
    
    return df_clean


def prepare_final_dataset(
    original_csv: str = 'data/all_docker_features_behavioral.csv',
    rescanned_csv: str = 'data/rescanned_images.csv',
    n_synthetic_safe: int = 30,
    n_synthetic_risky: int = 30,
    output_csv: str = 'data/final_training_data.csv',
    target_ratio: float = 1.2,
    noise_level: float = 0.08,
    missing_strategy: str = 'median',
    random_state: int = 42
) -> Tuple[pd.DataFrame, Dict]:
    """Complete pipeline"""
    
    logger.info("\n" + "="*70)
    logger.info("🚀 COMPLETE DATASET PREPARATION PIPELINE")
    logger.info("="*70)
    
    # Step 1: Merge all sources
    df_merged = merge_all_datasets(
        original_csv, rescanned_csv,
        n_synthetic_safe, n_synthetic_risky,
        'data/merged_complete.csv'
    )
    
    # Step 2: Clean
    df_clean = clean_dataset(df_merged)
    
    # Step 3: Balance
    df_balanced = balance_with_noise(df_clean, target_ratio, noise_level, random_state)
    
    # Step 4: Handle missing
    df_final = handle_missing_values(df_balanced, missing_strategy)
    
    # Save
    logger.info("\n" + "="*70)
    logger.info("💾 Saving Final Dataset")
    logger.info("="*70)
    
    df_final.to_csv(output_csv, index=False)
    logger.info(f"✓ Saved: {output_csv}")
    
    # Stats
    stats = {
        'total': len(df_final),
        'benign': len(df_final[df_final['label'] == 0]),
        'malicious': len(df_final[df_final['label'] == 1]),
        'features': len(df_final.columns) - 1
    }
    
    logger.info("\n" + "="*70)
    logger.info("✅ PIPELINE COMPLETE")
    logger.info("="*70)
    logger.info(f"\n📊 Final Statistics:")
    logger.info(f"   Total: {stats['total']}")
    logger.info(f"   Benign: {stats['benign']}")
    logger.info(f"   Malicious: {stats['malicious']}")
    logger.info(f"   Features: {stats['features']}")
    logger.info(f"   Ratio: {max(stats['benign'], stats['malicious'])/min(stats['benign'], stats['malicious']):.2f}:1")
    
    logger.info(f"\n📋 Features:")
    for i, col in enumerate([c for c in df_final.columns if c != 'label'], 1):
        logger.info(f"   {i:2d}. {col}")
    
    logger.info("\n🎯 Dataset ready for ML training!")
    
    return df_final, stats


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Complete dataset preparation pipeline')
    parser.add_argument('--original', default='data/all_docker_features_behavioral.csv')
    parser.add_argument('--rescanned', default='data/rescanned_images.csv')
    parser.add_argument('--output', default='data/final_training_data.csv')
    parser.add_argument('--synthetic-safe', type=int, default=30,
                       help='Number of synthetic safe samples to add')
    parser.add_argument('--synthetic-risky', type=int, default=30,
                       help='Number of synthetic risky samples to add')
    parser.add_argument('--ratio', type=float, default=1.2)
    parser.add_argument('--noise', type=float, default=0.08)
    parser.add_argument('--missing-strategy', choices=['median', 'mean', 'drop'], default='median')
    parser.add_argument('--seed', type=int, default=42)
    
    args = parser.parse_args()
    
    if not Path(args.original).exists():
        logger.error(f"❌ Original file not found: {args.original}")
        exit(1)
    
    if not Path(args.rescanned).exists():
        logger.error(f"❌ Rescanned file not found: {args.rescanned}")
        exit(1)
    
    try:
        df_final, stats = prepare_final_dataset(
            original_csv=args.original,
            rescanned_csv=args.rescanned,
            n_synthetic_safe=args.synthetic_safe,
            n_synthetic_risky=args.synthetic_risky,
            output_csv=args.output,
            target_ratio=args.ratio,
            noise_level=args.noise,
            missing_strategy=args.missing_strategy,
            random_state=args.seed
        )
        
        logger.info(f"\n✅ Success! Final dataset: {args.output}")
        
    except Exception as e:
        logger.error(f"\n❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()
        exit(1)