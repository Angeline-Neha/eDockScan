#!/usr/bin/env python3
"""
Synthetic Docker Image Security Dataset Generator

Generates realistic synthetic data for training ML models when real scan data is limited.
Uses statistical distributions learned from real data to create plausible synthetic samples.

Features:
- Learns distributions from real dataset
- Maintains feature correlations
- Generates both safe and risky samples
- Enforces realistic constraints
- Exact column order matching
"""

import pandas as pd
import numpy as np
import json
import os
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from scipy import stats

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Exact column order from real dataset
COLUMN_ORDER = [
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
    'high_entropy_files',
    'suspicious_ports',
    'avg_file_entropy',
    'high_entropy_ratio',
    'stratum_indicators',
    'raw_ip_connections',
    'suspicious_dns_queries',
    'stripped_binaries_ratio',
    'packed_binary_score',
    'layer_deletion_score',
    'temp_file_activity',
    'process_injection_risk',
    'privilege_escalation_risk',
    'crypto_mining_behavior',
    'anti_analysis_score',
    'label'
]


class SyntheticDataGenerator:
    """Generate realistic synthetic Docker image security features"""
    
    def __init__(self, real_data_path: Optional[str] = None):
        self.real_data_path = real_data_path
        self.real_df = None
        self.safe_stats = {}
        self.risky_stats = {}
        
        if real_data_path and os.path.exists(real_data_path):
            self._learn_from_real_data(real_data_path)
        else:
            logger.warning("No real data provided, using default distributions")
            self._use_default_distributions()
    
    def _learn_from_real_data(self, data_path: str):
        """Learn statistical distributions from real data"""
        logger.info(f"Learning from real data: {data_path}")
        
        self.real_df = pd.read_csv(data_path)
        
        # Separate safe and risky images
        safe_df = self.real_df[self.real_df['label'] == 0]
        risky_df = self.real_df[self.real_df['label'] == 1]
        
        logger.info(f"Real data: {len(safe_df)} safe, {len(risky_df)} risky")
        
        # Learn statistics for each class
        for col in COLUMN_ORDER:
            if col == 'label':
                continue
            
            if col in safe_df.columns:
                self.safe_stats[col] = self._compute_column_stats(safe_df[col])
                self.risky_stats[col] = self._compute_column_stats(risky_df[col])
                
                # Log features with high null rates
                if self.safe_stats[col]['null_rate'] > 0.5:
                    logger.info(f"  {col}: {self.safe_stats[col]['null_rate']*100:.1f}% null (safe)")
                if self.risky_stats[col]['null_rate'] > 0.5:
                    logger.info(f"  {col}: {self.risky_stats[col]['null_rate']*100:.1f}% null (risky)")
        
        logger.info(f"Learned distributions for {len(self.safe_stats)} features")
    
    def _compute_column_stats(self, column: pd.Series) -> Dict:
        """Compute statistics for a column"""
        # Remove NaN values for statistics
        clean_data = column.dropna()
        
        if len(clean_data) == 0:
            return {
                'mean': 0,
                'std': 0,
                'min': 0,
                'max': 1,
                'q25': 0,
                'q50': 0,
                'q75': 0,
                'null_rate': 1.0,
                'unique_values': []
            }
        
        stats_dict = {
            'mean': float(clean_data.mean()),
            'std': float(clean_data.std()) if len(clean_data) > 1 else 0,
            'min': float(clean_data.min()),
            'max': float(clean_data.max()),
            'q25': float(clean_data.quantile(0.25)),
            'q50': float(clean_data.quantile(0.50)),
            'q75': float(clean_data.quantile(0.75)),
            'null_rate': float(column.isna().sum() / len(column)),
            'unique_values': sorted(clean_data.unique().tolist())
        }
        
        return stats_dict
    
    def _use_default_distributions(self):
        """Use default distributions when no real data is available"""
        logger.info("Using default distributions")
        
        # Safe image defaults (low risk)
        self.safe_stats = {
            'cryptominer_binary': {'mean': 0.0, 'std': 0.0, 'min': 0, 'max': 0, 'null_rate': 0.05},
            'mining_pools': {'mean': 0.0, 'std': 0.0, 'min': 0, 'max': 0, 'null_rate': 0.05},
            'hardcoded_secrets': {'mean': 0.1, 'std': 0.3, 'min': 0, 'max': 2, 'null_rate': 0.1},
            'external_calls': {'mean': 1.5, 'std': 1.2, 'min': 0, 'max': 5, 'null_rate': 0.1},
            'ssh_backdoor': {'mean': 0.05, 'std': 0.2, 'min': 0, 'max': 1, 'null_rate': 0.05},
            'runs_as_root': {'mean': 0.3, 'std': 0.5, 'min': 0, 'max': 1, 'null_rate': 0.1},
            'known_cves': {'mean': 5.0, 'std': 8.0, 'min': 0, 'max': 30, 'null_rate': 0.05},
            'outdated_base': {'mean': 0.1, 'std': 0.3, 'min': 0, 'max': 1, 'null_rate': 0.1},
            'typosquatting_score': {'mean': 0.3, 'std': 0.2, 'min': 0, 'max': 0.7, 'null_rate': 0.05},
            'image_age_days': {'mean': 180, 'std': 150, 'min': 1, 'max': 500, 'null_rate': 0.1},
            'high_entropy_files': {'mean': 1.0, 'std': 1.5, 'min': 0, 'max': 5, 'null_rate': 0.15},
            'suspicious_ports': {'mean': 0.5, 'std': 0.8, 'min': 0, 'max': 3, 'null_rate': 0.1},
            'avg_file_entropy': {'mean': 4.5, 'std': 1.0, 'min': 2.0, 'max': 6.5, 'null_rate': 0.15},
            'high_entropy_ratio': {'mean': 0.15, 'std': 0.1, 'min': 0, 'max': 0.4, 'null_rate': 0.15},
            'stratum_indicators': {'mean': 0.05, 'std': 0.1, 'min': 0, 'max': 0.3, 'null_rate': 0.2},
            'raw_ip_connections': {'mean': 0.1, 'std': 0.2, 'min': 0, 'max': 0.5, 'null_rate': 0.2},
            'suspicious_dns_queries': {'mean': 0.05, 'std': 0.1, 'min': 0, 'max': 0.3, 'null_rate': 0.2},
            'stripped_binaries_ratio': {'mean': 0.2, 'std': 0.15, 'min': 0, 'max': 0.5, 'null_rate': 0.2},
            'packed_binary_score': {'mean': 0.1, 'std': 0.15, 'min': 0, 'max': 0.4, 'null_rate': 0.2},
            'layer_deletion_score': {'mean': 0.15, 'std': 0.2, 'min': 0, 'max': 0.5, 'null_rate': 0.2},
            'temp_file_activity': {'mean': 0.1, 'std': 0.15, 'min': 0, 'max': 0.4, 'null_rate': 0.2},
            'process_injection_risk': {'mean': 0.05, 'std': 0.1, 'min': 0, 'max': 0.3, 'null_rate': 0.2},
            'privilege_escalation_risk': {'mean': 0.1, 'std': 0.15, 'min': 0, 'max': 0.4, 'null_rate': 0.2},
            'crypto_mining_behavior': {'mean': 0.05, 'std': 0.1, 'min': 0, 'max': 0.3, 'null_rate': 0.2},
            'anti_analysis_score': {'mean': 0.1, 'std': 0.15, 'min': 0, 'max': 0.4, 'null_rate': 0.2},
        }
        
        # Risky image defaults (higher risk)
        self.risky_stats = {
            'cryptominer_binary': {'mean': 0.15, 'std': 0.35, 'min': 0, 'max': 1, 'null_rate': 0.05},
            'mining_pools': {'mean': 0.8, 'std': 1.2, 'min': 0, 'max': 5, 'null_rate': 0.1},
            'hardcoded_secrets': {'mean': 2.5, 'std': 2.0, 'min': 0, 'max': 10, 'null_rate': 0.1},
            'external_calls': {'mean': 4.0, 'std': 2.5, 'min': 0, 'max': 10, 'null_rate': 0.1},
            'ssh_backdoor': {'mean': 0.2, 'std': 0.4, 'min': 0, 'max': 1, 'null_rate': 0.05},
            'runs_as_root': {'mean': 0.8, 'std': 0.4, 'min': 0, 'max': 1, 'null_rate': 0.05},
            'known_cves': {'mean': 35.0, 'std': 20.0, 'min': 5, 'max': 100, 'null_rate': 0.05},
            'outdated_base': {'mean': 0.7, 'std': 0.45, 'min': 0, 'max': 1, 'null_rate': 0.05},
            'typosquatting_score': {'mean': 0.5, 'std': 0.25, 'min': 0, 'max': 0.95, 'null_rate': 0.05},
            'image_age_days': {'mean': 800, 'std': 400, 'min': 300, 'max': 2000, 'null_rate': 0.1},
            'high_entropy_files': {'mean': 3.5, 'std': 2.5, 'min': 0, 'max': 10, 'null_rate': 0.15},
            'suspicious_ports': {'mean': 2.0, 'std': 1.5, 'min': 0, 'max': 5, 'null_rate': 0.1},
            'avg_file_entropy': {'mean': 5.8, 'std': 1.2, 'min': 4.0, 'max': 7.5, 'null_rate': 0.15},
            'high_entropy_ratio': {'mean': 0.45, 'std': 0.2, 'min': 0.1, 'max': 0.9, 'null_rate': 0.15},
            'stratum_indicators': {'mean': 0.35, 'std': 0.3, 'min': 0, 'max': 1.0, 'null_rate': 0.2},
            'raw_ip_connections': {'mean': 0.5, 'std': 0.3, 'min': 0, 'max': 1.0, 'null_rate': 0.2},
            'suspicious_dns_queries': {'mean': 0.4, 'std': 0.3, 'min': 0, 'max': 1.0, 'null_rate': 0.2},
            'stripped_binaries_ratio': {'mean': 0.6, 'std': 0.25, 'min': 0.2, 'max': 1.0, 'null_rate': 0.2},
            'packed_binary_score': {'mean': 0.5, 'std': 0.3, 'min': 0, 'max': 1.0, 'null_rate': 0.2},
            'layer_deletion_score': {'mean': 0.5, 'std': 0.3, 'min': 0, 'max': 1.0, 'null_rate': 0.2},
            'temp_file_activity': {'mean': 0.45, 'std': 0.3, 'min': 0, 'max': 1.0, 'null_rate': 0.2},
            'process_injection_risk': {'mean': 0.4, 'std': 0.3, 'min': 0, 'max': 1.0, 'null_rate': 0.2},
            'privilege_escalation_risk': {'mean': 0.5, 'std': 0.3, 'min': 0, 'max': 1.0, 'null_rate': 0.2},
            'crypto_mining_behavior': {'mean': 0.5, 'std': 0.35, 'min': 0, 'max': 1.0, 'null_rate': 0.2},
            'anti_analysis_score': {'mean': 0.55, 'std': 0.3, 'min': 0.1, 'max': 1.0, 'null_rate': 0.2},
        }
    
    def _generate_value(self, feature: str, stats: Dict, is_risky: bool) -> Optional[float]:
        """Generate a single feature value based on statistics"""
        
        # Handle null values
        if np.random.random() < stats.get('null_rate', 0.1):
            return None
        
        mean = stats['mean']
        std = stats['std']
        min_val = stats['min']
        max_val = stats['max']
        
        # Binary features (0 or 1)
        if feature in ['cryptominer_binary', 'ssh_backdoor', 'runs_as_root', 'outdated_base']:
            # Use mean as probability for binary features
            return 1 if np.random.random() < mean else 0
        
        # Integer features
        elif feature in ['mining_pools', 'hardcoded_secrets', 'external_calls', 
                         'known_cves', 'image_age_days', 'high_entropy_files', 'suspicious_ports']:
            # Use truncated normal distribution
            if std == 0:
                value = mean
            else:
                value = np.random.normal(mean, std)
            
            # Clip to bounds and round
            value = int(np.clip(np.round(value), min_val, max_val))
            return value
        
        # Float features (scores, ratios, etc.)
        else:
            if std == 0:
                value = mean
            else:
                # Use beta distribution for bounded [0, 1] features
                if max_val <= 1.0:
                    # Convert mean/std to beta parameters
                    if mean <= 0 or mean >= 1:
                        value = mean
                    else:
                        variance = min(std ** 2, mean * (1 - mean) * 0.99)
                        alpha = mean * ((mean * (1 - mean) / variance) - 1)
                        beta = (1 - mean) * ((mean * (1 - mean) / variance) - 1)
                        
                        if alpha > 0 and beta > 0:
                            value = np.random.beta(alpha, beta)
                        else:
                            value = np.random.normal(mean, std)
                else:
                    value = np.random.normal(mean, std)
            
            # Clip to bounds
            value = float(np.clip(value, min_val, max_val))
            
            # Round to reasonable precision
            return round(value, 3)
    
    def _enforce_correlations(self, row: Dict, is_risky: bool):
        """Enforce realistic correlations between features"""
        
        # Correlation 1: Cryptominer binary -> mining pools likely present
        if row.get('cryptominer_binary') == 1:
            if row.get('mining_pools') is not None and row['mining_pools'] == 0:
                row['mining_pools'] = np.random.randint(1, 4)
            if row.get('crypto_mining_behavior') is not None:
                row['crypto_mining_behavior'] = max(row['crypto_mining_behavior'], 0.5)
        
        # Correlation 2: High CVEs -> likely outdated
        if row.get('known_cves') is not None and row['known_cves'] > 20:
            if row.get('outdated_base') == 0:
                row['outdated_base'] = 1 if np.random.random() < 0.8 else 0
        
        # Correlation 3: SSH backdoor -> suspicious ports
        if row.get('ssh_backdoor') == 1:
            if row.get('suspicious_ports') is not None:
                row['suspicious_ports'] = max(row['suspicious_ports'], 1)
        
        # Correlation 4: High entropy -> packed binaries
        if row.get('high_entropy_ratio') is not None and row['high_entropy_ratio'] > 0.6:
            if row.get('packed_binary_score') is not None:
                row['packed_binary_score'] = max(row['packed_binary_score'], 0.4)
        
        # Correlation 5: Stratum indicators -> crypto mining behavior
        if row.get('stratum_indicators') is not None and row['stratum_indicators'] > 0.5:
            if row.get('crypto_mining_behavior') is not None:
                row['crypto_mining_behavior'] = max(row['crypto_mining_behavior'], 0.5)
        
        # Correlation 6: Process injection risk -> privilege escalation risk
        if row.get('process_injection_risk') is not None and row['process_injection_risk'] > 0.6:
            if row.get('privilege_escalation_risk') is not None:
                row['privilege_escalation_risk'] = max(row['privilege_escalation_risk'], 0.4)
    
    def generate_sample(self, is_risky: bool) -> Dict:
        """Generate a single synthetic sample"""
        
        stats = self.risky_stats if is_risky else self.safe_stats
        sample = {}
        
        # Generate each feature
        for feature in COLUMN_ORDER:
            if feature == 'label':
                sample[feature] = 1 if is_risky else 0
            elif feature in stats:
                sample[feature] = self._generate_value(feature, stats[feature], is_risky)
            else:
                sample[feature] = None
        
        # Enforce correlations
        self._enforce_correlations(sample, is_risky)
        
        return sample
    
    def generate_dataset(
        self,
        n_safe: int = 75,
        n_risky: int = 75,
        output_path: str = 'data/synthetic_docker_features.csv',
        seed: Optional[int] = None
    ) -> pd.DataFrame:
        """Generate a complete synthetic dataset"""
        
        if seed is not None:
            np.random.seed(seed)
            logger.info(f"Random seed set to {seed}")
        
        logger.info(f"Generating {n_safe} safe and {n_risky} risky samples...")
        
        samples = []
        
        # Generate safe samples
        for i in range(n_safe):
            sample = self.generate_sample(is_risky=False)
            samples.append(sample)
            if (i + 1) % 25 == 0:
                logger.info(f"  Generated {i + 1}/{n_safe} safe samples")
        
        # Generate risky samples
        for i in range(n_risky):
            sample = self.generate_sample(is_risky=True)
            samples.append(sample)
            if (i + 1) % 25 == 0:
                logger.info(f"  Generated {i + 1}/{n_risky} risky samples")
        
        # Create DataFrame with exact column order
        df = pd.DataFrame(samples)
        df = df[COLUMN_ORDER]
        
        # Shuffle rows
        df = df.sample(frac=1, random_state=seed).reset_index(drop=True)
        
        # Save to CSV
        os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
        df.to_csv(output_path, index=False)
        
        logger.info(f"\n✅ Synthetic dataset saved to {output_path}")
        self._print_statistics(df)
        
        return df
    
    def _print_statistics(self, df: pd.DataFrame):
        """Print dataset statistics"""
        logger.info("\n" + "="*70)
        logger.info("📊 SYNTHETIC DATASET STATISTICS")
        logger.info("="*70)
        
        logger.info(f"\nTotal samples: {len(df)}")
        logger.info(f"Safe (label=0): {len(df[df['label']==0])}")
        logger.info(f"Risky (label=1): {len(df[df['label']==1])}")
        
        logger.info(f"\n📋 Feature completeness (% non-null):")
        for col in COLUMN_ORDER:
            if col in df.columns and col != 'label':
                completeness = (df[col].notna().sum() / len(df)) * 100
                logger.info(f"   {col}: {completeness:.1f}%")
        
        # Key feature statistics by class
        logger.info(f"\n📈 Key features by class:")
        
        safe_df = df[df['label'] == 0]
        risky_df = df[df['label'] == 1]
        
        key_features = [
            'cryptominer_binary', 'known_cves', 'runs_as_root',
            'crypto_mining_behavior', 'high_entropy_ratio', 'outdated_base'
        ]
        
        for feature in key_features:
            if feature in df.columns:
                safe_mean = safe_df[feature].mean()
                risky_mean = risky_df[feature].mean()
                logger.info(f"   {feature}:")
                logger.info(f"      Safe:  {safe_mean:.3f}")
                logger.info(f"      Risky: {risky_mean:.3f}")


def merge_datasets(
    real_path: str,
    synthetic_path: str,
    output_path: str = 'data/merged_docker_features.csv',
    shuffle: bool = True,
    seed: Optional[int] = None
) -> pd.DataFrame:
    """Merge real and synthetic datasets"""
    
    logger.info("="*70)
    logger.info("🔀 MERGING DATASETS")
    logger.info("="*70)
    
    # Load datasets
    real_df = pd.read_csv(real_path)
    synthetic_df = pd.read_csv(synthetic_path)
    
    logger.info(f"\nReal dataset: {len(real_df)} samples")
    logger.info(f"Synthetic dataset: {len(synthetic_df)} samples")
    
    # Ensure same columns
    common_cols = [col for col in COLUMN_ORDER if col in real_df.columns and col in synthetic_df.columns]
    
    real_df = real_df[common_cols]
    synthetic_df = synthetic_df[common_cols]
    
    # Merge
    merged_df = pd.concat([real_df, synthetic_df], ignore_index=True)
    
    # Shuffle if requested
    if shuffle:
        if seed is not None:
            np.random.seed(seed)
        merged_df = merged_df.sample(frac=1).reset_index(drop=True)
        logger.info("Shuffled merged dataset")
    
    # Save
    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
    merged_df.to_csv(output_path, index=False)
    
    logger.info(f"\n✅ Merged dataset saved to {output_path}")
    logger.info(f"Total samples: {len(merged_df)}")
    logger.info(f"Safe (label=0): {len(merged_df[merged_df['label']==0])}")
    logger.info(f"Risky (label=1): {len(merged_df[merged_df['label']==1])}")
    logger.info("="*70)
    
    return merged_df


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Generate synthetic Docker image security dataset',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate 150 synthetic samples (75 safe + 75 risky)
  python generate_synthetic_data.py generate --safe 75 --risky 75
  
  # Learn from real data and generate
  python generate_synthetic_data.py generate --real-data data/enhanced_docker_features.csv --safe 100 --risky 100
  
  # Generate and merge with real data
  python generate_synthetic_data.py merge --real-data data/enhanced_docker_features.csv --synthetic data/synthetic_docker_features.csv
  
  # Generate with specific seed for reproducibility
  python generate_synthetic_data.py generate --safe 75 --risky 75 --seed 42
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # Generate command
    gen_parser = subparsers.add_parser('generate', help='Generate synthetic dataset')
    gen_parser.add_argument('--real-data', help='Path to real dataset (optional, for learning distributions)')
    gen_parser.add_argument('--safe', type=int, default=75, help='Number of safe samples')
    gen_parser.add_argument('--risky', type=int, default=75, help='Number of risky samples')
    gen_parser.add_argument('--output', default='data/synthetic_docker_features.csv', help='Output CSV file')
    gen_parser.add_argument('--seed', type=int, help='Random seed for reproducibility')
    
    # Merge command
    merge_parser = subparsers.add_parser('merge', help='Merge real and synthetic datasets')
    merge_parser.add_argument('--real-data', required=True, help='Path to real dataset')
    merge_parser.add_argument('--synthetic', required=True, help='Path to synthetic dataset')
    merge_parser.add_argument('--output', default='data/merged_docker_features.csv', help='Output CSV file')
    merge_parser.add_argument('--no-shuffle', action='store_true', help='Do not shuffle merged data')
    merge_parser.add_argument('--seed', type=int, help='Random seed for shuffling')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        exit(1)
    
    if args.command == 'generate':
        # Initialize generator
        generator = SyntheticDataGenerator(real_data_path=args.real_data)
        
        # Generate dataset
        df = generator.generate_dataset(
            n_safe=args.safe,
            n_risky=args.risky,
            output_path=args.output,
            seed=args.seed
        )
        
        logger.info(f"\n✅ Done! Generated {len(df)} samples")
    
    elif args.command == 'merge':
        # Merge datasets
        merged_df = merge_datasets(
            real_path=args.real_data,
            synthetic_path=args.synthetic,
            output_path=args.output,
            shuffle=not args.no_shuffle,
            seed=args.seed
        )
        
        logger.info(f"\n✅ Done! Merged dataset has {len(merged_df)} samples")