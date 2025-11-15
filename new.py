#!/usr/bin/env python3
"""
Synthetic Docker Image Dataset Generator
Creates realistic synthetic datasets that mimic real Docker image security features
with controlled characteristics and correlations.
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
import logging
from datetime import datetime, timedelta
import random

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class DistributionParams:
    """Parameters for feature distributions"""
    mean: float
    std: float
    min_val: float = 0.0
    max_val: float = 1.0
    
    
class SyntheticDockerGenerator:
    """
    Generates synthetic Docker image security datasets with realistic correlations
    """
    
    def __init__(self, seed: Optional[int] = 42):
        """
        Initialize generator
        
        Args:
            seed: Random seed for reproducibility
        """
        self.seed = seed
        if seed is not None:
            np.random.seed(seed)
            random.seed(seed)
        
        # Feature names matching your schema
        self.feature_names = [
            'cryptominer_binary', 'mining_pools', 'hardcoded_secrets',
            'external_calls', 'ssh_backdoor', 'runs_as_root',
            'known_cves', 'outdated_base', 'typosquatting_score',
            'image_age_days', 'high_entropy_files', 'suspicious_ports',
            'avg_file_entropy', 'high_entropy_ratio', 'stratum_indicators',
            'raw_ip_connections', 'suspicious_dns_queries', 'stripped_binaries_ratio',
            'packed_binary_score', 'layer_deletion_score', 'temp_file_activity',
            'process_injection_risk', 'privilege_escalation_risk',
            'crypto_mining_behavior', 'anti_analysis_score'
        ]
        
        # Define realistic distributions for safe vs risky images
        self._init_distributions()
        
        # Define feature correlations
        self._init_correlations()
    
    def _init_distributions(self):
        """Initialize distribution parameters for safe and risky images"""
        
        # SAFE IMAGE DISTRIBUTIONS (low risk values)
        self.safe_distributions = {
            # Binary features (mostly 0)
            'cryptominer_binary': {'prob': 0.001},
            'ssh_backdoor': {'prob': 0.05},
            'runs_as_root': {'prob': 0.3},
            'outdated_base': {'prob': 0.15},
            
            # Count features (low values)
            'mining_pools': {'mean': 0.02, 'std': 0.1, 'min': 0, 'max': 1},
            'hardcoded_secrets': {'mean': 0.5, 'std': 1.0, 'min': 0, 'max': 5},
            'external_calls': {'mean': 1.0, 'std': 1.5, 'min': 0, 'max': 5},
            'known_cves': {'mean': 2.0, 'std': 3.0, 'min': 0, 'max': 15},
            'high_entropy_files': {'mean': 1.5, 'std': 1.0, 'min': 0, 'max': 5},
            'suspicious_ports': {'mean': 0.5, 'std': 0.8, 'min': 0, 'max': 3},
            
            # Continuous features (0-1 scale, low values)
            'typosquatting_score': {'mean': 0.15, 'std': 0.1, 'min': 0, 'max': 0.5},
            'avg_file_entropy': {'mean': 0.05, 'std': 0.03, 'min': 0, 'max': 0.16},
            'high_entropy_ratio': {'mean': 0.02, 'std': 0.03, 'min': 0, 'max': 0.1},
            'stratum_indicators': {'mean': 0.01, 'std': 0.05, 'min': 0, 'max': 0.2},
            'raw_ip_connections': {'mean': 0.1, 'std': 0.15, 'min': 0, 'max': 0.5},
            'suspicious_dns_queries': {'mean': 0.05, 'std': 0.1, 'min': 0, 'max': 0.3},
            'stripped_binaries_ratio': {'mean': 0.1, 'std': 0.15, 'min': 0, 'max': 0.4},
            'packed_binary_score': {'mean': 0.05, 'std': 0.1, 'min': 0, 'max': 0.3},
            'layer_deletion_score': {'mean': 0.1, 'std': 0.15, 'min': 0, 'max': 0.4},
            'temp_file_activity': {'mean': 0.08, 'std': 0.12, 'min': 0, 'max': 0.4},
            'process_injection_risk': {'mean': 0.05, 'std': 0.1, 'min': 0, 'max': 0.3},
            'privilege_escalation_risk': {'mean': 0.1, 'std': 0.15, 'min': 0, 'max': 0.45},
            'crypto_mining_behavior': {'mean': 0.03, 'std': 0.05, 'min': 0, 'max': 0.15},
            'anti_analysis_score': {'mean': 0.15, 'std': 0.1, 'min': 0, 'max': 0.4},
            
            # Image age (newer images)
            'image_age_days': {'mean': 120, 'std': 90, 'min': 1, 'max': 500},
        }
        
        # RISKY IMAGE DISTRIBUTIONS (high risk values)
        self.risky_distributions = {
            # Binary features (higher probability)
            'cryptominer_binary': {'prob': 0.15},
            'ssh_backdoor': {'prob': 0.20},
            'runs_as_root': {'prob': 0.85},
            'outdated_base': {'prob': 0.70},
            
            # Count features (higher values)
            'mining_pools': {'mean': 0.4, 'std': 0.6, 'min': 0, 'max': 5},
            'hardcoded_secrets': {'mean': 3.0, 'std': 2.5, 'min': 0, 'max': 10},
            'external_calls': {'mean': 3.5, 'std': 2.0, 'min': 0, 'max': 10},
            'known_cves': {'mean': 25, 'std': 15, 'min': 5, 'max': 50},
            'high_entropy_files': {'mean': 3.5, 'std': 1.5, 'min': 1, 'max': 6},
            'suspicious_ports': {'mean': 2.5, 'std': 1.5, 'min': 0, 'max': 5},
            
            # Continuous features (higher values)
            'typosquatting_score': {'mean': 0.65, 'std': 0.25, 'min': 0.3, 'max': 1.0},
            'avg_file_entropy': {'mean': 0.12, 'std': 0.06, 'min': 0.05, 'max': 0.24},
            'high_entropy_ratio': {'mean': 0.15, 'std': 0.1, 'min': 0, 'max': 0.35},
            'stratum_indicators': {'mean': 0.5, 'std': 0.35, 'min': 0, 'max': 1.0},
            'raw_ip_connections': {'mean': 0.5, 'std': 0.3, 'min': 0.1, 'max': 1.0},
            'suspicious_dns_queries': {'mean': 0.4, 'std': 0.3, 'min': 0, 'max': 0.9},
            'stripped_binaries_ratio': {'mean': 0.3, 'std': 0.25, 'min': 0, 'max': 0.8},
            'packed_binary_score': {'mean': 0.25, 'std': 0.2, 'min': 0, 'max': 0.7},
            'layer_deletion_score': {'mean': 0.35, 'std': 0.25, 'min': 0, 'max': 0.8},
            'temp_file_activity': {'mean': 0.4, 'std': 0.25, 'min': 0.1, 'max': 0.9},
            'process_injection_risk': {'mean': 0.35, 'std': 0.25, 'min': 0, 'max': 0.75},
            'privilege_escalation_risk': {'mean': 0.5, 'std': 0.25, 'min': 0.15, 'max': 0.9},
            'crypto_mining_behavior': {'mean': 0.3, 'std': 0.2, 'min': 0.05, 'max': 0.8},
            'anti_analysis_score': {'mean': 0.6, 'std': 0.25, 'min': 0.2, 'max': 1.0},
            
            # Image age (older images)
            'image_age_days': {'mean': 800, 'std': 600, 'min': 365, 'max': 2500},
        }
    
    def _init_correlations(self):
        """Define realistic feature correlations"""
        
        self.correlations = {
            # Cryptominer binary correlates with mining indicators
            'cryptominer_binary': {
                'mining_pools': 0.85,
                'stratum_indicators': 0.80,
                'crypto_mining_behavior': 0.90,
                'high_entropy_files': 0.60,
                'packed_binary_score': 0.70,
            },
            
            # Outdated base correlates with CVEs
            'outdated_base': {
                'known_cves': 0.75,
                'image_age_days': 0.80,
            },
            
            # Root access correlates with privilege escalation
            'runs_as_root': {
                'privilege_escalation_risk': 0.65,
                'process_injection_risk': 0.50,
            },
            
            # Obfuscation indicators correlate
            'high_entropy_files': {
                'avg_file_entropy': 0.70,
                'high_entropy_ratio': 0.75,
                'packed_binary_score': 0.65,
                'anti_analysis_score': 0.60,
            },
            
            # Network indicators correlate
            'suspicious_ports': {
                'external_calls': 0.55,
                'raw_ip_connections': 0.60,
                'suspicious_dns_queries': 0.50,
            },
            
            # Backdoor correlates with suspicious activity
            'ssh_backdoor': {
                'suspicious_ports': 0.70,
                'temp_file_activity': 0.55,
            },
        }
    
    def _apply_correlations(self, df: pd.DataFrame, label: int) -> pd.DataFrame:
        """Apply realistic correlations between features"""
        
        for primary_feature, correlated_features in self.correlations.items():
            if primary_feature not in df.columns:
                continue
            
            for corr_feature, strength in correlated_features.items():
                if corr_feature not in df.columns:
                    continue
                
                # Get primary feature values
                primary_vals = df[primary_feature].values
                
                # For binary features
                if primary_feature in ['cryptominer_binary', 'ssh_backdoor', 'runs_as_root', 'outdated_base']:
                    # When primary is 1, boost correlated feature
                    mask = primary_vals == 1
                    if mask.any():
                        boost_factor = 1.0 + strength
                        df.loc[mask, corr_feature] *= boost_factor
                        
                        # Clip to valid range
                        if corr_feature in ['mining_pools', 'hardcoded_secrets', 'known_cves', 
                                           'high_entropy_files', 'suspicious_ports', 'external_calls']:
                            max_val = self.risky_distributions[corr_feature]['max']
                            df.loc[mask, corr_feature] = df.loc[mask, corr_feature].clip(upper=max_val)
                        else:
                            df.loc[mask, corr_feature] = df.loc[mask, corr_feature].clip(upper=1.0)
        
        return df
    
    def _generate_binary_feature(self, n: int, prob: float) -> np.ndarray:
        """Generate binary feature with given probability"""
        return np.random.binomial(1, prob, n)
    
    def _generate_continuous_feature(self, n: int, params: Dict) -> np.ndarray:
        """Generate continuous feature with truncated normal distribution"""
        mean = params['mean']
        std = params['std']
        min_val = params['min']
        max_val = params['max']
        
        # Generate normal distribution
        values = np.random.normal(mean, std, n)
        
        # Clip to valid range
        values = np.clip(values, min_val, max_val)
        
        return values
    
    def _add_noise(self, df: pd.DataFrame, noise_level: float = 0.05) -> pd.DataFrame:
        """Add realistic noise to features"""
        
        for col in df.columns:
            if col in ['label', 'image_name']:
                continue
            
            # Skip binary features
            if col in ['cryptominer_binary', 'ssh_backdoor', 'runs_as_root', 'outdated_base']:
                continue
            
            # Add Gaussian noise
            noise = np.random.normal(0, noise_level * df[col].std(), len(df))
            df[col] = df[col] + noise
            
            # Clip to valid ranges
            if col == 'image_age_days':
                df[col] = df[col].clip(lower=1, upper=3000)
            elif col in ['mining_pools', 'hardcoded_secrets', 'external_calls', 'known_cves',
                        'high_entropy_files', 'suspicious_ports']:
                max_val = 50 if col == 'known_cves' else 10
                df[col] = df[col].clip(lower=0, upper=max_val)
            else:
                df[col] = df[col].clip(lower=0, upper=1.0)
        
        return df
    
    def _generate_image_names(self, n_safe: int, n_risky: int) -> List[str]:
        """Generate realistic Docker image names"""
        
        safe_bases = [
            'nginx', 'python', 'node', 'ubuntu', 'postgres', 'mysql', 'redis',
            'alpine', 'debian', 'golang', 'java', 'php', 'ruby', 'httpd'
        ]
        
        risky_bases = [
            'ubuntu', 'debian', 'centos', 'python', 'node', 'php', 'postgres',
            'mysql', 'redis', 'nginx'
        ]
        
        tags = ['latest', 'alpine', 'slim', '1.0', '2.0', 'v1', 'stable']
        old_tags = ['14.04', '16.04', '2.7', '5.6', '9.6', '3.0', 'jessie', 'wheezy']
        
        image_names = []
        
        # Generate safe image names
        for i in range(n_safe):
            base = random.choice(safe_bases)
            tag = random.choice(tags)
            image_names.append(f"{base}:{tag}")
        
        # Generate risky image names
        for i in range(n_risky):
            base = random.choice(risky_bases)
            tag = random.choice(old_tags)
            
            # Some typosquatting
            if random.random() < 0.2:
                # Add typo
                if random.random() < 0.5:
                    base = base.replace('o', '0').replace('i', '1')
                else:
                    base = base + random.choice(['x', 'v2', '-alt', '_'])
            
            image_names.append(f"{base}:{tag}")
        
        return image_names
    
    def generate(
        self,
        n_safe: int = 500,
        n_risky: int = 500,
        noise_level: float = 0.05,
        apply_correlations: bool = True,
        missing_data_rate: float = 0.0
    ) -> pd.DataFrame:
        """
        Generate synthetic dataset
        
        Args:
            n_safe: Number of safe images
            n_risky: Number of risky images
            noise_level: Amount of noise to add (0-1)
            apply_correlations: Whether to apply feature correlations
            missing_data_rate: Proportion of missing values (0-1)
        
        Returns:
            DataFrame with synthetic features
        """
        
        logger.info(f"Generating synthetic dataset: {n_safe} safe + {n_risky} risky")
        
        all_data = []
        
        # Generate SAFE images
        logger.info("Generating safe images...")
        safe_data = {}
        
        for feature in self.feature_names:
            params = self.safe_distributions.get(feature, {})
            
            if 'prob' in params:
                # Binary feature
                safe_data[feature] = self._generate_binary_feature(n_safe, params['prob'])
            else:
                # Continuous/count feature
                safe_data[feature] = self._generate_continuous_feature(n_safe, params)
        
        safe_df = pd.DataFrame(safe_data)
        safe_df['label'] = 0
        
        if apply_correlations:
            safe_df = self._apply_correlations(safe_df, 0)
        
        all_data.append(safe_df)
        
        # Generate RISKY images
        logger.info("Generating risky images...")
        risky_data = {}
        
        for feature in self.feature_names:
            params = self.risky_distributions.get(feature, {})
            
            if 'prob' in params:
                risky_data[feature] = self._generate_binary_feature(n_risky, params['prob'])
            else:
                risky_data[feature] = self._generate_continuous_feature(n_risky, params)
        
        risky_df = pd.DataFrame(risky_data)
        risky_df['label'] = 1
        
        if apply_correlations:
            risky_df = self._apply_correlations(risky_df, 1)
        
        all_data.append(risky_df)
        
        # Combine
        df = pd.concat(all_data, ignore_index=True)
        
        # Add noise
        if noise_level > 0:
            logger.info(f"Adding noise (level: {noise_level})")
            df = self._add_noise(df, noise_level)
        
        # Add image names
        image_names = self._generate_image_names(n_safe, n_risky)
        df['image_name'] = image_names
        
        # Add missing data
        if missing_data_rate > 0:
            logger.info(f"Adding missing data ({missing_data_rate*100:.1f}%)")
            for col in df.columns:
                if col in ['label', 'image_name']:
                    continue
                
                # Randomly set values to NaN
                mask = np.random.random(len(df)) < missing_data_rate
                df.loc[mask, col] = np.nan
        
        # Round integer features
        int_features = ['cryptominer_binary', 'ssh_backdoor', 'runs_as_root', 'outdated_base',
                       'mining_pools', 'hardcoded_secrets', 'external_calls', 'known_cves',
                       'high_entropy_files', 'suspicious_ports', 'image_age_days']
        
        for col in int_features:
            if col in df.columns:
                df[col] = df[col].round().astype('Int64')  # Int64 supports NaN
        
        # Reorder columns
        cols = ['image_name'] + self.feature_names + ['label']
        df = df[cols]
        
        # Shuffle
        df = df.sample(frac=1, random_state=self.seed).reset_index(drop=True)
        
        logger.info(f"Generated dataset: {len(df)} rows, {len(df.columns)} columns")
        logger.info(f"  Safe: {(df['label']==0).sum()}")
        logger.info(f"  Risky: {(df['label']==1).sum()}")
        
        return df
    
    def generate_adversarial(self, n: int = 100) -> pd.DataFrame:
        """
        Generate adversarial examples (risky images disguised as safe)
        
        Args:
            n: Number of adversarial examples
        
        Returns:
            DataFrame with adversarial examples
        """
        
        logger.info(f"Generating {n} adversarial examples...")
        
        # Start with safe-looking features
        adv_data = {}
        
        for feature in self.feature_names:
            params = self.safe_distributions.get(feature, {})
            
            if 'prob' in params:
                # Use safe probability but slightly elevated
                adv_data[feature] = self._generate_binary_feature(n, params['prob'] * 2)
            else:
                # Use safe distribution but with higher mean
                adv_params = params.copy()
                adv_params['mean'] *= 1.5
                adv_data[feature] = self._generate_continuous_feature(n, adv_params)
        
        df = pd.DataFrame(adv_data)
        
        # Add subtle malicious indicators
        # 20% have cryptominer but hidden
        crypto_mask = np.random.random(n) < 0.2
        df.loc[crypto_mask, 'cryptominer_binary'] = 1
        df.loc[crypto_mask, 'crypto_mining_behavior'] *= 1.5
        df.loc[crypto_mask, 'high_entropy_files'] += 2
        
        # Add image names (typosquatting)
        legit_names = ['nginx', 'python', 'node', 'ubuntu', 'postgres']
        image_names = []
        for _ in range(n):
            base = random.choice(legit_names)
            # Subtle typo
            if random.random() < 0.5:
                base = base.replace('o', '0').replace('i', '1')
            image_names.append(f"{base}:latest")
        
        df['image_name'] = image_names
        df['label'] = 1  # Actually risky
        
        # Reorder columns
        cols = ['image_name'] + self.feature_names + ['label']
        df = df[cols]
        
        logger.info(f"Generated {n} adversarial examples")
        
        return df


def generate_datasets(output_dir: str = 'data/synthetic'):
    """Generate multiple synthetic datasets for different purposes"""
    
    import os
    os.makedirs(output_dir, exist_ok=True)
    
    generator = SyntheticDockerGenerator(seed=42)
    
    # 1. Balanced training set
    logger.info("\n" + "="*70)
    logger.info("1. Generating BALANCED TRAINING SET")
    logger.info("="*70)
    df_train = generator.generate(
        n_safe=5000,
        n_risky=5000,
        noise_level=0.05,
        apply_correlations=True,
        missing_data_rate=0.05
    )
    train_file = f"{output_dir}/synthetic_train_balanced.csv"
    df_train.to_csv(train_file, index=False)
    logger.info(f"✓ Saved: {train_file}")
    
    # 2. Imbalanced set (realistic - more safe than risky)
    logger.info("\n" + "="*70)
    logger.info("2. Generating IMBALANCED SET (80% safe, 20% risky)")
    logger.info("="*70)
    df_imbalanced = generator.generate(
        n_safe=8000,
        n_risky=2000,
        noise_level=0.05,
        apply_correlations=True,
        missing_data_rate=0.05
    )
    imbalanced_file = f"{output_dir}/synthetic_imbalanced.csv"
    df_imbalanced.to_csv(imbalanced_file, index=False)
    logger.info(f"✓ Saved: {imbalanced_file}")
    
    # 3. Test set (smaller, balanced)
    logger.info("\n" + "="*70)
    logger.info("3. Generating TEST SET")
    logger.info("="*70)
    df_test = generator.generate(
        n_safe=1000,
        n_risky=1000,
        noise_level=0.03,
        apply_correlations=True,
        missing_data_rate=0.02
    )
    test_file = f"{output_dir}/synthetic_test.csv"
    df_test.to_csv(test_file, index=False)
    logger.info(f"✓ Saved: {test_file}")
    
    # 4. Adversarial set
    logger.info("\n" + "="*70)
    logger.info("4. Generating ADVERSARIAL SET")
    logger.info("="*70)
    df_adv = generator.generate_adversarial(n=500)
    adv_file = f"{output_dir}/synthetic_adversarial.csv"
    df_adv.to_csv(adv_file, index=False)
    logger.info(f"✓ Saved: {adv_file}")
    
    # 5. High-quality set (no missing data, low noise)
    logger.info("\n" + "="*70)
    logger.info("5. Generating HIGH-QUALITY SET")
    logger.info("="*70)
    df_hq = generator.generate(
        n_safe=2000,
        n_risky=2000,
        noise_level=0.01,
        apply_correlations=True,
        missing_data_rate=0.0
    )
    hq_file = f"{output_dir}/synthetic_high_quality.csv"
    df_hq.to_csv(hq_file, index=False)
    logger.info(f"✓ Saved: {hq_file}")
    
    # Summary
    logger.info("\n" + "="*70)
    logger.info("📊 GENERATION SUMMARY")
    logger.info("="*70)
    logger.info(f"Total datasets generated: 5")
    logger.info(f"Total samples: {len(df_train) + len(df_imbalanced) + len(df_test) + len(df_adv) + len(df_hq)}")
    logger.info(f"Output directory: {output_dir}")
    logger.info("\nFiles:")
    logger.info(f"  1. {train_file} ({len(df_train)} rows)")
    logger.info(f"  2. {imbalanced_file} ({len(df_imbalanced)} rows)")
    logger.info(f"  3. {test_file} ({len(df_test)} rows)")
    logger.info(f"  4. {adv_file} ({len(df_adv)} rows)")
    logger.info(f"  5. {hq_file} ({len(df_hq)} rows)")
    logger.info("="*70)
    
    return {
        'train': df_train,
        'imbalanced': df_imbalanced,
        'test': df_test,
        'adversarial': df_adv,
        'high_quality': df_hq
    }


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Generate synthetic Docker image security datasets',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate all datasets
  python synthetic_generator.py all
  
  # Generate custom balanced set
  python synthetic_generator.py custom --n-safe 1000 --n-risky 1000 --output my_data.csv
  
  # Generate with high noise
  python synthetic_generator.py custom --n-safe 500 --n-risky 500 --noise 0.2
  
  # Generate adversarial examples
  python synthetic_generator.py adversarial --n 200 --output adversarial.csv
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # All datasets
    all_parser = subparsers.add_parser('all', help='Generate all standard datasets')
    all_parser.add_argument('--output-dir', default='data/synthetic',
                           help='Output directory')
    
    # Custom dataset
    custom_parser = subparsers.add_parser('custom', help='Generate custom dataset')
    custom_parser.add_argument('--n-safe', type=int, default=500,
                              help='Number of safe images')
    custom_parser.add_argument('--n-risky', type=int, default=500,
                              help='Number of risky images')
    custom_parser.add_argument('--noise', type=float, default=0.05,
                              help='Noise level (0-1)')
    custom_parser.add_argument('--missing', type=float, default=0.05,
                              help='Missing data rate (0-1)')
    custom_parser.add_argument('--no-correlations', action='store_true',
                              help='Disable feature correlations')
    custom_parser.add_argument('--output', default='data/synthetic/custom.csv',
                              help='Output CSV file')
    custom_parser.add_argument('--seed', type=int, default=42,
                              help='Random seed')
    
    # Adversarial dataset
    adv_parser = subparsers.add_parser('adversarial', help='Generate adversarial examples')
    adv_parser.add_argument('--n', type=int, default=100,
                           help='Number of adversarial examples')
    adv_parser.add_argument('--output', default='data/synthetic/adversarial.csv',
                           help='Output CSV file')
    adv_parser.add_argument('--seed', type=int, default=42,
                           help='Random seed')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        exit(1)
    
    if args.command == 'all':
        generate_datasets(args.output_dir)
    
    elif args.command == 'custom':
        generator = SyntheticDockerGenerator(seed=args.seed)
        
        df = generator.generate(
            n_safe=args.n_safe,
            n_risky=args.n_risky,
            noise_level=args.noise,
            apply_correlations=not args.no_correlations,
            missing_data_rate=args.missing
        )
        
        import os
        os.makedirs(os.path.dirname(args.output) or '.', exist_ok=True)
        df.to_csv(args.output, index=False)
        
        logger.info(f"\n✓ Saved custom dataset: {args.output}")
        logger.info(f"  Shape: {df.shape}")
        logger.info(f"  Safe: {(df['label']==0).sum()}")
        logger.info(f"  Risky: {(df['label']==1).sum()}")
    
    elif args.command == 'adversarial':
        generator = SyntheticDockerGenerator(seed=args.seed)
        
        df = generator.generate_adversarial(n=args.n)
        
        import os
        os.makedirs(os.path.dirname(args.output) or '.', exist_ok=True)
        df.to_csv(args.output, index=False)
        
        logger.info(f"\n✓ Saved adversarial dataset: {args.output}")
        logger.info(f"  Shape: {df.shape}")
        logger.info(f"  All labeled as risky: {(df['label']==1).sum()}")