#!/usr/bin/env python3
"""
Enhance Existing CSV with Behavioral Features
NO RESCANNING NEEDED - Uses your existing cache files!
"""

import pandas as pd
import json
from pathlib import Path
import hashlib
from backend.behavioral_analyzer import BehavioralAnalyzer
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def get_cache_path_for_image(cache_dir: Path, image_name: str) -> Path:
    """Get cache directory path for an image (same logic as your scanner)"""
    safe_name = hashlib.md5(image_name.encode()).hexdigest()[:12]
    return cache_dir / safe_name


def list_missing_cache_images(input_csv: str, cache_dir: str = 'scan_cache'):
    """
    List images that don't have cache (useful for selective rescanning)
    """
    df = pd.read_csv(input_csv)
    cache_path = Path(cache_dir)
    
    missing_images = []
    
    for idx, row in df.iterrows():
        image_name = row['image_name']
        image_cache_dir = get_cache_path_for_image(cache_path, image_name)
        trivy_file = image_cache_dir / 'trivy.json'
        syft_file = image_cache_dir / 'sbom.json'
        
        if not trivy_file.exists() or not syft_file.exists():
            missing_images.append(image_name)
    
    return missing_images


def enhance_csv_with_behavioral_features(
    input_csv: str,
    cache_dir: str = 'scan_cache',
    output_csv: str = None
):
    """
    Add behavioral features to existing CSV without rescanning
    
    Args:
        input_csv: Your existing CSV file (e.g., 'data/enhanced_docker_features.csv')
        cache_dir: Directory with cached scan results (default: 'scan_cache')
        output_csv: Output file (default: input_csv with '_behavioral' suffix)
    """
    
    if output_csv is None:
        output_csv = input_csv.replace('.csv', '_behavioral.csv')
    
    logger.info("="*70)
    logger.info("🚀 Enhancing CSV with Behavioral Features")
    logger.info("="*70)
    logger.info(f"Input CSV: {input_csv}")
    logger.info(f"Cache directory: {cache_dir}")
    logger.info(f"Output CSV: {output_csv}")
    logger.info("="*70)
    
    # Load existing CSV
    df = pd.read_csv(input_csv)
    logger.info(f"✓ Loaded {len(df)} images from CSV")
    
    # Initialize behavioral analyzer
    analyzer = BehavioralAnalyzer()
    cache_path = Path(cache_dir)
    
    # Track success/failure
    enhanced = 0
    failed = 0
    
    # New columns for behavioral features
    behavioral_columns = [
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
        'anti_analysis_score'
    ]
    
    # Initialize new columns with NaN
    for col in behavioral_columns:
        df[col] = float('nan')
    
    logger.info("\n🔍 Processing images...")
    
    # Count how many have cache first
    total_cached = 0
    for idx, row in df.iterrows():
        image_cache_dir = get_cache_path_for_image(cache_path, row['image_name'])
        if (image_cache_dir / 'trivy.json').exists() and (image_cache_dir / 'sbom.json').exists():
            total_cached += 1
    
    logger.info(f"📦 Found cache for {total_cached}/{len(df)} images")
    logger.info(f"⚠️  Missing cache for {len(df) - total_cached} images (will skip those)\n")
    
    # Process each image
    for idx, row in df.iterrows():
        image_name = row['image_name']
        
        # Get cache directory for this image
        image_cache_dir = get_cache_path_for_image(cache_path, image_name)
        trivy_file = image_cache_dir / 'trivy.json'
        syft_file = image_cache_dir / 'sbom.json'
        
        # Check if cache files exist
        if not trivy_file.exists() or not syft_file.exists():
            if (idx + 1) % 10 == 0 or idx < 25:  # Show more detail for first 25
                logger.warning(f"[{idx+1}/{len(df)}] ⚠️  Missing cache: {image_name}")
            failed += 1
            continue
        
        try:
            # Load cached scan results
            with open(trivy_file) as f:
                trivy_data = json.load(f)
            
            with open(syft_file) as f:
                syft_data = json.load(f)
            
            # Extract behavioral features
            behavioral_features = analyzer.analyze_image(
                image_name, trivy_data, syft_data
            )
            
            # Add to dataframe
            for feature_name, value in behavioral_features.items():
                if feature_name in behavioral_columns:
                    df.at[idx, feature_name] = value
            
            enhanced += 1
            
            # Log progress
            if (idx + 1) % 10 == 0:
                logger.info(f"[{idx+1}/{len(df)}] ✓ Processed {enhanced} images")
            
        except Exception as e:
            logger.error(f"[{idx+1}/{len(df)}] ❌ Error processing {image_name}: {e}")
            failed += 1
    
    # Save enhanced CSV
    df.to_csv(output_csv, index=False)
    
    # Print summary
    logger.info("\n" + "="*70)
    logger.info("✅ ENHANCEMENT COMPLETE")
    logger.info("="*70)
    logger.info(f"Successfully enhanced: {enhanced}/{len(df)} images ({enhanced/len(df)*100:.1f}%)")
    logger.info(f"Skipped (no cache): {failed}/{len(df)} images ({failed/len(df)*100:.1f}%)")
    
    if failed > 0:
        logger.info(f"\n💡 Note: {failed} images don't have cached data")
        logger.info("   Their behavioral features will be NaN (your ML model can handle this)")
        logger.info("   To get features for these images, you'd need to rescan them")
    
    logger.info(f"\n💾 Output saved to: {output_csv}")
    logger.info("="*70)
    
    # Show feature statistics
    logger.info("\n📊 New Feature Statistics:")
    logger.info("-"*70)
    
    for col in behavioral_columns:
        if col in df.columns:
            completeness = (df[col].notna().sum() / len(df)) * 100
            mean_val = df[col].mean()
            max_val = df[col].max()
            
            logger.info(f"{col:30s} | Complete: {completeness:5.1f}% | "
                       f"Mean: {mean_val:.3f} | Max: {max_val:.3f}")
    
    # Show high-risk images based on composite score
    logger.info("\n🔴 High-Risk Images (crypto_mining_behavior > 0.7):")
    logger.info("-"*70)
    
    high_risk = df[df['crypto_mining_behavior'] > 0.7].sort_values(
        'crypto_mining_behavior', ascending=False
    )
    
    if len(high_risk) > 0:
        for _, row in high_risk.head(10).iterrows():
            logger.info(f"  {row['image_name']:40s} | Score: {row['crypto_mining_behavior']:.3f} | "
                       f"Label: {'RISKY' if row.get('label', 0) == 1 else 'SAFE'}")
    else:
        logger.info("  None found")
    
    return df


def validate_enhancement(original_csv: str, enhanced_csv: str):
    """
    Compare original and enhanced CSV to validate enhancement
    """
    logger.info("\n" + "="*70)
    logger.info("🔍 VALIDATION: Comparing Original vs Enhanced")
    logger.info("="*70)
    
    df_old = pd.read_csv(original_csv)
    df_new = pd.read_csv(enhanced_csv)
    
    logger.info(f"Original columns: {len(df_old.columns)}")
    logger.info(f"Enhanced columns: {len(df_new.columns)}")
    logger.info(f"New features added: {len(df_new.columns) - len(df_old.columns)}")
    
    # Check if original features are unchanged
    common_cols = set(df_old.columns) & set(df_new.columns)
    
    all_match = True
    for col in common_cols:
        if col == 'image_name':
            continue
        
        # Compare with tolerance for floating point
        if not df_old[col].fillna(0).equals(df_new[col].fillna(0)):
            # Check if close enough (for floating point comparison)
            try:
                if not ((df_old[col].fillna(0) - df_new[col].fillna(0)).abs() < 0.0001).all():
                    logger.warning(f"⚠️  Column '{col}' values differ!")
                    all_match = False
            except:
                pass
    
    if all_match:
        logger.info("✅ Original features unchanged - enhancement successful!")
    else:
        logger.warning("⚠️  Some original features changed - check carefully")
    
    logger.info("="*70)


if __name__ == "__main__":
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Enhance existing CSV with behavioral features (no rescanning!)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Enhance your existing CSV
  python enhance_existing_csv.py data/enhanced_docker_features.csv
  
  # Specify custom cache directory
  python enhance_existing_csv.py data/enhanced_docker_features.csv --cache-dir scan_cache
  
  # Specify output file
  python enhance_existing_csv.py data/enhanced_docker_features.csv -o data/final_features.csv
  
  # With validation
  python enhance_existing_csv.py data/enhanced_docker_features.csv --validate
        """
    )
    
    parser.add_argument('input_csv', help='Input CSV file with existing features')
    parser.add_argument('--cache-dir', default='scan_cache', 
                       help='Cache directory with scan results (default: scan_cache)')
    parser.add_argument('-o', '--output', default=None,
                       help='Output CSV file (default: input_behavioral.csv)')
    parser.add_argument('--validate', action='store_true',
                       help='Validate enhancement after completion')
    
    args = parser.parse_args()
    
    # Check if input file exists
    if not Path(args.input_csv).exists():
        logger.error(f"❌ Input file not found: {args.input_csv}")
        sys.exit(1)
    
    # Check if cache directory exists
    if not Path(args.cache_dir).exists():
        logger.error(f"❌ Cache directory not found: {args.cache_dir}")
        logger.info("Make sure you're running this in the same directory where you ran the scanner")
        sys.exit(1)
    
    # Enhance CSV
    enhanced_df = enhance_csv_with_behavioral_features(
        args.input_csv,
        cache_dir=args.cache_dir,
        output_csv=args.output
    )
    
    # Validate if requested
    if args.validate:
        output_file = args.output or args.input_csv.replace('.csv', '_behavioral.csv')
        validate_enhancement(args.input_csv, output_file)
    
    logger.info("\n✅ Done! Your enhanced CSV is ready for ML training.")