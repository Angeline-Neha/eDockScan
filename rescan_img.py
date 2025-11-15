#!/usr/bin/env python3
"""
Rescan images with missing cache or partial scans
Then merge results back into the original CSV
"""
import os
import pandas as pd
import sys
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def identify_missing_images(csv_file: str, output_list: str = 'missing_images.txt'):
    """
    Identify images that need rescanning and save to a file
    """
    df = pd.read_csv(csv_file)
    
    logger.info("="*70)
    logger.info("🔍 Identifying Images Needing Rescan")
    logger.info("="*70)
    
    # Images needing rescan:
    # 1. scan_status == 'partial' (incomplete scans)
    # 2. Missing behavioral features (crypto_mining_behavior is NaN)
    # 3. scan_status == 'failed'
    
    needs_rescan = []
    
    for idx, row in df.iterrows():
        image_name = row['image_name']
        scan_status = row.get('scan_status', 'unknown')
        crypto_behavior = row.get('crypto_mining_behavior', None)
        
        reasons = []
        
        # Check scan status
        if pd.isna(scan_status) or scan_status in ['partial', 'failed', 'unknown']:
            reasons.append(f"scan_status={scan_status}")
        
        # Check if behavioral features are missing
        if pd.isna(crypto_behavior):
            reasons.append("missing_behavioral_features")
        
        if reasons:
            needs_rescan.append({
                'image': image_name,
                'reason': ', '.join(reasons),
                'label': row.get('label', 'unknown')
            })
    
    # Separate by label for balance
    safe_images = [item['image'] for item in needs_rescan if item['label'] == 0]
    risky_images = [item['image'] for item in needs_rescan if item['label'] == 1]
    unknown_images = [item['image'] for item in needs_rescan if item['label'] not in [0, 1]]
    
    logger.info(f"\n📊 Images Needing Rescan:")
    logger.info(f"   Safe (label=0): {len(safe_images)}")
    logger.info(f"   Risky (label=1): {len(risky_images)}")
    logger.info(f"   Unknown label: {len(unknown_images)}")
    logger.info(f"   Total: {len(needs_rescan)}")
    
    # Save to file
    with open(output_list, 'w') as f:
        f.write("# Images needing rescan\n")
        f.write(f"# Total: {len(needs_rescan)}\n")
        f.write(f"# Safe: {len(safe_images)}, Risky: {len(risky_images)}\n\n")
        
        for item in needs_rescan:
            f.write(f"{item['image']}\n")
    
    logger.info(f"\n💾 Saved to: {output_list}")
    
    # Show sample
    logger.info(f"\n📋 Sample images to rescan (first 10):")
    for item in needs_rescan[:10]:
        logger.info(f"   {item['image']:40s} | {item['reason']}")
    
    if len(needs_rescan) > 10:
        logger.info(f"   ... and {len(needs_rescan) - 10} more")
    
    logger.info("\n" + "="*70)
    
    return safe_images, risky_images


def create_rescan_script(safe_images, risky_images, output_script='rescan.py'):
    """
    Create a Python script to rescan only the missing images
    """
    
    script_content = f'''#!/usr/bin/env python3
"""
Auto-generated script to rescan {len(safe_images) + len(risky_images)} images with missing data
Generated from rescan_missing.py
"""

import sys
import os

# Import your scanner
from extract_features import extract_dataset_parallel

# Images to rescan
SAFE_IMAGES = {safe_images}

RISKY_IMAGES = {risky_images}

if __name__ == "__main__":
    print("="*70)
    print(f"🔄 Rescanning {{len(SAFE_IMAGES) + len(RISKY_IMAGES)}} images")
    print("="*70)
    print(f"Safe images: {{len(SAFE_IMAGES)}}")
    print(f"Risky images: {{len(RISKY_IMAGES)}}")
    print("="*70)
    
    # Run the scan
    df = extract_dataset_parallel(
        safe_images=SAFE_IMAGES,
        risky_images=RISKY_IMAGES,
        output_csv='data/rescanned_images.csv',
        timeout_per_image=300,
        max_workers=3
    )
    
    print("\\n✅ Rescan complete!")
    print("📊 Results saved to: data/rescanned_images.csv")
    print("\\n📋 Next steps:")
    print("   1. Review the rescanned data")
    print("   2. Run: python rescan_missing.py merge")
    print("      to merge back into data/final_training_data.csv")
'''
    
    with open(output_script, 'w') as f:
        f.write(script_content)
    
    # Make executable
    import stat
    os.chmod(output_script, os.stat(output_script).st_mode | stat.S_IEXEC)
    
    logger.info(f"✅ Created rescan script: {output_script}")
    logger.info(f"\n📋 To rescan, run:")
    logger.info(f"   python {output_script}")


def merge_rescanned_data(original_csv='data/final_training_data.csv',
                         rescanned_csv='data/rescanned_images.csv',
                         output_csv='data/final_training_data_complete.csv'):
    """
    Merge rescanned data back into the original CSV
    """
    
    logger.info("="*70)
    logger.info("🔀 Merging Rescanned Data")
    logger.info("="*70)
    
    # Load both CSVs
    df_original = pd.read_csv(original_csv)
    df_rescanned = pd.read_csv(rescanned_csv)
    
    logger.info(f"✓ Loaded original: {len(df_original)} rows")
    logger.info(f"✓ Loaded rescanned: {len(df_rescanned)} rows")
    
    # Create a dict of rescanned data for quick lookup
    rescanned_dict = {}
    for _, row in df_rescanned.iterrows():
        rescanned_dict[row['image_name']] = row.to_dict()
    
    # Update original dataframe
    updated_count = 0
    
    for idx, row in df_original.iterrows():
        image_name = row['image_name']
        
        if image_name in rescanned_dict:
            # Update this row with rescanned data
            rescanned_row = rescanned_dict[image_name]
            
            for col in rescanned_row.keys():
                if col != 'image_name':  # Don't overwrite image name
                    df_original.at[idx, col] = rescanned_row[col]
            
            updated_count += 1
    
    # Save merged CSV
    df_original.to_csv(output_csv, index=False)
    
    logger.info(f"\n✅ Merge complete!")
    logger.info(f"   Updated {updated_count} rows")
    logger.info(f"   Saved to: {output_csv}")
    
    # Show completeness statistics
    logger.info(f"\n📊 Data Completeness:")
    
    behavioral_cols = [
        'avg_file_entropy', 'high_entropy_ratio', 'stratum_indicators',
        'crypto_mining_behavior'
    ]
    
    for col in behavioral_cols:
        if col in df_original.columns:
            complete = df_original[col].notna().sum()
            total = len(df_original)
            pct = (complete / total) * 100
            logger.info(f"   {col:30s}: {complete}/{total} ({pct:.1f}%)")
    
    logger.info("="*70)
    
    return df_original


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Rescan images with missing data',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Step 1: Identify images needing rescan
  python rescan_missing.py identify data/final_training_data.csv
  
  # Step 2: Run the rescan
  python rescan.py
  
  # Step 3: Merge results back
  python rescan_missing.py merge
  
  # Or do everything at once:
  python rescan_missing.py identify data/final_training_data.csv && python rescan.py && python rescan_missing.py merge
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # Identify command
    identify_parser = subparsers.add_parser('identify', help='Identify images needing rescan')
    identify_parser.add_argument('csv_file', help='CSV file to analyze')
    identify_parser.add_argument('--output', default='missing_images.txt',
                                help='Output file for missing image list')
    
    # Merge command
    merge_parser = subparsers.add_parser('merge', help='Merge rescanned data back')
    merge_parser.add_argument('--original', default='data/final_training_data.csv',
                            help='Original CSV file')
    merge_parser.add_argument('--rescanned', default='data/rescanned_images.csv',
                            help='Rescanned CSV file')
    merge_parser.add_argument('--output', default='data/final_training_data_complete.csv',
                            help='Output merged CSV file')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    if args.command == 'identify':
        if not Path(args.csv_file).exists():
            logger.error(f"❌ File not found: {args.csv_file}")
            sys.exit(1)
        
        safe_imgs, risky_imgs = identify_missing_images(args.csv_file, args.output)
        
        # Create rescan script
        create_rescan_script(safe_imgs, risky_imgs)
        
        logger.info("\n" + "="*70)
        logger.info("✅ Ready to rescan!")
        logger.info("="*70)
        logger.info("\n📋 Next steps:")
        logger.info("   1. Review missing_images.txt")
        logger.info("   2. Run: python rescan.py")
        logger.info("   3. After scanning completes, run: python rescan_missing.py merge")
        logger.info("="*70)
    
    elif args.command == 'merge':
        if not Path(args.rescanned).exists():
            logger.error(f"❌ Rescanned file not found: {args.rescanned}")
            logger.error("   Run the rescan first: python rescan.py")
            sys.exit(1)
        
        merge_rescanned_data(args.original, args.rescanned, args.output)
        
        logger.info("\n✅ All done! Your complete dataset is ready:")
        logger.info(f"   {args.output}")