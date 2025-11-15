#!/usr/bin/env python3
"""
Script to remove high_entropy_files column from CSV and update feature extraction code
"""

import pandas as pd
import os
import shutil
from datetime import datetime

def clean_csv_with_output(csv_path, output_path, no_backup=False):
    """Remove high_entropy_files column from CSV with custom output path"""
    print(f"Processing: {csv_path}")
    
    if not os.path.exists(csv_path):
        print(f"❌ File not found: {csv_path}")
        return False
    
    # Create backup if needed
    if not no_backup:
        backup_path = csv_path.replace('.csv', f'_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv')
        shutil.copy2(csv_path, backup_path)
        print(f"✓ Backup created: {backup_path}")
    
    # Read CSV
    df = pd.read_csv(csv_path)
    print(f"✓ Loaded {len(df)} rows, {len(df.columns)} columns")
    
    # Check if column exists
    if 'high_entropy_files' not in df.columns:
        print("⚠️  Column 'high_entropy_files' not found - nothing to remove")
        return True
    
    # Remove column
    df_clean = df.drop(columns=['high_entropy_files'])
    print(f"✓ Removed 'high_entropy_files' column")
    
    # Save cleaned CSV
    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
    df_clean.to_csv(output_path, index=False)
    print(f"✓ Saved cleaned CSV: {output_path}")
    print(f"✓ New shape: {len(df_clean)} rows, {len(df_clean.columns)} columns")
    
    # Show remaining columns
    print(f"\n📋 Remaining columns ({len(df_clean.columns)}):")
    for i, col in enumerate(df_clean.columns, 1):
        print(f"   {i:2d}. {col}")
    
    return True

def update_feature_extraction_code_with_backup(code_path, no_backup=False):
    """Update extract_features.py to remove high_entropy_files references"""
    print(f"\nProcessing: {code_path}")
    
    if not os.path.exists(code_path):
        print(f"❌ File not found: {code_path}")
        return False
    
    # Create backup if needed
    if not no_backup:
        backup_path = code_path.replace('.py', f'_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.py')
        shutil.copy2(code_path, backup_path)
        print(f"✓ Backup created: {backup_path}")
    
    # Read file
    with open(code_path, 'r') as f:
        content = f.read()
    
    original_lines = content.count('\n')
    
    # Remove from COLUMN_ORDER
    lines = content.split('\n')
    new_lines = []
    removed_count = 0
    
    for line in lines:
        # Skip lines that are just 'high_entropy_files', (with optional spaces)
        if line.strip() == "'high_entropy_files'," or line.strip() == "'high_entropy_files'":
            removed_count += 1
            print(f"✓ Removed line from COLUMN_ORDER: {line.strip()}")
            continue
        new_lines.append(line)
    
    content = '\n'.join(new_lines)
    
    # Remove from ImageFeatures dataclass
    if 'high_entropy_files: Optional[int] = None' in content:
        content = content.replace('    high_entropy_files: Optional[int] = None\n', '')
        removed_count += 1
        print(f"✓ Removed from ImageFeatures dataclass")
    
    # Remove any comments mentioning it
    if 'high_entropy_files' in content.lower():
        print(f"⚠️  Warning: 'high_entropy_files' still found in code (possibly in comments)")
    
    # Save updated file
    with open(code_path, 'w') as f:
        f.write(content)
    
    new_lines_count = content.count('\n')
    print(f"✓ Saved updated code: {code_path}")
    print(f"✓ Removed {removed_count} references")
    print(f"✓ Lines: {original_lines} → {new_lines_count} (removed {original_lines - new_lines_count})")
    
    return True

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Remove high_entropy_files feature from CSV and code',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage with default paths
  python remove_high_entropy_files.py
  
  # Specify custom CSV path
  python remove_high_entropy_files.py --csv data/my_features.csv
  
  # Specify output path (different from input)
  python remove_high_entropy_files.py --csv data/input.csv --output data/cleaned.csv
  
  # Only clean CSV, don't modify Python code
  python remove_high_entropy_files.py --csv data/features.csv --no-code-update
  
  # Only update code, don't modify CSV
  python remove_high_entropy_files.py --code-only --code-path extract_features.py
        """
    )
    
    parser.add_argument('--csv', default='data/enhanced_docker_features.csv',
                        help='Input CSV file path (default: data/enhanced_docker_features.csv)')
    parser.add_argument('--output', default=None,
                        help='Output CSV file path (default: overwrite input file)')
    parser.add_argument('--code-path', default='extract_features.py',
                        help='Path to extract_features.py (default: extract_features.py)')
    parser.add_argument('--no-code-update', action='store_true',
                        help='Skip updating Python code, only clean CSV')
    parser.add_argument('--code-only', action='store_true',
                        help='Only update code, skip CSV cleaning')
    parser.add_argument('--no-backup', action='store_true',
                        help='Skip creating backups (not recommended)')
    parser.add_argument('-y', '--yes', action='store_true',
                        help='Skip confirmation prompt')
    
    args = parser.parse_args()
    
    print("="*70)
    print("🧹 REMOVING high_entropy_files FEATURE")
    print("="*70)
    print("\nConfiguration:")
    if not args.code_only:
        print(f"   Input CSV:  {args.csv}")
        print(f"   Output CSV: {args.output or args.csv + ' (overwrite)'}")
    if not args.no_code_update and not args.code_only:
        print(f"   Code file:  {args.code_path}")
    elif args.code_only:
        print(f"   Code file:  {args.code_path}")
        print(f"   CSV update: SKIPPED")
    print(f"   Backups:    {'DISABLED' if args.no_backup else 'ENABLED'}")
    print("\nThis script will:")
    if not args.code_only:
        print("1. Remove 'high_entropy_files' column from your CSV")
    if not args.no_code_update and not args.code_only:
        print("2. Update extract_features.py to remove the feature definition")
    elif args.code_only:
        print("1. Update extract_features.py to remove the feature definition")
    if not args.no_backup:
        print(f"{'3' if not args.code_only and not args.no_code_update else '2'}. Create backups of modified files")
    print("\n" + "="*70)
    
    # Get confirmation
    if not args.yes:
        response = input("\nProceed? (yes/no): ").strip().lower()
        if response not in ['yes', 'y']:
            print("❌ Aborted")
            return
    
    success1 = True
    success2 = True
    
    if not args.code_only:
        print("\n" + "="*70)
        print("STEP 1: Cleaning CSV")
        print("="*70)
        
        # Clean CSV
        output_path = args.output if args.output else args.csv
        success1 = clean_csv_with_output(args.csv, output_path, args.no_backup)
    
    if not args.no_code_update and not args.code_only:
        print("\n" + "="*70)
        print("STEP 2: Updating Python Code")
        print("="*70)
        
        # Update code
        success2 = update_feature_extraction_code_with_backup(args.code_path, args.no_backup)
    elif args.code_only:
        print("\n" + "="*70)
        print("Updating Python Code")
        print("="*70)
        
        success2 = update_feature_extraction_code_with_backup(args.code_path, args.no_backup)
    
    print("\n" + "="*70)
    if success1 and success2:
        print("✅ CLEANUP COMPLETE")
        print("="*70)
        print("\n📝 What was changed:")
        if not args.code_only:
            print("   1. Removed 'high_entropy_files' column from CSV")
            print(f"      Input:  {args.csv}")
            print(f"      Output: {args.output or args.csv}")
        if not args.no_code_update and not args.code_only:
            print("   2. Removed feature from ImageFeatures dataclass")
            print("   3. Removed from COLUMN_ORDER list")
            print(f"      File: {args.code_path}")
        elif args.code_only:
            print("   1. Removed feature from ImageFeatures dataclass")
            print("   2. Removed from COLUMN_ORDER list")
            print(f"      File: {args.code_path}")
        if not args.no_backup:
            print("\n💾 Backups created:")
            if not args.code_only:
                print(f"   - {args.csv.replace('.csv', '_backup_*.csv')}")
            if not args.no_code_update:
                print(f"   - {args.code_path.replace('.py', '_backup_*.py')}")
        print("\n⚡ Next steps:")
        print("   1. Review the changes")
        print("   2. Run your feature extraction again if needed")
        print("   3. Train your model with the cleaned data")
    else:
        print("⚠️  CLEANUP COMPLETED WITH WARNINGS")
        print("="*70)
        print("\nPlease review the output above for details")
    print("="*70)

if __name__ == "__main__":
    main()