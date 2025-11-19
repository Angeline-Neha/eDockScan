#!/usr/bin/env python3
"""
Test layer analysis on a specific image
"""

import json
from pathlib import Path
from backend.behavioral_analyzer import BehavioralAnalyzer, print_layer_analysis_report
from backend.extract import EnhancedRemoteDockerScanner

def analyze_layers(image_name):
    """Analyze and display layer-by-layer security analysis"""
    
    # Extract features (this runs all scans)
    scanner = EnhancedRemoteDockerScanner(timeout_per_scan=300)
    features = scanner.extract_features(image_name)
    
    if features.scan_status == 'failed':
        print(f"❌ Scan failed for {image_name}")
        return
    
    # Get cached trivy data
    cache_path = scanner.cache_manager.get_cache_path(image_name)
    trivy_file = cache_path / 'trivy.json'
    syft_file = cache_path / 'sbom.json'
    
    if not trivy_file.exists():
        print(f"❌ No trivy data found")
        return
    
    # Load data
    with open(trivy_file) as f:
        trivy_data = json.load(f)
    
    syft_data = {}
    if syft_file.exists():
        with open(syft_file) as f:
            syft_data = json.load(f)
    
    # Run behavioral analysis
    analyzer = BehavioralAnalyzer()
    
    metadata = trivy_data.get('Metadata', {})
    image_config = metadata.get('ImageConfig', {})
    history = image_config.get('history', [])
    
    if not history:
        print(f"⚠️  No layer history found")
        return
    
    # Analyze each layer
    print(f"\n{'='*80}")
    print(f"ANALYZING {len(history)} LAYERS...")
    print(f"{'='*80}")
    
    layer_analyses = []
    for idx, layer in enumerate(history):
        analysis = analyzer._analyze_layer(idx, layer)
        layer_analyses.append(analysis)
    
    # Generate remediations
    remediations = analyzer._generate_remediations(layer_analyses)
    
    # Print detailed report
    print_layer_analysis_report(layer_analyses, remediations, image_name)
    
    print(f"\n{'='*80}")
    print(f"BEHAVIORAL FEATURES SUMMARY")
    print(f"{'='*80}")
    
    behavioral_features = analyzer.analyze_image(image_name, trivy_data, syft_data)
    
    for feature, value in behavioral_features.items():
        if not feature.startswith('_') and value > 0:
            print(f"  {feature:35s}: {value}")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python test_layers.py <image_name>")
        sys.exit(1)
    
    image_name = sys.argv[1]
    analyze_layers(image_name)