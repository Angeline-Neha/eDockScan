#!/usr/bin/env python3
"""
Remote Docker Image Feature Extractor - Fixed Version
Remote scanning only (no local Docker pulls)
Generates all required features for ML model
"""

import subprocess
import json
import os
import time
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
import pandas as pd
from backend.behavioral_analyzer import BehavioralAnalyzer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class ImageFeatures:
    """Complete feature set for ML model"""
    # Core security features
    cryptominer_binary: int = 0
    mining_pools: int = 0
    hardcoded_secrets: int = 0
    external_calls: int = 0
    ssh_backdoor: int = 0
    runs_as_root: int = 0
    known_cves: int = 0
    outdated_base: int = 0
    typosquatting_score: float = 0.0
    image_age_days: int = 0
    high_entropy_files: int = 0
    suspicious_ports: int = 0
    
    # Behavioral features (from behavioral_analyzer)
    avg_file_entropy: float = 0.0
    high_entropy_ratio: float = 0.0
    stratum_indicators: float = 0.0
    raw_ip_connections: float = 0.0
    suspicious_dns_queries: float = 0.0
    stripped_binaries_ratio: float = 0.0
    packed_binary_score: float = 0.0
    layer_deletion_score: float = 0.0
    temp_file_activity: float = 0.0
    process_injection_risk: float = 0.0
    privilege_escalation_risk: float = 0.0
    crypto_mining_behavior: float = 0.0
    anti_analysis_score: float = 0.0
    
    # Label and metadata
    label: int = 0  # 0=safe, 1=risky
    image_name: str = ""
    scan_success: bool = True


class SecurityDetector:
    """Security pattern detection"""
    
    def __init__(self):
        self.cryptominer_binaries = [
            'xmrig', 'cgminer', 'ethminer', 'claymore', 'gminer',
            'minerd', 'cpuminer', 'ccminer', 'nanominer', 'teamredminer'
        ]
        
        self.mining_pools = [
            'pool.minexmr', 'nanopool', 'ethermine', 'f2pool',
            'stratum+tcp', 'mining.pool', 'supportxmr', 'nicehash'
        ]
        
        self.legitimate_images = [
            'nginx', 'python', 'node', 'ubuntu', 'postgres', 'mysql',
            'redis', 'mongodb', 'alpine', 'debian', 'golang', 'java'
        ]
    
    def calculate_typosquatting_score(self, image_name: str) -> float:
        """Simple typosquatting detection"""
        base_name = image_name.split(':')[0].split('/')[-1].lower()
        
        # Check exact matches first
        if base_name in self.legitimate_images:
            return 0.0
        
        # Check similarity
        from difflib import SequenceMatcher
        max_similarity = 0.0
        
        for legit in self.legitimate_images:
            similarity = SequenceMatcher(None, base_name, legit).ratio()
            if similarity > max_similarity:
                max_similarity = similarity
        
        # If highly similar but not exact, it's suspicious
        if 0.8 < max_similarity < 1.0:
            return max_similarity
        
        return 0.0


class RemoteDockerScanner:
    """Remote-only Docker image scanner"""
    
    def __init__(self, cache_dir='scan_cache', timeout=300):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.timeout = timeout
        self.security_detector = SecurityDetector()
        self.behavioral_analyzer = BehavioralAnalyzer()
        
        self._verify_tools()
    
    def _verify_tools(self):
        """Verify Trivy and Syft are installed"""
        for tool in ['trivy', 'syft']:
            try:
                result = subprocess.run(
                    [tool, '--version'],
                    capture_output=True,
                    timeout=5,
                    text=True
                )
                if result.returncode != 0:
                    raise FileNotFoundError
                logger.info(f"✓ {tool} found")
            except:
                logger.error(f"✗ {tool} not found. Install with: brew install {tool}")
                raise RuntimeError(f"{tool} is required")
    
    def extract_features(self, image_name: str, label: int) -> ImageFeatures:
        """Extract all features from image"""
        logger.info(f"Scanning: {image_name}")
        
        features = ImageFeatures(image_name=image_name, label=label)
        
        # Get cache directory
        import hashlib
        safe_name = hashlib.md5(image_name.encode()).hexdigest()[:12]
        cache_path = self.cache_dir / safe_name
        cache_path.mkdir(exist_ok=True)
        
        try:
            # 1. Run Trivy (vulnerabilities, secrets, config)
            trivy_data = self._run_trivy(image_name, cache_path)
            
            # 2. Run Syft (SBOM)
            syft_data = self._run_syft(image_name, cache_path)
            
            # 3. Extract core features
            if syft_data:
                self._extract_sbom_features(syft_data, features)
            
            if trivy_data:
                self._extract_trivy_features(trivy_data, features)
                self._extract_metadata_features(trivy_data, image_name, features)
            
            # 4. Extract behavioral features
            if trivy_data and syft_data:
                behavioral = self.behavioral_analyzer.analyze_image(
                    image_name, trivy_data, syft_data
                )
                for key, value in behavioral.items():
                    if hasattr(features, key):
                        setattr(features, key, value)
            
            logger.info(f"✓ Successfully scanned {image_name}")
            
        except Exception as e:
            logger.error(f"✗ Failed to scan {image_name}: {e}")
            features.scan_success = False
        
        return features
    
    def _run_trivy(self, image_name: str, cache_path: Path) -> Dict:
        """Run Trivy remotely"""
        output_file = cache_path / 'trivy.json'
        
        # Skip if cached
        if output_file.exists() and output_file.stat().st_size > 0:
            logger.debug(f"Using cached Trivy results for {image_name}")
            with open(output_file) as f:
                return json.load(f)
        
        try:
            cmd = [
                'trivy', 'image',
                '--format', 'json',
                '--output', str(output_file),
                '--scanners', 'vuln,secret,config',
                '--timeout', f'{self.timeout}s',
                '--quiet',
                image_name
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=self.timeout + 30,
                text=True
            )
            
            if output_file.exists() and output_file.stat().st_size > 0:
                with open(output_file) as f:
                    return json.load(f)
            else:
                logger.warning(f"Trivy returned no data for {image_name}")
                return {}
                
        except subprocess.TimeoutExpired:
            logger.warning(f"Trivy timeout for {image_name}")
            return {}
        except Exception as e:
            logger.warning(f"Trivy error for {image_name}: {str(e)[:100]}")
            return {}
    
    def _run_syft(self, image_name: str, cache_path: Path) -> Dict:
        """Run Syft remotely (SBOM generation)"""
        output_file = cache_path / 'sbom.json'
        
        # Skip if cached
        if output_file.exists() and output_file.stat().st_size > 0:
            logger.debug(f"Using cached Syft results for {image_name}")
            with open(output_file) as f:
                return json.load(f)
        
        # Skip known problematic images
        SKIP_IMAGES = [
            'scratch', 'kalilinux', 'metasploitable', 'remnux',
            'gitlab/gitlab-ce'
        ]
        
        if any(skip in image_name.lower() for skip in SKIP_IMAGES):
            logger.warning(f"Skipping {image_name} (too large/problematic)")
            return {}
        
        try:
            # Force remote-only scan
            cmd = [
                'syft',
                f'registry:{image_name}',
                '-o', 'json',
                '--file', str(output_file)
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=self.timeout,
                text=True
            )
            
            if output_file.exists() and output_file.stat().st_size > 0:
                with open(output_file) as f:
                    return json.load(f)
            else:
                logger.warning(f"Syft returned no data for {image_name}")
                return {}
                
        except subprocess.TimeoutExpired:
            logger.warning(f"Syft timeout for {image_name}")
            return {}
        except Exception as e:
            logger.warning(f"Syft error for {image_name}: {str(e)[:100]}")
            return {}
    
    def _extract_sbom_features(self, syft_data: Dict, features: ImageFeatures):
        """Extract features from SBOM"""
        artifacts = syft_data.get('artifacts', [])
        
        # Cryptominer detection
        for artifact in artifacts:
            name = artifact.get('name', '').lower()
            if any(miner in name for miner in self.security_detector.cryptominer_binaries):
                features.cryptominer_binary = 1
                break
        
        # SSH backdoor detection
        ssh_packages = ['openssh-server', 'sshd', 'dropbear']
        for artifact in artifacts:
            name = artifact.get('name', '').lower()
            if any(ssh in name for ssh in ssh_packages):
                features.ssh_backdoor = 1
                break
        
        # High entropy files (packed/obfuscated)
        suspicious_patterns = ['base64', 'encode', 'pack', 'obfus']
        for artifact in artifacts:
            name = artifact.get('name', '').lower()
            if any(pattern in name for pattern in suspicious_patterns):
                features.high_entropy_files += 1
        
        features.high_entropy_files = min(features.high_entropy_files, 10)
    
    def _extract_trivy_features(self, trivy_data: Dict, features: ImageFeatures):
        """Extract features from Trivy results"""
        results = trivy_data.get('Results', [])
        
        # Secrets
        for result in results:
            secrets = result.get('Secrets', [])
            features.hardcoded_secrets += len(secrets)
        
        features.hardcoded_secrets = min(features.hardcoded_secrets, 20)
        
        # CVEs
        cve_count = 0
        for result in results:
            vulnerabilities = result.get('Vulnerabilities', [])
            for vuln in vulnerabilities:
                severity = vuln.get('Severity', '').lower()
                if severity in ['critical', 'high']:
                    cve_count += 1
        
        features.known_cves = min(cve_count, 50)
        
        # Suspicious ports
        suspicious_ports = [22, 23, 3389, 5900]
        text = json.dumps(trivy_data).lower()
        for port in suspicious_ports:
            if str(port) in text:
                features.suspicious_ports += 1
        
        # Root user detection
        self._detect_root_user(trivy_data, features)
        
        # External calls (network configs)
        for result in results:
            misconfigs = result.get('Misconfigurations', [])
            for misconfig in misconfigs:
                title = misconfig.get('Title', '').lower()
                if any(word in title for word in ['port', 'expose', 'network']):
                    features.external_calls += 1
        
        features.external_calls = min(features.external_calls, 10)
    
    def _detect_root_user(self, trivy_data: Dict, features: ImageFeatures):
        """Detect if container runs as root"""
        metadata = trivy_data.get('Metadata', {})
        image_config = metadata.get('ImageConfig', {})
        config = image_config.get('config', {})
        
        user = config.get('User', '')
        
        if user and user not in ['', 'root', '0', '0:0']:
            features.runs_as_root = 0
        else:
            features.runs_as_root = 1
    
    def _extract_metadata_features(self, trivy_data: Dict, image_name: str, features: ImageFeatures):
        """Extract metadata features"""
        # Mining pools
        text = json.dumps(trivy_data).lower()
        for pool in self.security_detector.mining_pools:
            if pool in text:
                features.mining_pools += 1
        
        features.mining_pools = min(features.mining_pools, 10)
        
        # Image age
        metadata = trivy_data.get('Metadata', {})
        image_config = metadata.get('ImageConfig', {})
        created_str = image_config.get('created', '')
        
        if created_str:
            try:
                created_str = created_str.replace('Z', '+00:00')
                created_date = datetime.fromisoformat(created_str)
                age_days = (datetime.now(created_date.tzinfo) - created_date).days
                features.image_age_days = age_days
                features.outdated_base = 1 if age_days > 365 else 0
            except:
                pass
        
        # Typosquatting
        features.typosquatting_score = self.security_detector.calculate_typosquatting_score(image_name)


def extract_dataset(
    safe_images: List[str],
    risky_images: List[str],
    output_csv: str = 'docker_features.csv',
    max_workers: int = 3,
    timeout: int = 300
) -> pd.DataFrame:
    """
    Extract features from all images
    """
    logger.info("="*70)
    logger.info("🐳 REMOTE DOCKER FEATURE EXTRACTOR")
    logger.info("="*70)
    logger.info(f"Safe images: {len(safe_images)}")
    logger.info(f"Risky images: {len(risky_images)}")
    logger.info(f"Workers: {max_workers}")
    logger.info(f"Output: {output_csv}")
    logger.info("="*70)
    
    scanner = RemoteDockerScanner(timeout=timeout)
    
    # Combine images with labels
    all_images = [(img, 0) for img in safe_images] + [(img, 1) for img in risky_images]
    
    results = []
    failed = []
    
    # Process in parallel
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_image = {
            executor.submit(scanner.extract_features, img, label): (img, label)
            for img, label in all_images
        }
        
        completed = 0
        for future in as_completed(future_to_image):
            image_name, label = future_to_image[future]
            completed += 1
            
            try:
                features = future.result()
                
                if features.scan_success:
                    # Convert to dict and keep only needed columns
                    feature_dict = asdict(features)
                    # Remove metadata columns
                    feature_dict.pop('scan_success', None)
                    results.append(feature_dict)
                    logger.info(f"[{completed}/{len(all_images)}] ✓ {image_name}")
                else:
                    failed.append(image_name)
                    logger.warning(f"[{completed}/{len(all_images)}] ✗ {image_name}")
                    
            except Exception as e:
                logger.error(f"[{completed}/{len(all_images)}] Error: {image_name} - {e}")
                failed.append(image_name)
    
    # Create DataFrame
    df = pd.DataFrame(results)
    
    # Reorder columns - label and image_name at the end
    feature_cols = [col for col in df.columns if col not in ['label', 'image_name']]
    df = df[feature_cols + ['label', 'image_name']]
    
    # Save
    os.makedirs(os.path.dirname(output_csv) or '.', exist_ok=True)
    df.to_csv(output_csv, index=False)
    
    # Print summary
    logger.info("\n" + "="*70)
    logger.info("✅ EXTRACTION COMPLETE")
    logger.info("="*70)
    logger.info(f"Saved: {output_csv}")
    logger.info(f"Total rows: {len(df)}")
    logger.info(f"Safe (label=0): {len(df[df['label']==0])}")
    logger.info(f"Risky (label=1): {len(df[df['label']==1])}")
    logger.info(f"Failed: {len(failed)}")
    
    if failed:
        logger.warning(f"\nFailed images ({len(failed)}):")
        for img in failed[:5]:
            logger.warning(f"  - {img}")
        if len(failed) > 5:
            logger.warning(f"  ... and {len(failed)-5} more")
    
    logger.info("\n" + "="*70)
    
    return df


# Image lists for scanning
SAFE_IMAGES = [
    'nginx:alpine', 'python:3.11-slim', 'node:20-alpine',
    'postgres:16-alpine', 'redis:7-alpine', 'alpine:latest',
    'golang:1.21-alpine', 'mysql:8.0', 'debian:bookworm-slim',
    'ubuntu:22.04', 'mongodb:7.0', 'mariadb:11',
]

RISKY_IMAGES = [
    'ubuntu:14.04', 'ubuntu:16.04', 'debian:jessie',
    'centos:7', 'python:2.7', 'node:10',
    'php:5.6', 'postgres:9.6', 'mysql:5.5',
    'redis:3.0', 'nginx:1.10', 'tomcat:7',
]


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Extract Docker image features')
    parser.add_argument('--output', default='docker_features.csv', help='Output CSV file')
    parser.add_argument('--workers', type=int, default=3, help='Parallel workers')
    parser.add_argument('--timeout', type=int, default=300, help='Timeout per image (seconds)')
    parser.add_argument('--test', action='store_true', help='Test with 5 images')
    
    args = parser.parse_args()
    
    if args.test:
        logger.info("Running test with 5 images...")
        safe = SAFE_IMAGES[:3]
        risky = RISKY_IMAGES[:2]
    else:
        safe = SAFE_IMAGES
        risky = RISKY_IMAGES
    
    df = extract_dataset(
        safe,
        risky,
        output_csv=args.output,
        max_workers=args.workers,
        timeout=args.timeout
    )
    
    logger.info(f"\n✅ Done! Check {args.output}")