#!/usr/bin/env python3
"""
Behavioral Analyzer for Docker Images
Extracts runtime behavior indicators from static analysis
"""

import json
import re
import math
import logging
from typing import Dict, List, Optional, Any
from collections import defaultdict

logger = logging.getLogger(__name__)

class BehavioralAnalyzer:
    """Analyzes behavioral patterns from image metadata and SBOM"""
    
    def __init__(self):
        # Network indicators
        self.stratum_keywords = [
            'stratum+tcp', 'stratum+ssl', 'stratum://', 
            'mining.pool', 'pool.mining', 'xmr-pool',
            'stratum', 'mining-pool'
        ]
        
        self.raw_ip_patterns = [
            r'\b(?:\d{1,3}\.){3}\d{1,3}:\d+\b',  # IP:port
            r'tcp://(?:\d{1,3}\.){3}\d{1,3}',     # tcp://IP
            r'http://(?:\d{1,3}\.){3}\d{1,3}',    # http://IP
        ]
        
        self.suspicious_dns = [
            'dyndns', 'no-ip', 'ddns', 'dynamic',
            '.tk', '.ml', '.ga', '.cf', '.gq',  # Free TLDs
            'tunnel', 'ngrok', 'localtunnel'
        ]
        
        # Binary analysis indicators
        self.packer_signatures = [
            'upx', 'packed', 'compressed', 'obfuscated',
            'base64', 'encoded', 'encrypted'
        ]
        
        # Process behavior
        self.injection_indicators = [
            'ptrace', 'process_vm_writemem', 'ld_preload',
            'proc/self/mem', '/proc/*/mem', 'memfd_create'
        ]
        
        self.privilege_escalation = [
            'sudo', 'su ', 'setuid', 'setgid', 'capabilities',
            'cap_sys_admin', 'cap_net_admin', 'pkexec',
            'polkit', 'dbus', 'sudoers'
        ]
        
        # Crypto mining specific
        self.crypto_indicators = [
            'xmrig', 'miner', 'mining', 'hashrate', 'difficulty',
            'wallet', 'coinbase', 'cryptonight', 'randomx',
            'cuda', 'opencl', 'gpu-miner', 'cpu-miner',
            'monero', 'ethereum', 'bitcoin'
        ]
        
        # Anti-analysis
        self.anti_analysis = [
            'vm_detect', 'sandbox', 'debug', 'antivirus',
            'sleep', 'delay', 'usleep', 'anti-debug',
            'isdebuggerpresent', 'ptrace_deny'
        ]
    
    def analyze_image(self, image_name: str, trivy_data: Dict, syft_data: Dict) -> Dict[str, float]:
        """
        Analyze image and return behavioral features
        Returns: Dictionary with feature names and values
        """
        features = {}
        
        try:
            # Extract raw text for pattern matching
            trivy_text = json.dumps(trivy_data).lower()
            syft_text = json.dumps(syft_data).lower()
            combined_text = trivy_text + " " + syft_text
            
            # Extract artifacts
            artifacts = syft_data.get('artifacts', [])
            
            # 1. File entropy analysis
            features['avg_file_entropy'] = self._calculate_avg_entropy(artifacts)
            features['high_entropy_ratio'] = self._calculate_high_entropy_ratio(artifacts)
            
            # 2. Network indicators
            features['stratum_indicators'] = self._detect_stratum_connections(combined_text)
            features['raw_ip_connections'] = self._detect_raw_ip_connections(combined_text)
            features['suspicious_dns_queries'] = self._detect_suspicious_dns(combined_text)
            
            # 3. Binary analysis
            features['stripped_binaries_ratio'] = self._analyze_stripped_binaries(artifacts)
            features['packed_binary_score'] = self._detect_packed_binaries(artifacts, combined_text)
            
            # 4. Layer analysis
            features['layer_deletion_score'] = self._analyze_layer_deletions(trivy_data)
            features['temp_file_activity'] = self._detect_temp_file_activity(artifacts, trivy_text)
            
            # 5. Process behavior
            features['process_injection_risk'] = self._detect_injection_risk(combined_text)
            features['privilege_escalation_risk'] = self._detect_privilege_escalation(combined_text)
            
            # 6. Crypto mining behavior (composite score)
            features['crypto_mining_behavior'] = self._calculate_crypto_mining_score(
                combined_text, artifacts, features
            )
            
            # 7. Anti-analysis techniques
            features['anti_analysis_score'] = self._detect_anti_analysis(combined_text)
            
            # Normalize all scores to 0-1 range
            for key in features:
                if features[key] > 1.0:
                    features[key] = min(features[key], 1.0)
                features[key] = round(features[key], 4)
            
            logger.debug(f"Behavioral analysis complete for {image_name}")
            return features
            
        except Exception as e:
            logger.error(f"Behavioral analysis failed: {e}")
            # Return default values (0.0) for all features
            return {
                'avg_file_entropy': 0.0,
                'high_entropy_ratio': 0.0,
                'stratum_indicators': 0.0,
                'raw_ip_connections': 0.0,
                'suspicious_dns_queries': 0.0,
                'stripped_binaries_ratio': 0.0,
                'packed_binary_score': 0.0,
                'layer_deletion_score': 0.0,
                'temp_file_activity': 0.0,
                'process_injection_risk': 0.0,
                'privilege_escalation_risk': 0.0,
                'crypto_mining_behavior': 0.0,
                'anti_analysis_score': 0.0
            }
    
    def _calculate_avg_entropy(self, artifacts: List[Dict]) -> float:
        """Calculate average entropy across binary files"""
        if not artifacts:
            return 0.0
        
        # Simulate entropy based on file types
        binary_extensions = ['.so', '.bin', '', '.exe', '.elf']
        binary_count = 0
        total_entropy = 0.0
        
        for artifact in artifacts[:100]:  # Sample first 100
            name = artifact.get('name', '').lower()
            
            # Check if it's a binary
            is_binary = any(name.endswith(ext) for ext in binary_extensions)
            if is_binary or '/' in artifact.get('locations', [{}])[0].get('path', ''):
                binary_count += 1
                # Estimate entropy (higher for compiled binaries)
                if 'lib' in name or '.so' in name:
                    total_entropy += 7.2  # Libraries typically high entropy
                else:
                    total_entropy += 6.5  # Regular binaries
        
        if binary_count == 0:
            return 0.0
        
        return min(total_entropy / binary_count / 8.0, 1.0)  # Normalize to 0-1
    
    def _calculate_high_entropy_ratio(self, artifacts: List[Dict]) -> float:
        """Calculate ratio of high-entropy files (potential obfuscation)"""
        if not artifacts:
            return 0.0
        
        high_entropy_count = 0
        total_files = 0
        
        suspicious_patterns = ['base64', 'encoded', 'packed', 'compress', 'crypt']
        
        for artifact in artifacts[:100]:
            name = artifact.get('name', '').lower()
            total_files += 1
            
            # Check for suspicious patterns
            if any(pattern in name for pattern in suspicious_patterns):
                high_entropy_count += 1
        
        if total_files == 0:
            return 0.0
        
        return round(high_entropy_count / total_files, 4)
    
    def _detect_stratum_connections(self, text: str) -> float:
        """Detect stratum mining protocol indicators"""
        count = sum(1 for keyword in self.stratum_keywords if keyword in text)
        return min(count / 3.0, 1.0)  # Normalize
    
    def _detect_raw_ip_connections(self, text: str) -> float:
        """Detect hardcoded IP addresses (suspicious)"""
        matches = 0
        for pattern in self.raw_ip_patterns:
            matches += len(re.findall(pattern, text))
        
        return min(matches / 10.0, 1.0)  # Normalize
    
    def _detect_suspicious_dns(self, text: str) -> float:
        """Detect suspicious DNS patterns"""
        count = sum(1 for pattern in self.suspicious_dns if pattern in text)
        return min(count / 5.0, 1.0)
    
    def _analyze_stripped_binaries(self, artifacts: List[Dict]) -> float:
        """Analyze ratio of stripped binaries (obfuscation indicator)"""
        if not artifacts:
            return 0.0
        
        binary_count = 0
        stripped_count = 0
        
        for artifact in artifacts[:100]:
            name = artifact.get('name', '').lower()
            
            # Simple heuristic: binaries in /usr/bin, /bin without common names
            locations = artifact.get('locations', [])
            if locations:
                path = locations[0].get('path', '')
                if '/bin/' in path and not any(common in name for common in ['sh', 'bash', 'ls', 'cat']):
                    binary_count += 1
                    # Stripped binaries typically smaller or no debug info
                    if 'stripped' in str(artifact).lower():
                        stripped_count += 1
        
        if binary_count == 0:
            return 0.0
        
        return round(stripped_count / binary_count, 4)
    
    def _detect_packed_binaries(self, artifacts: List[Dict], text: str) -> float:
        """Detect packed/compressed binaries"""
        score = 0.0
        
        # Check for packer signatures in text
        for signature in self.packer_signatures:
            if signature in text:
                score += 0.2
        
        # Check for suspicious binary names
        for artifact in artifacts[:50]:
            name = artifact.get('name', '').lower()
            if any(sig in name for sig in self.packer_signatures):
                score += 0.1
        
        return min(score, 1.0)
    
    def _analyze_layer_deletions(self, trivy_data: Dict) -> float:
        """Analyze suspicious layer deletion patterns"""
        metadata = trivy_data.get('Metadata', {})
        history = metadata.get('ImageConfig', {}).get('history', [])
        
        deletion_score = 0.0
        
        for layer in history:
            created_by = layer.get('created_by', '').lower()
            
            # Check for file deletions
            if 'rm -rf' in created_by or 'rm -r' in created_by:
                deletion_score += 0.2
            
            # Check for evidence cleanup
            if any(pattern in created_by for pattern in ['/tmp/', '/var/tmp/', '.bash_history', 'history -c']):
                deletion_score += 0.1
        
        return min(deletion_score, 1.0)
    
    def _detect_temp_file_activity(self, artifacts: List[Dict], text: str) -> float:
        """Detect suspicious temporary file activity"""
        temp_paths = ['/tmp/', '/var/tmp/', '/dev/shm/', '/.cache/']
        
        temp_count = 0
        for artifact in artifacts[:100]:
            locations = artifact.get('locations', [])
            for loc in locations:
                path = loc.get('path', '')
                if any(temp in path for temp in temp_paths):
                    temp_count += 1
        
        # Also check text for temp file references
        text_score = sum(0.1 for temp in temp_paths if temp in text)
        
        return min((temp_count / 10.0) + text_score, 1.0)
    
    def _detect_injection_risk(self, text: str) -> float:
        """Detect process injection indicators"""
        count = sum(1 for indicator in self.injection_indicators if indicator in text)
        return min(count / 5.0, 1.0)
    
    def _detect_privilege_escalation(self, text: str) -> float:
        """Detect privilege escalation risks"""
        count = sum(1 for indicator in self.privilege_escalation if indicator in text)
        return min(count / 5.0, 1.0)
    
    def _calculate_crypto_mining_score(self, text: str, artifacts: List[Dict], features: Dict) -> float:
        """Calculate composite crypto mining behavior score"""
        score = 0.0
        
        # 1. Direct crypto indicators
        crypto_count = sum(1 for indicator in self.crypto_indicators if indicator in text)
        score += min(crypto_count / 5.0, 0.3)
        
        # 2. Network indicators (stratum, raw IPs)
        score += features.get('stratum_indicators', 0.0) * 0.3
        score += features.get('raw_ip_connections', 0.0) * 0.2
        
        # 3. Obfuscation (high entropy, packed binaries)
        score += features.get('high_entropy_ratio', 0.0) * 0.1
        score += features.get('packed_binary_score', 0.0) * 0.1
        
        return min(score, 1.0)
    
    def _detect_anti_analysis(self, text: str) -> float:
        """Detect anti-analysis/anti-debugging techniques"""
        count = sum(1 for indicator in self.anti_analysis if indicator in text)
        
        # Extra weight for VM detection
        if 'vm_detect' in text or 'vmware' in text:
            count += 2
        
        return min(count / 5.0, 1.0)