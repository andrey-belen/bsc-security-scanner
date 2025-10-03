"""
Enhanced Security Analyzer - Main orchestrator for precise token analysis
Implements the complete detection pipeline with archetype-specific analysis
"""

import re
from typing import Dict, List, Optional
from web3 import Web3

from config import get_rpc_endpoint
from .enhanced_archetype import (
    EnhancedArchetypeClassifier, TokenArchetype, Finding,
    detect_tax_mechanism, analyze_stablecoin_controls, generate_findings
)
from .simulation import TransactionSimulator, detect_wrapper_reentrancy
from .source_analyzer import SourceCodeAnalyzer


class EnhancedSecurityAnalyzer:
    """
    Main security analyzer with archetype-aware detection
    Fixes misclassification of stablecoins and wrappers as honeypots
    """

    def __init__(self, fork_url: Optional[str] = None):
        self.w3 = Web3(Web3.HTTPProvider(get_rpc_endpoint()))
        self.classifier = EnhancedArchetypeClassifier()
        self.simulator = TransactionSimulator(fork_url)
        self.source_analyzer = SourceCodeAnalyzer()

    def analyze_contract(self, address: str, quick_scan: bool = False) -> Dict:
        """
        Main analysis function with archetype-first approach

        Args:
            address: Contract address to analyze
            quick_scan: Skip simulation if True

        Returns:
            Complete analysis results
        """
        # Step 1: Get source code and ABI
        source_code = self.source_analyzer.get_verified_source_code(address)
        abi = None  # Could be extracted from source or BSCScan

        # Step 2: Classify archetype first
        classification = self.classifier.classify_archetype(address, source_code, abi)
        archetype = classification["archetype"]
        classification_confidence = classification["confidence"]

        # Step 3: Run archetype-specific analysis
        detections = {}

        if archetype == TokenArchetype.WRAPPER_TOKEN:
            detections = self._analyze_wrapper_token(address, source_code)
        elif archetype == TokenArchetype.STABLECOIN:
            detections = self._analyze_stablecoin(address, source_code)
        elif archetype == TokenArchetype.TAX_HONEYPOT_TOKEN:
            detections = self._analyze_tax_honeypot_token(address, source_code, quick_scan)
        elif archetype == TokenArchetype.STANDARD_ERC20:
            detections = self._analyze_standard_token(address, source_code, quick_scan)
        else:
            # Unknown archetype - run comprehensive analysis
            detections = self._analyze_unknown_token(address, source_code, quick_scan)

        # Step 4: Generate findings based on archetype
        findings = generate_findings(archetype, detections)

        # Step 5: Calculate overall risk score
        risk_score = self._calculate_risk_score(findings, archetype, classification_confidence)

        return {
            "address": address,
            "archetype": {
                "type": archetype,
                "confidence": classification_confidence,
                "detection_method": classification.get("detection_method", "unknown")
            },
            "findings": [self._finding_to_dict(f) for f in findings],
            "risk_score": risk_score,
            "risk_level": self._get_risk_level(risk_score),
            "analysis_confidence": self._calculate_overall_confidence(detections),
            "detections": detections
        }

    def _analyze_wrapper_token(self, address: str, source_code: Optional[str]) -> Dict:
        """Analyze wrapper tokens (WBNB, WETH style)"""
        detections = {}

        if source_code:
            # Check for reentrancy in withdraw function
            reentrancy_analysis = detect_wrapper_reentrancy(source_code)
            detections["reentrancy_analysis"] = reentrancy_analysis

            # Check for proper access controls
            access_analysis = self._check_wrapper_access_controls(source_code)
            detections["access_controls"] = access_analysis

        # Basic function analysis
        basic_analysis = self._check_basic_wrapper_functions(address)
        detections["basic_functions"] = basic_analysis

        return detections

    def _analyze_stablecoin(self, address: str, source_code: Optional[str]) -> Dict:
        """Analyze stablecoins (USDT, BUSD, etc.)"""
        detections = {}

        if source_code:
            # Analyze centralized controls (expected for stablecoins)
            controls_analysis = analyze_stablecoin_controls(source_code)
            detections["stablecoin_controls"] = controls_analysis

            # Check for proper multi-sig or timelock
            governance_analysis = self._check_stablecoin_governance(source_code)
            detections["governance"] = governance_analysis

        # Check for compliance features
        compliance_analysis = self._check_compliance_features(address, source_code)
        detections["compliance"] = compliance_analysis

        return detections

    def _analyze_tax_honeypot_token(self, address: str, source_code: Optional[str], quick_scan: bool) -> Dict:
        """Analyze potential tax/honeypot tokens"""
        detections = {}

        if source_code:
            # Detailed tax mechanism analysis
            tax_analysis = detect_tax_mechanism(source_code)
            detections["tax_mechanism"] = tax_analysis

            # Check for blacklist mechanisms
            blacklist_analysis = self._check_blacklist_mechanisms(source_code)
            detections["blacklist"] = blacklist_analysis

            # Check for reflection mechanisms
            reflection_analysis = self._check_reflection_mechanism(source_code)
            detections["reflection"] = reflection_analysis

        # Simulation-based honeypot detection (skip if quick scan)
        if not quick_scan:
            simulation_analysis = self.simulator.simulate_buy_sell(address, TokenArchetype.TAX_HONEYPOT_TOKEN)
            detections["honeypot_simulation"] = simulation_analysis

        return detections

    def _analyze_standard_token(self, address: str, source_code: Optional[str], quick_scan: bool) -> Dict:
        """Analyze standard ERC20 tokens"""
        detections = {}

        # Check for any suspicious patterns that shouldn't be in standard tokens
        if source_code:
            suspicious_analysis = self._check_suspicious_patterns(source_code)
            detections["suspicious_patterns"] = suspicious_analysis

        # Basic ownership analysis
        ownership_analysis = self._check_ownership_patterns(address, source_code)
        detections["ownership"] = ownership_analysis

        # Light simulation to verify basic functionality
        if not quick_scan:
            basic_simulation = self.simulator.simulate_buy_sell(address, TokenArchetype.STANDARD_ERC20)
            detections["basic_functionality"] = basic_simulation

        return detections

    def _analyze_unknown_token(self, address: str, source_code: Optional[str], quick_scan: bool) -> Dict:
        """Analyze tokens with unknown archetype"""
        detections = {}

        # Run all analysis types with lower confidence
        if source_code:
            tax_analysis = detect_tax_mechanism(source_code)
            detections["potential_tax"] = tax_analysis

            stablecoin_analysis = analyze_stablecoin_controls(source_code)
            detections["potential_stablecoin"] = stablecoin_analysis

            reentrancy_analysis = detect_wrapper_reentrancy(source_code)
            detections["potential_reentrancy"] = reentrancy_analysis

        # Conservative simulation
        if not quick_scan:
            simulation_analysis = self.simulator.simulate_buy_sell(address, TokenArchetype.UNKNOWN)
            detections["comprehensive_simulation"] = simulation_analysis

        return detections

    def _check_wrapper_access_controls(self, source_code: str) -> Dict:
        """Check wrapper token access controls"""
        findings = []

        # Look for admin functions in wrapper tokens
        admin_patterns = [
            r"function\s+(pause|setPaused|setFee)\s*\([^)]*\)\s+.*?onlyOwner",
            r"function\s+(upgrade|changeImplementation)\s*\([^)]*\)"
        ]

        for pattern in admin_patterns:
            matches = list(re.finditer(pattern, source_code, re.IGNORECASE))
            if matches:
                findings.append(Finding(
                    id="unexpected_admin_functions",
                    severity="medium",
                    type="centralized_control",
                    description="Wrapper has unexpected admin functions",
                    evidence=[match.group(0) for match in matches],
                    confidence=0.8
                ))

        return {"findings": findings, "confidence": 0.8}

    def _check_basic_wrapper_functions(self, address: str) -> Dict:
        """Check basic wrapper functionality"""
        findings = []

        try:
            # Try to call deposit/withdraw functions (view-only check)
            bytecode = self.w3.eth.get_code(Web3.toChecksumAddress(address))

            # Check for deposit selector
            if "d0e30db0" in bytecode.hex():  # deposit()
                findings.append(Finding(
                    id="deposit_function_present",
                    severity="info",
                    type="wrapper_function",
                    description="Deposit function detected",
                    evidence=["Function selector 0xd0e30db0 found"],
                    confidence=0.9
                ))

            # Check for withdraw selector
            if "2e1a7d4d" in bytecode.hex():  # withdraw(uint256)
                findings.append(Finding(
                    id="withdraw_function_present",
                    severity="info",
                    type="wrapper_function",
                    description="Withdraw function detected",
                    evidence=["Function selector 0x2e1a7d4d found"],
                    confidence=0.9
                ))

        except Exception as e:
            findings.append(Finding(
                id="function_check_failed",
                severity="warning",
                type="analysis_error",
                description=f"Could not verify wrapper functions: {str(e)}",
                evidence=[str(e)],
                confidence=0.3
            ))

        return {"findings": findings, "confidence": 0.7}

    def _check_stablecoin_governance(self, source_code: str) -> Dict:
        """Check stablecoin governance mechanisms"""
        findings = []

        # Look for multisig patterns
        multisig_patterns = [
            r"require\s*\(\s*signers\s*>=\s*\d+",
            r"MultiSigWallet",
            r"function\s+confirmTransaction"
        ]

        multisig_found = any(re.search(pattern, source_code, re.IGNORECASE)
                           for pattern in multisig_patterns)

        if multisig_found:
            findings.append(Finding(
                id="multisig_governance",
                severity="info",
                type="governance",
                description="Multi-signature governance detected",
                evidence=["Multi-sig patterns found in code"],
                confidence=0.8
            ))
        else:
            findings.append(Finding(
                id="single_owner_control",
                severity="medium",
                type="centralized_control",
                description="Single owner control detected (no multi-sig)",
                evidence=["No multi-sig patterns found"],
                confidence=0.7
            ))

        return {"findings": findings, "confidence": 0.8}

    def _check_compliance_features(self, address: str, source_code: Optional[str]) -> Dict:
        """Check for regulatory compliance features"""
        findings = []

        if source_code:
            # Look for compliance-related functions
            compliance_patterns = [
                r"function\s+(freeze|unfreeze|seize)\s*\([^)]*\)",
                r"function\s+wipeFrozenAddress\s*\([^)]*\)",
                r"function\s+isBlackListed\s*\([^)]*\)"
            ]

            for pattern in compliance_patterns:
                matches = list(re.finditer(pattern, source_code, re.IGNORECASE))
                if matches:
                    findings.append(Finding(
                        id="compliance_features",
                        severity="info",
                        type="regulatory_compliance",
                        description="Regulatory compliance features detected",
                        evidence=[match.group(0) for match in matches],
                        confidence=0.9
                    ))

        return {"findings": findings, "confidence": 0.8}

    def _check_blacklist_mechanisms(self, source_code: str) -> Dict:
        """Check for blacklist mechanisms in tax tokens"""
        findings = []

        # Look for blacklist variables and functions
        blacklist_patterns = [
            r"mapping\s*\([^)]*\)\s+.*?blacklist",
            r"function\s+(blacklist|addToBlacklist|removeFromBlacklist)\s*\([^)]*\)",
            r"require\s*\(\s*!.*?blacklist.*?\[.*?\]"
        ]

        for pattern in blacklist_patterns:
            matches = list(re.finditer(pattern, source_code, re.IGNORECASE))
            if matches:
                findings.append(Finding(
                    id="blacklist_mechanism",
                    severity="high",
                    type="blacklist",
                    description="Blacklist mechanism detected",
                    evidence=[match.group(0) for match in matches],
                    confidence=0.9
                ))

        return {"findings": findings, "confidence": 0.9}

    def _check_reflection_mechanism(self, source_code: str) -> Dict:
        """Check for reflection/redistribution mechanisms"""
        findings = []

        reflection_patterns = [
            r"function\s+_reflectFee\s*\([^)]*\)",
            r"_rTotal\s*=\s*_tTotal",
            r"function\s+(reflect|redistribute)\s*\([^)]*\)"
        ]

        for pattern in reflection_patterns:
            matches = list(re.finditer(pattern, source_code, re.IGNORECASE))
            if matches:
                findings.append(Finding(
                    id="reflection_mechanism",
                    severity="medium",
                    type="reflection",
                    description="Reflection/redistribution mechanism detected",
                    evidence=[match.group(0) for match in matches],
                    confidence=0.8
                ))

        return {"findings": findings, "confidence": 0.8}

    def _check_suspicious_patterns(self, source_code: str) -> Dict:
        """Check for patterns suspicious in standard tokens"""
        findings = []

        # These should not be in standard tokens
        suspicious_patterns = [
            (r"function\s+setTax", "Tax function in standard token"),
            (r"function\s+setFee", "Fee function in standard token"),
            (r"_transfer.*?fee", "Fee logic in transfer function"),
            (r"function\s+blacklist", "Blacklist function in standard token")
        ]

        for pattern, description in suspicious_patterns:
            matches = list(re.finditer(pattern, source_code, re.IGNORECASE))
            if matches:
                findings.append(Finding(
                    id="suspicious_function",
                    severity="high",
                    type="suspicious_pattern",
                    description=description,
                    evidence=[match.group(0) for match in matches],
                    confidence=0.8
                ))

        return {"findings": findings, "confidence": 0.8}

    def _check_ownership_patterns(self, address: str, source_code: Optional[str]) -> Dict:
        """Check ownership patterns"""
        findings = []

        if source_code:
            # Look for owner-only functions
            owner_only_pattern = r"function\s+\w+\s*\([^)]*\)\s+.*?onlyOwner"
            owner_functions = list(re.finditer(owner_only_pattern, source_code, re.IGNORECASE))

            if len(owner_functions) > 5:
                findings.append(Finding(
                    id="many_owner_functions",
                    severity="medium",
                    type="centralized_control",
                    description=f"Many owner-only functions detected ({len(owner_functions)})",
                    evidence=[f"{len(owner_functions)} owner-only functions found"],
                    confidence=0.7
                ))

            # Check for renounceOwnership
            if re.search(r"function\s+renounceOwnership", source_code, re.IGNORECASE):
                findings.append(Finding(
                    id="ownership_renounceable",
                    severity="info",
                    type="ownership",
                    description="Ownership can be renounced",
                    evidence=["renounceOwnership function found"],
                    confidence=0.9
                ))

        return {"findings": findings, "confidence": 0.7}

    def _calculate_risk_score(self, findings: List[Finding], archetype: str, classification_confidence: float) -> int:
        """Calculate risk score based on findings and archetype"""
        base_score = 0

        # Score based on findings
        for finding in findings:
            severity_scores = {
                "critical": 30,
                "high": 20,
                "medium": 10,
                "low": 5,
                "info": 0
            }
            finding_score = severity_scores.get(finding.severity, 10)
            weighted_score = finding_score * finding.confidence
            base_score += weighted_score

        # Adjust based on archetype expectations
        if archetype == TokenArchetype.STABLECOIN:
            # Reduce score for expected centralized controls
            base_score = int(base_score * 0.6)
        elif archetype == TokenArchetype.WRAPPER_TOKEN:
            # Wrapper tokens are generally safer
            base_score = int(base_score * 0.7)
        elif archetype == TokenArchetype.TAX_HONEYPOT_TOKEN:
            # Tax tokens have inherently higher risk
            base_score = int(base_score * 1.2)

        # Adjust for classification confidence
        if classification_confidence < 0.5:
            base_score = int(base_score * 1.1)  # Increase uncertainty penalty

        return min(base_score, 100)

    def _get_risk_level(self, risk_score: int) -> str:
        """Get risk level from score"""
        if risk_score >= 80:
            return "CRITICAL"
        elif risk_score >= 60:
            return "HIGH"
        elif risk_score >= 30:
            return "MEDIUM"
        elif risk_score >= 10:
            return "LOW"
        else:
            return "VERY LOW"

    def _calculate_overall_confidence(self, detections: Dict) -> float:
        """Calculate overall analysis confidence"""
        confidences = []

        for detection_type, detection_data in detections.items():
            if isinstance(detection_data, dict) and "confidence" in detection_data:
                confidences.append(detection_data["confidence"])

        return sum(confidences) / len(confidences) if confidences else 0.5

    def _finding_to_dict(self, finding: Finding) -> Dict:
        """Convert Finding dataclass to dictionary"""
        return {
            "id": finding.id,
            "severity": finding.severity,
            "type": finding.type,
            "description": finding.description,
            "evidence": finding.evidence,
            "confidence": finding.confidence
        }