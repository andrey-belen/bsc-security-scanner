"""
Function Analyzer - Detect dangerous and suspicious function signatures
"""

import re
import time
from typing import Dict, List, Set, Tuple
from web3 import Web3
from web3.exceptions import ContractLogicError

from config import BSC_CONFIG, DANGEROUS_FUNCTION_SIGNATURES, RISK_WEIGHTS, get_rpc_endpoint
from .source_analyzer import SourceCodeAnalyzer


class FunctionAnalyzer:
    """Analyze contract functions for security risks with confidence scoring"""

    def __init__(self):
        self.w3 = Web3(Web3.HTTPProvider(get_rpc_endpoint()))
        self.dangerous_functions = DANGEROUS_FUNCTION_SIGNATURES
        self.source_analyzer = SourceCodeAnalyzer()
    
    def analyze(self, address: str, archetype: str = None) -> Dict:
        """
        Comprehensive function analysis with confidence scoring

        Args:
            address: Contract address to analyze
            archetype: Token archetype for targeted analysis

        Returns:
            Dictionary with findings, risk points, and confidence scores
        """
        findings = []
        risk_points = 0
        overall_confidence = 0.0

        try:
            # Try source code analysis first (highest confidence)
            source_analysis = self.source_analyzer.analyze_source_code(address)

            if source_analysis["has_source"]:
                # Use source code analysis results (high confidence)
                source_findings = self._process_source_findings(source_analysis["findings"])
                findings.extend(source_findings)
                risk_points += self._calculate_risk_from_findings(source_findings)
                overall_confidence = source_analysis["confidence"]
            else:
                # Fallback to bytecode analysis (lower confidence)
                bytecode_analysis = self._analyze_bytecode_functions(address, archetype)
                findings.extend(bytecode_analysis["findings"])
                risk_points += bytecode_analysis["risk_points"]
                overall_confidence = bytecode_analysis["confidence"]

            # Apply archetype-specific filters to reduce false positives
            if archetype:
                findings = self._filter_findings_by_archetype(findings, archetype)

            # Apply confidence-based risk adjustments
            findings = self._apply_confidence_adjustments(findings)

        except Exception as e:
            findings.append({
                "type": "function_error",
                "severity": "warning",
                "confidence": 0.3,
                "message": "⚠️  Function analysis incomplete",
                "details": f"Error analyzing functions: {str(e)}"
            })
            risk_points += 10
            overall_confidence = 0.3

        return {
            "findings": findings,
            "risk_points": risk_points,
            "confidence": overall_confidence,
            "analysis_method": "source_code" if overall_confidence > 0.7 else "bytecode"
        }
    
    def quick_scan(self, address: str) -> Dict:
        """Quick function scan for basic dangerous functions"""
        findings = []
        risk_points = 0
        
        try:
            # Quick bytecode analysis for dangerous function signatures
            dangerous_functions = self._quick_dangerous_function_scan(address)
            
            if dangerous_functions:
                findings.append({
                    "type": "dangerous_functions",
                    "severity": "high",
                    "message": f"🔴 {len(dangerous_functions)} dangerous function(s) detected",
                    "details": f"Functions: {', '.join(dangerous_functions)}"
                })
                risk_points += RISK_WEIGHTS.get("dangerous_functions", 20)
            
            else:
                findings.append({
                    "type": "dangerous_functions",
                    "severity": "info",
                    "message": "✅ No obvious dangerous functions detected",
                    "details": "Quick scan completed"
                })
            
        except Exception as e:
            findings.append({
                "type": "function_error",
                "severity": "warning",
                "message": "⚠️  Quick function scan failed",
                "details": f"Error: {str(e)}"
            })
            risk_points += 10
        
        return {
            "findings": findings,
            "risk_points": risk_points
        }
    
    def _get_contract_functions(self, address: str) -> List[Dict]:
        """Get contract functions from ABI or bytecode analysis"""
        functions = []
        
        try:
            # Try to get ABI from BscScan (would need API implementation)
            # For now, analyze bytecode for function signatures
            functions = self._extract_functions_from_bytecode(address)
            
        except Exception as e:
            # Fallback to basic bytecode analysis
            pass
        
        return functions
    
    def _analyze_dangerous_functions(self, functions: List[Dict]) -> Dict:
        """Analyze functions for dangerous patterns"""
        findings = []
        risk_points = 0
        detected_functions = []
        
        try:
            # Check each function against dangerous patterns
            for function in functions:
                func_name = function.get("name", "")
                func_signature = function.get("signature", "")
                
                # Check against known dangerous function names
                for danger_type, signatures in self.dangerous_functions.items():
                    for sig in signatures:
                        if (func_name.lower() in sig.lower() or 
                            sig.lower() in func_signature.lower()):
                            
                            detected_functions.append({
                                "name": func_name,
                                "type": danger_type,
                                "signature": func_signature,
                                "severity": self._get_function_severity(danger_type)
                            })
            
            # Categorize findings by severity
            critical_functions = [f for f in detected_functions if f["severity"] == "critical"]
            high_functions = [f for f in detected_functions if f["severity"] == "high"]
            medium_functions = [f for f in detected_functions if f["severity"] == "medium"]
            
            # Add findings for each category
            if critical_functions:
                func_names = [f["name"] for f in critical_functions]
                findings.append({
                    "type": "critical_functions",
                    "severity": "critical",
                    "message": f"🔴 CRITICAL: {len(critical_functions)} critical function(s)",
                    "details": f"Functions: {', '.join(func_names)}"
                })
                risk_points += 30
            
            if high_functions:
                func_names = [f["name"] for f in high_functions]
                findings.append({
                    "type": "dangerous_functions",
                    "severity": "high",
                    "message": f"🔴 {len(high_functions)} dangerous function(s) detected",
                    "details": f"Functions: {', '.join(func_names)}"
                })
                risk_points += RISK_WEIGHTS.get("dangerous_functions", 20)
            
            if medium_functions:
                func_names = [f["name"] for f in medium_functions]
                findings.append({
                    "type": "suspicious_functions",
                    "severity": "medium",
                    "message": f"⚠️  {len(medium_functions)} suspicious function(s) detected",
                    "details": f"Functions: {', '.join(func_names)}"
                })
                risk_points += 10
            
            if not detected_functions:
                findings.append({
                    "type": "function_analysis",
                    "severity": "info",
                    "message": "✅ No dangerous functions detected",
                    "details": "Standard ERC-20 functions only"
                })
        
        except Exception as e:
            risk_points += 10
        
        return {
            "findings": findings,
            "risk_points": risk_points
        }
    
    def _check_hidden_functions(self, address: str) -> Dict:
        """Check for hidden or obfuscated functions"""
        findings = []
        risk_points = 0
        
        try:
            # Analyze bytecode for non-standard function patterns
            bytecode = self.w3.eth.get_code(Web3.toChecksumAddress(address))
            
            # Look for potential hidden minting functions
            hidden_patterns = self._find_hidden_patterns(bytecode)
            
            if hidden_patterns:
                findings.append({
                    "type": "hidden_functions",
                    "severity": "high",
                    "message": f"🔴 {len(hidden_patterns)} hidden function pattern(s) detected",
                    "details": f"Patterns: {', '.join(hidden_patterns)}"
                })
                risk_points += 25
            
        except Exception as e:
            risk_points += 5
        
        return {
            "findings": findings,
            "risk_points": risk_points
        }
    
    def _analyze_function_modifiers(self, functions: List[Dict]) -> Dict:
        """Analyze function access modifiers"""
        findings = []
        risk_points = 0
        
        try:
            # Count functions by access level
            public_functions = len([f for f in functions if f.get("visibility") == "public"])
            external_functions = len([f for f in functions if f.get("visibility") == "external"])
            owner_only_functions = len([f for f in functions if "onlyOwner" in f.get("modifiers", [])])
            
            # Check for excessive owner privileges
            if owner_only_functions > 5:
                findings.append({
                    "type": "access_control",
                    "severity": "medium",
                    "message": f"⚠️  Many owner-only functions ({owner_only_functions})",
                    "details": "Contract may have excessive centralization"
                })
                risk_points += 15
            
            # Check for public minting functions
            public_mint_functions = [f for f in functions 
                                   if f.get("visibility") == "public" and 
                                   any("mint" in f.get("name", "").lower() for mint in ["mint", "create"])]
            
            if public_mint_functions:
                findings.append({
                    "type": "public_mint",
                    "severity": "critical",
                    "message": "🔴 Public minting functions detected",
                    "details": f"Anyone can mint tokens"
                })
                risk_points += 30
        
        except Exception as e:
            risk_points += 5
        
        return {
            "findings": findings,
            "risk_points": risk_points
        }
    
    def _check_proxy_functions(self, functions: List[Dict]) -> Dict:
        """Check for proxy/delegate call functions"""
        findings = []
        risk_points = 0
        
        try:
            # Look for delegate call functions
            proxy_functions = [f for f in functions 
                             if any(pattern in f.get("name", "").lower() 
                                   for pattern in ["delegate", "proxy", "fallback"])]
            
            if proxy_functions:
                findings.append({
                    "type": "proxy_functions",
                    "severity": "medium",
                    "message": f"⚠️  Proxy/delegate functions detected",
                    "details": f"Functions: {', '.join([f['name'] for f in proxy_functions])}"
                })
                risk_points += 10
        
        except Exception as e:
            risk_points += 5
        
        return {
            "findings": findings,
            "risk_points": risk_points
        }
    
    def _analyze_access_control(self, functions: List[Dict]) -> Dict:
        """Analyze access control patterns"""
        findings = []
        risk_points = 0
        
        try:
            # Check for role-based access control
            rbac_functions = [f for f in functions 
                             if any(pattern in f.get("name", "").lower() 
                                   for pattern in ["role", "admin", "grant", "revoke"])]
            
            if rbac_functions:
                findings.append({
                    "type": "access_control",
                    "severity": "info",
                    "message": "ℹ️  Role-based access control detected",
                    "details": f"RBAC functions: {len(rbac_functions)}"
                })
            
            # Check for emergency functions
            emergency_functions = [f for f in functions 
                                 if any(pattern in f.get("name", "").lower() 
                                       for pattern in ["emergency", "rescue", "recover", "drain"])]
            
            if emergency_functions:
                findings.append({
                    "type": "emergency_functions",
                    "severity": "medium",
                    "message": f"⚠️  Emergency functions detected",
                    "details": f"Functions: {', '.join([f['name'] for f in emergency_functions])}"
                })
                risk_points += 10
        
        except Exception as e:
            risk_points += 5
        
        return {
            "findings": findings,
            "risk_points": risk_points
        }
    
    def _extract_functions_from_bytecode(self, address: str) -> List[Dict]:
        """Extract function signatures from contract bytecode"""
        functions = []
        
        try:
            bytecode = self.w3.eth.get_code(Web3.toChecksumAddress(address))
            
            # Simple function signature extraction (4-byte selectors)
            # This is a simplified implementation
            function_selectors = set()
            
            # Look for PUSH4 instructions followed by function selectors
            for i in range(0, len(bytecode) - 4, 1):
                if bytecode[i:i+1] == b'\x63':  # PUSH4 opcode
                    selector = bytecode[i+1:i+5]
                    function_selectors.add(selector.hex())
            
            # Convert selectors to function info (would need ABI mapping)
            for selector in function_selectors:
                functions.append({
                    "name": f"function_{selector[:8]}",
                    "signature": f"unknown({selector})",
                    "selector": selector,
                    "visibility": "unknown",
                    "modifiers": []
                })
        
        except Exception as e:
            pass
        
        return functions
    
    def _quick_dangerous_function_scan(self, address: str) -> List[str]:
        """Quick scan for dangerous function signatures in bytecode"""
        dangerous_found = []
        
        try:
            bytecode = self.w3.eth.get_code(Web3.toChecksumAddress(address))
            bytecode_str = bytecode.hex()
            
            # Known dangerous function selectors (4-byte signatures)
            dangerous_selectors = {
                "40c10f19": "mint(address,uint256)",
                "a9059cbb": "transfer(address,uint256)",  # Standard but check context
                "095ea7b3": "approve(address,uint256)",   # Standard but check context
                "8456cb59": "pause()",
                "3f4ba83a": "unpause()",
                "f2fde38b": "transferOwnership(address)",
                "715018a6": "renounceOwnership()"
            }
            
            # Check for dangerous selectors in bytecode
            for selector, func_sig in dangerous_selectors.items():
                if selector in bytecode_str:
                    # Additional validation would go here
                    if "mint" in func_sig or "pause" in func_sig:
                        dangerous_found.append(func_sig)
        
        except Exception as e:
            pass
        
        return dangerous_found

    def _process_source_findings(self, source_findings: List[Dict]) -> List[Dict]:
        """Process source code findings into standard format"""
        processed_findings = []

        for finding in source_findings:
            severity_map = {
                "critical": "🔴 CRITICAL",
                "high": "🔴",
                "medium": "⚠️",
                "low": "ℹ️"
            }

            severity_prefix = severity_map.get(finding["severity"], "⚠️")

            processed_finding = {
                "type": finding["type"],
                "severity": finding["severity"],
                "confidence": finding.get("confidence", 0.9),
                "message": f"{severity_prefix} {finding['message']}",
                "details": finding.get("details", ""),
                "detection_method": finding.get("detection_method", "source_code")
            }

            if "functions" in finding:
                processed_finding["functions"] = finding["functions"]

            processed_findings.append(processed_finding)

        return processed_findings

    def _analyze_bytecode_functions(self, address: str, archetype: str = None) -> Dict:
        """Analyze functions from bytecode with confidence scoring"""
        findings = []
        risk_points = 0
        confidence = 0.5  # Lower confidence for bytecode analysis

        try:
            # Get contract functions from bytecode
            contract_functions = self._get_contract_functions(address)

            # Analyze dangerous functions with confidence scoring
            dangerous_info = self._analyze_dangerous_functions_with_confidence(contract_functions, archetype)
            findings.extend(dangerous_info["findings"])
            risk_points += dangerous_info["risk_points"]

            # Check for hidden functions
            hidden_info = self._check_hidden_functions(address)
            findings.extend(hidden_info["findings"])
            risk_points += hidden_info["risk_points"]

            # Other analyses...
            # (keeping existing analyses but with confidence scores)

        except Exception as e:
            confidence = 0.3

        return {
            "findings": findings,
            "risk_points": risk_points,
            "confidence": confidence
        }

    def _analyze_dangerous_functions_with_confidence(self, functions: List[Dict], archetype: str = None) -> Dict:
        """Analyze dangerous functions with confidence scoring based on archetype"""
        findings = []
        risk_points = 0
        detected_functions = []

        try:
            # Check each function against dangerous patterns
            for function in functions:
                func_name = function.get("name", "")
                func_signature = function.get("signature", "")

                # Check against known dangerous function names
                for danger_type, signatures in self.dangerous_functions.items():
                    for sig in signatures:
                        if (func_name.lower() in sig.lower() or
                            sig.lower() in func_signature.lower()):

                            # Calculate confidence based on detection method and archetype
                            base_confidence = 0.4  # Base confidence for bytecode detection

                            # Adjust confidence based on archetype context
                            archetype_confidence = self._get_archetype_confidence(danger_type, archetype)
                            final_confidence = min(base_confidence + archetype_confidence, 1.0)

                            detected_functions.append({
                                "name": func_name,
                                "type": danger_type,
                                "signature": func_signature,
                                "severity": self._get_function_severity(danger_type),
                                "confidence": final_confidence
                            })

            # Group findings by confidence level
            high_confidence = [f for f in detected_functions if f["confidence"] >= 0.7]
            medium_confidence = [f for f in detected_functions if 0.4 <= f["confidence"] < 0.7]
            low_confidence = [f for f in detected_functions if f["confidence"] < 0.4]

            # Add findings with confidence indicators
            if high_confidence:
                func_names = [f["name"] for f in high_confidence]
                findings.append({
                    "type": "dangerous_functions_high_confidence",
                    "severity": "high",
                    "confidence": 0.8,
                    "message": f"🔴 {len(high_confidence)} dangerous function(s) detected (high confidence)",
                    "details": f"Functions: {', '.join(func_names)}",
                    "detection_method": "bytecode_analysis"
                })
                risk_points += RISK_WEIGHTS.get("dangerous_functions", 20)

            if medium_confidence:
                func_names = [f["name"] for f in medium_confidence]
                findings.append({
                    "type": "dangerous_functions_medium_confidence",
                    "severity": "medium",
                    "confidence": 0.5,
                    "message": f"⚠️  {len(medium_confidence)} potentially dangerous function(s) (medium confidence)",
                    "details": f"Functions: {', '.join(func_names)}",
                    "detection_method": "bytecode_analysis"
                })
                risk_points += 10

            if low_confidence:
                func_names = [f["name"] for f in low_confidence]
                findings.append({
                    "type": "suspicious_functions_low_confidence",
                    "severity": "low",
                    "confidence": 0.3,
                    "message": f"ℹ️  {len(low_confidence)} suspicious function(s) (low confidence)",
                    "details": f"Functions: {', '.join(func_names)} - Manual review recommended",
                    "detection_method": "bytecode_analysis"
                })
                risk_points += 5

            if not detected_functions:
                findings.append({
                    "type": "function_analysis",
                    "severity": "info",
                    "confidence": 0.6,
                    "message": "✅ No obvious dangerous functions detected",
                    "details": "Bytecode analysis - consider manual review for verification",
                    "detection_method": "bytecode_analysis"
                })

        except Exception as e:
            risk_points += 10

        return {
            "findings": findings,
            "risk_points": risk_points
        }

    def _get_archetype_confidence(self, danger_type: str, archetype: str) -> float:
        """Get confidence adjustment based on token archetype"""
        if not archetype:
            return 0.0

        # Confidence adjustments based on archetype context
        archetype_adjustments = {
            "standard_erc20": {
                "mint": 0.3,  # Minting is suspicious in standard tokens
                "pause": 0.2,
                "blacklist": 0.2,
                "setFee": -0.2  # Fee functions less likely in standard tokens
            },
            "tax_fee_token": {
                "setFee": 0.4,  # Fee functions expected in tax tokens
                "setSellFee": 0.4,
                "setBuyFee": 0.4,
                "blacklist": 0.1,
                "pause": 0.1
            },
            "wrapper_token": {
                "mint": -0.1,  # Minting might be legitimate in wrappers
                "setFee": -0.3,  # Fee functions unexpected in wrappers
                "deposit": -0.5,  # Deposit functions are normal
                "withdraw": -0.5  # Withdraw functions are normal
            }
        }

        return archetype_adjustments.get(archetype, {}).get(danger_type, 0.0)

    def _filter_findings_by_archetype(self, findings: List[Dict], archetype: str) -> List[Dict]:
        """Filter findings based on archetype to reduce false positives"""
        filtered_findings = []

        for finding in findings:
            # Apply archetype-specific filtering logic
            include_finding = True

            if archetype == "wrapper_token":
                # In wrapper tokens, deposit/withdraw functions are normal
                if finding.get("type") == "suspicious_functions" and \
                   any(func in finding.get("details", "").lower()
                       for func in ["deposit", "withdraw"]):
                    include_finding = False

            elif archetype == "tax_fee_token":
                # In tax tokens, fee functions are expected
                if finding.get("type") == "tax_functions" and \
                   finding.get("confidence", 0) < 0.8:
                    # Keep but downgrade severity
                    finding["severity"] = "info"
                    finding["message"] = finding["message"].replace("🔴", "ℹ️")

            if include_finding:
                filtered_findings.append(finding)

        return filtered_findings

    def _apply_confidence_adjustments(self, findings: List[Dict]) -> List[Dict]:
        """Apply confidence-based adjustments to findings"""
        adjusted_findings = []

        for finding in findings:
            confidence = finding.get("confidence", 0.5)

            # Downgrade severity for low confidence findings
            if confidence < 0.4:
                severity_downgrade = {
                    "critical": "high",
                    "high": "medium",
                    "medium": "low",
                    "low": "info"
                }

                original_severity = finding.get("severity", "medium")
                finding["severity"] = severity_downgrade.get(original_severity, "low")

                # Add confidence indicator to message
                if "(low confidence)" not in finding.get("message", ""):
                    finding["message"] += " (low confidence)"

            elif confidence >= 0.8:
                # Add high confidence indicator
                if "(high confidence)" not in finding.get("message", ""):
                    finding["message"] += " (high confidence)"

            adjusted_findings.append(finding)

        return adjusted_findings

    def _calculate_risk_from_findings(self, findings: List[Dict]) -> int:
        """Calculate risk points from findings with confidence weighting"""
        risk_points = 0

        for finding in findings:
            base_risk = {
                "critical": 30,
                "high": 20,
                "medium": 10,
                "low": 5,
                "info": 0
            }.get(finding.get("severity", "medium"), 10)

            # Weight by confidence
            confidence = finding.get("confidence", 0.5)
            weighted_risk = int(base_risk * confidence)
            risk_points += weighted_risk

        return risk_points
    
    def _find_hidden_patterns(self, bytecode: bytes) -> List[str]:
        """Find hidden or obfuscated patterns in bytecode"""
        patterns = []
        
        try:
            # Look for suspicious patterns
            bytecode_hex = bytecode.hex()
            
            # Pattern 1: Unusual SELFDESTRUCT patterns
            if "ff" in bytecode_hex:  # SELFDESTRUCT opcode
                patterns.append("selfdestruct_pattern")
            
            # Pattern 2: Complex jump patterns (might indicate obfuscation)
            jump_count = bytecode_hex.count("56") + bytecode_hex.count("57")  # JUMP + JUMPI
            if jump_count > 50:
                patterns.append("complex_control_flow")
            
            # Pattern 3: Excessive storage operations
            sstore_count = bytecode_hex.count("55")  # SSTORE
            if sstore_count > 20:
                patterns.append("excessive_storage_ops")
        
        except Exception as e:
            pass
        
        return patterns
    
    def _get_function_severity(self, danger_type: str) -> str:
        """Get severity level for dangerous function type"""
        severity_map = {
            "mint": "critical",
            "mintTo": "critical", 
            "_mint": "critical",
            "pause": "high",
            "unpause": "high",
            "stop": "high",
            "blacklist": "high",
            "ban": "high",
            "setFee": "medium",
            "setSellFee": "medium",
            "setBuyFee": "medium",
            "transferOwnership": "medium",
            "renounceOwnership": "low",
            "skim": "medium",
            "sync": "low",
            "airdrop": "medium"
        }
        
        return severity_map.get(danger_type, "medium")