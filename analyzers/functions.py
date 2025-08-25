"""
Function Analyzer - Detect dangerous and suspicious function signatures
"""

import re
import time
from typing import Dict, List, Set, Tuple
from web3 import Web3
from web3.exceptions import ContractLogicError

from config import BSC_CONFIG, DANGEROUS_FUNCTION_SIGNATURES, RISK_WEIGHTS, get_rpc_endpoint


class FunctionAnalyzer:
    """Analyze contract functions for security risks"""
    
    def __init__(self):
        self.w3 = Web3(Web3.HTTPProvider(get_rpc_endpoint()))
        self.dangerous_functions = DANGEROUS_FUNCTION_SIGNATURES
    
    def analyze(self, address: str) -> Dict:
        """
        Comprehensive function analysis
        
        Args:
            address: Contract address to analyze
            
        Returns:
            Dictionary with findings and risk points
        """
        findings = []
        risk_points = 0
        
        try:
            # Get contract ABI if available
            contract_functions = self._get_contract_functions(address)
            
            # Analyze dangerous functions
            dangerous_info = self._analyze_dangerous_functions(contract_functions)
            findings.extend(dangerous_info["findings"])
            risk_points += dangerous_info["risk_points"]
            
            # Check for hidden functions
            hidden_info = self._check_hidden_functions(address)
            findings.extend(hidden_info["findings"])
            risk_points += hidden_info["risk_points"]
            
            # Analyze function modifiers
            modifier_info = self._analyze_function_modifiers(contract_functions)
            findings.extend(modifier_info["findings"])
            risk_points += modifier_info["risk_points"]
            
            # Check for proxy/delegate call patterns
            proxy_info = self._check_proxy_functions(contract_functions)
            findings.extend(proxy_info["findings"])
            risk_points += proxy_info["risk_points"]
            
            # Analyze access control
            access_info = self._analyze_access_control(contract_functions)
            findings.extend(access_info["findings"])
            risk_points += access_info["risk_points"]
            
        except Exception as e:
            findings.append({
                "type": "function_error",
                "severity": "warning",
                "message": "⚠️  Function analysis incomplete",
                "details": f"Error analyzing functions: {str(e)}"
            })
            risk_points += 10
        
        return {
            "findings": findings,
            "risk_points": risk_points
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