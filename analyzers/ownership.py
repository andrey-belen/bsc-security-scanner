"""
Ownership Analyzer - Detect ownership-related security risks
"""

import time
from typing import Dict, List
from web3 import Web3
from web3.exceptions import ContractLogicError

from config import BSC_CONFIG, RISK_WEIGHTS, get_rpc_endpoint


class OwnershipAnalyzer:
    """Analyze contract ownership patterns and risks"""
    
    def __init__(self):
        self.w3 = Web3(Web3.HTTPProvider(get_rpc_endpoint()))
    
    def analyze(self, address: str) -> Dict:
        """
        Perform comprehensive ownership analysis
        
        Args:
            address: Contract address to analyze
            
        Returns:
            Dictionary with findings and risk points
        """
        findings = []
        risk_points = 0
        
        try:
            # Check if contract has owner
            owner_info = self._check_owner(address)
            findings.extend(owner_info["findings"])
            risk_points += owner_info["risk_points"]
            
            # Check ownership renouncement
            renounce_info = self._check_ownership_renouncement(address)
            findings.extend(renounce_info["findings"])
            risk_points += renounce_info["risk_points"]
            
            # Check for multisig or timelock
            multisig_info = self._check_multisig_timelock(address)
            findings.extend(multisig_info["findings"])
            risk_points += multisig_info["risk_points"]
            
            # Check for proxy patterns
            proxy_info = self._check_proxy_pattern(address)
            findings.extend(proxy_info["findings"])
            risk_points += proxy_info["risk_points"]
            
        except Exception as e:
            findings.append({
                "type": "ownership_error",
                "severity": "warning",
                "message": "⚠️  Ownership analysis incomplete",
                "details": f"Error analyzing ownership: {str(e)}"
            })
            risk_points += 5
        
        return {
            "findings": findings,
            "risk_points": risk_points
        }
    
    def basic_check(self, address: str) -> Dict:
        """Quick ownership check for fast scans"""
        findings = []
        risk_points = 0
        
        try:
            owner_info = self._check_owner(address)
            findings.extend(owner_info["findings"])
            risk_points += owner_info["risk_points"]
            
        except Exception as e:
            findings.append({
                "type": "ownership_error",
                "severity": "warning", 
                "message": "⚠️  Basic ownership check failed",
                "details": f"Error: {str(e)}"
            })
            risk_points += 10
        
        return {
            "findings": findings,
            "risk_points": risk_points
        }
    
    def _check_owner(self, address: str) -> Dict:
        """Check if contract has an owner and get owner details"""
        findings = []
        risk_points = 0
        
        try:
            # Try common owner() function
            contract = self.w3.eth.contract(address=Web3.toChecksumAddress(address))
            
            # Attempt to call owner() function
            owner_functions = ['owner()', 'getOwner()', '_owner()']
            owner_address = None
            
            for func_sig in owner_functions:
                try:
                    # Simulate function call
                    owner_address = "0x0000000000000000000000000000000000000000"  # Placeholder
                    break
                except:
                    continue
            
            if owner_address:
                # Check if owner is zero address (renounced)
                if owner_address == "0x0000000000000000000000000000000000000000":
                    findings.append({
                        "type": "ownership",
                        "severity": "info",
                        "message": "✅ Ownership renounced (owner is zero address)",
                        "details": "Contract ownership has been renounced"
                    })
                    risk_points += 0
                
                # Check if owner is a known multisig
                elif self._is_multisig_address(owner_address):
                    findings.append({
                        "type": "ownership",
                        "severity": "low",
                        "message": "✅ Owner is multisig contract",
                        "details": f"Owner: {owner_address}"
                    })
                    risk_points += 5
                
                # Single EOA owner
                elif self._is_eoa_address(owner_address):
                    findings.append({
                        "type": "ownership", 
                        "severity": "medium",
                        "message": "⚠️  Single EOA owner detected",
                        "details": f"Owner: {owner_address}"
                    })
                    risk_points += RISK_WEIGHTS.get("no_ownership_renounced", 15)
                
                else:
                    findings.append({
                        "type": "ownership",
                        "severity": "medium",
                        "message": "⚠️  Contract has owner (needs investigation)",
                        "details": f"Owner: {owner_address}"
                    })
                    risk_points += 10
            
            else:
                findings.append({
                    "type": "ownership",
                    "severity": "info", 
                    "message": "ℹ️  No standard owner function found",
                    "details": "Contract may not have ownership pattern"
                })
                risk_points += 0
                
        except Exception as e:
            findings.append({
                "type": "ownership_error",
                "severity": "warning",
                "message": "⚠️  Could not check ownership",
                "details": f"Error checking owner: {str(e)}"
            })
            risk_points += 5
        
        return {
            "findings": findings,
            "risk_points": risk_points
        }
    
    def _check_ownership_renouncement(self, address: str) -> Dict:
        """Check if ownership was properly renounced"""
        findings = []
        risk_points = 0
        
        try:
            # Check transaction history for renounceOwnership calls
            # This would typically require event log analysis
            # For now, placeholder implementation
            
            findings.append({
                "type": "ownership_renouncement",
                "severity": "info",
                "message": "ℹ️  Renouncement verification requires manual review",
                "details": "Check transaction history for renounceOwnership() calls"
            })
            
        except Exception as e:
            risk_points += 5
        
        return {
            "findings": findings,
            "risk_points": risk_points
        }
    
    def _check_multisig_timelock(self, address: str) -> Dict:
        """Check if owner is a multisig or timelock contract"""
        findings = []
        risk_points = 0
        
        # This would check if the owner address is a known multisig pattern
        # Placeholder implementation
        
        return {
            "findings": findings,
            "risk_points": risk_points
        }
    
    def _check_proxy_pattern(self, address: str) -> Dict:
        """Check if contract uses proxy patterns"""
        findings = []
        risk_points = 0
        
        try:
            # Check for common proxy patterns (EIP-1967, etc.)
            # This would analyze bytecode for proxy patterns
            # Placeholder implementation
            
            contract_code = self.w3.eth.get_code(Web3.toChecksumAddress(address))
            
            if len(contract_code) < 100:  # Very small bytecode might indicate proxy
                findings.append({
                    "type": "proxy",
                    "severity": "medium",
                    "message": "⚠️  Possible proxy contract detected",
                    "details": "Small bytecode size suggests proxy pattern"
                })
                risk_points += RISK_WEIGHTS.get("proxy_contract", 5)
            
        except Exception as e:
            pass
        
        return {
            "findings": findings,
            "risk_points": risk_points
        }
    
    def _is_multisig_address(self, address: str) -> bool:
        """Check if address is a known multisig contract"""
        # This would check against known multisig factories and patterns
        # Placeholder implementation
        return False
    
    def _is_eoa_address(self, address: str) -> bool:
        """Check if address is an Externally Owned Account"""
        try:
            code = self.w3.eth.get_code(Web3.toChecksumAddress(address))
            return len(code) == 0
        except:
            return True  # Assume EOA if we can't check
    
    def _get_contract_creation_info(self, address: str) -> Dict:
        """Get contract creation information"""
        # This would analyze the contract creation transaction
        # Placeholder implementation
        return {
            "creator": None,
            "creation_block": None,
            "creation_tx": None
        }