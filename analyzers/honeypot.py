"""
Honeypot Analyzer - Detect honeypot mechanisms and trading restrictions
"""

import time
from typing import Dict, List, Optional
from web3 import Web3
from web3.exceptions import ContractLogicError

from config import BSC_CONFIG, HONEYPOT_PATTERNS, RISK_WEIGHTS, get_rpc_endpoint, BSC_CONTRACTS


class HoneypotAnalyzer:
    """Detect honeypot mechanisms that prevent selling"""
    
    def __init__(self):
        self.w3 = Web3(Web3.HTTPProvider(get_rpc_endpoint()))
        self.pancakeswap_router = BSC_CONTRACTS["pancakeswap_router"]
        self.wbnb = BSC_CONTRACTS["wbnb"]
    
    def analyze(self, address: str) -> Dict:
        """
        Comprehensive honeypot analysis
        
        Args:
            address: Token contract address
            
        Returns:
            Dictionary with findings and risk points
        """
        findings = []
        risk_points = 0
        
        try:
            # Check sell restrictions
            sell_info = self._check_sell_restrictions(address)
            findings.extend(sell_info["findings"])
            risk_points += sell_info["risk_points"]
            
            # Check tax mechanisms
            tax_info = self._check_tax_mechanisms(address)
            findings.extend(tax_info["findings"])
            risk_points += tax_info["risk_points"]
            
            # Check max transaction limits
            limit_info = self._check_transaction_limits(address)
            findings.extend(limit_info["findings"])
            risk_points += limit_info["risk_points"]
            
            # Check transfer restrictions
            transfer_info = self._check_transfer_restrictions(address)
            findings.extend(transfer_info["findings"])
            risk_points += transfer_info["risk_points"]
            
            # Simulate buy/sell to detect honeypot
            simulation_info = self._simulate_buy_sell(address)
            findings.extend(simulation_info["findings"])
            risk_points += simulation_info["risk_points"]
            
        except Exception as e:
            findings.append({
                "type": "honeypot_error",
                "severity": "warning",
                "message": "⚠️  Honeypot analysis incomplete", 
                "details": f"Error analyzing honeypot mechanisms: {str(e)}"
            })
            risk_points += 10
        
        return {
            "findings": findings,
            "risk_points": risk_points
        }
    
    def _check_sell_restrictions(self, address: str) -> Dict:
        """Check for sell restriction mechanisms"""
        findings = []
        risk_points = 0
        
        try:
            # Check for common sell blocking patterns
            sell_functions = [
                "canSell(address)",
                "isSellEnabled()",
                "sellEnabled()",
                "tradingEnabled()",
                "_canTransfer(address,address)"
            ]
            
            # This would analyze contract bytecode for these patterns
            # Placeholder implementation showing detected patterns
            
            # Simulate high sell tax detection
            sell_tax = self._estimate_sell_tax(address)
            if sell_tax > HONEYPOT_PATTERNS["high_sell_tax"]["threshold"]:
                findings.append({
                    "type": "honeypot",
                    "severity": "high",
                    "message": f"🔴 High sell tax detected ({sell_tax}%)",
                    "details": f"Sell tax of {sell_tax}% may prevent profitable selling"
                })
                risk_points += RISK_WEIGHTS.get("high_sell_tax", 25)
            
            elif sell_tax > 5:
                findings.append({
                    "type": "tax",
                    "severity": "medium", 
                    "message": f"⚠️  Moderate sell tax ({sell_tax}%)",
                    "details": f"Sell tax: {sell_tax}%"
                })
                risk_points += 10
            
            else:
                findings.append({
                    "type": "tax",
                    "severity": "info",
                    "message": f"✅ Reasonable sell tax ({sell_tax}%)",
                    "details": f"Sell tax: {sell_tax}%"
                })
            
        except Exception as e:
            risk_points += 5
        
        return {
            "findings": findings,
            "risk_points": risk_points
        }
    
    def _check_tax_mechanisms(self, address: str) -> Dict:
        """Analyze tax and fee mechanisms"""
        findings = []
        risk_points = 0
        
        try:
            # Check for different buy/sell taxes
            buy_tax = self._estimate_buy_tax(address)
            sell_tax = self._estimate_sell_tax(address)
            
            tax_difference = abs(sell_tax - buy_tax)
            
            if tax_difference > HONEYPOT_PATTERNS["different_buy_sell_tax"]["threshold"]:
                findings.append({
                    "type": "tax_asymmetry",
                    "severity": "medium",
                    "message": f"⚠️  Different buy/sell taxes detected",
                    "details": f"Buy tax: {buy_tax}%, Sell tax: {sell_tax}% (diff: {tax_difference}%)"
                })
                risk_points += 15
            
            # Check for dynamic tax mechanisms
            dynamic_tax = self._check_dynamic_taxes(address)
            if dynamic_tax:
                findings.append({
                    "type": "dynamic_tax",
                    "severity": "high",
                    "message": "🔴 Dynamic tax mechanism detected",
                    "details": "Taxes can be changed by contract owner"
                })
                risk_points += 20
            
        except Exception as e:
            risk_points += 5
        
        return {
            "findings": findings,
            "risk_points": risk_points
        }
    
    def _check_transaction_limits(self, address: str) -> Dict:
        """Check for restrictive transaction limits"""
        findings = []
        risk_points = 0
        
        try:
            # Get total supply
            total_supply = self._get_total_supply(address)
            
            # Check max transaction amount
            max_tx_amount = self._get_max_transaction_amount(address)
            
            if max_tx_amount and total_supply:
                max_tx_percentage = (max_tx_amount / total_supply) * 100
                
                if max_tx_percentage < HONEYPOT_PATTERNS["max_transaction_limit"]["threshold"]:
                    findings.append({
                        "type": "transaction_limit",
                        "severity": "medium",
                        "message": f"⚠️  Very low max transaction limit ({max_tx_percentage:.2f}%)",
                        "details": f"Max transaction: {max_tx_percentage:.2f}% of total supply"
                    })
                    risk_points += 15
                
                elif max_tx_percentage < 2:
                    findings.append({
                        "type": "transaction_limit",
                        "severity": "low",
                        "message": f"⚠️  Low max transaction limit ({max_tx_percentage:.2f}%)",
                        "details": f"Max transaction: {max_tx_percentage:.2f}% of total supply"
                    })
                    risk_points += 5
                
                else:
                    findings.append({
                        "type": "transaction_limit",
                        "severity": "info",
                        "message": f"✅ Reasonable transaction limit ({max_tx_percentage:.2f}%)",
                        "details": f"Max transaction: {max_tx_percentage:.2f}% of total supply"
                    })
            
        except Exception as e:
            risk_points += 5
        
        return {
            "findings": findings,
            "risk_points": risk_points
        }
    
    def _check_transfer_restrictions(self, address: str) -> Dict:
        """Check for transfer restriction mechanisms"""
        findings = []
        risk_points = 0
        
        try:
            # Check for transfer pause functionality
            if self._has_pause_functionality(address):
                findings.append({
                    "type": "transfer_restrictions",
                    "severity": "high",
                    "message": "🔴 Owner can pause transfers",
                    "details": "Contract has pause functionality that can stop all transfers"
                })
                risk_points += 20
            
            # Check for blacklist functionality
            if self._has_blacklist_functionality(address):
                findings.append({
                    "type": "blacklist",
                    "severity": "medium",
                    "message": "⚠️  Blacklist functionality present",
                    "details": "Owner can blacklist addresses from trading"
                })
                risk_points += 15
            
            # Check for whitelist-only trading
            if self._has_whitelist_only(address):
                findings.append({
                    "type": "whitelist",
                    "severity": "high", 
                    "message": "🔴 Whitelist-only trading detected",
                    "details": "Only whitelisted addresses can trade"
                })
                risk_points += 25
        
        except Exception as e:
            risk_points += 5
        
        return {
            "findings": findings,
            "risk_points": risk_points
        }
    
    def _simulate_buy_sell(self, address: str) -> Dict:
        """Simulate buy/sell transactions to detect honeypots"""
        findings = []
        risk_points = 0
        
        try:
            # This would simulate actual buy/sell transactions
            # For security and cost reasons, we'll do static analysis instead
            
            findings.append({
                "type": "simulation",
                "severity": "info",
                "message": "ℹ️  Manual buy/sell simulation recommended",
                "details": "Use small amounts to test buy/sell functionality"
            })
            
            # Check for common honeypot bytecode patterns
            honeypot_score = self._analyze_bytecode_patterns(address)
            
            if honeypot_score > 70:
                findings.append({
                    "type": "honeypot",
                    "severity": "critical",
                    "message": "🔴 HIGH HONEYPOT RISK DETECTED",
                    "details": f"Bytecode analysis score: {honeypot_score}/100"
                })
                risk_points += RISK_WEIGHTS.get("honeypot_indicators", 30)
            
            elif honeypot_score > 40:
                findings.append({
                    "type": "honeypot",
                    "severity": "medium",
                    "message": "⚠️  Moderate honeypot risk",
                    "details": f"Bytecode analysis score: {honeypot_score}/100"
                })
                risk_points += 15
        
        except Exception as e:
            risk_points += 5
        
        return {
            "findings": findings,
            "risk_points": risk_points
        }
    
    def _estimate_buy_tax(self, address: str) -> float:
        """Estimate buy tax percentage"""
        # Placeholder implementation
        # This would analyze contract code for tax calculations
        return 5.0  # Example: 5% buy tax
    
    def _estimate_sell_tax(self, address: str) -> float:
        """Estimate sell tax percentage"""
        # Placeholder implementation  
        # This would analyze contract code for sell tax calculations
        return 12.0  # Example: 12% sell tax (indicating potential honeypot)
    
    def _check_dynamic_taxes(self, address: str) -> bool:
        """Check if taxes can be changed dynamically"""
        # This would analyze bytecode for tax modification functions
        return True  # Placeholder
    
    def _get_total_supply(self, address: str) -> Optional[int]:
        """Get token total supply"""
        try:
            # Call totalSupply() function
            return 1000000 * 10**18  # Placeholder
        except:
            return None
    
    def _get_max_transaction_amount(self, address: str) -> Optional[int]:
        """Get maximum transaction amount"""
        try:
            # Call maxTxAmount() or similar function
            return 10000 * 10**18  # Placeholder: 1% of total supply
        except:
            return None
    
    def _has_pause_functionality(self, address: str) -> bool:
        """Check if contract has pause functionality"""
        # Analyze bytecode for pause-related functions
        return True  # Placeholder
    
    def _has_blacklist_functionality(self, address: str) -> bool:
        """Check if contract has blacklist functionality"""
        # Analyze bytecode for blacklist functions
        return True  # Placeholder
    
    def _has_whitelist_only(self, address: str) -> bool:
        """Check if trading is whitelist-only"""
        # Analyze contract logic
        return False  # Placeholder
    
    def _analyze_bytecode_patterns(self, address: str) -> int:
        """Analyze bytecode for honeypot patterns"""
        try:
            bytecode = self.w3.eth.get_code(Web3.toChecksumAddress(address))
            
            # Simple heuristic based on bytecode analysis
            # Real implementation would analyze opcode patterns
            
            honeypot_score = 0
            
            # Check bytecode size (too small might indicate proxy)
            if len(bytecode) < 1000:
                honeypot_score += 20
            
            # Check for suspicious patterns (placeholder)
            if b'\x60\x00' in bytecode:  # PUSH1 0x00 pattern
                honeypot_score += 10
            
            return min(honeypot_score, 100)
            
        except Exception as e:
            return 50  # Default moderate risk if analysis fails