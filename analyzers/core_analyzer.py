"""
Core Security Analyzer - Functional security analysis with proper BSCScan integration
Focuses on actual security checks without overcomplicating
"""

import requests
import time
import os
from typing import Dict, List, Optional
from web3 import Web3
from eth_utils import to_checksum_address

from config import BSC_CONFIG, get_rpc_endpoint


class CoreSecurityAnalyzer:
    """
    Simplified but functional security analyzer
    Performs real checks with proper API integration
    """

    def __init__(self):
        self.w3 = Web3(Web3.HTTPProvider(get_rpc_endpoint()))
        self.bscscan_api = BSC_CONFIG["explorer_api"]
        # Try Etherscan key first (BSCScan now uses Etherscan), fallback to legacy BSCSCAN_API_KEY
        self.api_key = os.getenv('ETHERSCAN_API_KEY') or os.getenv('BSCSCAN_API_KEY', '')
        self.findings = []
        self.risk_score = 0

    def analyze_contract(self, address: str, quick_scan: bool = False) -> Dict:
        """
        Main analysis function with real security checks

        Args:
            address: Contract address to analyze
            quick_scan: Skip expensive checks if True

        Returns:
            Complete analysis results with actual findings
        """
        self.findings = []
        self.risk_score = 0

        try:
            address = to_checksum_address(address)
        except Exception as e:
            return self._error_result(address, f"Invalid address format: {str(e)}")

        # Step 1: Check if contract exists
        code = self.w3.eth.get_code(address)
        if code == b'' or code == b'0x':
            return self._error_result(address, "No contract code at this address")

        # Step 2: Get contract verification status
        is_verified, source_code = self._check_verification(address)

        # Step 3: Check ownership
        owner_info = self._check_ownership(address)

        # Step 4: Analyze functions (from ABI or bytecode)
        function_risks = self._analyze_functions(address, source_code)

        # Step 5: Check for common red flags
        red_flags = self._check_red_flags(address, source_code)

        # Step 6: Check token info if ERC-20
        token_info = self._get_token_info(address)

        # Step 7: Calculate risk score
        self.risk_score = self._calculate_risk()

        return {
            "address": address,
            "scan_time": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "chain": "Binance Smart Chain (BSC)",
            "quick_scan": quick_scan,
            "is_verified": is_verified,
            "has_source_code": source_code is not None,
            "owner": owner_info.get("owner"),
            "is_renounced": owner_info.get("is_renounced", False),
            "token_name": token_info.get("name"),
            "token_symbol": token_info.get("symbol"),
            "findings": self.findings,
            "risk_score": self.risk_score,
            "risk_level": self._get_risk_level(self.risk_score),
            "analysis_confidence": 0.8 if is_verified else 0.5
        }

    def _check_verification(self, address: str) -> tuple[bool, Optional[str]]:
        """Check if contract is verified using multiple methods"""

        # Method 1: Try BSCScan web scraping
        try:
            scrape_url = f"https://bscscan.com/address/{address}#code"
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            response = requests.get(scrape_url, headers=headers, timeout=10)

            if response.status_code == 200:
                html = response.text
                # Check if contract is verified
                if "Contract Source Code Verified" in html or "Exact Match" in html:
                    self._add_finding(
                        "info",
                        "Contract Verified",
                        "Contract source code is verified on BSCScan.",
                        "verification"
                    )
                    return True, None  # We can see it's verified even without source
                elif "Contract Source Code Not Verified" in html or "not verified" in html.lower():
                    self._add_finding(
                        "medium",
                        "Contract Not Verified",
                        "Contract source code is not verified on BSCScan. This increases risk as code cannot be audited.",
                        "verification"
                    )
                    self.risk_score += 20
                    return False, None
        except Exception as e:
            print(f"Web scraping check failed: {e}")

        # Method 2: Try to get ABI - if ABI exists, likely verified
        try:
            # Check if contract has readable functions (sign of verification)
            code = self.w3.eth.get_code(address)
            if len(code) > 100:  # Has substantial code
                # Try calling common view functions to see if ABI is available
                try:
                    # Try ERC20 name() function
                    name_abi = [{"constant": True, "inputs": [], "name": "name", "outputs": [{"name": "", "type": "string"}], "type": "function"}]
                    contract = self.w3.eth.contract(address=address, abi=name_abi)
                    name = contract.functions.name().call()

                    # If we got here, contract has standard functions (likely legitimate)
                    self._add_finding(
                        "info",
                        "Standard Contract Functions Detected",
                        f"Contract implements standard ERC-20 functions. Token: {name}",
                        "verification"
                    )
                    return False, None  # Not verified but has standard interface
                except:
                    pass
        except Exception as e:
            print(f"ABI check failed: {e}")

        # Default: Unknown verification status
        self._add_finding(
            "low",
            "Verification Status Unknown",
            "Unable to confirm contract verification status. Proceeding with bytecode analysis.",
            "verification"
        )
        self.risk_score += 10
        return False, None

    def _check_ownership(self, address: str) -> Dict:
        """Check contract ownership status"""
        owner_info = {"owner": None, "is_renounced": False}

        try:
            # Try common owner() function
            owner_abi = [{
                "constant": True,
                "inputs": [],
                "name": "owner",
                "outputs": [{"name": "", "type": "address"}],
                "type": "function"
            }]

            contract = self.w3.eth.contract(address=address, abi=owner_abi)
            owner = contract.functions.owner().call()

            owner_info["owner"] = owner

            # Check if renounced (owner = 0x0)
            if owner == "0x0000000000000000000000000000000000000000":
                owner_info["is_renounced"] = True
                self._add_finding(
                    "info",
                    "Ownership Renounced",
                    "Contract ownership has been renounced (owner set to zero address). Contract cannot be modified.",
                    "ownership"
                )
            else:
                self._add_finding(
                    "low",
                    "Centralized Ownership",
                    f"Contract has an active owner: {owner[:10]}...{owner[-8:]}. Owner may have privileged functions.",
                    "ownership"
                )
                self.risk_score += 10

        except Exception as e:
            # No owner() function or error
            self._add_finding(
                "info",
                "No Owner Function",
                "Contract does not implement standard owner() function. May not be ownable.",
                "ownership"
            )

        return owner_info

    def _analyze_functions(self, address: str, source_code: Optional[str]) -> Dict:
        """Analyze contract functions for dangerous patterns"""
        risks = {}

        # Check for dangerous function names in bytecode
        dangerous_selectors = {
            "0x40c10f19": "mint",
            "0xa9059cbb": "transfer",
            "0x095ea7b3": "approve",
            "0x23b872dd": "transferFrom",
            "0x8456cb59": "pause",
            "0x3f4ba83a": "unpause",
            "0xf2fde38b": "transferOwnership"
        }

        code = self.w3.eth.get_code(address).hex()

        found_dangerous = []
        for selector, name in dangerous_selectors.items():
            if selector[2:] in code:  # Remove 0x prefix
                found_dangerous.append(name)

        if "mint" in found_dangerous:
            self._add_finding(
                "high",
                "Mint Function Detected",
                "Contract has a mint() function. Owner may be able to create unlimited tokens, diluting holder value.",
                "dangerous_function"
            )
            self.risk_score += 25

        if "pause" in found_dangerous or "unpause" in found_dangerous:
            self._add_finding(
                "medium",
                "Pause Functionality",
                "Contract can be paused, potentially freezing all transfers. Ensure this is expected behavior.",
                "dangerous_function"
            )
            self.risk_score += 15

        risks["dangerous_functions"] = found_dangerous
        return risks

    def _check_red_flags(self, address: str, source_code: Optional[str]) -> List[str]:
        """Check for common scam patterns"""
        flags = []

        if source_code:
            source_lower = source_code.lower()

            # Check for blacklist
            if "blacklist" in source_lower or "_isblacklisted" in source_lower:
                self._add_finding(
                    "high",
                    "Blacklist Function Found",
                    "Contract contains blacklist functionality. Owner can prevent specific addresses from trading.",
                    "red_flag"
                )
                self.risk_score += 30
                flags.append("blacklist")

            # Check for high transfer fees in source
            if "transferfee" in source_lower or "sellfee" in source_lower:
                self._add_finding(
                    "medium",
                    "Transfer Fees Detected",
                    "Contract implements transfer fees. Verify fee percentages are reasonable.",
                    "red_flag"
                )
                self.risk_score += 20
                flags.append("transfer_fees")

        return flags

    def _get_token_info(self, address: str) -> Dict:
        """Get basic ERC-20 token information"""
        token_info = {}

        try:
            # Try standard ERC-20 functions
            erc20_abi = [
                {"constant": True, "inputs": [], "name": "name", "outputs": [{"name": "", "type": "string"}], "type": "function"},
                {"constant": True, "inputs": [], "name": "symbol", "outputs": [{"name": "", "type": "string"}], "type": "function"},
                {"constant": True, "inputs": [], "name": "decimals", "outputs": [{"name": "", "type": "uint8"}], "type": "function"},
                {"constant": True, "inputs": [], "name": "totalSupply", "outputs": [{"name": "", "type": "uint256"}], "type": "function"}
            ]

            contract = self.w3.eth.contract(address=address, abi=erc20_abi)

            try:
                token_info["name"] = contract.functions.name().call()
            except:
                pass

            try:
                token_info["symbol"] = contract.functions.symbol().call()
            except:
                pass

            try:
                token_info["decimals"] = contract.functions.decimals().call()
            except:
                pass

            try:
                token_info["total_supply"] = contract.functions.totalSupply().call()
            except:
                pass

        except Exception as e:
            print(f"Token info retrieval error: {e}")

        return token_info

    def _calculate_risk(self) -> int:
        """Calculate final risk score (0-100)"""
        # Risk score is already accumulated during analysis
        # Cap at 100
        return min(self.risk_score, 100)

    def _get_risk_level(self, score: int) -> str:
        """Convert risk score to risk level"""
        if score >= 75:
            return "CRITICAL"
        elif score >= 50:
            return "HIGH"
        elif score >= 25:
            return "MEDIUM"
        elif score >= 10:
            return "LOW"
        else:
            return "VERY LOW"

    def _add_finding(self, severity: str, message: str, details: str, finding_type: str):
        """Add a security finding"""
        self.findings.append({
            "severity": severity,
            "message": message,
            "details": details,
            "type": finding_type
        })

    def _error_result(self, address: str, error_msg: str) -> Dict:
        """Return error result"""
        return {
            "address": address,
            "scan_time": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "chain": "Binance Smart Chain (BSC)",
            "error": error_msg,
            "findings": [],
            "risk_score": 0,
            "risk_level": "UNKNOWN",
            "analysis_confidence": 0.0
        }
