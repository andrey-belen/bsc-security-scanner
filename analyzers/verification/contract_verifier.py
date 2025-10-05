"""
Contract Verifier - Handle contract verification via Etherscan API
"""

import requests
import os
from typing import Dict, List, Optional, Tuple, Callable

from config import BSC_CONFIG


class ContractVerifier:
    """
    Handles contract verification using Etherscan API for BSCScan integration
    Note: BSCScan now uses Etherscan infrastructure, so ETHERSCAN_API_KEY works
    """

    def __init__(self, add_finding: Callable, positive_factors: List):
        """
        Initialize contract verifier

        Args:
            add_finding: Callback function to add findings
            positive_factors: List to track positive risk reduction factors
        """
        self.bscscan_api = BSC_CONFIG["explorer_api"]
        # BSCScan now uses Etherscan API infrastructure - use ETHERSCAN_API_KEY
        self.api_key = os.getenv('ETHERSCAN_API_KEY') or os.getenv('BSCSCAN_API_KEY', '')
        self.add_finding = add_finding
        self.positive_factors = positive_factors
        self.has_safemath = False

    def check_verification(self, address: str) -> Tuple[bool, Optional[str], Optional[list], Optional[dict]]:
        """
        Check contract verification using Etherscan API

        Args:
            address: Contract address to verify

        Returns:
            tuple: (is_verified, source_code, abi, metadata)
        """
        if not self.api_key:
            self.add_finding(
                "low",
                "No API Key",
                "ETHERSCAN_API_KEY not set. Get free BSCScan API key from bscscan.com/myapikey. Verification check unavailable.",
                "verification"
            )
            return False, None, None, None

        try:
            # Use Etherscan V2 multi-chain API to get source code
            params = {
                "chainid": BSC_CONFIG["chain_id"],  # 56 for BSC
                "module": "contract",
                "action": "getsourcecode",
                "address": address,
                "apikey": self.api_key
            }

            response = requests.get(self.bscscan_api, params=params, timeout=10)
            response.raise_for_status()
            data = response.json()

            if data["status"] == "1" and data["result"]:
                result = data["result"][0]
                source_code = result.get("SourceCode", "")
                abi = result.get("ABI", "")

                # Extract metadata
                metadata = {
                    "compiler_version": result.get("CompilerVersion", ""),
                    "optimization_used": result.get("OptimizationUsed", ""),
                    "runs": result.get("Runs", ""),
                    "contract_name": result.get("ContractName", ""),
                    "evm_version": result.get("EVMVersion", ""),
                    "library": result.get("Library", ""),
                    "license_type": result.get("LicenseType", ""),
                    "proxy": result.get("Proxy", "0"),
                    "implementation": result.get("Implementation", "")
                }

                # Contract is verified if source code exists
                if source_code and source_code != "":
                    # Analyze compiler version for security issues (pass source for SafeMath detection)
                    self._analyze_compiler_version(metadata["compiler_version"], source_code)

                    # Check optimizer settings
                    if metadata["optimization_used"] == "0":
                        self.add_finding(
                            "low",
                            "Optimizer Disabled",
                            "Contract compiled without optimization. May have higher gas costs but no security impact.",
                            "compiler"
                        )

                    # Check if proxy contract
                    if metadata["proxy"] == "1":
                        impl = metadata['implementation']
                        impl_display = f"{impl[:10]}...{impl[-8:]}" if impl else "Unknown"
                        self.add_finding(
                            "medium",
                            "Proxy Contract Detected",
                            f"This is an upgradeable proxy contract. Implementation: {impl_display}",
                            "proxy"
                        )

                    self.add_finding(
                        "info",
                        "Contract Verified",
                        f"Contract source code is verified on BSCScan. Compiler: {metadata['compiler_version']}, License: {metadata['license_type']}",
                        "verification"
                    )

                    # Positive factor: verified contract reduces risk
                    self.positive_factors.append(5)

                    # Additional positive factor if optimizer enabled
                    if metadata["optimization_used"] == "1":
                        self.positive_factors.append(3)

                    # Parse ABI if available
                    try:
                        import json
                        abi_parsed = json.loads(abi) if abi and abi != "Contract source code not verified" else None
                    except:
                        abi_parsed = None

                    return True, source_code, abi_parsed, metadata
                else:
                    self.add_finding(
                        "medium",
                        "Contract Not Verified",
                        "Contract source code is not verified on BSCScan. This increases risk as code cannot be audited.",
                        "verification"
                    )
                    return False, None, None, None
            else:
                # API returned error or no result
                self.add_finding(
                    "medium",
                    "Verification Check Failed",
                    f"Unable to verify contract status via API: {data.get('message', 'Unknown error')}",
                    "verification"
                )
                return False, None, None, None

        except requests.exceptions.Timeout:
            self.add_finding(
                "low",
                "Verification Check Timeout",
                "BSCScan API request timed out. Continuing with bytecode analysis.",
                "verification"
            )
            return False, None, None, None
        except Exception as e:
            self.add_finding(
                "low",
                "Verification Check Error",
                f"Error checking verification: {str(e)}",
                "verification"
            )
            return False, None, None, None

    def _analyze_compiler_version(self, compiler_version: str, source_code: Optional[str] = None):
        """Analyze compiler version for security vulnerabilities with SafeMath detection"""
        if not compiler_version:
            return

        try:
            # Extract version number (e.g., "v0.5.16+commit.9c3226ce" -> "0.5.16")
            import re
            match = re.search(r'v?(\d+\.\d+\.\d+)', compiler_version)
            if match:
                version = match.group(1)
                major, minor, patch = map(int, version.split('.'))

                # Check for SafeMath in source code
                if source_code:
                    source_lower = source_code.lower()
                    self.has_safemath = "safemath" in source_lower and "using safemath" in source_lower

                # Flag Solidity versions before 0.8.0 (no overflow/underflow protection)
                if major == 0 and minor < 8:
                    # Versions 0.5.x and 0.6.x/0.7.x - flag based on SafeMath usage
                    if self.has_safemath:
                        # SafeMath mitigates the overflow risk
                        self.add_finding(
                            "low",
                            "Old Compiler with SafeMath",
                            f"Contract compiled with Solidity {version} (pre-0.8.0) but uses SafeMath library for overflow protection. Risk mitigated.",
                            "compiler"
                        )
                    else:
                        # No SafeMath - higher risk
                        if minor < 6:
                            # Very old versions without SafeMath
                            self.add_finding(
                                "high",
                                "Critically Outdated Compiler",
                                f"Contract compiled with very old Solidity {version} without SafeMath. Multiple known vulnerabilities.",
                                "compiler"
                            )
                        else:
                            # 0.6.x/0.7.x without SafeMath
                            self.add_finding(
                                "medium",
                                "Old Compiler Without SafeMath",
                                f"Contract compiled with Solidity {version} without SafeMath. Vulnerable to overflow/underflow attacks.",
                                "compiler"
                            )

        except Exception as e:
            print(f"Error analyzing compiler version: {e}")
