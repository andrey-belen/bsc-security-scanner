"""
Function Analyzer - Analyze contract functions for dangerous patterns and privileges
"""

from typing import Dict, List, Optional, Callable
from web3 import Web3


class FunctionAnalyzer:
    """Analyze contract functions for dangerous patterns and privileges"""

    def __init__(self, web3: Web3, add_finding: Callable):
        """
        Initialize function analyzer

        Args:
            web3: Web3 instance for blockchain interactions
            add_finding: Callback function to add findings
        """
        self.w3 = web3
        self.add_finding = add_finding

    def analyze_functions(self, address: str, source_code: Optional[str], abi: Optional[list]) -> Dict:
        """
        Analyze contract functions for dangerous patterns and privileges

        Args:
            address: Contract address
            source_code: Contract source code (optional)
            abi: Contract ABI (optional)

        Returns:
            Dictionary with risks analysis
        """
        risks = {}
        dangerous_found = []
        privilege_functions = []
        access_control = {"type": "unknown", "functions": []}

        if abi:
            # Analyze each function in ABI
            for item in abi:
                if item.get("type") == "function":
                    name = item.get("name", "")
                    name_lower = name.lower()
                    state_mutability = item.get("stateMutability", "")

                    # Detect privilege functions
                    privilege_keywords = ["mint", "burn", "pause", "unpause", "blacklist", "transferownership",
                                        "upgradeto", "setfee", "settax", "ban", "grantRole", "revokeRole"]

                    for keyword in privilege_keywords:
                        if keyword in name_lower:
                            privilege_functions.append(name)
                            break

                    # Detect access control patterns
                    if name_lower in ["onlyowner", "hasrole", "grantrole", "revokerole"]:
                        access_control["functions"].append(name)

                    # Specific dangerous function checks
                    if "mint" in name_lower and "mint" not in dangerous_found:
                        dangerous_found.append("mint")

                    if ("pause" in name_lower or "unpause" in name_lower) and "pause" not in dangerous_found:
                        dangerous_found.append("pause")

                    if ("blacklist" in name_lower or "ban" in name_lower) and "blacklist" not in dangerous_found:
                        dangerous_found.append("blacklist")

                    if ("setfee" in name_lower or "settax" in name_lower) and "fee_manipulation" not in dangerous_found:
                        dangerous_found.append("fee_manipulation")

                    # Critical: delegatecall and selfdestruct
                    if "delegatecall" in name_lower:
                        dangerous_found.append("delegatecall")
                        self.add_finding(
                            "critical",
                            "Delegatecall Function",
                            f"Function '{name}' uses delegatecall. This can execute arbitrary code and is extremely dangerous.",
                            "dangerous_function"
                        )

                    if "selfdestruct" in name_lower or "destroy" in name_lower:
                        dangerous_found.append("selfdestruct")
                        self.add_finding(
                            "critical",
                            "Self-Destruct Function",
                            f"Function '{name}' can destroy the contract. All funds could be lost permanently.",
                            "dangerous_function"
                        )

                    # Proxy upgrade detection
                    if "upgradeto" in name_lower:
                        dangerous_found.append("upgradeable")
                        self.add_finding(
                            "high",
                            "Upgradeable Contract",
                            f"Function '{name}' allows contract upgrade. Implementation can be changed at any time.",
                            "dangerous_function"
                        )

            # Determine access control type
            if any("grantrole" in f.lower() or "hasrole" in f.lower() for f in access_control["functions"]):
                access_control["type"] = "role_based"
                self.add_finding(
                    "info",
                    "Role-Based Access Control",
                    f"Contract uses role-based permissions. {len(privilege_functions)} privileged functions detected.",
                    "access_control"
                )
            elif privilege_functions:
                access_control["type"] = "owner_based"

            # Report on privilege functions
            if len(privilege_functions) > 5:
                self.add_finding(
                    "medium",
                    "Many Privileged Functions",
                    f"Contract has {len(privilege_functions)} privileged functions. High centralization risk.",
                    "access_control"
                )

        else:
            # Fallback: Check bytecode for function selectors
            dangerous_selectors = {
                "0x40c10f19": "mint",
                "0x8456cb59": "pause",
                "0x3f4ba83a": "unpause",
                "0xf2fde38b": "transferOwnership"
            }

            code = self.w3.eth.get_code(address).hex()

            for selector, name in dangerous_selectors.items():
                if selector[2:] in code:  # Remove 0x prefix
                    if name not in dangerous_found:
                        dangerous_found.append(name)

        # Add findings for dangerous functions
        if "mint" in dangerous_found:
            self.add_finding(
                "high",
                "Mint Function Detected",
                "Contract has a mint() function. Owner may be able to create unlimited tokens, diluting holder value.",
                "dangerous_function"
            )

        if "pause" in dangerous_found:
            self.add_finding(
                "medium",
                "Pause Functionality",
                "Contract can be paused, potentially freezing all transfers. Ensure this is expected behavior.",
                "dangerous_function"
            )

        if "blacklist" in dangerous_found:
            self.add_finding(
                "high",
                "Blacklist Function Found",
                "Contract contains blacklist functionality. Owner can prevent specific addresses from trading.",
                "dangerous_function"
            )

        if "fee_manipulation" in dangerous_found:
            self.add_finding(
                "medium",
                "Fee Manipulation Functions",
                "Contract allows owner to modify fees/taxes. Verify fee limits are in place.",
                "dangerous_function"
            )

        risks["dangerous_functions"] = dangerous_found
        risks["privilege_functions"] = privilege_functions
        risks["access_control"] = access_control
        return risks
