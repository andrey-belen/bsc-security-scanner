"""
Ownership Checker - Analyze contract ownership patterns
"""

from typing import Dict, List, Optional, Callable
from web3 import Web3


class OwnershipChecker:
    """Analyze contract ownership status and patterns"""

    def __init__(self, web3: Web3, add_finding: Callable, positive_factors: List):
        """
        Initialize ownership checker

        Args:
            web3: Web3 instance for blockchain interactions
            add_finding: Callback function to add findings
            positive_factors: List to track positive risk reduction factors
        """
        self.w3 = web3
        self.add_finding = add_finding
        self.positive_factors = positive_factors

    def check_ownership(self, address: str, abi: Optional[list]) -> Dict:
        """
        Check contract ownership status with enhanced verification

        Args:
            address: Contract address to check
            abi: Contract ABI (optional)

        Returns:
            Dictionary with owner info: {owner, is_renounced, owner_type}
        """
        owner_info = {"owner": None, "is_renounced": False, "owner_type": "unknown"}

        try:
            # Try standard owner() function
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
                self.add_finding(
                    "info",
                    "Ownership Renounced",
                    "Contract ownership has been renounced (owner set to zero address). Contract cannot be modified.",
                    "ownership"
                )
                # Positive factor: renounced ownership reduces risk
                self.positive_factors.append(15)
            else:
                # Check if owner is a contract (multisig) or EOA
                owner_code = self.w3.eth.get_code(owner)
                if owner_code and owner_code != b'' and owner_code != b'0x':
                    owner_info["owner_type"] = "contract"
                    self.add_finding(
                        "info",
                        "Contract-Owned (Multisig/DAO)",
                        f"Owner is a contract address (likely multisig or DAO): {owner[:10]}...{owner[-8:]}. Lower centralization risk.",
                        "ownership"
                    )
                    # Positive factor: multisig ownership reduces risk
                    self.positive_factors.append(10)
                else:
                    owner_info["owner_type"] = "EOA"
                    self.add_finding(
                        "medium",
                        "EOA Owner (High Risk)",
                        f"Owner is an externally owned account (EOA): {owner[:10]}...{owner[-8:]}. Single wallet controls all privileges. HIGH centralization risk.",
                        "ownership"
                    )

        except Exception:
            # No owner() function or error
            self.add_finding(
                "info",
                "No Owner Function",
                "Contract does not implement standard owner() function. May not be ownable.",
                "ownership"
            )

        return owner_info
