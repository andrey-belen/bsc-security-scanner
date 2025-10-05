"""
Token Classifier - Identify token types and known contracts
"""

from typing import Dict, Optional, Callable, List
from web3 import Web3


class TokenClassifier:
    """Classify tokens and identify known contracts"""

    def __init__(self, web3: Web3, add_finding: Callable, positive_factors: List):
        """
        Initialize token classifier

        Args:
            web3: Web3 instance for blockchain interactions
            add_finding: Callback function to add findings
            positive_factors: List to track positive risk reduction factors
        """
        self.w3 = web3
        self.add_finding = add_finding
        self.positive_factors = positive_factors
        self.is_stablecoin = False
        self.is_known_infrastructure = False

    def detect_token_type(self, address: str, token_info: Dict):
        """
        Detect if token is a known stablecoin or known infrastructure

        Args:
            address: Contract address
            token_info: Token metadata (name, symbol, etc.)
        """
        address_lower = address.lower()

        # Known infrastructure contracts (Router, Factory, WBNB) - audited and expected to have privileged functions
        known_infrastructure = {
            "0x10ed43c718714eb63d5aa57b78b54704e256024e": "PancakeSwap Router V2",
            "0xca143ce32fe78f1f7019d7d551a6402fc5350c73": "PancakeSwap Factory V2",
            "0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c": "Wrapped BNB (WBNB)",
            "0x05ff2b0db69458a0750badebc4f9e13add608c7f": "PancakeSwap Router V1",
        }

        # Check if this is known infrastructure first
        if address_lower in known_infrastructure:
            self.is_known_infrastructure = True
            infra_name = known_infrastructure[address_lower]
            self.add_finding(
                "info",
                f"Known Infrastructure: {infra_name}",
                f"This is a recognized DeFi infrastructure contract. Centralized functions are expected and audited.",
                "token_type"
            )
            # Major positive factor for known audited infrastructure
            self.positive_factors.append(30)
            return

        # Known stablecoin addresses on BSC
        known_stablecoins = {
            "0xe9e7cea3dedca5984780bafc599bd69add087d56": "BUSD",  # Binance USD
            "0x55d398326f99059ff775485246999027b3197955": "USDT",  # Tether USD
            "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d": "USDC",  # USD Coin
            "0x1af3f329e8be154074d8769d1ffa4ee058b1dbc3": "DAI",   # Dai Stablecoin
        }

        # Check by address
        if address_lower in known_stablecoins:
            self.is_stablecoin = True
            stablecoin_name = known_stablecoins[address_lower]
            self.add_finding(
                "info",
                f"Known Stablecoin: {stablecoin_name}",
                f"This is a recognized stablecoin. Centralized controls (mint, burn, owner) are expected for regulatory compliance.",
                "token_type"
            )
            return

        # Check by symbol/name
        if token_info:
            symbol = token_info.get("symbol", "").upper()
            name = token_info.get("name", "").upper()

            # Stablecoin indicators
            stablecoin_indicators = ["USD", "USDT", "USDC", "BUSD", "DAI", "TUSD", "USDD"]
            for indicator in stablecoin_indicators:
                if indicator in symbol or indicator in name:
                    self.is_stablecoin = True
                    self.add_finding(
                        "info",
                        "Likely Stablecoin",
                        f"Token appears to be a stablecoin based on name/symbol. Centralized features may be expected.",
                        "token_type"
                    )
                    return

    def get_token_info(self, address: str, abi: Optional[list]) -> Dict:
        """
        Get basic ERC-20 token information

        Args:
            address: Contract address
            abi: Contract ABI (optional)

        Returns:
            Dictionary with token information
        """
        token_info = {}

        try:
            # Use ABI if available, otherwise use standard ERC-20 ABI
            if not abi:
                abi = [
                    {"constant": True, "inputs": [], "name": "name", "outputs": [{"name": "", "type": "string"}], "type": "function"},
                    {"constant": True, "inputs": [], "name": "symbol", "outputs": [{"name": "", "type": "string"}], "type": "function"},
                    {"constant": True, "inputs": [], "name": "decimals", "outputs": [{"name": "", "type": "uint8"}], "type": "function"},
                    {"constant": True, "inputs": [], "name": "totalSupply", "outputs": [{"name": "", "type": "uint256"}], "type": "function"}
                ]

            contract = self.w3.eth.contract(address=address, abi=abi)

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
