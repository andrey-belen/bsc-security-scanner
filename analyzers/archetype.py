"""
Token Archetype Classifier - Classify contracts into specific token types
to enable targeted security analysis
"""

import re
from typing import Dict, List, Optional, Set
from web3 import Web3
from web3.exceptions import ContractLogicError

from config import BSC_CONFIG, BSC_CONTRACTS, get_rpc_endpoint


class TokenArchetype:
    """Token archetype enumeration"""
    STANDARD_ERC20 = "standard_erc20"
    TAX_FEE_TOKEN = "tax_fee_token"
    WRAPPER_TOKEN = "wrapper_token"
    DEX_ROUTER = "dex_router"
    DEX_FACTORY = "dex_factory"
    PROXY_TOKEN = "proxy_token"
    DEFLATIONARY = "deflationary_token"
    REBASE_TOKEN = "rebase_token"
    NFT_TOKEN = "nft_token"
    UNKNOWN = "unknown"


class ArchetypeClassifier:
    """Classify token contracts into specific archetypes"""

    def __init__(self):
        self.w3 = Web3(Web3.HTTPProvider(get_rpc_endpoint()))

        # Standard ERC-20 function signatures
        self.standard_erc20_functions = {
            "0x70a08231",  # balanceOf(address)
            "0xa9059cbb",  # transfer(address,uint256)
            "0x23b872dd",  # transferFrom(address,address,uint256)
            "0x095ea7b3",  # approve(address,uint256)
            "0xdd62ed3e",  # allowance(address,address)
            "0x18160ddd",  # totalSupply()
        }

        # Tax/fee token indicators
        self.tax_fee_indicators = {
            "functions": [
                "setTaxFee", "setBuyFee", "setSellFee", "setMarketingFee",
                "setReflectionFee", "setLiquidityFee", "setFeeRate",
                "updateFees", "changeFee", "setFeePercent"
            ],
            "variables": [
                "_taxFee", "_marketingFee", "_liquidityFee", "buyFee",
                "sellFee", "reflectionFee", "feeRate", "taxPercent"
            ]
        }

        # Wrapper token indicators (WETH/WBNB style)
        self.wrapper_indicators = {
            "functions": ["deposit", "withdraw", "fallback"],
            "events": ["Deposit", "Withdrawal"],
            "patterns": ["wrap", "unwrap"]
        }

        # DEX router indicators
        self.dex_router_indicators = {
            "functions": [
                "swapExactTokensForTokens", "swapTokensForExactTokens",
                "swapExactETHForTokens", "swapTokensForExactETH",
                "addLiquidity", "removeLiquidity", "getAmountOut",
                "getAmountIn", "getAmountsOut", "getAmountsIn"
            ]
        }

        # DEX factory indicators
        self.dex_factory_indicators = {
            "functions": [
                "createPair", "getPair", "allPairs", "allPairsLength",
                "feeTo", "feeToSetter", "setFeeTo", "setFeeToSetter"
            ]
        }

        # Proxy pattern indicators
        self.proxy_indicators = {
            "functions": ["implementation", "upgrade", "upgradeTo"],
            "patterns": ["delegate", "proxy", "fallback"],
            "bytecode_patterns": ["3d602d80600a3d3981f3363d3d373d3d3d363d73"]
        }

    def classify(self, address: str) -> Dict:
        """
        Classify token contract into archetype

        Args:
            address: Contract address to classify

        Returns:
            Classification results with confidence scores
        """
        try:
            bytecode = self.w3.eth.get_code(Web3.toChecksumAddress(address))

            # Extract function signatures from bytecode
            function_signatures = self._extract_function_signatures(bytecode)

            # Get contract source code if verified
            source_code = self._get_verified_source_code(address)

            # Perform classification analysis
            classification_scores = {}

            # Check each archetype
            classification_scores[TokenArchetype.STANDARD_ERC20] = self._score_standard_erc20(
                function_signatures, source_code, bytecode
            )

            classification_scores[TokenArchetype.TAX_FEE_TOKEN] = self._score_tax_fee_token(
                function_signatures, source_code, bytecode
            )

            classification_scores[TokenArchetype.WRAPPER_TOKEN] = self._score_wrapper_token(
                function_signatures, source_code, bytecode
            )

            classification_scores[TokenArchetype.DEX_ROUTER] = self._score_dex_router(
                function_signatures, source_code, bytecode
            )

            classification_scores[TokenArchetype.DEX_FACTORY] = self._score_dex_factory(
                function_signatures, source_code, bytecode
            )

            classification_scores[TokenArchetype.PROXY_TOKEN] = self._score_proxy_token(
                function_signatures, source_code, bytecode
            )

            # Determine primary archetype
            primary_archetype = max(classification_scores.items(), key=lambda x: x[1])
            confidence = primary_archetype[1]
            archetype = primary_archetype[0] if confidence > 0.3 else TokenArchetype.UNKNOWN

            # Determine secondary characteristics
            secondary_traits = []
            for arch_type, score in classification_scores.items():
                if arch_type != archetype and score > 0.2:
                    secondary_traits.append(arch_type)

            return {
                "primary_archetype": archetype,
                "confidence": confidence,
                "secondary_traits": secondary_traits,
                "scores": classification_scores,
                "function_signatures": list(function_signatures),
                "has_source_code": source_code is not None,
                "bytecode_size": len(bytecode)
            }

        except Exception as e:
            return {
                "primary_archetype": TokenArchetype.UNKNOWN,
                "confidence": 0.0,
                "secondary_traits": [],
                "scores": {},
                "error": str(e)
            }

    def _extract_function_signatures(self, bytecode: bytes) -> Set[str]:
        """Extract 4-byte function signatures from bytecode"""
        signatures = set()

        try:
            bytecode_hex = bytecode.hex()

            # Look for PUSH4 instructions (0x63) followed by 4-byte signatures
            for i in range(0, len(bytecode_hex) - 8, 2):
                if bytecode_hex[i:i+2] == "63":  # PUSH4 opcode
                    signature = bytecode_hex[i+2:i+10]
                    signatures.add("0x" + signature)

        except Exception:
            pass

        return signatures

    def _get_verified_source_code(self, address: str) -> Optional[str]:
        """Get verified source code from BSCScan (placeholder)"""
        # This would integrate with BSCScan API to get verified source code
        # For now, return None as placeholder
        return None

    def _score_standard_erc20(self, signatures: Set[str], source: Optional[str], bytecode: bytes) -> float:
        """Score likelihood of being a standard ERC-20 token"""
        score = 0.0

        # Check for standard ERC-20 functions
        erc20_matches = len(self.standard_erc20_functions.intersection(signatures))
        if erc20_matches >= 5:  # Has most standard functions
            score += 0.6
        elif erc20_matches >= 3:
            score += 0.3

        # Check for absence of complex mechanisms
        complex_indicators = 0

        # Look for tax/fee indicators in signatures
        tax_patterns = ["fee", "tax", "marketing", "reflection"]
        for sig in signatures:
            if any(pattern in sig.lower() for pattern in tax_patterns):
                complex_indicators += 1

        if complex_indicators == 0:
            score += 0.3
        elif complex_indicators <= 2:
            score += 0.1

        # Check bytecode complexity (simpler = more likely standard)
        bytecode_complexity = len(bytecode) / 1000  # Normalize by 1KB
        if bytecode_complexity < 10:  # Less than 10KB
            score += 0.1

        return min(score, 1.0)

    def _score_tax_fee_token(self, signatures: Set[str], source: Optional[str], bytecode: bytes) -> float:
        """Score likelihood of being a tax/fee token"""
        score = 0.0

        # Check for tax/fee function signatures
        tax_function_matches = 0
        for sig in signatures:
            sig_lower = sig.lower()
            for func in self.tax_fee_indicators["functions"]:
                if func.lower() in sig_lower:
                    tax_function_matches += 1
                    break

        if tax_function_matches >= 3:
            score += 0.7
        elif tax_function_matches >= 1:
            score += 0.4

        # Check source code for tax variables (if available)
        if source:
            tax_var_matches = 0
            source_lower = source.lower()
            for var in self.tax_fee_indicators["variables"]:
                if var.lower() in source_lower:
                    tax_var_matches += 1

            if tax_var_matches >= 2:
                score += 0.3

        # Check for reflection mechanism indicators
        reflection_indicators = ["reflect", "rfi", "redistribution"]
        for indicator in reflection_indicators:
            if any(indicator in sig.lower() for sig in signatures):
                score += 0.2
                break

        return min(score, 1.0)

    def _score_wrapper_token(self, signatures: Set[str], source: Optional[str], bytecode: bytes) -> float:
        """Score likelihood of being a wrapper token (WETH/WBNB style)"""
        score = 0.0

        # Check for wrapper-specific functions
        wrapper_functions = ["deposit", "withdraw"]
        wrapper_matches = 0

        for sig in signatures:
            sig_lower = sig.lower()
            for func in wrapper_functions:
                if func in sig_lower:
                    wrapper_matches += 1
                    break

        if wrapper_matches >= 2:
            score += 0.8
        elif wrapper_matches >= 1:
            score += 0.4

        # Check for fallback function (typical in wrappers)
        if any("fallback" in sig.lower() for sig in signatures):
            score += 0.3

        # Wrapper tokens typically have simpler bytecode
        if len(bytecode) < 5000:  # Less than 5KB
            score += 0.2

        return min(score, 1.0)

    def _score_dex_router(self, signatures: Set[str], source: Optional[str], bytecode: bytes) -> float:
        """Score likelihood of being a DEX router"""
        score = 0.0

        # Check for DEX router functions
        router_matches = 0
        for sig in signatures:
            sig_lower = sig.lower()
            for func in self.dex_router_indicators["functions"]:
                if func.lower() in sig_lower:
                    router_matches += 1
                    break

        if router_matches >= 5:
            score += 0.9
        elif router_matches >= 3:
            score += 0.6
        elif router_matches >= 1:
            score += 0.3

        # DEX routers typically have large bytecode
        if len(bytecode) > 20000:  # Greater than 20KB
            score += 0.1

        return min(score, 1.0)

    def _score_dex_factory(self, signatures: Set[str], source: Optional[str], bytecode: bytes) -> float:
        """Score likelihood of being a DEX factory"""
        score = 0.0

        # Check for DEX factory functions
        factory_matches = 0
        for sig in signatures:
            sig_lower = sig.lower()
            for func in self.dex_factory_indicators["functions"]:
                if func.lower() in sig_lower:
                    factory_matches += 1
                    break

        if factory_matches >= 4:
            score += 0.9
        elif factory_matches >= 2:
            score += 0.6
        elif factory_matches >= 1:
            score += 0.3

        return min(score, 1.0)

    def _score_proxy_token(self, signatures: Set[str], source: Optional[str], bytecode: bytes) -> float:
        """Score likelihood of being a proxy token"""
        score = 0.0

        # Check for proxy function signatures
        proxy_matches = 0
        for sig in signatures:
            sig_lower = sig.lower()
            for func in self.proxy_indicators["functions"]:
                if func.lower() in sig_lower:
                    proxy_matches += 1
                    break

        if proxy_matches >= 2:
            score += 0.6
        elif proxy_matches >= 1:
            score += 0.3

        # Check for proxy bytecode patterns
        bytecode_hex = bytecode.hex()
        for pattern in self.proxy_indicators["bytecode_patterns"]:
            if pattern in bytecode_hex:
                score += 0.5
                break

        # Proxy contracts typically have very small bytecode
        if len(bytecode) < 1000:  # Less than 1KB
            score += 0.3

        return min(score, 1.0)

    def get_archetype_specific_risks(self, archetype: str) -> List[str]:
        """Get archetype-specific security risks to focus on"""
        risk_mapping = {
            TokenArchetype.STANDARD_ERC20: [
                "ownership_centralization",
                "minting_functions",
                "pause_functionality"
            ],
            TokenArchetype.TAX_FEE_TOKEN: [
                "high_taxes",
                "tax_manipulation",
                "blacklist_functions",
                "honeypot_mechanisms",
                "reflection_exploits"
            ],
            TokenArchetype.WRAPPER_TOKEN: [
                "deposit_withdraw_bugs",
                "balance_tracking_issues",
                "reentrancy_attacks"
            ],
            TokenArchetype.DEX_ROUTER: [
                "slippage_manipulation",
                "price_oracle_attacks",
                "liquidity_drainage"
            ],
            TokenArchetype.DEX_FACTORY: [
                "pair_creation_exploits",
                "fee_manipulation",
                "governance_attacks"
            ],
            TokenArchetype.PROXY_TOKEN: [
                "upgrade_risks",
                "implementation_bugs",
                "admin_key_compromise"
            ]
        }

        return risk_mapping.get(archetype, [
            "ownership_centralization",
            "unknown_mechanisms"
        ])