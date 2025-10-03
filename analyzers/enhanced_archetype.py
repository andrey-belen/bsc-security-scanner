"""
Enhanced Token Archetype Classifier - Precise detection to avoid misclassification
of stablecoins and wrappers as honeypots
"""

import re
import json
import ast
from typing import Dict, List, Optional, Set, Tuple
from web3 import Web3
from web3.exceptions import ContractLogicError
from dataclasses import dataclass

from config import BSC_CONFIG, BSC_CONTRACTS, get_rpc_endpoint
from .source_analyzer import SourceCodeAnalyzer


@dataclass
class Finding:
    """Security finding with confidence and evidence"""
    id: str
    severity: str  # critical, high, medium, low, info
    type: str
    description: str
    evidence: List[str]
    confidence: float  # 0.0 - 1.0


class TokenArchetype:
    """Enhanced token archetype enumeration"""
    STABLECOIN = "stablecoin"
    WRAPPER_TOKEN = "wrapper_token"
    TAX_HONEYPOT_TOKEN = "tax_honeypot_token"
    STANDARD_ERC20 = "standard_erc20"
    DEX_ROUTER = "dex_router"
    DEX_FACTORY = "dex_factory"
    GOVERNANCE_TOKEN = "governance_token"
    UNKNOWN = "unknown"


class EnhancedArchetypeClassifier:
    """Enhanced classifier with precise detection patterns"""

    def __init__(self):
        self.w3 = Web3(Web3.HTTPProvider(get_rpc_endpoint()))
        self.source_analyzer = SourceCodeAnalyzer()

        # Wrapper token function selectors
        self.wrapper_selectors = {
            "0xd0e30db0",  # deposit()
            "0x2e1a7d4d",  # withdraw(uint256)
            "0x3ccfd60b",  # withdraw()
        }

        # Wrapper token patterns
        self.wrapper_patterns = {
            "function_names": ["deposit", "withdraw", "fallback", "receive"],
            "payable_deposit": r"function\s+deposit\s*\(\s*\)\s+payable",
            "withdraw_native": r"function\s+withdraw\s*\(\s*uint256.*?\)\s+.*?msg\.sender\.transfer",
        }

        # Stablecoin patterns
        self.stablecoin_patterns = {
            "mint_burn": ["mint", "burn", "burnFrom"],
            "centralized_controls": ["pause", "unpause", "blacklist", "addToBlacklist", "freeze"],
            "regulatory": ["seize", "freeze", "unfreeze", "wipeFrozenAddress"],
            "symbols": ["USDT", "USDC", "BUSD", "DAI", "TUSD", "FRAX"],
        }

        # Tax/Honeypot detection patterns
        self.tax_patterns = {
            "transfer_override": r"function\s+_transfer\s*\([^)]+\)\s+.*?override",
            "fee_calculation": r"uint256\s+\w*[Ff]ee\w*\s*=\s*amount\s*\*\s*\w+\s*\/\s*\d+",
            "fee_subtraction": r"amount\s*=\s*amount\s*-\s*\w*[Ff]ee\w*",
            "marketing_wallet": r"_transfer\s*\(\s*\w+,\s*\w*[Mm]arketing\w*,\s*\w*[Ff]ee\w*\)",
            "reflection_logic": r"_reflectFee\s*\(\s*\w*[Ff]ee\w*\s*\)",
        }

    def classify_archetype(self, address: str, contract_code: Optional[str] = None, abi: Optional[List] = None) -> Dict:
        """
        Primary classification function with high accuracy

        Args:
            address: Contract address
            contract_code: Source code if available
            abi: Contract ABI if available

        Returns:
            Classification result with confidence
        """
        try:
            # Get contract data
            if not contract_code:
                contract_code = self.source_analyzer.get_verified_source_code(address)

            bytecode = self.w3.eth.get_code(Web3.toChecksumAddress(address))
            function_selectors = self._extract_function_selectors(bytecode)

            # Run classification in order of specificity
            classification_results = []

            # 1. Check for wrapper tokens first (highest specificity)
            wrapper_result = self._detect_wrapper_token(contract_code, function_selectors, bytecode)
            classification_results.append(("wrapper", wrapper_result))

            # 2. Check for stablecoins
            stablecoin_result = self._detect_stablecoin(contract_code, function_selectors, address)
            classification_results.append(("stablecoin", stablecoin_result))

            # 3. Check for tax/honeypot tokens
            tax_result = self._detect_tax_honeypot_token(contract_code, function_selectors)
            classification_results.append(("tax_honeypot", tax_result))

            # 4. Check for DEX components
            dex_result = self._detect_dex_component(contract_code, function_selectors)
            classification_results.append(("dex", dex_result))

            # 5. Default to standard ERC20
            standard_result = self._detect_standard_erc20(function_selectors)
            classification_results.append(("standard", standard_result))

            # Determine primary archetype
            primary_archetype, confidence = self._select_primary_archetype(classification_results)

            return {
                "archetype": primary_archetype,
                "confidence": confidence,
                "detection_method": "source_code" if contract_code else "bytecode",
                "all_scores": {name: score for name, score in classification_results},
                "function_selectors": list(function_selectors),
                "bytecode_size": len(bytecode)
            }

        except Exception as e:
            return {
                "archetype": TokenArchetype.UNKNOWN,
                "confidence": 0.0,
                "error": str(e),
                "detection_method": "failed"
            }

    def _detect_wrapper_token(self, source_code: Optional[str], selectors: Set[str], bytecode: bytes) -> float:
        """Detect wrapper tokens (WBNB, WETH style)"""
        confidence = 0.0

        # Check for wrapper function selectors (highest confidence)
        wrapper_selector_matches = len(self.wrapper_selectors.intersection(selectors))
        if wrapper_selector_matches >= 2:
            confidence += 0.8
        elif wrapper_selector_matches >= 1:
            confidence += 0.4

        if source_code:
            # Check for payable deposit function
            if re.search(self.wrapper_patterns["payable_deposit"], source_code, re.IGNORECASE):
                confidence += 0.3

            # Check for withdraw with native transfer
            if re.search(self.wrapper_patterns["withdraw_native"], source_code, re.IGNORECASE):
                confidence += 0.3

            # Check function names
            function_matches = sum(1 for name in self.wrapper_patterns["function_names"]
                                 if name in source_code.lower())
            if function_matches >= 3:
                confidence += 0.2

            # Wrappers typically have minimal additional logic
            if len(source_code.split('\n')) < 200:  # Simple contracts
                confidence += 0.1

        # Bytecode size check (wrappers are usually small)
        if len(bytecode) < 3000:  # Less than 3KB
            confidence += 0.1

        return min(confidence, 1.0)

    def _detect_stablecoin(self, source_code: Optional[str], selectors: Set[str], address: str) -> float:
        """Detect stablecoins (USDT, BUSD, etc.)"""
        confidence = 0.0

        # Check if it's a known stablecoin address
        known_stablecoins = {
            "0xe9e7cea3dedca5984780bafc599bd69add087d56": "BUSD",
            "0x55d398326f99059ff775485246999027b3197955": "USDT",
            "0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d": "USDC",
        }

        if address.lower() in known_stablecoins:
            return 0.95

        if source_code:
            # Check for stablecoin symbols
            symbol_matches = sum(1 for symbol in self.stablecoin_patterns["symbols"]
                               if symbol in source_code.upper())
            if symbol_matches > 0:
                confidence += 0.4

            # Check for centralized mint/burn controls
            mint_burn_matches = sum(1 for func in self.stablecoin_patterns["mint_burn"]
                                  if re.search(rf"function\s+{func}\s*\(", source_code, re.IGNORECASE))
            if mint_burn_matches >= 2:
                confidence += 0.3

            # Check for centralized controls (pause, blacklist)
            control_matches = sum(1 for func in self.stablecoin_patterns["centralized_controls"]
                                if re.search(rf"function\s+{func}", source_code, re.IGNORECASE))
            if control_matches >= 2:
                confidence += 0.3

            # Check for regulatory functions
            regulatory_matches = sum(1 for func in self.stablecoin_patterns["regulatory"]
                                   if re.search(rf"function\s+{func}", source_code, re.IGNORECASE))
            if regulatory_matches > 0:
                confidence += 0.2

            # Check for owner-only modifiers on critical functions
            if re.search(r"function\s+(mint|burn|pause)\s*\([^)]*\)\s+.*?onlyOwner", source_code, re.IGNORECASE):
                confidence += 0.2

        return min(confidence, 1.0)

    def _detect_tax_honeypot_token(self, source_code: Optional[str], selectors: Set[str]) -> float:
        """Detect tax/fee tokens and honeypots"""
        confidence = 0.0

        if source_code:
            # Look for _transfer override with fee logic
            if re.search(self.tax_patterns["transfer_override"], source_code, re.IGNORECASE):
                confidence += 0.3

                # Check for explicit fee calculation
                if re.search(self.tax_patterns["fee_calculation"], source_code, re.IGNORECASE):
                    confidence += 0.4

                # Check for fee subtraction
                if re.search(self.tax_patterns["fee_subtraction"], source_code, re.IGNORECASE):
                    confidence += 0.3

                # Check for marketing wallet transfers
                if re.search(self.tax_patterns["marketing_wallet"], source_code, re.IGNORECASE):
                    confidence += 0.2

                # Check for reflection logic
                if re.search(self.tax_patterns["reflection_logic"], source_code, re.IGNORECASE):
                    confidence += 0.2

            # Look for tax setter functions
            tax_setters = ["setTaxFee", "setBuyFee", "setSellFee", "setMarketingFee"]
            setter_matches = sum(1 for setter in tax_setters
                               if re.search(rf"function\s+{setter}", source_code, re.IGNORECASE))
            if setter_matches > 0:
                confidence += 0.3

        # Bytecode-based detection (lower confidence)
        else:
            # Look for complex control flow that might indicate tax logic
            # This is a simplified heuristic
            pass

        return min(confidence, 1.0)

    def _detect_dex_component(self, source_code: Optional[str], selectors: Set[str]) -> float:
        """Detect DEX routers/factories"""
        confidence = 0.0

        dex_functions = [
            "swapExactTokensForTokens", "addLiquidity", "removeLiquidity",
            "createPair", "getPair", "getAmountOut"
        ]

        if source_code:
            dex_matches = sum(1 for func in dex_functions
                            if re.search(rf"function\s+{func}", source_code, re.IGNORECASE))
            if dex_matches >= 3:
                confidence += 0.8
            elif dex_matches >= 1:
                confidence += 0.4

        return min(confidence, 1.0)

    def _detect_standard_erc20(self, selectors: Set[str]) -> float:
        """Detect standard ERC20 tokens"""
        standard_functions = {
            "0x70a08231",  # balanceOf
            "0xa9059cbb",  # transfer
            "0x23b872dd",  # transferFrom
            "0x095ea7b3",  # approve
            "0xdd62ed3e",  # allowance
            "0x18160ddd",  # totalSupply
        }

        matches = len(standard_functions.intersection(selectors))
        if matches >= 5:
            return 0.7
        elif matches >= 3:
            return 0.4
        else:
            return 0.1

    def _extract_function_selectors(self, bytecode: bytes) -> Set[str]:
        """Extract 4-byte function selectors from bytecode"""
        selectors = set()
        bytecode_hex = bytecode.hex()

        # Look for PUSH4 instructions (0x63) followed by 4-byte selectors
        for i in range(0, len(bytecode_hex) - 8, 2):
            if bytecode_hex[i:i+2] == "63":  # PUSH4
                selector = bytecode_hex[i+2:i+10]
                selectors.add("0x" + selector)

        return selectors

    def _select_primary_archetype(self, classification_results: List[Tuple[str, float]]) -> Tuple[str, float]:
        """Select the primary archetype based on confidence scores"""
        archetype_map = {
            "wrapper": TokenArchetype.WRAPPER_TOKEN,
            "stablecoin": TokenArchetype.STABLECOIN,
            "tax_honeypot": TokenArchetype.TAX_HONEYPOT_TOKEN,
            "dex": TokenArchetype.DEX_ROUTER,
            "standard": TokenArchetype.STANDARD_ERC20
        }

        # Sort by confidence, highest first
        sorted_results = sorted(classification_results, key=lambda x: x[1], reverse=True)

        # Return the highest confidence result if it's above threshold
        top_result = sorted_results[0]
        if top_result[1] >= 0.6:
            return archetype_map[top_result[0]], top_result[1]

        # If no clear winner, check for mixed signals
        high_confidence_results = [r for r in sorted_results if r[1] >= 0.4]
        if len(high_confidence_results) > 1:
            return TokenArchetype.UNKNOWN, 0.3

        # Default to standard ERC20 if low confidence across the board
        return TokenArchetype.STANDARD_ERC20, 0.4


def detect_tax_mechanism(source_code: str) -> Dict:
    """
    Detect tax mechanisms in source code
    Only run if archetype == TAX_HONEYPOT_TOKEN
    """
    findings = []

    if not source_code:
        return {"findings": findings, "confidence": 0.0}

    # Look for _transfer function with fee logic
    transfer_pattern = r"function\s+_transfer\s*\([^)]+\)\s+[^{]*\{([^}]+)\}"
    transfer_matches = re.finditer(transfer_pattern, source_code, re.IGNORECASE | re.DOTALL)

    for match in transfer_matches:
        transfer_body = match.group(1)

        # Check for fee calculation pattern
        fee_calc_pattern = r"uint256\s+(\w*[Ff]ee\w*)\s*=\s*amount\s*\*\s*(\w+)\s*\/\s*(\d+)"
        fee_match = re.search(fee_calc_pattern, transfer_body)

        if fee_match:
            fee_var = fee_match.group(1)
            tax_var = fee_match.group(2)
            divisor = fee_match.group(3)

            # Check for amount subtraction
            subtraction_pattern = rf"amount\s*=\s*amount\s*-\s*{fee_var}"
            if re.search(subtraction_pattern, transfer_body):

                # Check for fee transfer
                fee_transfer_pattern = rf"_transfer\s*\([^,]+,\s*\w+,\s*{fee_var}\)"
                if re.search(fee_transfer_pattern, transfer_body):

                    findings.append(Finding(
                        id="tax_mechanism_detected",
                        severity="high",
                        type="tax_mechanism",
                        description=f"Tax mechanism detected: {fee_var} = amount * {tax_var} / {divisor}",
                        evidence=[f"Fee calculation: {fee_match.group(0)}"],
                        confidence=0.9
                    ))

    # Look for tax setter functions
    setter_patterns = [
        r"function\s+(setTax\w*|set\w*Fee)\s*\([^)]*\)\s+.*?onlyOwner",
        r"function\s+(changeFee|updateFee)\s*\([^)]*\)\s+.*?onlyOwner"
    ]

    for pattern in setter_patterns:
        matches = re.finditer(pattern, source_code, re.IGNORECASE)
        for match in matches:
            findings.append(Finding(
                id="dynamic_tax_detected",
                severity="high",
                type="dynamic_tax",
                description=f"Dynamic tax function detected: {match.group(1)}",
                evidence=[match.group(0)],
                confidence=0.95
            ))

    confidence = 0.9 if findings else 0.1
    return {"findings": findings, "confidence": confidence}


def analyze_stablecoin_controls(source_code: str) -> Dict:
    """
    Analyze stablecoin centralized controls
    """
    findings = []

    if not source_code:
        return {"findings": findings, "confidence": 0.0}

    # Check for mint/burn functions
    mint_pattern = r"function\s+(mint|mintTo)\s*\([^)]*\)\s+.*?onlyOwner"
    burn_pattern = r"function\s+(burn|burnFrom)\s*\([^)]*\)"

    mint_matches = list(re.finditer(mint_pattern, source_code, re.IGNORECASE))
    burn_matches = list(re.finditer(burn_pattern, source_code, re.IGNORECASE))

    if mint_matches:
        findings.append(Finding(
            id="centralized_minting",
            severity="high",
            type="centralized_control",
            description="Owner can mint new tokens",
            evidence=[match.group(0) for match in mint_matches],
            confidence=0.95
        ))

    if burn_matches:
        findings.append(Finding(
            id="burn_capability",
            severity="medium",
            type="centralized_control",
            description="Contract can burn tokens",
            evidence=[match.group(0) for match in burn_matches],
            confidence=0.9
        ))

    # Check for pause functionality
    pause_pattern = r"function\s+(pause|unpause)\s*\([^)]*\)\s+.*?onlyOwner"
    pause_matches = list(re.finditer(pause_pattern, source_code, re.IGNORECASE))

    if pause_matches:
        findings.append(Finding(
            id="pause_capability",
            severity="high",
            type="centralized_control",
            description="Owner can pause all transfers",
            evidence=[match.group(0) for match in pause_matches],
            confidence=0.95
        ))

    # Check for blacklist functionality
    blacklist_pattern = r"function\s+(blacklist|addToBlacklist|freeze)\s*\([^)]*\)\s+.*?onlyOwner"
    blacklist_matches = list(re.finditer(blacklist_pattern, source_code, re.IGNORECASE))

    if blacklist_matches:
        findings.append(Finding(
            id="blacklist_capability",
            severity="high",
            type="centralized_control",
            description="Owner can blacklist addresses",
            evidence=[match.group(0) for match in blacklist_matches],
            confidence=0.95
        ))

    confidence = 0.9 if findings else 0.3
    return {"findings": findings, "confidence": confidence}


def generate_findings(archetype: str, detections: Dict) -> List[Finding]:
    """
    Generate appropriate findings based on archetype
    """
    findings = []

    if archetype == TokenArchetype.STABLECOIN:
        # For stablecoins, centralized controls are expected but should be reported
        stablecoin_findings = detections.get("stablecoin_controls", {}).get("findings", [])
        for finding in stablecoin_findings:
            # Adjust messaging for stablecoins
            finding.description = f"Stablecoin feature: {finding.description}"
            finding.severity = "medium"  # Lower severity for expected features
        findings.extend(stablecoin_findings)

    elif archetype == TokenArchetype.WRAPPER_TOKEN:
        # For wrappers, check for reentrancy issues
        wrapper_findings = detections.get("wrapper_analysis", {}).get("findings", [])
        findings.extend(wrapper_findings)

    elif archetype == TokenArchetype.TAX_HONEYPOT_TOKEN:
        # For tax tokens, report tax mechanisms
        tax_findings = detections.get("tax_mechanism", {}).get("findings", [])
        honeypot_findings = detections.get("honeypot_simulation", {}).get("findings", [])
        findings.extend(tax_findings + honeypot_findings)

    elif archetype == TokenArchetype.STANDARD_ERC20:
        # For standard tokens, any complex mechanisms are suspicious
        suspicious_findings = detections.get("suspicious_patterns", {}).get("findings", [])
        findings.extend(suspicious_findings)

    return findings