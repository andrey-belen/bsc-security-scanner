"""
Risk Calculator - Calculate risk scores based on findings
"""

from typing import List, Dict


class RiskCalculator:
    """Calculate and manage risk scores"""

    def __init__(self):
        """Initialize risk calculator"""
        self.severity_weights = {
            "critical": 40,  # Each critical finding contributes up to 40 points
            "high": 25,      # Each high finding contributes up to 25 points
            "medium": 15,    # Each medium finding contributes up to 15 points
            "low": 5,        # Each low finding contributes up to 5 points
            "info": 0        # Info findings don't add to score
        }

    def calculate_risk(self, findings: List[Dict], positive_factors: List[int],
                      token_symbol: str = "", token_name: str = "",
                      is_verified: bool = False, is_renounced: bool = False,
                      owner_type: str = "unknown", is_known_infrastructure: bool = False) -> int:
        """
        Calculate final risk score (0-100) using weighted severity model with context multipliers

        Formula: (Base score from findings + contextual adjustments - positive factors) × context multipliers

        Args:
            findings: List of security findings
            positive_factors: List of risk reduction factors
            token_symbol: Token symbol (for stablecoin/major token detection)
            token_name: Token name (for router/infrastructure detection)
            is_verified: Whether contract is verified on BSCScan
            is_renounced: Whether ownership is renounced
            owner_type: Type of owner (eoa, multisig, contract, renounced)
            is_known_infrastructure: Whether this is a known infrastructure token

        Returns:
            Risk score between 0 and 100
        """
        # Group findings by severity
        findings_by_severity = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
        for finding in findings:
            severity = finding.get("severity", "info")
            # Skip positive findings (they're already in positive_factors)
            if not finding.get("positive", False):
                findings_by_severity[severity].append(finding)

        # Calculate base score using weighted approach
        base_score = 0

        # Critical findings have the highest impact
        if findings_by_severity["critical"]:
            # First critical finding = full weight, subsequent ones have diminishing returns
            base_score += self.severity_weights["critical"]
            base_score += min(len(findings_by_severity["critical"]) - 1, 3) * 10

        # High severity findings
        if findings_by_severity["high"]:
            base_score += self.severity_weights["high"]
            base_score += min(len(findings_by_severity["high"]) - 1, 2) * 8

        # Medium severity findings
        if findings_by_severity["medium"]:
            base_score += self.severity_weights["medium"]
            base_score += min(len(findings_by_severity["medium"]) - 1, 2) * 5

        # Low severity findings
        if findings_by_severity["low"]:
            base_score += min(len(findings_by_severity["low"]), 3) * 3

        # Apply positive factors (risk reduction)
        risk_reduction = sum(positive_factors)

        # Calculate final score before multipliers
        final_score = max(0, base_score - risk_reduction)

        # Apply context-aware multipliers (reduce risk for trusted tokens)
        multiplier = 1.0

        # Stablecoin and major infrastructure tokens - significantly reduce risk
        if token_symbol.upper() in ["BUSD", "USDT", "USDC", "DAI", "WBNB", "BNB", "ETH", "BTCB"]:
            multiplier *= 0.3
        elif "router" in token_name.lower() or "factory" in token_name.lower():
            multiplier *= 0.5
        elif is_known_infrastructure:
            multiplier *= 0.4

        # Positive modifiers for security features
        if is_verified:
            multiplier *= 0.9

        if is_renounced:
            multiplier *= 0.8

        if owner_type == "multisig":
            multiplier *= 0.85

        # Apply multiplier
        final_score = int(final_score * multiplier)

        # Cap at 100
        return min(final_score, 100)

    def get_risk_level(self, score: int) -> str:
        """
        Convert risk score to risk level based on enhanced severity model

        CRITICAL (80+): Honeypot, unprotected selfdestruct/delegatecall, unlimited mint
        HIGH (60-79): Owner can mint unlimited, pause/blacklist, proxy with EOA admin, old compiler
        MEDIUM (30-59): Transfer fees/taxes, missing events, centralized EOA control
        LOW (10-29): Tokenomics quirks, optimizer settings, verified contract
        VERY LOW (0-9): Well-audited infrastructure, renounced ownership

        Args:
            score: Risk score (0-100)

        Returns:
            Risk level string
        """
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 30:
            return "MEDIUM"
        elif score >= 10:
            return "LOW"
        else:
            return "VERY LOW"

    def adjust_findings_for_stablecoin(self, findings: List[Dict]) -> List[Dict]:
        """
        Adjust risk severity for legitimate stablecoin features

        Args:
            findings: List of security findings

        Returns:
            Adjusted findings list
        """
        for finding in findings:
            # Mint function is expected for stablecoins
            if "mint" in finding["message"].lower() and finding["severity"] == "high":
                finding["severity"] = "info"
                finding["details"] = "Stablecoin: " + finding["details"] + " This is expected for centralized stablecoin issuance."

            # EOA owner is common for regulated stablecoins
            if "eoa owner" in finding["message"].lower() and finding["severity"] == "medium":
                finding["severity"] = "low"
                finding["details"] = "Stablecoin: " + finding["details"] + " Centralized control is standard for regulated stablecoins."

        return findings
