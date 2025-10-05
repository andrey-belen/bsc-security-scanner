"""
Core Security Analyzer - Main orchestrator for security analysis
Coordinates specialized analyzers for comprehensive contract analysis
"""

import time
from typing import Dict, List, Optional
from web3 import Web3
from eth_utils import to_checksum_address

from config import get_rpc_endpoint
from .holder_analyzer import HolderDistributionAnalyzer
from .liquidity_analyzer import LiquidityPoolAnalyzer
from .transaction_simulator import TransactionSimulator
from .verification.contract_verifier import ContractVerifier
from .ownership.ownership_checker import OwnershipChecker
from .functions.function_analyzer import FunctionAnalyzer
from .source.source_code_analyzer import SourceCodeAnalyzer
from .source.token_classifier import TokenClassifier
from .scoring.risk_calculator import RiskCalculator


class CoreSecurityAnalyzer:
    """
    Core security analyzer - orchestrates all specialized analyzers
    Coordinates verification, ownership, function, source code, and risk analysis
    """

    def __init__(self):
        self.w3 = Web3(Web3.HTTPProvider(get_rpc_endpoint()))
        self.findings = []
        self.positive_factors = []  # Track risk reduction factors

        # Initialize specialized analyzers with callback for adding findings
        self.verifier = ContractVerifier(self._add_finding, self.positive_factors)
        self.ownership_checker = OwnershipChecker(self.w3, self._add_finding, self.positive_factors)
        self.function_analyzer = FunctionAnalyzer(self.w3, self._add_finding)
        self.source_analyzer = SourceCodeAnalyzer(self._add_finding)
        self.token_classifier = TokenClassifier(self.w3, self._add_finding, self.positive_factors)
        self.risk_calculator = RiskCalculator()

        # Initialize advanced analyzers
        self.holder_analyzer = HolderDistributionAnalyzer(web3=self.w3)
        self.liquidity_analyzer = LiquidityPoolAnalyzer(web3=self.w3)
        self.transaction_simulator = TransactionSimulator(web3=self.w3)

    def analyze_contract(self, address: str, quick_scan: bool = False) -> Dict:
        """
        Main analysis function with real security checks using Etherscan API

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

        # Step 2: Get contract verification status and source code via API
        is_verified, source_code, abi, metadata = self.verifier.check_verification(address)

        # Step 3: Check ownership
        owner_info = self.ownership_checker.check_ownership(address, abi)

        # Step 4: Analyze contract inheritance if source available
        inheritance_info = {}
        if source_code:
            inheritance_info = self.source_analyzer.analyze_inheritance(source_code)

        # Step 5: Analyze functions (from ABI or bytecode)
        function_risks = self.function_analyzer.analyze_functions(address, source_code, abi)

        # Step 6: Check event coverage if ABI available
        event_coverage = {}
        if abi:
            event_coverage = self.source_analyzer.check_event_coverage(abi)

        # Step 7: Check for common red flags in source code
        red_flags = self.source_analyzer.check_red_flags(address, source_code)

        # Step 8: Check token info if ERC-20
        token_info = self.token_classifier.get_token_info(address, abi)

        # Step 8.5: Detect if this is a known stablecoin or legitimate centralized token
        self.token_classifier.detect_token_type(address, token_info)

        # Step 9: Advanced Analysis (holder distribution, liquidity, honeypot detection)
        holder_analysis = None
        liquidity_analysis = None
        simulation_analysis = None

        if not quick_scan:
            # Liquidity analysis (run first to get LP pool addresses)
            try:
                liquidity_analysis = self.liquidity_analyzer.analyze_liquidity(
                    address,
                    token_symbol=token_info.get('symbol', ''),
                    token_name=token_info.get('name', '')
                )
                # Merge liquidity findings into main findings
                for finding in liquidity_analysis.get('findings', []):
                    self._add_finding(
                        finding['severity'],
                        finding['message'],
                        finding['details'],
                        category='liquidity',
                        positive=finding.get('positive', False)
                    )
                # Adjust risk score with context
                lp_risk = self.liquidity_analyzer.calculate_risk_adjustment(
                    liquidity_analysis['metrics'],
                    token_symbol=token_info.get('symbol', ''),
                    num_pools=liquidity_analysis['metrics'].get('pools_found', 0)
                )
                self.risk_score += lp_risk
            except Exception as e:
                self._add_finding("low", "Liquidity Analysis Failed", f"Could not analyze liquidity: {str(e)}", "liquidity")

            # Holder distribution analysis
            try:
                deployer = owner_info.get('owner')
                lp_pools = liquidity_analysis.get('pools', []) if liquidity_analysis else []
                holder_analysis = self.holder_analyzer.analyze_holders(
                    address,
                    deployer_address=deployer,
                    owner_address=deployer,
                    lp_pools=lp_pools
                )
                # Merge holder findings
                for finding in holder_analysis.get('findings', []):
                    self._add_finding(
                        finding['severity'],
                        finding['message'],
                        finding['details'],
                        category='holders',
                        positive=finding.get('positive', False)
                    )
                # Adjust risk score
                holder_risk = self.holder_analyzer.calculate_risk_adjustment(holder_analysis['metrics'])
                self.risk_score += holder_risk
            except Exception as e:
                self._add_finding("low", "Holder Analysis Failed", f"Could not analyze holders: {str(e)}", "holders")

            # Transaction simulation (honeypot detection)
            try:
                pool_address = lp_pools[0] if lp_pools else None
                simulation_analysis = self.transaction_simulator.simulate_transactions(address, pool_address)
                # Merge simulation findings
                for finding in simulation_analysis.get('findings', []):
                    self._add_finding(
                        finding['severity'],
                        finding['message'],
                        finding['details'],
                        category='honeypot'
                    )
                # Adjust risk score
                sim_risk = self.transaction_simulator.calculate_risk_adjustment(
                    simulation_analysis['is_honeypot'],
                    simulation_analysis['findings']
                )
                self.risk_score += sim_risk
            except Exception as e:
                self._add_finding("low", "Simulation Failed", f"Could not simulate transactions: {str(e)}", "honeypot")

        # Step 10: Adjust findings if stablecoin
        if self.token_classifier.is_stablecoin:
            self.findings = self.risk_calculator.adjust_findings_for_stablecoin(self.findings)

        # Step 11: Calculate final risk score with context multipliers
        self.risk_score = self.risk_calculator.calculate_risk(
            self.findings,
            self.positive_factors,
            token_symbol=token_info.get('symbol', ''),
            token_name=token_info.get('name', ''),
            is_verified=is_verified,
            is_renounced=owner_info.get('is_renounced', False),
            owner_type=owner_info.get('owner_type', 'unknown'),
            is_known_infrastructure=self.token_classifier.is_known_infrastructure
        )

        result = {
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
            "risk_level": self.risk_calculator.get_risk_level(self.risk_score),
            "analysis_confidence": 0.9 if is_verified else 0.6
        }

        # Add advanced analysis results if available
        if holder_analysis:
            result['holder_distribution'] = holder_analysis
        if liquidity_analysis:
            result['liquidity'] = liquidity_analysis
        if simulation_analysis:
            result['honeypot_check'] = simulation_analysis

        return result

    def _add_finding(self, severity: str, message: str, details: str, finding_type: str = None, category: str = None, positive: bool = False):
        """Add a security finding"""
        finding = {
            "severity": severity,
            "message": message,
            "details": details,
            "type": finding_type or category or "general"
        }
        if positive:
            finding["positive"] = True
        self.findings.append(finding)

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
