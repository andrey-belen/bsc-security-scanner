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
                liquidity_analysis = self.liquidity_analyzer.analyze_liquidity(address)
                # Merge liquidity findings into main findings
                for finding in liquidity_analysis.get('findings', []):
                    self._add_finding(
                        finding['severity'],
                        finding['message'],
                        finding['details'],
                        category='liquidity',
                        positive=finding.get('positive', False)
                    )
                # Adjust risk score
                lp_risk = self.liquidity_analyzer.calculate_risk_adjustment(liquidity_analysis['metrics'])
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

        # Step 11: Calculate final risk score
        self.risk_score = self.risk_calculator.calculate_risk(self.findings, self.positive_factors)

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
        """
        Check contract verification using Etherscan API
        Note: BSCScan now uses Etherscan infrastructure, so this works for BSC contracts

        Returns:
            tuple: (is_verified, source_code, abi, metadata)
        """
        if not self.api_key:
            self._add_finding(
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
                        self._add_finding(
                            "low",
                            "Optimizer Disabled",
                            "Contract compiled without optimization. May have higher gas costs but no security impact.",
                            "compiler"
                        )

                    # Check if proxy contract
                    if metadata["proxy"] == "1":
                        self._add_finding(
                            "medium",
                            "Proxy Contract Detected",
                            f"This is an upgradeable proxy contract. Implementation: {metadata['implementation'][:10]}...{metadata['implementation'][-8:] if metadata['implementation'] else 'Unknown'}",
                            "proxy"
                        )

                    self._add_finding(
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
                    self._add_finding(
                        "medium",
                        "Contract Not Verified",
                        "Contract source code is not verified on BSCScan. This increases risk as code cannot be audited.",
                        "verification"
                    )
                    return False, None, None, None
            else:
                # API returned error or no result
                self._add_finding(
                    "medium",
                    "Verification Check Failed",
                    f"Unable to verify contract status via API: {data.get('message', 'Unknown error')}",
                    "verification"
                )
                return False, None, None, None

        except requests.exceptions.Timeout:
            self._add_finding(
                "low",
                "Verification Check Timeout",
                "BSCScan API request timed out. Continuing with bytecode analysis.",
                "verification"
            )
            return False, None, None, None
        except Exception as e:
            self._add_finding(
                "low",
                "Verification Check Error",
                f"Error checking verification: {str(e)}",
                "verification"
            )
            return False, None, None, None

    def _check_ownership(self, address: str, abi: Optional[list]) -> Dict:
        """Check contract ownership status with enhanced verification"""
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
                self._add_finding(
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
                    self._add_finding(
                        "info",
                        "Contract-Owned (Multisig/DAO)",
                        f"Owner is a contract address (likely multisig or DAO): {owner[:10]}...{owner[-8:]}. Lower centralization risk.",
                        "ownership"
                    )
                    # Positive factor: multisig ownership reduces risk
                    self.positive_factors.append(10)
                else:
                    owner_info["owner_type"] = "EOA"
                    self._add_finding(
                        "medium",
                        "EOA Owner (High Risk)",
                        f"Owner is an externally owned account (EOA): {owner[:10]}...{owner[-8:]}. Single wallet controls all privileges. HIGH centralization risk.",
                        "ownership"
                    )

        except Exception:
            # No owner() function or error
            self._add_finding(
                "info",
                "No Owner Function",
                "Contract does not implement standard owner() function. May not be ownable.",
                "ownership"
            )

        return owner_info

    def _analyze_functions(self, address: str, source_code: Optional[str], abi: Optional[list]) -> Dict:
        """Analyze contract functions for dangerous patterns and privileges"""
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
                    if "mint" in name_lower and name not in dangerous_found:
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
                        self._add_finding(
                            "critical",
                            "Delegatecall Function",
                            f"Function '{name}' uses delegatecall. This can execute arbitrary code and is extremely dangerous.",
                            "dangerous_function"
                        )

                    if "selfdestruct" in name_lower or "destroy" in name_lower:
                        dangerous_found.append("selfdestruct")
                        self._add_finding(
                            "critical",
                            "Self-Destruct Function",
                            f"Function '{name}' can destroy the contract. All funds could be lost permanently.",
                            "dangerous_function"
                        )

                    # Proxy upgrade detection
                    if "upgradeto" in name_lower:
                        dangerous_found.append("upgradeable")
                        self._add_finding(
                            "high",
                            "Upgradeable Contract",
                            f"Function '{name}' allows contract upgrade. Implementation can be changed at any time.",
                            "dangerous_function"
                        )

            # Determine access control type
            if any("grantrole" in f.lower() or "hasrole" in f.lower() for f in access_control["functions"]):
                access_control["type"] = "role_based"
                self._add_finding(
                    "info",
                    "Role-Based Access Control",
                    f"Contract uses role-based permissions. {len(privilege_functions)} privileged functions detected.",
                    "access_control"
                )
            elif privilege_functions:
                access_control["type"] = "owner_based"

            # Report on privilege functions
            if len(privilege_functions) > 5:
                self._add_finding(
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
            self._add_finding(
                "high",
                "Mint Function Detected",
                "Contract has a mint() function. Owner may be able to create unlimited tokens, diluting holder value.",
                "dangerous_function"
            )

        if "pause" in dangerous_found:
            self._add_finding(
                "medium",
                "Pause Functionality",
                "Contract can be paused, potentially freezing all transfers. Ensure this is expected behavior.",
                "dangerous_function"
            )

        if "blacklist" in dangerous_found:
            self._add_finding(
                "high",
                "Blacklist Function Found",
                "Contract contains blacklist functionality. Owner can prevent specific addresses from trading.",
                "dangerous_function"
            )

        if "fee_manipulation" in dangerous_found:
            self._add_finding(
                "medium",
                "Fee Manipulation Functions",
                "Contract allows owner to modify fees/taxes. Verify fee limits are in place.",
                "dangerous_function"
            )

        risks["dangerous_functions"] = dangerous_found
        risks["privilege_functions"] = privilege_functions
        risks["access_control"] = access_control
        return risks

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
                        self._add_finding(
                            "low",
                            "Old Compiler with SafeMath",
                            f"Contract compiled with Solidity {version} (pre-0.8.0) but uses SafeMath library for overflow protection. Risk mitigated.",
                            "compiler"
                        )
                    else:
                        # No SafeMath - higher risk
                        if minor < 6:
                            # Very old versions without SafeMath
                            self._add_finding(
                                "high",
                                "Critically Outdated Compiler",
                                f"Contract compiled with very old Solidity {version} without SafeMath. Multiple known vulnerabilities.",
                                "compiler"
                            )
                        else:
                            # 0.6.x/0.7.x without SafeMath
                            self._add_finding(
                                "medium",
                                "Old Compiler Without SafeMath",
                                f"Contract compiled with Solidity {version} without SafeMath. Vulnerable to overflow/underflow attacks.",
                                "compiler"
                            )

        except Exception as e:
            print(f"Error analyzing compiler version: {e}")

    def _analyze_contract_inheritance(self, source_code: str) -> Dict:
        """Analyze contract inheritance patterns"""
        inheritance = {
            "ownable": False,
            "pausable": False,
            "access_control": False,
            "erc20": False,
            "proxy": False,
            "reentrancy_guard": False
        }

        if not source_code:
            return inheritance

        source_lower = source_code.lower()

        # Check for common patterns
        if "ownable" in source_lower or "is ownable" in source_lower:
            inheritance["ownable"] = True

        if "pausable" in source_lower or "is pausable" in source_lower:
            inheritance["pausable"] = True
            self._add_finding(
                "info",
                "Pausable Contract",
                "Contract inherits from Pausable. Owner may be able to pause token transfers.",
                "inheritance"
            )

        if "accesscontrol" in source_lower or "is accesscontrol" in source_lower:
            inheritance["access_control"] = True
            self._add_finding(
                "info",
                "Role-Based Access Control",
                "Contract uses AccessControl for role-based permissions. Check role assignments carefully.",
                "inheritance"
            )

        if "ierc20" in source_lower or "is ierc20" in source_lower or "is erc20" in source_lower:
            inheritance["erc20"] = True

        if "upgradeableproxy" in source_lower or "transparentupgradeableproxy" in source_lower:
            inheritance["proxy"] = True

        if "reentrancyguard" in source_lower or "nonreentrant" in source_lower:
            inheritance["reentrancy_guard"] = True
            self._add_finding(
                "info",
                "Reentrancy Protection",
                "Contract uses ReentrancyGuard for protection against reentrancy attacks.",
                "inheritance"
            )

        return inheritance

    def _check_red_flags(self, address: str, source_code: Optional[str]) -> List[str]:
        """Check for common scam patterns and dangerous code in source code"""
        flags = []

        if source_code:
            source_lower = source_code.lower()

            # Check for blacklist
            if "blacklist" in source_lower or "_isblacklisted" in source_lower or "ban(" in source_lower or "blockuser" in source_lower:
                if not any(f["type"] == "red_flag" and "blacklist" in f["message"].lower() for f in self.findings):
                    self._add_finding(
                        "high",
                        "Blacklist Pattern in Source",
                        "Source code contains blacklist implementation. Owner can prevent specific addresses from trading.",
                        "red_flag"
                    )
                    flags.append("blacklist")

            # Check for transfer fees
            if "transferfee" in source_lower or "sellfee" in source_lower or "buyfee" in source_lower or "taxfee" in source_lower:
                self._add_finding(
                    "medium",
                    "Transfer Fees Detected",
                    "Contract implements transfer fees. Verify fee percentages are reasonable (<10%).",
                    "red_flag"
                )
                flags.append("transfer_fees")

            # Check for reentrancy-unsafe external calls
            if "call.value" in source_lower.replace(" ", "") or "call{value:" in source_lower.replace(" ", ""):
                self._add_finding(
                    "critical",
                    "Unsafe External Call Pattern",
                    "Contract uses low-level call.value or call{value:} which can be vulnerable to reentrancy attacks.",
                    "red_flag"
                )
                flags.append("unsafe_call")

            # Check for selfdestruct
            if "selfdestruct(" in source_lower or "suicide(" in source_lower:
                self._add_finding(
                    "critical",
                    "Self-Destruct Function Detected",
                    "Contract contains selfdestruct which can permanently destroy the contract and all funds.",
                    "red_flag"
                )
                flags.append("selfdestruct")

            # Check for delegatecall
            if "delegatecall(" in source_lower:
                self._add_finding(
                    "high",
                    "Delegatecall Detected",
                    "Contract uses delegatecall which can be dangerous if not properly secured. May allow arbitrary code execution.",
                    "red_flag"
                )
                flags.append("delegatecall")

            # Check for backdoor-like functions
            backdoor_patterns = ["withdrawall", "emergencywithdraw", "rugpull", "skim(", "sweep("]
            for pattern in backdoor_patterns:
                if pattern in source_lower.replace(" ", ""):
                    self._add_finding(
                        "critical",
                        "Potential Backdoor Function",
                        f"Contract contains suspicious function pattern '{pattern}' which may allow owner to drain funds.",
                        "red_flag"
                    )
                    flags.append("backdoor")
                    break

            # Check for ownership transfer without timelock
            if ("transferownership(" in source_lower.replace(" ", "") and
                "timelock" not in source_lower):
                self._add_finding(
                    "medium",
                    "Ownership Transfer Without Timelock",
                    "Contract allows ownership transfer without timelock protection. Ownership can change instantly.",
                    "red_flag"
                )
                flags.append("no_timelock")

        return flags

    def _check_event_coverage(self, abi: list) -> Dict:
        """Check if contract has proper event emissions for state changes"""
        events = []
        functions = []
        coverage = {"has_events": False, "missing_events": [], "score": 0}

        # Extract events and functions from ABI
        for item in abi:
            if item.get("type") == "event":
                events.append(item.get("name", "").lower())
            elif item.get("type") == "function":
                func_name = item.get("name", "").lower()
                state_mutability = item.get("stateMutability", "")
                # Only check state-changing functions
                if state_mutability in ["nonpayable", "payable", ""]:
                    functions.append(func_name)

        coverage["has_events"] = len(events) > 0

        # Check for expected ERC-20 events
        expected_erc20_events = ["transfer", "approval"]
        for event in expected_erc20_events:
            if event not in events and any(event in f for f in functions):
                coverage["missing_events"].append(f"{event.title()} event")

        # Check if privileged functions emit events
        privilege_functions = ["mint", "burn", "pause", "unpause", "transferownership", "blacklist"]
        for priv_func in privilege_functions:
            if any(priv_func in f for f in functions):
                # Check if there's a corresponding event
                has_event = any(priv_func in e for e in events)
                if not has_event:
                    coverage["missing_events"].append(f"{priv_func.title()} event")

        # Calculate coverage score
        if len(events) == 0:
            coverage["score"] = 0
            self._add_finding(
                "medium",
                "No Events Detected",
                "Contract does not emit any events. This makes it difficult to track state changes.",
                "events"
            )
        elif len(coverage["missing_events"]) > 3:
            coverage["score"] = 30
            self._add_finding(
                "low",
                "Incomplete Event Coverage",
                f"Contract missing events for {len(coverage['missing_events'])} important functions. Reduced transparency.",
                "events"
            )
        elif len(coverage["missing_events"]) > 0:
            coverage["score"] = 60
        else:
            coverage["score"] = 100
            self._add_finding(
                "info",
                "Good Event Coverage",
                "Contract has comprehensive event emissions for state changes.",
                "events"
            )

        return coverage

    def _detect_token_type(self, address: str, token_info: Dict):
        """Detect if token is a known stablecoin or known infrastructure"""
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
            self._add_finding(
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
            self._add_finding(
                "info",
                f"Known Stablecoin: {stablecoin_name}",
                f"This is a recognized stablecoin. Centralized controls (mint, burn, owner) are expected for regulatory compliance.",
                "token_type"
            )
            # Reduce risk scores that were added for legitimate stablecoin features
            self._adjust_stablecoin_risk()
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
                    self._add_finding(
                        "info",
                        "Likely Stablecoin",
                        f"Token appears to be a stablecoin based on name/symbol. Centralized features may be expected.",
                        "token_type"
                    )
                    self._adjust_stablecoin_risk()
                    return

    def _adjust_stablecoin_risk(self):
        """Adjust risk severity for legitimate stablecoin features"""
        # Check findings for stablecoin-appropriate features and downgrade severity
        for finding in self.findings:
            # Mint function is expected for stablecoins
            if "mint" in finding["message"].lower() and finding["severity"] == "high":
                finding["severity"] = "info"
                finding["details"] = "Stablecoin: " + finding["details"] + " This is expected for centralized stablecoin issuance."

            # EOA owner is common for regulated stablecoins
            if "eoa owner" in finding["message"].lower() and finding["severity"] == "medium":
                finding["severity"] = "low"
                finding["details"] = "Stablecoin: " + finding["details"] + " Centralized control is standard for regulated stablecoins."

    def _get_token_info(self, address: str, abi: Optional[list]) -> Dict:
        """Get basic ERC-20 token information"""
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

    def _calculate_risk(self) -> int:
        """
        Calculate final risk score (0-100) using weighted severity model
        Formula: Base score from findings + contextual adjustments - positive factors
        """
        # Severity weights (maximum impact each type can have)
        severity_weights = {
            "critical": 40,  # Each critical finding contributes up to 40 points
            "high": 25,      # Each high finding contributes up to 25 points
            "medium": 15,    # Each medium finding contributes up to 15 points
            "low": 5,        # Each low finding contributes up to 5 points
            "info": 0        # Info findings don't add to score
        }

        # Group findings by severity
        findings_by_severity = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
        for finding in self.findings:
            severity = finding.get("severity", "info")
            findings_by_severity[severity].append(finding)

        # Calculate base score using weighted approach
        base_score = 0

        # Critical findings have the highest impact
        if findings_by_severity["critical"]:
            # First critical finding = full weight, subsequent ones have diminishing returns
            base_score += severity_weights["critical"]
            base_score += min(len(findings_by_severity["critical"]) - 1, 3) * 10

        # High severity findings
        if findings_by_severity["high"]:
            base_score += severity_weights["high"]
            base_score += min(len(findings_by_severity["high"]) - 1, 2) * 8

        # Medium severity findings
        if findings_by_severity["medium"]:
            base_score += severity_weights["medium"]
            base_score += min(len(findings_by_severity["medium"]) - 1, 2) * 5

        # Low severity findings
        if findings_by_severity["low"]:
            base_score += min(len(findings_by_severity["low"]), 3) * 3

        # Apply positive factors (risk reduction)
        risk_reduction = sum(self.positive_factors)

        # Calculate final score
        final_score = max(0, base_score - risk_reduction)

        # Cap at 100
        return min(final_score, 100)

    def _get_risk_level(self, score: int) -> str:
        """
        Convert risk score to risk level based on enhanced severity model

        CRITICAL (80+): Honeypot, unprotected selfdestruct/delegatecall, unlimited mint
        HIGH (60-79): Owner can mint unlimited, pause/blacklist, proxy with EOA admin, old compiler
        MEDIUM (30-59): Transfer fees/taxes, missing events, centralized EOA control
        LOW (10-29): Tokenomics quirks, optimizer settings, verified contract
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
