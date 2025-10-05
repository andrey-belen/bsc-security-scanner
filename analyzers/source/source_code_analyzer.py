"""
Source Code Analyzer - Analyze contract source code for patterns and vulnerabilities
"""

from typing import Dict, List, Optional, Callable


class SourceCodeAnalyzer:
    """Analyze contract source code, inheritance, events, and red flags"""

    def __init__(self, add_finding: Callable):
        """
        Initialize source code analyzer

        Args:
            add_finding: Callback function to add findings
        """
        self.add_finding = add_finding

    def analyze_inheritance(self, source_code: str) -> Dict:
        """
        Analyze contract inheritance patterns

        Args:
            source_code: Contract source code

        Returns:
            Dictionary with inheritance patterns
        """
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
            self.add_finding(
                "info",
                "Pausable Contract",
                "Contract inherits from Pausable. Owner may be able to pause token transfers.",
                "inheritance"
            )

        if "accesscontrol" in source_lower or "is accesscontrol" in source_lower:
            inheritance["access_control"] = True
            self.add_finding(
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
            self.add_finding(
                "info",
                "Reentrancy Protection",
                "Contract uses ReentrancyGuard for protection against reentrancy attacks.",
                "inheritance"
            )

        return inheritance

    def check_red_flags(self, address: str, source_code: Optional[str]) -> List[str]:
        """
        Check for common scam patterns and dangerous code in source code

        Args:
            address: Contract address
            source_code: Contract source code (optional)

        Returns:
            List of red flags found
        """
        flags = []

        if source_code:
            source_lower = source_code.lower()

            # Check for blacklist
            if "blacklist" in source_lower or "_isblacklisted" in source_lower or "ban(" in source_lower or "blockuser" in source_lower:
                if not any(f["type"] == "red_flag" and "blacklist" in f["message"].lower() for f in getattr(self, '_temp_findings', [])):
                    self.add_finding(
                        "high",
                        "Blacklist Pattern in Source",
                        "Source code contains blacklist implementation. Owner can prevent specific addresses from trading.",
                        "red_flag"
                    )
                    flags.append("blacklist")

            # Check for transfer fees
            if "transferfee" in source_lower or "sellfee" in source_lower or "buyfee" in source_lower or "taxfee" in source_lower:
                self.add_finding(
                    "medium",
                    "Transfer Fees Detected",
                    "Contract implements transfer fees. Verify fee percentages are reasonable (<10%).",
                    "red_flag"
                )
                flags.append("transfer_fees")

            # Check for reentrancy-unsafe external calls
            if "call.value" in source_lower.replace(" ", "") or "call{value:" in source_lower.replace(" ", ""):
                self.add_finding(
                    "critical",
                    "Unsafe External Call Pattern",
                    "Contract uses low-level call.value or call{value:} which can be vulnerable to reentrancy attacks.",
                    "red_flag"
                )
                flags.append("unsafe_call")

            # Check for selfdestruct
            if "selfdestruct(" in source_lower or "suicide(" in source_lower:
                self.add_finding(
                    "critical",
                    "Self-Destruct Function Detected",
                    "Contract contains selfdestruct which can permanently destroy the contract and all funds.",
                    "red_flag"
                )
                flags.append("selfdestruct")

            # Check for delegatecall
            if "delegatecall(" in source_lower:
                self.add_finding(
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
                    self.add_finding(
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
                self.add_finding(
                    "medium",
                    "Ownership Transfer Without Timelock",
                    "Contract allows ownership transfer without timelock protection. Ownership can change instantly.",
                    "red_flag"
                )
                flags.append("no_timelock")

        return flags

    def check_event_coverage(self, abi: list) -> Dict:
        """
        Check if contract has proper event emissions for state changes

        Args:
            abi: Contract ABI

        Returns:
            Dictionary with event coverage analysis
        """
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
            self.add_finding(
                "medium",
                "No Events Detected",
                "Contract does not emit any events. This makes it difficult to track state changes.",
                "events"
            )
        elif len(coverage["missing_events"]) > 3:
            coverage["score"] = 30
            self.add_finding(
                "low",
                "Incomplete Event Coverage",
                f"Contract missing events for {len(coverage['missing_events'])} important functions. Reduced transparency.",
                "events"
            )
        elif len(coverage["missing_events"]) > 0:
            coverage["score"] = 60
        else:
            coverage["score"] = 100
            self.add_finding(
                "info",
                "Good Event Coverage",
                "Contract has comprehensive event emissions for state changes.",
                "events"
            )

        return coverage
