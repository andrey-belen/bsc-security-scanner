"""
Source Code Analyzer - Parse verified source code for precise detection
of security vulnerabilities and contract mechanisms
"""

import re
import requests
import time
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass

from config import BSCSCAN_CONFIG, get_bscscan_api_key


@dataclass
class FunctionInfo:
    """Information about a contract function"""
    name: str
    visibility: str
    modifiers: List[str]
    parameters: List[str]
    returns: List[str]
    line_number: int
    confidence: float = 1.0


@dataclass
class VariableInfo:
    """Information about a contract variable"""
    name: str
    type: str
    visibility: str
    is_constant: bool
    initial_value: Optional[str]
    line_number: int


class SourceCodeAnalyzer:
    """Analyze verified source code for precise vulnerability detection"""

    def __init__(self):
        self.api_key = get_bscscan_api_key()

        # Improved function patterns with confidence scoring
        self.dangerous_patterns = {
            "mint_functions": {
                "patterns": [
                    r"function\s+mint\s*\(",
                    r"function\s+mintTo\s*\(",
                    r"function\s+_mint\s*\(",
                    r"function\s+mintTokens\s*\(",
                    r"function\s+createTokens\s*\("
                ],
                "severity": "critical",
                "confidence": 0.95
            },
            "tax_functions": {
                "patterns": [
                    r"function\s+setTax\w*\s*\(",
                    r"function\s+set\w*Fee\s*\(",
                    r"function\s+updateFee\w*\s*\(",
                    r"function\s+changeFee\w*\s*\(",
                    r"function\s+setFeePercent\s*\("
                ],
                "severity": "high",
                "confidence": 0.9
            },
            "blacklist_functions": {
                "patterns": [
                    r"function\s+blacklist\w*\s*\(",
                    r"function\s+addToBlacklist\s*\(",
                    r"function\s+removeFromBlacklist\s*\(",
                    r"function\s+setBlacklist\s*\(",
                    r"function\s+banAddress\s*\("
                ],
                "severity": "high",
                "confidence": 0.95
            },
            "pause_functions": {
                "patterns": [
                    r"function\s+pause\s*\(",
                    r"function\s+unpause\s*\(",
                    r"function\s+pauseContract\s*\(",
                    r"function\s+setTradingEnabled\s*\(",
                    r"function\s+enableTrading\s*\("
                ],
                "severity": "high",
                "confidence": 0.95
            },
            "ownership_functions": {
                "patterns": [
                    r"function\s+transferOwnership\s*\(",
                    r"function\s+renounceOwnership\s*\(",
                    r"function\s+changeOwner\s*\(",
                    r"function\s+setOwner\s*\("
                ],
                "severity": "medium",
                "confidence": 0.9
            }
        }

        # Tax/fee variable patterns
        self.tax_variable_patterns = {
            "buy_tax": [r"\b\w*[Bb]uy\w*[Ff]ee\w*\b", r"\b\w*[Bb]uy\w*[Tt]ax\w*\b"],
            "sell_tax": [r"\b\w*[Ss]ell\w*[Ff]ee\w*\b", r"\b\w*[Ss]ell\w*[Tt]ax\w*\b"],
            "marketing_fee": [r"\b\w*[Mm]arketing\w*[Ff]ee\w*\b"],
            "reflection_fee": [r"\b\w*[Rr]eflection\w*[Ff]ee\w*\b", r"\b\w*[Rr]fi\w*[Ff]ee\w*\b"],
            "liquidity_fee": [r"\b\w*[Ll]iquidity\w*[Ff]ee\w*\b"],
            "total_fee": [r"\b\w*[Tt]otal\w*[Ff]ee\w*\b", r"\b\w*[Ff]ee\w*[Tt]otal\w*\b"]
        }

    def get_verified_source_code(self, address: str) -> Optional[str]:
        """Fetch verified source code from BSCScan"""
        try:
            url = f"{BSCSCAN_CONFIG['api_url']}"
            params = {
                "module": "contract",
                "action": "getsourcecode",
                "address": address,
                "apikey": self.api_key
            }

            response = requests.get(url, params=params, timeout=BSCSCAN_CONFIG['timeout'])
            response.raise_for_status()

            data = response.json()
            if data.get("status") == "1" and data.get("result"):
                result = data["result"][0]
                source_code = result.get("SourceCode", "")

                # Handle different source code formats
                if source_code.startswith("{{"):
                    # Multiple file source code (JSON format)
                    import json
                    try:
                        source_data = json.loads(source_code[1:-1])  # Remove outer braces
                        # Combine all source files
                        combined_source = ""
                        for file_path, content in source_data.get("sources", {}).items():
                            combined_source += f"\n// File: {file_path}\n"
                            combined_source += content.get("content", "")
                        return combined_source
                    except json.JSONDecodeError:
                        return source_code

                return source_code if source_code else None

        except Exception as e:
            print(f"Error fetching source code: {e}")
            return None

    def analyze_source_code(self, address: str) -> Dict:
        """Analyze verified source code for security vulnerabilities"""
        source_code = self.get_verified_source_code(address)

        if not source_code:
            return {
                "has_source": False,
                "findings": [],
                "functions": [],
                "variables": [],
                "confidence": 0.0
            }

        findings = []
        functions = self._extract_functions(source_code)
        variables = self._extract_variables(source_code)

        # Analyze dangerous functions with high confidence
        function_findings = self._analyze_dangerous_functions(source_code, functions)
        findings.extend(function_findings)

        # Analyze tax/fee mechanisms
        tax_findings = self._analyze_tax_mechanisms(source_code, variables)
        findings.extend(tax_findings)

        # Analyze blacklist mechanisms
        blacklist_findings = self._analyze_blacklist_mechanisms(source_code, functions)
        findings.extend(blacklist_findings)

        # Analyze pause mechanisms
        pause_findings = self._analyze_pause_mechanisms(source_code, functions)
        findings.extend(pause_findings)

        # Calculate overall confidence
        total_confidence = self._calculate_confidence(findings, functions, variables)

        return {
            "has_source": True,
            "findings": findings,
            "functions": functions,
            "variables": variables,
            "confidence": total_confidence,
            "source_lines": len(source_code.split('\n')),
            "is_verified": True
        }

    def _extract_functions(self, source_code: str) -> List[FunctionInfo]:
        """Extract function information from source code"""
        functions = []
        lines = source_code.split('\n')

        # Improved function regex pattern
        function_pattern = r'function\s+(\w+)\s*\([^)]*\)\s*(public|private|internal|external)?\s*(.*?)\s*(?:returns\s*\([^)]*\))?\s*\{'

        for i, line in enumerate(lines):
            matches = re.finditer(function_pattern, line, re.IGNORECASE)
            for match in matches:
                func_name = match.group(1)
                visibility = match.group(2) or "internal"
                modifiers_str = match.group(3) or ""

                # Extract modifiers
                modifiers = []
                modifier_patterns = [
                    r'\bonlyOwner\b',
                    r'\bonlyAdmin\b',
                    r'\bwhenNotPaused\b',
                    r'\bwhenPaused\b',
                    r'\bnonReentrant\b'
                ]

                for pattern in modifier_patterns:
                    if re.search(pattern, modifiers_str, re.IGNORECASE):
                        modifiers.append(pattern.strip('\\b'))

                functions.append(FunctionInfo(
                    name=func_name,
                    visibility=visibility.lower(),
                    modifiers=modifiers,
                    parameters=[],  # Could be extracted if needed
                    returns=[],     # Could be extracted if needed
                    line_number=i + 1
                ))

        return functions

    def _extract_variables(self, source_code: str) -> List[VariableInfo]:
        """Extract variable information from source code"""
        variables = []
        lines = source_code.split('\n')

        # Variable declaration patterns
        var_pattern = r'(uint256|uint|int256|int|bool|address|string|bytes32)\s+(public|private|internal)?\s*(constant)?\s+(\w+)(?:\s*=\s*([^;]+))?'

        for i, line in enumerate(lines):
            # Skip comments and function bodies
            if '//' in line or '/*' in line or line.strip().startswith('*'):
                continue

            matches = re.finditer(var_pattern, line, re.IGNORECASE)
            for match in matches:
                var_type = match.group(1)
                visibility = match.group(2) or "internal"
                is_constant = match.group(3) is not None
                var_name = match.group(4)
                initial_value = match.group(5)

                if initial_value:
                    initial_value = initial_value.strip().rstrip(';')

                variables.append(VariableInfo(
                    name=var_name,
                    type=var_type.lower(),
                    visibility=visibility.lower(),
                    is_constant=is_constant,
                    initial_value=initial_value,
                    line_number=i + 1
                ))

        return variables

    def _analyze_dangerous_functions(self, source_code: str, functions: List[FunctionInfo]) -> List[Dict]:
        """Analyze source code for dangerous functions with high confidence"""
        findings = []

        for pattern_type, pattern_info in self.dangerous_patterns.items():
            matched_functions = []

            for pattern in pattern_info["patterns"]:
                matches = re.finditer(pattern, source_code, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    # Find the function name
                    func_match = re.search(r'function\s+(\w+)', match.group(0))
                    if func_match:
                        func_name = func_match.group(1)
                        matched_functions.append(func_name)

            if matched_functions:
                # Remove duplicates while preserving order
                unique_functions = list(dict.fromkeys(matched_functions))

                findings.append({
                    "type": pattern_type,
                    "severity": pattern_info["severity"],
                    "confidence": pattern_info["confidence"],
                    "message": f"Detected {pattern_type.replace('_', ' ')}: {', '.join(unique_functions)}",
                    "functions": unique_functions,
                    "detection_method": "source_code_analysis"
                })

        return findings

    def _analyze_tax_mechanisms(self, source_code: str, variables: List[VariableInfo]) -> List[Dict]:
        """Analyze tax/fee mechanisms in source code"""
        findings = []
        detected_taxes = {}

        # Look for tax/fee variables
        for var in variables:
            for tax_type, patterns in self.tax_variable_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, var.name, re.IGNORECASE):
                        if tax_type not in detected_taxes:
                            detected_taxes[tax_type] = []
                        detected_taxes[tax_type].append(var.name)
                        break

        # Analyze tax modification functions
        tax_modification_functions = []
        tax_func_pattern = r'function\s+(\w*[Ss]et\w*[Ff]ee\w*|\w*[Cc]hange\w*[Ff]ee\w*|\w*[Uu]pdate\w*[Ff]ee\w*)\s*\('
        matches = re.finditer(tax_func_pattern, source_code, re.IGNORECASE)
        for match in matches:
            func_name = match.group(1)
            tax_modification_functions.append(func_name)

        # Look for asymmetric tax logic
        asymmetric_logic = self._detect_asymmetric_tax_logic(source_code)

        if detected_taxes:
            tax_types = list(detected_taxes.keys())
            findings.append({
                "type": "tax_variables",
                "severity": "medium",
                "confidence": 0.9,
                "message": f"Tax variables detected: {', '.join(tax_types)}",
                "tax_types": tax_types,
                "variables": detected_taxes,
                "detection_method": "source_code_analysis"
            })

        if tax_modification_functions:
            findings.append({
                "type": "dynamic_tax_functions",
                "severity": "high",
                "confidence": 0.95,
                "message": f"Tax modification functions: {', '.join(tax_modification_functions)}",
                "functions": tax_modification_functions,
                "detection_method": "source_code_analysis"
            })

        if asymmetric_logic:
            findings.append({
                "type": "asymmetric_tax_logic",
                "severity": "high",
                "confidence": 0.8,
                "message": "Asymmetric buy/sell tax logic detected",
                "details": asymmetric_logic,
                "detection_method": "source_code_analysis"
            })

        return findings

    def _analyze_blacklist_mechanisms(self, source_code: str, functions: List[FunctionInfo]) -> List[Dict]:
        """Analyze blacklist mechanisms"""
        findings = []

        # Look for blacklist variables
        blacklist_vars = []
        blacklist_var_patterns = [
            r'\b\w*[Bb]lacklist\w*\b',
            r'\b\w*[Bb]anned\w*\b',
            r'\b\w*[Bb]locked\w*\b'
        ]

        for pattern in blacklist_var_patterns:
            matches = re.finditer(pattern, source_code, re.IGNORECASE)
            for match in matches:
                if 'mapping' in source_code[match.start()-50:match.end()+50]:
                    blacklist_vars.append(match.group(0))

        # Look for blacklist functions
        blacklist_functions = []
        for func in functions:
            if any(keyword in func.name.lower() for keyword in ['blacklist', 'ban', 'block']):
                blacklist_functions.append(func.name)

        if blacklist_vars or blacklist_functions:
            findings.append({
                "type": "blacklist_mechanism",
                "severity": "high",
                "confidence": 0.95,
                "message": "Blacklist mechanism detected",
                "variables": list(set(blacklist_vars)),
                "functions": blacklist_functions,
                "detection_method": "source_code_analysis"
            })

        return findings

    def _analyze_pause_mechanisms(self, source_code: str, functions: List[FunctionInfo]) -> List[Dict]:
        """Analyze pause mechanisms"""
        findings = []

        # Look for pause state variables
        pause_vars = []
        pause_patterns = [r'\b\w*[Pp]aused\w*\b', r'\b\w*[Tt]radingEnabled\w*\b']

        for pattern in pause_patterns:
            matches = re.finditer(pattern, source_code, re.IGNORECASE)
            for match in matches:
                if 'bool' in source_code[match.start()-20:match.end()+20]:
                    pause_vars.append(match.group(0))

        # Look for pause functions
        pause_functions = []
        for func in functions:
            if any(keyword in func.name.lower() for keyword in ['pause', 'unpause', 'trading']):
                pause_functions.append(func.name)

        if pause_vars or pause_functions:
            findings.append({
                "type": "pause_mechanism",
                "severity": "high",
                "confidence": 0.9,
                "message": "Pause mechanism detected",
                "variables": list(set(pause_vars)),
                "functions": pause_functions,
                "detection_method": "source_code_analysis"
            })

        return findings

    def _detect_asymmetric_tax_logic(self, source_code: str) -> Optional[str]:
        """Detect asymmetric buy/sell tax logic"""
        # Look for conditional logic that treats buy/sell differently
        asymmetric_patterns = [
            r'if\s*\([^)]*sell[^)]*\)\s*\{[^}]*fee[^}]*\}',
            r'if\s*\([^)]*buy[^)]*\)\s*\{[^}]*fee[^}]*\}',
            r'sender\s*==\s*\w*[Pp]air.*fee',
            r'recipient\s*==\s*\w*[Pp]air.*fee'
        ]

        for pattern in asymmetric_patterns:
            if re.search(pattern, source_code, re.IGNORECASE | re.DOTALL):
                return "Detected conditional tax logic based on transaction direction"

        return None

    def _calculate_confidence(self, findings: List[Dict], functions: List[FunctionInfo], variables: List[VariableInfo]) -> float:
        """Calculate overall analysis confidence"""
        if not findings:
            return 1.0  # High confidence if no issues found

        # Weight confidence by detection method and evidence strength
        total_confidence = 0.0
        total_weight = 0.0

        for finding in findings:
            confidence = finding.get("confidence", 0.5)
            weight = 1.0

            # Higher weight for source code analysis vs bytecode analysis
            if finding.get("detection_method") == "source_code_analysis":
                weight = 2.0

            total_confidence += confidence * weight
            total_weight += weight

        return total_confidence / total_weight if total_weight > 0 else 0.5