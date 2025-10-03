#!/usr/bin/env python3
"""
BSC Security Scanner - Professional smart contract security analysis tool for BEP-20 tokens
Developed for security internship portfolio demonstration
"""

import argparse
import json
import sys
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import track
from rich import print as rprint

from config import BSC_CONFIG, is_valid_bsc_address
from analyzers.core_analyzer import CoreSecurityAnalyzer
from utils.error_handler import (
    ErrorAggregator, with_retry, RetryConfig,
    SecurityScannerError, ContractNotFoundError,
    default_rate_limiter, with_rate_limit
)
from utils.cache import (
    cache_contract_result, get_cached_contract_result,
    get_contract_cache_key
)


class BSCSecurityScanner:
    """Main BSC Security Scanner class"""

    def __init__(self):
        self.console = Console()
        self.core_analyzer = CoreSecurityAnalyzer()
        self.error_aggregator = ErrorAggregator()
        
    def scan_contract(self, address: str, quick_scan: bool = False) -> Dict:
        """
        Perform comprehensive security scan of BEP-20 contract
        
        Args:
            address: Contract address to scan
            quick_scan: If True, perform only basic checks
            
        Returns:
            Dictionary containing scan results
        """
        
        # Validate address format
        if not is_valid_bsc_address(address):
            raise ContractNotFoundError(f"Invalid BSC address format: {address}")

        # Check cache first
        cache_key = get_contract_cache_key(address)
        cached_result = get_cached_contract_result(address)
        if cached_result:
            self.console.print(f"📋 [green]Using cached results for {address}[/green]")
            return cached_result

        # Use core analyzer
        self.console.print(f"\n🔍 [bold cyan]Enhanced BSC Security Scanner[/bold cyan]")
        self.console.print("=" * 50)

        results = self.core_analyzer.analyze_contract(address, quick_scan)

        # Cache results
        cache_contract_result(address, results)

        return results
        
        self.console.print(f"\n🔍 [bold cyan]BSC Security Scanner[/bold cyan]")
        self.console.print("=" * 50)
        
        scan_results = {
            "address": address,
            "scan_time": datetime.now().isoformat(),
            "chain": "Binance Smart Chain (BSC)",
            "quick_scan": quick_scan,
            "findings": [],
            "risk_score": 0,
            "risk_level": "UNKNOWN",
            "errors": [],
            "warnings": []
        }
        
        try:
            # Basic contract validation
            self.console.print(f"📍 [bold]Address:[/bold] {address}")
            
            # Get basic contract info with error handling
            contract_info = self._get_contract_info_safe(address)
            scan_results.update(contract_info)
            
            self.console.print(f"🏷️  [bold]Token:[/bold] {contract_info.get('name', 'Unknown')}")
            self.console.print(f"🔗 [bold]Chain:[/bold] {scan_results['chain']}")
            
            # Perform security analyses with error handling
            analyses = []
            
            if not quick_scan:
                analyses = [
                    ("Contract Verification", self._check_verification),
                    ("Ownership Analysis", self.ownership_analyzer.analyze),
                    ("Honeypot Detection", self.honeypot_analyzer.analyze),
                    ("Function Analysis", self.function_analyzer.analyze),
                    ("Liquidity Analysis", self._check_liquidity),
                    ("Holder Distribution", self._check_holder_distribution)
                ]
            else:
                analyses = [
                    ("Contract Verification", self._check_verification),
                    ("Basic Ownership", self.ownership_analyzer.basic_check),
                    ("Quick Function Scan", self.function_analyzer.quick_scan)
                ]
            
            self.console.print(f"\n🔐 [bold green]Security Analysis:[/bold green]")
            
            for analysis_name, analysis_func in track(analyses, description="Analyzing..."):
                try:
                    # Apply rate limiting
                    default_rate_limiter.wait_if_needed()
                    
                    # Execute analysis with retry logic
                    result = self._execute_analysis_safe(analysis_func, address, analysis_name)
                    
                    if result:
                        scan_results["findings"].extend(result.get("findings", []))
                        scan_results["risk_score"] += result.get("risk_points", 0)
                        
                        # Display findings
                        self._display_findings(result.get("findings", []))
                    
                except Exception as e:
                    self.error_aggregator.add_error(e, analysis_name)
                    self.console.print(f"⚠️  [yellow]Warning: {analysis_name} failed: {str(e)}[/yellow]")
                    scan_results["warnings"].append({
                        "analysis": analysis_name,
                        "error": str(e),
                        "timestamp": datetime.now().isoformat()
                    })
            
            # Calculate final risk level
            scan_results["risk_level"] = self._calculate_risk_level(scan_results["risk_score"])
            
            # Add error summary to results
            scan_results["errors"] = [
                {"type": e["type"], "context": e["context"]} 
                for e in self.error_aggregator.errors
            ]
            
            # Display final results and errors
            self._display_summary(scan_results)
            self.error_aggregator.display_summary()
            
            # Cache results if successful
            if not quick_scan and scan_results["risk_level"] != "UNKNOWN":
                cache_contract_result(address, scan_results, ttl=3600)

            return scan_results
            
        except Exception as e:
            self.console.print(f"❌ [bold red]Scan failed: {str(e)}[/bold red]")
            scan_results["error"] = str(e)
            scan_results["error_type"] = type(e).__name__
            return scan_results
    
    def _get_contract_info_safe(self, address: str) -> Dict:
        """Get basic contract information with error handling"""
        try:
            return self._get_contract_info(address)
        except Exception as e:
            self.error_aggregator.add_warning(f"Failed to get contract info: {str(e)}", "contract_info")
            return {
                "name": "Unknown",
                "symbol": "UNKNOWN", 
                "decimals": 18,
                "total_supply": "0",
                "is_verified": False
            }
    
    @with_retry(RetryConfig(max_attempts=3, base_delay=1.0))
    def _get_contract_info(self, address: str) -> Dict:
        """Get basic contract information"""
        # This would typically connect to BSC RPC
        # For now, return placeholder data with some realistic examples
        import random
        
        # Simulate occasional failures for testing
        if random.random() < 0.1:  # 10% chance of failure
            raise ConnectionError("RPC connection timeout")
        
        return {
            "name": "Example Token",
            "symbol": "EXAMPLE", 
            "decimals": 18,
            "total_supply": "1000000000000000000000000",
            "is_verified": True
        }
    
    @with_retry(RetryConfig(max_attempts=2, base_delay=0.5))
    def _execute_analysis_safe(self, analysis_func, address: str, analysis_name: str, **kwargs) -> Dict:
        """Execute analysis function with error handling"""
        try:
            if kwargs:
                return analysis_func(address, **kwargs)
            else:
                return analysis_func(address)
        except Exception as e:
            self.error_aggregator.add_error(e, analysis_name)
            return {
                "findings": [{
                    "type": "analysis_error",
                    "severity": "warning",
                    "message": f"⚠️  {analysis_name} analysis failed",
                    "details": f"Error: {str(e)}"
                }],
                "risk_points": 5  # Small penalty for failed analysis
            }
    
    def _check_verification(self, address: str) -> Dict:
        """Check if contract is verified on BscScan"""
        # Placeholder implementation
        return {
            "findings": [{
                "type": "verification",
                "severity": "info",
                "message": "✅ Contract verified on BscScan",
                "details": "Source code is publicly available"
            }],
            "risk_points": 0
        }
    
    def _check_liquidity(self, address: str) -> Dict:
        """Analyze liquidity and lock status"""
        # Placeholder implementation
        return {
            "findings": [{
                "type": "liquidity",
                "severity": "medium",
                "message": "⚠️  Liquidity lock not detected",
                "details": "Unable to verify liquidity lock status"
            }],
            "risk_points": 15
        }
    
    def _check_holder_distribution(self, address: str) -> Dict:
        """Check token holder distribution for whale concentration"""
        # Placeholder implementation  
        return {
            "findings": [{
                "type": "distribution",
                "severity": "low",
                "message": "✅ Reasonable holder distribution",
                "details": "Top 10 holders control <50% of supply"
            }],
            "risk_points": 5
        }
    
    def _display_findings(self, findings: List[Dict]):
        """Display analysis findings"""
        for finding in findings:
            self.console.print(f"{finding['message']}")
    
    def _calculate_risk_level(self, risk_score: int) -> str:
        """Calculate risk level based on score"""
        if risk_score >= 80:
            return "CRITICAL"
        elif risk_score >= 60:
            return "HIGH" 
        elif risk_score >= 30:
            return "MEDIUM"
        elif risk_score >= 10:
            return "LOW"
        else:
            return "VERY LOW"
    
    def _display_summary(self, scan_results: Dict):
        """Display scan summary"""
        risk_level = scan_results["risk_level"]
        risk_score = scan_results["risk_score"]
        
        # Color code risk level
        color_map = {
            "VERY LOW": "green",
            "LOW": "green", 
            "MEDIUM": "yellow",
            "HIGH": "red",
            "CRITICAL": "bold red"
        }
        
        color = color_map.get(risk_level, "white")
        
        self.console.print(f"\n🎯 [bold]Risk Score:[/bold] [{color}]{risk_level} ({risk_score}/100)[/{color}]")
        self.console.print(f"\n📊 [bold]Summary:[/bold] Found {len(scan_results['findings'])} security findings")
    
    def generate_report(self, scan_results: Dict, output_format: str = "json", output_path: Optional[str] = None) -> str:
        """Generate detailed security report"""
        
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            address_short = scan_results["address"][:8]
            output_path = f"./reports/{address_short}_{timestamp}.{output_format}"
        
        # Ensure reports directory exists
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        
        if output_format == "json":
            with open(output_path, 'w') as f:
                json.dump(scan_results, f, indent=2)
        
        elif output_format == "markdown":
            markdown_content = self._generate_markdown_report(scan_results)
            with open(output_path, 'w') as f:
                f.write(markdown_content)
        
        self.console.print(f"\n📄 [bold green]Report saved:[/bold green] {output_path}")
        return output_path
    
    def _generate_markdown_report(self, scan_results: Dict) -> str:
        """Generate markdown format report"""
        
        md_content = f"""# BSC Security Scan Report

## Contract Information
- **Address**: `{scan_results['address']}`
- **Chain**: {scan_results['chain']}
- **Scan Time**: {scan_results['scan_time']}
- **Token Name**: {scan_results.get('name', 'Unknown')}
- **Symbol**: {scan_results.get('symbol', 'Unknown')}

## Risk Assessment
- **Risk Score**: {scan_results['risk_score']}/100
- **Risk Level**: **{scan_results['risk_level']}**

## Security Findings

"""
        
        for finding in scan_results['findings']:
            severity_emoji = {
                'critical': '🔴',
                'high': '🔴', 
                'medium': '⚠️',
                'low': '✅',
                'info': 'ℹ️'
            }.get(finding['severity'], '❓')
            
            md_content += f"### {severity_emoji} {finding['message']}\n"
            md_content += f"- **Type**: {finding['type']}\n"
            md_content += f"- **Severity**: {finding['severity']}\n"
            md_content += f"- **Details**: {finding['details']}\n\n"
        
        md_content += """
---
*Generated by BSC Security Scanner - Educational purposes only*
"""
        
        return md_content

    def _get_archetype_specific_analyses(self, archetype: str, quick_scan: bool) -> List[Tuple]:
        """Get analyses specific to the token archetype"""
        base_analyses = [("Contract Verification", self._check_verification)]

        if archetype == TokenArchetype.STANDARD_ERC20:
            if not quick_scan:
                return base_analyses + [
                    ("Ownership Analysis", self.ownership_analyzer.analyze),
                    ("Function Analysis", self.function_analyzer.analyze),
                    ("Liquidity Analysis", self._check_liquidity),
                    ("Holder Distribution", self._check_holder_distribution)
                ]
            else:
                return base_analyses + [
                    ("Basic Ownership", self.ownership_analyzer.basic_check),
                    ("Quick Function Scan", self.function_analyzer.quick_scan)
                ]

        elif archetype == TokenArchetype.TAX_FEE_TOKEN:
            if not quick_scan:
                return base_analyses + [
                    ("Ownership Analysis", self.ownership_analyzer.analyze),
                    ("Tax/Fee Mechanisms", self.honeypot_analyzer.analyze),  # Focus on tax analysis
                    ("Function Analysis", self.function_analyzer.analyze),
                    ("Blacklist Detection", self._check_blacklist_mechanisms),
                    ("Liquidity Analysis", self._check_liquidity)
                ]
            else:
                return base_analyses + [
                    ("Basic Ownership", self.ownership_analyzer.basic_check),
                    ("Quick Tax Check", self.honeypot_analyzer._check_tax_mechanisms),
                    ("Quick Function Scan", self.function_analyzer.quick_scan)
                ]

        elif archetype == TokenArchetype.WRAPPER_TOKEN:
            if not quick_scan:
                return base_analyses + [
                    ("Ownership Analysis", self.ownership_analyzer.analyze),
                    ("Function Analysis", self.function_analyzer.analyze),
                    ("Deposit/Withdraw Analysis", self._check_wrapper_mechanisms)
                ]
            else:
                return base_analyses + [
                    ("Basic Ownership", self.ownership_analyzer.basic_check),
                    ("Quick Function Scan", self.function_analyzer.quick_scan)
                ]

        elif archetype == TokenArchetype.DEX_ROUTER or archetype == TokenArchetype.DEX_FACTORY:
            if not quick_scan:
                return base_analyses + [
                    ("Ownership Analysis", self.ownership_analyzer.analyze),
                    ("Function Analysis", self.function_analyzer.analyze),
                    ("DEX Security Analysis", self._check_dex_security)
                ]
            else:
                return base_analyses + [
                    ("Basic Ownership", self.ownership_analyzer.basic_check),
                    ("Quick Function Scan", self.function_analyzer.quick_scan)
                ]

        else:  # Unknown or mixed archetype
            if not quick_scan:
                return base_analyses + [
                    ("Ownership Analysis", self.ownership_analyzer.analyze),
                    ("Honeypot Detection", self.honeypot_analyzer.analyze),
                    ("Function Analysis", self.function_analyzer.analyze),
                    ("Liquidity Analysis", self._check_liquidity),
                    ("Holder Distribution", self._check_holder_distribution)
                ]
            else:
                return base_analyses + [
                    ("Basic Ownership", self.ownership_analyzer.basic_check),
                    ("Quick Function Scan", self.function_analyzer.quick_scan)
                ]

    def _adjust_risk_score_by_archetype(self, base_score: int, archetype: str, confidence_scores: Dict) -> int:
        """Adjust risk score based on archetype context and confidence"""
        adjusted_score = base_score

        # Apply archetype-specific adjustments
        if archetype == TokenArchetype.TAX_FEE_TOKEN:
            # Tax tokens naturally have higher base risk, adjust accordingly
            tax_findings = any('tax' in str(finding).lower() for finding in confidence_scores)
            if not tax_findings:
                adjusted_score = int(base_score * 0.9)  # Slight reduction if no tax issues found

        elif archetype == TokenArchetype.WRAPPER_TOKEN:
            # Wrapper tokens have different risk profile
            adjusted_score = int(base_score * 0.8)  # Generally lower risk

        elif archetype == TokenArchetype.STANDARD_ERC20:
            # Standard tokens should have minimal additional mechanisms
            function_confidence = confidence_scores.get("Function Analysis", 0.5)
            if function_confidence > 0.8:
                adjusted_score = int(base_score * 1.0)  # No adjustment for high confidence
            else:
                adjusted_score = int(base_score * 0.9)  # Slight reduction for lower confidence

        # Apply overall confidence adjustment
        avg_confidence = sum(confidence_scores.values()) / len(confidence_scores) if confidence_scores else 0.5
        confidence_multiplier = 0.7 + (avg_confidence * 0.3)  # Scale from 0.7 to 1.0

        final_score = int(adjusted_score * confidence_multiplier)
        return max(final_score, 0)  # Ensure non-negative

    def _display_findings_with_confidence(self, findings: List[Dict]) -> None:
        """Display findings with confidence indicators"""
        for finding in findings:
            message = finding.get("message", "")
            confidence = finding.get("confidence", 0.5)

            # Add confidence indicator if not already present
            if confidence < 0.4 and "(low confidence)" not in message:
                message += " (low confidence)"
            elif confidence >= 0.8 and "(high confidence)" not in message:
                message += " (high confidence)"

            self.console.print(message)

    def _check_blacklist_mechanisms(self, address: str) -> Dict:
        """Specialized analysis for blacklist mechanisms"""
        # This would be a focused analysis for blacklist functionality
        # For now, delegate to honeypot analyzer
        return self.honeypot_analyzer._check_transfer_restrictions(address)

    def _check_wrapper_mechanisms(self, address: str) -> Dict:
        """Specialized analysis for wrapper token mechanisms"""
        # Placeholder for wrapper-specific analysis
        return {"findings": [], "risk_points": 0, "confidence": 0.7}

    def _check_dex_security(self, address: str) -> Dict:
        """Specialized analysis for DEX security"""
        # Placeholder for DEX-specific analysis
        return {"findings": [], "risk_points": 0, "confidence": 0.7}

    def _scan_with_enhanced_analyzer(self, address: str, quick_scan: bool) -> Dict:
        """
        Scan using the enhanced analyzer with archetype-first approach
        """
        try:
            self.console.print(f"\n🔍 [bold cyan]Enhanced BSC Security Scanner[/bold cyan]")
            self.console.print("=" * 50)
            self.console.print(f"📍 [bold]Address:[/bold] {address}")

            # Run enhanced analysis
            enhanced_results = self.enhanced_analyzer.analyze_contract(address, quick_scan)

            # Display archetype
            archetype_info = enhanced_results["archetype"]
            archetype_display = archetype_info["type"].replace('_', ' ').title()
            confidence_display = f"{archetype_info['confidence']:.1%}"

            if archetype_info["confidence"] >= 0.7:
                self.console.print(f"🔬 [bold green]Token Type:[/bold green] {archetype_display} (confidence: {confidence_display})")
            elif archetype_info["confidence"] >= 0.4:
                self.console.print(f"🔬 [bold yellow]Token Type:[/bold yellow] {archetype_display} (confidence: {confidence_display})")
            else:
                self.console.print(f"🔬 [bold red]Token Type:[/bold red] Unknown/Mixed (confidence: {confidence_display})")

            # Display analysis results
            self.console.print(f"\n🔐 [bold green]Security Analysis Results:[/bold green]")

            # Convert enhanced findings to legacy format for display
            legacy_findings = []
            for finding in enhanced_results["findings"]:
                severity_emoji = {
                    'critical': '🔴',
                    'high': '🔴',
                    'medium': '⚠️',
                    'low': '✅',
                    'info': 'ℹ️'
                }.get(finding['severity'], '❓')

                # Format message with confidence indicator
                message = f"{severity_emoji} {finding['description']}"
                if finding['confidence'] < 0.4:
                    message += " (low confidence)"
                elif finding['confidence'] >= 0.8:
                    message += " (high confidence)"

                legacy_findings.append({
                    "type": finding["type"],
                    "severity": finding["severity"],
                    "message": message,
                    "details": ", ".join(finding["evidence"]) if finding["evidence"] else finding["description"],
                    "confidence": finding["confidence"]
                })

            # Display findings
            self._display_findings_with_confidence(legacy_findings)

            # Display summary
            risk_level = enhanced_results["risk_level"]
            risk_score = enhanced_results["risk_score"]

            self.console.print(f"\n🎯 [bold]Risk Assessment:[/bold]")
            self.console.print(f"📊 Risk Score: {risk_score}/100")

            risk_color = {
                "VERY LOW": "green",
                "LOW": "green",
                "MEDIUM": "yellow",
                "HIGH": "red",
                "CRITICAL": "red"
            }.get(risk_level, "white")

            self.console.print(f"🚨 Risk Level: [{risk_color}]{risk_level}[/{risk_color}]")

            # Convert to legacy format for compatibility
            scan_results = {
                "address": address,
                "scan_time": datetime.now().isoformat(),
                "chain": "Binance Smart Chain (BSC)",
                "quick_scan": quick_scan,
                "findings": legacy_findings,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "archetype": archetype_info,
                "analysis_confidence": enhanced_results["analysis_confidence"],
                "enhanced": True
            }

            # Cache results if successful
            if not quick_scan and risk_level != "UNKNOWN":
                cache_contract_result(address, scan_results, ttl=3600)

            return scan_results

        except Exception as e:
            self.console.print(f"❌ [bold red]Enhanced scan failed: {str(e)}[/bold red]")
            self.console.print("⚠️ [yellow]Falling back to legacy analyzer...[/yellow]")
            # Fall back to legacy analyzer
            self.use_enhanced = False
            return self.scan_contract(address, quick_scan)


def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(
        description="BSC Security Scanner - Analyze BEP-20 tokens for security vulnerabilities",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py --address 0x8076c74c5e3f5852e2f86380b9ca2a2c38acf763
  python scanner.py --address 0x... --output report.json
  python scanner.py --address 0x... --quick
  python scanner.py --batch contracts.txt
        """
    )
    
    parser.add_argument("--address", "-a", help="Contract address to scan")
    parser.add_argument("--batch", "-b", help="File containing list of addresses to scan")
    parser.add_argument("--output", "-o", help="Output file path for report")
    parser.add_argument("--format", "-f", choices=["json", "markdown"], default="json", help="Report format")
    parser.add_argument("--quick", "-q", action="store_true", help="Perform quick scan only")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    scanner = BSCSecurityScanner()
    
    # Validate arguments
    if not args.address and not args.batch:
        parser.error("Must specify either --address or --batch")
    
    try:
        if args.address:
            # Single address scan
            results = scanner.scan_contract(args.address, quick_scan=args.quick)
            
            # Generate report if requested
            if args.output or args.format:
                scanner.generate_report(results, args.format, args.output)
        
        elif args.batch:
            # Batch scan
            scanner.console.print(f"🔍 [bold cyan]Starting batch scan from {args.batch}[/bold cyan]")
            
            try:
                with open(args.batch, 'r') as f:
                    addresses = [line.strip() for line in f if line.strip()]
                
                for i, address in enumerate(addresses, 1):
                    scanner.console.print(f"\n📍 [bold]Scanning {i}/{len(addresses)}:[/bold] {address}")
                    results = scanner.scan_contract(address, quick_scan=args.quick)
                    
                    # Auto-generate reports for batch scans
                    scanner.generate_report(results, args.format)
                    
                    # Rate limiting
                    if i < len(addresses):
                        time.sleep(2)
                        
            except FileNotFoundError:
                scanner.console.print(f"❌ [bold red]Error: Batch file '{args.batch}' not found[/bold red]")
                sys.exit(1)
    
    except KeyboardInterrupt:
        scanner.console.print(f"\n⚡ [yellow]Scan interrupted by user[/yellow]")
        sys.exit(0)
    
    except Exception as e:
        scanner.console.print(f"❌ [bold red]Unexpected error: {str(e)}[/bold red]")
        sys.exit(1)


if __name__ == "__main__":
    main()