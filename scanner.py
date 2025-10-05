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
from reports.report_generator import ReportGenerator
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
        self.report_generator = ReportGenerator()
        
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

    def generate_report(self, scan_results: Dict, output_format: str = "json", output_path: Optional[str] = None) -> str:
        """Generate detailed security report"""
        return self.report_generator.generate_report(scan_results, output_format, output_path)


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