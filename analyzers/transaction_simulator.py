"""
Transaction Simulator - Detects honeypots through buy/sell transaction simulation
Simulates trades on PancakeSwap to detect sell restrictions and tax mismatches
"""

import os
from typing import Dict, Optional
from web3 import Web3
from eth_utils import to_checksum_address
import time

from config import BSC_CONTRACTS, get_rpc_endpoint


# PancakeSwap Router V2 ABI (minimal for swaps)
ROUTER_ABI = [
    {
        "inputs": [
            {"internalType": "uint256", "name": "amountOutMin", "type": "uint256"},
            {"internalType": "address[]", "name": "path", "type": "address[]"},
            {"internalType": "address", "name": "to", "type": "address"},
            {"internalType": "uint256", "name": "deadline", "type": "uint256"}
        ],
        "name": "swapExactETHForTokens",
        "outputs": [{"internalType": "uint256[]", "name": "amounts", "type": "uint256[]"}],
        "stateMutability": "payable",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "uint256", "name": "amountIn", "type": "uint256"},
            {"internalType": "uint256", "name": "amountOutMin", "type": "uint256"},
            {"internalType": "address[]", "name": "path", "type": "address[]"},
            {"internalType": "address", "name": "to", "type": "address"},
            {"internalType": "uint256", "name": "deadline", "type": "uint256"}
        ],
        "name": "swapExactTokensForETH",
        "outputs": [{"internalType": "uint256[]", "name": "amounts", "type": "uint256[]"}],
        "stateMutability": "nonpayable",
        "type": "function"
    }
]

# ERC20 ABI (minimal for approve)
ERC20_ABI = [
    {
        "constant": False,
        "inputs": [
            {"name": "spender", "type": "address"},
            {"name": "value", "type": "uint256"}
        ],
        "name": "approve",
        "outputs": [{"name": "", "type": "bool"}],
        "type": "function"
    },
    {
        "constant": True,
        "inputs": [],
        "name": "decimals",
        "outputs": [{"name": "", "type": "uint8"}],
        "type": "function"
    }
]


class TransactionSimulator:
    """Simulates buy/sell transactions to detect honeypots"""

    def __init__(self, web3: Optional[Web3] = None):
        self.w3 = web3 or Web3(Web3.HTTPProvider(get_rpc_endpoint()))
        self.router_address = to_checksum_address(BSC_CONTRACTS["pancakeswap_router"])
        self.wbnb_address = to_checksum_address(BSC_CONTRACTS["wbnb"])
        self.simulation_address = "0x0000000000000000000000000000000000000001"  # Test address
        self.test_amount_bnb = self.w3.to_wei(0.1, 'ether')  # 0.1 BNB
        self.findings = []

    def simulate_transactions(self, token_address: str, pool_address: Optional[str] = None) -> Dict:
        """
        Main simulation function - tests buy and sell transactions

        Args:
            token_address: Token contract address to test
            pool_address: Optional LP pool address (if known from liquidity analyzer)

        Returns:
            Dictionary with simulation results and findings
        """
        self.findings = []
        token_address = to_checksum_address(token_address)

        # Simulate buy transaction
        buy_result = self._simulate_buy(token_address)

        if not buy_result['success']:
            self._add_finding("critical", "Cannot Buy Token",
                            f"Buy simulation failed: {buy_result['error']}")
            return self._build_result(buy_result, None, is_honeypot=True)

        # Simulate sell transaction
        sell_result = self._simulate_sell(token_address, buy_result['tokens_received'])

        # Analyze results
        is_honeypot, simulation_confidence = self._analyze_simulation_results(buy_result, sell_result)

        return self._build_result(buy_result, sell_result, is_honeypot, simulation_confidence)

    def _simulate_buy(self, token_address: str) -> Dict:
        """Simulate buying tokens with BNB"""
        try:
            router = self.w3.eth.contract(address=self.router_address, abi=ROUTER_ABI)

            path = [self.wbnb_address, token_address]
            deadline = int(time.time()) + 300  # 5 minutes from now

            # Simulate the swap using eth_call (no actual transaction)
            result = router.functions.swapExactETHForTokens(
                0,  # amountOutMin - accept any amount
                path,
                self.simulation_address,
                deadline
            ).call({
                'from': self.simulation_address,
                'value': self.test_amount_bnb,
                'gas': 500000
            })

            tokens_received = result[-1]  # Last element is output amount

            return {
                'success': True,
                'tokens_received': tokens_received,
                'bnb_spent': self.test_amount_bnb,
                'error': None
            }

        except Exception as e:
            error_msg = str(e)
            return {
                'success': False,
                'tokens_received': 0,
                'bnb_spent': self.test_amount_bnb,
                'error': error_msg
            }

    def _simulate_sell(self, token_address: str, token_amount: int) -> Dict:
        """Simulate selling tokens for BNB"""
        try:
            # First, simulate approval
            token_contract = self.w3.eth.contract(address=token_address, abi=ERC20_ABI)

            # Simulate approve call
            token_contract.functions.approve(self.router_address, token_amount).call({
                'from': self.simulation_address
            })

            # Now simulate the sell swap
            router = self.w3.eth.contract(address=self.router_address, abi=ROUTER_ABI)

            path = [token_address, self.wbnb_address]
            deadline = int(time.time()) + 300

            result = router.functions.swapExactTokensForETH(
                token_amount,
                0,  # amountOutMin - accept any amount
                path,
                self.simulation_address,
                deadline
            ).call({
                'from': self.simulation_address,
                'gas': 500000
            })

            bnb_received = result[-1]

            return {
                'success': True,
                'bnb_received': bnb_received,
                'tokens_sold': token_amount,
                'error': None
            }

        except Exception as e:
            error_msg = str(e)
            return {
                'success': False,
                'bnb_received': 0,
                'tokens_sold': token_amount,
                'error': error_msg
            }

    def _analyze_simulation_results(self, buy_result: Dict, sell_result: Dict) -> tuple[bool, float]:
        """Analyze simulation results to detect honeypots"""
        is_honeypot = False
        simulation_confidence = 1.0  # Default high confidence

        # Critical: Sell transaction failed - but check reason
        if not sell_result['success']:
            error_msg = sell_result['error'].lower()

            # Benign errors - these are NOT honeypots, just simulation artifacts
            benign_errors = [
                'transfer_from_failed',
                'transferhelper',
                'insufficient allowance',
                'insufficient balance',
                'transfer amount exceeds balance',
                'erc20: transfer amount exceeds allowance',
                'ds-math-sub-underflow',  # Insufficient balance in different format
            ]

            is_benign = any(benign_err in error_msg for benign_err in benign_errors)

            if is_benign:
                # Not a honeypot - just a simulation limitation (router-level revert)
                is_honeypot = False  # Explicitly set to false
                simulation_confidence = 0.3  # Low confidence in this simulation
                self._add_finding("info", "Simulation Error",
                                f"Sell reverted due to missing allowance/balance, not a honeypot. This is expected in simulation. Error: {sell_result['error'][:100]}")
            else:
                # Check for actual token-level restrictions (true honeypots)
                honeypot_indicators = [
                    'tradingpaused',
                    'trading not enabled',
                    'selllimitexceeded',
                    'sell limit exceeded',
                    'max_tx',
                    'maxtx',
                    'onlyowner',
                    'transfer paused',
                    'blacklisted',
                    'cooldown',
                    'cannot sell',
                    'sell not allowed',
                    'trading is not enabled',
                    'transfers are disabled'
                ]

                is_true_honeypot = any(indicator in error_msg for indicator in honeypot_indicators)

                if is_true_honeypot:
                    is_honeypot = True
                    self._add_finding("critical", "HONEYPOT DETECTED - Sell Restricted",
                                    f"Token contract prevents selling: {sell_result['error'][:150]}")
                else:
                    # Unknown error - do NOT flag as honeypot, just warn
                    is_honeypot = False  # Explicitly set to false - innocent until proven guilty
                    simulation_confidence = 0.5
                    self._add_finding("medium", "Sell Simulation Failed - Unknown Error",
                                    f"Sell failed with uncertain error. Likely a simulation artifact, not necessarily a honeypot. Error: {sell_result['error'][:150]}")

            return is_honeypot, simulation_confidence

        # Calculate actual taxes
        buy_tax = self._calculate_buy_tax(buy_result)
        sell_tax = self._calculate_sell_tax(buy_result, sell_result)

        # Check for excessive sell tax
        if sell_tax > 50:
            is_honeypot = True
            self._add_finding("critical", "HONEYPOT - Excessive Sell Tax",
                            f"Sell tax is {sell_tax:.1f}% - cannot profitably sell")

        # Check for tax asymmetry
        tax_difference = abs(sell_tax - buy_tax)
        if tax_difference > 20:
            is_honeypot = True
            self._add_finding("critical", "HONEYPOT - Asymmetric Taxes",
                            f"Buy tax: {buy_tax:.1f}%, Sell tax: {sell_tax:.1f}% - difference: {tax_difference:.1f}%")
        elif tax_difference > 10:
            self._add_finding("high", "Tax Mismatch Detected",
                            f"Buy: {buy_tax:.1f}%, Sell: {sell_tax:.1f}% - {tax_difference:.1f}% difference")

        # Info: Report calculated taxes
        if buy_tax > 0 or sell_tax > 0:
            self._add_finding("info", "Transaction Taxes",
                            f"Buy tax: {buy_tax:.1f}%, Sell tax: {sell_tax:.1f}%")

        # Check slippage/impact
        slippage = self._calculate_slippage(buy_result, sell_result)
        if slippage > 30:
            self._add_finding("medium", "High Slippage Detected",
                            f"Round-trip slippage: {slippage:.1f}% - low liquidity or high fees")

        return is_honeypot, simulation_confidence

    def _calculate_buy_tax(self, buy_result: Dict) -> float:
        """Calculate effective buy tax percentage"""
        # This is simplified - ideally we'd calculate expected tokens based on pool reserves
        # For now, we'll return 0 as we need pool data for accurate calculation
        # This will be improved when integrated with liquidity analyzer
        return 0.0

    def _calculate_sell_tax(self, buy_result: Dict, sell_result: Dict) -> float:
        """Calculate effective sell tax percentage"""
        bnb_spent = buy_result['bnb_spent']
        bnb_received = sell_result['bnb_received']

        if bnb_spent == 0:
            return 0.0

        # Calculate loss percentage (includes slippage + taxes + fees)
        loss_percent = ((bnb_spent - bnb_received) / bnb_spent) * 100

        # Assume 0.25% DEX fee each way = 0.5% total
        dex_fees = 0.5

        # Tax is approximately loss - DEX fees (simplified)
        tax_estimate = max(0, loss_percent - dex_fees)

        return tax_estimate

    def _calculate_slippage(self, buy_result: Dict, sell_result: Dict) -> float:
        """Calculate round-trip slippage percentage"""
        bnb_spent = buy_result['bnb_spent']
        bnb_received = sell_result['bnb_received']

        if bnb_spent == 0:
            return 0.0

        slippage = ((bnb_spent - bnb_received) / bnb_spent) * 100
        return slippage

    def _add_finding(self, severity: str, message: str, details: str):
        """Add a finding to the results"""
        self.findings.append({
            "severity": severity,
            "message": message,
            "details": details
        })

    def _build_result(self, buy_result: Dict, sell_result: Optional[Dict], is_honeypot: bool, simulation_confidence: float = 1.0) -> Dict:
        """Build the final simulation result"""
        return {
            "findings": self.findings,
            "is_honeypot": is_honeypot,
            "simulation_confidence": simulation_confidence,
            "simulation_results": {
                "buy": {
                    "success": buy_result['success'],
                    "tokens_received": buy_result.get('tokens_received', 0),
                    "error": buy_result.get('error')
                },
                "sell": {
                    "success": sell_result['success'] if sell_result else False,
                    "bnb_received": sell_result.get('bnb_received', 0) if sell_result else 0,
                    "error": sell_result.get('error') if sell_result else "Sell not attempted"
                } if sell_result else None
            }
        }

    def calculate_risk_adjustment(self, is_honeypot: bool, findings: list) -> int:
        """Calculate risk score adjustment based on simulation results"""
        risk_adjustment = 0

        if is_honeypot:
            risk_adjustment += 40  # Critical risk

        # Check for high severity findings
        for finding in findings:
            if finding['severity'] == 'high' and 'mismatch' in finding['message'].lower():
                risk_adjustment += 15

        return risk_adjustment
