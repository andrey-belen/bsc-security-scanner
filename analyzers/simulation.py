"""
Buy/Sell Simulation for Honeypot Detection
Performs actual transaction simulation on forked BSC node
"""

import time
import json
from typing import Dict, List, Optional, Tuple
from web3 import Web3
try:
    from web3.middleware import geth_poa_middleware
except ImportError:
    from web3.middleware import ExtraDataToPOAMiddleware as geth_poa_middleware
from eth_account import Account

from config import BSC_CONFIG, BSC_CONTRACTS, get_rpc_endpoint
from .enhanced_archetype import Finding, TokenArchetype


class TransactionSimulator:
    """Simulate buy/sell transactions to detect honeypots"""

    def __init__(self, fork_url: Optional[str] = None):
        """
        Initialize simulator with optional fork URL

        Args:
            fork_url: Hardhat/Tenderly fork URL for simulation
        """
        self.fork_url = fork_url or get_rpc_endpoint()
        self.w3 = Web3(Web3.HTTPProvider(self.fork_url))
        self.w3.middleware_onion.inject(geth_poa_middleware, layer=0)

        # PancakeSwap router for swaps
        self.router_address = BSC_CONTRACTS["pancakeswap_router"]
        self.wbnb_address = BSC_CONTRACTS["wbnb"]

        # Simulation account (funded in fork)
        self.sim_account = Account.create()

        # Router ABI for swaps
        self.router_abi = self._get_router_abi()

    def simulate_buy_sell(self, token_address: str, archetype: str) -> Dict:
        """
        Simulate buy and sell transactions to detect honeypots

        Args:
            token_address: Token contract address
            archetype: Token archetype (skip simulation for stablecoins/wrappers)

        Returns:
            Simulation results with findings
        """
        findings = []

        # Skip simulation for stablecoins and wrappers
        if archetype in [TokenArchetype.STABLECOIN, TokenArchetype.WRAPPER_TOKEN]:
            return {
                "findings": [],
                "confidence": 1.0,
                "skipped": True,
                "reason": f"Simulation skipped for {archetype}"
            }

        try:
            # Setup simulation environment
            self._setup_simulation_account()

            # Get initial balances
            initial_bnb = self.w3.eth.get_balance(self.sim_account.address)
            initial_tokens = self._get_token_balance(token_address, self.sim_account.address)

            # Perform buy transaction
            buy_result = self._simulate_buy(token_address, 0.01)  # 0.01 BNB

            if not buy_result["success"]:
                findings.append(Finding(
                    id="buy_failed",
                    severity="medium",
                    type="transaction_failure",
                    description="Buy transaction failed",
                    evidence=[buy_result.get("error", "Unknown error")],
                    confidence=0.8
                ))
                return {"findings": findings, "confidence": 0.8}

            # Get tokens received
            tokens_received = self._get_token_balance(token_address, self.sim_account.address) - initial_tokens

            if tokens_received <= 0:
                findings.append(Finding(
                    id="no_tokens_received",
                    severity="critical",
                    type="honeypot",
                    description="Buy succeeded but no tokens received",
                    evidence=["Token balance unchanged after buy"],
                    confidence=0.95
                ))
                return {"findings": findings, "confidence": 0.95}

            # Wait a bit to simulate real trading
            time.sleep(1)

            # Perform sell transaction
            sell_result = self._simulate_sell(token_address, tokens_received)

            if not sell_result["success"]:
                # Check if it's a revert or just failed
                if "revert" in sell_result.get("error", "").lower():
                    findings.append(Finding(
                        id="sell_reverted",
                        severity="critical",
                        type="honeypot",
                        description="Sell transaction reverted - potential honeypot",
                        evidence=[sell_result.get("error", "")],
                        confidence=0.95
                    ))
                else:
                    findings.append(Finding(
                        id="sell_failed",
                        severity="high",
                        type="transaction_failure",
                        description="Sell transaction failed",
                        evidence=[sell_result.get("error", "")],
                        confidence=0.7
                    ))
                return {"findings": findings, "confidence": 0.9}

            # Calculate sell results
            final_bnb = self.w3.eth.get_balance(self.sim_account.address)
            bnb_received = final_bnb - (initial_bnb - int(0.01 * 10**18))  # Subtract buy amount

            # Calculate effective fee
            bnb_spent = int(0.01 * 10**18)
            if bnb_received > 0:
                effective_fee_percent = ((bnb_spent - bnb_received) / bnb_spent) * 100

                if effective_fee_percent > 20:
                    findings.append(Finding(
                        id="excessive_tax",
                        severity="high",
                        type="excessive_tax",
                        description=f"Excessive tax detected: {effective_fee_percent:.1f}%",
                        evidence=[f"Buy: {bnb_spent/10**18:.4f} BNB, Received back: {bnb_received/10**18:.4f} BNB"],
                        confidence=0.9
                    ))
                elif effective_fee_percent > 10:
                    findings.append(Finding(
                        id="high_tax",
                        severity="medium",
                        type="high_tax",
                        description=f"High tax detected: {effective_fee_percent:.1f}%",
                        evidence=[f"Buy: {bnb_spent/10**18:.4f} BNB, Received back: {bnb_received/10**18:.4f} BNB"],
                        confidence=0.8
                    ))
                else:
                    findings.append(Finding(
                        id="trading_works",
                        severity="info",
                        type="legitimate_trading",
                        description=f"Buy/sell simulation successful, tax: {effective_fee_percent:.1f}%",
                        evidence=["Both buy and sell transactions completed successfully"],
                        confidence=0.9
                    ))

            return {
                "findings": findings,
                "confidence": 0.9,
                "simulation_data": {
                    "buy_success": buy_result["success"],
                    "sell_success": sell_result["success"],
                    "tokens_received": tokens_received,
                    "bnb_recovered": bnb_received,
                    "effective_fee_percent": effective_fee_percent if bnb_received > 0 else None
                }
            }

        except Exception as e:
            findings.append(Finding(
                id="simulation_error",
                severity="warning",
                type="simulation_error",
                description=f"Simulation failed: {str(e)}",
                evidence=[str(e)],
                confidence=0.3
            ))
            return {"findings": findings, "confidence": 0.3}

    def _setup_simulation_account(self):
        """Setup simulation account with BNB for testing"""
        # In a real fork environment, this would fund the account
        # For now, assume the account is pre-funded
        pass

    def _simulate_buy(self, token_address: str, bnb_amount: float) -> Dict:
        """Simulate buying tokens with BNB"""
        try:
            router_contract = self.w3.eth.contract(
                address=self.router_address,
                abi=self.router_abi
            )

            # Calculate minimum tokens out (with 5% slippage)
            amounts_out = router_contract.functions.getAmountsOut(
                int(bnb_amount * 10**18),
                [self.wbnb_address, token_address]
            ).call()

            min_tokens_out = int(amounts_out[1] * 0.95)  # 5% slippage

            # Build swap transaction
            swap_tx = router_contract.functions.swapExactETHForTokens(
                min_tokens_out,
                [self.wbnb_address, token_address],
                self.sim_account.address,
                int(time.time()) + 300  # 5 minutes deadline
            ).build_transaction({
                'from': self.sim_account.address,
                'value': int(bnb_amount * 10**18),
                'gas': 300000,
                'gasPrice': self.w3.to_wei('5', 'gwei'),
                'nonce': self.w3.eth.get_transaction_count(self.sim_account.address)
            })

            # Sign and send transaction
            signed_tx = self.w3.eth.account.sign_transaction(swap_tx, self.sim_account.key)
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)

            # Wait for confirmation
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=30)

            return {
                "success": receipt.status == 1,
                "tx_hash": tx_hash.hex(),
                "gas_used": receipt.gasUsed
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def _simulate_sell(self, token_address: str, token_amount: int) -> Dict:
        """Simulate selling tokens for BNB"""
        try:
            router_contract = self.w3.eth.contract(
                address=self.router_address,
                abi=self.router_abi
            )

            # First approve router to spend tokens
            token_contract = self.w3.eth.contract(
                address=token_address,
                abi=self._get_erc20_abi()
            )

            approve_tx = token_contract.functions.approve(
                self.router_address,
                token_amount
            ).build_transaction({
                'from': self.sim_account.address,
                'gas': 100000,
                'gasPrice': self.w3.to_wei('5', 'gwei'),
                'nonce': self.w3.eth.get_transaction_count(self.sim_account.address)
            })

            signed_approve = self.w3.eth.account.sign_transaction(approve_tx, self.sim_account.key)
            approve_hash = self.w3.eth.send_raw_transaction(signed_approve.rawTransaction)
            self.w3.eth.wait_for_transaction_receipt(approve_hash, timeout=30)

            # Calculate minimum BNB out
            amounts_out = router_contract.functions.getAmountsOut(
                token_amount,
                [token_address, self.wbnb_address]
            ).call()

            min_bnb_out = int(amounts_out[1] * 0.95)  # 5% slippage

            # Build sell transaction
            sell_tx = router_contract.functions.swapExactTokensForETH(
                token_amount,
                min_bnb_out,
                [token_address, self.wbnb_address],
                self.sim_account.address,
                int(time.time()) + 300
            ).build_transaction({
                'from': self.sim_account.address,
                'gas': 300000,
                'gasPrice': self.w3.to_wei('5', 'gwei'),
                'nonce': self.w3.eth.get_transaction_count(self.sim_account.address)
            })

            # Sign and send transaction
            signed_tx = self.w3.eth.account.sign_transaction(sell_tx, self.sim_account.key)
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)

            # Wait for confirmation
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=30)

            return {
                "success": receipt.status == 1,
                "tx_hash": tx_hash.hex(),
                "gas_used": receipt.gasUsed
            }

        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def _get_token_balance(self, token_address: str, account: str) -> int:
        """Get token balance for account"""
        try:
            token_contract = self.w3.eth.contract(
                address=token_address,
                abi=self._get_erc20_abi()
            )
            return token_contract.functions.balanceOf(account).call()
        except:
            return 0

    def _get_router_abi(self) -> List:
        """Get PancakeSwap router ABI"""
        return [
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
            },
            {
                "inputs": [
                    {"internalType": "uint256", "name": "amountIn", "type": "uint256"},
                    {"internalType": "address[]", "name": "path", "type": "address[]"}
                ],
                "name": "getAmountsOut",
                "outputs": [{"internalType": "uint256[]", "name": "amounts", "type": "uint256[]"}],
                "stateMutability": "view",
                "type": "function"
            }
        ]

    def _get_erc20_abi(self) -> List:
        """Get basic ERC20 ABI"""
        return [
            {
                "inputs": [{"internalType": "address", "name": "account", "type": "address"}],
                "name": "balanceOf",
                "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
                "stateMutability": "view",
                "type": "function"
            },
            {
                "inputs": [
                    {"internalType": "address", "name": "spender", "type": "address"},
                    {"internalType": "uint256", "name": "amount", "type": "uint256"}
                ],
                "name": "approve",
                "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
                "stateMutability": "nonpayable",
                "type": "function"
            }
        ]


def detect_wrapper_reentrancy(source_code: str) -> Dict:
    """
    Analyze wrapper tokens for reentrancy vulnerabilities
    Check withdraw function order: state update before external call
    """
    findings = []

    if not source_code:
        return {"findings": findings, "confidence": 0.0}

    # Look for withdraw function
    withdraw_pattern = r"function\s+withdraw\s*\([^)]*\)\s+[^{]*\{([^}]+)\}"
    withdraw_matches = re.finditer(withdraw_pattern, source_code, re.IGNORECASE | re.DOTALL)

    for match in withdraw_matches:
        withdraw_body = match.group(1)

        # Check for state updates and external calls
        balance_update = re.search(r"balanceOf\[.*?\]\s*[-=]", withdraw_body)
        external_call = re.search(r"msg\.sender\.(transfer|call|send)", withdraw_body)

        if balance_update and external_call:
            # Check order - balance update should come before external call
            balance_pos = balance_update.start()
            call_pos = external_call.start()

            if call_pos < balance_pos:
                findings.append(Finding(
                    id="reentrancy_vulnerability",
                    severity="critical",
                    type="reentrancy",
                    description="Potential reentrancy in withdraw function - external call before state update",
                    evidence=[match.group(0)],
                    confidence=0.9
                ))
            else:
                findings.append(Finding(
                    id="safe_withdraw_pattern",
                    severity="info",
                    type="safe_pattern",
                    description="Withdraw function follows safe pattern - state update before external call",
                    evidence=["Correct order: state update then external call"],
                    confidence=0.8
                ))

    confidence = 0.8 if findings else 0.5
    return {"findings": findings, "confidence": confidence}