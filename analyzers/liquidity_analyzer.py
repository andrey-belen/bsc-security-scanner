"""
Liquidity Pool Analyzer - Detects rug pull risks through LP token analysis
Analyzes liquidity locks, burns, and pool depth across major BSC DEXs
"""

import os
from typing import Dict, List, Optional, Tuple
from web3 import Web3
from eth_utils import to_checksum_address

from config import DEX_FACTORIES, LOCK_CONTRACTS, SPECIAL_ADDRESSES, BSC_CONTRACTS, get_rpc_endpoint


# Minimal ABIs for required functions
FACTORY_ABI = [
    {
        "constant": True,
        "inputs": [{"name": "tokenA", "type": "address"}, {"name": "tokenB", "type": "address"}],
        "name": "getPair",
        "outputs": [{"name": "pair", "type": "address"}],
        "type": "function"
    }
]

LP_TOKEN_ABI = [
    {
        "constant": True,
        "inputs": [],
        "name": "totalSupply",
        "outputs": [{"name": "", "type": "uint256"}],
        "type": "function"
    },
    {
        "constant": True,
        "inputs": [{"name": "owner", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"name": "", "type": "uint256"}],
        "type": "function"
    },
    {
        "constant": True,
        "inputs": [],
        "name": "getReserves",
        "outputs": [
            {"name": "reserve0", "type": "uint112"},
            {"name": "reserve1", "type": "uint112"},
            {"name": "blockTimestampLast", "type": "uint32"}
        ],
        "type": "function"
    },
    {
        "constant": True,
        "inputs": [],
        "name": "token0",
        "outputs": [{"name": "", "type": "address"}],
        "type": "function"
    },
    {
        "constant": True,
        "inputs": [],
        "name": "token1",
        "outputs": [{"name": "", "type": "address"}],
        "type": "function"
    }
]


class LiquidityPoolAnalyzer:
    """Analyzes liquidity pool security for rug pull detection"""

    def __init__(self, web3: Optional[Web3] = None):
        self.w3 = web3 or Web3(Web3.HTTPProvider(get_rpc_endpoint()))
        self.wbnb_address = to_checksum_address(BSC_CONTRACTS["wbnb"])
        self.findings = []
        self.pools_found = []
        self.token_symbol = ""
        self.token_name = ""

    def analyze_liquidity(self, token_address: str, token_symbol: str = "", token_name: str = "") -> Dict:
        """
        Main analysis function - discovers pools and analyzes LP token security

        Args:
            token_address: Token contract address to analyze
            token_symbol: Token symbol (for context-aware analysis)
            token_name: Token name (for context-aware analysis)

        Returns:
            Dictionary with liquidity findings and metrics
        """
        self.findings = []
        self.pools_found = []
        self.token_symbol = token_symbol.upper()
        self.token_name = token_name.lower()

        token_address = to_checksum_address(token_address)

        # Discover liquidity pools across DEXs
        pools = self._discover_pools(token_address)

        if not pools:
            self._add_finding("high", "No Liquidity Pools Found",
                            "No liquidity detected on major DEXs - cannot trade or high rug pull risk")
            return self._build_result(0, 0, 0, 0)

        # Analyze each pool
        total_liquidity_usd = 0
        total_lp_burned = 0
        total_lp_locked = 0
        total_lp_unlocked = 0
        lock_details = []

        for pool_info in pools:
            lp_analysis = self._analyze_lp_tokens(pool_info)

            total_liquidity_usd += lp_analysis.get('liquidity_usd', 0)
            total_lp_burned += lp_analysis.get('burned_percent', 0)
            total_lp_locked += lp_analysis.get('locked_percent', 0)
            total_lp_unlocked += lp_analysis.get('unlocked_percent', 0)

            if lp_analysis.get('lock_info'):
                lock_details.extend(lp_analysis['lock_info'])

        # Calculate averages
        num_pools = len(pools)
        avg_burned = total_lp_burned / num_pools if num_pools > 0 else 0
        avg_locked = total_lp_locked / num_pools if num_pools > 0 else 0
        avg_unlocked = total_lp_unlocked / num_pools if num_pools > 0 else 0

        # Generate findings based on metrics
        self._generate_liquidity_findings(total_liquidity_usd, avg_burned, avg_locked, avg_unlocked, lock_details, num_pools)

        return self._build_result(total_liquidity_usd, avg_burned, avg_locked, avg_unlocked, lock_details)

    def _discover_pools(self, token_address: str) -> List[Dict]:
        """Discover liquidity pools across major DEXs"""
        pools = []

        for dex_name, factory_address in DEX_FACTORIES.items():
            try:
                factory = self.w3.eth.contract(
                    address=to_checksum_address(factory_address),
                    abi=FACTORY_ABI
                )

                # Get pair address for TOKEN/WBNB
                pair_address = factory.functions.getPair(token_address, self.wbnb_address).call()

                # Check if pair exists (not zero address)
                if pair_address != "0x0000000000000000000000000000000000000000":
                    pair_address = to_checksum_address(pair_address)

                    # Get pool reserves
                    pair_contract = self.w3.eth.contract(address=pair_address, abi=LP_TOKEN_ABI)
                    reserves = pair_contract.functions.getReserves().call()
                    token0 = pair_contract.functions.token0().call()
                    token1 = pair_contract.functions.token1().call()

                    # Determine which reserve is BNB
                    if token0.lower() == self.wbnb_address.lower():
                        bnb_reserve = reserves[0]
                        token_reserve = reserves[1]
                    else:
                        bnb_reserve = reserves[1]
                        token_reserve = reserves[0]

                    pools.append({
                        'dex': dex_name,
                        'pair_address': pair_address,
                        'bnb_reserve': bnb_reserve,
                        'token_reserve': token_reserve
                    })

                    self.pools_found.append(f"{dex_name}: {pair_address}")

            except Exception as e:
                # Pool doesn't exist on this DEX or error querying
                continue

        return pools

    def _analyze_lp_tokens(self, pool_info: Dict) -> Dict:
        """Analyze LP token distribution (burned, locked, unlocked)"""
        pair_address = pool_info['pair_address']

        try:
            lp_contract = self.w3.eth.contract(address=pair_address, abi=LP_TOKEN_ABI)
            total_supply = lp_contract.functions.totalSupply().call()

            if total_supply == 0:
                return {'burned_percent': 0, 'locked_percent': 0, 'unlocked_percent': 100}

            # Check burned LP tokens
            burned_balance = 0
            for burn_addr in [SPECIAL_ADDRESSES['burn_dead'], SPECIAL_ADDRESSES['burn_zero']]:
                try:
                    balance = lp_contract.functions.balanceOf(to_checksum_address(burn_addr)).call()
                    burned_balance += balance
                except:
                    continue

            # Check locked LP tokens
            locked_balance = 0
            lock_info = []
            for lock_name, lock_addr in LOCK_CONTRACTS.items():
                if lock_addr == "0x0000000000000000000000000000000000000000":
                    continue  # Skip placeholder
                try:
                    balance = lp_contract.functions.balanceOf(to_checksum_address(lock_addr)).call()
                    if balance > 0:
                        locked_balance += balance
                        lock_info.append({
                            'platform': lock_name,
                            'amount': balance,
                            'percent': (balance / total_supply) * 100
                        })
                except:
                    continue

            # Calculate percentages
            burned_percent = (burned_balance / total_supply) * 100
            locked_percent = (locked_balance / total_supply) * 100
            unlocked_percent = 100 - burned_percent - locked_percent

            # Estimate liquidity in USD (simplified - using BNB reserve * 2)
            bnb_reserve_ether = self.w3.from_wei(pool_info['bnb_reserve'], 'ether')
            # Assume BNB ~$300 (this should ideally use a price oracle)
            liquidity_usd = float(bnb_reserve_ether) * 2 * 300

            return {
                'liquidity_usd': liquidity_usd,
                'burned_percent': burned_percent,
                'locked_percent': locked_percent,
                'unlocked_percent': unlocked_percent,
                'lock_info': lock_info
            }

        except Exception as e:
            return {'burned_percent': 0, 'locked_percent': 0, 'unlocked_percent': 100}

    def _generate_liquidity_findings(self, liquidity_usd: float, burned_pct: float,
                                     locked_pct: float, unlocked_pct: float, lock_details: List, num_pools: int):
        """Generate security findings based on liquidity metrics"""

        # Check if this is a known stablecoin or major infrastructure token
        known_major_tokens = ["BUSD", "USDT", "USDC", "DAI", "WBNB", "BNB", "ETH", "BTCB"]
        is_major_token = self.token_symbol in known_major_tokens or "wrapped" in self.token_name

        # Low liquidity warning
        if liquidity_usd < 10000:
            self._add_finding("high", "Low Liquidity Pool",
                            f"Total liquidity only ${liquidity_usd:,.0f} - difficult to exit positions")
        elif liquidity_usd < 50000:
            self._add_finding("medium", "Moderate Liquidity",
                            f"Liquidity: ${liquidity_usd:,.0f} - be cautious with large trades")
        else:
            self._add_finding("info", "Healthy Liquidity",
                            f"Total liquidity: ${liquidity_usd:,.0f}")

        # LP Token security analysis
        if burned_pct > 50:
            self._add_finding("info", "LP Tokens Burned",
                            f"{burned_pct:.1f}% of LP tokens burned - excellent security",
                            positive=True)

        if locked_pct > 50:
            if lock_details:
                lock_platforms = ", ".join([f"{l['platform']} ({l['percent']:.1f}%)" for l in lock_details])
                self._add_finding("info", "LP Tokens Locked",
                                f"{locked_pct:.1f}% locked in: {lock_platforms}",
                                positive=True)
            else:
                self._add_finding("info", "LP Tokens Locked",
                                f"{locked_pct:.1f}% locked - good security",
                                positive=True)

        # LP Unlock analysis - skip for major tokens and tokens with many pools
        skip_lp_unlock_check = is_major_token or num_pools > 3

        if skip_lp_unlock_check:
            if num_pools > 3:
                self._add_finding("info", f"Liquidity Diversity: {num_pools} pools found",
                                f"Liquidity spread across multiple DEXes - third-party managed pools (LP lock check not applicable)",
                                positive=True)
            else:
                self._add_finding("info", f"Major Infrastructure Token: {self.token_symbol}",
                                f"This is a widely-used token with third-party managed liquidity (LP lock check not applicable)",
                                positive=True)
        else:
            # Regular tokens - check LP unlock status
            if unlocked_pct > 80:
                self._add_finding("critical", "LP Tokens Unlocked - RUG PULL RISK",
                                f"{unlocked_pct:.1f}% of LP tokens are unlocked and can be withdrawn by deployer")
            elif unlocked_pct > 50:
                self._add_finding("high", "Majority of LP Unlocked",
                                f"{unlocked_pct:.1f}% unlocked - moderate rug pull risk")
            elif unlocked_pct > 20:
                self._add_finding("medium", "Some LP Unlocked",
                                f"{unlocked_pct:.1f}% unlocked - minor risk")

    def _add_finding(self, severity: str, message: str, details: str, positive: bool = False):
        """Add a finding to the results"""
        self.findings.append({
            "severity": severity,
            "message": message,
            "details": details,
            "positive": positive
        })

    def _build_result(self, liquidity_usd: float, burned_pct: float,
                     locked_pct: float, unlocked_pct: float, lock_details: List = None) -> Dict:
        """Build the final analysis result"""
        return {
            "findings": self.findings,
            "metrics": {
                "total_liquidity_usd": liquidity_usd,
                "lp_burned_percent": burned_pct,
                "lp_locked_percent": locked_pct,
                "lp_unlocked_percent": unlocked_pct,
                "pools_found": len(self.pools_found),
                "lock_details": lock_details or []
            },
            "pools": self.pools_found
        }

    def calculate_risk_adjustment(self, metrics: Dict, token_symbol: str = "", num_pools: int = 0) -> int:
        """Calculate risk score adjustment based on liquidity analysis"""
        risk_adjustment = 0

        burned_pct = metrics.get('lp_burned_percent', 0)
        locked_pct = metrics.get('lp_locked_percent', 0)
        unlocked_pct = metrics.get('lp_unlocked_percent', 0)
        liquidity_usd = metrics.get('total_liquidity_usd', 0)
        pools_found = num_pools or metrics.get('pools_found', 0)

        # Check if major token or high liquidity diversity
        known_major_tokens = ["BUSD", "USDT", "USDC", "DAI", "WBNB", "BNB", "ETH", "BTCB"]
        is_major_token = token_symbol.upper() in known_major_tokens
        skip_lp_scoring = is_major_token or pools_found > 3

        # Positive factors (reduce risk)
        if burned_pct > 50:
            risk_adjustment -= 20  # Excellent security
        elif burned_pct > 25:
            risk_adjustment -= 10  # Good security

        if locked_pct > 50:
            risk_adjustment -= 15  # Good security
        elif locked_pct > 25:
            risk_adjustment -= 8  # Moderate security

        # Liquidity diversity bonus
        if pools_found > 3:
            risk_adjustment -= 10  # Multiple pools reduce centralization risk

        # Negative factors (increase risk) - but skip for major tokens
        if not skip_lp_scoring:
            if unlocked_pct > 80:
                risk_adjustment += 20  # High rug pull risk
            elif unlocked_pct > 50:
                risk_adjustment += 10  # Moderate risk

        if liquidity_usd < 10000:
            risk_adjustment += 10  # Low liquidity risk
        elif liquidity_usd < 50000:
            risk_adjustment += 5  # Moderate liquidity

        return risk_adjustment
