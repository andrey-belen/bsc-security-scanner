"""
Holder Distribution Analyzer - Detects whale concentration and pump & dump risks
Analyzes token holder distribution to identify centralization risks
"""

import os
import requests
from typing import Dict, List, Optional
from web3 import Web3
from eth_utils import to_checksum_address

from config import SPECIAL_ADDRESSES, LOCK_CONTRACTS, BSC_CONTRACTS, get_rpc_endpoint, get_bscscan_api_key


# ERC20 ABI for balance queries
ERC20_ABI = [
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
    }
]


class HolderDistributionAnalyzer:
    """Analyzes token holder distribution for centralization risks"""

    def __init__(self, web3: Optional[Web3] = None):
        self.w3 = web3 or Web3(Web3.HTTPProvider(get_rpc_endpoint()))
        self.api_key = get_bscscan_api_key()
        self.findings = []

    def analyze_holders(self, token_address: str, deployer_address: Optional[str] = None,
                       owner_address: Optional[str] = None, lp_pools: Optional[List[str]] = None) -> Dict:
        """
        Main analysis function - retrieves and analyzes holder distribution

        Args:
            token_address: Token contract address to analyze
            deployer_address: Contract deployer address (if known)
            owner_address: Contract owner address (if known)
            lp_pools: List of LP pool addresses to label correctly

        Returns:
            Dictionary with holder distribution findings and metrics
        """
        self.findings = []
        token_address = to_checksum_address(token_address)

        # Get total supply
        total_supply = self._get_total_supply(token_address)
        if total_supply == 0:
            self._add_finding("high", "Zero Total Supply",
                            "Token has no supply - unusual and potentially problematic")
            return self._build_result([], 0, 0, 0, 0)

        # Get top holders
        holders = self._get_top_holders(token_address)

        if not holders:
            # No penalty for missing holder data - API timeout or unavailable
            self._add_finding("info", "Holder Data Unavailable",
                            "Unable to fetch holder information from BSCScan API (timeout or unavailable). No risk penalty applied.")
            return self._build_result([], 0, 0, 0, total_supply)

        # Label special addresses
        labeled_holders = self._label_holders(holders, deployer_address, owner_address, lp_pools or [])

        # Calculate circulating supply (excluding burn addresses)
        circulating_supply = self._calculate_circulating_supply(labeled_holders, total_supply)

        # Calculate holder percentages based on circulating supply
        for holder in labeled_holders:
            holder['percentage'] = (holder['balance'] / circulating_supply) * 100 if circulating_supply > 0 else 0

        # Calculate concentration metrics
        metrics = self._calculate_concentration_metrics(labeled_holders)

        # Generate findings
        self._generate_holder_findings(metrics, labeled_holders)

        return self._build_result(labeled_holders[:10], metrics['top_10_pct'], metrics['whale_count'],
                                 len(holders), circulating_supply)

    def _get_total_supply(self, token_address: str) -> int:
        """Get token total supply"""
        try:
            contract = self.w3.eth.contract(address=token_address, abi=ERC20_ABI)
            return contract.functions.totalSupply().call()
        except:
            return 0

    def _get_top_holders(self, token_address: str) -> List[Dict]:
        """Retrieve top token holders from BSCScan API"""
        try:
            url = "https://api.bscscan.com/api"
            params = {
                "module": "token",
                "action": "tokenholderlist",
                "contractaddress": token_address,
                "page": 1,
                "offset": 50,  # Top 50 holders
                "apikey": self.api_key
            }

            response = requests.get(url, params=params, timeout=10)
            data = response.json()

            if data.get("status") == "1" and data.get("result"):
                holders = []
                for h in data["result"]:
                    holders.append({
                        'address': to_checksum_address(h['TokenHolderAddress']),
                        'balance': int(h['TokenHolderQuantity']),
                        'label': 'Holder'
                    })
                return holders
            else:
                # API failed, fall back to empty list
                return []

        except Exception as e:
            # Fallback: return empty list
            return []

    def _label_holders(self, holders: List[Dict], deployer: Optional[str],
                      owner: Optional[str], lp_pools: List[str]) -> List[Dict]:
        """Label special addresses (deployer, owner, burn, lock, LP pools)"""

        # Build label mapping
        labels = {}

        # Burn addresses
        labels[SPECIAL_ADDRESSES['burn_dead'].lower()] = "🔥 Burn Address"
        labels[SPECIAL_ADDRESSES['burn_zero'].lower()] = "🔥 Zero Address"

        # Lock contracts
        for lock_name, lock_addr in LOCK_CONTRACTS.items():
            if lock_addr != "0x0000000000000000000000000000000000000000":
                labels[lock_addr.lower()] = f"🔒 {lock_name}"

        # LP Pools
        for pool_addr in lp_pools:
            labels[pool_addr.lower()] = "💧 LP Pool"

        # Deployer and Owner
        if deployer:
            labels[deployer.lower()] = "👤 Deployer"
        if owner and owner != deployer:
            labels[owner.lower()] = "👤 Owner"

        # Apply labels
        for holder in holders:
            addr_lower = holder['address'].lower()
            if addr_lower in labels:
                holder['label'] = labels[addr_lower]
            else:
                # Check if whale (>5%)
                # We'll update this after calculating percentages
                holder['label'] = 'Holder'

        return holders

    def _calculate_circulating_supply(self, holders: List[Dict], total_supply: int) -> int:
        """Calculate circulating supply (excluding burn addresses)"""
        burned_amount = 0

        for holder in holders:
            if '🔥' in holder['label']:
                burned_amount += holder['balance']

        return total_supply - burned_amount

    def _calculate_concentration_metrics(self, holders: List[Dict]) -> Dict:
        """Calculate concentration metrics (top 1%, top 10%, whales)"""

        # Filter out special addresses for concentration calculation
        non_special_holders = [
            h for h in holders
            if not any(marker in h['label'] for marker in ['🔥', '💧', '🔒'])
        ]

        if not non_special_holders:
            return {
                'top_1_pct': 0,
                'top_10_pct': 0,
                'whale_count': 0,
                'total_holders': len(holders)
            }

        # Top 1
        top_1_pct = non_special_holders[0]['percentage'] if len(non_special_holders) > 0 else 0

        # Top 10
        top_10 = non_special_holders[:10]
        top_10_pct = sum(h['percentage'] for h in top_10)

        # Count whales (>5% and not special address)
        whale_count = sum(1 for h in non_special_holders if h['percentage'] > 5)

        # Update labels for whales
        for holder in non_special_holders:
            if holder['percentage'] > 5 and holder['label'] == 'Holder':
                holder['label'] = '🐋 Whale'

        return {
            'top_1_pct': top_1_pct,
            'top_10_pct': top_10_pct,
            'whale_count': whale_count,
            'total_holders': len(holders)
        }

    def _generate_holder_findings(self, metrics: Dict, holders: List[Dict]):
        """Generate security findings based on holder distribution"""

        top_1_pct = metrics['top_1_pct']
        top_10_pct = metrics['top_10_pct']
        whale_count = metrics['whale_count']
        total_holders = metrics['total_holders']

        # Critical: Single holder controls >25%
        if top_1_pct > 25:
            top_holder = next((h for h in holders if h['percentage'] == top_1_pct), None)
            addr_label = top_holder['label'] if top_holder else 'Unknown'
            self._add_finding("critical", f"Single Holder Controls {top_1_pct:.1f}%",
                            f"{addr_label} holds {top_1_pct:.1f}% of supply - extreme centralization risk")

        # High: Top 10 control >50%
        elif top_10_pct > 50:
            self._add_finding("high", f"Top 10 Holders Control {top_10_pct:.1f}%",
                            "High concentration - vulnerable to coordinated dump")

        # Medium: Top 10 control >30%
        elif top_10_pct > 30:
            self._add_finding("medium", f"Moderate Concentration: Top 10 Hold {top_10_pct:.1f}%",
                            "Some centralization risk present")

        # Positive: Good distribution
        else:
            self._add_finding("info", f"Good Distribution: Top 10 Hold {top_10_pct:.1f}%",
                            "Well-distributed token reduces manipulation risk",
                            positive=True)

        # Whale count
        if whale_count > 5:
            self._add_finding("medium", f"{whale_count} Whale Holders Detected",
                            f"{whale_count} addresses hold >5% each - potential for coordinated action")
        elif whale_count > 0:
            self._add_finding("info", f"{whale_count} Whale Holder(s)",
                            f"{whale_count} address(es) hold >5% of supply")

        # Total holders
        if total_holders > 1000:
            self._add_finding("info", f"Healthy Holder Count: {total_holders:,}",
                            "Wide distribution is positive for decentralization",
                            positive=True)
        elif total_holders < 100:
            self._add_finding("medium", f"Low Holder Count: {total_holders}",
                            "Limited distribution - token may be new or low interest")

        # Check if deployer/owner still holds significant amount
        for holder in holders[:10]:  # Check top 10
            if '👤' in holder['label'] and holder['percentage'] > 10:
                self._add_finding("high", f"{holder['label']} Holds {holder['percentage']:.1f}%",
                                f"Creator still controls significant supply - centralization risk")

    def _add_finding(self, severity: str, message: str, details: str, positive: bool = False):
        """Add a finding to the results"""
        self.findings.append({
            "severity": severity,
            "message": message,
            "details": details,
            "positive": positive
        })

    def _build_result(self, top_holders: List[Dict], top_10_pct: float,
                     whale_count: int, total_holders: int, circulating_supply: int) -> Dict:
        """Build the final analysis result"""
        return {
            "findings": self.findings,
            "metrics": {
                "top_10_concentration": top_10_pct,
                "whale_count": whale_count,
                "total_holders": total_holders,
                "circulating_supply": circulating_supply
            },
            "top_holders": [
                {
                    "address": h['address'],
                    "balance": h['balance'],
                    "percentage": h['percentage'],
                    "label": h['label']
                }
                for h in top_holders
            ]
        }

    def calculate_risk_adjustment(self, metrics: Dict) -> int:
        """Calculate risk score adjustment based on holder distribution"""
        risk_adjustment = 0

        top_10_pct = metrics.get('top_10_concentration', 0)
        total_holders = metrics.get('total_holders', 0)

        # If no holder data available, don't adjust risk
        if total_holders == 0:
            return 0  # No penalty for missing data

        # Negative factors (increase risk)
        if top_10_pct > 50:
            risk_adjustment += 15  # High concentration
        elif top_10_pct > 30:
            risk_adjustment += 5  # Moderate concentration

        # Additional penalty for extreme concentration (single holder >25%)
        # This would be detected in findings, but we check metrics
        if top_10_pct > 70:  # Implies very high single holder
            risk_adjustment += 10  # Extra penalty

        # Positive factors (reduce risk)
        if total_holders > 1000:
            risk_adjustment -= 5  # Good distribution
        if top_10_pct < 30:
            risk_adjustment -= 10  # Excellent distribution

        return risk_adjustment
