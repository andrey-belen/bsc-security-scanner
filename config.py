"""
BSC Configuration - RPC endpoints and contract addresses
Note: BSCScan now uses Etherscan API infrastructure, so use ETHERSCAN_API_KEY from etherscan.io
"""

import os
from typing import List, Dict

# BSC Public RPC Endpoints (no API key required)
BSC_RPC_ENDPOINTS = [
    "https://bsc-dataseed.binance.org/",
    "https://bsc-dataseed1.binance.org/",
    "https://bsc-dataseed2.binance.org/",
    "https://bsc-dataseed3.binance.org/",
    "https://bsc-dataseed4.binance.org/",
    "https://bsc-dataseed1.defibit.io/",
    "https://bsc-dataseed2.defibit.io/",
    "https://bsc-dataseed3.defibit.io/",
    "https://bsc-dataseed4.defibit.io/",
    "https://bsc-dataseed1.ninicoin.io/",
    "https://bsc-dataseed2.ninicoin.io/",
    "https://bsc-dataseed3.ninicoin.io/",
    "https://bsc-dataseed4.ninicoin.io/"
]

# BSC Network Configuration
# Note: Etherscan API is now multi-chain and supports BSC
# Use api.etherscan.io with chain parameter for BSC
BSC_CONFIG = {
    "chain_id": 56,
    "name": "Binance Smart Chain",
    "symbol": "BNB",
    "decimals": 18,
    "rpc_endpoints": BSC_RPC_ENDPOINTS,
    "explorer": "https://bscscan.com",
    "explorer_api": "https://api.etherscan.io/v2/api",  # Etherscan V2 multi-chain API
    "chain_param": "bsc"  # Chain identifier for multi-chain API
}

# Rate limiting settings
RATE_LIMIT_CONFIG = {
    "requests_per_second": 5,
    "retry_attempts": 3,
    "retry_delay": 1.0,
    "timeout": 30
}

# Important BSC contract addresses
BSC_CONTRACTS = {
    "pancakeswap_router": "0x10ED43C718714eb63d5aA57B78B54704E256024E",
    "pancakeswap_factory": "0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73",
    "wbnb": "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c",
    "busd": "0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56",
    "usdt": "0x55d398326f99059fF775485246999027B3197955"
}

# DEX Factory Addresses for Liquidity Pool Discovery
DEX_FACTORIES = {
    "PancakeSwap V2": "0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73",
    "PancakeSwap V1": "0xBCfCcbde45cE874adCB698cC183deBcF17952812",
    "BiSwap": "0x858E3312ed3A876947EA49d572A7C42DE08af7EE",
    "ApeSwap": "0x0841BD0B734E4F5853f0dD8d7Ea041c241fb0Da6"
}

# Known LP Lock Contract Addresses
LOCK_CONTRACTS = {
    "PinkLock": "0x407993575c91ce7643a4d4cCACc9A98c36eE1BBE",  # BSC PinkLock V2
    "Mudra": "0x3F4D6bf08CB7A003488Ef082102C2e6418a4551e",
    "Unicrypt": "0xC8C4419c4Bd7d75F3F7c2ef319Dd470BC33F0Fa3",  # BSC Unicrypt
    "Team Finance": "0x0000000000000000000000000000000000000000"  # Placeholder - update if used
}

# Special Addresses (Burn, Zero, etc)
SPECIAL_ADDRESSES = {
    "burn_dead": "0x000000000000000000000000000000000000dEaD",
    "burn_zero": "0x0000000000000000000000000000000000000000"
}

# Common dangerous function signatures for BEP-20 tokens
DANGEROUS_FUNCTION_SIGNATURES = {
    # Minting functions
    "mint": ["mint(address,uint256)", "mint(uint256)"],
    "mintTo": ["mintTo(address,uint256)"],
    "_mint": ["_mint(address,uint256)"],
    
    # Pause/Stop functions  
    "pause": ["pause()", "pauseContract()"],
    "unpause": ["unpause()", "unpauseContract()"],
    "stop": ["stop()", "stopContract()"],
    "start": ["start()", "startContract()"],
    
    # Blacklist functions
    "blacklist": ["blacklist(address)", "addToBlacklist(address)"],
    "blacklistAddress": ["blacklistAddress(address)"],
    "setBlacklist": ["setBlacklist(address,bool)"],
    "ban": ["ban(address)", "banAddress(address)"],
    
    # Fee/Tax manipulation
    "setFee": ["setFee(uint256)", "setTaxFee(uint256)"],
    "setSellFee": ["setSellFee(uint256)"],
    "setBuyFee": ["setBuyFee(uint256)"],
    "setMaxTax": ["setMaxTax(uint256)"],
    "updateFees": ["updateFees(uint256,uint256)"],
    
    # Ownership transfers
    "transferOwnership": ["transferOwnership(address)"],
    "renounceOwnership": ["renounceOwnership()"],
    "changeOwner": ["changeOwner(address)"],
    
    # Liquidity manipulation
    "skim": ["skim(address)", "skim()"],
    "sync": ["sync()"],
    "removeLiquidity": ["removeLiquidity(uint256)"],
    
    # Balance/Token manipulation
    "setBalance": ["setBalance(address,uint256)"],
    "updateBalance": ["updateBalance(address,uint256)"],
    "airdrop": ["airdrop(address[],uint256[])"],
    "multiSend": ["multiSend(address[],uint256[])"]
}

# Honeypot detection patterns
HONEYPOT_PATTERNS = {
    "high_sell_tax": {
        "threshold": 10,  # >10% sell tax
        "severity": "high",
        "description": "High sell tax detected"
    },
    "different_buy_sell_tax": {
        "threshold": 5,   # >5% difference
        "severity": "medium", 
        "description": "Different buy/sell taxes"
    },
    "max_transaction_limit": {
        "threshold": 1,   # <1% of total supply
        "severity": "medium",
        "description": "Very low max transaction limit"
    },
    "transfer_disabled": {
        "severity": "critical",
        "description": "Token transfers are disabled"
    }
}

# Risk scoring weights
RISK_WEIGHTS = {
    "unverified_contract": 25,
    "no_ownership_renounced": 15,
    "dangerous_functions": 20,
    "high_sell_tax": 25,
    "honeypot_indicators": 30,
    "no_liquidity_lock": 15,
    "whale_concentration": 10,
    "new_contract": 10,
    "proxy_contract": 5
}

# BscScan API configuration
BSCSCAN_CONFIG = {
    "api_url": "https://api.bscscan.com/api",
    "rate_limit": 5,  # requests per second
    "timeout": 10
}

# Cache configuration
CACHE_CONFIG = {
    "enabled": True,
    "ttl": 300,  # 5 minutes
    "max_size": 1000
}

def get_rpc_endpoint() -> str:
    """Get a random RPC endpoint for load balancing"""
    import random
    return random.choice(BSC_RPC_ENDPOINTS)

def get_bscscan_api_key() -> str:
    """
    Get Etherscan API key from environment
    Note: Etherscan API is now multi-chain and supports BSC via chain parameter
    """
    return os.getenv("ETHERSCAN_API_KEY", "")

def is_valid_bsc_address(address: str) -> bool:
    """
    Validate BSC address format
    Note: BSC uses same address format as Ethereum (0x + 40 hex chars)
    """
    if not address.startswith("0x"):
        return False
    if len(address) != 42:
        return False
    try:
        int(address, 16)
        return True
    except ValueError:
        return False