# 🛡️ BSC Security Scanner

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![Node.js](https://img.shields.io/badge/Node.js-18+-green.svg)](https://nodejs.org)
[![React](https://img.shields.io/badge/React-18+-blue.svg)](https://reactjs.org)
[![BSC](https://img.shields.io/badge/BSC-Binance%20Smart%20Chain-yellow.svg)](https://bscscan.com)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Professional smart contract security analysis tool for BEP-20 tokens on Binance Smart Chain with modern React dashboard**

> ⚠️ **Educational Use Only**: This tool is designed for security research and educational purposes. Always conduct your own research before making investment decisions.

## 🚀 Quick Start

### Full Stack Dashboard (Recommended)
```bash
# Start both backend and frontend
./start-fullstack.sh

# Access the dashboard
open http://localhost:3000
```

### CLI Scanner Only
```bash
# Install dependencies
pip install -r requirements.txt

# Run scan
python scanner.py --address 0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56
```

## 📦 What's Included

- **🎨 React Dashboard**: Modern web UI with real-time analysis
- **🔌 REST API**: Node.js/Express backend with async processing
- **🐍 Python CLI**: Powerful command-line scanner
- **💾 SQLite Database**: Automatic result caching
- **📊 Rich Reports**: JSON, Markdown, and visual outputs

## 🌟 Key Features

### Advanced Security Analysis
- **✅ Context-Aware Detection**: Distinguishes between scams and legitimate DeFi (stablecoins, routers, etc.)
- **🔬 Source Code Analysis**: Deep inspection of verified contracts using Etherscan API
- **🎯 Weighted Risk Scoring**: Smart severity model with diminishing returns
- **🏗️ Infrastructure Whitelisting**: Known contracts (PancakeSwap, WBNB, BUSD) properly recognized
- **🔍 Compiler Version Checks**: Detects vulnerable Solidity versions with SafeMath detection
- **🛡️ Comprehensive Pattern Detection**: Finds honeypots, rug pulls, and dangerous functions

### What We Analyze

#### From Etherscan API (Verified Contracts)
- Compiler version and optimization settings
- Contract inheritance patterns (Ownable, Pausable, AccessControl)
- Source code red flags (blacklist, selfdestruct, delegatecall, backdoors)
- ABI-based privilege function detection
- Event coverage analysis

#### From On-Chain Data
- Owner type detection (EOA vs Multisig)
- Ownership renouncement status
- Token information (name, symbol, decimals, supply)
- Dangerous function selectors from bytecode

#### Advanced Detection
- **Honeypot Patterns**: Cannot sell after purchase
- **Backdoor Functions**: withdrawAll, emergencyWithdraw, skim
- **Reentrancy Risks**: Unsafe call.value patterns
- **Proxy Upgrades**: Detects upgradeable contracts
- **Access Control**: Role-based vs owner-based permissions

### Intelligent Risk Scoring

Our weighted severity model provides accurate risk assessment:

```
Risk Score = Base Score - Positive Factors

Where:
- Critical findings: 40 pts (+ 10 per additional)
- High findings: 25 pts (+ 8 per additional)
- Medium findings: 15 pts (+ 5 per additional)
- Low findings: 5 pts (capped at 3)

Positive Factors (Risk Reduction):
- Known Infrastructure: -30 pts
- Ownership Renounced: -15 pts
- Multisig Owner: -10 pts
- Verified Contract: -5 pts
- Optimizer Enabled: -3 pts
```

| Risk Level | Score | Example |
|------------|-------|---------|
| **VERY LOW** | 0-9 | WBNB (0/100) |
| **LOW** | 10-29 | BUSD (13/100) |
| **MEDIUM** | 30-59 | PancakeSwap Router (30/100) |
| **HIGH** | 60-79 | Suspicious tokens with multiple dangerous functions |
| **CRITICAL** | 80-100 | Honeypots, unprotected selfdestruct, unlimited mint |

## 🛠️ Installation

### Prerequisites
- Python 3.8+
- Node.js 18+
- npm or yarn

### Setup

```bash
# Clone repository
git clone https://github.com/andrei/bsc-security-scanner.git
cd bsc-security-scanner

# Install Python dependencies
pip install -r requirements.txt

# Install Node.js dependencies
npm install

# Setup frontend
cd frontend
npm install
cd ..

# Configure environment
cp .env.example .env
# Edit .env and add your ETHERSCAN_API_KEY from https://etherscan.io/myapikey
```

### Get API Key (Required)

The scanner uses Etherscan's multi-chain API to analyze BSC contracts:

1. Visit https://etherscan.io/myapikey
2. Create free account
3. Generate API key
4. Add to `.env` file:
   ```
   ETHERSCAN_API_KEY=your_key_here
   ```

## 🎯 Usage

### React Dashboard

```bash
# Start full stack (recommended)
./start-fullstack.sh

# Or start individually
./start-backend.sh    # Port 3001
./start-frontend.sh   # Port 3000

# Access dashboard
open http://localhost:3000
```

**Dashboard Features:**
- 🔍 Real-time contract analysis
- 📊 Visual risk indicators
- 💾 Automatic caching with clear cache button
- 📋 Detailed findings breakdown
- 🎨 Modern, responsive UI

### Python CLI

```bash
# Single contract scan
python scanner.py --address 0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56

# Quick scan (faster, basic checks)
python scanner.py --address 0x... --quick

# Generate JSON report
python scanner.py --address 0x... --output report.json

# Batch scanning
python scanner.py --batch contracts/test_addresses.txt
```

### API Endpoints

```bash
# Health check
curl http://localhost:3001/health

# Async analysis
curl -X POST http://localhost:3001/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"address": "0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56"}'

# Check status
curl http://localhost:3001/api/analyze/{id}/status

# Clear cache
curl -X POST http://localhost:3001/api/cache/clear
```

## 📋 Example Analysis

### BUSD (Legitimate Stablecoin)
```json
{
  "risk_score": 13,
  "risk_level": "LOW",
  "token_name": "BUSD Token",
  "is_stablecoin": true,
  "findings": [
    {
      "severity": "info",
      "message": "Known Stablecoin: BUSD",
      "details": "Centralized controls expected for regulatory compliance"
    },
    {
      "severity": "info",
      "message": "Mint Function Detected",
      "details": "Expected for centralized stablecoin issuance"
    },
    {
      "severity": "low",
      "message": "Old Compiler with SafeMath",
      "details": "Risk mitigated by SafeMath library"
    }
  ]
}
```

### PancakeSwap Router (Known Infrastructure)
```json
{
  "risk_score": 30,
  "risk_level": "MEDIUM",
  "is_known_infrastructure": true,
  "positive_factors": 38,
  "findings": [
    {
      "severity": "info",
      "message": "Known Infrastructure: PancakeSwap Router V2",
      "details": "Recognized DeFi infrastructure. Centralized functions expected and audited."
    }
  ]
}
```

### Honeypot Token (Scam)
```json
{
  "risk_score": 95,
  "risk_level": "CRITICAL",
  "findings": [
    {
      "severity": "critical",
      "message": "Self-Destruct Function Detected",
      "details": "Contract can be permanently destroyed"
    },
    {
      "severity": "critical",
      "message": "Potential Backdoor Function",
      "details": "Function allows owner to drain funds"
    }
  ]
}
```

## 🏗️ Project Structure

```
bsc-security-scanner/
├── README.md                       # This file
├── scanner.py                      # Python CLI entry point
├── config.py                       # BSC configuration & known contracts
├── server.js                       # Express API server
├── package.json                    # Node.js dependencies
├── requirements.txt                # Python dependencies
├── .env.example                    # Environment template
│
├── analyzers/                      # Core analysis engine
│   ├── __init__.py
│   └── core_analyzer.py           # Main security analyzer
│
├── frontend/                       # React dashboard
│   ├── src/
│   │   ├── App.tsx               # Main React component
│   │   ├── services/api.ts       # API service
│   │   └── App.css              # Styles
│   ├── package.json
│   └── vite.config.ts
│
├── database/                       # SQLite caching
│   └── db.js                      # Database operations
│
├── cache/                         # Memory caching
│   └── cache.js                  # NodeCache wrapper
│
├── utils/                         # Utilities
│   ├── cache.py                  # Python cache
│   └── error_handler.py         # Error handling
│
├── ai_docs/                       # Feature documentation
│   └── features/                 # Implementation specs
│
└── start-*.sh                    # Startup scripts
```

## 🔬 Technical Details

### Etherscan V2 Multi-Chain API Integration

The scanner uses Etherscan's V2 API which supports BSC:

```python
# API call example
params = {
    "chainid": 56,  # BSC
    "module": "contract",
    "action": "getsourcecode",
    "address": address,
    "apikey": ETHERSCAN_API_KEY
}
```

### Analyzer Architecture

1. **Contract Verification** (Etherscan API)
   - Source code retrieval
   - Compiler metadata extraction
   - ABI parsing

2. **Compiler Analysis**
   - Version vulnerability checking
   - SafeMath detection
   - Optimization verification

3. **Source Code Inspection**
   - Pattern matching for dangerous code
   - Inheritance analysis
   - Function signature detection

4. **On-Chain Verification**
   - Owner() calls via Web3
   - EOA vs Contract detection
   - Token info retrieval

5. **Risk Calculation**
   - Weighted severity scoring
   - Positive factor deduction
   - Context-aware adjustments

## 📊 Recognized Contracts

### Known Infrastructure (Auto-whitelisted)
- **PancakeSwap Router V2**: `0x10ed43c718714eb63d5aa57b78b54704e256024e`
- **PancakeSwap Factory V2**: `0xca143ce32fe78f1f7019d7d551a6402fc5350c73`
- **Wrapped BNB (WBNB)**: `0xbb4cdb9cbd36b01bd1cbaebf2de08d9173bc095c`

### Known Stablecoins (Context-aware analysis)
- **BUSD**: `0xe9e7cea3dedca5984780bafc599bd69add087d56`
- **USDT**: `0x55d398326f99059ff775485246999027b3197955`
- **USDC**: `0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d`
- **DAI**: `0x1af3f329e8be154074d8769d1ffa4ee058b1dbc3`

## 🤝 Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup
```bash
# Backend development (with auto-reload)
npm run dev

# Frontend development
cd frontend && npm run dev

# Run Python tests
pytest tests/ -v

# Format Python code
black scanner.py analyzers/
```

## ⚠️ Disclaimer

**IMPORTANT**: This tool is for educational and research purposes only.

- ❌ **Not Financial Advice**: Don't use as sole basis for investments
- ⚠️ **No Guarantees**: May not catch all vulnerabilities
- 🔍 **Do Your Research**: Always verify findings independently
- 📊 **Tool Limitations**: Based on publicly available data only

The developers are not responsible for any financial losses.

## 📜 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🏆 Acknowledgments

- **Binance Smart Chain** for infrastructure
- **Etherscan** for multi-chain API support
- **OpenZeppelin** for security standards
- **Web3.py** for blockchain integration
- **React** and **Vite** for modern frontend

---

**Built with ❤️ for the BSC security community**

*Star ⭐ this repository if you find it useful!*
