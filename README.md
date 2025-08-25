# 🛡️ BSC Security Scanner

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![BSC](https://img.shields.io/badge/BSC-Binance%20Smart%20Chain-yellow.svg)](https://bscscan.com)
[![Security](https://img.shields.io/badge/Security-Analysis-red.svg)](https://github.com/andrei/bsc-security-scanner)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Maintained](https://img.shields.io/badge/Maintained-Yes-brightgreen.svg)](https://github.com/andrei/bsc-security-scanner)

**Professional smart contract security analysis tool for BEP-20 tokens on Binance Smart Chain**

> ⚠️ **Educational Use Only**: This tool is designed for security research and educational purposes. Always conduct your own research before making investment decisions.

## 🚀 Features

### Core Security Analysis
- **🔍 Contract Verification**: Checks if source code is verified on BscScan
- **👑 Ownership Analysis**: Detects ownership patterns, renouncement status, and centralization risks
- **🍯 Honeypot Detection**: Identifies selling restrictions, high taxes, and trading limitations
- **⚠️ Function Analysis**: Scans for dangerous functions (mint, pause, blacklist, etc.)
- **💰 Liquidity Analysis**: Checks liquidity lock status and concentration
- **🐋 Holder Distribution**: Analyzes whale concentration and distribution patterns

### Advanced Detection Capabilities
- **Hidden mint functions** that can inflate supply
- **Ownership renouncement status** and multisig patterns
- **Honeypot indicators** preventing profitable selling
- **High tax/fee functions** that drain user funds
- **Pausable token risks** allowing owner to halt trading
- **Blacklist functions** that can freeze user funds
- **Proxy patterns** and upgrade risks

### Professional Output
- **Rich Terminal UI** with colored output and progress bars
- **Risk Scoring System** (Low/Medium/High/Critical)
- **JSON Reports** for automated analysis
- **Markdown Reports** for documentation
- **Batch Scanning** for multiple contracts
- **Rate Limiting** to avoid RPC bans

## 📸 Example Output

```
🔍 BSC Security Scanner
==================================================
📍 Address: 0x8076c74c5e3f5852e2f86380b9ca2a2c38acf763
🏷️  Token: SafeMoon
🔗 Chain: Binance Smart Chain (BSC)

🔐 Security Analysis:
✅ Contract verified on BscScan
⚠️  Single EOA owner detected
🔴 High sell tax detected (12%)
⚠️  Different buy/sell taxes detected
🔴 3 dangerous function(s) detected
🔴 Owner can pause transfers
⚠️  Blacklist functionality present

🎯 Risk Score: HIGH (75/100)
📊 Summary: Found 10 security findings
```

## 🛠️ Installation

### Prerequisites
- Python 3.8 or higher
- Git

### Quick Setup
```bash
# Clone the repository
git clone https://github.com/andrei/bsc-security-scanner.git
cd bsc-security-scanner

# Install dependencies
pip install -r requirements.txt

# Run your first scan
python scanner.py --address 0x8076c74c5e3f5852e2f86380b9ca2a2c38acf763
```

### Virtual Environment (Recommended)
```bash
# Create virtual environment
python -m venv bsc-scanner-env

# Activate virtual environment
# On Windows:
bsc-scanner-env\\Scripts\\activate
# On macOS/Linux:
source bsc-scanner-env/bin/activate

# Install dependencies
pip install -r requirements.txt
```

## 🎯 Usage

### Single Contract Scan
```bash
# Basic scan
python scanner.py --address 0x8076c74c5e3f5852e2f86380b9ca2a2c38acf763

# Quick scan (faster, fewer checks)
python scanner.py --address 0x8076c74c5e3f5852e2f86380b9ca2a2c38acf763 --quick

# Generate JSON report
python scanner.py --address 0x8076c74c5e3f5852e2f86380b9ca2a2c38acf763 --output report.json

# Generate Markdown report
python scanner.py --address 0x8076c74c5e3f5852e2f86380b9ca2a2c38acf763 --format markdown
```

### Batch Scanning
```bash
# Scan multiple contracts from file
python scanner.py --batch contracts/test_addresses.txt

# Batch scan with custom output format
python scanner.py --batch contracts/test_addresses.txt --format markdown
```

### Advanced Options
```bash
# Verbose output for debugging
python scanner.py --address 0x... --verbose

# Custom output file
python scanner.py --address 0x... --output /path/to/custom_report.json

# Help and all options
python scanner.py --help
```

## 📋 Command Line Options

| Option | Description |
|--------|-------------|
| `--address`, `-a` | Contract address to scan |
| `--batch`, `-b` | File containing list of addresses |
| `--output`, `-o` | Output file path for report |
| `--format`, `-f` | Report format (json/markdown) |
| `--quick`, `-q` | Perform quick scan only |
| `--verbose`, `-v` | Enable verbose output |

## 🏗️ Project Structure

```
bsc-security-scanner/
├── README.md                 # This file
├── scanner.py               # Main scanner application
├── config.py               # BSC configuration and constants
├── requirements.txt        # Python dependencies
├── analyzers/             # Analysis modules
│   ├── __init__.py
│   ├── ownership.py       # Ownership analysis
│   ├── honeypot.py       # Honeypot detection
│   └── functions.py      # Function analysis
├── reports/              # Generated reports
│   └── sample_scan.json # Example output
└── contracts/           # Test contract addresses
    └── test_addresses.txt
```

## 🔍 Security Checks

### Ownership Analysis
- **Owner Detection**: Identifies contract owner and type (EOA/multisig/contract)
- **Renouncement Verification**: Checks if ownership has been properly renounced
- **Centralization Risk**: Assesses concentration of control

### Honeypot Detection
- **Sell Restrictions**: Identifies mechanisms that prevent selling
- **Tax Analysis**: Detects asymmetric buy/sell taxes
- **Transfer Limits**: Checks for restrictive transaction limits
- **Bytecode Analysis**: Scans for honeypot patterns in contract code

### Function Analysis
- **Dangerous Functions**: Detects mint, pause, blacklist, and other risky functions
- **Access Control**: Analyzes function visibility and modifiers
- **Hidden Functions**: Identifies obfuscated or non-standard functions

### Liquidity & Distribution
- **Liquidity Lock**: Verifies if liquidity is locked
- **Holder Analysis**: Checks for whale concentration
- **Distribution Patterns**: Identifies unusual token distributions

## 🎯 Risk Scoring System

The scanner uses a weighted scoring system to assess overall contract risk:

| Risk Level | Score Range | Description |
|------------|-------------|-------------|
| **VERY LOW** | 0-9 | Minimal risk, standard ERC-20 |
| **LOW** | 10-29 | Some minor concerns |
| **MEDIUM** | 30-59 | Moderate risk, proceed with caution |
| **HIGH** | 60-79 | High risk, significant concerns |
| **CRITICAL** | 80-100 | Extreme risk, likely scam/honeypot |

### Risk Factors and Weights
- Unverified contract: 25 points
- No ownership renounced: 15 points
- Dangerous functions: 20 points
- High sell tax (>10%): 25 points
- Honeypot indicators: 30 points
- No liquidity lock: 15 points
- Whale concentration: 10 points

## 🌐 Why BSC Security Matters

Binance Smart Chain has become a hotbed for both legitimate projects and malicious actors. Common BSC-specific risks include:

### Unique BSC Vulnerabilities
- **Cross-chain bridge risks** not present on Ethereum
- **Lower gas fees** enabling more frequent rug pulls
- **Fast block times** allowing rapid token manipulation
- **BSC-specific DEX mechanics** (PancakeSwap patterns)
- **Different token standards** and implementations

### Common Attack Vectors
1. **Honeypot Tokens**: Allow buying but prevent selling
2. **Rug Pulls**: Developers drain liquidity after launch
3. **High Tax Scams**: Excessive taxes that drain user funds
4. **Ownership Abuse**: Centralized control for malicious purposes
5. **Fake Token Clones**: Impersonating legitimate projects

## 📊 Real-World Examples

### SafeMoon Analysis
```json
{
  "risk_level": "HIGH",
  "risk_score": 75,
  "key_findings": [
    "High sell tax (12%)",
    "Centralized ownership",
    "Blacklist functionality",
    "Pause mechanism"
  ]
}
```

### Typical Honeypot Pattern
```json
{
  "risk_level": "CRITICAL", 
  "risk_score": 95,
  "key_findings": [
    "Cannot sell after purchase",
    "Hidden mint functions",
    "Transfer restrictions",
    "Unverified contract"
  ]
}
```

## 🔬 Technical Implementation

### BSC Integration
- **RPC Endpoints**: Multiple BSC public nodes for redundancy
- **Web3.py**: Direct blockchain interaction for contract analysis
- **BscScan API**: Contract verification and metadata
- **Bytecode Analysis**: Direct smart contract code examination

### Analysis Techniques
- **Static Analysis**: Bytecode pattern recognition
- **Function Signature Detection**: 4-byte selector analysis
- **ABI Parsing**: Interface analysis where available
- **Transaction Simulation**: Safe testing of contract behavior

## 🚧 Future Improvements

### Planned Features
- [ ] **Web Interface**: Flask-based web UI for easier access
- [ ] **Real-time Monitoring**: Track contracts over time
- [ ] **Machine Learning**: ML-based risk assessment
- [ ] **API Integration**: RESTful API for automated scanning
- [ ] **Mobile App**: React Native mobile scanner
- [ ] **Browser Extension**: One-click scanning from BSC explorers

### Enhanced Analysis
- [ ] **Liquidity Pool Analysis**: Deep DEX integration
- [ ] **Token Holder Behavior**: Transaction pattern analysis
- [ ] **Cross-contract Dependencies**: Related contract scanning
- [ ] **Historical Analysis**: Time-series risk assessment
- [ ] **Social Media Integration**: Community sentiment analysis

### Performance Improvements
- [ ] **Caching Layer**: Redis for faster repeated scans
- [ ] **Parallel Processing**: Multi-threaded analysis
- [ ] **Database Integration**: PostgreSQL for scan history
- [ ] **Rate Limiting**: Intelligent request management

## 🤝 Contributing

We welcome contributions from the security community! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup
```bash
# Clone and setup development environment
git clone https://github.com/andrei/bsc-security-scanner.git
cd bsc-security-scanner

# Install development dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run tests
pytest tests/

# Code formatting
black scanner.py analyzers/
flake8 scanner.py analyzers/
```

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

**IMPORTANT**: This tool is for educational and research purposes only. 

- **Not Financial Advice**: Results should not be used as the sole basis for investment decisions
- **No Guarantees**: Security analysis may not catch all vulnerabilities
- **Due Diligence**: Always conduct your own research
- **Risk Warning**: Cryptocurrency investments carry inherent risks
- **Tool Limitations**: Analysis is based on publicly available information

The developers are not responsible for any financial losses incurred from using this tool.

## 📞 Support & Contact

- **GitHub Issues**: [Report bugs or request features](https://github.com/andrei/bsc-security-scanner/issues)
- **Security Reports**: Please responsibly disclose security issues
- **Feature Requests**: We welcome suggestions for improvements

## 🏆 Acknowledgments

- **Binance Smart Chain**: For providing robust infrastructure
- **OpenZeppelin**: For security best practices and standards
- **Web3.py**: For excellent blockchain integration tools
- **Rich**: For beautiful terminal output
- **BSC Community**: For continuous feedback and testing

---

**Built with ❤️ for the BSC security community**

*Star ⭐ this repository if you find it useful!*