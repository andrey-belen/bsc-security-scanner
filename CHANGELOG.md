# Changelog

All notable changes to the BSC Security Scanner project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2025-10-05

### 🚀 Advanced Analyzers Added

#### New Modular Architecture
- **Holder Distribution Analyzer** (`holder_analyzer.py`)
  - Fetches top 50 holders via BSCScan API
  - Labels special addresses (burn, LP pools, deployer, owner)
  - Calculates concentration metrics and whale detection
  - Risk scoring based on holder distribution

- **Liquidity Pool Analyzer** (`liquidity_analyzer.py`)
  - Multi-DEX support (PancakeSwap V1/V2, BiSwap, ApeSwap)
  - LP token distribution analysis (burned/locked/unlocked)
  - Rug pull risk detection
  - Lock platform detection (PinkLock, Mudra, Unicrypt)

- **Transaction Simulator** (`transaction_simulator.py`)
  - Buy/sell simulation via PancakeSwap Router
  - Honeypot detection (cannot sell)
  - Tax asymmetry detection
  - Round-trip slippage calculation

### 🛠️ Infrastructure Improvements

#### Unified Startup System
- **New `start.sh` script** - Single command to start full stack
  - Automatic dependency checking and installation
  - Health checks for both backend and frontend
  - Port cleanup and process management
  - Detailed logging to backend.log and frontend.log
  - Visual feedback with color-coded status

- **NPM Script Integration** - `npm run fullstack` command
- **QUICKSTART.md** - Quick reference guide for new users
- **Deprecated Scripts Removed** - Cleaned up old startup files

#### Configuration-Driven Design
- **DEX Support** - Add new DEXs by editing `config.py` `DEX_FACTORIES`
- **Lock Platforms** - Add new lock contracts via `config.py` `LOCK_CONTRACTS`
- **Special Addresses** - Centralized burn and zero address definitions

### 📚 Documentation

- **Updated CLAUDE.md** - Complete architecture documentation
  - Modular analyzer design explained
  - Analysis flow (quick scan vs full scan)
  - Report output structure with examples
  - Development guide for adding new analyzers

- **Configuration Guide** - All `config.py` constants documented
- **Report Structure** - JSON output format fully documented

### 🐛 Bug Fixes

- Fixed "No response from server" error on fullstack startup
- Backend now properly monitored with health checks before frontend starts
- Process cleanup on Ctrl+C now works correctly

## [1.1.0] - 2025-10-04

### 🎉 Major Features Added

#### Context-Aware Analysis
- **Infrastructure Whitelisting**: Automatically recognizes known DeFi protocols
  - PancakeSwap Router V2, Factory V2
  - Wrapped BNB (WBNB)
  - Major stablecoins (BUSD, USDT, USDC, DAI)
- **Stablecoin Detection**: Distinguishes legitimate stablecoins from scams
  - Automatic severity downgrade for expected features (mint, centralized owner)
  - Context-aware messaging explaining regulatory requirements

#### Enhanced Risk Scoring
- **Weighted Severity Model**: Revolutionary new scoring system
  - Diminishing returns for multiple findings (prevents score inflation)
  - Critical: 40 pts + 10 each additional
  - High: 25 pts + 8 each additional
  - Medium: 15 pts + 5 each additional
  - Low: 3 pts each (capped at 3)
- **Positive Risk Factors**: Risk reduction for good practices
  - Known Infrastructure: -30 pts
  - Ownership Renounced: -15 pts
  - Multisig Owner: -10 pts
  - Verified Contract: -5 pts
  - Optimizer Enabled: -3 pts
- **Adjusted Risk Levels**: More accurate thresholds
  - CRITICAL: 80-100 (was 75-100)
  - MEDIUM: 30-59 (was 25-49)

#### Advanced Source Code Analysis
- **Compiler Security Analysis**
  - SafeMath library detection
  - Version-specific vulnerability checks
  - Solidity <0.8.0 flagged with context (SafeMath reduces risk)
- **Enhanced Pattern Detection**
  - Reentrancy-unsafe call patterns (call.value, call{value:})
  - Backdoor functions (withdrawAll, emergencyWithdraw, rugpull, skim, sweep)
  - Self-destruct and delegatecall detection
  - Ownership transfer without timelock
- **Contract Inheritance Analysis**
  - Detects Ownable, Pausable, AccessControl patterns
  - ReentrancyGuard identification
  - Proxy contract detection

#### ABI-Based Function Analysis
- **Privilege Function Detection**
  - Comprehensive detection of mint, burn, pause, blacklist, upgradeTo
  - Access control type identification (role-based vs owner-based)
  - Privilege function count tracking (>5 = medium risk)
- **Event Coverage Analysis**
  - Validates event emissions for state changes
  - Checks Transfer, Approval, and privileged function events
  - Flags missing events as transparency issue

#### Owner Analysis Enhancement
- **EOA vs Multisig Detection**
  - On-chain verification of owner type
  - Multisig/DAO owners flagged as lower risk
  - EOA owners properly contextualized (high risk for unknown tokens, expected for stablecoins)

### 🔧 Improvements

#### API Integration
- **Etherscan V2 Multi-Chain API**: Full BSC support
  - Uses `chainid=56` parameter
  - Single API key works for all chains
  - Better rate limiting and error handling

#### Caching System
- **Clear Cache Feature**: User-controlled cache invalidation
  - Clear cache button in UI
  - Backend endpoint: POST /api/cache/clear
  - Clears all layers: Python, Node.js, SQLite, file system

#### Documentation
- **Complete README Rewrite**: Updated with all features
  - Quick start guide for dashboard
  - API endpoint documentation
  - Real test results (BUSD: 13/100, WBNB: 0/100, Router: 30/100)
- **Implementation Status Document**: Feature-by-feature completion status
- **Updated CLAUDE.md**: Developer documentation

### 🐛 Bug Fixes

- Fixed double-counting of compiler version issues
- Fixed stablecoins being flagged as scams
- Fixed linear risk accumulation causing inflated scores
- Fixed cache not clearing completely
- Fixed API V1 deprecation errors (switched to V2)

### 🗑️ Removed

- Removed non-functional analyzer files (7 files cleaned up)
- Removed all web scraping code (API-only approach)
- Removed linear risk score accumulation (replaced with weighted model)

### 📊 Test Results

Version 1.1.0 properly scores:
- **BUSD**: 13/100 (LOW) - Previously 75/100 (HIGH) ❌
- **WBNB**: 0/100 (VERY LOW) - Previously would have been HIGH ❌
- **PancakeSwap Router**: 30/100 (MEDIUM) - Balanced despite critical patterns ✅

---

## [1.0.0] - 2025-10-03

### 🎉 Initial Release

#### Core Features
- **Python CLI Scanner**: Command-line security analysis tool
- **React Dashboard**: Modern web UI with TailwindCSS
- **Express API Backend**: RESTful API with async processing
- **SQLite Database**: Automatic result caching

#### Security Analysis
- Contract verification via BscScan API (V1)
- Ownership detection and analysis
- Dangerous function detection (mint, pause, blacklist)
- Basic honeypot detection
- Risk scoring system (0-100)

#### Infrastructure
- Multi-RPC endpoint support for BSC
- Rate limiting and error handling
- JSON and Markdown report generation
- Batch scanning support

### Known Issues (Fixed in 1.1.0)
- ⚠️ Stablecoins flagged as high risk
- ⚠️ Linear risk scoring too aggressive
- ⚠️ No context-aware detection
- ⚠️ Compiler issues double-counted
- ⚠️ BscScan API V1 deprecation warnings

---

## Version Numbering

- **Major (X.0.0)**: Breaking changes, major new features
- **Minor (1.X.0)**: New features, no breaking changes
- **Patch (1.1.X)**: Bug fixes, small improvements

---

[1.1.0]: https://github.com/andrei/bsc-security-scanner/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/andrei/bsc-security-scanner/releases/tag/v1.0.0
