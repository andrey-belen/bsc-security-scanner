# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Architecture Overview

This is a full-stack BSC (Binance Smart Chain) security scanner application with three main components:

### Backend (Node.js/Express)
- **Entry Point**: `server.js` - Express API server (port 3001)
- **Purpose**: RESTful API that wraps the Python CLI scanner
- **Key Features**: Rate limiting, async analysis processing, CORS support

### Frontend (React/TypeScript)
- **Location**: `frontend/` directory
- **Tech Stack**: React + TypeScript + Vite + TailwindCSS
- **Port**: 3000
- **Purpose**: Modern web UI for contract analysis

### Python CLI Scanner
- **Entry Point**: `scanner.py` - Core security analysis engine
- **Purpose**: Smart contract security analysis for BEP-20 tokens
- **Analyzers**: Located in `analyzers/` (ownership.py, honeypot.py, functions.py)

## Development Commands

### Full Stack Application
```bash
# Start both backend and frontend together (recommended)
./start-fullstack.sh

# Start services individually
./start-backend.sh    # Backend only (port 3001)
./start-frontend.sh   # Frontend only (port 3000)
```

### Backend Development
```bash
npm start            # Production mode
npm run dev          # Development with nodemon
npm test             # Run Jest tests
```

### Frontend Development
```bash
cd frontend
npm run dev          # Development server (Vite)
npm run build        # TypeScript compile + Vite build
npm run lint         # ESLint
npm run preview      # Preview built app
```

### Python CLI Scanner
```bash
# Install Python dependencies
pip install -r requirements.txt

# Run enhanced analysis (default)
python scanner.py --address 0x8076c74c5e3f5852e2f86380b9ca2a2c38acf763

# Test known contracts for accuracy
python test_enhanced_scanner.py

# Quick scan mode (skips simulation)
python scanner.py --address 0x... --quick

# Batch scanning
python scanner.py --batch contracts/test_addresses.txt

# Generate reports
python scanner.py --address 0x... --output report.json
python scanner.py --address 0x... --format markdown

# Run regression tests
python -m pytest tests/test_enhanced_analyzer.py -v
```

## Key Configuration Files

- `config.py` - BSC RPC endpoints, contract addresses, risk scoring weights
- `package.json` - Backend Node.js dependencies and scripts
- `frontend/package.json` - Frontend React/TypeScript dependencies
- `requirements.txt` - Python dependencies for the scanner
- `.env.example` - Environment variables template

## Important File Locations

- **Analyzers**: `analyzers/` - Core security analysis modules
  - `enhanced_archetype.py` - Enhanced token classification system (NEW)
  - `enhanced_analyzer.py` - Main orchestrator with archetype-first approach (NEW)
  - `simulation.py` - Buy/sell simulation for honeypot detection (NEW)
  - `source_analyzer.py` - Verified source code analysis
  - `functions.py` - Enhanced function analysis with confidence scoring
  - `ownership.py` - Ownership analysis
  - `honeypot.py` - Honeypot detection
- **Reports**: `reports/` - Generated security analysis reports
- **Temp Reports**: `temp_reports/` - Temporary files for web app
- **Contracts**: `contracts/` - Test contract addresses
- **Utils**: `utils/` - Utility functions

## API Endpoints

- `GET /health` - Health check
- `GET /api/info` - API information
- `POST /api/analyze` - Start async analysis
- `GET /api/analyze/:id/status` - Check analysis status
- `POST /api/analyze-sync` - Synchronous analysis (quick scans)

## Rate Limiting

The backend implements rate limiting (10 requests per 15 minutes per IP) on analysis endpoints to prevent abuse.

## Security Analysis Features

### Token Archetype Classification
The scanner first classifies contracts into specific archetypes for targeted analysis:
- **Standard ERC-20/BEP-20**: Basic token functionality
- **Tax/Fee Token**: Tokens with buy/sell taxes or reflection mechanisms
- **Wrapper Token**: WETH/WBNB style wrappers
- **DEX Router/Factory**: Decentralized exchange components
- **Proxy Token**: Upgradeable proxy patterns

### Enhanced Detection Capabilities
- **Archetype-First Classification**: Classifies tokens into specific types before analysis
  - Wrapper tokens (WBNB/WETH style) - detects deposit()/withdraw() functions
  - Stablecoins (BUSD/USDT) - identifies centralized controls as expected features
  - Tax/Honeypot tokens - precise tax mechanism detection in _transfer function
  - Standard ERC-20 - comprehensive analysis for unexpected mechanisms
- **Source Code Analysis**: Parses verified contracts for precise vulnerability detection
- **Buy/Sell Simulation**: Uses forked BSC node to test actual trading functionality
- **Confidence Scoring**: Each finding includes confidence levels based on detection method
- **False Positive Reduction**: Eliminates misclassification of legitimate tokens as honeypots
- **Context-Aware Risk Scoring**: Adjusts risk based on token archetype and detection confidence

### Security Checks
The scanner detects:
- Contract verification status
- Ownership patterns and renouncement
- Honeypot mechanisms and high taxes
- Dangerous functions (mint, pause, blacklist)
- Tax/fee manipulation capabilities
- Blacklist and pause functionality
- Liquidity analysis and holder distribution
- Risk scoring with archetype-specific weighting

## Development Notes

- Uses multiple BSC RPC endpoints for redundancy (configured in `config.py`)
- Web app integrates the Python CLI via child processes
- Frontend uses Axios for API communication
- TailwindCSS for styling with responsive design
- TypeScript for type safety in frontend
- Rich terminal output in Python CLI

## Python CLI Architecture

### Main Scanner Flow
The scanner follows an archetype-first analysis approach:
1. **Address Validation**: Validates BSC address format in `scanner.py`
2. **Archetype Classification**: `enhanced_analyzer.py` classifies token type first
3. **Archetype-Specific Analysis**: Runs targeted checks based on token type
4. **Finding Generation**: Produces findings with confidence scores
5. **Risk Calculation**: Calculates final risk score adjusted for archetype and confidence

### Enhanced vs Legacy Analyzers
- **Enhanced Analyzer** (default): `enhanced_analyzer.py` with archetype-first approach
  - Reduces false positives by understanding token context (e.g., stablecoins vs scams)
  - Uses source code analysis when available
  - Integrates simulation for buy/sell testing
  - Flag: `scanner.use_enhanced = True` (default)
- **Legacy Analyzer**: Original analysis flow without archetype classification
  - Fallback when enhanced analyzer fails
  - Used by setting `scanner.use_enhanced = False`

### Error Handling & Retry Logic
- All RPC calls wrapped with `@with_retry` decorator from `utils/error_handler.py`
- Rate limiting enforced via `default_rate_limiter` (5 req/sec configured in `config.py`)
- Error aggregation via `ErrorAggregator` for comprehensive error reporting
- Caching layer in `utils/cache.py` to reduce redundant RPC calls (5min TTL)

### Backend-Python Integration
The Node.js backend spawns Python processes and reads JSON output:
- Backend calls: `python3 scanner.py --address 0x... --output temp_reports/temp_*.json`
- Python writes JSON report to temp file
- Backend reads JSON and returns via API
- Temp files cleaned up after response sent

## Working with Tests

### Python Tests
```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test file
python -m pytest tests/test_enhanced_analyzer.py -v

# Run test for known contracts (regression tests)
python test_enhanced_scanner.py
```

### Backend Tests
```bash
# Run Jest tests
npm test

# Run with coverage
npm test -- --coverage
```

## Common Development Tasks

### Adding a New Security Check
1. Add detection logic to appropriate analyzer in `analyzers/`
2. Update risk weight in `config.py` `RISK_WEIGHTS` if needed
3. Add test case in `tests/` directory
4. Update archetype-specific analysis in `enhanced_analyzer.py` if archetype-dependent

### Modifying Archetype Classification
1. Edit `analyzers/enhanced_archetype.py`
2. Update `EnhancedArchetypeClassifier.classify_archetype()` method
3. Test with `python test_enhanced_scanner.py` to verify known contracts still classify correctly

### Debugging RPC Issues
- Check `config.py` for list of RPC endpoints
- RPC selection is random via `get_rpc_endpoint()` for load balancing
- Increase retry attempts in `utils/error_handler.py` if needed
- Check rate limiting settings in `RATE_LIMIT_CONFIG`