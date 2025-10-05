# Quick Start Guide

## One-Command Startup

```bash
./start.sh
```

That's it! This will:
- ✅ Check all dependencies (Node.js 20+, Python 3.8+)
- ✅ Install npm packages if needed
- ✅ Install Python packages if needed
- ✅ Create .env file from template if missing
- ✅ Start backend on port 3001
- ✅ Start frontend on port 3000
- ✅ Verify both servers are healthy
- ✅ Clean up processes on Ctrl+C

## Alternative: NPM Command

```bash
npm run fullstack
```

## Access the Application

Once started, open your browser:
- **Frontend Dashboard**: http://localhost:3000
- **Backend API**: http://localhost:3001
- **Health Check**: http://localhost:3001/health

## First-Time Setup

1. **Get API Key** (Required for full functionality):
   ```bash
   # Visit https://etherscan.io/myapikey
   # Create free account and generate API key
   ```

2. **Edit .env file**:
   ```bash
   nano .env
   # or
   code .env
   ```

3. **Add your API key**:
   ```env
   ETHERSCAN_API_KEY=your_actual_api_key_here
   ```

4. **Start the scanner**:
   ```bash
   ./start.sh
   ```

## Development Mode

### Start Individual Services

**Backend only** (for API development):
```bash
npm start
# or with auto-reload
npm run dev
```

**Frontend only** (requires backend running on port 3001):
```bash
cd frontend && npm run dev
```

## Python CLI Only

If you only want to use the command-line scanner:

```bash
# Install Python dependencies
pip3 install -r requirements.txt

# Scan a token
python3 scanner.py --address 0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56

# Quick scan (faster, skips advanced analyzers)
python3 scanner.py --address 0x... --quick
```

## Troubleshooting

### Node.js Version Error
If you see "Node.js version 20+ required":

**Using nvm (recommended)**:
```bash
nvm install 20
nvm use 20
./start.sh
```

**Or download Node.js 20+ from**: https://nodejs.org/

### "No response from server"
- Backend didn't start properly
- Run `./start.sh` which includes health checks
- Check if port 3001 is already in use: `lsof -ti:3001`

### Port Already in Use
The start.sh script automatically cleans up ports 3000 and 3001. If issues persist:
```bash
# Kill processes manually
lsof -ti:3001 | xargs kill -9
lsof -ti:3000 | xargs kill -9
```

### "Cannot find module"
Install dependencies:
```bash
npm install                    # Backend
cd frontend && npm install     # Frontend
pip3 install -r requirements.txt  # Python
```

### API Key Not Working
- Ensure you're using an Etherscan API key (not BSCScan)
- Etherscan now provides multi-chain access including BSC
- Free tier: 5 req/sec, 100k calls/day
- Get key from: https://etherscan.io/myapikey

## Stopping the Application

Press `Ctrl+C` in the terminal where start.sh is running. All processes will be cleanly terminated.

## Next Steps

1. Open http://localhost:3000
2. Enter a BSC token address (e.g., `0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56`)
3. Click "Analyze Token"
4. View comprehensive security report

## Example Addresses to Test

- **BUSD (Stablecoin)**: `0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56`
- **WBNB (Wrapped BNB)**: `0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c`
- **PancakeSwap Router**: `0x10ED43C718714eb63d5aA57B78B54704E256024E`

---

**Need Help?** Check the [README.md](README.md) for detailed documentation.
