#!/bin/bash
# Simple startup script for BSC Security Scanner

set -e

echo "🚀 Starting BSC Security Scanner"
echo ""

# Load nvm if available
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"

# Use Node 20
nvm use 20 2>/dev/null || echo "Warning: Could not switch to Node 20"

# Rebuild native modules if needed
if [ ! -f ".node20_rebuilt" ]; then
    echo "📦 Rebuilding native modules for Node 20..."
    npm rebuild
    touch .node20_rebuilt
fi

# Clean up any existing processes
lsof -ti:3001 | xargs kill -9 2>/dev/null || true
lsof -ti:3000 | xargs kill -9 2>/dev/null || true
sleep 1

# Cleanup on exit
cleanup() {
    echo ""
    echo "🛑 Shutting down..."
    jobs -p | xargs kill 2>/dev/null || true
    lsof -ti:3001 | xargs kill -9 2>/dev/null || true
    lsof -ti:3000 | xargs kill -9 2>/dev/null || true
    exit 0
}
trap cleanup INT TERM EXIT

# Start backend
echo "🔧 Starting backend (port 3001)..."
node server.js &

# Wait for backend
sleep 3

# Start frontend
echo "📱 Starting frontend (port 3000)..."
cd frontend
npm run dev &
cd ..

echo ""
echo "✅ Running!"
echo "   Frontend: http://localhost:3000"
echo "   Backend:  http://localhost:3001"
echo ""
echo "Press Ctrl+C to stop"

wait
