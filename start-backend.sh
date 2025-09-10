#!/bin/bash
# Start the Node.js Express backend server

# Load nvm and use Node 20
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
nvm use 20

echo "🚀 Starting BSC Security Scanner Backend..."
echo "Backend API will be available at: http://localhost:3001"
echo "Health check: http://localhost:3001/health"
echo "API docs: http://localhost:3001/api/info"
echo ""

# Install dependencies if not already installed
if [ ! -d "node_modules" ]; then
    echo "📦 Installing backend dependencies..."
    npm install
fi

# Create temp_reports directory if it doesn't exist
mkdir -p temp_reports

# Start the server
node server.js