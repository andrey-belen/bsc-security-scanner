#!/bin/bash
# Start the React frontend development server

# Load nvm and use Node 20
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
nvm use 20

cd frontend
echo "🚀 Starting BSC Security Scanner Frontend..."
echo "Frontend will be available at: http://localhost:3000"
npm run dev