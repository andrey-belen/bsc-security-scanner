#!/bin/bash
# Start both backend and frontend concurrently

# Load nvm and use Node 20
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
nvm use 20

echo "🚀 Starting BSC Security Scanner Full-Stack Application..."
echo ""
echo "Backend: http://localhost:3001"
echo "Frontend: http://localhost:3000"
echo ""

# Check if required dependencies are installed
if [ ! -f "package.json" ]; then
    echo "❌ Backend package.json not found. Run setup first."
    exit 1
fi

if [ ! -f "frontend/package.json" ]; then
    echo "❌ Frontend package.json not found. Run setup first."
    exit 1
fi

# Install backend dependencies if needed
if [ ! -d "node_modules" ]; then
    echo "📦 Installing backend dependencies..."
    npm install
fi

# Install frontend dependencies if needed
if [ ! -d "frontend/node_modules" ]; then
    echo "📦 Installing frontend dependencies..."
    cd frontend
    npm install
    cd ..
fi

# Create necessary directories
mkdir -p temp_reports
mkdir -p reports

# Function to kill background processes on exit
cleanup() {
    echo ""
    echo "🛑 Shutting down servers..."
    kill $(jobs -p) 2>/dev/null
    exit
}

trap cleanup EXIT

# Start backend
echo "Starting backend server..."
node server.js &
BACKEND_PID=$!

# Wait a moment for backend to start
sleep 2

# Start frontend
echo "Starting frontend server..."
cd frontend
npm run dev &
FRONTEND_PID=$!

# Wait for both processes
echo ""
echo "✅ Both servers started successfully!"
echo "📱 Frontend: http://localhost:3000"
echo "🔧 Backend: http://localhost:3001"
echo "🔍 Health check: http://localhost:3001/health"
echo ""
echo "Press Ctrl+C to stop both servers"

# Wait for user to interrupt
wait