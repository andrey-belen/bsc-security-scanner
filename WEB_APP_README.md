# BSC Security Scanner - Full Stack Web Application

A professional full-stack web application built around the existing Python BSC Security Scanner CLI tool for analyzing smart contract security on Binance Smart Chain.

## 🏗️ Architecture

- **Backend**: Node.js + Express API server (Port 3001)
- **Frontend**: React + TypeScript with Vite (Port 3000)
- **CLI Integration**: Python security scanner integrated as child process
- **Styling**: TailwindCSS for modern, responsive design

## 🚀 Quick Start

### Prerequisites
- Node.js (v16 or higher)
- Python 3.8+
- All Python dependencies from `requirements.txt`

### Option 1: Start Both Services (Recommended)
```bash
./start-fullstack.sh
```
This will start both backend and frontend servers concurrently.

### Option 2: Start Services Separately

**Backend Only:**
```bash
./start-backend.sh
```

**Frontend Only:**
```bash
./start-frontend.sh
```

## 📱 Usage

1. Open your browser to `http://localhost:3000`
2. Enter a BSC contract address (e.g., `0x8076c74c5e3f5852e2f86380b9ca2a2c38acf763`)
3. Choose between Quick Scan (30-60s) or Full Analysis (2-3 minutes)
4. View detailed security analysis results
5. Download reports as JSON files

## 🔧 API Endpoints

### Health Check
```bash
GET http://localhost:3001/health
```

### API Information
```bash
GET http://localhost:3001/api/info
```

### Start Analysis
```bash
POST http://localhost:3001/api/analyze
Content-Type: application/json

{
  "address": "0x8076c74c5e3f5852e2f86380b9ca2a2c38acf763",
  "quickScan": false
}
```

### Check Analysis Status
```bash
GET http://localhost:3001/api/analyze/:analysisId/status
```

### Synchronous Analysis (for quick scans)
```bash
POST http://localhost:3001/api/analyze-sync
Content-Type: application/json

{
  "address": "0x8076c74c5e3f5852e2f86380b9ca2a2c38acf763",
  "quickScan": true
}
```

## 🎨 Features

### Frontend Features
- **Modern React UI**: Clean, professional interface with TypeScript
- **Real-time Analysis**: Live progress tracking with estimated completion times
- **Interactive Results**: Risk scores with progress bars, severity-coded findings
- **Responsive Design**: Works on desktop, tablet, and mobile devices
- **Export Functionality**: Download scan results as JSON reports
- **Loading States**: Professional loading animations and progress indicators
- **Error Handling**: Comprehensive error messages and retry options

### Backend Features
- **RESTful API**: Clean REST endpoints with proper HTTP status codes
- **Asynchronous Processing**: Non-blocking analysis with status polling
- **Rate Limiting**: Built-in protection against abuse (10 requests per 15 minutes)
- **Concurrent Analysis**: Handle multiple simultaneous scan requests
- **Error Handling**: Robust error handling with detailed error messages
- **CORS Support**: Proper CORS configuration for frontend integration
- **Security Headers**: Helmet.js for security hardening
- **Request Validation**: Input validation and sanitization

### Integration Features
- **Python CLI Integration**: Seamless integration with existing scanner
- **Temporary File Management**: Automatic cleanup of temporary reports
- **Process Management**: Proper child process handling and cleanup
- **Caching**: Built-in result caching to avoid duplicate analyses

## 📊 Analysis Results

The scanner provides detailed security analysis including:

- **Risk Assessment**: Overall risk score (0-100) with color-coded risk levels
- **Contract Verification**: Source code verification status on BSCScan
- **Ownership Analysis**: Contract ownership patterns and renouncement status
- **Honeypot Detection**: Detection of honeypot mechanisms and high taxes
- **Function Analysis**: Analysis of contract functions for suspicious patterns
- **Liquidity Analysis**: Liquidity lock status and trading restrictions
- **Token Distribution**: Holder distribution analysis for whale concentration

## 🛠️ Development

### Project Structure
```
bsc-security-scanner/
├── backend files (server.js, package.json, etc.)
├── frontend/                 # React TypeScript application
│   ├── src/
│   │   ├── components/      # React components
│   │   ├── services/        # API service layer
│   │   ├── types/          # TypeScript type definitions
│   │   └── App.tsx         # Main application component
│   ├── package.json
│   └── vite.config.ts
├── scanner.py              # Original Python CLI scanner
├── start-*.sh             # Startup scripts
└── temp_reports/          # Temporary analysis reports
```

### Environment Configuration
Copy `.env.example` to `.env` and configure:
```env
PORT=3001
NODE_ENV=development
FRONTEND_URL=http://localhost:3000
```

### Rate Limiting
- **Window**: 15 minutes
- **Max Requests**: 10 per IP
- **Scope**: Analysis endpoints only

## 🔒 Security Considerations

- Input validation on all API endpoints
- Rate limiting to prevent abuse
- Proper error handling to prevent information disclosure
- Secure headers via Helmet.js
- CORS configuration for frontend integration
- Temporary file cleanup to prevent disk space issues

## 🎯 Portfolio Highlights

This project demonstrates:
- **Full-Stack Development**: Complete web application with modern tech stack
- **API Design**: RESTful API with proper status codes and error handling
- **React/TypeScript**: Modern frontend development with type safety
- **System Integration**: Integrating existing CLI tools into web applications
- **Async Processing**: Handling long-running operations in web applications
- **Professional UI/UX**: Clean, responsive design with loading states and animations
- **Security Best Practices**: Rate limiting, input validation, and secure headers

## 📝 Example Contract Addresses

Try these example addresses for testing:
- `0x8076c74c5e3f5852e2f86380b9ca2a2c38acf763` - Example token contract
- `0xe9e7cea3dedca5984780bafc599bd69add087d56` - BUSD token
- `0x55d398326f99059ff775485246999027b3197955` - USDT token

---

*Built for security internship portfolio demonstration - Educational purposes only*