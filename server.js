#!/usr/bin/env node

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const compression = require('compression');
const morgan = require('morgan');
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs').promises;
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;

// Security middleware
app.use(helmet());
app.use(compression());

// CORS configuration
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Logging middleware
app.use(morgan('combined'));

// Rate limiting
const analyzeRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Limit each IP to 10 requests per windowMs
  message: {
    error: 'Too many analysis requests from this IP, please try again later.'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Store for tracking ongoing analyses
const activeAnalyses = new Map();

// BSC address validation regex
const BSC_ADDRESS_REGEX = /^0x[a-fA-F0-9]{40}$/;

// Validation middleware
const validateContractAddress = [
  body('address')
    .matches(BSC_ADDRESS_REGEX)
    .withMessage('Invalid BSC contract address format'),
  body('quickScan')
    .optional()
    .isBoolean()
    .withMessage('quickScan must be a boolean'),
];

// Helper function to validate BSC address
const isValidBSCAddress = (address) => {
  return BSC_ADDRESS_REGEX.test(address);
};

// Helper function to run Python scanner
const runPythonScanner = (address, quickScan = false) => {
  return new Promise((resolve, reject) => {
    const scriptPath = path.join(__dirname, 'scanner.py');
    const args = ['--address', address];
    
    if (quickScan) {
      args.push('--quick');
    }

    console.log(`Starting analysis for ${address} (quick: ${quickScan})`);

    const pythonProcess = spawn('python3', [scriptPath, ...args], {
      cwd: __dirname,
      stdio: ['pipe', 'pipe', 'pipe']
    });

    let stdout = '';
    let stderr = '';

    pythonProcess.stdout.on('data', (data) => {
      stdout += data.toString();
    });

    pythonProcess.stderr.on('data', (data) => {
      stderr += data.toString();
    });

    pythonProcess.on('close', (code) => {
      if (code === 0) {
        try {
          // The Python script outputs JSON to stdout after all the rich console output
          // We need to extract the JSON from the output
          const lines = stdout.split('\n');
          let jsonOutput = '';
          let foundJson = false;
          
          // Look for JSON output (it should be the last substantial output)
          for (let i = lines.length - 1; i >= 0; i--) {
            const line = lines[i].trim();
            if (line.startsWith('{')) {
              jsonOutput = line;
              foundJson = true;
              break;
            }
          }

          if (!foundJson) {
            // If no JSON found in stdout, create a result from the scan
            // Since the Python script doesn't output JSON to stdout by default,
            // we'll need to modify our approach
            reject(new Error('No JSON output found from Python scanner'));
            return;
          }

          const result = JSON.parse(jsonOutput);
          resolve(result);
        } catch (error) {
          console.error('Failed to parse JSON output:', error);
          console.error('Stdout:', stdout);
          console.error('Stderr:', stderr);
          reject(new Error('Failed to parse scanner output'));
        }
      } else {
        console.error(`Python script exited with code ${code}`);
        console.error('Stderr:', stderr);
        reject(new Error(`Scanner failed with exit code ${code}: ${stderr}`));
      }
    });

    pythonProcess.on('error', (error) => {
      console.error('Failed to start Python process:', error);
      reject(new Error(`Failed to start scanner: ${error.message}`));
    });
  });
};

// Modified helper function to run Python scanner and return JSON
const runPythonScannerWithJSON = async (address, quickScan = false) => {
  const scriptPath = path.join(__dirname, 'scanner.py');
  const tempOutputFile = path.join(__dirname, 'temp_reports', `temp_${Date.now()}.json`);
  
  // Ensure temp directory exists
  await fs.mkdir(path.dirname(tempOutputFile), { recursive: true });

  return new Promise((resolve, reject) => {
    const args = ['--address', address, '--output', tempOutputFile];
    
    if (quickScan) {
      args.push('--quick');
    }

    console.log(`Starting analysis for ${address} (quick: ${quickScan})`);

    const pythonProcess = spawn('python3', [scriptPath, ...args], {
      cwd: __dirname,
      stdio: ['pipe', 'pipe', 'pipe']
    });

    let stderr = '';

    pythonProcess.stderr.on('data', (data) => {
      stderr += data.toString();
    });

    pythonProcess.on('close', async (code) => {
      try {
        if (code === 0) {
          // Read the generated JSON file
          const reportData = await fs.readFile(tempOutputFile, 'utf8');
          const result = JSON.parse(reportData);
          
          // Clean up temp file
          await fs.unlink(tempOutputFile).catch(() => {});
          
          resolve(result);
        } else {
          console.error(`Python script exited with code ${code}`);
          console.error('Stderr:', stderr);
          reject(new Error(`Scanner failed with exit code ${code}: ${stderr}`));
        }
      } catch (error) {
        console.error('Failed to read or parse output file:', error);
        reject(new Error(`Failed to process scanner output: ${error.message}`));
      }
    });

    pythonProcess.on('error', (error) => {
      console.error('Failed to start Python process:', error);
      reject(new Error(`Failed to start scanner: ${error.message}`));
    });
  });
};

// Routes

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    activeAnalyses: activeAnalyses.size
  });
});

// Get API info
app.get('/api/info', (req, res) => {
  res.json({
    name: 'BSC Security Scanner API',
    version: '1.0.0',
    description: 'REST API for analyzing BSC smart contract security',
    endpoints: {
      analyze: 'POST /api/analyze',
      status: 'GET /api/analyze/:analysisId/status'
    },
    rateLimit: {
      windowMs: 15 * 60 * 1000,
      maxRequests: 10
    }
  });
});

// Main analysis endpoint
app.post('/api/analyze', analyzeRateLimit, validateContractAddress, async (req, res) => {
  // Check validation results
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      error: 'Validation failed',
      details: errors.array()
    });
  }

  const { address, quickScan = false } = req.body;
  const analysisId = `${address}-${Date.now()}`;

  // Check if this address is already being analyzed
  const existingAnalysis = Array.from(activeAnalyses.values())
    .find(analysis => analysis.address === address && analysis.status === 'running');

  if (existingAnalysis) {
    return res.status(409).json({
      error: 'Analysis already in progress for this address',
      analysisId: existingAnalysis.id,
      status: 'running'
    });
  }

  // Store analysis info
  activeAnalyses.set(analysisId, {
    id: analysisId,
    address,
    quickScan,
    status: 'running',
    startTime: new Date().toISOString(),
    clientIp: req.ip
  });

  // Start analysis asynchronously
  (async () => {
    try {
      console.log(`Starting analysis ${analysisId} for ${address}`);
      const result = await runPythonScannerWithJSON(address, quickScan);
      
      activeAnalyses.set(analysisId, {
        ...activeAnalyses.get(analysisId),
        status: 'completed',
        result,
        completedTime: new Date().toISOString()
      });

      console.log(`Completed analysis ${analysisId} for ${address}`);
    } catch (error) {
      console.error(`Failed analysis ${analysisId} for ${address}:`, error);
      activeAnalyses.set(analysisId, {
        ...activeAnalyses.get(analysisId),
        status: 'failed',
        error: error.message,
        completedTime: new Date().toISOString()
      });
    }
  })();

  // Return immediate response with analysis ID
  res.status(202).json({
    message: 'Analysis started',
    analysisId,
    status: 'running',
    estimatedTime: quickScan ? '30-60 seconds' : '2-3 minutes',
    statusUrl: `/api/analyze/${analysisId}/status`
  });
});

// Get analysis status
app.get('/api/analyze/:analysisId/status', (req, res) => {
  const { analysisId } = req.params;
  const analysis = activeAnalyses.get(analysisId);

  if (!analysis) {
    return res.status(404).json({
      error: 'Analysis not found',
      analysisId
    });
  }

  if (analysis.status === 'completed') {
    res.json({
      analysisId,
      status: 'completed',
      result: analysis.result,
      startTime: analysis.startTime,
      completedTime: analysis.completedTime
    });

    // Clean up old completed analyses after sending response
    setTimeout(() => {
      activeAnalyses.delete(analysisId);
    }, 60000); // Keep for 1 minute
  } else if (analysis.status === 'failed') {
    res.status(500).json({
      analysisId,
      status: 'failed',
      error: analysis.error,
      startTime: analysis.startTime,
      completedTime: analysis.completedTime
    });

    // Clean up failed analyses
    setTimeout(() => {
      activeAnalyses.delete(analysisId);
    }, 60000);
  } else {
    res.json({
      analysisId,
      status: 'running',
      startTime: analysis.startTime,
      progress: 'Analyzing contract security...'
    });
  }
});

// Synchronous analysis endpoint (for simple cases)
app.post('/api/analyze-sync', analyzeRateLimit, validateContractAddress, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      error: 'Validation failed',
      details: errors.array()
    });
  }

  const { address, quickScan = false } = req.body;

  try {
    console.log(`Starting synchronous analysis for ${address}`);
    const result = await runPythonScannerWithJSON(address, quickScan);
    
    res.json({
      status: 'completed',
      result,
      address,
      quickScan
    });
  } catch (error) {
    console.error(`Synchronous analysis failed for ${address}:`, error);
    res.status(500).json({
      error: 'Analysis failed',
      message: error.message,
      address
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    path: req.path,
    method: req.method
  });
});

// Cleanup old analyses periodically
setInterval(() => {
  const cutoff = Date.now() - 30 * 60 * 1000; // 30 minutes
  for (const [id, analysis] of activeAnalyses.entries()) {
    if (new Date(analysis.startTime).getTime() < cutoff) {
      activeAnalyses.delete(id);
      console.log(`Cleaned up old analysis: ${id}`);
    }
  }
}, 10 * 60 * 1000); // Run every 10 minutes

// Start server
app.listen(PORT, () => {
  console.log(`🚀 BSC Security Scanner API running on port ${PORT}`);
  console.log(`📊 Health check: http://localhost:${PORT}/health`);
  console.log(`📖 API info: http://localhost:${PORT}/api/info`);
  console.log(`🔍 Analysis endpoint: POST http://localhost:${PORT}/api/analyze`);
});

module.exports = app;