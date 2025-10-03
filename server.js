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

// Database and cache modules
const { initDatabase, storeScanResult, getCachedScanResult, getStats: getDbStats } = require('./database/db');
const { getCached, setCached, getStats: getCacheStats } = require('./cache/cache');

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
  max: parseInt(process.env.RATE_LIMIT_MAX) || 10,
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

/**
 * Run Python scanner and return results
 */
async function runPythonScannerWithJSON(address, quickScan = false) {
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
}

/**
 * Get cached result with 3-layer check: Memory → Database → Analysis
 */
async function getCachedOrAnalyze(address, quickScan = false) {
  // Layer 1: Check in-memory cache (fastest)
  const memCached = getCached(address);
  if (memCached) {
    return memCached;
  }

  // Layer 2: Check database cache (24-hour TTL)
  const dbCached = await getCachedScanResult(address, 24);
  if (dbCached) {
    // Populate memory cache for future requests
    setCached(address, dbCached);
    return {
      ...dbCached,
      cache_source: 'database'
    };
  }

  // Layer 3: No cache, run analysis
  console.log(`No cache found for ${address}, running fresh analysis`);
  const results = await runPythonScannerWithJSON(address, quickScan);

  // Store in database for future use
  try {
    const dbId = await storeScanResult(address, results);
    results.db_id = dbId;
  } catch (error) {
    console.error('Failed to store results in database:', error.message);
    // Continue anyway, analysis succeeded
  }

  // Store in memory cache
  setCached(address, results);

  return {
    ...results,
    cached: false,
    cache_source: 'fresh'
  };
}

// Routes

/**
 * Health check endpoint
 */
app.get('/health', async (req, res) => {
  try {
    const dbStats = await getDbStats();
    const cacheStats = getCacheStats();

    res.json({
      status: 'ok',
      timestamp: new Date().toISOString(),
      activeAnalyses: activeAnalyses.size,
      database: dbStats,
      cache: cacheStats
    });
  } catch (error) {
    res.status(500).json({
      status: 'error',
      message: error.message
    });
  }
});

/**
 * Get API info
 */
app.get('/api/info', (req, res) => {
  res.json({
    name: 'BSC Security Scanner API',
    version: '1.0.0',
    description: 'REST API for analyzing BSC smart contract security',
    endpoints: {
      analyze: 'POST /api/analyze',
      analyzeSync: 'POST /api/analyze-sync',
      status: 'GET /api/analyze/:analysisId/status',
      health: 'GET /health'
    },
    rateLimit: {
      windowMs: 15 * 60 * 1000,
      maxRequests: parseInt(process.env.RATE_LIMIT_MAX) || 10
    },
    caching: {
      memoryTTL: '5 minutes',
      databaseTTL: '24 hours'
    }
  });
});

/**
 * Synchronous analysis endpoint (uses cache)
 */
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
    console.log(`Synchronous analysis request for ${address}`);
    const result = await getCachedOrAnalyze(address, quickScan);

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

/**
 * Asynchronous analysis endpoint
 */
app.post('/api/analyze', analyzeRateLimit, validateContractAddress, async (req, res) => {
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
      console.log(`Starting async analysis ${analysisId} for ${address}`);
      const result = await getCachedOrAnalyze(address, quickScan);

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
    estimatedTime: quickScan ? '30-60 seconds' : '60-120 seconds',
    statusUrl: `/api/analyze/${analysisId}/status`
  });
});

/**
 * Get analysis status
 */
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

// Initialize database and start server
async function startServer() {
  try {
    // Initialize database
    await initDatabase();

    // Start server
    app.listen(PORT, () => {
      console.log(`🚀 BSC Security Scanner API running on port ${PORT}`);
      console.log(`📊 Health check: http://localhost:${PORT}/health`);
      console.log(`📖 API info: http://localhost:${PORT}/api/info`);
      console.log(`🔍 Analysis endpoint: POST http://localhost:${PORT}/api/analyze-sync`);
      console.log(`⚡ Async analysis: POST http://localhost:${PORT}/api/analyze`);
      console.log(`💾 Database: SQLite (./database/bsc_scanner.db)`);
      console.log(`🗄️  Cache: In-memory (5min TTL)`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

// Handle graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully');
  process.exit(0);
});

// Start the server
startServer();

module.exports = app;
