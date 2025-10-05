/**
 * Analysis Routes - Handle contract analysis endpoints
 */

const express = require('express');
const router = express.Router();
const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const { getCachedOrAnalyze, getAnalysisStatus } = require('../services/scanner_service');
const { validateContractAddress } = require('../middleware/validation');

// Rate limiting for analysis endpoints
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

/**
 * POST /api/analyze - Start async analysis
 */
router.post('/analyze', analyzeRateLimit, validateContractAddress, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { address, quickScan = false } = req.body;
  const analysisId = `${address}_${Date.now()}`;

  try {
    // Start analysis asynchronously
    activeAnalyses.set(analysisId, {
      address,
      status: 'pending',
      startTime: Date.now()
    });

    // Run analysis in background
    getCachedOrAnalyze(address, quickScan)
      .then(result => {
        activeAnalyses.set(analysisId, {
          address,
          status: 'completed',
          result,
          completedTime: Date.now()
        });
      })
      .catch(error => {
        activeAnalyses.set(analysisId, {
          address,
          status: 'failed',
          error: error.message,
          completedTime: Date.now()
        });
      });

    res.json({
      analysisId,
      status: 'pending',
      message: 'Analysis started',
      statusUrl: `/api/analyze/${analysisId}/status`
    });

  } catch (error) {
    console.error('Analysis error:', error);
    res.status(500).json({ error: 'Failed to start analysis' });
  }
});

/**
 * GET /api/analyze/:id/status - Check analysis status
 */
router.get('/analyze/:id/status', (req, res) => {
  const { id } = req.params;
  const analysis = activeAnalyses.get(id);

  if (!analysis) {
    return res.status(404).json({ error: 'Analysis not found' });
  }

  const response = {
    status: analysis.status,
    address: analysis.address
  };

  if (analysis.status === 'completed') {
    response.result = analysis.result;
  } else if (analysis.status === 'failed') {
    response.error = analysis.error;
  }

  res.json(response);
});

/**
 * POST /api/analyze-sync - Synchronous analysis with caching
 */
router.post('/analyze-sync', analyzeRateLimit, validateContractAddress, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { address, quickScan = false } = req.body;

  try {
    const result = await getCachedOrAnalyze(address, quickScan);
    res.json(result);
  } catch (error) {
    console.error('Sync analysis error:', error);
    res.status(500).json({
      error: 'Analysis failed',
      details: error.message
    });
  }
});

module.exports = router;
