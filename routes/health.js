/**
 * Health Routes - Health check and API info endpoints
 */

const express = require('express');
const router = express.Router();
const { getStats: getDbStats } = require('../database/db');
const { getStats: getCacheStats } = require('../cache/cache');

/**
 * GET /health - Health check endpoint
 */
router.get('/health', async (req, res) => {
  try {
    const dbStats = await getDbStats();
    const cacheStats = getCacheStats();

    res.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      database: {
        connected: true,
        totalScans: dbStats.totalScans,
        oldestScan: dbStats.oldestScan,
        newestScan: dbStats.newestScan
      },
      cache: {
        size: cacheStats.keys,
        hitRate: cacheStats.hitRate,
        hits: cacheStats.hits,
        misses: cacheStats.misses
      },
      uptime: process.uptime(),
      memory: process.memoryUsage()
    });
  } catch (error) {
    res.status(500).json({
      status: 'unhealthy',
      error: error.message
    });
  }
});

/**
 * GET /api/info - API information
 */
router.get('/api/info', (req, res) => {
  res.json({
    name: 'BSC Security Scanner API',
    version: '2.0.0',
    description: 'Smart contract security analysis API for Binance Smart Chain',
    endpoints: {
      health: 'GET /health',
      info: 'GET /api/info',
      analyzeAsync: 'POST /api/analyze',
      analyzeStatus: 'GET /api/analyze/:id/status',
      analyzeSync: 'POST /api/analyze-sync',
      clearCache: 'POST /api/cache/clear'
    },
    rateLimit: {
      windowMs: 15 * 60 * 1000,
      maxRequests: parseInt(process.env.RATE_LIMIT_MAX) || 10
    },
    features: [
      '3-layer caching (memory, database, file)',
      'Async and sync analysis modes',
      'Contract verification via Etherscan API',
      'Ownership analysis',
      'Function and ABI analysis',
      'Holder distribution analysis',
      'Liquidity pool analysis',
      'Honeypot detection'
    ]
  });
});

module.exports = router;
