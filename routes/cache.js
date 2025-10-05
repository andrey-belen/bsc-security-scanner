/**
 * Cache Routes - Cache management endpoints
 */

const express = require('express');
const router = express.Router();
const { clearAllCaches } = require('../services/scanner_service');

/**
 * POST /api/cache/clear - Clear all caches
 */
router.post('/api/cache/clear', async (req, res) => {
  try {
    const result = await clearAllCaches();

    res.json({
      success: true,
      message: 'All caches cleared successfully',
      details: result
    });
  } catch (error) {
    console.error('Cache clear error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to clear caches',
      details: error.message
    });
  }
});

module.exports = router;
