/**
 * In-memory cache layer using node-cache
 * Provides fast access to recently scanned contracts (5-minute TTL)
 */

const NodeCache = require('node-cache');

// Initialize cache with 5-minute TTL (300 seconds)
const cache = new NodeCache({
  stdTTL: parseInt(process.env.CACHE_TTL) || 300,
  checkperiod: 60, // Check for expired keys every 60 seconds
  useClones: false // Performance: don't clone objects
});

/**
 * Get cached scan result
 * @param {string} address - Contract address
 * @returns {object|null} - Cached result or null
 */
function getCached(address) {
  const key = address.toLowerCase();
  const value = cache.get(key);

  if (value) {
    console.log(`✓ Cache HIT: ${address}`);
    return {
      ...value,
      cached: true,
      cache_source: 'memory'
    };
  }

  console.log(`✗ Cache MISS: ${address}`);
  return null;
}

/**
 * Store scan result in cache
 * @param {string} address - Contract address
 * @param {object} results - Scan results to cache
 * @returns {boolean} - Success status
 */
function setCached(address, results) {
  try {
    const key = address.toLowerCase();
    cache.set(key, results);
    console.log(`✓ Cached result for: ${address}`);
    return true;
  } catch (error) {
    console.error('Error setting cache:', error.message);
    return false;
  }
}

/**
 * Invalidate cache entry
 * @param {string} address - Contract address
 * @returns {boolean} - Success status
 */
function invalidate(address) {
  const key = address.toLowerCase();
  const deleted = cache.del(key);
  if (deleted) {
    console.log(`✓ Invalidated cache for: ${address}`);
  }
  return deleted > 0;
}

/**
 * Clear all cache entries
 */
function clearAll() {
  cache.flushAll();
  console.log('✓ Cache cleared');
}

/**
 * Get cache statistics
 * @returns {object} - Cache stats
 */
function getStats() {
  const stats = cache.getStats();
  const keys = cache.keys();

  return {
    hits: stats.hits,
    misses: stats.misses,
    keys_count: keys.length,
    hit_rate: stats.hits + stats.misses > 0
      ? ((stats.hits / (stats.hits + stats.misses)) * 100).toFixed(2) + '%'
      : '0%'
  };
}

// Handle cache events
cache.on('expired', (key, value) => {
  console.log(`⏱ Cache expired: ${key}`);
});

cache.on('flush', () => {
  console.log('🗑 Cache flushed');
});

module.exports = {
  cache,
  getCached,
  setCached,
  invalidate,
  clearAll,
  getStats
};
