/**
 * Simple in-memory cache for Node.js backend
 */

const NodeCache = require('node-cache');

// Create cache instance with 5 minute TTL
const cache = new NodeCache({ stdTTL: 300, checkperiod: 60 });

/**
 * Get value from cache
 * @param {string} key - Cache key
 * @returns {any} Cached value or undefined
 */
function getCached(key) {
  return cache.get(key);
}

/**
 * Set value in cache
 * @param {string} key - Cache key
 * @param {any} value - Value to cache
 * @param {number} ttl - Time to live in seconds (optional)
 */
function setCached(key, value, ttl) {
  if (ttl) {
    cache.set(key, value, ttl);
  } else {
    cache.set(key, value);
  }
}

/**
 * Clear all cache
 */
function clearCache() {
  cache.flushAll();
  console.log('Memory cache cleared');
}

/**
 * Get cache statistics
 * @returns {object} Cache stats
 */
function getStats() {
  const stats = cache.getStats();
  return {
    keys: cache.keys().length,
    hits: stats.hits,
    misses: stats.misses,
    ksize: stats.ksize,
    vsize: stats.vsize
  };
}

module.exports = {
  getCached,
  setCached,
  clearCache,
  getStats,
  cache
};
