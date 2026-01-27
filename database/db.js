/**
 * Database connection and query interface
 * Supports both SQLite (development) and PostgreSQL (production)
 */

const knex = require('knex');
const config = require('../knexfile.js');

const environment = process.env.NODE_ENV || 'development';
const db = knex(config[environment]);

/**
 * Initialize database and run migrations
 */
async function initDatabase() {
  try {
    // Run pending migrations
    await db.migrate.latest();
    console.log('✓ Database migrations completed');

    // Test connection
    await db.raw('SELECT 1');
    console.log(`✓ Database connected (${environment})`);

    return true;
  } catch (error) {
    console.error('✗ Database initialization failed:', error.message);
    throw error;
  }
}

/**
 * Store scan results in database
 * @param {string} address - Contract address
 * @param {object} results - Complete scan results
 * @returns {Promise<number>} - Inserted row ID
 */
async function storeScanResult(address, results) {
  try {
    const [id] = await db('scans').insert({
      address: address.toLowerCase(),
      scan_timestamp: new Date(),
      results_json: JSON.stringify(results),
      risk_level: results.risk_level || 'UNKNOWN',
      risk_score: results.risk_score || 0
    });

    return id;
  } catch (error) {
    console.error('Error storing scan result:', error.message);
    throw error;
  }
}

/**
 * Retrieve cached scan results (within 24 hours)
 * @param {string} address - Contract address
 * @param {number} ttlHours - Cache TTL in hours (default 24)
 * @returns {Promise<object|null>} - Cached results or null
 */
async function getCachedScanResult(address, ttlHours = 24) {
  try {
    const cutoffTime = new Date(Date.now() - ttlHours * 60 * 60 * 1000);

    const result = await db('scans')
      .where('address', address.toLowerCase())
      .where('scan_timestamp', '>', cutoffTime)
      .orderBy('scan_timestamp', 'desc')
      .first();

    if (result) {
      return {
        ...JSON.parse(result.results_json),
        cached: true,
        cache_timestamp: result.scan_timestamp,
        db_id: result.id
      };
    }

    return null;
  } catch (error) {
    console.error('Error retrieving cached result:', error.message);
    return null;
  }
}

/**
 * Get scan by ID
 * @param {number} id - Database ID
 * @returns {Promise<object|null>}
 */
async function getScanById(id) {
  try {
    const result = await db('scans').where('id', id).first();

    if (result) {
      return {
        ...JSON.parse(result.results_json),
        db_id: result.id,
        scan_timestamp: result.scan_timestamp
      };
    }

    return null;
  } catch (error) {
    console.error('Error retrieving scan by ID:', error.message);
    return null;
  }
}

/**
 * Update existing scan result (UPSERT pattern)
 * @param {string} address - Contract address
 * @param {object} results - Updated scan results
 * @returns {Promise<number>} - Updated/inserted row ID
 */
async function upsertScanResult(address, results) {
  try {
    const existing = await db('scans')
      .where('address', address.toLowerCase())
      .orderBy('scan_timestamp', 'desc')
      .first();

    if (existing) {
      // Update existing record
      await db('scans')
        .where('id', existing.id)
        .update({
          scan_timestamp: new Date(),
          results_json: JSON.stringify(results),
          risk_level: results.risk_level || 'UNKNOWN',
          risk_score: results.risk_score || 0
        });

      return existing.id;
    } else {
      // Insert new record
      return await storeScanResult(address, results);
    }
  } catch (error) {
    console.error('Error upserting scan result:', error.message);
    throw error;
  }
}

/**
 * Get database statistics
 * @returns {Promise<object>} - Stats object
 */
async function getStats() {
  try {
    const totalScans = await db('scans').count('* as count').first();
    const uniqueAddresses = await db('scans').countDistinct('address as count').first();
    const recentScans = await db('scans')
      .where('scan_timestamp', '>', new Date(Date.now() - 24 * 60 * 60 * 1000))
      .count('* as count')
      .first();

    return {
      total_scans: totalScans.count,
      unique_addresses: uniqueAddresses.count,
      scans_last_24h: recentScans.count
    };
  } catch (error) {
    console.error('Error getting database stats:', error.message);
    return null;
  }
}

/**
 * Clear all scans from database
 * @returns {Promise<number>} - Number of deleted rows
 */
async function clearAllScans() {
  try {
    const count = await db('scans').del();
    console.log(`✓ Cleared ${count} scans from database`);
    return count;
  } catch (error) {
    console.error('Error clearing scans:', error.message);
    throw error;
  }
}

/**
 * Close database connection
 */
async function closeDatabase() {
  await db.destroy();
  console.log('✓ Database connection closed');
}

module.exports = {
  db,
  initDatabase,
  storeScanResult,
  getCachedScanResult,
  getScanById,
  upsertScanResult,
  getStats,
  clearAllScans,
  closeDatabase
};
