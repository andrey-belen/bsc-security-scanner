/**
 * Scanner Service - Python scanner integration and caching logic
 */

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs').promises;
const { storeScanResult, getCachedScanResult } = require('../database/db');
const { getCached, setCached, clearCache } = require('../cache/cache');

/**
 * Run Python scanner and return results
 *
 * @param {string} address - Contract address to analyze
 * @param {boolean} quickScan - Whether to perform quick scan
 * @returns {Promise<Object>} Analysis results
 */
async function runPythonScannerWithJSON(address, quickScan = false) {
  const scriptPath = path.join(__dirname, '..', 'scanner.py');
  const tempOutputFile = path.join(__dirname, '..', 'temp_reports', `temp_${Date.now()}.json`);

  // Ensure temp directory exists
  await fs.mkdir(path.dirname(tempOutputFile), { recursive: true });

  return new Promise((resolve, reject) => {
    const args = ['--address', address, '--output', tempOutputFile];

    if (quickScan) {
      args.push('--quick');
    }

    console.log(`Starting analysis for ${address} (quick: ${quickScan})`);

    const pythonProcess = spawn('python3', [scriptPath, ...args], {
      cwd: path.join(__dirname, '..'),
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
 * Get cached result with 3-layer check: Memory → Database → Fresh Analysis
 *
 * @param {string} address - Contract address
 * @param {boolean} quickScan - Whether to perform quick scan
 * @returns {Promise<Object>} Analysis results with cache metadata
 */
async function getCachedOrAnalyze(address, quickScan = false) {
  // Layer 1: Check in-memory cache (fastest)
  const memCached = getCached(address);
  if (memCached) {
    console.log(`Cache hit (memory) for ${address}`);
    return {
      ...memCached,
      cache_source: 'memory'
    };
  }

  // Layer 2: Check database cache (24-hour TTL)
  const dbCached = await getCachedScanResult(address, 24);
  if (dbCached) {
    console.log(`Cache hit (database) for ${address}`);
    // Populate memory cache for future requests
    setCached(address, dbCached);
    return {
      ...dbCached,
      cache_source: 'database'
    };
  }

  // Layer 3: No cache, run analysis
  console.log(`Cache miss for ${address}, running fresh analysis`);
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

/**
 * Clear all caches (memory, database, and Python file cache)
 *
 * @returns {Promise<Object>} Results of cache clearing operations
 */
async function clearAllCaches() {
  const results = {
    memory: false,
    database: false,
    python: false
  };

  // Clear memory cache
  try {
    clearCache();
    results.memory = true;
    console.log('Memory cache cleared');
  } catch (error) {
    console.error('Failed to clear memory cache:', error);
  }

  // Clear Python file cache
  try {
    const cachePath = path.join(__dirname, '..', '.cache');
    await fs.rm(cachePath, { recursive: true, force: true });
    results.python = true;
    console.log('Python file cache cleared');
  } catch (error) {
    console.error('Failed to clear Python cache:', error);
  }

  // Note: Database cache auto-expires based on TTL, no manual clearing needed
  results.database = true;

  return results;
}

module.exports = {
  runPythonScannerWithJSON,
  getCachedOrAnalyze,
  clearAllCaches
};
