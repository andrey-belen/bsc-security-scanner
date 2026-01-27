#!/usr/bin/env node

/**
 * BSC Security Scanner API Server
 * Express server with modular routes and services
 */

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');
require('dotenv').config();

// Database initialization
const { initDatabase } = require('./database/db');

// Routes
const healthRoutes = require('./routes/health');
const analyzeRoutes = require('./routes/analyze');
const cacheRoutes = require('./routes/cache');

const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;

// Security middleware
app.use(helmet());
app.use(compression());

// CORS configuration
const corsOrigin = process.env.NODE_ENV === 'production'
  ? true  // Allow same-origin in production
  : process.env.FRONTEND_URL || 'http://localhost:3000';
app.use(cors({
  origin: corsOrigin,
  credentials: true
}));

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Logging middleware
app.use(morgan('combined'));

// Mount routes
app.use('/', healthRoutes);
app.use('/api', analyzeRoutes);
app.use('/', cacheRoutes);

// Serve frontend in production
if (process.env.NODE_ENV === 'production') {
  const fs = require('fs');
  // Try public/ first, fall back to frontend/dist
  const staticDir = fs.existsSync(path.join(__dirname, 'public', 'index.html'))
    ? path.join(__dirname, 'public')
    : path.join(__dirname, 'frontend', 'dist');

  console.log(`📁 Serving static files from: ${staticDir}`);
  app.use(express.static(staticDir));
  app.get('*', (req, res, next) => {
    if (req.path.startsWith('/api') || req.path === '/health') {
      return next();
    }
    res.sendFile(path.join(staticDir, 'index.html'));
  });
}

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    path: req.path,
    method: req.method
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    error: 'Internal server error',
    message: err.message
  });
});

// Initialize database and start server
async function startServer() {
  try {
    console.log('🔧 Initializing database...');
    await initDatabase();
    console.log('✅ Database initialized');

    app.listen(PORT, () => {
      console.log(`🚀 BSC Security Scanner API running on port ${PORT}`);
      console.log(`📊 Health check: http://localhost:${PORT}/health`);
      console.log(`📖 API info: http://localhost:${PORT}/api/info`);
      console.log(`🔍 Analysis endpoint: http://localhost:${PORT}/api/analyze-sync`);
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
}

// Handle graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM signal received: closing HTTP server');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT signal received: closing HTTP server');
  process.exit(0);
});

startServer();
