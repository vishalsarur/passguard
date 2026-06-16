/**
 * server.js — PassGuard Express server.
 *
 * Implements:
 *   - SEC-03: TLS-ready (put behind nginx/Caddy in production)
 *   - SEC-04: CORS restricted to configured origin
 *   - SEC-07: Per-IP rate limiting on all API endpoints
 *   - SEC-02: Access logs DO NOT include password or hash prefix params
 */

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cache = require('./cache');
const routes = require('./routes');

const app = express();
const PORT = parseInt(process.env.PORT || '4000', 10);

// ── Security headers (SEC-03 partial — full TLS via reverse proxy) ────────────
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' },
}));

// ── CORS (SEC-04) ─────────────────────────────────────────────────────────────
const allowedOrigins = (process.env.CORS_ORIGIN || 'http://localhost:5173')
  .split(',')
  .map(o => o.trim());

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (CLI tools, curl) in development
    if (!origin || process.env.NODE_ENV !== 'production') return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    callback(new Error(`CORS: Origin ${origin} not allowed`));
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Accept'],
}));

// ── Body parsing ──────────────────────────────────────────────────────────────
app.use(express.json({ limit: '10kb' }));

// ── Privacy-safe request logging (SEC-02: never log prefix or password) ───────
app.use((req, res, next) => {
  // Sanitize URL before logging — remove sensitive query params
  const safeUrl = req.path; // intentionally exclude query string
  const ts = new Date().toISOString();
  const method = req.method;
  res.on('finish', () => {
    console.log(`${ts} ${method} ${safeUrl} → ${res.statusCode}`);
  });
  next();
});

// ── Rate limiting (SEC-07) ────────────────────────────────────────────────────
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_MAX || '100', 10),
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests. Please slow down.' },
  skip: (req) => process.env.NODE_ENV !== 'production' && req.ip === '127.0.0.1',
});

app.use('/api', limiter);

// ── Routes ────────────────────────────────────────────────────────────────────
app.use('/api', routes);

// ── 404 handler ───────────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: 'Not found', path: req.path });
});

// ── Error handler ─────────────────────────────────────────────────────────────
app.use((err, req, res, _next) => {
  console.error('[error]', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

// ── Boot ──────────────────────────────────────────────────────────────────────
async function boot() {
  await cache.initRedis();
  app.listen(PORT, () => {
    console.log(`\n🔐 PassGuard backend running on http://localhost:${PORT}`);
    console.log(`   CORS allowed: ${allowedOrigins.join(', ')}`);
    console.log(`   Redis: ${process.env.REDIS_URL ? 'configured' : 'not configured (memory fallback)'}`);
    console.log(`   HIBP API key: ${process.env.HIBP_API_KEY && process.env.HIBP_API_KEY !== 'your_hibp_api_key_here' ? 'set ✓' : 'not set (email check disabled)'}\n`);
  });
}

boot().catch(err => {
  console.error('Failed to start server:', err);
  process.exit(1);
});

module.exports = app;
