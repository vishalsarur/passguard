/**
 * routes.js — API route definitions for PassGuard backend.
 *
 * Endpoints:
 *   POST /api/analyze            — Password strength analysis (for CLI / non-browser clients)
 *   GET  /api/breach/password    — k-anonymity password breach check
 *   GET  /api/breach/email       — Email breach check via HIBP
 *   GET  /api/health             — Health check
 */

const express = require('express');
const router = express.Router();
const { analyze } = require('./analyzer');
const { checkPasswordHash, checkEmail } = require('./hibp');
const cache = require('./cache');

// ── Health check ──────────────────────────────────────────────────────────────
router.get('/health', async (req, res) => {
  const cacheStats = await cache.stats();
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    cache: cacheStats,
    hibpApiKey: !!process.env.HIBP_API_KEY && process.env.HIBP_API_KEY !== 'your_hibp_api_key_here',
  });
});

// ── POST /api/analyze ─────────────────────────────────────────────────────────
// Server-side strength analysis for non-browser clients (CLI, integrations).
// IMPORTANT: The raw password is NEVER logged (see SEC-01/SEC-02).
router.post('/analyze', (req, res) => {
  const { password } = req.body;
  if (!password || typeof password !== 'string') {
    return res.status(400).json({ error: 'Missing or invalid "password" field' });
  }
  if (password.length > 512) {
    return res.status(400).json({ error: 'Password exceeds 512 character limit (SEC-05)' });
  }
  try {
    const result = analyze(password);
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ── GET /api/breach/password ──────────────────────────────────────────────────
// k-anonymity password breach check.
// Only the 5-char SHA-1 prefix is accepted — full hash is NEVER stored/logged.
// SEC-02: prefix is NOT logged via express-request-handler.
router.get('/breach/password', async (req, res) => {
  const { prefix, hash } = req.query;

  if (!prefix || typeof prefix !== 'string' || prefix.length !== 5 || !/^[a-fA-F0-9]{5}$/.test(prefix)) {
    return res.status(400).json({ error: 'Invalid prefix. Must be exactly 5 hex characters.' });
  }
  if (!hash || typeof hash !== 'string' || hash.length !== 40 || !/^[a-fA-F0-9]{40}$/.test(hash)) {
    return res.status(400).json({ error: 'Invalid hash. Must be a full 40-char SHA-1 hex string.' });
  }

  try {
    const result = await checkPasswordHash(prefix, hash);
    res.json(result);
  } catch (err) {
    if (err.name === 'AbortError' || err.code === 'ECONNREFUSED') {
      return res.status(503).json({
        error: 'HIBP_UNAVAILABLE',
        message: 'Breach check service is temporarily unavailable. Strength analysis is unaffected.',
      });
    }
    res.status(502).json({ error: 'Upstream error', message: err.message });
  }
});

// ── GET /api/breach/email ─────────────────────────────────────────────────────
router.get('/breach/email', async (req, res) => {
  const { email } = req.query;

  if (!email || typeof email !== 'string' || !email.includes('@')) {
    return res.status(400).json({ error: 'Invalid email address.' });
  }
  if (email.length > 320) {
    return res.status(400).json({ error: 'Email address too long.' });
  }

  try {
    const result = await checkEmail(email.toLowerCase().trim());
    if (result.error && result.code === 'NO_API_KEY') {
      return res.status(501).json(result);
    }
    res.json(result);
  } catch (err) {
    if (err.name === 'AbortError') {
      return res.status(503).json({
        error: 'HIBP_UNAVAILABLE',
        message: 'Email breach service is temporarily unavailable.',
      });
    }
    res.status(502).json({ error: 'Upstream error', message: err.message });
  }
});

module.exports = router;
