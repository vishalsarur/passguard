/**
 * hibp.js — HaveIBeenPwned integration.
 *
 * Password check uses k-anonymity: only the first 5 hex chars of the SHA-1 hash
 * are sent to HIBP. The full hash is NEVER transmitted.
 *
 * Email check proxies the HIBP /breachedaccount endpoint using the server-held API key.
 */

const fetch = require('node-fetch');
const crypto = require('crypto');
const cache = require('./cache');

const HIBP_BASE = 'https://haveibeenpwned.com/api/v3';
const HIBP_PW_BASE = 'https://api.pwnedpasswords.com';
const HIBP_TIMEOUT = 8000;
const CACHE_TTL = parseInt(process.env.CACHE_TTL || '86400', 10);

/**
 * Check a password prefix against HIBP Pwned Passwords (k-anonymity).
 * Only the 5-char prefix is sent — suffix matching is done here server-side.
 *
 * @param {string} prefix - First 5 hex chars of the SHA-1 hash
 * @returns {string} Raw HIBP suffix list (hash_suffix:count per line)
 */
async function getPwnedRange(prefix) {
  const cacheKey = `hibp:range:${prefix.toUpperCase()}`;

  // Check cache first
  const cached = await cache.get(cacheKey);
  if (cached) {
    return { data: cached, fromCache: true };
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), HIBP_TIMEOUT);

  try {
    const res = await fetch(`${HIBP_PW_BASE}/range/${prefix}?addpadding=true`, {
      headers: { 'User-Agent': 'PassGuard-Tool/1.0' },
      signal: controller.signal,
    });

    if (!res.ok) throw new Error(`HIBP range returned ${res.status}`);
    const text = await res.text();

    // Cache the suffix list (SEC-02: prefix does NOT appear in access logs)
    await cache.set(cacheKey, text, CACHE_TTL);

    return { data: text, fromCache: false };
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * Check a full password hash suffix against a HIBP suffix list.
 * @param {string} suffixList - Raw HIBP range response
 * @param {string} fullHash - Full 40-char SHA-1 hash (uppercase)
 * @returns {{ pwned: boolean, count: number }}
 */
function matchSuffix(suffixList, fullHash) {
  const suffix = fullHash.slice(5).toUpperCase();
  const lines = suffixList.split('\n');
  for (const line of lines) {
    const [s, c] = line.trim().split(':');
    if (s === suffix) {
      return { pwned: true, count: parseInt(c, 10) };
    }
  }
  return { pwned: false, count: 0 };
}

/**
 * Full password breach check.
 * Accepts the raw password, hashes it locally, checks via k-anonymity.
 *
 * @param {string} prefix - First 5 chars of client SHA-1 hash
 * @param {string} fullHash - Full SHA-1 hash (client-provided or computed)
 */
async function checkPasswordHash(prefix, fullHash) {
  const { data, fromCache } = await getPwnedRange(prefix.toUpperCase());
  const result = matchSuffix(data, fullHash.toUpperCase());
  return {
    ...result,
    message: result.pwned
      ? `This password has been seen ${result.count.toLocaleString()} time(s) in data breaches. Do not use it.`
      : 'This password was not found in known data breaches.',
    fromCache,
  };
}

/**
 * Email breach check via HIBP /breachedaccount.
 * Requires HIBP_API_KEY environment variable.
 *
 * @param {string} email
 */
async function checkEmail(email) {
  const apiKey = process.env.HIBP_API_KEY;
  if (!apiKey || apiKey === 'your_hibp_api_key_here') {
    return {
      error: true,
      code: 'NO_API_KEY',
      message: 'Email breach check requires an HIBP API key. Set HIBP_API_KEY in your .env file.',
    };
  }

  const cacheKey = `hibp:email:${email.toLowerCase()}`;
  const cached = await cache.get(cacheKey);
  if (cached) {
    return { ...JSON.parse(cached), fromCache: true };
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), HIBP_TIMEOUT);

  try {
    const res = await fetch(
      `${HIBP_BASE}/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`,
      {
        headers: {
          'hibp-api-key': apiKey,
          'User-Agent': 'PassGuard-Tool/1.0',
        },
        signal: controller.signal,
      }
    );

    if (res.status === 404) {
      const result = { breached: false, count: 0, breaches: [], message: 'No breaches found for this email address.' };
      await cache.set(cacheKey, JSON.stringify(result), CACHE_TTL);
      return result;
    }
    if (res.status === 401) return { error: true, code: 'UNAUTHORIZED', message: 'Invalid HIBP API key.' };
    if (res.status === 429) return { error: true, code: 'RATE_LIMITED', message: 'HIBP rate limit hit. Please wait a moment.' };
    if (!res.ok) throw new Error(`HIBP email returned ${res.status}`);

    const data = await res.json();
    const result = {
      breached: true,
      count: data.length,
      breaches: data.map(b => ({
        name: b.Name,
        domain: b.Domain,
        date: b.BreachDate,
        dataClasses: b.DataClasses,
        description: b.Description,
      })),
      message: `This email was found in ${data.length} breach${data.length !== 1 ? 'es' : ''}.`,
    };
    await cache.set(cacheKey, JSON.stringify(result), CACHE_TTL);
    return { ...result, fromCache: false };
  } finally {
    clearTimeout(timeout);
  }
}

module.exports = { checkPasswordHash, checkEmail };
