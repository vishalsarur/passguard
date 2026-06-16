/**
 * cache.js — Redis cache with graceful in-memory fallback.
 * If Redis is unavailable, falls back to a simple Map-based LRU cache.
 */

const TTL = parseInt(process.env.CACHE_TTL || '86400', 10);

// In-memory fallback (max 5000 entries)
const memCache = new Map();
const MEM_MAX = 5000;

function memSet(key, value) {
  if (memCache.size >= MEM_MAX) {
    const first = memCache.keys().next().value;
    memCache.delete(first);
  }
  memCache.set(key, { value, expires: Date.now() + TTL * 1000 });
}

function memGet(key) {
  const entry = memCache.get(key);
  if (!entry) return null;
  if (Date.now() > entry.expires) { memCache.delete(key); return null; }
  return entry.value;
}

let redis = null;
let redisAvailable = false;

async function initRedis() {
  const redisUrl = process.env.REDIS_URL;
  if (!redisUrl || redisUrl === 'redis://localhost:6379' && process.env.NODE_ENV !== 'production') {
    console.log('[cache] No REDIS_URL — using in-memory fallback cache');
    return;
  }
  try {
    const Redis = require('ioredis');
    redis = new Redis(redisUrl, {
      connectTimeout: 3000,
      lazyConnect: true,
      maxRetriesPerRequest: 1,
    });
    await redis.connect();
    redisAvailable = true;
    console.log('[cache] Redis connected');
    redis.on('error', (err) => {
      if (redisAvailable) console.warn('[cache] Redis error, falling back to memory:', err.message);
      redisAvailable = false;
    });
    redis.on('connect', () => { redisAvailable = true; });
  } catch (err) {
    console.warn('[cache] Redis unavailable, using in-memory fallback:', err.message);
    redisAvailable = false;
  }
}

async function get(key) {
  if (redisAvailable && redis) {
    try {
      const val = await redis.get(key);
      return val ? val : null;
    } catch { /* fall through */ }
  }
  return memGet(key);
}

async function set(key, value, ttl = TTL) {
  if (redisAvailable && redis) {
    try {
      await redis.set(key, value, 'EX', ttl);
      return;
    } catch { /* fall through */ }
  }
  memSet(key, value);
}

async function stats() {
  const type = redisAvailable ? 'redis' : 'memory';
  const size = redisAvailable ? null : memCache.size;
  return { type, size };
}

module.exports = { initRedis, get, set, stats };
