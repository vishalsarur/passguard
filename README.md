# PassGuard — Password Strength Analyzer & Credential Breach Checker

A privacy-first fullstack tool that evaluates password strength and checks credentials against known breach databases — **zero raw-password transmission**.

## Architecture

```
passguard/
├── backend/          Node.js + Express API
│   ├── src/
│   │   ├── server.js     Entry point, rate limiting, CORS, logging
│   │   ├── routes.js     REST endpoints
│   │   ├── analyzer.js   zxcvbn + entropy analysis
│   │   ├── hibp.js       k-anonymity breach checking
│   │   └── cache.js      Redis / in-memory fallback
│   └── Dockerfile
├── frontend/         React + Vite SPA
│   ├── src/
│   │   ├── App.jsx
│   │   ├── StrengthMeter.jsx
│   │   ├── CrackTimes.jsx
│   │   ├── Panels.jsx
│   │   ├── BreachChecker.jsx
│   │   ├── usePasswordAnalysis.js   (client-side zxcvbn)
│   │   └── useBreachCheck.js        (k-anonymity + backend API)
│   ├── nginx.conf
│   └── Dockerfile
├── cli/
│   └── passguard_cli.py   Python CLI tool
└── docker-compose.yml
```

## Quick Start (Docker — recommended)

```bash
# 1. Clone / enter the project
cd passguard

# 2. Configure environment
cp backend/.env.example backend/.env
# Edit backend/.env — add your HIBP_API_KEY for email breach checks

# 3. Start everything
docker compose up --build

# App:     http://localhost:3000
# API:     http://localhost:4000/api/health
# Redis:   internal only
```

## Local Development (without Docker)

### Backend

```bash
cd backend
npm install
cp .env.example .env    # fill in your values
npm run dev             # starts on http://localhost:4000
```

### Frontend

```bash
cd frontend
npm install
npm run dev             # starts on http://localhost:5173
                        # proxies /api → http://localhost:4000
```

> Both must run simultaneously for full functionality.

## CLI Tool

```bash
# Interactive mode
python3 cli/passguard_cli.py

# Analyze a specific password
python3 cli/passguard_cli.py --password "MyPassword123"

# Skip breach check (offline use)
python3 cli/passguard_cli.py --password "test" --no-breach

# JSON output (pipe-friendly)
python3 cli/passguard_cli.py --password "test" --json

# Bulk CSV audit
python3 cli/passguard_cli.py --csv passwords.csv --output-csv-json

# Email breach check (requires HIBP_API_KEY env var)
HIBP_API_KEY=your_key python3 cli/passguard_cli.py --email user@example.com
```

CSV format: must have a column named `password` (case-insensitive).

## API Reference

### `POST /api/analyze`
Server-side strength analysis (for non-browser clients).
```json
// Request
{ "password": "YourPassword123!" }

// Response
{
  "score": 3,
  "strength_label": "Strong",
  "entropy_bits": 75.2,
  "crack_times": {
    "online_throttled": "centuries",
    "offline_slow_hash": "3 years",
    "offline_fast_hash": "1 hour"
  },
  "penalties": [],
  "suggestions": ["Use at least 12 characters."]
}
```

### `GET /api/breach/password?prefix=ABCDE&hash=ABCDE...`
k-anonymity password breach check. Only the 5-char SHA-1 prefix is sent.
The full hash suffix is matched locally on the backend.

```json
{ "pwned": true, "count": 38214, "message": "...", "fromCache": false }
```

### `GET /api/breach/email?email=user@example.com`
Email breach check via HIBP. Requires `HIBP_API_KEY` in `.env`.
```json
{
  "breached": true,
  "count": 3,
  "breaches": [{ "name": "Adobe", "date": "2013-10-04", "dataClasses": ["Passwords", "Emails"] }]
}
```

### `GET /api/health`
Returns server status, cache type, and HIBP key presence.

## Security Architecture

| Requirement | Implementation |
|---|---|
| SEC-01: Zero raw-password transmission | Strength analysis runs in-browser (zxcvbn). Only 5-char SHA-1 prefix sent for breach checks. |
| SEC-02: No password/prefix logging | Express logger strips query strings. Prefix excluded from logs. |
| SEC-03: TLS | Put behind nginx/Caddy with HTTPS in production. HSTS header set. |
| SEC-04: CORS | Restricted to `CORS_ORIGIN` env var. Whitelist enforced. |
| SEC-05: Input sanitization | UTF-8 normalize. 512 char limit enforced at API layer. |
| SEC-06: HIBP key security | Stored as env var only. Never in source or client bundle. |
| SEC-07: Rate limiting | `express-rate-limit`: 100 req / 15 min / IP on all `/api` routes. |

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `PORT` | `4000` | Backend port |
| `HIBP_API_KEY` | — | Required for email breach check |
| `REDIS_URL` | — | Redis connection URL (falls back to memory if unset) |
| `CACHE_TTL` | `86400` | Cache TTL in seconds (24 hours) |
| `CORS_ORIGIN` | `http://localhost:5173` | Allowed frontend origin(s) |
| `RATE_LIMIT_MAX` | `100` | Max requests per 15 min per IP |
| `NODE_ENV` | `development` | Set to `production` for stricter CORS |

## Success Metrics (from blueprint)

| Metric | Target | How |
|---|---|---|
| Strength analysis latency | < 100ms p95 | Runs entirely in browser (zxcvbn) |
| Breach check latency | < 500ms p95 | Redis cache + HIBP timeout of 8s |
| Cache hit rate | > 60% after 24h | Redis with 24–72h TTL |
| Privacy compliance | Zero raw-password logs | Query strings excluded from access logs |
| API uptime | ≥ 99.5% | Graceful degradation when HIBP unreachable |
