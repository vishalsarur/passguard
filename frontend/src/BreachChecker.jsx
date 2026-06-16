import React, { useState } from 'react';
import { useBreachCheck } from './useBreachCheck';

const s = {
  card: {
    background: '#0f0f1a',
    border: '1px solid #252535',
    borderRadius: '10px',
    padding: '1rem 1.1rem',
  },
  header: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginBottom: '0.8rem',
  },
  title: {
    fontFamily: "'Space Mono', monospace",
    fontSize: '0.62rem',
    textTransform: 'uppercase',
    letterSpacing: '0.12em',
    color: '#64647a',
  },
  checkBtn: (disabled) => ({
    fontFamily: "'Space Mono', monospace",
    fontSize: '0.68rem',
    padding: '0.35rem 0.9rem',
    background: disabled ? '#1e1e2e' : '#7c5cfc',
    color: disabled ? '#64647a' : '#fff',
    border: 'none',
    borderRadius: '6px',
    cursor: disabled ? 'not-allowed' : 'pointer',
    letterSpacing: '0.04em',
    transition: 'opacity 0.2s',
    opacity: disabled ? 0.5 : 1,
  }),
  badge: (type) => {
    const map = {
      safe: { bg: 'rgba(74,222,128,0.1)', color: '#4ade80', border: 'rgba(74,222,128,0.25)' },
      pwned: { bg: 'rgba(248,113,113,0.1)', color: '#f87171', border: 'rgba(248,113,113,0.25)' },
      checking: { bg: 'rgba(124,92,252,0.1)', color: '#7c5cfc', border: 'rgba(124,92,252,0.25)' },
      warn: { bg: 'rgba(251,191,36,0.1)', color: '#fbbf24', border: 'rgba(251,191,36,0.25)' },
    };
    const c = map[type] || map.warn;
    return {
      display: 'inline-flex',
      alignItems: 'center',
      gap: '0.3rem',
      padding: '0.2rem 0.65rem',
      borderRadius: '20px',
      background: c.bg,
      color: c.color,
      border: `1px solid ${c.border}`,
      fontFamily: "'Space Mono', monospace",
      fontSize: '0.68rem',
      fontWeight: 700,
    };
  },
  countBig: {
    fontFamily: "'Space Mono', monospace",
    fontSize: '1.6rem',
    fontWeight: 700,
    color: '#f87171',
    display: 'block',
    margin: '0.4rem 0 0.2rem',
  },
  small: { fontSize: '0.75rem', color: '#64647a', lineHeight: 1.5 },
  divider: { borderTop: '1px solid #1e1e2e', margin: '0.8rem 0' },
  emailRow: { display: 'flex', gap: '0.5rem' },
  emailInput: {
    flex: 1,
    padding: '0.4rem 0.7rem',
    fontSize: '0.78rem',
    background: '#181825',
    border: '1px solid #252535',
    color: '#e2e2f0',
    borderRadius: '6px',
    outline: 'none',
    fontFamily: "'DM Sans', sans-serif",
  },
  emailBtn: (loading) => ({
    fontFamily: "'Space Mono', monospace",
    fontSize: '0.68rem',
    padding: '0.4rem 0.85rem',
    background: '#181825',
    color: '#7c5cfc',
    border: '1px solid rgba(124,92,252,0.4)',
    borderRadius: '6px',
    cursor: loading ? 'not-allowed' : 'pointer',
    whiteSpace: 'nowrap',
    opacity: loading ? 0.6 : 1,
  }),
  breachTag: {
    display: 'inline-block',
    background: '#181825',
    border: '1px solid #252535',
    borderRadius: '4px',
    padding: '0.15rem 0.5rem',
    margin: '2px 3px 2px 0',
    fontSize: '0.68rem',
    fontFamily: "'Space Mono', monospace",
    color: '#8888a0',
  },
  cacheNote: { fontSize: '0.65rem', color: '#3d3d52', marginTop: '0.4rem' },
};

function PwBreachResult({ result, loading }) {
  if (loading) return <span style={s.badge('checking')}><i className="ti ti-loader" aria-hidden="true" /> Checking...</span>;
  if (!result) return <p style={s.small}>Enter a password above, then check if it appears in known breaches.</p>;

  if (result.status === 'unavailable') return (
    <div>
      <span style={s.badge('warn')}><i className="ti ti-wifi-off" aria-hidden="true" /> Breach check unavailable</span>
      <p style={{ ...s.small, marginTop: '0.4rem' }}>{result.message}</p>
    </div>
  );
  if (result.status === 'error') return (
    <div>
      <span style={s.badge('warn')}><i className="ti ti-alert-circle" aria-hidden="true" /> Error</span>
      <p style={{ ...s.small, marginTop: '0.4rem' }}>{result.message}</p>
    </div>
  );
  if (result.status === 'pwned') return (
    <div>
      <span style={s.badge('pwned')}><i className="ti ti-flame" aria-hidden="true" /> Compromised</span>
      <span style={s.countBig}>{result.count.toLocaleString()}×</span>
      <p style={s.small}>This password has been seen in known data breaches. Do not use it anywhere.</p>
      {result.fromCache && <p style={s.cacheNote}>Served from cache</p>}
    </div>
  );
  return (
    <div>
      <span style={s.badge('safe')}><i className="ti ti-shield-check" aria-hidden="true" /> Not found in breaches</span>
      <p style={{ ...s.small, marginTop: '0.4rem' }}>Not found in the HIBP database. Also consider the strength score above.</p>
      {result.fromCache && <p style={s.cacheNote}>Served from cache</p>}
    </div>
  );
}

function EmailBreachResult({ result, loading }) {
  if (loading) return <span style={{ ...s.badge('checking'), fontSize: '0.62rem', marginTop: '0.5rem', display: 'inline-flex' }}><i className="ti ti-loader" aria-hidden="true" /> Checking...</span>;
  if (!result) return null;

  if (result.status === 'no_key') return (
    <p style={{ ...s.small, color: '#fbbf24', marginTop: '0.4rem' }}>
      <i className="ti ti-key" aria-hidden="true" /> {result.message}
    </p>
  );
  if (result.status === 'unavailable' || result.status === 'error') return (
    <p style={{ ...s.small, color: '#fbbf24', marginTop: '0.4rem' }}>{result.message}</p>
  );
  if (result.status === 'safe') return (
    <div style={{ marginTop: '0.4rem' }}>
      <span style={{ ...s.badge('safe'), fontSize: '0.62rem' }}><i className="ti ti-shield-check" aria-hidden="true" /> No breaches found</span>
    </div>
  );
  return (
    <div style={{ marginTop: '0.4rem' }}>
      <span style={{ ...s.badge('pwned'), fontSize: '0.62rem' }}><i className="ti ti-alert-triangle" aria-hidden="true" /> Found in {result.count} breach{result.count !== 1 ? 'es' : ''}</span>
      <div style={{ marginTop: '0.5rem' }}>
        {result.breaches?.map(b => (
          <span key={b.name} style={s.breachTag} title={b.dataClasses?.join(', ')}>{b.name}</span>
        ))}
      </div>
      {result.fromCache && <p style={s.cacheNote}>Served from cache</p>}
    </div>
  );
}

export default function BreachChecker({ password }) {
  const [emailVal, setEmailVal] = useState('');
  const { checkPassword, pwResult, pwLoading, checkEmail, emailResult, emailLoading } = useBreachCheck();

  return (
    <div style={s.card}>
      <div style={s.header}>
        <span style={s.title}>Breach check — HIBP k-anonymity</span>
        <button
          style={s.checkBtn(!password || pwLoading)}
          disabled={!password || pwLoading}
          onClick={() => checkPassword(password)}
        >
          {pwLoading ? 'Checking...' : 'Check password'}
        </button>
      </div>

      <PwBreachResult result={pwResult} loading={pwLoading} />

      <div style={s.divider} />

      <div style={s.emailRow}>
        <input
          type="email"
          style={s.emailInput}
          placeholder="Check email address breaches..."
          value={emailVal}
          onChange={e => setEmailVal(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && checkEmail(emailVal)}
          autoComplete="off"
        />
        <button
          style={s.emailBtn(emailLoading)}
          disabled={emailLoading}
          onClick={() => checkEmail(emailVal)}
        >
          Check email
        </button>
      </div>
      <EmailBreachResult result={emailResult} loading={emailLoading} />
    </div>
  );
}
