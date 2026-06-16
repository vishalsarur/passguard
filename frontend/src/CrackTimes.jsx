import React from 'react';

const s = {
  card: {
    background: '#0f0f1a',
    border: '1px solid #252535',
    borderRadius: '10px',
    padding: '1rem',
  },
  title: {
    fontFamily: "'Space Mono', monospace",
    fontSize: '0.62rem',
    textTransform: 'uppercase',
    letterSpacing: '0.12em',
    color: '#64647a',
    marginBottom: '0.8rem',
  },
  row: {
    marginBottom: '0.65rem',
    paddingBottom: '0.65rem',
    borderBottom: '1px solid #1e1e2e',
  },
  rowLast: { marginBottom: 0 },
  profile: { fontSize: '0.7rem', color: '#64647a', marginBottom: '0.2rem' },
  time: {
    fontFamily: "'Space Mono', monospace",
    fontSize: '0.9rem',
    fontWeight: 700,
    color: '#e2e2f0',
  },
};

const profiles = [
  { key: 'online_throttled', label: 'Online throttled', sub: '~100 guesses/sec' },
  { key: 'offline_slow', label: 'Offline slow hash', sub: 'bcrypt ~10K/sec' },
  { key: 'offline_fast', label: 'Offline fast hash', sub: 'MD5/SHA-1 ~10B/sec' },
];

export default function CrackTimes({ crack_times }) {
  if (!crack_times) return null;
  return (
    <div style={s.card}>
      <div style={s.title}>Crack time estimates</div>
      {profiles.map((p, i) => (
        <div key={p.key} style={i < profiles.length - 1 ? s.row : { ...s.row, ...s.rowLast, borderBottom: 'none', paddingBottom: 0 }}>
          <div style={s.profile}>{p.label} <span style={{ color: '#3d3d52' }}>({p.sub})</span></div>
          <div style={s.time}>{crack_times[p.key] || '—'}</div>
        </div>
      ))}
    </div>
  );
}
